// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018-2019 HiSilicon Limited. */
#include <asm/page.h>
#include <linux/bitmap.h>
#include <linux/debugfs.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/irqreturn.h>
#include <linux/log2.h>
#include <linux/seq_file.h>
#include "qm.h"
#include "qm_usr_if.h"

/* eq/aeq irq enable */
#define QM_VF_AEQ_INT_SOURCE		0x0
#define QM_VF_AEQ_INT_MASK		0x4
#define QM_VF_EQ_INT_SOURCE		0x8
#define QM_VF_EQ_INT_MASK		0xc
#define QM_IRQ_NUM_V1			1
#define QM_IRQ_NUM_PF_V2		4
#define QM_IRQ_NUM_VF_V2		2

/* mailbox */
#define QM_MB_CMD_SQC			0x0
#define QM_MB_CMD_CQC			0x1
#define QM_MB_CMD_EQC			0x2
#define QM_MB_CMD_AEQC			0x3
#define QM_MB_CMD_SQC_BT		0x4
#define QM_MB_CMD_CQC_BT		0x5
#define QM_MB_CMD_SQC_VFT_V2		0x6

#define QM_MB_CMD_SEND_BASE		0x300
#define QM_MB_EVENT_SHIFT		8
#define QM_MB_BUSY_SHIFT		13
#define QM_MB_OP_SHIFT			14
#define QM_MB_CMD_DATA_ADDR_L		0x304
#define QM_MB_CMD_DATA_ADDR_H		0x308

/* sqc shift */
#define QM_SQ_HOP_NUM_SHIFT		0
#define QM_SQ_PAGE_SIZE_SHIFT		4
#define QM_SQ_BUF_SIZE_SHIFT		8
#define QM_SQ_SQE_SIZE_SHIFT		12
#define QM_SQ_PRIORITY_SHIFT		0
#define QM_SQ_ORDERS_SHIFT		4
#define QM_SQ_TYPE_SHIFT		8

#define QM_SQ_TYPE_MASK			0xf

/* cqc shift */
#define QM_CQ_HOP_NUM_SHIFT		0
#define QM_CQ_PAGE_SIZE_SHIFT		4
#define QM_CQ_BUF_SIZE_SHIFT		8
#define QM_CQ_CQE_SIZE_SHIFT		12
#define QM_CQ_PHASE_SHIFT		0
#define QM_CQ_FLAG_SHIFT		1

#define QM_CQE_PHASE(cqe)		(le16_to_cpu((cqe)->w7) & 0x1)

#define QM_QC_CQE_SIZE			4

/* eqc shift */
#define QM_EQE_AEQE_SIZE		(2UL << 12)
#define QM_EQC_PHASE_SHIFT		16

#define QM_EQE_PHASE(eqe)		((le32_to_cpu((eqe)->dw0) >> 16) & 0x1)
#define QM_EQE_CQN_MASK			0xffff

#define QM_AEQE_PHASE(aeqe)		((le32_to_cpu((aeqe)->dw0) >> 16) & 0x1)
#define QM_AEQE_TYPE_SHIFT		17

#define QM_DOORBELL_CMD_SQ		0
#define QM_DOORBELL_CMD_CQ		1
#define QM_DOORBELL_CMD_EQ		2
#define QM_DOORBELL_CMD_AEQ		3

#define QM_DOORBELL_BASE_V1		0x340
#define QM_DOORBELL_SQ_CQ_BASE_V2	0x1000
#define QM_DOORBELL_EQ_AEQ_BASE_V2	0x2000

#define QM_MEM_START_INIT		0x100040
#define QM_MEM_INIT_DONE		0x100044
#define QM_VFT_CFG_RDY			0x10006c
#define QM_VFT_CFG_OP_WR		0x100058
#define QM_VFT_CFG_TYPE			0x10005c
#define QM_SQC_VFT			0x0
#define QM_CQC_VFT			0x1
#define QM_VFT_CFG_ADDRESS		0x100060
#define QM_VFT_CFG_OP_ENABLE		0x100054

#define QM_VFT_CFG_DATA_L		0x100064
#define QM_VFT_CFG_DATA_H		0x100068
#define QM_SQC_VFT_BUF_SIZE		(7ULL << 8)
#define QM_SQC_VFT_SQC_SIZE		(5ULL << 12)
#define QM_SQC_VFT_INDEX_NUMBER		(1ULL << 16)
#define QM_SQC_VFT_START_SQN_SHIFT	28
#define QM_SQC_VFT_VALID		(1ULL << 44)
#define QM_SQC_VFT_SQN_SHIFT		45
#define QM_CQC_VFT_BUF_SIZE		(7ULL << 8)
#define QM_CQC_VFT_SQC_SIZE		(5ULL << 12)
#define QM_CQC_VFT_INDEX_NUMBER		(1ULL << 16)
#define QM_CQC_VFT_VALID		(1ULL << 28)

#define QM_SQC_VFT_BASE_SHIFT_V2	28
#define QM_SQC_VFT_BASE_MASK_V2		0x3ff
#define QM_SQC_VFT_NUM_SHIFT_V2		45
#define QM_SQC_VFT_NUM_MASK_v2		0x3ff

#define QM_DFX_CNT_CLR_CE		0x100118
#define QM_IN_IDLE_ST_REG        0x1040e4

#define QM_ABNORMAL_INT_SOURCE		0x100000
#define QM_ABNORMAL_INT_MASK		0x100004
#define QM_HW_ERROR_IRQ_DISABLE		GENMASK(12, 0)
#define QM_ABNORMAL_INT_STATUS		0x100008
#define QM_ABNORMAL_INF00		0x100010
#define QM_FIFO_OVERFLOW_TYPE		0xc0
#define QM_FIFO_OVERFLOW_VF		0x3f
#define QM_ABNORMAL_INF01		0x100014
#define QM_DB_TIMEOUT_TYPE		0xc0
#define QM_DB_TIMEOUT_VF		0x3f
#define QM_RAS_CE_ENABLE		0x1000ec
#define QM_RAS_FE_ENABLE		0x1000f0
#define QM_RAS_NFE_ENABLE		0x1000f4
#define QM_RAS_CE_THRESHOLD		0x1000f8
#define QM_RAS_MSI_INT_SEL		0x1040f4
#define QM_ABNORMAL_INT_SOURCE_CLR	GENMASK(12, 0)

#define QM_CACHE_WB_START		0x204
#define QM_CACHE_WB_DONE		0x208
#define QM_V2_BASE_OFFSET		0x1000

#define QM_DB_CMD_SHIFT_V1		16
#define QM_DB_INDEX_SHIFT_V1		32
#define QM_DB_PRIORITY_SHIFT_V1		48
#define QM_DB_CMD_SHIFT_V2		12
#define QM_DB_RAND_SHIFT_V2		16
#define QM_DB_INDEX_SHIFT_V2		32
#define QM_DB_PRIORITY_SHIFT_V2		48

#define QM_EQ_EVENT_IRQ_VECTOR		0
#define QM_AEQ_EVENT_IRQ_VECTOR		1
#define QM_ABNORMAL_EVENT_IRQ_VECTOR	3

#define QM_ABNORMAL_INT_MASK_VALUE	0x1fff

#define QM_SQE_DATA_ALIGN_MASK		0x7f

#define POLL_PERIOD			10
#define POLL_TIMEOUT			1000
#define TEMPBUFFER_LEN			22

#define QM_DB_TIMEOUT_TYPE_SHIFT	6
#define QM_FIFO_OVERFLOW_TYPE_SHIFT	6

#define TASK_TIMEOUT			10000

#define WAIT_PERIOD			20
#define MAX_WAIT_COUNTS			1000

#define CURRENT_Q_MASK			0x0000ffff

#define QM_MK_CQC_DW3_V1(hop_num, pg_sz, buf_sz, cqe_sz) \
	(((hop_num) << QM_CQ_HOP_NUM_SHIFT)	| \
	((pg_sz) << QM_CQ_PAGE_SIZE_SHIFT)	| \
	((buf_sz) << QM_CQ_BUF_SIZE_SHIFT)	| \
	((cqe_sz) << QM_CQ_CQE_SIZE_SHIFT))
#define QM_MK_CQC_DW3_V2(cqe_sz) \
	((QM_Q_DEPTH - 1) | ((cqe_sz) << QM_CQ_CQE_SIZE_SHIFT))
#define QM_MK_SQC_W13(priority, orders, alg_type) \
	(((priority) << QM_SQ_PRIORITY_SHIFT)	| \
	((orders) << QM_SQ_ORDERS_SHIFT)	| \
	(((alg_type) & QM_SQ_TYPE_MASK) << QM_SQ_TYPE_SHIFT))
#define QM_MK_SQC_DW3_V1(hop_num, pg_sz, buf_sz, sqe_sz) \
	(((hop_num) << QM_SQ_HOP_NUM_SHIFT)	| \
	((pg_sz) << QM_SQ_PAGE_SIZE_SHIFT)	| \
	((buf_sz) << QM_SQ_BUF_SIZE_SHIFT)	| \
	((u32)ilog2(sqe_sz) << QM_SQ_SQE_SIZE_SHIFT))
#define QM_MK_SQC_DW3_V2(sqe_sz) \
	((QM_Q_DEPTH - 1) | ((u32)ilog2(sqe_sz) << QM_SQ_SQE_SIZE_SHIFT))

#define INIT_QC_COMMON(qc, base, pasid) do {			\
	(qc)->head = 0;						\
	(qc)->tail = 0;						\
	(qc)->base_l = cpu_to_le32(lower_32_bits(base));	\
	(qc)->base_h = cpu_to_le32(upper_32_bits(base));	\
	(qc)->dw3 = 0;						\
	(qc)->w8 = 0;						\
	(qc)->rsvd0 = 0;					\
	(qc)->pasid = cpu_to_le16(pasid);			\
	(qc)->w11 = 0;						\
	(qc)->rsvd1 = 0;					\
} while (0)

#define QMC_ALIGN(sz) ALIGN(sz, 32)

static int __hisi_qm_start(struct hisi_qm *qm);

enum vft_type {
	SQC_VFT = 0,
	CQC_VFT,
};

struct hisi_qm_hw_ops {
	int (*get_vft)(struct hisi_qm *qm, u32 *base, u32 *number);
	void (*qm_db)(struct hisi_qm *qm, u16 qn,
		      u8 cmd, u16 index, u8 priority);
	u32 (*get_irq_num)(struct hisi_qm *qm);
	int (*debug_init)(struct hisi_qm *qm);
	void (*hw_error_init)(struct hisi_qm *qm, u32 ce, u32 nfe, u32 fe,
			      u32 msi);
	void (*hw_error_uninit)(struct hisi_qm *qm);
	pci_ers_result_t (*hw_error_handle)(struct hisi_qm *qm);
};

static const char * const qm_debug_file_name[] = {
	[CURRENT_Q]    = "current_q",
	[CLEAR_ENABLE] = "clear_enable",
	[QM_STATE] = "qm_state",
};

struct hisi_qm_hw_error {
	u32 int_msk;
	const char *msg;
};

static const struct hisi_qm_hw_error qm_hw_error[] = {
	{ .int_msk = BIT(0), .msg = "qm_axi_rresp" },
	{ .int_msk = BIT(1), .msg = "qm_axi_bresp" },
	{ .int_msk = BIT(2), .msg = "qm_ecc_mbit" },
	{ .int_msk = BIT(3), .msg = "qm_ecc_1bit" },
	{ .int_msk = BIT(4), .msg = "qm_acc_get_task_timeout" },
	{ .int_msk = BIT(5), .msg = "qm_acc_do_task_timeout" },
	{ .int_msk = BIT(6), .msg = "qm_acc_wb_not_ready_timeout" },
	{ .int_msk = BIT(7), .msg = "qm_sq_cq_vf_invalid" },
	{ .int_msk = BIT(8), .msg = "qm_cq_vf_invalid" },
	{ .int_msk = BIT(9), .msg = "qm_sq_vf_invalid" },
	{ .int_msk = BIT(10), .msg = "qm_db_timeout" },
	{ .int_msk = BIT(11), .msg = "qm_of_fifo_of" },
	{ .int_msk = BIT(12), .msg = "qm_db_random_invalid" },
	{ /* sentinel */ }
};

static const char * const qm_db_timeout[] = {
	"sq", "cq", "eq", "aeq",
};

static const char * const qm_fifo_overflow[] = {
	"cq", "eq", "aeq",
};

static const char * const qm_s[] = {
	"init", "start", "close", "stop",
};

static const char * const qp_s[] = {
	"none", "init", "start", "stop", "close",
};

static bool qm_avail_state(struct hisi_qm *qm, enum qm_state new)
{
	enum qm_state curr = atomic_read(&qm->status.flags);
	bool avail = false;

	switch (curr) {
	case QM_INIT:
		if (new == QM_START || new == QM_CLOSE)
			avail = true;
		break;
	case QM_START:
		if (new == QM_STOP)
			avail = true;
		break;
	case QM_STOP:
		if (new == QM_CLOSE || new == QM_START)
			avail = true;
		break;
	default:
		break;
	}
	dev_dbg(&qm->pdev->dev, "change qm state from %s to %s\n",
		qm_s[curr], qm_s[new]);
	if (!avail)
		dev_warn(&qm->pdev->dev, "Can not change qm state from %s to %s\n",
			 qm_s[curr], qm_s[new]);
	return avail;
}

static bool qm_qp_avail_state(struct hisi_qm *qm, struct hisi_qp *qp,
			      enum qp_state new)
{
	enum qm_state qm_curr = atomic_read(&qm->status.flags);
	enum qp_state qp_curr = 0;
	bool avail = false;

	if (qp)
		qp_curr = atomic_read(&qp->qp_status.flags);

	switch (new) {
	case QP_INIT:
		if (qm_curr == QM_START || qm_curr == QM_INIT)
			avail = true;
		break;
	case QP_START:
		if ((qm_curr == QM_START && qp_curr == QP_INIT) ||
		    (qm_curr == QM_START && qp_curr == QP_STOP))
			avail = true;
		break;
	case QP_STOP:
		if ((qm_curr == QM_START && qp_curr == QP_START) ||
		    (qp_curr == QP_INIT))
			avail = true;
		break;
	case QP_CLOSE:
		if ((qm_curr == QM_START && qp_curr == QP_INIT) ||
		    (qm_curr == QM_START && qp_curr == QP_STOP) ||
		    (qm_curr == QM_STOP && qp_curr == QP_STOP)  ||
		    (qm_curr == QM_STOP && qp_curr == QP_INIT))
			avail = true;
		break;
	default:
		break;
	}

	dev_dbg(&qm->pdev->dev, "change qp state from %s to %s in QM %s\n",
		qp_s[qp_curr], qp_s[new], qm_s[qm_curr]);

	if (!avail)
		dev_warn(&qm->pdev->dev,
			 "Can not change qp state from %s to %s in QM %s\n",
			 qp_s[qp_curr], qp_s[new], qm_s[qm_curr]);
	return avail;
}

/* return 0 mailbox ready, -ETIMEDOUT hardware timeout */
static int qm_wait_mb_ready(struct hisi_qm *qm)
{
	u32 val;

	return readl_relaxed_poll_timeout(qm->io_base + QM_MB_CMD_SEND_BASE,
					  val, !((val >> QM_MB_BUSY_SHIFT) &
					  0x1), POLL_PERIOD, POLL_TIMEOUT);
}

/* 128 bit should be wrote to hardware at one time to trigger a mailbox */
static void qm_mb_write(struct hisi_qm *qm, const void *src)
{
	void __iomem *fun_base = qm->io_base + QM_MB_CMD_SEND_BASE;
	unsigned long tmp0 = 0, tmp1 = 0;

	asm volatile("ldp %0, %1, %3\n"
		     "stp %0, %1, %2\n"
		     "dsb sy\n"
		     : "=&r" (tmp0),
		       "=&r" (tmp1),
		       "+Q" (*((char __iomem *)fun_base))
		     : "Q" (*((char *)src))
		     : "memory");
}

static int qm_mb(struct hisi_qm *qm, u8 cmd, dma_addr_t dma_addr, u16 queue,
		 bool op)
{
	struct qm_mailbox mailbox;
	int ret = 0;

	dev_dbg(&qm->pdev->dev, "QM mailbox request to q%u: %u-%llx\n", queue,
		cmd, dma_addr);

	mailbox.w0 = cpu_to_le16(cmd |
		     (op ? 0x1 << QM_MB_OP_SHIFT : 0) |
		     (0x1 << QM_MB_BUSY_SHIFT));
	mailbox.queue_num = cpu_to_le16(queue);
	mailbox.base_l = cpu_to_le32(lower_32_bits(dma_addr));
	mailbox.base_h = cpu_to_le32(upper_32_bits(dma_addr));
	mailbox.rsvd = 0;

	mutex_lock(&qm->mailbox_lock);

	if (unlikely(qm_wait_mb_ready(qm))) {
		ret = -EBUSY;
		dev_err(&qm->pdev->dev, "QM mailbox is busy to start!\n");
		goto busy_unlock;
	}

	qm_mb_write(qm, &mailbox);

	if (unlikely(qm_wait_mb_ready(qm))) {
		ret = -EBUSY;
		dev_err(&qm->pdev->dev, "QM mailbox operation timeout!\n");
		goto busy_unlock;
	}

busy_unlock:
	mutex_unlock(&qm->mailbox_lock);

	return ret;
}

static void qm_db_v1(struct hisi_qm *qm, u16 qn, u8 cmd, u16 index, u8 priority)
{
	u64 doorbell;

	doorbell = qn | ((u64)cmd << QM_DB_CMD_SHIFT_V1) |
		   ((u64)index << QM_DB_INDEX_SHIFT_V1)  |
		   ((u64)priority << QM_DB_PRIORITY_SHIFT_V1);

	writeq(doorbell, qm->io_base + QM_DOORBELL_BASE_V1);
}

static void qm_db_v2(struct hisi_qm *qm, u16 qn, u8 cmd, u16 index, u8 priority)
{
	u64 doorbell;
	u64 dbase;
	u16 randata = 0;

	if (cmd == QM_DOORBELL_CMD_SQ || cmd == QM_DOORBELL_CMD_CQ)
		dbase = QM_DOORBELL_SQ_CQ_BASE_V2;
	else
		dbase = QM_DOORBELL_EQ_AEQ_BASE_V2;

	doorbell = qn | ((u64)cmd << QM_DB_CMD_SHIFT_V2) |
		   ((u64)randata << QM_DB_RAND_SHIFT_V2) |
		   ((u64)index << QM_DB_INDEX_SHIFT_V2)	 |
		   ((u64)priority << QM_DB_PRIORITY_SHIFT_V2);

	writeq(doorbell, qm->io_base + dbase);
}

static void qm_db(struct hisi_qm *qm, u16 qn, u8 cmd, u16 index, u8 priority)
{
	dev_dbg(&qm->pdev->dev, "QM doorbell request: qn=%u, cmd=%u, index=%u\n",
		qn, cmd, index);

	qm->ops->qm_db(qm, qn, cmd, index, priority);
}

/* Put qm memory into active, so that other configs become available */
static int qm_dev_mem_reset(struct hisi_qm *qm)
{
	u32 val;

	writel(0x1, qm->io_base + QM_MEM_START_INIT);
	return readl_relaxed_poll_timeout(qm->io_base + QM_MEM_INIT_DONE, val,
					  val & BIT(0), POLL_PERIOD,
					  POLL_TIMEOUT);
}

static u32 qm_get_irq_num_v1(struct hisi_qm *qm)
{
	return QM_IRQ_NUM_V1;
}

static u32 qm_get_irq_num_v2(struct hisi_qm *qm)
{
	if (qm->fun_type == QM_HW_PF)
		return QM_IRQ_NUM_PF_V2;
	else
		return QM_IRQ_NUM_VF_V2;
}

static struct hisi_qp *qm_to_hisi_qp(struct hisi_qm *qm, struct qm_eqe *eqe)
{
	return qm->qp_array[le32_to_cpu(eqe->dw0) & QM_EQE_CQN_MASK];
}

static void qm_sq_head_update(struct hisi_qp *qp)
{
	if (qp->qp_status.sq_head == QM_Q_DEPTH - 1)
		qp->qp_status.sq_head = 0;
	else
		qp->qp_status.sq_head++;
}

static void qm_cq_head_update(struct hisi_qp *qp)
{
	if (qp->qp_status.cq_head == QM_Q_DEPTH - 1) {
		qp->qp_status.cqc_phase = !qp->qp_status.cqc_phase;
		qp->qp_status.cq_head = 0;
	} else {
		qp->qp_status.cq_head++;
	}
}

static void qm_poll_qp(struct hisi_qp *qp, struct hisi_qm *qm)
{
	struct qm_cqe *cqe;

	if (qp->event_cb)
		qp->event_cb(qp);
	else {
		cqe = qp->cqe + qp->qp_status.cq_head;

		if (qp->req_cb) {
			while (QM_CQE_PHASE(cqe) == qp->qp_status.cqc_phase) {
				dma_rmb();
				qp->req_cb(qp, qp->sqe + qm->sqe_size *
					   le16_to_cpu(cqe->sq_head));
				qm_cq_head_update(qp);
				cqe = qp->cqe + qp->qp_status.cq_head;
				qm_db(qm, qp->qp_id, QM_DOORBELL_CMD_CQ,
				      qp->qp_status.cq_head, 0);
				qm_sq_head_update(qp);
				atomic_dec(&qp->qp_status.used);
			}
			/* set c_flag */
			qm_db(qm, qp->qp_id, QM_DOORBELL_CMD_CQ,
			      qp->qp_status.cq_head, 1);
		} else {
			if (QM_CQE_PHASE(cqe) == qp->qp_status.cqc_phase) {
				dma_rmb();
				complete(&qp->completion);
				qm_cq_head_update(qp);
				cqe = qp->cqe + qp->qp_status.cq_head;
				qm_db(qm, qp->qp_id, QM_DOORBELL_CMD_CQ,
				      qp->qp_status.cq_head, 0);
				/* set c_flag */
				qm_db(qm, qp->qp_id, QM_DOORBELL_CMD_CQ,
				      qp->qp_status.cq_head, 1);
				atomic_dec(&qp->qp_status.used);
			}
		}

	}
}

static void qm_work_process(struct work_struct *work)
{
	struct hisi_qm *qm = container_of(work, struct hisi_qm, work);
	struct qm_eqe *eqe = qm->eqe + qm->status.eq_head;
	struct hisi_qp *qp;
	int eqe_num = 0;

	while (QM_EQE_PHASE(eqe) == qm->status.eqc_phase) {
		eqe_num++;
		qp = qm_to_hisi_qp(qm, eqe);
		if (qp)
			qm_poll_qp(qp, qm);

		if (qm->status.eq_head == QM_EQ_DEPTH - 1) {
			qm->status.eqc_phase = !qm->status.eqc_phase;
			eqe = qm->eqe;
			qm->status.eq_head = 0;
		} else {
			eqe++;
			qm->status.eq_head++;
		}

		if (eqe_num == QM_Q_DEPTH / 2 - 1) {
			eqe_num = 0;
			qm_db(qm, 0, QM_DOORBELL_CMD_EQ, qm->status.eq_head, 0);
		}
	}

	qm_db(qm, 0, QM_DOORBELL_CMD_EQ, qm->status.eq_head, 0);
}

static irqreturn_t do_qm_irq(int irq, void *data)
{
	struct hisi_qm *qm = (struct hisi_qm *)data;

	if (qm->wq)
		queue_work(qm->wq, &qm->work);
	else
		schedule_work(&qm->work);

	return IRQ_HANDLED;
}

static irqreturn_t qm_irq(int irq, void *data)
{
	struct hisi_qm *qm = data;

	if (readl(qm->io_base + QM_VF_EQ_INT_SOURCE))
		return do_qm_irq(irq, data);

	dev_err(&qm->pdev->dev, "invalid int source\n");
	qm_db(qm, 0, QM_DOORBELL_CMD_EQ, qm->status.eq_head, 0);
	return IRQ_NONE;
}

static irqreturn_t qm_aeq_irq(int irq, void *data)
{
	struct hisi_qm *qm = data;
	struct qm_aeqe *aeqe = qm->aeqe + qm->status.aeq_head;
	u32 type;

	if (!readl(qm->io_base + QM_VF_AEQ_INT_SOURCE))
		return IRQ_NONE;

	while (QM_AEQE_PHASE(aeqe) == qm->status.aeqc_phase) {
		type = le32_to_cpu(aeqe->dw0) >> QM_AEQE_TYPE_SHIFT;
		if (type < ARRAY_SIZE(qm_fifo_overflow))
			dev_err(&qm->pdev->dev, "%s overflow\n",
				qm_fifo_overflow[type]);
		else
			dev_err(&qm->pdev->dev, "unknown error type %d\n",
				type);

		if (qm->status.aeq_head == QM_Q_DEPTH - 1) {
			qm->status.aeqc_phase = !qm->status.aeqc_phase;
			aeqe = qm->aeqe;
			qm->status.aeq_head = 0;
		} else {
			aeqe++;
			qm->status.aeq_head++;
		}

		qm_db(qm, 0, QM_DOORBELL_CMD_AEQ, qm->status.aeq_head, 0);
	}

	return IRQ_HANDLED;
}

static irqreturn_t qm_abnormal_irq(int irq, void *data)
{
	const struct hisi_qm_hw_error *err = qm_hw_error;
	struct hisi_qm *qm = data;
	struct device *dev = &qm->pdev->dev;
	u32 error_status, tmp;

	if (qm->abnormal_fix) {
		qm->abnormal_fix(qm);
		return IRQ_HANDLED;
	}

	/* read err sts */
	tmp = readl(qm->io_base + QM_ABNORMAL_INT_STATUS);
	error_status = qm->msi_mask & tmp;

	while (err->msg) {
		if (err->int_msk & error_status)
			dev_err(dev, "%s [error status=0x%x] found\n",
				 err->msg, err->int_msk);

		err++;
	}

	/* clear err sts */
	writel(error_status, qm->io_base + QM_ABNORMAL_INT_SOURCE);

	return IRQ_HANDLED;
}

static int qm_irq_register(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	int ret;

	ret = request_irq(pci_irq_vector(pdev, QM_EQ_EVENT_IRQ_VECTOR),
				   qm_irq, IRQF_SHARED,
				   qm->dev_name, qm);
	if (ret)
		return ret;

	if (qm->ver == QM_HW_V2) {
		ret = request_irq(pci_irq_vector(pdev, QM_AEQ_EVENT_IRQ_VECTOR),
				  qm_aeq_irq, IRQF_SHARED, qm->dev_name, qm);
		if (ret)
			goto err_aeq_irq;

		if (qm->fun_type == QM_HW_PF) {
			ret = request_irq(pci_irq_vector(pdev,
					  QM_ABNORMAL_EVENT_IRQ_VECTOR),
					  qm_abnormal_irq, IRQF_SHARED,
					  qm->dev_name, qm);
			if (ret)
				goto err_abonormal_irq;
		}
	}

	return 0;

err_abonormal_irq:
	free_irq(pci_irq_vector(pdev, QM_AEQ_EVENT_IRQ_VECTOR), qm);
err_aeq_irq:
	free_irq(pci_irq_vector(pdev, QM_EQ_EVENT_IRQ_VECTOR), qm);
	return ret;
}

static void qm_irq_unregister(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;

	free_irq(pci_irq_vector(pdev, QM_EQ_EVENT_IRQ_VECTOR), qm);

	if (qm->ver == QM_HW_V2) {
		free_irq(pci_irq_vector(pdev, QM_AEQ_EVENT_IRQ_VECTOR), qm);

		if (qm->fun_type == QM_HW_PF)
			free_irq(pci_irq_vector(pdev,
				 QM_ABNORMAL_EVENT_IRQ_VECTOR), qm);
	}
}

static void qm_init_qp_status(struct hisi_qp *qp)
{
	struct hisi_qp_status *qp_status = &qp->qp_status;

	qp_status->sq_tail = 0;
	qp_status->sq_head = 0;
	qp_status->cq_head = 0;
	qp_status->cqc_phase = true;
}

static void qm_vft_data_cfg(struct hisi_qm *qm, enum vft_type type, u32 base,
			    u32 number)
{
	u64 tmp = 0;

	if (number > 0) {
		switch (type) {
		case SQC_VFT:
			switch (qm->ver) {
			case QM_HW_V1:
				tmp = QM_SQC_VFT_BUF_SIZE |
				      QM_SQC_VFT_SQC_SIZE |
				      QM_SQC_VFT_INDEX_NUMBER |
				      QM_SQC_VFT_VALID |
				      (u64)base << QM_SQC_VFT_START_SQN_SHIFT;
				break;
			case QM_HW_V2:
				tmp = (u64)base << QM_SQC_VFT_START_SQN_SHIFT |
				      QM_SQC_VFT_VALID |
				      (u64)(number - 1) << QM_SQC_VFT_SQN_SHIFT;
				break;
			case QM_HW_UNKNOWN:
				break;
			}
			break;
		case CQC_VFT:
			switch (qm->ver) {
			case QM_HW_V1:
				tmp = QM_CQC_VFT_BUF_SIZE |
				      QM_CQC_VFT_SQC_SIZE |
				      QM_CQC_VFT_INDEX_NUMBER |
				      QM_CQC_VFT_VALID;
				break;
			case QM_HW_V2:
				tmp = QM_CQC_VFT_VALID;
				break;
			case QM_HW_UNKNOWN:
				break;
			}
			break;
		}
	}

	writel(lower_32_bits(tmp), qm->io_base + QM_VFT_CFG_DATA_L);
	writel(upper_32_bits(tmp), qm->io_base + QM_VFT_CFG_DATA_H);
}

static int qm_set_vft_common(struct hisi_qm *qm, enum vft_type type,
			     u32 fun_num, u32 base, u32 number)
{
	int ret;
	unsigned int val;

	ret = readl_relaxed_poll_timeout(qm->io_base + QM_VFT_CFG_RDY, val,
					 val & BIT(0), POLL_PERIOD,
					 POLL_TIMEOUT);
	if (ret)
		return ret;

	writel(0x0, qm->io_base + QM_VFT_CFG_OP_WR);
	writel(type, qm->io_base + QM_VFT_CFG_TYPE);
	writel(fun_num, qm->io_base + QM_VFT_CFG_ADDRESS);

	qm_vft_data_cfg(qm, type, base, number);

	writel(0x0, qm->io_base + QM_VFT_CFG_RDY);
	writel(0x1, qm->io_base + QM_VFT_CFG_OP_ENABLE);

	return readl_relaxed_poll_timeout(qm->io_base + QM_VFT_CFG_RDY, val,
					  val & BIT(0), POLL_PERIOD,
					  POLL_TIMEOUT);
}

/* The config should be conducted after qm_dev_mem_reset() */
static int qm_set_sqc_cqc_vft(struct hisi_qm *qm, u32 fun_num, u32 base,
			      u32 number)
{
	int ret, i;

	for (i = SQC_VFT; i <= CQC_VFT; i++) {
		ret = qm_set_vft_common(qm, i, fun_num, base, number);
		if (ret)
			return ret;
	}

	return 0;
}

static int qm_get_vft_v2(struct hisi_qm *qm, u32 *base, u32 *number)
{
	u64 sqc_vft;
	int ret;

	ret = qm_mb(qm, QM_MB_CMD_SQC_VFT_V2, 0, 0, 1);
	if (ret)
		return ret;

	sqc_vft = readl(qm->io_base + QM_MB_CMD_DATA_ADDR_L) |
		  ((u64)readl(qm->io_base + QM_MB_CMD_DATA_ADDR_H) << 32);
	*base = QM_SQC_VFT_BASE_MASK_V2 & (sqc_vft >> QM_SQC_VFT_BASE_SHIFT_V2);
	*number = (QM_SQC_VFT_NUM_MASK_v2 &
		  (sqc_vft >> QM_SQC_VFT_NUM_SHIFT_V2)) + 1;

	return 0;
}

static struct hisi_qm *file_to_qm(struct debugfs_file *file)
{
	struct qm_debug *debug = file->debug;

	return container_of(debug, struct hisi_qm, debug);
}

static u32 current_q_read(struct debugfs_file *file)
{
	struct hisi_qm *qm = file_to_qm(file);

	return (readl(qm->io_base + QM_DFX_SQE_CNT_VF_SQN) >> QM_DFX_QN_SHIFT);
}

static int current_q_write(struct debugfs_file *file, u32 val)
{
	struct hisi_qm *qm = file_to_qm(file);
	u32 tmp;

	if (val >= qm->debug.curr_qm_qp_num)
		return -EINVAL;

	tmp = val << QM_DFX_QN_SHIFT |
	      (readl(qm->io_base + QM_DFX_SQE_CNT_VF_SQN) & CURRENT_Q_MASK);
	writel(tmp, qm->io_base + QM_DFX_SQE_CNT_VF_SQN);

	tmp = val << QM_DFX_QN_SHIFT |
	      (readl(qm->io_base + QM_DFX_CQE_CNT_VF_CQN) & CURRENT_Q_MASK);
	writel(tmp, qm->io_base + QM_DFX_CQE_CNT_VF_CQN);

	return 0;
}

static u32 clear_enable_read(struct debugfs_file *file)
{
	struct hisi_qm *qm = file_to_qm(file);

	return readl(qm->io_base + QM_DFX_CNT_CLR_CE);
}

/* rd_clr_ctrl 1 enable read clear, otherwise 0 disable it */
static int clear_enable_write(struct debugfs_file *file, u32 rd_clr_ctrl)
{
	struct hisi_qm *qm = file_to_qm(file);

	if (rd_clr_ctrl > 1)
		return -EINVAL;

	writel(rd_clr_ctrl, qm->io_base + QM_DFX_CNT_CLR_CE);

	return 0;
}

static u32 qm_state_read(struct debugfs_file *file)
{
	struct hisi_qm *qm = file_to_qm(file);

	return readl(qm->io_base + QM_IN_IDLE_ST_REG);
}

static ssize_t qm_debug_read(struct file *filp, char __user *buf,
			     size_t count, loff_t *pos)
{
	struct debugfs_file *file = filp->private_data;
	enum qm_debug_file index = file->index;
	char tbuf[TEMPBUFFER_LEN];
	u32 val;
	int ret;

	mutex_lock(&file->lock);
	switch (index) {
	case CURRENT_Q:
		val = current_q_read(file);
		break;
	case CLEAR_ENABLE:
		val = clear_enable_read(file);
		break;
	case QM_STATE:
		val = qm_state_read(file);
		break;
	default:
		mutex_unlock(&file->lock);
		return -EINVAL;
	}
	mutex_unlock(&file->lock);
	ret = sprintf(tbuf, "%u\n", val);

	return simple_read_from_buffer(buf, count, pos, tbuf, ret);
}

static ssize_t qm_debug_write(struct file *filp, const char __user *buf,
			      size_t count, loff_t *pos)
{
	struct debugfs_file *file = filp->private_data;
	enum qm_debug_file index = file->index;
	unsigned long val;
	char tbuf[TEMPBUFFER_LEN];
	int len, ret;

	if (*pos != 0)
		return 0;

	if (count >= TEMPBUFFER_LEN)
		return -ENOSPC;

	len = simple_write_to_buffer(tbuf, TEMPBUFFER_LEN - 1, pos, buf, count);
	if (len < 0)
		return len;

	tbuf[len] = '\0';
	if (kstrtoul(tbuf, 0, &val))
		return -EFAULT;

	mutex_lock(&file->lock);
	switch (index) {
	case CURRENT_Q:
		ret = current_q_write(file, val);
		if (ret)
			goto err_input;
		break;
	case CLEAR_ENABLE:
		ret = clear_enable_write(file, val);
		if (ret)
			goto err_input;
		break;
	default:
		ret = -EINVAL;
		goto err_input;
	}
	mutex_unlock(&file->lock);

	return count;

err_input:
	mutex_unlock(&file->lock);
	return ret;
}

static const struct file_operations qm_debug_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = qm_debug_read,
	.write = qm_debug_write,
};

struct qm_dfx_registers {
	char  *reg_name;
	u64   reg_offset;
};

static struct qm_dfx_registers qm_dfx_regs[] = {
	/* these regs are read clear */
	{"QM_ECC_1BIT_CNT               ",  0x104000ull},
	{"QM_ECC_MBIT_CNT               ",  0x104008ull},
	{"QM_DFX_MB_CNT                 ",  0x104018ull},
	{"QM_DFX_DB_CNT                 ",  0x104028ull},
	{"QM_DFX_SQE_CNT                ",  0x104038ull},
	{"QM_DFX_CQE_CNT                ",  0x104048ull},
	{"QM_DFX_SEND_SQE_TO_ACC_CNT    ",  0x104050ull},
	{"QM_DFX_WB_SQE_FROM_ACC_CNT    ",  0x104058ull},
	{"QM_DFX_ACC_FINISH_CNT         ",  0x104060ull},
	{"QM_DFX_CQE_ERR_CNT            ",  0x1040b4ull},

	{"QM_DFX_FUNS_ACTIVE_ST         ",  0x200ull},
	{"QM_ECC_1BIT_INF               ",  0x104004ull},
	{"QM_ECC_MBIT_INF               ",  0x10400cull},
	{"QM_DFX_ACC_RDY_VLD0           ",  0x1040a0ull},
	{"QM_DFX_ACC_RDY_VLD1           ",  0x1040a4ull},
	{"QM_DFX_AXI_RDY_VLD            ",  0x1040a8ull},
	{"QM_DFX_FF_ST0                 ",  0x1040c8ull},
	{"QM_DFX_FF_ST1                 ",  0x1040ccull},
	{"QM_DFX_FF_ST2                 ",  0x1040d0ull},
	{"QM_DFX_FF_ST3                 ",  0x1040d4ull},
	{"QM_DFX_FF_ST4                 ",  0x1040d8ull},
	{"QM_DFX_FF_ST5                 ",  0x1040dcull},
	{"QM_DFX_FF_ST6                 ",  0x1040e0ull},
	{"QM_IN_IDLE_ST                 ",  0x1040e4ull},
	{ NULL, 0}
};

static struct qm_dfx_registers qm_vf_dfx_regs[] = {
	{"QM_DFX_FUNS_ACTIVE_ST         ",  0x200ull},
	{ NULL, 0}
};

static int qm_regs_show(struct seq_file *s, void *unused)
{
	struct hisi_qm *qm = s->private;
	struct qm_dfx_registers *regs;
	u32 val;

	if (qm->fun_type == QM_HW_PF)
		regs = qm_dfx_regs;
	else
		regs = qm_vf_dfx_regs;

	while (regs->reg_name) {
		val = readl(qm->io_base + regs->reg_offset);
		seq_printf(s, "%s= 0x%08x\n", regs->reg_name, val);
		regs++;
	}

	return 0;
}

static int qm_regs_open(struct inode *inode, struct file *file)
{
	return single_open(file, qm_regs_show, inode->i_private);
}

static const struct file_operations qm_regs_fops = {
	.owner = THIS_MODULE,
	.open = qm_regs_open,
	.read = seq_read,
	.release = single_release,
};

static int qm_create_debugfs_file(struct hisi_qm *qm, enum qm_debug_file index)
{
	struct dentry *qm_d = qm->debug.qm_d, *tmp;
	struct debugfs_file *file = qm->debug.files + index;

	tmp = debugfs_create_file(qm_debug_file_name[index], 0600, qm_d, file,
				  &qm_debug_fops);
	if (IS_ERR(tmp))
		return -ENOENT;

	file->index = index;
	mutex_init(&file->lock);
	file->debug = &qm->debug;

	return 0;
}

static void qm_hw_error_init_v1(struct hisi_qm *qm, u32 ce, u32 nfe, u32 fe,
				u32 msi)
{
	dev_info(&qm->pdev->dev,
		 "QM v%d does not support hw error handle\n", qm->ver);

	writel(QM_ABNORMAL_INT_MASK_VALUE, qm->io_base + QM_ABNORMAL_INT_MASK);
}

static void qm_hw_error_init_v2(struct hisi_qm *qm, u32 ce, u32 nfe, u32 fe,
				u32 msi)
{
	u32 irq_enable = ce | nfe | fe | msi;
	u32 irq_unmask = ~irq_enable;

	qm->error_mask = ce | nfe | fe;
	qm->msi_mask = msi;

	/* clear QM hw residual error source */
	writel(QM_ABNORMAL_INT_SOURCE_CLR, qm->io_base +
	       QM_ABNORMAL_INT_SOURCE);

	/* configure error type */
	writel(ce, qm->io_base + QM_RAS_CE_ENABLE);
	writel(0x1, qm->io_base + QM_RAS_CE_THRESHOLD);
	writel(nfe, qm->io_base + QM_RAS_NFE_ENABLE);
	writel(fe, qm->io_base + QM_RAS_FE_ENABLE);

	/* use RAS irq default, so only set QM_RAS_MSI_INT_SEL for MSI */
	writel(msi, qm->io_base + QM_RAS_MSI_INT_SEL);

	irq_unmask &= readl(qm->io_base + QM_ABNORMAL_INT_MASK);
	writel(irq_unmask, qm->io_base + QM_ABNORMAL_INT_MASK);
}

static void qm_hw_error_uninit_v2(struct hisi_qm *qm)
{
	writel(QM_HW_ERROR_IRQ_DISABLE, qm->io_base + QM_ABNORMAL_INT_MASK);
}

static void qm_log_hw_error(struct hisi_qm *qm, u32 error_status)
{
	const struct hisi_qm_hw_error *err;
	struct device *dev = &qm->pdev->dev;
	u32 reg_val, type, vf_num;
	int i;

	for (i = 0; i < ARRAY_SIZE(qm_hw_error); i++) {
		err = &qm_hw_error[i];
		if (!(err->int_msk & error_status))
			continue;

		dev_err(dev, "%s [error status=0x%x] found\n",
			 err->msg, err->int_msk);

		if (err->int_msk & QM_DB_TIMEOUT) {
			reg_val = readl(qm->io_base +
					QM_ABNORMAL_INF01);
			type = (reg_val & QM_DB_TIMEOUT_TYPE) >>
			       QM_DB_TIMEOUT_TYPE_SHIFT;
			vf_num = reg_val & QM_DB_TIMEOUT_VF;
			dev_err(dev, "qm %s doorbell timeout in function %u\n",
				 qm_db_timeout[type], vf_num);
		} else if (err->int_msk & QM_OF_FIFO_OF) {
			reg_val = readl(qm->io_base +
					QM_ABNORMAL_INF00);
			type = (reg_val & QM_FIFO_OVERFLOW_TYPE) >>
			       QM_FIFO_OVERFLOW_TYPE_SHIFT;
			vf_num = reg_val & QM_FIFO_OVERFLOW_VF;

			if (type < ARRAY_SIZE(qm_fifo_overflow))
				dev_err(dev, "qm %s fifo overflow in function %u\n",
					 qm_fifo_overflow[type],
					 vf_num);
			else
				dev_err(dev, "unknown error type\n");
		}
	}
}

static pci_ers_result_t qm_hw_error_handle_v2(struct hisi_qm *qm)
{
	u32 error_status, tmp;

	/* read err sts */
	tmp = readl(qm->io_base + QM_ABNORMAL_INT_STATUS);
	error_status = qm->error_mask & tmp;

	if (error_status) {
		qm_log_hw_error(qm, error_status);

		/* clear err sts */
		writel(error_status, qm->io_base + QM_ABNORMAL_INT_SOURCE);

		return PCI_ERS_RESULT_NEED_RESET;
	}

	return PCI_ERS_RESULT_RECOVERED;
}

static const struct hisi_qm_hw_ops qm_hw_ops_v1 = {
	.qm_db = qm_db_v1,
	.get_irq_num = qm_get_irq_num_v1,
	.hw_error_init = qm_hw_error_init_v1,
};

static const struct hisi_qm_hw_ops qm_hw_ops_v2 = {
	.get_vft = qm_get_vft_v2,
	.qm_db = qm_db_v2,
	.get_irq_num = qm_get_irq_num_v2,
	.hw_error_init = qm_hw_error_init_v2,
	.hw_error_uninit = qm_hw_error_uninit_v2,
	.hw_error_handle = qm_hw_error_handle_v2,
};

static void *qm_get_avail_sqe(struct hisi_qp *qp)
{
	struct hisi_qp_status *qp_status = &qp->qp_status;
	u16 sq_tail = qp_status->sq_tail;

	if (unlikely(atomic_read(&qp->qp_status.used) == QM_Q_DEPTH))
		return NULL;

	return qp->sqe + sq_tail * qp->qm->sqe_size;
}

static struct hisi_qp *hisi_qm_create_qp_nolock(struct hisi_qm *qm,
						u8 alg_type)
{
	struct device *dev = &qm->pdev->dev;
	struct hisi_qp *qp;
	int qp_id, ret;

	if (!qm_qp_avail_state(qm, NULL, QP_INIT))
		return ERR_PTR(-EPERM);

	qp = kzalloc(sizeof(*qp), GFP_KERNEL);
	if (!qp)
		return ERR_PTR(-ENOMEM);

	qp_id = find_first_zero_bit(qm->qp_bitmap, qm->qp_num);
	if (qp_id >= qm->qp_num) {
		dev_info_ratelimited(&qm->pdev->dev, "QM all queues are busy!\n");
		ret = -EBUSY;
		goto err_free_qp;
	}
	set_bit(qp_id, qm->qp_bitmap);
	qm->qp_array[qp_id] = qp;
	qp->qm = qm;

	/* allocate qp dma memory, uacce uses dus region for this */
	if (qm->use_dma_api) {
		qp->qdma.size = qm->sqe_size * QM_Q_DEPTH +
				sizeof(struct cqe) * QM_Q_DEPTH;
		/* one more page for device or qp statuses */
		qp->qdma.size = PAGE_ALIGN(qp->qdma.size) + PAGE_SIZE;
		qp->qdma.va = dma_alloc_coherent(dev, qp->qdma.size,
						 &qp->qdma.dma,
						 GFP_KERNEL);
		if (!qp->qdma.va) {
			ret = -ENOMEM;
			goto err_clear_bit;
		}

		dev_dbg(dev, "allocate qp dma buf(va=%pK, dma=%pad, size=%zx)\n",
			qp->qdma.va, &qp->qdma.dma, qp->qdma.size);
	}

	qp->qp_id = qp_id;
	qp->alg_type = alg_type;
	qp->c_flag = 1;
	qp->is_in_kernel = true;
	init_completion(&qp->completion);
	atomic_set(&qp->qp_status.flags, QP_INIT);

	return qp;

err_clear_bit:
	qm->qp_array[qp_id] = NULL;
	clear_bit(qp_id, qm->qp_bitmap);
err_free_qp:
	kfree(qp);
	return ERR_PTR(ret);
}

/**
 * hisi_qm_create_qp() - Create a queue pair from qm.
 * @qm: The qm we create a qp from.
 * @alg_type: Accelerator specific algorithm type in sqc.
 *
 * return created qp, -EBUSY if all qps in qm allocated, -ENOMEM if allocating
 * qp memory fails.
 */
struct hisi_qp *hisi_qm_create_qp(struct hisi_qm *qm, u8 alg_type)
{
	struct hisi_qp *qp;

	down_write(&qm->qps_lock);
	qp = hisi_qm_create_qp_nolock(qm, alg_type);
	up_write(&qm->qps_lock);

	return qp;
}
EXPORT_SYMBOL_GPL(hisi_qm_create_qp);

/**
 * hisi_qm_release_qp() - Release a qp back to its qm.
 * @qp: The qp we want to release.
 *
 * This function releases the resource of a qp.
 */
void hisi_qm_release_qp(struct hisi_qp *qp)
{
	struct hisi_qm *qm = qp->qm;
	struct qm_dma *qdma = &qp->qdma;
	struct device *dev = &qm->pdev->dev;

	down_write(&qm->qps_lock);
	if (!qm_qp_avail_state(qm, qp, QP_CLOSE)) {
		up_write(&qm->qps_lock);
		return;
	}
	if (qm->use_dma_api && qdma->va)
		dma_free_coherent(dev, qdma->size, qdma->va, qdma->dma);

	dev_dbg(dev, "release qp %d\n", qp->qp_id);
	qm->qp_array[qp->qp_id] = NULL;
	clear_bit(qp->qp_id, qm->qp_bitmap);

	kfree(qp);
	up_write(&qm->qps_lock);
}
EXPORT_SYMBOL_GPL(hisi_qm_release_qp);

static int qm_sq_ctx_cfg(struct hisi_qp *qp, int qp_id, int pasid)
{
	struct hisi_qm *qm = qp->qm;
	struct device *dev = &qm->pdev->dev;
	enum qm_hw_ver ver = qm->ver;
	struct qm_sqc *sqc;
	dma_addr_t sqc_dma;
	int ret;

	if (qm->use_dma_api) {
		sqc = kzalloc(sizeof(struct qm_sqc), GFP_KERNEL);
		if (!sqc)
			return -ENOMEM;
		sqc_dma = dma_map_single(dev, sqc, sizeof(struct qm_sqc),
					 DMA_TO_DEVICE);
		if (dma_mapping_error(dev, sqc_dma)) {
			kfree(sqc);
			return -ENOMEM;
		}
	} else {
		sqc = qm->reserve;
		sqc_dma = qm->reserve_dma;
	}

	INIT_QC_COMMON(sqc, qp->sqe_dma, pasid);
	if (ver == QM_HW_V1) {
		sqc->dw3 = cpu_to_le32(QM_MK_SQC_DW3_V1(0, 0, 0, qm->sqe_size));
		sqc->w8 = cpu_to_le16(QM_Q_DEPTH - 1);
	} else if (ver == QM_HW_V2) {
		sqc->dw3 = cpu_to_le32(QM_MK_SQC_DW3_V2(qm->sqe_size));
		sqc->w8 = 0; /* rand_qc */
	}
	sqc->cq_num = cpu_to_le16(qp_id);
	sqc->w13 = cpu_to_le16(QM_MK_SQC_W13(0, 1, qp->alg_type));

	ret = qm_mb(qm, QM_MB_CMD_SQC, sqc_dma, qp_id, 0);
	if (qm->use_dma_api) {
		dma_unmap_single(dev, sqc_dma, sizeof(struct qm_sqc),
				 DMA_TO_DEVICE);
		kfree(sqc);
	} else {
		memset(sqc, 0, sizeof(struct qm_sqc));
	}

	return ret;
}

static int qm_cq_ctx_cfg(struct hisi_qp *qp, int qp_id, int pasid)
{
	struct hisi_qm *qm = qp->qm;
	struct device *dev = &qm->pdev->dev;
	enum qm_hw_ver ver = qm->ver;
	struct qm_cqc *cqc;
	dma_addr_t cqc_dma;
	int ret;

	if (qm->use_dma_api) {
		cqc = kzalloc(sizeof(struct qm_cqc), GFP_KERNEL);
		if (!cqc)
			return -ENOMEM;

		cqc_dma = dma_map_single(dev, cqc, sizeof(struct qm_cqc),
					 DMA_TO_DEVICE);
		if (dma_mapping_error(dev, cqc_dma)) {
			kfree(cqc);
			return -ENOMEM;
		}
	} else {
		cqc = qm->reserve;
		cqc_dma = qm->reserve_dma;
	}

	INIT_QC_COMMON(cqc, qp->cqe_dma, pasid);
	if (ver == QM_HW_V1) {
		cqc->dw3 = cpu_to_le32(QM_MK_CQC_DW3_V1(0, 0, 0,
							QM_QC_CQE_SIZE));
		cqc->w8 = cpu_to_le16(QM_Q_DEPTH - 1);
	} else if (ver == QM_HW_V2) {
		cqc->dw3 = cpu_to_le32(QM_MK_CQC_DW3_V2(QM_QC_CQE_SIZE));
		cqc->w8 = 0; /* rand_qc */
	}
	cqc->dw6 = cpu_to_le32(1 << QM_CQ_PHASE_SHIFT |
			       qp->c_flag << QM_CQ_FLAG_SHIFT);

	ret = qm_mb(qm, QM_MB_CMD_CQC, cqc_dma, qp_id, 0);
	if (qm->use_dma_api) {
		dma_unmap_single(dev, cqc_dma, sizeof(struct qm_cqc),
				 DMA_TO_DEVICE);
		kfree(cqc);
	} else {
		memset(cqc, 0, sizeof(struct qm_cqc));
	}

	return ret;
}

static int qm_qp_ctx_cfg(struct hisi_qp *qp, int qp_id, int pasid)
{
	int ret;

	qm_init_qp_status(qp);

	ret = qm_sq_ctx_cfg(qp, qp_id, pasid);
	if (ret)
		return ret;

	return qm_cq_ctx_cfg(qp, qp_id, pasid);
}

static int hisi_qm_start_qp_nolock(struct hisi_qp *qp, unsigned long arg)
{
	struct hisi_qm *qm = qp->qm;
	struct device *dev = &qm->pdev->dev;
	enum qm_hw_ver ver = qm->ver;
	int qp_id = qp->qp_id;
	int pasid = arg;
	size_t off = 0;
	int ret;

	if (!qm_qp_avail_state(qm, qp, QP_START))
		return -EPERM;

#define QP_INIT_BUF(qp, type, size) do { \
	(qp)->type = ((qp)->qdma.va + (off)); \
	(qp)->type##_dma = (qp)->qdma.dma + (off); \
	off += (size); \
} while (0)

	if (!qp->qdma.dma) {
		dev_err(dev, "cannot get qm dma buffer\n");
		return -EINVAL;
	}

	/* sq need 128 bytes alignment */
	if (qp->qdma.dma & QM_SQE_DATA_ALIGN_MASK) {
		dev_err(dev, "qm sq is not aligned to 128 byte\n");
		return -EINVAL;
	}

	QP_INIT_BUF(qp, sqe, qm->sqe_size * QM_Q_DEPTH);
	QP_INIT_BUF(qp, cqe, sizeof(struct cqe) * QM_Q_DEPTH);

	dev_dbg(dev, "init qp buffer(v%d):\n"
		     " sqe	(%pK, %lx)\n"
		     " cqe	(%pK, %lx)\n",
		     ver,
		     qp->sqe, (unsigned long)qp->sqe_dma,
		     qp->cqe, (unsigned long)qp->cqe_dma);

	ret = qm_qp_ctx_cfg(qp, qp_id, pasid);
	if (ret)
		return ret;
	atomic_set(&qp->qp_status.flags, QP_START);
	dev_dbg(dev, "queue %d started\n", qp_id);

	return qp_id;
}

/**
 * hisi_qm_start_qp() - Start a qp into running.
 * @qp: The qp we want to start to run.
 * @arg: Accelerator specific argument.
 *
 * After this function, qp can receive request from user. Return qp_id if
 * successful, Return -EBUSY if failed.
 */
int hisi_qm_start_qp(struct hisi_qp *qp, unsigned long arg)
{
	struct hisi_qm *qm = qp->qm;
	int ret;

	down_write(&qm->qps_lock);
	ret = hisi_qm_start_qp_nolock(qp, arg);
	up_write(&qm->qps_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_start_qp);

static int hisi_qm_stop_qp_nolock(struct hisi_qp *qp)
{
	struct device *dev = &qp->qm->pdev->dev;
	int i = 0;

	/* it is stopped */
	if (atomic_read(&qp->qp_status.flags) == QP_STOP)
		return 0;
	if (!qm_qp_avail_state(qp->qm, qp, QP_STOP))
		return -EPERM;

	atomic_set(&qp->qp_status.flags, QP_STOP);

	while (atomic_read(&qp->qp_status.used)) {
		i++;
		msleep(WAIT_PERIOD);
		if (i == MAX_WAIT_COUNTS) {
			dev_err(dev, "Cannot drain out data for stopping, system may hang up!!!\n");
			break;
		}
	}

	dev_dbg(dev, "stop queue %u!", qp->qp_id);

	return 0;
}

/**
 * hisi_qm_stop_qp() - Stop a qp in qm.
 * @qp: The qp we want to stop.
 *
 * This function is reverse of hisi_qm_start_qp. Return 0 if successful.
 */
int hisi_qm_stop_qp(struct hisi_qp *qp)
{
	int ret;

	down_write(&qp->qm->qps_lock);
	ret = hisi_qm_stop_qp_nolock(qp);
	up_write(&qp->qm->qps_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_stop_qp);

/**
 * hisi_qp_send() - Queue up a task in the hardware queue.
 * @qp: The qp in which to put the message.
 * @msg: The message.
 *
 * This function will return -EBUSY if qp is currently full, and -EAGAIN
 * if qp related qm is resetting.
 *
 * Note: This function may run with qm_irq_thread and ACC reset at same time.
 *       It has no race with qm_irq_thread. However, during hisi_qp_send, ACC
 *       reset may happen, we have no lock here considering performance. This
 *       causes current qm_db sending fail or can not receive sended sqe. QM
 *       sync/async receive function should handle the error sqe. ACC reset
 *       done function should clear used sqe to 0.
 */
int hisi_qp_send(struct hisi_qp *qp, const void *msg)
{
	struct hisi_qp_status *qp_status = &qp->qp_status;
	u16 sq_tail = qp_status->sq_tail;
	u16 sq_tail_next = (sq_tail + 1) % QM_Q_DEPTH;
	void *sqe = qm_get_avail_sqe(qp);

	if (unlikely(atomic_read(&qp->qp_status.flags) == QP_STOP ||
		     atomic_read(&qp->qm->status.flags) == QM_STOP)) {
		dev_info(&qp->qm->pdev->dev, "QM resetting...\n");
		return -EAGAIN;
	}

	if (!sqe)
		return -EBUSY;

	memcpy(sqe, msg, qp->qm->sqe_size);

	qm_db(qp->qm, qp->qp_id, QM_DOORBELL_CMD_SQ, sq_tail_next, 0);
	atomic_inc(&qp->qp_status.used);
	qp_status->sq_tail = sq_tail_next;

	return 0;
}
EXPORT_SYMBOL_GPL(hisi_qp_send);

/**
 * hisi_qp_wait() - Wait a task in qp to finish.
 * @qp: The qp which will wait.
 *
 * This function will block and wait task finish in qp, or return -ETIME for
 * timeout.
 *
 * This function should be called after hisi_qp_send.
 */
int hisi_qp_wait(struct hisi_qp *qp)
{
	if (wait_for_completion_timeout(&qp->completion,
					msecs_to_jiffies(TASK_TIMEOUT)) == 0) {
		atomic_dec(&qp->qp_status.used);
		dev_err(&qp->qm->pdev->dev, "QM task timeout\n");
		return -ETIME;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(hisi_qp_wait);

static void hisi_qm_cache_wb(struct hisi_qm *qm)
{
	unsigned int val;

	if (qm->ver == QM_HW_V2) {
		writel(0x1, qm->io_base + QM_CACHE_WB_START);
		if (readl_relaxed_poll_timeout(qm->io_base + QM_CACHE_WB_DONE,
					       val, val & BIT(0), POLL_PERIOD,
					       POLL_TIMEOUT))
			dev_err(&qm->pdev->dev,
				"QM writeback sqc cache fail!\n");
	}
}

int hisi_qm_get_free_qp_num(struct hisi_qm *qm)
{
	int i, ret;

	down_read(&qm->qps_lock);
	for (i = 0, ret = 0; i < qm->qp_num; i++)
		if (!qm->qp_array[i])
			ret++;
	up_read(&qm->qps_lock);

	if (!qm->use_dma_api)
		ret = (ret == qm->qp_num) ? 1 : 0;

	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_get_free_qp_num);

#ifdef CONFIG_CRYPTO_QM_UACCE
static void qm_qp_event_notifier(struct hisi_qp *qp)
{
	uacce_wake_up(qp->uacce_q);
}

static int hisi_qm_get_available_instances(struct uacce *uacce)
{
	return hisi_qm_get_free_qp_num(uacce->priv);
}

static void hisi_qm_set_hw_reset(struct hisi_qm *qm)
{
	struct hisi_qp *qp;
	u32 *addr;
	int i;

	for (i = 0; i < qm->qp_num; i++) {
		qp = qm->qp_array[i];
		if (qp) {
			/* Use last 32 bits of DUS to save reset status. */
			addr = (u32 *)(qp->qdma.va + qp->qdma.size) - 1;
			*addr = 1;

			/* make sure setup is completed */
			mb();
		}
	}
}

static int hisi_qm_uacce_get_queue(struct uacce *uacce, unsigned long arg,
				   struct uacce_queue **q)
{
	struct hisi_qm *qm = uacce->priv;
	struct hisi_qp *qp;
	struct uacce_queue *wd_q;
	u8 alg_type = 0;

	down_write(&qm->qps_lock);
	qp = hisi_qm_create_qp_nolock(qm, alg_type);
	if (IS_ERR(qp)) {
		up_write(&qm->qps_lock);
		return PTR_ERR(qp);
	}

	wd_q = kzalloc(sizeof(struct uacce_queue), GFP_KERNEL);
	if (!wd_q) {
		up_write(&qm->qps_lock);
		hisi_qm_release_qp(qp);
		return -ENOMEM;
	}

	wd_q->priv = qp;
	wd_q->uacce = uacce;
	*q = wd_q;
	qp->uacce_q = wd_q;
	qp->event_cb = qm_qp_event_notifier;
	qp->pasid = arg;
	qp->is_in_kernel = false;
	init_waitqueue_head(&wd_q->wait);

	up_write(&qm->qps_lock);
	return 0;
}

static void hisi_qm_uacce_put_queue(struct uacce_queue *q)
{
	struct hisi_qp *qp = q->priv;

	/* need to stop hardware, but can not support in v1 */
	hisi_qm_release_qp(qp);
}

/* map sq/cq/doorbell to user space */
static int hisi_qm_uacce_mmap(struct uacce_queue *q,
			      struct vm_area_struct *vma,
			      struct uacce_qfile_region *qfr)
{
	struct hisi_qp *qp = (struct hisi_qp *)q->priv;
	struct hisi_qm *qm = qp->qm;
	size_t sz = vma->vm_end - vma->vm_start;
	struct pci_dev *pdev = qm->pdev;
	struct device *dev = &pdev->dev;
	unsigned long vm_pgoff;
	int ret;

	switch (qfr->type) {
	case UACCE_QFRT_MMIO:
		if (qm->ver == QM_HW_V2) {
			if (WARN_ON(sz > PAGE_SIZE * (QM_DOORBELL_PAGE_NR +
				QM_V2_DOORBELL_OFFSET / PAGE_SIZE)))
				return -EINVAL;
		} else {
			if (WARN_ON(sz > PAGE_SIZE * QM_DOORBELL_PAGE_NR))
				return -EINVAL;
		}

		vma->vm_flags |= VM_IO;

		/*
		 * Warning: This is not safe as multiple processes use the same
		 * doorbell, v1/v2 hardware interface problem. It will be fixed
		 * it in next version.
		 */
		return remap_pfn_range(vma, vma->vm_start,
				       qm->phys_base >> PAGE_SHIFT,
				       sz, pgprot_noncached(vma->vm_page_prot));
	case UACCE_QFRT_DUS:
		if (qm->use_dma_api) {
			if (sz != qp->qdma.size) {
				dev_err(dev, "wrong queue size %ld vs %ld\n",
					 sz, qp->qdma.size);
				return -EINVAL;
			}

			/* dma_mmap_coherent() requires vm_pgoff as 0
			 * restore vm_pfoff to initial value for mmap()
			 */
			vm_pgoff = vma->vm_pgoff;
			vma->vm_pgoff = 0;
			ret = dma_mmap_coherent(dev, vma, qp->qdma.va,
						qp->qdma.dma, sz);
			vma->vm_pgoff = vm_pgoff;
			return ret;
		}
		return -EINVAL;

	default:
		return -EINVAL;
	}
}

static int hisi_qm_uacce_start_queue(struct uacce_queue *q)
{
	int ret;
	struct hisi_qm *qm = q->uacce->priv;
	struct hisi_qp *qp = q->priv;

	dev_dbg(&q->uacce->dev, "uacce queue start\n");

	/* without SVA, iommu api should be called after user mmap dko */
	if (!qm->use_dma_api) {
		qm->qdma.dma = q->qfrs[UACCE_QFRT_DKO]->iova;
		qm->qdma.va = q->qfrs[UACCE_QFRT_DKO]->kaddr;
		qm->qdma.size = q->qfrs[UACCE_QFRT_DKO]->nr_pages >> PAGE_SHIFT;
		dev_dbg(&q->uacce->dev,
			"use dko space: va=%pK, dma=%lx, size=%llx\n",
			qm->qdma.va, (unsigned long)qm->qdma.dma,
			qm->size);
		ret = __hisi_qm_start(qm);
		if (ret)
			return ret;

		qp->qdma.dma = q->qfrs[UACCE_QFRT_DUS]->iova;
		qp->qdma.va = q->qfrs[UACCE_QFRT_DUS]->kaddr;
		qp->qdma.size = q->qfrs[UACCE_QFRT_DUS]->nr_pages >> PAGE_SHIFT;
	}

	ret = hisi_qm_start_qp(qp, qp->pasid);
	if (ret && !qm->use_dma_api)
		hisi_qm_stop(qm, QM_NORMAL);

	return ret;
}

static void hisi_qm_uacce_stop_queue(struct uacce_queue *q)
{
	struct hisi_qm *qm = q->uacce->priv;
	struct hisi_qp *qp = q->priv;

	hisi_qm_stop_qp(qp);

	if (!qm->use_dma_api) {
		/*
		 * In uacce_mode=1, we flush qm sqc here.
		 * In uacce_fops_release, the working flow is stop_queue ->
		 * unmap memory -> put_queue. Before unmapping memory, we
		 * should flush sqc back to memory.
		 */
		hisi_qm_cache_wb(qm);
	}
}

static int qm_set_sqctype(struct uacce_queue *q, u16 type)
{
	struct hisi_qm *qm = q->uacce->priv;
	struct hisi_qp *qp = q->priv;

	down_write(&qm->qps_lock);
	qp->alg_type = type;
	up_write(&qm->qps_lock);

	return 0;
}

static long hisi_qm_uacce_ioctl(struct uacce_queue *q, unsigned int cmd,
				unsigned long arg)
{
	struct hisi_qp *qp = q->priv;
	struct hisi_qp_ctx qp_ctx;

	if (cmd == UACCE_CMD_QM_SET_QP_CTX) {
		if (copy_from_user(&qp_ctx, (void __user *)arg,
				   sizeof(struct hisi_qp_ctx)))
			return -EFAULT;

		if (qp_ctx.qc_type != 0 && qp_ctx.qc_type != 1)
			return -EINVAL;

		qm_set_sqctype(q, qp_ctx.qc_type);
		qp_ctx.id = qp->qp_id;
		qp->c_flag = 0;
		if (copy_to_user((void __user *)arg, &qp_ctx,
				 sizeof(struct hisi_qp_ctx)))
			return -EFAULT;
	} else {
		return -EINVAL;
	}

	return 0;
}

static enum uacce_dev_state hisi_qm_get_state(struct uacce *uacce)
{
	struct hisi_qm *qm = uacce->priv;
	enum qm_state curr;

	curr = atomic_read(&qm->status.flags);
	if (curr == QM_STOP)
		return UACCE_DEV_ERR;
	else
		return UACCE_DEV_NORMAL;
}

/*
 * the device is set the UACCE_DEV_SVA, but it will be cut if SVA patch is not
 * available
 */
static struct uacce_ops uacce_qm_ops = {
	.get_available_instances = hisi_qm_get_available_instances,
	.get_queue = hisi_qm_uacce_get_queue,
	.put_queue = hisi_qm_uacce_put_queue,
	.start_queue = hisi_qm_uacce_start_queue,
	.stop_queue = hisi_qm_uacce_stop_queue,
	.mmap = hisi_qm_uacce_mmap,
	.ioctl = hisi_qm_uacce_ioctl,
	.get_dev_state = hisi_qm_get_state,
};

static int qm_register_uacce(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct uacce *uacce = &qm->uacce;
	int i;

	uacce->name = dev_name(&pdev->dev);
	uacce->drv_name = pdev->driver->name;
	uacce->pdev = &pdev->dev;
	uacce->is_vf = pdev->is_virtfn;
	uacce->priv = qm;
	uacce->ops = &uacce_qm_ops;
	uacce->algs = qm->algs;

	if (uacce->is_vf) {
		struct uacce *pf_uacce;
		struct device *pf_dev = &(pci_physfn(pdev)->dev);

		/* VF uses PF's isoalte data */
		pf_uacce = dev_to_uacce(pf_dev);
		if (!pf_uacce) {
			dev_err(&pdev->dev, "fail to PF device\n");
			return -ENODEV;
		}

		uacce->isolate = &pf_uacce->isolate_data;
	} else {
		uacce->isolate = &uacce->isolate_data;
	}

	if (qm->ver == QM_HW_V1)
		uacce->api_ver = HISI_QM_API_VER_BASE;
	else
		uacce->api_ver = HISI_QM_API_VER2_BASE;

	if (qm->use_dma_api) {
		/*
		 * Noiommu, SVA, and crypto-only modes are all using dma api.
		 * So we don't use uacce to allocate memory. We allocate it
		 * by ourself with the UACCE_DEV_DRVMAP_DUS flag.
		 */
		if (qm->use_sva) {
			uacce->flags = UACCE_DEV_SVA | UACCE_DEV_DRVMAP_DUS;
		} else {

			uacce->flags = UACCE_DEV_NOIOMMU |
				       UACCE_DEV_DRVMAP_DUS;
			if (qm->ver == QM_HW_V1)
				uacce->api_ver = HISI_QM_API_VER_BASE
						 UACCE_API_VER_NOIOMMU_SUBFIX;
			else
				uacce->api_ver = HISI_QM_API_VER2_BASE
						 UACCE_API_VER_NOIOMMU_SUBFIX;
		}
	}

	for (i = 0; i < UACCE_QFRT_MAX; i++)
		uacce->qf_pg_start[i] = UACCE_QFR_NA;


	return uacce_register(uacce);
}

static int qm_unregister_uacce(struct hisi_qm *qm)
{
	int ret;

	ret = uacce_unregister(&qm->uacce);
	if (ret)
		return ret;

	memset(&qm->uacce, 0, sizeof(qm->uacce));

	return 0;
}
#endif

/**
 * hisi_qm_init() - Initialize configures about qm.
 * @qm: The qm needed init.
 *
 * This function init qm, then we can call hisi_qm_start to put qm into work.
 */
int hisi_qm_init(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct device *dev = &pdev->dev;
	unsigned int num_vec;
	int ret;

	switch (qm->ver) {
	case QM_HW_V1:
		qm->ops = &qm_hw_ops_v1;
		break;
	case QM_HW_V2:
		qm->ops = &qm_hw_ops_v2;
		break;
	default:
		return -EINVAL;
	}

#ifdef CONFIG_CRYPTO_QM_UACCE
	if (qm->use_uacce) {
		dev_info(dev, "qm register to uacce\n");
		ret = qm_register_uacce(qm);
		if (ret < 0) {
			dev_err(dev, "fail to register uacce (%d)\n", ret);
			return ret;
		}
	}
#endif

	ret = pci_enable_device_mem(pdev);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to enable device mem!\n");
		goto err_unregister_uacce;
	}

	ret = pci_request_mem_regions(pdev, qm->dev_name);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to request mem regions!\n");
		goto err_disable_pcidev;
	}

#ifdef CONFIG_CRYPTO_QM_UACCE
	qm->phys_base = pci_resource_start(pdev, PCI_BAR_2);
	qm->size = pci_resource_len(qm->pdev, PCI_BAR_2);
#endif
	qm->io_base = devm_ioremap(dev, pci_resource_start(pdev, PCI_BAR_2),
				   pci_resource_len(qm->pdev, PCI_BAR_2));
	if (!qm->io_base) {
		ret = -EIO;
		goto err_release_mem_regions;
	}

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret < 0) {
		dev_err(dev, "Failed to set 64 bit dma mask %d", ret);
		goto err_iounmap;
	}
	pci_set_master(pdev);

	num_vec = qm->ops->get_irq_num(qm);
	ret = pci_alloc_irq_vectors(pdev, num_vec, num_vec, PCI_IRQ_MSI);
	if (ret < 0) {
		dev_err(dev, "Failed to enable MSI vectors!\n");
		goto err_iounmap;
	}

	ret = qm_irq_register(qm);
	if (ret)
		goto err_free_irq_vectors;

	mutex_init(&qm->mailbox_lock);
	init_rwsem(&qm->qps_lock);
	atomic_set(&qm->status.flags, QM_INIT);
	INIT_WORK(&qm->work, qm_work_process);

	dev_dbg(dev, "init qm %s with %s\n",
		pdev->is_physfn ? "pf" : "vf",
		qm->use_dma_api ? "dma api" : "iommu api");

	return 0;

err_free_irq_vectors:
	pci_free_irq_vectors(pdev);
err_iounmap:
	devm_iounmap(dev, qm->io_base);
err_release_mem_regions:
	pci_release_mem_regions(pdev);
err_disable_pcidev:
	pci_disable_device(pdev);
err_unregister_uacce:
#ifdef CONFIG_CRYPTO_QM_UACCE
	if (qm->use_uacce)
		qm_unregister_uacce(qm);
#endif

	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_init);

/**
 * hisi_qm_uninit() - Uninitialize qm.
 * @qm: The qm needed uninit.
 *
 * This function uninits qm related device resources.
 */
void hisi_qm_uninit(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct device *dev = &pdev->dev;

	down_write(&qm->qps_lock);
	if (!qm_avail_state(qm, QM_CLOSE)) {
		up_write(&qm->qps_lock);
		return;
	}
	/* qm hardware buffer free on put_queue if no dma api */
	if (qm->use_dma_api && qm->qdma.va) {
		hisi_qm_cache_wb(qm);
		dma_free_coherent(dev, qm->qdma.size,
				  qm->qdma.va, qm->qdma.dma);
		memset(&qm->qdma, 0, sizeof(qm->qdma));
	}

	qm_irq_unregister(qm);
	pci_free_irq_vectors(pdev);
	pci_release_mem_regions(pdev);
	pci_disable_device(pdev);

#ifdef CONFIG_CRYPTO_QM_UACCE
	if (qm->use_uacce)
		uacce_unregister(&qm->uacce);
#endif
	up_write(&qm->qps_lock);
}
EXPORT_SYMBOL_GPL(hisi_qm_uninit);

/**
 * hisi_qm_frozen() - Try to froze QM to cut continuous queue request. If
 * there is user on the QM, return failure without doing anything.
 * @qm: The qm needed to be fronzen.
 *
 * This function frozes QM, then we can do SRIOV disabling.
 */
int hisi_qm_frozen(struct hisi_qm *qm)
{
	int count, i;

	down_write(&qm->qps_lock);
	for (i = 0, count = 0; i < qm->qp_num; i++)
		if (!qm->qp_array[i])
			count++;

	if (count == qm->qp_num) {
		bitmap_set(qm->qp_bitmap, 0, qm->qp_num);
	} else {
		up_write(&qm->qps_lock);
		return -EBUSY;
	}
	up_write(&qm->qps_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(hisi_qm_frozen);

/**
 * hisi_qm_get_vft() - Get vft from a qm.
 * @qm: The qm we want to get its vft.
 * @base: The base number of queue in vft.
 * @number: The number of queues in vft.
 *
 * We can allocate multiple queues to a qm by configuring virtual function
 * table. We get related configures by this function. Normally, we call this
 * function in VF driver to get the queue information.
 *
 * qm hw v1 does not support this interface.
 */
int hisi_qm_get_vft(struct hisi_qm *qm, u32 *base, u32 *number)
{
	if (!base || !number)
		return -EINVAL;

	if (!qm->ops->get_vft) {
		dev_err(&qm->pdev->dev, "Don't support vft read!\n");
		return -EINVAL;
	}

	return qm->ops->get_vft(qm, base, number);
}
EXPORT_SYMBOL_GPL(hisi_qm_get_vft);

/**
 * hisi_qm_set_vft() - Set "virtual function table" for a qm.
 * @fun_num: Number of operated function.
 * @qm: The qm in which to set vft, alway in a PF.
 * @base: The base number of queue in vft.
 * @number: The number of queues in vft.
 *
 * This function is alway called in PF driver, it is used to assign queues
 * among PF and VFs. Number is zero means invalid corresponding entry.
 *
 * Assign queues A~B to PF: hisi_qm_set_vft(qm, 0, A, B - A + 1)
 * Assign queues A~B to VF: hisi_qm_set_vft(qm, 2, A, B - A + 1)
 * (VF function number 0x2)
 */
int hisi_qm_set_vft(struct hisi_qm *qm, u32 fun_num, u32 base,
		    u32 number)
{
	u32 max_q_num = qm->ctrl_q_num;

	if (base >= max_q_num || number > max_q_num ||
	    (base + number) > max_q_num)
		return -EINVAL;

	return qm_set_sqc_cqc_vft(qm, fun_num, base, number);
}
EXPORT_SYMBOL_GPL(hisi_qm_set_vft);

static void qm_init_eq_aeq_status(struct hisi_qm *qm)
{
	struct hisi_qm_status *status = &qm->status;

	status->eq_head = 0;
	status->aeq_head = 0;
	status->eqc_phase = true;
	status->aeqc_phase = true;
}

static int qm_eq_ctx_cfg(struct hisi_qm *qm)
{
	struct device *dev = &qm->pdev->dev;
	struct qm_eqc *eqc;
	dma_addr_t eqc_dma;
	int ret;

	if (qm->use_dma_api) {
		eqc = kzalloc(sizeof(struct qm_eqc), GFP_KERNEL);
		if (!eqc)
			return -ENOMEM;
		eqc_dma = dma_map_single(dev, eqc, sizeof(struct qm_eqc),
					 DMA_TO_DEVICE);
		if (dma_mapping_error(dev, eqc_dma)) {
			kfree(eqc);
			return -ENOMEM;
		}
	} else {
		eqc = qm->reserve;
		eqc_dma = qm->reserve_dma;
	}

	eqc->base_l = cpu_to_le32(lower_32_bits(qm->eqe_dma));
	eqc->base_h = cpu_to_le32(upper_32_bits(qm->eqe_dma));
	if (qm->ver == QM_HW_V1)
		eqc->dw3 = cpu_to_le32(QM_EQE_AEQE_SIZE);
	eqc->dw6 = cpu_to_le32((QM_EQ_DEPTH - 1) | (1 << QM_EQC_PHASE_SHIFT));
	ret = qm_mb(qm, QM_MB_CMD_EQC, eqc_dma, 0, 0);
	if (qm->use_dma_api) {
		dma_unmap_single(dev, eqc_dma, sizeof(struct qm_eqc),
				 DMA_TO_DEVICE);
		kfree(eqc);
	} else
		memset(eqc, 0, sizeof(struct qm_eqc));

	return ret;
}

static int qm_aeq_ctx_cfg(struct hisi_qm *qm)
{
	struct device *dev = &qm->pdev->dev;
	struct qm_aeqc *aeqc;
	dma_addr_t aeqc_dma;
	int ret;

	if (qm->use_dma_api) {
		aeqc = kzalloc(sizeof(struct qm_aeqc), GFP_KERNEL);
		if (!aeqc)
			return -ENOMEM;
		aeqc_dma = dma_map_single(dev, aeqc, sizeof(struct qm_aeqc),
					  DMA_TO_DEVICE);
		if (dma_mapping_error(dev, aeqc_dma)) {
			kfree(aeqc);
			return -ENOMEM;
		}
	} else {
		aeqc = qm->reserve;
		aeqc_dma = qm->reserve_dma;
	}

	aeqc->base_l = cpu_to_le32(lower_32_bits(qm->aeqe_dma));
	aeqc->base_h = cpu_to_le32(upper_32_bits(qm->aeqe_dma));
	aeqc->dw6 = cpu_to_le32((QM_Q_DEPTH - 1) | (1 << QM_EQC_PHASE_SHIFT));
	ret = qm_mb(qm, QM_MB_CMD_AEQC, aeqc_dma, 0, 0);
	if (qm->use_dma_api) {
		dma_unmap_single(dev, aeqc_dma, sizeof(struct qm_aeqc),
				 DMA_TO_DEVICE);
		kfree(aeqc);
	} else
		memset(aeqc, 0, sizeof(struct qm_aeqc));

	return ret;
}

static int qm_eq_aeq_ctx_cfg(struct hisi_qm *qm)
{
	struct device *dev = &qm->pdev->dev;
	int ret;

	qm_init_eq_aeq_status(qm);

	ret = qm_eq_ctx_cfg(qm);
	if (ret) {
		dev_err(dev, "Set eqc failed!\n");
		return ret;
	}

	return qm_aeq_ctx_cfg(qm);
}

static int __hisi_qm_start(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct device *dev = &pdev->dev;
	size_t off = 0;
	int ret;
#ifdef CONFIG_CRYPTO_QM_UACCE
	size_t dko_size;
#endif

#define QM_INIT_BUF(qm, type, num) do { \
	(qm)->type = ((qm)->qdma.va + (off)); \
	(qm)->type##_dma = (qm)->qdma.dma + (off); \
	off += QMC_ALIGN(sizeof(struct qm_##type) * (num)); \
} while (0)

	/* dma must be ready before start, nomatter by init or by uacce mmap */
	WARN_ON(!qm->qdma.dma);

	if (qm->qp_num == 0)
		return -EINVAL;

	if (qm->fun_type == QM_HW_PF) {
		ret = qm_dev_mem_reset(qm);
		if (ret)
			return ret;

		ret = hisi_qm_set_vft(qm, 0, qm->qp_base, qm->qp_num);
		if (ret)
			return ret;
	}

	QM_INIT_BUF(qm, eqe, QM_EQ_DEPTH);
	QM_INIT_BUF(qm, aeqe, QM_Q_DEPTH);
	QM_INIT_BUF(qm, sqc, qm->qp_num);
	QM_INIT_BUF(qm, cqc, qm->qp_num);
	/* get reserved dma memory */
	qm->reserve = qm->qdma.va + off;
	qm->reserve_dma = qm->qdma.dma + off;
	off += PAGE_SIZE;

	dev_dbg(dev, "init qm buffer:\n"
		     " eqe	(%pK, %lx)\n"
		     " aeqe	(%pK, %lx)\n"
		     " sqc	(%pK, %lx)\n"
		     " cqc	(%pK, %lx)\n",
		     qm->eqe, (unsigned long)qm->eqe_dma,
		     qm->aeqe, (unsigned long)qm->aeqe_dma,
		     qm->sqc, (unsigned long)qm->sqc_dma,
		     qm->cqc, (unsigned long)qm->cqc_dma);

#ifdef CONFIG_CRYPTO_QM_UACCE
	/* check if the size exceed the DKO boundary */
	if (qm->use_uacce && !qm->use_dma_api) {
		WARN_ON(qm->uacce.qf_pg_start[UACCE_QFRT_DKO] == UACCE_QFR_NA);
		dko_size = qm->uacce.qf_pg_start[UACCE_QFRT_DUS] -
			   qm->uacce.qf_pg_start[UACCE_QFRT_DKO];
		dko_size <<= PAGE_SHIFT;
		dev_dbg(&qm->pdev->dev,
			"kernel-only buffer used (0x%lx/0x%lx)\n", off,
			dko_size);
		if (off > dko_size)
			return -EINVAL;
	}
#endif
	ret = qm_eq_aeq_ctx_cfg(qm);
	if (ret)
		return ret;

	ret = qm_mb(qm, QM_MB_CMD_SQC_BT, qm->sqc_dma, 0, 0);
	if (ret)
		return ret;

	ret = qm_mb(qm, QM_MB_CMD_CQC_BT, qm->cqc_dma, 0, 0);
	if (ret)
		return ret;

	writel(0x0, qm->io_base + QM_VF_EQ_INT_MASK);
	writel(0x0, qm->io_base + QM_VF_AEQ_INT_MASK);

	return 0;
}

/* restart stopped qm and qps in reset flow */
int hisi_qm_restart(struct hisi_qm *qm)
{
	struct device *dev = &qm->pdev->dev;
	struct hisi_qp *qp;
	int ret, i;

	ret = hisi_qm_start(qm);
	if (ret < 0)
		return ret;

	down_write(&qm->qps_lock);
	for (i = 0; i < qm->qp_num; i++) {
		qp = qm->qp_array[i];

		if (qp && atomic_read(&qp->qp_status.flags) == QP_STOP &&
		    qp->is_resetting && qp->is_in_kernel) {
			ret = hisi_qm_start_qp_nolock(qp, 0);
			if (ret < 0) {
				dev_err(dev, "Failed to start qp%d!\n", i);

				up_write(&qm->qps_lock);
				return ret;
			}
			qp->is_resetting = false;
		}
	}
	up_write(&qm->qps_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(hisi_qm_restart);

/**
 * hisi_qm_start() - start qm
 * @qm: The qm to be started.
 *
 * This function starts a qm, then we can allocate qp from this qm.
 */
int hisi_qm_start(struct hisi_qm *qm)
{
	struct device *dev = &qm->pdev->dev;

#ifdef CONFIG_CRYPTO_QM_UACCE
	struct uacce *uacce = &qm->uacce;
	unsigned long dus_page_nr = 0;
	unsigned long dko_page_nr = 0;
	unsigned long mmio_page_nr;
#endif
	int ret;

	down_write(&qm->qps_lock);

	if (!qm_avail_state(qm, QM_START)) {
		up_write(&qm->qps_lock);
		return -EPERM;
	}

#ifdef CONFIG_CRYPTO_QM_UACCE
	if (qm->use_uacce) {
		/* Add one more page for device or qp status */
		dus_page_nr = (PAGE_SIZE - 1 + qm->sqe_size * QM_Q_DEPTH +
			       sizeof(struct cqe) * QM_Q_DEPTH + PAGE_SIZE) >>
			       PAGE_SHIFT;
		dko_page_nr = (PAGE_SIZE - 1 +
			QMC_ALIGN(sizeof(struct qm_eqe) * QM_EQ_DEPTH) +
			QMC_ALIGN(sizeof(struct qm_aeqe) * QM_Q_DEPTH) +
			QMC_ALIGN(sizeof(struct qm_sqc) * qm->qp_num) +
			QMC_ALIGN(sizeof(struct qm_cqc) * qm->qp_num) +
			/* let's reserve one page for possible usage */
			PAGE_SIZE) >> PAGE_SHIFT;
	}
#endif

	dev_dbg(dev, "qm start with %d queue pairs\n", qm->qp_num);

	if (!qm->qp_num) {
		dev_err(dev, "qp_num should not be 0\n");
		ret = -EINVAL;
		goto err_unlock;
	}

	/* reset qfr definition */
#ifdef CONFIG_CRYPTO_QM_UACCE
	if (qm->ver == QM_HW_V2)
		mmio_page_nr = QM_DOORBELL_PAGE_NR +
				QM_V2_DOORBELL_OFFSET / PAGE_SIZE;
	else
		mmio_page_nr = QM_DOORBELL_PAGE_NR;
	if (qm->use_uacce && qm->use_dma_api) {
		uacce->qf_pg_start[UACCE_QFRT_MMIO] = 0;
		uacce->qf_pg_start[UACCE_QFRT_DKO]  = UACCE_QFR_NA;
		uacce->qf_pg_start[UACCE_QFRT_DUS]  = mmio_page_nr;
		uacce->qf_pg_start[UACCE_QFRT_SS]   = mmio_page_nr +
						      dus_page_nr;
	} else if (qm->use_uacce) {
		uacce->qf_pg_start[UACCE_QFRT_MMIO] = 0;
		uacce->qf_pg_start[UACCE_QFRT_DKO]  = mmio_page_nr;
		uacce->qf_pg_start[UACCE_QFRT_DUS]  = mmio_page_nr +
						      dko_page_nr;
		uacce->qf_pg_start[UACCE_QFRT_SS]   = mmio_page_nr +
						      dko_page_nr +
						      dus_page_nr;
	}
#endif

	if (!qm->qp_bitmap) {
		qm->qp_bitmap = devm_kcalloc(dev, BITS_TO_LONGS(qm->qp_num),
					     sizeof(long), GFP_ATOMIC);
		qm->qp_array = devm_kcalloc(dev, qm->qp_num,
					    sizeof(struct hisi_qp *),
					    GFP_ATOMIC);
		if (!qm->qp_bitmap || !qm->qp_array) {
			ret = -ENOMEM;
			goto err_unlock;
		}
	}

	if (!qm->use_dma_api) {
		/*
		 * without SVA, qm have to be started after user region is
		 * mapped
		 */
		dev_dbg(&qm->pdev->dev, "qm delay start\n");
		atomic_set(&qm->status.flags, QM_START);
		up_write(&qm->qps_lock);
		return 0;
	} else if (!qm->qdma.va) {
		qm->qdma.size = QMC_ALIGN(sizeof(struct qm_eqe) * QM_EQ_DEPTH) +
				QMC_ALIGN(sizeof(struct qm_aeqe) * QM_Q_DEPTH) +
				QMC_ALIGN(sizeof(struct qm_sqc) * qm->qp_num) +
				QMC_ALIGN(sizeof(struct qm_cqc) * qm->qp_num);
		qm->qdma.va = dma_alloc_coherent(dev, qm->qdma.size,
						 &qm->qdma.dma,
						 GFP_ATOMIC | __GFP_ZERO);
		dev_dbg(dev, "allocate qm dma buf(va=%pK, dma=%pad, size=%zx)\n",
			qm->qdma.va, &qm->qdma.dma, qm->qdma.size);
		if (!qm->qdma.va) {
			ret = -ENOMEM;
			goto err_unlock;
		}
	}

	ret = __hisi_qm_start(qm);
	if (!ret)
		atomic_set(&qm->status.flags, QM_START);

err_unlock:
	up_write(&qm->qps_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_start);

/* Stop started qps in reset flow */
static int qm_stop_started_qp(struct hisi_qm *qm)
{
	struct device *dev = &qm->pdev->dev;
	struct hisi_qp *qp;
	int i, ret;

	for (i = 0; i < qm->qp_num; i++) {
		qp = qm->qp_array[i];
		if (qp && atomic_read(&qp->qp_status.flags) == QP_START) {
			ret = hisi_qm_stop_qp_nolock(qp);
			if (ret < 0) {
				dev_err(dev, "Failed to stop qp%d!\n", i);
				return ret;
			}

			qp->is_resetting = true;
		}
	}

	return 0;
}

/**
 * hisi_qm_stop() - Stop a qm.
 * @qm: The qm which will be stopped.
 * @r: The reason to stop qm.
 *
 * This function stops qm and its qps, then qm can not accept request.
 * Related resources are not released at this state, we can use hisi_qm_start
 * to let qm start again.
 */
int hisi_qm_stop(struct hisi_qm *qm, enum qm_stop_reason r)
{
	struct device *dev = &qm->pdev->dev;
	int ret = 0;

	down_write(&qm->qps_lock);

	qm->status.stop_reason = r;

	if (!qm_avail_state(qm, QM_STOP)) {
		ret = -EPERM;
		goto err_unlock;
	}

	if (qm->status.stop_reason == QM_SOFT_RESET ||
	    qm->status.stop_reason == QM_FLR) {
		ret = qm_stop_started_qp(qm);
		if (ret < 0)
			goto err_unlock;
#ifdef CONFIG_CRYPTO_QM_UACCE
		hisi_qm_set_hw_reset(qm);
#endif
	}

	/* Mask eq and aeq irq */
	writel(0x1, qm->io_base + QM_VF_EQ_INT_MASK);
	writel(0x1, qm->io_base + QM_VF_AEQ_INT_MASK);

	if (qm->fun_type == QM_HW_PF) {
		ret = hisi_qm_set_vft(qm, 0, 0, 0);
		if (ret) {
			dev_err(dev, "Failed to set vft!\n");
			ret = -EBUSY;
			goto err_unlock;
		}
	}

	hisi_qm_clear_queues(qm);
	atomic_set(&qm->status.flags, QM_STOP);
err_unlock:
	up_write(&qm->qps_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_stop);

/**
 * hisi_qm_debug_regs_clear() - clear qm debug related registers.
 * @qm: The qm for which we want to clear.
 */
void hisi_qm_debug_regs_clear(struct hisi_qm *qm)
{
	struct qm_dfx_registers *regs;
	int i;

	/* clear current_q */
	writel(0x0, qm->io_base + QM_DFX_SQE_CNT_VF_SQN);
	writel(0x0, qm->io_base + QM_DFX_CQE_CNT_VF_CQN);

	/* clear regs, these cnt regs are read_clear */
	writel(0x1, qm->io_base + QM_DFX_CNT_CLR_CE);

	regs = qm_dfx_regs;
#define CNT_CYC_REGS_NUM		10
	for (i = 0; i < CNT_CYC_REGS_NUM; i++) {
		readl(qm->io_base + regs->reg_offset);
		regs++;
	}

	/* clear clear_enable */
	writel(0x0, qm->io_base + QM_DFX_CNT_CLR_CE);
}
EXPORT_SYMBOL_GPL(hisi_qm_debug_regs_clear);

/**
 * hisi_qm_debug_init() - Initialize qm related debugfs files.
 * @qm: The qm for which we want to add debugfs files.
 *
 * Create qm related debugfs files.
 */
int hisi_qm_debug_init(struct hisi_qm *qm)
{
	struct dentry *qm_d, *qm_regs;
	int i, ret;

	qm_d = debugfs_create_dir("qm", qm->debug.debug_root);
	if (IS_ERR(qm_d))
		return -ENOENT;
	qm->debug.qm_d = qm_d;

	/* only show this in PF */
	if (qm->fun_type == QM_HW_PF)
		for (i = CURRENT_Q; i < DEBUG_FILE_NUM; i++)
			if (qm_create_debugfs_file(qm, i)) {
				ret = -ENOENT;
				goto failed_to_create;
			}

	qm_regs = debugfs_create_file("qm_regs", 0444, qm->debug.qm_d, qm,
				      &qm_regs_fops);
	if (IS_ERR(qm_regs)) {
		ret = -ENOENT;
		goto failed_to_create;
	}

	return 0;

failed_to_create:
	debugfs_remove_recursive(qm_d);
	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_debug_init);

/**
 * hisi_qm_hw_error_init() - Configure qm hardware error report method.
 * @qm: The qm which we want to configure.
 * @ce: Correctable error configure.
 * @nfe: Non-fatal error configure.
 * @fe: Fatal error configure.
 * @msi: Error reported by message signal interrupt.
 *
 * Hardware errors of qm can be reported either by RAS interrupts which will
 * be handled by UEFI and then PCIe AER or by device MSI. User can configure
 * each error to use either of above two methods. For RAS interrupts, we can
 * configure an error as one of correctable error, non-fatal error or
 * fatal error.
 *
 * Bits indicating errors can be configured to ce, nfe, fe and msi to enable
 * related report methods. Error report will be masked if related error bit
 * does not configure.
 */
void hisi_qm_hw_error_init(struct hisi_qm *qm, u32 ce, u32 nfe, u32 fe,
			   u32 msi)
{
	if (!qm->ops->hw_error_init) {
		dev_err(&qm->pdev->dev,
			"QM version %d doesn't support hw error handling!\n",
			qm->ver);
		return;
	}

	qm->ops->hw_error_init(qm, ce, nfe, fe, msi);
}
EXPORT_SYMBOL_GPL(hisi_qm_hw_error_init);

void hisi_qm_hw_error_uninit(struct hisi_qm *qm)
{
	if (!qm->ops->hw_error_uninit) {
		dev_err(&qm->pdev->dev,
			"QM version %d doesn't support hw error handling!\n",
			qm->ver);
		return;
	}

	qm->ops->hw_error_uninit(qm);
}
EXPORT_SYMBOL_GPL(hisi_qm_hw_error_uninit);

/**
 * hisi_qm_hw_error_handle() - Handle qm non-fatal hardware errors.
 * @qm: The qm which has non-fatal hardware errors.
 *
 * Accelerators use this function to handle qm non-fatal hardware errors.
 */
pci_ers_result_t hisi_qm_hw_error_handle(struct hisi_qm *qm)
{
	if (!qm->ops->hw_error_handle) {
		dev_err(&qm->pdev->dev,
			"QM version %d doesn't support hw error report!\n",
			qm->ver);
		return PCI_ERS_RESULT_NONE;
	}

	return qm->ops->hw_error_handle(qm);
}
EXPORT_SYMBOL_GPL(hisi_qm_hw_error_handle);

/**
 * hisi_qm_clear_queues() - Clear memory of queues in a qm.
 * @qm: The qm which memory needs clear.
 *
 * This function clears all queues memory in a qm. Reset of accelerator can
 * use this to clear queues.
 */
void hisi_qm_clear_queues(struct hisi_qm *qm)
{
	struct hisi_qp *qp;
	int i;

	for (i = 0; i < qm->qp_num; i++) {
		qp = qm->qp_array[i];
		if (qp)
			/* device state use the last page */
			memset(qp->qdma.va, 0, qp->qdma.size - PAGE_SIZE);
	}

	memset(qm->qdma.va, 0, qm->qdma.size);
}
EXPORT_SYMBOL_GPL(hisi_qm_clear_queues);

/**
 * hisi_qm_get_hw_version() - Get hardware version of a qm.
 * @pdev: The device which hardware version we want to get.
 *
 * This function gets the hardware version of a qm. Return QM_HW_UNKNOWN
 * if the hardware version is not supported.
 */
enum qm_hw_ver hisi_qm_get_hw_version(struct pci_dev *pdev)
{
	switch (pdev->revision) {
	case QM_HW_V1:
	case QM_HW_V2:
		return pdev->revision;
	default:
		return QM_HW_UNKNOWN;
	}
}
EXPORT_SYMBOL_GPL(hisi_qm_get_hw_version);

int hisi_qm_get_hw_error_status(struct hisi_qm *qm)
{
	u32 err_sts;

	err_sts = readl(qm->io_base + QM_ABNORMAL_INT_STATUS) &
			QM_ECC_MBIT;
	if (err_sts)
		return err_sts;

	return 0;
}
EXPORT_SYMBOL_GPL(hisi_qm_get_hw_error_status);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zhou Wang <wangzhou1@hisilicon.com>");
MODULE_DESCRIPTION("HiSilicon Accelerator queue manager driver");
MODULE_VERSION("1.1.10");
