// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 HiSilicon Limited. */
#include <asm/page.h>
#include <linux/acpi.h>
#include <linux/aer.h>
#include <linux/bitmap.h>
#include <linux/dma-mapping.h>
#include <linux/idr.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/irqreturn.h>
#include <linux/log2.h>
#include <linux/pm_runtime.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include "../include_uapi_linux/uacce.h"
#include "../include_linux/uacce.h"

#include <linux/uaccess.h>
#include "hisi_qm.h"
#include "hisi_acc_qm.h"

/* eq/aeq irq enable */
#define QM_VF_AEQ_INT_SOURCE		0x0
#define QM_VF_AEQ_INT_MASK		0x4
#define QM_VF_EQ_INT_SOURCE		0x8
#define QM_VF_EQ_INT_MASK		0xc
#define QM_IRQ_NUM_V1			1
#define QM_IRQ_NUM_PF_V2		4
#define QM_IRQ_NUM_VF_V2		2
#define QM_IRQ_NUM_PF_V3		4
#define QM_IRQ_NUM_VF_V3		3

#define QM_EQ_EVENT_IRQ_VECTOR		0
#define QM_AEQ_EVENT_IRQ_VECTOR		1
#define QM_CMD_EVENT_IRQ_VECTOR		2
#define QM_ABNORMAL_EVENT_IRQ_VECTOR	3

/* mailbox */
#define QM_MB_PING_ALL_VFS		0xffff
#define QM_MB_CMD_DATA_SHIFT	32
#define QM_MB_CMD_DATA_MASK		GENMASK(31, 0)
#define QM_MB_STATUS_MASK		GENMASK(12, 9)
#define QM_MB_SIZE			16

/* sqc shift */
#define QM_SQ_HOP_NUM_SHIFT		0
#define QM_SQ_PAGE_SIZE_SHIFT		4
#define QM_SQ_BUF_SIZE_SHIFT		8
#define QM_SQ_SQE_SIZE_SHIFT		12
#define QM_SQ_PRIORITY_SHIFT		0
#define QM_SQ_ORDERS_SHIFT		4
#define QM_SQ_TYPE_SHIFT		8
#define QM_QC_PASID_ENABLE		0x1
#define QM_QC_PASID_ENABLE_SHIFT	7

#define QM_SQ_TYPE_MASK			GENMASK(3, 0)
#define QM_QC_TAIL_IDX_SHIFT		6

/* cqc shift */
#define QM_CQ_HOP_NUM_SHIFT		0
#define QM_CQ_PAGE_SIZE_SHIFT		4
#define QM_CQ_BUF_SIZE_SHIFT		8
#define QM_CQ_CQE_SIZE_SHIFT		12
#define QM_CQ_PHASE_SHIFT		0
#define QM_CQ_FLAG_SHIFT		1
#define QM_QC_CQE_SIZE			4

/* eqc shift */
#define QM_EQE_AEQE_SIZE		(2UL << 12)
#define QM_EQC_PHASE_SHIFT		16
#define QM_EQE_CQN_MASK			GENMASK(15, 0)
#define QM_AEQE_TYPE_SHIFT		17
#define QM_AEQE_TYPE_MASK		GENMASK(4, 0)
#define QM_AEQE_CQN_MASK		GENMASK(15, 0)
#define QM_EQE_AEQE_TYPE_SHIFT		16
#define QM_CQ_OVERFLOW			0
#define QM_EQ_OVERFLOW			1
#define QM_CQE_ERROR			2

#define QM_DOORBELL_CMD_SQ		0
#define QM_DOORBELL_CMD_CQ		1
#define QM_DOORBELL_CMD_EQ		2
#define QM_DOORBELL_CMD_AEQ		3

#define QM_DOORBELL_BASE_V1		0x340
#define QM_DB_CMD_SHIFT_V1		16
#define QM_DB_INDEX_SHIFT_V1		32
#define QM_DB_PRIORITY_SHIFT_V1		48
#define QM_QUE_ISO_CFG_V		0x0030
#define QM_PAGE_SIZE			0x0034
#define QM_QUE_ISO_EN			0x100154
#define QM_CAPBILITY			0x100158
#define QM_QP_NUM_MASK			GENMASK(10, 0)
#define QM_QP_DB_INTERVAL		0x10000

#define QM_MEM_START_MASK		BIT(0)
#define QM_MEM_START_INIT		0x100040
#define QM_MEM_INIT_DONE		0x100044
#define QM_VFT_CFG_RDY			0x10006c
#define QM_VFT_CFG_OP_WR		0x100058
#define QM_VFT_CFG_TYPE			0x10005c
#define QM_SQC_VFT			0x0
#define QM_CQC_VFT			0x1
#define QM_VFT_CFG			0x100060
#define QM_VFT_CFG_OP_ENABLE		0x100054
#define QM_PM_CTRL			0x100148
#define QM_IDLE_DISABLE			BIT(9)

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
#define QM_SQC_VFT_BASE_MASK_V2		GENMASK(15, 0)
#define QM_SQC_VFT_NUM_SHIFT_V2		45
#define QM_SQC_VFT_NUM_MASK_v2		GENMASK(9, 0)

#define QM_DFX_CNT_CLR_CE		0x100118

#define QM_ABNORMAL_INT_SOURCE		0x100000
#define QM_ABNORMAL_INT_SOURCE_CLR	GENMASK(14, 0)
#define QM_ABNORMAL_INT_MASK		0x100004
#define QM_ABNORMAL_INT_MASK_VALUE	0x7fff
#define QM_ABNORMAL_INT_STATUS		0x100008
#define QM_ABNORMAL_INT_SET		0x10000c
#define QM_ABNORMAL_INF00		0x100010
#define QM_FIFO_OVERFLOW_TYPE		0xc0
#define QM_FIFO_OVERFLOW_TYPE_SHIFT	6
#define QM_FIFO_OVERFLOW_VF		0x3f
#define QM_ABNORMAL_INF01		0x100014
#define QM_DB_TIMEOUT_TYPE		0xc0
#define QM_DB_TIMEOUT_TYPE_SHIFT	6
#define QM_DB_TIMEOUT_VF		0x3f
#define QM_RAS_CE_ENABLE		0x1000ec
#define QM_RAS_FE_ENABLE		0x1000f0
#define QM_RAS_NFE_ENABLE		0x1000f4
#define QM_RAS_CE_THRESHOLD		0x1000f8
#define QM_RAS_CE_TIMES_PER_IRQ		1
#define QM_RAS_MSI_INT_SEL		0x1040f4
#define QM_OOO_SHUTDOWN_SEL		0x1040f8

#define QM_RESET_WAIT_TIMEOUT		400
#define QM_PEH_VENDOR_ID		0x10000d8
#define ACC_VENDOR_ID_VALUE		0x5a5a
#define QM_PEH_DFX_INFO0		0x10000fc
#define QM_PEH_DFX_INFO1		0x100100
#define QM_PEH_DFX_MASK			(BIT(0) | BIT(2))
#define QM_PEH_MSI_FINISH_MASK		GENMASK(19, 16)
#define ACC_PEH_SRIOV_CTRL_VF_MSE_SHIFT 3
#define ACC_PEH_MSI_DISABLE		GENMASK(31, 0)
#define ACC_MASTER_GLOBAL_CTRL_SHUTDOWN 0x1
#define ACC_MASTER_TRANS_RETURN_RW	3
#define ACC_MASTER_TRANS_RETURN		0x300150
#define ACC_MASTER_GLOBAL_CTRL		0x300000
#define ACC_AM_CFG_PORT_WR_EN		0x30001c
#define QM_RAS_NFE_MBIT_DISABLE		~QM_ECC_MBIT
#define ACC_AM_ROB_ECC_INI_STS		0x300104
#define ACC_ROB_ECC_ERR_MULTPL		BIT(1)
#define QM_MSI_CAP_ENABLE		BIT(16)

/* interfunction communication */
#define QM_IFC_READY_STATUS		0x100128
#define QM_IFC_INT_SET_P		0x100130
#define QM_IFC_INT_CFG			0x100134
#define QM_IFC_INT_SOURCE_P		0x100138
#define QM_IFC_INT_SOURCE_V		0x0020
#define QM_IFC_INT_MASK			0x0024
#define QM_IFC_INT_STATUS		0x0028
#define QM_IFC_INT_SET_V		0x002c
#define QM_IFC_SEND_ALL_VFS		GENMASK(6, 0)
#define QM_IFC_INT_SOURCE_CLR		GENMASK(63, 0)
#define QM_IFC_INT_SOURCE_MASK		BIT(0)
#define QM_IFC_INT_DISABLE		BIT(0)
#define QM_IFC_INT_STATUS_MASK		BIT(0)
#define QM_IFC_INT_SET_MASK		BIT(0)
#define QM_WAIT_DST_ACK			1000
#define QM_MAX_PF_WAIT_COUNT		10
#define QM_MAX_VF_WAIT_COUNT		40
#define QM_VF_RESET_WAIT_US				20000
#define QM_VF_RESET_WAIT_CNT			3000
#define QM_VF_RESET_WAIT_TIMEOUT_US		\
	(QM_VF_RESET_WAIT_US * QM_VF_RESET_WAIT_CNT)

#define QM_DFX_MB_CNT_VF		0x104010
#define QM_DFX_DB_CNT_VF		0x104020
#define QM_DFX_SQE_CNT_VF_SQN		0x104030
#define QM_DFX_CQE_CNT_VF_CQN		0x104040
#define QM_IN_IDLE_ST_REG		0x1040e4
#define QM_DFX_QN_SHIFT			16
#define CURRENT_FUN_MASK		GENMASK(5, 0)
#define CURRENT_Q_MASK			GENMASK(31, 16)

#define POLL_PERIOD			10
#define QM_MB_MAX_STOP_CNT		48000
#define WAIT_MB_STOP_TIMEOUT		(POLL_TIMEOUT * QM_MB_MAX_STOP_CNT)
#define WAIT_MB_READY_TIMEOUT		(POLL_TIMEOUT * QM_MB_MAX_WAIT_CNT)
#define WAIT_PERIOD_US_MAX		200
#define WAIT_PERIOD_US_MIN		100
#define MAX_WAIT_COUNTS			10000
#define MAX_WAIT_MB_FREE		1000
#define QM_CACHE_WB_START		0x204
#define QM_CACHE_WB_DONE		0x208

#define PCI_BAR_2			2
#define PCI_BAR_4			4
#define QM_SQE_DATA_ALIGN_MASK		GENMASK(6, 0)
#define QMC_ALIGN(sz) 			ALIGN(sz, 32)

#define QM_DBG_READ_LEN		256
#define QM_DBG_WRITE_LEN		1024
#define QM_DBG_TMP_BUF_LEN		22
#define QM_PCI_COMMAND_INVALID		~0
#define TASK_TIMEOUT			10000
#define QM_RESET_STOP_TX_OFFSET		1
#define QM_RESET_STOP_RX_OFFSET		2

#define WAIT_PERIOD			20
#define REMOVE_WAIT_DELAY		10
#define QM_SQE_ADDR_MASK		GENMASK(7, 0)
#define QM_EQ_DEPTH			(1024 * 2)
#define QM_AUTOSUSPEND_DELAY		3000

#define QM_DRIVER_DOWN		0
#define QM_RST_SCHED			1
#define QM_RESETTING			2
#define QM_QOS_PARAM_NUM		2
#define QM_QOS_VAL_NUM			1
#define QM_QOS_BDF_PARAM_NUM		4
#define QM_QOS_MAX_VAL			1000
#define QM_QOS_RATE			100
#define QM_QOS_EXPAND_RATE		1000
#define QM_SHAPER_CIR_B_MASK		GENMASK(7, 0)
#define QM_SHAPER_CIR_U_MASK		GENMASK(10, 8)
#define QM_SHAPER_CIR_S_MASK		GENMASK(14, 11)
#define QM_SHAPER_FACTOR_CIR_U_SHIFT	8
#define QM_SHAPER_FACTOR_CIR_S_SHIFT	11
#define QM_SHAPER_FACTOR_CBS_B_SHIFT	15
#define QM_SHAPER_FACTOR_CBS_S_SHIFT	19
#define QM_SHAPER_CBS_B			1
#define QM_SHAPER_CBS_S			16
#define QM_SHAPER_VFT_OFFSET		6
#define WAIT_FOR_QOS_VF			100
#define QM_QOS_MIN_ERROR_RATE		5
#define QM_QOS_TYPICAL_NUM		8
#define QM_SHAPER_MIN_CBS_S		8
#define QM_QOS_TICK			0x300U
#define QM_QOS_DIVISOR_CLK		0X1F40U
#define QM_QOS_MAX_CIR_B		200
#define QM_QOS_MIN_CIR_B		100
#define QM_QOS_MAX_CIR_U		6
#define QM_QOS_MAX_CIR_S		11
#define QM_QOS_VAL_MAX_LEN		32
#define QM_DFX_BASE		0x0100000
#define QM_DFX_STATE1		0x0104000
#define QM_DFX_STATE2		0x01040C8
#define QM_DFX_COMMON		0x0000
#define QM_DFX_BASE_LEN		0x5A
#define QM_DFX_STATE1_LEN		0x2E
#define QM_DFX_STATE2_LEN		0x11
#define QM_DFX_COMMON_LEN		0xC3
#define QM_DFX_REGS_LEN		4UL

#define PAGE_SIZE_4K		0x0
#define PAGE_SIZE_16K		0x1
#define PAGE_SIZE_64K		0x2

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
	(qc)->base_l = cpu_to_le32(lower_32_bits(base));	\
	(qc)->base_h = cpu_to_le32(upper_32_bits(base));	\
	(qc)->pasid = cpu_to_le16(pasid);			\
} while (0)

enum vft_type {
	SQC_VFT = 0,
	CQC_VFT,
	SHAPER_VFT,
};

enum acc_err_result {
	ACC_ERR_NONE,
	ACC_ERR_NEED_RESET,
	ACC_ERR_RECOVERED,
};

enum qm_alg_type {
	ALG_TYPE_0,
	ALG_TYPE_1,
};

enum qm_mb_cmd {
	QM_PF_FLR_PREPARE = 0X01,
	QM_PF_SRST_PREPARE,
	QM_PF_RESET_DONE,
	QM_VF_PREPARE_DONE,
	QM_VF_PREPARE_FAIL,
	QM_VF_START_DONE,
	QM_VF_START_FAIL,
	QM_PF_SET_QOS,
	QM_VF_SET_QOS,
};

struct qm_ceq {
	__le32 rsvd0;
	__le16 cmd_id;
	__le16 rsvd1;
	__le16 sq_head;
	__le16 sq_num;
	__le16 rsvd2;
	__le16 w7;
};

struct qm_eqe {
	__le32 dw0;
};

struct qm_qeqe {
	__le32 dw0;
};

struct qm_sqc {
	__le16 head;
	__le16 tail;
	__le32 base_l;
	__le32 base_h;
	__le32 dw3;
	__le16 w8;
	__le16 rsvd0;
	__le16 pasid;
	__le16 w11;
	__le16 cq_num;
	__le16 w13;
	__le32 rsvd1;
};

struct qm_cqc {
	__le16 head;
	__le16 tail;
	__le32 base_l;
	__le32 base_h;
	__le32 dw3;
	__le16 w8;
	__le16 rsvd0;
	__le16 pasid;
	__le16 w11;
	__le16 w13;
	__le32 rsvd1;
};

struct qm_eqc {
	__le16 head;
	__le16 tail;
	__le32 base_l;
	__le32 base_h;
	__le32 dw3;
	__le32 rsvd[2];
	__le32 dw6;
};

struct qm_aeqc {
	__le16 head;
	__le16 tail;
	__le32 base_l;
	__le32 base_h;
	__le32 dw3;
	__le32 rsvd[2];
	__le32 dw6;
};

struct qm_mailbox {
	__le16 w0;
	__le16 queue_num;
	__le32 base_l;
	__le32 base_h;
	__le32 rsvd;
};

struct qm_doorbell {
	__le16 queue_num;
	__le16 cmd;
	__le16 index;
	__le16 priority;
};

struct hisi_qm_resource {
	struct hisi_qm *qm;
	int distance;
	struct list_head list;
};

struct hisi_qm_hw_ops {
	int (*get_vft)(struct hisi_qm *qm, u32 *base, u32 *number);
	void (*qm_db)(struct hisi_qm *qm, u16 qn,
		      u8 cmd, u16 index, u8 priority);
	u32 (*get_irq_num)(struct hisi_qm *qm);
	int (*debug_init)(struct hisi_qm *qm);
	void (*hw_error_init)(struct hisi_qm *qm, u32 ce, u32 nfe, u32 fe);
	void (*hw_error_uninit)(struct hisi_qm *qm);
	enum acc_err_result (*hw_error_handle)(struct hisi_qm *qm);
	int (*drain_qm)(struct hisi_qm *qm);
	int (*stop_op)(struct hisi_qm *qm);
	int (*set_msi)(struct hisi_qm *qm);
	int (*ping_all_vfs)(struct hisi_qm *qm, u64 cmd);
	int (*ping_pf)(struct hisi_qm *qm, u64 cmd);
};

struct qm_dfx_item {
	const char *namel
	u32 offset;
};

static struct qm_dfx_item qm_dfx_files[] = {
	{"err_irq", offsetof(struct qm_dfx, err_irq_cnt)},
	{"aeq_irq", offsetof(struct qm_dfx, aeq_irq_cnt)},
	{"abnormal_irq", offsetof(struct qm_dfx, abnormal_irq_cnt)},
	{"create_qp_err", offsetof(struct qm_dfx, create_qp_err_cnt)},
	{"mb_err", offsetof(struct qm_dfx, mb_err_cnt)},
};

static const char * const qm_debug_file_name[] = {
	[CURRENT_QM]    = "current_qm",
	[CURRENT_Q]    = "current_q",
	[CLEAR_ENABLE] = "clear_enable",
};

struct hisi_qm_hw_error {
	u32 int_msk;
	const char *msg;
	enum reset_level reset_level;
};

static const struct hisi_qm_hw_error qm_hw_error[] = {
	{
		.int_msk = BIT(0),
		.msg = "qm_axi_rresp",
		.reset_level = GLOBAL_RESET
	}, {
		.int_msk = BIT(1), 
		.msg = "qm_axi_bresp",
		.reset_level = GLOBAL_RESET
	}, { 
		.int_msk = BIT(2), 
		.msg = "qm_ecc_mbit",
		.reset_level = GLOBAL_RESET
	}, { 
		.int_msk = BIT(3), 
		.msg = "qm_ecc_1bit",
		.reset_level = NONE_RESET
	}, {
		.int_msk = BIT(4),
		.msg = "qm_acc_get_task_timeout",
		.reset_level = GLOBAL_RESET
	}, {
		.int_msk = BIT(5),
		.msg = "qm_acc_do_task_timeout",
		.reset_level = GLOBAL_RESET
	}, {
		.int_msk = BIT(6),
		.msg = "qm_acc_wb_not_ready_timeout",
		.reset_level = GLOBAL_RESET
	}, {
		.int_msk = BIT(7),
		.msg = "qm_sq_cq_vf_invalid",
		.reset_level = NONE_RESET
	}, {
		.int_msk = BIT(8),
		.msg = "qm_cq_vf_invalid",
		.reset_level = NONE_RESET
	}, {
		.int_msk = BIT(9),
		.msg = "qm_sq_vf_invalid",
		.reset_level = NONE_RESET
	}, {
		.int_msk = BIT(10),
		.msg = "qm_db_timeout",
		.reset_level = GLOBAL_RESET
	}, {
		.int_msk = BIT(11),
		.msg = "qm_of_fifo_of",
		.reset_level = GLOBAL_RESET
	}, {
		.int_msk = BIT(12), 
		.msg = "qm_db_random_invalid",
		.reset_level = NONE_RESET
	}, {
		.int_msk = BIT(13), 
		.msg = "qm_mailbox_timeout",
		.reset_level = GLOBAL_RESET
	}, {
		.int_msk = BIT(14), 
		.msg = "qm_flr_timeout",
		.reset_level = GLOBAL_RESET
	}, {
		/* sentinel */
	}
};

/* define the QM's dfx regs region and region length */
static struct dfx_diff_registers qm_diff_regs[] = {
	{
		.reg_offset = QM_DFX_BASE,
		.reg_len = QM_DFX_BASE_LEN,
	}, {
		.reg_offset = QM_DFX_STATE1,
		.reg_len = QM_DFX_STATE1_LEN,
	}, {
		.reg_offset = QM_DFX_STATE2,
		.reg_len = QM_DFX_STATE2_LEN,
	}, {
		.reg_offset = QM_DFX_COMMON,
		.reg_len = QM_DFX_COMMON_LEN,
	}
};

static const char * const qm_db_timeout[] = {
	"sq", "cq", "eq", "aeq",
};

static const char * const qm_fifo_overflow[] = {
	"cq", "eq", "aeq",
};

static const char * const qm_s[] = {
	"work", "stop",
};

struct qm_typical_qos_table {
	u32 start;
	u32 end;
	u32 val;
};

/* the qos step is 100 */
static struct qm_typical_qos_table shaper_cir_s[] = {
	{100, 100, 4},
	{200, 200, 3},
	{300, 500, 2},
	{600, 1000, 1},
	{1100, 100000, 0},
};

static struct qm_typical_qos_table shaper_cbs_s[] = {
	{100, 200, 9},
	{300, 500, 11},
	{600, 1000, 12},
	{1100, 10000, 16},
	{10100, 25000, 17},
	{25100, 50000, 18},
	{50100, 100000, 19}
};

static u32 qm_get_hw_error_status(struct hisi_qm *qm)
{
	return readl(qm->io_base + QM_ABNORMAL_INT_STATUS);
}

static u32 qm_get_dev_err_status(struct hisi_qm *qm)
{
	return qm->err_ini->get_dev_hw_err_status(qm);
}

/* Check if the error causes the master ooo block */
static int qm_check_dev_error(struct hisi_qm *qm)
{
	u32 val, dev_val;

	if (qm->fun_type == QM_HW_VF)
		return 0;
	
	val = qm_get_hw_error_status(qm);
	dev_val = qm_get_dev_error_status(qm);

	if (qm->ver < QM_HW_V3)
		return (val & QM_ECC_MBIT) ||
			   (dev_val & qm->err_info.ecc_2bits_mask);

	return (val & readl(qm->io_base + QM_OOO_SHUTDOWN_SEL)) ||
		   (dev_val & qm->err_info.ooo_shutdown_mask);
}

static void qm_mb_pre_init(struct qm_mailbox *mailbox, u8 cmd,
				u64 base, u16, queue, bool op)
{
	mailbox->w0 = cpu_to_le16((cmd) |
		((op) ? 0x1 << QM_MB_OP_SHIFT : 0) |
		(0x1 << QM_MB_BUSY_SHIFT));
	mailbox->queue_num = cpu_to_le16(queue);
	mailbox->base_l = cpu_to_le32(lower_32_bits(base));
	mailbox->base_h = cpu_to_le32(upper_32_bits(base));
	mailbox->rsvd = 0;
}

/* return 0 mailbox ready, -ETIMEDOUT hardware timeout */
int qm_wait_mb_ready(struct hisi_qm *qm, u32 timeout)
{
	u32 val;

	return readl_relaxed_poll_timeout(qm->io_base + QM_MB_CMD_SEND_BASE,
					  val, !((val >> QM_MB_BUSY_SHIFT) &
					  0x1), POLL_PERIOD, timeout);
}
EXPORT_SYMBOL_GPL(qm_wait_mb_ready);

/* 128 bit should be written to hardware at one time to trigger a mailbox */
static void qm_mb_write(struct hisi_qm *qm, const void *src)
{
	void __iomem *fun_base = qm->io_base + QM_MB_CMD_SEND_BASE;
	unsigned long tmp0 = 0;
	unsigned long tmp1 = 0;

	if (!IS_ENABLED(CONFIG_ARM64)) {
		memcpy_toio(fun_base, src, QM_MB_SIZE);
		wmb();
		return;
	}

	asm volatile("ldp %0, %1, %3\n"
		     "stp %0, %1, %2\n"
		     "dsb sy\n"
		     : "=&r" (tmp0),
		       "=&r" (tmp1),
		       "+Q" (*((char __iomem *)fun_base))
		     : "Q" (*((char *)src))
		     : "memory");
}

static int qm_mb_nolock(struct hisi_qm *qm, struct qm_mailbox *mailbox,
			u32 timeout, bool is_cmd)
{
	int ret = -ETIMEDOUT;
	u32 val;

	if (!is_cmd && unlikely(qm_wait_mb_ready(qm, POLL_TIMEOUT))) {
		ret = -EBUSY;
		goto mb_err_cnt_increase;
	}

	qm_mb_write(qm, mailbox);

	if (unlikely(qm_wait_mb_ready(qm, timeout))) {
		dev_err(&qm->pdev->dev, "QM mailbox operation timeout!\n");
		goto mb_err_cnt_increase;
	}

	val = readl(qm->io_base + QM_MB_CMD_SEND_BASE);
	val &= QM_MB_STATUS_MASK;
	if (val) {
		dev_err(&qm->pdev->dev, "QM mailbox operation timeout!\n");
		ret = -EIO;
		goto mb_err_cnt_increase;
	}

	return 0;

mb_err_cnt_increase:
	atomic64_inc(&qm->debug.dfx.mb_err_cnt);
	return ret;
}

int qm_mb(struct hisi_qm *qm, u8 cmd, dma_addr_t dma_addr, u16 queue,
		 bool op)
{
	struct hisi_qm *pf_qm = pci_get_drvdata(pci_physfn(qm->pdev));
	struct qm_mailbox mailbox;
	u32 timeout;
	int ret;

	dev_dbg(&qm->pdev->dev, "QM mailbox request to q%u: %u-%llx\n",
		queue, cmd, (unsigned long long)dma_addr);
	
	if (cmd == QM_MB_CMD_STOP_QP || cmd == QM_MB_CMD_FLUSH_QM)
		timeout = WAIT_MB_STOP_TIMEOUT;
	else
		timeout = WAIT_MB_READY_TIMEOUT;
	
	/* No need to judge if master OOO is blocked. */
	if (qm_check_dev_error(pf_qm)) {
		dev_err(&qm->pdev->dev, "QM mailbox operation failed since qm is stop!\n");
		return -EINVAL;
	}

	qm_mb_pre_init(&mailbox, cmd, dma_addr, queue, op);

	mutex_lock(&qm->mailbox_lock);
	ret = qm_mb_nolock(qm, &mailbox, timeout, false);
	mutex_unlock(&qm->mailbox_lock);

	if (ret == -EBUSY)
		dev_err(&qm->pdev->dev, "QM mailbox is busy to start!\n");

	return ret;
}
EXPORT_SYMBOL_GPL(qm_mb);

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
	void __iomem *io_base = qm->io_base;
	u16 randata = 0;
	u64 doorbell;

	if (cmd == QM_DOORBELL_CMD_SQ || cmd == QM_DOORBELL_CMD_CQ)
		io_base = qm->db_io_base + (u64)qn * qm->db_interval +
				QM_DOORBELL_SQ_CQ_BASE_V2;
	else
		io_base += QM_DOORBELL_EQ_AEQ_BASE_V2;

	doorbell = qn | ((u64)cmd << QM_DB_CMD_SHIFT_V2) |
		   ((u64)randata << QM_DB_RAND_SHIFT_V2) |
		   ((u64)index << QM_DB_INDEX_SHIFT_V2)	 |
		   ((u64)priority << QM_DB_PRIORITY_SHIFT_V2);

	writeq(doorbell, io_base);
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

	writel(QM_MEM_START_MASK, qm->io_base + QM_MEM_START_INIT);
	return readl_relaxed_poll_timeout(qm->io_base + QM_MEM_INIT_DONE, val,
					  val & QM_MEM_START_MASK, POLL_PERIOD,
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

	return QM_IRQ_NUM_VF_V2;
}

static u32 qm_get_irq_num_v3(struct hisi_qm *qm)
{
	if (qm->fun_type == QM_HW_PF)
		return QM_IRQ_NUM_PF_V3;

	return QM_IRQ_NUM_VF_V3;
}

static int qm_pm_get_sync(struct hisi_qm *qm)
{
	struct device *dev = &qm->pdev->dev;
	int ret;

	if (qm->fun_type == QM_HW_VF || qm->ver < QM_HW_V3)
		return 0;

	ret = pm_runtime_resume_and_get(dev);
	if (ret < 0) {
		dev_err(dev, "failed to get_sync(%d).\n", ret);
		return ret;
	}

	return 0;
}

static void qm_pm_put_sync(struct hisi_qm *qm)
{
	struct device *dev = &qm->pdev->dev;

	if (qm->fun_type == QM_HW_VF || qm->ver < QM_HW_V3)
		return;
	
	pm_runtime_mark_last_busy(dev);
	pm_runtime_put_autosuspend(dev);
}

static struct hisi_qp *qm_to_hisi_qp(struct hisi_qm *qm, struct qm_eqe *eqe)
{
	u16 cqn = le32_to_cpu(eqe->dw0) & QM_EQE_CQN_MASK;

	return &qm->qp_array[cqn];
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
	struct qm_cqe *cqe = qp->cqe + qp->qp_status.cq_head;
	struct uacce_queue *q = qp->uacce_q;
	int update = 0;

	if (unlikely(atomic_read(&qp->qp_status.flags) == QP_STOP))
		return;

	if (qp->event_cb) {
		/*
		 * If multi thread poll one queue, each thread will produce
		 * one event, so we query one cqe and break out of the loop.
		 * If only one thread poll one queue, we need query all cqe
		 * to ensure that we poll a cleaned queue next time.
		 */
		 while((le16_to_cpu(cqe->w7) & 0x1) ==
		 	qp->qp_status.cqc_phase) {
			dma_rmb();
			qm_cq_head_update(qp);
			cqe = qe->cqe + qp->qp_status.cq_head;
			updated = 1;
			if (!wq_has_single_sleeper(&q->wait))
				break;
		}

		if (updated) {
			atomic_inc(&qp->qp_status.complete_task);
			qp->event_cb(qp);
		}

		return;
	}

	if (qp->req_cb) {
		while ((le16_to_cpu(cqe->w7) & 0x1) == 
			qp->qp_status.cqc_phase) {
			dma_rmb();
			qp->req_cb(qp, qp->sqe + qm->sqe_size *
					le16_to_cpu(cqe->sq_head));
			qm_cq_head_update(qp);
			cqe = qp->cqe + qp->qp_status.cq_head;
			qm_db(qm, qp->qp_id, QM_DOORBELL_CMD_CQ,
					qp->qp_status.cq_head, 0);
			atomic_dec(&qp->qp_status.used);
		}

		/* set c_flag */
		qm_db(qm, qp->qp_id, QM_DOORBELL_CMD_CQ,
				qp->qp_status.cq_head, 1);
	}
}

static void qm_work_process(struct work_struct *work)
{
	struct hisi_qm *qm = container_of(work, struct hisi_qm, work);
	struct qm_eqe *eqe = qm->eqe + qm->status.eq_head;
	struct hisi_qp *qp;
	int eqe_num = 0;

	while (((le16_to_cpu(cqe->dw0) >> QM_EQE_AEQE_TYPE_SHIFT) & 0x1) == 
		qm->status.eqc_phase) {
		eqe_num++;
		qp = qm_to_hisi_qp(qm, eqe);
		qm_poll_qp(qp, qm);

		if (qm->status.eq_head == QM_EQ_DEPTH - 1) {
			qm->status.eqc_phase = !qm->status.eqc_phase;
			eqe = qm->eqe;
			qm->status.eq_head = 0;
		} else {
			eqe++;
			qm->status.eq_head++;
		}

		if (eqe_num == (QM_Q_DEPTH >> 1) - 1) {
			eqe_num = 0;
			qm_db(qm, 0, QM_DOORBELL_CMD_EQ, qm->status.eq_head, 0);
		}
	}

	qm_db(qm, 0, QM_DOORBELL_CMD_EQ, qm->status.eq_head, 0);
}

static irqreturn_t do_qm_irq(int irq, void *data)
{
	struct hisi_qm *qm = (struct hisi_qm *)data;

	/* the workqueue created by device driver of QM */
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

	atomic64_inc(&qm->debug.dfx.err_irq_cnt);
	dev_err(&qm->pdev->dev, "invalid int source\n");
	qm_db(qm, 0, QM_DOORBELL_CMD_EQ, qm->status.eq_head, 0);

	return IRQ_NONE;
}

static irqreturn_t qm_mb_cmd_irq(int irq, void *data)
{
	struct hisi_qm *qm = data;
	u32 val;

	val = readl(qm->io_base + QM_VF_AEQ_INT_SOURCE);
	val &= QM_IFC_INT_STATUS_MASK;
	if (!val)
		return IRQ_NONE;

	schedule_work(&qm->cmd_process);

	return IRQ_HANDLED;
}

static int qm_wait_reset_finish(struct hisi_qm *qm)
{
	int delay = 0;

	/* All reset requests need to be queued for processing */
	while (test_and_set_bit(QM_RESETTING, &qm->misc_ctl)) {
		msleep(++delay);
		if (delay > QM_RESET_WAIT_TIMEOUT)
			return -EBUSY;
	}

	return 0;
}

static int qm_reset_prepare_ready(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct hisi_qm *pf_qm = pci_get_drvdata(pci_physfn(pdev));

	/*
	 * PF and VF on host doesnot support resetting at the
	 * same time on Kunpeng 920.
	 */
	if (qm->ver < QM_HW_V3)
		return qm_wait_reset_finish(pf_qm);
	
	return qm_wait_reset_finish(qm);
}

static void qm_reset_bit_clear(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct hisi_qm *pf_qm = pci_get_drvdata(pci_physfn(pdev));

	if (qm->ver < QM_HW_V3)
		clear_bit(QM_RESETTING, &pf_qm->misc_ctl);

	clear_bit(QM_RESETTING, &qm->misc_ctl);
}

static void qm_set_qp_disable(struct hisi_qp *qp, int offset)
{
	u32 *addr;

	if (qp->is_in_kernel)
		return;

	addr = (u32 *)(qp->qdma.va + qp->qdma.size) - offset;
	*addr = 1;

	/* make sure setup is completed */
	rmb();
}

static void qm_disable_qp(struct hisi_qm *qm, u32 qp_id)
{
	struct hisi_qp *qp = & qm->qp_array[qp_id];

	qm_set_qp_disable(qp, QM_RESET_STOP_TX_OFFSET);
	hisi_qm_stop_qp(qp);
	qm_set_qp_disable(qp, QM_RESET_STOP_RX_OFFSET);
}

static void qm_reset_function(struct hisi_qm *qm)
{
	struct hisi_qm *pf_qm = pci_get_drvdata(pci_physfn(pdev));
	struct device *dev = &qm->pdev->dev;
	int ret;

	if (qm_check_dev_error(pf_qm))
		return;

	ret = qm_reset_prepare_ready(qm);
	if (ret) {
		dev_err(dev, "reset function not ready\n");
		return;
	}

	ret = hisi_qm_stop_qp(qm, QM_DOWN);
	if (ret) {
		dev_err(dev, "failed to stop qm when reset function!\n");
		goto clear_bit;
	}

	ret = hisi_qm_start(qm);
	if (ret)
		dev_err(dev, "failed to start qm when reset function!\n");

clear_bit:
	qm_reset_bit_clear(qm);
}

static irqreturn_t qm_aeq_thread(int irq, void *data)
{
	struct hisi_qm *qm = data;
	struct qm_aeqe * aeqe = qm->aeqe + qm->status.aeqe_head;
	struct device *dev = &qm->pdev->dev;
	u32 type, qp_id;

	whiler (((le32_to_cpu(aeqe->dw0) >> QM_EQE_AEQE_TYPE_SHIFT) & 0x1) ==
		qm->status.aeqc_phase) {
		type = (le32_to_cpu(aeqe->dw0) >> QM_AEQE_TYPE_SHIFT) &
			QM_AEQE_TYPE_MASK;
		qp_id = le32_to_cpu(aeqe->dw0) & QM_AEQE_CQN_MASK;

		switch (type) {
		case QM_EQ_OVERFLOW:
			dev_err(dev, "eq overflowm, reset function!\n");
			qm_reset_function(qm);
			return IRQ_HANDLED;
		case QM_CQ_OVERFLOW:
			dev_err(dev, "cq overflowm, stop op(%u)!\n", qp_id);
			fallthrough;
		case QM_CQE_ERROR:
			qm_disable_qp(qm, qp_id);
			break;
		default:
			dev_err(dev, "unknown error type %u\n", type);
			break;
		}

		if (qm->status.aeq_head == QM_Q_DEPTH - 1) {
			qm->status.aeqc_phase = !qm->status.aeqc_phase;
			aeqe = qm->aeqe;
			qm->status.aeq_head = 0;
		} else {
			aeqe++;
			qm->status.aeq_head++;
		}
	}

	qm_db(qm, 0, QM_DOORBELL_CMD_AEQ, qm->status.aeq_head, 0);

	return IRQ_HANDLED;
}

static irqreturn_t qm_aeq_irq(int irq, void *date)
{
	struct hisi_qm *qm = data;

	atomic64_inc(&qm->debug.dfx.aeq_irq_cnt);
	if (!readl(qm->io_base + QM_VF_AEQ_INT_SOURCE))
		return IRQ_NONE;
	
	return IRQ_WAKE_THREAD;
}

static void qm_irq_unregister(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;

	free_irq(pci_irq_vector(pdev, QM_EQ_EVENT_IRQ_VECTOR), qm);

	if (qm->ver == QM_HW_V1) {
		free_irq(pci_irq_vector(pdev, QM_AEQ_EVENT_IRQ_VECTOR), qm);

		if (qm->fun_type == QM_HW_PF)
			free_irq(pci_irq_vector(pdev,
				 QM_ABNORMAL_EVENT_IRQ_VECTOR), qm);
	}

	if (qm->ver > QM_HW_V2)
		free_irq(pci_irq_vector(pdev, QM_CMD_EVENT_IRQ_VECTOR), qm);
}

static void qm_init_qp_status(struct hisi_qp *qp)
{
	struct hisi_qp_status *qp_status = &qp->qp_status;

	qp_status->sq_tail = 0;
	qp_status->cq_head = 0;
	qp_status->cqc_phase = true;
	atomic_set(&qp_status->used, 0);
	atomic_set(&qp_status->send_ref, 0);
	atomic_set(&qp_status->complete_task, 0);
}

static void qm_init_prefetch(struct hisi_qm *qm)
{
	struct device *dev = &qm->pdev->dev;
	u32 page_type = PAGE_SIZE_4k;

	if (qm->ver < QM_HW_V3)
		return;
	
	switch (PAGE_SIZE) {
	case SZ_4K:
		page_type = PAGE_SIZE_4K;
		break;
	case SZ_16K:
		page_type = PAGE_SIZE_16K;
		break;
	case SZ_64K:
		page_type = PAGE_SIZE_64K;
		break;
	default:
		dev_err(dev, "system page size is not support: %lu, default set to 4KB",
			PAGE_SIZE);
	}

	writel(page_type, qm->io_base + QM_PAGE_SIZE);
}

/*
 * acc_sahper_para_calc() Get the IR value by the qos formula, the returm value
 * is the expected qos calculated.
 * the formula:
 * IR = X Mbps if ir = 1 means IR = 100 Mbps, if ir = 10000 means = 10Gbps
 *
 *		IR_b * (2 ^ IR_u) * 8000
 * IR(Mbps) = 
 *			Tick * (2 ^ IR_s)
 */
static u32 acc_shaper_para_calc(u64 cir_b, u64 cir_u, u64 cir_s)
{
	return ((cir_b * QM_QOS_DIVISOR_CLK) * (1 << cir_u)) /
					(QM_QOS_TICK * (1 << cir_s));
}

static u32 acc_shaper_calc_cbs_s(u32 ir)
{
	int table_size = ARRAY_SIZE(shaper_cbs_s);
	int i;

	for (i = 0; i < table_size; i++) {
		if (ir >= shaper_cbs_s[i].start && ir <= shaper_cbs_s[i].end)
			return shaper_cbs_s[i].val;
	}

	return QM_SHAPER_MIN_CBS_S;
}

static u32 acc_shaper_calc_cir_s(u32 ir)
{
	int table_size = ARRAY_SIZE(shaper_cir_s);
	int i;

	for (i = 0; i < table_size; i++) {
		if (ir >= shaper_cir_s[i].start && ir <= shaper_cir_s[i].end)
			return shaper_cir_s[i].val;
	}

	return 0;
}

static int qm_get_shaper_para(u32 ir, struct qm_shaper_factor *factor)
{
	u32 cir_b, cir_u, cir_s, ir_calc;
	u32 error_rate;

	factor->cbs_s = acc_shaper_calc_cbs_s(ir);
	cir_s = acc_shaper_calc_cir_s(ir);

	for (cir_b = QM_QOS_MIN_CIR_B; cir_b <= QM_QOS_MAX_CIR_B; cir_b++) {
		for (cir_u = 0; cir_u <= QM_QOS_MAX_CIR_U; cir_u++) {
			ir_calc = acc_shaper_para_calc(cir_b, cir_u, cir_s);

			error_rate = QM_QOS_EXPAND_RATE * (u32)abs(ir_calc - ir) / ir;
			if (error_rate <= QM_QOS_MIN_ERROR_RATE) {
				facor->cir_b = cir_b;
				facor->cir_u = cir_u;
				facor->cir_s = cir_s;
				return 0;
			}
		}
	}

	return -EINVAL;
}

static void qm_vft_data_cfg(struct hisi_qm *qm, enum vft_type type, u32 base,
			    u32 number, struct qm_shaper_factor *factor)
{
	u64 tmp = 0;

	if (number > 0) {
		switch (type) {
		case SQC_VFT:
			if (qm->ver == QM_HW_V1) {
				tmp = QM_SQC_VFT_BUF_SIZE 	|
				      QM_SQC_VFT_SQC_SIZE 	|
				      QM_SQC_VFT_INDEX_NUMBER 	|
				      QM_SQC_VFT_VALID 	|
				      (u64)base << QM_SQC_VFT_START_SQN_SHIFT;
			} else {
				tmp = (u64)base << QM_SQC_VFT_START_SQN_SHIFT |
				      QM_SQC_VFT_VALID |
				      (u64)(number - 1) << QM_SQC_VFT_SQN_SHIFT;
			}
			break;
		case CQC_VFT:
			if (qm->ver == QM_HW_V1) {
				tmp = QM_CQC_VFT_BUF_SIZE 	|
				      QM_CQC_VFT_SQC_SIZE 	|
				      QM_CQC_VFT_INDEX_NUMBER 	|
				      QM_CQC_VFT_VALID;
			} else {
				tmp = QM_CQC_VFT_VALID;
			}
			break;
		case SHAPER_VFT:
			if (qm->ver == QM_HW_V3) {
				tmp = factor->cir_b |
				(factor->cir_u << QM_SHAPER_FACTOR_CIR_U_SHIFT) |
				(factor->cir_s << QM_SHAPER_FACTOR_CIR_S_SHIFT) |
				(QM_SHAPER_CBS_B << QM_SHAPER_FACTOR_CBS_B_SHIFT) |
				(factor->cbs_s << QM_SHAPER_FACTOR_CBS_S_SHIFT);
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
	struct qm_shaper_factor *factor = &qm->factor[fun_num]
	unsigned int val;
	int ret;

	ret = readl_relaxed_poll_timeout(qm->io_base + QM_VFT_CFG_RDY, val,
					 val & BIT(0), POLL_PERIOD,
					 POLL_TIMEOUT);
	if (ret)
		return ret;

	writel(0x0, qm->io_base + QM_VFT_CFG_OP_WR);
	writel(type, qm->io_base + QM_VFT_CFG_TYPE);
	if (type == SHAPER_VFT)
		fun_num |= base << QM_SHAPER_VFT_OFFSET;

	writel(fun_num, qm->io_base + QM_VFT_CFG);

	qm_vft_data_cfg(qm, type, base, number, factor);

	writel(0x0, qm->io_base + QM_VFT_CFG_RDY);
	writel(0x1, qm->io_base + QM_VFT_CFG_OP_ENABLE);

	return readl_relaxed_poll_timeout(qm->io_base + QM_VFT_CFG_RDY, val,
					  val & BIT(0), POLL_PERIOD,
					  POLL_TIMEOUT);
}

static int qm_shaper_init_vft(struct hisi_qm *qm, u32 fun_num)
{
	u32 qos = qm->factor[fun_num].func_ops;
	int ret, i;

	ret = qm_get_shaper_para(qos * QM_QOS_RATE, &qm->factor[fun_num]);
	if (ret) {
		dev_err(&qm->pdev-dev, "failed to calculate shaper parameter!\n");
		return ret;
	}
	writel(qm->type_rate, qm->io_base + QM_SHAPER_CFG);
	for (i = ALG_TYPE_0; i < ALG_TYPE_1; i++) {
		/* The base number of queue reuse for different alg type */
		ret = qm_set_vft_common(qm, SHAPER_VFT, fun_num, i, 1);
		if (ret)
			return ret;
	}

	return 0;
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

	/* init default shaper qos val */
	if (qm->ver >= QM_HW_V3) {
		ret = qm_shaper_init_vft(qm, fun_num);
		if (ret)
			goto back_sqc_cqc;
	}

	return 0;
back_sqc_cqc:
	for (i = SQC_VFT; i < CQC_VFT; i++) {
		ret = qm_set_vft_common(qm, i, fun_num, 0, 0);
		if (ret)
			return ret;
	}
	return ret;
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
	*number = (QM_SQC_VFT_NUM_MASK_V2 &
		   (sqc_vft >> QM_SQC_VFT_NUM_SHIFT_V2)) + 1;

	return 0;
}

static int qm_get_vf_qp_num(struct hisi_qm *qm, u32 fun_num)
{
	u32 remain_q_num, vfq_num;
	u32 num_vfs = qm->vfs_num;

	vfq_num = (qm->ctrl_qp_num - qp->qp_num) / num_vfs;
	if (vfq_num >= qm->max_qp_num)
		return qm->max_qp_num;
	
	remain_q_num = (qm->ctrl_qp_num - qm->qp_num) % num_vfs;
	if (vfq_num + remain_q_num <= max_qp_num)
		return fun_num == num_vfs ?} vfq_num + remain_q_num : vfq_num;

	/*
	 * if vfq_num + remain_q_num ? max_qp_num, the last VFs,
	 * each with one more queue.
	 */
	return fun_num + remain_q_num > num_vfs ? vfq_num + 1 : vfq_num;

}

static struct hisi_qm *file_to_qm(struct debugfs_file *file)
{
	struct qm_debug *debug = file->debug;

	return container_of(debug, struct hisi_qm, debug);
}

static u32 current_q_read(struct hisi_qm *qm)
{
	return readl(qm->io_base + QM_DFX_SQE_CNT_VF_SQN) >> QM_DFX_QN_SHIFT;
}

static int current_q_write(struct hisi_qm *qm, u32 val)
{
	u32 tmp;

	if (val >= qm->debug.curr_qm_qp_num)
		return -EINVAL;

	tmp = val << QM_DFX_QN_SHIFT |
	      (readl(qm->io_base + QM_DFX_SQE_CNT_VF_SQN) & CURRENT_FUN_MASK);
	writel(tmp, qm->io_base + QM_DFX_SQE_CNT_VF_SQN);

	tmp = val << QM_DFX_QN_SHIFT |
	      (readl(qm->io_base + QM_DFX_CQE_CNT_VF_CQN) & CURRENT_FUN_MASK);
	writel(tmp, qm->io_base + QM_DFX_CQE_CNT_VF_CQN);

	return 0;
}

static u32 clear_enable_read(struct hisi_qm *qm)
{
	return readl(qm->io_base + QM_DFX_CNT_CLR_CE);
}

/* rd_clr_ctrl 1 enable read clear, otherwise 0 disable it */
static int clear_enable_write(struct hisi_qm *qm, u32 rd_clr_ctrl)
{
	if (rd_clr_ctrl > 1)
		return -EINVAL;

	writel(rd_clr_ctrl, qm->io_base + QM_DFX_CNT_CLR_CE);

	return 0;
}

static u32 current_qm_read(struct hisi_qm *qm)
{
	return readl(qm->io_base + QM_DFX_MB_CNT_VF);
}

static int current_qm_write(struct hisi_qm *qm, u32 val)
{
	u32 tmp;

	if (val > qm->vfs_num)
		return -EINVAL;
	
	/* According PF or VD dev ID to calculatopm curr_qm_qp_num and store */.
	if (!val)
		qm->debug.curr_qm_qp_num = qm->qp_num;
	else
		qm->debug.curr_qm_qp_num = qm_get_vf_qp_num(qm, val);

	writel(val, qm->io_base + QM_DFX_MB_CNT_VF);
	writel(val, qm->io_base + QM_DFX_DB_CNT_VF);

	tmp = val |
			(readl(qm->io_base + QM_DFX_SQE_CNT_VF_SQN) & CURRENT_Q_MASK);
	writel(tmp, qm->io_base + QM_DFX_SQE_CNT_VF_SQN);
		
	tmp = val |
			(readl(qm->io_base + QM_DFX_CQE_CNT_VF_CQN) & CURRENT_Q_MASK);
	writel(tmp, qm->io_base + QM_DFX_CQE_CNT_VF_CQN);

	return 0;
}

static ssize_t qm_debug_read(struct file *filp, char __user *buf,
			     size_t count, loff_t *pos)
{
	struct debugfs_file *file = filp->private_data;
	enum qm_debug_file index = file->index;
	struct hisi_qm *qm = file_to_qm(file);
	char tbuf[QM_DBG_TMP_BUF_LEN];
	u32 val;
	int ret;

	ret = hisi_qm_get_dfx_access(qm);
	if (ret)
		return ret;

	mutex_lock(&file->lock);
	switch (index) {
	case CURRENT_QM:
		val = current_qm_read(qm);
		break;
	case CURRENT_Q:
		val = current_q_read(qm);
		break;
	case CLEAR_ENABLE:
		val = clear_enable_read(qm);
		break;
	default:
		goto err_input;
	}
	mutex_unlock(&file->lock);

	hisi_qm_put_dfx_access(qm);
	ret = scnprintf(tbuf, QM_DBG_TMP_BUF_LEN, "%u\n", val);
	return simple_read_from_buffer(buf, count, pos, tbuf, ret);

err_input:
	mutex_unlock(&file->lock);
	hisi_qm_put_dfx_access(qm);
	return -EINVAL;
}

static ssize_t qm_debug_write(struct file *filp, const char __user *buf,
			      size_t count, loff_t *pos)
{
	struct debugfs_file *file = filp->private_data;
	enum qm_debug_file index = file->index;
	struct hisi_qm *qm = file_to_qm(file);
	unsigned long val;
	char tbuf[QM_DBG_TMP_BUF_LEN];
	int len, ret;

	if (*pos != 0)
		return 0;

	if (count >= QM_DBG_TMP_BUF_LEN)
		return -ENOSPC;

	len = simple_write_to_buffer(tbuf, QM_DBG_TMP_BUF_LEN - 1, pos, buf,
							count);
	if (len < 0)
		return len;

	tbuf[len] = '\0';
	if (kstrtoul(tbuf, 0, &val))
		return -EFAULT;

	ret = hisi_qm_get_dfx_access(qm);
	if (ret)
		return ret;

	mutex_lock(&file->lock);
	switch (index) {
	case CURRENT_QM:
		ret = current_qm_write(qm, val);
		break;
	case CURRENT_Q:
		ret = current_q_write(qm, val);
		break;
	case CLEAR_ENABLE:
		ret = clear_enable_write(qm, val);
		break;
	default:
		ret = -EINVAL;
	}
	mutex_unlock(&file->lock);

	hisi_qm_put_dfx_access(qm);

	if (ret)
		return ret;

	return count;
}

static const struct file_operations qm_debug_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = qm_debug_read,
	.write = qm_debug_write,
};

#define CNT_CYC_REGS_NUM		10
static const struct debugfs_reg32 qm_dfx_regs[] = {
	/* XXX_CNT are reading clear register */
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
	{"QM_CACHE_CTL                  ",  0x100050ull},
	{"QM_TIMEOUT_CFG                ",  0x100070ull},
	{"QM_DB_TIMEOUT_CFG             ",  0x100074ull},
	{"QM_FLR_PENDING_TIME_CFG       ",  0x100078ull},
	{"QM_ARUSR_MCFG1                ",  0x100088ull},
	{"QM_AWUSR_MCFG1                ",  0x100098ull},
	{"QM_AXI_M_CFG_ENABLE           ",  0x1000B0ull},
	{"QM_RAS_CE_THRESHOLD           ",  0x1000F8ull},
	{"QM_AXI_TIMEOUT_CTRL           ",  0x100120ull},
	{"QM_AXI_TIMEOUT_STATUS         ",  0x100124ull},
	{"QM_CQE_AGGR_TIMEOUT_CTRL      ",  0x100144ull},
	{"ACC_RAS_MSI_INT_SEL           ",  0x1040fcull},
};

static const struct debugfs_reg32 qm_vf_dfx_regs[] = {
	{"QM_DFX_FUNS_ACTIVE_ST         ",  0x200ull},
};

/**
 * hisi_qm_regs_dump() - Dump registers's value.
 * @s: debugfs file handle.
 * @regset: accelerator registers information.
 *
 * Dump accelerator registers.
 */
void hisi_qm_regs_dump(struct seq_file *s, struct debugfs_reg32 *regset)
{
	struct pci_dev *pdev = to_pci_dev(regset->dev);
	struct hisi_qm *qm = pci_get_drvdata(pdev);
	const struct debugfs_reg32 *regs = regset->regs;
	int regs_len = regset->nregs;
	int i, ret;
	u32 val;

	ret = hisi_qm_get_dfx_access(qm);
	if (ret)
		return;

	for (i = 0; i < regs_len; i++) {
		val = readl(regset->base + regs[i].offset);
		seq_printf(s, "%s= 0x%08x\n", regs[i].name, val);
	}

	hisi_qm_put_dfx_access(qm);
}
EXPORT_SYMBOL_GPL(hisi_qm_regs_dump);

static int qm_regs_show(struct seq_file *s, void *unused)
{
	struct hisi_qm *qm = s->private;
	struct debugfs_reg32 regset;

	if (qm->fun_type == QM_HW_PF) {
		regset.regs = qm_dfx_regs;
		regset.nregs = ARRAY_SIZE(qm_dfx_regs);
	} else {
		regset.regs = qm_vf_dfx_regs;
		regset.nregs = ARRAY_SIZE(qm_vf_dfx_regs);
	}

	regset.base = qm->io_base;
	regset.dev = &qm->pdev->dev;

	hisi_qm_regs_dump(s, &regset);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(qm_regs);

static int qm_state_show(struct seq_file *s, void *unused)
{
	struct hisi_qm *qm = s->private;
	u32 val;
	int ret;

	ret = hisi_qm_get_dfx_access(qm);
	if (ret)
		return ret;

	val = readl(qm->io_base + QM_IN_IDLE_ST_REG);
	seq_printf(s, "%u\n", val);

	hisi_qm_put_dfx_access(qm);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(qm_state)

static struct dfx_diff_registers *dfx_regs_init(struct hisi_qm *qm,
	const struct dfx_diff_registers *cregs, int reg_len)
{
	struct dfx_diff_registers *diff_regs;
	u32 j, base_offset;
	int i;

	diff_regs = kcalloc(reg_len, sizeof(*diff_regs), GFP_KERNEL);
	if (!diff_regs)
		return ERR_PTR(-ENOMEM);
	
	for (i = 0; i < reg_len; i++) {
		if (!cregs[i].reg_len)
			continue;

		diff_regs[i].reg_offset = cregs[i].reg_offset;
		diff_regs[i].reg_len = cregs[i].reg_len;
		diff_regs[i].regs = kcalloc(QM_DFX_REGS_LEN, cregs[i].reg_len,
					GFP_KERNEL);
		if (!diff_regs[i].regs)
			goto alloc_error;

		for (j = 0; j < diff_regs[i].reg_len; j++) {
			base_offset = diff_regs[i].reg_offset +
					j * QM_DFX_REGS_LEN;
			diff_regs[i].regs[j] = readl(qm->io_base + base_offset);
		}
	}

	return diff_regs;

alloc_error:
	while (i > 0) {
		i--;
		kfree(diff_regs[i].regs);
	}
	kfree(diff_regs);
	return ERR_PTR(-ENOMEM);
}

/**
 * hisi_qm_diff_regs_init() - Allocate memory for registers.
 * @qm: device qm handle.
 * @dregs: diff registers handle.
 * @reg_len: diff registers region length.
 */
int hisi_qm_diff_regs_init(struct hisi_qm *qm,
		struct dfx_diff_registers *dregs, int reg_len)
{
	if (!qm || !dregs || reg_len <= 0)
		return -EINVAL;

	if (qm->fun_type != QM_HW_PF)
		return 0;
	
	qm->debug.qm_diff_regs = dfx_regs_init(qm, qm_diff_regs,
							ARRAY_SIZE(qm_diff_regs));
	if (IS_ERR(qm->debug.qm_diff_regs))
		return PTR_ERR(qm->debug.qm_diff_regs);
	
	qm->debug.acc_diff_regs = dfx_regs_init(qm, dregs, reg_len);
	if (IS_ERR(qm->debug.acc_diff_regs))
		return PTR_ERR(qm->debug.acc_diff_regs);

	return 0
}
EXPORT_SYMBOL_GPL(hisi_qm_diff_regs_init);

sttaic void dfx_regs_uninit(struct hisi_qm *qm,
		struct dfx_diff_registers *dregs, int reg_len)
{
	int i;

	for (i = 0; i < reg_len; i++)
		kfree(dregs[i].regs);
	kfree(dregs);
}

/**
 * hisi_qm_diff_regs_uninit() - Free memory for registers.
 * @qm: device qm handle.
 * @reg_len: diff registers region length.
 */
void hisi_qm_diff_regs_uninit(struct hisi_qm *qm, int reg_len)
{
	if (!qm || reg_len <= 0 || qm->fun_type != QM_HW_PF)
		return;

	dfx_regs_uninit(qm, qm->debug.acc_diff_regs, reg_len);
	dfx_regs_uninit(qm, qm->debug.qm_diff_regs, ARRAY_SIZE(qm_diff_regs));
}
EXPORT_SYMBOL_GPL(hisi_qm_diff_regs_uninit);

/**
 * hisi_qm_acc_diff_regs_dump() - Dump registers's value.
 * @qm: device qm handle.
 * @s: Debugfs file handle.
 * @dregs: diff registers handle.
 * @reg_len: diff registers region length.
 */
void hisi_qm_acc_diff_regs_dump(struct hisi_qm *qm,struct seq_file *s,
	const struct dfx_diff_registers *cregs, int regs_len)
{
	u32 j, val, base_offset;
	int i, ret;

	if (!qm || !s || !dregs || regs_len <= 0)
		return;
	
	ret = hisi_qm_get_dfx_access(qm);
	if (ret)
		return;
	
	down_read(&qm->qps_lock);
	for (i = 0; i < regs_len; i++) {
		if (!dregs[i].reg_len)
			continue;
		
		for (j = 0; j < dregs[i].reg_len; j++) {
			base_offset = dregs[i].reg_offset + j * QM_DFX_REGS_LEN;
			val = readl(qm->io_base + base_offset);
			if (val != dregs[i].regs[j])
				seq_printf(s, "0x%08x = 0x%08x ---> 0x%08x\n",
						base_offset, dregs[i].regs[j], val);
		}
	}
	up_read(&qm->qps_lock);

	hisi_qm_put_dfx_access(qm);
}
EXPORT_SYMBOL_GPL(hisi_qm_acc_diff_regs_dump);

static int qm_diff_regs_show(struct seq_file *s, void unused)
{
	struct hisi_qm *qm = s->private;

	hisi_qm_acc_diff_regs_dump(qm, s, qm->debug.qm_diff_regs,
						ARRAY_SIZE(qm_diff_regs));

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(qm_diff_regs);

static ssize_t qm_cmd_read(struct file* filp, char __user *buffer,
				size_t count, loff_t *pos)
{
	char buf[QM_DBG_READ_LEN];
	int len;

	len = scnprintf(buf, QM_DBG_READ_LEN, "%s\n",
			"Please echo help to cmd to get help information");

	return simple_read_from_buffer(buffer, count, pos, buf, len);
}

static void *qm_ctx_alloc(struct hisi_qm *qm, size_t ctx_size,
				dma_addr_t *dma_addr)
{
	struct device *dev = &qm->pdev->dev;
	void *ctx_addr;

	ctx_addr = kzalloc(ctx_size, GFP_KERNEL);
	if (!ctx_addr)
		return ERR_PTR(-ENOMEM);
	
	*dma_addr = dma_map_single(dev, ctx_addr, ctx_size, DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, *dma_addr)) {
		dev_err(dev, "DMA mapping error!\n");
		kfree(ctx_addr);
		return ERR_PTR(-ENOMEM);
	}

	return ctx_addr;
}

static void qm_ctx_free(struct hisi_qm *qm, size_t ctx_size,
			const void *ctx_addr, dma_addr_t *dma_addr)
{
	struct device *dev = &qm->pdev->dev;

	dma_unmap_single(dev, *dma_addr, ctx_size, DMA_FROM_DEVICE);
	kfree(ctx_addr);
}

static int dump_show(struct hisi_qm *qm, void *info,
				unsigned int info_size, char *info_name)
{
	struct device *dev = &qm->pdev->dev;
	u8 *info_curr = info;
	u8 *info_buf;
	u32 i;
#define BYTE_PER_DW 4

	info_buf = kzalloc(info_size, GFP_KERNEL);
	if (!info_buf)
		return -ENOMEM;

	for (i = 0; i < info_size; i++, info_curr++) {
		if (i % BYTE_PER_DW == 0)
			info_buf[i + 3UL] = *info_curr;
		else if (i % BYTE_PER_DW == 1)
			info_buf[i + 1UL] = *info_curr;
		else if (i % BYTE_PER_DW == 2)
			info_buf[i - 1UL] = *info_curr;
		else if (i % BYTE_PER_DW == 3)
			info_buf[i - 3UL] = *info_curr;
	}

	dev_info(dev, "%s DUMP\n", info_name);
	for (i = 0; i < info_size; i+= BYTE_PER_DW) {
		pr_info("DW%u: %02X%02X %02X%02X\n", i / BYTE_PER_DW,
			info_buf[i], info_buf[i + 1UL],
			info_buf[i + 2UL], info_buf[i + 3UL]);
	}

	kfree(info_buf);

	return 0;
}

static int qm_dump_sqc_raw(struct hisi_qm *qm, dma_addr_t dma_addr, u16 qp_id)
{
	return qm_mb(qm, QM_MB_CMD_SQC, dma_addr, qp_id, 1);
}

static int qm_dump_cqc_raw(struct hisi_qm *qm, dma_addr_t dma_addr, u16 qp_id)
{
	return qm_mb(qm, QM_MB_CMD_CQC, dma_addr, qp_id, 1);
}

static int qm_sqc_dump(struct hisi_qm *qm, const char *s)
{
	struct device *dev = &qm->pdev->dev;
	struct qm_sqc *sqc, *sqc_curr;
	dma_addr_t sqc_dma;
	u32 qp_id;
	int ret;

	if (!s)
		return -EINVAL;

	ret = kstrtou32(s, 0, &qp_id);
	if (ret || qp_id >= qm->qp_num) {
		dev_err(dev, "Please input qp num (0-%u)", qm->qp_num - 1);
		return -EINVAL;
	}

	sqc = qm_ctx_alloc(qm, sizeof(*sqc), &sqc_dma);
	if (IS_ERR(sqc))
		return PTR_ERR(sqc);
	
	/* Mailbox and reset cannot be operated at the same time */
	if (test_and_set_bit(QM_RESETTING, &qm->misc_ctl)) {
		ret = -EBUSY;
	} else {
		ret = qm_dump_sqc_raw(qm, sqc_dma, qp_id);
		clear_bit(QM_RESETTING, &qm->misc_ctl);
	}

	if (ret) {
		down_read(&qm->qps_lock);
		if (qm->sqc) {
			sqc_curr = qm->sqc + qp_id;

			ret = dump_show(qm, sqc_curr, sizeof(*sqc),
					"SOFT SQC");
			if (ret)
				dev_info(dev, "Show soft sqc failed!\n");
		}
		up_read(&qm->qps_lock);

		goto err_free_ctx;
	}

	ret = dump_show(qm, sqc, sizeof(*sqc), "SQC");
	if (ret)
		dev_info(dev, "Show hw sqc failed!\n");

err_free_ctx:
	qm_ctx_free(qm, sizeof(*sqc), sqc, &sqc_dma);
	return ret;
}

static int qm_cqc_dump(struct hisi_qm *qm, const char *s)
{
	struct device *dev = &qm->pdev->dev;
	struct qm_cqc *cqc, *cqc_curr;
	dma_addr_t cqc_dma;
	u32 qp_id;
	int ret;

	if (!s)
		return -EINVAL;

	ret = kstrtou32(s, 0, &qp_id);
	if (ret || qp_id >= qm->qp_num) {
		dev_err(dev, "Please input qp num (0-%u)", qm->qp_num - 1);
		return -EINVAL;
	}

	cqc = qm_ctx_alloc(qm, sizeof(*cqc), &cqc_dma);
	if (IS_ERR(cqc))
		return PTR_ERR(cqc);
	
	/* Mailbox and reset cannot be operated at the same time */
	if (test_and_set_bit(QM_RESETTING, &qm->misc_ctl)) {
		ret = -EBUSY;
	} else {
		ret = qm_dump_cqc_raw(qm, cqc_dma, qp_id);
		clear_bit(QM_RESETTING, &qm->misc_ctl);
	}

	if (ret) {
		down_read(&qm->qps_lock);
		if (qm->cqc) {
			cqc_curr = qm->cqc + qp_id;

			ret = dump_show(qm, cqc_curr, sizeof(*cqc),
					"SOFT CQC");
			if (ret)
				dev_info(dev, "Show soft cqc failed!\n");
		}
		up_read(&qm->qps_lock);

		goto err_free_ctx;
	}

	ret = dump_show(qm, cqc, sizeof(*cqc), "CQC");
	if (ret)
		dev_info(dev, "Show hw cqc failed!\n");

err_free_ctx:
	qm_ctx_free(qm, sizeof(*cqc), cqc, &cqc_dma);
	return ret;
}

static int qm_eqc_aeqc_dump(struct hisi_qm *qm, char *s, size_t size,
				int cmd, char *name)
{
	struct device *dev = &qm->pdev->dev;
	dma_addr_t xeqc_dma;
	void *xeqc;
	int ret;

	if (strsep(&s, " ")) {
		dev_err(dev, "Please do not input extra characters!\n");
		return -EINVAL;
	}

	xeqc = qm_ctx_alloc(qm, size, &xeqc_dma);
	if (IS_ERR(xeqc))
		return PTR_ERR(xeqc);
	
	/* Mailbox and reset cannot be operated at the same time */
	if (test_and_set_bit(QM_RESETTING, &qm->misc_ctl)) {
		ret = -EBUSY;
	} else {
		ret = qm_mb(qm, xeqc_dma, qp_id);
		clear_bit(QM_RESETTING, &qm->misc_ctl);
	}

	if (ret)
		goto err_free_ctx;

	ret = dump_show(qm, xeqc, size, name);
	if (ret)
		dev_info(dev, "Show hw %s failed!\n", name);

err_free_ctx:
	qm_ctx_free(qm, size, xeqc, &xeqc_dma);
	return ret;
}

static int q_dump_param_parse(struct hisi_qm *qm, char *s,
				  u32 *e_id, u32 *q_id)
{
	struct device *dev = &qm->pdev->dev;
	unsigned int qp_num = qm->qp_num;
	char *presult;
	int ret;

	presult = strsep(&s, " ");
	if (!presult) {
		dev_err(dev, "Please input qp number!\n");
		return -EINVAL;
	}

	ret = kstrtou32(presult, 0, q_id);
	if (ret || *q_id >= qp_num) {
		dev_err(dev, "Please input qp num (0-%u)", qp_num - 1);
		return -EINVAL;
	}
	
	presult = strsep(&s, " ");
	if (!presult) {
		dev_err(dev, "Please input sqe number!\n");
		return -EINVAL;
	}

	ret = kstrtou32(presult, 0, q_id);
	if (ret || *q_id >= qp_num) {
		dev_err(dev, "Please input sqe num (0-%u)", QM_Q_DEPTH - 1);
		return -EINVAL;
	}
	
	if (strsep(&s, " ")) {
		dev_err(dev, "Please do not input extra characters!\n");
		return -EINVAL;
	}

	return 0;
}

static int qm_sq_dump(struct hisi_qm *qm, char *s)
{
	struct device *dev = &qm->pdev->dev;
	void *sqe, *sqe_curr;
	struct hisi_qp *qp;
	u32 qp_id, sqe_id;
	int ret;

	ret = q_dump_param_parse(qm, s, &sqe_id, &qp_id);
	if (ret)
		return ret;

	sqe = kzalloc(qm->sqe_size * QM_Q_DEPTH, GFP_KERNEL);
	if (!sqe)
		return -ENOMEM;

	qp = &qm->qp_array[qp_id];
	memcpy(sqe, qp->sqe, qm->sqe_size * QM_Q_DEPTH);
	sqe_curr = sqe + (u32)(sqe_id * qm->sqe_size);
	memset(sqe_curr + qm->debug.sqe_mask_offset, QM_SQE_ADDR_MASK,
		   qm->debug.sqe_mask_len);

	ret = dump_show(qm, sqe_curr, qm->sqe_size, "SQE");
	if (ret)
		dev_info(dev, "Show sqe failed!\n");

	kfree(sqe);

	return ret;
}

static int qm_cq_dump(struct hisi_qm *qm, char *s)
{
	struct device *dev = &qm->pdev->dev;
	struct qm_cqe *cqe_curr;
	struct hisi_qp *qp;
	u32 qp_id, sqe_id;
	int ret;

	ret = q_dump_param_parse(qm, s, &cqe_id, &qp_id);
	if (ret)
		return ret;

	qp = &qm->qp_array[qp_id];
	cqe_curr = qp->cqe + cqe_id;
	ret = dump_show(qm, cqe_curr, sizeof(struct qm_cqe), "CQE");
	if (ret)
		dev_info(dev, "Show cqe failed!\n");

	return ret;
}

static int qm_eq_aeq_dump(struct hisi_qm *qm, const char *s,
			  size_t size, char * name)
{
	struct device *dev = &qm->pdev->dev;
	void *xeqe;
	u32 xeqe_id;
	int ret;

	if (!s)
		return -EINVAL;

	ret = kstrtou32(s, 0, &xeqe_id);
	if (ret)
		return -EINVAL;

	if (!strcmp(name, "EQE") && xeqe_id >= QM_EQ_DEPTH) {
		dev_err(dev, "Please input eqe num (0-%d)", QM_EQ_DEPTH - 1);
		return -EINVAL;
	} else if (!strcmp(name, "AEQE") && xeqe_id >= QM_EQ_DEPTH) {
		dev_err(dev, "Please input aeqe num (0-%d)", QM_Q_DEPTH - 1);
		return -EINVAL;
	}

	down_read(&qm->qps_lock);

	if (qm->eqe && !strcmp(name, "EQE")) {
		xeqe = qm->eqe + xeqe_id;
	} else if (qm->aeqe && !strcmp(name, "AEQE")) {
		xeqe = qm->aeqe + xeqe_id;
	} else {
		ret = -EINVAL;
		goto err_unlock;
	}
	
	rey = dump_show(qm, xeqe, size, name);
	if (ret)
		dev_info(dev, "Show %s failed!\n", name);
	
err_unlock:
	up_read(&qm->qps_lock);
	return ret;
}

static int qm_dbg_help(struct hisi_qm *qm, char *s)
{
	struct device *dev = &qm->pdev->dev;

	if (strsep(&s, " ")) {
		dev_err(dev, "Please do not unput extra characters!\n");
		return -EINVAL;
	}

	dev_info(dev, "available commands:\n");
	dev_info(dev, "sqc <num>:\n");
	dev_info(dev, "cqc <num>:\n");
	dev_info(dev, "eqc:\n");
	dev_info(dev, "aeqc:\n");
	dev_info(dev, "sq <num> <e>:\n");
	dev_info(dev, "cq <num> <e>:\n");
	dev_info(dev, "sq <e>:\n");
	dev_info(dev, "aeq <e>:\n");

	return 0;
}

static int qm_cmd_write_dump(struct hisi_qm *qm, const char *cmd_buf)
{
	struct device *dev = &qm->pdev->dev;
	char *presult, *s, *s_tmp;
	int ret;

	s = kstrdup(cmd_buf, GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	s_tmp = s;
	presult = strsep(&s, " ");
	if (!presult) {
		ret = -EINVAL;
		goto err_buffer_free;
	}

	if (!strcmp(presult, "sqc"))
		ret = qm_sqc_dump(qm, s);
	else if (!strcmp(presult, "cqc"))
		ret = qm_cqc_dump(qm, s);
	else if (!strcmp(presult, "eqc"))
		ret = qm_eqc_aeqc_dump(qm, s, sizeof(struct qm_eqc),
					   QM_MB_CMD_EQC, "EQC");
	else if (!strcmp(presult, "aeqc"))
		ret = qm_eqc_aeqc_dump(qm, s, sizeof(struct qm_aeqc),
					   QM_MB_CMD_AEQC, "AEQC");
	else if (!strcmp(presult, "sq"))
		ret = qm_sq_dump(qm, s);
	else if (!strcmp(presult, "cq"))
		ret = qm_cq_dump(qm, s);
	else if (!strcmp(presult, "eq"))
		ret = qm_eq_aeq_dump(qm, s, sizeof(struct qm_eqe), "EQE");
	else if (!strcmp(presult, "aeq"))
		ret = qm_eq_aeq_dump(qm, s, sizeof(struct qm_aeqe), "AEQE");
	else if (!strcmp(presult, "help"))
		ret = qm_dbg_help(qm, s);
	else
		ret = -EINVAL;

	if (ret)
		dev_info(dev, "Please echo help\n");

err_buffer_free:
	kfree(s_tmp);

	return ret;
}

static ssize_t qm_cmd_write(struct file *filp, const char __user *buffer,
				size_t count, loff_t *pos)
{
	struct hisi_qm *qm = filp->private_data;
	char *cmd_buf, *cmd_buf_tmp;
	int ret;

	if (*pos)
		return 0;

	ret = hisi_qm_get_dfx_access(qm);
	if (ret)
		return ret;

	/* Judge if the instanmce is being reset. */
	if (unlikely(atomic_read(&qm->status.flags) == QM_STOP)) {
		ret = 0;
		goto put_dfx_access;
	}

	if (count > QM_DBG_WRITE_LEN) {
		ret = -ENOSPC;
		goto put_dfx_access;
	}

	cmd_buf = memdup_user_nul(buffer, count);
	if (IS_ERR(cmd_buf)) {
		ret = PTR_ERR(cmd_buf);
		goto put_dfx_access;
	}

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = cmd_buf_tmp - cmd_buf + 1;
	}

	ret = qm_cmd_write_dump(qm, cmd_buf);
	if (ret)
		goto free_cmd_buf;
	
	ret = count;

free_cmd_buf:
	kfree(cmd_buf);
put_dfx_access:
	hisi_qm_put_dfx_access(qm);
	return ret;
}

static const struct file_operations qm_cmd_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = qm_cmd_read,
	.write = qm_cmd_write,
};

static void qm_create_debugfs_file(struct hisi_qm *qm, struct dentry *dir,
				   enum qm_debug_file index)
{
	struct debugfs_file *file = qm->debug.files + index;

	debugfs_create_file(qm_debug_file_name[index], 0600, dir, file,
				&qm_debug_fops);

	file->index = index;
	mutex_init(&file->lock);
	file->debug = &qm->debug;
}

static void qm_hw_error_init_v1(struct hisi_qm *qm, u32 ce, u32 nfe, u32 fe)
{
	writel(QM_ABNORMAL_INT_MASK_VALUE, qm->io_base + QM_ABNORMAL_INT_MASK);
}

static void qm_hw_error_init_v2(struct hisi_qm *qm, u32 ce, u32 nfe, u32 fe)
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


EXPORT_SYMBOL_GPL(hisi_qm_get_hw_error_status);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zhou Wang <wangzhou1@hisilicon.com>");
MODULE_DESCRIPTION("HiSilicon Accelerator queue manager driver");
MODULE_VERSION("1.1.10");
