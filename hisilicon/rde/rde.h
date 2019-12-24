/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2018-2019 HiSilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef __RDE_H__
#define __RDE_H__

#include <linux/list.h>
#include "../qm.h"
#include "rde_usr_if.h"
#include "rde_api.h"

#undef pr_fmt
#define pr_fmt(fmt)	"hisi_rde: " fmt

struct hisi_rde_ctrl;

enum hisi_rde_status {
	HISI_RDE_RESET,
};

struct hisi_rde {
	struct hisi_qm qm;
	struct list_head list;
	struct hisi_rde_ctrl *ctrl;
	struct work_struct reset_work;
	struct mutex *rde_list_lock;
	unsigned long status;
	u32 smmu_state;
	int q_ref;
};

#define RDE_CM_LOAD_ENABLE		1
#define RDE_MPCC_MAX_SRC_NUM	17
#define RDE_FLEXEC_MAX_SRC_NUM	32
#define RDE_MPCC_CMSIZE		2176
#define RDE_FLEXEC_CMSIZE		1024
#define RDE_MEM_SAVE_SHIFT		2
#define RDE_BUF_TYPE_SHIFT		3
#define SGL_DATA_OFFSET_SHIFT	8
#define RDE_COEF_GF_SHIFT		32
#define RDE_LBA_BLK			8
#define RDE_LBA_DWORD_CNT		5
#define DIF_CHK_GRD_CTRL_SHIFT	4
#define DIF_CHK_REF_CTRL_SHIFT	32
#define DIF_LBA_SHIFT			32
#define DIF_GEN_PAD_CTRL_SHIFT	32
#define DIF_GEN_REF_CTRL_SHIFT	35
#define DIF_GEN_APP_CTRL_SHIFT	38
#define DIF_GEN_VER_CTRL_SHIFT	41
#define DIF_GEN_GRD_CTRL_SHIFT	44
#define DIF_APP_TAG_SHIFT		48
#define DIF_VERSION_SHIFT		56
#define RDE_TASK_DONE_STATUS	0x80
#define RDE_CRC16_IV			0x310004
#define RDE_PRP_PAGE_SIZE		0x31022c
#define RDE_SGL_SGE_OFFSET		0x310228
#define RDE_INVLD_REQ_ID		(-1)
#define RDE_ALG_TYPE_MSK		0x60
#define RDE_BUF_TYPE_MSK		0x18
#define RDE_MAX_SRC_PLATE_NUM	32
#define RDE_MAX_DST_PLATE_NUM	17
#define SRC_ADDR_TABLE_NUM		48
#define DST_ADDR_TABLE_NUM		26
#define SRC_DIF_TABLE_NUM		20
#define DST_DIF_TABLE_NUM		17
#define RDE_STATUS_MSK		0x7f
#define RDE_DONE_MSK			0x1
#define RDE_DONE_SHIFT		7
#define RDE_PER_SRC_COEF_SIZE	32
#define RDE_PER_SRC_COEF_TIMES	4
#define RDE_UPD_GN_FLAG		0x80
#define RDE_UPD_PARITY_SHIFT		7


#define RDE_GN_CNT(i)	(((i + 1) % 2 == 0) ? ((i + 1) >> 1) : ((i + 2) >> 1))
#define RDE_GN_FLAG(i)	(((i + 1) % 2 == 0) ? 2 : 1)
#define RDE_GN_SHIFT(x)	(RDE_COEF_GF_SHIFT * (x == 1 ? 1 : 0))
#define RDE_CLR_CNT(i)	(((i - 1) / RDE_LBA_BLK + 1) * RDE_LBA_DWORD_CNT)


/*src data addr table, should be 64byte aligned.*/
struct rde_src_tbl {
	u64 content[SRC_ADDR_TABLE_NUM];
};

/*src data dif table, should be 64byte aligned.*/
struct rde_src_tag_tbl {
	u64 content[SRC_DIF_TABLE_NUM];
};

/*dst data addr table, should be 64byte aligned.*/
struct rde_dst_tbl {
	u64 content[DST_ADDR_TABLE_NUM];
};

/*dst data dif table, should be 64byte aligned.*/
struct rde_dst_tag_tbl {
	u64 content[DST_DIF_TABLE_NUM];
};

/*inner msg structure, keep addr info*/
struct hisi_rde_msg {
	struct rde_src_tbl *src_addr;
	dma_addr_t src_dma_addr;
	struct rde_dst_tbl *dst_addr;
	dma_addr_t dst_dma_addr;
	struct rde_src_tag_tbl *src_tag_addr;
	dma_addr_t src_tag_dma_addr;
	struct rde_dst_tag_tbl *dst_tag_addr;
	dma_addr_t dst_tag_dma_addr;
	u64 src_record[RDE_MAX_SRC_PLATE_NUM];
	u64 dst_record[RDE_MAX_DST_PLATE_NUM];
	struct hisi_rde_sqe sqe;
	struct raid_ec_ctrl *udata;
	u32 req_id;
};

/*rde ctx structure, acc_init api can alloc and init this structure*/
struct hisi_rde_ctx {
	struct device *dev;
	struct hisi_qp *qp;
	struct hisi_rde *rde_dev;
	struct hisi_rde_msg *req_list;
	unsigned long *req_bitmap;
	spinlock_t req_lock;
	u32 smmu_state;
	u32 session_num;
	u8 addr_type;
};

/*inner structure, to distinguish diffenernt alg and operation*/
struct rde_type {
	u8 alg_mode;
	u8 mem_mode;
	u8 buf_mode;
	u8 alg_type;
};

/*RDE algorithm types.*/
enum {
	MPCC = 0x00, /*EC */
	PQ_FLEXEC = 0x40, /*RAID5/RAID6/FlexEC */
	XOR = 0x60, /* XOR */
};

/*RDE buffer access types.*/
enum {
	PBUF = 0x00, /*Direct Access */
	SGL = 0x08, /*Scatter Gather List */
	PRP = 0x10, /*Physical Region Page List */
	REVD = 0x18, /*Reserved */
};

/*RDE DIF GRD types.*/
enum {
	NO_GRD = 0, /*no GRD domain */
	GRD = 1, /*GRD domain without checking */
	GRD_CHECK = 2, /*GRD domain with checking */
};

/*RDE DIF REF types.*/
enum {
	NO_REF = 0, /*no REF domain */
	REF = 1, /*REF domain without checking */
	REF_CHECK_LBA = 2, /*REF domain checking with lab */
	REF_CHECK_PRI = 3, /*REF domain checking with private infoformation */
};

/*RDE IO abort switch.*/
enum {
	NO_ABORT = 0, /*don't abort the io */
	ABORT = 1, /*abort the io */
};

/*RDE coefficient matrix load enable.*/
enum {
	NO_CM_LOAD = 0, /*don't load matrix */
	CM_LOAD = 1, /*load matrix */
};

/*RDE coefficient matrix types.*/
enum {
	CM_ENCODE = 0, /*encode type */
	CM_DECODE = 1, /*decode type */
};

/*RDE algorithms block size.*/
enum {
	ALG_BLK_512B = 0, /*512 bytes */
	ALG_BLK_4K = 1, /*4K bytes */
};

/*RDE crc iv enable.*/
enum {
	NO_CRCIV = 0, /*default IV is 0 */
	CRCIV = 1, /*IV is register's value */
};

/*RDE crc iv switch.*/
enum {
	CRCIV0 = 0, /*select crc16_iv0 of register */
	CRCIV1 = 1, /*select crc16_iv1 of register */
};

/*RDE DIF types.*/
enum {
	NO_RDE_DIF = 0, /*without DIF */
	RDE_DIF = 1, /*DIF */
};

/*RDE page padding types.*/
enum {
	NO_PAD = 0, /*without padding */
	PRE_PAD = 1, /*padding before DIF */
	POST_PAD = 2, /*padding after DIF */
};

enum {
	QNUM_64 = 64,
	QNUM_128 = 128,
	QNUM_256 = 256,
	QNUM_512 = 512,
	QNUM_1024 = 1024,
	QNUM_BUTT
};

enum {
	QDEPTH_64 = 64,
	QDEPTH_128 = 128,
	QDEPTH_256 = 256,
	QDEPTH_512 = 512,
	QDEPTH_1024 = 1024,
	QDEPTH_BUTT
};

static inline void rde_bd_dump(struct hisi_rde_sqe *bd)
{
	int i;

	pr_info("====== BD info start======\n");
	for (i = 0; i < sizeof(struct hisi_rde_sqe) / sizeof(u64); i++)
		pr_info("sqe-word[%d]: 0x%llx.\n", i, *((u64 *)bd + i));

	pr_info("====== BD info end======\n");
}

static inline void rde_table_dump(const struct hisi_rde_msg *req)
{
	int i;

	for (i = 0; i < SRC_ADDR_TABLE_NUM; i++) {
		if (req->src_addr->content[i])
			pr_info("src addr info[%d] content is 0x%llx\n",
				i, req->src_addr->content[i]);
	}

	for (i = 0; i < DST_ADDR_TABLE_NUM; i++) {
		if (req->dst_addr->content[i])
			pr_info("dst addr info[%d] content is 0x%llx\n",
				i, req->dst_addr->content[i]);
	}
}

struct hisi_rde *find_rde_device(int node);
int hisi_rde_abnormal_fix(struct hisi_qm *qm);

#endif
