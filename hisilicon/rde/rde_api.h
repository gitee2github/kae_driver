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

#ifndef __RDE_API_H__
#define __RDE_API_H__

/**
 * @brief dif pad type
 */
enum DIF_PAGE_LAYOUT_PAD_TYPE_E {
	DIF_PAGE_LAYOUT_PAD_NONE = 0x0,
	DIF_PAGE_LAYOUT_PAD_AHEAD_DIF = 0x1, /* 4096+56+8 */
	DIF_PAGE_LAYOUT_PAD_BEHIND_DIF = 0x2, /* 4096+8+56 */
	DIF_PAGE_LAYOUT_PAD_BUTT
};

/**
 * @brief dif pad gen mode enumeration, rde only support 0,3,5.
 */
enum DIF_PAGE_LAYOUT_PAD_GEN_CTRL_E {
	DIF_PAGE_LAYOUT_PAD_GEN_NONE = 0x0,
	DIF_PAGE_LAYOUT_PAD_GEN_FROM_ZERO = 0x3,
	DIF_PAGE_LAYOUT_PAD_GEN_FROM_SOURCE_DATA = 0x4,
	DIF_PAGE_LAYOUT_PAD_GEN_FROM_RAID_OR_EC = 0x5,
	DIF_PAGE_LAYOUT_PAD_GEN_BUTT
};

/**
 * @brief dif grd gen mode enumeration.
 */
enum DIF_GRD_GEN_CTRL_E {
	DIF_GRD_GEN_NONE = 0x0,
	DIF_GRD_GEN_FROM_T10CRC = 0x1,
	DIF_GRD_GEN_FROM_RAID_OR_EC = 0x5,
	DIF_GRD_GEN_BUTT
};

/**
 * @brief dif ver gen mode enumeration, rde only support 0 or 1.
 */
enum DIF_VER_GEN_CTRL_E {
	DIF_VER_GEN_NONE = 0x0,
	DIF_VER_GEN_FROM_INPUT = 0x1,
	DIF_VER_GEN_FROM_ZERO = 0x3,
	DIF_VER_GEN_FROM_SOURCE_DATA = 0x4,
	DIF_VER_GEN_BUTT
};

/**
 * @brief dif app gen mode enumeration, rde only support 0,1,5.
 */
enum DIF_APP_GEN_CTRL_E {
	DIF_APP_GEN_NONE = 0x0,
	DIF_APP_GEN_FROM_INPUT = 0x1,
	DIF_APP_GEN_FROM_ZERO = 0x3,
	DIF_APP_GEN_FROM_SOURCE_DATA = 0x4,
	DIF_APP_GEN_FROM_RAID_OR_EC = 0x5,
	DIF_APP_GEN_BUTT
};

/**
 * @brief dif ref gen mode enumeration, rde only support 0,1,2,5.
 */
enum DIF_REF_GEN_CTRL_E {
	DIF_REF_GEN_NONE = 0x0,
	DIF_REF_GEN_FROM_INPUT_LBA = 0x1,
	DIF_REF_GEN_FROM_PRIVATE_INFO = 0x2,
	DIF_REF_GEN_FROM_ZERO = 0x3,
	DIF_REF_GEN_FROM_SOURCE_DATA = 0x4,
	DIF_REF_GEN_FROM_RAID_OR_EC = 0x5,
	DIF_REF_GEN_BUTT
};

/**
 * @brief dif verify mode enumeration, grd: rde only support 0,1,2.
 */
enum DIF_VERIFY_CTRL_E {
	DIF_VERIFY_NONE = 0x0,
	DIF_VERIFY_DO_NOT_VERIFY = 0x1,
	DIF_VERIFY_ALL_BLOCK = 0x2,
	DIF_VERIFY_BY_PRIVATE_INFO = 0x3,
	DIF_VERIFY_BUTT
};

/**
 * @brief data store mode, sdk do not support prp temporarily.
 */
enum ACC_BUF_TYPE_E {
	ACC_BUF_TYPE_PBUFFER = 0x0,
	ACC_BUF_TYPE_SGL = 0x1,
	ACC_BUF_TYPE_PRP = 0x2,
	ACC_BUF_TYPE_BUTT
};

/**
 * @brief rde operation enumeration.
 */
enum ACC_OPT_RAID_E {
	ACC_OPT_GEN = 0x0, /*generate*/
	ACC_OPT_VLD = 0x1, /*validate*/
	ACC_OPT_UPD = 0x2, /*update*/
	ACC_OPT_RCT = 0x3, /*reconstruct*/
	ACC_OPT_RAID_BUTT
};

/**
 * @brief input addr type mode
 * @note
 * value 0 means input virt addr from
 * kzalloc/get_free_pages/dma_alloc_coherent
 * value 1 means input phy addr directly without tranform
 * value 2 means input virt addr from vmalloc,
 *	and this addr type only supports pbuf data store mode
 *	in smmu bypass mode
 */
enum ACC_ADDR_TYPE_E {
	VA_FROM_NORMAL_DMA_ZONE = 0x0,
	PA_PASS_THROUGH = 0x1,
	VA_FROM_HIGHMEM_ZONE = 0x2,
	ACC_ADDR_TYPE_BUTT
};

/**
 * @brief WRR sched, weights is 1:2:3:4:5:6:7:8:9:10:11:12:13:14:15:16.
 */
enum ACC_PRT_E {
	ACC_PRT_WEIGHTS_1 = 0x0,
	ACC_PRT_WEIGHTS_2,
	ACC_PRT_WEIGHTS_3,
	ACC_PRT_WEIGHTS_4,
	ACC_PRT_WEIGHTS_5,
	ACC_PRT_WEIGHTS_6,
	ACC_PRT_WEIGHTS_7,
	ACC_PRT_WEIGHTS_8,
	ACC_PRT_WEIGHTS_9,
	ACC_PRT_WEIGHTS_10,
	ACC_PRT_WEIGHTS_11,
	ACC_PRT_WEIGHTS_12,
	ACC_PRT_WEIGHTS_13,
	ACC_PRT_WEIGHTS_14,
	ACC_PRT_WEIGHTS_15,
	ACC_PRT_WEIGHTS_16,
	ACC_PRT_BUTT,
};

/**
 * @brief sge structure, should fill buf and len.
 * @note
 * usually, just need to fill buf and len
 */
struct sgl_entry_hw {
	char *buf; /* page data start address, 64bit */
	void *page_ctrl;
	uint32_t len; /* valid data len, Byte*/
	uint32_t pad;
	uint32_t pad0;
	uint32_t pad1;
};

/**
 * @brief sgl  structure.
 * @note
 * usually, just need to  fill next, entry_sum_in_chain, entry_sum_in_sgl,
 *	entry_num_in_sgl and entry
 * entry_sum_in_chain is valid from the first sgl
 * entry_sum_in_sgl <= entry_num_in_sgl
 * sgl_entry point is determined by entry_sum_in_sgl
 */
struct sgl_hw {
	/*next sgl point, to make up chain, 64bit */
	struct sgl_hw *next;
	/*sum of entry_sum_in_sgl in sgl chain*/
	uint16_t entry_sum_in_chain;
	/*valid sgl_entry num in this sgl*/
	uint16_t entry_sum_in_sgl;
	/*sgl_entry num in this sgl*/
	uint16_t entry_num_in_sgl;
	uint8_t pad0[2];
	uint64_t serial_num;
	uint32_t flag;
	uint32_t cpu_id;
	uint8_t pad1[8];
	uint8_t reserved[24];
	/*sgl_entry point*/
	struct sgl_entry_hw entries[0];
};

/**
 * @brief sgl structure for rde.
 * @note
 * parity is just valid in update mode
 */
struct rde_sgl {
	/*source and destination data block SGL address*/
	struct sgl_hw *ctrl;
	/*offset of per data disk in the SGL chain*/
	uint32_t buf_offset;
	/*data disk is 0, parity disk is 1*/
	uint8_t parity;
	uint8_t reserve;
	/*the index corresponding to src and dst disk*/
	uint16_t column;
};

/**
 * @brief pbuf structure for rde.
 * @note
 * parity is just valid in update mode
 */
struct rde_pbuf {
	char *pbuf;
	uint32_t reserve1;
	uint8_t parity;
	uint8_t reserve2;
	uint16_t column;
};

/**
 * @brief dif data structure.
 */
struct dif_data {
	uint16_t grd;  /*16bit gurad tag*/
	uint8_t ver;   /*8bit version*/
	uint8_t app;   /*8bit application information field*/
	uint32_t ref;  /* 32bit reference tag*/
};

/**
 * @brief dif gen ctrl structure.
 */
struct dif_gen {
	/* DIF_PAGE_LAYOUT_PAD_GEN_CTRL_E */
	uint32_t page_layout_gen_type:4;
	/* DIF_GRD_GEN_CTRL_E */
	uint32_t grd_gen_type:4;
	/* DIF_VER_GEN_CTRL_E */
	uint32_t ver_gen_type:4;
	/* DIF_APP_GEN_CTRL_E */
	uint32_t app_gen_type:4;
	/* DIF_REF_GEN_CTRL_E */
	uint32_t ref_gen_type:4;
	/* DIF_PAGE_LAYOUT_PAD_TYPE_E */
	uint32_t page_layout_pad_type:2;
	uint32_t reserved:10;
};

/**
 * @brief dif verify ctrl structure.
 * @note
 * just need to fill grd_verify_type and ref_verify_type
 */
struct dif_verify {
	uint16_t page_layout_pad_type:2;
	uint16_t grd_verify_type:4; /*DIF_VERIFY_CTRL_E */
	uint16_t ref_verify_type:4; /* DIF_VERIFY_CTRL_E */
	uint16_t reserved:6;
};

/**
 * @brief dif ctrl structure.
 */
struct dif_ctrl {
	struct dif_gen gen;
	struct dif_verify verify;
};

/**
 * @brief general dif structure.
 * @note
 * RDE need not to fill lba
 */
struct acc_dif {
	uint64_t lba; /*lba for dif ref field*/
	uint32_t priv; /*private info for dif ref field*/
	uint8_t ver; /*8bit version*/
	uint8_t app; /*8bit application information field*/
	struct dif_ctrl ctrl;
};

/**
 * @brief ctrl information for per request,
 * user should alloc and init this structure.
 * @note
 * only mpcc support mem_saving mode, no mem_saving is 0x0, mem_saving is 0x1
 */
struct raid_ec_ctrl {
	/*src data address, reference rde data structure*/
	void *src_data;
	/*dst data address, reference rde data structure*/
	void *dst_data;
	/*number of source disks*/
	uint32_t src_num;
	/*number of dst disks*/
	uint32_t dst_num;
	/*support 512,520,4096,4104,4160*/
	uint32_t block_size;
	/*number of sector*/
	uint32_t input_block;
	/*data len of per disk, block_size (with dif)* input_block*/
	uint32_t data_len;
	/*ACC_BUF_TYPE_E*/
	uint32_t buf_type;
	/*dif information of source disks*/
	struct acc_dif src_dif;
	/*dif information of dest disks*/
	struct acc_dif dst_dif;
	/*coe_matrix reload control, 0: do not load, 1: load*/
	uint8_t cm_load;
	/*length of loaded coe_matrix, equal to src_num*/
	uint8_t cm_len;
	/*algorithm granularity, 0: 512 gran, 1: 4096 gran*/
	uint8_t alg_blk_size;
	/*mem saving or not, default 0*/
	uint8_t mem_saving;
	/*coe matrix address, should be 64byte aligned*/
	void *coe_matrix;
	void *priv;	/*design for user*/
};

/**
 * @brief acc_callback of user.
 * @note
 * ctx means struct acc_ctx
 * tag means struct raid_ec_ctrl
 */
typedef void (*acc_callback)(void *ctx, void *tag, int status, size_t len);

/**
 * @brief acc ctx structure, acc_init api will init this structure
 */
struct acc_ctx {
	/*reserved for SDK to point to hisi_rde_ctx structure*/
	void *inner;
	/*callback function for pool and asynchronously api  */
	acc_callback cb;
	/*ACC_PRT_E */
	uint8_t priority;
	/*ACC_ADDR_TYPE_E*/
	uint8_t addr_type;
};

/**
 *
 * @brief set T10 CRC seed.
 *
 * @param [in] seed T10 CRC seed.
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 *
 */
int acc_set_pi_crc_seed(uint16_t seed);

/**
 *
 * @brief set the PRP page size.
 *
 * @param [in] page_size typical values: 4096 bytes, 8192 bytes.
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 * Not supported yet
 *
 */
int acc_set_prp_mem_page_size(uint32_t page_size_byte);

/**
 *
 * @brief set the offset of SGE related to SGL.
 *
 * @param [in] offset typical values: 32 bytes, 64 bytes.
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 * Not supported yet
 *
 */
int acc_set_sge_offset_from_sgl(uint32_t offset_byte);

/**
 *
 * @brief initialization before you call the other api.
 *
 * @param [in] ctx is the context which manage the instance.
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 * Be sure you will fill para cb and addr_type, then call this function.
 *
 */
int acc_init(struct acc_ctx *ctx);

/**
 *
 * @brief reconfig callback of ctx.
 *
 * @param [in] ctx is the context which manage the instance.
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 *
 */
int acc_setup_callback(struct acc_ctx *ctx, acc_callback cb);

/**
 *
 * @brief release resource that alloced by acc_init().
 *
 * @param [in] ctx is the context which manage the instance.
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 *
 */
int acc_clear(struct acc_ctx *ctx);

/**
 *
 * @brief flexec/raid5/raid6 operation asynchronously.
 *
 * @param [in] ctx is the context which manage the instance.
 * @param [in] ctrl is the parameter data of current io.
 * @param [in] op_type is from ACC_OPT_RAID_E
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 *Multiple concurrent processing is not supported for the same instance.
 */
int acc_do_flexec_asyn(struct acc_ctx *ctx,
	struct raid_ec_ctrl *ctrl, uint8_t op_type);

/**
 *
 * @brief mpcc operation asynchronously.
 *
 * @param [in] ctx is the context which manage the instance.
 * @param [in] ctrl is the parameter data of current io.
 * @param [in] op_type is from ACC_OPT_RAID_E
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 *Multiple concurrent processing is not supported for the same instance.
 */
int acc_do_mpcc_asyn(struct acc_ctx *ctx,
	struct raid_ec_ctrl *ctrl, uint8_t op_type);

/**
 *
 * @brief flexec/raid5/raid6 operation synchronously.
 *
 * @param [in] ctx is the context which manage the instance.
 * @param [in] ctrl is the parameter data of current io.
 * @param [in] op_type is from ACC_OPT_RAID_E
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 *Multiple concurrent processing is not supported for the same instance.
 */
int acc_do_flexec(struct acc_ctx *ctx,
	struct raid_ec_ctrl *ctrl, uint8_t op_type);

/**
 *
 * @brief mpcc operation synchronously.
 *
 * @param [in] ctx is the context which manage the instance.
 * @param [in] ctrl is the parameter data of current io.
 * @param [in] op_type is from ACC_OPT_RAID_E
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 *Multiple concurrent processing is not supported for the same instance.
 */
int acc_do_mpcc(struct acc_ctx *ctx,
	struct raid_ec_ctrl *ctrl, uint8_t op_type);

#endif /* __ACC_API_H__ */
