/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018-2019 HiSilicon Limited. */

#ifndef __HISI_SEC_V2_CRYPTO_H
#define __HISI_SEC_V2_CRYPTO_H

#define SEC_AIV_SIZE 12
#define SEC_IV_SIZE 24
#define SEC_MAX_KEY_SIZE 64
#define SEC_COMM_SCENE  0
#define SEC_IPSEC_SCENE 1
#define SEC_STREAM_SCENE    0X7
#define SEC_MAX_STREAMS 128
#define SEC_SHA1_ALIGN_SZ   64
#define SEC_MAX_SG_OF_REMAIN    8
#define PINGPONG_BUF_NUM    2
#define SEC_MIN_BLOCK_SZ    1
#define MERGE_SGL_NUM       2

enum sec_calg {
    SEC_CALG_3DES = 0x1;
    SEC_CALG_AES  = 0x2;
    SEC_CALG_SM4  = 0x3;
};

enum sec_hash_alg {
    SEC_A_HMAC_SHA1     = 0x10,
    SEC_A_HMAC_SHA256   = 0x11,
    SEC_A_HMAC_MD5      = 0x12,
    SEC_A_HMAC_SHA512   = 0x15,
    SEC_A_HMAC_SM3      = 0x26,
};

enum sec_mac_len {
    SEC_HMAC_CCM_MAC    = 16,
    SEC_HMAC_GCM_MAC    = 16,
    SEC_SM3_MAC         = 32,
    SEC_HMAC_SM3_MAC    = 32,
    SEC_HMAC_MD5_MAC    = 16,
    SEC_HMAC_SHA1_MAC   = 20,
    SEC_HMAC_SHA256_MAC = 32,
    SEC_HMAC_SHA512_MAC = 64,
};

enum sec_cmode {
    SEC_CMODE_ECB   = 0x0,
    SEC_CMODE_CBC   = 0x1,
    SEC_CMODE_CFB   = 0x2,
    SEC_CMODE_OFB   = 0x3,
    SEC_CMODE_CTR   = 0x4,
    SEC_CMODE_CCM   = 0x5,
    SEC_CMODE_GCM   = 0x6,
    SEC_CMODE_XTS   = 0x7,
};

enum sec_ckey_type {
    SEC_CKEY_128BIT = 0x0,
    SEC_CKEY_192BIT = 0x1,
    SEC_CKEY_256BIT = 0x2,
    SEC_CKEY_3DES_3KEY = 0x1,
    SEC_CKEY_3DES_2KEY = 0x3,
};

enum sec_bd_type {
    SEC_BD_TYPE1 = 0x1,
    SEC_BD_TYPE2 = 0x2,
    SEC_BD_TYPE3 = 0x3,
};

enum sec_auth {
    SEC_NO_AUTH = 0x0,
    SEC_AUTH_TYPE1 = 0x1,
    SEC_AUTH_TYPE2 = 0x2,
};

enum sec_cipher_dir {
    SEC_CIPHER_ENC = 0x1,
    SEC_CIPHER_DEC = 0x2,
};

enum sec_addr_type {
    SEC_PBUF = 0x0,
    SEC_SGL  = 0x1,
    SEC_PRP  = 0x2,
};

struct bd_status {
    u64 tag;
    u8 done;
    u8 err_type;
    u16 flag;
    u16 icv;
};

enum {
    AUTHPAD_PAD,
    AUTHPAD_NOPAD,
};


struct sec_sqe_type2 {
	__le32 mac_key_alg;
    __le16 icvw_kmode;
    __u8 c_alg;
    __u8 rsvd4;
    __le32 alen_ivllen;
    __le32 clen_ivllen;
    __le16 auth_src_offset;
    __le16 cipher_src_offset;
    __le16 cs_ip_header_offset;
    __le16 cs_udp_header_offset;
    __le16 pass_word_len;
    __le16 dk_len;
    __u8 salt3;
    __u8 salt2;
    __u8 salt1;
    __u8 salt0;

    __le16 tag;
    __le16 rsvd5;
    __le16 cph_pad;
    __le16 c_pad_len_field;

    __le64 long_a_data_len;
    __le64 a_ivin_addr;
    __le64 a_key_addr;
    __le64 mac_addr;
    __le64 c_ivin_addr;
    __le64 c_key_addr;
    __le64 data_src_addr;
    __le64 data_dst_addr;

    __le16 done_flag;

    __u8 error_type;
    __u8 warning_type;
    __u8 mac_i3;
    __u8 mac_i2;
    __u8 mac_i1;
    __u8 mac_i0;
    __le16 check_sum_i;
    __u8 tls_pad_len_i;
    __u8 rsvd12;
    __le32 counter;
};

struct sec_sqe {
	__u8 type_cipher_auth;
	__u8 sds_sa_type;
	__u8 sdm_addr_type;
	__u8 rsvd0;
	__u8 huk_key_ci;
	__u8 ai_apd_cs;
	__u8 rca_key_frm;
	__u8 iv_tls_ld;
	struct sec_sqe_type2 type2;
};

struct bd3_auth_ivin {
    __le64 a_ivin_addr;
    __le32 rsvd0;
    __le32 rsvd1;
} __packed __aligned(4);

struct bd3_skip_data {
    __le32 rsvd0;
    __le32 gran_num;
    __le32 src_skip_data_len;
    __le32 dst_skip_data_len;
};

struct bd3_stream_scene {
    __le64 c_ivin_addr;
    __le64 long_a_data_len;
    __u8 stream_auth_pad;
    __u8 plaintext_type;
    __le16 pad_len_1p3;
} __packed __aligned(4);

struct bd3_no_scene {
    __le64 c_ivin_addr;
    __le32 rsvd0;
    __le32 rsvd1;
    __le32 rsvd2;
} __packed __aligned(4);

struct bd3_check_sum {
    __u8 rsvd0;
    __u8 hac_sva_status;
    __le16 check_sum_i;
};

struct bd3_tls_type_back {
    __u8 tls_1p3_type_back;
    __u8 hac_sva_status;
    __le16 pad_len_1p3_back;
};

struct sec_sqe3 {
    __le32 bd_param;
    __le16 c_icv_key;
    __u8 c_mode_alg;
    __u8 huk_iv_seq;

    __le64 tag;
    __le64 data_src_addr;
    __le64 a_key_addr;

    union{
        struct bd3_auth_ivin auth_ivin;
        struct bd3_skip_data skip_data;
    };

    __le64 c_key_addr;
    __le32 auth_mac_key;
    __le32 salt;
    __le16 auth_src_offset;
    __le16 cipher_src_offset;
    __le32 a_len_key;
    __le32 clen_ivin;
    __le64 data_dst_addr;
    __le64 mac_addr;
    union {
        struct bd3_stream_scene stream_scene;
        struct bd3_no_scene no_scene;
    };

    __le16 done_flag;
    __u8 error_type;
    __u8 warning_type;
    union {
        __le32 mac_i;
        __le32 kek_key_addr_l;
    };
    union {
        __le32 kek_key_addr_h;
        struct bd3_check_sum check_sum;
        struct bd3_tls_type_back tls_type_back;
    };
    __le32 counter;
} __packed __aligned(4);

int sec_register_to_crypto(struct hisi_qm *qm);
void sec_unregister_from_crypto(struct hisi_qm *qm);

#endif
