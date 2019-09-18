/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Cavium, Inc
 */

#ifndef _CPT_MCODE_DEFINES_H_
#define _CPT_MCODE_DEFINES_H_

#include <rte_byteorder.h>
#include <rte_memory.h>

/*
 * This file defines macros and structures according to microcode spec
 *
 */
/* SE opcodes */
#define CPT_MAJOR_OP_FC		0x33
#define CPT_MAJOR_OP_HASH	0x34
#define CPT_MAJOR_OP_HMAC	0x35
#define CPT_MAJOR_OP_ZUC_SNOW3G	0x37
#define CPT_MAJOR_OP_KASUMI	0x38
#define CPT_MAJOR_OP_MISC	0x01

#define CPT_BYTE_16		16
#define CPT_BYTE_24		24
#define CPT_BYTE_32		32
#define CPT_MAX_SG_IN_OUT_CNT	32
#define CPT_MAX_SG_CNT		(CPT_MAX_SG_IN_OUT_CNT/2)

#define COMPLETION_CODE_SIZE	8
#define COMPLETION_CODE_INIT	0

#define SG_LIST_HDR_SIZE	(8u)
#define SG_ENTRY_SIZE		sizeof(sg_comp_t)

#define CPT_DMA_MODE		(1 << 7)

#define CPT_FROM_CTX		0
#define CPT_FROM_DPTR		1

#define FC_GEN			0x1
#define ZUC_SNOW3G		0x2
#define KASUMI			0x3
#define HASH_HMAC		0x4

#define ZS_EA			0x1
#define ZS_IA			0x2
#define K_F8			0x4
#define K_F9			0x8

#define CPT_OP_CIPHER_ENCRYPT	0x1
#define CPT_OP_CIPHER_DECRYPT	0x2
#define CPT_OP_CIPHER_MASK	0x3

#define CPT_OP_AUTH_VERIFY	0x4
#define CPT_OP_AUTH_GENERATE	0x8
#define CPT_OP_AUTH_MASK	0xC

#define CPT_OP_ENCODE	(CPT_OP_CIPHER_ENCRYPT | CPT_OP_AUTH_GENERATE)
#define CPT_OP_DECODE	(CPT_OP_CIPHER_DECRYPT | CPT_OP_AUTH_VERIFY)

/* #define CPT_ALWAYS_USE_SG_MODE */
#define CPT_ALWAYS_USE_SEPARATE_BUF

/*
 * Parameters for Flexi Crypto
 * requests
 */
#define VALID_AAD_BUF 0x01
#define VALID_MAC_BUF 0x02
#define VALID_IV_BUF 0x04
#define SINGLE_BUF_INPLACE 0x08
#define SINGLE_BUF_HEADTAILROOM 0x10

#define ENCR_IV_OFFSET(__d_offs) ((__d_offs >> 32) & 0xffff)
#define ENCR_OFFSET(__d_offs) ((__d_offs >> 16) & 0xffff)
#define AUTH_OFFSET(__d_offs) (__d_offs & 0xffff)
#define ENCR_DLEN(__d_lens) (__d_lens >> 32)
#define AUTH_DLEN(__d_lens) (__d_lens & 0xffffffff)

/* FC offset_control at start of DPTR in bytes */
#define OFF_CTRL_LEN  8 /**< bytes */

typedef enum {
	MD5_TYPE        = 1,
	SHA1_TYPE       = 2,
	SHA2_SHA224     = 3,
	SHA2_SHA256     = 4,
	SHA2_SHA384     = 5,
	SHA2_SHA512     = 6,
	GMAC_TYPE       = 7,
	XCBC_TYPE       = 8,
	SHA3_SHA224     = 10,
	SHA3_SHA256     = 11,
	SHA3_SHA384     = 12,
	SHA3_SHA512     = 13,
	SHA3_SHAKE256   = 14,
	SHA3_SHAKE512   = 15,

	/* These are only for software use */
	ZUC_EIA3        = 0x90,
	SNOW3G_UIA2     = 0x91,
	KASUMI_F9_CBC   = 0x92,
	KASUMI_F9_ECB   = 0x93,
} mc_hash_type_t;

typedef enum {
	/* To support passthrough */
	PASSTHROUGH  = 0x0,
	/*
	 * These are defined by MC for Flexi crypto
	 * for field of 4 bits
	 */
	DES3_CBC    = 0x1,
	DES3_ECB    = 0x2,
	AES_CBC     = 0x3,
	AES_ECB     = 0x4,
	AES_CFB     = 0x5,
	AES_CTR     = 0x6,
	AES_GCM     = 0x7,
	AES_XTS     = 0x8,

	/* These are only for software use */
	ZUC_EEA3        = 0x90,
	SNOW3G_UEA2     = 0x91,
	KASUMI_F8_CBC   = 0x92,
	KASUMI_F8_ECB   = 0x93,
} mc_cipher_type_t;

typedef enum {
	AES_128_BIT = 0x1,
	AES_192_BIT = 0x2,
	AES_256_BIT = 0x3
} mc_aes_type_t;

typedef enum {
	/* Microcode errors */
	NO_ERR = 0x00,
	ERR_OPCODE_UNSUPPORTED = 0x01,

	/* SCATTER GATHER */
	ERR_SCATTER_GATHER_WRITE_LENGTH = 0x02,
	ERR_SCATTER_GATHER_LIST = 0x03,
	ERR_SCATTER_GATHER_NOT_SUPPORTED = 0x04,

	/* SE GC */
	ERR_GC_LENGTH_INVALID = 0x41,
	ERR_GC_RANDOM_LEN_INVALID = 0x42,
	ERR_GC_DATA_LEN_INVALID = 0x43,
	ERR_GC_DRBG_TYPE_INVALID = 0x44,
	ERR_GC_CTX_LEN_INVALID = 0x45,
	ERR_GC_CIPHER_UNSUPPORTED = 0x46,
	ERR_GC_AUTH_UNSUPPORTED = 0x47,
	ERR_GC_OFFSET_INVALID = 0x48,
	ERR_GC_HASH_MODE_UNSUPPORTED = 0x49,
	ERR_GC_DRBG_ENTROPY_LEN_INVALID = 0x4a,
	ERR_GC_DRBG_ADDNL_LEN_INVALID = 0x4b,
	ERR_GC_ICV_MISCOMPARE = 0x4c,
	ERR_GC_DATA_UNALIGNED = 0x4d,

	/* API Layer */
	ERR_BAD_ALT_CCODE = 0xfd,
	ERR_REQ_PENDING = 0xfe,
	ERR_REQ_TIMEOUT = 0xff,

	ERR_BAD_INPUT_LENGTH = (0x40000000 | 384),    /* 0x40000180 */
	ERR_BAD_KEY_LENGTH,
	ERR_BAD_KEY_HANDLE,
	ERR_BAD_CONTEXT_HANDLE,
	ERR_BAD_SCALAR_LENGTH,
	ERR_BAD_DIGEST_LENGTH,
	ERR_BAD_INPUT_ARG,
	ERR_BAD_RECORD_PADDING,
	ERR_NB_REQUEST_PENDING,
	ERR_EIO,
	ERR_ENODEV,
} mc_error_code_t;

/**
 * Enumeration cpt_comp_e
 *
 * CPT Completion Enumeration
 * Enumerates the values of CPT_RES_S[COMPCODE].
 */
typedef enum {
	CPT_8X_COMP_E_NOTDONE    = (0x00),
	CPT_8X_COMP_E_GOOD       = (0x01),
	CPT_8X_COMP_E_FAULT      = (0x02),
	CPT_8X_COMP_E_SWERR      = (0x03),
	CPT_8X_COMP_E_HWERR      = (0x04),
	CPT_8X_COMP_E_LAST_ENTRY = (0xFF)
} cpt_comp_e_t;

typedef struct sglist_comp {
	union {
		uint64_t len;
		struct {
			uint16_t len[4];
		} s;
	} u;
	uint64_t ptr[4];
} sg_comp_t;

struct cpt_sess_misc {
	/** CPT opcode */
	uint16_t cpt_op:4;
	/** ZUC, SNOW3G &  KASUMI flags */
	uint16_t zsk_flag:4;
	/** Flag for AES GCM */
	uint16_t aes_gcm:1;
	/** Flag for AES CTR */
	uint16_t aes_ctr:1;
	/** Flag for NULL cipher/auth */
	uint16_t is_null:1;
	/** Flag for GMAC */
	uint16_t is_gmac:1;
	/** AAD length */
	uint16_t aad_length;
	/** MAC len in bytes */
	uint8_t mac_len;
	/** IV length in bytes */
	uint8_t iv_length;
	/** Auth IV length in bytes */
	uint8_t auth_iv_length;
	/** Reserved field */
	uint8_t rsvd1;
	/** IV offset in bytes */
	uint16_t iv_offset;
	/** Auth IV offset in bytes */
	uint16_t auth_iv_offset;
	/** Salt */
	uint32_t salt;
	/** Context DMA address */
	phys_addr_t ctx_dma_addr;
};

typedef union {
	uint64_t flags;
	struct {
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
		uint64_t enc_cipher   : 4;
		uint64_t reserved1    : 1;
		uint64_t aes_key      : 2;
		uint64_t iv_source    : 1;
		uint64_t hash_type    : 4;
		uint64_t reserved2    : 3;
		uint64_t auth_input_type : 1;
		uint64_t mac_len      : 8;
		uint64_t reserved3    : 8;
		uint64_t encr_offset  : 16;
		uint64_t iv_offset    : 8;
		uint64_t auth_offset  : 8;
#else
		uint64_t auth_offset  : 8;
		uint64_t iv_offset    : 8;
		uint64_t encr_offset  : 16;
		uint64_t reserved3    : 8;
		uint64_t mac_len      : 8;
		uint64_t auth_input_type : 1;
		uint64_t reserved2    : 3;
		uint64_t hash_type    : 4;
		uint64_t iv_source    : 1;
		uint64_t aes_key      : 2;
		uint64_t reserved1    : 1;
		uint64_t enc_cipher   : 4;
#endif
	} e;
} encr_ctrl_t;

typedef struct {
	encr_ctrl_t enc_ctrl;
	uint8_t  encr_key[32];
	uint8_t  encr_iv[16];
} mc_enc_context_t;

typedef struct {
	uint8_t  ipad[64];
	uint8_t  opad[64];
} mc_fc_hmac_context_t;

typedef struct {
	mc_enc_context_t     enc;
	mc_fc_hmac_context_t hmac;
} mc_fc_context_t;

typedef struct {
	uint8_t encr_auth_iv[16];
	uint8_t ci_key[16];
	uint8_t zuc_const[32];
} mc_zuc_snow3g_ctx_t;

typedef struct {
	uint8_t reg_A[8];
	uint8_t ci_key[16];
} mc_kasumi_ctx_t;

struct cpt_ctx {
	/* Below fields are accessed by sw */
	uint64_t enc_cipher	:8;
	uint64_t hash_type	:8;
	uint64_t mac_len	:8;
	uint64_t auth_key_len	:8;
	uint64_t fc_type	:4;
	uint64_t hmac		:1;
	uint64_t zsk_flags	:3;
	uint64_t k_ecb		:1;
	uint64_t snow3g		:1;
	uint64_t rsvd		:22;
	/* Below fields are accessed by hardware */
	union {
		mc_fc_context_t fctx;
		mc_zuc_snow3g_ctx_t zs_ctx;
		mc_kasumi_ctx_t k_ctx;
	};
	uint8_t  auth_key[64];
};

/* Buffer pointer */
typedef struct buf_ptr {
	void *vaddr;
	phys_addr_t dma_addr;
	uint32_t size;
	uint32_t resv;
} buf_ptr_t;

/* IOV Pointer */
typedef struct{
	int buf_cnt;
	buf_ptr_t bufs[0];
} iov_ptr_t;

typedef union opcode_info {
	uint16_t flags;
	struct {
		uint8_t major;
		uint8_t minor;
	} s;
} opcode_info_t;

typedef struct fc_params {
	/* 0th cache line */
	union {
		buf_ptr_t bufs[1];
		struct {
			iov_ptr_t *src_iov;
			iov_ptr_t *dst_iov;
		};
	};
	void *iv_buf;
	void *auth_iv_buf;
	buf_ptr_t meta_buf;
	buf_ptr_t ctx_buf;
	uint64_t rsvd2;

	/* 1st cache line */
	buf_ptr_t aad_buf;
	buf_ptr_t mac_buf;

} fc_params_t;

/*
 * Parameters for digest
 * generate requests
 * Only src_iov, op, ctx_buf, mac_buf, prep_req
 * meta_buf, auth_data_len are used for digest gen.
 */
typedef struct fc_params digest_params_t;

/* Cipher Algorithms */
typedef mc_cipher_type_t cipher_type_t;

/* Auth Algorithms */
typedef mc_hash_type_t auth_type_t;

/* Helper macros */

#define CPT_P_ENC_CTRL(fctx)  fctx->enc.enc_ctrl.e

#define SRC_IOV_SIZE \
	(sizeof(iov_ptr_t) + (sizeof(buf_ptr_t) * CPT_MAX_SG_CNT))
#define DST_IOV_SIZE \
	(sizeof(iov_ptr_t) + (sizeof(buf_ptr_t) * CPT_MAX_SG_CNT))

#define SESS_PRIV(__sess) \
	(void *)((uint8_t *)__sess + sizeof(struct cpt_sess_misc))

#endif /* _CPT_MCODE_DEFINES_H_ */
