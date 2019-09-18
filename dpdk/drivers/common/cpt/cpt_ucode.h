/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Cavium, Inc
 */

#ifndef _CPT_UCODE_H_
#define _CPT_UCODE_H_
#include <stdbool.h>

#include "cpt_common.h"
#include "cpt_hw_types.h"
#include "cpt_mcode_defines.h"

/*
 * This file defines functions that are interfaces to microcode spec.
 *
 */

static uint8_t zuc_d[32] = {
	0x44, 0xD7, 0x26, 0xBC, 0x62, 0x6B, 0x13, 0x5E,
	0x57, 0x89, 0x35, 0xE2, 0x71, 0x35, 0x09, 0xAF,
	0x4D, 0x78, 0x2F, 0x13, 0x6B, 0xC4, 0x1A, 0xF1,
	0x5E, 0x26, 0x3C, 0x4D, 0x78, 0x9A, 0x47, 0xAC
};

static __rte_always_inline int
cpt_is_algo_supported(struct rte_crypto_sym_xform *xform)
{
	/*
	 * Microcode only supports the following combination.
	 * Encryption followed by authentication
	 * Authentication followed by decryption
	 */
	if (xform->next) {
		if ((xform->type == RTE_CRYPTO_SYM_XFORM_AUTH) &&
		    (xform->next->type == RTE_CRYPTO_SYM_XFORM_CIPHER) &&
		    (xform->next->cipher.op == RTE_CRYPTO_CIPHER_OP_ENCRYPT)) {
			/* Unsupported as of now by microcode */
			CPT_LOG_DP_ERR("Unsupported combination");
			return -1;
		}
		if ((xform->type == RTE_CRYPTO_SYM_XFORM_CIPHER) &&
		    (xform->next->type == RTE_CRYPTO_SYM_XFORM_AUTH) &&
		    (xform->cipher.op == RTE_CRYPTO_CIPHER_OP_DECRYPT)) {
			/* For GMAC auth there is no cipher operation */
			if (xform->aead.algo != RTE_CRYPTO_AEAD_AES_GCM ||
			    xform->next->auth.algo !=
			    RTE_CRYPTO_AUTH_AES_GMAC) {
				/* Unsupported as of now by microcode */
				CPT_LOG_DP_ERR("Unsupported combination");
				return -1;
			}
		}
	}
	return 0;
}

static __rte_always_inline void
gen_key_snow3g(uint8_t *ck, uint32_t *keyx)
{
	int i, base;

	for (i = 0; i < 4; i++) {
		base = 4 * i;
		keyx[3 - i] = (ck[base] << 24) | (ck[base + 1] << 16) |
			(ck[base + 2] << 8) | (ck[base + 3]);
		keyx[3 - i] = rte_cpu_to_be_32(keyx[3 - i]);
	}
}

static __rte_always_inline void
cpt_fc_salt_update(void *ctx,
		   uint8_t *salt)
{
	struct cpt_ctx *cpt_ctx = ctx;
	memcpy(&cpt_ctx->fctx.enc.encr_iv, salt, 4);
}

static __rte_always_inline int
cpt_fc_ciph_validate_key_aes(uint16_t key_len)
{
	switch (key_len) {
	case CPT_BYTE_16:
	case CPT_BYTE_24:
	case CPT_BYTE_32:
		return 0;
	default:
		return -1;
	}
}

static __rte_always_inline int
cpt_fc_ciph_validate_key(cipher_type_t type, struct cpt_ctx *cpt_ctx,
		uint16_t key_len)
{
	int fc_type = 0;
	switch (type) {
	case PASSTHROUGH:
		fc_type = FC_GEN;
		break;
	case DES3_CBC:
	case DES3_ECB:
		fc_type = FC_GEN;
		break;
	case AES_CBC:
	case AES_ECB:
	case AES_CFB:
	case AES_CTR:
	case AES_GCM:
		if (unlikely(cpt_fc_ciph_validate_key_aes(key_len) != 0))
			return -1;
		fc_type = FC_GEN;
		break;
	case AES_XTS:
		key_len = key_len / 2;
		if (unlikely(key_len == CPT_BYTE_24)) {
			CPT_LOG_DP_ERR("Invalid AES key len for XTS");
			return -1;
		}
		if (unlikely(cpt_fc_ciph_validate_key_aes(key_len) != 0))
			return -1;
		fc_type = FC_GEN;
		break;
	case ZUC_EEA3:
	case SNOW3G_UEA2:
		if (unlikely(key_len != 16))
			return -1;
		/* No support for AEAD yet */
		if (unlikely(cpt_ctx->hash_type))
			return -1;
		fc_type = ZUC_SNOW3G;
		break;
	case KASUMI_F8_CBC:
	case KASUMI_F8_ECB:
		if (unlikely(key_len != 16))
			return -1;
		/* No support for AEAD yet */
		if (unlikely(cpt_ctx->hash_type))
			return -1;
		fc_type = KASUMI;
		break;
	default:
		return -1;
	}
	return fc_type;
}

static __rte_always_inline void
cpt_fc_ciph_set_key_passthrough(struct cpt_ctx *cpt_ctx, mc_fc_context_t *fctx)
{
	cpt_ctx->enc_cipher = 0;
	CPT_P_ENC_CTRL(fctx).enc_cipher = 0;
}

static __rte_always_inline void
cpt_fc_ciph_set_key_set_aes_key_type(mc_fc_context_t *fctx, uint16_t key_len)
{
	mc_aes_type_t aes_key_type = 0;
	switch (key_len) {
	case CPT_BYTE_16:
		aes_key_type = AES_128_BIT;
		break;
	case CPT_BYTE_24:
		aes_key_type = AES_192_BIT;
		break;
	case CPT_BYTE_32:
		aes_key_type = AES_256_BIT;
		break;
	default:
		/* This should not happen */
		CPT_LOG_DP_ERR("Invalid AES key len");
		return;
	}
	CPT_P_ENC_CTRL(fctx).aes_key = aes_key_type;
}

static __rte_always_inline void
cpt_fc_ciph_set_key_snow3g_uea2(struct cpt_ctx *cpt_ctx, uint8_t *key,
		uint16_t key_len)
{
	uint32_t keyx[4];
	cpt_ctx->snow3g = 1;
	gen_key_snow3g(key, keyx);
	memcpy(cpt_ctx->zs_ctx.ci_key, keyx, key_len);
	cpt_ctx->fc_type = ZUC_SNOW3G;
	cpt_ctx->zsk_flags = 0;
}

static __rte_always_inline void
cpt_fc_ciph_set_key_zuc_eea3(struct cpt_ctx *cpt_ctx, uint8_t *key,
		uint16_t key_len)
{
	cpt_ctx->snow3g = 0;
	memcpy(cpt_ctx->zs_ctx.ci_key, key, key_len);
	memcpy(cpt_ctx->zs_ctx.zuc_const, zuc_d, 32);
	cpt_ctx->fc_type = ZUC_SNOW3G;
	cpt_ctx->zsk_flags = 0;
}

static __rte_always_inline void
cpt_fc_ciph_set_key_kasumi_f8_ecb(struct cpt_ctx *cpt_ctx, uint8_t *key,
		uint16_t key_len)
{
	cpt_ctx->k_ecb = 1;
	memcpy(cpt_ctx->k_ctx.ci_key, key, key_len);
	cpt_ctx->zsk_flags = 0;
	cpt_ctx->fc_type = KASUMI;
}

static __rte_always_inline void
cpt_fc_ciph_set_key_kasumi_f8_cbc(struct cpt_ctx *cpt_ctx, uint8_t *key,
		uint16_t key_len)
{
	memcpy(cpt_ctx->k_ctx.ci_key, key, key_len);
	cpt_ctx->zsk_flags = 0;
	cpt_ctx->fc_type = KASUMI;
}

static __rte_always_inline int
cpt_fc_ciph_set_key(void *ctx, cipher_type_t type, uint8_t *key,
		    uint16_t key_len, uint8_t *salt)
{
	struct cpt_ctx *cpt_ctx = ctx;
	mc_fc_context_t *fctx = &cpt_ctx->fctx;
	uint64_t *ctrl_flags = NULL;
	int fc_type;

	/* Validate key before proceeding */
	fc_type = cpt_fc_ciph_validate_key(type, cpt_ctx, key_len);
	if (unlikely(fc_type == -1))
		return -1;

	if (fc_type == FC_GEN) {
		cpt_ctx->fc_type = FC_GEN;
		ctrl_flags = (uint64_t *)&(fctx->enc.enc_ctrl.flags);
		*ctrl_flags = rte_be_to_cpu_64(*ctrl_flags);
		/*
		 * We need to always say IV is from DPTR as user can
		 * sometimes iverride IV per operation.
		 */
		CPT_P_ENC_CTRL(fctx).iv_source = CPT_FROM_DPTR;
	}

	switch (type) {
	case PASSTHROUGH:
		cpt_fc_ciph_set_key_passthrough(cpt_ctx, fctx);
		goto fc_success;
	case DES3_CBC:
		/* CPT performs DES using 3DES with the 8B DES-key
		 * replicated 2 more times to match the 24B 3DES-key.
		 * Eg. If org. key is "0x0a 0x0b", then new key is
		 * "0x0a 0x0b 0x0a 0x0b 0x0a 0x0b"
		 */
		if (key_len == 8) {
			/* Skipping the first 8B as it will be copied
			 * in the regular code flow
			 */
			memcpy(fctx->enc.encr_key+key_len, key, key_len);
			memcpy(fctx->enc.encr_key+2*key_len, key, key_len);
		}
		break;
	case DES3_ECB:
		/* For DES3_ECB IV need to be from CTX. */
		CPT_P_ENC_CTRL(fctx).iv_source = CPT_FROM_CTX;
		break;
	case AES_CBC:
	case AES_ECB:
	case AES_CFB:
	case AES_CTR:
		cpt_fc_ciph_set_key_set_aes_key_type(fctx, key_len);
		break;
	case AES_GCM:
		/* Even though iv source is from dptr,
		 * aes_gcm salt is taken from ctx
		 */
		if (salt) {
			memcpy(fctx->enc.encr_iv, salt, 4);
			/* Assuming it was just salt update
			 * and nothing else
			 */
			if (!key)
				goto fc_success;
		}
		cpt_fc_ciph_set_key_set_aes_key_type(fctx, key_len);
		break;
	case AES_XTS:
		key_len = key_len / 2;
		cpt_fc_ciph_set_key_set_aes_key_type(fctx, key_len);

		/* Copy key2 for XTS into ipad */
		memset(fctx->hmac.ipad, 0, sizeof(fctx->hmac.ipad));
		memcpy(fctx->hmac.ipad, &key[key_len], key_len);
		break;
	case SNOW3G_UEA2:
		cpt_fc_ciph_set_key_snow3g_uea2(cpt_ctx, key, key_len);
		goto success;
	case ZUC_EEA3:
		cpt_fc_ciph_set_key_zuc_eea3(cpt_ctx, key, key_len);
		goto success;
	case KASUMI_F8_ECB:
		cpt_fc_ciph_set_key_kasumi_f8_ecb(cpt_ctx, key, key_len);
		goto success;
	case KASUMI_F8_CBC:
		cpt_fc_ciph_set_key_kasumi_f8_cbc(cpt_ctx, key, key_len);
		goto success;
	default:
		break;
	}

	/* Only for FC_GEN case */

	/* For GMAC auth, cipher must be NULL */
	if (cpt_ctx->hash_type != GMAC_TYPE)
		CPT_P_ENC_CTRL(fctx).enc_cipher = type;

	memcpy(fctx->enc.encr_key, key, key_len);

fc_success:
	*ctrl_flags = rte_cpu_to_be_64(*ctrl_flags);

success:
	cpt_ctx->enc_cipher = type;

	return 0;
}

static __rte_always_inline uint32_t
fill_sg_comp(sg_comp_t *list,
	     uint32_t i,
	     phys_addr_t dma_addr,
	     uint32_t size)
{
	sg_comp_t *to = &list[i>>2];

	to->u.s.len[i%4] = rte_cpu_to_be_16(size);
	to->ptr[i%4] = rte_cpu_to_be_64(dma_addr);
	i++;
	return i;
}

static __rte_always_inline uint32_t
fill_sg_comp_from_buf(sg_comp_t *list,
		      uint32_t i,
		      buf_ptr_t *from)
{
	sg_comp_t *to = &list[i>>2];

	to->u.s.len[i%4] = rte_cpu_to_be_16(from->size);
	to->ptr[i%4] = rte_cpu_to_be_64(from->dma_addr);
	i++;
	return i;
}

static __rte_always_inline uint32_t
fill_sg_comp_from_buf_min(sg_comp_t *list,
			  uint32_t i,
			  buf_ptr_t *from,
			  uint32_t *psize)
{
	sg_comp_t *to = &list[i >> 2];
	uint32_t size = *psize;
	uint32_t e_len;

	e_len = (size > from->size) ? from->size : size;
	to->u.s.len[i % 4] = rte_cpu_to_be_16(e_len);
	to->ptr[i % 4] = rte_cpu_to_be_64(from->dma_addr);
	*psize -= e_len;
	i++;
	return i;
}

/*
 * This fills the MC expected SGIO list
 * from IOV given by user.
 */
static __rte_always_inline uint32_t
fill_sg_comp_from_iov(sg_comp_t *list,
		      uint32_t i,
		      iov_ptr_t *from, uint32_t from_offset,
		      uint32_t *psize, buf_ptr_t *extra_buf,
		      uint32_t extra_offset)
{
	int32_t j;
	uint32_t extra_len = extra_buf ? extra_buf->size : 0;
	uint32_t size = *psize - extra_len;
	buf_ptr_t *bufs;

	bufs = from->bufs;
	for (j = 0; (j < from->buf_cnt) && size; j++) {
		phys_addr_t e_dma_addr;
		uint32_t e_len;
		sg_comp_t *to = &list[i >> 2];

		if (!bufs[j].size)
			continue;

		if (unlikely(from_offset)) {
			if (from_offset >= bufs[j].size) {
				from_offset -= bufs[j].size;
				continue;
			}
			e_dma_addr = bufs[j].dma_addr + from_offset;
			e_len = (size > (bufs[j].size - from_offset)) ?
				(bufs[j].size - from_offset) : size;
			from_offset = 0;
		} else {
			e_dma_addr = bufs[j].dma_addr;
			e_len = (size > bufs[j].size) ?
				bufs[j].size : size;
		}

		to->u.s.len[i % 4] = rte_cpu_to_be_16(e_len);
		to->ptr[i % 4] = rte_cpu_to_be_64(e_dma_addr);

		if (extra_len && (e_len >= extra_offset)) {
			/* Break the data at given offset */
			uint32_t next_len = e_len - extra_offset;
			phys_addr_t next_dma = e_dma_addr + extra_offset;

			if (!extra_offset) {
				i--;
			} else {
				e_len = extra_offset;
				size -= e_len;
				to->u.s.len[i % 4] = rte_cpu_to_be_16(e_len);
			}

			/* Insert extra data ptr */
			if (extra_len) {
				i++;
				to = &list[i >> 2];
				to->u.s.len[i % 4] =
					rte_cpu_to_be_16(extra_buf->size);
				to->ptr[i % 4] =
					rte_cpu_to_be_64(extra_buf->dma_addr);

				/* size already decremented by extra len */
			}

			/* insert the rest of the data */
			if (next_len) {
				i++;
				to = &list[i >> 2];
				to->u.s.len[i % 4] = rte_cpu_to_be_16(next_len);
				to->ptr[i % 4] = rte_cpu_to_be_64(next_dma);
				size -= next_len;
			}
			extra_len = 0;

		} else {
			size -= e_len;
		}
		if (extra_offset)
			extra_offset -= size;
		i++;
	}

	*psize = size;
	return (uint32_t)i;
}

static __rte_always_inline int
cpt_digest_gen_prep(uint32_t flags,
		    uint64_t d_lens,
		    digest_params_t *params,
		    void *op,
		    void **prep_req)
{
	struct cpt_request_info *req;
	uint32_t size, i;
	int32_t m_size;
	uint16_t data_len, mac_len, key_len;
	auth_type_t hash_type;
	buf_ptr_t *meta_p;
	struct cpt_ctx *ctx;
	sg_comp_t *gather_comp;
	sg_comp_t *scatter_comp;
	uint8_t *in_buffer;
	uint32_t g_size_bytes, s_size_bytes;
	uint64_t dptr_dma, rptr_dma;
	vq_cmd_word0_t vq_cmd_w0;
	vq_cmd_word3_t vq_cmd_w3;
	void *c_vaddr, *m_vaddr;
	uint64_t c_dma, m_dma;
	opcode_info_t opcode;

	if (!params || !params->ctx_buf.vaddr)
		return ERR_BAD_INPUT_ARG;

	ctx = params->ctx_buf.vaddr;
	meta_p = &params->meta_buf;

	if (!meta_p->vaddr || !meta_p->dma_addr)
		return ERR_BAD_INPUT_ARG;

	if (meta_p->size < sizeof(struct cpt_request_info))
		return ERR_BAD_INPUT_ARG;

	m_vaddr = meta_p->vaddr;
	m_dma = meta_p->dma_addr;
	m_size = meta_p->size;

	/*
	 * Save initial space that followed app data for completion code &
	 * alternate completion code to fall in same cache line as app data
	 */
	m_vaddr = (uint8_t *)m_vaddr + COMPLETION_CODE_SIZE;
	m_dma += COMPLETION_CODE_SIZE;
	size = (uint8_t *)RTE_PTR_ALIGN((uint8_t *)m_vaddr, 16) -
		(uint8_t *)m_vaddr;
	c_vaddr = (uint8_t *)m_vaddr + size;
	c_dma = m_dma + size;
	size += sizeof(cpt_res_s_t);

	m_vaddr = (uint8_t *)m_vaddr + size;
	m_dma += size;
	m_size -= size;

	req = m_vaddr;

	size = sizeof(struct cpt_request_info);
	m_vaddr = (uint8_t *)m_vaddr + size;
	m_dma += size;
	m_size -= size;

	hash_type = ctx->hash_type;
	mac_len = ctx->mac_len;
	key_len = ctx->auth_key_len;
	data_len = AUTH_DLEN(d_lens);

	/*GP op header */
	vq_cmd_w0.u64 = 0;
	vq_cmd_w0.s.param2 = rte_cpu_to_be_16(((uint16_t)hash_type << 8));
	if (ctx->hmac) {
		opcode.s.major = CPT_MAJOR_OP_HMAC | CPT_DMA_MODE;
		vq_cmd_w0.s.param1 = rte_cpu_to_be_16(key_len);
		vq_cmd_w0.s.dlen =
			rte_cpu_to_be_16((data_len + ROUNDUP8(key_len)));
	} else {
		opcode.s.major = CPT_MAJOR_OP_HASH | CPT_DMA_MODE;
		vq_cmd_w0.s.param1 = 0;
		vq_cmd_w0.s.dlen = rte_cpu_to_be_16(data_len);
	}

	opcode.s.minor = 0;

	/* Null auth only case enters the if */
	if (unlikely(!hash_type && !ctx->enc_cipher)) {
		opcode.s.major = CPT_MAJOR_OP_MISC;
		/* Minor op is passthrough */
		opcode.s.minor = 0x03;
		/* Send out completion code only */
		vq_cmd_w0.s.param2 = rte_cpu_to_be_16(0x1);
	}

	vq_cmd_w0.s.opcode = rte_cpu_to_be_16(opcode.flags);

	/* DPTR has SG list */
	in_buffer = m_vaddr;
	dptr_dma = m_dma;

	((uint16_t *)in_buffer)[0] = 0;
	((uint16_t *)in_buffer)[1] = 0;

	/* TODO Add error check if space will be sufficient */
	gather_comp = (sg_comp_t *)((uint8_t *)m_vaddr + 8);

	/*
	 * Input gather list
	 */

	i = 0;

	if (ctx->hmac) {
		uint64_t k_dma = params->ctx_buf.dma_addr +
			offsetof(struct cpt_ctx, auth_key);
		/* Key */
		i = fill_sg_comp(gather_comp, i, k_dma, ROUNDUP8(key_len));
	}

	/* input data */
	size = data_len;
	if (size) {
		i = fill_sg_comp_from_iov(gather_comp, i, params->src_iov,
					  0, &size, NULL, 0);
		if (size) {
			CPT_LOG_DP_DEBUG("Insufficient dst IOV size, short"
					 " by %dB", size);
			return ERR_BAD_INPUT_ARG;
		}
	} else {
		/*
		 * Looks like we need to support zero data
		 * gather ptr in case of hash & hmac
		 */
		i++;
	}
	((uint16_t *)in_buffer)[2] = rte_cpu_to_be_16(i);
	g_size_bytes = ((i + 3) / 4) * sizeof(sg_comp_t);

	/*
	 * Output Gather list
	 */

	i = 0;
	scatter_comp = (sg_comp_t *)((uint8_t *)gather_comp + g_size_bytes);

	if (flags & VALID_MAC_BUF) {
		if (params->mac_buf.size < mac_len)
			return ERR_BAD_INPUT_ARG;

		size = mac_len;
		i = fill_sg_comp_from_buf_min(scatter_comp, i,
					      &params->mac_buf, &size);
	} else {
		size = mac_len;
		i = fill_sg_comp_from_iov(scatter_comp, i,
					  params->src_iov, data_len,
					  &size, NULL, 0);
		if (size) {
			CPT_LOG_DP_DEBUG("Insufficient dst IOV size, short by"
					 " %dB", size);
			return ERR_BAD_INPUT_ARG;
		}
	}

	((uint16_t *)in_buffer)[3] = rte_cpu_to_be_16(i);
	s_size_bytes = ((i + 3) / 4) * sizeof(sg_comp_t);

	size = g_size_bytes + s_size_bytes + SG_LIST_HDR_SIZE;

	/* This is DPTR len incase of SG mode */
	vq_cmd_w0.s.dlen = rte_cpu_to_be_16(size);

	m_vaddr = (uint8_t *)m_vaddr + size;
	m_dma += size;
	m_size -= size;

	/* cpt alternate completion address saved earlier */
	req->alternate_caddr = (uint64_t *)((uint8_t *)c_vaddr - 8);
	*req->alternate_caddr = ~((uint64_t)COMPLETION_CODE_INIT);
	rptr_dma = c_dma - 8;

	req->ist.ei1 = dptr_dma;
	req->ist.ei2 = rptr_dma;
	/* First 16-bit swap then 64-bit swap */
	/* TODO: HACK: Reverse the vq_cmd and cpt_req bit field definitions
	 * to eliminate all the swapping
	 */
	vq_cmd_w0.u64 = rte_cpu_to_be_64(vq_cmd_w0.u64);

	/* vq command w3 */
	vq_cmd_w3.u64 = 0;

	/* 16 byte aligned cpt res address */
	req->completion_addr = (uint64_t *)((uint8_t *)c_vaddr);
	*req->completion_addr = COMPLETION_CODE_INIT;
	req->comp_baddr  = c_dma;

	/* Fill microcode part of instruction */
	req->ist.ei0 = vq_cmd_w0.u64;
	req->ist.ei3 = vq_cmd_w3.u64;

	req->op = op;

	*prep_req = req;
	return 0;
}

static __rte_always_inline int
cpt_enc_hmac_prep(uint32_t flags,
		  uint64_t d_offs,
		  uint64_t d_lens,
		  fc_params_t *fc_params,
		  void *op,
		  void **prep_req)
{
	uint32_t iv_offset = 0;
	int32_t inputlen, outputlen, enc_dlen, auth_dlen;
	struct cpt_ctx *cpt_ctx;
	uint32_t cipher_type, hash_type;
	uint32_t mac_len, size;
	uint8_t iv_len = 16;
	struct cpt_request_info *req;
	buf_ptr_t *meta_p, *aad_buf = NULL;
	uint32_t encr_offset, auth_offset;
	uint32_t encr_data_len, auth_data_len, aad_len = 0;
	uint32_t passthrough_len = 0;
	void *m_vaddr, *offset_vaddr;
	uint64_t m_dma, offset_dma, ctx_dma;
	vq_cmd_word0_t vq_cmd_w0;
	vq_cmd_word3_t vq_cmd_w3;
	void *c_vaddr;
	uint64_t c_dma;
	int32_t m_size;
	opcode_info_t opcode;

	meta_p = &fc_params->meta_buf;
	m_vaddr = meta_p->vaddr;
	m_dma = meta_p->dma_addr;
	m_size = meta_p->size;

	encr_offset = ENCR_OFFSET(d_offs);
	auth_offset = AUTH_OFFSET(d_offs);
	encr_data_len = ENCR_DLEN(d_lens);
	auth_data_len = AUTH_DLEN(d_lens);
	if (unlikely(flags & VALID_AAD_BUF)) {
		/*
		 * We dont support both aad
		 * and auth data separately
		 */
		auth_data_len = 0;
		auth_offset = 0;
		aad_len = fc_params->aad_buf.size;
		aad_buf = &fc_params->aad_buf;
	}
	cpt_ctx = fc_params->ctx_buf.vaddr;
	cipher_type = cpt_ctx->enc_cipher;
	hash_type = cpt_ctx->hash_type;
	mac_len = cpt_ctx->mac_len;

	/*
	 * Save initial space that followed app data for completion code &
	 * alternate completion code to fall in same cache line as app data
	 */
	m_vaddr = (uint8_t *)m_vaddr + COMPLETION_CODE_SIZE;
	m_dma += COMPLETION_CODE_SIZE;
	size = (uint8_t *)RTE_PTR_ALIGN((uint8_t *)m_vaddr, 16) -
		(uint8_t *)m_vaddr;

	c_vaddr = (uint8_t *)m_vaddr + size;
	c_dma = m_dma + size;
	size += sizeof(cpt_res_s_t);

	m_vaddr = (uint8_t *)m_vaddr + size;
	m_dma += size;
	m_size -= size;

	/* start cpt request info struct at 8 byte boundary */
	size = (uint8_t *)RTE_PTR_ALIGN(m_vaddr, 8) -
		(uint8_t *)m_vaddr;

	req = (struct cpt_request_info *)((uint8_t *)m_vaddr + size);

	size += sizeof(struct cpt_request_info);
	m_vaddr = (uint8_t *)m_vaddr + size;
	m_dma += size;
	m_size -= size;

	if (hash_type == GMAC_TYPE)
		encr_data_len = 0;

	if (unlikely(!(flags & VALID_IV_BUF))) {
		iv_len = 0;
		iv_offset = ENCR_IV_OFFSET(d_offs);
	}

	if (unlikely(flags & VALID_AAD_BUF)) {
		/*
		 * When AAD is given, data above encr_offset is pass through
		 * Since AAD is given as separate pointer and not as offset,
		 * this is a special case as we need to fragment input data
		 * into passthrough + encr_data and then insert AAD in between.
		 */
		if (hash_type != GMAC_TYPE) {
			passthrough_len = encr_offset;
			auth_offset = passthrough_len + iv_len;
			encr_offset = passthrough_len + aad_len + iv_len;
			auth_data_len = aad_len + encr_data_len;
		} else {
			passthrough_len = 16 + aad_len;
			auth_offset = passthrough_len + iv_len;
			auth_data_len = aad_len;
		}
	} else {
		encr_offset += iv_len;
		auth_offset += iv_len;
	}

	/* Encryption */
	opcode.s.major = CPT_MAJOR_OP_FC;
	opcode.s.minor = 0;

	auth_dlen = auth_offset + auth_data_len;
	enc_dlen = encr_data_len + encr_offset;
	if (unlikely(encr_data_len & 0xf)) {
		if ((cipher_type == DES3_CBC) || (cipher_type == DES3_ECB))
			enc_dlen = ROUNDUP8(encr_data_len) + encr_offset;
		else if (likely((cipher_type == AES_CBC) ||
				(cipher_type == AES_ECB)))
			enc_dlen = ROUNDUP16(encr_data_len) + encr_offset;
	}

	if (unlikely(hash_type == GMAC_TYPE)) {
		encr_offset = auth_dlen;
		enc_dlen = 0;
	}

	if (unlikely(auth_dlen > enc_dlen)) {
		inputlen = auth_dlen;
		outputlen = auth_dlen + mac_len;
	} else {
		inputlen = enc_dlen;
		outputlen = enc_dlen + mac_len;
	}

	/* GP op header */
	vq_cmd_w0.u64 = 0;
	vq_cmd_w0.s.param1 = rte_cpu_to_be_16(encr_data_len);
	vq_cmd_w0.s.param2 = rte_cpu_to_be_16(auth_data_len);
	/*
	 * In 83XX since we have a limitation of
	 * IV & Offset control word not part of instruction
	 * and need to be part of Data Buffer, we check if
	 * head room is there and then only do the Direct mode processing
	 */
	if (likely((flags & SINGLE_BUF_INPLACE) &&
		   (flags & SINGLE_BUF_HEADTAILROOM))) {
		void *dm_vaddr = fc_params->bufs[0].vaddr;
		uint64_t dm_dma_addr = fc_params->bufs[0].dma_addr;
		/*
		 * This flag indicates that there is 24 bytes head room and
		 * 8 bytes tail room available, so that we get to do
		 * DIRECT MODE with limitation
		 */

		offset_vaddr = (uint8_t *)dm_vaddr - OFF_CTRL_LEN - iv_len;
		offset_dma = dm_dma_addr - OFF_CTRL_LEN - iv_len;

		/* DPTR */
		req->ist.ei1 = offset_dma;
		/* RPTR should just exclude offset control word */
		req->ist.ei2 = dm_dma_addr - iv_len;
		req->alternate_caddr = (uint64_t *)((uint8_t *)dm_vaddr
						    + outputlen - iv_len);

		vq_cmd_w0.s.dlen = rte_cpu_to_be_16(inputlen + OFF_CTRL_LEN);

		vq_cmd_w0.s.opcode = rte_cpu_to_be_16(opcode.flags);

		if (likely(iv_len)) {
			uint64_t *dest = (uint64_t *)((uint8_t *)offset_vaddr
						      + OFF_CTRL_LEN);
			uint64_t *src = fc_params->iv_buf;
			dest[0] = src[0];
			dest[1] = src[1];
		}

		*(uint64_t *)offset_vaddr =
			rte_cpu_to_be_64(((uint64_t)encr_offset << 16) |
				((uint64_t)iv_offset << 8) |
				((uint64_t)auth_offset));

	} else {
		uint32_t i, g_size_bytes, s_size_bytes;
		uint64_t dptr_dma, rptr_dma;
		sg_comp_t *gather_comp;
		sg_comp_t *scatter_comp;
		uint8_t *in_buffer;

		/* This falls under strict SG mode */
		offset_vaddr = m_vaddr;
		offset_dma = m_dma;
		size = OFF_CTRL_LEN + iv_len;

		m_vaddr = (uint8_t *)m_vaddr + size;
		m_dma += size;
		m_size -= size;

		opcode.s.major |= CPT_DMA_MODE;

		vq_cmd_w0.s.opcode = rte_cpu_to_be_16(opcode.flags);

		if (likely(iv_len)) {
			uint64_t *dest = (uint64_t *)((uint8_t *)offset_vaddr
						      + OFF_CTRL_LEN);
			uint64_t *src = fc_params->iv_buf;
			dest[0] = src[0];
			dest[1] = src[1];
		}

		*(uint64_t *)offset_vaddr =
			rte_cpu_to_be_64(((uint64_t)encr_offset << 16) |
				((uint64_t)iv_offset << 8) |
				((uint64_t)auth_offset));

		/* DPTR has SG list */
		in_buffer = m_vaddr;
		dptr_dma = m_dma;

		((uint16_t *)in_buffer)[0] = 0;
		((uint16_t *)in_buffer)[1] = 0;

		/* TODO Add error check if space will be sufficient */
		gather_comp = (sg_comp_t *)((uint8_t *)m_vaddr + 8);

		/*
		 * Input Gather List
		 */

		i = 0;

		/* Offset control word that includes iv */
		i = fill_sg_comp(gather_comp, i, offset_dma,
				 OFF_CTRL_LEN + iv_len);

		/* Add input data */
		size = inputlen - iv_len;
		if (likely(size)) {
			uint32_t aad_offset = aad_len ? passthrough_len : 0;

			if (unlikely(flags & SINGLE_BUF_INPLACE)) {
				i = fill_sg_comp_from_buf_min(gather_comp, i,
							      fc_params->bufs,
							      &size);
			} else {
				i = fill_sg_comp_from_iov(gather_comp, i,
							  fc_params->src_iov,
							  0, &size,
							  aad_buf, aad_offset);
			}

			if (unlikely(size)) {
				CPT_LOG_DP_ERR("Insufficient buffer space,"
					       " size %d needed", size);
				return ERR_BAD_INPUT_ARG;
			}
		}
		((uint16_t *)in_buffer)[2] = rte_cpu_to_be_16(i);
		g_size_bytes = ((i + 3) / 4) * sizeof(sg_comp_t);

		/*
		 * Output Scatter list
		 */
		i = 0;
		scatter_comp =
			(sg_comp_t *)((uint8_t *)gather_comp + g_size_bytes);

		/* Add IV */
		if (likely(iv_len)) {
			i = fill_sg_comp(scatter_comp, i,
					 offset_dma + OFF_CTRL_LEN,
					 iv_len);
		}

		/* output data or output data + digest*/
		if (unlikely(flags & VALID_MAC_BUF)) {
			size = outputlen - iv_len - mac_len;
			if (size) {
				uint32_t aad_offset =
					aad_len ? passthrough_len : 0;

				if (unlikely(flags & SINGLE_BUF_INPLACE)) {
					i = fill_sg_comp_from_buf_min(
							scatter_comp,
							i,
							fc_params->bufs,
							&size);
				} else {
					i = fill_sg_comp_from_iov(scatter_comp,
							i,
							fc_params->dst_iov,
							0,
							&size,
							aad_buf,
							aad_offset);
				}
				if (size)
					return ERR_BAD_INPUT_ARG;
			}
			/* mac_data */
			if (mac_len) {
				i = fill_sg_comp_from_buf(scatter_comp, i,
							  &fc_params->mac_buf);
			}
		} else {
			/* Output including mac */
			size = outputlen - iv_len;
			if (likely(size)) {
				uint32_t aad_offset =
					aad_len ? passthrough_len : 0;

				if (unlikely(flags & SINGLE_BUF_INPLACE)) {
					i = fill_sg_comp_from_buf_min(
							scatter_comp,
							i,
							fc_params->bufs,
							&size);
				} else {
					i = fill_sg_comp_from_iov(scatter_comp,
							i,
							fc_params->dst_iov,
							0,
							&size,
							aad_buf,
							aad_offset);
				}
				if (unlikely(size)) {
					CPT_LOG_DP_ERR("Insufficient buffer"
						       " space, size %d needed",
						       size);
					return ERR_BAD_INPUT_ARG;
				}
			}
		}
		((uint16_t *)in_buffer)[3] = rte_cpu_to_be_16(i);
		s_size_bytes = ((i + 3) / 4) * sizeof(sg_comp_t);

		size = g_size_bytes + s_size_bytes + SG_LIST_HDR_SIZE;

		/* This is DPTR len incase of SG mode */
		vq_cmd_w0.s.dlen = rte_cpu_to_be_16(size);

		m_vaddr = (uint8_t *)m_vaddr + size;
		m_dma += size;
		m_size -= size;

		/* cpt alternate completion address saved earlier */
		req->alternate_caddr = (uint64_t *)((uint8_t *)c_vaddr - 8);
		*req->alternate_caddr = ~((uint64_t)COMPLETION_CODE_INIT);
		rptr_dma = c_dma - 8;

		req->ist.ei1 = dptr_dma;
		req->ist.ei2 = rptr_dma;
	}

	/* First 16-bit swap then 64-bit swap */
	/* TODO: HACK: Reverse the vq_cmd and cpt_req bit field definitions
	 * to eliminate all the swapping
	 */
	vq_cmd_w0.u64 = rte_cpu_to_be_64(vq_cmd_w0.u64);

	ctx_dma = fc_params->ctx_buf.dma_addr +
		offsetof(struct cpt_ctx, fctx);
	/* vq command w3 */
	vq_cmd_w3.u64 = 0;
	vq_cmd_w3.s.grp = 0;
	vq_cmd_w3.s.cptr = ctx_dma;

	/* 16 byte aligned cpt res address */
	req->completion_addr = (uint64_t *)((uint8_t *)c_vaddr);
	*req->completion_addr = COMPLETION_CODE_INIT;
	req->comp_baddr  = c_dma;

	/* Fill microcode part of instruction */
	req->ist.ei0 = vq_cmd_w0.u64;
	req->ist.ei3 = vq_cmd_w3.u64;

	req->op  = op;

	*prep_req = req;
	return 0;
}

static __rte_always_inline int
cpt_dec_hmac_prep(uint32_t flags,
		  uint64_t d_offs,
		  uint64_t d_lens,
		  fc_params_t *fc_params,
		  void *op,
		  void **prep_req)
{
	uint32_t iv_offset = 0, size;
	int32_t inputlen, outputlen, enc_dlen, auth_dlen;
	struct cpt_ctx *cpt_ctx;
	int32_t hash_type, mac_len, m_size;
	uint8_t iv_len = 16;
	struct cpt_request_info *req;
	buf_ptr_t *meta_p, *aad_buf = NULL;
	uint32_t encr_offset, auth_offset;
	uint32_t encr_data_len, auth_data_len, aad_len = 0;
	uint32_t passthrough_len = 0;
	void *m_vaddr, *offset_vaddr;
	uint64_t m_dma, offset_dma, ctx_dma;
	opcode_info_t opcode;
	vq_cmd_word0_t vq_cmd_w0;
	vq_cmd_word3_t vq_cmd_w3;
	void *c_vaddr;
	uint64_t c_dma;

	meta_p = &fc_params->meta_buf;
	m_vaddr = meta_p->vaddr;
	m_dma = meta_p->dma_addr;
	m_size = meta_p->size;

	encr_offset = ENCR_OFFSET(d_offs);
	auth_offset = AUTH_OFFSET(d_offs);
	encr_data_len = ENCR_DLEN(d_lens);
	auth_data_len = AUTH_DLEN(d_lens);

	if (unlikely(flags & VALID_AAD_BUF)) {
		/*
		 * We dont support both aad
		 * and auth data separately
		 */
		auth_data_len = 0;
		auth_offset = 0;
		aad_len = fc_params->aad_buf.size;
		aad_buf = &fc_params->aad_buf;
	}

	cpt_ctx = fc_params->ctx_buf.vaddr;
	hash_type = cpt_ctx->hash_type;
	mac_len = cpt_ctx->mac_len;

	if (hash_type == GMAC_TYPE)
		encr_data_len = 0;

	if (unlikely(!(flags & VALID_IV_BUF))) {
		iv_len = 0;
		iv_offset = ENCR_IV_OFFSET(d_offs);
	}

	if (unlikely(flags & VALID_AAD_BUF)) {
		/*
		 * When AAD is given, data above encr_offset is pass through
		 * Since AAD is given as separate pointer and not as offset,
		 * this is a special case as we need to fragment input data
		 * into passthrough + encr_data and then insert AAD in between.
		 */
		if (hash_type != GMAC_TYPE) {
			passthrough_len = encr_offset;
			auth_offset = passthrough_len + iv_len;
			encr_offset = passthrough_len + aad_len + iv_len;
			auth_data_len = aad_len + encr_data_len;
		} else {
			passthrough_len = 16 + aad_len;
			auth_offset = passthrough_len + iv_len;
			auth_data_len = aad_len;
		}
	} else {
		encr_offset += iv_len;
		auth_offset += iv_len;
	}

	/*
	 * Save initial space that followed app data for completion code &
	 * alternate completion code to fall in same cache line as app data
	 */
	m_vaddr = (uint8_t *)m_vaddr + COMPLETION_CODE_SIZE;
	m_dma += COMPLETION_CODE_SIZE;
	size = (uint8_t *)RTE_PTR_ALIGN((uint8_t *)m_vaddr, 16) -
	       (uint8_t *)m_vaddr;
	c_vaddr = (uint8_t *)m_vaddr + size;
	c_dma = m_dma + size;
	size += sizeof(cpt_res_s_t);

	m_vaddr = (uint8_t *)m_vaddr + size;
	m_dma += size;
	m_size -= size;

	/* start cpt request info structure at 8 byte alignment */
	size = (uint8_t *)RTE_PTR_ALIGN(m_vaddr, 8) -
		(uint8_t *)m_vaddr;

	req = (struct cpt_request_info *)((uint8_t *)m_vaddr + size);

	size += sizeof(struct cpt_request_info);
	m_vaddr = (uint8_t *)m_vaddr + size;
	m_dma += size;
	m_size -= size;

	/* Decryption */
	opcode.s.major = CPT_MAJOR_OP_FC;
	opcode.s.minor = 1;

	enc_dlen = encr_offset + encr_data_len;
	auth_dlen = auth_offset + auth_data_len;

	if (auth_dlen > enc_dlen) {
		inputlen = auth_dlen + mac_len;
		outputlen = auth_dlen;
	} else {
		inputlen = enc_dlen + mac_len;
		outputlen = enc_dlen;
	}

	if (hash_type == GMAC_TYPE)
		encr_offset = inputlen;

	vq_cmd_w0.u64 = 0;
	vq_cmd_w0.s.param1 = rte_cpu_to_be_16(encr_data_len);
	vq_cmd_w0.s.param2 = rte_cpu_to_be_16(auth_data_len);

	/*
	 * In 83XX since we have a limitation of
	 * IV & Offset control word not part of instruction
	 * and need to be part of Data Buffer, we check if
	 * head room is there and then only do the Direct mode processing
	 */
	if (likely((flags & SINGLE_BUF_INPLACE) &&
		   (flags & SINGLE_BUF_HEADTAILROOM))) {
		void *dm_vaddr = fc_params->bufs[0].vaddr;
		uint64_t dm_dma_addr = fc_params->bufs[0].dma_addr;
		/*
		 * This flag indicates that there is 24 bytes head room and
		 * 8 bytes tail room available, so that we get to do
		 * DIRECT MODE with limitation
		 */

		offset_vaddr = (uint8_t *)dm_vaddr - OFF_CTRL_LEN - iv_len;
		offset_dma = dm_dma_addr - OFF_CTRL_LEN - iv_len;
		req->ist.ei1 = offset_dma;

		/* RPTR should just exclude offset control word */
		req->ist.ei2 = dm_dma_addr - iv_len;

		req->alternate_caddr = (uint64_t *)((uint8_t *)dm_vaddr +
					outputlen - iv_len);
		/* since this is decryption,
		 * don't touch the content of
		 * alternate ccode space as it contains
		 * hmac.
		 */

		vq_cmd_w0.s.dlen = rte_cpu_to_be_16(inputlen + OFF_CTRL_LEN);

		vq_cmd_w0.s.opcode = rte_cpu_to_be_16(opcode.flags);

		if (likely(iv_len)) {
			uint64_t *dest = (uint64_t *)((uint8_t *)offset_vaddr +
						      OFF_CTRL_LEN);
			uint64_t *src = fc_params->iv_buf;
			dest[0] = src[0];
			dest[1] = src[1];
		}

		*(uint64_t *)offset_vaddr =
			rte_cpu_to_be_64(((uint64_t)encr_offset << 16) |
				((uint64_t)iv_offset << 8) |
				((uint64_t)auth_offset));

	} else {
		uint64_t dptr_dma, rptr_dma;
		uint32_t g_size_bytes, s_size_bytes;
		sg_comp_t *gather_comp;
		sg_comp_t *scatter_comp;
		uint8_t *in_buffer;
		uint8_t i = 0;

		/* This falls under strict SG mode */
		offset_vaddr = m_vaddr;
		offset_dma = m_dma;
		size = OFF_CTRL_LEN + iv_len;

		m_vaddr = (uint8_t *)m_vaddr + size;
		m_dma += size;
		m_size -= size;

		opcode.s.major |= CPT_DMA_MODE;

		vq_cmd_w0.s.opcode = rte_cpu_to_be_16(opcode.flags);

		if (likely(iv_len)) {
			uint64_t *dest = (uint64_t *)((uint8_t *)offset_vaddr +
						      OFF_CTRL_LEN);
			uint64_t *src = fc_params->iv_buf;
			dest[0] = src[0];
			dest[1] = src[1];
		}

		*(uint64_t *)offset_vaddr =
			rte_cpu_to_be_64(((uint64_t)encr_offset << 16) |
				((uint64_t)iv_offset << 8) |
				((uint64_t)auth_offset));

		/* DPTR has SG list */
		in_buffer = m_vaddr;
		dptr_dma = m_dma;

		((uint16_t *)in_buffer)[0] = 0;
		((uint16_t *)in_buffer)[1] = 0;

		/* TODO Add error check if space will be sufficient */
		gather_comp = (sg_comp_t *)((uint8_t *)m_vaddr + 8);

		/*
		 * Input Gather List
		 */
		i = 0;

		/* Offset control word that includes iv */
		i = fill_sg_comp(gather_comp, i, offset_dma,
				 OFF_CTRL_LEN + iv_len);

		/* Add input data */
		if (flags & VALID_MAC_BUF) {
			size = inputlen - iv_len - mac_len;
			if (size) {
				/* input data only */
				if (unlikely(flags & SINGLE_BUF_INPLACE)) {
					i = fill_sg_comp_from_buf_min(
							gather_comp, i,
							fc_params->bufs,
							&size);
				} else {
					uint32_t aad_offset = aad_len ?
						passthrough_len : 0;

					i = fill_sg_comp_from_iov(gather_comp,
							i,
							fc_params->src_iov,
							0, &size,
							aad_buf,
							aad_offset);
				}
				if (size)
					return ERR_BAD_INPUT_ARG;
			}

			/* mac data */
			if (mac_len) {
				i = fill_sg_comp_from_buf(gather_comp, i,
							  &fc_params->mac_buf);
			}
		} else {
			/* input data + mac */
			size = inputlen - iv_len;
			if (size) {
				if (unlikely(flags & SINGLE_BUF_INPLACE)) {
					i = fill_sg_comp_from_buf_min(
							gather_comp, i,
							fc_params->bufs,
							&size);
				} else {
					uint32_t aad_offset = aad_len ?
						passthrough_len : 0;

					if (!fc_params->src_iov)
						return ERR_BAD_INPUT_ARG;

					i = fill_sg_comp_from_iov(
							gather_comp, i,
							fc_params->src_iov,
							0, &size,
							aad_buf,
							aad_offset);
				}

				if (size)
					return ERR_BAD_INPUT_ARG;
			}
		}
		((uint16_t *)in_buffer)[2] = rte_cpu_to_be_16(i);
		g_size_bytes = ((i + 3) / 4) * sizeof(sg_comp_t);

		/*
		 * Output Scatter List
		 */

		i = 0;
		scatter_comp =
			(sg_comp_t *)((uint8_t *)gather_comp + g_size_bytes);

		/* Add iv */
		if (iv_len) {
			i = fill_sg_comp(scatter_comp, i,
					 offset_dma + OFF_CTRL_LEN,
					 iv_len);
		}

		/* Add output data */
		size = outputlen - iv_len;
		if (size) {
			if (unlikely(flags & SINGLE_BUF_INPLACE)) {
				/* handle single buffer here */
				i = fill_sg_comp_from_buf_min(scatter_comp, i,
							      fc_params->bufs,
							      &size);
			} else {
				uint32_t aad_offset = aad_len ?
					passthrough_len : 0;

				if (!fc_params->dst_iov)
					return ERR_BAD_INPUT_ARG;

				i = fill_sg_comp_from_iov(scatter_comp, i,
							  fc_params->dst_iov, 0,
							  &size, aad_buf,
							  aad_offset);
			}

			if (unlikely(size))
				return ERR_BAD_INPUT_ARG;
		}

		((uint16_t *)in_buffer)[3] = rte_cpu_to_be_16(i);
		s_size_bytes = ((i + 3) / 4) * sizeof(sg_comp_t);

		size = g_size_bytes + s_size_bytes + SG_LIST_HDR_SIZE;

		/* This is DPTR len incase of SG mode */
		vq_cmd_w0.s.dlen = rte_cpu_to_be_16(size);

		m_vaddr = (uint8_t *)m_vaddr + size;
		m_dma += size;
		m_size -= size;

		/* cpt alternate completion address saved earlier */
		req->alternate_caddr = (uint64_t *)((uint8_t *)c_vaddr - 8);
		*req->alternate_caddr = ~((uint64_t)COMPLETION_CODE_INIT);
		rptr_dma = c_dma - 8;
		size += COMPLETION_CODE_SIZE;

		req->ist.ei1 = dptr_dma;
		req->ist.ei2 = rptr_dma;
	}

	/* First 16-bit swap then 64-bit swap */
	/* TODO: HACK: Reverse the vq_cmd and cpt_req bit field definitions
	 * to eliminate all the swapping
	 */
	vq_cmd_w0.u64 = rte_cpu_to_be_64(vq_cmd_w0.u64);

	ctx_dma = fc_params->ctx_buf.dma_addr +
		offsetof(struct cpt_ctx, fctx);
	/* vq command w3 */
	vq_cmd_w3.u64 = 0;
	vq_cmd_w3.s.grp = 0;
	vq_cmd_w3.s.cptr = ctx_dma;

	/* 16 byte aligned cpt res address */
	req->completion_addr = (uint64_t *)((uint8_t *)c_vaddr);
	*req->completion_addr = COMPLETION_CODE_INIT;
	req->comp_baddr  = c_dma;

	/* Fill microcode part of instruction */
	req->ist.ei0 = vq_cmd_w0.u64;
	req->ist.ei3 = vq_cmd_w3.u64;

	req->op = op;

	*prep_req = req;
	return 0;
}

static __rte_always_inline int
cpt_zuc_snow3g_enc_prep(uint32_t req_flags,
			uint64_t d_offs,
			uint64_t d_lens,
			fc_params_t *params,
			void *op,
			void **prep_req)
{
	uint32_t size;
	int32_t inputlen, outputlen;
	struct cpt_ctx *cpt_ctx;
	uint32_t mac_len = 0;
	uint8_t snow3g, j;
	struct cpt_request_info *req;
	buf_ptr_t *buf_p;
	uint32_t encr_offset = 0, auth_offset = 0;
	uint32_t encr_data_len = 0, auth_data_len = 0;
	int flags, iv_len = 16, m_size;
	void *m_vaddr, *c_vaddr;
	uint64_t m_dma, c_dma, offset_ctrl;
	uint64_t *offset_vaddr, offset_dma;
	uint32_t *iv_s, iv[4];
	vq_cmd_word0_t vq_cmd_w0;
	vq_cmd_word3_t vq_cmd_w3;
	opcode_info_t opcode;

	buf_p = &params->meta_buf;
	m_vaddr = buf_p->vaddr;
	m_dma = buf_p->dma_addr;
	m_size = buf_p->size;

	cpt_ctx = params->ctx_buf.vaddr;
	flags = cpt_ctx->zsk_flags;
	mac_len = cpt_ctx->mac_len;
	snow3g = cpt_ctx->snow3g;

	/*
	 * Save initial space that followed app data for completion code &
	 * alternate completion code to fall in same cache line as app data
	 */
	m_vaddr = (uint8_t *)m_vaddr + COMPLETION_CODE_SIZE;
	m_dma += COMPLETION_CODE_SIZE;
	size = (uint8_t *)RTE_PTR_ALIGN((uint8_t *)m_vaddr, 16) -
		(uint8_t *)m_vaddr;

	c_vaddr = (uint8_t *)m_vaddr + size;
	c_dma = m_dma + size;
	size += sizeof(cpt_res_s_t);

	m_vaddr = (uint8_t *)m_vaddr + size;
	m_dma += size;
	m_size -= size;

	/* Reserve memory for cpt request info */
	req = m_vaddr;

	size = sizeof(struct cpt_request_info);
	m_vaddr = (uint8_t *)m_vaddr + size;
	m_dma += size;
	m_size -= size;

	opcode.s.major = CPT_MAJOR_OP_ZUC_SNOW3G;

	/* indicates CPTR ctx, operation type, KEY & IV mode from DPTR */
	opcode.s.minor = ((1 << 6) | (snow3g << 5) | (0 << 4) |
			  (0 << 3) | (flags & 0x7));

	if (flags == 0x1) {
		/*
		 * Microcode expects offsets in bytes
		 * TODO: Rounding off
		 */
		auth_data_len = AUTH_DLEN(d_lens);

		/* EIA3 or UIA2 */
		auth_offset = AUTH_OFFSET(d_offs);
		auth_offset = auth_offset / 8;

		/* consider iv len */
		auth_offset += iv_len;

		inputlen = auth_offset + (RTE_ALIGN(auth_data_len, 8) / 8);
		outputlen = mac_len;

		offset_ctrl = rte_cpu_to_be_64((uint64_t)auth_offset);

	} else {
		/* EEA3 or UEA2 */
		/*
		 * Microcode expects offsets in bytes
		 * TODO: Rounding off
		 */
		encr_data_len = ENCR_DLEN(d_lens);

		encr_offset = ENCR_OFFSET(d_offs);
		encr_offset = encr_offset / 8;
		/* consider iv len */
		encr_offset += iv_len;

		inputlen = encr_offset + (RTE_ALIGN(encr_data_len, 8) / 8);
		outputlen = inputlen;

		/* iv offset is 0 */
		offset_ctrl = rte_cpu_to_be_64((uint64_t)encr_offset << 16);
	}

	/* IV */
	iv_s = (flags == 0x1) ? params->auth_iv_buf :
		params->iv_buf;

	if (snow3g) {
		/*
		 * DPDK seems to provide it in form of IV3 IV2 IV1 IV0
		 * and BigEndian, MC needs it as IV0 IV1 IV2 IV3
		 */

		for (j = 0; j < 4; j++)
			iv[j] = iv_s[3 - j];
	} else {
		/* ZUC doesn't need a swap */
		for (j = 0; j < 4; j++)
			iv[j] = iv_s[j];
	}

	/*
	 * GP op header, lengths are expected in bits.
	 */
	vq_cmd_w0.u64 = 0;
	vq_cmd_w0.s.param1 = rte_cpu_to_be_16(encr_data_len);
	vq_cmd_w0.s.param2 = rte_cpu_to_be_16(auth_data_len);

	/*
	 * In 83XX since we have a limitation of
	 * IV & Offset control word not part of instruction
	 * and need to be part of Data Buffer, we check if
	 * head room is there and then only do the Direct mode processing
	 */
	if (likely((req_flags & SINGLE_BUF_INPLACE) &&
		   (req_flags & SINGLE_BUF_HEADTAILROOM))) {
		void *dm_vaddr = params->bufs[0].vaddr;
		uint64_t dm_dma_addr = params->bufs[0].dma_addr;
		/*
		 * This flag indicates that there is 24 bytes head room and
		 * 8 bytes tail room available, so that we get to do
		 * DIRECT MODE with limitation
		 */

		offset_vaddr = (uint64_t *)((uint8_t *)dm_vaddr -
					    OFF_CTRL_LEN - iv_len);
		offset_dma = dm_dma_addr - OFF_CTRL_LEN - iv_len;

		/* DPTR */
		req->ist.ei1 = offset_dma;
		/* RPTR should just exclude offset control word */
		req->ist.ei2 = dm_dma_addr - iv_len;
		req->alternate_caddr = (uint64_t *)((uint8_t *)dm_vaddr
						    + outputlen - iv_len);

		vq_cmd_w0.s.dlen = rte_cpu_to_be_16(inputlen + OFF_CTRL_LEN);

		vq_cmd_w0.s.opcode = rte_cpu_to_be_16(opcode.flags);

		if (likely(iv_len)) {
			uint32_t *iv_d = (uint32_t *)((uint8_t *)offset_vaddr
						      + OFF_CTRL_LEN);
			memcpy(iv_d, iv, 16);
		}

		*offset_vaddr = offset_ctrl;
	} else {
		uint32_t i, g_size_bytes, s_size_bytes;
		uint64_t dptr_dma, rptr_dma;
		sg_comp_t *gather_comp;
		sg_comp_t *scatter_comp;
		uint8_t *in_buffer;
		uint32_t *iv_d;

		/* save space for iv */
		offset_vaddr = m_vaddr;
		offset_dma = m_dma;

		m_vaddr = (uint8_t *)m_vaddr + OFF_CTRL_LEN + iv_len;
		m_dma += OFF_CTRL_LEN + iv_len;
		m_size -= OFF_CTRL_LEN + iv_len;

		opcode.s.major |= CPT_DMA_MODE;

		vq_cmd_w0.s.opcode = rte_cpu_to_be_16(opcode.flags);

		/* DPTR has SG list */
		in_buffer = m_vaddr;
		dptr_dma = m_dma;

		((uint16_t *)in_buffer)[0] = 0;
		((uint16_t *)in_buffer)[1] = 0;

		/* TODO Add error check if space will be sufficient */
		gather_comp = (sg_comp_t *)((uint8_t *)m_vaddr + 8);

		/*
		 * Input Gather List
		 */
		i = 0;

		/* Offset control word followed by iv */

		i = fill_sg_comp(gather_comp, i, offset_dma,
				 OFF_CTRL_LEN + iv_len);

		/* iv offset is 0 */
		*offset_vaddr = offset_ctrl;

		iv_d = (uint32_t *)((uint8_t *)offset_vaddr + OFF_CTRL_LEN);
		memcpy(iv_d, iv, 16);

		/* input data */
		size = inputlen - iv_len;
		if (size) {
			i = fill_sg_comp_from_iov(gather_comp, i,
						  params->src_iov,
						  0, &size, NULL, 0);
			if (size)
				return ERR_BAD_INPUT_ARG;
		}
		((uint16_t *)in_buffer)[2] = rte_cpu_to_be_16(i);
		g_size_bytes = ((i + 3) / 4) * sizeof(sg_comp_t);

		/*
		 * Output Scatter List
		 */

		i = 0;
		scatter_comp =
			(sg_comp_t *)((uint8_t *)gather_comp + g_size_bytes);

		if (flags == 0x1) {
			/* IV in SLIST only for EEA3 & UEA2 */
			iv_len = 0;
		}

		if (iv_len) {
			i = fill_sg_comp(scatter_comp, i,
					 offset_dma + OFF_CTRL_LEN, iv_len);
		}

		/* Add output data */
		if (req_flags & VALID_MAC_BUF) {
			size = outputlen - iv_len - mac_len;
			if (size) {
				i = fill_sg_comp_from_iov(scatter_comp, i,
							  params->dst_iov, 0,
							  &size, NULL, 0);

				if (size)
					return ERR_BAD_INPUT_ARG;
			}

			/* mac data */
			if (mac_len) {
				i = fill_sg_comp_from_buf(scatter_comp, i,
							  &params->mac_buf);
			}
		} else {
			/* Output including mac */
			size = outputlen - iv_len;
			if (size) {
				i = fill_sg_comp_from_iov(scatter_comp, i,
							  params->dst_iov, 0,
							  &size, NULL, 0);

				if (size)
					return ERR_BAD_INPUT_ARG;
			}
		}
		((uint16_t *)in_buffer)[3] = rte_cpu_to_be_16(i);
		s_size_bytes = ((i + 3) / 4) * sizeof(sg_comp_t);

		size = g_size_bytes + s_size_bytes + SG_LIST_HDR_SIZE;

		/* This is DPTR len incase of SG mode */
		vq_cmd_w0.s.dlen = rte_cpu_to_be_16(size);

		m_vaddr = (uint8_t *)m_vaddr + size;
		m_dma += size;
		m_size -= size;

		/* cpt alternate completion address saved earlier */
		req->alternate_caddr = (uint64_t *)((uint8_t *)c_vaddr - 8);
		*req->alternate_caddr = ~((uint64_t)COMPLETION_CODE_INIT);
		rptr_dma = c_dma - 8;

		req->ist.ei1 = dptr_dma;
		req->ist.ei2 = rptr_dma;
	}

	/* First 16-bit swap then 64-bit swap */
	/* TODO: HACK: Reverse the vq_cmd and cpt_req bit field definitions
	 * to eliminate all the swapping
	 */
	vq_cmd_w0.u64 = rte_cpu_to_be_64(vq_cmd_w0.u64);

	/* vq command w3 */
	vq_cmd_w3.u64 = 0;
	vq_cmd_w3.s.grp = 0;
	vq_cmd_w3.s.cptr = params->ctx_buf.dma_addr +
		offsetof(struct cpt_ctx, zs_ctx);

	/* 16 byte aligned cpt res address */
	req->completion_addr = (uint64_t *)((uint8_t *)c_vaddr);
	*req->completion_addr = COMPLETION_CODE_INIT;
	req->comp_baddr  = c_dma;

	/* Fill microcode part of instruction */
	req->ist.ei0 = vq_cmd_w0.u64;
	req->ist.ei3 = vq_cmd_w3.u64;

	req->op = op;

	*prep_req = req;
	return 0;
}

static __rte_always_inline int
cpt_zuc_snow3g_dec_prep(uint32_t req_flags,
			uint64_t d_offs,
			uint64_t d_lens,
			fc_params_t *params,
			void *op,
			void **prep_req)
{
	uint32_t size;
	int32_t inputlen = 0, outputlen;
	struct cpt_ctx *cpt_ctx;
	uint8_t snow3g, iv_len = 16;
	struct cpt_request_info *req;
	buf_ptr_t *buf_p;
	uint32_t encr_offset;
	uint32_t encr_data_len;
	int flags, m_size;
	void *m_vaddr, *c_vaddr;
	uint64_t m_dma, c_dma;
	uint64_t *offset_vaddr, offset_dma;
	uint32_t *iv_s, iv[4], j;
	vq_cmd_word0_t vq_cmd_w0;
	vq_cmd_word3_t vq_cmd_w3;
	opcode_info_t opcode;

	buf_p = &params->meta_buf;
	m_vaddr = buf_p->vaddr;
	m_dma = buf_p->dma_addr;
	m_size = buf_p->size;

	/*
	 * Microcode expects offsets in bytes
	 * TODO: Rounding off
	 */
	encr_offset = ENCR_OFFSET(d_offs) / 8;
	encr_data_len = ENCR_DLEN(d_lens);

	cpt_ctx = params->ctx_buf.vaddr;
	flags = cpt_ctx->zsk_flags;
	snow3g = cpt_ctx->snow3g;
	/*
	 * Save initial space that followed app data for completion code &
	 * alternate completion code to fall in same cache line as app data
	 */
	m_vaddr = (uint8_t *)m_vaddr + COMPLETION_CODE_SIZE;
	m_dma += COMPLETION_CODE_SIZE;
	size = (uint8_t *)RTE_PTR_ALIGN((uint8_t *)m_vaddr, 16) -
		(uint8_t *)m_vaddr;

	c_vaddr = (uint8_t *)m_vaddr + size;
	c_dma = m_dma + size;
	size += sizeof(cpt_res_s_t);

	m_vaddr = (uint8_t *)m_vaddr + size;
	m_dma += size;
	m_size -= size;

	/* Reserve memory for cpt request info */
	req = m_vaddr;

	size = sizeof(struct cpt_request_info);
	m_vaddr = (uint8_t *)m_vaddr + size;
	m_dma += size;
	m_size -= size;

	opcode.s.major = CPT_MAJOR_OP_ZUC_SNOW3G;

	/* indicates CPTR ctx, operation type, KEY & IV mode from DPTR */
	opcode.s.minor = ((1 << 6) | (snow3g << 5) | (0 << 4) |
			  (0 << 3) | (flags & 0x7));

	/* consider iv len */
	encr_offset += iv_len;

	inputlen = encr_offset +
		(RTE_ALIGN(encr_data_len, 8) / 8);
	outputlen = inputlen;

	/* IV */
	iv_s = params->iv_buf;
	if (snow3g) {
		/*
		 * DPDK seems to provide it in form of IV3 IV2 IV1 IV0
		 * and BigEndian, MC needs it as IV0 IV1 IV2 IV3
		 */

		for (j = 0; j < 4; j++)
			iv[j] = iv_s[3 - j];
	} else {
		/* ZUC doesn't need a swap */
		for (j = 0; j < 4; j++)
			iv[j] = iv_s[j];
	}

	/*
	 * GP op header, lengths are expected in bits.
	 */
	vq_cmd_w0.u64 = 0;
	vq_cmd_w0.s.param1 = rte_cpu_to_be_16(encr_data_len);

	/*
	 * In 83XX since we have a limitation of
	 * IV & Offset control word not part of instruction
	 * and need to be part of Data Buffer, we check if
	 * head room is there and then only do the Direct mode processing
	 */
	if (likely((req_flags & SINGLE_BUF_INPLACE) &&
		   (req_flags & SINGLE_BUF_HEADTAILROOM))) {
		void *dm_vaddr = params->bufs[0].vaddr;
		uint64_t dm_dma_addr = params->bufs[0].dma_addr;
		/*
		 * This flag indicates that there is 24 bytes head room and
		 * 8 bytes tail room available, so that we get to do
		 * DIRECT MODE with limitation
		 */

		offset_vaddr = (uint64_t *)((uint8_t *)dm_vaddr -
					    OFF_CTRL_LEN - iv_len);
		offset_dma = dm_dma_addr - OFF_CTRL_LEN - iv_len;

		/* DPTR */
		req->ist.ei1 = offset_dma;
		/* RPTR should just exclude offset control word */
		req->ist.ei2 = dm_dma_addr - iv_len;
		req->alternate_caddr = (uint64_t *)((uint8_t *)dm_vaddr
						    + outputlen - iv_len);

		vq_cmd_w0.s.dlen = rte_cpu_to_be_16(inputlen + OFF_CTRL_LEN);

		vq_cmd_w0.s.opcode = rte_cpu_to_be_16(opcode.flags);

		if (likely(iv_len)) {
			uint32_t *iv_d = (uint32_t *)((uint8_t *)offset_vaddr
						      + OFF_CTRL_LEN);
			memcpy(iv_d, iv, 16);
		}

		/* iv offset is 0 */
		*offset_vaddr = rte_cpu_to_be_64((uint64_t)encr_offset << 16);
	} else {
		uint32_t i, g_size_bytes, s_size_bytes;
		uint64_t dptr_dma, rptr_dma;
		sg_comp_t *gather_comp;
		sg_comp_t *scatter_comp;
		uint8_t *in_buffer;
		uint32_t *iv_d;

		/* save space for offset and iv... */
		offset_vaddr = m_vaddr;
		offset_dma = m_dma;

		m_vaddr = (uint8_t *)m_vaddr + OFF_CTRL_LEN + iv_len;
		m_dma += OFF_CTRL_LEN + iv_len;
		m_size -= OFF_CTRL_LEN + iv_len;

		opcode.s.major |= CPT_DMA_MODE;

		vq_cmd_w0.s.opcode = rte_cpu_to_be_16(opcode.flags);

		/* DPTR has SG list */
		in_buffer = m_vaddr;
		dptr_dma = m_dma;

		((uint16_t *)in_buffer)[0] = 0;
		((uint16_t *)in_buffer)[1] = 0;

		/* TODO Add error check if space will be sufficient */
		gather_comp = (sg_comp_t *)((uint8_t *)m_vaddr + 8);

		/*
		 * Input Gather List
		 */
		i = 0;

		/* Offset control word */

		/* iv offset is 0 */
		*offset_vaddr = rte_cpu_to_be_64((uint64_t)encr_offset << 16);

		i = fill_sg_comp(gather_comp, i, offset_dma,
				 OFF_CTRL_LEN + iv_len);

		iv_d = (uint32_t *)((uint8_t *)offset_vaddr + OFF_CTRL_LEN);
		memcpy(iv_d, iv, 16);

		/* Add input data */
		size = inputlen - iv_len;
		if (size) {
			i = fill_sg_comp_from_iov(gather_comp, i,
						  params->src_iov,
						  0, &size, NULL, 0);
			if (size)
				return ERR_BAD_INPUT_ARG;
		}
		((uint16_t *)in_buffer)[2] = rte_cpu_to_be_16(i);
		g_size_bytes = ((i + 3) / 4) * sizeof(sg_comp_t);

		/*
		 * Output Scatter List
		 */

		i = 0;
		scatter_comp =
			(sg_comp_t *)((uint8_t *)gather_comp + g_size_bytes);

		/* IV */
		i = fill_sg_comp(scatter_comp, i,
				 offset_dma + OFF_CTRL_LEN,
				 iv_len);

		/* Add output data */
		size = outputlen - iv_len;
		if (size) {
			i = fill_sg_comp_from_iov(scatter_comp, i,
						  params->dst_iov, 0,
						  &size, NULL, 0);

			if (size)
				return ERR_BAD_INPUT_ARG;
		}
		((uint16_t *)in_buffer)[3] = rte_cpu_to_be_16(i);
		s_size_bytes = ((i + 3) / 4) * sizeof(sg_comp_t);

		size = g_size_bytes + s_size_bytes + SG_LIST_HDR_SIZE;

		/* This is DPTR len incase of SG mode */
		vq_cmd_w0.s.dlen = rte_cpu_to_be_16(size);

		m_vaddr = (uint8_t *)m_vaddr + size;
		m_dma += size;
		m_size -= size;

		/* cpt alternate completion address saved earlier */
		req->alternate_caddr = (uint64_t *)((uint8_t *)c_vaddr - 8);
		*req->alternate_caddr = ~((uint64_t)COMPLETION_CODE_INIT);
		rptr_dma = c_dma - 8;

		req->ist.ei1 = dptr_dma;
		req->ist.ei2 = rptr_dma;
	}

	/* First 16-bit swap then 64-bit swap */
	/* TODO: HACK: Reverse the vq_cmd and cpt_req bit field definitions
	 * to eliminate all the swapping
	 */
	vq_cmd_w0.u64 = rte_cpu_to_be_64(vq_cmd_w0.u64);

	/* vq command w3 */
	vq_cmd_w3.u64 = 0;
	vq_cmd_w3.s.grp = 0;
	vq_cmd_w3.s.cptr = params->ctx_buf.dma_addr +
		offsetof(struct cpt_ctx, zs_ctx);

	/* 16 byte aligned cpt res address */
	req->completion_addr = (uint64_t *)((uint8_t *)c_vaddr);
	*req->completion_addr = COMPLETION_CODE_INIT;
	req->comp_baddr  = c_dma;

	/* Fill microcode part of instruction */
	req->ist.ei0 = vq_cmd_w0.u64;
	req->ist.ei3 = vq_cmd_w3.u64;

	req->op = op;

	*prep_req = req;
	return 0;
}

static __rte_always_inline int
cpt_kasumi_enc_prep(uint32_t req_flags,
		    uint64_t d_offs,
		    uint64_t d_lens,
		    fc_params_t *params,
		    void *op,
		    void **prep_req)
{
	uint32_t size;
	int32_t inputlen = 0, outputlen = 0;
	struct cpt_ctx *cpt_ctx;
	uint32_t mac_len = 0;
	uint8_t i = 0;
	struct cpt_request_info *req;
	buf_ptr_t *buf_p;
	uint32_t encr_offset, auth_offset;
	uint32_t encr_data_len, auth_data_len;
	int flags, m_size;
	uint8_t *iv_s, *iv_d, iv_len = 8;
	uint8_t dir = 0;
	void *m_vaddr, *c_vaddr;
	uint64_t m_dma, c_dma;
	uint64_t *offset_vaddr, offset_dma;
	vq_cmd_word0_t vq_cmd_w0;
	vq_cmd_word3_t vq_cmd_w3;
	opcode_info_t opcode;
	uint8_t *in_buffer;
	uint32_t g_size_bytes, s_size_bytes;
	uint64_t dptr_dma, rptr_dma;
	sg_comp_t *gather_comp;
	sg_comp_t *scatter_comp;

	buf_p = &params->meta_buf;
	m_vaddr = buf_p->vaddr;
	m_dma = buf_p->dma_addr;
	m_size = buf_p->size;

	encr_offset = ENCR_OFFSET(d_offs) / 8;
	auth_offset = AUTH_OFFSET(d_offs) / 8;
	encr_data_len = ENCR_DLEN(d_lens);
	auth_data_len = AUTH_DLEN(d_lens);

	cpt_ctx = params->ctx_buf.vaddr;
	flags = cpt_ctx->zsk_flags;
	mac_len = cpt_ctx->mac_len;

	if (flags == 0x0)
		iv_s = params->iv_buf;
	else
		iv_s = params->auth_iv_buf;

	dir = iv_s[8] & 0x1;

	/*
	 * Save initial space that followed app data for completion code &
	 * alternate completion code to fall in same cache line as app data
	 */
	m_vaddr = (uint8_t *)m_vaddr + COMPLETION_CODE_SIZE;
	m_dma += COMPLETION_CODE_SIZE;
	size = (uint8_t *)RTE_PTR_ALIGN((uint8_t *)m_vaddr, 16) -
		(uint8_t *)m_vaddr;

	c_vaddr = (uint8_t *)m_vaddr + size;
	c_dma = m_dma + size;
	size += sizeof(cpt_res_s_t);

	m_vaddr = (uint8_t *)m_vaddr + size;
	m_dma += size;
	m_size -= size;

	/* Reserve memory for cpt request info */
	req = m_vaddr;

	size = sizeof(struct cpt_request_info);
	m_vaddr = (uint8_t *)m_vaddr + size;
	m_dma += size;
	m_size -= size;

	opcode.s.major = CPT_MAJOR_OP_KASUMI | CPT_DMA_MODE;

	/* indicates ECB/CBC, direction, ctx from cptr, iv from dptr */
	opcode.s.minor = ((1 << 6) | (cpt_ctx->k_ecb << 5) |
			  (dir << 4) | (0 << 3) | (flags & 0x7));

	/*
	 * GP op header, lengths are expected in bits.
	 */
	vq_cmd_w0.u64 = 0;
	vq_cmd_w0.s.param1 = rte_cpu_to_be_16(encr_data_len);
	vq_cmd_w0.s.param2 = rte_cpu_to_be_16(auth_data_len);
	vq_cmd_w0.s.opcode = rte_cpu_to_be_16(opcode.flags);

	/* consider iv len */
	if (flags == 0x0) {
		encr_offset += iv_len;
		auth_offset += iv_len;
	}

	/* save space for offset ctrl and iv */
	offset_vaddr = m_vaddr;
	offset_dma = m_dma;

	m_vaddr = (uint8_t *)m_vaddr + OFF_CTRL_LEN + iv_len;
	m_dma += OFF_CTRL_LEN + iv_len;
	m_size -= OFF_CTRL_LEN + iv_len;

	/* DPTR has SG list */
	in_buffer = m_vaddr;
	dptr_dma = m_dma;

	((uint16_t *)in_buffer)[0] = 0;
	((uint16_t *)in_buffer)[1] = 0;

	/* TODO Add error check if space will be sufficient */
	gather_comp = (sg_comp_t *)((uint8_t *)m_vaddr + 8);

	/*
	 * Input Gather List
	 */
	i = 0;

	/* Offset control word followed by iv */

	if (flags == 0x0) {
		inputlen = encr_offset + (RTE_ALIGN(encr_data_len, 8) / 8);
		outputlen = inputlen;
		/* iv offset is 0 */
		*offset_vaddr = rte_cpu_to_be_64((uint64_t)encr_offset << 16);
	} else {
		inputlen = auth_offset + (RTE_ALIGN(auth_data_len, 8) / 8);
		outputlen = mac_len;
		/* iv offset is 0 */
		*offset_vaddr = rte_cpu_to_be_64((uint64_t)auth_offset);
	}

	i = fill_sg_comp(gather_comp, i, offset_dma, OFF_CTRL_LEN + iv_len);

	/* IV */
	iv_d = (uint8_t *)offset_vaddr + OFF_CTRL_LEN;
	memcpy(iv_d, iv_s, iv_len);

	/* input data */
	size = inputlen - iv_len;
	if (size) {
		i = fill_sg_comp_from_iov(gather_comp, i,
					  params->src_iov, 0,
					  &size, NULL, 0);

		if (size)
			return ERR_BAD_INPUT_ARG;
	}
	((uint16_t *)in_buffer)[2] = rte_cpu_to_be_16(i);
	g_size_bytes = ((i + 3) / 4) * sizeof(sg_comp_t);

	/*
	 * Output Scatter List
	 */

	i = 0;
	scatter_comp = (sg_comp_t *)((uint8_t *)gather_comp + g_size_bytes);

	if (flags == 0x1) {
		/* IV in SLIST only for F8 */
		iv_len = 0;
	}

	/* IV */
	if (iv_len) {
		i = fill_sg_comp(scatter_comp, i,
				 offset_dma + OFF_CTRL_LEN,
				 iv_len);
	}

	/* Add output data */
	if (req_flags & VALID_MAC_BUF) {
		size = outputlen - iv_len - mac_len;
		if (size) {
			i = fill_sg_comp_from_iov(scatter_comp, i,
						  params->dst_iov, 0,
						  &size, NULL, 0);

			if (size)
				return ERR_BAD_INPUT_ARG;
		}

		/* mac data */
		if (mac_len) {
			i = fill_sg_comp_from_buf(scatter_comp, i,
						  &params->mac_buf);
		}
	} else {
		/* Output including mac */
		size = outputlen - iv_len;
		if (size) {
			i = fill_sg_comp_from_iov(scatter_comp, i,
						  params->dst_iov, 0,
						  &size, NULL, 0);

			if (size)
				return ERR_BAD_INPUT_ARG;
		}
	}
	((uint16_t *)in_buffer)[3] = rte_cpu_to_be_16(i);
	s_size_bytes = ((i + 3) / 4) * sizeof(sg_comp_t);

	size = g_size_bytes + s_size_bytes + SG_LIST_HDR_SIZE;

	/* This is DPTR len incase of SG mode */
	vq_cmd_w0.s.dlen = rte_cpu_to_be_16(size);

	m_vaddr = (uint8_t *)m_vaddr + size;
	m_dma += size;
	m_size -= size;

	/* cpt alternate completion address saved earlier */
	req->alternate_caddr = (uint64_t *)((uint8_t *)c_vaddr - 8);
	*req->alternate_caddr = ~((uint64_t)COMPLETION_CODE_INIT);
	rptr_dma = c_dma - 8;

	req->ist.ei1 = dptr_dma;
	req->ist.ei2 = rptr_dma;

	/* First 16-bit swap then 64-bit swap */
	/* TODO: HACK: Reverse the vq_cmd and cpt_req bit field definitions
	 * to eliminate all the swapping
	 */
	vq_cmd_w0.u64 = rte_cpu_to_be_64(vq_cmd_w0.u64);

	/* vq command w3 */
	vq_cmd_w3.u64 = 0;
	vq_cmd_w3.s.grp = 0;
	vq_cmd_w3.s.cptr = params->ctx_buf.dma_addr +
		offsetof(struct cpt_ctx, k_ctx);

	/* 16 byte aligned cpt res address */
	req->completion_addr = (uint64_t *)((uint8_t *)c_vaddr);
	*req->completion_addr = COMPLETION_CODE_INIT;
	req->comp_baddr  = c_dma;

	/* Fill microcode part of instruction */
	req->ist.ei0 = vq_cmd_w0.u64;
	req->ist.ei3 = vq_cmd_w3.u64;

	req->op = op;

	*prep_req = req;
	return 0;
}

static __rte_always_inline int
cpt_kasumi_dec_prep(uint64_t d_offs,
		    uint64_t d_lens,
		    fc_params_t *params,
		    void *op,
		    void **prep_req)
{
	uint32_t size;
	int32_t inputlen = 0, outputlen;
	struct cpt_ctx *cpt_ctx;
	uint8_t i = 0, iv_len = 8;
	struct cpt_request_info *req;
	buf_ptr_t *buf_p;
	uint32_t encr_offset;
	uint32_t encr_data_len;
	int flags, m_size;
	uint8_t dir = 0;
	void *m_vaddr, *c_vaddr;
	uint64_t m_dma, c_dma;
	uint64_t *offset_vaddr, offset_dma;
	vq_cmd_word0_t vq_cmd_w0;
	vq_cmd_word3_t vq_cmd_w3;
	opcode_info_t opcode;
	uint8_t *in_buffer;
	uint32_t g_size_bytes, s_size_bytes;
	uint64_t dptr_dma, rptr_dma;
	sg_comp_t *gather_comp;
	sg_comp_t *scatter_comp;

	buf_p = &params->meta_buf;
	m_vaddr = buf_p->vaddr;
	m_dma = buf_p->dma_addr;
	m_size = buf_p->size;

	encr_offset = ENCR_OFFSET(d_offs) / 8;
	encr_data_len = ENCR_DLEN(d_lens);

	cpt_ctx = params->ctx_buf.vaddr;
	flags = cpt_ctx->zsk_flags;
	/*
	 * Save initial space that followed app data for completion code &
	 * alternate completion code to fall in same cache line as app data
	 */
	m_vaddr = (uint8_t *)m_vaddr + COMPLETION_CODE_SIZE;
	m_dma += COMPLETION_CODE_SIZE;
	size = (uint8_t *)RTE_PTR_ALIGN((uint8_t *)m_vaddr, 16) -
		(uint8_t *)m_vaddr;

	c_vaddr = (uint8_t *)m_vaddr + size;
	c_dma = m_dma + size;
	size += sizeof(cpt_res_s_t);

	m_vaddr = (uint8_t *)m_vaddr + size;
	m_dma += size;
	m_size -= size;

	/* Reserve memory for cpt request info */
	req = m_vaddr;

	size = sizeof(struct cpt_request_info);
	m_vaddr = (uint8_t *)m_vaddr + size;
	m_dma += size;
	m_size -= size;

	opcode.s.major = CPT_MAJOR_OP_KASUMI | CPT_DMA_MODE;

	/* indicates ECB/CBC, direction, ctx from cptr, iv from dptr */
	opcode.s.minor = ((1 << 6) | (cpt_ctx->k_ecb << 5) |
			  (dir << 4) | (0 << 3) | (flags & 0x7));

	/*
	 * GP op header, lengths are expected in bits.
	 */
	vq_cmd_w0.u64 = 0;
	vq_cmd_w0.s.param1 = rte_cpu_to_be_16(encr_data_len);
	vq_cmd_w0.s.opcode = rte_cpu_to_be_16(opcode.flags);

	/* consider iv len */
	encr_offset += iv_len;

	inputlen = iv_len + (RTE_ALIGN(encr_data_len, 8) / 8);
	outputlen = inputlen;

	/* save space for offset ctrl & iv */
	offset_vaddr = m_vaddr;
	offset_dma = m_dma;

	m_vaddr = (uint8_t *)m_vaddr + OFF_CTRL_LEN + iv_len;
	m_dma += OFF_CTRL_LEN + iv_len;
	m_size -= OFF_CTRL_LEN + iv_len;

	/* DPTR has SG list */
	in_buffer = m_vaddr;
	dptr_dma = m_dma;

	((uint16_t *)in_buffer)[0] = 0;
	((uint16_t *)in_buffer)[1] = 0;

	/* TODO Add error check if space will be sufficient */
	gather_comp = (sg_comp_t *)((uint8_t *)m_vaddr + 8);

	/*
	 * Input Gather List
	 */
	i = 0;

	/* Offset control word followed by iv */
	*offset_vaddr = rte_cpu_to_be_64((uint64_t)encr_offset << 16);

	i = fill_sg_comp(gather_comp, i, offset_dma, OFF_CTRL_LEN + iv_len);

	/* IV */
	memcpy((uint8_t *)offset_vaddr + OFF_CTRL_LEN,
	       params->iv_buf, iv_len);

	/* Add input data */
	size = inputlen - iv_len;
	if (size) {
		i = fill_sg_comp_from_iov(gather_comp, i,
					  params->src_iov,
					  0, &size, NULL, 0);
		if (size)
			return ERR_BAD_INPUT_ARG;
	}
	((uint16_t *)in_buffer)[2] = rte_cpu_to_be_16(i);
	g_size_bytes = ((i + 3) / 4) * sizeof(sg_comp_t);

	/*
	 * Output Scatter List
	 */

	i = 0;
	scatter_comp = (sg_comp_t *)((uint8_t *)gather_comp + g_size_bytes);

	/* IV */
	i = fill_sg_comp(scatter_comp, i,
			 offset_dma + OFF_CTRL_LEN,
			 iv_len);

	/* Add output data */
	size = outputlen - iv_len;
	if (size) {
		i = fill_sg_comp_from_iov(scatter_comp, i,
					  params->dst_iov, 0,
					  &size, NULL, 0);
		if (size)
			return ERR_BAD_INPUT_ARG;
	}
	((uint16_t *)in_buffer)[3] = rte_cpu_to_be_16(i);
	s_size_bytes = ((i + 3) / 4) * sizeof(sg_comp_t);

	size = g_size_bytes + s_size_bytes + SG_LIST_HDR_SIZE;

	/* This is DPTR len incase of SG mode */
	vq_cmd_w0.s.dlen = rte_cpu_to_be_16(size);

	m_vaddr = (uint8_t *)m_vaddr + size;
	m_dma += size;
	m_size -= size;

	/* cpt alternate completion address saved earlier */
	req->alternate_caddr = (uint64_t *)((uint8_t *)c_vaddr - 8);
	*req->alternate_caddr = ~((uint64_t)COMPLETION_CODE_INIT);
	rptr_dma = c_dma - 8;

	req->ist.ei1 = dptr_dma;
	req->ist.ei2 = rptr_dma;

	/* First 16-bit swap then 64-bit swap */
	/* TODO: HACK: Reverse the vq_cmd and cpt_req bit field definitions
	 * to eliminate all the swapping
	 */
	vq_cmd_w0.u64 = rte_cpu_to_be_64(vq_cmd_w0.u64);

	/* vq command w3 */
	vq_cmd_w3.u64 = 0;
	vq_cmd_w3.s.grp = 0;
	vq_cmd_w3.s.cptr = params->ctx_buf.dma_addr +
		offsetof(struct cpt_ctx, k_ctx);

	/* 16 byte aligned cpt res address */
	req->completion_addr = (uint64_t *)((uint8_t *)c_vaddr);
	*req->completion_addr = COMPLETION_CODE_INIT;
	req->comp_baddr  = c_dma;

	/* Fill microcode part of instruction */
	req->ist.ei0 = vq_cmd_w0.u64;
	req->ist.ei3 = vq_cmd_w3.u64;

	req->op = op;

	*prep_req = req;
	return 0;
}

static __rte_always_inline void *
cpt_fc_dec_hmac_prep(uint32_t flags,
		     uint64_t d_offs,
		     uint64_t d_lens,
		     fc_params_t *fc_params,
		     void *op, int *ret_val)
{
	struct cpt_ctx *ctx = fc_params->ctx_buf.vaddr;
	uint8_t fc_type;
	void *prep_req = NULL;
	int ret;

	fc_type = ctx->fc_type;

	if (likely(fc_type == FC_GEN)) {
		ret = cpt_dec_hmac_prep(flags, d_offs, d_lens,
					fc_params, op, &prep_req);
	} else if (fc_type == ZUC_SNOW3G) {
		ret = cpt_zuc_snow3g_dec_prep(flags, d_offs, d_lens,
					      fc_params, op, &prep_req);
	} else if (fc_type == KASUMI) {
		ret = cpt_kasumi_dec_prep(d_offs, d_lens, fc_params, op,
					  &prep_req);
	} else {
		/*
		 * For AUTH_ONLY case,
		 * MC only supports digest generation and verification
		 * should be done in software by memcmp()
		 */

		ret = ERR_EIO;
	}

	if (unlikely(!prep_req))
		*ret_val = ret;
	return prep_req;
}

static __rte_always_inline void *__hot
cpt_fc_enc_hmac_prep(uint32_t flags, uint64_t d_offs, uint64_t d_lens,
		     fc_params_t *fc_params, void *op, int *ret_val)
{
	struct cpt_ctx *ctx = fc_params->ctx_buf.vaddr;
	uint8_t fc_type;
	void *prep_req = NULL;
	int ret;

	fc_type = ctx->fc_type;

	/* Common api for rest of the ops */
	if (likely(fc_type == FC_GEN)) {
		ret = cpt_enc_hmac_prep(flags, d_offs, d_lens,
					fc_params, op, &prep_req);
	} else if (fc_type == ZUC_SNOW3G) {
		ret = cpt_zuc_snow3g_enc_prep(flags, d_offs, d_lens,
					      fc_params, op, &prep_req);
	} else if (fc_type == KASUMI) {
		ret = cpt_kasumi_enc_prep(flags, d_offs, d_lens,
					  fc_params, op, &prep_req);
	} else if (fc_type == HASH_HMAC) {
		ret = cpt_digest_gen_prep(flags, d_lens, fc_params, op,
					  &prep_req);
	} else {
		ret = ERR_EIO;
	}

	if (unlikely(!prep_req))
		*ret_val = ret;
	return prep_req;
}

static __rte_always_inline int
cpt_fc_auth_set_key(void *ctx, auth_type_t type, uint8_t *key,
		    uint16_t key_len, uint16_t mac_len)
{
	struct cpt_ctx *cpt_ctx = ctx;
	mc_fc_context_t *fctx = &cpt_ctx->fctx;
	uint64_t *ctrl_flags = NULL;

	if ((type >= ZUC_EIA3) && (type <= KASUMI_F9_ECB)) {
		uint32_t keyx[4];

		if (key_len != 16)
			return -1;
		/* No support for AEAD yet */
		if (cpt_ctx->enc_cipher)
			return -1;
		/* For ZUC/SNOW3G/Kasumi */
		switch (type) {
		case SNOW3G_UIA2:
			cpt_ctx->snow3g = 1;
			gen_key_snow3g(key, keyx);
			memcpy(cpt_ctx->zs_ctx.ci_key, keyx, key_len);
			cpt_ctx->fc_type = ZUC_SNOW3G;
			cpt_ctx->zsk_flags = 0x1;
			break;
		case ZUC_EIA3:
			cpt_ctx->snow3g = 0;
			memcpy(cpt_ctx->zs_ctx.ci_key, key, key_len);
			memcpy(cpt_ctx->zs_ctx.zuc_const, zuc_d, 32);
			cpt_ctx->fc_type = ZUC_SNOW3G;
			cpt_ctx->zsk_flags = 0x1;
			break;
		case KASUMI_F9_ECB:
			/* Kasumi ECB mode */
			cpt_ctx->k_ecb = 1;
			memcpy(cpt_ctx->k_ctx.ci_key, key, key_len);
			cpt_ctx->fc_type = KASUMI;
			cpt_ctx->zsk_flags = 0x1;
			break;
		case KASUMI_F9_CBC:
			memcpy(cpt_ctx->k_ctx.ci_key, key, key_len);
			cpt_ctx->fc_type = KASUMI;
			cpt_ctx->zsk_flags = 0x1;
			break;
		default:
			return -1;
		}
		cpt_ctx->mac_len = 4;
		cpt_ctx->hash_type = type;
		return 0;
	}

	if (!(cpt_ctx->fc_type == FC_GEN && !type)) {
		if (!cpt_ctx->fc_type || !cpt_ctx->enc_cipher)
			cpt_ctx->fc_type = HASH_HMAC;
	}

	ctrl_flags = (uint64_t *)&fctx->enc.enc_ctrl.flags;
	*ctrl_flags = rte_be_to_cpu_64(*ctrl_flags);

	/* For GMAC auth, cipher must be NULL */
	if (type == GMAC_TYPE)
		CPT_P_ENC_CTRL(fctx).enc_cipher = 0;

	CPT_P_ENC_CTRL(fctx).hash_type = cpt_ctx->hash_type = type;
	CPT_P_ENC_CTRL(fctx).mac_len = cpt_ctx->mac_len = mac_len;

	if (key_len) {
		cpt_ctx->hmac = 1;
		memset(cpt_ctx->auth_key, 0, sizeof(cpt_ctx->auth_key));
		memcpy(cpt_ctx->auth_key, key, key_len);
		cpt_ctx->auth_key_len = key_len;
		memset(fctx->hmac.ipad, 0, sizeof(fctx->hmac.ipad));
		memset(fctx->hmac.opad, 0, sizeof(fctx->hmac.opad));
		memcpy(fctx->hmac.opad, key, key_len);
		CPT_P_ENC_CTRL(fctx).auth_input_type = 1;
	}
	*ctrl_flags = rte_cpu_to_be_64(*ctrl_flags);
	return 0;
}

static __rte_always_inline int
fill_sess_aead(struct rte_crypto_sym_xform *xform,
		 struct cpt_sess_misc *sess)
{
	struct rte_crypto_aead_xform *aead_form;
	cipher_type_t enc_type = 0; /* NULL Cipher type */
	auth_type_t auth_type = 0; /* NULL Auth type */
	uint32_t cipher_key_len = 0;
	uint8_t zsk_flag = 0, aes_gcm = 0;
	aead_form = &xform->aead;
	void *ctx;

	if (aead_form->op == RTE_CRYPTO_AEAD_OP_ENCRYPT &&
	   aead_form->algo == RTE_CRYPTO_AEAD_AES_GCM) {
		sess->cpt_op |= CPT_OP_CIPHER_ENCRYPT;
		sess->cpt_op |= CPT_OP_AUTH_GENERATE;
	} else if (aead_form->op == RTE_CRYPTO_AEAD_OP_DECRYPT &&
		aead_form->algo == RTE_CRYPTO_AEAD_AES_GCM) {
		sess->cpt_op |= CPT_OP_CIPHER_DECRYPT;
		sess->cpt_op |= CPT_OP_AUTH_VERIFY;
	} else {
		CPT_LOG_DP_ERR("Unknown cipher operation\n");
		return -1;
	}
	switch (aead_form->algo) {
	case RTE_CRYPTO_AEAD_AES_GCM:
		enc_type = AES_GCM;
		cipher_key_len = 16;
		aes_gcm = 1;
		break;
	case RTE_CRYPTO_AEAD_AES_CCM:
		CPT_LOG_DP_ERR("Crypto: Unsupported cipher algo %u",
			       aead_form->algo);
		return -1;
	default:
		CPT_LOG_DP_ERR("Crypto: Undefined cipher algo %u specified",
			       aead_form->algo);
		return -1;
	}
	if (aead_form->key.length < cipher_key_len) {
		CPT_LOG_DP_ERR("Invalid cipher params keylen %lu",
			       (unsigned int long)aead_form->key.length);
		return -1;
	}
	sess->zsk_flag = zsk_flag;
	sess->aes_gcm = aes_gcm;
	sess->mac_len = aead_form->digest_length;
	sess->iv_offset = aead_form->iv.offset;
	sess->iv_length = aead_form->iv.length;
	sess->aad_length = aead_form->aad_length;
	ctx = (void *)((uint8_t *)sess + sizeof(struct cpt_sess_misc)),

	cpt_fc_ciph_set_key(ctx, enc_type, aead_form->key.data,
			aead_form->key.length, NULL);

	cpt_fc_auth_set_key(ctx, auth_type, NULL, 0, aead_form->digest_length);

	return 0;
}

static __rte_always_inline int
fill_sess_cipher(struct rte_crypto_sym_xform *xform,
		 struct cpt_sess_misc *sess)
{
	struct rte_crypto_cipher_xform *c_form;
	cipher_type_t enc_type = 0; /* NULL Cipher type */
	uint32_t cipher_key_len = 0;
	uint8_t zsk_flag = 0, aes_gcm = 0, aes_ctr = 0, is_null = 0;

	if (xform->type != RTE_CRYPTO_SYM_XFORM_CIPHER)
		return -1;

	c_form = &xform->cipher;

	if (c_form->op == RTE_CRYPTO_CIPHER_OP_ENCRYPT)
		sess->cpt_op |= CPT_OP_CIPHER_ENCRYPT;
	else if (c_form->op == RTE_CRYPTO_CIPHER_OP_DECRYPT)
		sess->cpt_op |= CPT_OP_CIPHER_DECRYPT;
	else {
		CPT_LOG_DP_ERR("Unknown cipher operation\n");
		return -1;
	}

	switch (c_form->algo) {
	case RTE_CRYPTO_CIPHER_AES_CBC:
		enc_type = AES_CBC;
		cipher_key_len = 16;
		break;
	case RTE_CRYPTO_CIPHER_3DES_CBC:
		enc_type = DES3_CBC;
		cipher_key_len = 24;
		break;
	case RTE_CRYPTO_CIPHER_DES_CBC:
		/* DES is implemented using 3DES in hardware */
		enc_type = DES3_CBC;
		cipher_key_len = 8;
		break;
	case RTE_CRYPTO_CIPHER_AES_CTR:
		enc_type = AES_CTR;
		cipher_key_len = 16;
		aes_ctr = 1;
		break;
	case RTE_CRYPTO_CIPHER_NULL:
		enc_type = 0;
		is_null = 1;
		break;
	case RTE_CRYPTO_CIPHER_KASUMI_F8:
		enc_type = KASUMI_F8_ECB;
		cipher_key_len = 16;
		zsk_flag = K_F8;
		break;
	case RTE_CRYPTO_CIPHER_SNOW3G_UEA2:
		enc_type = SNOW3G_UEA2;
		cipher_key_len = 16;
		zsk_flag = ZS_EA;
		break;
	case RTE_CRYPTO_CIPHER_ZUC_EEA3:
		enc_type = ZUC_EEA3;
		cipher_key_len = 16;
		zsk_flag = ZS_EA;
		break;
	case RTE_CRYPTO_CIPHER_AES_XTS:
		enc_type = AES_XTS;
		cipher_key_len = 16;
		break;
	case RTE_CRYPTO_CIPHER_3DES_ECB:
		enc_type = DES3_ECB;
		cipher_key_len = 24;
		break;
	case RTE_CRYPTO_CIPHER_AES_ECB:
		enc_type = AES_ECB;
		cipher_key_len = 16;
		break;
	case RTE_CRYPTO_CIPHER_3DES_CTR:
	case RTE_CRYPTO_CIPHER_AES_F8:
	case RTE_CRYPTO_CIPHER_ARC4:
		CPT_LOG_DP_ERR("Crypto: Unsupported cipher algo %u",
			       c_form->algo);
		return -1;
	default:
		CPT_LOG_DP_ERR("Crypto: Undefined cipher algo %u specified",
			       c_form->algo);
		return -1;
	}

	if (c_form->key.length < cipher_key_len) {
		CPT_LOG_DP_ERR("Invalid cipher params keylen %lu",
			       (unsigned long) c_form->key.length);
		return -1;
	}

	sess->zsk_flag = zsk_flag;
	sess->aes_gcm = aes_gcm;
	sess->aes_ctr = aes_ctr;
	sess->iv_offset = c_form->iv.offset;
	sess->iv_length = c_form->iv.length;
	sess->is_null = is_null;

	cpt_fc_ciph_set_key(SESS_PRIV(sess), enc_type, c_form->key.data,
			    c_form->key.length, NULL);

	return 0;
}

static __rte_always_inline int
fill_sess_auth(struct rte_crypto_sym_xform *xform,
	       struct cpt_sess_misc *sess)
{
	struct rte_crypto_auth_xform *a_form;
	auth_type_t auth_type = 0; /* NULL Auth type */
	uint8_t zsk_flag = 0, aes_gcm = 0, is_null = 0;

	if (xform->type != RTE_CRYPTO_SYM_XFORM_AUTH)
		goto error_out;

	a_form = &xform->auth;

	if (a_form->op == RTE_CRYPTO_AUTH_OP_VERIFY)
		sess->cpt_op |= CPT_OP_AUTH_VERIFY;
	else if (a_form->op == RTE_CRYPTO_AUTH_OP_GENERATE)
		sess->cpt_op |= CPT_OP_AUTH_GENERATE;
	else {
		CPT_LOG_DP_ERR("Unknown auth operation");
		return -1;
	}

	if (a_form->key.length > 64) {
		CPT_LOG_DP_ERR("Auth key length is big");
		return -1;
	}

	switch (a_form->algo) {
	case RTE_CRYPTO_AUTH_SHA1_HMAC:
		/* Fall through */
	case RTE_CRYPTO_AUTH_SHA1:
		auth_type = SHA1_TYPE;
		break;
	case RTE_CRYPTO_AUTH_SHA256_HMAC:
	case RTE_CRYPTO_AUTH_SHA256:
		auth_type = SHA2_SHA256;
		break;
	case RTE_CRYPTO_AUTH_SHA512_HMAC:
	case RTE_CRYPTO_AUTH_SHA512:
		auth_type = SHA2_SHA512;
		break;
	case RTE_CRYPTO_AUTH_AES_GMAC:
		auth_type = GMAC_TYPE;
		aes_gcm = 1;
		break;
	case RTE_CRYPTO_AUTH_SHA224_HMAC:
	case RTE_CRYPTO_AUTH_SHA224:
		auth_type = SHA2_SHA224;
		break;
	case RTE_CRYPTO_AUTH_SHA384_HMAC:
	case RTE_CRYPTO_AUTH_SHA384:
		auth_type = SHA2_SHA384;
		break;
	case RTE_CRYPTO_AUTH_MD5_HMAC:
	case RTE_CRYPTO_AUTH_MD5:
		auth_type = MD5_TYPE;
		break;
	case RTE_CRYPTO_AUTH_KASUMI_F9:
		auth_type = KASUMI_F9_ECB;
		/*
		 * Indicate that direction needs to be taken out
		 * from end of src
		 */
		zsk_flag = K_F9;
		break;
	case RTE_CRYPTO_AUTH_SNOW3G_UIA2:
		auth_type = SNOW3G_UIA2;
		zsk_flag = ZS_IA;
		break;
	case RTE_CRYPTO_AUTH_ZUC_EIA3:
		auth_type = ZUC_EIA3;
		zsk_flag = ZS_IA;
		break;
	case RTE_CRYPTO_AUTH_NULL:
		auth_type = 0;
		is_null = 1;
		break;
	case RTE_CRYPTO_AUTH_AES_XCBC_MAC:
	case RTE_CRYPTO_AUTH_AES_CMAC:
	case RTE_CRYPTO_AUTH_AES_CBC_MAC:
		CPT_LOG_DP_ERR("Crypto: Unsupported hash algo %u",
			       a_form->algo);
		goto error_out;
	default:
		CPT_LOG_DP_ERR("Crypto: Undefined Hash algo %u specified",
			       a_form->algo);
		goto error_out;
	}

	sess->zsk_flag = zsk_flag;
	sess->aes_gcm = aes_gcm;
	sess->mac_len = a_form->digest_length;
	sess->is_null = is_null;
	if (zsk_flag) {
		sess->auth_iv_offset = a_form->iv.offset;
		sess->auth_iv_length = a_form->iv.length;
	}
	cpt_fc_auth_set_key(SESS_PRIV(sess), auth_type, a_form->key.data,
			    a_form->key.length, a_form->digest_length);

	return 0;

error_out:
	return -1;
}

static __rte_always_inline int
fill_sess_gmac(struct rte_crypto_sym_xform *xform,
		 struct cpt_sess_misc *sess)
{
	struct rte_crypto_auth_xform *a_form;
	cipher_type_t enc_type = 0; /* NULL Cipher type */
	auth_type_t auth_type = 0; /* NULL Auth type */
	uint8_t zsk_flag = 0, aes_gcm = 0;
	void *ctx;

	if (xform->type != RTE_CRYPTO_SYM_XFORM_AUTH)
		return -1;

	a_form = &xform->auth;

	if (a_form->op == RTE_CRYPTO_AUTH_OP_GENERATE)
		sess->cpt_op |= CPT_OP_ENCODE;
	else if (a_form->op == RTE_CRYPTO_AUTH_OP_VERIFY)
		sess->cpt_op |= CPT_OP_DECODE;
	else {
		CPT_LOG_DP_ERR("Unknown auth operation");
		return -1;
	}

	switch (a_form->algo) {
	case RTE_CRYPTO_AUTH_AES_GMAC:
		enc_type = AES_GCM;
		auth_type = GMAC_TYPE;
		break;
	default:
		CPT_LOG_DP_ERR("Crypto: Undefined cipher algo %u specified",
			       a_form->algo);
		return -1;
	}

	sess->zsk_flag = zsk_flag;
	sess->aes_gcm = aes_gcm;
	sess->is_gmac = 1;
	sess->iv_offset = a_form->iv.offset;
	sess->iv_length = a_form->iv.length;
	sess->mac_len = a_form->digest_length;
	ctx = (void *)((uint8_t *)sess + sizeof(struct cpt_sess_misc)),

	cpt_fc_ciph_set_key(ctx, enc_type, a_form->key.data,
			a_form->key.length, NULL);
	cpt_fc_auth_set_key(ctx, auth_type, NULL, 0, a_form->digest_length);

	return 0;
}

static __rte_always_inline void *
alloc_op_meta(struct rte_mbuf *m_src,
	      buf_ptr_t *buf,
	      int32_t len,
	      struct rte_mempool *cpt_meta_pool)
{
	uint8_t *mdata;

#ifndef CPT_ALWAYS_USE_SEPARATE_BUF
	if (likely(m_src && (m_src->nb_segs == 1))) {
		int32_t tailroom;
		phys_addr_t mphys;

		/* Check if tailroom is sufficient to hold meta data */
		tailroom = rte_pktmbuf_tailroom(m_src);
		if (likely(tailroom > len + 8)) {
			mdata = (uint8_t *)m_src->buf_addr + m_src->buf_len;
			mphys = m_src->buf_physaddr + m_src->buf_len;
			mdata -= len;
			mphys -= len;
			buf->vaddr = mdata;
			buf->dma_addr = mphys;
			buf->size = len;
			/* Indicate that this is a mbuf allocated mdata */
			mdata = (uint8_t *)((uint64_t)mdata | 1ull);
			return mdata;
		}
	}
#else
	RTE_SET_USED(m_src);
#endif

	if (unlikely(rte_mempool_get(cpt_meta_pool, (void **)&mdata) < 0))
		return NULL;

	buf->vaddr = mdata;
	buf->dma_addr = rte_mempool_virt2iova(mdata);
	buf->size = len;

	return mdata;
}

/**
 * cpt_free_metabuf - free metabuf to mempool.
 * @param instance: pointer to instance.
 * @param objp: pointer to the metabuf.
 */
static __rte_always_inline void
free_op_meta(void *mdata, struct rte_mempool *cpt_meta_pool)
{
	bool nofree = ((uintptr_t)mdata & 1ull);

	if (likely(nofree))
		return;
	rte_mempool_put(cpt_meta_pool, mdata);
}

static __rte_always_inline uint32_t
prepare_iov_from_pkt(struct rte_mbuf *pkt,
		     iov_ptr_t *iovec, uint32_t start_offset)
{
	uint16_t index = 0;
	void *seg_data = NULL;
	phys_addr_t seg_phys;
	int32_t seg_size = 0;

	if (!pkt) {
		iovec->buf_cnt = 0;
		return 0;
	}

	if (!start_offset) {
		seg_data = rte_pktmbuf_mtod(pkt, void *);
		seg_phys = rte_pktmbuf_mtophys(pkt);
		seg_size = pkt->data_len;
	} else {
		while (start_offset >= pkt->data_len) {
			start_offset -= pkt->data_len;
			pkt = pkt->next;
		}

		seg_data = rte_pktmbuf_mtod_offset(pkt, void *, start_offset);
		seg_phys = rte_pktmbuf_mtophys_offset(pkt, start_offset);
		seg_size = pkt->data_len - start_offset;
		if (!seg_size)
			return 1;
	}

	/* first seg */
	iovec->bufs[index].vaddr = seg_data;
	iovec->bufs[index].dma_addr = seg_phys;
	iovec->bufs[index].size = seg_size;
	index++;
	pkt = pkt->next;

	while (unlikely(pkt != NULL)) {
		seg_data = rte_pktmbuf_mtod(pkt, void *);
		seg_phys = rte_pktmbuf_mtophys(pkt);
		seg_size = pkt->data_len;
		if (!seg_size)
			break;

		iovec->bufs[index].vaddr = seg_data;
		iovec->bufs[index].dma_addr = seg_phys;
		iovec->bufs[index].size = seg_size;

		index++;

		pkt = pkt->next;
	}

	iovec->buf_cnt = index;
	return 0;
}

static __rte_always_inline uint32_t
prepare_iov_from_pkt_inplace(struct rte_mbuf *pkt,
			     fc_params_t *param,
			     uint32_t *flags)
{
	uint16_t index = 0;
	void *seg_data = NULL;
	phys_addr_t seg_phys;
	uint32_t seg_size = 0;
	iov_ptr_t *iovec;

	seg_data = rte_pktmbuf_mtod(pkt, void *);
	seg_phys = rte_pktmbuf_mtophys(pkt);
	seg_size = pkt->data_len;

	/* first seg */
	if (likely(!pkt->next)) {
		uint32_t headroom, tailroom;

		*flags |= SINGLE_BUF_INPLACE;
		headroom = rte_pktmbuf_headroom(pkt);
		tailroom = rte_pktmbuf_tailroom(pkt);
		if (likely((headroom >= 24) &&
		    (tailroom >= 8))) {
			/* In 83XX this is prerequivisit for Direct mode */
			*flags |= SINGLE_BUF_HEADTAILROOM;
		}
		param->bufs[0].vaddr = seg_data;
		param->bufs[0].dma_addr = seg_phys;
		param->bufs[0].size = seg_size;
		return 0;
	}
	iovec = param->src_iov;
	iovec->bufs[index].vaddr = seg_data;
	iovec->bufs[index].dma_addr = seg_phys;
	iovec->bufs[index].size = seg_size;
	index++;
	pkt = pkt->next;

	while (unlikely(pkt != NULL)) {
		seg_data = rte_pktmbuf_mtod(pkt, void *);
		seg_phys = rte_pktmbuf_mtophys(pkt);
		seg_size = pkt->data_len;

		if (!seg_size)
			break;

		iovec->bufs[index].vaddr = seg_data;
		iovec->bufs[index].dma_addr = seg_phys;
		iovec->bufs[index].size = seg_size;

		index++;

		pkt = pkt->next;
	}

	iovec->buf_cnt = index;
	return 0;
}

static __rte_always_inline void *
fill_fc_params(struct rte_crypto_op *cop,
	       struct cpt_sess_misc *sess_misc,
	       void **mdata_ptr,
	       int *op_ret)
{
	uint32_t space = 0;
	struct rte_crypto_sym_op *sym_op = cop->sym;
	void *mdata;
	uintptr_t *op;
	uint32_t mc_hash_off;
	uint32_t flags = 0;
	uint64_t d_offs, d_lens;
	void *prep_req = NULL;
	struct rte_mbuf *m_src, *m_dst;
	uint8_t cpt_op = sess_misc->cpt_op;
	uint8_t zsk_flag = sess_misc->zsk_flag;
	uint8_t aes_gcm = sess_misc->aes_gcm;
	uint16_t mac_len = sess_misc->mac_len;
#ifdef CPT_ALWAYS_USE_SG_MODE
	uint8_t inplace = 0;
#else
	uint8_t inplace = 1;
#endif
	fc_params_t fc_params;
	char src[SRC_IOV_SIZE];
	char dst[SRC_IOV_SIZE];
	uint32_t iv_buf[4];
	struct cptvf_meta_info *cpt_m_info =
				(struct cptvf_meta_info *)(*mdata_ptr);

	if (likely(sess_misc->iv_length)) {
		flags |= VALID_IV_BUF;
		fc_params.iv_buf = rte_crypto_op_ctod_offset(cop,
				   uint8_t *, sess_misc->iv_offset);
		if (sess_misc->aes_ctr &&
		    unlikely(sess_misc->iv_length != 16)) {
			memcpy((uint8_t *)iv_buf,
				rte_crypto_op_ctod_offset(cop,
				uint8_t *, sess_misc->iv_offset), 12);
			iv_buf[3] = rte_cpu_to_be_32(0x1);
			fc_params.iv_buf = iv_buf;
		}
	}

	if (zsk_flag) {
		fc_params.auth_iv_buf = rte_crypto_op_ctod_offset(cop,
					uint8_t *,
					sess_misc->auth_iv_offset);
		if (zsk_flag == K_F9) {
			CPT_LOG_DP_ERR("Should not reach here for "
			"kasumi F9\n");
		}
		if (zsk_flag != ZS_EA)
			inplace = 0;
	}
	m_src = sym_op->m_src;
	m_dst = sym_op->m_dst;

	if (aes_gcm) {
		uint8_t *salt;
		uint8_t *aad_data;
		uint16_t aad_len;

		d_offs = sym_op->aead.data.offset;
		d_lens = sym_op->aead.data.length;
		mc_hash_off = sym_op->aead.data.offset +
			      sym_op->aead.data.length;

		aad_data = sym_op->aead.aad.data;
		aad_len = sess_misc->aad_length;
		if (likely((aad_data + aad_len) ==
			   rte_pktmbuf_mtod_offset(m_src,
				uint8_t *,
				sym_op->aead.data.offset))) {
			d_offs = (d_offs - aad_len) | (d_offs << 16);
			d_lens = (d_lens + aad_len) | (d_lens << 32);
		} else {
			fc_params.aad_buf.vaddr = sym_op->aead.aad.data;
			fc_params.aad_buf.dma_addr = sym_op->aead.aad.phys_addr;
			fc_params.aad_buf.size = aad_len;
			flags |= VALID_AAD_BUF;
			inplace = 0;
			d_offs = d_offs << 16;
			d_lens = d_lens << 32;
		}

		salt = fc_params.iv_buf;
		if (unlikely(*(uint32_t *)salt != sess_misc->salt)) {
			cpt_fc_salt_update(SESS_PRIV(sess_misc), salt);
			sess_misc->salt = *(uint32_t *)salt;
		}
		fc_params.iv_buf = salt + 4;
		if (likely(mac_len)) {
			struct rte_mbuf *m = (cpt_op & CPT_OP_ENCODE) ? m_dst :
					     m_src;

			if (!m)
				m = m_src;

			/* hmac immediately following data is best case */
			if (unlikely(rte_pktmbuf_mtod(m, uint8_t *) +
			    mc_hash_off !=
			    (uint8_t *)sym_op->aead.digest.data)) {
				flags |= VALID_MAC_BUF;
				fc_params.mac_buf.size = sess_misc->mac_len;
				fc_params.mac_buf.vaddr =
				  sym_op->aead.digest.data;
				fc_params.mac_buf.dma_addr =
				 sym_op->aead.digest.phys_addr;
				inplace = 0;
			}
		}
	} else {
		d_offs = sym_op->cipher.data.offset;
		d_lens = sym_op->cipher.data.length;
		mc_hash_off = sym_op->cipher.data.offset +
			      sym_op->cipher.data.length;
		d_offs = (d_offs << 16) | sym_op->auth.data.offset;
		d_lens = (d_lens << 32) | sym_op->auth.data.length;

		if (mc_hash_off < (sym_op->auth.data.offset +
				   sym_op->auth.data.length)){
			mc_hash_off = (sym_op->auth.data.offset +
				       sym_op->auth.data.length);
		}
		/* for gmac, salt should be updated like in gcm */
		if (unlikely(sess_misc->is_gmac)) {
			uint8_t *salt;
			salt = fc_params.iv_buf;
			if (unlikely(*(uint32_t *)salt != sess_misc->salt)) {
				cpt_fc_salt_update(SESS_PRIV(sess_misc), salt);
				sess_misc->salt = *(uint32_t *)salt;
			}
			fc_params.iv_buf = salt + 4;
		}
		if (likely(mac_len)) {
			struct rte_mbuf *m;

			m = (cpt_op & CPT_OP_ENCODE) ? m_dst : m_src;
			if (!m)
				m = m_src;

			/* hmac immediately following data is best case */
			if (unlikely(rte_pktmbuf_mtod(m, uint8_t *) +
			    mc_hash_off !=
			     (uint8_t *)sym_op->auth.digest.data)) {
				flags |= VALID_MAC_BUF;
				fc_params.mac_buf.size =
					sess_misc->mac_len;
				fc_params.mac_buf.vaddr =
					sym_op->auth.digest.data;
				fc_params.mac_buf.dma_addr =
				sym_op->auth.digest.phys_addr;
				inplace = 0;
			}
		}
	}
	fc_params.ctx_buf.vaddr = SESS_PRIV(sess_misc);
	fc_params.ctx_buf.dma_addr = sess_misc->ctx_dma_addr;

	if (unlikely(sess_misc->is_null || sess_misc->cpt_op == CPT_OP_DECODE))
		inplace = 0;

	if (likely(!m_dst && inplace)) {
		/* Case of single buffer without AAD buf or
		 * separate mac buf in place and
		 * not air crypto
		 */
		fc_params.dst_iov = fc_params.src_iov = (void *)src;

		if (unlikely(prepare_iov_from_pkt_inplace(m_src,
							  &fc_params,
							  &flags))) {
			CPT_LOG_DP_ERR("Prepare inplace src iov failed");
			*op_ret = -1;
			return NULL;
		}

	} else {
		/* Out of place processing */
		fc_params.src_iov = (void *)src;
		fc_params.dst_iov = (void *)dst;

		/* Store SG I/O in the api for reuse */
		if (prepare_iov_from_pkt(m_src, fc_params.src_iov, 0)) {
			CPT_LOG_DP_ERR("Prepare src iov failed");
			*op_ret = -1;
			return NULL;
		}

		if (unlikely(m_dst != NULL)) {
			uint32_t pkt_len;

			/* Try to make room as much as src has */
			m_dst = sym_op->m_dst;
			pkt_len = rte_pktmbuf_pkt_len(m_dst);

			if (unlikely(pkt_len < rte_pktmbuf_pkt_len(m_src))) {
				pkt_len = rte_pktmbuf_pkt_len(m_src) - pkt_len;
				if (!rte_pktmbuf_append(m_dst, pkt_len)) {
					CPT_LOG_DP_ERR("Not enough space in "
						       "m_dst %p, need %u"
						       " more",
						       m_dst, pkt_len);
					return NULL;
				}
			}

			if (prepare_iov_from_pkt(m_dst, fc_params.dst_iov, 0)) {
				CPT_LOG_DP_ERR("Prepare dst iov failed for "
					       "m_dst %p", m_dst);
				return NULL;
			}
		} else {
			fc_params.dst_iov = (void *)src;
		}
	}

	if (likely(flags & SINGLE_BUF_HEADTAILROOM))
		mdata = alloc_op_meta(m_src,
				      &fc_params.meta_buf,
				      cpt_m_info->cptvf_op_sb_mlen,
				      cpt_m_info->cptvf_meta_pool);
	else
		mdata = alloc_op_meta(NULL,
				      &fc_params.meta_buf,
				      cpt_m_info->cptvf_op_mlen,
				      cpt_m_info->cptvf_meta_pool);

	if (unlikely(mdata == NULL)) {
		CPT_LOG_DP_ERR("Error allocating meta buffer for request");
		return NULL;
	}

	op = (uintptr_t *)((uintptr_t)mdata & (uintptr_t)~1ull);
	op[0] = (uintptr_t)mdata;
	op[1] = (uintptr_t)cop;
	op[2] = op[3] = 0; /* Used to indicate auth verify */
	space += 4 * sizeof(uint64_t);

	fc_params.meta_buf.vaddr = (uint8_t *)op + space;
	fc_params.meta_buf.dma_addr += space;
	fc_params.meta_buf.size -= space;

	/* Finally prepare the instruction */
	if (cpt_op & CPT_OP_ENCODE)
		prep_req = cpt_fc_enc_hmac_prep(flags, d_offs, d_lens,
						&fc_params, op, op_ret);
	else
		prep_req = cpt_fc_dec_hmac_prep(flags, d_offs, d_lens,
						&fc_params, op, op_ret);

	if (unlikely(!prep_req))
		free_op_meta(mdata, cpt_m_info->cptvf_meta_pool);
	*mdata_ptr = mdata;
	return prep_req;
}

static __rte_always_inline void
compl_auth_verify(struct rte_crypto_op *op,
		      uint8_t *gen_mac,
		      uint64_t mac_len)
{
	uint8_t *mac;
	struct rte_crypto_sym_op *sym_op = op->sym;

	if (sym_op->auth.digest.data)
		mac = sym_op->auth.digest.data;
	else
		mac = rte_pktmbuf_mtod_offset(sym_op->m_src,
					      uint8_t *,
					      sym_op->auth.data.length +
					      sym_op->auth.data.offset);
	if (!mac) {
		op->status = RTE_CRYPTO_OP_STATUS_ERROR;
		return;
	}

	if (memcmp(mac, gen_mac, mac_len))
		op->status = RTE_CRYPTO_OP_STATUS_AUTH_FAILED;
	else
		op->status = RTE_CRYPTO_OP_STATUS_SUCCESS;
}

static __rte_always_inline int
instance_session_cfg(struct rte_crypto_sym_xform *xform, void *sess)
{
	struct rte_crypto_sym_xform *chain;

	CPT_PMD_INIT_FUNC_TRACE();

	if (cpt_is_algo_supported(xform))
		goto err;

	chain = xform;
	while (chain) {
		switch (chain->type) {
		case RTE_CRYPTO_SYM_XFORM_AEAD:
			if (fill_sess_aead(chain, sess))
				goto err;
			break;
		case RTE_CRYPTO_SYM_XFORM_CIPHER:
			if (fill_sess_cipher(chain, sess))
				goto err;
			break;
		case RTE_CRYPTO_SYM_XFORM_AUTH:
			if (chain->auth.algo == RTE_CRYPTO_AUTH_AES_GMAC) {
				if (fill_sess_gmac(chain, sess))
					goto err;
			} else {
				if (fill_sess_auth(chain, sess))
					goto err;
			}
			break;
		default:
			CPT_LOG_DP_ERR("Invalid crypto xform type");
			break;
		}
		chain = chain->next;
	}

	return 0;

err:
	return -1;
}

static __rte_always_inline void
find_kasumif9_direction_and_length(uint8_t *src,
				   uint32_t counter_num_bytes,
				   uint32_t *addr_length_in_bits,
				   uint8_t *addr_direction)
{
	uint8_t found = 0;
	uint32_t pos;
	uint8_t last_byte;
	while (!found && counter_num_bytes > 0) {
		counter_num_bytes--;
		if (src[counter_num_bytes] == 0x00)
			continue;
		pos = rte_bsf32(src[counter_num_bytes]);
		if (pos == 7) {
			if (likely(counter_num_bytes > 0)) {
				last_byte = src[counter_num_bytes - 1];
				*addr_direction  =  last_byte & 0x1;
				*addr_length_in_bits = counter_num_bytes * 8
							- 1;
			}
		} else {
			last_byte = src[counter_num_bytes];
			*addr_direction = (last_byte >> (pos + 1)) & 0x1;
			*addr_length_in_bits = counter_num_bytes * 8
						+ (8 - (pos + 2));
		}
		found = 1;
	}
}

/*
 * This handles all auth only except AES_GMAC
 */
static __rte_always_inline void *
fill_digest_params(struct rte_crypto_op *cop,
		   struct cpt_sess_misc *sess,
		   void **mdata_ptr,
		   int *op_ret)
{
	uint32_t space = 0;
	struct rte_crypto_sym_op *sym_op = cop->sym;
	void *mdata;
	phys_addr_t mphys;
	uint64_t *op;
	uint32_t auth_range_off;
	uint32_t flags = 0;
	uint64_t d_offs = 0, d_lens;
	void *prep_req = NULL;
	struct rte_mbuf *m_src, *m_dst;
	uint16_t auth_op = sess->cpt_op & CPT_OP_AUTH_MASK;
	uint8_t zsk_flag = sess->zsk_flag;
	uint16_t mac_len = sess->mac_len;
	fc_params_t params;
	char src[SRC_IOV_SIZE];
	uint8_t iv_buf[16];
	memset(&params, 0, sizeof(fc_params_t));
	struct cptvf_meta_info *cpt_m_info =
				(struct cptvf_meta_info *)(*mdata_ptr);

	m_src = sym_op->m_src;

	/* For just digest lets force mempool alloc */
	mdata = alloc_op_meta(NULL, &params.meta_buf, cpt_m_info->cptvf_op_mlen,
			      cpt_m_info->cptvf_meta_pool);
	if (mdata == NULL) {
		CPT_LOG_DP_ERR("Error allocating meta buffer for request");
		*op_ret = -ENOMEM;
		return NULL;
	}

	mphys = params.meta_buf.dma_addr;

	op = mdata;
	op[0] = (uintptr_t)mdata;
	op[1] = (uintptr_t)cop;
	op[2] = op[3] = 0; /* Used to indicate auth verify */
	space += 4 * sizeof(uint64_t);

	auth_range_off = sym_op->auth.data.offset;

	flags = VALID_MAC_BUF;
	params.src_iov = (void *)src;
	if (unlikely(zsk_flag)) {
		/*
		 * Since for Zuc, Kasumi, Snow3g offsets are in bits
		 * we will send pass through even for auth only case,
		 * let MC handle it
		 */
		d_offs = auth_range_off;
		auth_range_off = 0;
		params.auth_iv_buf = rte_crypto_op_ctod_offset(cop,
					uint8_t *, sess->auth_iv_offset);
		if (zsk_flag == K_F9) {
			uint32_t length_in_bits, num_bytes;
			uint8_t *src, direction = 0;
			uint32_t counter_num_bytes;

			memcpy(iv_buf, rte_pktmbuf_mtod(cop->sym->m_src,
							uint8_t *), 8);
			/*
			 * This is kasumi f9, take direction from
			 * source buffer
			 */
			length_in_bits = cop->sym->auth.data.length;
			num_bytes = (length_in_bits >> 3);
			counter_num_bytes = num_bytes;
			src = rte_pktmbuf_mtod(cop->sym->m_src, uint8_t *);
			find_kasumif9_direction_and_length(src,
						counter_num_bytes,
						&length_in_bits,
						&direction);
			length_in_bits -= 64;
			cop->sym->auth.data.offset += 64;
			d_offs = cop->sym->auth.data.offset;
			auth_range_off = d_offs / 8;
			cop->sym->auth.data.length = length_in_bits;

			/* Store it at end of auth iv */
			iv_buf[8] = direction;
			params.auth_iv_buf = iv_buf;
		}
	}

	d_lens = sym_op->auth.data.length;

	params.ctx_buf.vaddr = SESS_PRIV(sess);
	params.ctx_buf.dma_addr = sess->ctx_dma_addr;

	if (auth_op == CPT_OP_AUTH_GENERATE) {
		if (sym_op->auth.digest.data) {
			/*
			 * Digest to be generated
			 * in separate buffer
			 */
			params.mac_buf.size =
				sess->mac_len;
			params.mac_buf.vaddr =
				sym_op->auth.digest.data;
			params.mac_buf.dma_addr =
				sym_op->auth.digest.phys_addr;
		} else {
			uint32_t off = sym_op->auth.data.offset +
				sym_op->auth.data.length;
			int32_t dlen, space;

			m_dst = sym_op->m_dst ?
				sym_op->m_dst : sym_op->m_src;
			dlen = rte_pktmbuf_pkt_len(m_dst);

			space = off + mac_len - dlen;
			if (space > 0)
				if (!rte_pktmbuf_append(m_dst, space)) {
					CPT_LOG_DP_ERR("Failed to extend "
						       "mbuf by %uB", space);
					goto err;
				}

			params.mac_buf.vaddr =
				rte_pktmbuf_mtod_offset(m_dst, void *, off);
			params.mac_buf.dma_addr =
				rte_pktmbuf_mtophys_offset(m_dst, off);
			params.mac_buf.size = mac_len;
		}
	} else {
		/* Need space for storing generated mac */
		params.mac_buf.vaddr = (uint8_t *)mdata + space;
		params.mac_buf.dma_addr = mphys + space;
		params.mac_buf.size = mac_len;
		space += RTE_ALIGN_CEIL(mac_len, 8);
		op[2] = (uintptr_t)params.mac_buf.vaddr;
		op[3] = mac_len;
	}

	params.meta_buf.vaddr = (uint8_t *)mdata + space;
	params.meta_buf.dma_addr = mphys + space;
	params.meta_buf.size -= space;

	/* Out of place processing */
	params.src_iov = (void *)src;

	/*Store SG I/O in the api for reuse */
	if (prepare_iov_from_pkt(m_src, params.src_iov, auth_range_off)) {
		CPT_LOG_DP_ERR("Prepare src iov failed");
		*op_ret = -1;
		goto err;
	}

	prep_req = cpt_fc_enc_hmac_prep(flags, d_offs, d_lens,
					&params, op, op_ret);
	*mdata_ptr = mdata;
	return prep_req;
err:
	if (unlikely(!prep_req))
		free_op_meta(mdata, cpt_m_info->cptvf_meta_pool);
	return NULL;
}

#endif /*_CPT_UCODE_H_ */
