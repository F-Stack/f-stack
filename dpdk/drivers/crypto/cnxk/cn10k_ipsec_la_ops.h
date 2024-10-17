/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#ifndef __CN10K_IPSEC_LA_OPS_H__
#define __CN10K_IPSEC_LA_OPS_H__

#include <rte_crypto_sym.h>
#include <rte_security.h>

#include "cn10k_cryptodev.h"
#include "cn10k_ipsec.h"
#include "cnxk_cryptodev.h"

static inline void
ipsec_po_sa_iv_set(struct cn10k_sec_session *sess, struct rte_crypto_op *cop)
{
	uint64_t *iv = &sess->sa.out_sa.iv.u64[0];
	uint64_t *tmp_iv;

	memcpy(iv, rte_crypto_op_ctod_offset(cop, uint8_t *, sess->iv_offset), 16);
	tmp_iv = (uint64_t *)iv;
	*tmp_iv = rte_be_to_cpu_64(*tmp_iv);

	tmp_iv = (uint64_t *)(iv + 1);
	*tmp_iv = rte_be_to_cpu_64(*tmp_iv);
}

static inline void
ipsec_po_sa_aes_gcm_iv_set(struct cn10k_sec_session *sess, struct rte_crypto_op *cop)
{
	uint8_t *iv = &sess->sa.out_sa.iv.s.iv_dbg1[0];
	uint32_t *tmp_iv;

	memcpy(iv, rte_crypto_op_ctod_offset(cop, uint8_t *, sess->iv_offset), 4);
	tmp_iv = (uint32_t *)iv;
	*tmp_iv = rte_be_to_cpu_32(*tmp_iv);

	iv = &sess->sa.out_sa.iv.s.iv_dbg2[0];
	memcpy(iv, rte_crypto_op_ctod_offset(cop, uint8_t *, sess->iv_offset + 4), 4);
	tmp_iv = (uint32_t *)iv;
	*tmp_iv = rte_be_to_cpu_32(*tmp_iv);
}

static __rte_always_inline int
process_outb_sa(struct roc_cpt_lf *lf, struct rte_crypto_op *cop, struct cn10k_sec_session *sess,
		struct cpt_inst_s *inst)
{
	struct rte_crypto_sym_op *sym_op = cop->sym;
	struct rte_mbuf *m_src = sym_op->m_src;
	uint64_t inst_w4_u64 = sess->inst.w4;
	uint64_t dptr;

	if (unlikely(rte_pktmbuf_tailroom(m_src) < sess->max_extended_len)) {
		plt_dp_err("Not enough tail room");
		return -ENOMEM;
	}

	RTE_SET_USED(lf);

#ifdef LA_IPSEC_DEBUG
	if (sess->sa.out_sa.w2.s.iv_src == ROC_IE_OT_SA_IV_SRC_FROM_SA) {
		if (sess->sa.out_sa.w2.s.enc_type == ROC_IE_OT_SA_ENC_AES_GCM ||
		    sess->sa.out_sa.w2.s.enc_type == ROC_IE_OT_SA_ENC_AES_CCM ||
		    sess->sa.out_sa.w2.s.auth_type == ROC_IE_OT_SA_AUTH_AES_GMAC)
			ipsec_po_sa_aes_gcm_iv_set(sess, cop);
		else
			ipsec_po_sa_iv_set(sess, cop);
	}

	/* Trigger CTX reload to fetch new data from DRAM */
	roc_cpt_lf_ctx_reload(lf, &sess->sa.out_sa);
	rte_delay_ms(1);
#endif

	if (m_src->ol_flags & RTE_MBUF_F_TX_IP_CKSUM)
		inst_w4_u64 &= ~BIT_ULL(33);

	if (m_src->ol_flags & RTE_MBUF_F_TX_L4_MASK)
		inst_w4_u64 &= ~BIT_ULL(32);

	/* Prepare CPT instruction */
	inst->w4.u64 = inst_w4_u64 | rte_pktmbuf_pkt_len(m_src);
	dptr = rte_pktmbuf_mtod(m_src, uint64_t);
	inst->dptr = dptr;

	return 0;
}

static __rte_always_inline int
process_inb_sa(struct rte_crypto_op *cop, struct cn10k_sec_session *sess, struct cpt_inst_s *inst)
{
	struct rte_crypto_sym_op *sym_op = cop->sym;
	struct rte_mbuf *m_src = sym_op->m_src;
	uint64_t dptr;

	/* Prepare CPT instruction */
	inst->w4.u64 = sess->inst.w4 | rte_pktmbuf_pkt_len(m_src);
	dptr = rte_pktmbuf_mtod(m_src, uint64_t);
	inst->dptr = dptr;

	return 0;
}

#endif /* __CN10K_IPSEC_LA_OPS_H__ */
