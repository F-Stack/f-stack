/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <cryptodev_pmd.h>
#include <rte_esp.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_security.h>
#include <rte_security_driver.h>
#include <rte_udp.h>

#include "cn10k_ipsec.h"
#include "cnxk_cryptodev.h"
#include "cnxk_cryptodev_ops.h"
#include "cnxk_ipsec.h"
#include "cnxk_security.h"

#include "roc_api.h"

static uint64_t
ipsec_cpt_inst_w7_get(struct roc_cpt *roc_cpt, void *sa)
{
	union cpt_inst_w7 w7;

	w7.u64 = 0;
	w7.s.egrp = roc_cpt->eng_grp[CPT_ENG_TYPE_IE];
	w7.s.ctx_val = 1;
	w7.s.cptr = (uint64_t)sa;
	rte_mb();

	return w7.u64;
}

static int
cn10k_ipsec_outb_sa_create(struct roc_cpt *roc_cpt, struct roc_cpt_lf *lf,
			   struct rte_security_ipsec_xform *ipsec_xfrm,
			   struct rte_crypto_sym_xform *crypto_xfrm,
			   struct cn10k_sec_session *sec_sess)
{
	union roc_ot_ipsec_outb_param1 param1;
	struct roc_ot_ipsec_outb_sa *sa_dptr;
	struct cnxk_ipsec_outb_rlens rlens;
	struct cn10k_ipsec_sa *sa;
	union cpt_inst_w4 inst_w4;
	void *out_sa;
	int ret = 0;

	sa = &sec_sess->sa;
	out_sa = &sa->out_sa;

	/* Allocate memory to be used as dptr for CPT ucode WRITE_SA op */
	sa_dptr = plt_zmalloc(sizeof(struct roc_ot_ipsec_outb_sa), 8);
	if (sa_dptr == NULL) {
		plt_err("Couldn't allocate memory for SA dptr");
		return -ENOMEM;
	}

	/* Translate security parameters to SA */
	ret = cnxk_ot_ipsec_outb_sa_fill(sa_dptr, ipsec_xfrm, crypto_xfrm);
	if (ret) {
		plt_err("Could not fill outbound session parameters");
		goto sa_dptr_free;
	}

	sec_sess->inst.w7 = ipsec_cpt_inst_w7_get(roc_cpt, out_sa);

#ifdef LA_IPSEC_DEBUG
	/* Use IV from application in debug mode */
	if (ipsec_xfrm->options.iv_gen_disable == 1) {
		sa_dptr->w2.s.iv_src = ROC_IE_OT_SA_IV_SRC_FROM_SA;
		if (crypto_xfrm->type == RTE_CRYPTO_SYM_XFORM_AEAD) {
			sec_sess->iv_offset = crypto_xfrm->aead.iv.offset;
			sec_sess->iv_length = crypto_xfrm->aead.iv.length;
		} else if (crypto_xfrm->type == RTE_CRYPTO_SYM_XFORM_CIPHER) {
			sec_sess->iv_offset = crypto_xfrm->cipher.iv.offset;
			sec_sess->iv_length = crypto_xfrm->cipher.iv.length;
		} else {
			sec_sess->iv_offset = crypto_xfrm->auth.iv.offset;
			sec_sess->iv_length = crypto_xfrm->auth.iv.length;
		}
	}
#else
	if (ipsec_xfrm->options.iv_gen_disable != 0) {
		plt_err("Application provided IV not supported");
		ret = -ENOTSUP;
		goto sa_dptr_free;
	}
#endif

	sec_sess->is_outbound = true;

	/* Get Rlen calculation data */
	ret = cnxk_ipsec_outb_rlens_get(&rlens, ipsec_xfrm, crypto_xfrm);
	if (ret)
		goto sa_dptr_free;

	sec_sess->max_extended_len = rlens.max_extended_len;

	/* pre-populate CPT INST word 4 */
	inst_w4.u64 = 0;
	inst_w4.s.opcode_major = ROC_IE_OT_MAJOR_OP_PROCESS_OUTBOUND_IPSEC | ROC_IE_OT_INPLACE_BIT;

	param1.u16 = 0;

	param1.s.ttl_or_hop_limit = ipsec_xfrm->options.dec_ttl;

	/* Disable IP checksum computation by default */
	param1.s.ip_csum_disable = ROC_IE_OT_SA_INNER_PKT_IP_CSUM_DISABLE;

	if (ipsec_xfrm->options.ip_csum_enable) {
		param1.s.ip_csum_disable =
			ROC_IE_OT_SA_INNER_PKT_IP_CSUM_ENABLE;
	}

	/* Disable L4 checksum computation by default */
	param1.s.l4_csum_disable = ROC_IE_OT_SA_INNER_PKT_L4_CSUM_DISABLE;

	if (ipsec_xfrm->options.l4_csum_enable) {
		param1.s.l4_csum_disable =
			ROC_IE_OT_SA_INNER_PKT_L4_CSUM_ENABLE;
	}

	inst_w4.s.param1 = param1.u16;

	sec_sess->inst.w4 = inst_w4.u64;

	if (ipsec_xfrm->options.stats == 1) {
		/* Enable mib counters */
		sa_dptr->w0.s.count_mib_bytes = 1;
		sa_dptr->w0.s.count_mib_pkts = 1;
	}

	memset(out_sa, 0, sizeof(struct roc_ot_ipsec_outb_sa));

	/* Copy word0 from sa_dptr to populate ctx_push_sz ctx_size fields */
	memcpy(out_sa, sa_dptr, 8);

	plt_atomic_thread_fence(__ATOMIC_SEQ_CST);

	/* Write session using microcode opcode */
	ret = roc_cpt_ctx_write(lf, sa_dptr, out_sa,
				sizeof(struct roc_ot_ipsec_outb_sa));
	if (ret) {
		plt_err("Could not write outbound session to hardware");
		goto sa_dptr_free;
	}

	/* Trigger CTX flush so that data is written back to DRAM */
	roc_cpt_lf_ctx_flush(lf, out_sa, false);

	plt_atomic_thread_fence(__ATOMIC_SEQ_CST);

sa_dptr_free:
	plt_free(sa_dptr);

	return ret;
}

static int
cn10k_ipsec_inb_sa_create(struct roc_cpt *roc_cpt, struct roc_cpt_lf *lf,
			  struct rte_security_ipsec_xform *ipsec_xfrm,
			  struct rte_crypto_sym_xform *crypto_xfrm,
			  struct cn10k_sec_session *sec_sess)
{
	union roc_ot_ipsec_inb_param1 param1;
	struct roc_ot_ipsec_inb_sa *sa_dptr;
	struct cn10k_ipsec_sa *sa;
	union cpt_inst_w4 inst_w4;
	void *in_sa;
	int ret = 0;

	sa = &sec_sess->sa;
	in_sa = &sa->in_sa;

	/* Allocate memory to be used as dptr for CPT ucode WRITE_SA op */
	sa_dptr = plt_zmalloc(sizeof(struct roc_ot_ipsec_inb_sa), 8);
	if (sa_dptr == NULL) {
		plt_err("Couldn't allocate memory for SA dptr");
		return -ENOMEM;
	}

	/* Translate security parameters to SA */
	ret = cnxk_ot_ipsec_inb_sa_fill(sa_dptr, ipsec_xfrm, crypto_xfrm,
					false);
	if (ret) {
		plt_err("Could not fill inbound session parameters");
		goto sa_dptr_free;
	}

	sec_sess->is_outbound = false;
	sec_sess->inst.w7 = ipsec_cpt_inst_w7_get(roc_cpt, in_sa);

	/* pre-populate CPT INST word 4 */
	inst_w4.u64 = 0;
	inst_w4.s.opcode_major = ROC_IE_OT_MAJOR_OP_PROCESS_INBOUND_IPSEC | ROC_IE_OT_INPLACE_BIT;

	param1.u16 = 0;

	/* Disable IP checksum verification by default */
	param1.s.ip_csum_disable = ROC_IE_OT_SA_INNER_PKT_IP_CSUM_DISABLE;

	if (ipsec_xfrm->options.ip_csum_enable) {
		param1.s.ip_csum_disable =
			ROC_IE_OT_SA_INNER_PKT_IP_CSUM_ENABLE;
	}

	/* Disable L4 checksum verification by default */
	param1.s.l4_csum_disable = ROC_IE_OT_SA_INNER_PKT_L4_CSUM_DISABLE;

	if (ipsec_xfrm->options.l4_csum_enable) {
		param1.s.l4_csum_disable =
			ROC_IE_OT_SA_INNER_PKT_L4_CSUM_ENABLE;
	}

	param1.s.esp_trailer_disable = 1;

	inst_w4.s.param1 = param1.u16;

	sec_sess->inst.w4 = inst_w4.u64;

	if (ipsec_xfrm->options.stats == 1) {
		/* Enable mib counters */
		sa_dptr->w0.s.count_mib_bytes = 1;
		sa_dptr->w0.s.count_mib_pkts = 1;
	}

	memset(in_sa, 0, sizeof(struct roc_ot_ipsec_inb_sa));

	/* Copy word0 from sa_dptr to populate ctx_push_sz ctx_size fields */
	memcpy(in_sa, sa_dptr, 8);

	plt_atomic_thread_fence(__ATOMIC_SEQ_CST);

	/* Write session using microcode opcode */
	ret = roc_cpt_ctx_write(lf, sa_dptr, in_sa,
				sizeof(struct roc_ot_ipsec_inb_sa));
	if (ret) {
		plt_err("Could not write inbound session to hardware");
		goto sa_dptr_free;
	}

	/* Trigger CTX flush so that data is written back to DRAM */
	roc_cpt_lf_ctx_flush(lf, in_sa, true);

	plt_atomic_thread_fence(__ATOMIC_SEQ_CST);

sa_dptr_free:
	plt_free(sa_dptr);

	return ret;
}

static int
cn10k_ipsec_session_create(void *dev,
			   struct rte_security_ipsec_xform *ipsec_xfrm,
			   struct rte_crypto_sym_xform *crypto_xfrm,
			   struct rte_security_session *sess)
{
	struct rte_cryptodev *crypto_dev = dev;
	struct roc_cpt *roc_cpt;
	struct cnxk_cpt_vf *vf;
	struct cnxk_cpt_qp *qp;
	int ret;

	qp = crypto_dev->data->queue_pairs[0];
	if (qp == NULL) {
		plt_err("Setup cpt queue pair before creating security session");
		return -EPERM;
	}

	ret = cnxk_ipsec_xform_verify(ipsec_xfrm, crypto_xfrm);
	if (ret)
		return ret;

	vf = crypto_dev->data->dev_private;
	roc_cpt = &vf->cpt;

	if (ipsec_xfrm->direction == RTE_SECURITY_IPSEC_SA_DIR_INGRESS)
		return cn10k_ipsec_inb_sa_create(roc_cpt, &qp->lf, ipsec_xfrm, crypto_xfrm,
						 (struct cn10k_sec_session *)sess);
	else
		return cn10k_ipsec_outb_sa_create(roc_cpt, &qp->lf, ipsec_xfrm, crypto_xfrm,
						  (struct cn10k_sec_session *)sess);
}

static int
cn10k_sec_session_create(void *device, struct rte_security_session_conf *conf,
			 struct rte_security_session *sess)
{
	if (conf->action_type != RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL)
		return -EINVAL;

	if (conf->protocol != RTE_SECURITY_PROTOCOL_IPSEC)
		return -ENOTSUP;

	return cn10k_ipsec_session_create(device, &conf->ipsec,
					 conf->crypto_xform, sess);
}

static int
cn10k_sec_session_destroy(void *dev, struct rte_security_session *sec_sess)
{
	struct rte_cryptodev *crypto_dev = dev;
	union roc_ot_ipsec_sa_word2 *w2;
	struct cn10k_sec_session *sess;
	struct cn10k_ipsec_sa *sa;
	struct cnxk_cpt_qp *qp;
	struct roc_cpt_lf *lf;
	void *sa_dptr = NULL;
	int ret;

	if (unlikely(sec_sess == NULL))
		return -EINVAL;

	sess = (struct cn10k_sec_session *)sec_sess;

	qp = crypto_dev->data->queue_pairs[0];
	if (unlikely(qp == NULL))
		return -ENOTSUP;

	lf = &qp->lf;

	sa = &sess->sa;

	/* Trigger CTX flush to write dirty data back to DRAM */
	roc_cpt_lf_ctx_flush(lf, &sa->in_sa, false);

	ret = -1;

	if (sess->is_outbound) {
		sa_dptr = plt_zmalloc(sizeof(struct roc_ot_ipsec_outb_sa), 8);
		if (sa_dptr != NULL) {
			roc_ot_ipsec_outb_sa_init(sa_dptr);

			ret = roc_cpt_ctx_write(
				lf, sa_dptr, &sa->out_sa,
				sizeof(struct roc_ot_ipsec_outb_sa));
		}
	} else {
		sa_dptr = plt_zmalloc(sizeof(struct roc_ot_ipsec_inb_sa), 8);
		if (sa_dptr != NULL) {
			roc_ot_ipsec_inb_sa_init(sa_dptr, false);

			ret = roc_cpt_ctx_write(
				lf, sa_dptr, &sa->in_sa,
				sizeof(struct roc_ot_ipsec_inb_sa));
		}
	}

	plt_free(sa_dptr);

	if (ret) {
		/* MC write_ctx failed. Attempt reload of CTX */

		/* Wait for 1 ms so that flush is complete */
		rte_delay_ms(1);

		w2 = (union roc_ot_ipsec_sa_word2 *)&sa->in_sa.w2;
		w2->s.valid = 0;

		plt_atomic_thread_fence(__ATOMIC_SEQ_CST);

		/* Trigger CTX reload to fetch new data from DRAM */
		roc_cpt_lf_ctx_reload(lf, &sa->in_sa);
	}

	return 0;
}

static unsigned int
cn10k_sec_session_get_size(void *device __rte_unused)
{
	return sizeof(struct cn10k_sec_session) - sizeof(struct rte_security_session);
}

static int
cn10k_sec_session_stats_get(void *device, struct rte_security_session *sess,
			    struct rte_security_stats *stats)
{
	struct rte_cryptodev *crypto_dev = device;
	struct roc_ot_ipsec_outb_sa *out_sa;
	struct roc_ot_ipsec_inb_sa *in_sa;
	struct cn10k_sec_session *priv;
	struct cn10k_ipsec_sa *sa;
	struct cnxk_cpt_qp *qp;

	if (unlikely(sess == NULL))
		return -EINVAL;

	priv = (struct cn10k_sec_session *)sess;

	qp = crypto_dev->data->queue_pairs[0];
	if (qp == NULL)
		return -EINVAL;

	stats->protocol = RTE_SECURITY_PROTOCOL_IPSEC;
	sa = &priv->sa;

	if (priv->is_outbound) {
		out_sa = &sa->out_sa;
		roc_cpt_lf_ctx_flush(&qp->lf, out_sa, false);
		rte_delay_ms(1);
		stats->ipsec.opackets = out_sa->ctx.mib_pkts;
		stats->ipsec.obytes = out_sa->ctx.mib_octs;
	} else {
		in_sa = &sa->in_sa;
		roc_cpt_lf_ctx_flush(&qp->lf, in_sa, false);
		rte_delay_ms(1);
		stats->ipsec.ipackets = in_sa->ctx.mib_pkts;
		stats->ipsec.ibytes = in_sa->ctx.mib_octs;
	}

	return 0;
}

static int
cn10k_sec_session_update(void *device, struct rte_security_session *sess,
			 struct rte_security_session_conf *conf)
{
	struct rte_cryptodev *crypto_dev = device;
	struct cn10k_sec_session *priv;
	struct roc_cpt *roc_cpt;
	struct cnxk_cpt_qp *qp;
	struct cnxk_cpt_vf *vf;
	int ret;

	priv = SECURITY_GET_SESS_PRIV(sess);
	if (priv == NULL)
		return -EINVAL;

	qp = crypto_dev->data->queue_pairs[0];
	if (qp == NULL)
		return -EINVAL;

	if (conf->ipsec.direction == RTE_SECURITY_IPSEC_SA_DIR_INGRESS)
		return -ENOTSUP;

	ret = cnxk_ipsec_xform_verify(&conf->ipsec, conf->crypto_xform);
	if (ret)
		return ret;

	vf = crypto_dev->data->dev_private;
	roc_cpt = &vf->cpt;

	return cn10k_ipsec_outb_sa_create(roc_cpt, &qp->lf, &conf->ipsec, conf->crypto_xform,
					  (struct cn10k_sec_session *)sess);
}

/* Update platform specific security ops */
void
cn10k_sec_ops_override(void)
{
	/* Update platform specific ops */
	cnxk_sec_ops.session_create = cn10k_sec_session_create;
	cnxk_sec_ops.session_destroy = cn10k_sec_session_destroy;
	cnxk_sec_ops.session_get_size = cn10k_sec_session_get_size;
	cnxk_sec_ops.session_stats_get = cn10k_sec_session_stats_get;
	cnxk_sec_ops.session_update = cn10k_sec_session_update;
}
