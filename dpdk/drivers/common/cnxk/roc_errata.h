/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */
#ifndef _ROC_ERRATA_H_
#define _ROC_ERRATA_H_

/* Errata IPBUNIXRX-40129 */
static inline bool
roc_errata_nix_has_no_drop_re(void)
{
	return (roc_model_is_cn10ka_a0() || roc_model_is_cnf10ka_a0() ||
		roc_model_is_cnf10kb_a0());
}

/* Errata NIX-34873 */
static inline bool
roc_errata_nix_has_cq_min_size_4k(void)
{
	return (roc_model_is_cn96_a0() || roc_model_is_cn95_a0());
}

/* Errata IPBUNPA-37480 */
static inline bool
roc_errata_npa_has_no_fc_stype_ststp(void)
{
	return roc_model_is_cn10ka_a0() ? true : false;
}

/* Errata IPBUNIXTX-39337 */
static inline bool
roc_errata_nix_has_no_drop_aging(void)
{
	return (roc_model_is_cn10ka_a0() || roc_model_is_cnf10ka_a0());
}

/* Errata IPBUNIXRX-40130 */
static inline bool
roc_errata_nix_has_no_vwqe_flush_op(void)
{
	return (roc_model_is_cn10ka_a0() || roc_model_is_cnf10ka_a0() ||
		roc_model_is_cnf10kb_a0());
}

/* Errata IPBURVUM-38481 */
static inline bool
roc_errata_ruvm_has_no_interrupt_with_msixen(void)
{
	return true;
}

/* Errata IPBUNIXTX-39300 */
static inline bool
roc_errata_nix_has_assign_incorrect_qintidx(void)
{
	return true;
}

/* Errata IPBUCPT-38551 */
static inline bool
roc_errata_cpt_has_use_incorrect_ldwb(void)
{
	return true;
}

/* Errata IPBUNIXTX-39322 */
static inline bool
roc_errata_nix_has_overwrite_incorrect_sq_intr(void)
{
	return true;
}

/* Errata IPBUNIXTX-39248 */
static inline bool
roc_errata_nix_has_perf_issue_on_stats_update(void)
{
	return true;
}

/* Errata IPBUCPT-38726, IPBUCPT-38727 */
static inline bool
roc_errata_cpt_hang_on_x2p_bp(void)
{
	return roc_model_is_cn10ka_a0() || roc_model_is_cn10ka_a1();
}

/* IPBUNIXRX-40400 */
static inline bool
roc_errata_nix_no_meta_aura(void)
{
	return roc_model_is_cn10ka_a0();
}

/* Errata IPBUNIXTX-35039 */
static inline bool
roc_errata_nix_sdp_send_has_mtu_size_16k(void)
{
	return (roc_model_is_cnf95xxn_a0() || roc_model_is_cnf95xxo_a0() ||
		roc_model_is_cn96_a0() || roc_model_is_cn96_b0());
}

#endif /* _ROC_ERRATA_H_ */
