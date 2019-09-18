/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016 - 2018 Cavium Inc.
 * All rights reserved.
 * www.cavium.com
 */

#ifndef __ECORE_SP_COMMANDS_H__
#define __ECORE_SP_COMMANDS_H__

#include "ecore.h"
#include "ecore_spq.h"
#include "ecore_sp_api.h"

#define ECORE_SP_EQ_COMPLETION  0x01
#define ECORE_SP_CQE_COMPLETION 0x02

struct ecore_sp_init_data {
	/* The CID and FID aren't necessarily derived from hwfn,
	 * e.g., in IOV scenarios. CID might defer between SPQ and
	 * other elements.
	 */
	u32				cid;
	u16				opaque_fid;

	/* Information regarding operation upon sending & completion */
	enum spq_mode			comp_mode;
	struct ecore_spq_comp_cb	*p_comp_data;

};

/**
 * @brief Acquire and initialize and SPQ entry for a given ramrod.
 *
 * @param p_hwfn
 * @param pp_ent - will be filled with a pointer to an entry upon success
 * @param cmd - dependent upon protocol
 * @param protocol
 * @param p_data - various configuration required for ramrod
 *
 * @return ECORE_SUCCESS upon success, otherwise failure.
 */
enum _ecore_status_t ecore_sp_init_request(struct ecore_hwfn *p_hwfn,
					   struct ecore_spq_entry **pp_ent,
					   u8 cmd,
					   u8 protocol,
					   struct ecore_sp_init_data *p_data);

/**
 * @brief ecore_sp_pf_start - PF Function Start Ramrod
 *
 * This ramrod is sent to initialize a physical function (PF). It will
 * configure the function related parameters and write its completion to the
 * event ring specified in the parameters.
 *
 * Ramrods complete on the common event ring for the PF. This ring is
 * allocated by the driver on host memory and its parameters are written
 * to the internal RAM of the UStorm by the Function Start Ramrod.
 *
 * @param p_hwfn
 * @param p_ptt
 * @param p_tunn - pf start tunneling configuration
 * @param allow_npar_tx_switch - npar tx switching to be used
 *	  for vports configured for tx-switching.
 *
 * @return enum _ecore_status_t
 */

enum _ecore_status_t ecore_sp_pf_start(struct ecore_hwfn *p_hwfn,
				       struct ecore_ptt *p_ptt,
				       struct ecore_tunnel_info *p_tunn,
				       bool allow_npar_tx_switch);

/**
 * @brief ecore_sp_pf_update - PF Function Update Ramrod
 *
 * This ramrod updates function-related parameters. Every parameter can be
 * updated independently, according to configuration flags.
 *
 * @note Final phase API.
 *
 * @param p_hwfn
 *
 * @return enum _ecore_status_t
 */

enum _ecore_status_t ecore_sp_pf_update_dcbx(struct ecore_hwfn *p_hwfn);

/**
 * @brief ecore_sp_pf_stop - PF Function Stop Ramrod
 *
 * This ramrod is sent to close a Physical Function (PF). It is the last ramrod
 * sent and the last completion written to the PFs Event Ring. This ramrod also
 * deletes the context for the Slowhwfn connection on this PF.
 *
 * @note Not required for first packet.
 *
 * @param p_hwfn
 *
 * @return enum _ecore_status_t
 */

enum _ecore_status_t ecore_sp_pf_stop(struct ecore_hwfn *p_hwfn);

/**
 * @brief ecore_sp_heartbeat_ramrod - Send empty Ramrod
 *
 * @param p_hwfn
 *
 * @return enum _ecore_status_t
 */

enum _ecore_status_t ecore_sp_heartbeat_ramrod(struct ecore_hwfn *p_hwfn);

struct ecore_rl_update_params {
	u8 qcn_update_param_flg;
	u8 dcqcn_update_param_flg;
	u8 rl_init_flg;
	u8 rl_start_flg;
	u8 rl_stop_flg;
	u8 rl_id_first;
	u8 rl_id_last;
	u8 dcqcn_reset_alpha_on_idle;
	u8 rl_bc_stage_th;
	u8 rl_timer_stage_th;
	u8 rl_dc_qcn_flg; /* If set, RL will used for DCQCN */
	u32 rl_bc_rate; /* Byte Counter Limit */
	u32 rl_max_rate; /* Maximum rate in Mbps resolution */
	u32 rl_r_ai; /* Active increase rate */
	u32 rl_r_hai; /* Hyper active increase rate */
	u32 dcqcn_gd; /* DCQCN Alpha update gain */
	u32 dcqcn_k_us; /* DCQCN Alpha update interval */
	u32 dcqcn_timeuot_us;
	u32 qcn_timeuot_us;
};

/**
 * @brief ecore_sp_rl_update - Update rate limiters
 *
 * @param p_hwfn
 * @param params
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t ecore_sp_rl_update(struct ecore_hwfn *p_hwfn,
					struct ecore_rl_update_params *params);

/**
 * @brief ecore_sp_pf_update_stag - PF STAG value update Ramrod
 *
 * @param p_hwfn
 *
 * @return enum _ecore_status_t
 */

enum _ecore_status_t ecore_sp_pf_update_stag(struct ecore_hwfn *p_hwfn);

/**
 * @brief ecore_sp_pf_update_ufp - PF ufp update Ramrod
 *
 * @param p_hwfn
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t ecore_sp_pf_update_ufp(struct ecore_hwfn *p_hwfn);

#endif /*__ECORE_SP_COMMANDS_H__*/
