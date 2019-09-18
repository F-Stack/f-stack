/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2015-2018 Solarflare Communications Inc.
 * All rights reserved.
 */

#include "efx.h"
#include "efx_impl.h"


#if EFSYS_OPT_MEDFORD

static	__checkReturn	efx_rc_t
medford_nic_get_required_pcie_bandwidth(
	__in		efx_nic_t *enp,
	__out		uint32_t *bandwidth_mbpsp)
{
	uint32_t bandwidth;
	efx_rc_t rc;

	if ((rc = ef10_nic_get_port_mode_bandwidth(enp,
						    &bandwidth)) != 0)
		goto fail1;

	*bandwidth_mbpsp = bandwidth;

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

	__checkReturn	efx_rc_t
medford_board_cfg(
	__in		efx_nic_t *enp)
{
	efx_nic_cfg_t *encp = &(enp->en_nic_cfg);
	uint32_t sysclk, dpcpu_clk;
	uint32_t end_padding;
	uint32_t bandwidth;
	efx_rc_t rc;

	/*
	 * Enable firmware workarounds for hardware errata.
	 * Expected responses are:
	 *  - 0 (zero):
	 *	Success: workaround enabled or disabled as requested.
	 *  - MC_CMD_ERR_ENOSYS (reported as ENOTSUP):
	 *	Firmware does not support the MC_CMD_WORKAROUND request.
	 *	(assume that the workaround is not supported).
	 *  - MC_CMD_ERR_ENOENT (reported as ENOENT):
	 *	Firmware does not support the requested workaround.
	 *  - MC_CMD_ERR_EPERM  (reported as EACCES):
	 *	Unprivileged function cannot enable/disable workarounds.
	 *
	 * See efx_mcdi_request_errcode() for MCDI error translations.
	 */


	if (EFX_PCI_FUNCTION_IS_VF(encp)) {
		/*
		 * Interrupt testing does not work for VFs. See bug50084 and
		 * bug71432 comment 21.
		 */
		encp->enc_bug41750_workaround = B_TRUE;
	}

	/* Chained multicast is always enabled on Medford */
	encp->enc_bug26807_workaround = B_TRUE;

	/*
	 * If the bug61265 workaround is enabled, then interrupt holdoff timers
	 * cannot be controlled by timer table writes, so MCDI must be used
	 * (timer table writes can still be used for wakeup timers).
	 */
	rc = efx_mcdi_set_workaround(enp, MC_CMD_WORKAROUND_BUG61265, B_TRUE,
	    NULL);
	if ((rc == 0) || (rc == EACCES))
		encp->enc_bug61265_workaround = B_TRUE;
	else if ((rc == ENOTSUP) || (rc == ENOENT))
		encp->enc_bug61265_workaround = B_FALSE;
	else
		goto fail1;

	/* Checksums for TSO sends can be incorrect on Medford. */
	encp->enc_bug61297_workaround = B_TRUE;

	/* Get clock frequencies (in MHz). */
	if ((rc = efx_mcdi_get_clock(enp, &sysclk, &dpcpu_clk)) != 0)
		goto fail2;

	/*
	 * The Medford timer quantum is 1536 dpcpu_clk cycles, documented for
	 * the EV_TMR_VAL field of EV_TIMER_TBL. Scale for MHz and ns units.
	 */
	encp->enc_evq_timer_quantum_ns = 1536000UL / dpcpu_clk; /* 1536 cycles */
	encp->enc_evq_timer_max_us = (encp->enc_evq_timer_quantum_ns <<
		    FRF_CZ_TC_TIMER_VAL_WIDTH) / 1000;

	/* Alignment for receive packet DMA buffers */
	encp->enc_rx_buf_align_start = 1;

	/* Get the RX DMA end padding alignment configuration */
	if ((rc = efx_mcdi_get_rxdp_config(enp, &end_padding)) != 0) {
		if (rc != EACCES)
			goto fail3;

		/* Assume largest tail padding size supported by hardware */
		end_padding = 256;
	}
	encp->enc_rx_buf_align_end = end_padding;

	/*
	 * The maximum supported transmit queue size is 2048. TXQs with 4096
	 * descriptors are not supported as the top bit is used for vfifo
	 * stuffing.
	 */
	encp->enc_txq_max_ndescs = 2048;

	EFX_STATIC_ASSERT(MEDFORD_PIOBUF_NBUFS <= EF10_MAX_PIOBUF_NBUFS);
	encp->enc_piobuf_limit = MEDFORD_PIOBUF_NBUFS;
	encp->enc_piobuf_size = MEDFORD_PIOBUF_SIZE;
	encp->enc_piobuf_min_alloc_size = MEDFORD_MIN_PIO_ALLOC_SIZE;

	/*
	 * Medford stores a single global copy of VPD, not per-PF as on
	 * Huntington.
	 */
	encp->enc_vpd_is_global = B_TRUE;

	rc = medford_nic_get_required_pcie_bandwidth(enp, &bandwidth);
	if (rc != 0)
		goto fail4;
	encp->enc_required_pcie_bandwidth_mbps = bandwidth;
	encp->enc_max_pcie_link_gen = EFX_PCIE_LINK_SPEED_GEN3;

	return (0);

fail4:
	EFSYS_PROBE(fail4);
fail3:
	EFSYS_PROBE(fail3);
fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

#endif	/* EFSYS_OPT_MEDFORD */
