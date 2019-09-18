/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2016-2018 Solarflare Communications Inc.
 * All rights reserved.
 *
 * This software was jointly developed between OKTET Labs (under contract
 * for Solarflare) and Solarflare Communications, Inc.
 */

#ifndef _SFC_TWEAK_H_
#define _SFC_TWEAK_H_

/*
 * The header is intended to collect defines/constants which could be
 * tweaked to improve the PMD performance characteristics depending on
 * the usecase or requirements (CPU load, packet rate, latency).
 */

/**
 * Number of Rx descriptors in the bulk submitted on Rx ring refill.
 */
#define SFC_RX_REFILL_BULK	(RTE_CACHE_LINE_SIZE / sizeof(efx_qword_t))

/**
 * Make the transmit path reap at least one time per a burst;
 * this improves cache locality because the same mbufs may be used to send
 * subsequent bursts in certain cases because of well-timed reap
 */
#define SFC_TX_XMIT_PKTS_REAP_AT_LEAST_ONCE	0

/** Default free threshold follows recommendations from DPDK documentation */
#define SFC_TX_DEFAULT_FREE_THRESH	32

/** Number of mbufs to be freed in bulk in a single call */
#define SFC_TX_REAP_BULK_SIZE		32

/**
 * Default head-of-line block timeout to wait for Rx descriptor before
 * packet drop because of no descriptors available.
 *
 * DPDK FW variant only with equal stride super-buffer Rx mode.
 */
#define SFC_RXD_WAIT_TIMEOUT_NS_DEF	(200U * 1000)

#endif /* _SFC_TWEAK_H_ */
