/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include "cn10k_worker.h"

#define T(name, sz, flags)                                                     \
	SSO_TX_SEG(cn10k_sso_hws_tx_adptr_enq_seg_##name, sz, flags)

NIX_TX_FASTPATH_MODES_64_79
#undef T
