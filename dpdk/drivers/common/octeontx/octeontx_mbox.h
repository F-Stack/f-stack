/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Cavium, Inc
 */

#ifndef __OCTEONTX_MBOX_H__
#define __OCTEONTX_MBOX_H__

#include <rte_common.h>
#include <rte_spinlock.h>

#define SSOW_BAR4_LEN			(64 * 1024)
#define SSO_VHGRP_PF_MBOX(x)		(0x200ULL | ((x) << 3))

#define MBOX_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, octeontx_logtype_mbox,\
			"%s() line %u: " fmt "\n", __func__, __LINE__, ## args)

#define mbox_log_info(fmt, ...) MBOX_LOG(INFO, fmt, ##__VA_ARGS__)
#define mbox_log_dbg(fmt, ...) MBOX_LOG(DEBUG, fmt, ##__VA_ARGS__)
#define mbox_log_err(fmt, ...) MBOX_LOG(ERR, fmt, ##__VA_ARGS__)
#define mbox_func_trace mbox_log_dbg

extern int octeontx_logtype_mbox;

struct octeontx_mbox_hdr {
	uint16_t vfid;  /* VF index or pf resource index local to the domain */
	uint8_t coproc; /* Coprocessor id */
	uint8_t msg;    /* Message id */
	uint8_t res_code; /* Functional layer response code */
};

int octeontx_mbox_set_ram_mbox_base(uint8_t *ram_mbox_base);
int octeontx_mbox_set_reg(uint8_t *reg);
int octeontx_mbox_send(struct octeontx_mbox_hdr *hdr,
		void *txdata, uint16_t txlen, void *rxdata, uint16_t rxlen);

#endif /* __OCTEONTX_MBOX_H__ */
