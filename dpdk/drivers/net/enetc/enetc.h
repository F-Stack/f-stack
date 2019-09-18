/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 NXP
 */

#ifndef _ENETC_H_
#define _ENETC_H_

#include <rte_time.h>

#include "base/enetc_hw.h"

#define PCI_VENDOR_ID_FREESCALE 0x1957

/* Max TX rings per ENETC. */
#define MAX_TX_RINGS	2

/* Max RX rings per ENTEC. */
#define MAX_RX_RINGS	1

/* Max BD counts per Ring. */
#define MAX_BD_COUNT   64000
/* Min BD counts per Ring. */
#define MIN_BD_COUNT   32
/* BD ALIGN */
#define BD_ALIGN       8

/*
 * upper_32_bits - return bits 32-63 of a number
 * @n: the number we're accessing
 *
 * A basic shift-right of a 64- or 32-bit quantity.  Use this to suppress
 * the "right shift count >= width of type" warning when that quantity is
 * 32-bits.
 */
#define upper_32_bits(n) ((uint32_t)(((n) >> 16) >> 16))

/*
 * lower_32_bits - return bits 0-31 of a number
 * @n: the number we're accessing
 */
#define lower_32_bits(n) ((uint32_t)(n))

#define ENETC_TXBD(BDR, i) (&(((struct enetc_tx_bd *)((BDR).bd_base))[i]))
#define ENETC_RXBD(BDR, i) (&(((union enetc_rx_bd *)((BDR).bd_base))[i]))

struct enetc_swbd {
	struct rte_mbuf *buffer_addr;
};

struct enetc_bdr {
	struct rte_eth_dev *ndev;
	struct rte_mempool *mb_pool;   /* mbuf pool to populate RX ring. */
	void *bd_base;			/* points to Rx or Tx BD ring */
	union {
		void *tcir;
		void *rcir;
	};
	uint16_t index;
	int bd_count; /* # of BDs */
	int next_to_use;
	int next_to_clean;
	struct enetc_swbd *q_swbd;
	union {
		void *tcisr; /* Tx */
		int next_to_alloc; /* Rx */
	};
};

/*
 * Structure to store private data for each driver instance (for each port).
 */
struct enetc_eth_adapter {
	struct rte_eth_dev *ndev;
	struct enetc_eth_hw hw;
};

#define ENETC_DEV_PRIVATE(adapter) \
	((struct enetc_eth_adapter *)adapter)

#define ENETC_DEV_PRIVATE_TO_HW(adapter) \
	(&((struct enetc_eth_adapter *)adapter)->hw)

#define ENETC_DEV_PRIVATE_TO_STATS(adapter) \
	(&((struct enetc_eth_adapter *)adapter)->stats)

#define ENETC_DEV_PRIVATE_TO_INTR(adapter) \
	(&((struct enetc_eth_adapter *)adapter)->intr)

#define ENETC_GET_HW_ADDR(reg, addr) ((void *)(((size_t)reg) + (addr)))
#define ENETC_REG_READ(addr) (*(uint32_t *)addr)
#define ENETC_REG_WRITE(addr, val) (*(uint32_t *)addr = val)
#define ENETC_REG_WRITE_RELAXED(addr, val) (*(uint32_t *)addr = val)

/*
 * RX/TX ENETC function prototypes
 */
uint16_t enetc_xmit_pkts(void *txq, struct rte_mbuf **tx_pkts,
		uint16_t nb_pkts);
uint16_t enetc_recv_pkts(void *rxq, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts);


int enetc_refill_rx_ring(struct enetc_bdr *rx_ring, const int buff_cnt);

static inline int
enetc_bd_unused(struct enetc_bdr *bdr)
{
	if (bdr->next_to_clean > bdr->next_to_use)
		return bdr->next_to_clean - bdr->next_to_use - 1;

	return bdr->bd_count + bdr->next_to_clean - bdr->next_to_use - 1;
}
#endif /* _ENETC_H_ */
