/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2016-2018 Solarflare Communications Inc.
 * All rights reserved.
 *
 * This software was jointly developed between OKTET Labs (under contract
 * for Solarflare) and Solarflare Communications, Inc.
 */

#ifndef _SFC_DP_TX_H
#define _SFC_DP_TX_H

#include <rte_ethdev_driver.h>

#include "sfc_dp.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generic transmit queue information used on data path.
 * It must be kept as small as it is possible since it is built into
 * the structure used on datapath.
 */
struct sfc_dp_txq {
	struct sfc_dp_queue	dpq;
};

/**
 * Datapath transmit queue creation information.
 *
 * The structure is used just to pass information from control path to
 * datapath. It could be just function arguments, but it would be hardly
 * readable.
 */
struct sfc_dp_tx_qcreate_info {
	/** Maximum number of pushed Tx descriptors */
	unsigned int		max_fill_level;
	/** Minimum number of unused Tx descriptors to do reap */
	unsigned int		free_thresh;
	/** Offloads enabled on the transmit queue */
	uint64_t		offloads;
	/** Tx queue size */
	unsigned int		txq_entries;
	/** Maximum size of data in the DMA descriptor */
	uint16_t		dma_desc_size_max;
	/** DMA-mapped Tx descriptors ring */
	void			*txq_hw_ring;
	/** Associated event queue size */
	unsigned int		evq_entries;
	/** Hardware event ring */
	void			*evq_hw_ring;
	/** The queue index in hardware (required to push right doorbell) */
	unsigned int		hw_index;
	/** Virtual address of the memory-mapped BAR to push Tx doorbell */
	volatile void		*mem_bar;
	/** VI window size shift */
	unsigned int		vi_window_shift;
	/**
	 * Maximum number of bytes into the packet the TCP header can start for
	 * the hardware to apply TSO packet edits.
	 */
	uint16_t		tso_tcp_header_offset_limit;
};

/**
 * Get Tx datapath specific device info.
 *
 * @param dev_info		Device info to be adjusted
 */
typedef void (sfc_dp_tx_get_dev_info_t)(struct rte_eth_dev_info *dev_info);

/**
 * Get size of transmit and event queue rings by the number of Tx
 * descriptors.
 *
 * @param nb_tx_desc		Number of Tx descriptors
 * @param txq_entries		Location for number of Tx ring entries
 * @param evq_entries		Location for number of event ring entries
 * @param txq_max_fill_level	Location for maximum Tx ring fill level
 *
 * @return 0 or positive errno.
 */
typedef int (sfc_dp_tx_qsize_up_rings_t)(uint16_t nb_tx_desc,
					 unsigned int *txq_entries,
					 unsigned int *evq_entries,
					 unsigned int *txq_max_fill_level);

/**
 * Allocate and initialize datapath transmit queue.
 *
 * @param port_id	The port identifier
 * @param queue_id	The queue identifier
 * @param pci_addr	PCI function address
 * @param socket_id	Socket identifier to allocate memory
 * @param info		Tx queue details wrapped in structure
 * @param dp_txqp	Location for generic datapath transmit queue pointer
 *
 * @return 0 or positive errno.
 */
typedef int (sfc_dp_tx_qcreate_t)(uint16_t port_id, uint16_t queue_id,
				  const struct rte_pci_addr *pci_addr,
				  int socket_id,
				  const struct sfc_dp_tx_qcreate_info *info,
				  struct sfc_dp_txq **dp_txqp);

/**
 * Free resources allocated for datapath transmit queue.
 */
typedef void (sfc_dp_tx_qdestroy_t)(struct sfc_dp_txq *dp_txq);

/**
 * Transmit queue start callback.
 *
 * It handovers EvQ to the datapath.
 */
typedef int (sfc_dp_tx_qstart_t)(struct sfc_dp_txq *dp_txq,
				 unsigned int evq_read_ptr,
				 unsigned int txq_desc_index);

/**
 * Transmit queue stop function called before the queue flush.
 *
 * It returns EvQ to the control path.
 */
typedef void (sfc_dp_tx_qstop_t)(struct sfc_dp_txq *dp_txq,
				 unsigned int *evq_read_ptr);

/**
 * Transmit event handler used during queue flush only.
 */
typedef bool (sfc_dp_tx_qtx_ev_t)(struct sfc_dp_txq *dp_txq, unsigned int id);

/**
 * Transmit queue function called after the queue flush.
 */
typedef void (sfc_dp_tx_qreap_t)(struct sfc_dp_txq *dp_txq);

/**
 * Check Tx descriptor status
 */
typedef int (sfc_dp_tx_qdesc_status_t)(struct sfc_dp_txq *dp_txq,
				       uint16_t offset);

/** Transmit datapath definition */
struct sfc_dp_tx {
	struct sfc_dp			dp;

	unsigned int			features;
#define SFC_DP_TX_FEAT_VLAN_INSERT	0x1
#define SFC_DP_TX_FEAT_TSO		0x2
#define SFC_DP_TX_FEAT_MULTI_SEG	0x4
#define SFC_DP_TX_FEAT_MULTI_PROCESS	0x8
#define SFC_DP_TX_FEAT_MULTI_POOL	0x10
#define SFC_DP_TX_FEAT_REFCNT		0x20
	sfc_dp_tx_get_dev_info_t	*get_dev_info;
	sfc_dp_tx_qsize_up_rings_t	*qsize_up_rings;
	sfc_dp_tx_qcreate_t		*qcreate;
	sfc_dp_tx_qdestroy_t		*qdestroy;
	sfc_dp_tx_qstart_t		*qstart;
	sfc_dp_tx_qstop_t		*qstop;
	sfc_dp_tx_qtx_ev_t		*qtx_ev;
	sfc_dp_tx_qreap_t		*qreap;
	sfc_dp_tx_qdesc_status_t	*qdesc_status;
	eth_tx_burst_t			pkt_burst;
};

static inline struct sfc_dp_tx *
sfc_dp_find_tx_by_name(struct sfc_dp_list *head, const char *name)
{
	struct sfc_dp *p = sfc_dp_find_by_name(head, SFC_DP_TX, name);

	return (p == NULL) ? NULL : container_of(p, struct sfc_dp_tx, dp);
}

static inline struct sfc_dp_tx *
sfc_dp_find_tx_by_caps(struct sfc_dp_list *head, unsigned int avail_caps)
{
	struct sfc_dp *p = sfc_dp_find_by_caps(head, SFC_DP_TX, avail_caps);

	return (p == NULL) ? NULL : container_of(p, struct sfc_dp_tx, dp);
}

extern struct sfc_dp_tx sfc_efx_tx;
extern struct sfc_dp_tx sfc_ef10_tx;
extern struct sfc_dp_tx sfc_ef10_simple_tx;

#ifdef __cplusplus
}
#endif
#endif /* _SFC_DP_TX_H */
