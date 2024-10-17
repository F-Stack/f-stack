/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#ifndef _ICE_RXTX_VEC_COMMON_H_
#define _ICE_RXTX_VEC_COMMON_H_

#include "ice_rxtx.h"

#ifndef __INTEL_COMPILER
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif

static inline uint16_t
ice_rx_reassemble_packets(struct ice_rx_queue *rxq, struct rte_mbuf **rx_bufs,
			  uint16_t nb_bufs, uint8_t *split_flags)
{
	struct rte_mbuf *pkts[ICE_VPMD_RX_BURST] = {0}; /*finished pkts*/
	struct rte_mbuf *start = rxq->pkt_first_seg;
	struct rte_mbuf *end =  rxq->pkt_last_seg;
	unsigned int pkt_idx, buf_idx;

	for (buf_idx = 0, pkt_idx = 0; buf_idx < nb_bufs; buf_idx++) {
		if (end) {
			/* processing a split packet */
			end->next = rx_bufs[buf_idx];
			rx_bufs[buf_idx]->data_len += rxq->crc_len;

			start->nb_segs++;
			start->pkt_len += rx_bufs[buf_idx]->data_len;
			end = end->next;

			if (!split_flags[buf_idx]) {
				/* it's the last packet of the set */
				start->hash = end->hash;
				start->vlan_tci = end->vlan_tci;
				start->ol_flags = end->ol_flags;
				/* we need to strip crc for the whole packet */
				start->pkt_len -= rxq->crc_len;
				if (end->data_len > rxq->crc_len) {
					end->data_len -= rxq->crc_len;
				} else {
					/* free up last mbuf */
					struct rte_mbuf *secondlast = start;

					start->nb_segs--;
					while (secondlast->next != end)
						secondlast = secondlast->next;
					secondlast->data_len -= (rxq->crc_len -
							end->data_len);
					secondlast->next = NULL;
					rte_pktmbuf_free_seg(end);
				}
				pkts[pkt_idx++] = start;
				start = NULL;
				end = NULL;
			}
		} else {
			/* not processing a split packet */
			if (!split_flags[buf_idx]) {
				/* not a split packet, save and skip */
				pkts[pkt_idx++] = rx_bufs[buf_idx];
				continue;
			}
			start = rx_bufs[buf_idx];
			end = start;
			rx_bufs[buf_idx]->data_len += rxq->crc_len;
			rx_bufs[buf_idx]->pkt_len += rxq->crc_len;
		}
	}

	/* save the partial packet for next time */
	rxq->pkt_first_seg = start;
	rxq->pkt_last_seg = end;
	memcpy(rx_bufs, pkts, pkt_idx * (sizeof(*pkts)));
	return pkt_idx;
}

static __rte_always_inline int
ice_tx_free_bufs_vec(struct ice_tx_queue *txq)
{
	struct ice_tx_entry *txep;
	uint32_t n;
	uint32_t i;
	int nb_free = 0;
	struct rte_mbuf *m, *free[ICE_TX_MAX_FREE_BUF_SZ];

	/* check DD bits on threshold descriptor */
	if ((txq->tx_ring[txq->tx_next_dd].cmd_type_offset_bsz &
			rte_cpu_to_le_64(ICE_TXD_QW1_DTYPE_M)) !=
			rte_cpu_to_le_64(ICE_TX_DESC_DTYPE_DESC_DONE))
		return 0;

	n = txq->tx_rs_thresh;

	 /* first buffer to free from S/W ring is at index
	  * tx_next_dd - (tx_rs_thresh-1)
	  */
	txep = &txq->sw_ring[txq->tx_next_dd - (n - 1)];
	m = rte_pktmbuf_prefree_seg(txep[0].mbuf);
	if (likely(m)) {
		free[0] = m;
		nb_free = 1;
		for (i = 1; i < n; i++) {
			m = rte_pktmbuf_prefree_seg(txep[i].mbuf);
			if (likely(m)) {
				if (likely(m->pool == free[0]->pool)) {
					free[nb_free++] = m;
				} else {
					rte_mempool_put_bulk(free[0]->pool,
							     (void *)free,
							     nb_free);
					free[0] = m;
					nb_free = 1;
				}
			}
		}
		rte_mempool_put_bulk(free[0]->pool, (void **)free, nb_free);
	} else {
		for (i = 1; i < n; i++) {
			m = rte_pktmbuf_prefree_seg(txep[i].mbuf);
			if (m)
				rte_mempool_put(m->pool, m);
		}
	}

	/* buffers were freed, update counters */
	txq->nb_tx_free = (uint16_t)(txq->nb_tx_free + txq->tx_rs_thresh);
	txq->tx_next_dd = (uint16_t)(txq->tx_next_dd + txq->tx_rs_thresh);
	if (txq->tx_next_dd >= txq->nb_tx_desc)
		txq->tx_next_dd = (uint16_t)(txq->tx_rs_thresh - 1);

	return txq->tx_rs_thresh;
}

static __rte_always_inline void
ice_tx_backlog_entry(struct ice_tx_entry *txep,
		     struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	int i;

	for (i = 0; i < (int)nb_pkts; ++i)
		txep[i].mbuf = tx_pkts[i];
}

static inline void
_ice_rx_queue_release_mbufs_vec(struct ice_rx_queue *rxq)
{
	const unsigned int mask = rxq->nb_rx_desc - 1;
	unsigned int i;

	if (unlikely(!rxq->sw_ring)) {
		PMD_DRV_LOG(DEBUG, "sw_ring is NULL");
		return;
	}

	if (rxq->rxrearm_nb >= rxq->nb_rx_desc)
		return;

	/* free all mbufs that are valid in the ring */
	if (rxq->rxrearm_nb == 0) {
		for (i = 0; i < rxq->nb_rx_desc; i++) {
			if (rxq->sw_ring[i].mbuf)
				rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
		}
	} else {
		for (i = rxq->rx_tail;
		     i != rxq->rxrearm_start;
		     i = (i + 1) & mask) {
			if (rxq->sw_ring[i].mbuf)
				rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
		}
	}

	rxq->rxrearm_nb = rxq->nb_rx_desc;

	/* set all entries to NULL */
	memset(rxq->sw_ring, 0, sizeof(rxq->sw_ring[0]) * rxq->nb_rx_desc);
}

static inline void
_ice_tx_queue_release_mbufs_vec(struct ice_tx_queue *txq)
{
	uint16_t i;

	if (unlikely(!txq || !txq->sw_ring)) {
		PMD_DRV_LOG(DEBUG, "Pointer to rxq or sw_ring is NULL");
		return;
	}

	/**
	 *  vPMD tx will not set sw_ring's mbuf to NULL after free,
	 *  so need to free remains more carefully.
	 */
	i = txq->tx_next_dd - txq->tx_rs_thresh + 1;

#ifdef __AVX512VL__
	struct rte_eth_dev *dev = &rte_eth_devices[txq->vsi->adapter->pf.dev_data->port_id];

	if (dev->tx_pkt_burst == ice_xmit_pkts_vec_avx512 ||
	    dev->tx_pkt_burst == ice_xmit_pkts_vec_avx512_offload) {
		struct ice_vec_tx_entry *swr = (void *)txq->sw_ring;

		if (txq->tx_tail < i) {
			for (; i < txq->nb_tx_desc; i++) {
				rte_pktmbuf_free_seg(swr[i].mbuf);
				swr[i].mbuf = NULL;
			}
			i = 0;
		}
		for (; i < txq->tx_tail; i++) {
			rte_pktmbuf_free_seg(swr[i].mbuf);
			swr[i].mbuf = NULL;
		}
	} else
#endif
	{
		if (txq->tx_tail < i) {
			for (; i < txq->nb_tx_desc; i++) {
				rte_pktmbuf_free_seg(txq->sw_ring[i].mbuf);
				txq->sw_ring[i].mbuf = NULL;
			}
			i = 0;
		}
		for (; i < txq->tx_tail; i++) {
			rte_pktmbuf_free_seg(txq->sw_ring[i].mbuf);
			txq->sw_ring[i].mbuf = NULL;
		}
	}
}

static inline int
ice_rxq_vec_setup_default(struct ice_rx_queue *rxq)
{
	uintptr_t p;
	struct rte_mbuf mb_def = { .buf_addr = 0 }; /* zeroed mbuf */

	mb_def.nb_segs = 1;
	mb_def.data_off = RTE_PKTMBUF_HEADROOM;
	mb_def.port = rxq->port_id;
	rte_mbuf_refcnt_set(&mb_def, 1);

	/* prevent compiler reordering: rearm_data covers previous fields */
	rte_compiler_barrier();
	p = (uintptr_t)&mb_def.rearm_data;
	rxq->mbuf_initializer = *(uint64_t *)p;
	return 0;
}

#define ICE_TX_NO_VECTOR_FLAGS (			\
		RTE_ETH_TX_OFFLOAD_MULTI_SEGS |		\
		RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM |	\
		RTE_ETH_TX_OFFLOAD_TCP_TSO |	\
		RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO |    \
		RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO |    \
		RTE_ETH_TX_OFFLOAD_IPIP_TNL_TSO |    \
		RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO |    \
		RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM)

#define ICE_TX_VECTOR_OFFLOAD (				\
		RTE_ETH_TX_OFFLOAD_VLAN_INSERT |		\
		RTE_ETH_TX_OFFLOAD_QINQ_INSERT |		\
		RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |		\
		RTE_ETH_TX_OFFLOAD_SCTP_CKSUM |		\
		RTE_ETH_TX_OFFLOAD_UDP_CKSUM |		\
		RTE_ETH_TX_OFFLOAD_TCP_CKSUM)

#define ICE_RX_VECTOR_OFFLOAD (				\
		RTE_ETH_RX_OFFLOAD_CHECKSUM |		\
		RTE_ETH_RX_OFFLOAD_SCTP_CKSUM |		\
		RTE_ETH_RX_OFFLOAD_VLAN |			\
		RTE_ETH_RX_OFFLOAD_RSS_HASH)

#define ICE_VECTOR_PATH		0
#define ICE_VECTOR_OFFLOAD_PATH	1

static inline int
ice_rx_vec_queue_default(struct ice_rx_queue *rxq)
{
	if (!rxq)
		return -1;

	if (!rte_is_power_of_2(rxq->nb_rx_desc))
		return -1;

	if (rxq->rx_free_thresh < ICE_VPMD_RX_BURST)
		return -1;

	if (rxq->nb_rx_desc % rxq->rx_free_thresh)
		return -1;

	if (rxq->proto_xtr != PROTO_XTR_NONE)
		return -1;

	if (rxq->offloads & RTE_ETH_RX_OFFLOAD_TIMESTAMP)
		return -1;

	if (rxq->offloads & RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT)
		return -1;

	if (rxq->offloads & ICE_RX_VECTOR_OFFLOAD)
		return ICE_VECTOR_OFFLOAD_PATH;

	return ICE_VECTOR_PATH;
}

static inline int
ice_tx_vec_queue_default(struct ice_tx_queue *txq)
{
	if (!txq)
		return -1;

	if (txq->tx_rs_thresh < ICE_VPMD_TX_BURST ||
	    txq->tx_rs_thresh > ICE_TX_MAX_FREE_BUF_SZ)
		return -1;

	if (txq->offloads & ICE_TX_NO_VECTOR_FLAGS)
		return -1;

	if (txq->offloads & ICE_TX_VECTOR_OFFLOAD)
		return ICE_VECTOR_OFFLOAD_PATH;

	return ICE_VECTOR_PATH;
}

static inline int
ice_rx_vec_dev_check_default(struct rte_eth_dev *dev)
{
	int i;
	struct ice_rx_queue *rxq;
	int ret = 0;
	int result = 0;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		ret = (ice_rx_vec_queue_default(rxq));
		if (ret < 0)
			return -1;
		if (ret == ICE_VECTOR_OFFLOAD_PATH)
			result = ret;
	}

	return result;
}

static inline int
ice_tx_vec_dev_check_default(struct rte_eth_dev *dev)
{
	int i;
	struct ice_tx_queue *txq;
	int ret = 0;
	int result = 0;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		ret = ice_tx_vec_queue_default(txq);
		if (ret < 0)
			return -1;
		if (ret == ICE_VECTOR_OFFLOAD_PATH)
			result = ret;
	}

	return result;
}

static inline void
ice_txd_enable_offload(struct rte_mbuf *tx_pkt,
		       uint64_t *txd_hi)
{
	uint64_t ol_flags = tx_pkt->ol_flags;
	uint32_t td_cmd = 0;
	uint32_t td_offset = 0;

	/* Tx Checksum Offload */
	/* SET MACLEN */
	td_offset |= (tx_pkt->l2_len >> 1) <<
		ICE_TX_DESC_LEN_MACLEN_S;

	/* Enable L3 checksum offload */
	if (ol_flags & RTE_MBUF_F_TX_IP_CKSUM) {
		td_cmd |= ICE_TX_DESC_CMD_IIPT_IPV4_CSUM;
		td_offset |= (tx_pkt->l3_len >> 2) <<
			ICE_TX_DESC_LEN_IPLEN_S;
	} else if (ol_flags & RTE_MBUF_F_TX_IPV4) {
		td_cmd |= ICE_TX_DESC_CMD_IIPT_IPV4;
		td_offset |= (tx_pkt->l3_len >> 2) <<
			ICE_TX_DESC_LEN_IPLEN_S;
	} else if (ol_flags & RTE_MBUF_F_TX_IPV6) {
		td_cmd |= ICE_TX_DESC_CMD_IIPT_IPV6;
		td_offset |= (tx_pkt->l3_len >> 2) <<
			ICE_TX_DESC_LEN_IPLEN_S;
	}

	/* Enable L4 checksum offloads */
	switch (ol_flags & RTE_MBUF_F_TX_L4_MASK) {
	case RTE_MBUF_F_TX_TCP_CKSUM:
		td_cmd |= ICE_TX_DESC_CMD_L4T_EOFT_TCP;
		td_offset |= (sizeof(struct rte_tcp_hdr) >> 2) <<
			ICE_TX_DESC_LEN_L4_LEN_S;
		break;
	case RTE_MBUF_F_TX_SCTP_CKSUM:
		td_cmd |= ICE_TX_DESC_CMD_L4T_EOFT_SCTP;
		td_offset |= (sizeof(struct rte_sctp_hdr) >> 2) <<
			ICE_TX_DESC_LEN_L4_LEN_S;
		break;
	case RTE_MBUF_F_TX_UDP_CKSUM:
		td_cmd |= ICE_TX_DESC_CMD_L4T_EOFT_UDP;
		td_offset |= (sizeof(struct rte_udp_hdr) >> 2) <<
			ICE_TX_DESC_LEN_L4_LEN_S;
		break;
	default:
		break;
	}

	*txd_hi |= ((uint64_t)td_offset) << ICE_TXD_QW1_OFFSET_S;

	/* Tx VLAN/QINQ insertion Offload */
	if (ol_flags & (RTE_MBUF_F_TX_VLAN | RTE_MBUF_F_TX_QINQ)) {
		td_cmd |= ICE_TX_DESC_CMD_IL2TAG1;
		*txd_hi |= ((uint64_t)tx_pkt->vlan_tci <<
				ICE_TXD_QW1_L2TAG1_S);
	}

	*txd_hi |= ((uint64_t)td_cmd) << ICE_TXD_QW1_CMD_S;
}
#endif
