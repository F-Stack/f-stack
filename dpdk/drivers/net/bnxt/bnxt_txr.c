/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2014-2018 Broadcom
 * All rights reserved.
 */

#include <inttypes.h>

#include <rte_byteorder.h>
#include <rte_malloc.h>

#include "bnxt.h"
#include "bnxt_cpr.h"
#include "bnxt_ring.h"
#include "bnxt_txq.h"
#include "bnxt_txr.h"
#include "hsi_struct_def_dpdk.h"
#include <stdbool.h>

/*
 * TX Ring handling
 */

void bnxt_free_tx_rings(struct bnxt *bp)
{
	int i;

	for (i = 0; i < (int)bp->tx_nr_rings; i++) {
		struct bnxt_tx_queue *txq = bp->tx_queues[i];

		if (!txq)
			continue;

		bnxt_free_ring(txq->tx_ring->tx_ring_struct);
		rte_free(txq->tx_ring->tx_ring_struct);
		rte_free(txq->tx_ring);

		bnxt_free_ring(txq->cp_ring->cp_ring_struct);
		rte_free(txq->cp_ring->cp_ring_struct);
		rte_free(txq->cp_ring);

		rte_free(txq);
		bp->tx_queues[i] = NULL;
	}
}

int bnxt_init_one_tx_ring(struct bnxt_tx_queue *txq)
{
	struct bnxt_tx_ring_info *txr = txq->tx_ring;
	struct bnxt_ring *ring = txr->tx_ring_struct;

	txq->tx_wake_thresh = ring->ring_size / 2;
	ring->fw_ring_id = INVALID_HW_RING_ID;

	return 0;
}

int bnxt_init_tx_ring_struct(struct bnxt_tx_queue *txq, unsigned int socket_id)
{
	struct bnxt_cp_ring_info *cpr;
	struct bnxt_tx_ring_info *txr;
	struct bnxt_ring *ring;

	txr = rte_zmalloc_socket("bnxt_tx_ring",
				 sizeof(struct bnxt_tx_ring_info),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (txr == NULL)
		return -ENOMEM;
	txq->tx_ring = txr;

	ring = rte_zmalloc_socket("bnxt_tx_ring_struct",
				  sizeof(struct bnxt_ring),
				  RTE_CACHE_LINE_SIZE, socket_id);
	if (ring == NULL)
		return -ENOMEM;
	txr->tx_ring_struct = ring;
	ring->ring_size = rte_align32pow2(txq->nb_tx_desc);
	ring->ring_mask = ring->ring_size - 1;
	ring->bd = (void *)txr->tx_desc_ring;
	ring->bd_dma = txr->tx_desc_mapping;
	ring->vmem_size = ring->ring_size * sizeof(struct bnxt_sw_tx_bd);
	ring->vmem = (void **)&txr->tx_buf_ring;

	cpr = rte_zmalloc_socket("bnxt_tx_ring",
				 sizeof(struct bnxt_cp_ring_info),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (cpr == NULL)
		return -ENOMEM;
	txq->cp_ring = cpr;

	ring = rte_zmalloc_socket("bnxt_tx_ring_struct",
				  sizeof(struct bnxt_ring),
				  RTE_CACHE_LINE_SIZE, socket_id);
	if (ring == NULL)
		return -ENOMEM;
	cpr->cp_ring_struct = ring;
	ring->ring_size = txr->tx_ring_struct->ring_size;
	ring->ring_mask = ring->ring_size - 1;
	ring->bd = (void *)cpr->cp_desc_ring;
	ring->bd_dma = cpr->cp_desc_mapping;
	ring->vmem_size = 0;
	ring->vmem = NULL;

	return 0;
}

static inline uint32_t bnxt_tx_bds_in_hw(struct bnxt_tx_queue *txq)
{
	return ((txq->tx_ring->tx_prod - txq->tx_ring->tx_cons) &
		txq->tx_ring->tx_ring_struct->ring_mask);
}

static inline uint32_t bnxt_tx_avail(struct bnxt_tx_queue *txq)
{
	/* Tell compiler to fetch tx indices from memory. */
	rte_compiler_barrier();

	return ((txq->tx_ring->tx_ring_struct->ring_size -
		 bnxt_tx_bds_in_hw(txq)) - 1);
}

static uint16_t bnxt_start_xmit(struct rte_mbuf *tx_pkt,
				struct bnxt_tx_queue *txq,
				uint16_t *coal_pkts,
				struct tx_bd_long **last_txbd)
{
	struct bnxt_tx_ring_info *txr = txq->tx_ring;
	struct tx_bd_long *txbd;
	struct tx_bd_long_hi *txbd1 = NULL;
	uint32_t vlan_tag_flags, cfa_action;
	bool long_bd = false;
	unsigned short nr_bds = 0;
	struct rte_mbuf *m_seg;
	struct bnxt_sw_tx_bd *tx_buf;
	static const uint32_t lhint_arr[4] = {
		TX_BD_LONG_FLAGS_LHINT_LT512,
		TX_BD_LONG_FLAGS_LHINT_LT1K,
		TX_BD_LONG_FLAGS_LHINT_LT2K,
		TX_BD_LONG_FLAGS_LHINT_LT2K
	};

	if (tx_pkt->ol_flags & (PKT_TX_TCP_SEG | PKT_TX_TCP_CKSUM |
				PKT_TX_UDP_CKSUM | PKT_TX_IP_CKSUM |
				PKT_TX_VLAN_PKT | PKT_TX_OUTER_IP_CKSUM |
				PKT_TX_TUNNEL_GRE | PKT_TX_TUNNEL_VXLAN |
				PKT_TX_TUNNEL_GENEVE))
		long_bd = true;

	nr_bds = long_bd + tx_pkt->nb_segs;
	if (unlikely(bnxt_tx_avail(txq) < nr_bds))
		return -ENOMEM;

	/* Check if number of Tx descriptors is above HW limit */
	if (unlikely(nr_bds > BNXT_MAX_TSO_SEGS)) {
		PMD_DRV_LOG(ERR,
			    "Num descriptors %d exceeds HW limit\n", nr_bds);
		return -ENOSPC;
	}

	/* If packet length is less than minimum packet size, pad it */
	if (unlikely(rte_pktmbuf_pkt_len(tx_pkt) < BNXT_MIN_PKT_SIZE)) {
		uint8_t pad = BNXT_MIN_PKT_SIZE - rte_pktmbuf_pkt_len(tx_pkt);
		char *seg = rte_pktmbuf_append(tx_pkt, pad);

		if (!seg) {
			PMD_DRV_LOG(ERR,
				    "Failed to pad mbuf by %d bytes\n",
				    pad);
			return -ENOMEM;
		}

		/* Note: data_len, pkt len are updated in rte_pktmbuf_append */
		memset(seg, 0, pad);
	}

	/* Check non zero data_len */
	RTE_VERIFY(tx_pkt->data_len);

	tx_buf = &txr->tx_buf_ring[txr->tx_prod];
	tx_buf->mbuf = tx_pkt;
	tx_buf->nr_bds = nr_bds;

	txbd = &txr->tx_desc_ring[txr->tx_prod];
	txbd->opaque = *coal_pkts;
	txbd->flags_type = nr_bds << TX_BD_LONG_FLAGS_BD_CNT_SFT;
	txbd->flags_type |= TX_BD_SHORT_FLAGS_COAL_NOW;
	txbd->flags_type |= TX_BD_LONG_FLAGS_NO_CMPL;
	txbd->len = tx_pkt->data_len;
	if (tx_pkt->pkt_len >= 2014)
		txbd->flags_type |= TX_BD_LONG_FLAGS_LHINT_GTE2K;
	else
		txbd->flags_type |= lhint_arr[tx_pkt->pkt_len >> 9];
	txbd->address = rte_cpu_to_le_64(rte_mbuf_data_iova(tx_buf->mbuf));
	*last_txbd = txbd;

	if (long_bd) {
		txbd->flags_type |= TX_BD_LONG_TYPE_TX_BD_LONG;
		vlan_tag_flags = 0;
		cfa_action = 0;
		if (tx_buf->mbuf->ol_flags & PKT_TX_VLAN_PKT) {
			/* shurd: Should this mask at
			 * TX_BD_LONG_CFA_META_VLAN_VID_MASK?
			 */
			vlan_tag_flags = TX_BD_LONG_CFA_META_KEY_VLAN_TAG |
				tx_buf->mbuf->vlan_tci;
			/* Currently supports 8021Q, 8021AD vlan offloads
			 * QINQ1, QINQ2, QINQ3 vlan headers are deprecated
			 */
			/* DPDK only supports 802.11q VLAN packets */
			vlan_tag_flags |=
					TX_BD_LONG_CFA_META_VLAN_TPID_TPID8100;
		}

		txr->tx_prod = RING_NEXT(txr->tx_ring_struct, txr->tx_prod);

		txbd1 = (struct tx_bd_long_hi *)
					&txr->tx_desc_ring[txr->tx_prod];
		txbd1->lflags = 0;
		txbd1->cfa_meta = vlan_tag_flags;
		txbd1->cfa_action = cfa_action;

		if (tx_pkt->ol_flags & PKT_TX_TCP_SEG) {
			uint16_t hdr_size;

			/* TSO */
			txbd1->lflags |= TX_BD_LONG_LFLAGS_LSO;
			hdr_size = tx_pkt->l2_len + tx_pkt->l3_len +
					tx_pkt->l4_len + tx_pkt->outer_l2_len +
					tx_pkt->outer_l3_len;
			/* The hdr_size is multiple of 16bit units not 8bit.
			 * Hence divide by 2.
			 */
			txbd1->hdr_size = hdr_size >> 1;
			txbd1->mss = tx_pkt->tso_segsz;
			RTE_VERIFY(txbd1->mss);

		} else if ((tx_pkt->ol_flags & PKT_TX_OIP_IIP_TCP_UDP_CKSUM) ==
			   PKT_TX_OIP_IIP_TCP_UDP_CKSUM) {
			/* Outer IP, Inner IP, Inner TCP/UDP CSO */
			txbd1->lflags |= TX_BD_FLG_TIP_IP_TCP_UDP_CHKSUM;
			txbd1->mss = 0;
		} else if ((tx_pkt->ol_flags & PKT_TX_OIP_IIP_TCP_CKSUM) ==
			   PKT_TX_OIP_IIP_TCP_CKSUM) {
			/* Outer IP, Inner IP, Inner TCP/UDP CSO */
			txbd1->lflags |= TX_BD_FLG_TIP_IP_TCP_UDP_CHKSUM;
			txbd1->mss = 0;
		} else if ((tx_pkt->ol_flags & PKT_TX_OIP_IIP_UDP_CKSUM) ==
			   PKT_TX_OIP_IIP_UDP_CKSUM) {
			/* Outer IP, Inner IP, Inner TCP/UDP CSO */
			txbd1->lflags |= TX_BD_FLG_TIP_IP_TCP_UDP_CHKSUM;
			txbd1->mss = 0;
		} else if ((tx_pkt->ol_flags & PKT_TX_IIP_TCP_UDP_CKSUM) ==
			   PKT_TX_IIP_TCP_UDP_CKSUM) {
			/* (Inner) IP, (Inner) TCP/UDP CSO */
			txbd1->lflags |= TX_BD_FLG_IP_TCP_UDP_CHKSUM;
			txbd1->mss = 0;
		} else if ((tx_pkt->ol_flags & PKT_TX_IIP_UDP_CKSUM) ==
			   PKT_TX_IIP_UDP_CKSUM) {
			/* (Inner) IP, (Inner) TCP/UDP CSO */
			txbd1->lflags |= TX_BD_FLG_IP_TCP_UDP_CHKSUM;
			txbd1->mss = 0;
		} else if ((tx_pkt->ol_flags & PKT_TX_IIP_TCP_CKSUM) ==
			   PKT_TX_IIP_TCP_CKSUM) {
			/* (Inner) IP, (Inner) TCP/UDP CSO */
			txbd1->lflags |= TX_BD_FLG_IP_TCP_UDP_CHKSUM;
			txbd1->mss = 0;
		} else if ((tx_pkt->ol_flags & PKT_TX_OIP_TCP_UDP_CKSUM) ==
			   PKT_TX_OIP_TCP_UDP_CKSUM) {
			/* Outer IP, (Inner) TCP/UDP CSO */
			txbd1->lflags |= TX_BD_FLG_TIP_TCP_UDP_CHKSUM;
			txbd1->mss = 0;
		} else if ((tx_pkt->ol_flags & PKT_TX_OIP_UDP_CKSUM) ==
			   PKT_TX_OIP_UDP_CKSUM) {
			/* Outer IP, (Inner) TCP/UDP CSO */
			txbd1->lflags |= TX_BD_FLG_TIP_TCP_UDP_CHKSUM;
			txbd1->mss = 0;
		} else if ((tx_pkt->ol_flags & PKT_TX_OIP_TCP_CKSUM) ==
			   PKT_TX_OIP_TCP_CKSUM) {
			/* Outer IP, (Inner) TCP/UDP CSO */
			txbd1->lflags |= TX_BD_FLG_TIP_TCP_UDP_CHKSUM;
			txbd1->mss = 0;
		} else if ((tx_pkt->ol_flags & PKT_TX_OIP_IIP_CKSUM) ==
			   PKT_TX_OIP_IIP_CKSUM) {
			/* Outer IP, Inner IP CSO */
			txbd1->lflags |= TX_BD_FLG_TIP_IP_CHKSUM;
			txbd1->mss = 0;
		} else if ((tx_pkt->ol_flags & PKT_TX_TCP_UDP_CKSUM) ==
			   PKT_TX_TCP_UDP_CKSUM) {
			/* TCP/UDP CSO */
			txbd1->lflags |= TX_BD_LONG_LFLAGS_TCP_UDP_CHKSUM;
			txbd1->mss = 0;
		} else if ((tx_pkt->ol_flags & PKT_TX_TCP_CKSUM) ==
			   PKT_TX_TCP_CKSUM) {
			/* TCP/UDP CSO */
			txbd1->lflags |= TX_BD_LONG_LFLAGS_TCP_UDP_CHKSUM;
			txbd1->mss = 0;
		} else if ((tx_pkt->ol_flags & PKT_TX_UDP_CKSUM) ==
			   PKT_TX_UDP_CKSUM) {
			/* TCP/UDP CSO */
			txbd1->lflags |= TX_BD_LONG_LFLAGS_TCP_UDP_CHKSUM;
			txbd1->mss = 0;
		} else if ((tx_pkt->ol_flags & PKT_TX_IP_CKSUM) ==
			   PKT_TX_IP_CKSUM) {
			/* IP CSO */
			txbd1->lflags |= TX_BD_LONG_LFLAGS_IP_CHKSUM;
			txbd1->mss = 0;
		} else if ((tx_pkt->ol_flags & PKT_TX_OUTER_IP_CKSUM) ==
			   PKT_TX_OUTER_IP_CKSUM) {
			/* IP CSO */
			txbd1->lflags |= TX_BD_LONG_LFLAGS_T_IP_CHKSUM;
			txbd1->mss = 0;
		}
	} else {
		txbd->flags_type |= TX_BD_SHORT_TYPE_TX_BD_SHORT;
	}

	m_seg = tx_pkt->next;
	while (m_seg) {
		/* Check non zero data_len */
		RTE_VERIFY(m_seg->data_len);
		txr->tx_prod = RING_NEXT(txr->tx_ring_struct, txr->tx_prod);
		tx_buf = &txr->tx_buf_ring[txr->tx_prod];

		txbd = &txr->tx_desc_ring[txr->tx_prod];
		txbd->address = rte_cpu_to_le_64(rte_mbuf_data_iova(m_seg));
		txbd->flags_type = TX_BD_SHORT_TYPE_TX_BD_SHORT;
		txbd->len = m_seg->data_len;

		m_seg = m_seg->next;
	}

	txbd->flags_type |= TX_BD_LONG_FLAGS_PACKET_END;

	txr->tx_prod = RING_NEXT(txr->tx_ring_struct, txr->tx_prod);

	return 0;
}

static void bnxt_tx_cmp(struct bnxt_tx_queue *txq, int nr_pkts)
{
	struct bnxt_tx_ring_info *txr = txq->tx_ring;
	uint16_t cons = txr->tx_cons;
	int i, j;

	for (i = 0; i < nr_pkts; i++) {
		struct bnxt_sw_tx_bd *tx_buf;
		struct rte_mbuf *mbuf;

		tx_buf = &txr->tx_buf_ring[cons];
		cons = RING_NEXT(txr->tx_ring_struct, cons);
		mbuf = tx_buf->mbuf;
		tx_buf->mbuf = NULL;

		/* EW - no need to unmap DMA memory? */

		for (j = 1; j < tx_buf->nr_bds; j++)
			cons = RING_NEXT(txr->tx_ring_struct, cons);
		rte_pktmbuf_free(mbuf);
	}

	txr->tx_cons = cons;
}

static int bnxt_handle_tx_cp(struct bnxt_tx_queue *txq)
{
	struct bnxt_cp_ring_info *cpr = txq->cp_ring;
	uint32_t raw_cons = cpr->cp_raw_cons;
	uint32_t cons;
	uint32_t nb_tx_pkts = 0;
	struct tx_cmpl *txcmp;
	struct cmpl_base *cp_desc_ring = cpr->cp_desc_ring;
	struct bnxt_ring *cp_ring_struct = cpr->cp_ring_struct;
	uint32_t ring_mask = cp_ring_struct->ring_mask;
	uint32_t opaque = 0;

	if (bnxt_tx_bds_in_hw(txq) < txq->tx_free_thresh)
		return 0;

	do {
		cons = RING_CMPL(ring_mask, raw_cons);
		txcmp = (struct tx_cmpl *)&cpr->cp_desc_ring[cons];
		rte_prefetch_non_temporal(&cp_desc_ring[(cons + 2) &
							ring_mask]);

		if (!CMPL_VALID(txcmp, cpr->valid))
			break;
		opaque = rte_cpu_to_le_32(txcmp->opaque);
		NEXT_CMPL(cpr, cons, cpr->valid, 1);
		rte_prefetch0(&cp_desc_ring[cons]);

		if (CMP_TYPE(txcmp) == TX_CMPL_TYPE_TX_L2)
			nb_tx_pkts += opaque;
		else
			RTE_LOG_DP(ERR, PMD,
					"Unhandled CMP type %02x\n",
					CMP_TYPE(txcmp));
		raw_cons = cons;
	} while (nb_tx_pkts < ring_mask);

	if (nb_tx_pkts) {
		bnxt_tx_cmp(txq, nb_tx_pkts);
		cpr->cp_raw_cons = raw_cons;
		B_CP_DB(cpr, cpr->cp_raw_cons, ring_mask);
	}

	return nb_tx_pkts;
}

uint16_t bnxt_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
			       uint16_t nb_pkts)
{
	int rc;
	uint16_t nb_tx_pkts = 0;
	uint16_t coal_pkts = 0;
	struct bnxt_tx_queue *txq = tx_queue;
	struct tx_bd_long *last_txbd = NULL;

	/* Handle TX completions */
	bnxt_handle_tx_cp(txq);

	/* Tx queue was stopped; wait for it to be restarted */
	if (txq->tx_deferred_start) {
		PMD_DRV_LOG(DEBUG, "Tx q stopped;return\n");
		return 0;
	}

	/* Handle TX burst request */
	for (nb_tx_pkts = 0; nb_tx_pkts < nb_pkts; nb_tx_pkts++) {
		coal_pkts++;
		rc = bnxt_start_xmit(tx_pkts[nb_tx_pkts], txq,
				     &coal_pkts, &last_txbd);

		if (unlikely(rc))
			break;
	}

	if (likely(nb_tx_pkts)) {
		/* Request a completion on the last packet */
		last_txbd->flags_type &= ~TX_BD_LONG_FLAGS_NO_CMPL;
		B_TX_DB(txq->tx_ring->tx_doorbell, txq->tx_ring->tx_prod);
	}

	return nb_tx_pkts;
}

int bnxt_tx_queue_start(struct rte_eth_dev *dev, uint16_t tx_queue_id)
{
	struct bnxt *bp = dev->data->dev_private;
	struct bnxt_tx_queue *txq = bp->tx_queues[tx_queue_id];

	dev->data->tx_queue_state[tx_queue_id] = RTE_ETH_QUEUE_STATE_STARTED;
	txq->tx_deferred_start = false;
	PMD_DRV_LOG(DEBUG, "Tx queue started\n");

	return 0;
}

int bnxt_tx_queue_stop(struct rte_eth_dev *dev, uint16_t tx_queue_id)
{
	struct bnxt *bp = dev->data->dev_private;
	struct bnxt_tx_queue *txq = bp->tx_queues[tx_queue_id];

	/* Handle TX completions */
	bnxt_handle_tx_cp(txq);

	dev->data->tx_queue_state[tx_queue_id] = RTE_ETH_QUEUE_STATE_STOPPED;
	txq->tx_deferred_start = true;
	PMD_DRV_LOG(DEBUG, "Tx queue stopped\n");

	return 0;
}
