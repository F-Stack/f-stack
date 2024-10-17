/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2014-2021 Broadcom
 * All rights reserved.
 */

#include <inttypes.h>

#include <rte_byteorder.h>
#include <rte_malloc.h>

#include "bnxt.h"
#include "bnxt_hwrm.h"
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

		rte_memzone_free(txq->mz);
		txq->mz = NULL;

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
	ring->vmem_size = ring->ring_size * sizeof(struct rte_mbuf *);
	ring->vmem = (void **)&txr->tx_buf_ring;
	ring->fw_ring_id = INVALID_HW_RING_ID;

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
	ring->fw_ring_id = INVALID_HW_RING_ID;

	return 0;
}

static bool
bnxt_xmit_need_long_bd(struct rte_mbuf *tx_pkt, struct bnxt_tx_queue *txq)
{
	if (tx_pkt->ol_flags & (RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_TCP_CKSUM |
				RTE_MBUF_F_TX_UDP_CKSUM | RTE_MBUF_F_TX_IP_CKSUM |
				RTE_MBUF_F_TX_VLAN | RTE_MBUF_F_TX_OUTER_IP_CKSUM |
				RTE_MBUF_F_TX_TUNNEL_GRE | RTE_MBUF_F_TX_TUNNEL_VXLAN |
				RTE_MBUF_F_TX_TUNNEL_GENEVE | RTE_MBUF_F_TX_IEEE1588_TMST |
				RTE_MBUF_F_TX_QINQ) ||
	     (BNXT_TRUFLOW_EN(txq->bp) &&
	      (txq->bp->tx_cfa_action || txq->vfr_tx_cfa_action)))
		return true;
	return false;
}

static bool
bnxt_zero_data_len_tso_segsz(struct rte_mbuf *tx_pkt, uint8_t data_len_chk)
{
	const char *type_str = "Data len";
	uint16_t len_to_check = tx_pkt->data_len;

	if (data_len_chk == 0) {
		type_str = "TSO Seg size";
		len_to_check = tx_pkt->tso_segsz;
	}

	if (len_to_check == 0) {
		PMD_DRV_LOG(ERR, "Error! Tx pkt %s == 0\n", type_str);
		rte_pktmbuf_dump(stdout, tx_pkt, 64);
		rte_dump_stack();
		return true;
	}
	return false;
}

static uint16_t bnxt_start_xmit(struct rte_mbuf *tx_pkt,
				struct bnxt_tx_queue *txq,
				uint16_t *coal_pkts,
				struct tx_bd_long **last_txbd)
{
	struct bnxt_tx_ring_info *txr = txq->tx_ring;
	struct bnxt_ring *ring = txr->tx_ring_struct;
	uint32_t outer_tpid_bd = 0;
	struct tx_bd_long *txbd;
	struct tx_bd_long_hi *txbd1 = NULL;
	uint32_t vlan_tag_flags;
	bool long_bd = false;
	unsigned short nr_bds;
	uint16_t prod;
	struct rte_mbuf *m_seg;
	struct rte_mbuf **tx_buf;
	static const uint32_t lhint_arr[4] = {
		TX_BD_LONG_FLAGS_LHINT_LT512,
		TX_BD_LONG_FLAGS_LHINT_LT1K,
		TX_BD_LONG_FLAGS_LHINT_LT2K,
		TX_BD_LONG_FLAGS_LHINT_LT2K
	};

	if (unlikely(is_bnxt_in_error(txq->bp)))
		return -EIO;

	long_bd = bnxt_xmit_need_long_bd(tx_pkt, txq);
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
	if (unlikely(bnxt_zero_data_len_tso_segsz(tx_pkt, 1)))
		return -EIO;

	prod = RING_IDX(ring, txr->tx_raw_prod);
	tx_buf = &txr->tx_buf_ring[prod];
	*tx_buf = tx_pkt;

	txbd = &txr->tx_desc_ring[prod];
	txbd->opaque = *coal_pkts;
	txbd->flags_type = nr_bds << TX_BD_LONG_FLAGS_BD_CNT_SFT;
	txbd->flags_type |= TX_BD_SHORT_FLAGS_COAL_NOW;
	txbd->flags_type |= TX_BD_LONG_FLAGS_NO_CMPL;
	txbd->len = tx_pkt->data_len;
	if (tx_pkt->pkt_len >= 2048)
		txbd->flags_type |= TX_BD_LONG_FLAGS_LHINT_GTE2K;
	else
		txbd->flags_type |= lhint_arr[tx_pkt->pkt_len >> 9];
	txbd->address = rte_cpu_to_le_64(rte_mbuf_data_iova(tx_pkt));
	*last_txbd = txbd;

	if (long_bd) {
		txbd->flags_type |= TX_BD_LONG_TYPE_TX_BD_LONG;
		vlan_tag_flags = 0;

		/* HW can accelerate only outer vlan in QinQ mode */
		if (tx_pkt->ol_flags & RTE_MBUF_F_TX_QINQ) {
			vlan_tag_flags = TX_BD_LONG_CFA_META_KEY_VLAN_TAG |
				tx_pkt->vlan_tci_outer;
			outer_tpid_bd = txq->bp->outer_tpid_bd &
				BNXT_OUTER_TPID_BD_MASK;
			vlan_tag_flags |= outer_tpid_bd;
		} else if (tx_pkt->ol_flags & RTE_MBUF_F_TX_VLAN) {
			/* shurd: Should this mask at
			 * TX_BD_LONG_CFA_META_VLAN_VID_MASK?
			 */
			vlan_tag_flags = TX_BD_LONG_CFA_META_KEY_VLAN_TAG |
				tx_pkt->vlan_tci;
			/* Currently supports 8021Q, 8021AD vlan offloads
			 * QINQ1, QINQ2, QINQ3 vlan headers are deprecated
			 */
			/* DPDK only supports 802.11q VLAN packets */
			vlan_tag_flags |=
					TX_BD_LONG_CFA_META_VLAN_TPID_TPID8100;
		}

		txr->tx_raw_prod = RING_NEXT(txr->tx_raw_prod);

		prod = RING_IDX(ring, txr->tx_raw_prod);
		txbd1 = (struct tx_bd_long_hi *)&txr->tx_desc_ring[prod];
		txbd1->lflags = 0;
		txbd1->cfa_meta = vlan_tag_flags;
		/* Legacy tx_bd_long_hi->mss =
		 * tx_bd_long_hi->kid_or_ts_high_mss
		 */
		txbd1->kid_or_ts_high_mss = 0;

		if (txq->vfr_tx_cfa_action)
			txbd1->cfa_action = txq->vfr_tx_cfa_action;
		else
			txbd1->cfa_action = txq->bp->tx_cfa_action;

		if (tx_pkt->ol_flags & RTE_MBUF_F_TX_TCP_SEG) {
			uint16_t hdr_size;

			/* TSO */
			txbd1->lflags |= TX_BD_LONG_LFLAGS_LSO |
					 TX_BD_LONG_LFLAGS_T_IPID;
			hdr_size = tx_pkt->l2_len + tx_pkt->l3_len +
					tx_pkt->l4_len;
			hdr_size += (tx_pkt->ol_flags & RTE_MBUF_F_TX_TUNNEL_MASK) ?
				    tx_pkt->outer_l2_len +
				    tx_pkt->outer_l3_len : 0;
			/* The hdr_size is multiple of 16bit units not 8bit.
			 * Hence divide by 2.
			 * Also legacy hdr_size = kid_or_ts_low_hdr_size.
			 */
			txbd1->kid_or_ts_low_hdr_size = hdr_size >> 1;
			txbd1->kid_or_ts_high_mss = tx_pkt->tso_segsz;
			if (unlikely(bnxt_zero_data_len_tso_segsz(tx_pkt, 0)))
				return -EIO;

		} else if ((tx_pkt->ol_flags & PKT_TX_OIP_IIP_TCP_UDP_CKSUM) ==
			   PKT_TX_OIP_IIP_TCP_UDP_CKSUM) {
			/* Outer IP, Inner IP, Inner TCP/UDP CSO */
			txbd1->lflags |= TX_BD_FLG_TIP_IP_TCP_UDP_CHKSUM;
		} else if ((tx_pkt->ol_flags & PKT_TX_OIP_IIP_TCP_CKSUM) ==
			   PKT_TX_OIP_IIP_TCP_CKSUM) {
			/* Outer IP, Inner IP, Inner TCP/UDP CSO */
			txbd1->lflags |= TX_BD_FLG_TIP_IP_TCP_UDP_CHKSUM;
		} else if ((tx_pkt->ol_flags & PKT_TX_OIP_IIP_UDP_CKSUM) ==
			   PKT_TX_OIP_IIP_UDP_CKSUM) {
			/* Outer IP, Inner IP, Inner TCP/UDP CSO */
			txbd1->lflags |= TX_BD_FLG_TIP_IP_TCP_UDP_CHKSUM;
		} else if ((tx_pkt->ol_flags & PKT_TX_IIP_TCP_UDP_CKSUM) ==
			   PKT_TX_IIP_TCP_UDP_CKSUM) {
			/* (Inner) IP, (Inner) TCP/UDP CSO */
			txbd1->lflags |= TX_BD_FLG_IP_TCP_UDP_CHKSUM;
		} else if ((tx_pkt->ol_flags & PKT_TX_IIP_UDP_CKSUM) ==
			   PKT_TX_IIP_UDP_CKSUM) {
			/* (Inner) IP, (Inner) TCP/UDP CSO */
			txbd1->lflags |= TX_BD_FLG_IP_TCP_UDP_CHKSUM;
		} else if ((tx_pkt->ol_flags & PKT_TX_IIP_TCP_CKSUM) ==
			   PKT_TX_IIP_TCP_CKSUM) {
			/* (Inner) IP, (Inner) TCP/UDP CSO */
			txbd1->lflags |= TX_BD_FLG_IP_TCP_UDP_CHKSUM;
		} else if ((tx_pkt->ol_flags & PKT_TX_OIP_TCP_UDP_CKSUM) ==
			   PKT_TX_OIP_TCP_UDP_CKSUM) {
			/* Outer IP, (Inner) TCP/UDP CSO */
			txbd1->lflags |= TX_BD_FLG_TIP_TCP_UDP_CHKSUM;
		} else if ((tx_pkt->ol_flags & PKT_TX_OIP_UDP_CKSUM) ==
			   PKT_TX_OIP_UDP_CKSUM) {
			/* Outer IP, (Inner) TCP/UDP CSO */
			txbd1->lflags |= TX_BD_FLG_TIP_TCP_UDP_CHKSUM;
		} else if ((tx_pkt->ol_flags & PKT_TX_OIP_TCP_CKSUM) ==
			   PKT_TX_OIP_TCP_CKSUM) {
			/* Outer IP, (Inner) TCP/UDP CSO */
			txbd1->lflags |= TX_BD_FLG_TIP_TCP_UDP_CHKSUM;
		} else if ((tx_pkt->ol_flags & PKT_TX_OIP_IIP_CKSUM) ==
			   PKT_TX_OIP_IIP_CKSUM) {
			/* Outer IP, Inner IP CSO */
			txbd1->lflags |= TX_BD_FLG_TIP_IP_CHKSUM;
		} else if ((tx_pkt->ol_flags & PKT_TX_TCP_UDP_CKSUM) ==
			   PKT_TX_TCP_UDP_CKSUM) {
			/* TCP/UDP CSO */
			txbd1->lflags |= TX_BD_LONG_LFLAGS_TCP_UDP_CHKSUM;
		} else if ((tx_pkt->ol_flags & RTE_MBUF_F_TX_TCP_CKSUM) ==
			   RTE_MBUF_F_TX_TCP_CKSUM) {
			/* TCP/UDP CSO */
			txbd1->lflags |= TX_BD_LONG_LFLAGS_TCP_UDP_CHKSUM;
		} else if ((tx_pkt->ol_flags & RTE_MBUF_F_TX_UDP_CKSUM) ==
			   RTE_MBUF_F_TX_UDP_CKSUM) {
			/* TCP/UDP CSO */
			txbd1->lflags |= TX_BD_LONG_LFLAGS_TCP_UDP_CHKSUM;
		} else if ((tx_pkt->ol_flags & RTE_MBUF_F_TX_IP_CKSUM) ==
			   RTE_MBUF_F_TX_IP_CKSUM) {
			/* IP CSO */
			txbd1->lflags |= TX_BD_LONG_LFLAGS_IP_CHKSUM;
		} else if ((tx_pkt->ol_flags & RTE_MBUF_F_TX_OUTER_IP_CKSUM) ==
			   RTE_MBUF_F_TX_OUTER_IP_CKSUM) {
			/* IP CSO */
			txbd1->lflags |= TX_BD_LONG_LFLAGS_T_IP_CHKSUM;
		} else if ((tx_pkt->ol_flags & RTE_MBUF_F_TX_IEEE1588_TMST) ==
			   RTE_MBUF_F_TX_IEEE1588_TMST) {
			/* PTP */
			txbd1->lflags |= TX_BD_LONG_LFLAGS_STAMP;
		}
	} else {
		txbd->flags_type |= TX_BD_SHORT_TYPE_TX_BD_SHORT;
	}

	m_seg = tx_pkt->next;
	while (m_seg) {
		/* Check non zero data_len */
		if (unlikely(bnxt_zero_data_len_tso_segsz(m_seg, 1)))
			return -EIO;
		txr->tx_raw_prod = RING_NEXT(txr->tx_raw_prod);

		prod = RING_IDX(ring, txr->tx_raw_prod);
		tx_buf = &txr->tx_buf_ring[prod];
		*tx_buf = m_seg;

		txbd = &txr->tx_desc_ring[prod];
		txbd->address = rte_cpu_to_le_64(rte_mbuf_data_iova(m_seg));
		txbd->flags_type = TX_BD_SHORT_TYPE_TX_BD_SHORT;
		txbd->len = m_seg->data_len;

		m_seg = m_seg->next;
	}

	txbd->flags_type |= TX_BD_LONG_FLAGS_PACKET_END;

	txr->tx_raw_prod = RING_NEXT(txr->tx_raw_prod);

	return 0;
}

/*
 * Transmit completion function for use when RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE
 * is enabled.
 */
static void bnxt_tx_cmp_fast(struct bnxt_tx_queue *txq, int nr_pkts)
{
	struct bnxt_tx_ring_info *txr = txq->tx_ring;
	struct bnxt_ring *ring = txr->tx_ring_struct;
	struct rte_mbuf **free = txq->free;
	uint16_t raw_cons = txr->tx_raw_cons;
	unsigned int blk = 0;
	int i, j;

	for (i = 0; i < nr_pkts; i++) {
		struct rte_mbuf **tx_buf;
		unsigned short nr_bds;

		tx_buf = &txr->tx_buf_ring[RING_IDX(ring, raw_cons)];
		nr_bds = (*tx_buf)->nb_segs +
			 bnxt_xmit_need_long_bd(*tx_buf, txq);
		for (j = 0; j < nr_bds; j++) {
			if (*tx_buf) {
				/* Add mbuf to the bulk free array */
				free[blk++] = *tx_buf;
				*tx_buf = NULL;
			}
			raw_cons = RING_NEXT(raw_cons);
			tx_buf = &txr->tx_buf_ring[RING_IDX(ring, raw_cons)];
		}
	}
	if (blk)
		rte_mempool_put_bulk(free[0]->pool, (void *)free, blk);

	txr->tx_raw_cons = raw_cons;
}

static void bnxt_tx_cmp(struct bnxt_tx_queue *txq, int nr_pkts)
{
	struct bnxt_tx_ring_info *txr = txq->tx_ring;
	struct bnxt_ring *ring = txr->tx_ring_struct;
	struct rte_mempool *pool = NULL;
	struct rte_mbuf **free = txq->free;
	uint16_t raw_cons = txr->tx_raw_cons;
	unsigned int blk = 0;
	int i, j;

	for (i = 0; i < nr_pkts; i++) {
		struct rte_mbuf *mbuf;
		struct rte_mbuf **tx_buf;
		unsigned short nr_bds;

		tx_buf = &txr->tx_buf_ring[RING_IDX(ring, raw_cons)];
		nr_bds = (*tx_buf)->nb_segs +
			 bnxt_xmit_need_long_bd(*tx_buf, txq);
		for (j = 0; j < nr_bds; j++) {
			mbuf = *tx_buf;
			*tx_buf = NULL;
			raw_cons = RING_NEXT(raw_cons);
			tx_buf = &txr->tx_buf_ring[RING_IDX(ring, raw_cons)];
			if (!mbuf)	/* long_bd's tx_buf ? */
				continue;

			mbuf = rte_pktmbuf_prefree_seg(mbuf);
			if (unlikely(!mbuf))
				continue;

			/* EW - no need to unmap DMA memory? */

			if (likely(mbuf->pool == pool)) {
				/* Add mbuf to the bulk free array */
				free[blk++] = mbuf;
			} else {
				/* Found an mbuf from a different pool. Free
				 * mbufs accumulated so far to the previous
				 * pool
				 */
				if (likely(pool != NULL))
					rte_mempool_put_bulk(pool,
							     (void *)free,
							     blk);

				/* Start accumulating mbufs in a new pool */
				free[0] = mbuf;
				pool = mbuf->pool;
				blk = 1;
			}
		}
	}
	if (blk)
		rte_mempool_put_bulk(pool, (void *)free, blk);

	txr->tx_raw_cons = raw_cons;
}

static int bnxt_handle_tx_cp(struct bnxt_tx_queue *txq)
{
	uint32_t nb_tx_pkts = 0, cons, ring_mask, opaque;
	struct bnxt_cp_ring_info *cpr = txq->cp_ring;
	uint32_t raw_cons = cpr->cp_raw_cons;
	struct bnxt_ring *cp_ring_struct;
	struct tx_cmpl *txcmp;

	if (bnxt_tx_bds_in_hw(txq) < txq->tx_free_thresh)
		return 0;

	cp_ring_struct = cpr->cp_ring_struct;
	ring_mask = cp_ring_struct->ring_mask;

	do {
		cons = RING_CMPL(ring_mask, raw_cons);
		txcmp = (struct tx_cmpl *)&cpr->cp_desc_ring[cons];

		if (!bnxt_cpr_cmp_valid(txcmp, raw_cons, ring_mask + 1))
			break;

		opaque = rte_le_to_cpu_32(txcmp->opaque);

		if (CMP_TYPE(txcmp) == TX_CMPL_TYPE_TX_L2)
			nb_tx_pkts += opaque;
		else
			RTE_LOG_DP(ERR, PMD,
					"Unhandled CMP type %02x\n",
					CMP_TYPE(txcmp));
		raw_cons = NEXT_RAW_CMP(raw_cons);
	} while (nb_tx_pkts < ring_mask);

	if (nb_tx_pkts) {
		if (txq->offloads & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
			bnxt_tx_cmp_fast(txq, nb_tx_pkts);
		else
			bnxt_tx_cmp(txq, nb_tx_pkts);
		cpr->cp_raw_cons = raw_cons;
		bnxt_db_cq(cpr);
	}

	return nb_tx_pkts;
}

uint16_t bnxt_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
			       uint16_t nb_pkts)
{
	struct bnxt_tx_queue *txq = tx_queue;
	uint16_t rc;

	pthread_mutex_lock(&txq->txq_lock);
	rc = _bnxt_xmit_pkts(tx_queue, tx_pkts, nb_pkts);
	pthread_mutex_unlock(&txq->txq_lock);

	return rc;
}

uint16_t _bnxt_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
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
	if (unlikely(!txq->tx_started)) {
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
		bnxt_db_write(&txq->tx_ring->tx_db, txq->tx_ring->tx_raw_prod);
	}

	return nb_tx_pkts;
}

int bnxt_tx_queue_start(struct rte_eth_dev *dev, uint16_t tx_queue_id)
{
	struct bnxt *bp = dev->data->dev_private;
	struct bnxt_tx_queue *txq = bp->tx_queues[tx_queue_id];
	int rc = 0;

	rc = is_bnxt_in_error(bp);
	if (rc)
		return rc;

	/* reset the previous stats for the tx_queue since the counters
	 * will be cleared when the queue is started.
	 */
	memset(&bp->prev_tx_ring_stats[tx_queue_id], 0,
	       sizeof(struct bnxt_ring_stats));

	bnxt_free_hwrm_tx_ring(bp, tx_queue_id);
	rc = bnxt_alloc_hwrm_tx_ring(bp, tx_queue_id);
	if (rc)
		return rc;

	dev->data->tx_queue_state[tx_queue_id] = RTE_ETH_QUEUE_STATE_STARTED;
	txq->tx_started = true;
	PMD_DRV_LOG(DEBUG, "Tx queue started\n");

	return 0;
}

int bnxt_tx_queue_stop(struct rte_eth_dev *dev, uint16_t tx_queue_id)
{
	struct bnxt *bp = dev->data->dev_private;
	struct bnxt_tx_queue *txq = bp->tx_queues[tx_queue_id];
	int rc = 0;

	rc = is_bnxt_in_error(bp);
	if (rc)
		return rc;

	/* Handle TX completions */
	bnxt_handle_tx_cp(txq);

	dev->data->tx_queue_state[tx_queue_id] = RTE_ETH_QUEUE_STATE_STOPPED;
	txq->tx_started = false;
	PMD_DRV_LOG(DEBUG, "Tx queue stopped\n");

	return 0;
}

/* Sweep the Tx completion queue till HWRM_DONE for ring flush is received.
 * The mbufs will not be freed in this call.
 * They will be freed during ring free as a part of mem cleanup.
 */
int bnxt_flush_tx_cmp(struct bnxt_cp_ring_info *cpr)
{
	uint32_t raw_cons = cpr->cp_raw_cons;
	uint32_t cons;
	uint32_t nb_tx_pkts = 0;
	struct tx_cmpl *txcmp;
	struct cmpl_base *cp_desc_ring = cpr->cp_desc_ring;
	struct bnxt_ring *cp_ring_struct = cpr->cp_ring_struct;
	uint32_t ring_mask = cp_ring_struct->ring_mask;
	uint32_t opaque = 0;

	do {
		cons = RING_CMPL(ring_mask, raw_cons);
		txcmp = (struct tx_cmpl *)&cp_desc_ring[cons];

		if (!bnxt_cpr_cmp_valid(txcmp, raw_cons, ring_mask + 1))
			break;

		opaque = rte_cpu_to_le_32(txcmp->opaque);
		raw_cons = NEXT_RAW_CMP(raw_cons);

		if (CMP_TYPE(txcmp) == TX_CMPL_TYPE_TX_L2)
			nb_tx_pkts += opaque;
		else if (CMP_TYPE(txcmp) == HWRM_CMPL_TYPE_HWRM_DONE)
			return 1;
	} while (nb_tx_pkts < ring_mask);

	if (nb_tx_pkts) {
		cpr->cp_raw_cons = raw_cons;
		bnxt_db_cq(cpr);
	}

	return 0;
}
