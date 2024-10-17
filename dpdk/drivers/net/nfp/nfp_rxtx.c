/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2021 Netronome Systems, Inc.
 * All rights reserved.
 *
 * Small portions derived from code Copyright(c) 2010-2015 Intel Corporation.
 */

/*
 * vim:shiftwidth=8:noexpandtab
 *
 * @file dpdk/pmd/nfp_rxtx.c
 *
 * Netronome vNIC DPDK Poll-Mode Driver: Rx/Tx functions
 */

#include <ethdev_driver.h>
#include <ethdev_pci.h>

#include "nfp_common.h"
#include "nfp_ctrl.h"
#include "nfp_rxtx.h"
#include "nfp_logs.h"
#include "nfpcore/nfp_mip.h"
#include "nfpcore/nfp_rtsym.h"
#include "nfpcore/nfp-common/nfp_platform.h"

static int
nfp_net_rx_fill_freelist(struct nfp_net_rxq *rxq)
{
	struct nfp_net_rx_buff *rxe = rxq->rxbufs;
	uint64_t dma_addr;
	unsigned int i;

	PMD_RX_LOG(DEBUG, "Fill Rx Freelist for %u descriptors",
		   rxq->rx_count);

	for (i = 0; i < rxq->rx_count; i++) {
		struct nfp_net_rx_desc *rxd;
		struct rte_mbuf *mbuf = rte_pktmbuf_alloc(rxq->mem_pool);

		if (mbuf == NULL) {
			PMD_DRV_LOG(ERR, "RX mbuf alloc failed queue_id=%u",
				(unsigned int)rxq->qidx);
			return -ENOMEM;
		}

		dma_addr = rte_cpu_to_le_64(RTE_MBUF_DMA_ADDR_DEFAULT(mbuf));

		rxd = &rxq->rxds[i];
		rxd->fld.dd = 0;
		rxd->fld.dma_addr_hi = (dma_addr >> 32) & 0xffff;
		rxd->fld.dma_addr_lo = dma_addr & 0xffffffff;
		rxe[i].mbuf = mbuf;
		PMD_RX_LOG(DEBUG, "[%d]: %" PRIx64, i, dma_addr);
	}

	/* Make sure all writes are flushed before telling the hardware */
	rte_wmb();

	/* Not advertising the whole ring as the firmware gets confused if so */
	PMD_RX_LOG(DEBUG, "Increment FL write pointer in %u",
		   rxq->rx_count - 1);

	nfp_qcp_ptr_add(rxq->qcp_fl, NFP_QCP_WRITE_PTR, rxq->rx_count - 1);

	return 0;
}

int
nfp_net_rx_freelist_setup(struct rte_eth_dev *dev)
{
	int i;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		if (nfp_net_rx_fill_freelist(dev->data->rx_queues[i]) < 0)
			return -1;
	}
	return 0;
}

uint32_t
nfp_net_rx_queue_count(void *rx_queue)
{
	struct nfp_net_rxq *rxq;
	struct nfp_net_rx_desc *rxds;
	uint32_t idx;
	uint32_t count;

	rxq = rx_queue;

	idx = rxq->rd_p;

	count = 0;

	/*
	 * Other PMDs are just checking the DD bit in intervals of 4
	 * descriptors and counting all four if the first has the DD
	 * bit on. Of course, this is not accurate but can be good for
	 * performance. But ideally that should be done in descriptors
	 * chunks belonging to the same cache line
	 */

	while (count < rxq->rx_count) {
		rxds = &rxq->rxds[idx];
		if ((rxds->rxd.meta_len_dd & PCIE_DESC_RX_DD) == 0)
			break;

		count++;
		idx++;

		/* Wrapping? */
		if ((idx) == rxq->rx_count)
			idx = 0;
	}

	return count;
}

/*
 * nfp_net_set_hash - Set mbuf hash data
 *
 * The RSS hash and hash-type are pre-pended to the packet data.
 * Extract and decode it and set the mbuf fields.
 */
static inline void
nfp_net_set_hash(struct nfp_net_rxq *rxq, struct nfp_net_rx_desc *rxd,
		 struct rte_mbuf *mbuf)
{
	struct nfp_net_hw *hw = rxq->hw;
	uint8_t *meta_offset;
	uint32_t meta_info;
	uint32_t hash = 0;
	uint32_t hash_type = 0;

	if (!(hw->ctrl & NFP_NET_CFG_CTRL_RSS_ANY))
		return;

	/* this is true for new firmwares */
	if (likely(((hw->cap & NFP_NET_CFG_CTRL_RSS2) ||
	    (NFD_CFG_MAJOR_VERSION_of(hw->ver) == 4)) &&
	     NFP_DESC_META_LEN(rxd))) {
		/*
		 * new metadata api:
		 * <----  32 bit  ----->
		 * m    field type word
		 * e     data field #2
		 * t     data field #1
		 * a     data field #0
		 * ====================
		 *    packet data
		 *
		 * Field type word contains up to 8 4bit field types
		 * A 4bit field type refers to a data field word
		 * A data field word can have several 4bit field types
		 */
		meta_offset = rte_pktmbuf_mtod(mbuf, uint8_t *);
		meta_offset -= NFP_DESC_META_LEN(rxd);
		meta_info = rte_be_to_cpu_32(*(uint32_t *)meta_offset);
		meta_offset += 4;
		/* NFP PMD just supports metadata for hashing */
		switch (meta_info & NFP_NET_META_FIELD_MASK) {
		case NFP_NET_META_HASH:
			/* next field type is about the hash type */
			meta_info >>= NFP_NET_META_FIELD_SIZE;
			/* hash value is in the data field */
			hash = rte_be_to_cpu_32(*(uint32_t *)meta_offset);
			hash_type = meta_info & NFP_NET_META_FIELD_MASK;
			break;
		default:
			/* Unsupported metadata can be a performance issue */
			return;
		}
	} else {
		if (!(rxd->rxd.flags & PCIE_DESC_RX_RSS))
			return;

		hash = rte_be_to_cpu_32(*(uint32_t *)NFP_HASH_OFFSET);
		hash_type = rte_be_to_cpu_32(*(uint32_t *)NFP_HASH_TYPE_OFFSET);
	}

	mbuf->hash.rss = hash;
	mbuf->ol_flags |= RTE_MBUF_F_RX_RSS_HASH;

	switch (hash_type) {
	case NFP_NET_RSS_IPV4:
		mbuf->packet_type |= RTE_PTYPE_INNER_L3_IPV4;
		break;
	case NFP_NET_RSS_IPV6:
		mbuf->packet_type |= RTE_PTYPE_INNER_L3_IPV6;
		break;
	case NFP_NET_RSS_IPV6_EX:
		mbuf->packet_type |= RTE_PTYPE_INNER_L3_IPV6_EXT;
		break;
	case NFP_NET_RSS_IPV4_TCP:
		mbuf->packet_type |= RTE_PTYPE_INNER_L3_IPV6_EXT;
		break;
	case NFP_NET_RSS_IPV6_TCP:
		mbuf->packet_type |= RTE_PTYPE_INNER_L3_IPV6_EXT;
		break;
	case NFP_NET_RSS_IPV4_UDP:
		mbuf->packet_type |= RTE_PTYPE_INNER_L3_IPV6_EXT;
		break;
	case NFP_NET_RSS_IPV6_UDP:
		mbuf->packet_type |= RTE_PTYPE_INNER_L3_IPV6_EXT;
		break;
	default:
		mbuf->packet_type |= RTE_PTYPE_INNER_L4_MASK;
	}
}

/*
 * RX path design:
 *
 * There are some decisions to take:
 * 1) How to check DD RX descriptors bit
 * 2) How and when to allocate new mbufs
 *
 * Current implementation checks just one single DD bit each loop. As each
 * descriptor is 8 bytes, it is likely a good idea to check descriptors in
 * a single cache line instead. Tests with this change have not shown any
 * performance improvement but it requires further investigation. For example,
 * depending on which descriptor is next, the number of descriptors could be
 * less than 8 for just checking those in the same cache line. This implies
 * extra work which could be counterproductive by itself. Indeed, last firmware
 * changes are just doing this: writing several descriptors with the DD bit
 * for saving PCIe bandwidth and DMA operations from the NFP.
 *
 * Mbuf allocation is done when a new packet is received. Then the descriptor
 * is automatically linked with the new mbuf and the old one is given to the
 * user. The main drawback with this design is mbuf allocation is heavier than
 * using bulk allocations allowed by DPDK with rte_mempool_get_bulk. From the
 * cache point of view it does not seem allocating the mbuf early on as we are
 * doing now have any benefit at all. Again, tests with this change have not
 * shown any improvement. Also, rte_mempool_get_bulk returns all or nothing
 * so looking at the implications of this type of allocation should be studied
 * deeply
 */

uint16_t
nfp_net_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct nfp_net_rxq *rxq;
	struct nfp_net_rx_desc *rxds;
	struct nfp_net_rx_buff *rxb;
	struct nfp_net_hw *hw;
	struct rte_mbuf *mb;
	struct rte_mbuf *new_mb;
	uint16_t nb_hold;
	uint64_t dma_addr;
	uint16_t avail;

	avail = 0;
	rxq = rx_queue;
	if (unlikely(rxq == NULL)) {
		/*
		 * DPDK just checks the queue is lower than max queues
		 * enabled. But the queue needs to be configured
		 */
		RTE_LOG_DP(ERR, PMD, "RX Bad queue\n");
		return avail;
	}

	hw = rxq->hw;
	nb_hold = 0;

	while (avail < nb_pkts) {
		rxb = &rxq->rxbufs[rxq->rd_p];
		if (unlikely(rxb == NULL)) {
			RTE_LOG_DP(ERR, PMD, "rxb does not exist!\n");
			break;
		}

		rxds = &rxq->rxds[rxq->rd_p];
		if ((rxds->rxd.meta_len_dd & PCIE_DESC_RX_DD) == 0)
			break;

		/*
		 * Memory barrier to ensure that we won't do other
		 * reads before the DD bit.
		 */
		rte_rmb();

		/*
		 * We got a packet. Let's alloc a new mbuf for refilling the
		 * free descriptor ring as soon as possible
		 */
		new_mb = rte_pktmbuf_alloc(rxq->mem_pool);
		if (unlikely(new_mb == NULL)) {
			RTE_LOG_DP(DEBUG, PMD,
			"RX mbuf alloc failed port_id=%u queue_id=%u\n",
				rxq->port_id, (unsigned int)rxq->qidx);
			nfp_net_mbuf_alloc_failed(rxq);
			break;
		}

		/*
		 * Grab the mbuf and refill the descriptor with the
		 * previously allocated mbuf
		 */
		mb = rxb->mbuf;
		rxb->mbuf = new_mb;

		PMD_RX_LOG(DEBUG, "Packet len: %u, mbuf_size: %u",
			   rxds->rxd.data_len, rxq->mbuf_size);

		/* Size of this segment */
		mb->data_len = rxds->rxd.data_len - NFP_DESC_META_LEN(rxds);
		/* Size of the whole packet. We just support 1 segment */
		mb->pkt_len = rxds->rxd.data_len - NFP_DESC_META_LEN(rxds);

		if (unlikely((mb->data_len + hw->rx_offset) >
			     rxq->mbuf_size)) {
			/*
			 * This should not happen and the user has the
			 * responsibility of avoiding it. But we have
			 * to give some info about the error
			 */
			RTE_LOG_DP(ERR, PMD,
				"mbuf overflow likely due to the RX offset.\n"
				"\t\tYour mbuf size should have extra space for"
				" RX offset=%u bytes.\n"
				"\t\tCurrently you just have %u bytes available"
				" but the received packet is %u bytes long",
				hw->rx_offset,
				rxq->mbuf_size - hw->rx_offset,
				mb->data_len);
			rte_pktmbuf_free(mb);
			break;
		}

		/* Filling the received mbuf with packet info */
		if (hw->rx_offset)
			mb->data_off = RTE_PKTMBUF_HEADROOM + hw->rx_offset;
		else
			mb->data_off = RTE_PKTMBUF_HEADROOM +
				       NFP_DESC_META_LEN(rxds);

		/* No scatter mode supported */
		mb->nb_segs = 1;
		mb->next = NULL;

		mb->port = rxq->port_id;

		/* Checking the RSS flag */
		nfp_net_set_hash(rxq, rxds, mb);

		/* Checking the checksum flag */
		nfp_net_rx_cksum(rxq, rxds, mb);

		if ((rxds->rxd.flags & PCIE_DESC_RX_VLAN) &&
		    (hw->ctrl & NFP_NET_CFG_CTRL_RXVLAN)) {
			mb->vlan_tci = rte_cpu_to_le_32(rxds->rxd.vlan);
			mb->ol_flags |= RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED;
		}

		/* Adding the mbuf to the mbuf array passed by the app */
		rx_pkts[avail++] = mb;

		/* Now resetting and updating the descriptor */
		rxds->vals[0] = 0;
		rxds->vals[1] = 0;
		dma_addr = rte_cpu_to_le_64(RTE_MBUF_DMA_ADDR_DEFAULT(new_mb));
		rxds->fld.dd = 0;
		rxds->fld.dma_addr_hi = (dma_addr >> 32) & 0xffff;
		rxds->fld.dma_addr_lo = dma_addr & 0xffffffff;
		nb_hold++;

		rxq->rd_p++;
		if (unlikely(rxq->rd_p == rxq->rx_count)) /* wrapping?*/
			rxq->rd_p = 0;
	}

	if (nb_hold == 0)
		return nb_hold;

	PMD_RX_LOG(DEBUG, "RX  port_id=%u queue_id=%u, %d packets received",
		   rxq->port_id, (unsigned int)rxq->qidx, nb_hold);

	nb_hold += rxq->nb_rx_hold;

	/*
	 * FL descriptors needs to be written before incrementing the
	 * FL queue WR pointer
	 */
	rte_wmb();
	if (nb_hold > rxq->rx_free_thresh) {
		PMD_RX_LOG(DEBUG, "port=%u queue=%u nb_hold=%u avail=%u",
			   rxq->port_id, (unsigned int)rxq->qidx,
			   (unsigned int)nb_hold, (unsigned int)avail);
		nfp_qcp_ptr_add(rxq->qcp_fl, NFP_QCP_WRITE_PTR, nb_hold);
		nb_hold = 0;
	}
	rxq->nb_rx_hold = nb_hold;

	return avail;
}

static void
nfp_net_rx_queue_release_mbufs(struct nfp_net_rxq *rxq)
{
	unsigned int i;

	if (rxq->rxbufs == NULL)
		return;

	for (i = 0; i < rxq->rx_count; i++) {
		if (rxq->rxbufs[i].mbuf) {
			rte_pktmbuf_free_seg(rxq->rxbufs[i].mbuf);
			rxq->rxbufs[i].mbuf = NULL;
		}
	}
}

void
nfp_net_rx_queue_release(struct rte_eth_dev *dev, uint16_t queue_idx)
{
	struct nfp_net_rxq *rxq = dev->data->rx_queues[queue_idx];

	if (rxq) {
		nfp_net_rx_queue_release_mbufs(rxq);
		rte_eth_dma_zone_free(dev, "rx_ring", queue_idx);
		rte_free(rxq->rxbufs);
		rte_free(rxq);
	}
}

void
nfp_net_reset_rx_queue(struct nfp_net_rxq *rxq)
{
	nfp_net_rx_queue_release_mbufs(rxq);
	rxq->rd_p = 0;
	rxq->nb_rx_hold = 0;
}

int
nfp_net_rx_queue_setup(struct rte_eth_dev *dev,
		       uint16_t queue_idx, uint16_t nb_desc,
		       unsigned int socket_id,
		       const struct rte_eth_rxconf *rx_conf,
		       struct rte_mempool *mp)
{
	const struct rte_memzone *tz;
	struct nfp_net_rxq *rxq;
	struct nfp_net_hw *hw;
	uint32_t rx_desc_sz;

	hw = NFP_NET_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	PMD_INIT_FUNC_TRACE();

	/* Validating number of descriptors */
	rx_desc_sz = nb_desc * sizeof(struct nfp_net_rx_desc);
	if (rx_desc_sz % NFP_ALIGN_RING_DESC != 0 ||
	    nb_desc > NFP_NET_MAX_RX_DESC ||
	    nb_desc < NFP_NET_MIN_RX_DESC) {
		PMD_DRV_LOG(ERR, "Wrong nb_desc value");
		return -EINVAL;
	}

	/*
	 * Free memory prior to re-allocation if needed. This is the case after
	 * calling nfp_net_stop
	 */
	if (dev->data->rx_queues[queue_idx]) {
		nfp_net_rx_queue_release(dev, queue_idx);
		dev->data->rx_queues[queue_idx] = NULL;
	}

	/* Allocating rx queue data structure */
	rxq = rte_zmalloc_socket("ethdev RX queue", sizeof(struct nfp_net_rxq),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (rxq == NULL)
		return -ENOMEM;

	dev->data->rx_queues[queue_idx] = rxq;

	/* Hw queues mapping based on firmware configuration */
	rxq->qidx = queue_idx;
	rxq->fl_qcidx = queue_idx * hw->stride_rx;
	rxq->rx_qcidx = rxq->fl_qcidx + (hw->stride_rx - 1);
	rxq->qcp_fl = hw->rx_bar + NFP_QCP_QUEUE_OFF(rxq->fl_qcidx);
	rxq->qcp_rx = hw->rx_bar + NFP_QCP_QUEUE_OFF(rxq->rx_qcidx);

	/*
	 * Tracking mbuf size for detecting a potential mbuf overflow due to
	 * RX offset
	 */
	rxq->mem_pool = mp;
	rxq->mbuf_size = rxq->mem_pool->elt_size;
	rxq->mbuf_size -= (sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM);
	hw->flbufsz = rxq->mbuf_size;

	rxq->rx_count = nb_desc;
	rxq->port_id = dev->data->port_id;
	rxq->rx_free_thresh = rx_conf->rx_free_thresh;
	rxq->drop_en = rx_conf->rx_drop_en;

	/*
	 * Allocate RX ring hardware descriptors. A memzone large enough to
	 * handle the maximum ring size is allocated in order to allow for
	 * resizing in later calls to the queue setup function.
	 */
	tz = rte_eth_dma_zone_reserve(dev, "rx_ring", queue_idx,
				   sizeof(struct nfp_net_rx_desc) *
				   NFP_NET_MAX_RX_DESC, NFP_MEMZONE_ALIGN,
				   socket_id);

	if (tz == NULL) {
		PMD_DRV_LOG(ERR, "Error allocating rx dma");
		nfp_net_rx_queue_release(dev, queue_idx);
		dev->data->rx_queues[queue_idx] = NULL;
		return -ENOMEM;
	}

	/* Saving physical and virtual addresses for the RX ring */
	rxq->dma = (uint64_t)tz->iova;
	rxq->rxds = (struct nfp_net_rx_desc *)tz->addr;

	/* mbuf pointers array for referencing mbufs linked to RX descriptors */
	rxq->rxbufs = rte_zmalloc_socket("rxq->rxbufs",
					 sizeof(*rxq->rxbufs) * nb_desc,
					 RTE_CACHE_LINE_SIZE, socket_id);
	if (rxq->rxbufs == NULL) {
		nfp_net_rx_queue_release(dev, queue_idx);
		dev->data->rx_queues[queue_idx] = NULL;
		return -ENOMEM;
	}

	PMD_RX_LOG(DEBUG, "rxbufs=%p hw_ring=%p dma_addr=0x%" PRIx64,
		   rxq->rxbufs, rxq->rxds, (unsigned long)rxq->dma);

	nfp_net_reset_rx_queue(rxq);

	rxq->hw = hw;

	/*
	 * Telling the HW about the physical address of the RX ring and number
	 * of descriptors in log2 format
	 */
	nn_cfg_writeq(hw, NFP_NET_CFG_RXR_ADDR(queue_idx), rxq->dma);
	nn_cfg_writeb(hw, NFP_NET_CFG_RXR_SZ(queue_idx), rte_log2_u32(nb_desc));

	return 0;
}

/*
 * nfp_net_tx_free_bufs - Check for descriptors with a complete
 * status
 * @txq: TX queue to work with
 * Returns number of descriptors freed
 */
int
nfp_net_tx_free_bufs(struct nfp_net_txq *txq)
{
	uint32_t qcp_rd_p;
	int todo;

	PMD_TX_LOG(DEBUG, "queue %u. Check for descriptor with a complete"
		   " status", txq->qidx);

	/* Work out how many packets have been sent */
	qcp_rd_p = nfp_qcp_read(txq->qcp_q, NFP_QCP_READ_PTR);

	if (qcp_rd_p == txq->rd_p) {
		PMD_TX_LOG(DEBUG, "queue %u: It seems harrier is not sending "
			   "packets (%u, %u)", txq->qidx,
			   qcp_rd_p, txq->rd_p);
		return 0;
	}

	if (qcp_rd_p > txq->rd_p)
		todo = qcp_rd_p - txq->rd_p;
	else
		todo = qcp_rd_p + txq->tx_count - txq->rd_p;

	PMD_TX_LOG(DEBUG, "qcp_rd_p %u, txq->rd_p: %u, qcp->rd_p: %u",
		   qcp_rd_p, txq->rd_p, txq->rd_p);

	if (todo == 0)
		return todo;

	txq->rd_p += todo;
	if (unlikely(txq->rd_p >= txq->tx_count))
		txq->rd_p -= txq->tx_count;

	return todo;
}

static void
nfp_net_tx_queue_release_mbufs(struct nfp_net_txq *txq)
{
	unsigned int i;

	if (txq->txbufs == NULL)
		return;

	for (i = 0; i < txq->tx_count; i++) {
		if (txq->txbufs[i].mbuf) {
			rte_pktmbuf_free_seg(txq->txbufs[i].mbuf);
			txq->txbufs[i].mbuf = NULL;
		}
	}
}

void
nfp_net_tx_queue_release(struct rte_eth_dev *dev, uint16_t queue_idx)
{
	struct nfp_net_txq *txq = dev->data->tx_queues[queue_idx];

	if (txq) {
		nfp_net_tx_queue_release_mbufs(txq);
		rte_eth_dma_zone_free(dev, "tx_ring", queue_idx);
		rte_free(txq->txbufs);
		rte_free(txq);
	}
}

void
nfp_net_reset_tx_queue(struct nfp_net_txq *txq)
{
	nfp_net_tx_queue_release_mbufs(txq);
	txq->wr_p = 0;
	txq->rd_p = 0;
}

static int
nfp_net_nfd3_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
		       uint16_t nb_desc, unsigned int socket_id,
		       const struct rte_eth_txconf *tx_conf)
{
	const struct rte_memzone *tz;
	struct nfp_net_txq *txq;
	uint16_t tx_free_thresh;
	struct nfp_net_hw *hw;
	uint32_t tx_desc_sz;

	hw = NFP_NET_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	PMD_INIT_FUNC_TRACE();

	/* Validating number of descriptors */
	tx_desc_sz = nb_desc * sizeof(struct nfp_net_nfd3_tx_desc);
	if (tx_desc_sz % NFP_ALIGN_RING_DESC != 0 ||
	    nb_desc > NFP_NET_MAX_TX_DESC ||
	    nb_desc < NFP_NET_MIN_TX_DESC) {
		PMD_DRV_LOG(ERR, "Wrong nb_desc value");
		return -EINVAL;
	}

	tx_free_thresh = (uint16_t)((tx_conf->tx_free_thresh) ?
				    tx_conf->tx_free_thresh :
				    DEFAULT_TX_FREE_THRESH);

	if (tx_free_thresh > (nb_desc)) {
		PMD_DRV_LOG(ERR,
			"tx_free_thresh must be less than the number of TX "
			"descriptors. (tx_free_thresh=%u port=%d "
			"queue=%d)", (unsigned int)tx_free_thresh,
			dev->data->port_id, (int)queue_idx);
		return -(EINVAL);
	}

	/*
	 * Free memory prior to re-allocation if needed. This is the case after
	 * calling nfp_net_stop
	 */
	if (dev->data->tx_queues[queue_idx]) {
		PMD_TX_LOG(DEBUG, "Freeing memory prior to re-allocation %d",
			   queue_idx);
		nfp_net_tx_queue_release(dev, queue_idx);
		dev->data->tx_queues[queue_idx] = NULL;
	}

	/* Allocating tx queue data structure */
	txq = rte_zmalloc_socket("ethdev TX queue", sizeof(struct nfp_net_txq),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (txq == NULL) {
		PMD_DRV_LOG(ERR, "Error allocating tx dma");
		return -ENOMEM;
	}

	dev->data->tx_queues[queue_idx] = txq;

	/*
	 * Allocate TX ring hardware descriptors. A memzone large enough to
	 * handle the maximum ring size is allocated in order to allow for
	 * resizing in later calls to the queue setup function.
	 */
	tz = rte_eth_dma_zone_reserve(dev, "tx_ring", queue_idx,
				   sizeof(struct nfp_net_nfd3_tx_desc) *
				   NFP_NET_MAX_TX_DESC, NFP_MEMZONE_ALIGN,
				   socket_id);
	if (tz == NULL) {
		PMD_DRV_LOG(ERR, "Error allocating tx dma");
		nfp_net_tx_queue_release(dev, queue_idx);
		dev->data->tx_queues[queue_idx] = NULL;
		return -ENOMEM;
	}

	txq->tx_count = nb_desc;
	txq->tx_free_thresh = tx_free_thresh;
	txq->tx_pthresh = tx_conf->tx_thresh.pthresh;
	txq->tx_hthresh = tx_conf->tx_thresh.hthresh;
	txq->tx_wthresh = tx_conf->tx_thresh.wthresh;

	/* queue mapping based on firmware configuration */
	txq->qidx = queue_idx;
	txq->tx_qcidx = queue_idx * hw->stride_tx;
	txq->qcp_q = hw->tx_bar + NFP_QCP_QUEUE_OFF(txq->tx_qcidx);

	txq->port_id = dev->data->port_id;

	/* Saving physical and virtual addresses for the TX ring */
	txq->dma = (uint64_t)tz->iova;
	txq->txds = (struct nfp_net_nfd3_tx_desc *)tz->addr;

	/* mbuf pointers array for referencing mbufs linked to TX descriptors */
	txq->txbufs = rte_zmalloc_socket("txq->txbufs",
					 sizeof(*txq->txbufs) * nb_desc,
					 RTE_CACHE_LINE_SIZE, socket_id);
	if (txq->txbufs == NULL) {
		nfp_net_tx_queue_release(dev, queue_idx);
		dev->data->tx_queues[queue_idx] = NULL;
		return -ENOMEM;
	}
	PMD_TX_LOG(DEBUG, "txbufs=%p hw_ring=%p dma_addr=0x%" PRIx64,
		   txq->txbufs, txq->txds, (unsigned long)txq->dma);

	nfp_net_reset_tx_queue(txq);

	txq->hw = hw;

	/*
	 * Telling the HW about the physical address of the TX ring and number
	 * of descriptors in log2 format
	 */
	nn_cfg_writeq(hw, NFP_NET_CFG_TXR_ADDR(queue_idx), txq->dma);
	nn_cfg_writeb(hw, NFP_NET_CFG_TXR_SZ(queue_idx), rte_log2_u32(nb_desc));

	return 0;
}

uint16_t
nfp_net_nfd3_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct nfp_net_txq *txq;
	struct nfp_net_hw *hw;
	struct nfp_net_nfd3_tx_desc *txds, txd;
	struct rte_mbuf *pkt;
	uint64_t dma_addr;
	int pkt_size, dma_size;
	uint16_t free_descs, issued_descs;
	struct rte_mbuf **lmbuf;
	int i;

	txq = tx_queue;
	hw = txq->hw;
	txds = &txq->txds[txq->wr_p];

	PMD_TX_LOG(DEBUG, "working for queue %u at pos %d and %u packets",
		   txq->qidx, txq->wr_p, nb_pkts);

	if ((nfp_net_nfd3_free_tx_desc(txq) < nb_pkts) || (nfp_net_nfd3_txq_full(txq)))
		nfp_net_tx_free_bufs(txq);

	free_descs = (uint16_t)nfp_net_nfd3_free_tx_desc(txq);
	if (unlikely(free_descs == 0))
		return 0;

	pkt = *tx_pkts;

	i = 0;
	issued_descs = 0;
	PMD_TX_LOG(DEBUG, "queue: %u. Sending %u packets",
		   txq->qidx, nb_pkts);
	/* Sending packets */
	while ((i < nb_pkts) && free_descs) {
		/* Grabbing the mbuf linked to the current descriptor */
		lmbuf = &txq->txbufs[txq->wr_p].mbuf;
		/* Warming the cache for releasing the mbuf later on */
		RTE_MBUF_PREFETCH_TO_FREE(*lmbuf);

		pkt = *(tx_pkts + i);

		if (unlikely(pkt->nb_segs > 1 &&
			     !(hw->cap & NFP_NET_CFG_CTRL_GATHER))) {
			PMD_INIT_LOG(INFO, "NFP_NET_CFG_CTRL_GATHER not set");
			rte_panic("Multisegment packet unsupported\n");
		}

		/* Checking if we have enough descriptors */
		if (unlikely(pkt->nb_segs > free_descs))
			goto xmit_end;

		/*
		 * Checksum and VLAN flags just in the first descriptor for a
		 * multisegment packet, but TSO info needs to be in all of them.
		 */
		txd.data_len = pkt->pkt_len;
		nfp_net_nfd3_tx_tso(txq, &txd, pkt);
		nfp_net_nfd3_tx_cksum(txq, &txd, pkt);

		if ((pkt->ol_flags & RTE_MBUF_F_TX_VLAN) &&
		    (hw->cap & NFP_NET_CFG_CTRL_TXVLAN)) {
			txd.flags |= PCIE_DESC_TX_VLAN;
			txd.vlan = pkt->vlan_tci;
		}

		/*
		 * mbuf data_len is the data in one segment and pkt_len data
		 * in the whole packet. When the packet is just one segment,
		 * then data_len = pkt_len
		 */
		pkt_size = pkt->pkt_len;

		while (pkt) {
			/* Copying TSO, VLAN and cksum info */
			*txds = txd;

			/* Releasing mbuf used by this descriptor previously*/
			if (*lmbuf)
				rte_pktmbuf_free_seg(*lmbuf);

			/*
			 * Linking mbuf with descriptor for being released
			 * next time descriptor is used
			 */
			*lmbuf = pkt;

			dma_size = pkt->data_len;
			dma_addr = rte_mbuf_data_iova(pkt);
			PMD_TX_LOG(DEBUG, "Working with mbuf at dma address:"
				   "%" PRIx64 "", dma_addr);

			/* Filling descriptors fields */
			txds->dma_len = dma_size;
			txds->data_len = txd.data_len;
			txds->dma_addr_hi = (dma_addr >> 32) & 0xff;
			txds->dma_addr_lo = (dma_addr & 0xffffffff);
			ASSERT(free_descs > 0);
			free_descs--;

			txq->wr_p++;
			if (unlikely(txq->wr_p == txq->tx_count)) /* wrapping?*/
				txq->wr_p = 0;

			pkt_size -= dma_size;

			/*
			 * Making the EOP, packets with just one segment
			 * the priority
			 */
			if (likely(!pkt_size))
				txds->offset_eop = PCIE_DESC_TX_EOP;
			else
				txds->offset_eop = 0;

			pkt = pkt->next;
			/* Referencing next free TX descriptor */
			txds = &txq->txds[txq->wr_p];
			lmbuf = &txq->txbufs[txq->wr_p].mbuf;
			issued_descs++;
		}
		i++;
	}

xmit_end:
	/* Increment write pointers. Force memory write before we let HW know */
	rte_wmb();
	nfp_qcp_ptr_add(txq->qcp_q, NFP_QCP_WRITE_PTR, issued_descs);

	return i;
}

static int
nfp_net_nfdk_tx_queue_setup(struct rte_eth_dev *dev,
		uint16_t queue_idx,
		uint16_t nb_desc,
		unsigned int socket_id,
		const struct rte_eth_txconf *tx_conf)
{
	const struct rte_memzone *tz;
	struct nfp_net_txq *txq;
	uint16_t tx_free_thresh;
	struct nfp_net_hw *hw;
	uint32_t tx_desc_sz;

	hw = NFP_NET_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	PMD_INIT_FUNC_TRACE();

	/* Validating number of descriptors */
	tx_desc_sz = nb_desc * sizeof(struct nfp_net_nfdk_tx_desc);
	if (((NFDK_TX_DESC_PER_SIMPLE_PKT * tx_desc_sz) % NFP_ALIGN_RING_DESC) != 0 ||
	    ((NFDK_TX_DESC_PER_SIMPLE_PKT * nb_desc) % NFDK_TX_DESC_BLOCK_CNT) != 0 ||
	      nb_desc > NFP_NET_MAX_TX_DESC || nb_desc < NFP_NET_MIN_TX_DESC) {
		PMD_DRV_LOG(ERR, "Wrong nb_desc value");
		return -EINVAL;
	}

	tx_free_thresh = (uint16_t)((tx_conf->tx_free_thresh) ?
				tx_conf->tx_free_thresh :
				DEFAULT_TX_FREE_THRESH);

	if (tx_free_thresh > (nb_desc)) {
		PMD_DRV_LOG(ERR,
			"tx_free_thresh must be less than the number of TX "
			"descriptors. (tx_free_thresh=%u port=%d "
			"queue=%d)", (unsigned int)tx_free_thresh,
			dev->data->port_id, (int)queue_idx);
		return -(EINVAL);
	}

	/*
	 * Free memory prior to re-allocation if needed. This is the case after
	 * calling nfp_net_stop
	 */
	if (dev->data->tx_queues[queue_idx]) {
		PMD_TX_LOG(DEBUG, "Freeing memory prior to re-allocation %d",
				queue_idx);
		nfp_net_tx_queue_release(dev, queue_idx);
		dev->data->tx_queues[queue_idx] = NULL;
	}

	/* Allocating tx queue data structure */
	txq = rte_zmalloc_socket("ethdev TX queue", sizeof(struct nfp_net_txq),
			RTE_CACHE_LINE_SIZE, socket_id);
	if (txq == NULL) {
		PMD_DRV_LOG(ERR, "Error allocating tx dma");
		return -ENOMEM;
	}

	/*
	 * Allocate TX ring hardware descriptors. A memzone large enough to
	 * handle the maximum ring size is allocated in order to allow for
	 * resizing in later calls to the queue setup function.
	 */
	tz = rte_eth_dma_zone_reserve(dev, "tx_ring", queue_idx,
				sizeof(struct nfp_net_nfdk_tx_desc) *
				NFDK_TX_DESC_PER_SIMPLE_PKT *
				NFP_NET_MAX_TX_DESC, NFP_MEMZONE_ALIGN,
				socket_id);
	if (tz == NULL) {
		PMD_DRV_LOG(ERR, "Error allocating tx dma");
		nfp_net_tx_queue_release(dev, queue_idx);
		return -ENOMEM;
	}

	txq->tx_count = nb_desc * NFDK_TX_DESC_PER_SIMPLE_PKT;
	txq->tx_free_thresh = tx_free_thresh;
	txq->tx_pthresh = tx_conf->tx_thresh.pthresh;
	txq->tx_hthresh = tx_conf->tx_thresh.hthresh;
	txq->tx_wthresh = tx_conf->tx_thresh.wthresh;

	/* queue mapping based on firmware configuration */
	txq->qidx = queue_idx;
	txq->tx_qcidx = queue_idx * hw->stride_tx;
	txq->qcp_q = hw->tx_bar + NFP_QCP_QUEUE_OFF(txq->tx_qcidx);

	txq->port_id = dev->data->port_id;

	/* Saving physical and virtual addresses for the TX ring */
	txq->dma = (uint64_t)tz->iova;
	txq->ktxds = (struct nfp_net_nfdk_tx_desc *)tz->addr;

	/* mbuf pointers array for referencing mbufs linked to TX descriptors */
	txq->txbufs = rte_zmalloc_socket("txq->txbufs",
				sizeof(*txq->txbufs) * txq->tx_count,
				RTE_CACHE_LINE_SIZE, socket_id);

	if (txq->txbufs == NULL) {
		nfp_net_tx_queue_release(dev, queue_idx);
		return -ENOMEM;
	}
	PMD_TX_LOG(DEBUG, "txbufs=%p hw_ring=%p dma_addr=0x%" PRIx64,
		txq->txbufs, txq->ktxds, (unsigned long)txq->dma);

	nfp_net_reset_tx_queue(txq);

	dev->data->tx_queues[queue_idx] = txq;
	txq->hw = hw;
	/*
	 * Telling the HW about the physical address of the TX ring and number
	 * of descriptors in log2 format
	 */
	nn_cfg_writeq(hw, NFP_NET_CFG_TXR_ADDR(queue_idx), txq->dma);
	nn_cfg_writeb(hw, NFP_NET_CFG_TXR_SZ(queue_idx), rte_log2_u32(txq->tx_count));

	return 0;
}

int
nfp_net_tx_queue_setup(struct rte_eth_dev *dev,
		uint16_t queue_idx,
		uint16_t nb_desc,
		unsigned int socket_id,
		const struct rte_eth_txconf *tx_conf)
{
	struct nfp_net_hw *hw;

	hw = NFP_NET_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	switch (NFD_CFG_CLASS_VER_of(hw->ver)) {
	case NFP_NET_CFG_VERSION_DP_NFD3:
		return nfp_net_nfd3_tx_queue_setup(dev, queue_idx,
				nb_desc, socket_id, tx_conf);
	case NFP_NET_CFG_VERSION_DP_NFDK:
		if (NFD_CFG_MAJOR_VERSION_of(hw->ver) < 5) {
			PMD_DRV_LOG(ERR, "NFDK must use ABI 5 or newer, found: %d",
				NFD_CFG_MAJOR_VERSION_of(hw->ver));
			return -EINVAL;
		}
		return nfp_net_nfdk_tx_queue_setup(dev, queue_idx,
				nb_desc, socket_id, tx_conf);
	default:
		PMD_DRV_LOG(ERR, "The version of firmware is not correct.");
		return -EINVAL;
	}
}

static inline uint32_t
nfp_net_nfdk_free_tx_desc(struct nfp_net_txq *txq)
{
	uint32_t free_desc;

	if (txq->wr_p >= txq->rd_p)
		free_desc = txq->tx_count - (txq->wr_p - txq->rd_p);
	else
		free_desc = txq->rd_p - txq->wr_p;

	return (free_desc > NFDK_TX_DESC_STOP_CNT) ?
		(free_desc - NFDK_TX_DESC_STOP_CNT) : 0;
}

static inline uint32_t
nfp_net_nfdk_txq_full(struct nfp_net_txq *txq)
{
	return (nfp_net_nfdk_free_tx_desc(txq) < txq->tx_free_thresh);
}

static inline int
nfp_net_nfdk_headlen_to_segs(unsigned int headlen)
{
	return DIV_ROUND_UP(headlen +
			NFDK_TX_MAX_DATA_PER_DESC -
			NFDK_TX_MAX_DATA_PER_HEAD,
			NFDK_TX_MAX_DATA_PER_DESC);
}

static int
nfp_net_nfdk_tx_maybe_close_block(struct nfp_net_txq *txq, struct rte_mbuf *pkt)
{
	unsigned int n_descs, wr_p, i, nop_slots;
	struct rte_mbuf *pkt_temp;

	pkt_temp = pkt;
	n_descs = nfp_net_nfdk_headlen_to_segs(pkt_temp->data_len);
	while (pkt_temp->next) {
		pkt_temp = pkt_temp->next;
		n_descs += DIV_ROUND_UP(pkt_temp->data_len, NFDK_TX_MAX_DATA_PER_DESC);
	}

	if (unlikely(n_descs > NFDK_TX_DESC_GATHER_MAX))
		return -EINVAL;

	/* Under count by 1 (don't count meta) for the round down to work out */
	n_descs += !!(pkt->ol_flags & RTE_MBUF_F_TX_TCP_SEG);

	if (round_down(txq->wr_p, NFDK_TX_DESC_BLOCK_CNT) !=
			round_down(txq->wr_p + n_descs, NFDK_TX_DESC_BLOCK_CNT))
		goto close_block;

	if ((uint32_t)txq->data_pending + pkt->pkt_len > NFDK_TX_MAX_DATA_PER_BLOCK)
		goto close_block;

	return 0;

close_block:
	wr_p = txq->wr_p;
	nop_slots = D_BLOCK_CPL(wr_p);

	memset(&txq->ktxds[wr_p], 0, nop_slots * sizeof(struct nfp_net_nfdk_tx_desc));
	for (i = wr_p; i < nop_slots + wr_p; i++) {
		if (txq->txbufs[i].mbuf) {
			rte_pktmbuf_free_seg(txq->txbufs[i].mbuf);
			txq->txbufs[i].mbuf = NULL;
		}
	}
	txq->data_pending = 0;
	txq->wr_p = D_IDX(txq, txq->wr_p + nop_slots);

	return nop_slots;
}

static inline uint64_t
nfp_net_nfdk_tx_cksum(struct nfp_net_txq *txq, struct rte_mbuf *mb,
		uint64_t flags)
{
	uint64_t ol_flags;
	struct nfp_net_hw *hw = txq->hw;

	if (!(hw->cap & NFP_NET_CFG_CTRL_TXCSUM))
		return flags;

	ol_flags = mb->ol_flags;

	/* IPv6 does not need checksum */
	if (ol_flags & RTE_MBUF_F_TX_IP_CKSUM)
		flags |= NFDK_DESC_TX_L3_CSUM;

	if (ol_flags & RTE_MBUF_F_TX_L4_MASK)
		flags |= NFDK_DESC_TX_L4_CSUM;

	return flags;
}

static inline uint64_t
nfp_net_nfdk_tx_tso(struct nfp_net_txq *txq, struct rte_mbuf *mb)
{
	uint64_t ol_flags;
	struct nfp_net_nfdk_tx_desc txd;
	struct nfp_net_hw *hw = txq->hw;

	if (!(hw->cap & NFP_NET_CFG_CTRL_LSO_ANY))
		goto clean_txd;

	ol_flags = mb->ol_flags;

	if (!(ol_flags & RTE_MBUF_F_TX_TCP_SEG))
		goto clean_txd;

	txd.l3_offset = mb->l2_len;
	txd.l4_offset = mb->l2_len + mb->l3_len;
	txd.lso_meta_res = 0;
	txd.mss = rte_cpu_to_le_16(mb->tso_segsz);
	txd.lso_hdrlen = mb->l2_len + mb->l3_len + mb->l4_len;
	txd.lso_totsegs = (mb->pkt_len + mb->tso_segsz) / mb->tso_segsz;

	return txd.raw;

clean_txd:
	txd.l3_offset = 0;
	txd.l4_offset = 0;
	txd.lso_hdrlen = 0;
	txd.mss = 0;
	txd.lso_totsegs = 0;
	txd.lso_meta_res = 0;

	return txd.raw;
}

uint16_t
nfp_net_nfdk_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	uint32_t buf_idx;
	uint64_t dma_addr;
	uint16_t free_descs;
	uint32_t npkts = 0;
	uint64_t metadata = 0;
	uint16_t issued_descs = 0;
	struct nfp_net_txq *txq;
	struct nfp_net_hw *hw;
	struct nfp_net_nfdk_tx_desc *ktxds;
	struct rte_mbuf *pkt, *temp_pkt;
	struct rte_mbuf **lmbuf;

	txq = tx_queue;
	hw = txq->hw;

	PMD_TX_LOG(DEBUG, "working for queue %u at pos %d and %u packets",
		txq->qidx, txq->wr_p, nb_pkts);

	if ((nfp_net_nfdk_free_tx_desc(txq) < NFDK_TX_DESC_PER_SIMPLE_PKT *
			nb_pkts) || (nfp_net_nfdk_txq_full(txq)))
		nfp_net_tx_free_bufs(txq);

	free_descs = (uint16_t)nfp_net_nfdk_free_tx_desc(txq);
	if (unlikely(free_descs == 0))
		return 0;

	PMD_TX_LOG(DEBUG, "queue: %u. Sending %u packets", txq->qidx, nb_pkts);
	/* Sending packets */
	while ((npkts < nb_pkts) && free_descs) {
		uint32_t type, dma_len, dlen_type, tmp_dlen;
		int nop_descs, used_descs;

		pkt = *(tx_pkts + npkts);
		nop_descs = nfp_net_nfdk_tx_maybe_close_block(txq, pkt);
		if (nop_descs < 0)
			goto xmit_end;

		issued_descs += nop_descs;
		ktxds = &txq->ktxds[txq->wr_p];
		/* Grabbing the mbuf linked to the current descriptor */
		buf_idx = txq->wr_p;
		lmbuf = &txq->txbufs[buf_idx++].mbuf;
		/* Warming the cache for releasing the mbuf later on */
		RTE_MBUF_PREFETCH_TO_FREE(*lmbuf);

		temp_pkt = pkt;

		if (unlikely(pkt->nb_segs > 1 &&
				!(hw->cap & NFP_NET_CFG_CTRL_GATHER))) {
			PMD_INIT_LOG(INFO, "NFP_NET_CFG_CTRL_GATHER not set");
			PMD_INIT_LOG(INFO, "Multisegment packet unsupported");
			goto xmit_end;
		}

		/*
		 * Checksum and VLAN flags just in the first descriptor for a
		 * multisegment packet, but TSO info needs to be in all of them.
		 */

		dma_len = pkt->data_len;
		if ((hw->cap & NFP_NET_CFG_CTRL_LSO_ANY) &&
				(pkt->ol_flags & RTE_MBUF_F_TX_TCP_SEG)) {
			type = NFDK_DESC_TX_TYPE_TSO;
		} else if (pkt->next == NULL && dma_len <= NFDK_TX_MAX_DATA_PER_HEAD) {
			type = NFDK_DESC_TX_TYPE_SIMPLE;
		} else {
			type = NFDK_DESC_TX_TYPE_GATHER;
		}

		/* Implicitly truncates to chunk in below logic */
		dma_len -= 1;

		/*
		 * We will do our best to pass as much data as we can in descriptor
		 * and we need to make sure the first descriptor includes whole
		 * head since there is limitation in firmware side. Sometimes the
		 * value of 'dma_len & NFDK_DESC_TX_DMA_LEN_HEAD' will be less
		 * than packet head len.
		 */
		dlen_type = (dma_len > NFDK_DESC_TX_DMA_LEN_HEAD ?
				NFDK_DESC_TX_DMA_LEN_HEAD : dma_len) |
			(NFDK_DESC_TX_TYPE_HEAD & (type << 12));
		ktxds->dma_len_type = rte_cpu_to_le_16(dlen_type);
		dma_addr = rte_mbuf_data_iova(pkt);
		PMD_TX_LOG(DEBUG, "Working with mbuf at dma address:"
				"%" PRIx64 "", dma_addr);
		ktxds->dma_addr_hi = rte_cpu_to_le_16(dma_addr >> 32);
		ktxds->dma_addr_lo = rte_cpu_to_le_32(dma_addr & 0xffffffff);
		ktxds++;

		/*
		 * Preserve the original dlen_type, this way below the EOP logic
		 * can use dlen_type.
		 */
		tmp_dlen = dlen_type & NFDK_DESC_TX_DMA_LEN_HEAD;
		dma_len -= tmp_dlen;
		dma_addr += tmp_dlen + 1;

		/*
		 * The rest of the data (if any) will be in larger DMA descriptors
		 * and is handled with the dma_len loop.
		 */
		while (pkt) {
			if (*lmbuf)
				rte_pktmbuf_free_seg(*lmbuf);
			*lmbuf = pkt;
			while (dma_len > 0) {
				dma_len -= 1;
				dlen_type = NFDK_DESC_TX_DMA_LEN & dma_len;

				ktxds->dma_len_type = rte_cpu_to_le_16(dlen_type);
				ktxds->dma_addr_hi = rte_cpu_to_le_16(dma_addr >> 32);
				ktxds->dma_addr_lo = rte_cpu_to_le_32(dma_addr & 0xffffffff);
				ktxds++;

				dma_len -= dlen_type;
				dma_addr += dlen_type + 1;
			}

			if (!pkt->next)
				break;

			pkt = pkt->next;
			dma_len = pkt->data_len;
			dma_addr = rte_mbuf_data_iova(pkt);
			PMD_TX_LOG(DEBUG, "Working with mbuf at dma address:"
				"%" PRIx64 "", dma_addr);

			lmbuf = &txq->txbufs[buf_idx++].mbuf;
		}

		(ktxds - 1)->dma_len_type = rte_cpu_to_le_16(dlen_type | NFDK_DESC_TX_EOP);

		ktxds->raw = rte_cpu_to_le_64(nfp_net_nfdk_tx_cksum(txq, temp_pkt, metadata));
		ktxds++;

		if ((hw->cap & NFP_NET_CFG_CTRL_LSO_ANY) &&
				(temp_pkt->ol_flags & RTE_MBUF_F_TX_TCP_SEG)) {
			ktxds->raw = rte_cpu_to_le_64(nfp_net_nfdk_tx_tso(txq, temp_pkt));
			ktxds++;
		}

		used_descs = ktxds - txq->ktxds - txq->wr_p;
		if (round_down(txq->wr_p, NFDK_TX_DESC_BLOCK_CNT) !=
			round_down(txq->wr_p + used_descs - 1, NFDK_TX_DESC_BLOCK_CNT)) {
			PMD_INIT_LOG(INFO, "Used descs cross block boundary");
			goto xmit_end;
		}

		txq->wr_p = D_IDX(txq, txq->wr_p + used_descs);
		if (txq->wr_p % NFDK_TX_DESC_BLOCK_CNT)
			txq->data_pending += temp_pkt->pkt_len;
		else
			txq->data_pending = 0;

		issued_descs += used_descs;
		npkts++;
		free_descs = (uint16_t)nfp_net_nfdk_free_tx_desc(txq);
	}

xmit_end:
	/* Increment write pointers. Force memory write before we let HW know */
	rte_wmb();
	nfp_qcp_ptr_add(txq->qcp_q, NFP_QCP_WRITE_PTR, issued_descs);

	return npkts;
}
