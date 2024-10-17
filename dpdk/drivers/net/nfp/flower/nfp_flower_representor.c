/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Corigine, Inc.
 * All rights reserved.
 */

#include <rte_common.h>
#include <ethdev_pci.h>

#include "../nfp_common.h"
#include "../nfp_logs.h"
#include "../nfp_ctrl.h"
#include "../nfp_rxtx.h"
#include "../nfp_flow.h"
#include "../nfpcore/nfp_mip.h"
#include "../nfpcore/nfp_rtsym.h"
#include "../nfpcore/nfp_nsp.h"
#include "nfp_flower.h"
#include "nfp_flower_representor.h"
#include "nfp_flower_ctrl.h"
#include "nfp_flower_cmsg.h"

static int
nfp_pf_repr_rx_queue_setup(struct rte_eth_dev *dev,
		uint16_t queue_idx,
		uint16_t nb_desc,
		unsigned int socket_id,
		const struct rte_eth_rxconf *rx_conf,
		struct rte_mempool *mp)
{
	struct nfp_net_hw *hw;
	struct nfp_net_rxq *rxq;
	const struct rte_memzone *tz;
	struct nfp_flower_representor *repr;

	repr = (struct nfp_flower_representor *)dev->data->dev_private;
	hw = repr->app_fw_flower->pf_hw;

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
			sizeof(struct nfp_net_rx_desc) * NFP_NET_MAX_RX_DESC,
			NFP_MEMZONE_ALIGN, socket_id);
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

static int
nfp_pf_repr_tx_queue_setup(struct rte_eth_dev *dev,
		uint16_t queue_idx,
		uint16_t nb_desc,
		unsigned int socket_id,
		const struct rte_eth_txconf *tx_conf)
{
	struct nfp_net_hw *hw;
	struct nfp_net_txq *txq;
	uint16_t tx_free_thresh;
	const struct rte_memzone *tz;
	struct nfp_flower_representor *repr;

	repr = (struct nfp_flower_representor *)dev->data->dev_private;
	hw = repr->app_fw_flower->pf_hw;

	tx_free_thresh = (tx_conf->tx_free_thresh) ? tx_conf->tx_free_thresh :
			DEFAULT_TX_FREE_THRESH;
	if (tx_free_thresh > nb_desc)
		return -EINVAL;

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
			sizeof(struct nfp_net_nfd3_tx_desc) * NFP_NET_MAX_TX_DESC,
			NFP_MEMZONE_ALIGN, socket_id);
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

static int
nfp_flower_repr_link_update(struct rte_eth_dev *dev,
		__rte_unused int wait_to_complete)
{
	int ret;
	uint32_t nn_link_status;
	struct nfp_net_hw *pf_hw;
	struct rte_eth_link *link;
	struct nfp_flower_representor *repr;

	static const uint32_t ls_to_ethtool[] = {
		[NFP_NET_CFG_STS_LINK_RATE_UNSUPPORTED] = RTE_ETH_SPEED_NUM_NONE,
		[NFP_NET_CFG_STS_LINK_RATE_UNKNOWN]     = RTE_ETH_SPEED_NUM_NONE,
		[NFP_NET_CFG_STS_LINK_RATE_1G]          = RTE_ETH_SPEED_NUM_1G,
		[NFP_NET_CFG_STS_LINK_RATE_10G]         = RTE_ETH_SPEED_NUM_10G,
		[NFP_NET_CFG_STS_LINK_RATE_25G]         = RTE_ETH_SPEED_NUM_25G,
		[NFP_NET_CFG_STS_LINK_RATE_40G]         = RTE_ETH_SPEED_NUM_40G,
		[NFP_NET_CFG_STS_LINK_RATE_50G]         = RTE_ETH_SPEED_NUM_50G,
		[NFP_NET_CFG_STS_LINK_RATE_100G]        = RTE_ETH_SPEED_NUM_100G,
	};

	repr = (struct nfp_flower_representor *)dev->data->dev_private;
	link = &repr->link;
	pf_hw = repr->app_fw_flower->pf_hw;

	memset(link, 0, sizeof(struct rte_eth_link));
	nn_link_status = nn_cfg_readl(pf_hw, NFP_NET_CFG_STS);

	if (nn_link_status & NFP_NET_CFG_STS_LINK)
		link->link_status = RTE_ETH_LINK_UP;

	link->link_duplex = RTE_ETH_LINK_FULL_DUPLEX;

	nn_link_status = (nn_link_status >> NFP_NET_CFG_STS_LINK_RATE_SHIFT) &
			 NFP_NET_CFG_STS_LINK_RATE_MASK;

	if (nn_link_status >= RTE_DIM(ls_to_ethtool))
		link->link_speed = RTE_ETH_SPEED_NUM_NONE;
	else
		link->link_speed = ls_to_ethtool[nn_link_status];

	ret = rte_eth_linkstatus_set(dev, link);
	if (ret == 0) {
		if (link->link_status)
			PMD_DRV_LOG(INFO, "NIC Link is Up");
		else
			PMD_DRV_LOG(INFO, "NIC Link is Down");
	}

	return ret;
}

static int
nfp_flower_repr_dev_infos_get(__rte_unused struct rte_eth_dev *dev,
		struct rte_eth_dev_info *dev_info)
{
	/* Hardcoded pktlen and queues for now */
	dev_info->max_rx_queues = 1;
	dev_info->max_tx_queues = 1;
	dev_info->min_rx_bufsize = RTE_ETHER_MIN_MTU;
	dev_info->max_rx_pktlen = 9000;

	dev_info->rx_offload_capa = RTE_ETH_RX_OFFLOAD_VLAN_STRIP;
	dev_info->rx_offload_capa |= RTE_ETH_RX_OFFLOAD_IPV4_CKSUM |
			RTE_ETH_RX_OFFLOAD_UDP_CKSUM |
			RTE_ETH_RX_OFFLOAD_TCP_CKSUM;

	dev_info->tx_offload_capa = RTE_ETH_TX_OFFLOAD_VLAN_INSERT;
	dev_info->tx_offload_capa |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
			RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
			RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
	dev_info->tx_offload_capa |= RTE_ETH_TX_OFFLOAD_TCP_TSO;
	dev_info->tx_offload_capa |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

	dev_info->max_mac_addrs = 1;

	return 0;
}

static int
nfp_flower_repr_dev_configure(struct rte_eth_dev *dev)
{
	struct nfp_net_hw *pf_hw;
	struct rte_eth_conf *dev_conf;
	struct rte_eth_rxmode *rxmode;
	struct nfp_flower_representor *repr;

	repr = (struct nfp_flower_representor *)dev->data->dev_private;
	pf_hw = repr->app_fw_flower->pf_hw;

	dev_conf = &dev->data->dev_conf;
	rxmode = &dev_conf->rxmode;

	/* Checking MTU set */
	if (rxmode->mtu > pf_hw->flbufsz) {
		PMD_DRV_LOG(INFO, "MTU (%u) larger then current mbufsize (%u) not supported",
				rxmode->mtu, pf_hw->flbufsz);
		return -ERANGE;
	}

	return 0;
}

static int
nfp_flower_repr_dev_start(struct rte_eth_dev *dev)
{
	struct nfp_flower_representor *repr;
	struct nfp_app_fw_flower *app_fw_flower;
	uint16_t i;

	repr = (struct nfp_flower_representor *)dev->data->dev_private;
	app_fw_flower = repr->app_fw_flower;

	if (repr->repr_type == NFP_REPR_TYPE_PHYS_PORT) {
		nfp_eth_set_configured(app_fw_flower->pf_hw->pf_dev->cpp,
				repr->nfp_idx, 1);
	}

	nfp_flower_cmsg_port_mod(app_fw_flower, repr->port_id, true);

	for (i = 0; i < dev->data->nb_rx_queues; i++)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
	for (i = 0; i < dev->data->nb_tx_queues; i++)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;

	return 0;
}

static int
nfp_flower_repr_dev_stop(struct rte_eth_dev *dev)
{
	struct nfp_flower_representor *repr;
	struct nfp_app_fw_flower *app_fw_flower;
	uint16_t i;

	repr = (struct nfp_flower_representor *)dev->data->dev_private;
	app_fw_flower = repr->app_fw_flower;

	nfp_flower_cmsg_port_mod(app_fw_flower, repr->port_id, false);

	if (repr->repr_type == NFP_REPR_TYPE_PHYS_PORT) {
		nfp_eth_set_configured(app_fw_flower->pf_hw->pf_dev->cpp,
				repr->nfp_idx, 0);
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
	for (i = 0; i < dev->data->nb_tx_queues; i++)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;

	return 0;
}

static int
nfp_flower_repr_rx_queue_setup(struct rte_eth_dev *dev,
		uint16_t rx_queue_id,
		__rte_unused uint16_t nb_rx_desc,
		unsigned int socket_id,
		__rte_unused const struct rte_eth_rxconf *rx_conf,
		__rte_unused struct rte_mempool *mb_pool)
{
	struct nfp_net_rxq *rxq;
	struct nfp_net_hw *pf_hw;
	struct nfp_flower_representor *repr;

	repr = (struct nfp_flower_representor *)dev->data->dev_private;
	pf_hw = repr->app_fw_flower->pf_hw;

	/* Allocating rx queue data structure */
	rxq = rte_zmalloc_socket("ethdev RX queue", sizeof(struct nfp_net_rxq),
			RTE_CACHE_LINE_SIZE, socket_id);
	if (rxq == NULL)
		return -ENOMEM;

	rxq->hw = pf_hw;
	rxq->qidx = rx_queue_id;
	rxq->port_id = dev->data->port_id;
	dev->data->rx_queues[rx_queue_id] = rxq;

	return 0;
}

static int
nfp_flower_repr_tx_queue_setup(struct rte_eth_dev *dev,
		uint16_t tx_queue_id,
		__rte_unused uint16_t nb_tx_desc,
		unsigned int socket_id,
		__rte_unused const struct rte_eth_txconf *tx_conf)
{
	struct nfp_net_txq *txq;
	struct nfp_net_hw *pf_hw;
	struct nfp_flower_representor *repr;

	repr = (struct nfp_flower_representor *)dev->data->dev_private;
	pf_hw = repr->app_fw_flower->pf_hw;

	/* Allocating tx queue data structure */
	txq = rte_zmalloc_socket("ethdev TX queue", sizeof(struct nfp_net_txq),
			RTE_CACHE_LINE_SIZE, socket_id);
	if (txq == NULL)
		return -ENOMEM;

	txq->hw = pf_hw;
	txq->qidx = tx_queue_id;
	txq->port_id = dev->data->port_id;
	dev->data->tx_queues[tx_queue_id] = txq;

	return 0;
}

static int
nfp_flower_repr_stats_get(struct rte_eth_dev *ethdev,
		struct rte_eth_stats *stats)
{
	struct nfp_flower_representor *repr;

	repr = (struct nfp_flower_representor *)ethdev->data->dev_private;
	rte_memcpy(stats, &repr->repr_stats, sizeof(struct rte_eth_stats));

	return 0;
}

static int
nfp_flower_repr_stats_reset(struct rte_eth_dev *ethdev)
{
	struct nfp_flower_representor *repr;

	repr = (struct nfp_flower_representor *)ethdev->data->dev_private;
	memset(&repr->repr_stats, 0, sizeof(struct rte_eth_stats));

	return 0;
}

static int
nfp_flower_repr_mac_addr_set(struct rte_eth_dev *ethdev,
		struct rte_ether_addr *mac_addr)
{
	struct nfp_flower_representor *repr;

	repr = (struct nfp_flower_representor *)ethdev->data->dev_private;
	rte_ether_addr_copy(mac_addr, &repr->mac_addr);
	rte_ether_addr_copy(mac_addr, ethdev->data->mac_addrs);

	return 0;
}

static uint16_t
nfp_flower_repr_rx_burst(void *rx_queue,
		struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts)
{
	unsigned int available = 0;
	unsigned int total_dequeue;
	struct nfp_net_rxq *rxq;
	struct rte_eth_dev *dev;
	struct nfp_flower_representor *repr;

	rxq = rx_queue;
	if (unlikely(rxq == NULL)) {
		PMD_RX_LOG(ERR, "RX Bad queue");
		return 0;
	}

	dev = &rte_eth_devices[rxq->port_id];
	repr = dev->data->dev_private;
	if (unlikely(repr->ring == NULL)) {
		PMD_RX_LOG(ERR, "representor %s has no ring configured!",
				repr->name);
		return 0;
	}

	total_dequeue = rte_ring_dequeue_burst(repr->ring, (void *)rx_pkts,
			nb_pkts, &available);
	if (total_dequeue != 0) {
		PMD_RX_LOG(DEBUG, "Representor Rx burst for %s, port_id: 0x%x, "
				"received: %u, available: %u", repr->name,
				repr->port_id, total_dequeue, available);

		repr->repr_stats.ipackets += total_dequeue;
	}

	return total_dequeue;
}

static uint16_t
nfp_flower_repr_tx_burst(void *tx_queue,
		struct rte_mbuf **tx_pkts,
		uint16_t nb_pkts)
{
	uint16_t i;
	uint16_t sent;
	char *meta_offset;
	void *pf_tx_queue;
	struct nfp_net_txq *txq;
	struct nfp_net_hw *pf_hw;
	struct rte_eth_dev *dev;
	struct rte_eth_dev *repr_dev;
	struct nfp_flower_representor *repr;

	txq = tx_queue;
	if (unlikely(txq == NULL)) {
		PMD_TX_LOG(ERR, "TX Bad queue");
		return 0;
	}

	/* Grab a handle to the representor struct */
	repr_dev = &rte_eth_devices[txq->port_id];
	repr = repr_dev->data->dev_private;

	for (i = 0; i < nb_pkts; i++) {
		meta_offset = rte_pktmbuf_prepend(tx_pkts[i], FLOWER_PKT_DATA_OFFSET);
		*(uint32_t *)meta_offset = rte_cpu_to_be_32(NFP_NET_META_PORTID);
		meta_offset += 4;
		*(uint32_t *)meta_offset = rte_cpu_to_be_32(repr->port_id);
	}

	/* This points to the PF vNIC that owns this representor */
	pf_hw = txq->hw;
	dev = pf_hw->eth_dev;

	/* Only using Tx queue 0 for now. */
	pf_tx_queue = dev->data->tx_queues[0];
	sent = nfp_flower_pf_xmit_pkts(pf_tx_queue, tx_pkts, nb_pkts);
	if (sent != 0) {
		PMD_TX_LOG(DEBUG, "Representor Tx burst for %s, port_id: 0x%x transmitted: %u",
				repr->name, repr->port_id, sent);
		repr->repr_stats.opackets += sent;
	}

	return sent;
}

static void
nfp_flower_repr_free_queue(struct nfp_flower_representor *repr)
{
	uint16_t i;
	struct rte_eth_dev *eth_dev = repr->eth_dev;

	for (i = 0; i < eth_dev->data->nb_tx_queues; i++)
		rte_free(eth_dev->data->tx_queues[i]);

	for (i = 0; i < eth_dev->data->nb_rx_queues; i++)
		rte_free(eth_dev->data->rx_queues[i]);
}

static void
nfp_flower_pf_repr_close_queue(struct nfp_flower_representor *repr)
{
	struct rte_eth_dev *eth_dev = repr->eth_dev;

	/*
	 * We assume that the DPDK application is stopping all the
	 * threads/queues before calling the device close function.
	 */
	nfp_net_disable_queues(eth_dev);

	/* Clear queues */
	nfp_net_close_tx_queue(eth_dev);
	nfp_net_close_rx_queue(eth_dev);
}

static void
nfp_flower_repr_close_queue(struct nfp_flower_representor *repr)
{
	switch (repr->repr_type) {
	case NFP_REPR_TYPE_PHYS_PORT:
		nfp_flower_repr_free_queue(repr);
		break;
	case NFP_REPR_TYPE_PF:
		nfp_flower_pf_repr_close_queue(repr);
		break;
	case NFP_REPR_TYPE_VF:
		nfp_flower_repr_free_queue(repr);
		break;
	default:
		PMD_DRV_LOG(ERR, "Unsupported repr port type.");
		break;
	}
}

static int
nfp_flower_repr_uninit(struct rte_eth_dev *eth_dev)
{
	uint16_t index;
	struct nfp_flower_representor *repr;

	repr = eth_dev->data->dev_private;
	rte_ring_free(repr->ring);

	if (repr->repr_type == NFP_REPR_TYPE_PHYS_PORT) {
		index = NFP_FLOWER_CMSG_PORT_PHYS_PORT_NUM(repr->port_id);
		repr->app_fw_flower->phy_reprs[index] = NULL;
	} else {
		index = repr->vf_id;
		repr->app_fw_flower->vf_reprs[index] = NULL;
	}

	return 0;
}

static int
nfp_flower_pf_repr_uninit(struct rte_eth_dev *eth_dev)
{
	struct nfp_flower_representor *repr = eth_dev->data->dev_private;

	repr->app_fw_flower->pf_repr = NULL;

	return 0;
}

static void
nfp_flower_repr_free(struct nfp_flower_representor *repr,
		enum nfp_repr_type repr_type)
{
	switch (repr_type) {
	case NFP_REPR_TYPE_PHYS_PORT:
		nfp_flower_repr_uninit(repr->eth_dev);
		break;
	case NFP_REPR_TYPE_PF:
		nfp_flower_pf_repr_uninit(repr->eth_dev);
		break;
	case NFP_REPR_TYPE_VF:
		nfp_flower_repr_uninit(repr->eth_dev);
		break;
	default:
		PMD_DRV_LOG(ERR, "Unsupported repr port type.");
		break;
	}
}

/* Reset and stop device. The device can not be restarted. */
static int
nfp_flower_repr_dev_close(struct rte_eth_dev *dev)
{
	uint16_t i;
	struct nfp_net_hw *hw;
	struct nfp_pf_dev *pf_dev;
	struct nfp_flower_representor *repr;
	struct nfp_app_fw_flower *app_fw_flower;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	repr = dev->data->dev_private;
	app_fw_flower = repr->app_fw_flower;
	hw = app_fw_flower->pf_hw;
	pf_dev = hw->pf_dev;

	if (pf_dev->app_fw_id != NFP_APP_FW_FLOWER_NIC)
		return -EINVAL;

	nfp_flower_repr_close_queue(repr);

	nfp_flower_repr_free(repr, repr->repr_type);

	for (i = 0; i < MAX_FLOWER_VFS; i++) {
		if (app_fw_flower->vf_reprs[i] != NULL)
			return 0;
	}

	for (i = 0; i < MAX_FLOWER_PHYPORTS; i++) {
		if (app_fw_flower->phy_reprs[i] != NULL)
			return 0;
	}

	if (app_fw_flower->pf_repr != NULL)
		return 0;

	/* Now it is safe to free all PF resources */
	nfp_uninit_app_fw_flower(pf_dev);
	nfp_pf_uninit(pf_dev);

	return 0;
}

static const struct eth_dev_ops nfp_flower_pf_repr_dev_ops = {
	.dev_infos_get        = nfp_flower_repr_dev_infos_get,

	.dev_start            = nfp_flower_pf_start,
	.dev_configure        = nfp_flower_repr_dev_configure,
	.dev_stop             = nfp_flower_pf_stop,
	.dev_close            = nfp_flower_repr_dev_close,

	.rx_queue_setup       = nfp_pf_repr_rx_queue_setup,
	.tx_queue_setup       = nfp_pf_repr_tx_queue_setup,

	.link_update          = nfp_flower_repr_link_update,

	.stats_get            = nfp_flower_repr_stats_get,
	.stats_reset          = nfp_flower_repr_stats_reset,

	.promiscuous_enable   = nfp_net_promisc_enable,
	.promiscuous_disable  = nfp_net_promisc_disable,

	.mac_addr_set         = nfp_flower_repr_mac_addr_set,
};

static const struct eth_dev_ops nfp_flower_repr_dev_ops = {
	.dev_infos_get        = nfp_flower_repr_dev_infos_get,

	.dev_start            = nfp_flower_repr_dev_start,
	.dev_configure        = nfp_flower_repr_dev_configure,
	.dev_stop             = nfp_flower_repr_dev_stop,
	.dev_close            = nfp_flower_repr_dev_close,

	.rx_queue_setup       = nfp_flower_repr_rx_queue_setup,
	.tx_queue_setup       = nfp_flower_repr_tx_queue_setup,

	.link_update          = nfp_flower_repr_link_update,

	.stats_get            = nfp_flower_repr_stats_get,
	.stats_reset          = nfp_flower_repr_stats_reset,

	.promiscuous_enable   = nfp_net_promisc_enable,
	.promiscuous_disable  = nfp_net_promisc_disable,

	.mac_addr_set         = nfp_flower_repr_mac_addr_set,

	.flow_ops_get         = nfp_net_flow_ops_get,
};

static uint32_t
nfp_flower_get_phys_port_id(uint8_t port)
{
	return (NFP_FLOWER_CMSG_PORT_TYPE_PHYS_PORT << 28) | port;
}

static uint32_t
nfp_get_pcie_port_id(struct nfp_cpp *cpp,
		int type,
		uint8_t vnic,
		uint8_t queue)
{
	uint8_t nfp_pcie;
	uint32_t port_id;

	nfp_pcie = NFP_CPP_INTERFACE_UNIT_of(nfp_cpp_interface(cpp));
	port_id = ((nfp_pcie & 0x3) << 14) |
			((type & 0x3) << 12) |
			((vnic & 0x3f) << 6) |
			(queue & 0x3f) |
			((NFP_FLOWER_CMSG_PORT_TYPE_PCIE_PORT & 0xf) << 28);

	return port_id;
}

static int
nfp_flower_pf_repr_init(struct rte_eth_dev *eth_dev,
		void *init_params)
{
	struct nfp_flower_representor *repr;
	struct nfp_flower_representor *init_repr_data;

	/* Cast the input representor data to the correct struct here */
	init_repr_data = (struct nfp_flower_representor *)init_params;

	/* Memory has been allocated in the eth_dev_create() function */
	repr = eth_dev->data->dev_private;

	/* Copy data here from the input representor template*/
	repr->vf_id            = init_repr_data->vf_id;
	repr->switch_domain_id = init_repr_data->switch_domain_id;
	repr->repr_type        = init_repr_data->repr_type;
	repr->app_fw_flower    = init_repr_data->app_fw_flower;

	snprintf(repr->name, sizeof(repr->name), "%s", init_repr_data->name);

	eth_dev->dev_ops = &nfp_flower_pf_repr_dev_ops;
	eth_dev->rx_pkt_burst = nfp_flower_pf_recv_pkts;
	eth_dev->tx_pkt_burst = nfp_flower_pf_xmit_pkts;
	eth_dev->data->dev_flags |= RTE_ETH_DEV_REPRESENTOR;

	eth_dev->data->representor_id = 0;

	/* This backer port is that of the eth_device created for the PF vNIC */
	eth_dev->data->backer_port_id = 0;

	/* Only single queues for representor devices */
	eth_dev->data->nb_rx_queues = 1;
	eth_dev->data->nb_tx_queues = 1;

	/* Allocating memory for mac addr */
	eth_dev->data->mac_addrs = rte_zmalloc("mac_addr", RTE_ETHER_ADDR_LEN, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		PMD_INIT_LOG(ERR, "Failed to allocate memory for repr MAC");
		return -ENOMEM;
	}

	rte_ether_addr_copy(&init_repr_data->mac_addr, &repr->mac_addr);
	rte_ether_addr_copy(&init_repr_data->mac_addr, eth_dev->data->mac_addrs);

	repr->app_fw_flower->pf_repr = repr;
	repr->app_fw_flower->pf_hw->eth_dev = eth_dev;
	repr->eth_dev = eth_dev;

	return 0;
}

static int
nfp_flower_repr_init(struct rte_eth_dev *eth_dev,
		void *init_params)
{
	int ret;
	uint16_t index;
	unsigned int numa_node;
	char ring_name[RTE_ETH_NAME_MAX_LEN];
	struct nfp_app_fw_flower *app_fw_flower;
	struct nfp_flower_representor *repr;
	struct nfp_flower_representor *init_repr_data;

	/* Cast the input representor data to the correct struct here */
	init_repr_data = (struct nfp_flower_representor *)init_params;
	app_fw_flower = init_repr_data->app_fw_flower;

	/* Memory has been allocated in the eth_dev_create() function */
	repr = eth_dev->data->dev_private;

	/*
	 * We need multiproduce rings as we can have multiple PF ports.
	 * On the other hand, we need single consumer rings, as just one
	 * representor PMD will try to read from the ring.
	 */
	snprintf(ring_name, sizeof(ring_name), "%s_%s", init_repr_data->name, "ring");
	numa_node = rte_socket_id();
	repr->ring = rte_ring_create(ring_name, 256, numa_node, RING_F_SC_DEQ);
	if (repr->ring == NULL) {
		PMD_DRV_LOG(ERR, "rte_ring_create failed for %s", ring_name);
		return -ENOMEM;
	}

	/* Copy data here from the input representor template*/
	repr->vf_id            = init_repr_data->vf_id;
	repr->switch_domain_id = init_repr_data->switch_domain_id;
	repr->port_id          = init_repr_data->port_id;
	repr->nfp_idx          = init_repr_data->nfp_idx;
	repr->repr_type        = init_repr_data->repr_type;
	repr->app_fw_flower    = init_repr_data->app_fw_flower;

	snprintf(repr->name, sizeof(repr->name), "%s", init_repr_data->name);

	eth_dev->dev_ops = &nfp_flower_repr_dev_ops;
	eth_dev->rx_pkt_burst = nfp_flower_repr_rx_burst;
	eth_dev->tx_pkt_burst = nfp_flower_repr_tx_burst;
	eth_dev->data->dev_flags |= RTE_ETH_DEV_REPRESENTOR;

	if (repr->repr_type == NFP_REPR_TYPE_PHYS_PORT)
		eth_dev->data->representor_id = repr->vf_id;
	else
		eth_dev->data->representor_id = repr->vf_id +
				app_fw_flower->num_phyport_reprs + 1;

	/* This backer port is that of the eth_device created for the PF vNIC */
	eth_dev->data->backer_port_id = 0;

	/* Only single queues for representor devices */
	eth_dev->data->nb_rx_queues = 1;
	eth_dev->data->nb_tx_queues = 1;

	/* Allocating memory for mac addr */
	eth_dev->data->mac_addrs = rte_zmalloc("mac_addr", RTE_ETHER_ADDR_LEN, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		PMD_INIT_LOG(ERR, "Failed to allocate memory for repr MAC");
		ret = -ENOMEM;
		goto ring_cleanup;
	}

	rte_ether_addr_copy(&init_repr_data->mac_addr, &repr->mac_addr);
	rte_ether_addr_copy(&init_repr_data->mac_addr, eth_dev->data->mac_addrs);

	/* Send reify message to hardware to inform it about the new repr */
	ret = nfp_flower_cmsg_repr_reify(app_fw_flower, repr);
	if (ret != 0) {
		PMD_INIT_LOG(WARNING, "Failed to send repr reify message");
		goto mac_cleanup;
	}

	/* Add repr to correct array */
	if (repr->repr_type == NFP_REPR_TYPE_PHYS_PORT) {
		index = NFP_FLOWER_CMSG_PORT_PHYS_PORT_NUM(repr->port_id);
		app_fw_flower->phy_reprs[index] = repr;
	} else {
		index = repr->vf_id;
		app_fw_flower->vf_reprs[index] = repr;
	}

	repr->eth_dev = eth_dev;

	return 0;

mac_cleanup:
	rte_free(eth_dev->data->mac_addrs);
ring_cleanup:
	rte_ring_free(repr->ring);

	return ret;
}

static void
nfp_flower_repr_free_all(struct nfp_app_fw_flower *app_fw_flower)
{
	uint32_t i;
	struct nfp_flower_representor *repr;

	for (i = 0; i < MAX_FLOWER_VFS; i++) {
		repr = app_fw_flower->vf_reprs[i];
		if (repr != NULL) {
			nfp_flower_repr_free(repr, NFP_REPR_TYPE_VF);
			app_fw_flower->vf_reprs[i] = NULL;
		}
	}

	for (i = 0; i < MAX_FLOWER_PHYPORTS; i++) {
		repr = app_fw_flower->phy_reprs[i];
		if (repr != NULL) {
			nfp_flower_repr_free(repr, NFP_REPR_TYPE_PHYS_PORT);
			app_fw_flower->phy_reprs[i] = NULL;
		}
	}

	repr = app_fw_flower->pf_repr;
	if (repr != NULL) {
		nfp_flower_repr_free(repr, NFP_REPR_TYPE_PF);
		app_fw_flower->pf_repr = NULL;
	}
}

static int
nfp_flower_repr_alloc(struct nfp_app_fw_flower *app_fw_flower)
{
	int i;
	int ret;
	const char *pci_name;
	struct rte_eth_dev *eth_dev;
	struct rte_pci_device *pci_dev;
	struct nfp_eth_table *nfp_eth_table;
	struct nfp_eth_table_port *eth_port;
	struct nfp_flower_representor flower_repr = {
		.switch_domain_id = app_fw_flower->switch_domain_id,
		.app_fw_flower    = app_fw_flower,
	};

	nfp_eth_table = app_fw_flower->pf_hw->pf_dev->nfp_eth_table;
	eth_dev = app_fw_flower->ctrl_hw->eth_dev;

	/* Send a NFP_FLOWER_CMSG_TYPE_MAC_REPR cmsg to hardware*/
	ret = nfp_flower_cmsg_mac_repr(app_fw_flower);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Cloud not send mac repr cmsgs");
		return ret;
	}

	/* Create a rte_eth_dev for PF vNIC representor */
	flower_repr.repr_type = NFP_REPR_TYPE_PF;

	/* PF vNIC reprs get a random MAC address */
	rte_eth_random_addr(flower_repr.mac_addr.addr_bytes);

	pci_dev = app_fw_flower->pf_hw->pf_dev->pci_dev;

	pci_name = strchr(pci_dev->name, ':') + 1;

	snprintf(flower_repr.name, sizeof(flower_repr.name),
			"%s_repr_pf", pci_name);

	/* Create a eth_dev for this representor */
	ret = rte_eth_dev_create(eth_dev->device, flower_repr.name,
			sizeof(struct nfp_flower_representor),
			NULL, NULL, nfp_flower_pf_repr_init, &flower_repr);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Failed to init the pf repr");
		return -EINVAL;
	}

	/* Create a rte_eth_dev for every phyport representor */
	for (i = 0; i < app_fw_flower->num_phyport_reprs; i++) {
		eth_port = &nfp_eth_table->ports[i];
		flower_repr.repr_type = NFP_REPR_TYPE_PHYS_PORT;
		flower_repr.port_id = nfp_flower_get_phys_port_id(eth_port->index);
		flower_repr.nfp_idx = eth_port->index;
		flower_repr.vf_id = i + 1;

		/* Copy the real mac of the interface to the representor struct */
		rte_ether_addr_copy((struct rte_ether_addr *)eth_port->mac_addr,
				&flower_repr.mac_addr);
		snprintf(flower_repr.name, sizeof(flower_repr.name),
				"%s_repr_p%d", pci_name, i);

		/*
		 * Create a eth_dev for this representor
		 * This will also allocate private memory for the device
		 */
		ret = rte_eth_dev_create(eth_dev->device, flower_repr.name,
				sizeof(struct nfp_flower_representor),
				NULL, NULL, nfp_flower_repr_init, &flower_repr);
		if (ret != 0) {
			PMD_INIT_LOG(ERR, "Cloud not create eth_dev for repr");
			break;
		}
	}

	if (i < app_fw_flower->num_phyport_reprs)
		goto repr_free;

	/*
	 * Now allocate eth_dev's for VF representors.
	 * Also send reify messages
	 */
	for (i = 0; i < app_fw_flower->num_vf_reprs; i++) {
		flower_repr.repr_type = NFP_REPR_TYPE_VF;
		flower_repr.port_id = nfp_get_pcie_port_id(app_fw_flower->pf_hw->cpp,
				NFP_FLOWER_CMSG_PORT_VNIC_TYPE_VF, i, 0);
		flower_repr.nfp_idx = 0;
		flower_repr.vf_id = i;

		/* VF reprs get a random MAC address */
		rte_eth_random_addr(flower_repr.mac_addr.addr_bytes);
		snprintf(flower_repr.name, sizeof(flower_repr.name),
				"%s_repr_vf%d", pci_name, i);

		 /* This will also allocate private memory for the device*/
		ret = rte_eth_dev_create(eth_dev->device, flower_repr.name,
				sizeof(struct nfp_flower_representor),
				NULL, NULL, nfp_flower_repr_init, &flower_repr);
		if (ret != 0) {
			PMD_INIT_LOG(ERR, "Cloud not create eth_dev for repr");
			break;
		}
	}

	if (i < app_fw_flower->num_vf_reprs)
		goto repr_free;

	return 0;

repr_free:
	nfp_flower_repr_free_all(app_fw_flower);

	return ret;
}

int
nfp_flower_repr_create(struct nfp_app_fw_flower *app_fw_flower)
{
	int ret;
	struct nfp_pf_dev *pf_dev;
	struct rte_pci_device *pci_dev;
	struct nfp_eth_table *nfp_eth_table;
	struct rte_eth_devargs eth_da = {
		.nb_representor_ports = 0
	};

	pf_dev = app_fw_flower->pf_hw->pf_dev;
	pci_dev = pf_dev->pci_dev;

	/* Allocate a switch domain for the flower app */
	ret = rte_eth_switch_domain_alloc(&app_fw_flower->switch_domain_id);
	if (ret != 0)
		PMD_INIT_LOG(WARNING, "failed to allocate switch domain for device");

	/* Now parse PCI device args passed for representor info */
	if (pci_dev->device.devargs != NULL) {
		ret = rte_eth_devargs_parse(pci_dev->device.devargs->args, &eth_da);
		if (ret != 0) {
			PMD_INIT_LOG(ERR, "devarg parse failed");
			return -EINVAL;
		}
	}

	if (eth_da.nb_representor_ports == 0) {
		PMD_INIT_LOG(DEBUG, "No representor port need to create.");
		return 0;
	}

	/* There always exist phy repr */
	nfp_eth_table = pf_dev->nfp_eth_table;
	if (eth_da.nb_representor_ports < nfp_eth_table->count + 1) {
		PMD_INIT_LOG(ERR, "Should also create repr port for phy port and PF vNIC.");
		return -ERANGE;
	}

	/* Only support VF representor creation via the command line */
	if (eth_da.type != RTE_ETH_REPRESENTOR_VF) {
		PMD_INIT_LOG(ERR, "Unsupported representor type: %d", eth_da.type);
		return -ENOTSUP;
	}

	/* Fill in flower app with repr counts */
	app_fw_flower->num_phyport_reprs = (uint8_t)nfp_eth_table->count;
	app_fw_flower->num_vf_reprs = eth_da.nb_representor_ports -
			nfp_eth_table->count - 1;

	PMD_INIT_LOG(INFO, "%d number of VF reprs", app_fw_flower->num_vf_reprs);
	PMD_INIT_LOG(INFO, "%d number of phyport reprs", app_fw_flower->num_phyport_reprs);

	ret = nfp_flower_repr_alloc(app_fw_flower);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "representors allocation failed");
		ret = -EINVAL;
		goto domain_free;
	}

	return 0;

domain_free:
	if (rte_eth_switch_domain_free(app_fw_flower->switch_domain_id) != 0)
		PMD_INIT_LOG(WARNING, "Failed to free switch domain for device");

	return ret;
}
