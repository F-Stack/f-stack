/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2021 Netronome Systems, Inc.
 * All rights reserved.
 *
 * Small portions derived from code Copyright(c) 2010-2015 Intel Corporation.
 */

/*
 * vim:shiftwidth=8:noexpandtab
 *
 * @file dpdk/pmd/nfp_ethdev_vf.c
 *
 * Netronome vNIC  VF DPDK Poll-Mode Driver: Main entry point
 */

#include <rte_alarm.h>

#include "nfpcore/nfp_mip.h"
#include "nfpcore/nfp_rtsym.h"

#include "nfp_common.h"
#include "nfp_ctrl.h"
#include "nfp_rxtx.h"
#include "nfp_logs.h"

static void
nfp_netvf_read_mac(struct nfp_net_hw *hw)
{
	uint32_t tmp;

	tmp = rte_be_to_cpu_32(nn_cfg_readl(hw, NFP_NET_CFG_MACADDR));
	memcpy(&hw->mac_addr[0], &tmp, 4);

	tmp = rte_be_to_cpu_32(nn_cfg_readl(hw, NFP_NET_CFG_MACADDR + 4));
	memcpy(&hw->mac_addr[4], &tmp, 2);
}

static int
nfp_netvf_start(struct rte_eth_dev *dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;
	uint32_t new_ctrl, update = 0;
	struct nfp_net_hw *hw;
	struct rte_eth_conf *dev_conf;
	struct rte_eth_rxmode *rxmode;
	uint32_t intr_vector;
	uint16_t i;
	int ret;

	hw = NFP_NET_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	PMD_INIT_LOG(DEBUG, "Start");

	/* Disabling queues just in case... */
	nfp_net_disable_queues(dev);

	/* Enabling the required queues in the device */
	nfp_net_enable_queues(dev);

	/* check and configure queue intr-vector mapping */
	if (dev->data->dev_conf.intr_conf.rxq != 0) {
		if (rte_intr_type_get(intr_handle) ==
						RTE_INTR_HANDLE_UIO) {
			/*
			 * Better not to share LSC with RX interrupts.
			 * Unregistering LSC interrupt handler
			 */
			rte_intr_callback_unregister(pci_dev->intr_handle,
				nfp_net_dev_interrupt_handler, (void *)dev);

			if (dev->data->nb_rx_queues > 1) {
				PMD_INIT_LOG(ERR, "PMD rx interrupt only "
					     "supports 1 queue with UIO");
				return -EIO;
			}
		}
		intr_vector = dev->data->nb_rx_queues;
		if (rte_intr_efd_enable(intr_handle, intr_vector))
			return -1;

		nfp_configure_rx_interrupt(dev, intr_handle);
		update = NFP_NET_CFG_UPDATE_MSIX;
	}

	rte_intr_enable(intr_handle);

	new_ctrl = nfp_check_offloads(dev);

	/* Writing configuration parameters in the device */
	nfp_net_params_setup(hw);

	dev_conf = &dev->data->dev_conf;
	rxmode = &dev_conf->rxmode;

	if (rxmode->mq_mode & RTE_ETH_MQ_RX_RSS) {
		nfp_net_rss_config_default(dev);
		update |= NFP_NET_CFG_UPDATE_RSS;
		if (hw->cap & NFP_NET_CFG_CTRL_RSS2)
			new_ctrl |= NFP_NET_CFG_CTRL_RSS2;
		else
			new_ctrl |= NFP_NET_CFG_CTRL_RSS;
	}

	/* Enable device */
	new_ctrl |= NFP_NET_CFG_CTRL_ENABLE;

	update |= NFP_NET_CFG_UPDATE_GEN | NFP_NET_CFG_UPDATE_RING;

	if (hw->cap & NFP_NET_CFG_CTRL_RINGCFG)
		new_ctrl |= NFP_NET_CFG_CTRL_RINGCFG;

	nn_cfg_writel(hw, NFP_NET_CFG_CTRL, new_ctrl);
	if (nfp_net_reconfig(hw, new_ctrl, update) < 0)
		return -EIO;

	hw->ctrl = new_ctrl;

	/*
	 * Allocating rte mbufs for configured rx queues.
	 * This requires queues being enabled before
	 */
	if (nfp_net_rx_freelist_setup(dev) < 0) {
		ret = -ENOMEM;
		goto error;
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
	for (i = 0; i < dev->data->nb_tx_queues; i++)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;

	return 0;

error:
	/*
	 * An error returned by this function should mean the app
	 * exiting and then the system releasing all the memory
	 * allocated even memory coming from hugepages.
	 *
	 * The device could be enabled at this point with some queues
	 * ready for getting packets. This is true if the call to
	 * nfp_net_rx_freelist_setup() succeeds for some queues but
	 * fails for subsequent queues.
	 *
	 * This should make the app exiting but better if we tell the
	 * device first.
	 */
	nfp_net_disable_queues(dev);

	return ret;
}

static int
nfp_netvf_stop(struct rte_eth_dev *dev)
{
	PMD_INIT_LOG(DEBUG, "Stop");

	nfp_net_disable_queues(dev);

	/* Clear queues */
	nfp_net_stop_tx_queue(dev);

	nfp_net_stop_rx_queue(dev);

	return 0;
}

static int
nfp_netvf_set_link_up(struct rte_eth_dev *dev __rte_unused)
{
	return -ENOTSUP;
}

/* Set the link down. */
static int
nfp_netvf_set_link_down(struct rte_eth_dev *dev __rte_unused)
{
	return -ENOTSUP;
}

/* Reset and stop device. The device can not be restarted. */
static int
nfp_netvf_close(struct rte_eth_dev *dev)
{
	struct rte_pci_device *pci_dev;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	PMD_INIT_LOG(DEBUG, "Close");

	pci_dev = RTE_ETH_DEV_TO_PCI(dev);

	/*
	 * We assume that the DPDK application is stopping all the
	 * threads/queues before calling the device close function.
	 */

	nfp_net_disable_queues(dev);

	/* Clear queues */
	nfp_net_close_tx_queue(dev);

	nfp_net_close_rx_queue(dev);

	rte_intr_disable(pci_dev->intr_handle);

	/* unregister callback func from eal lib */
	rte_intr_callback_unregister(pci_dev->intr_handle,
				     nfp_net_dev_interrupt_handler,
				     (void *)dev);

	/* Cancel possible impending LSC work here before releasing the port*/
	rte_eal_alarm_cancel(nfp_net_dev_interrupt_delayed_handler,
			     (void *)dev);

	/*
	 * The ixgbe PMD disables the pcie master on the
	 * device. The i40e does not...
	 */

	return 0;
}

/* Initialise and register VF driver with DPDK Application */
static const struct eth_dev_ops nfp_netvf_eth_dev_ops = {
	.dev_configure		= nfp_net_configure,
	.dev_start		= nfp_netvf_start,
	.dev_stop		= nfp_netvf_stop,
	.dev_set_link_up	= nfp_netvf_set_link_up,
	.dev_set_link_down	= nfp_netvf_set_link_down,
	.dev_close		= nfp_netvf_close,
	.promiscuous_enable	= nfp_net_promisc_enable,
	.promiscuous_disable	= nfp_net_promisc_disable,
	.link_update		= nfp_net_link_update,
	.stats_get		= nfp_net_stats_get,
	.stats_reset		= nfp_net_stats_reset,
	.dev_infos_get		= nfp_net_infos_get,
	.dev_supported_ptypes_get = nfp_net_supported_ptypes_get,
	.mtu_set		= nfp_net_dev_mtu_set,
	.mac_addr_set		= nfp_net_set_mac_addr,
	.vlan_offload_set	= nfp_net_vlan_offload_set,
	.reta_update		= nfp_net_reta_update,
	.reta_query		= nfp_net_reta_query,
	.rss_hash_update	= nfp_net_rss_hash_update,
	.rss_hash_conf_get	= nfp_net_rss_hash_conf_get,
	.rx_queue_setup		= nfp_net_rx_queue_setup,
	.rx_queue_release	= nfp_net_rx_queue_release,
	.tx_queue_setup		= nfp_net_tx_queue_setup,
	.tx_queue_release	= nfp_net_tx_queue_release,
	.rx_queue_intr_enable   = nfp_rx_queue_intr_enable,
	.rx_queue_intr_disable  = nfp_rx_queue_intr_disable,
};

static inline int
nfp_netvf_ethdev_ops_mount(struct nfp_net_hw *hw, struct rte_eth_dev *eth_dev)
{
	switch (NFD_CFG_CLASS_VER_of(hw->ver)) {
	case NFP_NET_CFG_VERSION_DP_NFD3:
		eth_dev->tx_pkt_burst = &nfp_net_nfd3_xmit_pkts;
		break;
	case NFP_NET_CFG_VERSION_DP_NFDK:
		if (NFD_CFG_MAJOR_VERSION_of(hw->ver) < 5) {
			PMD_DRV_LOG(ERR, "NFDK must use ABI 5 or newer, found: %d",
				NFD_CFG_MAJOR_VERSION_of(hw->ver));
			return -EINVAL;
		}
		eth_dev->tx_pkt_burst = &nfp_net_nfdk_xmit_pkts;
		break;
	default:
		PMD_DRV_LOG(ERR, "The version of firmware is not correct.");
		return -EINVAL;
	}

	eth_dev->dev_ops = &nfp_netvf_eth_dev_ops;
	eth_dev->rx_queue_count = nfp_net_rx_queue_count;
	eth_dev->rx_pkt_burst = &nfp_net_recv_pkts;

	return 0;
}

static int
nfp_netvf_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev;
	struct nfp_net_hw *hw;
	struct rte_ether_addr *tmp_ether_addr;

	uint64_t tx_bar_off = 0, rx_bar_off = 0;
	uint32_t start_q;
	int stride = 4;
	int port = 0;
	int err;

	PMD_INIT_FUNC_TRACE();

	pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	hw = NFP_NET_DEV_PRIVATE_TO_HW(eth_dev->data->dev_private);

	hw->ctrl_bar = (uint8_t *)pci_dev->mem_resource[0].addr;
	if (hw->ctrl_bar == NULL) {
		PMD_DRV_LOG(ERR,
			"hw->ctrl_bar is NULL. BAR0 not configured");
		return -ENODEV;
	}

	PMD_INIT_LOG(DEBUG, "ctrl bar: %p", hw->ctrl_bar);

	hw->ver = nn_cfg_readl(hw, NFP_NET_CFG_VERSION);

	if (nfp_net_check_dma_mask(hw, pci_dev->name) != 0)
		return -ENODEV;

	if (nfp_netvf_ethdev_ops_mount(hw, eth_dev))
		return -EINVAL;

	/* For secondary processes, the primary has done all the work */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	hw->device_id = pci_dev->id.device_id;
	hw->vendor_id = pci_dev->id.vendor_id;
	hw->subsystem_device_id = pci_dev->id.subsystem_device_id;
	hw->subsystem_vendor_id = pci_dev->id.subsystem_vendor_id;

	PMD_INIT_LOG(DEBUG, "nfp_net: device (%u:%u) %u:%u:%u:%u",
		     pci_dev->id.vendor_id, pci_dev->id.device_id,
		     pci_dev->addr.domain, pci_dev->addr.bus,
		     pci_dev->addr.devid, pci_dev->addr.function);

	hw->max_rx_queues = nn_cfg_readl(hw, NFP_NET_CFG_MAX_RXRINGS);
	hw->max_tx_queues = nn_cfg_readl(hw, NFP_NET_CFG_MAX_TXRINGS);

	/* Work out where in the BAR the queues start. */
	switch (pci_dev->id.device_id) {
	case PCI_DEVICE_ID_NFP3800_VF_NIC:
	case PCI_DEVICE_ID_NFP6000_VF_NIC:
		start_q = nn_cfg_readl(hw, NFP_NET_CFG_START_TXQ);
		tx_bar_off = nfp_pci_queue(pci_dev, start_q);
		start_q = nn_cfg_readl(hw, NFP_NET_CFG_START_RXQ);
		rx_bar_off = nfp_pci_queue(pci_dev, start_q);
		break;
	default:
		PMD_DRV_LOG(ERR, "nfp_net: no device ID matching");
		err = -ENODEV;
		goto dev_err_ctrl_map;
	}

	PMD_INIT_LOG(DEBUG, "tx_bar_off: 0x%" PRIx64 "", tx_bar_off);
	PMD_INIT_LOG(DEBUG, "rx_bar_off: 0x%" PRIx64 "", rx_bar_off);

	hw->tx_bar = (uint8_t *)pci_dev->mem_resource[2].addr +
		     tx_bar_off;
	hw->rx_bar = (uint8_t *)pci_dev->mem_resource[2].addr +
		     rx_bar_off;

	PMD_INIT_LOG(DEBUG, "ctrl_bar: %p, tx_bar: %p, rx_bar: %p",
		     hw->ctrl_bar, hw->tx_bar, hw->rx_bar);

	nfp_net_cfg_queue_setup(hw);

	/* Get some of the read-only fields from the config BAR */
	hw->cap = nn_cfg_readl(hw, NFP_NET_CFG_CAP);
	hw->max_mtu = nn_cfg_readl(hw, NFP_NET_CFG_MAX_MTU);
	hw->mtu = RTE_ETHER_MTU;
	hw->flbufsz = DEFAULT_FLBUF_SIZE;

	/* VLAN insertion is incompatible with LSOv2 */
	if (hw->cap & NFP_NET_CFG_CTRL_LSO2)
		hw->cap &= ~NFP_NET_CFG_CTRL_TXVLAN;

	if (NFD_CFG_MAJOR_VERSION_of(hw->ver) < 2)
		hw->rx_offset = NFP_NET_RX_OFFSET;
	else
		hw->rx_offset = nn_cfg_readl(hw, NFP_NET_CFG_RX_OFFSET_ADDR);

	PMD_INIT_LOG(INFO, "VER: %u.%u, Maximum supported MTU: %d",
			   NFD_CFG_MAJOR_VERSION_of(hw->ver),
			   NFD_CFG_MINOR_VERSION_of(hw->ver), hw->max_mtu);

	PMD_INIT_LOG(INFO, "CAP: %#x, %s%s%s%s%s%s%s%s%s%s%s%s%s%s", hw->cap,
		     hw->cap & NFP_NET_CFG_CTRL_PROMISC ? "PROMISC " : "",
		     hw->cap & NFP_NET_CFG_CTRL_L2BC    ? "L2BCFILT " : "",
		     hw->cap & NFP_NET_CFG_CTRL_L2MC    ? "L2MCFILT " : "",
		     hw->cap & NFP_NET_CFG_CTRL_RXCSUM  ? "RXCSUM "  : "",
		     hw->cap & NFP_NET_CFG_CTRL_TXCSUM  ? "TXCSUM "  : "",
		     hw->cap & NFP_NET_CFG_CTRL_RXVLAN  ? "RXVLAN "  : "",
		     hw->cap & NFP_NET_CFG_CTRL_TXVLAN  ? "TXVLAN "  : "",
		     hw->cap & NFP_NET_CFG_CTRL_SCATTER ? "SCATTER " : "",
		     hw->cap & NFP_NET_CFG_CTRL_GATHER  ? "GATHER "  : "",
		     hw->cap & NFP_NET_CFG_CTRL_LIVE_ADDR ? "LIVE_ADDR "  : "",
		     hw->cap & NFP_NET_CFG_CTRL_LSO     ? "TSO "     : "",
		     hw->cap & NFP_NET_CFG_CTRL_LSO2     ? "TSOv2 "     : "",
		     hw->cap & NFP_NET_CFG_CTRL_RSS     ? "RSS "     : "",
		     hw->cap & NFP_NET_CFG_CTRL_RSS2     ? "RSSv2 "     : "");

	hw->ctrl = 0;

	hw->stride_rx = stride;
	hw->stride_tx = stride;

	PMD_INIT_LOG(INFO, "max_rx_queues: %u, max_tx_queues: %u",
		     hw->max_rx_queues, hw->max_tx_queues);

	/* Initializing spinlock for reconfigs */
	rte_spinlock_init(&hw->reconfig_lock);

	/* Allocating memory for mac addr */
	eth_dev->data->mac_addrs = rte_zmalloc("mac_addr",
					       RTE_ETHER_ADDR_LEN, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		PMD_INIT_LOG(ERR, "Failed to space for MAC address");
		err = -ENOMEM;
		goto dev_err_queues_map;
	}

	nfp_netvf_read_mac(hw);

	tmp_ether_addr = (struct rte_ether_addr *)&hw->mac_addr;
	if (!rte_is_valid_assigned_ether_addr(tmp_ether_addr)) {
		PMD_INIT_LOG(INFO, "Using random mac address for port %d",
				   port);
		/* Using random mac addresses for VFs */
		rte_eth_random_addr(&hw->mac_addr[0]);
		nfp_net_write_mac(hw, (uint8_t *)&hw->mac_addr);
	}

	/* Copying mac address to DPDK eth_dev struct */
	rte_ether_addr_copy((struct rte_ether_addr *)hw->mac_addr,
			&eth_dev->data->mac_addrs[0]);

	if (!(hw->cap & NFP_NET_CFG_CTRL_LIVE_ADDR))
		eth_dev->data->dev_flags |= RTE_ETH_DEV_NOLIVE_MAC_ADDR;

	eth_dev->data->dev_flags |= RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;

	PMD_INIT_LOG(INFO, "port %d VendorID=0x%x DeviceID=0x%x "
		     "mac=%02x:%02x:%02x:%02x:%02x:%02x",
		     eth_dev->data->port_id, pci_dev->id.vendor_id,
		     pci_dev->id.device_id,
		     hw->mac_addr[0], hw->mac_addr[1], hw->mac_addr[2],
		     hw->mac_addr[3], hw->mac_addr[4], hw->mac_addr[5]);

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		/* Registering LSC interrupt handler */
		rte_intr_callback_register(pci_dev->intr_handle,
					   nfp_net_dev_interrupt_handler,
					   (void *)eth_dev);
		/* Telling the firmware about the LSC interrupt entry */
		nn_cfg_writeb(hw, NFP_NET_CFG_LSC, NFP_NET_IRQ_LSC_IDX);
		/* Unmask the LSC interrupt */
		nfp_net_irq_unmask(eth_dev);
		/* Recording current stats counters values */
		nfp_net_stats_reset(eth_dev);
	}

	return 0;

dev_err_queues_map:
		nfp_cpp_area_free(hw->hwqueues_area);
dev_err_ctrl_map:
		nfp_cpp_area_free(hw->ctrl_area);

	return err;
}

static const struct rte_pci_id pci_id_nfp_vf_net_map[] = {
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_NETRONOME,
			       PCI_DEVICE_ID_NFP3800_VF_NIC)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_NETRONOME,
			       PCI_DEVICE_ID_NFP6000_VF_NIC)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_CORIGINE,
			       PCI_DEVICE_ID_NFP3800_VF_NIC)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_CORIGINE,
			       PCI_DEVICE_ID_NFP6000_VF_NIC)
	},
	{
		.vendor_id = 0,
	},
};

static int nfp_vf_pci_uninit(struct rte_eth_dev *eth_dev)
{
	/* VF cleanup, just free private port data */
	return nfp_netvf_close(eth_dev);
}

static int eth_nfp_vf_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
		sizeof(struct nfp_net_adapter), nfp_netvf_init);
}

static int eth_nfp_vf_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev, nfp_vf_pci_uninit);
}

static struct rte_pci_driver rte_nfp_net_vf_pmd = {
	.id_table = pci_id_nfp_vf_net_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = eth_nfp_vf_pci_probe,
	.remove = eth_nfp_vf_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_nfp_vf, rte_nfp_net_vf_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_nfp_vf, pci_id_nfp_vf_net_map);
RTE_PMD_REGISTER_KMOD_DEP(net_nfp_vf, "* igb_uio | uio_pci_generic | vfio");
/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
