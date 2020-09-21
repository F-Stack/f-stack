/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017 6WIND S.A.
 * Copyright 2017 Mellanox Technologies, Ltd
 */

#include <unistd.h>

#include <rte_flow.h>
#include <rte_flow_driver.h>
#include <rte_cycles.h>

#include "failsafe_private.h"

/** Print a message out of a flow error. */
static int
fs_flow_complain(struct rte_flow_error *error)
{
	static const char *const errstrlist[] = {
		[RTE_FLOW_ERROR_TYPE_NONE] = "no error",
		[RTE_FLOW_ERROR_TYPE_UNSPECIFIED] = "cause unspecified",
		[RTE_FLOW_ERROR_TYPE_HANDLE] = "flow rule (handle)",
		[RTE_FLOW_ERROR_TYPE_ATTR_GROUP] = "group field",
		[RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY] = "priority field",
		[RTE_FLOW_ERROR_TYPE_ATTR_INGRESS] = "ingress field",
		[RTE_FLOW_ERROR_TYPE_ATTR_EGRESS] = "egress field",
		[RTE_FLOW_ERROR_TYPE_ATTR] = "attributes structure",
		[RTE_FLOW_ERROR_TYPE_ITEM_NUM] = "pattern length",
		[RTE_FLOW_ERROR_TYPE_ITEM] = "specific pattern item",
		[RTE_FLOW_ERROR_TYPE_ACTION_NUM] = "number of actions",
		[RTE_FLOW_ERROR_TYPE_ACTION] = "specific action",
	};
	const char *errstr;
	char buf[32];
	int err = rte_errno;

	if ((unsigned int)error->type >= RTE_DIM(errstrlist) ||
			!errstrlist[error->type])
		errstr = "unknown type";
	else
		errstr = errstrlist[error->type];
	ERROR("Caught error type %d (%s): %s%s\n",
		error->type, errstr,
		error->cause ? (snprintf(buf, sizeof(buf), "cause: %p, ",
				error->cause), buf) : "",
		error->message ? error->message : "(no stated reason)");
	return -err;
}

static int
eth_dev_flow_isolate_set(struct rte_eth_dev *dev,
			 struct sub_device *sdev)
{
	struct rte_flow_error ferror;
	int ret;

	if (!PRIV(dev)->flow_isolated) {
		DEBUG("Flow isolation already disabled");
	} else {
		DEBUG("Enabling flow isolation");
		ret = rte_flow_isolate(PORT_ID(sdev),
				       PRIV(dev)->flow_isolated,
				       &ferror);
		if (ret) {
			fs_flow_complain(&ferror);
			return ret;
		}
	}
	return 0;
}

static int
fs_eth_dev_conf_apply(struct rte_eth_dev *dev,
		struct sub_device *sdev)
{
	struct rte_eth_dev *edev;
	struct rte_vlan_filter_conf *vfc1;
	struct rte_vlan_filter_conf *vfc2;
	struct rte_flow *flow;
	struct rte_flow_error ferror;
	uint32_t i;
	int ret;

	edev = ETH(sdev);
	/* RX queue setup */
	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct rxq *rxq;

		rxq = dev->data->rx_queues[i];
		ret = rte_eth_rx_queue_setup(PORT_ID(sdev), i,
				rxq->info.nb_desc, rxq->socket_id,
				&rxq->info.conf, rxq->info.mp);
		if (ret) {
			ERROR("rx_queue_setup failed");
			return ret;
		}
	}
	/* TX queue setup */
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		struct txq *txq;

		txq = dev->data->tx_queues[i];
		ret = rte_eth_tx_queue_setup(PORT_ID(sdev), i,
				txq->info.nb_desc, txq->socket_id,
				&txq->info.conf);
		if (ret) {
			ERROR("tx_queue_setup failed");
			return ret;
		}
	}
	/* dev_link.link_status */
	if (dev->data->dev_link.link_status !=
	    edev->data->dev_link.link_status) {
		DEBUG("Configuring link_status");
		if (dev->data->dev_link.link_status)
			ret = rte_eth_dev_set_link_up(PORT_ID(sdev));
		else
			ret = rte_eth_dev_set_link_down(PORT_ID(sdev));
		if (ret) {
			ERROR("Failed to apply link_status");
			return ret;
		}
	} else {
		DEBUG("link_status already set");
	}
	/* promiscuous */
	if (dev->data->promiscuous != edev->data->promiscuous) {
		DEBUG("Configuring promiscuous");
		if (dev->data->promiscuous)
			rte_eth_promiscuous_enable(PORT_ID(sdev));
		else
			rte_eth_promiscuous_disable(PORT_ID(sdev));
	} else {
		DEBUG("promiscuous already set");
	}
	/* all_multicast */
	if (dev->data->all_multicast != edev->data->all_multicast) {
		DEBUG("Configuring all_multicast");
		if (dev->data->all_multicast)
			rte_eth_allmulticast_enable(PORT_ID(sdev));
		else
			rte_eth_allmulticast_disable(PORT_ID(sdev));
	} else {
		DEBUG("all_multicast already set");
	}
	/* MTU */
	if (dev->data->mtu != edev->data->mtu) {
		DEBUG("Configuring MTU");
		ret = rte_eth_dev_set_mtu(PORT_ID(sdev), dev->data->mtu);
		if (ret) {
			ERROR("Failed to apply MTU");
			return ret;
		}
	} else {
		DEBUG("MTU already set");
	}
	/* default MAC */
	DEBUG("Configuring default MAC address");
	ret = rte_eth_dev_default_mac_addr_set(PORT_ID(sdev),
			&dev->data->mac_addrs[0]);
	if (ret) {
		ERROR("Setting default MAC address failed");
		return ret;
	}
	/* additional MAC */
	if (PRIV(dev)->nb_mac_addr > 1)
		DEBUG("Configure additional MAC address%s",
			(PRIV(dev)->nb_mac_addr > 2 ? "es" : ""));
	for (i = 1; i < PRIV(dev)->nb_mac_addr; i++) {
		struct ether_addr *ea;

		ea = &dev->data->mac_addrs[i];
		ret = rte_eth_dev_mac_addr_add(PORT_ID(sdev), ea,
				PRIV(dev)->mac_addr_pool[i]);
		if (ret) {
			char ea_fmt[ETHER_ADDR_FMT_SIZE];

			ether_format_addr(ea_fmt, ETHER_ADDR_FMT_SIZE, ea);
			ERROR("Adding MAC address %s failed", ea_fmt);
			return ret;
		}
	}
	/*
	 * Propagate multicast MAC addresses to sub-devices,
	 * if non zero number of addresses is set.
	 * The condition is required to avoid breakage of failsafe
	 * for sub-devices which do not support the operation
	 * if the feature is really not used.
	 */
	if (PRIV(dev)->nb_mcast_addr > 0) {
		DEBUG("Configuring multicast MAC addresses");
		ret = rte_eth_dev_set_mc_addr_list(PORT_ID(sdev),
						   PRIV(dev)->mcast_addrs,
						   PRIV(dev)->nb_mcast_addr);
		if (ret) {
			ERROR("Failed to apply multicast MAC addresses");
			return ret;
		}
	}
	/* VLAN filter */
	vfc1 = &dev->data->vlan_filter_conf;
	vfc2 = &edev->data->vlan_filter_conf;
	if (memcmp(vfc1, vfc2, sizeof(struct rte_vlan_filter_conf))) {
		uint64_t vbit;
		uint64_t ids;
		size_t i;
		uint16_t vlan_id;

		DEBUG("Configuring VLAN filter");
		for (i = 0; i < RTE_DIM(vfc1->ids); i++) {
			if (vfc1->ids[i] == 0)
				continue;
			ids = vfc1->ids[i];
			while (ids) {
				vlan_id = 64 * i;
				/* count trailing zeroes */
				vbit = ~ids & (ids - 1);
				/* clear least significant bit set */
				ids ^= (ids ^ (ids - 1)) ^ vbit;
				for (; vbit; vlan_id++)
					vbit >>= 1;
				ret = rte_eth_dev_vlan_filter(
					PORT_ID(sdev), vlan_id, 1);
				if (ret) {
					ERROR("Failed to apply VLAN filter %hu",
						vlan_id);
					return ret;
				}
			}
		}
	} else {
		DEBUG("VLAN filter already set");
	}
	/* rte_flow */
	if (TAILQ_EMPTY(&PRIV(dev)->flow_list)) {
		DEBUG("rte_flow already set");
	} else {
		DEBUG("Resetting rte_flow configuration");
		ret = rte_flow_flush(PORT_ID(sdev), &ferror);
		if (ret) {
			fs_flow_complain(&ferror);
			return ret;
		}
		i = 0;
		rte_errno = 0;
		DEBUG("Configuring rte_flow");
		TAILQ_FOREACH(flow, &PRIV(dev)->flow_list, next) {
			DEBUG("Creating flow #%" PRIu32, i++);
			flow->flows[SUB_ID(sdev)] =
				rte_flow_create(PORT_ID(sdev),
						flow->rule.attr,
						flow->rule.pattern,
						flow->rule.actions,
						&ferror);
			ret = rte_errno;
			if (ret)
				break;
		}
		if (ret) {
			fs_flow_complain(&ferror);
			return ret;
		}
	}
	return 0;
}

static void
fs_dev_remove(struct sub_device *sdev)
{
	int ret;

	if (sdev == NULL)
		return;
	switch (sdev->state) {
	case DEV_STARTED:
		failsafe_rx_intr_uninstall_subdevice(sdev);
		rte_eth_dev_stop(PORT_ID(sdev));
		sdev->state = DEV_ACTIVE;
		/* fallthrough */
	case DEV_ACTIVE:
		failsafe_eth_dev_unregister_callbacks(sdev);
		rte_eth_dev_close(PORT_ID(sdev));
		sdev->state = DEV_PROBED;
		/* fallthrough */
	case DEV_PROBED:
		ret = rte_dev_remove(sdev->dev);
		if (ret < 0) {
			ERROR("Bus detach failed for sub_device %u",
			      SUB_ID(sdev));
		} else {
			rte_eth_dev_release_port(ETH(sdev));
		}
		sdev->state = DEV_PARSED;
		/* fallthrough */
	case DEV_PARSED:
	case DEV_UNDEFINED:
		sdev->state = DEV_UNDEFINED;
		/* the end */
		break;
	}
	sdev->remove = 0;
	failsafe_hotplug_alarm_install(sdev->fs_dev);
}

static void
fs_dev_stats_save(struct sub_device *sdev)
{
	struct rte_eth_stats stats;
	int err;

	/* Attempt to read current stats. */
	err = rte_eth_stats_get(PORT_ID(sdev), &stats);
	if (err) {
		uint64_t timestamp = sdev->stats_snapshot.timestamp;

		WARN("Could not access latest statistics from sub-device %d.\n",
			 SUB_ID(sdev));
		if (timestamp != 0)
			WARN("Using latest snapshot taken before %"PRIu64" seconds.\n",
				 (rte_rdtsc() - timestamp) / rte_get_tsc_hz());
	}
	failsafe_stats_increment(&PRIV(sdev->fs_dev)->stats_accumulator,
			err ? &sdev->stats_snapshot.stats : &stats);
	memset(&sdev->stats_snapshot, 0, sizeof(sdev->stats_snapshot));
}

static inline int
fs_rxtx_clean(struct sub_device *sdev)
{
	uint16_t i;

	for (i = 0; i < ETH(sdev)->data->nb_rx_queues; i++)
		if (FS_ATOMIC_RX(sdev, i))
			return 0;
	for (i = 0; i < ETH(sdev)->data->nb_tx_queues; i++)
		if (FS_ATOMIC_TX(sdev, i))
			return 0;
	return 1;
}

void
failsafe_eth_dev_unregister_callbacks(struct sub_device *sdev)
{
	int ret;

	if (sdev == NULL)
		return;
	if (sdev->rmv_callback) {
		ret = rte_eth_dev_callback_unregister(PORT_ID(sdev),
						RTE_ETH_EVENT_INTR_RMV,
						failsafe_eth_rmv_event_callback,
						sdev);
		if (ret)
			WARN("Failed to unregister RMV callback for sub_device"
			     " %d", SUB_ID(sdev));
		sdev->rmv_callback = 0;
	}
	if (sdev->lsc_callback) {
		ret = rte_eth_dev_callback_unregister(PORT_ID(sdev),
						RTE_ETH_EVENT_INTR_LSC,
						failsafe_eth_lsc_event_callback,
						sdev);
		if (ret)
			WARN("Failed to unregister LSC callback for sub_device"
			     " %d", SUB_ID(sdev));
		sdev->lsc_callback = 0;
	}
}

void
failsafe_dev_remove(struct rte_eth_dev *dev)
{
	struct sub_device *sdev;
	uint8_t i;

	FOREACH_SUBDEV_STATE(sdev, i, dev, DEV_ACTIVE)
		if (sdev->remove && fs_rxtx_clean(sdev)) {
			if (fs_lock(dev, 1) != 0)
				return;
			fs_dev_stats_save(sdev);
			fs_dev_remove(sdev);
			fs_unlock(dev, 1);
		}
}

static int
failsafe_eth_dev_rx_queues_sync(struct rte_eth_dev *dev)
{
	struct rxq *rxq;
	int ret;
	uint16_t i;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];

		if (rxq->info.conf.rx_deferred_start &&
		    dev->data->rx_queue_state[i] ==
						RTE_ETH_QUEUE_STATE_STARTED) {
			/*
			 * The subdevice Rx queue does not launch on device
			 * start if deferred start flag is set. It needs to be
			 * started manually in case an appropriate failsafe Rx
			 * queue has been started earlier.
			 */
			ret = dev->dev_ops->rx_queue_start(dev, i);
			if (ret) {
				ERROR("Could not synchronize Rx queue %d", i);
				return ret;
			}
		} else if (dev->data->rx_queue_state[i] ==
						RTE_ETH_QUEUE_STATE_STOPPED) {
			/*
			 * The subdevice Rx queue needs to be stopped manually
			 * in case an appropriate failsafe Rx queue has been
			 * stopped earlier.
			 */
			ret = dev->dev_ops->rx_queue_stop(dev, i);
			if (ret) {
				ERROR("Could not synchronize Rx queue %d", i);
				return ret;
			}
		}
	}
	return 0;
}

static int
failsafe_eth_dev_tx_queues_sync(struct rte_eth_dev *dev)
{
	struct txq *txq;
	int ret;
	uint16_t i;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];

		if (txq->info.conf.tx_deferred_start &&
		    dev->data->tx_queue_state[i] ==
						RTE_ETH_QUEUE_STATE_STARTED) {
			/*
			 * The subdevice Tx queue does not launch on device
			 * start if deferred start flag is set. It needs to be
			 * started manually in case an appropriate failsafe Tx
			 * queue has been started earlier.
			 */
			ret = dev->dev_ops->tx_queue_start(dev, i);
			if (ret) {
				ERROR("Could not synchronize Tx queue %d", i);
				return ret;
			}
		} else if (dev->data->tx_queue_state[i] ==
						RTE_ETH_QUEUE_STATE_STOPPED) {
			/*
			 * The subdevice Tx queue needs to be stopped manually
			 * in case an appropriate failsafe Tx queue has been
			 * stopped earlier.
			 */
			ret = dev->dev_ops->tx_queue_stop(dev, i);
			if (ret) {
				ERROR("Could not synchronize Tx queue %d", i);
				return ret;
			}
		}
	}
	return 0;
}

int
failsafe_eth_dev_state_sync(struct rte_eth_dev *dev)
{
	struct sub_device *sdev;
	uint32_t inactive;
	int ret;
	uint8_t i;

	if (PRIV(dev)->state < DEV_PARSED)
		return 0;

	ret = failsafe_args_parse_subs(dev);
	if (ret)
		goto err_remove;

	if (PRIV(dev)->state < DEV_PROBED)
		return 0;
	ret = failsafe_eal_init(dev);
	if (ret)
		goto err_remove;
	if (PRIV(dev)->state < DEV_ACTIVE)
		return 0;
	inactive = 0;
	FOREACH_SUBDEV(sdev, i, dev) {
		if (sdev->state == DEV_PROBED) {
			inactive |= UINT32_C(1) << i;
			ret = eth_dev_flow_isolate_set(dev, sdev);
			if (ret) {
				ERROR("Could not apply configuration to sub_device %d",
				      i);
				goto err_remove;
			}
		}
	}
	ret = dev->dev_ops->dev_configure(dev);
	if (ret)
		goto err_remove;
	FOREACH_SUBDEV(sdev, i, dev) {
		if (inactive & (UINT32_C(1) << i)) {
			ret = fs_eth_dev_conf_apply(dev, sdev);
			if (ret) {
				ERROR("Could not apply configuration to sub_device %d",
				      i);
				goto err_remove;
			}
		}
	}
	/*
	 * If new devices have been configured, check if
	 * the link state has changed.
	 */
	if (inactive)
		dev->dev_ops->link_update(dev, 1);
	if (PRIV(dev)->state < DEV_STARTED)
		return 0;
	ret = dev->dev_ops->dev_start(dev);
	if (ret)
		goto err_remove;
	ret = failsafe_eth_dev_rx_queues_sync(dev);
	if (ret)
		goto err_remove;
	ret = failsafe_eth_dev_tx_queues_sync(dev);
	if (ret)
		goto err_remove;
	return 0;
err_remove:
	FOREACH_SUBDEV(sdev, i, dev)
		if (sdev->state != PRIV(dev)->state)
			sdev->remove = 1;
	return ret;
}

void
failsafe_stats_increment(struct rte_eth_stats *to, struct rte_eth_stats *from)
{
	uint32_t i;

	RTE_ASSERT(to != NULL && from != NULL);
	to->ipackets += from->ipackets;
	to->opackets += from->opackets;
	to->ibytes += from->ibytes;
	to->obytes += from->obytes;
	to->imissed += from->imissed;
	to->ierrors += from->ierrors;
	to->oerrors += from->oerrors;
	to->rx_nombuf += from->rx_nombuf;
	for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
		to->q_ipackets[i] += from->q_ipackets[i];
		to->q_opackets[i] += from->q_opackets[i];
		to->q_ibytes[i] += from->q_ibytes[i];
		to->q_obytes[i] += from->q_obytes[i];
		to->q_errors[i] += from->q_errors[i];
	}
}

int
failsafe_eth_rmv_event_callback(uint16_t port_id __rte_unused,
				enum rte_eth_event_type event __rte_unused,
				void *cb_arg, void *out __rte_unused)
{
	struct sub_device *sdev = cb_arg;

	fs_lock(sdev->fs_dev, 0);
	/* Switch as soon as possible tx_dev. */
	fs_switch_dev(sdev->fs_dev, sdev);
	/* Use safe bursts in any case. */
	failsafe_set_burst_fn(sdev->fs_dev, 1);
	/*
	 * Async removal, the sub-PMD will try to unregister
	 * the callback at the source of the current thread context.
	 */
	sdev->remove = 1;
	fs_unlock(sdev->fs_dev, 0);
	return 0;
}

int
failsafe_eth_lsc_event_callback(uint16_t port_id __rte_unused,
				enum rte_eth_event_type event __rte_unused,
				void *cb_arg, void *out __rte_unused)
{
	struct rte_eth_dev *dev = cb_arg;
	int ret;

	ret = dev->dev_ops->link_update(dev, 0);
	/* We must pass on the LSC event */
	if (ret)
		return _rte_eth_dev_callback_process(dev,
						     RTE_ETH_EVENT_INTR_LSC,
						     NULL);
	else
		return 0;
}

/* Take sub-device ownership before it becomes exposed to the application. */
int
failsafe_eth_new_event_callback(uint16_t port_id,
				enum rte_eth_event_type event __rte_unused,
				void *cb_arg, void *out __rte_unused)
{
	struct rte_eth_dev *fs_dev = cb_arg;
	struct sub_device *sdev;
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	uint8_t i;

	FOREACH_SUBDEV_STATE(sdev, i, fs_dev, DEV_PARSED) {
		if (sdev->state >= DEV_PROBED)
			continue;
		if (strcmp(sdev->devargs.name, dev->device->name) != 0)
			continue;
		rte_eth_dev_owner_set(port_id, &PRIV(fs_dev)->my_owner);
		/* The actual owner will be checked after the port probing. */
		break;
	}
	return 0;
}
