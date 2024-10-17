/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ethdev_driver.h>
#include <ethdev_vdev.h>
#include <rte_malloc.h>
#include <bus_vdev_driver.h>
#include <rte_kvargs.h>
#include <rte_errno.h>
#include <rte_ring.h>

#include "rte_eth_softnic.h"
#include "rte_eth_softnic_internals.h"

#define PMD_PARAM_FIRMWARE                                 "firmware"
#define PMD_PARAM_CONN_PORT                                "conn_port"
#define PMD_PARAM_CPU_ID                                   "cpu_id"
#define PMD_PARAM_SC                                       "sc"


static const char * const pmd_valid_args[] = {
	PMD_PARAM_FIRMWARE,
	PMD_PARAM_CONN_PORT,
	PMD_PARAM_CPU_ID,
	PMD_PARAM_SC,
	NULL
};

static const char welcome[] =
	"\n"
	"Welcome to Soft NIC!\n"
	"\n";

static const char prompt[] = "softnic> ";

static const struct softnic_conn_params conn_params_default = {
	.welcome = welcome,
	.prompt = prompt,
	.addr = "0.0.0.0",
	.port = 0,
	.buf_size = 1024 * 1024,
	.msg_in_len_max = 1024,
	.msg_out_len_max = 1024 * 1024,
	.msg_handle = softnic_cli_process,
	.msg_handle_arg = NULL,
};

RTE_LOG_REGISTER_DEFAULT(pmd_softnic_logtype, NOTICE);

#define PMD_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, pmd_softnic_logtype, \
		"%s(): " fmt "\n", __func__, ##args)

static int
pmd_dev_infos_get(struct rte_eth_dev *dev __rte_unused,
	struct rte_eth_dev_info *dev_info)
{
	dev_info->max_rx_pktlen = UINT32_MAX;
	dev_info->max_rx_queues = UINT16_MAX;
	dev_info->max_tx_queues = UINT16_MAX;
	dev_info->dev_capa &= ~RTE_ETH_DEV_CAPA_FLOW_RULE_KEEP;

	return 0;
}

static int
pmd_dev_configure(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static int
pmd_rx_queue_setup(struct rte_eth_dev *dev,
	uint16_t rx_queue_id,
	uint16_t nb_rx_desc,
	unsigned int socket_id __rte_unused,
	const struct rte_eth_rxconf *rx_conf __rte_unused,
	struct rte_mempool *mb_pool __rte_unused)
{
	char name[NAME_SIZE];
	struct pmd_internals *p = dev->data->dev_private;
	struct softnic_swq *swq;

	struct softnic_swq_params params = {
		.size = nb_rx_desc,
	};

	snprintf(name, sizeof(name), "RXQ%u", rx_queue_id);

	swq = softnic_swq_create(p,
		name,
		&params);
	if (swq == NULL)
		return -1;

	dev->data->rx_queues[rx_queue_id] = swq->r;
	return 0;
}

static int
pmd_tx_queue_setup(struct rte_eth_dev *dev,
	uint16_t tx_queue_id,
	uint16_t nb_tx_desc,
	unsigned int socket_id __rte_unused,
	const struct rte_eth_txconf *tx_conf __rte_unused)
{
	char name[NAME_SIZE];
	struct pmd_internals *p = dev->data->dev_private;
	struct softnic_swq *swq;

	struct softnic_swq_params params = {
		.size = nb_tx_desc,
	};

	snprintf(name, sizeof(name), "TXQ%u", tx_queue_id);

	swq = softnic_swq_create(p,
		name,
		&params);
	if (swq == NULL)
		return -1;

	dev->data->tx_queues[tx_queue_id] = swq->r;
	return 0;
}

static int
pmd_dev_start(struct rte_eth_dev *dev)
{
	struct pmd_internals *p = dev->data->dev_private;
	int status;
	uint16_t i;

	/* Firmware */
	status = softnic_cli_script_process(p,
		p->params.firmware,
		conn_params_default.msg_in_len_max,
		conn_params_default.msg_out_len_max);
	if (status)
		return status;

	/* Link UP */
	dev->data->dev_link.link_status = RTE_ETH_LINK_UP;

	for (i = 0; i < dev->data->nb_rx_queues; i++)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
	for (i = 0; i < dev->data->nb_tx_queues; i++)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;

	return 0;
}

static int
pmd_dev_stop(struct rte_eth_dev *dev)
{
	struct pmd_internals *p = dev->data->dev_private;
	uint16_t i;

	/* Link DOWN */
	dev->data->dev_link.link_status = RTE_ETH_LINK_DOWN;

	/* Firmware */
	softnic_pipeline_disable_all(p);
	softnic_pipeline_free(p);
	softnic_softnic_swq_free_keep_rxq_txq(p);
	softnic_mempool_free(p);

	for (i = 0; i < dev->data->nb_rx_queues; i++)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
	for (i = 0; i < dev->data->nb_tx_queues; i++)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;

	return 0;
}

static void
pmd_free(struct pmd_internals *p)
{
	if (p == NULL)
		return;

	if (p->params.conn_port)
		softnic_conn_free(p->conn);

	softnic_thread_free(p);
	softnic_pipeline_free(p);
	softnic_swq_free(p);
	softnic_mempool_free(p);

	rte_free(p);
}

static int
pmd_dev_close(struct rte_eth_dev *dev)
{
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	pmd_free(dev->data->dev_private);
	dev->data->dev_private = NULL; /* already freed */
	dev->data->mac_addrs = NULL; /* statically allocated */
	return 0;
}

static int
pmd_link_update(struct rte_eth_dev *dev __rte_unused,
	int wait_to_complete __rte_unused)
{
	return 0;
}

static const struct eth_dev_ops pmd_ops = {
	.dev_configure = pmd_dev_configure,
	.dev_start = pmd_dev_start,
	.dev_stop = pmd_dev_stop,
	.dev_close = pmd_dev_close,
	.link_update = pmd_link_update,
	.dev_infos_get = pmd_dev_infos_get,
	.rx_queue_setup = pmd_rx_queue_setup,
	.tx_queue_setup = pmd_tx_queue_setup,
};

static uint16_t
pmd_rx_pkt_burst(void *rxq,
	struct rte_mbuf **rx_pkts,
	uint16_t nb_pkts)
{
	return (uint16_t)rte_ring_sc_dequeue_burst(rxq,
		(void **)rx_pkts,
		nb_pkts,
		NULL);
}

static uint16_t
pmd_tx_pkt_burst(void *txq,
	struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts)
{
	return (uint16_t)rte_ring_sp_enqueue_burst(txq,
		(void **)tx_pkts,
		nb_pkts,
		NULL);
}

static void *
pmd_init(struct pmd_params *params)
{
	struct pmd_internals *p;
	int status;

	p = rte_zmalloc_socket(params->name,
		sizeof(struct pmd_internals),
		0,
		params->cpu_id);
	if (p == NULL)
		return NULL;

	/* Params */
	memcpy(&p->params, params, sizeof(p->params));

	/* Resources */
	softnic_mempool_init(p);
	softnic_swq_init(p);
	softnic_pipeline_init(p);

	status = softnic_thread_init(p);
	if (status) {
		rte_free(p);
		return NULL;
	}

	if (params->conn_port) {
		struct softnic_conn_params conn_params;

		memcpy(&conn_params, &conn_params_default, sizeof(conn_params));
		conn_params.port = p->params.conn_port;
		conn_params.msg_handle_arg = p;

		p->conn = softnic_conn_init(&conn_params);
		if (p->conn == NULL) {
			softnic_thread_free(p);
			rte_free(p);
			return NULL;
		}
	}

	return p;
}

static struct rte_ether_addr eth_addr = {
	.addr_bytes = {0},
};

static int
pmd_ethdev_register(struct rte_vdev_device *vdev,
	struct pmd_params *params,
	void *dev_private)
{
	struct rte_eth_dev *dev;

	/* Ethdev entry allocation */
	dev = rte_eth_dev_allocate(params->name);
	if (!dev)
		return -ENOMEM;

	/* dev */
	dev->rx_pkt_burst = pmd_rx_pkt_burst;
	dev->tx_pkt_burst = pmd_tx_pkt_burst;
	dev->tx_pkt_prepare = NULL;
	dev->dev_ops = &pmd_ops;
	dev->device = &vdev->device;

	/* dev->data */
	dev->data->dev_private = dev_private;
	dev->data->dev_link.link_speed = RTE_ETH_SPEED_NUM_100G;
	dev->data->dev_link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
	dev->data->dev_link.link_autoneg = RTE_ETH_LINK_FIXED;
	dev->data->dev_link.link_status = RTE_ETH_LINK_DOWN;
	dev->data->mac_addrs = &eth_addr;
	dev->data->promiscuous = 1;
	dev->data->numa_node = params->cpu_id;

	rte_eth_dev_probing_finish(dev);

	return 0;
}

static int
get_string(const char *key __rte_unused, const char *value, void *extra_args)
{
	if (!value || !extra_args)
		return -EINVAL;

	*(char **)extra_args = strdup(value);

	if (!*(char **)extra_args)
		return -ENOMEM;

	return 0;
}

static int
get_uint32(const char *key __rte_unused, const char *value, void *extra_args)
{
	if (!value || !extra_args)
		return -EINVAL;

	*(uint32_t *)extra_args = strtoull(value, NULL, 0);

	return 0;
}

static int
get_uint16(const char *key __rte_unused, const char *value, void *extra_args)
{
	if (!value || !extra_args)
		return -EINVAL;

	*(uint16_t *)extra_args = strtoull(value, NULL, 0);

	return 0;
}

static int
pmd_parse_args(struct pmd_params *p, const char *params)
{
	struct rte_kvargs *kvlist;
	int ret = 0;
	char *firmware = NULL;

	kvlist = rte_kvargs_parse(params, pmd_valid_args);
	if (kvlist == NULL)
		return -EINVAL;

	/* Set default values */
	memset(p, 0, sizeof(*p));
	if (rte_strscpy(p->firmware, SOFTNIC_FIRMWARE,
			sizeof(p->firmware)) < 0) {
		PMD_LOG(WARNING,
			"\"%s\": firmware path should be shorter than %zu",
			SOFTNIC_FIRMWARE, sizeof(p->firmware));
		ret = -EINVAL;
		goto out_free;
	}
	p->cpu_id = SOFTNIC_CPU_ID;
	p->sc = SOFTNIC_SC;

	/* Firmware script (optional) */
	if (rte_kvargs_count(kvlist, PMD_PARAM_FIRMWARE) == 1) {
		ret = rte_kvargs_process(kvlist, PMD_PARAM_FIRMWARE,
			&get_string, &firmware);
		if (ret < 0)
			goto out_free;

		if (rte_strscpy(p->firmware, firmware,
				sizeof(p->firmware)) < 0) {
			PMD_LOG(WARNING,
				"\"%s\": "
				"firmware path should be shorter than %zu",
				firmware, sizeof(p->firmware));
			free(firmware);
			ret = -EINVAL;
			goto out_free;
		}
		free(firmware);
	}
	/* Connection listening port (optional) */
	if (rte_kvargs_count(kvlist, PMD_PARAM_CONN_PORT) == 1) {
		ret = rte_kvargs_process(kvlist, PMD_PARAM_CONN_PORT,
			&get_uint16, &p->conn_port);
		if (ret < 0)
			goto out_free;
	}

	/* CPU ID (optional) */
	if (rte_kvargs_count(kvlist, PMD_PARAM_CPU_ID) == 1) {
		ret = rte_kvargs_process(kvlist, PMD_PARAM_CPU_ID,
			&get_uint32, &p->cpu_id);
		if (ret < 0)
			goto out_free;
	}

	/* Service cores (optional) */
	if (rte_kvargs_count(kvlist, PMD_PARAM_SC) == 1) {
		ret = rte_kvargs_process(kvlist, PMD_PARAM_SC,
			&get_uint32, &p->sc);
		if (ret < 0)
			goto out_free;
	}

out_free:
	rte_kvargs_free(kvlist);
	return ret;
}

static int
pmd_probe(struct rte_vdev_device *vdev)
{
	struct pmd_params p;
	const char *params;
	int status = 0;

	void *dev_private;
	const char *name = rte_vdev_device_name(vdev);

	PMD_LOG(INFO, "Probing device \"%s\"", name);

	/* Parse input arguments */
	params = rte_vdev_device_args(vdev);
	if (!params)
		return -EINVAL;

	status = pmd_parse_args(&p, params);
	if (status)
		return status;

	if (rte_strscpy(p.name, name, sizeof(p.name)) < 0) {
		PMD_LOG(WARNING,
			"\"%s\": device name should be shorter than %zu",
			name, sizeof(p.name));
		return -EINVAL;
	}

	/* Allocate and initialize soft ethdev private data */
	dev_private = pmd_init(&p);
	if (dev_private == NULL)
		return -ENOMEM;

	/* Register soft ethdev */
	PMD_LOG(INFO, "Creating soft ethdev \"%s\"", p.name);

	status = pmd_ethdev_register(vdev, &p, dev_private);
	if (status) {
		pmd_free(dev_private);
		return status;
	}

	return 0;
}

static int
pmd_remove(struct rte_vdev_device *vdev)
{
	struct rte_eth_dev *dev = NULL;

	if (!vdev)
		return -EINVAL;

	PMD_LOG(INFO, "Removing device \"%s\"", rte_vdev_device_name(vdev));

	/* Find the ethdev entry */
	dev = rte_eth_dev_allocated(rte_vdev_device_name(vdev));
	if (dev == NULL)
		return 0; /* port already released */

	pmd_dev_close(dev);
	rte_eth_dev_release_port(dev);

	return 0;
}

static struct rte_vdev_driver pmd_softnic_drv = {
	.probe = pmd_probe,
	.remove = pmd_remove,
};

RTE_PMD_REGISTER_VDEV(net_softnic, pmd_softnic_drv);
RTE_PMD_REGISTER_PARAM_STRING(net_softnic,
	PMD_PARAM_FIRMWARE "=<string> "
	PMD_PARAM_CONN_PORT "=<uint16> "
	PMD_PARAM_CPU_ID "=<uint32> "
);

int
rte_pmd_softnic_manage(uint16_t port_id)
{
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct pmd_internals *softnic;

#ifdef RTE_LIBRTE_ETHDEV_DEBUG
	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, 0);
#endif

	softnic = dev->data->dev_private;

	softnic_conn_poll_for_conn(softnic->conn);

	softnic_conn_poll_for_msg(softnic->conn);

	return 0;
}
