/*-
 *   BSD LICENSE
 *
 *   Copyright 2015 6WIND S.A.
 *   Copyright 2015 Mellanox.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of 6WIND S.A. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <net/if.h>
#include <sys/mman.h>

/* Verbs header. */
/* ISO C doesn't support unnamed structs/unions, disabling -pedantic. */
#ifdef PEDANTIC
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include <infiniband/verbs.h>
#ifdef PEDANTIC
#pragma GCC diagnostic error "-Wpedantic"
#endif

#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_ethdev_pci.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_common.h>
#include <rte_eal_memconfig.h>
#include <rte_kvargs.h>

#include "mlx5.h"
#include "mlx5_utils.h"
#include "mlx5_rxtx.h"
#include "mlx5_autoconf.h"
#include "mlx5_defs.h"

/* Device parameter to enable RX completion queue compression. */
#define MLX5_RXQ_CQE_COMP_EN "rxq_cqe_comp_en"

/* Device parameter to configure inline send. */
#define MLX5_TXQ_INLINE "txq_inline"

/*
 * Device parameter to configure the number of TX queues threshold for
 * enabling inline send.
 */
#define MLX5_TXQS_MIN_INLINE "txqs_min_inline"

/* Device parameter to enable multi-packet send WQEs. */
#define MLX5_TXQ_MPW_EN "txq_mpw_en"

/* Device parameter to include 2 dsegs in the title WQEBB. */
#define MLX5_TXQ_MPW_HDR_DSEG_EN "txq_mpw_hdr_dseg_en"

/* Device parameter to limit the size of inlining packet. */
#define MLX5_TXQ_MAX_INLINE_LEN "txq_max_inline_len"

/* Device parameter to enable hardware TSO offload. */
#define MLX5_TSO "tso"

/* Device parameter to enable hardware Tx vector. */
#define MLX5_TX_VEC_EN "tx_vec_en"

/* Device parameter to enable hardware Rx vector. */
#define MLX5_RX_VEC_EN "rx_vec_en"

/* Default PMD specific parameter value. */
#define MLX5_ARG_UNSET (-1)

#ifndef HAVE_IBV_MLX5_MOD_MPW
#define MLX5DV_CONTEXT_FLAGS_MPW_ALLOWED (1 << 2)
#define MLX5DV_CONTEXT_FLAGS_ENHANCED_MPW (1 << 3)
#endif

#ifndef HAVE_IBV_MLX5_MOD_CQE_128B_COMP
#define MLX5DV_CONTEXT_FLAGS_CQE_128B_COMP (1 << 4)
#endif

struct mlx5_args {
	int cqe_comp;
	int txq_inline;
	int txqs_inline;
	int mps;
	int mpw_hdr_dseg;
	int inline_max_packet_sz;
	int tso;
	int tx_vec_en;
	int rx_vec_en;
};

/** Driver-specific log messages type. */
int mlx5_logtype;

/**
 * Retrieve integer value from environment variable.
 *
 * @param[in] name
 *   Environment variable name.
 *
 * @return
 *   Integer value, 0 if the variable is not set.
 */
int
mlx5_getenv_int(const char *name)
{
	const char *val = getenv(name);

	if (val == NULL)
		return 0;
	return atoi(val);
}

/**
 * Verbs callback to allocate a memory. This function should allocate the space
 * according to the size provided residing inside a huge page.
 * Please note that all allocation must respect the alignment from libmlx5
 * (i.e. currently sysconf(_SC_PAGESIZE)).
 *
 * @param[in] size
 *   The size in bytes of the memory to allocate.
 * @param[in] data
 *   A pointer to the callback data.
 *
 * @return
 *   Allocated buffer, NULL otherwise and rte_errno is set.
 */
static void *
mlx5_alloc_verbs_buf(size_t size, void *data)
{
	struct priv *priv = data;
	void *ret;
	size_t alignment = sysconf(_SC_PAGESIZE);
	unsigned int socket = SOCKET_ID_ANY;

	if (priv->verbs_alloc_ctx.type == MLX5_VERBS_ALLOC_TYPE_TX_QUEUE) {
		const struct mlx5_txq_ctrl *ctrl = priv->verbs_alloc_ctx.obj;

		socket = ctrl->socket;
	} else if (priv->verbs_alloc_ctx.type ==
		   MLX5_VERBS_ALLOC_TYPE_RX_QUEUE) {
		const struct mlx5_rxq_ctrl *ctrl = priv->verbs_alloc_ctx.obj;

		socket = ctrl->socket;
	}
	assert(data != NULL);
	ret = rte_malloc_socket(__func__, size, alignment, socket);
	if (!ret && size)
		rte_errno = ENOMEM;
	return ret;
}

/**
 * Verbs callback to free a memory.
 *
 * @param[in] ptr
 *   A pointer to the memory to free.
 * @param[in] data
 *   A pointer to the callback data.
 */
static void
mlx5_free_verbs_buf(void *ptr, void *data __rte_unused)
{
	assert(data != NULL);
	rte_free(ptr);
}

/**
 * DPDK callback to close the device.
 *
 * Destroy all queues and objects, free memory.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 */
static void
mlx5_dev_close(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	unsigned int i;
	int ret;

	DRV_LOG(DEBUG, "port %u closing device \"%s\"",
		dev->data->port_id,
		((priv->ctx != NULL) ? priv->ctx->device->name : ""));
	/* In case mlx5_dev_stop() has not been called. */
	mlx5_dev_interrupt_handler_uninstall(dev);
	mlx5_traffic_disable(dev);
	/* Prevent crashes when queues are still in use. */
	dev->rx_pkt_burst = removed_rx_burst;
	dev->tx_pkt_burst = removed_tx_burst;
	if (priv->rxqs != NULL) {
		/* XXX race condition if mlx5_rx_burst() is still running. */
		usleep(1000);
		for (i = 0; (i != priv->rxqs_n); ++i)
			mlx5_rxq_release(dev, i);
		priv->rxqs_n = 0;
		priv->rxqs = NULL;
	}
	if (priv->txqs != NULL) {
		/* XXX race condition if mlx5_tx_burst() is still running. */
		usleep(1000);
		for (i = 0; (i != priv->txqs_n); ++i)
			mlx5_txq_release(dev, i);
		priv->txqs_n = 0;
		priv->txqs = NULL;
	}
	if (priv->pd != NULL) {
		assert(priv->ctx != NULL);
		claim_zero(ibv_dealloc_pd(priv->pd));
		claim_zero(ibv_close_device(priv->ctx));
	} else
		assert(priv->ctx == NULL);
	if (priv->rss_conf.rss_key != NULL)
		rte_free(priv->rss_conf.rss_key);
	if (priv->reta_idx != NULL)
		rte_free(priv->reta_idx);
	if (priv->primary_socket)
		mlx5_socket_uninit(dev);
	ret = mlx5_hrxq_ibv_verify(dev);
	if (ret)
		DRV_LOG(WARNING, "port %u some hash Rx queue still remain",
			dev->data->port_id);
	ret = mlx5_ind_table_ibv_verify(dev);
	if (ret)
		DRV_LOG(WARNING, "port %u some indirection table still remain",
			dev->data->port_id);
	ret = mlx5_rxq_ibv_verify(dev);
	if (ret)
		DRV_LOG(WARNING, "port %u some Verbs Rx queue still remain",
			dev->data->port_id);
	ret = mlx5_rxq_verify(dev);
	if (ret)
		DRV_LOG(WARNING, "port %u some Rx queues still remain",
			dev->data->port_id);
	ret = mlx5_txq_ibv_verify(dev);
	if (ret)
		DRV_LOG(WARNING, "port %u some Verbs Tx queue still remain",
			dev->data->port_id);
	ret = mlx5_txq_verify(dev);
	if (ret)
		DRV_LOG(WARNING, "port %u some Tx queues still remain",
			dev->data->port_id);
	ret = mlx5_flow_verify(dev);
	if (ret)
		DRV_LOG(WARNING, "port %u some flows still remain",
			dev->data->port_id);
	ret = mlx5_mr_verify(dev);
	if (ret)
		DRV_LOG(WARNING, "port %u some memory region still remain",
			dev->data->port_id);
	memset(priv, 0, sizeof(*priv));
}

const struct eth_dev_ops mlx5_dev_ops = {
	.dev_configure = mlx5_dev_configure,
	.dev_start = mlx5_dev_start,
	.dev_stop = mlx5_dev_stop,
	.dev_set_link_down = mlx5_set_link_down,
	.dev_set_link_up = mlx5_set_link_up,
	.dev_close = mlx5_dev_close,
	.promiscuous_enable = mlx5_promiscuous_enable,
	.promiscuous_disable = mlx5_promiscuous_disable,
	.allmulticast_enable = mlx5_allmulticast_enable,
	.allmulticast_disable = mlx5_allmulticast_disable,
	.link_update = mlx5_link_update,
	.stats_get = mlx5_stats_get,
	.stats_reset = mlx5_stats_reset,
	.xstats_get = mlx5_xstats_get,
	.xstats_reset = mlx5_xstats_reset,
	.xstats_get_names = mlx5_xstats_get_names,
	.dev_infos_get = mlx5_dev_infos_get,
	.dev_supported_ptypes_get = mlx5_dev_supported_ptypes_get,
	.vlan_filter_set = mlx5_vlan_filter_set,
	.rx_queue_setup = mlx5_rx_queue_setup,
	.tx_queue_setup = mlx5_tx_queue_setup,
	.rx_queue_release = mlx5_rx_queue_release,
	.tx_queue_release = mlx5_tx_queue_release,
	.flow_ctrl_get = mlx5_dev_get_flow_ctrl,
	.flow_ctrl_set = mlx5_dev_set_flow_ctrl,
	.mac_addr_remove = mlx5_mac_addr_remove,
	.mac_addr_add = mlx5_mac_addr_add,
	.mac_addr_set = mlx5_mac_addr_set,
	.mtu_set = mlx5_dev_set_mtu,
	.vlan_strip_queue_set = mlx5_vlan_strip_queue_set,
	.vlan_offload_set = mlx5_vlan_offload_set,
	.reta_update = mlx5_dev_rss_reta_update,
	.reta_query = mlx5_dev_rss_reta_query,
	.rss_hash_update = mlx5_rss_hash_update,
	.rss_hash_conf_get = mlx5_rss_hash_conf_get,
	.filter_ctrl = mlx5_dev_filter_ctrl,
	.rx_descriptor_status = mlx5_rx_descriptor_status,
	.tx_descriptor_status = mlx5_tx_descriptor_status,
	.rx_queue_intr_enable = mlx5_rx_intr_enable,
	.rx_queue_intr_disable = mlx5_rx_intr_disable,
};

static const struct eth_dev_ops mlx5_dev_sec_ops = {
	.stats_get = mlx5_stats_get,
	.stats_reset = mlx5_stats_reset,
	.xstats_get = mlx5_xstats_get,
	.xstats_reset = mlx5_xstats_reset,
	.xstats_get_names = mlx5_xstats_get_names,
	.dev_infos_get = mlx5_dev_infos_get,
	.rx_descriptor_status = mlx5_rx_descriptor_status,
	.tx_descriptor_status = mlx5_tx_descriptor_status,
};

/* Available operators in flow isolated mode. */
const struct eth_dev_ops mlx5_dev_ops_isolate = {
	.dev_configure = mlx5_dev_configure,
	.dev_start = mlx5_dev_start,
	.dev_stop = mlx5_dev_stop,
	.dev_set_link_down = mlx5_set_link_down,
	.dev_set_link_up = mlx5_set_link_up,
	.dev_close = mlx5_dev_close,
	.promiscuous_enable = mlx5_promiscuous_enable,
	.promiscuous_disable = mlx5_promiscuous_disable,
	.allmulticast_enable = mlx5_allmulticast_enable,
	.allmulticast_disable = mlx5_allmulticast_disable,
	.link_update = mlx5_link_update,
	.stats_get = mlx5_stats_get,
	.stats_reset = mlx5_stats_reset,
	.xstats_get = mlx5_xstats_get,
	.xstats_reset = mlx5_xstats_reset,
	.xstats_get_names = mlx5_xstats_get_names,
	.dev_infos_get = mlx5_dev_infos_get,
	.dev_supported_ptypes_get = mlx5_dev_supported_ptypes_get,
	.vlan_filter_set = mlx5_vlan_filter_set,
	.rx_queue_setup = mlx5_rx_queue_setup,
	.tx_queue_setup = mlx5_tx_queue_setup,
	.rx_queue_release = mlx5_rx_queue_release,
	.tx_queue_release = mlx5_tx_queue_release,
	.flow_ctrl_get = mlx5_dev_get_flow_ctrl,
	.flow_ctrl_set = mlx5_dev_set_flow_ctrl,
	.mac_addr_remove = mlx5_mac_addr_remove,
	.mac_addr_add = mlx5_mac_addr_add,
	.mac_addr_set = mlx5_mac_addr_set,
	.mtu_set = mlx5_dev_set_mtu,
	.vlan_strip_queue_set = mlx5_vlan_strip_queue_set,
	.vlan_offload_set = mlx5_vlan_offload_set,
	.filter_ctrl = mlx5_dev_filter_ctrl,
	.rx_descriptor_status = mlx5_rx_descriptor_status,
	.tx_descriptor_status = mlx5_tx_descriptor_status,
	.rx_queue_intr_enable = mlx5_rx_intr_enable,
	.rx_queue_intr_disable = mlx5_rx_intr_disable,
};

static struct {
	struct rte_pci_addr pci_addr; /* associated PCI address */
	uint32_t ports; /* physical ports bitfield. */
} mlx5_dev[32];

/**
 * Get device index in mlx5_dev[] from PCI bus address.
 *
 * @param[in] pci_addr
 *   PCI bus address to look for.
 *
 * @return
 *   mlx5_dev[] index on success, -1 on failure.
 */
static int
mlx5_dev_idx(struct rte_pci_addr *pci_addr)
{
	unsigned int i;
	int ret = -1;

	assert(pci_addr != NULL);
	for (i = 0; (i != RTE_DIM(mlx5_dev)); ++i) {
		if ((mlx5_dev[i].pci_addr.domain == pci_addr->domain) &&
		    (mlx5_dev[i].pci_addr.bus == pci_addr->bus) &&
		    (mlx5_dev[i].pci_addr.devid == pci_addr->devid) &&
		    (mlx5_dev[i].pci_addr.function == pci_addr->function))
			return i;
		if ((mlx5_dev[i].ports == 0) && (ret == -1))
			ret = i;
	}
	return ret;
}

/**
 * Verify and store value for device argument.
 *
 * @param[in] key
 *   Key argument to verify.
 * @param[in] val
 *   Value associated with key.
 * @param opaque
 *   User data.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_args_check(const char *key, const char *val, void *opaque)
{
	struct mlx5_args *args = opaque;
	unsigned long tmp;

	errno = 0;
	tmp = strtoul(val, NULL, 0);
	if (errno) {
		rte_errno = errno;
		DRV_LOG(WARNING, "%s: \"%s\" is not a valid integer", key, val);
		return -rte_errno;
	}
	if (strcmp(MLX5_RXQ_CQE_COMP_EN, key) == 0) {
		args->cqe_comp = !!tmp;
	} else if (strcmp(MLX5_TXQ_INLINE, key) == 0) {
		args->txq_inline = tmp;
	} else if (strcmp(MLX5_TXQS_MIN_INLINE, key) == 0) {
		args->txqs_inline = tmp;
	} else if (strcmp(MLX5_TXQ_MPW_EN, key) == 0) {
		args->mps = !!tmp;
	} else if (strcmp(MLX5_TXQ_MPW_HDR_DSEG_EN, key) == 0) {
		args->mpw_hdr_dseg = !!tmp;
	} else if (strcmp(MLX5_TXQ_MAX_INLINE_LEN, key) == 0) {
		args->inline_max_packet_sz = tmp;
	} else if (strcmp(MLX5_TSO, key) == 0) {
		args->tso = !!tmp;
	} else if (strcmp(MLX5_TX_VEC_EN, key) == 0) {
		args->tx_vec_en = !!tmp;
	} else if (strcmp(MLX5_RX_VEC_EN, key) == 0) {
		args->rx_vec_en = !!tmp;
	} else {
		DRV_LOG(WARNING, "%s: unknown parameter", key);
		rte_errno = EINVAL;
		return -rte_errno;
	}
	return 0;
}

/**
 * Parse device parameters.
 *
 * @param priv
 *   Pointer to private structure.
 * @param devargs
 *   Device arguments structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_args(struct mlx5_args *args, struct rte_devargs *devargs)
{
	const char **params = (const char *[]){
		MLX5_RXQ_CQE_COMP_EN,
		MLX5_TXQ_INLINE,
		MLX5_TXQS_MIN_INLINE,
		MLX5_TXQ_MPW_EN,
		MLX5_TXQ_MPW_HDR_DSEG_EN,
		MLX5_TXQ_MAX_INLINE_LEN,
		MLX5_TSO,
		MLX5_TX_VEC_EN,
		MLX5_RX_VEC_EN,
		NULL,
	};
	struct rte_kvargs *kvlist;
	int ret = 0;
	int i;

	if (devargs == NULL)
		return 0;
	/* Following UGLY cast is done to pass checkpatch. */
	kvlist = rte_kvargs_parse(devargs->args, params);
	if (kvlist == NULL)
		return 0;
	/* Process parameters. */
	for (i = 0; (params[i] != NULL); ++i) {
		if (rte_kvargs_count(kvlist, params[i])) {
			ret = rte_kvargs_process(kvlist, params[i],
						 mlx5_args_check, args);
			if (ret) {
				rte_errno = EINVAL;
				rte_kvargs_free(kvlist);
				return -rte_errno;
			}
		}
	}
	rte_kvargs_free(kvlist);
	return 0;
}

static struct rte_pci_driver mlx5_driver;

/*
 * Reserved UAR address space for TXQ UAR(hw doorbell) mapping, process
 * local resource used by both primary and secondary to avoid duplicate
 * reservation.
 * The space has to be available on both primary and secondary process,
 * TXQ UAR maps to this area using fixed mmap w/o double check.
 */
static void *uar_base;

/**
 * Reserve UAR address space for primary process.
 *
 * @param[in] dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_uar_init_primary(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	void *addr = (void *)0;
	int i;
	const struct rte_mem_config *mcfg;

	if (uar_base) { /* UAR address space mapped. */
		priv->uar_base = uar_base;
		return 0;
	}
	/* find out lower bound of hugepage segments */
	mcfg = rte_eal_get_configuration()->mem_config;
	for (i = 0; i < RTE_MAX_MEMSEG && mcfg->memseg[i].addr; i++) {
		if (addr)
			addr = RTE_MIN(addr, mcfg->memseg[i].addr);
		else
			addr = mcfg->memseg[i].addr;
	}
	/* keep distance to hugepages to minimize potential conflicts. */
	addr = RTE_PTR_SUB(addr, MLX5_UAR_OFFSET + MLX5_UAR_SIZE);
	/* anonymous mmap, no real memory consumption. */
	addr = mmap(addr, MLX5_UAR_SIZE,
		    PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		DRV_LOG(ERR,
			"port %u failed to reserve UAR address space, please"
			" adjust MLX5_UAR_SIZE or try --base-virtaddr",
			dev->data->port_id);
		rte_errno = ENOMEM;
		return -rte_errno;
	}
	/* Accept either same addr or a new addr returned from mmap if target
	 * range occupied.
	 */
	DRV_LOG(INFO, "port %u reserved UAR address space: %p",
		dev->data->port_id, addr);
	priv->uar_base = addr; /* for primary and secondary UAR re-mmap. */
	uar_base = addr; /* process local, don't reserve again. */
	return 0;
}

/**
 * Reserve UAR address space for secondary process, align with
 * primary process.
 *
 * @param[in] dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_uar_init_secondary(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	void *addr;

	assert(priv->uar_base);
	if (uar_base) { /* already reserved. */
		assert(uar_base == priv->uar_base);
		return 0;
	}
	/* anonymous mmap, no real memory consumption. */
	addr = mmap(priv->uar_base, MLX5_UAR_SIZE,
		    PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		DRV_LOG(ERR, "port %u UAR mmap failed: %p size: %llu",
			dev->data->port_id, priv->uar_base, MLX5_UAR_SIZE);
		rte_errno = ENXIO;
		return -rte_errno;
	}
	if (priv->uar_base != addr) {
		DRV_LOG(ERR,
			"port %u UAR address %p size %llu occupied, please"
			" adjust MLX5_UAR_OFFSET or try EAL parameter"
			" --base-virtaddr",
			dev->data->port_id, priv->uar_base, MLX5_UAR_SIZE);
		rte_errno = ENXIO;
		return -rte_errno;
	}
	uar_base = addr; /* process local, don't reserve again */
	DRV_LOG(INFO, "port %u reserved UAR address space: %p",
		dev->data->port_id, addr);
	return 0;
}

/**
 * Assign parameters from args into priv, only non default
 * values are considered.
 *
 * @param[out] priv
 *   Pointer to private structure.
 * @param[in] args
 *   Pointer to args values.
 */
static void
mlx5_args_assign(struct priv *priv, struct mlx5_args *args)
{
	if (args->cqe_comp != MLX5_ARG_UNSET)
		priv->cqe_comp = args->cqe_comp;
	if (args->txq_inline != MLX5_ARG_UNSET)
		priv->txq_inline = args->txq_inline;
	if (args->txqs_inline != MLX5_ARG_UNSET)
		priv->txqs_inline = args->txqs_inline;
	if (args->mps != MLX5_ARG_UNSET)
		priv->mps = args->mps ? priv->mps : 0;
	if (args->mpw_hdr_dseg != MLX5_ARG_UNSET)
		priv->mpw_hdr_dseg = args->mpw_hdr_dseg;
	if (args->inline_max_packet_sz != MLX5_ARG_UNSET)
		priv->inline_max_packet_sz = args->inline_max_packet_sz;
	if (args->tso != MLX5_ARG_UNSET)
		priv->tso = args->tso;
	if (args->tx_vec_en != MLX5_ARG_UNSET)
		priv->tx_vec_en = args->tx_vec_en;
	if (args->rx_vec_en != MLX5_ARG_UNSET)
		priv->rx_vec_en = args->rx_vec_en;
}

/**
 * DPDK callback to register a PCI device.
 *
 * This function creates an Ethernet device for each port of a given
 * PCI device.
 *
 * @param[in] pci_drv
 *   PCI driver structure (mlx5_driver).
 * @param[in] pci_dev
 *   PCI device information.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	       struct rte_pci_device *pci_dev)
{
	struct ibv_device **list = NULL;
	struct ibv_device *ibv_dev;
	int err = 0;
	struct ibv_context *attr_ctx = NULL;
	struct ibv_device_attr_ex device_attr;
	unsigned int mps;
	unsigned int cqe_comp;
	unsigned int tunnel_en = 0;
	int idx;
	int i;
	struct mlx5dv_context attrs_out;
#ifdef HAVE_IBV_DEVICE_COUNTERS_SET_SUPPORT
	struct ibv_counter_set_description cs_desc = { .counter_type = 0 };
#endif

	assert(pci_drv == &mlx5_driver);
	/* Get mlx5_dev[] index. */
	idx = mlx5_dev_idx(&pci_dev->addr);
	if (idx == -1) {
		DRV_LOG(ERR, "this driver cannot support any more adapters");
		err = ENOMEM;
		goto error;
	}
	DRV_LOG(DEBUG, "using driver device index %d", idx);
	/* Save PCI address. */
	mlx5_dev[idx].pci_addr = pci_dev->addr;
	list = ibv_get_device_list(&i);
	if (list == NULL) {
		assert(errno);
		err = errno;
		if (errno == ENOSYS)
			DRV_LOG(ERR,
				"cannot list devices, is ib_uverbs loaded?");
		goto error;
	}
	assert(i >= 0);
	/*
	 * For each listed device, check related sysfs entry against
	 * the provided PCI ID.
	 */
	while (i != 0) {
		struct rte_pci_addr pci_addr;

		--i;
		DRV_LOG(DEBUG, "checking device \"%s\"", list[i]->name);
		if (mlx5_ibv_device_to_pci_addr(list[i], &pci_addr))
			continue;
		if ((pci_dev->addr.domain != pci_addr.domain) ||
		    (pci_dev->addr.bus != pci_addr.bus) ||
		    (pci_dev->addr.devid != pci_addr.devid) ||
		    (pci_dev->addr.function != pci_addr.function))
			continue;
		switch (pci_dev->id.device_id) {
		case PCI_DEVICE_ID_MELLANOX_CONNECTX4:
			tunnel_en = 1;
			break;
		case PCI_DEVICE_ID_MELLANOX_CONNECTX4LX:
		case PCI_DEVICE_ID_MELLANOX_CONNECTX5:
		case PCI_DEVICE_ID_MELLANOX_CONNECTX5VF:
		case PCI_DEVICE_ID_MELLANOX_CONNECTX5EX:
		case PCI_DEVICE_ID_MELLANOX_CONNECTX5EXVF:
			tunnel_en = 1;
			break;
		default:
			break;
		}
		DRV_LOG(INFO, "PCI information matches, using device \"%s\"",
		     list[i]->name);
		attr_ctx = ibv_open_device(list[i]);
		rte_errno = errno;
		err = rte_errno;
		break;
	}
	if (attr_ctx == NULL) {
		switch (err) {
		case 0:
			DRV_LOG(ERR,
				"cannot access device, is mlx5_ib loaded?");
			err = ENODEV;
			break;
		case EINVAL:
			DRV_LOG(ERR,
				"cannot use device, are drivers up to date?");
			break;
		}
		goto error;
	}
	ibv_dev = list[i];
	DRV_LOG(DEBUG, "device opened");
	/*
	 * Multi-packet send is supported by ConnectX-4 Lx PF as well
	 * as all ConnectX-5 devices.
	 */
	mlx5dv_query_device(attr_ctx, &attrs_out);
	if (attrs_out.flags & MLX5DV_CONTEXT_FLAGS_MPW_ALLOWED) {
		if (attrs_out.flags & MLX5DV_CONTEXT_FLAGS_ENHANCED_MPW) {
			DRV_LOG(DEBUG, "enhanced MPW is supported");
			mps = MLX5_MPW_ENHANCED;
		} else {
			DRV_LOG(DEBUG, "MPW is supported");
			mps = MLX5_MPW;
		}
	} else {
		DRV_LOG(DEBUG, "MPW isn't supported");
		mps = MLX5_MPW_DISABLED;
	}
	if (RTE_CACHE_LINE_SIZE == 128 &&
	    !(attrs_out.flags & MLX5DV_CONTEXT_FLAGS_CQE_128B_COMP))
		cqe_comp = 0;
	else
		cqe_comp = 1;
	err = ibv_query_device_ex(attr_ctx, NULL, &device_attr);
	if (err) {
		DEBUG("ibv_query_device_ex() failed");
		goto error;
	}
	DRV_LOG(INFO, "%u port(s) detected",
		device_attr.orig_attr.phys_port_cnt);
	for (i = 0; i < device_attr.orig_attr.phys_port_cnt; i++) {
		char name[RTE_ETH_NAME_MAX_LEN];
		uint32_t port = i + 1; /* ports are indexed from one */
		uint32_t test = (1 << i);
		struct ibv_context *ctx = NULL;
		struct ibv_port_attr port_attr;
		struct ibv_pd *pd = NULL;
		struct priv *priv = NULL;
		struct rte_eth_dev *eth_dev = NULL;
		struct ibv_device_attr_ex device_attr_ex;
		struct ether_addr mac;
		struct mlx5_args args = {
			.cqe_comp = MLX5_ARG_UNSET,
			.txq_inline = MLX5_ARG_UNSET,
			.txqs_inline = MLX5_ARG_UNSET,
			.mps = MLX5_ARG_UNSET,
			.mpw_hdr_dseg = MLX5_ARG_UNSET,
			.inline_max_packet_sz = MLX5_ARG_UNSET,
			.tso = MLX5_ARG_UNSET,
			.tx_vec_en = MLX5_ARG_UNSET,
			.rx_vec_en = MLX5_ARG_UNSET,
		};

		snprintf(name, sizeof(name), PCI_PRI_FMT,
			 pci_dev->addr.domain, pci_dev->addr.bus,
			 pci_dev->addr.devid, pci_dev->addr.function);
		mlx5_dev[idx].ports |= test;
		if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
			eth_dev = rte_eth_dev_attach_secondary(name);
			if (eth_dev == NULL) {
				DRV_LOG(ERR, "can not attach rte ethdev");
				rte_errno = ENOMEM;
				err = rte_errno;
				goto error;
			}
			eth_dev->device = &pci_dev->device;
			eth_dev->dev_ops = &mlx5_dev_sec_ops;
			err = mlx5_uar_init_secondary(eth_dev);
			if (err) {
				err = rte_errno;
				goto error;
			}
			/* Receive command fd from primary process */
			err = mlx5_socket_connect(eth_dev);
			if (err < 0) {
				err = rte_errno;
				goto error;
			}
			/* Remap UAR for Tx queues. */
			err = mlx5_tx_uar_remap(eth_dev, err);
			if (err) {
				err = rte_errno;
				goto error;
			}
			/*
			 * Ethdev pointer is still required as input since
			 * the primary device is not accessible from the
			 * secondary process.
			 */
			eth_dev->rx_pkt_burst =
				mlx5_select_rx_function(eth_dev);
			eth_dev->tx_pkt_burst =
				mlx5_select_tx_function(eth_dev);
			continue;
		}
		DRV_LOG(DEBUG, "using port %u (%08" PRIx32 ")", port, test);
		ctx = ibv_open_device(ibv_dev);
		if (ctx == NULL) {
			err = ENODEV;
			goto port_error;
		}
		/* Check port status. */
		err = ibv_query_port(ctx, port, &port_attr);
		if (err) {
			DRV_LOG(ERR, "port query failed: %s", strerror(err));
			goto port_error;
		}
		if (port_attr.link_layer != IBV_LINK_LAYER_ETHERNET) {
			DRV_LOG(ERR,
				"port %d is not configured in Ethernet mode",
				port);
			err = EINVAL;
			goto port_error;
		}
		if (port_attr.state != IBV_PORT_ACTIVE)
			DRV_LOG(DEBUG, "port %d is not active: \"%s\" (%d)",
				port, ibv_port_state_str(port_attr.state),
				port_attr.state);
		/* Allocate protection domain. */
		pd = ibv_alloc_pd(ctx);
		if (pd == NULL) {
			DRV_LOG(ERR, "PD allocation failure");
			err = ENOMEM;
			goto port_error;
		}
		mlx5_dev[idx].ports |= test;
		/* from rte_ethdev.c */
		priv = rte_zmalloc("ethdev private structure",
				   sizeof(*priv),
				   RTE_CACHE_LINE_SIZE);
		if (priv == NULL) {
			DRV_LOG(ERR, "priv allocation failure");
			err = ENOMEM;
			goto port_error;
		}
		priv->ctx = ctx;
		strncpy(priv->ibdev_path, priv->ctx->device->ibdev_path,
			sizeof(priv->ibdev_path));
		priv->device_attr = device_attr;
		priv->port = port;
		priv->pd = pd;
		priv->mtu = ETHER_MTU;
		priv->mps = mps; /* Enable MPW by default if supported. */
		priv->cqe_comp = cqe_comp;
		priv->tunnel_en = tunnel_en;
		/* Enable vector by default if supported. */
		priv->tx_vec_en = 1;
		priv->rx_vec_en = 1;
		err = mlx5_args(&args, pci_dev->device.devargs);
		if (err) {
			DRV_LOG(ERR, "failed to process device arguments: %s",
				strerror(err));
			err = rte_errno;
			goto port_error;
		}
		mlx5_args_assign(priv, &args);
		err = ibv_query_device_ex(ctx, NULL, &device_attr_ex);
		if (err) {
			DRV_LOG(ERR, "ibv_query_device_ex() failed");
			goto port_error;
		}
		priv->hw_csum =
			!!(device_attr_ex.device_cap_flags_ex &
			   IBV_DEVICE_RAW_IP_CSUM);
		DRV_LOG(DEBUG, "checksum offloading is %ssupported",
			(priv->hw_csum ? "" : "not "));

#ifdef HAVE_IBV_DEVICE_VXLAN_SUPPORT
		priv->hw_csum_l2tun = !!(exp_device_attr.exp_device_cap_flags &
					 IBV_DEVICE_VXLAN_SUPPORT);
#endif
		DRV_LOG(DEBUG, "Rx L2 tunnel checksum offloads are %ssupported",
			(priv->hw_csum_l2tun ? "" : "not "));

#ifdef HAVE_IBV_DEVICE_COUNTERS_SET_SUPPORT
		priv->counter_set_supported = !!(device_attr.max_counter_sets);
		ibv_describe_counter_set(ctx, 0, &cs_desc);
		DRV_LOG(DEBUG,
			"counter type = %d, num of cs = %ld, attributes = %d",
			cs_desc.counter_type, cs_desc.num_of_cs,
			cs_desc.attributes);
#endif
		priv->ind_table_max_size =
			device_attr_ex.rss_caps.max_rwq_indirection_table_size;
		/* Remove this check once DPDK supports larger/variable
		 * indirection tables. */
		if (priv->ind_table_max_size >
				(unsigned int)ETH_RSS_RETA_SIZE_512)
			priv->ind_table_max_size = ETH_RSS_RETA_SIZE_512;
		DRV_LOG(DEBUG, "maximum Rx indirection table size is %u",
			priv->ind_table_max_size);
		priv->hw_vlan_strip = !!(device_attr_ex.raw_packet_caps &
					 IBV_RAW_PACKET_CAP_CVLAN_STRIPPING);
		DRV_LOG(DEBUG, "VLAN stripping is %ssupported",
			(priv->hw_vlan_strip ? "" : "not "));

		priv->hw_fcs_strip = !!(device_attr_ex.raw_packet_caps &
					IBV_RAW_PACKET_CAP_SCATTER_FCS);
		DRV_LOG(DEBUG, "FCS stripping configuration is %ssupported",
			(priv->hw_fcs_strip ? "" : "not "));

#ifdef HAVE_IBV_WQ_FLAG_RX_END_PADDING
		priv->hw_padding = !!device_attr_ex.rx_pad_end_addr_align;
#endif
		DRV_LOG(DEBUG,
			"hardware Rx end alignment padding is %ssupported",
			(priv->hw_padding ? "" : "not "));
		priv->tso = ((priv->tso) &&
			    (device_attr_ex.tso_caps.max_tso > 0) &&
			    (device_attr_ex.tso_caps.supported_qpts &
			    (1 << IBV_QPT_RAW_PACKET)));
		if (priv->tso)
			priv->max_tso_payload_sz =
				device_attr_ex.tso_caps.max_tso;
		if (priv->mps && !mps) {
			DRV_LOG(ERR,
				"multi-packet send not supported on this device"
				" (" MLX5_TXQ_MPW_EN ")");
			err = ENOTSUP;
			goto port_error;
		} else if (priv->mps && priv->tso) {
			DRV_LOG(WARNING,
				"multi-packet send not supported in conjunction"
				" with TSO. MPS disabled");
			priv->mps = 0;
		}
		DRV_LOG(INFO, "%s MPS is %s",
			priv->mps == MLX5_MPW_ENHANCED ? "enhanced " : "",
			priv->mps != MLX5_MPW_DISABLED ? "enabled" :
							 "disabled");
		/* Set default values for Enhanced MPW, a.k.a MPWv2. */
		if (priv->mps == MLX5_MPW_ENHANCED) {
			if (args.txqs_inline == MLX5_ARG_UNSET)
				priv->txqs_inline = MLX5_EMPW_MIN_TXQS;
			if (args.inline_max_packet_sz == MLX5_ARG_UNSET)
				priv->inline_max_packet_sz =
					MLX5_EMPW_MAX_INLINE_LEN;
			if (args.txq_inline == MLX5_ARG_UNSET)
				priv->txq_inline = MLX5_WQE_SIZE_MAX -
						   MLX5_WQE_SIZE;
		}
		if (priv->cqe_comp && !cqe_comp) {
			DRV_LOG(WARNING, "Rx CQE compression isn't supported");
			priv->cqe_comp = 0;
		}
		eth_dev = rte_eth_dev_allocate(name);
		if (eth_dev == NULL) {
			DRV_LOG(ERR, "can not allocate rte ethdev");
			err = ENOMEM;
			goto port_error;
		}
		eth_dev->data->dev_private = priv;
		priv->dev_data = eth_dev->data;
		eth_dev->data->mac_addrs = priv->mac;
		eth_dev->device = &pci_dev->device;
		rte_eth_copy_pci_info(eth_dev, pci_dev);
		eth_dev->device->driver = &mlx5_driver.driver;
		err = mlx5_uar_init_primary(eth_dev);
		if (err) {
			err = rte_errno;
			goto port_error;
		}
		/* Configure the first MAC address by default. */
		if (mlx5_get_mac(eth_dev, &mac.addr_bytes)) {
			DRV_LOG(ERR,
				"port %u cannot get MAC address, is mlx5_en"
				" loaded? (errno: %s)",
				eth_dev->data->port_id, strerror(errno));
			err = ENODEV;
			goto port_error;
		}
		DRV_LOG(INFO,
			"port %u MAC address is %02x:%02x:%02x:%02x:%02x:%02x",
			eth_dev->data->port_id,
			mac.addr_bytes[0], mac.addr_bytes[1],
			mac.addr_bytes[2], mac.addr_bytes[3],
			mac.addr_bytes[4], mac.addr_bytes[5]);
#ifndef NDEBUG
		{
			char ifname[IF_NAMESIZE];

			if (mlx5_get_ifname(eth_dev, &ifname) == 0)
				DRV_LOG(DEBUG, "port %u ifname is \"%s\"",
					eth_dev->data->port_id, ifname);
			else
				DRV_LOG(DEBUG, "port %u ifname is unknown",
					eth_dev->data->port_id);
		}
#endif
		/* Get actual MTU if possible. */
		err = mlx5_get_mtu(eth_dev, &priv->mtu);
		if (err) {
			err = rte_errno;
			goto port_error;
		}
		DRV_LOG(DEBUG, "port %u MTU is %u", eth_dev->data->port_id,
			priv->mtu);
		/*
		 * Initialize burst functions to prevent crashes before link-up.
		 */
		eth_dev->rx_pkt_burst = removed_rx_burst;
		eth_dev->tx_pkt_burst = removed_tx_burst;
		eth_dev->dev_ops = &mlx5_dev_ops;
		/* Register MAC address. */
		claim_zero(mlx5_mac_addr_add(eth_dev, &mac, 0, 0));
		TAILQ_INIT(&priv->flows);
		TAILQ_INIT(&priv->ctrl_flows);
		/* Hint libmlx5 to use PMD allocator for data plane resources */
		struct mlx5dv_ctx_allocators alctr = {
			.alloc = &mlx5_alloc_verbs_buf,
			.free = &mlx5_free_verbs_buf,
			.data = priv,
		};
		mlx5dv_set_context_attr(ctx, MLX5DV_CTX_ATTR_BUF_ALLOCATORS,
					(void *)((uintptr_t)&alctr));
		/* Bring Ethernet device up. */
		DRV_LOG(DEBUG, "port %u forcing Ethernet interface up",
			eth_dev->data->port_id);
		mlx5_set_link_up(eth_dev);
		/*
		 * Even though the interrupt handler is not installed yet,
		 * interrupts will still trigger on the asyn_fd from
		 * Verbs context returned by ibv_open_device().
		 */
		mlx5_link_update(eth_dev, 0);
		continue;
port_error:
		if (priv)
			rte_free(priv);
		if (pd)
			claim_zero(ibv_dealloc_pd(pd));
		if (ctx)
			claim_zero(ibv_close_device(ctx));
		if (eth_dev && rte_eal_process_type() == RTE_PROC_PRIMARY)
			rte_eth_dev_release_port(eth_dev);
		break;
	}
	/*
	 * XXX if something went wrong in the loop above, there is a resource
	 * leak (ctx, pd, priv, dpdk ethdev) but we can do nothing about it as
	 * long as the dpdk does not provide a way to deallocate a ethdev and a
	 * way to enumerate the registered ethdevs to free the previous ones.
	 */
	/* no port found, complain */
	if (!mlx5_dev[idx].ports) {
		rte_errno = ENODEV;
		err = rte_errno;
	}
error:
	if (attr_ctx)
		claim_zero(ibv_close_device(attr_ctx));
	if (list)
		ibv_free_device_list(list);
	if (err) {
		rte_errno = err;
		return -rte_errno;
	}
	return 0;
}

static const struct rte_pci_id mlx5_pci_id_map[] = {
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX4)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX4VF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX4LX)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX4LXVF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5VF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5EX)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5EXVF)
	},
	{
		.vendor_id = 0
	}
};

static struct rte_pci_driver mlx5_driver = {
	.driver = {
		.name = MLX5_DRIVER_NAME
	},
	.id_table = mlx5_pci_id_map,
	.probe = mlx5_pci_probe,
	.drv_flags = RTE_PCI_DRV_INTR_LSC | RTE_PCI_DRV_INTR_RMV,
};

/**
 * Driver initialization routine.
 */
RTE_INIT(rte_mlx5_pmd_init);
static void
rte_mlx5_pmd_init(void)
{
	/* Build the static table for ptype conversion. */
	mlx5_set_ptype_table();
	/*
	 * RDMAV_HUGEPAGES_SAFE tells ibv_fork_init() we intend to use
	 * huge pages. Calling ibv_fork_init() during init allows
	 * applications to use fork() safely for purposes other than
	 * using this PMD, which is not supported in forked processes.
	 */
	setenv("RDMAV_HUGEPAGES_SAFE", "1", 1);
	/* Match the size of Rx completion entry to the size of a cacheline. */
	if (RTE_CACHE_LINE_SIZE == 128)
		setenv("MLX5_CQE_SIZE", "128", 0);
	ibv_fork_init();
	rte_pci_register(&mlx5_driver);
}

RTE_PMD_EXPORT_NAME(net_mlx5, __COUNTER__);
RTE_PMD_REGISTER_PCI_TABLE(net_mlx5, mlx5_pci_id_map);
RTE_PMD_REGISTER_KMOD_DEP(net_mlx5, "* ib_uverbs & mlx5_core & mlx5_ib");

/** Initialize driver log type. */
RTE_INIT(vdev_netvsc_init_log)
{
	mlx5_logtype = rte_log_register("pmd.net.mlx5");
	if (mlx5_logtype >= 0)
		rte_log_set_level(mlx5_logtype, RTE_LOG_NOTICE);
}
