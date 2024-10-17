/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2015 6WIND S.A.
 * Copyright 2015 Mellanox Technologies, Ltd
 */

#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/queue.h>

#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <ethdev_driver.h>
#include <rte_common.h>
#include <rte_interrupts.h>
#include <rte_debug.h>
#include <rte_io.h>
#include <rte_eal_paging.h>

#include <mlx5_glue.h>
#include <mlx5_malloc.h>
#include <mlx5_common.h>
#include <mlx5_common_mr.h>

#include "mlx5_defs.h"
#include "mlx5.h"
#include "mlx5_rx.h"
#include "mlx5_utils.h"
#include "mlx5_autoconf.h"
#include "mlx5_devx.h"
#include "rte_pmd_mlx5.h"


/* Default RSS hash key also used for ConnectX-3. */
uint8_t rss_hash_default_key[] = {
	0x2c, 0xc6, 0x81, 0xd1,
	0x5b, 0xdb, 0xf4, 0xf7,
	0xfc, 0xa2, 0x83, 0x19,
	0xdb, 0x1a, 0x3e, 0x94,
	0x6b, 0x9e, 0x38, 0xd9,
	0x2c, 0x9c, 0x03, 0xd1,
	0xad, 0x99, 0x44, 0xa7,
	0xd9, 0x56, 0x3d, 0x59,
	0x06, 0x3c, 0x25, 0xf3,
	0xfc, 0x1f, 0xdc, 0x2a,
};

/* Length of the default RSS hash key. */
static_assert(MLX5_RSS_HASH_KEY_LEN ==
	      (unsigned int)sizeof(rss_hash_default_key),
	      "wrong RSS default key size.");

/**
 * Calculate the number of CQEs in CQ for the Rx queue.
 *
 *  @param rxq_data
 *     Pointer to receive queue structure.
 *
 * @return
 *   Number of CQEs in CQ.
 */
unsigned int
mlx5_rxq_cqe_num(struct mlx5_rxq_data *rxq_data)
{
	unsigned int cqe_n;
	unsigned int wqe_n = 1 << rxq_data->elts_n;

	if (mlx5_rxq_mprq_enabled(rxq_data))
		cqe_n = wqe_n * RTE_BIT32(rxq_data->log_strd_num) - 1;
	else
		cqe_n = wqe_n - 1;
	return cqe_n;
}

/**
 * Allocate RX queue elements for Multi-Packet RQ.
 *
 * @param rxq_ctrl
 *   Pointer to RX queue structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
rxq_alloc_elts_mprq(struct mlx5_rxq_ctrl *rxq_ctrl)
{
	struct mlx5_rxq_data *rxq = &rxq_ctrl->rxq;
	unsigned int wqe_n = 1 << rxq->elts_n;
	unsigned int i;
	int err;

	/* Iterate on segments. */
	for (i = 0; i <= wqe_n; ++i) {
		struct mlx5_mprq_buf *buf;

		if (rte_mempool_get(rxq->mprq_mp, (void **)&buf) < 0) {
			DRV_LOG(ERR, "port %u empty mbuf pool", rxq->port_id);
			rte_errno = ENOMEM;
			goto error;
		}
		if (i < wqe_n)
			(*rxq->mprq_bufs)[i] = buf;
		else
			rxq->mprq_repl = buf;
	}
	DRV_LOG(DEBUG,
		"port %u MPRQ queue %u allocated and configured %u segments",
		rxq->port_id, rxq->idx, wqe_n);
	return 0;
error:
	err = rte_errno; /* Save rte_errno before cleanup. */
	wqe_n = i;
	for (i = 0; (i != wqe_n); ++i) {
		if ((*rxq->mprq_bufs)[i] != NULL)
			rte_mempool_put(rxq->mprq_mp,
					(*rxq->mprq_bufs)[i]);
		(*rxq->mprq_bufs)[i] = NULL;
	}
	DRV_LOG(DEBUG, "port %u MPRQ queue %u failed, freed everything",
		rxq->port_id, rxq->idx);
	rte_errno = err; /* Restore rte_errno. */
	return -rte_errno;
}

/**
 * Allocate RX queue elements for Single-Packet RQ.
 *
 * @param rxq_ctrl
 *   Pointer to RX queue structure.
 *
 * @return
 *   0 on success, negative errno value on failure.
 */
static int
rxq_alloc_elts_sprq(struct mlx5_rxq_ctrl *rxq_ctrl)
{
	const unsigned int sges_n = 1 << rxq_ctrl->rxq.sges_n;
	unsigned int elts_n = mlx5_rxq_mprq_enabled(&rxq_ctrl->rxq) ?
			      RTE_BIT32(rxq_ctrl->rxq.elts_n) *
			      RTE_BIT32(rxq_ctrl->rxq.log_strd_num) :
			      RTE_BIT32(rxq_ctrl->rxq.elts_n);
	bool has_vec_support = mlx5_rxq_check_vec_support(&rxq_ctrl->rxq) > 0;
	unsigned int i;
	int err;

	/* Iterate on segments. */
	for (i = 0; (i != elts_n); ++i) {
		struct mlx5_eth_rxseg *seg = &rxq_ctrl->rxq.rxseg[i % sges_n];
		struct rte_mbuf *buf;

		buf = rte_pktmbuf_alloc(seg->mp);
		if (buf == NULL) {
			if (rxq_ctrl->share_group == 0)
				DRV_LOG(ERR, "port %u queue %u empty mbuf pool",
					RXQ_PORT_ID(rxq_ctrl),
					rxq_ctrl->rxq.idx);
			else
				DRV_LOG(ERR, "share group %u queue %u empty mbuf pool",
					rxq_ctrl->share_group,
					rxq_ctrl->share_qid);
			rte_errno = ENOMEM;
			goto error;
		}
		/* Only vectored Rx routines rely on headroom size. */
		MLX5_ASSERT(!has_vec_support ||
			    DATA_OFF(buf) >= RTE_PKTMBUF_HEADROOM);
		/* Buffer is supposed to be empty. */
		MLX5_ASSERT(rte_pktmbuf_data_len(buf) == 0);
		MLX5_ASSERT(rte_pktmbuf_pkt_len(buf) == 0);
		MLX5_ASSERT(!buf->next);
		SET_DATA_OFF(buf, seg->offset);
		PORT(buf) = rxq_ctrl->rxq.port_id;
		DATA_LEN(buf) = seg->length;
		PKT_LEN(buf) = seg->length;
		NB_SEGS(buf) = 1;
		(*rxq_ctrl->rxq.elts)[i] = buf;
	}
	/* If Rx vector is activated. */
	if (has_vec_support) {
		struct mlx5_rxq_data *rxq = &rxq_ctrl->rxq;
		struct rte_mbuf *mbuf_init = &rxq->fake_mbuf;
		struct rte_pktmbuf_pool_private *priv =
			(struct rte_pktmbuf_pool_private *)
				rte_mempool_get_priv(rxq_ctrl->rxq.mp);
		int j;

		/* Initialize default rearm_data for vPMD. */
		mbuf_init->data_off = RTE_PKTMBUF_HEADROOM;
		rte_mbuf_refcnt_set(mbuf_init, 1);
		mbuf_init->nb_segs = 1;
		/* For shared queues port is provided in CQE */
		mbuf_init->port = rxq->shared ? 0 : rxq->port_id;
		if (priv->flags & RTE_PKTMBUF_POOL_F_PINNED_EXT_BUF)
			mbuf_init->ol_flags = RTE_MBUF_F_EXTERNAL;
		/*
		 * prevent compiler reordering:
		 * rearm_data covers previous fields.
		 */
		rte_compiler_barrier();
		rxq->mbuf_initializer =
			*(rte_xmm_t *)&mbuf_init->rearm_data;
		/* Padding with a fake mbuf for vectorized Rx. */
		for (j = 0; j < MLX5_VPMD_DESCS_PER_LOOP; ++j)
			(*rxq->elts)[elts_n + j] = &rxq->fake_mbuf;
	}
	if (rxq_ctrl->share_group == 0)
		DRV_LOG(DEBUG,
			"port %u SPRQ queue %u allocated and configured %u segments (max %u packets)",
			RXQ_PORT_ID(rxq_ctrl), rxq_ctrl->rxq.idx, elts_n,
			elts_n / (1 << rxq_ctrl->rxq.sges_n));
	else
		DRV_LOG(DEBUG,
			"share group %u SPRQ queue %u allocated and configured %u segments (max %u packets)",
			rxq_ctrl->share_group, rxq_ctrl->share_qid, elts_n,
			elts_n / (1 << rxq_ctrl->rxq.sges_n));
	return 0;
error:
	err = rte_errno; /* Save rte_errno before cleanup. */
	elts_n = i;
	for (i = 0; (i != elts_n); ++i) {
		if ((*rxq_ctrl->rxq.elts)[i] != NULL)
			rte_pktmbuf_free_seg((*rxq_ctrl->rxq.elts)[i]);
		(*rxq_ctrl->rxq.elts)[i] = NULL;
	}
	if (rxq_ctrl->share_group == 0)
		DRV_LOG(DEBUG, "port %u SPRQ queue %u failed, freed everything",
			RXQ_PORT_ID(rxq_ctrl), rxq_ctrl->rxq.idx);
	else
		DRV_LOG(DEBUG, "share group %u SPRQ queue %u failed, freed everything",
			rxq_ctrl->share_group, rxq_ctrl->share_qid);
	rte_errno = err; /* Restore rte_errno. */
	return -rte_errno;
}

/**
 * Allocate RX queue elements.
 *
 * @param rxq_ctrl
 *   Pointer to RX queue structure.
 *
 * @return
 *   0 on success, negative errno value on failure.
 */
int
rxq_alloc_elts(struct mlx5_rxq_ctrl *rxq_ctrl)
{
	int ret = 0;

	/**
	 * For MPRQ we need to allocate both MPRQ buffers
	 * for WQEs and simple mbufs for vector processing.
	 */
	if (mlx5_rxq_mprq_enabled(&rxq_ctrl->rxq))
		ret = rxq_alloc_elts_mprq(rxq_ctrl);
	if (ret == 0)
		ret = rxq_alloc_elts_sprq(rxq_ctrl);
	return ret;
}

/**
 * Free RX queue elements for Multi-Packet RQ.
 *
 * @param rxq_ctrl
 *   Pointer to RX queue structure.
 */
static void
rxq_free_elts_mprq(struct mlx5_rxq_ctrl *rxq_ctrl)
{
	struct mlx5_rxq_data *rxq = &rxq_ctrl->rxq;
	uint16_t i;

	DRV_LOG(DEBUG, "port %u Multi-Packet Rx queue %u freeing %d WRs",
		rxq->port_id, rxq->idx, (1u << rxq->elts_n));
	if (rxq->mprq_bufs == NULL)
		return;
	for (i = 0; (i != (1u << rxq->elts_n)); ++i) {
		if ((*rxq->mprq_bufs)[i] != NULL)
			mlx5_mprq_buf_free((*rxq->mprq_bufs)[i]);
		(*rxq->mprq_bufs)[i] = NULL;
	}
	if (rxq->mprq_repl != NULL) {
		mlx5_mprq_buf_free(rxq->mprq_repl);
		rxq->mprq_repl = NULL;
	}
}

/**
 * Free RX queue elements for Single-Packet RQ.
 *
 * @param rxq_ctrl
 *   Pointer to RX queue structure.
 */
static void
rxq_free_elts_sprq(struct mlx5_rxq_ctrl *rxq_ctrl)
{
	struct mlx5_rxq_data *rxq = &rxq_ctrl->rxq;
	const uint16_t q_n = mlx5_rxq_mprq_enabled(&rxq_ctrl->rxq) ?
		RTE_BIT32(rxq->elts_n) * RTE_BIT32(rxq->log_strd_num) :
		RTE_BIT32(rxq->elts_n);
	const uint16_t q_mask = q_n - 1;
	uint16_t elts_ci = mlx5_rxq_mprq_enabled(&rxq_ctrl->rxq) ?
		rxq->elts_ci : rxq->rq_ci;
	uint16_t used = q_n - (elts_ci - rxq->rq_pi);
	uint16_t i;

	if (rxq_ctrl->share_group == 0)
		DRV_LOG(DEBUG, "port %u Rx queue %u freeing %d WRs",
			RXQ_PORT_ID(rxq_ctrl), rxq->idx, q_n);
	else
		DRV_LOG(DEBUG, "share group %u Rx queue %u freeing %d WRs",
			rxq_ctrl->share_group, rxq_ctrl->share_qid, q_n);
	if (rxq->elts == NULL)
		return;
	/**
	 * Some mbuf in the Ring belongs to the application.
	 * They cannot be freed.
	 */
	if (mlx5_rxq_check_vec_support(rxq) > 0) {
		for (i = 0; i < used; ++i)
			(*rxq->elts)[(elts_ci + i) & q_mask] = NULL;
		rxq->rq_pi = elts_ci;
	}
	for (i = 0; i != q_n; ++i) {
		if ((*rxq->elts)[i] != NULL)
			rte_pktmbuf_free_seg((*rxq->elts)[i]);
		(*rxq->elts)[i] = NULL;
	}
}

/**
 * Free RX queue elements.
 *
 * @param rxq_ctrl
 *   Pointer to RX queue structure.
 */
static void
rxq_free_elts(struct mlx5_rxq_ctrl *rxq_ctrl)
{
	/*
	 * For MPRQ we need to allocate both MPRQ buffers
	 * for WQEs and simple mbufs for vector processing.
	 */
	if (mlx5_rxq_mprq_enabled(&rxq_ctrl->rxq))
		rxq_free_elts_mprq(rxq_ctrl);
	rxq_free_elts_sprq(rxq_ctrl);
}

/**
 * Returns the per-queue supported offloads.
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   Supported Rx offloads.
 */
uint64_t
mlx5_get_rx_queue_offloads(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	uint64_t offloads = (RTE_ETH_RX_OFFLOAD_SCATTER |
			     RTE_ETH_RX_OFFLOAD_TIMESTAMP |
			     RTE_ETH_RX_OFFLOAD_RSS_HASH);

	if (!priv->config.mprq.enabled)
		offloads |= RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT;
	if (priv->sh->config.hw_fcs_strip)
		offloads |= RTE_ETH_RX_OFFLOAD_KEEP_CRC;
	if (priv->sh->dev_cap.hw_csum)
		offloads |= (RTE_ETH_RX_OFFLOAD_IPV4_CKSUM |
			     RTE_ETH_RX_OFFLOAD_UDP_CKSUM |
			     RTE_ETH_RX_OFFLOAD_TCP_CKSUM);
	if (priv->sh->dev_cap.hw_vlan_strip)
		offloads |= RTE_ETH_RX_OFFLOAD_VLAN_STRIP;
	if (priv->sh->config.lro_allowed)
		offloads |= RTE_ETH_RX_OFFLOAD_TCP_LRO;
	return offloads;
}


/**
 * Returns the per-port supported offloads.
 *
 * @return
 *   Supported Rx offloads.
 */
uint64_t
mlx5_get_rx_port_offloads(void)
{
	uint64_t offloads = RTE_ETH_RX_OFFLOAD_VLAN_FILTER;

	return offloads;
}

/**
 * Verify if the queue can be released.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param idx
 *   RX queue index.
 *
 * @return
 *   1 if the queue can be released
 *   0 if the queue can not be released, there are references to it.
 *   Negative errno and rte_errno is set if queue doesn't exist.
 */
static int
mlx5_rxq_releasable(struct rte_eth_dev *dev, uint16_t idx)
{
	struct mlx5_rxq_priv *rxq = mlx5_rxq_get(dev, idx);

	if (rxq == NULL) {
		rte_errno = EINVAL;
		return -rte_errno;
	}
	return (__atomic_load_n(&rxq->refcnt, __ATOMIC_RELAXED) == 1);
}

/* Fetches and drops all SW-owned and error CQEs to synchronize CQ. */
static void
rxq_sync_cq(struct mlx5_rxq_data *rxq)
{
	const uint16_t cqe_n = 1 << rxq->cqe_n;
	const uint16_t cqe_mask = cqe_n - 1;
	volatile struct mlx5_cqe *cqe;
	int ret, i;

	i = cqe_n;
	do {
		cqe = &(*rxq->cqes)[rxq->cq_ci & cqe_mask];
		ret = check_cqe(cqe, cqe_n, rxq->cq_ci);
		if (ret == MLX5_CQE_STATUS_HW_OWN)
			break;
		if (ret == MLX5_CQE_STATUS_ERR) {
			rxq->cq_ci++;
			continue;
		}
		MLX5_ASSERT(ret == MLX5_CQE_STATUS_SW_OWN);
		if (MLX5_CQE_FORMAT(cqe->op_own) != MLX5_COMPRESSED) {
			rxq->cq_ci++;
			continue;
		}
		/* Compute the next non compressed CQE. */
		rxq->cq_ci += rte_be_to_cpu_32(cqe->byte_cnt);

	} while (--i);
	/* Move all CQEs to HW ownership, including possible MiniCQEs. */
	for (i = 0; i < cqe_n; i++) {
		cqe = &(*rxq->cqes)[i];
		cqe->op_own = MLX5_CQE_INVALIDATE;
	}
	/* Resync CQE and WQE (WQ in RESET state). */
	rte_io_wmb();
	*rxq->cq_db = rte_cpu_to_be_32(rxq->cq_ci);
	rte_io_wmb();
	*rxq->rq_db = rte_cpu_to_be_32(0);
	rte_io_wmb();
}

/**
 * Rx queue stop. Device queue goes to the RESET state,
 * all involved mbufs are freed from WQ.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param idx
 *   RX queue index.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_rx_queue_stop_primary(struct rte_eth_dev *dev, uint16_t idx)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_rxq_priv *rxq = mlx5_rxq_get(dev, idx);
	struct mlx5_rxq_ctrl *rxq_ctrl = rxq->ctrl;
	int ret;

	MLX5_ASSERT(rxq != NULL && rxq_ctrl != NULL);
	MLX5_ASSERT(rte_eal_process_type() == RTE_PROC_PRIMARY);
	ret = priv->obj_ops.rxq_obj_modify(rxq, MLX5_RXQ_MOD_RDY2RST);
	if (ret) {
		DRV_LOG(ERR, "Cannot change Rx WQ state to RESET:  %s",
			strerror(errno));
		rte_errno = errno;
		return ret;
	}
	/* Remove all processes CQEs. */
	rxq_sync_cq(&rxq_ctrl->rxq);
	/* Free all involved mbufs. */
	rxq_free_elts(rxq_ctrl);
	/* Set the actual queue state. */
	dev->data->rx_queue_state[idx] = RTE_ETH_QUEUE_STATE_STOPPED;
	return 0;
}

/**
 * Rx queue stop. Device queue goes to the RESET state,
 * all involved mbufs are freed from WQ.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param idx
 *   RX queue index.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_rx_queue_stop(struct rte_eth_dev *dev, uint16_t idx)
{
	eth_rx_burst_t pkt_burst = dev->rx_pkt_burst;
	int ret;

	if (rte_eth_dev_is_rx_hairpin_queue(dev, idx)) {
		DRV_LOG(ERR, "Hairpin queue can't be stopped");
		rte_errno = EINVAL;
		return -EINVAL;
	}
	if (dev->data->rx_queue_state[idx] == RTE_ETH_QUEUE_STATE_STOPPED)
		return 0;
	/*
	 * Vectorized Rx burst requires the CQ and RQ indices
	 * synchronized, that might be broken on RQ restart
	 * and cause Rx malfunction, so queue stopping is
	 * not supported if vectorized Rx burst is engaged.
	 * The routine pointer depends on the process type,
	 * should perform check there. MPRQ is not supported as well.
	 */
	if (pkt_burst != mlx5_rx_burst) {
		DRV_LOG(ERR, "Rx queue stop is only supported "
			"for non-vectorized single-packet Rx");
		rte_errno = EINVAL;
		return -EINVAL;
	}
	if (rte_eal_process_type() ==  RTE_PROC_SECONDARY) {
		ret = mlx5_mp_os_req_queue_control(dev, idx,
						   MLX5_MP_REQ_QUEUE_RX_STOP);
	} else {
		ret = mlx5_rx_queue_stop_primary(dev, idx);
	}
	return ret;
}

/**
 * Rx queue start. Device queue goes to the ready state,
 * all required mbufs are allocated and WQ is replenished.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param idx
 *   RX queue index.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_rx_queue_start_primary(struct rte_eth_dev *dev, uint16_t idx)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_rxq_priv *rxq = mlx5_rxq_get(dev, idx);
	struct mlx5_rxq_data *rxq_data = &rxq->ctrl->rxq;
	int ret;

	MLX5_ASSERT(rxq != NULL && rxq->ctrl != NULL);
	MLX5_ASSERT(rte_eal_process_type() == RTE_PROC_PRIMARY);
	/* Allocate needed buffers. */
	ret = rxq_alloc_elts(rxq->ctrl);
	if (ret) {
		DRV_LOG(ERR, "Cannot reallocate buffers for Rx WQ");
		rte_errno = errno;
		return ret;
	}
	rte_io_wmb();
	*rxq_data->cq_db = rte_cpu_to_be_32(rxq_data->cq_ci);
	rte_io_wmb();
	/* Reset RQ consumer before moving queue to READY state. */
	*rxq_data->rq_db = rte_cpu_to_be_32(0);
	rte_io_wmb();
	ret = priv->obj_ops.rxq_obj_modify(rxq, MLX5_RXQ_MOD_RST2RDY);
	if (ret) {
		DRV_LOG(ERR, "Cannot change Rx WQ state to READY:  %s",
			strerror(errno));
		rte_errno = errno;
		return ret;
	}
	/* Reinitialize RQ - set WQEs. */
	mlx5_rxq_initialize(rxq_data);
	rxq_data->err_state = MLX5_RXQ_ERR_STATE_NO_ERROR;
	/* Set actual queue state. */
	dev->data->rx_queue_state[idx] = RTE_ETH_QUEUE_STATE_STARTED;
	return 0;
}

/**
 * Rx queue start. Device queue goes to the ready state,
 * all required mbufs are allocated and WQ is replenished.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param idx
 *   RX queue index.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_rx_queue_start(struct rte_eth_dev *dev, uint16_t idx)
{
	int ret;

	if (rte_eth_dev_is_rx_hairpin_queue(dev, idx)) {
		DRV_LOG(ERR, "Hairpin queue can't be started");
		rte_errno = EINVAL;
		return -EINVAL;
	}
	if (dev->data->rx_queue_state[idx] == RTE_ETH_QUEUE_STATE_STARTED)
		return 0;
	if (rte_eal_process_type() ==  RTE_PROC_SECONDARY) {
		ret = mlx5_mp_os_req_queue_control(dev, idx,
						   MLX5_MP_REQ_QUEUE_RX_START);
	} else {
		ret = mlx5_rx_queue_start_primary(dev, idx);
	}
	return ret;
}

/**
 * Rx queue presetup checks.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param idx
 *   RX queue index.
 * @param desc
 *   Number of descriptors to configure in queue.
 * @param[out] rxq_ctrl
 *   Address of pointer to shared Rx queue control.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_rx_queue_pre_setup(struct rte_eth_dev *dev, uint16_t idx, uint16_t *desc,
			struct mlx5_rxq_ctrl **rxq_ctrl)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_rxq_priv *rxq;
	bool empty;

	if (!rte_is_power_of_2(*desc)) {
		*desc = 1 << log2above(*desc);
		DRV_LOG(WARNING,
			"port %u increased number of descriptors in Rx queue %u"
			" to the next power of two (%d)",
			dev->data->port_id, idx, *desc);
	}
	DRV_LOG(DEBUG, "port %u configuring Rx queue %u for %u descriptors",
		dev->data->port_id, idx, *desc);
	if (idx >= priv->rxqs_n) {
		DRV_LOG(ERR, "port %u Rx queue index out of range (%u >= %u)",
			dev->data->port_id, idx, priv->rxqs_n);
		rte_errno = EOVERFLOW;
		return -rte_errno;
	}
	if (rxq_ctrl == NULL || *rxq_ctrl == NULL)
		return 0;
	if (!(*rxq_ctrl)->rxq.shared) {
		if (!mlx5_rxq_releasable(dev, idx)) {
			DRV_LOG(ERR, "port %u unable to release queue index %u",
				dev->data->port_id, idx);
			rte_errno = EBUSY;
			return -rte_errno;
		}
		mlx5_rxq_release(dev, idx);
	} else {
		if ((*rxq_ctrl)->obj != NULL)
			/* Some port using shared Rx queue has been started. */
			return 0;
		/* Release all owner RxQ to reconfigure Shared RxQ. */
		do {
			rxq = LIST_FIRST(&(*rxq_ctrl)->owners);
			LIST_REMOVE(rxq, owner_entry);
			empty = LIST_EMPTY(&(*rxq_ctrl)->owners);
			mlx5_rxq_release(ETH_DEV(rxq->priv), rxq->idx);
		} while (!empty);
		*rxq_ctrl = NULL;
	}
	return 0;
}

/**
 * Get the shared Rx queue object that matches group and queue index.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param group
 *   Shared RXQ group.
 * @param share_qid
 *   Shared RX queue index.
 *
 * @return
 *   Shared RXQ object that matching, or NULL if not found.
 */
static struct mlx5_rxq_ctrl *
mlx5_shared_rxq_get(struct rte_eth_dev *dev, uint32_t group, uint16_t share_qid)
{
	struct mlx5_rxq_ctrl *rxq_ctrl;
	struct mlx5_priv *priv = dev->data->dev_private;

	LIST_FOREACH(rxq_ctrl, &priv->sh->shared_rxqs, share_entry) {
		if (rxq_ctrl->share_group == group &&
		    rxq_ctrl->share_qid == share_qid)
			return rxq_ctrl;
	}
	return NULL;
}

/**
 * Check whether requested Rx queue configuration matches shared RXQ.
 *
 * @param rxq_ctrl
 *   Pointer to shared RXQ.
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param idx
 *   Queue index.
 * @param desc
 *   Number of descriptors to configure in queue.
 * @param socket
 *   NUMA socket on which memory must be allocated.
 * @param[in] conf
 *   Thresholds parameters.
 * @param mp
 *   Memory pool for buffer allocations.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static bool
mlx5_shared_rxq_match(struct mlx5_rxq_ctrl *rxq_ctrl, struct rte_eth_dev *dev,
		      uint16_t idx, uint16_t desc, unsigned int socket,
		      const struct rte_eth_rxconf *conf,
		      struct rte_mempool *mp)
{
	struct mlx5_priv *spriv = LIST_FIRST(&rxq_ctrl->owners)->priv;
	struct mlx5_priv *priv = dev->data->dev_private;
	unsigned int i;

	RTE_SET_USED(conf);
	if (rxq_ctrl->socket != socket) {
		DRV_LOG(ERR, "port %u queue index %u failed to join shared group: socket mismatch",
			dev->data->port_id, idx);
		return false;
	}
	if (rxq_ctrl->rxq.elts_n != log2above(desc)) {
		DRV_LOG(ERR, "port %u queue index %u failed to join shared group: descriptor number mismatch",
			dev->data->port_id, idx);
		return false;
	}
	if (priv->mtu != spriv->mtu) {
		DRV_LOG(ERR, "port %u queue index %u failed to join shared group: mtu mismatch",
			dev->data->port_id, idx);
		return false;
	}
	if (priv->dev_data->dev_conf.intr_conf.rxq !=
	    spriv->dev_data->dev_conf.intr_conf.rxq) {
		DRV_LOG(ERR, "port %u queue index %u failed to join shared group: interrupt mismatch",
			dev->data->port_id, idx);
		return false;
	}
	if (mp != NULL && rxq_ctrl->rxq.mp != mp) {
		DRV_LOG(ERR, "port %u queue index %u failed to join shared group: mempool mismatch",
			dev->data->port_id, idx);
		return false;
	} else if (mp == NULL) {
		if (conf->rx_nseg != rxq_ctrl->rxseg_n) {
			DRV_LOG(ERR, "port %u queue index %u failed to join shared group: segment number mismatch",
				dev->data->port_id, idx);
			return false;
		}
		for (i = 0; i < conf->rx_nseg; i++) {
			if (memcmp(&conf->rx_seg[i].split, &rxq_ctrl->rxseg[i],
				   sizeof(struct rte_eth_rxseg_split))) {
				DRV_LOG(ERR, "port %u queue index %u failed to join shared group: segment %u configuration mismatch",
					dev->data->port_id, idx, i);
				return false;
			}
		}
	}
	if (priv->config.hw_padding != spriv->config.hw_padding) {
		DRV_LOG(ERR, "port %u queue index %u failed to join shared group: padding mismatch",
			dev->data->port_id, idx);
		return false;
	}
	if (priv->config.cqe_comp != spriv->config.cqe_comp ||
	    (priv->config.cqe_comp &&
	     priv->config.cqe_comp_fmt != spriv->config.cqe_comp_fmt)) {
		DRV_LOG(ERR, "port %u queue index %u failed to join shared group: CQE compression mismatch",
			dev->data->port_id, idx);
		return false;
	}
	return true;
}

/**
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param idx
 *   RX queue index.
 * @param desc
 *   Number of descriptors to configure in queue.
 * @param socket
 *   NUMA socket on which memory must be allocated.
 * @param[in] conf
 *   Thresholds parameters.
 * @param mp
 *   Memory pool for buffer allocations.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_rx_queue_setup(struct rte_eth_dev *dev, uint16_t idx, uint16_t desc,
		    unsigned int socket, const struct rte_eth_rxconf *conf,
		    struct rte_mempool *mp)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_rxq_priv *rxq;
	struct mlx5_rxq_ctrl *rxq_ctrl = NULL;
	struct rte_eth_rxseg_split *rx_seg =
				(struct rte_eth_rxseg_split *)conf->rx_seg;
	struct rte_eth_rxseg_split rx_single = {.mp = mp};
	uint16_t n_seg = conf->rx_nseg;
	int res;
	uint64_t offloads = conf->offloads |
			    dev->data->dev_conf.rxmode.offloads;
	bool is_extmem = false;

	if ((offloads & RTE_ETH_RX_OFFLOAD_TCP_LRO) &&
	    !priv->sh->config.lro_allowed) {
		DRV_LOG(ERR,
			"Port %u queue %u LRO is configured but not allowed.",
			dev->data->port_id, idx);
		rte_errno = EINVAL;
		return -rte_errno;
	}
	if (mp) {
		/*
		 * The parameters should be checked on rte_eth_dev layer.
		 * If mp is specified it means the compatible configuration
		 * without buffer split feature tuning.
		 */
		rx_seg = &rx_single;
		n_seg = 1;
		is_extmem = rte_pktmbuf_priv_flags(mp) &
			    RTE_PKTMBUF_POOL_F_PINNED_EXT_BUF;
	}
	if (n_seg > 1) {
		/* The offloads should be checked on rte_eth_dev layer. */
		MLX5_ASSERT(offloads & RTE_ETH_RX_OFFLOAD_SCATTER);
		if (!(offloads & RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT)) {
			DRV_LOG(ERR, "port %u queue index %u split "
				     "offload not configured",
				     dev->data->port_id, idx);
			rte_errno = ENOSPC;
			return -rte_errno;
		}
		MLX5_ASSERT(n_seg < MLX5_MAX_RXQ_NSEG);
	}
	if (conf->share_group > 0) {
		if (!priv->sh->cdev->config.hca_attr.mem_rq_rmp) {
			DRV_LOG(ERR, "port %u queue index %u shared Rx queue not supported by fw",
				     dev->data->port_id, idx);
			rte_errno = EINVAL;
			return -rte_errno;
		}
		if (priv->obj_ops.rxq_obj_new != devx_obj_ops.rxq_obj_new) {
			DRV_LOG(ERR, "port %u queue index %u shared Rx queue needs DevX api",
				     dev->data->port_id, idx);
			rte_errno = EINVAL;
			return -rte_errno;
		}
		if (conf->share_qid >= priv->rxqs_n) {
			DRV_LOG(ERR, "port %u shared Rx queue index %u > number of Rx queues %u",
				dev->data->port_id, conf->share_qid,
				priv->rxqs_n);
			rte_errno = EINVAL;
			return -rte_errno;
		}
		if (priv->config.mprq.enabled) {
			DRV_LOG(ERR, "port %u shared Rx queue index %u: not supported when MPRQ enabled",
				dev->data->port_id, conf->share_qid);
			rte_errno = EINVAL;
			return -rte_errno;
		}
		/* Try to reuse shared RXQ. */
		rxq_ctrl = mlx5_shared_rxq_get(dev, conf->share_group,
					       conf->share_qid);
		res = mlx5_rx_queue_pre_setup(dev, idx, &desc, &rxq_ctrl);
		if (res)
			return res;
		if (rxq_ctrl != NULL &&
		    !mlx5_shared_rxq_match(rxq_ctrl, dev, idx, desc, socket,
					   conf, mp)) {
			rte_errno = EINVAL;
			return -rte_errno;
		}
	} else {
		res = mlx5_rx_queue_pre_setup(dev, idx, &desc, &rxq_ctrl);
		if (res)
			return res;
	}
	/* Allocate RXQ. */
	rxq = mlx5_malloc(MLX5_MEM_RTE | MLX5_MEM_ZERO, sizeof(*rxq), 0,
			  SOCKET_ID_ANY);
	if (!rxq) {
		DRV_LOG(ERR, "port %u unable to allocate rx queue index %u private data",
			dev->data->port_id, idx);
		rte_errno = ENOMEM;
		return -rte_errno;
	}
	if (rxq_ctrl == NULL) {
		rxq_ctrl = mlx5_rxq_new(dev, idx, desc, socket, conf, rx_seg,
					n_seg, is_extmem);
		if (rxq_ctrl == NULL) {
			DRV_LOG(ERR, "port %u unable to allocate rx queue index %u",
				dev->data->port_id, idx);
			mlx5_free(rxq);
			rte_errno = ENOMEM;
			return -rte_errno;
		}
	}
	rxq->priv = priv;
	rxq->idx = idx;
	(*priv->rxq_privs)[idx] = rxq;
	/* Join owner list. */
	LIST_INSERT_HEAD(&rxq_ctrl->owners, rxq, owner_entry);
	rxq->ctrl = rxq_ctrl;
	mlx5_rxq_ref(dev, idx);
	DRV_LOG(DEBUG, "port %u adding Rx queue %u to list",
		dev->data->port_id, idx);
	dev->data->rx_queues[idx] = &rxq_ctrl->rxq;
	return 0;
}

/**
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param idx
 *   RX queue index.
 * @param desc
 *   Number of descriptors to configure in queue.
 * @param hairpin_conf
 *   Hairpin configuration parameters.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_rx_hairpin_queue_setup(struct rte_eth_dev *dev, uint16_t idx,
			    uint16_t desc,
			    const struct rte_eth_hairpin_conf *hairpin_conf)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_rxq_priv *rxq;
	struct mlx5_rxq_ctrl *rxq_ctrl;
	int res;

	res = mlx5_rx_queue_pre_setup(dev, idx, &desc, NULL);
	if (res)
		return res;
	if (hairpin_conf->peer_count != 1) {
		rte_errno = EINVAL;
		DRV_LOG(ERR, "port %u unable to setup Rx hairpin queue index %u"
			" peer count is %u", dev->data->port_id,
			idx, hairpin_conf->peer_count);
		return -rte_errno;
	}
	if (hairpin_conf->peers[0].port == dev->data->port_id) {
		if (hairpin_conf->peers[0].queue >= priv->txqs_n) {
			rte_errno = EINVAL;
			DRV_LOG(ERR, "port %u unable to setup Rx hairpin queue"
				" index %u, Tx %u is larger than %u",
				dev->data->port_id, idx,
				hairpin_conf->peers[0].queue, priv->txqs_n);
			return -rte_errno;
		}
	} else {
		if (hairpin_conf->manual_bind == 0 ||
		    hairpin_conf->tx_explicit == 0) {
			rte_errno = EINVAL;
			DRV_LOG(ERR, "port %u unable to setup Rx hairpin queue"
				" index %u peer port %u with attributes %u %u",
				dev->data->port_id, idx,
				hairpin_conf->peers[0].port,
				hairpin_conf->manual_bind,
				hairpin_conf->tx_explicit);
			return -rte_errno;
		}
	}
	rxq = mlx5_malloc(MLX5_MEM_RTE | MLX5_MEM_ZERO, sizeof(*rxq), 0,
			  SOCKET_ID_ANY);
	if (!rxq) {
		DRV_LOG(ERR, "port %u unable to allocate hairpin rx queue index %u private data",
			dev->data->port_id, idx);
		rte_errno = ENOMEM;
		return -rte_errno;
	}
	rxq->priv = priv;
	rxq->idx = idx;
	(*priv->rxq_privs)[idx] = rxq;
	rxq_ctrl = mlx5_rxq_hairpin_new(dev, rxq, desc, hairpin_conf);
	if (!rxq_ctrl) {
		DRV_LOG(ERR, "port %u unable to allocate hairpin queue index %u",
			dev->data->port_id, idx);
		mlx5_free(rxq);
		(*priv->rxq_privs)[idx] = NULL;
		rte_errno = ENOMEM;
		return -rte_errno;
	}
	DRV_LOG(DEBUG, "port %u adding hairpin Rx queue %u to list",
		dev->data->port_id, idx);
	dev->data->rx_queues[idx] = &rxq_ctrl->rxq;
	return 0;
}

/**
 * DPDK callback to release a RX queue.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param qid
 *   Receive queue index.
 */
void
mlx5_rx_queue_release(struct rte_eth_dev *dev, uint16_t qid)
{
	struct mlx5_rxq_data *rxq = dev->data->rx_queues[qid];

	if (rxq == NULL)
		return;
	if (!mlx5_rxq_releasable(dev, qid))
		rte_panic("port %u Rx queue %u is still used by a flow and"
			  " cannot be removed\n", dev->data->port_id, qid);
	mlx5_rxq_release(dev, qid);
}

/**
 * Allocate queue vector and fill epoll fd list for Rx interrupts.
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_rx_intr_vec_enable(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	unsigned int i;
	unsigned int rxqs_n = priv->rxqs_n;
	unsigned int n = RTE_MIN(rxqs_n, (uint32_t)RTE_MAX_RXTX_INTR_VEC_ID);
	unsigned int count = 0;
	struct rte_intr_handle *intr_handle = dev->intr_handle;

	if (!dev->data->dev_conf.intr_conf.rxq)
		return 0;
	mlx5_rx_intr_vec_disable(dev);
	if (rte_intr_vec_list_alloc(intr_handle, NULL, n)) {
		DRV_LOG(ERR,
			"port %u failed to allocate memory for interrupt"
			" vector, Rx interrupts will not be supported",
			dev->data->port_id);
		rte_errno = ENOMEM;
		return -rte_errno;
	}

	if (rte_intr_type_set(intr_handle, RTE_INTR_HANDLE_EXT))
		return -rte_errno;

	for (i = 0; i != n; ++i) {
		/* This rxq obj must not be released in this function. */
		struct mlx5_rxq_priv *rxq = mlx5_rxq_get(dev, i);
		struct mlx5_rxq_obj *rxq_obj = rxq ? rxq->ctrl->obj : NULL;
		int rc;

		/* Skip queues that cannot request interrupts. */
		if (!rxq_obj || (!rxq_obj->ibv_channel &&
				 !rxq_obj->devx_channel)) {
			/* Use invalid intr_vec[] index to disable entry. */
			if (rte_intr_vec_list_index_set(intr_handle, i,
			   RTE_INTR_VEC_RXTX_OFFSET + RTE_MAX_RXTX_INTR_VEC_ID))
				return -rte_errno;
			continue;
		}
		mlx5_rxq_ref(dev, i);
		if (count >= RTE_MAX_RXTX_INTR_VEC_ID) {
			DRV_LOG(ERR,
				"port %u too many Rx queues for interrupt"
				" vector size (%d), Rx interrupts cannot be"
				" enabled",
				dev->data->port_id, RTE_MAX_RXTX_INTR_VEC_ID);
			mlx5_rx_intr_vec_disable(dev);
			rte_errno = ENOMEM;
			return -rte_errno;
		}
		rc = mlx5_os_set_nonblock_channel_fd(rxq_obj->fd);
		if (rc < 0) {
			rte_errno = errno;
			DRV_LOG(ERR,
				"port %u failed to make Rx interrupt file"
				" descriptor %d non-blocking for queue index"
				" %d",
				dev->data->port_id, rxq_obj->fd, i);
			mlx5_rx_intr_vec_disable(dev);
			return -rte_errno;
		}

		if (rte_intr_vec_list_index_set(intr_handle, i,
					RTE_INTR_VEC_RXTX_OFFSET + count))
			return -rte_errno;
		if (rte_intr_efds_index_set(intr_handle, count,
						   rxq_obj->fd))
			return -rte_errno;
		count++;
	}
	if (!count)
		mlx5_rx_intr_vec_disable(dev);
	else if (rte_intr_nb_efd_set(intr_handle, count))
		return -rte_errno;
	return 0;
}

/**
 * Clean up Rx interrupts handler.
 *
 * @param dev
 *   Pointer to Ethernet device.
 */
void
mlx5_rx_intr_vec_disable(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_intr_handle *intr_handle = dev->intr_handle;
	unsigned int i;
	unsigned int rxqs_n = priv->rxqs_n;
	unsigned int n = RTE_MIN(rxqs_n, (uint32_t)RTE_MAX_RXTX_INTR_VEC_ID);

	if (!dev->data->dev_conf.intr_conf.rxq)
		return;
	if (rte_intr_vec_list_index_get(intr_handle, 0) < 0)
		goto free;
	for (i = 0; i != n; ++i) {
		if (rte_intr_vec_list_index_get(intr_handle, i) ==
		    RTE_INTR_VEC_RXTX_OFFSET + RTE_MAX_RXTX_INTR_VEC_ID)
			continue;
		/**
		 * Need to access directly the queue to release the reference
		 * kept in mlx5_rx_intr_vec_enable().
		 */
		mlx5_rxq_deref(dev, i);
	}
free:
	rte_intr_free_epoll_fd(intr_handle);

	rte_intr_vec_list_free(intr_handle);

	rte_intr_nb_efd_set(intr_handle, 0);
}

/**
 *  MLX5 CQ notification .
 *
 *  @param rxq
 *     Pointer to receive queue structure.
 *  @param sq_n_rxq
 *     Sequence number per receive queue .
 */
static inline void
mlx5_arm_cq(struct mlx5_rxq_data *rxq, int sq_n_rxq)
{
	int sq_n = 0;
	uint32_t doorbell_hi;
	uint64_t doorbell;

	sq_n = sq_n_rxq & MLX5_CQ_SQN_MASK;
	doorbell_hi = sq_n << MLX5_CQ_SQN_OFFSET | (rxq->cq_ci & MLX5_CI_MASK);
	doorbell = (uint64_t)doorbell_hi << 32;
	doorbell |= rxq->cqn;
	mlx5_doorbell_ring(&rxq->uar_data, rte_cpu_to_be_64(doorbell),
			   doorbell_hi, &rxq->cq_db[MLX5_CQ_ARM_DB], 0);
}

/**
 * DPDK callback for Rx queue interrupt enable.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param rx_queue_id
 *   Rx queue number.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_rx_intr_enable(struct rte_eth_dev *dev, uint16_t rx_queue_id)
{
	struct mlx5_rxq_priv *rxq = mlx5_rxq_get(dev, rx_queue_id);
	if (!rxq)
		goto error;
	if (rxq->ctrl->irq) {
		if (!rxq->ctrl->obj)
			goto error;
		mlx5_arm_cq(&rxq->ctrl->rxq, rxq->ctrl->rxq.cq_arm_sn);
	}
	return 0;
error:
	rte_errno = EINVAL;
	return -rte_errno;
}

/**
 * DPDK callback for Rx queue interrupt disable.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param rx_queue_id
 *   Rx queue number.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_rx_intr_disable(struct rte_eth_dev *dev, uint16_t rx_queue_id)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_rxq_priv *rxq = mlx5_rxq_get(dev, rx_queue_id);
	int ret = 0;

	if (!rxq) {
		rte_errno = EINVAL;
		return -rte_errno;
	}
	if (!rxq->ctrl->obj)
		goto error;
	if (rxq->ctrl->irq) {
		ret = priv->obj_ops.rxq_event_get(rxq->ctrl->obj);
		if (ret < 0)
			goto error;
		rxq->ctrl->rxq.cq_arm_sn++;
	}
	return 0;
error:
	/**
	 * The ret variable may be EAGAIN which means the get_event function was
	 * called before receiving one.
	 */
	if (ret < 0)
		rte_errno = errno;
	else
		rte_errno = EINVAL;
	if (rte_errno != EAGAIN)
		DRV_LOG(WARNING, "port %u unable to disable interrupt on Rx queue %d",
			dev->data->port_id, rx_queue_id);
	return -rte_errno;
}

/**
 * Verify the Rx queue objects list is empty
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   The number of objects not released.
 */
int
mlx5_rxq_obj_verify(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	int ret = 0;
	struct mlx5_rxq_obj *rxq_obj;

	LIST_FOREACH(rxq_obj, &priv->rxqsobj, next) {
		if (rxq_obj->rxq_ctrl == NULL)
			continue;
		if (rxq_obj->rxq_ctrl->rxq.shared &&
		    !LIST_EMPTY(&rxq_obj->rxq_ctrl->owners))
			continue;
		DRV_LOG(DEBUG, "port %u Rx queue %u still referenced",
			dev->data->port_id, rxq_obj->rxq_ctrl->rxq.idx);
		++ret;
	}
	return ret;
}

/**
 * Callback function to initialize mbufs for Multi-Packet RQ.
 */
static inline void
mlx5_mprq_buf_init(struct rte_mempool *mp, void *opaque_arg,
		    void *_m, unsigned int i __rte_unused)
{
	struct mlx5_mprq_buf *buf = _m;
	struct rte_mbuf_ext_shared_info *shinfo;
	unsigned int strd_n = (unsigned int)(uintptr_t)opaque_arg;
	unsigned int j;

	memset(_m, 0, sizeof(*buf));
	buf->mp = mp;
	__atomic_store_n(&buf->refcnt, 1, __ATOMIC_RELAXED);
	for (j = 0; j != strd_n; ++j) {
		shinfo = &buf->shinfos[j];
		shinfo->free_cb = mlx5_mprq_buf_free_cb;
		shinfo->fcb_opaque = buf;
	}
}

/**
 * Free mempool of Multi-Packet RQ.
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   0 on success, negative errno value on failure.
 */
int
mlx5_mprq_free_mp(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_mempool *mp = priv->mprq_mp;
	unsigned int i;

	if (mp == NULL)
		return 0;
	DRV_LOG(DEBUG, "port %u freeing mempool (%s) for Multi-Packet RQ",
		dev->data->port_id, mp->name);
	/*
	 * If a buffer in the pool has been externally attached to a mbuf and it
	 * is still in use by application, destroying the Rx queue can spoil
	 * the packet. It is unlikely to happen but if application dynamically
	 * creates and destroys with holding Rx packets, this can happen.
	 *
	 * TODO: It is unavoidable for now because the mempool for Multi-Packet
	 * RQ isn't provided by application but managed by PMD.
	 */
	if (!rte_mempool_full(mp)) {
		DRV_LOG(ERR,
			"port %u mempool for Multi-Packet RQ is still in use",
			dev->data->port_id);
		rte_errno = EBUSY;
		return -rte_errno;
	}
	rte_mempool_free(mp);
	/* Unset mempool for each Rx queue. */
	for (i = 0; i != priv->rxqs_n; ++i) {
		struct mlx5_rxq_data *rxq = mlx5_rxq_data_get(dev, i);

		if (rxq == NULL)
			continue;
		rxq->mprq_mp = NULL;
	}
	priv->mprq_mp = NULL;
	return 0;
}

/**
 * Allocate a mempool for Multi-Packet RQ. All configured Rx queues share the
 * mempool. If already allocated, reuse it if there're enough elements.
 * Otherwise, resize it.
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   0 on success, negative errno value on failure.
 */
int
mlx5_mprq_alloc_mp(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_mempool *mp = priv->mprq_mp;
	char name[RTE_MEMPOOL_NAMESIZE];
	unsigned int desc = 0;
	unsigned int buf_len;
	unsigned int obj_num;
	unsigned int obj_size;
	unsigned int log_strd_num = 0;
	unsigned int log_strd_sz = 0;
	unsigned int i;
	unsigned int n_ibv = 0;
	int ret;

	if (!mlx5_mprq_enabled(dev))
		return 0;
	/* Count the total number of descriptors configured. */
	for (i = 0; i != priv->rxqs_n; ++i) {
		struct mlx5_rxq_ctrl *rxq_ctrl = mlx5_rxq_ctrl_get(dev, i);
		struct mlx5_rxq_data *rxq;

		if (rxq_ctrl == NULL || rxq_ctrl->is_hairpin)
			continue;
		rxq = &rxq_ctrl->rxq;
		n_ibv++;
		desc += 1 << rxq->elts_n;
		/* Get the max number of strides. */
		if (log_strd_num < rxq->log_strd_num)
			log_strd_num = rxq->log_strd_num;
		/* Get the max size of a stride. */
		if (log_strd_sz < rxq->log_strd_sz)
			log_strd_sz = rxq->log_strd_sz;
	}
	MLX5_ASSERT(log_strd_num && log_strd_sz);
	buf_len = RTE_BIT32(log_strd_num) * RTE_BIT32(log_strd_sz);
	obj_size = sizeof(struct mlx5_mprq_buf) + buf_len +
		   RTE_BIT32(log_strd_num) *
		   sizeof(struct rte_mbuf_ext_shared_info) +
		   RTE_PKTMBUF_HEADROOM;
	/*
	 * Received packets can be either memcpy'd or externally referenced. In
	 * case that the packet is attached to an mbuf as an external buffer, as
	 * it isn't possible to predict how the buffers will be queued by
	 * application, there's no option to exactly pre-allocate needed buffers
	 * in advance but to speculatively prepares enough buffers.
	 *
	 * In the data path, if this Mempool is depleted, PMD will try to memcpy
	 * received packets to buffers provided by application (rxq->mp) until
	 * this Mempool gets available again.
	 */
	desc *= 4;
	obj_num = desc + MLX5_MPRQ_MP_CACHE_SZ * n_ibv;
	/*
	 * rte_mempool_create_empty() has sanity check to refuse large cache
	 * size compared to the number of elements.
	 * CACHE_FLUSHTHRESH_MULTIPLIER is defined in a C file, so using a
	 * constant number 2 instead.
	 */
	obj_num = RTE_MAX(obj_num, MLX5_MPRQ_MP_CACHE_SZ * 2);
	/* Check a mempool is already allocated and if it can be resued. */
	if (mp != NULL && mp->elt_size >= obj_size && mp->size >= obj_num) {
		DRV_LOG(DEBUG, "port %u mempool %s is being reused",
			dev->data->port_id, mp->name);
		/* Reuse. */
		goto exit;
	} else if (mp != NULL) {
		DRV_LOG(DEBUG, "port %u mempool %s should be resized, freeing it",
			dev->data->port_id, mp->name);
		/*
		 * If failed to free, which means it may be still in use, no way
		 * but to keep using the existing one. On buffer underrun,
		 * packets will be memcpy'd instead of external buffer
		 * attachment.
		 */
		if (mlx5_mprq_free_mp(dev)) {
			if (mp->elt_size >= obj_size)
				goto exit;
			else
				return -rte_errno;
		}
	}
	snprintf(name, sizeof(name), "port-%u-mprq", dev->data->port_id);
	mp = rte_mempool_create(name, obj_num, obj_size, MLX5_MPRQ_MP_CACHE_SZ,
				0, NULL, NULL, mlx5_mprq_buf_init,
				(void *)((uintptr_t)1 << log_strd_num),
				dev->device->numa_node, 0);
	if (mp == NULL) {
		DRV_LOG(ERR,
			"port %u failed to allocate a mempool for"
			" Multi-Packet RQ, count=%u, size=%u",
			dev->data->port_id, obj_num, obj_size);
		rte_errno = ENOMEM;
		return -rte_errno;
	}
	ret = mlx5_mr_mempool_register(priv->sh->cdev, mp, false);
	if (ret < 0 && rte_errno != EEXIST) {
		ret = rte_errno;
		DRV_LOG(ERR, "port %u failed to register a mempool for Multi-Packet RQ",
			dev->data->port_id);
		rte_mempool_free(mp);
		rte_errno = ret;
		return -rte_errno;
	}
	priv->mprq_mp = mp;
exit:
	/* Set mempool for each Rx queue. */
	for (i = 0; i != priv->rxqs_n; ++i) {
		struct mlx5_rxq_ctrl *rxq_ctrl = mlx5_rxq_ctrl_get(dev, i);

		if (rxq_ctrl == NULL || rxq_ctrl->is_hairpin)
			continue;
		rxq_ctrl->rxq.mprq_mp = mp;
	}
	DRV_LOG(INFO, "port %u Multi-Packet RQ is configured",
		dev->data->port_id);
	return 0;
}

#define MLX5_MAX_TCP_HDR_OFFSET ((unsigned int)(sizeof(struct rte_ether_hdr) + \
					sizeof(struct rte_vlan_hdr) * 2 + \
					sizeof(struct rte_ipv6_hdr)))
#define MAX_TCP_OPTION_SIZE 40u
#define MLX5_MAX_LRO_HEADER_FIX ((unsigned int)(MLX5_MAX_TCP_HDR_OFFSET + \
				 sizeof(struct rte_tcp_hdr) + \
				 MAX_TCP_OPTION_SIZE))

/**
 * Adjust the maximum LRO massage size.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param idx
 *   RX queue index.
 * @param max_lro_size
 *   The maximum size for LRO packet.
 */
static void
mlx5_max_lro_msg_size_adjust(struct rte_eth_dev *dev, uint16_t idx,
			     uint32_t max_lro_size)
{
	struct mlx5_priv *priv = dev->data->dev_private;

	if (priv->sh->cdev->config.hca_attr.lro_max_msg_sz_mode ==
	    MLX5_LRO_MAX_MSG_SIZE_START_FROM_L4 && max_lro_size >
	    MLX5_MAX_TCP_HDR_OFFSET)
		max_lro_size -= MLX5_MAX_TCP_HDR_OFFSET;
	max_lro_size = RTE_MIN(max_lro_size, MLX5_MAX_LRO_SIZE);
	if (priv->max_lro_msg_size)
		priv->max_lro_msg_size =
			RTE_MIN((uint32_t)priv->max_lro_msg_size, max_lro_size);
	else
		priv->max_lro_msg_size = max_lro_size;
	DRV_LOG(DEBUG,
		"port %u Rx Queue %u max LRO message size adjusted to %u bytes",
		dev->data->port_id, idx, priv->max_lro_msg_size);
}

/**
 * Prepare both size and number of stride for Multi-Packet RQ.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param idx
 *   RX queue index.
 * @param desc
 *   Number of descriptors to configure in queue.
 * @param rx_seg_en
 *   Indicator if Rx segment enables, if so Multi-Packet RQ doesn't enable.
 * @param min_mbuf_size
 *   Non scatter min mbuf size, max_rx_pktlen plus overhead.
 * @param actual_log_stride_num
 *   Log number of strides to configure for this queue.
 * @param actual_log_stride_size
 *   Log stride size to configure for this queue.
 * @param is_extmem
 *   Is external pinned memory pool used.
 * @return
 *   0 if Multi-Packet RQ is supported, otherwise -1.
 */
static int
mlx5_mprq_prepare(struct rte_eth_dev *dev, uint16_t idx, uint16_t desc,
		  bool rx_seg_en, uint32_t min_mbuf_size,
		  uint32_t *actual_log_stride_num,
		  uint32_t *actual_log_stride_size,
		  bool is_extmem)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_port_config *config = &priv->config;
	struct mlx5_dev_cap *dev_cap = &priv->sh->dev_cap;
	uint32_t log_min_stride_num = dev_cap->mprq.log_min_stride_num;
	uint32_t log_max_stride_num = dev_cap->mprq.log_max_stride_num;
	uint32_t log_def_stride_num =
			RTE_MIN(RTE_MAX(MLX5_MPRQ_DEFAULT_LOG_STRIDE_NUM,
					log_min_stride_num),
				log_max_stride_num);
	uint32_t log_min_stride_size = dev_cap->mprq.log_min_stride_size;
	uint32_t log_max_stride_size = dev_cap->mprq.log_max_stride_size;
	uint32_t log_def_stride_size =
			RTE_MIN(RTE_MAX(MLX5_MPRQ_DEFAULT_LOG_STRIDE_SIZE,
					log_min_stride_size),
				log_max_stride_size);
	uint32_t log_stride_wqe_size;

	if (mlx5_check_mprq_support(dev) != 1 || rx_seg_en || is_extmem)
		goto unsupport;
	/* Checks if chosen number of strides is in supported range. */
	if (config->mprq.log_stride_num > log_max_stride_num ||
	    config->mprq.log_stride_num < log_min_stride_num) {
		*actual_log_stride_num = log_def_stride_num;
		DRV_LOG(WARNING,
			"Port %u Rx queue %u number of strides for Multi-Packet RQ is out of range, setting default value (%u)",
			dev->data->port_id, idx, RTE_BIT32(log_def_stride_num));
	} else {
		*actual_log_stride_num = config->mprq.log_stride_num;
	}
	/* Checks if chosen size of stride is in supported range. */
	if (config->mprq.log_stride_size != (uint32_t)MLX5_ARG_UNSET) {
		if (config->mprq.log_stride_size > log_max_stride_size ||
			config->mprq.log_stride_size < log_min_stride_size) {
			*actual_log_stride_size = log_def_stride_size;
			DRV_LOG(WARNING,
				"Port %u Rx queue %u size of a stride for Multi-Packet RQ is out of range, setting default value (%u)",
				dev->data->port_id, idx,
				RTE_BIT32(log_def_stride_size));
		} else {
			*actual_log_stride_size = config->mprq.log_stride_size;
		}
	} else {
		/* Make the stride fit the mbuf size by default. */
		if (min_mbuf_size <= RTE_BIT32(log_max_stride_size)) {
			DRV_LOG(WARNING,
				"Port %u Rx queue %u size of a stride for Multi-Packet RQ is adjusted to match the mbuf size (%u)",
				dev->data->port_id, idx, min_mbuf_size);
			*actual_log_stride_size = log2above(min_mbuf_size);
		} else {
			goto unsupport;
		}
	}
	/* Make sure the stride size is greater than the headroom. */
	if (RTE_BIT32(*actual_log_stride_size) < RTE_PKTMBUF_HEADROOM) {
		if (RTE_BIT32(log_max_stride_size) > RTE_PKTMBUF_HEADROOM) {
			DRV_LOG(WARNING,
				"Port %u Rx queue %u size of a stride for Multi-Packet RQ is adjusted to accommodate the headroom (%u)",
				dev->data->port_id, idx, RTE_PKTMBUF_HEADROOM);
			*actual_log_stride_size = log2above(RTE_PKTMBUF_HEADROOM);
		} else {
			goto unsupport;
		}
	}
	log_stride_wqe_size = *actual_log_stride_num + *actual_log_stride_size;
	/* Check if WQE buffer size is supported by hardware. */
	if (log_stride_wqe_size < dev_cap->mprq.log_min_stride_wqe_size) {
		*actual_log_stride_num = log_def_stride_num;
		*actual_log_stride_size = log_def_stride_size;
		DRV_LOG(WARNING,
			"Port %u Rx queue %u size of WQE buffer for Multi-Packet RQ is too small, setting default values (stride_num_n=%u, stride_size_n=%u)",
			dev->data->port_id, idx, RTE_BIT32(log_def_stride_num),
			RTE_BIT32(log_def_stride_size));
		log_stride_wqe_size = log_def_stride_num + log_def_stride_size;
	}
	MLX5_ASSERT(log_stride_wqe_size >=
		    dev_cap->mprq.log_min_stride_wqe_size);
	if (desc <= RTE_BIT32(*actual_log_stride_num))
		goto unsupport;
	if (min_mbuf_size > RTE_BIT32(log_stride_wqe_size)) {
		DRV_LOG(WARNING, "Port %u Rx queue %u "
			"Multi-Packet RQ is unsupported, WQE buffer size (%u) "
			"is smaller than min mbuf size (%u)",
			dev->data->port_id, idx, RTE_BIT32(log_stride_wqe_size),
			min_mbuf_size);
		goto unsupport;
	}
	DRV_LOG(DEBUG, "Port %u Rx queue %u "
		"Multi-Packet RQ is enabled strd_num_n = %u, strd_sz_n = %u",
		dev->data->port_id, idx, RTE_BIT32(*actual_log_stride_num),
		RTE_BIT32(*actual_log_stride_size));
	return 0;
unsupport:
	if (config->mprq.enabled)
		DRV_LOG(WARNING,
			"Port %u MPRQ is requested but cannot be enabled\n"
			" (requested: pkt_sz = %u, desc_num = %u,"
			" rxq_num = %u, stride_sz = %u, stride_num = %u\n"
			"  supported: min_rxqs_num = %u, min_buf_wqe_sz = %u"
			" min_stride_sz = %u, max_stride_sz = %u).\n"
			"Rx segment is %senabled. External mempool is %sused.",
			dev->data->port_id, min_mbuf_size, desc, priv->rxqs_n,
			config->mprq.log_stride_size == (uint32_t)MLX5_ARG_UNSET ?
			RTE_BIT32(MLX5_MPRQ_DEFAULT_LOG_STRIDE_SIZE) :
			RTE_BIT32(config->mprq.log_stride_size),
			RTE_BIT32(config->mprq.log_stride_num),
			config->mprq.min_rxqs_num,
			RTE_BIT32(dev_cap->mprq.log_min_stride_wqe_size),
			RTE_BIT32(dev_cap->mprq.log_min_stride_size),
			RTE_BIT32(dev_cap->mprq.log_max_stride_size),
			rx_seg_en ? "" : "not ", is_extmem ? "" : "not ");
	return -1;
}

/**
 * Create a DPDK Rx queue.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param idx
 *   RX queue index.
 * @param desc
 *   Number of descriptors to configure in queue.
 * @param socket
 *   NUMA socket on which memory must be allocated.
 *
 * @return
 *   A DPDK queue object on success, NULL otherwise and rte_errno is set.
 */
struct mlx5_rxq_ctrl *
mlx5_rxq_new(struct rte_eth_dev *dev, uint16_t idx, uint16_t desc,
	     unsigned int socket, const struct rte_eth_rxconf *conf,
	     const struct rte_eth_rxseg_split *rx_seg, uint16_t n_seg,
	     bool is_extmem)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_rxq_ctrl *tmpl;
	unsigned int mb_len = rte_pktmbuf_data_room_size(rx_seg[0].mp);
	struct mlx5_port_config *config = &priv->config;
	uint64_t offloads = conf->offloads |
			   dev->data->dev_conf.rxmode.offloads;
	unsigned int lro_on_queue = !!(offloads & RTE_ETH_RX_OFFLOAD_TCP_LRO);
	unsigned int max_rx_pktlen = lro_on_queue ?
			dev->data->dev_conf.rxmode.max_lro_pkt_size :
			dev->data->mtu + (unsigned int)RTE_ETHER_HDR_LEN +
				RTE_ETHER_CRC_LEN;
	unsigned int non_scatter_min_mbuf_size = max_rx_pktlen +
							RTE_PKTMBUF_HEADROOM;
	unsigned int max_lro_size = 0;
	unsigned int first_mb_free_size = mb_len - RTE_PKTMBUF_HEADROOM;
	uint32_t mprq_log_actual_stride_num = 0;
	uint32_t mprq_log_actual_stride_size = 0;
	bool rx_seg_en = n_seg != 1 || rx_seg[0].offset || rx_seg[0].length;
	const int mprq_en = !mlx5_mprq_prepare(dev, idx, desc, rx_seg_en,
					       non_scatter_min_mbuf_size,
					       &mprq_log_actual_stride_num,
					       &mprq_log_actual_stride_size,
					       is_extmem);
	/*
	 * Always allocate extra slots, even if eventually
	 * the vector Rx will not be used.
	 */
	uint16_t desc_n = desc + config->rx_vec_en * MLX5_VPMD_DESCS_PER_LOOP;
	size_t alloc_size = sizeof(*tmpl) + desc_n * sizeof(struct rte_mbuf *);
	const struct rte_eth_rxseg_split *qs_seg = rx_seg;
	unsigned int tail_len;

	if (mprq_en) {
		/* Trim the number of descs needed. */
		desc >>= mprq_log_actual_stride_num;
		alloc_size += desc * sizeof(struct mlx5_mprq_buf *);
	}
	tmpl = mlx5_malloc(MLX5_MEM_RTE | MLX5_MEM_ZERO, alloc_size, 0, socket);
	if (!tmpl) {
		rte_errno = ENOMEM;
		return NULL;
	}
	LIST_INIT(&tmpl->owners);
	MLX5_ASSERT(n_seg && n_seg <= MLX5_MAX_RXQ_NSEG);
	/*
	 * Save the original segment configuration in the shared queue
	 * descriptor for the later check on the sibling queue creation.
	 */
	tmpl->rxseg_n = n_seg;
	rte_memcpy(tmpl->rxseg, qs_seg,
		   sizeof(struct rte_eth_rxseg_split) * n_seg);
	/*
	 * Build the array of actual buffer offsets and lengths.
	 * Pad with the buffers from the last memory pool if
	 * needed to handle max size packets, replace zero length
	 * with the buffer length from the pool.
	 */
	tail_len = max_rx_pktlen;
	do {
		struct mlx5_eth_rxseg *hw_seg =
					&tmpl->rxq.rxseg[tmpl->rxq.rxseg_n];
		uint32_t buf_len, offset, seg_len;

		/*
		 * For the buffers beyond descriptions offset is zero,
		 * the first buffer contains head room.
		 */
		buf_len = rte_pktmbuf_data_room_size(qs_seg->mp);
		offset = (tmpl->rxq.rxseg_n >= n_seg ? 0 : qs_seg->offset) +
			 (tmpl->rxq.rxseg_n ? 0 : RTE_PKTMBUF_HEADROOM);
		/*
		 * For the buffers beyond descriptions the length is
		 * pool buffer length, zero lengths are replaced with
		 * pool buffer length either.
		 */
		seg_len = tmpl->rxq.rxseg_n >= n_seg ? buf_len :
						       qs_seg->length ?
						       qs_seg->length :
						       (buf_len - offset);
		/* Check is done in long int, now overflows. */
		if (buf_len < seg_len + offset) {
			DRV_LOG(ERR, "port %u Rx queue %u: Split offset/length "
				     "%u/%u can't be satisfied",
				     dev->data->port_id, idx,
				     qs_seg->length, qs_seg->offset);
			rte_errno = EINVAL;
			goto error;
		}
		if (seg_len > tail_len)
			seg_len = buf_len - offset;
		if (++tmpl->rxq.rxseg_n > MLX5_MAX_RXQ_NSEG) {
			DRV_LOG(ERR,
				"port %u too many SGEs (%u) needed to handle"
				" requested maximum packet size %u, the maximum"
				" supported are %u", dev->data->port_id,
				tmpl->rxq.rxseg_n, max_rx_pktlen,
				MLX5_MAX_RXQ_NSEG);
			rte_errno = ENOTSUP;
			goto error;
		}
		/* Build the actual scattering element in the queue object. */
		hw_seg->mp = qs_seg->mp;
		MLX5_ASSERT(offset <= UINT16_MAX);
		MLX5_ASSERT(seg_len <= UINT16_MAX);
		hw_seg->offset = (uint16_t)offset;
		hw_seg->length = (uint16_t)seg_len;
		/*
		 * Advance the segment descriptor, the padding is the based
		 * on the attributes of the last descriptor.
		 */
		if (tmpl->rxq.rxseg_n < n_seg)
			qs_seg++;
		tail_len -= RTE_MIN(tail_len, seg_len);
	} while (tail_len || !rte_is_power_of_2(tmpl->rxq.rxseg_n));
	MLX5_ASSERT(tmpl->rxq.rxseg_n &&
		    tmpl->rxq.rxseg_n <= MLX5_MAX_RXQ_NSEG);
	if (tmpl->rxq.rxseg_n > 1 && !(offloads & RTE_ETH_RX_OFFLOAD_SCATTER)) {
		DRV_LOG(ERR, "port %u Rx queue %u: Scatter offload is not"
			" configured and no enough mbuf space(%u) to contain "
			"the maximum RX packet length(%u) with head-room(%u)",
			dev->data->port_id, idx, mb_len, max_rx_pktlen,
			RTE_PKTMBUF_HEADROOM);
		rte_errno = ENOSPC;
		goto error;
	}
	tmpl->is_hairpin = false;
	if (mlx5_mr_ctrl_init(&tmpl->rxq.mr_ctrl,
			      &priv->sh->cdev->mr_scache.dev_gen, socket)) {
		/* rte_errno is already set. */
		goto error;
	}
	tmpl->socket = socket;
	if (dev->data->dev_conf.intr_conf.rxq)
		tmpl->irq = 1;
	if (mprq_en) {
		/* TODO: Rx scatter isn't supported yet. */
		tmpl->rxq.sges_n = 0;
		tmpl->rxq.log_strd_num = mprq_log_actual_stride_num;
		tmpl->rxq.log_strd_sz = mprq_log_actual_stride_size;
		tmpl->rxq.strd_shift_en = MLX5_MPRQ_TWO_BYTE_SHIFT;
		tmpl->rxq.strd_scatter_en =
				!!(offloads & RTE_ETH_RX_OFFLOAD_SCATTER);
		tmpl->rxq.mprq_max_memcpy_len = RTE_MIN(first_mb_free_size,
				config->mprq.max_memcpy_len);
		max_lro_size = RTE_MIN(max_rx_pktlen,
				       RTE_BIT32(tmpl->rxq.log_strd_num) *
				       RTE_BIT32(tmpl->rxq.log_strd_sz));
	} else if (tmpl->rxq.rxseg_n == 1) {
		MLX5_ASSERT(max_rx_pktlen <= first_mb_free_size);
		tmpl->rxq.sges_n = 0;
		max_lro_size = max_rx_pktlen;
	} else if (offloads & RTE_ETH_RX_OFFLOAD_SCATTER) {
		unsigned int sges_n;

		if (lro_on_queue && first_mb_free_size <
		    MLX5_MAX_LRO_HEADER_FIX) {
			DRV_LOG(ERR, "Not enough space in the first segment(%u)"
				" to include the max header size(%u) for LRO",
				first_mb_free_size, MLX5_MAX_LRO_HEADER_FIX);
			rte_errno = ENOTSUP;
			goto error;
		}
		/*
		 * Determine the number of SGEs needed for a full packet
		 * and round it to the next power of two.
		 */
		sges_n = log2above(tmpl->rxq.rxseg_n);
		if (sges_n > MLX5_MAX_LOG_RQ_SEGS) {
			DRV_LOG(ERR,
				"port %u too many SGEs (%u) needed to handle"
				" requested maximum packet size %u, the maximum"
				" supported are %u", dev->data->port_id,
				1 << sges_n, max_rx_pktlen,
				1u << MLX5_MAX_LOG_RQ_SEGS);
			rte_errno = ENOTSUP;
			goto error;
		}
		tmpl->rxq.sges_n = sges_n;
		max_lro_size = max_rx_pktlen;
	}
	DRV_LOG(DEBUG, "port %u maximum number of segments per packet: %u",
		dev->data->port_id, 1 << tmpl->rxq.sges_n);
	if (desc % (1 << tmpl->rxq.sges_n)) {
		DRV_LOG(ERR,
			"port %u number of Rx queue descriptors (%u) is not a"
			" multiple of SGEs per packet (%u)",
			dev->data->port_id,
			desc,
			1 << tmpl->rxq.sges_n);
		rte_errno = EINVAL;
		goto error;
	}
	mlx5_max_lro_msg_size_adjust(dev, idx, max_lro_size);
	/* Toggle RX checksum offload if hardware supports it. */
	tmpl->rxq.csum = !!(offloads & RTE_ETH_RX_OFFLOAD_CHECKSUM);
	/* Configure Rx timestamp. */
	tmpl->rxq.hw_timestamp = !!(offloads & RTE_ETH_RX_OFFLOAD_TIMESTAMP);
	tmpl->rxq.timestamp_rx_flag = 0;
	if (tmpl->rxq.hw_timestamp && rte_mbuf_dyn_rx_timestamp_register(
			&tmpl->rxq.timestamp_offset,
			&tmpl->rxq.timestamp_rx_flag) != 0) {
		DRV_LOG(ERR, "Cannot register Rx timestamp field/flag");
		goto error;
	}
	/* Configure VLAN stripping. */
	tmpl->rxq.vlan_strip = !!(offloads & RTE_ETH_RX_OFFLOAD_VLAN_STRIP);
	/* By default, FCS (CRC) is stripped by hardware. */
	tmpl->rxq.crc_present = 0;
	tmpl->rxq.lro = lro_on_queue;
	if (offloads & RTE_ETH_RX_OFFLOAD_KEEP_CRC) {
		if (priv->sh->config.hw_fcs_strip) {
			/*
			 * RQs used for LRO-enabled TIRs should not be
			 * configured to scatter the FCS.
			 */
			if (lro_on_queue)
				DRV_LOG(WARNING,
					"port %u CRC stripping has been "
					"disabled but will still be performed "
					"by hardware, because LRO is enabled",
					dev->data->port_id);
			else
				tmpl->rxq.crc_present = 1;
		} else {
			DRV_LOG(WARNING,
				"port %u CRC stripping has been disabled but will"
				" still be performed by hardware, make sure MLNX_OFED"
				" and firmware are up to date",
				dev->data->port_id);
		}
	}
	DRV_LOG(DEBUG,
		"port %u CRC stripping is %s, %u bytes will be subtracted from"
		" incoming frames to hide it",
		dev->data->port_id,
		tmpl->rxq.crc_present ? "disabled" : "enabled",
		tmpl->rxq.crc_present << 2);
	tmpl->rxq.rss_hash = !!priv->rss_conf.rss_hf &&
		(!!(dev->data->dev_conf.rxmode.mq_mode & RTE_ETH_MQ_RX_RSS));
	/* Save port ID. */
	tmpl->rxq.port_id = dev->data->port_id;
	tmpl->sh = priv->sh;
	tmpl->rxq.mp = rx_seg[0].mp;
	tmpl->rxq.elts_n = log2above(desc);
	tmpl->rxq.rq_repl_thresh = MLX5_VPMD_RXQ_RPLNSH_THRESH(desc_n);
	tmpl->rxq.elts = (struct rte_mbuf *(*)[desc_n])(tmpl + 1);
	tmpl->rxq.mprq_bufs =
		(struct mlx5_mprq_buf *(*)[desc])(*tmpl->rxq.elts + desc_n);
	tmpl->rxq.idx = idx;
	if (conf->share_group > 0) {
		tmpl->rxq.shared = 1;
		tmpl->share_group = conf->share_group;
		tmpl->share_qid = conf->share_qid;
		LIST_INSERT_HEAD(&priv->sh->shared_rxqs, tmpl, share_entry);
	}
	LIST_INSERT_HEAD(&priv->rxqsctrl, tmpl, next);
	return tmpl;
error:
	mlx5_mr_btree_free(&tmpl->rxq.mr_ctrl.cache_bh);
	mlx5_free(tmpl);
	return NULL;
}

/**
 * Create a DPDK Rx hairpin queue.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param rxq
 *   RX queue.
 * @param desc
 *   Number of descriptors to configure in queue.
 * @param hairpin_conf
 *   The hairpin binding configuration.
 *
 * @return
 *   A DPDK queue object on success, NULL otherwise and rte_errno is set.
 */
struct mlx5_rxq_ctrl *
mlx5_rxq_hairpin_new(struct rte_eth_dev *dev, struct mlx5_rxq_priv *rxq,
		     uint16_t desc,
		     const struct rte_eth_hairpin_conf *hairpin_conf)
{
	uint16_t idx = rxq->idx;
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_rxq_ctrl *tmpl;

	tmpl = mlx5_malloc(MLX5_MEM_RTE | MLX5_MEM_ZERO, sizeof(*tmpl), 0,
			   SOCKET_ID_ANY);
	if (!tmpl) {
		rte_errno = ENOMEM;
		return NULL;
	}
	LIST_INIT(&tmpl->owners);
	rxq->ctrl = tmpl;
	LIST_INSERT_HEAD(&tmpl->owners, rxq, owner_entry);
	tmpl->is_hairpin = true;
	tmpl->socket = SOCKET_ID_ANY;
	tmpl->rxq.rss_hash = 0;
	tmpl->rxq.port_id = dev->data->port_id;
	tmpl->sh = priv->sh;
	tmpl->rxq.mp = NULL;
	tmpl->rxq.elts_n = log2above(desc);
	tmpl->rxq.elts = NULL;
	tmpl->rxq.mr_ctrl.cache_bh = (struct mlx5_mr_btree) { 0 };
	tmpl->rxq.idx = idx;
	rxq->hairpin_conf = *hairpin_conf;
	mlx5_rxq_ref(dev, idx);
	LIST_INSERT_HEAD(&priv->rxqsctrl, tmpl, next);
	return tmpl;
}

/**
 * Increase Rx queue reference count.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param idx
 *   RX queue index.
 *
 * @return
 *   A pointer to the queue if it exists, NULL otherwise.
 */
struct mlx5_rxq_priv *
mlx5_rxq_ref(struct rte_eth_dev *dev, uint16_t idx)
{
	struct mlx5_rxq_priv *rxq = mlx5_rxq_get(dev, idx);

	if (rxq != NULL)
		__atomic_fetch_add(&rxq->refcnt, 1, __ATOMIC_RELAXED);
	return rxq;
}

/**
 * Dereference a Rx queue.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param idx
 *   RX queue index.
 *
 * @return
 *   Updated reference count.
 */
uint32_t
mlx5_rxq_deref(struct rte_eth_dev *dev, uint16_t idx)
{
	struct mlx5_rxq_priv *rxq = mlx5_rxq_get(dev, idx);

	if (rxq == NULL)
		return 0;
	return __atomic_sub_fetch(&rxq->refcnt, 1, __ATOMIC_RELAXED);
}

/**
 * Get a Rx queue.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param idx
 *   RX queue index.
 *
 * @return
 *   A pointer to the queue if it exists, NULL otherwise.
 */
struct mlx5_rxq_priv *
mlx5_rxq_get(struct rte_eth_dev *dev, uint16_t idx)
{
	struct mlx5_priv *priv = dev->data->dev_private;

	if (idx >= priv->rxqs_n)
		return NULL;
	MLX5_ASSERT(priv->rxq_privs != NULL);
	return (*priv->rxq_privs)[idx];
}

/**
 * Get Rx queue shareable control.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param idx
 *   RX queue index.
 *
 * @return
 *   A pointer to the queue control if it exists, NULL otherwise.
 */
struct mlx5_rxq_ctrl *
mlx5_rxq_ctrl_get(struct rte_eth_dev *dev, uint16_t idx)
{
	struct mlx5_rxq_priv *rxq = mlx5_rxq_get(dev, idx);

	return rxq == NULL ? NULL : rxq->ctrl;
}

/**
 * Get Rx queue shareable data.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param idx
 *   RX queue index.
 *
 * @return
 *   A pointer to the queue data if it exists, NULL otherwise.
 */
struct mlx5_rxq_data *
mlx5_rxq_data_get(struct rte_eth_dev *dev, uint16_t idx)
{
	struct mlx5_rxq_priv *rxq = mlx5_rxq_get(dev, idx);

	return rxq == NULL ? NULL : &rxq->ctrl->rxq;
}

/**
 * Increase an external Rx queue reference count.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param idx
 *   External RX queue index.
 *
 * @return
 *   A pointer to the queue if it exists, NULL otherwise.
 */
struct mlx5_external_rxq *
mlx5_ext_rxq_ref(struct rte_eth_dev *dev, uint16_t idx)
{
	struct mlx5_external_rxq *rxq = mlx5_ext_rxq_get(dev, idx);

	__atomic_fetch_add(&rxq->refcnt, 1, __ATOMIC_RELAXED);
	return rxq;
}

/**
 * Decrease an external Rx queue reference count.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param idx
 *   External RX queue index.
 *
 * @return
 *   Updated reference count.
 */
uint32_t
mlx5_ext_rxq_deref(struct rte_eth_dev *dev, uint16_t idx)
{
	struct mlx5_external_rxq *rxq = mlx5_ext_rxq_get(dev, idx);

	return __atomic_sub_fetch(&rxq->refcnt, 1, __ATOMIC_RELAXED);
}

/**
 * Get an external Rx queue.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param idx
 *   External Rx queue index.
 *
 * @return
 *   A pointer to the queue if it exists, NULL otherwise.
 */
struct mlx5_external_rxq *
mlx5_ext_rxq_get(struct rte_eth_dev *dev, uint16_t idx)
{
	struct mlx5_priv *priv = dev->data->dev_private;

	MLX5_ASSERT(mlx5_is_external_rxq(dev, idx));
	return &priv->ext_rxqs[idx - MLX5_EXTERNAL_RX_QUEUE_ID_MIN];
}

/**
 * Dereference a list of Rx queues.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param queues
 *   List of Rx queues to deref.
 * @param queues_n
 *   Number of queues in the array.
 */
static void
mlx5_rxqs_deref(struct rte_eth_dev *dev, uint16_t *queues,
		const uint32_t queues_n)
{
	uint32_t i;

	for (i = 0; i < queues_n; i++) {
		if (mlx5_is_external_rxq(dev, queues[i]))
			claim_nonzero(mlx5_ext_rxq_deref(dev, queues[i]));
		else
			claim_nonzero(mlx5_rxq_deref(dev, queues[i]));
	}
}

/**
 * Increase reference count for list of Rx queues.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param queues
 *   List of Rx queues to ref.
 * @param queues_n
 *   Number of queues in the array.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_rxqs_ref(struct rte_eth_dev *dev, uint16_t *queues,
	      const uint32_t queues_n)
{
	uint32_t i;

	for (i = 0; i != queues_n; ++i) {
		if (mlx5_is_external_rxq(dev, queues[i])) {
			if (mlx5_ext_rxq_ref(dev, queues[i]) == NULL)
				goto error;
		} else {
			if (mlx5_rxq_ref(dev, queues[i]) == NULL)
				goto error;
		}
	}
	return 0;
error:
	mlx5_rxqs_deref(dev, queues, i);
	rte_errno = EINVAL;
	return -rte_errno;
}

/**
 * Release a Rx queue.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param idx
 *   RX queue index.
 *
 * @return
 *   1 while a reference on it exists, 0 when freed.
 */
int
mlx5_rxq_release(struct rte_eth_dev *dev, uint16_t idx)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_rxq_priv *rxq;
	struct mlx5_rxq_ctrl *rxq_ctrl;
	uint32_t refcnt;

	if (priv->rxq_privs == NULL)
		return 0;
	rxq = mlx5_rxq_get(dev, idx);
	if (rxq == NULL || rxq->refcnt == 0)
		return 0;
	rxq_ctrl = rxq->ctrl;
	refcnt = mlx5_rxq_deref(dev, idx);
	if (refcnt > 1) {
		return 1;
	} else if (refcnt == 1) { /* RxQ stopped. */
		priv->obj_ops.rxq_obj_release(rxq);
		if (!rxq_ctrl->started && rxq_ctrl->obj != NULL) {
			LIST_REMOVE(rxq_ctrl->obj, next);
			mlx5_free(rxq_ctrl->obj);
			rxq_ctrl->obj = NULL;
		}
		if (!rxq_ctrl->is_hairpin) {
			if (!rxq_ctrl->started)
				rxq_free_elts(rxq_ctrl);
			dev->data->rx_queue_state[idx] =
					RTE_ETH_QUEUE_STATE_STOPPED;
		}
	} else { /* Refcnt zero, closing device. */
		LIST_REMOVE(rxq_ctrl, next);
		LIST_REMOVE(rxq, owner_entry);
		if (LIST_EMPTY(&rxq_ctrl->owners)) {
			if (!rxq_ctrl->is_hairpin)
				mlx5_mr_btree_free
					(&rxq_ctrl->rxq.mr_ctrl.cache_bh);
			if (rxq_ctrl->rxq.shared)
				LIST_REMOVE(rxq_ctrl, share_entry);
			mlx5_free(rxq_ctrl);
		}
		dev->data->rx_queues[idx] = NULL;
		mlx5_free(rxq);
		(*priv->rxq_privs)[idx] = NULL;
	}
	return 0;
}

/**
 * Verify the Rx Queue list is empty
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   The number of object not released.
 */
int
mlx5_rxq_verify(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_rxq_ctrl *rxq_ctrl;
	int ret = 0;

	LIST_FOREACH(rxq_ctrl, &priv->rxqsctrl, next) {
		DRV_LOG(DEBUG, "port %u Rx Queue %u still referenced",
			dev->data->port_id, rxq_ctrl->rxq.idx);
		++ret;
	}
	return ret;
}

/**
 * Verify the external Rx Queue list is empty.
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   The number of object not released.
 */
int
mlx5_ext_rxq_verify(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_external_rxq *rxq;
	uint32_t i;
	int ret = 0;

	if (priv->ext_rxqs == NULL)
		return 0;

	for (i = MLX5_EXTERNAL_RX_QUEUE_ID_MIN; i <= UINT16_MAX ; ++i) {
		rxq = mlx5_ext_rxq_get(dev, i);
		if (rxq->refcnt < 2)
			continue;
		DRV_LOG(DEBUG, "Port %u external RxQ %u still referenced.",
			dev->data->port_id, i);
		++ret;
	}
	return ret;
}

/**
 * Check whether RxQ type is Hairpin.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param idx
 *   Rx queue index.
 *
 * @return
 *   True if Rx queue type is Hairpin, otherwise False.
 */
bool
mlx5_rxq_is_hairpin(struct rte_eth_dev *dev, uint16_t idx)
{
	struct mlx5_rxq_ctrl *rxq_ctrl;

	if (mlx5_is_external_rxq(dev, idx))
		return false;
	rxq_ctrl = mlx5_rxq_ctrl_get(dev, idx);
	return (rxq_ctrl != NULL && rxq_ctrl->is_hairpin);
}

/*
 * Get a Rx hairpin queue configuration.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param idx
 *   Rx queue index.
 *
 * @return
 *   Pointer to the configuration if a hairpin RX queue, otherwise NULL.
 */
const struct rte_eth_hairpin_conf *
mlx5_rxq_get_hairpin_conf(struct rte_eth_dev *dev, uint16_t idx)
{
	if (mlx5_rxq_is_hairpin(dev, idx)) {
		struct mlx5_rxq_priv *rxq = mlx5_rxq_get(dev, idx);

		return rxq != NULL ? &rxq->hairpin_conf : NULL;
	}
	return NULL;
}

/**
 * Match queues listed in arguments to queues contained in indirection table
 * object.
 *
 * @param ind_tbl
 *   Pointer to indirection table to match.
 * @param queues
 *   Queues to match to queues in indirection table.
 * @param queues_n
 *   Number of queues in the array.
 *
 * @return
 *   1 if all queues in indirection table match 0 otherwise.
 */
static int
mlx5_ind_table_obj_match_queues(const struct mlx5_ind_table_obj *ind_tbl,
				const uint16_t *queues, uint32_t queues_n)
{
	return (ind_tbl->queues_n == queues_n) &&
		(!memcmp(ind_tbl->queues, queues,
			 ind_tbl->queues_n * sizeof(ind_tbl->queues[0])));
}

/**
 * Get an indirection table.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param queues
 *   Queues entering in the indirection table.
 * @param queues_n
 *   Number of queues in the array.
 *
 * @return
 *   An indirection table if found.
 */
struct mlx5_ind_table_obj *
mlx5_ind_table_obj_get(struct rte_eth_dev *dev, const uint16_t *queues,
		       uint32_t queues_n)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_ind_table_obj *ind_tbl;

	rte_rwlock_read_lock(&priv->ind_tbls_lock);
	LIST_FOREACH(ind_tbl, &priv->ind_tbls, next) {
		if ((ind_tbl->queues_n == queues_n) &&
		    (memcmp(ind_tbl->queues, queues,
			    ind_tbl->queues_n * sizeof(ind_tbl->queues[0]))
		     == 0)) {
			__atomic_fetch_add(&ind_tbl->refcnt, 1,
					   __ATOMIC_RELAXED);
			break;
		}
	}
	rte_rwlock_read_unlock(&priv->ind_tbls_lock);
	return ind_tbl;
}

/**
 * Release an indirection table.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param ind_table
 *   Indirection table to release.
 * @param deref_rxqs
 *   If true, then dereference RX queues related to indirection table.
 *   Otherwise, no additional action will be taken.
 *
 * @return
 *   1 while a reference on it exists, 0 when freed.
 */
int
mlx5_ind_table_obj_release(struct rte_eth_dev *dev,
			   struct mlx5_ind_table_obj *ind_tbl,
			   bool deref_rxqs)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	unsigned int ret;

	rte_rwlock_write_lock(&priv->ind_tbls_lock);
	ret = __atomic_sub_fetch(&ind_tbl->refcnt, 1, __ATOMIC_RELAXED);
	if (!ret)
		LIST_REMOVE(ind_tbl, next);
	rte_rwlock_write_unlock(&priv->ind_tbls_lock);
	if (ret)
		return 1;
	priv->obj_ops.ind_table_destroy(ind_tbl);
	if (deref_rxqs)
		mlx5_rxqs_deref(dev, ind_tbl->queues, ind_tbl->queues_n);
	mlx5_free(ind_tbl);
	return 0;
}

/**
 * Verify the Rx Queue list is empty
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   The number of object not released.
 */
int
mlx5_ind_table_obj_verify(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_ind_table_obj *ind_tbl;
	int ret = 0;

	rte_rwlock_read_lock(&priv->ind_tbls_lock);
	LIST_FOREACH(ind_tbl, &priv->ind_tbls, next) {
		DRV_LOG(DEBUG,
			"port %u indirection table obj %p still referenced",
			dev->data->port_id, (void *)ind_tbl);
		++ret;
	}
	rte_rwlock_read_unlock(&priv->ind_tbls_lock);
	return ret;
}

/**
 * Setup an indirection table structure fields.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param ind_table
 *   Indirection table to modify.
 * @param ref_qs
 *   Whether to increment RxQ reference counters.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_ind_table_obj_setup(struct rte_eth_dev *dev,
			 struct mlx5_ind_table_obj *ind_tbl,
			 bool ref_qs)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	uint32_t queues_n = ind_tbl->queues_n;
	int ret;
	const unsigned int n = rte_is_power_of_2(queues_n) ?
			       log2above(queues_n) :
			       log2above(priv->sh->dev_cap.ind_table_max_size);

	if (ref_qs && mlx5_rxqs_ref(dev, ind_tbl->queues, queues_n) < 0) {
		DRV_LOG(DEBUG, "Port %u invalid indirection table queues.",
			dev->data->port_id);
		return -rte_errno;
	}
	ret = priv->obj_ops.ind_table_new(dev, n, ind_tbl);
	if (ret) {
		DRV_LOG(DEBUG, "Port %u cannot create a new indirection table.",
			dev->data->port_id);
		if (ref_qs) {
			int err = rte_errno;

			mlx5_rxqs_deref(dev, ind_tbl->queues, queues_n);
			rte_errno = err;
		}
		return ret;
	}
	__atomic_fetch_add(&ind_tbl->refcnt, 1, __ATOMIC_RELAXED);
	return 0;
}

/**
 * Create an indirection table.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param queues
 *   Queues entering in the indirection table.
 * @param queues_n
 *   Number of queues in the array.
 * @param standalone
 *   Indirection table for Standalone queue.
 * @param ref_qs
 *   Whether to increment RxQ reference counters.
 *
 * @return
 *   The Verbs/DevX object initialized, NULL otherwise and rte_errno is set.
 */
struct mlx5_ind_table_obj *
mlx5_ind_table_obj_new(struct rte_eth_dev *dev, const uint16_t *queues,
		       uint32_t queues_n, bool standalone, bool ref_qs)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_ind_table_obj *ind_tbl;
	int ret;
	uint32_t max_queues_n = priv->rxqs_n > queues_n ? priv->rxqs_n : queues_n;

	/*
	 * Allocate maximum queues for shared action as queue number
	 * maybe modified later.
	 */
	ind_tbl = mlx5_malloc(MLX5_MEM_ZERO, sizeof(*ind_tbl) +
			      (standalone ? max_queues_n : queues_n) *
			      sizeof(uint16_t), 0, SOCKET_ID_ANY);
	if (!ind_tbl) {
		rte_errno = ENOMEM;
		return NULL;
	}
	ind_tbl->queues_n = queues_n;
	ind_tbl->queues = (uint16_t *)(ind_tbl + 1);
	memcpy(ind_tbl->queues, queues, queues_n * sizeof(*queues));
	ret = mlx5_ind_table_obj_setup(dev, ind_tbl, ref_qs);
	if (ret < 0) {
		mlx5_free(ind_tbl);
		return NULL;
	}
	rte_rwlock_write_lock(&priv->ind_tbls_lock);
	if (!standalone)
		LIST_INSERT_HEAD(&priv->ind_tbls, ind_tbl, next);
	else
		LIST_INSERT_HEAD(&priv->standalone_ind_tbls, ind_tbl, next);
	rte_rwlock_write_unlock(&priv->ind_tbls_lock);

	return ind_tbl;
}

static int
mlx5_ind_table_obj_check_standalone(struct rte_eth_dev *dev __rte_unused,
				    struct mlx5_ind_table_obj *ind_tbl)
{
	uint32_t refcnt;

	refcnt = __atomic_load_n(&ind_tbl->refcnt, __ATOMIC_RELAXED);
	if (refcnt <= 1)
		return 0;
	/*
	 * Modification of indirection tables having more than 1
	 * reference is unsupported.
	 */
	DRV_LOG(DEBUG,
		"Port %u cannot modify indirection table %p (refcnt %u > 1).",
		dev->data->port_id, (void *)ind_tbl, refcnt);
	rte_errno = EINVAL;
	return -rte_errno;
}

/**
 * Modify an indirection table.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param ind_table
 *   Indirection table to modify.
 * @param queues
 *   Queues replacement for the indirection table.
 * @param queues_n
 *   Number of queues in the array.
 * @param standalone
 *   Indirection table for Standalone queue.
 * @param ref_new_qs
 *   Whether to increment new RxQ set reference counters.
 * @param deref_old_qs
 *   Whether to decrement old RxQ set reference counters.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_ind_table_obj_modify(struct rte_eth_dev *dev,
			  struct mlx5_ind_table_obj *ind_tbl,
			  uint16_t *queues, const uint32_t queues_n,
			  bool standalone, bool ref_new_qs, bool deref_old_qs)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	int ret;
	const unsigned int n = rte_is_power_of_2(queues_n) ?
			       log2above(queues_n) :
			       log2above(priv->sh->dev_cap.ind_table_max_size);

	MLX5_ASSERT(standalone);
	RTE_SET_USED(standalone);
	if (mlx5_ind_table_obj_check_standalone(dev, ind_tbl) < 0)
		return -rte_errno;
	if (ref_new_qs && mlx5_rxqs_ref(dev, queues, queues_n) < 0) {
		DRV_LOG(DEBUG, "Port %u invalid indirection table queues.",
			dev->data->port_id);
		return -rte_errno;
	}
	MLX5_ASSERT(priv->obj_ops.ind_table_modify);
	ret = priv->obj_ops.ind_table_modify(dev, n, queues, queues_n, ind_tbl);
	if (ret) {
		DRV_LOG(DEBUG, "Port %u cannot modify indirection table.",
			dev->data->port_id);
		if (ref_new_qs) {
			int err = rte_errno;

			mlx5_rxqs_deref(dev, queues, queues_n);
			rte_errno = err;
		}
		return ret;
	}
	if (deref_old_qs)
		mlx5_rxqs_deref(dev, ind_tbl->queues, ind_tbl->queues_n);
	ind_tbl->queues_n = queues_n;
	ind_tbl->queues = queues;
	return 0;
}

/**
 * Attach an indirection table to its queues.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param ind_table
 *   Indirection table to attach.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_ind_table_obj_attach(struct rte_eth_dev *dev,
			  struct mlx5_ind_table_obj *ind_tbl)
{
	int ret;

	ret = mlx5_ind_table_obj_modify(dev, ind_tbl, ind_tbl->queues,
					ind_tbl->queues_n,
					true /* standalone */,
					true /* ref_new_qs */,
					false /* deref_old_qs */);
	if (ret != 0)
		DRV_LOG(ERR, "Port %u could not modify indirect table obj %p",
			dev->data->port_id, (void *)ind_tbl);
	return ret;
}

/**
 * Detach an indirection table from its queues.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param ind_table
 *   Indirection table to detach.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_ind_table_obj_detach(struct rte_eth_dev *dev,
			  struct mlx5_ind_table_obj *ind_tbl)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	const unsigned int n = rte_is_power_of_2(ind_tbl->queues_n) ?
			       log2above(ind_tbl->queues_n) :
			       log2above(priv->sh->dev_cap.ind_table_max_size);
	unsigned int i;
	int ret;

	ret = mlx5_ind_table_obj_check_standalone(dev, ind_tbl);
	if (ret != 0)
		return ret;
	MLX5_ASSERT(priv->obj_ops.ind_table_modify);
	ret = priv->obj_ops.ind_table_modify(dev, n, NULL, 0, ind_tbl);
	if (ret != 0) {
		DRV_LOG(ERR, "Port %u could not modify indirect table obj %p",
			dev->data->port_id, (void *)ind_tbl);
		return ret;
	}
	for (i = 0; i < ind_tbl->queues_n; i++)
		mlx5_rxq_release(dev, ind_tbl->queues[i]);
	return ret;
}

int
mlx5_hrxq_match_cb(void *tool_ctx __rte_unused, struct mlx5_list_entry *entry,
		   void *cb_ctx)
{
	struct mlx5_flow_cb_ctx *ctx = cb_ctx;
	struct mlx5_flow_rss_desc *rss_desc = ctx->data;
	struct mlx5_hrxq *hrxq = container_of(entry, typeof(*hrxq), entry);

	return (hrxq->rss_key_len != rss_desc->key_len ||
	    memcmp(hrxq->rss_key, rss_desc->key, rss_desc->key_len) ||
	    hrxq->hws_flags != rss_desc->hws_flags ||
	    hrxq->hash_fields != rss_desc->hash_fields ||
	    hrxq->ind_table->queues_n != rss_desc->queue_num ||
	    memcmp(hrxq->ind_table->queues, rss_desc->queue,
	    rss_desc->queue_num * sizeof(rss_desc->queue[0])));
}

/**
 * Modify an Rx Hash queue configuration.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param hrxq
 *   Index to Hash Rx queue to modify.
 * @param rss_key
 *   RSS key for the Rx hash queue.
 * @param rss_key_len
 *   RSS key length.
 * @param hash_fields
 *   Verbs protocol hash field to make the RSS on.
 * @param queues
 *   Queues entering in hash queue. In case of empty hash_fields only the
 *   first queue index will be taken for the indirection table.
 * @param queues_n
 *   Number of queues.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_hrxq_modify(struct rte_eth_dev *dev, uint32_t hrxq_idx,
		 const uint8_t *rss_key, uint32_t rss_key_len,
		 uint64_t hash_fields,
		 const uint16_t *queues, uint32_t queues_n)
{
	int err;
	struct mlx5_ind_table_obj *ind_tbl = NULL;
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_hrxq *hrxq =
		mlx5_ipool_get(priv->sh->ipool[MLX5_IPOOL_HRXQ], hrxq_idx);
	bool dev_started = !!dev->data->dev_started;
	int ret;

	if (!hrxq) {
		rte_errno = EINVAL;
		return -rte_errno;
	}
	/* validations */
	if (hrxq->rss_key_len != rss_key_len) {
		/* rss_key_len is fixed size 40 byte & not supposed to change */
		rte_errno = EINVAL;
		return -rte_errno;
	}
	queues_n = hash_fields ? queues_n : 1;
	if (mlx5_ind_table_obj_match_queues(hrxq->ind_table,
					    queues, queues_n)) {
		ind_tbl = hrxq->ind_table;
	} else {
		if (hrxq->standalone) {
			/*
			 * Replacement of indirection table unsupported for
			 * standalone hrxq objects (used by shared RSS).
			 */
			rte_errno = ENOTSUP;
			return -rte_errno;
		}
		ind_tbl = mlx5_ind_table_obj_get(dev, queues, queues_n);
		if (!ind_tbl)
			ind_tbl = mlx5_ind_table_obj_new(dev, queues, queues_n,
							 hrxq->standalone,
							 dev_started);
	}
	if (!ind_tbl) {
		rte_errno = ENOMEM;
		return -rte_errno;
	}
	MLX5_ASSERT(priv->obj_ops.hrxq_modify);
	ret = priv->obj_ops.hrxq_modify(dev, hrxq, rss_key,
					hash_fields, ind_tbl);
	if (ret) {
		rte_errno = errno;
		goto error;
	}
	if (ind_tbl != hrxq->ind_table) {
		MLX5_ASSERT(!hrxq->standalone);
		mlx5_ind_table_obj_release(dev, hrxq->ind_table, true);
		hrxq->ind_table = ind_tbl;
	}
	hrxq->hash_fields = hash_fields;
	memcpy(hrxq->rss_key, rss_key, rss_key_len);
	return 0;
error:
	err = rte_errno;
	if (ind_tbl != hrxq->ind_table) {
		MLX5_ASSERT(!hrxq->standalone);
		mlx5_ind_table_obj_release(dev, ind_tbl, true);
	}
	rte_errno = err;
	return -rte_errno;
}

static void
__mlx5_hrxq_remove(struct rte_eth_dev *dev, struct mlx5_hrxq *hrxq)
{
	struct mlx5_priv *priv = dev->data->dev_private;

#ifdef HAVE_IBV_FLOW_DV_SUPPORT
	if (hrxq->hws_flags)
		mlx5dr_action_destroy(hrxq->action);
	else
		mlx5_glue->destroy_flow_action(hrxq->action);
#endif
	priv->obj_ops.hrxq_destroy(hrxq);
	if (!hrxq->standalone) {
		mlx5_ind_table_obj_release(dev, hrxq->ind_table,
					   hrxq->hws_flags ?
					   (!!dev->data->dev_started) : true);
	}
	mlx5_ipool_free(priv->sh->ipool[MLX5_IPOOL_HRXQ], hrxq->idx);
}

/**
 * Release the hash Rx queue.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param hrxq
 *   Index to Hash Rx queue to release.
 *
 * @param list
 *   mlx5 list pointer.
 * @param entry
 *   Hash queue entry pointer.
 */
void
mlx5_hrxq_remove_cb(void *tool_ctx, struct mlx5_list_entry *entry)
{
	struct rte_eth_dev *dev = tool_ctx;
	struct mlx5_hrxq *hrxq = container_of(entry, typeof(*hrxq), entry);

	__mlx5_hrxq_remove(dev, hrxq);
}

static struct mlx5_hrxq *
__mlx5_hrxq_create(struct rte_eth_dev *dev,
		   struct mlx5_flow_rss_desc *rss_desc)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	const uint8_t *rss_key = rss_desc->key;
	uint32_t rss_key_len =  rss_desc->key_len;
	bool standalone = !!rss_desc->shared_rss;
	const uint16_t *queues =
		standalone ? rss_desc->const_q : rss_desc->queue;
	uint32_t queues_n = rss_desc->queue_num;
	struct mlx5_hrxq *hrxq = NULL;
	uint32_t hrxq_idx = 0;
	struct mlx5_ind_table_obj *ind_tbl = rss_desc->ind_tbl;
	int ret;

	queues_n = rss_desc->hash_fields ? queues_n : 1;
	if (!ind_tbl && !rss_desc->hws_flags)
		ind_tbl = mlx5_ind_table_obj_get(dev, queues, queues_n);
	if (!ind_tbl)
		ind_tbl = mlx5_ind_table_obj_new(dev, queues, queues_n,
						 standalone ||
						 rss_desc->hws_flags,
						 !!dev->data->dev_started);
	if (!ind_tbl)
		return NULL;
	hrxq = mlx5_ipool_zmalloc(priv->sh->ipool[MLX5_IPOOL_HRXQ], &hrxq_idx);
	if (!hrxq)
		goto error;
	hrxq->standalone = standalone;
	hrxq->idx = hrxq_idx;
	hrxq->ind_table = ind_tbl;
	hrxq->rss_key_len = rss_key_len;
	hrxq->hash_fields = rss_desc->hash_fields;
	hrxq->hws_flags = rss_desc->hws_flags;
	memcpy(hrxq->rss_key, rss_key, rss_key_len);
	ret = priv->obj_ops.hrxq_new(dev, hrxq, rss_desc->tunnel);
	if (ret < 0)
		goto error;
	return hrxq;
error:
	if (!rss_desc->ind_tbl)
		mlx5_ind_table_obj_release(dev, ind_tbl, true);
	if (hrxq)
		mlx5_ipool_free(priv->sh->ipool[MLX5_IPOOL_HRXQ], hrxq_idx);
	return NULL;
}

struct mlx5_list_entry *
mlx5_hrxq_create_cb(void *tool_ctx, void *cb_ctx)
{
	struct rte_eth_dev *dev = tool_ctx;
	struct mlx5_flow_cb_ctx *ctx = cb_ctx;
	struct mlx5_flow_rss_desc *rss_desc = ctx->data;
	struct mlx5_hrxq *hrxq;

	hrxq = __mlx5_hrxq_create(dev, rss_desc);
	return hrxq ? &hrxq->entry : NULL;
}

struct mlx5_list_entry *
mlx5_hrxq_clone_cb(void *tool_ctx, struct mlx5_list_entry *entry,
		    void *cb_ctx __rte_unused)
{
	struct rte_eth_dev *dev = tool_ctx;
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_hrxq *hrxq;
	uint32_t hrxq_idx = 0;

	hrxq = mlx5_ipool_zmalloc(priv->sh->ipool[MLX5_IPOOL_HRXQ], &hrxq_idx);
	if (!hrxq)
		return NULL;
	memcpy(hrxq, entry, sizeof(*hrxq) + MLX5_RSS_HASH_KEY_LEN);
	hrxq->idx = hrxq_idx;
	return &hrxq->entry;
}

void
mlx5_hrxq_clone_free_cb(void *tool_ctx, struct mlx5_list_entry *entry)
{
	struct rte_eth_dev *dev = tool_ctx;
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_hrxq *hrxq = container_of(entry, typeof(*hrxq), entry);

	mlx5_ipool_free(priv->sh->ipool[MLX5_IPOOL_HRXQ], hrxq->idx);
}

/**
 * Get an Rx Hash queue.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param rss_desc
 *   RSS configuration for the Rx hash queue.
 *
 * @return
 *   An hash Rx queue on success.
 */
struct mlx5_hrxq *mlx5_hrxq_get(struct rte_eth_dev *dev,
		       struct mlx5_flow_rss_desc *rss_desc)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_hrxq *hrxq = NULL;
	struct mlx5_list_entry *entry;
	struct mlx5_flow_cb_ctx ctx = {
		.data = rss_desc,
	};

	if (rss_desc->shared_rss) {
		hrxq = __mlx5_hrxq_create(dev, rss_desc);
	} else {
		entry = mlx5_list_register(priv->hrxqs, &ctx);
		if (!entry)
			return NULL;
		hrxq = container_of(entry, typeof(*hrxq), entry);
	}
	return hrxq;
}

/**
 * Release the hash Rx queue.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param hrxq_idx
 *   Hash Rx queue to release.
 *
 * @return
 *   1 while a reference on it exists, 0 when freed.
 */
int mlx5_hrxq_obj_release(struct rte_eth_dev *dev, struct mlx5_hrxq *hrxq)
{
	struct mlx5_priv *priv = dev->data->dev_private;

	if (!hrxq)
		return 0;
	if (!hrxq->standalone)
		return mlx5_list_unregister(priv->hrxqs, &hrxq->entry);
	__mlx5_hrxq_remove(dev, hrxq);
	return 0;
}

/**
 * Release the hash Rx queue with index.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param hrxq_idx
 *   Index to Hash Rx queue to release.
 *
 * @return
 *   1 while a reference on it exists, 0 when freed.
 */
int mlx5_hrxq_release(struct rte_eth_dev *dev, uint32_t hrxq_idx)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_hrxq *hrxq;

	hrxq = mlx5_ipool_get(priv->sh->ipool[MLX5_IPOOL_HRXQ], hrxq_idx);
	return mlx5_hrxq_obj_release(dev, hrxq);
}

/**
 * Create a drop Rx Hash queue.
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   The Verbs/DevX object initialized, NULL otherwise and rte_errno is set.
 */
struct mlx5_hrxq *
mlx5_drop_action_create(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_hrxq *hrxq = NULL;
	int ret;

	if (priv->drop_queue.hrxq)
		return priv->drop_queue.hrxq;
	hrxq = mlx5_malloc(MLX5_MEM_ZERO, sizeof(*hrxq) + MLX5_RSS_HASH_KEY_LEN, 0, SOCKET_ID_ANY);
	if (!hrxq) {
		DRV_LOG(WARNING,
			"Port %u cannot allocate memory for drop queue.",
			dev->data->port_id);
		rte_errno = ENOMEM;
		goto error;
	}
	priv->drop_queue.hrxq = hrxq;
	hrxq->ind_table = mlx5_malloc(MLX5_MEM_ZERO, sizeof(*hrxq->ind_table),
				      0, SOCKET_ID_ANY);
	if (!hrxq->ind_table) {
		rte_errno = ENOMEM;
		goto error;
	}
	ret = priv->obj_ops.drop_action_create(dev);
	if (ret < 0)
		goto error;
	return hrxq;
error:
	if (hrxq) {
		if (hrxq->ind_table)
			mlx5_free(hrxq->ind_table);
		priv->drop_queue.hrxq = NULL;
		mlx5_free(hrxq);
	}
	return NULL;
}

/**
 * Release a drop hash Rx queue.
 *
 * @param dev
 *   Pointer to Ethernet device.
 */
void
mlx5_drop_action_destroy(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_hrxq *hrxq = priv->drop_queue.hrxq;

	if (!priv->drop_queue.hrxq)
		return;
	priv->obj_ops.drop_action_destroy(dev);
	mlx5_free(priv->drop_queue.rxq);
	mlx5_free(hrxq->ind_table);
	mlx5_free(hrxq);
	priv->drop_queue.rxq = NULL;
	priv->drop_queue.hrxq = NULL;
}

/**
 * Verify the Rx Queue list is empty
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   The number of object not released.
 */
uint32_t
mlx5_hrxq_verify(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;

	return mlx5_list_get_entry_num(priv->hrxqs);
}

/**
 * Set the Rx queue timestamp conversion parameters
 *
 * @param[in] dev
 *   Pointer to the Ethernet device structure.
 */
void
mlx5_rxq_timestamp_set(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_dev_ctx_shared *sh = priv->sh;
	unsigned int i;

	for (i = 0; i != priv->rxqs_n; ++i) {
		struct mlx5_rxq_data *data = mlx5_rxq_data_get(dev, i);

		if (data == NULL)
			continue;
		data->sh = sh;
		data->rt_timestamp = sh->dev_cap.rt_timestamp;
	}
}

/**
 * Validate given external RxQ rte_plow index, and get pointer to concurrent
 * external RxQ object to map/unmap.
 *
 * @param[in] port_id
 *   The port identifier of the Ethernet device.
 * @param[in] dpdk_idx
 *   Queue index in rte_flow.
 *
 * @return
 *   Pointer to concurrent external RxQ on success,
 *   NULL otherwise and rte_errno is set.
 */
static struct mlx5_external_rxq *
mlx5_external_rx_queue_get_validate(uint16_t port_id, uint16_t dpdk_idx)
{
	struct rte_eth_dev *dev;
	struct mlx5_priv *priv;

	if (dpdk_idx < MLX5_EXTERNAL_RX_QUEUE_ID_MIN) {
		DRV_LOG(ERR, "Queue index %u should be in range: [%u, %u].",
			dpdk_idx, MLX5_EXTERNAL_RX_QUEUE_ID_MIN, UINT16_MAX);
		rte_errno = EINVAL;
		return NULL;
	}
	if (rte_eth_dev_is_valid_port(port_id) < 0) {
		DRV_LOG(ERR, "There is no Ethernet device for port %u.",
			port_id);
		rte_errno = ENODEV;
		return NULL;
	}
	dev = &rte_eth_devices[port_id];
	priv = dev->data->dev_private;
	if (!mlx5_imported_pd_and_ctx(priv->sh->cdev)) {
		DRV_LOG(ERR, "Port %u "
			"external RxQ isn't supported on local PD and CTX.",
			port_id);
		rte_errno = ENOTSUP;
		return NULL;
	}
	if (!mlx5_devx_obj_ops_en(priv->sh)) {
		DRV_LOG(ERR,
			"Port %u external RxQ isn't supported by Verbs API.",
			port_id);
		rte_errno = ENOTSUP;
		return NULL;
	}
	/*
	 * When user configures remote PD and CTX and device creates RxQ by
	 * DevX, external RxQs array is allocated.
	 */
	MLX5_ASSERT(priv->ext_rxqs != NULL);
	return &priv->ext_rxqs[dpdk_idx - MLX5_EXTERNAL_RX_QUEUE_ID_MIN];
}

int
rte_pmd_mlx5_external_rx_queue_id_map(uint16_t port_id, uint16_t dpdk_idx,
				      uint32_t hw_idx)
{
	struct mlx5_external_rxq *ext_rxq;
	uint32_t unmapped = 0;

	ext_rxq = mlx5_external_rx_queue_get_validate(port_id, dpdk_idx);
	if (ext_rxq == NULL)
		return -rte_errno;
	if (!__atomic_compare_exchange_n(&ext_rxq->refcnt, &unmapped, 1, false,
					 __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
		if (ext_rxq->hw_id != hw_idx) {
			DRV_LOG(ERR, "Port %u external RxQ index %u "
				"is already mapped to HW index (requesting is "
				"%u, existing is %u).",
				port_id, dpdk_idx, hw_idx, ext_rxq->hw_id);
			rte_errno = EEXIST;
			return -rte_errno;
		}
		DRV_LOG(WARNING, "Port %u external RxQ index %u "
			"is already mapped to the requested HW index (%u)",
			port_id, dpdk_idx, hw_idx);

	} else {
		ext_rxq->hw_id = hw_idx;
		DRV_LOG(DEBUG, "Port %u external RxQ index %u "
			"is successfully mapped to the requested HW index (%u)",
			port_id, dpdk_idx, hw_idx);
	}
	return 0;
}

int
rte_pmd_mlx5_external_rx_queue_id_unmap(uint16_t port_id, uint16_t dpdk_idx)
{
	struct mlx5_external_rxq *ext_rxq;
	uint32_t mapped = 1;

	ext_rxq = mlx5_external_rx_queue_get_validate(port_id, dpdk_idx);
	if (ext_rxq == NULL)
		return -rte_errno;
	if (ext_rxq->refcnt > 1) {
		DRV_LOG(ERR, "Port %u external RxQ index %u still referenced.",
			port_id, dpdk_idx);
		rte_errno = EINVAL;
		return -rte_errno;
	}
	if (!__atomic_compare_exchange_n(&ext_rxq->refcnt, &mapped, 0, false,
					 __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
		DRV_LOG(ERR, "Port %u external RxQ index %u doesn't exist.",
			port_id, dpdk_idx);
		rte_errno = EINVAL;
		return -rte_errno;
	}
	DRV_LOG(DEBUG,
		"Port %u external RxQ index %u is successfully unmapped.",
		port_id, dpdk_idx);
	return 0;
}
