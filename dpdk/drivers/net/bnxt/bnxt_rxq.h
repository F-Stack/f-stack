/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2014-2018 Broadcom
 * All rights reserved.
 */

#ifndef _BNXT_RQX_H_
#define _BNXT_RQX_H_

struct bnxt;
struct bnxt_rx_ring_info;
struct bnxt_cp_ring_info;
struct bnxt_rx_queue {
	rte_spinlock_t		lock;	/* Synchronize between rx_queue_stop
					 * and fast path
					 */
	struct rte_mempool	*mb_pool; /* mbuf pool for RX ring */
	struct rte_mbuf		*pkt_first_seg; /* 1st seg of pkt */
	struct rte_mbuf		*pkt_last_seg; /* Last seg of pkt */
	uint64_t		mbuf_initializer; /* val to init mbuf */
	uint16_t		nb_rx_desc; /* num of RX desc */
	uint16_t		rx_tail; /* cur val of RDT register */
	uint16_t		nb_rx_hold; /* num held free RX desc */
	uint16_t		rx_free_thresh; /* max free RX desc to hold */
	uint16_t		queue_id; /* RX queue index */
	uint16_t		reg_idx; /* RX queue register index */
	uint16_t		port_id; /* Device port identifier */
	uint8_t			crc_len; /* 0 if CRC stripped, 4 otherwise */
	uint8_t			rx_deferred_start; /* not in global dev start */

	struct bnxt		*bp;
	int			index;
	struct bnxt_vnic_info	*vnic;

	uint32_t			rx_buf_size;
	uint32_t			rx_buf_use_size;  /* useable size */
	struct bnxt_rx_ring_info	*rx_ring;
	struct bnxt_cp_ring_info	*cp_ring;
	rte_atomic64_t		rx_mbuf_alloc_fail;
	const struct rte_memzone *mz;
};

void bnxt_free_rxq_stats(struct bnxt_rx_queue *rxq);
int bnxt_mq_rx_configure(struct bnxt *bp);
void bnxt_rx_queue_release_op(void *rx_queue);
int bnxt_rx_queue_setup_op(struct rte_eth_dev *eth_dev,
			       uint16_t queue_idx,
			       uint16_t nb_desc,
			       unsigned int socket_id,
			       const struct rte_eth_rxconf *rx_conf,
			       struct rte_mempool *mp);
void bnxt_free_rx_mbufs(struct bnxt *bp);
int bnxt_rx_queue_intr_enable_op(struct rte_eth_dev *eth_dev,
				 uint16_t queue_id);
int bnxt_rx_queue_intr_disable_op(struct rte_eth_dev *eth_dev,
				  uint16_t queue_id);
int bnxt_rx_queue_start(struct rte_eth_dev *dev,
			uint16_t rx_queue_id);
int bnxt_rx_queue_stop(struct rte_eth_dev *dev,
		       uint16_t rx_queue_id);
void bnxt_rx_queue_release_mbufs(struct bnxt_rx_queue *rxq);
#endif
