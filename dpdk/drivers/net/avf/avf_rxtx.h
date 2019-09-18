/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _AVF_RXTX_H_
#define _AVF_RXTX_H_

/* In QLEN must be whole number of 32 descriptors. */
#define AVF_ALIGN_RING_DESC      32
#define AVF_MIN_RING_DESC        64
#define AVF_MAX_RING_DESC        4096
#define AVF_DMA_MEM_ALIGN        4096
/* Base address of the HW descriptor ring should be 128B aligned. */
#define AVF_RING_BASE_ALIGN      128

/* used for Rx Bulk Allocate */
#define AVF_RX_MAX_BURST         32

/* used for Vector PMD */
#define AVF_VPMD_RX_MAX_BURST    32
#define AVF_VPMD_TX_MAX_BURST    32
#define AVF_VPMD_DESCS_PER_LOOP  4
#define AVF_VPMD_TX_MAX_FREE_BUF 64

#define AVF_NO_VECTOR_FLAGS (				 \
		DEV_TX_OFFLOAD_MULTI_SEGS |		 \
		DEV_TX_OFFLOAD_VLAN_INSERT |		 \
		DEV_TX_OFFLOAD_SCTP_CKSUM |		 \
		DEV_TX_OFFLOAD_UDP_CKSUM |		 \
		DEV_TX_OFFLOAD_TCP_CKSUM)

#define DEFAULT_TX_RS_THRESH     32
#define DEFAULT_TX_FREE_THRESH   32

#define AVF_MIN_TSO_MSS          256
#define AVF_MAX_TSO_MSS          9668
#define AVF_TSO_MAX_SEG          UINT8_MAX
#define AVF_TX_MAX_MTU_SEG       8

#define AVF_TX_CKSUM_OFFLOAD_MASK (		 \
		PKT_TX_IP_CKSUM |		 \
		PKT_TX_L4_MASK |		 \
		PKT_TX_TCP_SEG)

#define AVF_TX_OFFLOAD_MASK (  \
		PKT_TX_OUTER_IPV6 |		 \
		PKT_TX_OUTER_IPV4 |		 \
		PKT_TX_IPV6 |			 \
		PKT_TX_IPV4 |			 \
		PKT_TX_VLAN_PKT |		 \
		PKT_TX_IP_CKSUM |		 \
		PKT_TX_L4_MASK |		 \
		PKT_TX_TCP_SEG)

#define AVF_TX_OFFLOAD_NOTSUP_MASK \
		(PKT_TX_OFFLOAD_MASK ^ AVF_TX_OFFLOAD_MASK)

/* HW desc structure, both 16-byte and 32-byte types are supported */
#ifdef RTE_LIBRTE_AVF_16BYTE_RX_DESC
#define avf_rx_desc avf_16byte_rx_desc
#else
#define avf_rx_desc avf_32byte_rx_desc
#endif

struct avf_rxq_ops {
	void (*release_mbufs)(struct avf_rx_queue *rxq);
};

struct avf_txq_ops {
	void (*release_mbufs)(struct avf_tx_queue *txq);
};

/* Structure associated with each Rx queue. */
struct avf_rx_queue {
	struct rte_mempool *mp;       /* mbuf pool to populate Rx ring */
	const struct rte_memzone *mz; /* memzone for Rx ring */
	volatile union avf_rx_desc *rx_ring; /* Rx ring virtual address */
	uint64_t rx_ring_phys_addr;   /* Rx ring DMA address */
	struct rte_mbuf **sw_ring;     /* address of SW ring */
	uint16_t nb_rx_desc;          /* ring length */
	uint16_t rx_tail;             /* current value of tail */
	volatile uint8_t *qrx_tail;   /* register address of tail */
	uint16_t rx_free_thresh;      /* max free RX desc to hold */
	uint16_t nb_rx_hold;          /* number of held free RX desc */
	struct rte_mbuf *pkt_first_seg; /* first segment of current packet */
	struct rte_mbuf *pkt_last_seg;  /* last segment of current packet */
	struct rte_mbuf fake_mbuf;      /* dummy mbuf */

	/* used for VPMD */
	uint16_t rxrearm_nb;       /* number of remaining to be re-armed */
	uint16_t rxrearm_start;    /* the idx we start the re-arming from */
	uint64_t mbuf_initializer; /* value to init mbufs */

	/* for rx bulk */
	uint16_t rx_nb_avail;      /* number of staged packets ready */
	uint16_t rx_next_avail;    /* index of next staged packets */
	uint16_t rx_free_trigger;  /* triggers rx buffer allocation */
	struct rte_mbuf *rx_stage[AVF_RX_MAX_BURST * 2]; /* store mbuf */

	uint16_t port_id;        /* device port ID */
	uint8_t crc_len;        /* 0 if CRC stripped, 4 otherwise */
	uint16_t queue_id;      /* Rx queue index */
	uint16_t rx_buf_len;    /* The packet buffer size */
	uint16_t rx_hdr_len;    /* The header buffer size */
	uint16_t max_pkt_len;   /* Maximum packet length */

	bool q_set;             /* if rx queue has been configured */
	bool rx_deferred_start; /* don't start this queue in dev start */
	const struct avf_rxq_ops *ops;
};

struct avf_tx_entry {
	struct rte_mbuf *mbuf;
	uint16_t next_id;
	uint16_t last_id;
};

/* Structure associated with each TX queue. */
struct avf_tx_queue {
	const struct rte_memzone *mz;  /* memzone for Tx ring */
	volatile struct avf_tx_desc *tx_ring; /* Tx ring virtual address */
	uint64_t tx_ring_phys_addr;    /* Tx ring DMA address */
	struct avf_tx_entry *sw_ring;  /* address array of SW ring */
	uint16_t nb_tx_desc;           /* ring length */
	uint16_t tx_tail;              /* current value of tail */
	volatile uint8_t *qtx_tail;    /* register address of tail */
	/* number of used desc since RS bit set */
	uint16_t nb_used;
	uint16_t nb_free;
	uint16_t last_desc_cleaned;    /* last desc have been cleaned*/
	uint16_t free_thresh;
	uint16_t rs_thresh;

	uint16_t port_id;
	uint16_t queue_id;
	uint64_t offloads;
	uint16_t next_dd;              /* next to set RS, for VPMD */
	uint16_t next_rs;              /* next to check DD,  for VPMD */

	bool q_set;                    /* if rx queue has been configured */
	bool tx_deferred_start;        /* don't start this queue in dev start */
	const struct avf_txq_ops *ops;
};

/* Offload features */
union avf_tx_offload {
	uint64_t data;
	struct {
		uint64_t l2_len:7; /* L2 (MAC) Header Length. */
		uint64_t l3_len:9; /* L3 (IP) Header Length. */
		uint64_t l4_len:8; /* L4 Header Length. */
		uint64_t tso_segsz:16; /* TCP TSO segment size */
		/* uint64_t unused : 24; */
	};
};

int avf_dev_rx_queue_setup(struct rte_eth_dev *dev,
			   uint16_t queue_idx,
			   uint16_t nb_desc,
			   unsigned int socket_id,
			   const struct rte_eth_rxconf *rx_conf,
			   struct rte_mempool *mp);

int avf_dev_rx_queue_start(struct rte_eth_dev *dev, uint16_t rx_queue_id);
int avf_dev_rx_queue_stop(struct rte_eth_dev *dev, uint16_t rx_queue_id);
void avf_dev_rx_queue_release(void *rxq);

int avf_dev_tx_queue_setup(struct rte_eth_dev *dev,
			   uint16_t queue_idx,
			   uint16_t nb_desc,
			   unsigned int socket_id,
			   const struct rte_eth_txconf *tx_conf);
int avf_dev_tx_queue_start(struct rte_eth_dev *dev, uint16_t tx_queue_id);
int avf_dev_tx_queue_stop(struct rte_eth_dev *dev, uint16_t tx_queue_id);
void avf_dev_tx_queue_release(void *txq);
void avf_stop_queues(struct rte_eth_dev *dev);
uint16_t avf_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
		       uint16_t nb_pkts);
uint16_t avf_recv_scattered_pkts(void *rx_queue,
				 struct rte_mbuf **rx_pkts,
				 uint16_t nb_pkts);
uint16_t avf_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
		       uint16_t nb_pkts);
uint16_t avf_prep_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
		       uint16_t nb_pkts);
void avf_set_rx_function(struct rte_eth_dev *dev);
void avf_set_tx_function(struct rte_eth_dev *dev);
void avf_dev_rxq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
			  struct rte_eth_rxq_info *qinfo);
void avf_dev_txq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
			  struct rte_eth_txq_info *qinfo);
uint32_t avf_dev_rxq_count(struct rte_eth_dev *dev, uint16_t queue_id);
int avf_dev_rx_desc_status(void *rx_queue, uint16_t offset);
int avf_dev_tx_desc_status(void *tx_queue, uint16_t offset);

uint16_t avf_recv_pkts_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
			   uint16_t nb_pkts);
uint16_t avf_recv_scattered_pkts_vec(void *rx_queue,
				     struct rte_mbuf **rx_pkts,
				     uint16_t nb_pkts);
uint16_t avf_xmit_fixed_burst_vec(void *tx_queue, struct rte_mbuf **tx_pkts,
				  uint16_t nb_pkts);
int avf_rxq_vec_setup(struct avf_rx_queue *rxq);
int avf_txq_vec_setup(struct avf_tx_queue *txq);

static inline
void avf_dump_rx_descriptor(struct avf_rx_queue *rxq,
			    const volatile void *desc,
			    uint16_t rx_id)
{
#ifdef RTE_LIBRTE_AVF_16BYTE_RX_DESC
	const volatile union avf_16byte_rx_desc *rx_desc = desc;

	printf("Queue %d Rx_desc %d: QW0: 0x%016"PRIx64" QW1: 0x%016"PRIx64"\n",
	       rxq->queue_id, rx_id, rx_desc->read.pkt_addr,
	       rx_desc->read.hdr_addr);
#else
	const volatile union avf_32byte_rx_desc *rx_desc = desc;

	printf("Queue %d Rx_desc %d: QW0: 0x%016"PRIx64" QW1: 0x%016"PRIx64
	       " QW2: 0x%016"PRIx64" QW3: 0x%016"PRIx64"\n", rxq->queue_id,
	       rx_id, rx_desc->read.pkt_addr, rx_desc->read.hdr_addr,
	       rx_desc->read.rsvd1, rx_desc->read.rsvd2);
#endif
}

/* All the descriptors are 16 bytes, so just use one of them
 * to print the qwords
 */
static inline
void avf_dump_tx_descriptor(const struct avf_tx_queue *txq,
			    const volatile void *desc, uint16_t tx_id)
{
	const char *name;
	const volatile struct avf_tx_desc *tx_desc = desc;
	enum avf_tx_desc_dtype_value type;

	type = (enum avf_tx_desc_dtype_value)rte_le_to_cpu_64(
		tx_desc->cmd_type_offset_bsz &
		rte_cpu_to_le_64(AVF_TXD_QW1_DTYPE_MASK));
	switch (type) {
	case AVF_TX_DESC_DTYPE_DATA:
		name = "Tx_data_desc";
		break;
	case AVF_TX_DESC_DTYPE_CONTEXT:
		name = "Tx_context_desc";
		break;
	default:
		name = "unknown_desc";
		break;
	}

	printf("Queue %d %s %d: QW0: 0x%016"PRIx64" QW1: 0x%016"PRIx64"\n",
	       txq->queue_id, name, tx_id, tx_desc->buffer_addr,
	       tx_desc->cmd_type_offset_bsz);
}

#ifdef DEBUG_DUMP_DESC
#define AVF_DUMP_RX_DESC(rxq, desc, rx_id) \
	avf_dump_rx_descriptor(rxq, desc, rx_id)
#define AVF_DUMP_TX_DESC(txq, desc, tx_id) \
	avf_dump_tx_descriptor(txq, desc, tx_id)
#else
#define AVF_DUMP_RX_DESC(rxq, desc, rx_id) do { } while (0)
#define AVF_DUMP_TX_DESC(txq, desc, tx_id) do { } while (0)
#endif

#endif /* _AVF_RXTX_H_ */
