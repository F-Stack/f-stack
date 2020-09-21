/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2008-2017 Cisco Systems, Inc.  All rights reserved.
 * Copyright 2007 Nuova Systems, Inc.  All rights reserved.
 */

#ifndef _ENIC_H_
#define _ENIC_H_

#include "vnic_enet.h"
#include "vnic_dev.h"
#include "vnic_wq.h"
#include "vnic_rq.h"
#include "vnic_cq.h"
#include "vnic_intr.h"
#include "vnic_stats.h"
#include "vnic_nic.h"
#include "vnic_rss.h"
#include "enic_res.h"
#include "cq_enet_desc.h"
#include <stdbool.h>
#include <sys/queue.h>
#include <rte_spinlock.h>

#define DRV_NAME		"enic_pmd"
#define DRV_DESCRIPTION		"Cisco VIC Ethernet NIC Poll-mode Driver"
#define DRV_COPYRIGHT		"Copyright 2008-2015 Cisco Systems, Inc"

#define ENIC_MAX_MAC_ADDR	64

#define VLAN_ETH_HLEN           18

#define ENICPMD_SETTING(enic, f) ((enic->config.flags & VENETF_##f) ? 1 : 0)

#define ENICPMD_BDF_LENGTH      13   /* 0000:00:00.0'\0' */
#define ENIC_CALC_IP_CKSUM      1
#define ENIC_CALC_TCP_UDP_CKSUM 2
#define ENIC_MAX_MTU            9000
#define ENIC_PAGE_SIZE          4096
#define PAGE_ROUND_UP(x) \
	((((unsigned long)(x)) + ENIC_PAGE_SIZE-1) & (~(ENIC_PAGE_SIZE-1)))

#define ENICPMD_VFIO_PATH          "/dev/vfio/vfio"
/*#define ENIC_DESC_COUNT_MAKE_ODD (x) do{if ((~(x)) & 1) { (x)--; } }while(0)*/

#define PCI_DEVICE_ID_CISCO_VIC_ENET         0x0043  /* ethernet vnic */
#define PCI_DEVICE_ID_CISCO_VIC_ENET_VF      0x0071  /* enet SRIOV VF */

/* Special Filter id for non-specific packet flagging. Don't change value */
#define ENIC_MAGIC_FILTER_ID 0xffff

#define ENICPMD_FDIR_MAX           64

/* HW default VXLAN port */
#define ENIC_DEFAULT_VXLAN_PORT	   4789

/*
 * Interrupt 0: LSC and errors
 * Interrupt 1: rx queue 0
 * Interrupt 2: rx queue 1
 * ...
 */
#define ENICPMD_LSC_INTR_OFFSET 0
#define ENICPMD_RXQ_INTR_OFFSET 1

struct enic_fdir_node {
	struct rte_eth_fdir_filter filter;
	u16 fltr_id;
	u16 rq_index;
};

struct enic_fdir {
	struct rte_eth_fdir_stats stats;
	struct rte_hash *hash;
	struct enic_fdir_node *nodes[ENICPMD_FDIR_MAX];
	u32 modes;
	u32 types_mask;
	void (*copy_fltr_fn)(struct filter_v2 *filt,
			     const struct rte_eth_fdir_input *input,
			     const struct rte_eth_fdir_masks *masks);
};

struct enic_soft_stats {
	rte_atomic64_t rx_nombuf;
	rte_atomic64_t rx_packet_errors;
	rte_atomic64_t tx_oversized;
};

struct enic_memzone_entry {
	const struct rte_memzone *rz;
	LIST_ENTRY(enic_memzone_entry) entries;
};

struct rte_flow {
	LIST_ENTRY(rte_flow) next;
	u16 enic_filter_id;
	struct filter_v2 enic_filter;
};

/* Per-instance private data structure */
struct enic {
	struct enic *next;
	struct rte_pci_device *pdev;
	struct vnic_enet_config config;
	struct vnic_dev_bar bar0;
	struct vnic_dev *vdev;

	/*
	 * mbuf_initializer contains 64 bits of mbuf rearm_data, used by
	 * the avx2 handler at this time.
	 */
	uint64_t mbuf_initializer;
	unsigned int port_id;
	bool overlay_offload;
	struct rte_eth_dev *rte_dev;
	struct enic_fdir fdir;
	char bdf_name[ENICPMD_BDF_LENGTH];
	int dev_fd;
	int iommu_group_fd;
	int iommu_groupid;
	int eventfd;
	uint8_t mac_addr[ETH_ALEN];
	pthread_t err_intr_thread;
	int promisc;
	int allmulti;
	u8 ig_vlan_strip_en;
	int link_status;
	u8 hw_ip_checksum;
	u16 max_mtu;
	u8 adv_filters;
	u32 flow_filter_mode;
	u8 filter_actions; /* HW supported actions */
	bool vxlan;
	bool disable_overlay; /* devargs disable_overlay=1 */
	uint8_t enable_avx2_rx;  /* devargs enable-avx2-rx=1 */
	bool nic_cfg_chk;     /* NIC_CFG_CHK available */
	bool udp_rss_weak;    /* Bodega style UDP RSS */
	uint8_t ig_vlan_rewrite_mode; /* devargs ig-vlan-rewrite */
	uint16_t vxlan_port;  /* current vxlan port pushed to NIC */

	unsigned int flags;
	unsigned int priv_flags;

	/* work queue (len = conf_wq_count) */
	struct vnic_wq *wq;
	unsigned int wq_count; /* equals eth_dev nb_tx_queues */

	/* receive queue (len = conf_rq_count) */
	struct vnic_rq *rq;
	unsigned int rq_count; /* equals eth_dev nb_rx_queues */

	/* completion queue (len = conf_cq_count) */
	struct vnic_cq *cq;
	unsigned int cq_count; /* equals rq_count + wq_count */

	/* interrupt vectors (len = conf_intr_count) */
	struct vnic_intr *intr;
	unsigned int intr_count; /* equals enabled interrupts (lsc + rxqs) */

	/* software counters */
	struct enic_soft_stats soft_stats;

	/* configured resources on vic */
	unsigned int conf_rq_count;
	unsigned int conf_wq_count;
	unsigned int conf_cq_count;
	unsigned int conf_intr_count;

	/* linked list storing memory allocations */
	LIST_HEAD(enic_memzone_list, enic_memzone_entry) memzone_list;
	rte_spinlock_t memzone_list_lock;
	rte_spinlock_t mtu_lock;

	LIST_HEAD(enic_flows, rte_flow) flows;

	/* RSS */
	uint16_t reta_size;
	uint8_t hash_key_size;
	uint64_t flow_type_rss_offloads; /* 0 indicates RSS not supported */
	/*
	 * Keep a copy of current RSS config for queries, as we cannot retrieve
	 * it from the NIC.
	 */
	uint8_t rss_hash_type; /* NIC_CFG_RSS_HASH_TYPE flags */
	uint8_t rss_enable;
	uint64_t rss_hf; /* ETH_RSS flags */
	union vnic_rss_key rss_key;
	union vnic_rss_cpu rss_cpu;

	uint64_t rx_offload_capa; /* DEV_RX_OFFLOAD flags */
	uint64_t tx_offload_capa; /* DEV_TX_OFFLOAD flags */
	uint64_t tx_queue_offload_capa; /* DEV_TX_OFFLOAD flags */
	uint64_t tx_offload_mask; /* PKT_TX flags accepted */
};

/* Compute ethdev's max packet size from MTU */
static inline uint32_t enic_mtu_to_max_rx_pktlen(uint32_t mtu)
{
	/* ethdev max size includes eth whereas NIC MTU does not */
	return mtu + ETHER_HDR_LEN;
}

/* Get the CQ index from a Start of Packet(SOP) RQ index */
static inline unsigned int enic_sop_rq_idx_to_cq_idx(unsigned int sop_idx)
{
	return sop_idx / 2;
}

/* Get the RTE RQ index from a Start of Packet(SOP) RQ index */
static inline unsigned int enic_sop_rq_idx_to_rte_idx(unsigned int sop_idx)
{
	return sop_idx / 2;
}

/* Get the Start of Packet(SOP) RQ index from a RTE RQ index */
static inline unsigned int enic_rte_rq_idx_to_sop_idx(unsigned int rte_idx)
{
	return rte_idx * 2;
}

/* Get the Data RQ index from a RTE RQ index */
static inline unsigned int enic_rte_rq_idx_to_data_idx(unsigned int rte_idx)
{
	return rte_idx * 2 + 1;
}

static inline unsigned int enic_vnic_rq_count(struct enic *enic)
{
	return enic->rq_count * 2;
}

static inline unsigned int enic_cq_rq(__rte_unused struct enic *enic, unsigned int rq)
{
	/* Scatter rx uses two receive queues together with one
	 * completion queue, so the completion queue number is no
	 * longer the same as the rq number.
	 */
	return rq / 2;
}

static inline unsigned int enic_cq_wq(struct enic *enic, unsigned int wq)
{
	return enic->rq_count + wq;
}

static inline struct enic *pmd_priv(struct rte_eth_dev *eth_dev)
{
	return eth_dev->data->dev_private;
}

static inline uint32_t
enic_ring_add(uint32_t n_descriptors, uint32_t i0, uint32_t i1)
{
	uint32_t d = i0 + i1;
	d -= (d >= n_descriptors) ? n_descriptors : 0;
	return d;
}

static inline uint32_t
enic_ring_sub(uint32_t n_descriptors, uint32_t i0, uint32_t i1)
{
	int32_t d = i1 - i0;
	return (uint32_t)((d < 0) ? ((int32_t)n_descriptors + d) : d);
}

static inline uint32_t
enic_ring_incr(uint32_t n_descriptors, uint32_t idx)
{
	idx++;
	if (unlikely(idx == n_descriptors))
		idx = 0;
	return idx;
}

void enic_fdir_stats_get(struct enic *enic,
			 struct rte_eth_fdir_stats *stats);
int enic_fdir_add_fltr(struct enic *enic,
		       struct rte_eth_fdir_filter *params);
int enic_fdir_del_fltr(struct enic *enic,
		       struct rte_eth_fdir_filter *params);
void enic_free_wq(void *txq);
int enic_alloc_intr_resources(struct enic *enic);
int enic_setup_finish(struct enic *enic);
int enic_alloc_wq(struct enic *enic, uint16_t queue_idx,
		  unsigned int socket_id, uint16_t nb_desc);
void enic_start_wq(struct enic *enic, uint16_t queue_idx);
int enic_stop_wq(struct enic *enic, uint16_t queue_idx);
void enic_start_rq(struct enic *enic, uint16_t queue_idx);
int enic_stop_rq(struct enic *enic, uint16_t queue_idx);
void enic_free_rq(void *rxq);
int enic_alloc_rq(struct enic *enic, uint16_t queue_idx,
		  unsigned int socket_id, struct rte_mempool *mp,
		  uint16_t nb_desc, uint16_t free_thresh);
int enic_set_vnic_res(struct enic *enic);
int enic_init_rss_nic_cfg(struct enic *enic);
int enic_set_rss_conf(struct enic *enic,
		      struct rte_eth_rss_conf *rss_conf);
int enic_set_rss_reta(struct enic *enic, union vnic_rss_cpu *rss_cpu);
int enic_set_vlan_strip(struct enic *enic);
int enic_enable(struct enic *enic);
int enic_disable(struct enic *enic);
void enic_remove(struct enic *enic);
int enic_get_link_status(struct enic *enic);
int enic_dev_stats_get(struct enic *enic,
		       struct rte_eth_stats *r_stats);
void enic_dev_stats_clear(struct enic *enic);
void enic_add_packet_filter(struct enic *enic);
int enic_set_mac_address(struct enic *enic, uint8_t *mac_addr);
int enic_del_mac_address(struct enic *enic, int mac_index);
unsigned int enic_cleanup_wq(struct enic *enic, struct vnic_wq *wq);
void enic_send_pkt(struct enic *enic, struct vnic_wq *wq,
		   struct rte_mbuf *tx_pkt, unsigned short len,
		   uint8_t sop, uint8_t eop, uint8_t cq_entry,
		   uint16_t ol_flags, uint16_t vlan_tag);

void enic_post_wq_index(struct vnic_wq *wq);
int enic_probe(struct enic *enic);
int enic_clsf_init(struct enic *enic);
void enic_clsf_destroy(struct enic *enic);
uint16_t enic_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
			uint16_t nb_pkts);
uint16_t enic_noscatter_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
				  uint16_t nb_pkts);
uint16_t enic_dummy_recv_pkts(void *rx_queue,
			      struct rte_mbuf **rx_pkts,
			      uint16_t nb_pkts);
uint16_t enic_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
			uint16_t nb_pkts);
uint16_t enic_simple_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
			       uint16_t nb_pkts);
uint16_t enic_prep_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
			uint16_t nb_pkts);
int enic_set_mtu(struct enic *enic, uint16_t new_mtu);
int enic_link_update(struct enic *enic);
bool enic_use_vector_rx_handler(struct enic *enic);
void enic_fdir_info(struct enic *enic);
void enic_fdir_info_get(struct enic *enic, struct rte_eth_fdir_info *stats);
extern const struct rte_flow_ops enic_flow_ops;
#endif /* _ENIC_H_ */
