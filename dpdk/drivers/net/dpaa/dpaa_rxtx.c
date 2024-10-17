/* SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright 2016 Freescale Semiconductor, Inc. All rights reserved.
 *   Copyright 2017,2019-2021 NXP
 *
 */

/* System headers */
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <sched.h>
#include <pthread.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_interrupts.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_pci.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_memory.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_alarm.h>
#include <rte_ether.h>
#include <ethdev_driver.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_net.h>
#include <rte_eventdev.h>

#include "dpaa_ethdev.h"
#include "dpaa_rxtx.h"
#include <bus_dpaa_driver.h>
#include <dpaa_mempool.h>

#include <qman.h>
#include <fsl_usd.h>
#include <fsl_qman.h>
#include <fsl_bman.h>
#include <dpaa_of.h>
#include <netcfg.h>

#define DPAA_MBUF_TO_CONTIG_FD(_mbuf, _fd, _bpid) \
	do { \
		(_fd)->cmd = 0; \
		(_fd)->opaque_addr = 0; \
		(_fd)->opaque = QM_FD_CONTIG << DPAA_FD_FORMAT_SHIFT; \
		(_fd)->opaque |= ((_mbuf)->data_off) << DPAA_FD_OFFSET_SHIFT; \
		(_fd)->opaque |= (_mbuf)->pkt_len; \
		(_fd)->addr = (_mbuf)->buf_iova; \
		(_fd)->bpid = _bpid; \
	} while (0)

#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
#define DISPLAY_PRINT printf
static void dpaa_display_frame_info(const struct qm_fd *fd,
			uint32_t fqid, bool rx)
{
	int ii;
	char *ptr;
	struct annotations_t *annot = rte_dpaa_mem_ptov(fd->addr);
	uint8_t format;

	if (!fd->status) {
		/* Do not display correct packets.*/
		return;
	}

	format = (fd->opaque & DPAA_FD_FORMAT_MASK) >>
				DPAA_FD_FORMAT_SHIFT;

	DISPLAY_PRINT("fqid %d bpid %d addr 0x%lx, format %d\r\n",
		      fqid, fd->bpid, (unsigned long)fd->addr, fd->format);
	DISPLAY_PRINT("off %d, len %d stat 0x%x\r\n",
		      fd->offset, fd->length20, fd->status);
	if (rx) {
		ptr = (char *)&annot->parse;
		DISPLAY_PRINT("RX parser result:\r\n");
		for (ii = 0; ii < (int)sizeof(struct dpaa_eth_parse_results_t);
			ii++) {
			DISPLAY_PRINT("%02x ", ptr[ii]);
			if (((ii + 1) % 16) == 0)
				DISPLAY_PRINT("\n");
		}
		DISPLAY_PRINT("\n");
	}

	if (unlikely(format == qm_fd_sg)) {
		/*TBD:S/G display: to be implemented*/
		return;
	}

	DISPLAY_PRINT("Frame payload:\r\n");
	ptr = (char *)annot;
	ptr += fd->offset;
	for (ii = 0; ii < fd->length20; ii++) {
		DISPLAY_PRINT("%02x ", ptr[ii]);
		if (((ii + 1) % 16) == 0)
			printf("\n");
	}
	DISPLAY_PRINT("\n");
}
#else
#define dpaa_display_frame_info(a, b, c)
#endif

static inline void dpaa_slow_parsing(struct rte_mbuf *m __rte_unused,
				     uint64_t prs __rte_unused)
{
	DPAA_DP_LOG(DEBUG, "Slow parsing");
	/*TBD:XXX: to be implemented*/
}

static inline void dpaa_eth_packet_info(struct rte_mbuf *m, void *fd_virt_addr)
{
	struct annotations_t *annot = GET_ANNOTATIONS(fd_virt_addr);
	uint64_t prs = *((uintptr_t *)(&annot->parse)) & DPAA_PARSE_MASK;

	DPAA_DP_LOG(DEBUG, " Parsing mbuf: %p with annotations: %p", m, annot);

	m->ol_flags = RTE_MBUF_F_RX_RSS_HASH | RTE_MBUF_F_RX_IP_CKSUM_GOOD |
		RTE_MBUF_F_RX_L4_CKSUM_GOOD;

	switch (prs) {
	case DPAA_PKT_TYPE_IPV4:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4;
		break;
	case DPAA_PKT_TYPE_IPV6:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6;
		break;
	case DPAA_PKT_TYPE_ETHER:
		m->packet_type = RTE_PTYPE_L2_ETHER;
		break;
	case DPAA_PKT_TYPE_IPV4_FRAG:
	case DPAA_PKT_TYPE_IPV4_FRAG_UDP:
	case DPAA_PKT_TYPE_IPV4_FRAG_TCP:
	case DPAA_PKT_TYPE_IPV4_FRAG_SCTP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_FRAG;
		break;
	case DPAA_PKT_TYPE_IPV6_FRAG:
	case DPAA_PKT_TYPE_IPV6_FRAG_UDP:
	case DPAA_PKT_TYPE_IPV6_FRAG_TCP:
	case DPAA_PKT_TYPE_IPV6_FRAG_SCTP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_FRAG;
		break;
	case DPAA_PKT_TYPE_IPV4_EXT:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4_EXT;
		break;
	case DPAA_PKT_TYPE_IPV6_EXT:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6_EXT;
		break;
	case DPAA_PKT_TYPE_IPV4_TCP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP;
		break;
	case DPAA_PKT_TYPE_IPV6_TCP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP;
		break;
	case DPAA_PKT_TYPE_IPV4_UDP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_UDP;
		break;
	case DPAA_PKT_TYPE_IPV6_UDP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_UDP;
		break;
	case DPAA_PKT_TYPE_IPSEC_IPV4:
		if (*((uintptr_t *)&annot->parse) & DPAA_PARSE_ESP_MASK)
			m->packet_type = RTE_PTYPE_L2_ETHER |
				RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_ESP;
		break;
	case DPAA_PKT_TYPE_IPSEC_IPV6:
		if (*((uintptr_t *)&annot->parse) & DPAA_PARSE_ESP_MASK)
			m->packet_type = RTE_PTYPE_L2_ETHER |
				RTE_PTYPE_L3_IPV6 | RTE_PTYPE_TUNNEL_ESP;
		break;
	case DPAA_PKT_TYPE_IPV4_EXT_UDP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L4_UDP;
		break;
	case DPAA_PKT_TYPE_IPV6_EXT_UDP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L4_UDP;
		break;
	case DPAA_PKT_TYPE_IPV4_EXT_TCP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L4_TCP;
		break;
	case DPAA_PKT_TYPE_IPV6_EXT_TCP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L4_TCP;
		break;
	case DPAA_PKT_TYPE_IPV4_SCTP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_SCTP;
		break;
	case DPAA_PKT_TYPE_IPV6_SCTP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_SCTP;
		break;
	case DPAA_PKT_TYPE_IPV4_CSUM_ERR:
	case DPAA_PKT_TYPE_IPV6_CSUM_ERR:
		m->ol_flags = RTE_MBUF_F_RX_RSS_HASH | RTE_MBUF_F_RX_IP_CKSUM_BAD;
		break;
	case DPAA_PKT_TYPE_IPV4_TCP_CSUM_ERR:
	case DPAA_PKT_TYPE_IPV6_TCP_CSUM_ERR:
	case DPAA_PKT_TYPE_IPV4_UDP_CSUM_ERR:
	case DPAA_PKT_TYPE_IPV6_UDP_CSUM_ERR:
		m->ol_flags = RTE_MBUF_F_RX_RSS_HASH | RTE_MBUF_F_RX_L4_CKSUM_BAD;
		break;
	case DPAA_PKT_TYPE_NONE:
		m->packet_type = 0;
		break;
	/* More switch cases can be added */
	default:
		dpaa_slow_parsing(m, prs);
	}

	m->tx_offload = annot->parse.ip_off[0];
	m->tx_offload |= (annot->parse.l4_off - annot->parse.ip_off[0])
					<< DPAA_PKT_L3_LEN_SHIFT;

	/* Set the hash values */
	m->hash.rss = (uint32_t)(annot->hash);

	/* Check if Vlan is present */
	if (prs & DPAA_PARSE_VLAN_MASK)
		m->ol_flags |= RTE_MBUF_F_RX_VLAN;
	/* Packet received without stripping the vlan */
}

static inline void dpaa_checksum(struct rte_mbuf *mbuf)
{
	struct rte_ether_hdr *eth_hdr =
		rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	char *l3_hdr = (char *)eth_hdr + mbuf->l2_len;
	struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)l3_hdr;
	struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)l3_hdr;

	DPAA_DP_LOG(DEBUG, "Calculating checksum for mbuf: %p", mbuf);

	if (((mbuf->packet_type & RTE_PTYPE_L3_MASK) == RTE_PTYPE_L3_IPV4) ||
	    ((mbuf->packet_type & RTE_PTYPE_L3_MASK) ==
	    RTE_PTYPE_L3_IPV4_EXT)) {
		ipv4_hdr = (struct rte_ipv4_hdr *)l3_hdr;
		ipv4_hdr->hdr_checksum = 0;
		ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
	} else if (((mbuf->packet_type & RTE_PTYPE_L3_MASK) ==
		   RTE_PTYPE_L3_IPV6) ||
		   ((mbuf->packet_type & RTE_PTYPE_L3_MASK) ==
		   RTE_PTYPE_L3_IPV6_EXT))
		ipv6_hdr = (struct rte_ipv6_hdr *)l3_hdr;

	if ((mbuf->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP) {
		struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(l3_hdr +
					  mbuf->l3_len);
		tcp_hdr->cksum = 0;
		if (eth_hdr->ether_type == htons(RTE_ETHER_TYPE_IPV4))
			tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ipv4_hdr,
							       tcp_hdr);
		else /* assume ethertype == RTE_ETHER_TYPE_IPV6 */
			tcp_hdr->cksum = rte_ipv6_udptcp_cksum(ipv6_hdr,
							       tcp_hdr);
	} else if ((mbuf->packet_type & RTE_PTYPE_L4_MASK) ==
		   RTE_PTYPE_L4_UDP) {
		struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(l3_hdr +
							     mbuf->l3_len);
		udp_hdr->dgram_cksum = 0;
		if (eth_hdr->ether_type == htons(RTE_ETHER_TYPE_IPV4))
			udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr,
								     udp_hdr);
		else /* assume ethertype == RTE_ETHER_TYPE_IPV6 */
			udp_hdr->dgram_cksum = rte_ipv6_udptcp_cksum(ipv6_hdr,
								     udp_hdr);
	}
}

static inline void dpaa_checksum_offload(struct rte_mbuf *mbuf,
					 struct qm_fd *fd, char *prs_buf)
{
	struct dpaa_eth_parse_results_t *prs;

	DPAA_DP_LOG(DEBUG, " Offloading checksum for mbuf: %p", mbuf);

	prs = GET_TX_PRS(prs_buf);
	prs->l3r = 0;
	prs->l4r = 0;
	if (((mbuf->packet_type & RTE_PTYPE_L3_MASK) == RTE_PTYPE_L3_IPV4) ||
	   ((mbuf->packet_type & RTE_PTYPE_L3_MASK) ==
	   RTE_PTYPE_L3_IPV4_EXT))
		prs->l3r = DPAA_L3_PARSE_RESULT_IPV4;
	else if (((mbuf->packet_type & RTE_PTYPE_L3_MASK) ==
		   RTE_PTYPE_L3_IPV6) ||
		 ((mbuf->packet_type & RTE_PTYPE_L3_MASK) ==
		RTE_PTYPE_L3_IPV6_EXT))
		prs->l3r = DPAA_L3_PARSE_RESULT_IPV6;

	if ((mbuf->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP)
		prs->l4r = DPAA_L4_PARSE_RESULT_TCP;
	else if ((mbuf->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_UDP)
		prs->l4r = DPAA_L4_PARSE_RESULT_UDP;

	prs->ip_off[0] = mbuf->l2_len;
	prs->l4_off = mbuf->l3_len + mbuf->l2_len;
	/* Enable L3 (and L4, if TCP or UDP) HW checksum*/
	fd->cmd = DPAA_FD_CMD_RPD | DPAA_FD_CMD_DTC;
}

static inline void
dpaa_unsegmented_checksum(struct rte_mbuf *mbuf, struct qm_fd *fd_arr)
{
	if (!mbuf->packet_type) {
		struct rte_net_hdr_lens hdr_lens;

		mbuf->packet_type = rte_net_get_ptype(mbuf, &hdr_lens,
				RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK
				| RTE_PTYPE_L4_MASK);
		mbuf->l2_len = hdr_lens.l2_len;
		mbuf->l3_len = hdr_lens.l3_len;
	}
	if (mbuf->data_off < (DEFAULT_TX_ICEOF +
	    sizeof(struct dpaa_eth_parse_results_t))) {
		DPAA_DP_LOG(DEBUG, "Checksum offload Err: "
			"Not enough Headroom "
			"space for correct Checksum offload."
			"So Calculating checksum in Software.");
		dpaa_checksum(mbuf);
	} else {
		dpaa_checksum_offload(mbuf, fd_arr, mbuf->buf_addr);
	}
}

static struct rte_mbuf *
dpaa_eth_sg_to_mbuf(const struct qm_fd *fd, uint32_t ifid)
{
	struct dpaa_bp_info *bp_info = DPAA_BPID_TO_POOL_INFO(fd->bpid);
	struct rte_mbuf *first_seg, *prev_seg, *cur_seg, *temp;
	struct qm_sg_entry *sgt, *sg_temp;
	void *vaddr, *sg_vaddr;
	int i = 0;
	uint16_t fd_offset = fd->offset;

	vaddr = DPAA_MEMPOOL_PTOV(bp_info, qm_fd_addr(fd));
	if (!vaddr) {
		DPAA_PMD_ERR("unable to convert physical address");
		return NULL;
	}
	sgt = vaddr + fd_offset;
	sg_temp = &sgt[i++];
	hw_sg_to_cpu(sg_temp);
	temp = (struct rte_mbuf *)((char *)vaddr - bp_info->meta_data_size);
	sg_vaddr = DPAA_MEMPOOL_PTOV(bp_info, qm_sg_entry_get64(sg_temp));

	first_seg = (struct rte_mbuf *)((char *)sg_vaddr -
						bp_info->meta_data_size);
	first_seg->data_off = sg_temp->offset;
	first_seg->data_len = sg_temp->length;
	first_seg->pkt_len = sg_temp->length;
	rte_mbuf_refcnt_set(first_seg, 1);

	first_seg->port = ifid;
	first_seg->nb_segs = 1;
	first_seg->ol_flags = 0;
	prev_seg = first_seg;
	while (i < DPAA_SGT_MAX_ENTRIES) {
		sg_temp = &sgt[i++];
		hw_sg_to_cpu(sg_temp);
		sg_vaddr = DPAA_MEMPOOL_PTOV(bp_info,
					     qm_sg_entry_get64(sg_temp));
		cur_seg = (struct rte_mbuf *)((char *)sg_vaddr -
						      bp_info->meta_data_size);
		cur_seg->data_off = sg_temp->offset;
		cur_seg->data_len = sg_temp->length;
		first_seg->pkt_len += sg_temp->length;
		first_seg->nb_segs += 1;
		rte_mbuf_refcnt_set(cur_seg, 1);
		prev_seg->next = cur_seg;
		if (sg_temp->final) {
			cur_seg->next = NULL;
			break;
		}
		prev_seg = cur_seg;
	}
	DPAA_DP_LOG(DEBUG, "Received an SG frame len =%d, num_sg =%d",
			first_seg->pkt_len, first_seg->nb_segs);

	dpaa_eth_packet_info(first_seg, vaddr);
	rte_pktmbuf_free_seg(temp);

	return first_seg;
}

static inline struct rte_mbuf *
dpaa_eth_fd_to_mbuf(const struct qm_fd *fd, uint32_t ifid)
{
	struct rte_mbuf *mbuf;
	struct dpaa_bp_info *bp_info = DPAA_BPID_TO_POOL_INFO(fd->bpid);
	void *ptr;
	uint8_t format =
		(fd->opaque & DPAA_FD_FORMAT_MASK) >> DPAA_FD_FORMAT_SHIFT;
	uint16_t offset;
	uint32_t length;

	if (unlikely(format == qm_fd_sg))
		return dpaa_eth_sg_to_mbuf(fd, ifid);

	offset = (fd->opaque & DPAA_FD_OFFSET_MASK) >> DPAA_FD_OFFSET_SHIFT;
	length = fd->opaque & DPAA_FD_LENGTH_MASK;

	DPAA_DP_LOG(DEBUG, " FD--->MBUF off %d len = %d", offset, length);

	/* Ignoring case when format != qm_fd_contig */
	ptr = DPAA_MEMPOOL_PTOV(bp_info, qm_fd_addr(fd));

	mbuf = (struct rte_mbuf *)((char *)ptr - bp_info->meta_data_size);
	/* Prefetch the Parse results and packet data to L1 */
	rte_prefetch0((void *)((uint8_t *)ptr + DEFAULT_RX_ICEOF));

	mbuf->data_off = offset;
	mbuf->data_len = length;
	mbuf->pkt_len = length;

	mbuf->port = ifid;
	mbuf->nb_segs = 1;
	mbuf->ol_flags = 0;
	mbuf->next = NULL;
	rte_mbuf_refcnt_set(mbuf, 1);
	dpaa_eth_packet_info(mbuf, mbuf->buf_addr);

	return mbuf;
}

uint16_t
dpaa_free_mbuf(const struct qm_fd *fd)
{
	struct rte_mbuf *mbuf;
	struct dpaa_bp_info *bp_info;
	uint8_t format;
	void *ptr;

	bp_info = DPAA_BPID_TO_POOL_INFO(fd->bpid);
	format = (fd->opaque & DPAA_FD_FORMAT_MASK) >> DPAA_FD_FORMAT_SHIFT;
	if (unlikely(format == qm_fd_sg)) {
		struct rte_mbuf *first_seg, *cur_seg;
		struct qm_sg_entry *sgt, *sg_temp;
		void *vaddr, *sg_vaddr;
		int i = 0;
		uint16_t fd_offset = fd->offset;

		vaddr = DPAA_MEMPOOL_PTOV(bp_info, qm_fd_addr(fd));
		if (!vaddr) {
			DPAA_PMD_ERR("unable to convert physical address");
			return -1;
		}
		sgt = vaddr + fd_offset;
		sg_temp = &sgt[i++];
		hw_sg_to_cpu(sg_temp);
		sg_vaddr = DPAA_MEMPOOL_PTOV(bp_info,
						qm_sg_entry_get64(sg_temp));
		first_seg = (struct rte_mbuf *)((char *)sg_vaddr -
						bp_info->meta_data_size);
		first_seg->nb_segs = 1;
		while (i < DPAA_SGT_MAX_ENTRIES) {
			sg_temp = &sgt[i++];
			hw_sg_to_cpu(sg_temp);
			if (sg_temp->bpid != 0xFF) {
				bp_info = DPAA_BPID_TO_POOL_INFO(sg_temp->bpid);
				sg_vaddr = DPAA_MEMPOOL_PTOV(bp_info,
						qm_sg_entry_get64(sg_temp));
				cur_seg = (struct rte_mbuf *)((char *)sg_vaddr -
						      bp_info->meta_data_size);
				rte_pktmbuf_free_seg(cur_seg);
			}
			if (sg_temp->final)
				break;
		}
		rte_pktmbuf_free_seg(first_seg);
		return 0;
	}

	ptr = DPAA_MEMPOOL_PTOV(bp_info, qm_fd_addr(fd));
	mbuf = (struct rte_mbuf *)((char *)ptr - bp_info->meta_data_size);

	rte_pktmbuf_free(mbuf);

	return 0;
}

/* Specific for LS1043 */
void
dpaa_rx_cb_no_prefetch(struct qman_fq **fq, struct qm_dqrr_entry **dqrr,
	   void **bufs, int num_bufs)
{
	struct rte_mbuf *mbuf;
	struct dpaa_bp_info *bp_info;
	const struct qm_fd *fd;
	void *ptr;
	struct dpaa_if *dpaa_intf;
	uint16_t offset, i;
	uint32_t length;
	uint8_t format;

	bp_info = DPAA_BPID_TO_POOL_INFO(dqrr[0]->fd.bpid);
	ptr = rte_dpaa_mem_ptov(qm_fd_addr(&dqrr[0]->fd));
	rte_prefetch0((void *)((uint8_t *)ptr + DEFAULT_RX_ICEOF));
	bufs[0] = (struct rte_mbuf *)((char *)ptr - bp_info->meta_data_size);

	for (i = 0; i < num_bufs; i++) {
		if (i < num_bufs - 1) {
			bp_info = DPAA_BPID_TO_POOL_INFO(dqrr[i + 1]->fd.bpid);
			ptr = rte_dpaa_mem_ptov(qm_fd_addr(&dqrr[i + 1]->fd));
			rte_prefetch0((void *)((uint8_t *)ptr +
					DEFAULT_RX_ICEOF));
			bufs[i + 1] = (struct rte_mbuf *)((char *)ptr -
					bp_info->meta_data_size);
		}

		fd = &dqrr[i]->fd;
		dpaa_intf = fq[0]->dpaa_intf;
		format = (fd->opaque & DPAA_FD_FORMAT_MASK) >>
				DPAA_FD_FORMAT_SHIFT;
		if (unlikely(format == qm_fd_sg)) {
			bufs[i] = dpaa_eth_sg_to_mbuf(fd, dpaa_intf->ifid);
			continue;
		}

		offset = (fd->opaque & DPAA_FD_OFFSET_MASK) >>
				DPAA_FD_OFFSET_SHIFT;
		length = fd->opaque & DPAA_FD_LENGTH_MASK;

		mbuf = bufs[i];
		mbuf->data_off = offset;
		mbuf->data_len = length;
		mbuf->pkt_len = length;
		mbuf->port = dpaa_intf->ifid;

		mbuf->nb_segs = 1;
		mbuf->ol_flags = 0;
		mbuf->next = NULL;
		rte_mbuf_refcnt_set(mbuf, 1);
		dpaa_eth_packet_info(mbuf, mbuf->buf_addr);
		dpaa_display_frame_info(fd, fq[0]->fqid, true);
	}
}

void
dpaa_rx_cb(struct qman_fq **fq, struct qm_dqrr_entry **dqrr,
	   void **bufs, int num_bufs)
{
	struct rte_mbuf *mbuf;
	const struct qm_fd *fd;
	struct dpaa_if *dpaa_intf;
	uint16_t offset, i;
	uint32_t length;
	uint8_t format;

	for (i = 0; i < num_bufs; i++) {
		fd = &dqrr[i]->fd;
		dpaa_intf = fq[0]->dpaa_intf;
		format = (fd->opaque & DPAA_FD_FORMAT_MASK) >>
				DPAA_FD_FORMAT_SHIFT;
		if (unlikely(format == qm_fd_sg)) {
			bufs[i] = dpaa_eth_sg_to_mbuf(fd, dpaa_intf->ifid);
			continue;
		}

		offset = (fd->opaque & DPAA_FD_OFFSET_MASK) >>
				DPAA_FD_OFFSET_SHIFT;
		length = fd->opaque & DPAA_FD_LENGTH_MASK;

		mbuf = bufs[i];
		mbuf->data_off = offset;
		mbuf->data_len = length;
		mbuf->pkt_len = length;
		mbuf->port = dpaa_intf->ifid;

		mbuf->nb_segs = 1;
		mbuf->ol_flags = 0;
		mbuf->next = NULL;
		rte_mbuf_refcnt_set(mbuf, 1);
		dpaa_eth_packet_info(mbuf, mbuf->buf_addr);
		dpaa_display_frame_info(fd, fq[0]->fqid, true);
	}
}

void dpaa_rx_cb_prepare(struct qm_dqrr_entry *dq, void **bufs)
{
	struct dpaa_bp_info *bp_info = DPAA_BPID_TO_POOL_INFO(dq->fd.bpid);
	void *ptr = rte_dpaa_mem_ptov(qm_fd_addr(&dq->fd));

	/* In case of LS1046, annotation stashing is disabled due to L2 cache
	 * being bottleneck in case of multicore scenario for this platform.
	 * So we prefetch the annotation beforehand, so that it is available
	 * in cache when accessed.
	 */
	rte_prefetch0((void *)((uint8_t *)ptr + DEFAULT_RX_ICEOF));

	*bufs = (struct rte_mbuf *)((char *)ptr - bp_info->meta_data_size);
}

static uint16_t
dpaa_eth_queue_portal_rx(struct qman_fq *fq,
			 struct rte_mbuf **bufs,
			 uint16_t nb_bufs)
{
	int ret;

	if (unlikely(!fq->qp_initialized)) {
		ret = rte_dpaa_portal_fq_init((void *)0, fq);
		if (ret) {
			DPAA_PMD_ERR("Failure in affining portal %d", ret);
			return 0;
		}
		fq->qp_initialized = 1;
	}

	return qman_portal_poll_rx(nb_bufs, (void **)bufs, fq->qp);
}

enum qman_cb_dqrr_result
dpaa_rx_cb_parallel(void *event,
		    struct qman_portal *qm __always_unused,
		    struct qman_fq *fq,
		    const struct qm_dqrr_entry *dqrr,
		    void **bufs)
{
	u32 ifid = ((struct dpaa_if *)fq->dpaa_intf)->ifid;
	struct rte_mbuf *mbuf;
	struct rte_event *ev = (struct rte_event *)event;

	mbuf = dpaa_eth_fd_to_mbuf(&dqrr->fd, ifid);
	ev->event_ptr = (void *)mbuf;
	ev->flow_id = fq->ev.flow_id;
	ev->sub_event_type = fq->ev.sub_event_type;
	ev->event_type = RTE_EVENT_TYPE_ETHDEV;
	ev->op = RTE_EVENT_OP_NEW;
	ev->sched_type = fq->ev.sched_type;
	ev->queue_id = fq->ev.queue_id;
	ev->priority = fq->ev.priority;
	ev->impl_opaque = (uint8_t)DPAA_INVALID_MBUF_SEQN;
	*dpaa_seqn(mbuf) = DPAA_INVALID_MBUF_SEQN;
	*bufs = mbuf;

	return qman_cb_dqrr_consume;
}

enum qman_cb_dqrr_result
dpaa_rx_cb_atomic(void *event,
		  struct qman_portal *qm __always_unused,
		  struct qman_fq *fq,
		  const struct qm_dqrr_entry *dqrr,
		  void **bufs)
{
	u8 index;
	u32 ifid = ((struct dpaa_if *)fq->dpaa_intf)->ifid;
	struct rte_mbuf *mbuf;
	struct rte_event *ev = (struct rte_event *)event;

	mbuf = dpaa_eth_fd_to_mbuf(&dqrr->fd, ifid);
	ev->event_ptr = (void *)mbuf;
	ev->flow_id = fq->ev.flow_id;
	ev->sub_event_type = fq->ev.sub_event_type;
	ev->event_type = RTE_EVENT_TYPE_ETHDEV;
	ev->op = RTE_EVENT_OP_NEW;
	ev->sched_type = fq->ev.sched_type;
	ev->queue_id = fq->ev.queue_id;
	ev->priority = fq->ev.priority;

	/* Save active dqrr entries */
	index = DQRR_PTR2IDX(dqrr);
	DPAA_PER_LCORE_DQRR_SIZE++;
	DPAA_PER_LCORE_DQRR_HELD |= 1 << index;
	DPAA_PER_LCORE_DQRR_MBUF(index) = mbuf;
	ev->impl_opaque = index + 1;
	*dpaa_seqn(mbuf) = (uint32_t)index + 1;
	*bufs = mbuf;

	return qman_cb_dqrr_defer;
}

#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
static inline void dpaa_eth_err_queue(struct dpaa_if *dpaa_intf)
{
	struct rte_mbuf *mbuf;
	struct qman_fq *debug_fq;
	int ret, i;
	struct qm_dqrr_entry *dq;
	struct qm_fd *fd;

	if (unlikely(!RTE_PER_LCORE(dpaa_io))) {
		ret = rte_dpaa_portal_init((void *)0);
		if (ret) {
			DPAA_PMD_ERR("Failure in affining portal");
			return;
		}
	}
	for (i = 0; i <= DPAA_DEBUG_FQ_TX_ERROR; i++) {
		debug_fq = &dpaa_intf->debug_queues[i];
		ret = qman_set_vdq(debug_fq, 4, QM_VDQCR_EXACT);
		if (ret)
			return;

		do {
			dq = qman_dequeue(debug_fq);
			if (!dq)
				continue;
			fd = &dq->fd;
			if (i == DPAA_DEBUG_FQ_RX_ERROR)
				DPAA_PMD_ERR("RX ERROR status: 0x%08x",
					fd->status);
			else
				DPAA_PMD_ERR("TX ERROR status: 0x%08x",
					fd->status);
			dpaa_display_frame_info(fd, debug_fq->fqid,
				i == DPAA_DEBUG_FQ_RX_ERROR);

			mbuf = dpaa_eth_fd_to_mbuf(fd, dpaa_intf->ifid);
			rte_pktmbuf_free(mbuf);
			qman_dqrr_consume(debug_fq, dq);
		} while (debug_fq->flags & QMAN_FQ_STATE_VDQCR);
	}
}
#endif

uint16_t dpaa_eth_queue_rx(void *q,
			   struct rte_mbuf **bufs,
			   uint16_t nb_bufs)
{
	struct qman_fq *fq = q;
	struct qm_dqrr_entry *dq;
	uint32_t num_rx = 0, ifid = ((struct dpaa_if *)fq->dpaa_intf)->ifid;
	int num_rx_bufs, ret;
	uint32_t vdqcr_flags = 0;

	if (unlikely(rte_dpaa_bpid_info == NULL &&
				rte_eal_process_type() == RTE_PROC_SECONDARY))
		rte_dpaa_bpid_info = fq->bp_array;

#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
	if (fq->fqid == ((struct dpaa_if *)fq->dpaa_intf)->rx_queues[0].fqid)
		dpaa_eth_err_queue((struct dpaa_if *)fq->dpaa_intf);
#endif

	if (likely(fq->is_static))
		return dpaa_eth_queue_portal_rx(fq, bufs, nb_bufs);

	if (unlikely(!DPAA_PER_LCORE_PORTAL)) {
		ret = rte_dpaa_portal_init((void *)0);
		if (ret) {
			DPAA_PMD_ERR("Failure in affining portal");
			return 0;
		}
	}

	/* Until request for four buffers, we provide exact number of buffers.
	 * Otherwise we do not set the QM_VDQCR_EXACT flag.
	 * Not setting QM_VDQCR_EXACT flag can provide two more buffers than
	 * requested, so we request two less in this case.
	 */
	if (nb_bufs < 4) {
		vdqcr_flags = QM_VDQCR_EXACT;
		num_rx_bufs = nb_bufs;
	} else {
		num_rx_bufs = nb_bufs > DPAA_MAX_DEQUEUE_NUM_FRAMES ?
			(DPAA_MAX_DEQUEUE_NUM_FRAMES - 2) : (nb_bufs - 2);
	}
	ret = qman_set_vdq(fq, num_rx_bufs, vdqcr_flags);
	if (ret)
		return 0;

	do {
		dq = qman_dequeue(fq);
		if (!dq)
			continue;
		bufs[num_rx++] = dpaa_eth_fd_to_mbuf(&dq->fd, ifid);
		dpaa_display_frame_info(&dq->fd, fq->fqid, true);
		qman_dqrr_consume(fq, dq);
	} while (fq->flags & QMAN_FQ_STATE_VDQCR);

	return num_rx;
}

static int
dpaa_eth_mbuf_to_sg_fd(struct rte_mbuf *mbuf,
		struct qm_fd *fd,
		struct dpaa_sw_buf_free *free_buf,
		uint32_t *free_count,
		uint32_t pkt_id)
{
	struct rte_mbuf *cur_seg = mbuf;
	struct rte_mbuf *temp, *mi;
	struct qm_sg_entry *sg_temp, *sgt;
	int i = 0;

	DPAA_DP_LOG(DEBUG, "Creating SG FD to transmit");

	temp = rte_pktmbuf_alloc(dpaa_tx_sg_pool);
	if (!temp) {
		DPAA_PMD_ERR("Failure in allocation of mbuf");
		return -1;
	}
	if (temp->buf_len < ((mbuf->nb_segs * sizeof(struct qm_sg_entry))
				+ temp->data_off)) {
		DPAA_PMD_ERR("Insufficient space in mbuf for SG entries");
		return -1;
	}

	fd->cmd = 0;
	fd->opaque_addr = 0;

	if (mbuf->ol_flags & DPAA_TX_CKSUM_OFFLOAD_MASK) {
		if (!mbuf->packet_type) {
			struct rte_net_hdr_lens hdr_lens;

			mbuf->packet_type = rte_net_get_ptype(mbuf, &hdr_lens,
					RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK
					| RTE_PTYPE_L4_MASK);
			mbuf->l2_len = hdr_lens.l2_len;
			mbuf->l3_len = hdr_lens.l3_len;
		}
		if (temp->data_off < DEFAULT_TX_ICEOF
			+ sizeof(struct dpaa_eth_parse_results_t))
			temp->data_off = DEFAULT_TX_ICEOF
				+ sizeof(struct dpaa_eth_parse_results_t);
		dcbz_64(temp->buf_addr);
		dpaa_checksum_offload(mbuf, fd, temp->buf_addr);
	}

	sgt = temp->buf_addr + temp->data_off;
	fd->format = QM_FD_SG;
	fd->addr = temp->buf_iova;
	fd->offset = temp->data_off;
	fd->bpid = DPAA_MEMPOOL_TO_BPID(dpaa_tx_sg_pool);
	fd->length20 = mbuf->pkt_len;

	while (i < DPAA_SGT_MAX_ENTRIES) {
		sg_temp = &sgt[i++];
		sg_temp->opaque = 0;
		sg_temp->val = 0;
		sg_temp->addr = cur_seg->buf_iova;
		sg_temp->offset = cur_seg->data_off;
		sg_temp->length = cur_seg->data_len;
		if (RTE_MBUF_DIRECT(cur_seg)) {
			if (rte_mbuf_refcnt_read(cur_seg) > 1) {
				/*If refcnt > 1, invalid bpid is set to ensure
				 * buffer is not freed by HW.
				 */
				sg_temp->bpid = 0xff;
				rte_mbuf_refcnt_update(cur_seg, -1);
			} else {
				sg_temp->bpid =
					DPAA_MEMPOOL_TO_BPID(cur_seg->pool);
			}
		} else if (RTE_MBUF_HAS_EXTBUF(cur_seg)) {
			free_buf[*free_count].seg = cur_seg;
			free_buf[*free_count].pkt_id = pkt_id;
			++*free_count;
			sg_temp->bpid = 0xff;
		} else {
			/* Get owner MBUF from indirect buffer */
			mi = rte_mbuf_from_indirect(cur_seg);
			if (rte_mbuf_refcnt_read(mi) > 1) {
				/*If refcnt > 1, invalid bpid is set to ensure
				 * owner buffer is not freed by HW.
				 */
				sg_temp->bpid = 0xff;
			} else {
				sg_temp->bpid = DPAA_MEMPOOL_TO_BPID(mi->pool);
				rte_mbuf_refcnt_update(mi, 1);
			}
			free_buf[*free_count].seg = cur_seg;
			free_buf[*free_count].pkt_id = pkt_id;
			++*free_count;
		}
		cur_seg = cur_seg->next;
		if (cur_seg == NULL) {
			sg_temp->final = 1;
			cpu_to_hw_sg(sg_temp);
			break;
		}
		cpu_to_hw_sg(sg_temp);
	}
	return 0;
}

/* Handle mbufs which are not segmented (non SG) */
static inline void
tx_on_dpaa_pool_unsegmented(struct rte_mbuf *mbuf,
			    struct dpaa_bp_info *bp_info,
			    struct qm_fd *fd_arr,
			    struct dpaa_sw_buf_free *buf_to_free,
			    uint32_t *free_count,
			    uint32_t pkt_id)
{
	struct rte_mbuf *mi = NULL;

	if (RTE_MBUF_DIRECT(mbuf)) {
		if (rte_mbuf_refcnt_read(mbuf) > 1) {
			/* In case of direct mbuf and mbuf being cloned,
			 * BMAN should _not_ release buffer.
			 */
			DPAA_MBUF_TO_CONTIG_FD(mbuf, fd_arr, 0xff);
			/* Buffer should be releasd by EAL */
			rte_mbuf_refcnt_update(mbuf, -1);
		} else {
			/* In case of direct mbuf and no cloning, mbuf can be
			 * released by BMAN.
			 */
			DPAA_MBUF_TO_CONTIG_FD(mbuf, fd_arr, bp_info->bpid);
		}
	} else if (RTE_MBUF_HAS_EXTBUF(mbuf)) {
		buf_to_free[*free_count].seg = mbuf;
		buf_to_free[*free_count].pkt_id = pkt_id;
		++*free_count;
		DPAA_MBUF_TO_CONTIG_FD(mbuf, fd_arr,
				bp_info ? bp_info->bpid : 0xff);
	} else {
		/* This is data-containing core mbuf: 'mi' */
		mi = rte_mbuf_from_indirect(mbuf);
		if (rte_mbuf_refcnt_read(mi) > 1) {
			/* In case of indirect mbuf, and mbuf being cloned,
			 * BMAN should _not_ release it and let EAL release
			 * it through pktmbuf_free below.
			 */
			DPAA_MBUF_TO_CONTIG_FD(mbuf, fd_arr, 0xff);
		} else {
			/* In case of indirect mbuf, and no cloning, core mbuf
			 * should be released by BMAN.
			 * Increate refcnt of core mbuf so that when
			 * pktmbuf_free is called and mbuf is released, EAL
			 * doesn't try to release core mbuf which would have
			 * been released by BMAN.
			 */
			rte_mbuf_refcnt_update(mi, 1);
			DPAA_MBUF_TO_CONTIG_FD(mbuf, fd_arr,
						bp_info ? bp_info->bpid : 0xff);
		}
		buf_to_free[*free_count].seg = mbuf;
		buf_to_free[*free_count].pkt_id = pkt_id;
		++*free_count;
	}

	if (mbuf->ol_flags & DPAA_TX_CKSUM_OFFLOAD_MASK)
		dpaa_unsegmented_checksum(mbuf, fd_arr);
}

/* Handle all mbufs on dpaa BMAN managed pool */
static inline uint16_t
tx_on_dpaa_pool(struct rte_mbuf *mbuf,
		struct dpaa_bp_info *bp_info,
		struct qm_fd *fd_arr,
		struct dpaa_sw_buf_free *buf_to_free,
		uint32_t *free_count,
		uint32_t pkt_id)
{
	DPAA_DP_LOG(DEBUG, "BMAN offloaded buffer, mbuf: %p", mbuf);

	if (mbuf->nb_segs == 1) {
		/* Case for non-segmented buffers */
		tx_on_dpaa_pool_unsegmented(mbuf, bp_info, fd_arr,
				buf_to_free, free_count, pkt_id);
	} else if (mbuf->nb_segs > 1 &&
		   mbuf->nb_segs <= DPAA_SGT_MAX_ENTRIES) {
		if (dpaa_eth_mbuf_to_sg_fd(mbuf, fd_arr, buf_to_free,
					   free_count, pkt_id)) {
			DPAA_PMD_DEBUG("Unable to create Scatter Gather FD");
			return 1;
		}
	} else {
		DPAA_PMD_DEBUG("Number of Segments not supported");
		return 1;
	}

	return 0;
}

/* Handle all mbufs on an external pool (non-dpaa) */
static inline struct rte_mbuf *
reallocate_mbuf(struct qman_fq *txq, struct rte_mbuf *mbuf)
{
	struct dpaa_if *dpaa_intf = txq->dpaa_intf;
	struct dpaa_bp_info *bp_info = dpaa_intf->bp_info;
	struct rte_mbuf *new_mbufs[DPAA_SGT_MAX_ENTRIES + 1] = {0};
	struct rte_mbuf *temp_mbuf;
	int num_new_segs, mbuf_greater, ret, extra_seg = 0, i = 0;
	uint64_t mbufs_size, bytes_to_copy, offset1 = 0, offset2 = 0;
	char *data;

	DPAA_DP_LOG(DEBUG, "Reallocating transmit buffer");

	mbufs_size = bp_info->size -
		bp_info->meta_data_size - RTE_PKTMBUF_HEADROOM;
	extra_seg = !!(mbuf->pkt_len % mbufs_size);
	num_new_segs = (mbuf->pkt_len / mbufs_size) + extra_seg;

	ret = rte_pktmbuf_alloc_bulk(bp_info->mp, new_mbufs, num_new_segs);
	if (ret != 0) {
		DPAA_DP_LOG(DEBUG, "Allocation for new buffers failed");
		return NULL;
	}

	temp_mbuf = mbuf;

	while (temp_mbuf) {
		/* If mbuf data is less than new mbuf remaining memory */
		if ((temp_mbuf->data_len - offset1) < (mbufs_size - offset2)) {
			bytes_to_copy = temp_mbuf->data_len - offset1;
			mbuf_greater = -1;
		/* If mbuf data is greater than new mbuf remaining memory */
		} else if ((temp_mbuf->data_len - offset1) >
			   (mbufs_size - offset2)) {
			bytes_to_copy = mbufs_size - offset2;
			mbuf_greater = 1;
		/* if mbuf data is equal to new mbuf remaining memory */
		} else {
			bytes_to_copy = temp_mbuf->data_len - offset1;
			mbuf_greater = 0;
		}

		/* Copy the data */
		data = rte_pktmbuf_append(new_mbufs[0], bytes_to_copy);

		rte_memcpy((uint8_t *)data, rte_pktmbuf_mtod_offset(mbuf,
			   void *, offset1), bytes_to_copy);

		/* Set new offsets and the temp buffers */
		if (mbuf_greater == -1) {
			offset1 = 0;
			offset2 += bytes_to_copy;
			temp_mbuf = temp_mbuf->next;
		} else if (mbuf_greater == 1) {
			offset2 = 0;
			offset1 += bytes_to_copy;
			new_mbufs[i]->next = new_mbufs[i + 1];
			new_mbufs[0]->nb_segs++;
			i++;
		} else {
			offset1 = 0;
			offset2 = 0;
			temp_mbuf = temp_mbuf->next;
			new_mbufs[i]->next = new_mbufs[i + 1];
			if (new_mbufs[i + 1])
				new_mbufs[0]->nb_segs++;
			i++;
		}
	}

	/* Copy other required fields */
	new_mbufs[0]->ol_flags = mbuf->ol_flags;
	new_mbufs[0]->packet_type = mbuf->packet_type;
	new_mbufs[0]->tx_offload = mbuf->tx_offload;

	rte_pktmbuf_free(mbuf);

	return new_mbufs[0];
}

uint16_t
dpaa_eth_queue_tx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	struct rte_mbuf *mbuf, *mi = NULL;
	struct rte_mempool *mp;
	struct dpaa_bp_info *bp_info;
	struct qm_fd fd_arr[DPAA_TX_BURST_SIZE];
	uint32_t frames_to_send, loop, sent = 0;
	uint16_t state;
	int ret, realloc_mbuf = 0;
	uint32_t seqn, index, flags[DPAA_TX_BURST_SIZE] = {0};
	struct dpaa_sw_buf_free buf_to_free[DPAA_MAX_SGS * DPAA_MAX_DEQUEUE_NUM_FRAMES];
	uint32_t free_count = 0;

	if (unlikely(!DPAA_PER_LCORE_PORTAL)) {
		ret = rte_dpaa_portal_init((void *)0);
		if (ret) {
			DPAA_PMD_ERR("Failure in affining portal");
			return 0;
		}
	}

	DPAA_DP_LOG(DEBUG, "Transmitting %d buffers on queue: %p", nb_bufs, q);

	while (nb_bufs) {
		frames_to_send = (nb_bufs > DPAA_TX_BURST_SIZE) ?
				DPAA_TX_BURST_SIZE : nb_bufs;
		for (loop = 0; loop < frames_to_send; loop++) {
			mbuf = *(bufs++);
			/* In case the data offset is not multiple of 16,
			 * FMAN can stall because of an errata. So reallocate
			 * the buffer in such case.
			 */
			if (dpaa_svr_family == SVR_LS1043A_FAMILY &&
					(mbuf->data_off & 0x7F) != 0x0)
				realloc_mbuf = 1;
			seqn = *dpaa_seqn(mbuf);
			if (seqn != DPAA_INVALID_MBUF_SEQN) {
				index = seqn - 1;
				if (DPAA_PER_LCORE_DQRR_HELD & (1 << index)) {
					flags[loop] =
					   ((index & QM_EQCR_DCA_IDXMASK) << 8);
					flags[loop] |= QMAN_ENQUEUE_FLAG_DCA;
					DPAA_PER_LCORE_DQRR_SIZE--;
					DPAA_PER_LCORE_DQRR_HELD &=
								~(1 << index);
				}
			}

			if (likely(RTE_MBUF_DIRECT(mbuf))) {
				mp = mbuf->pool;
				bp_info = DPAA_MEMPOOL_TO_POOL_INFO(mp);
				if (likely(mp->ops_index ==
						bp_info->dpaa_ops_index &&
					mbuf->nb_segs == 1 &&
					realloc_mbuf == 0 &&
					rte_mbuf_refcnt_read(mbuf) == 1)) {
					DPAA_MBUF_TO_CONTIG_FD(mbuf,
						&fd_arr[loop], bp_info->bpid);
					if (mbuf->ol_flags &
						DPAA_TX_CKSUM_OFFLOAD_MASK)
						dpaa_unsegmented_checksum(mbuf,
							&fd_arr[loop]);
					continue;
				}
			} else {
				mi = rte_mbuf_from_indirect(mbuf);
				mp = mi->pool;
			}

			if (unlikely(RTE_MBUF_HAS_EXTBUF(mbuf))) {
				bp_info = NULL;
				goto indirect_buf;
			}

			bp_info = DPAA_MEMPOOL_TO_POOL_INFO(mp);
			if (unlikely(mp->ops_index != bp_info->dpaa_ops_index ||
				     realloc_mbuf == 1)) {
				struct rte_mbuf *temp_mbuf;

				temp_mbuf = reallocate_mbuf(q, mbuf);
				if (!temp_mbuf) {
					/* Set frames_to_send & nb_bufs so
					 * that packets are transmitted till
					 * previous frame.
					 */
					frames_to_send = loop;
					nb_bufs = loop;
					goto send_pkts;
				}
				mbuf = temp_mbuf;
				realloc_mbuf = 0;
			}
indirect_buf:
			state = tx_on_dpaa_pool(mbuf, bp_info,
						&fd_arr[loop],
						buf_to_free,
						&free_count,
						loop);
			if (unlikely(state)) {
				/* Set frames_to_send & nb_bufs so
				 * that packets are transmitted till
				 * previous frame.
				 */
				frames_to_send = loop;
				nb_bufs = loop;
				goto send_pkts;
			}
		}

send_pkts:
		loop = 0;
		while (loop < frames_to_send) {
			loop += qman_enqueue_multi(q, &fd_arr[loop],
						   &flags[loop],
						   frames_to_send - loop);
		}
		nb_bufs -= frames_to_send;
		sent += frames_to_send;
	}

	DPAA_DP_LOG(DEBUG, "Transmitted %d buffers on queue: %p", sent, q);

	for (loop = 0; loop < free_count; loop++) {
		if (buf_to_free[loop].pkt_id < sent)
			rte_pktmbuf_free_seg(buf_to_free[loop].seg);
	}

	return sent;
}

uint16_t
dpaa_eth_queue_tx_slow(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	qman_ern_poll_free();

	return dpaa_eth_queue_tx(q, bufs, nb_bufs);
}

uint16_t dpaa_eth_tx_drop_all(void *q  __rte_unused,
			      struct rte_mbuf **bufs __rte_unused,
		uint16_t nb_bufs __rte_unused)
{
	DPAA_DP_LOG(DEBUG, "Drop all packets");

	/* Drop all incoming packets. No need to free packets here
	 * because the rte_eth f/w frees up the packets through tx_buffer
	 * callback in case this functions returns count less than nb_bufs
	 */
	return 0;
}
