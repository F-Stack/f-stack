/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#ifndef __L3FWD_LPM_SSE_H__
#define __L3FWD_LPM_SSE_H__

#include "l3fwd_sse.h"

/*
 * Read packet_type and destination IPV4 addresses from 4 mbufs.
 */
static inline void
processx4_step1(struct rte_mbuf *pkt[FWDSTEP],
		__m128i *dip,
		uint32_t *ipv4_flag)
{
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ether_hdr *eth_hdr;
	uint32_t x0, x1, x2, x3;

	eth_hdr = rte_pktmbuf_mtod(pkt[0], struct rte_ether_hdr *);
	ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
	x0 = ipv4_hdr->dst_addr;
	ipv4_flag[0] = pkt[0]->packet_type & RTE_PTYPE_L3_IPV4;

	eth_hdr = rte_pktmbuf_mtod(pkt[1], struct rte_ether_hdr *);
	ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
	x1 = ipv4_hdr->dst_addr;
	ipv4_flag[0] &= pkt[1]->packet_type;

	eth_hdr = rte_pktmbuf_mtod(pkt[2], struct rte_ether_hdr *);
	ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
	x2 = ipv4_hdr->dst_addr;
	ipv4_flag[0] &= pkt[2]->packet_type;

	eth_hdr = rte_pktmbuf_mtod(pkt[3], struct rte_ether_hdr *);
	ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
	x3 = ipv4_hdr->dst_addr;
	ipv4_flag[0] &= pkt[3]->packet_type;

	dip[0] = _mm_set_epi32(x3, x2, x1, x0);
}

/*
 * Lookup into LPM for destination port.
 * If lookup fails, use incoming port (portid) as destination port.
 */
static inline void
processx4_step2(const struct lcore_conf *qconf,
		__m128i dip,
		uint32_t ipv4_flag,
		uint16_t portid,
		struct rte_mbuf *pkt[FWDSTEP],
		uint16_t dprt[FWDSTEP])
{
	rte_xmm_t dst;
	const  __m128i bswap_mask = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11,
						4, 5, 6, 7, 0, 1, 2, 3);

	/* Byte swap 4 IPV4 addresses. */
	dip = _mm_shuffle_epi8(dip, bswap_mask);

	/* if all 4 packets are IPV4. */
	if (likely(ipv4_flag)) {
		rte_lpm_lookupx4(qconf->ipv4_lookup_struct, dip, dst.u32,
			portid);
		/* get rid of unused upper 16 bit for each dport. */
		dst.x = _mm_packs_epi32(dst.x, dst.x);
		*(uint64_t *)dprt = dst.u64[0];
	} else {
		dst.x = dip;
		dprt[0] = lpm_get_dst_port_with_ipv4(qconf, pkt[0], dst.u32[0], portid);
		dprt[1] = lpm_get_dst_port_with_ipv4(qconf, pkt[1], dst.u32[1], portid);
		dprt[2] = lpm_get_dst_port_with_ipv4(qconf, pkt[2], dst.u32[2], portid);
		dprt[3] = lpm_get_dst_port_with_ipv4(qconf, pkt[3], dst.u32[3], portid);
	}
}

/*
 * Buffer optimized handling of packets, invoked
 * from main_loop.
 */
static inline void
l3fwd_lpm_process_packets(int nb_rx, struct rte_mbuf **pkts_burst,
			  uint16_t portid, uint16_t *dst_port,
			  struct lcore_conf *qconf, const uint8_t do_step3)
{
	int32_t j;
	__m128i dip[MAX_PKT_BURST / FWDSTEP];
	uint32_t ipv4_flag[MAX_PKT_BURST / FWDSTEP];
	const int32_t k = RTE_ALIGN_FLOOR(nb_rx, FWDSTEP);

	for (j = 0; j != k; j += FWDSTEP)
		processx4_step1(&pkts_burst[j], &dip[j / FWDSTEP],
				&ipv4_flag[j / FWDSTEP]);

	for (j = 0; j != k; j += FWDSTEP)
		processx4_step2(qconf, dip[j / FWDSTEP],
				ipv4_flag[j / FWDSTEP], portid, &pkts_burst[j], &dst_port[j]);

	if (do_step3)
		for (j = 0; j != k; j += FWDSTEP)
			processx4_step3(&pkts_burst[j], &dst_port[j]);

	/* Classify last up to 3 packets one by one */
	switch (nb_rx % FWDSTEP) {
	case 3:
		dst_port[j] = lpm_get_dst_port(qconf, pkts_burst[j], portid);
		if (do_step3)
			process_packet(pkts_burst[j], &dst_port[j]);
		j++;
		/* fall-through */
	case 2:
		dst_port[j] = lpm_get_dst_port(qconf, pkts_burst[j], portid);
		if (do_step3)
			process_packet(pkts_burst[j], &dst_port[j]);
		j++;
		/* fall-through */
	case 1:
		dst_port[j] = lpm_get_dst_port(qconf, pkts_burst[j], portid);
		if (do_step3)
			process_packet(pkts_burst[j], &dst_port[j]);
		j++;
	}
}

static inline void
l3fwd_lpm_send_packets(int nb_rx, struct rte_mbuf **pkts_burst, uint16_t portid,
		       struct lcore_conf *qconf)
{
	uint16_t dst_port[MAX_PKT_BURST];

	l3fwd_lpm_process_packets(nb_rx, pkts_burst, portid, dst_port, qconf,
				  0);
	send_packets_multi(qconf, pkts_burst, dst_port, nb_rx);
}

#endif /* __L3FWD_LPM_SSE_H__ */
