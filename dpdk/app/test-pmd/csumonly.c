/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation.
 * Copyright 2014 6WIND S.A.
 */

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_vxlan.h>
#include <rte_sctp.h>
#include <rte_gtp.h>
#include <rte_prefetch.h>
#include <rte_string_fns.h>
#include <rte_flow.h>
#ifdef RTE_LIB_GRO
#include <rte_gro.h>
#endif
#ifdef RTE_LIB_GSO
#include <rte_gso.h>
#endif
#include <rte_geneve.h>

#include "testpmd.h"

#define IP_DEFTTL  64   /* from RFC 1340. */

#define GRE_CHECKSUM_PRESENT	0x8000
#define GRE_KEY_PRESENT		0x2000
#define GRE_SEQUENCE_PRESENT	0x1000
#define GRE_EXT_LEN		4
#define GRE_SUPPORTED_FIELDS	(GRE_CHECKSUM_PRESENT | GRE_KEY_PRESENT |\
				 GRE_SEQUENCE_PRESENT)

/* We cannot use rte_cpu_to_be_16() on a constant in a switch/case */
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
#define _htons(x) ((uint16_t)((((x) & 0x00ffU) << 8) | (((x) & 0xff00U) >> 8)))
#else
#define _htons(x) (x)
#endif

uint16_t vxlan_gpe_udp_port = RTE_VXLAN_GPE_DEFAULT_PORT;
uint16_t geneve_udp_port = RTE_GENEVE_DEFAULT_PORT;

/* structure that caches offload info for the current packet */
struct testpmd_offload_info {
	uint16_t ethertype;
#ifdef RTE_LIB_GSO
	uint8_t gso_enable;
#endif
	uint16_t l2_len;
	uint16_t l3_len;
	uint16_t l4_len;
	uint8_t l4_proto;
	uint8_t is_tunnel;
	uint16_t outer_ethertype;
	uint16_t outer_l2_len;
	uint16_t outer_l3_len;
	uint8_t outer_l4_proto;
	uint16_t tso_segsz;
	uint16_t tunnel_tso_segsz;
	uint32_t pkt_len;
};

/* simplified GRE header */
struct simple_gre_hdr {
	uint16_t flags;
	uint16_t proto;
} __rte_packed;

static uint16_t
get_udptcp_checksum(struct rte_mbuf *m, void *l3_hdr, uint16_t l4_off,
		    uint16_t ethertype)
{
	if (ethertype == _htons(RTE_ETHER_TYPE_IPV4))
		return rte_ipv4_udptcp_cksum_mbuf(m, l3_hdr, l4_off);
	else /* assume ethertype == RTE_ETHER_TYPE_IPV6 */
		return rte_ipv6_udptcp_cksum_mbuf(m, l3_hdr, l4_off);
}

/* Parse an IPv4 header to fill l3_len, l4_len, and l4_proto */
static void
parse_ipv4(struct rte_ipv4_hdr *ipv4_hdr, struct testpmd_offload_info *info)
{
	struct rte_tcp_hdr *tcp_hdr;

	info->l3_len = rte_ipv4_hdr_len(ipv4_hdr);
	info->l4_proto = ipv4_hdr->next_proto_id;

	/* only fill l4_len for TCP, it's useful for TSO */
	if (info->l4_proto == IPPROTO_TCP) {
		tcp_hdr = (struct rte_tcp_hdr *)
			((char *)ipv4_hdr + info->l3_len);
		info->l4_len = (tcp_hdr->data_off & 0xf0) >> 2;
	} else if (info->l4_proto == IPPROTO_UDP)
		info->l4_len = sizeof(struct rte_udp_hdr);
	else
		info->l4_len = 0;
}

/* Parse an IPv6 header to fill l3_len, l4_len, and l4_proto */
static void
parse_ipv6(struct rte_ipv6_hdr *ipv6_hdr, struct testpmd_offload_info *info)
{
	struct rte_tcp_hdr *tcp_hdr;

	info->l3_len = sizeof(struct rte_ipv6_hdr);
	info->l4_proto = ipv6_hdr->proto;

	/* only fill l4_len for TCP, it's useful for TSO */
	if (info->l4_proto == IPPROTO_TCP) {
		tcp_hdr = (struct rte_tcp_hdr *)
			((char *)ipv6_hdr + info->l3_len);
		info->l4_len = (tcp_hdr->data_off & 0xf0) >> 2;
	} else if (info->l4_proto == IPPROTO_UDP)
		info->l4_len = sizeof(struct rte_udp_hdr);
	else
		info->l4_len = 0;
}

/*
 * Parse an ethernet header to fill the ethertype, l2_len, l3_len and
 * ipproto. This function is able to recognize IPv4/IPv6 with optional VLAN
 * headers. The l4_len argument is only set in case of TCP (useful for TSO).
 */
static void
parse_ethernet(struct rte_ether_hdr *eth_hdr, struct testpmd_offload_info *info)
{
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_vlan_hdr *vlan_hdr;

	info->l2_len = sizeof(struct rte_ether_hdr);
	info->ethertype = eth_hdr->ether_type;

	while (info->ethertype == _htons(RTE_ETHER_TYPE_VLAN) ||
	       info->ethertype == _htons(RTE_ETHER_TYPE_QINQ)) {
		vlan_hdr = (struct rte_vlan_hdr *)
			((char *)eth_hdr + info->l2_len);
		info->l2_len  += sizeof(struct rte_vlan_hdr);
		info->ethertype = vlan_hdr->eth_proto;
	}

	switch (info->ethertype) {
	case _htons(RTE_ETHER_TYPE_IPV4):
		ipv4_hdr = (struct rte_ipv4_hdr *)
			((char *)eth_hdr + info->l2_len);
		parse_ipv4(ipv4_hdr, info);
		break;
	case _htons(RTE_ETHER_TYPE_IPV6):
		ipv6_hdr = (struct rte_ipv6_hdr *)
			((char *)eth_hdr + info->l2_len);
		parse_ipv6(ipv6_hdr, info);
		break;
	default:
		info->l4_len = 0;
		info->l3_len = 0;
		info->l4_proto = 0;
		break;
	}
}

/* Fill in outer layers length */
static void
update_tunnel_outer(struct testpmd_offload_info *info)
{
	info->is_tunnel = 1;
	info->outer_ethertype = info->ethertype;
	info->outer_l2_len = info->l2_len;
	info->outer_l3_len = info->l3_len;
	info->outer_l4_proto = info->l4_proto;
}

/*
 * Parse a GTP protocol header.
 * No optional fields and next extension header type.
 */
static void
parse_gtp(struct rte_udp_hdr *udp_hdr,
	  struct testpmd_offload_info *info)
{
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_gtp_hdr *gtp_hdr;
	uint8_t gtp_len = sizeof(*gtp_hdr);
	uint8_t ip_ver;

	/* Check udp destination port. */
	if (udp_hdr->dst_port != _htons(RTE_GTPC_UDP_PORT) &&
	    udp_hdr->src_port != _htons(RTE_GTPC_UDP_PORT) &&
	    udp_hdr->dst_port != _htons(RTE_GTPU_UDP_PORT))
		return;

	update_tunnel_outer(info);
	info->l2_len = 0;

	gtp_hdr = (struct rte_gtp_hdr *)((char *)udp_hdr +
		  sizeof(struct rte_udp_hdr));
	if (gtp_hdr->e || gtp_hdr->s || gtp_hdr->pn)
		gtp_len += sizeof(struct rte_gtp_hdr_ext_word);
	/*
	 * Check message type. If message type is 0xff, it is
	 * a GTP data packet. If not, it is a GTP control packet
	 */
	if (gtp_hdr->msg_type == 0xff) {
		ip_ver = *(uint8_t *)((char *)gtp_hdr + gtp_len);
		ip_ver = (ip_ver) & 0xf0;

		if (ip_ver == RTE_GTP_TYPE_IPV4) {
			ipv4_hdr = (struct rte_ipv4_hdr *)((char *)gtp_hdr +
				   gtp_len);
			info->ethertype = _htons(RTE_ETHER_TYPE_IPV4);
			parse_ipv4(ipv4_hdr, info);
		} else if (ip_ver == RTE_GTP_TYPE_IPV6) {
			ipv6_hdr = (struct rte_ipv6_hdr *)((char *)gtp_hdr +
				   gtp_len);
			info->ethertype = _htons(RTE_ETHER_TYPE_IPV6);
			parse_ipv6(ipv6_hdr, info);
		}
	} else {
		info->ethertype = 0;
		info->l4_len = 0;
		info->l3_len = 0;
		info->l4_proto = 0;
	}

	info->l2_len += gtp_len + sizeof(*udp_hdr);
}

/* Parse a vxlan header */
static void
parse_vxlan(struct rte_udp_hdr *udp_hdr,
	    struct testpmd_offload_info *info)
{
	struct rte_ether_hdr *eth_hdr;

	/* check udp destination port, RTE_VXLAN_DEFAULT_PORT (4789) is the
	 * default vxlan port (rfc7348) or that the rx offload flag is set
	 * (i40e only currently)
	 */
	if (udp_hdr->dst_port != _htons(RTE_VXLAN_DEFAULT_PORT))
		return;

	update_tunnel_outer(info);

	eth_hdr = (struct rte_ether_hdr *)((char *)udp_hdr +
		sizeof(struct rte_udp_hdr) +
		sizeof(struct rte_vxlan_hdr));

	parse_ethernet(eth_hdr, info);
	info->l2_len += RTE_ETHER_VXLAN_HLEN; /* add udp + vxlan */
}

/* Parse a vxlan-gpe header */
static void
parse_vxlan_gpe(struct rte_udp_hdr *udp_hdr,
	    struct testpmd_offload_info *info)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_vxlan_gpe_hdr *vxlan_gpe_hdr;
	uint8_t vxlan_gpe_len = sizeof(*vxlan_gpe_hdr);

	/* Check udp destination port. */
	if (udp_hdr->dst_port != _htons(vxlan_gpe_udp_port))
		return;

	vxlan_gpe_hdr = (struct rte_vxlan_gpe_hdr *)((char *)udp_hdr +
				sizeof(struct rte_udp_hdr));

	if (!vxlan_gpe_hdr->proto || vxlan_gpe_hdr->proto ==
	    RTE_VXLAN_GPE_TYPE_IPV4) {
		update_tunnel_outer(info);

		ipv4_hdr = (struct rte_ipv4_hdr *)((char *)vxlan_gpe_hdr +
			   vxlan_gpe_len);

		parse_ipv4(ipv4_hdr, info);
		info->ethertype = _htons(RTE_ETHER_TYPE_IPV4);
		info->l2_len = 0;

	} else if (vxlan_gpe_hdr->proto == RTE_VXLAN_GPE_TYPE_IPV6) {
		update_tunnel_outer(info);

		ipv6_hdr = (struct rte_ipv6_hdr *)((char *)vxlan_gpe_hdr +
			   vxlan_gpe_len);

		info->ethertype = _htons(RTE_ETHER_TYPE_IPV6);
		parse_ipv6(ipv6_hdr, info);
		info->l2_len = 0;

	} else if (vxlan_gpe_hdr->proto == RTE_VXLAN_GPE_TYPE_ETH) {
		update_tunnel_outer(info);

		eth_hdr = (struct rte_ether_hdr *)((char *)vxlan_gpe_hdr +
			  vxlan_gpe_len);

		parse_ethernet(eth_hdr, info);
	} else
		return;

	info->l2_len += RTE_ETHER_VXLAN_GPE_HLEN;
}

/* Parse a geneve header */
static void
parse_geneve(struct rte_udp_hdr *udp_hdr,
	    struct testpmd_offload_info *info)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_geneve_hdr *geneve_hdr;
	uint16_t geneve_len;

	/* Check udp destination port. */
	if (udp_hdr->dst_port != _htons(geneve_udp_port))
		return;

	geneve_hdr = (struct rte_geneve_hdr *)((char *)udp_hdr +
				sizeof(struct rte_udp_hdr));
	geneve_len = sizeof(struct rte_geneve_hdr) + geneve_hdr->opt_len * 4;
	if (!geneve_hdr->proto || geneve_hdr->proto ==
	    _htons(RTE_ETHER_TYPE_IPV4)) {
		update_tunnel_outer(info);
		ipv4_hdr = (struct rte_ipv4_hdr *)((char *)geneve_hdr +
			   geneve_len);
		parse_ipv4(ipv4_hdr, info);
		info->ethertype = _htons(RTE_ETHER_TYPE_IPV4);
		info->l2_len = 0;
	} else if (geneve_hdr->proto == _htons(RTE_ETHER_TYPE_IPV6)) {
		update_tunnel_outer(info);
		ipv6_hdr = (struct rte_ipv6_hdr *)((char *)geneve_hdr +
			   geneve_len);
		info->ethertype = _htons(RTE_ETHER_TYPE_IPV6);
		parse_ipv6(ipv6_hdr, info);
		info->l2_len = 0;

	} else if (geneve_hdr->proto == _htons(RTE_GENEVE_TYPE_ETH)) {
		update_tunnel_outer(info);
		eth_hdr = (struct rte_ether_hdr *)((char *)geneve_hdr +
			  geneve_len);
		parse_ethernet(eth_hdr, info);
	} else
		return;

	info->l2_len +=
		(sizeof(struct rte_udp_hdr) + sizeof(struct rte_geneve_hdr) +
		((struct rte_geneve_hdr *)geneve_hdr)->opt_len * 4);
}

/* Parse a gre header */
static void
parse_gre(struct simple_gre_hdr *gre_hdr, struct testpmd_offload_info *info)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	uint8_t gre_len = 0;

	gre_len += sizeof(struct simple_gre_hdr);

	if (gre_hdr->flags & _htons(GRE_KEY_PRESENT))
		gre_len += GRE_EXT_LEN;
	if (gre_hdr->flags & _htons(GRE_SEQUENCE_PRESENT))
		gre_len += GRE_EXT_LEN;
	if (gre_hdr->flags & _htons(GRE_CHECKSUM_PRESENT))
		gre_len += GRE_EXT_LEN;

	if (gre_hdr->proto == _htons(RTE_ETHER_TYPE_IPV4)) {
		update_tunnel_outer(info);

		ipv4_hdr = (struct rte_ipv4_hdr *)((char *)gre_hdr + gre_len);

		parse_ipv4(ipv4_hdr, info);
		info->ethertype = _htons(RTE_ETHER_TYPE_IPV4);
		info->l2_len = 0;

	} else if (gre_hdr->proto == _htons(RTE_ETHER_TYPE_IPV6)) {
		update_tunnel_outer(info);

		ipv6_hdr = (struct rte_ipv6_hdr *)((char *)gre_hdr + gre_len);

		info->ethertype = _htons(RTE_ETHER_TYPE_IPV6);
		parse_ipv6(ipv6_hdr, info);
		info->l2_len = 0;

	} else if (gre_hdr->proto == _htons(RTE_ETHER_TYPE_TEB)) {
		update_tunnel_outer(info);

		eth_hdr = (struct rte_ether_hdr *)((char *)gre_hdr + gre_len);

		parse_ethernet(eth_hdr, info);
	} else
		return;

	info->l2_len += gre_len;
}


/* Parse an encapsulated ip or ipv6 header */
static void
parse_encap_ip(void *encap_ip, struct testpmd_offload_info *info)
{
	struct rte_ipv4_hdr *ipv4_hdr = encap_ip;
	struct rte_ipv6_hdr *ipv6_hdr = encap_ip;
	uint8_t ip_version;

	ip_version = (ipv4_hdr->version_ihl & 0xf0) >> 4;

	if (ip_version != 4 && ip_version != 6)
		return;

	info->is_tunnel = 1;
	info->outer_ethertype = info->ethertype;
	info->outer_l2_len = info->l2_len;
	info->outer_l3_len = info->l3_len;

	if (ip_version == 4) {
		parse_ipv4(ipv4_hdr, info);
		info->ethertype = _htons(RTE_ETHER_TYPE_IPV4);
	} else {
		parse_ipv6(ipv6_hdr, info);
		info->ethertype = _htons(RTE_ETHER_TYPE_IPV6);
	}
	info->l2_len = 0;
}

/* if possible, calculate the checksum of a packet in hw or sw,
 * depending on the testpmd command line configuration */
static uint64_t
process_inner_cksums(void *l3_hdr, const struct testpmd_offload_info *info,
	uint64_t tx_offloads, struct rte_mbuf *m)
{
	struct rte_ipv4_hdr *ipv4_hdr = l3_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_sctp_hdr *sctp_hdr;
	uint64_t ol_flags = 0;
	uint32_t max_pkt_len, tso_segsz = 0;
	uint16_t l4_off;

	/* ensure packet is large enough to require tso */
	if (!info->is_tunnel) {
		max_pkt_len = info->l2_len + info->l3_len + info->l4_len +
			info->tso_segsz;
		if (info->tso_segsz != 0 && info->pkt_len > max_pkt_len)
			tso_segsz = info->tso_segsz;
	} else {
		max_pkt_len = info->outer_l2_len + info->outer_l3_len +
			info->l2_len + info->l3_len + info->l4_len +
			info->tunnel_tso_segsz;
		if (info->tunnel_tso_segsz != 0 && info->pkt_len > max_pkt_len)
			tso_segsz = info->tunnel_tso_segsz;
	}

	if (info->ethertype == _htons(RTE_ETHER_TYPE_IPV4)) {
		ipv4_hdr = l3_hdr;

		ol_flags |= RTE_MBUF_F_TX_IPV4;
		if (info->l4_proto == IPPROTO_TCP && tso_segsz) {
			ol_flags |= RTE_MBUF_F_TX_IP_CKSUM;
		} else {
			if (tx_offloads & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) {
				ol_flags |= RTE_MBUF_F_TX_IP_CKSUM;
			} else {
				ipv4_hdr->hdr_checksum = 0;
				ipv4_hdr->hdr_checksum =
					rte_ipv4_cksum(ipv4_hdr);
			}
		}
	} else if (info->ethertype == _htons(RTE_ETHER_TYPE_IPV6))
		ol_flags |= RTE_MBUF_F_TX_IPV6;
	else
		return 0; /* packet type not supported, nothing to do */

	if (info->l4_proto == IPPROTO_UDP) {
		udp_hdr = (struct rte_udp_hdr *)((char *)l3_hdr + info->l3_len);
		/* do not recalculate udp cksum if it was 0 */
		if (udp_hdr->dgram_cksum != 0) {
			if (tx_offloads & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) {
				ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
			} else {
				if (info->is_tunnel)
					l4_off = info->outer_l2_len +
						 info->outer_l3_len +
						 info->l2_len + info->l3_len;
				else
					l4_off = info->l2_len +	info->l3_len;
				udp_hdr->dgram_cksum = 0;
				udp_hdr->dgram_cksum =
					get_udptcp_checksum(m, l3_hdr, l4_off,
						info->ethertype);
			}
		}
#ifdef RTE_LIB_GSO
		if (info->gso_enable)
			ol_flags |= RTE_MBUF_F_TX_UDP_SEG;
#endif
	} else if (info->l4_proto == IPPROTO_TCP) {
		tcp_hdr = (struct rte_tcp_hdr *)((char *)l3_hdr + info->l3_len);
		if (tso_segsz)
			ol_flags |= RTE_MBUF_F_TX_TCP_SEG;
		else if (tx_offloads & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) {
			ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
		} else {
			if (info->is_tunnel)
				l4_off = info->outer_l2_len + info->outer_l3_len +
					 info->l2_len + info->l3_len;
			else
				l4_off = info->l2_len + info->l3_len;
			tcp_hdr->cksum = 0;
			tcp_hdr->cksum =
				get_udptcp_checksum(m, l3_hdr, l4_off,
					info->ethertype);
		}
#ifdef RTE_LIB_GSO
		if (info->gso_enable)
			ol_flags |= RTE_MBUF_F_TX_TCP_SEG;
#endif
	} else if (info->l4_proto == IPPROTO_SCTP) {
		sctp_hdr = (struct rte_sctp_hdr *)
			((char *)l3_hdr + info->l3_len);
		/* sctp payload must be a multiple of 4 to be
		 * offloaded */
		if ((tx_offloads & RTE_ETH_TX_OFFLOAD_SCTP_CKSUM) &&
			((ipv4_hdr->total_length & 0x3) == 0)) {
			ol_flags |= RTE_MBUF_F_TX_SCTP_CKSUM;
		} else {
			sctp_hdr->cksum = 0;
			/* XXX implement CRC32c, example available in
			 * RFC3309 */
		}
	}

	return ol_flags;
}

/* Calculate the checksum of outer header */
static uint64_t
process_outer_cksums(void *outer_l3_hdr, struct testpmd_offload_info *info,
	uint64_t tx_offloads, int tso_enabled, struct rte_mbuf *m)
{
	struct rte_udp_hdr *udp_hdr;
	uint64_t ol_flags = 0;

	if (info->outer_ethertype == _htons(RTE_ETHER_TYPE_IPV4)) {
		ol_flags |= RTE_MBUF_F_TX_OUTER_IPV4;

		if (tx_offloads	& RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM) {
			ol_flags |= RTE_MBUF_F_TX_OUTER_IP_CKSUM;
		} else {
			struct rte_ipv4_hdr *ipv4_hdr = outer_l3_hdr;

			ipv4_hdr->hdr_checksum = 0;
			ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
		}
	} else {
		ol_flags |= RTE_MBUF_F_TX_OUTER_IPV6;
	}

	if (info->outer_l4_proto != IPPROTO_UDP)
		return ol_flags;

	udp_hdr = (struct rte_udp_hdr *)
		((char *)outer_l3_hdr + info->outer_l3_len);

	if (tso_enabled)
		ol_flags |= RTE_MBUF_F_TX_TCP_SEG;

	/* Skip SW outer UDP checksum generation if HW supports it */
	if (tx_offloads & RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM) {
		ol_flags |= RTE_MBUF_F_TX_OUTER_UDP_CKSUM;
		return ol_flags;
	}

	/* outer UDP checksum is done in software. In the other side, for
	 * UDP tunneling, like VXLAN or Geneve, outer UDP checksum can be
	 * set to zero.
	 *
	 * If a packet will be TSOed into small packets by NIC, we cannot
	 * set/calculate a non-zero checksum, because it will be a wrong
	 * value after the packet be split into several small packets.
	 */
	if (tso_enabled)
		udp_hdr->dgram_cksum = 0;

	/* do not recalculate udp cksum if it was 0 */
	if (udp_hdr->dgram_cksum != 0) {
		udp_hdr->dgram_cksum = 0;
		udp_hdr->dgram_cksum = get_udptcp_checksum(m, outer_l3_hdr,
					info->outer_l2_len + info->outer_l3_len,
					info->outer_ethertype);
	}

	return ol_flags;
}

/*
 * Helper function.
 * Performs actual copying.
 * Returns number of segments in the destination mbuf on success,
 * or negative error code on failure.
 */
static int
mbuf_copy_split(const struct rte_mbuf *ms, struct rte_mbuf *md[],
	uint16_t seglen[], uint8_t nb_seg)
{
	uint32_t dlen, slen, tlen;
	uint32_t i, len;
	const struct rte_mbuf *m;
	const uint8_t *src;
	uint8_t *dst;

	dlen = 0;
	slen = 0;
	tlen = 0;

	dst = NULL;
	src = NULL;

	m = ms;
	i = 0;
	while (ms != NULL && i != nb_seg) {

		if (slen == 0) {
			slen = rte_pktmbuf_data_len(ms);
			src = rte_pktmbuf_mtod(ms, const uint8_t *);
		}

		if (dlen == 0) {
			dlen = RTE_MIN(seglen[i], slen);
			md[i]->data_len = dlen;
			md[i]->next = (i + 1 == nb_seg) ? NULL : md[i + 1];
			dst = rte_pktmbuf_mtod(md[i], uint8_t *);
		}

		len = RTE_MIN(slen, dlen);
		memcpy(dst, src, len);
		tlen += len;
		slen -= len;
		dlen -= len;
		src += len;
		dst += len;

		if (slen == 0)
			ms = ms->next;
		if (dlen == 0)
			i++;
	}

	if (ms != NULL)
		return -ENOBUFS;
	else if (tlen != m->pkt_len)
		return -EINVAL;

	md[0]->nb_segs = nb_seg;
	md[0]->pkt_len = tlen;
	md[0]->vlan_tci = m->vlan_tci;
	md[0]->vlan_tci_outer = m->vlan_tci_outer;
	md[0]->ol_flags = m->ol_flags;
	md[0]->tx_offload = m->tx_offload;

	return nb_seg;
}

/*
 * Allocate a new mbuf with up to tx_pkt_nb_segs segments.
 * Copy packet contents and offload information into the new segmented mbuf.
 */
static struct rte_mbuf *
pkt_copy_split(const struct rte_mbuf *pkt)
{
	int32_t n, rc;
	uint32_t i, len, nb_seg;
	struct rte_mempool *mp;
	uint16_t seglen[RTE_MAX_SEGS_PER_PKT];
	struct rte_mbuf *p, *md[RTE_MAX_SEGS_PER_PKT];

	mp = current_fwd_lcore()->mbp;

	if (tx_pkt_split == TX_PKT_SPLIT_RND)
		nb_seg = rte_rand() % tx_pkt_nb_segs + 1;
	else
		nb_seg = tx_pkt_nb_segs;

	memcpy(seglen, tx_pkt_seg_lengths, nb_seg * sizeof(seglen[0]));

	/* calculate number of segments to use and their length. */
	len = 0;
	for (i = 0; i != nb_seg && len < pkt->pkt_len; i++) {
		len += seglen[i];
		md[i] = NULL;
	}

	n = pkt->pkt_len - len;

	/* update size of the last segment to fit rest of the packet */
	if (n >= 0) {
		seglen[i - 1] += n;
		len += n;
	}

	nb_seg = i;
	while (i != 0) {
		p = rte_pktmbuf_alloc(mp);
		if (p == NULL) {
			TESTPMD_LOG(ERR,
				"failed to allocate %u-th of %u mbuf "
				"from mempool: %s\n",
				nb_seg - i, nb_seg, mp->name);
			break;
		}

		md[--i] = p;
		if (rte_pktmbuf_tailroom(md[i]) < seglen[i]) {
			TESTPMD_LOG(ERR, "mempool %s, %u-th segment: "
				"expected seglen: %u, "
				"actual mbuf tailroom: %u\n",
				mp->name, i, seglen[i],
				rte_pktmbuf_tailroom(md[i]));
			break;
		}
	}

	/* all mbufs successfully allocated, do copy */
	if (i == 0) {
		rc = mbuf_copy_split(pkt, md, seglen, nb_seg);
		if (rc < 0)
			TESTPMD_LOG(ERR,
				"mbuf_copy_split for %p(len=%u, nb_seg=%u) "
				"into %u segments failed with error code: %d\n",
				pkt, pkt->pkt_len, pkt->nb_segs, nb_seg, rc);

		/* figure out how many mbufs to free. */
		i = RTE_MAX(rc, 0);
	}

	/* free unused mbufs */
	for (; i != nb_seg; i++) {
		rte_pktmbuf_free_seg(md[i]);
		md[i] = NULL;
	}

	return md[0];
}

#if defined(RTE_LIB_GRO) || defined(RTE_LIB_GSO)
/*
 * Re-calculate IP checksum for merged/fragmented packets.
 */
static void
pkts_ip_csum_recalc(struct rte_mbuf **pkts_burst, const uint16_t nb_pkts, uint64_t tx_offloads)
{
	int i;
	struct rte_ipv4_hdr *ipv4_hdr;
	for (i = 0; i < nb_pkts; i++) {
		if ((pkts_burst[i]->ol_flags & RTE_MBUF_F_TX_IPV4) &&
			(tx_offloads & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) == 0) {
			ipv4_hdr = rte_pktmbuf_mtod_offset(pkts_burst[i],
						struct rte_ipv4_hdr *,
						pkts_burst[i]->l2_len);
			ipv4_hdr->hdr_checksum = 0;
			ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
		}
	}
}
#endif

/*
 * Receive a burst of packets, and for each packet:
 *  - parse packet, and try to recognize a supported packet type (1)
 *  - if it's not a supported packet type, don't touch the packet, else:
 *  - reprocess the checksum of all supported layers. This is done in SW
 *    or HW, depending on testpmd command line configuration
 *  - if TSO is enabled in testpmd command line, also flag the mbuf for TCP
 *    segmentation offload (this implies HW TCP checksum)
 * Then transmit packets on the output port.
 *
 * (1) Supported packets are:
 *   Ether / (vlan) / IP|IP6 / UDP|TCP|SCTP .
 *   Ether / (vlan) / outer IP|IP6 / outer UDP / VxLAN / Ether / IP|IP6 /
 *           UDP|TCP|SCTP
 *   Ether / (vlan) / outer IP|IP6 / outer UDP / VXLAN-GPE / Ether / IP|IP6 /
 *           UDP|TCP|SCTP
 *   Ether / (vlan) / outer IP|IP6 / outer UDP / VXLAN-GPE / IP|IP6 /
 *           UDP|TCP|SCTP
 *   Ether / (vlan) / outer IP / outer UDP / GTP / IP|IP6 / UDP|TCP|SCTP
 *   Ether / (vlan) / outer IP|IP6 / GRE / Ether / IP|IP6 / UDP|TCP|SCTP
 *   Ether / (vlan) / outer IP|IP6 / GRE / IP|IP6 / UDP|TCP|SCTP
 *   Ether / (vlan) / outer IP|IP6 / IP|IP6 / UDP|TCP|SCTP
 *
 * The testpmd command line for this forward engine sets the flags
 * TESTPMD_TX_OFFLOAD_* in ports[tx_port].tx_ol_flags. They control
 * whether a checksum must be calculated in software or in hardware. The
 * IP, UDP, TCP and SCTP flags always concern the inner layer. The
 * OUTER_IP is only useful for tunnel packets.
 */
static void
pkt_burst_checksum_forward(struct fwd_stream *fs)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
#ifdef RTE_LIB_GSO
	struct rte_mbuf *gso_segments[GSO_MAX_PKT_BURST];
	struct rte_gso_ctx *gso_ctx;
#endif
	struct rte_mbuf **tx_pkts_burst;
	struct rte_port *txp;
	struct rte_mbuf *m, *p;
	struct rte_ether_hdr *eth_hdr;
	void *l3_hdr = NULL, *outer_l3_hdr = NULL; /* can be IPv4 or IPv6 */
#ifdef RTE_LIB_GRO
	void **gro_ctx;
	uint16_t gro_pkts_num;
	uint8_t gro_enable;
#endif
	uint16_t nb_rx;
	uint16_t nb_tx;
	uint16_t nb_prep;
	uint16_t i;
	uint64_t rx_ol_flags, tx_ol_flags;
	uint64_t tx_offloads;
	uint32_t retry;
	uint32_t rx_bad_ip_csum;
	uint32_t rx_bad_l4_csum;
	uint32_t rx_bad_outer_l4_csum;
	uint32_t rx_bad_outer_ip_csum;
	struct testpmd_offload_info info;

	uint64_t start_tsc = 0;

	get_start_cycles(&start_tsc);

	/* receive a burst of packet */
	nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue, pkts_burst,
				 nb_pkt_per_burst);
	inc_rx_burst_stats(fs, nb_rx);
	if (unlikely(nb_rx == 0)) {
#ifndef RTE_LIB_GRO
		return ;
#else
		gro_enable = gro_ports[fs->rx_port].enable;
		/*
		 * Check if packets need to be flushed in the GRO context
		 * due to a timeout.
		 *
		 * Continue only in GRO heavyweight mode and if there are
		 * packets in the GRO context.
		 */
		if (!gro_enable || (gro_flush_cycles == GRO_DEFAULT_FLUSH_CYCLES) ||
			(rte_gro_get_pkt_count(current_fwd_lcore()->gro_ctx) == 0))
			return ;
#endif
	}

	fs->rx_packets += nb_rx;
	rx_bad_ip_csum = 0;
	rx_bad_l4_csum = 0;
	rx_bad_outer_l4_csum = 0;
	rx_bad_outer_ip_csum = 0;

	txp = &ports[fs->tx_port];
	tx_offloads = txp->dev_conf.txmode.offloads;
	memset(&info, 0, sizeof(info));
	info.tso_segsz = txp->tso_segsz;
	info.tunnel_tso_segsz = txp->tunnel_tso_segsz;
#ifdef RTE_LIB_GSO
	if (gso_ports[fs->tx_port].enable)
		info.gso_enable = 1;
#endif

	for (i = 0; i < nb_rx; i++) {
		if (likely(i < nb_rx - 1))
			rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i + 1],
						       void *));

		m = pkts_burst[i];
		info.is_tunnel = 0;
		info.pkt_len = rte_pktmbuf_pkt_len(m);
		tx_ol_flags = m->ol_flags &
			      (RTE_MBUF_F_INDIRECT | RTE_MBUF_F_EXTERNAL);
		rx_ol_flags = m->ol_flags;

		/* Update the L3/L4 checksum error packet statistics */
		if ((rx_ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) == RTE_MBUF_F_RX_IP_CKSUM_BAD)
			rx_bad_ip_csum += 1;
		if ((rx_ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) == RTE_MBUF_F_RX_L4_CKSUM_BAD)
			rx_bad_l4_csum += 1;
		if (rx_ol_flags & RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD)
			rx_bad_outer_l4_csum += 1;
		if (rx_ol_flags & RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD)
			rx_bad_outer_ip_csum += 1;

		/* step 1: dissect packet, parsing optional vlan, ip4/ip6, vxlan
		 * and inner headers */

		eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		if (ports[fs->tx_port].fwd_mac_swap) {
			rte_ether_addr_copy(&peer_eth_addrs[fs->peer_addr],
					    &eth_hdr->dst_addr);
			rte_ether_addr_copy(&ports[fs->tx_port].eth_addr,
					    &eth_hdr->src_addr);
		}
		parse_ethernet(eth_hdr, &info);
		l3_hdr = (char *)eth_hdr + info.l2_len;

		/* check if it's a supported tunnel */
		if (txp->parse_tunnel) {
			if (info.l4_proto == IPPROTO_UDP) {
				struct rte_udp_hdr *udp_hdr;

				udp_hdr = (struct rte_udp_hdr *)
					((char *)l3_hdr + info.l3_len);
				parse_gtp(udp_hdr, &info);
				if (info.is_tunnel) {
					tx_ol_flags |= RTE_MBUF_F_TX_TUNNEL_GTP;
					goto tunnel_update;
				}
				parse_vxlan_gpe(udp_hdr, &info);
				if (info.is_tunnel) {
					tx_ol_flags |=
						RTE_MBUF_F_TX_TUNNEL_VXLAN_GPE;
					goto tunnel_update;
				}
				parse_vxlan(udp_hdr, &info);
				if (info.is_tunnel) {
					tx_ol_flags |=
						RTE_MBUF_F_TX_TUNNEL_VXLAN;
					goto tunnel_update;
				}
				parse_geneve(udp_hdr, &info);
				if (info.is_tunnel) {
					tx_ol_flags |=
						RTE_MBUF_F_TX_TUNNEL_GENEVE;
					goto tunnel_update;
				}
				/* Always keep last. */
				if (unlikely(RTE_ETH_IS_TUNNEL_PKT(
							m->packet_type) != 0)) {
					TESTPMD_LOG(DEBUG, "Unknown tunnel packet. UDP dst port: %hu",
						udp_hdr->dst_port);
				}
			} else if (info.l4_proto == IPPROTO_GRE) {
				struct simple_gre_hdr *gre_hdr;

				gre_hdr = (struct simple_gre_hdr *)
					((char *)l3_hdr + info.l3_len);
				parse_gre(gre_hdr, &info);
				if (info.is_tunnel)
					tx_ol_flags |= RTE_MBUF_F_TX_TUNNEL_GRE;
			} else if (info.l4_proto == IPPROTO_IPIP) {
				void *encap_ip_hdr;

				encap_ip_hdr = (char *)l3_hdr + info.l3_len;
				parse_encap_ip(encap_ip_hdr, &info);
				if (info.is_tunnel)
					tx_ol_flags |= RTE_MBUF_F_TX_TUNNEL_IPIP;
			}
		}

tunnel_update:
		/* update l3_hdr and outer_l3_hdr if a tunnel was parsed */
		if (info.is_tunnel) {
			outer_l3_hdr = l3_hdr;
			l3_hdr = (char *)l3_hdr + info.outer_l3_len + info.l2_len;
		}

		/* step 2: depending on user command line configuration,
		 * recompute checksum either in software or flag the
		 * mbuf to offload the calculation to the NIC. If TSO
		 * is configured, prepare the mbuf for TCP segmentation. */

		/* process checksums of inner headers first */
		tx_ol_flags |= process_inner_cksums(l3_hdr, &info,
			tx_offloads, m);

		/* Then process outer headers if any. Note that the software
		 * checksum will be wrong if one of the inner checksums is
		 * processed in hardware. */
		if (info.is_tunnel == 1) {
			tx_ol_flags |= process_outer_cksums(outer_l3_hdr, &info,
					tx_offloads,
					!!(tx_ol_flags & RTE_MBUF_F_TX_TCP_SEG),
					m);
		}

		/* step 3: fill the mbuf meta data (flags and header lengths) */

		m->tx_offload = 0;
		if (info.is_tunnel == 1) {
			if (info.tunnel_tso_segsz ||
			    (tx_offloads &
			     RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM) ||
			    (tx_offloads &
			     RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM)) {
				m->outer_l2_len = info.outer_l2_len;
				m->outer_l3_len = info.outer_l3_len;
				m->l2_len = info.l2_len;
				m->l3_len = info.l3_len;
				m->l4_len = info.l4_len;
				m->tso_segsz = info.tunnel_tso_segsz;
			}
			else {
				/* if there is a outer UDP cksum
				   processed in sw and the inner in hw,
				   the outer checksum will be wrong as
				   the payload will be modified by the
				   hardware */
				m->l2_len = info.outer_l2_len +
					info.outer_l3_len + info.l2_len;
				m->l3_len = info.l3_len;
				m->l4_len = info.l4_len;
			}
		} else {
			/* this is only useful if an offload flag is
			 * set, but it does not hurt to fill it in any
			 * case */
			m->l2_len = info.l2_len;
			m->l3_len = info.l3_len;
			m->l4_len = info.l4_len;
			m->tso_segsz = info.tso_segsz;
		}
		m->ol_flags = tx_ol_flags;

		/* Do split & copy for the packet. */
		if (tx_pkt_split != TX_PKT_SPLIT_OFF) {
			p = pkt_copy_split(m);
			if (p != NULL) {
				rte_pktmbuf_free(m);
				m = p;
				pkts_burst[i] = m;
			}
		}

		/* if verbose mode is enabled, dump debug info */
		if (verbose_level > 0) {
			char buf[256];

			printf("-----------------\n");
			printf("port=%u, mbuf=%p, pkt_len=%u, nb_segs=%u:\n",
				fs->rx_port, m, m->pkt_len, m->nb_segs);
			/* dump rx parsed packet info */
			rte_get_rx_ol_flag_list(rx_ol_flags, buf, sizeof(buf));
			printf("rx: l2_len=%d ethertype=%x l3_len=%d "
				"l4_proto=%d l4_len=%d flags=%s\n",
				info.l2_len, rte_be_to_cpu_16(info.ethertype),
				info.l3_len, info.l4_proto, info.l4_len, buf);
			if (rx_ol_flags & RTE_MBUF_F_RX_LRO)
				printf("rx: m->lro_segsz=%u\n", m->tso_segsz);
			if (info.is_tunnel == 1)
				printf("rx: outer_l2_len=%d outer_ethertype=%x "
					"outer_l3_len=%d\n", info.outer_l2_len,
					rte_be_to_cpu_16(info.outer_ethertype),
					info.outer_l3_len);
			/* dump tx packet info */
			if ((tx_offloads & (RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
					    RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
					    RTE_ETH_TX_OFFLOAD_TCP_CKSUM |
					    RTE_ETH_TX_OFFLOAD_SCTP_CKSUM)) ||
				info.tso_segsz != 0)
				printf("tx: m->l2_len=%d m->l3_len=%d "
					"m->l4_len=%d\n",
					m->l2_len, m->l3_len, m->l4_len);
			if (info.is_tunnel == 1) {
				if ((tx_offloads &
				    RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM) ||
				    (tx_offloads &
				    RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM) ||
				    (tx_ol_flags & RTE_MBUF_F_TX_OUTER_IPV6))
					printf("tx: m->outer_l2_len=%d "
						"m->outer_l3_len=%d\n",
						m->outer_l2_len,
						m->outer_l3_len);
				if (info.tunnel_tso_segsz != 0 &&
						(m->ol_flags & RTE_MBUF_F_TX_TCP_SEG))
					printf("tx: m->tso_segsz=%d\n",
						m->tso_segsz);
			} else if (info.tso_segsz != 0 &&
					(m->ol_flags & RTE_MBUF_F_TX_TCP_SEG))
				printf("tx: m->tso_segsz=%d\n", m->tso_segsz);
			rte_get_tx_ol_flag_list(m->ol_flags, buf, sizeof(buf));
			printf("tx: flags=%s", buf);
			printf("\n");
		}
	}

#ifdef RTE_LIB_GRO
	gro_enable = gro_ports[fs->rx_port].enable;
	if (unlikely(gro_enable)) {
		if (gro_flush_cycles == GRO_DEFAULT_FLUSH_CYCLES) {
			nb_rx = rte_gro_reassemble_burst(pkts_burst, nb_rx,
					&(gro_ports[fs->rx_port].param));
		} else {
			gro_ctx = current_fwd_lcore()->gro_ctx;
			nb_rx = rte_gro_reassemble(pkts_burst, nb_rx, gro_ctx);

			if (++fs->gro_times >= gro_flush_cycles) {
				gro_pkts_num = rte_gro_get_pkt_count(gro_ctx);
				if (gro_pkts_num > MAX_PKT_BURST - nb_rx)
					gro_pkts_num = MAX_PKT_BURST - nb_rx;

				nb_rx += rte_gro_timeout_flush(gro_ctx, 0,
						RTE_GRO_TCP_IPV4,
						&pkts_burst[nb_rx],
						gro_pkts_num);
				fs->gro_times = 0;
			}
			if (nb_rx == 0)
				return;
		}

		pkts_ip_csum_recalc(pkts_burst, nb_rx, tx_offloads);
	}
#endif

#ifdef RTE_LIB_GSO
	if (gso_ports[fs->tx_port].enable != 0) {
		uint16_t nb_segments = 0;

		gso_ctx = &(current_fwd_lcore()->gso_ctx);
		gso_ctx->gso_size = gso_max_segment_size;
		for (i = 0; i < nb_rx; i++) {
			int ret;

			ret = rte_gso_segment(pkts_burst[i], gso_ctx,
					&gso_segments[nb_segments],
					GSO_MAX_PKT_BURST - nb_segments);
			if (ret >= 1) {
				/* pkts_burst[i] can be freed safely here. */
				rte_pktmbuf_free(pkts_burst[i]);
				nb_segments += ret;
			} else if (ret == 0) {
				/* 0 means it can be transmitted directly
				 * without gso.
				 */
				gso_segments[nb_segments] = pkts_burst[i];
				nb_segments += 1;
			} else {
				TESTPMD_LOG(DEBUG, "Unable to segment packet");
				rte_pktmbuf_free(pkts_burst[i]);
			}
		}

		tx_pkts_burst = gso_segments;
		nb_rx = nb_segments;

		pkts_ip_csum_recalc(tx_pkts_burst, nb_rx, tx_offloads);
	} else
#endif
		tx_pkts_burst = pkts_burst;

	nb_prep = rte_eth_tx_prepare(fs->tx_port, fs->tx_queue,
			tx_pkts_burst, nb_rx);
	if (nb_prep != nb_rx) {
		fprintf(stderr,
			"Preparing packet burst to transmit failed: %s\n",
			rte_strerror(rte_errno));
		fs->fwd_dropped += (nb_rx - nb_prep);
		rte_pktmbuf_free_bulk(&tx_pkts_burst[nb_prep], nb_rx - nb_prep);
	}

	nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue, tx_pkts_burst,
			nb_prep);

	/*
	 * Retry if necessary
	 */
	if (unlikely(nb_tx < nb_prep) && fs->retry_enabled) {
		retry = 0;
		while (nb_tx < nb_prep && retry++ < burst_tx_retry_num) {
			rte_delay_us(burst_tx_delay_time);
			nb_tx += rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
					&tx_pkts_burst[nb_tx], nb_prep - nb_tx);
		}
	}
	fs->tx_packets += nb_tx;
	fs->rx_bad_ip_csum += rx_bad_ip_csum;
	fs->rx_bad_l4_csum += rx_bad_l4_csum;
	fs->rx_bad_outer_l4_csum += rx_bad_outer_l4_csum;
	fs->rx_bad_outer_ip_csum += rx_bad_outer_ip_csum;

	inc_tx_burst_stats(fs, nb_tx);
	if (unlikely(nb_tx < nb_prep)) {
		fs->fwd_dropped += (nb_prep - nb_tx);
		do {
			rte_pktmbuf_free(tx_pkts_burst[nb_tx]);
		} while (++nb_tx < nb_prep);
	}

	get_end_cycles(fs, start_tsc);
}

static void
stream_init_checksum_forward(struct fwd_stream *fs)
{
	bool rx_stopped, tx_stopped;

	rx_stopped = ports[fs->rx_port].rxq[fs->rx_queue].state ==
						RTE_ETH_QUEUE_STATE_STOPPED;
	tx_stopped = ports[fs->tx_port].txq[fs->tx_queue].state ==
						RTE_ETH_QUEUE_STATE_STOPPED;
	fs->disabled = rx_stopped || tx_stopped;
}

struct fwd_engine csum_fwd_engine = {
	.fwd_mode_name  = "csum",
	.port_fwd_begin = NULL,
	.port_fwd_end   = NULL,
	.stream_init    = stream_init_checksum_forward,
	.packet_fwd     = pkt_burst_checksum_forward,
};
