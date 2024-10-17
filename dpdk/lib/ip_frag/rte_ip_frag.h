/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _RTE_IP_FRAG_H_
#define _RTE_IP_FRAG_H_

/**
 * @file
 * RTE IP Fragmentation and Reassembly
 *
 * Implementation of IP packet fragmentation and reassembly.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>

#include <rte_compat.h>
#include <rte_config.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_ip.h>
#include <rte_byteorder.h>

struct rte_mbuf;

/** death row size (in packets) */
#define RTE_IP_FRAG_DEATH_ROW_LEN 32

/** death row size in mbufs */
#define RTE_IP_FRAG_DEATH_ROW_MBUF_LEN \
	(RTE_IP_FRAG_DEATH_ROW_LEN * (RTE_LIBRTE_IP_FRAG_MAX_FRAG + 1))

/** mbuf death row (packets to be freed) */
struct rte_ip_frag_death_row {
	uint32_t cnt;          /**< number of mbufs currently on death row */
	struct rte_mbuf *row[RTE_IP_FRAG_DEATH_ROW_MBUF_LEN];
	/**< mbufs to be freed */
};

/**
 * Create a new IP fragmentation table.
 *
 * @param bucket_num
 *   Number of buckets in the hash table.
 * @param bucket_entries
 *   Number of entries per bucket (e.g. hash associativity).
 *   Should be power of two.
 * @param max_entries
 *   Maximum number of entries that could be stored in the table.
 *   The value should be less or equal then bucket_num * bucket_entries.
 * @param max_cycles
 *   Maximum TTL in cycles for each fragmented packet.
 * @param socket_id
 *   The *socket_id* argument is the socket identifier in the case of
 *   NUMA. The value can be *SOCKET_ID_ANY* if there is no NUMA constraints.
 * @return
 *   The pointer to the new allocated fragmentation table, on success. NULL on error.
 */
struct rte_ip_frag_tbl * rte_ip_frag_table_create(uint32_t bucket_num,
		uint32_t bucket_entries,  uint32_t max_entries,
		uint64_t max_cycles, int socket_id);

/**
 * Free allocated IP fragmentation table.
 *
 * @param tbl
 *   Fragmentation table to free.
 */
void
rte_ip_frag_table_destroy(struct rte_ip_frag_tbl *tbl);

/**
 * This function implements the fragmentation of IPv6 packets.
 *
 * @param pkt_in
 *   The input packet.
 * @param pkts_out
 *   Array storing the output fragments.
 * @param nb_pkts_out
 *   Number of fragments.
 * @param mtu_size
 *   Size in bytes of the Maximum Transfer Unit (MTU) for the outgoing IPv6
 *   datagrams. This value includes the size of the IPv6 header.
 * @param pool_direct
 *   MBUF pool used for allocating direct buffers for the output fragments.
 * @param pool_indirect
 *   MBUF pool used for allocating indirect buffers for the output fragments.
 * @return
 *   Upon successful completion - number of output fragments placed
 *   in the pkts_out array.
 *   Otherwise - (-1) * errno.
 */
int32_t
rte_ipv6_fragment_packet(struct rte_mbuf *pkt_in,
		struct rte_mbuf **pkts_out,
		uint16_t nb_pkts_out,
		uint16_t mtu_size,
		struct rte_mempool *pool_direct,
		struct rte_mempool *pool_indirect);

/**
 * This function implements reassembly of fragmented IPv6 packets.
 * Incoming mbuf should have its l2_len/l3_len fields setup correctly.
 *
 * @param tbl
 *   Table where to lookup/add the fragmented packet.
 * @param dr
 *   Death row to free buffers to
 * @param mb
 *   Incoming mbuf with IPv6 fragment.
 * @param tms
 *   Fragment arrival timestamp.
 * @param ip_hdr
 *   Pointer to the IPv6 header.
 * @param frag_hdr
 *   Pointer to the IPv6 fragment extension header.
 * @return
 *   Pointer to mbuf for reassembled packet, or NULL if:
 *   - an error occurred.
 *   - not all fragments of the packet are collected yet.
 */
struct rte_mbuf *rte_ipv6_frag_reassemble_packet(struct rte_ip_frag_tbl *tbl,
		struct rte_ip_frag_death_row *dr,
		struct rte_mbuf *mb, uint64_t tms, struct rte_ipv6_hdr *ip_hdr,
		struct rte_ipv6_fragment_ext *frag_hdr);

/**
 * Return a pointer to the packet's fragment header, if found.
 * It only looks at the extension header that's right after the fixed IPv6
 * header, and doesn't follow the whole chain of extension headers.
 *
 * @param hdr
 *   Pointer to the IPv6 header.
 * @return
 *   Pointer to the IPv6 fragment extension header, or NULL if it's not
 *   present.
 */
static inline struct rte_ipv6_fragment_ext *
rte_ipv6_frag_get_ipv6_fragment_header(struct rte_ipv6_hdr *hdr)
{
	if (hdr->proto == IPPROTO_FRAGMENT) {
		return (struct rte_ipv6_fragment_ext *) ++hdr;
	}
	else
		return NULL;
}

/**
 * IPv4 fragmentation.
 *
 * This function implements the fragmentation of IPv4 packets.
 *
 * @param pkt_in
 *   The input packet.
 * @param pkts_out
 *   Array storing the output fragments.
 * @param nb_pkts_out
 *   Number of fragments.
 * @param mtu_size
 *   Size in bytes of the Maximum Transfer Unit (MTU) for the outgoing IPv4
 *   datagrams. This value includes the size of the IPv4 header.
 * @param pool_direct
 *   MBUF pool used for allocating direct buffers for the output fragments.
 * @param pool_indirect
 *   MBUF pool used for allocating indirect buffers for the output fragments.
 * @return
 *   Upon successful completion - number of output fragments placed
 *   in the pkts_out array.
 *   Otherwise - (-1) * errno.
 */
int32_t rte_ipv4_fragment_packet(struct rte_mbuf *pkt_in,
			struct rte_mbuf **pkts_out,
			uint16_t nb_pkts_out, uint16_t mtu_size,
			struct rte_mempool *pool_direct,
			struct rte_mempool *pool_indirect);

/**
 * IPv4 fragmentation by copy.
 *
 * This function implements the fragmentation of IPv4 packets by copy
 * non-segmented mbuf.
 * This function is mainly used to adapt Tx MBUF_FAST_FREE offload.
 * MBUF_FAST_FREE: Device supports optimization for fast release of mbufs.
 * When set, application must guarantee that per-queue all mbufs comes from
 * the same mempool, has refcnt = 1, direct and non-segmented.
 *
 * @param pkt_in
 *   The input packet.
 * @param pkts_out
 *   Array storing the output fragments.
 * @param nb_pkts_out
 *   Number of fragments.
 * @param mtu_size
 *   Size in bytes of the Maximum Transfer Unit (MTU) for the outgoing IPv4
 *   datagrams. This value includes the size of the IPv4 header.
 * @param pool_direct
 *   MBUF pool used for allocating direct buffers for the output fragments.
 * @return
 *   Upon successful completion - number of output fragments placed
 *   in the pkts_out array.
 *   Otherwise - (-1) * errno.
 */
__rte_experimental
int32_t
rte_ipv4_fragment_copy_nonseg_packet(struct rte_mbuf *pkt_in,
	struct rte_mbuf **pkts_out,
	uint16_t nb_pkts_out,
	uint16_t mtu_size,
	struct rte_mempool *pool_direct);

/**
 * This function implements reassembly of fragmented IPv4 packets.
 * Incoming mbufs should have its l2_len/l3_len fields setup correctly.
 *
 * @param tbl
 *   Table where to lookup/add the fragmented packet.
 * @param dr
 *   Death row to free buffers to
 * @param mb
 *   Incoming mbuf with IPv4 fragment.
 * @param tms
 *   Fragment arrival timestamp.
 * @param ip_hdr
 *   Pointer to the IPV4 header inside the fragment.
 * @return
 *   Pointer to mbuf for reassembled packet, or NULL if:
 *   - an error occurred.
 *   - not all fragments of the packet are collected yet.
 */
struct rte_mbuf * rte_ipv4_frag_reassemble_packet(struct rte_ip_frag_tbl *tbl,
		struct rte_ip_frag_death_row *dr,
		struct rte_mbuf *mb, uint64_t tms, struct rte_ipv4_hdr *ip_hdr);

/**
 * Check if the IPv4 packet is fragmented
 *
 * @param hdr
 *   IPv4 header of the packet
 * @return
 *   1 if fragmented, 0 if not fragmented
 */
static inline int
rte_ipv4_frag_pkt_is_fragmented(const struct rte_ipv4_hdr *hdr)
{
	uint16_t flag_offset, ip_flag, ip_ofs;

	flag_offset = rte_be_to_cpu_16(hdr->fragment_offset);
	ip_ofs = (uint16_t)(flag_offset & RTE_IPV4_HDR_OFFSET_MASK);
	ip_flag = (uint16_t)(flag_offset & RTE_IPV4_HDR_MF_FLAG);

	return ip_flag != 0 || ip_ofs  != 0;
}

/**
 * Free mbufs on a given death row.
 *
 * @param dr
 *   Death row to free mbufs in.
 * @param prefetch
 *   How many buffers to prefetch before freeing.
 */
void rte_ip_frag_free_death_row(struct rte_ip_frag_death_row *dr,
		uint32_t prefetch);


/**
 * Dump fragmentation table statistics to file.
 *
 * @param f
 *   File to dump statistics to
 * @param tbl
 *   Fragmentation table to dump statistics from
 */
void
rte_ip_frag_table_statistics_dump(FILE * f, const struct rte_ip_frag_tbl *tbl);

/**
 * Delete expired fragments
 *
 * @param tbl
 *   Table to delete expired fragments from
 * @param dr
 *   Death row to free buffers to
 * @param tms
 *   Current timestamp
 */
__rte_experimental
void
rte_ip_frag_table_del_expired_entries(struct rte_ip_frag_tbl *tbl,
	struct rte_ip_frag_death_row *dr, uint64_t tms);

/**@{@name Obsolete macros, kept here for compatibility reasons.
 * Will be deprecated/removed in future DPDK releases.
 */
/** Obsolete */
#define IP_FRAG_DEATH_ROW_LEN		RTE_IP_FRAG_DEATH_ROW_LEN
/** Obsolete */
#define IP_FRAG_DEATH_ROW_MBUF_LEN	RTE_IP_FRAG_DEATH_ROW_MBUF_LEN
/** Obsolete */
#define ipv6_extension_fragment		rte_ipv6_fragment_ext
/**@}*/

#ifdef __cplusplus
}
#endif

#endif /* _RTE_IP_FRAG_H_ */
