/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _GSO_TCP4_H_
#define _GSO_TCP4_H_

#include <stdint.h>
#include <rte_mbuf.h>

/**
 * Segment an IPv4/TCP packet. This function doesn't check if the input
 * packet has correct checksums, and doesn't update checksums for output
 * GSO segments. Furthermore, it doesn't process IP fragment packets.
 *
 * @param pkt
 *  The packet mbuf to segment.
 * @param gso_size
 *  The max length of a GSO segment, measured in bytes.
 * @param ipid_delta
 *  The increasing unit of IP ids.
 * @param direct_pool
 *  MBUF pool used for allocating direct buffers for output segments.
 * @param indirect_pool
 *  MBUF pool used for allocating indirect buffers for output segments.
 * @param pkts_out
 *  Pointer array used to store the MBUF addresses of output GSO
 *  segments, when the function succeeds. If the memory space in
 *  pkts_out is insufficient, it fails and returns -EINVAL.
 * @param nb_pkts_out
 *  The max number of items that 'pkts_out' can keep.
 *
 * @return
 *   - The number of GSO segments filled in pkts_out on success.
 *   - Return -ENOMEM if run out of memory in MBUF pools.
 *   - Return -EINVAL for invalid parameters.
 */
int gso_tcp4_segment(struct rte_mbuf *pkt,
		uint16_t gso_size,
		uint8_t ip_delta,
		struct rte_mempool *direct_pool,
		struct rte_mempool *indirect_pool,
		struct rte_mbuf **pkts_out,
		uint16_t nb_pkts_out);
#endif
