/*
 * Copyright (C) 2017-2021 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _FSTACK_DPDK_KNI_H
#define _FSTACK_DPDK_KNI_H

#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

extern int enable_kni;
extern int nb_dev_ports;

struct kni_ratelimit {
    /* Important control plane packets enqueue to kni ring, such as arp, stp, ospf, etc. statistics for each process. */
    uint64_t console_packets;

    /* gerneal packets enqueue to kni ring, such ICMP pkts, statistics for each process. */
    uint64_t gerneal_packets;

    /* All packets forwarded to the kernel, statistics for primary process. */
    uint64_t kernel_packets;
};

extern struct kni_ratelimit kni_rate_limt;

enum FilterReturn {
    FILTER_UNKNOWN = -1,
    FILTER_KNI = 1,
    FILTER_ARP = 2,
#ifdef INET6
    FILTER_NDP = 3,  // Neighbor Solicitation/Advertisement, Router Solicitation/Advertisement/Redirect
#endif
    FILTER_OSPF = 4,
    FILTER_MULTI = 5,
};

void ff_kni_init(uint16_t nb_ports, int type, const char *tcp_ports,
    const char *udp_ports);

void ff_kni_alloc(uint16_t port_id, unsigned socket_id, int type, int port_idx,
    struct rte_mempool *mbuf_pool, unsigned ring_queue_size);

void ff_kni_process(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, unsigned count);

enum FilterReturn ff_kni_proto_filter(const void *data, uint16_t len, uint16_t eth_frame_type);

int ff_kni_enqueue(enum FilterReturn filter, uint16_t port_id, struct rte_mbuf *pkt);


#endif /* ifndef _FSTACK_DPDK_KNI_H */
