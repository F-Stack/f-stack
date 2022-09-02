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

#ifndef __FSTACK_MEMORY_H
#define __FSTACK_MEMORY_H

#ifdef __cplusplus
extern "C" {
#endif

#define MEMPOOL_CACHE_SIZE 256

#define DISPATCH_RING_SIZE 2048

#define MSG_RING_SIZE 32

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RX_QUEUE_SIZE 512
#define TX_QUEUE_SIZE 512

/*
 * Try to avoid TX buffering if we have at least MAX_TX_BURST packets to send.
 */
#define MAX_TX_BURST    (MAX_PKT_BURST / 2)

#define NB_SOCKETS 8

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET    3

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

struct ff_dpdk_if_context {
    void *sc;
    void *ifp;
    uint16_t port_id;
    struct ff_hw_features hw_features;
} __rte_cache_aligned;

struct mbuf_table {
    uint16_t len;
    struct rte_mbuf *m_table[MAX_PKT_BURST];
#ifdef FF_USE_PAGE_ARRAY
    void*            bsd_m_table[MAX_PKT_BURST];            // save bsd mbuf address which will be enquene into txring after NIC transmitted pkt.
#endif
};

struct lcore_rx_queue {
    uint16_t port_id;
    uint16_t queue_id;
} __rte_cache_aligned;

struct lcore_conf {
    uint16_t proc_id;
    uint16_t socket_id;
    uint16_t nb_queue_list[RTE_MAX_ETHPORTS];
    struct ff_port_cfg *port_cfgs;

    uint16_t nb_rx_queue;
    struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
    uint16_t nb_tx_port;
    uint16_t tx_port_id[RTE_MAX_ETHPORTS];
    uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
    struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
    //char *pcap[RTE_MAX_ETHPORTS];
} __rte_cache_aligned;

#ifdef FF_USE_PAGE_ARRAY
//  mbuf_txring save mbuf which had bursted into NIC,  m_tables has same length with NIC dev's sw_ring.
//  Then when txring.m_table[x] is reused, the packet in txring.m_table[x] had been transmited by NIC.
//  that means the mbuf can be freed safely.
struct mbuf_txring{
    void* m_table[TX_QUEUE_SIZE];    
    uint16_t head;        // next available element.
};

void ff_init_ref_pool(int nb_mbuf, int socketid);
int ff_mmap_init();
int ff_if_send_onepkt(struct ff_dpdk_if_context *ctx, void *m, int total);
int ff_enq_tx_bsdmbuf(uint8_t portid, void *p_mbuf, int nb_segs);
#endif

#ifdef __cplusplus
}
#endif

#endif


