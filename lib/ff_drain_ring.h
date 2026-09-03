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
 */

#ifndef _FF_DRAIN_RING_H_
#define _FF_DRAIN_RING_H_

#include <stdint.h>

/* C-NR-310: per-generation bidirectional drain rings (internal lib header;
 * the public surface for apps stays ff_api.h).
 *
 * A ring pair suffixed _q<Q>_g<N> belongs to queue Q of generation N:
 *   drain_rx_p<port>_q<Q>_g<N>
 *                          carries packets forwarded TOWARD generation N's
 *                          queue-Q stack instance.
 *                          Producers (MP): the peer's queue-Q worker
 *                          (flow-map miss) AND, with nb_queues >= 2, any
 *                          peer worker fanning out an ARP/NDP clone to
 *                          every queue (C-NR-304).
 *                          Consumer: generation N, queue Q (single consumer).
 *   drain_tx_p<port>_q<Q>_g<N>
 *                          carries packets sent BY generation N's queue-Q
 *                          instance while it no longer owns the hardware.
 *                          Producer: generation N, queue Q (single producer).
 *                          Consumer: the peer generation, which is the only
 *                          side allowed to call rte_eth_tx_burst.
 *
 * The queue dimension is mandatory, not cosmetic: F-Stack multi-process mode
 * runs one independent FreeBSD stack per queue, so a packet that belongs to
 * queue Q must be handed to the peer generation's queue-Q instance — a
 * queue-0 worker that dequeued a queue-1 packet would find no PCB for it and
 * answer with a RST. It is also what keeps the consumer side single per
 * ring: with N workers per generation, a single shared ring would have N
 * dequeuers.
 * The queue index is the same on both sides (RSS is symmetric), so a packet
 * received on queue Q is enqueued at queue Q for the peer.
 *
 * Flags (P1-a fix): drain_tx is RING_F_SP_ENQ | RING_F_SC_DEQ; drain_rx is
 * RING_F_SC_DEQ only (multi-producer — the ARP/NDP clone fan-out can race
 * the same-queue miss forwarder). Unlike dispatch_ring neither is
 * multi-consumer: a queue must never be drained from two processes.
 *
 * Rings only exist while graceful_reload=1; every entry point degrades to a
 * no-op otherwise. */

struct rte_mbuf;
struct ff_dpdk_if_context;

/* Create (primary) / attach (secondary) the ring pairs. No-op when
 * graceful_reload=0 or when already initialised. Returns 0 on success. */
int ff_drain_ring_init(void);

/* 1 once the rings are usable. */
int ff_drain_ring_ready(void);

/* The other generation (FF_RELOAD_GEN_MAX == 2). Destination generation
 * for FF_DISPATCH_PEER misses and for the ARP/NDP clone (C-NR-303/304):
 * the generation whose PCBs own the flow that just missed. */
int ff_drain_ring_peer_gen(void);

/* R-310-1: detach only — null the pointers and stop all enqueue/dequeue.
 * The rings themselves are intentionally not destroyed: only one process
 * could call rte_ring_free(), and the _g<gen> pairs are reused on the next
 * reload round, so freeing would force a rebuild. Idempotent. */
void ff_drain_ring_unregist(void);

/* Forward a flow-map miss to the draining generation.
 * 'gen' is the DESTINATION generation (i.e. the peer, the one that owns the
 * PCB); 'queue_id' is the queue this packet arrived on, which is the peer's
 * queue index too. Enqueueing with your own gen instead of the peer's
 * creates a self-loop: you would dequeue your own packet back.
 * The caller keeps mbuf ownership when this returns non-zero (full / not
 * ready) and must free it. */
int ff_drain_ring_rx_enqueue(uint16_t port_id, uint16_t queue_id, int gen,
    struct rte_mbuf *m);

/* Queue an outgoing packet for the peer generation to transmit.
 * 'gen' is the SOURCE generation (i.e. your own); the peer is the only side
 * allowed to call rte_eth_tx_burst, and it reads the source-generation ring.
 * 'queue_id' is your tx queue. Same ownership rule as
 * ff_drain_ring_rx_enqueue(). */
int ff_drain_ring_tx_enqueue(uint16_t port_id, uint16_t queue_id, int gen,
    struct rte_mbuf *m);

/* Consume this generation's inbound ring into the stack. Returns the number
 * of packets dequeued this pass — the same contract as process_dispatch_ring,
 * so main_loop can keep using `idle &= !n`. */
int ff_drain_ring_rx_dequeue(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, struct ff_dpdk_if_context *ctx);

/* Drain the peer generation's outbound ring straight to the hardware. This is
 * the only consumer of drain_ring_tx. Returns the number of packets sent. */
unsigned ff_drain_ring_tx_drain(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, unsigned max);

/* Counters (C-NR-309/310: ring-full may never be a silent drop). */
void ff_drain_ring_stats(uint64_t *rx_full, uint64_t *tx_full,
    uint64_t *tx_dropped);

#endif /* _FF_DRAIN_RING_H_ */
