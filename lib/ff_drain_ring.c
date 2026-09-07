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

/* C-NR-310: see lib/ff_drain_ring.h for the ring-pair ownership model. */

#include <stdint.h>
#include <stdio.h>

#include <rte_ring.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>

#include "ff_drain_ring.h"
#include "ff_dpdk_if.h"
#include "ff_config.h"
#include "ff_memory.h"
#include "ff_reload.h"
#include "ff_log.h"

/* One ring pair per (port, queue, generation): every queue is a separate
 * FreeBSD stack instance, so a packet must be handed back to the peer
 * generation's same queue. */
#define FF_DRAIN_RX_RING_FMT   "drain_rx_p%u_q%u_g%d"
#define FF_DRAIN_TX_RING_FMT   "drain_tx_p%u_q%u_g%d"
/* M5: same, namespaced by the master epoch slot (one digit — a ring name
 * is capped at 28 bytes). Slot 0 keeps the pre-M5 name byte-for-byte. */
#define FF_DRAIN_RX_RING_FMT_E "drain_rx_p%u_q%u_e%u_g%d"
#define FF_DRAIN_TX_RING_FMT_E "drain_tx_p%u_q%u_e%u_g%d"

/* Index layout: [queue * FF_RELOAD_EPOCH_SLOT_MAX + slot] * GEN_MAX + gen */
#define FF_DRAIN_RING_INDEX(q, slot, gen) \
    ((((unsigned)(q)) * FF_RELOAD_EPOCH_SLOT_MAX + (unsigned)(slot)) \
        * FF_RELOAD_GEN_MAX + (unsigned)(gen))

/* M5: same fit check as the msg rings — "drain_tx_p<port>_q<queue>_e<slot>_g<gen>"
 * with a uint16 port/queue is again exactly RTE_RING_NAMESIZE-1 bytes. */
typedef char ff_drain_ring_name_fit_check[
    (10                                   /* "drain_tx_p" */
     + 5 + 2 + 5                          /* port, "_q", queue (uint16) */
     + 2 + 1                              /* "_e" + epoch slot, one digit */
     + 2 + 1                              /* "_g" + generation */
     <= (size_t)(RTE_RING_NAMESIZE - 1)) ? 1 : -1];

/* Flat [queue * FF_RELOAD_GEN_MAX + gen], allocated per port from the
 * port's real queue count (same shape as init_dispatch_ring). */
static struct rte_ring **drain_ring_rx[RTE_MAX_ETHPORTS];
static struct rte_ring **drain_ring_tx[RTE_MAX_ETHPORTS];
static unsigned drain_ring_nb_queues[RTE_MAX_ETHPORTS];
static int drain_ring_up;

static uint64_t g_rx_full;
static uint64_t g_tx_full;
static uint64_t g_tx_dropped;

/* C-NR-406: local cumulative forward counters, flushed as deltas into the
 * shared drain block at ~1 Hz (single datapath thread per process, no
 * atomics needed until the flush). */
static uint64_t g_rx_fwd;
static uint64_t g_tx_fwd;
static uint64_t g_rx_fwd_flushed;
static uint64_t g_tx_fwd_flushed;

/* The peer generation; FF_RELOAD_GEN_MAX is 2 (compile-checked against
 * FF_MBUF_GEN_MAX in ff_dpdk_if.c), so the modulo is the same as ^1. */
static int
peer_gen(void)
{
    int g = ff_reload_gen();

    if (g < 0 || g >= FF_RELOAD_GEN_MAX)
        g = 0;
    return (g + 1) % FF_RELOAD_GEN_MAX;
}

/* The two enqueue entry points take 'gen' with opposite meanings (rx takes
 * the destination, tx takes the source), which is easy to get wrong and
 * silently produces a self-loop: you would dequeue your own packet back.
 * Reject the wrong side instead. Logged once — this is a coding error, not a
 * runtime condition, so it must not turn into per-packet log spam. */
static int gen_mismatch_warned;

static void
gen_mismatch_warn(const char *fn, int gen)
{
    if (__atomic_test_and_set(&gen_mismatch_warned, __ATOMIC_SEQ_CST))
        return;
    ff_log(FF_LOG_ERR, FF_LOGTYPE_FSTACK_LIB,
        "%s: gen %d is the wrong side (rx takes the destination generation, "
        "tx takes the source one); packet rejected\n", fn, gen);
}

static struct rte_ring *
pick_ring(struct rte_ring **rings, uint16_t port_id, uint16_t queue_id,
    unsigned slot, int gen)
{
    if (rings == NULL || gen < 0 || gen >= FF_RELOAD_GEN_MAX)
        return NULL;
    if (slot >= FF_RELOAD_EPOCH_SLOT_MAX)
        return NULL;
    if (port_id >= RTE_MAX_ETHPORTS ||
        (unsigned)queue_id >= drain_ring_nb_queues[port_id])
        return NULL;
    return rings[FF_DRAIN_RING_INDEX(queue_id, slot, gen)];
}

/* M5: ring name for one (port, queue, epoch slot, generation). */
static int
drain_ring_name(char *buf, size_t buflen, int tx, unsigned port_id,
    unsigned queue_id, unsigned slot, int gen)
{
    int n;

    if (slot == 0) {
        n = snprintf(buf, buflen, tx ? FF_DRAIN_TX_RING_FMT
            : FF_DRAIN_RX_RING_FMT, port_id, queue_id, gen);
    } else {
        n = snprintf(buf, buflen, tx ? FF_DRAIN_TX_RING_FMT_E
            : FF_DRAIN_RX_RING_FMT_E, port_id, queue_id, slot, gen);
    }
    if (n < 0 || (size_t)n >= RTE_RING_NAMESIZE)
        return -1;
    return 0;
}

int
ff_drain_ring_ready(void)
{
    return drain_ring_up;
}

int
ff_drain_ring_peer_gen(void)
{
    int gen;

    /* M5: across masters the peer is the newest live epoch's generation,
     * not the ping-pong of our own master. */
    ff_reload_peer_coord(NULL, &gen);
    if (gen < 0 || gen >= FF_RELOAD_GEN_MAX)
        return peer_gen();
    return gen;
}

int
ff_drain_ring_init(void)
{
    unsigned socketid, count;
    /* Wider than RTE_RING_NAMESIZE: three numeric fields make GCC's
     * worst-case digit count exceed 32, and a silently truncated ring name
     * would either fail to create or collide. The result is range-checked
     * against the real ring-name limit before use. */
    char name[64];
    int p, q, g, e;

    if (!ff_global_cfg.dpdk.graceful_reload)
        return 0;
    if (drain_ring_up)
        return 0;

    socketid = ff_cur_lcore_conf()->socket_id;
    count = ff_global_cfg.dpdk.drain_ring_size;
    if (count == 0)
        count = FF_DRAIN_RING_SIZE_DEFAULT;

    /* Unlike msg_ring, a generation needs BOTH pairs: it consumes its own
     * drain_rx (packets forwarded to it) and produces into its own
     * drain_tx, but the peer's rings are the ones it writes to / reads from
     * on the other direction. So every process attaches every generation.
     * The queue dimension is non-negotiable: one stack instance per queue,
     * and one consumer per queue ring. drain_tx stays SP: its only
     * producer is the parked generation's own queue-Q worker
     * (ff_divert_tx_mbuf). drain_rx must be MP (P1-a fix): a queue-Q rx
     * ring takes both the owner's queue-Q worker (flow-map misses) and,
     * with nb_queues >= 2, any OTHER owner worker fanning out an ARP/NDP
     * clone to every peer queue — two processes on an SP ring corrupt the
     * producer head. Cost: one CAS per enqueue, reload window only. */
    for (p = 0; p < ff_global_cfg.dpdk.nb_ports; p++) {
        uint16_t portid = ff_global_cfg.dpdk.portid_list[p];
        struct ff_port_cfg *pconf = &ff_global_cfg.dpdk.port_cfgs[portid];
        unsigned nb_queues = (unsigned)pconf->nb_lcores;
        size_t sz;

        if (nb_queues == 0)
            continue;

        /* R-310-1: unregist() only detaches, so on a later init() the
         * pointer arrays are still there — reuse them instead of leaking a
         * new block on every reload round. */
        sz = sizeof(struct rte_ring *) * nb_queues
            * FF_RELOAD_EPOCH_SLOT_MAX * FF_RELOAD_GEN_MAX;

        if (drain_ring_rx[portid] == NULL) {
            snprintf(name, sizeof(name), "drain_rx_ptr_p%u",
                (unsigned)portid);
            drain_ring_rx[portid] = rte_zmalloc(name, sz,
                RTE_CACHE_LINE_SIZE);
        }
        if (drain_ring_tx[portid] == NULL) {
            snprintf(name, sizeof(name), "drain_tx_ptr_p%u",
                (unsigned)portid);
            drain_ring_tx[portid] = rte_zmalloc(name, sz,
                RTE_CACHE_LINE_SIZE);
        }
        if (drain_ring_rx[portid] == NULL || drain_ring_tx[portid] == NULL)
            return -1;

        drain_ring_nb_queues[portid] = nb_queues;

        /* M5: every epoch slot is attached, like every generation is — a
         * process cannot know at init which peer coordinate the next
         * reload round will pair it with. The resident primary creates
         * them all (create_ring), so a secondary only ever looks them up
         * and the pre-M5 "primary creates / secondary attaches" policy is
         * left untouched. */
        for (q = 0; q < (int)nb_queues; q++) {
            for (e = 0; e < (int)FF_RELOAD_EPOCH_SLOT_MAX; e++) {
                for (g = 0; g < FF_RELOAD_GEN_MAX; g++) {
                    if (drain_ring_name(name, sizeof(name), 0,
                            (unsigned)portid, (unsigned)q, (unsigned)e,
                            g) != 0)
                        return -1;
                    /* P1-a: MP — see the comment above the port loop */
                    drain_ring_rx[portid][
                        FF_DRAIN_RING_INDEX(q, e, g)] =
                        create_ring(name, count, socketid, RING_F_SC_DEQ);

                    if (drain_ring_name(name, sizeof(name), 1,
                            (unsigned)portid, (unsigned)q, (unsigned)e,
                            g) != 0)
                        return -1;
                    drain_ring_tx[portid][
                        FF_DRAIN_RING_INDEX(q, e, g)] =
                        create_ring(name, count, socketid,
                            RING_F_SP_ENQ | RING_F_SC_DEQ);
                }
            }
        }
    }

    drain_ring_up = 1;
    return 0;
}

/* M5: drop everything a dead master left behind in one epoch slot's rings.
 * Only the process that won the slot takeover CAS ever calls this (see
 * ff_reload_gendir_reset_pending()), and it runs before that slot's rings
 * are used, so nobody else can be dequeuing them. */
void
ff_drain_ring_reset_slot(unsigned slot)
{
    uint16_t p;
    unsigned q, g;

    if (slot >= FF_RELOAD_EPOCH_SLOT_MAX)
        return;
    for (p = 0; p < RTE_MAX_ETHPORTS; p++) {
        if (drain_ring_rx[p] == NULL || drain_ring_tx[p] == NULL)
            continue;
        for (q = 0; q < drain_ring_nb_queues[p]; q++) {
            for (g = 0; g < (unsigned)FF_RELOAD_GEN_MAX; g++) {
                struct rte_ring *r;
                void *obj;

                r = drain_ring_rx[p][FF_DRAIN_RING_INDEX(q, slot, g)];
                while (r != NULL && rte_ring_dequeue(r, &obj) == 0)
                    rte_pktmbuf_free((struct rte_mbuf *)obj);
                r = drain_ring_tx[p][FF_DRAIN_RING_INDEX(q, slot, g)];
                while (r != NULL && rte_ring_dequeue(r, &obj) == 0)
                    rte_pktmbuf_free((struct rte_mbuf *)obj);
            }
        }
    }
}

void
ff_drain_ring_unregist(void)
{
    uint16_t p;
    unsigned q;

    drain_ring_up = 0;
    for (p = 0; p < RTE_MAX_ETHPORTS; p++) {
        if (drain_ring_rx[p] != NULL) {
            for (q = 0; q < drain_ring_nb_queues[p] * FF_RELOAD_EPOCH_SLOT_MAX
                * FF_RELOAD_GEN_MAX; q++)
                drain_ring_rx[p][q] = NULL;
        }
        if (drain_ring_tx[p] != NULL) {
            for (q = 0; q < drain_ring_nb_queues[p] * FF_RELOAD_EPOCH_SLOT_MAX
                * FF_RELOAD_GEN_MAX; q++)
                drain_ring_tx[p][q] = NULL;
        }
        /* The pointer arrays stay allocated (R-310-1: detach, never
         * destroy) so the next init() can reuse them. */
        drain_ring_nb_queues[p] = 0;
    }
}

int
ff_drain_ring_rx_enqueue(uint16_t port_id, uint16_t queue_id, int gen,
    struct rte_mbuf *m)
{
    struct rte_ring *r;
    uint32_t epoch;

    if (!drain_ring_up || m == NULL || port_id >= RTE_MAX_ETHPORTS)
        return -1;
    /* 'gen' is the DESTINATION: the generation that owns the PCB. Feeding
     * our own generation back would loop the packet straight back to us —
     * but "own" is the full (slot, gen) coordinate: a USR2 peer master
     * legitimately runs the SAME gen in a different epoch slot, and its
     * rings are namespaced by that slot, so only an exact self-match is a
     * loop (F-M5-1). */
    ff_reload_peer_coord(&epoch, NULL);
    if (gen == ff_reload_gen()
        && ff_reload_epoch_slot_of(epoch) == ff_reload_epoch_slot()) {
        gen_mismatch_warn(__func__, gen);
        return -1;
    }
    /* M5: the destination generation may belong to another master, so the
     * epoch comes from the directory (our own peer generation when there
     * is only one master). */
    r = pick_ring(drain_ring_rx[port_id], port_id, queue_id,
        ff_reload_epoch_slot_of(epoch), gen);
    if (r == NULL)
        return -1;

    if (rte_ring_enqueue(r, m) != 0) {
        g_rx_full++;
        return -1;
    }
    g_rx_fwd++;
    return 0;
}

int
ff_drain_ring_tx_enqueue(uint16_t port_id, uint16_t queue_id, int gen,
    struct rte_mbuf *m)
{
    struct rte_ring *r;

    if (!drain_ring_up || m == NULL || port_id >= RTE_MAX_ETHPORTS)
        return -1;
    /* 'gen' is the SOURCE: the peer reads the source generation's ring. */
    if (gen != ff_reload_gen()) {
        gen_mismatch_warn(__func__, gen);
        return -1;
    }
    r = pick_ring(drain_ring_tx[port_id], port_id, queue_id,
        ff_reload_epoch_slot(), gen);
    if (r == NULL)
        return -1;

    if (rte_ring_enqueue(r, m) != 0) {
        g_tx_full++;
        return -1;
    }
    return 0;
}

int
ff_drain_ring_rx_dequeue(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, struct ff_dpdk_if_context *ctx)
{
    struct rte_ring *r;
    uint16_t nb_rb;

    if (!drain_ring_up || pkts_burst == NULL || port_id >= RTE_MAX_ETHPORTS)
        return 0;
    r = pick_ring(drain_ring_rx[port_id], port_id, queue_id,
        ff_reload_epoch_slot(), ff_reload_gen());
    if (r == NULL)
        return 0;

    nb_rb = rte_ring_dequeue_burst(r, (void **)pkts_burst, MAX_PKT_BURST,
        NULL);
    if (nb_rb == 0)
        return 0;

    if (ctx == NULL) {
        /* No stack context (wrong mode / test): free instead of leaking. */
        uint16_t i;
        for (i = 0; i < nb_rb; i++)
            rte_pktmbuf_free(pkts_burst[i]);
        return 0;
    }

    /* pkts_from_ring=1: packets arriving from a ring must not be re-cloned
     * or re-dispatched (see the !pkts_from_ring guard in process_packets). */
    ff_dpdk_process_packets(port_id, queue_id, pkts_burst, nb_rb, ctx, 1);
    return (int)nb_rb;
}

unsigned
ff_drain_ring_tx_drain(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, unsigned max)
{
    struct rte_ring *r;
    uint16_t nb, sent;
    uint32_t epoch;
    int pg;

    if (!drain_ring_up || pkts_burst == NULL || port_id >= RTE_MAX_ETHPORTS)
        return 0;
    if (max == 0 || max > MAX_PKT_BURST)
        max = MAX_PKT_BURST;

    ff_reload_peer_coord(&epoch, &pg);
    r = pick_ring(drain_ring_tx[port_id], port_id, queue_id,
        ff_reload_epoch_slot_of(epoch), pg);
    if (r == NULL)
        return 0;

    nb = rte_ring_dequeue_burst(r, (void **)pkts_burst, max, NULL);
    if (nb == 0)
        return 0;

    sent = rte_eth_tx_burst(port_id, queue_id, pkts_burst, nb);
    if (sent < nb) {
        uint16_t i;
        for (i = sent; i < nb; i++)
            rte_pktmbuf_free(pkts_burst[i]);
        g_tx_dropped += (uint64_t)(nb - sent);
    }
    g_tx_fwd += sent;
    return sent;
}

void
ff_drain_ring_flush_stats(void)
{
    uint16_t p;
    unsigned q;

    /* publish the local deltas since the last flush */
    ff_reload_drain_fwd_add(0, g_rx_fwd - g_rx_fwd_flushed);
    g_rx_fwd_flushed = g_rx_fwd;
    ff_reload_drain_fwd_add(1, g_tx_fwd - g_tx_fwd_flushed);
    g_tx_fwd_flushed = g_tx_fwd;

    if (!drain_ring_up) {
        return;
    }

    /* watermarks: sample every attached ring; the max-update races between
     * the two generations are benign (observability only) */
    for (p = 0; p < RTE_MAX_ETHPORTS; p++) {
        if (drain_ring_rx[p] == NULL || drain_ring_tx[p] == NULL) {
            continue;
        }
        for (q = 0; q < drain_ring_nb_queues[p] * FF_RELOAD_EPOCH_SLOT_MAX
            * FF_RELOAD_GEN_MAX; q++) {
            ff_reload_drain_peak_max(0, rte_ring_count(drain_ring_rx[p][q]));
            ff_reload_drain_peak_max(1, rte_ring_count(drain_ring_tx[p][q]));
        }
    }
}

void
ff_drain_ring_stats(uint64_t *rx_full, uint64_t *tx_full, uint64_t *tx_dropped)
{
    if (rx_full != NULL)
        *rx_full = g_rx_full;
    if (tx_full != NULL)
        *tx_full = g_tx_full;
    if (tx_dropped != NULL)
        *tx_dropped = g_tx_dropped;
}
