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

/* C-NR-301: process-local software flow table.
 *
 * Why a table at all: during the graceful-reload handover the new generation
 * owns the hardware while the old one is still draining established
 * connections. Every inbound packet has to be classified as "new flow, mine"
 * or "old flow, forward to the draining generation". Querying the stack's
 * inpcb/syncache is not sufficient — see the entry-timing note below.
 *
 * Why process-local: each generation only ever consults its own table about
 * its own connections, so no hugepage/shared-memory backing is needed and no
 * multi-writer support has to be paid for.
 *
 * Concurrency: both the producer (syncache hook, inside ff_veth_input) and the
 * consumer (dispatcher callback) run on the datapath thread inside main_loop,
 * so the table is single-threaded in practice. The state word is nevertheless
 * read/written with SEQ_CST atomics so a sampler on another thread can never
 * observe a half-initialised entry. No locks are taken anywhere.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ff_flow_map.h"
#include "ff_config.h"
#include "ff_reload.h"

/* Capacity of new flows recorded inside one reload window. Power of two
 * (mask-based indexing). Sizing note: the table only has to hold the
 * connections accepted between the rx handover and the drain confirmation,
 * so this is a per-window figure, not a per-process connection limit. */
#define FF_FLOW_MAP_ENTRIES     (1u << 16)
#define FF_FLOW_MAP_MASK        (FF_FLOW_MAP_ENTRIES - 1)
#define FF_FLOW_MAP_PROBE_MAX   16

#define FF_FLOW_SLOT_EMPTY      0
#define FF_FLOW_SLOT_USED       1

struct ff_flow_slot {
    struct ff_flow_key key;
    uint32_t state;
};

static struct ff_flow_slot *g_table;
static int g_open;

/* Observability counters (deliberately plain: read by the sampler, never
 * used for correctness). */
static uint64_t g_inserted;
static uint64_t g_dup;
static uint64_t g_full;

/* FNV-1a over the raw 40 key bytes. The padding fields are zeroed by every
 * producer, so the hash is stable across v4/v6 and across processes. */
static uint32_t
flow_hash(const struct ff_flow_key *k)
{
    const unsigned char *p = (const unsigned char *)k;
    uint32_t h = 2166136261u;
    unsigned i;

    for (i = 0; i < sizeof(*k); i++) {
        h ^= (uint32_t)p[i];
        h *= 16777619u;
    }
    return h;
}

static int
slot_matches(const struct ff_flow_slot *s, const struct ff_flow_key *k)
{
    return memcmp(&s->key, k, sizeof(*k)) == 0;
}

/* Gate: recording is only meaningful for an app that actually runs the
 * graceful-reload handover. Cheap enough to sit in front of every SYN. */
static int
flow_map_active(void)
{
    if (!ff_global_cfg.dpdk.graceful_reload)
        return 0;
    if (!ff_reload_state_attached())
        return 0;
    return __atomic_load_n(&g_open, __ATOMIC_RELAXED) != 0;
}

int
ff_flow_map_active(void)
{
    return flow_map_active();
}

void
ff_flow_map_open(void)
{
    /* Pre-allocate here (control plane) so the first SYN of the window does
     * not pay the calloc on the datapath. On failure insert() retries
     * lazily and reports through the stats counters. */
    if (g_table == NULL) {
        g_table = (struct ff_flow_slot *)calloc(FF_FLOW_MAP_ENTRIES,
            sizeof(*g_table));
    }
    __atomic_store_n(&g_open, 1, __ATOMIC_SEQ_CST);
}

void
ff_flow_map_close(void)
{
    __atomic_store_n(&g_open, 0, __ATOMIC_SEQ_CST);

    /* The allocation is retained (not freed) so a lookup that is already in
     * flight on another thread can never touch freed memory; close() is
     * driven from the control plane while lookups run on the datapath. */
    if (g_table != NULL)
        memset(g_table, 0, (size_t)FF_FLOW_MAP_ENTRIES * sizeof(*g_table));
}

int
ff_flow_map_lookup(const struct ff_flow_key *key)
{
    struct ff_flow_slot *t;
    uint32_t idx;
    unsigned probe;

    if (key == NULL)
        return 0;
    if (!__atomic_load_n(&g_open, __ATOMIC_SEQ_CST))
        return 0;
    t = g_table;
    if (t == NULL)
        return 0;

    idx = flow_hash(key) & FF_FLOW_MAP_MASK;
    for (probe = 0; probe < FF_FLOW_MAP_PROBE_MAX; probe++) {
        if (__atomic_load_n(&t[idx].state, __ATOMIC_SEQ_CST) ==
            FF_FLOW_SLOT_EMPTY)
            return 0;
        if (slot_matches(&t[idx], key))
            return 1;
        idx = (idx + 1) & FF_FLOW_MAP_MASK;
    }
    return 0;
}

int
ff_flow_map_insert(const struct ff_flow_key *key)
{
    struct ff_flow_slot *t;
    uint32_t idx;
    unsigned probe;

    if (key == NULL)
        return -1;
    if (!flow_map_active())
        return -1;

    if (g_table == NULL) {
        /* Lazy fallback when open() could not allocate. Counted like a
         * full table: downstream an unrecorded flow is indistinguishable
         * from a table-full one (both forward the packet). */
        t = (struct ff_flow_slot *)calloc(FF_FLOW_MAP_ENTRIES, sizeof(*t));
        if (t == NULL) {
            g_full++;
            return -1;
        }
        g_table = t;
    }
    t = g_table;

    idx = flow_hash(key) & FF_FLOW_MAP_MASK;
    for (probe = 0; probe < FF_FLOW_MAP_PROBE_MAX; probe++) {
        uint32_t st = __atomic_load_n(&t[idx].state, __ATOMIC_SEQ_CST);

        if (st == FF_FLOW_SLOT_EMPTY) {
            memcpy(&t[idx].key, key, sizeof(*key));
            __atomic_store_n(&t[idx].state, FF_FLOW_SLOT_USED,
                __ATOMIC_SEQ_CST);
            g_inserted++;
            return 0;
        }
        if (slot_matches(&t[idx], key)) {
            /* Idempotent: a retransmitted SYN, or a four-tuple reused right
             * after a close, must not consume a second slot. */
            g_dup++;
            return 1;
        }
        idx = (idx + 1) & FF_FLOW_MAP_MASK;
    }

    /* Table (or probe chain) exhausted: degrade to "not mine" so the packet
     * is forwarded to the draining generation instead of being dropped. */
    g_full++;
    return -2;
}

void
ff_flow_map_stats(uint64_t *inserted, uint64_t *dup, uint64_t *full)
{
    if (inserted != NULL)
        *inserted = g_inserted;
    if (dup != NULL)
        *dup = g_dup;
    if (full != NULL)
        *full = g_full;
}
