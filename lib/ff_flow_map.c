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
 * Single-thread contract: the producer (syncache hook, inside ff_veth_input),
 * the consumer (dispatcher callback) and the control plane (open/close, the
 * 1 Hz stats report) all run on the datapath thread inside main_loop, and the
 * table is process-local heap memory. Accesses are therefore plain, with no
 * locks and no atomics. A sampler on another thread would need a real
 * publication mechanism (seqlock/RCU): the previous SEQ_CST-on-state was not
 * one — the capacity and its mask were plain reads and close() wiped the
 * whole table with memset.
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

/* P3 (C-P3-3): bounded growth of a full table — at most GROW_MAX doublings
 * per window and never beyond FF_FLOW_MAP_CAP_MAX (ff_flow_map.h). The
 * default capacity and therefore the default behaviour are unchanged. */
#define FF_FLOW_MAP_GROW_MAX    4

#define FF_FLOW_SLOT_EMPTY      0
#define FF_FLOW_SLOT_USED       1

struct ff_flow_slot {
    struct ff_flow_key key;
    uint32_t state;
    uint32_t hash;      /* flow_hash(key): compared before the 40-byte key */
};

static struct ff_flow_slot *g_table;
static int g_open;
/* Capacity of the live table (power of two) and its index mask, always kept
 * in sync: the mask must never describe a larger table than the one held. */
static uint32_t g_cap = FF_FLOW_MAP_ENTRIES;
static uint32_t g_cap_mask = FF_FLOW_MAP_MASK;
static uint32_t g_grown;

/* Observability counters (deliberately plain: observability only, never
 * used for correctness). */
static uint64_t g_inserted;
static uint64_t g_dup;
static uint64_t g_full;
static uint64_t g_grow_fail;
static uint64_t g_alloc_fail;

/* Portable word hash, no ISA or DPDK dependency. Only the bytes that carry
 * identity are mixed (V4 leaves src[1..3]/dst[1..3] zero), the two address
 * chains run in parallel to shorten the multiply chain, and the tail is
 * avalanched because the index comes from the low bits (h & mask). */
static uint32_t
flow_hash(const struct ff_flow_key *k)
{
    uint32_t a = 2166136261u, b = 2166136261u;
    uint32_t h;
    unsigned i, n;

    n = k->af == FF_FLOW_MAP_V6 ? 4u : 1u;
    for (i = 0; i < n; i++) {
        a = (a ^ k->src[i]) * 16777619u;
        b = (b ^ k->dst[i]) * 16777619u;
    }
    h = a * 16777619u ^ b;
    h ^= (uint32_t)k->af + (((uint32_t)k->sport << 16) | k->dport);
    h *= 16777619u;
    h ^= h >> 16;
    h *= 2246822519u;
    h ^= h >> 13;
    return h;
}

static int
slot_matches(const struct ff_flow_slot *s, const struct ff_flow_key *k,
    uint32_t h)
{
    return s->hash == h && memcmp(&s->key, k, sizeof(*k)) == 0;
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
    return g_open != 0;
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
        g_table = (struct ff_flow_slot *)calloc(g_cap, sizeof(*g_table));
        if (g_table == NULL)
            g_alloc_fail++;
    }
    g_grown = 0;
    g_open = 1;
}

void
ff_flow_map_close(void)
{
    g_open = 0;

    /* Single-thread contract: nothing can be reading the table here, so the
     * allocation is released and the steady state carries no flow-map memory
     * at all; the next open() re-creates it on the control plane.
     * g_cap is kept: it survives the window so a capacity set by cap_set()
     * still describes the table that the next open() rebuilds. */
    if (g_table != NULL) {
        free(g_table);
        g_table = NULL;
    }
    g_grown = 0;
}

int
ff_flow_map_lookup(const struct ff_flow_key *key)
{
    struct ff_flow_slot *t;
    uint32_t idx, mask, h;
    unsigned probe;

    if (key == NULL)
        return 0;
    if (!g_open)
        return 0;
    /* The mask is taken before the table: growth replaces the table before
     * the capacity, so this order never pairs a mask with a smaller table. */
    mask = g_cap_mask;
    t = g_table;
    if (t == NULL)
        return 0;
    h = flow_hash(key);
    idx = h & mask;
    {
        for (probe = 0; probe < FF_FLOW_MAP_PROBE_MAX; probe++) {
            uint32_t st = t[idx].state;

            if (st == FF_FLOW_SLOT_EMPTY)
                return 0;
            /* P3: a placeholder is not a flow yet — keep probing so an
             * unconfirmed SYN cannot claim "this generation". */
            if (st == FF_FLOW_SLOT_USED && slot_matches(&t[idx], key, h))
                return 1;
            idx = (idx + 1) & mask;
        }
    }
    return 0;
}

/* P3 (C-P3-3): double the table once, bounded by GROW_MAX and CAP_MAX.
 * Only USED entries are migrated (a placeholder is per-window and is
 * dropped); if any entry cannot be placed the whole migration is abandoned
 * and the old table stays authoritative. Returns 1 on success. */
static int
flow_map_grow(void)
{
    struct ff_flow_slot *nt, *old;
    uint32_t new_cap, i;

    if (g_grown >= FF_FLOW_MAP_GROW_MAX)
        return 0;
    new_cap = g_cap << 1;
    if (new_cap > FF_FLOW_MAP_CAP_MAX)
        return 0;

    nt = (struct ff_flow_slot *)calloc(new_cap, sizeof(*nt));
    if (nt == NULL) {
        g_alloc_fail++;
        return 0;
    }

    old = g_table;
    for (i = 0; old != NULL && i < g_cap; i++) {
        uint32_t idx;
        unsigned probe;
        int placed = 0;

        if (old[i].state != FF_FLOW_SLOT_USED)
            continue;

        idx = old[i].hash & (new_cap - 1);
        for (probe = 0; probe < FF_FLOW_MAP_PROBE_MAX; probe++) {
            if (nt[idx].state == FF_FLOW_SLOT_EMPTY) {
                memcpy(&nt[idx].key, &old[i].key, sizeof(nt[idx].key));
                nt[idx].hash = old[i].hash;
                nt[idx].state = FF_FLOW_SLOT_USED;
                placed = 1;
                break;
            }
            idx = (idx + 1) & (new_cap - 1);
        }
        if (!placed) {
            /* a half-migrated table never becomes the live one */
            free(nt);
            g_grow_fail++;
            return 0;
        }
    }

    /* replace the table first, then the capacity that describes it */
    g_table = nt;
    free(old);
    g_cap = new_cap;
    g_cap_mask = new_cap - 1;
    g_grown++;
    return 1;
}

int
ff_flow_map_insert(const struct ff_flow_key *key)
{
    struct ff_flow_slot *t;
    uint32_t idx, mask, h;
    unsigned probe;

    if (key == NULL)
        return -1;
    if (!flow_map_active())
        return -1;

    if (g_table == NULL) {
        /* Lazy fallback when open() could not allocate. Counted like a
         * full table: downstream an unrecorded flow is indistinguishable
         * from a table-full one (both forward the packet). */
        t = (struct ff_flow_slot *)calloc(g_cap, sizeof(*t));
        if (t == NULL) {
            g_alloc_fail++;
            g_full++;
            return -1;
        }
        g_table = t;
    }

again:
    /* mask first, then the table: growth replaces the table before the
     * capacity, and cap_set() may have dropped the table to NULL. */
    mask = g_cap_mask;
    t = g_table;
    if (t == NULL)
        return -1;
    h = flow_hash(key);
    idx = h & mask;
    for (probe = 0; probe < FF_FLOW_MAP_PROBE_MAX; probe++) {
        uint32_t st = t[idx].state;

        if (st == FF_FLOW_SLOT_EMPTY) {
            memcpy(&t[idx].key, key, sizeof(*key));
            t[idx].hash = h;
            t[idx].state = FF_FLOW_SLOT_USED;
            g_inserted++;
            return 0;
        }
        if (slot_matches(&t[idx], key, h)) {
            /* Idempotent: a retransmitted SYN, or a four-tuple reused right
             * after a close, must not consume a second slot. Refusing it
             * would leave the four-tuple permanently untracked for this
             * window. */
            g_dup++;
            return 1;
        }
        idx = (idx + 1) & mask;
    }

    /* P3 (C-P3-3): one bounded expansion, then a single retry. */
    if (flow_map_grow())
        goto again;

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

void
ff_flow_map_stats2(uint64_t *inserted, uint64_t *dup, uint64_t *full,
    uint64_t *grown, uint64_t *grow_fail, uint64_t *alloc_fail,
    uint32_t *cap)
{
    if (inserted != NULL)
        *inserted = g_inserted;
    if (dup != NULL)
        *dup = g_dup;
    if (full != NULL)
        *full = g_full;
    if (grown != NULL)
        *grown = g_grown;
    if (grow_fail != NULL)
        *grow_fail = g_grow_fail;
    if (alloc_fail != NULL)
        *alloc_fail = g_alloc_fail;
    if (cap != NULL)
        *cap = g_cap;
}

void
ff_flow_map_cap_set(uint32_t cap)
{
    if (cap < FF_FLOW_MAP_CAP_MIN || cap > FF_FLOW_MAP_CAP_MAX)
        return;
    if ((cap & (cap - 1)) != 0)
        return;                     /* power of two: mask indexing */
    /* Drop the table before the new capacity takes effect: nothing reads it
     * here (single-thread contract) and the next open() rebuilds it. */
    if (g_table != NULL) {
        free(g_table);
        g_table = NULL;
    }
    g_cap = cap;
    g_cap_mask = cap - 1;
    g_grown = 0;
}
