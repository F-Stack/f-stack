/*-
 * Copyright (C) 2017-2021 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the copyright notice,
 *    this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>          /* clock_gettime for the handover deadline */
#include <sched.h>         /* sched_yield while waiting for rx release */
#include <signal.h>        /* kill(pid, 0) for epoch liveness */
#include <errno.h>
#include <sys/socket.h>    /* socklen_t for ff_msg.h */

#include "ff_reload.h"     /* stdint/stddef + block layout */
#include "ff_config.h"
#include "ff_msg.h"

static struct ff_reload_state *g_reload_state;
static int g_reload_gen;

/* M5: master epoch + the generation directory (NULL when graceful_reload=0,
 * when there is no resident primary, or in any process that never ran
 * rte_eal_init — i.e. the nginx master). */
static uint32_t g_reload_epoch;
static struct ff_reload_gendir *g_reload_gendir;
/* 0 until the attach path confirms this process may publish ownership. */
static int g_reload_dir_publish;

/* sampler bookkeeping (per process) */
static uint64_t g_hb_last_cnt;
static uint64_t g_hb_last_advance;
static uint64_t g_hb_timeout_tsc;
static int      g_hb_inited;

#ifdef FF_RELOAD_FAULT_INJECTION
/* Test builds only (nginx_reload_spec 08, RT-05/06/07): named faults are
 * selected with the FF_FAULT environment variable. Default builds carry
 * none of this code. noinline keeps the hooks visible to nm. */
#include <stdlib.h>
#include <errno.h>

__attribute__((noinline)) static int
ff_reload_fault_is(const char *name)
{
    static const char *sel;
    static int inited;

    if (!inited) {
        sel = getenv("FF_FAULT");
        inited = 1;
    }
    return sel != NULL && strcmp(sel, name) == 0;
}

/* RT-05: FF_FAULT=ready_delay publishes READY FF_FAULT_DELAY_MS late
 * (default past the 60 s master READY wait, i.e. a forced timeout). */
__attribute__((noinline)) static void
ff_reload_fault_delay(void)
{
    const char *v = getenv("FF_FAULT_DELAY_MS");
    long ms = (v != NULL) ? strtol(v, NULL, 10) : 70000;
    struct timespec ts;

    if (ms <= 0) {
        ms = 70000;
    }
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}
#endif /* FF_RELOAD_FAULT_INJECTION */

/* ---- pure helpers ------------------------------------------------------ */

int
ff_reload_state_valid(const void *block, size_t len)
{
    const struct ff_reload_state *s = block;

    if (block == NULL || len < sizeof(*s))
        return 0;
    if (s->magic != FF_RELOAD_STATE_MAGIC)
        return 0;
    if (s->version != FF_RELOAD_STATE_VERSION)
        return 0;
    if (s->len != sizeof(*s))
        return 0;
    return 1;
}

int
ff_reload_msg_ring_name_e(char *buf, unsigned int buflen, const char *base,
    unsigned int proc_id, int msg_type, int gen, uint32_t epoch, int graceful)
{
    unsigned slot;
    int n;

    if (buf == NULL || buflen == 0 || base == NULL)
        return -1;

    slot = ff_reload_epoch_slot_of(epoch);

    if (!graceful) {
        if (msg_type < 0)
            n = snprintf(buf, buflen, "%s%u", base, proc_id);
        else
            n = snprintf(buf, buflen, "%s%u_%d", base, proc_id, msg_type);
    } else {
        if (gen < 0)
            gen = 0;
        if (gen >= FF_RELOAD_GEN_MAX)
            gen = FF_RELOAD_GEN_MAX - 1;
        /* slot 0 keeps the pre-M5 names byte-for-byte (P0-6 style); every
         * other slot inserts "_e<slot>", one digit — a ring name is capped
         * at 28 bytes and this is the only width that always fits. */
        if (slot == 0) {
            if (msg_type < 0)
                n = snprintf(buf, buflen, "%s%u_g%d", base, proc_id, gen);
            else
                n = snprintf(buf, buflen, "%s%u_%d_g%d", base, proc_id,
                    msg_type, gen);
        } else {
            if (msg_type < 0)
                n = snprintf(buf, buflen, "%s%u_e%u_g%d", base, proc_id,
                    slot, gen);
            else
                n = snprintf(buf, buflen, "%s%u_%d_e%u_g%d", base, proc_id,
                    msg_type, slot, gen);
        }
    }

    if (n < 0 || (unsigned int)n >= buflen)
        return -1;
    return 0;
}

int
ff_reload_msg_ring_name(char *buf, unsigned int buflen, const char *base,
    unsigned int proc_id, int msg_type, int gen, int graceful)
{
    return ff_reload_msg_ring_name_e(buf, buflen, base, proc_id, msg_type,
        gen, 0, graceful);
}

int
ff_reload_heartbeat_eval(uint64_t prev_cnt, uint64_t cur_cnt,
    uint64_t now, uint64_t *last_advance, uint64_t timeout)
{
    if (last_advance == NULL)
        return -1;

    if (cur_cnt != prev_cnt) {
        *last_advance = now;
        return 1;
    }

    if (timeout == 0)
        return 1;

    /* unsigned delta handles non-monotonic callers gracefully */
    if (now < *last_advance)
        return 1;

    return (now - *last_advance) < timeout;
}

/* ---- lifecycle / generation -------------------------------------------- */

void
ff_reload_attach_state(void *block)
{
    if (block == NULL) {
        g_reload_state = NULL;
        return;
    }
    if (!ff_reload_state_valid(block, sizeof(struct ff_reload_state))) {
        fprintf(stderr, "ff_reload: invalid shared state block, "
            "graceful-reload extras disabled\n");
        return;
    }
    g_reload_state = (struct ff_reload_state *)block;
}

int
ff_reload_state_attached(void)
{
    return g_reload_state != NULL;
}

void
ff_reload_set_gen(int gen)
{
    if (gen < 0 || gen >= FF_RELOAD_GEN_MAX)
        return;
    g_reload_gen = gen;
}

int
ff_reload_gen(void)
{
    return g_reload_gen;
}

/* ---- M5: master epoch + generation directory --------------------------- */

void
ff_reload_set_epoch(uint32_t epoch)
{
    if (epoch == FF_RELOAD_EPOCH_NONE)
        return;
    g_reload_epoch = epoch;
}

uint32_t
ff_reload_epoch(void)
{
    return g_reload_epoch;
}

unsigned
ff_reload_epoch_slot(void)
{
    return ff_reload_epoch_slot_of(g_reload_epoch);
}

int
ff_reload_gendir_install(void *addr, size_t len)
{
    const struct ff_reload_gendir *d = addr;

    if (d == NULL || len < sizeof(*d) || d->magic != FF_RELOAD_GENDIR_MAGIC
        || d->version != FF_RELOAD_GENDIR_VERSION
        || d->len != (uint32_t)sizeof(*d)
        || d->slot_max != FF_RELOAD_EPOCH_SLOT_MAX
        || d->gen_max != FF_RELOAD_GEN_MAX) {
        if (addr != NULL)
            fprintf(stderr, "ff_reload: incompatible generation directory, "
                "cross-master extras disabled\n");
        g_reload_gendir = NULL;
        return -1;
    }
    g_reload_gendir = (struct ff_reload_gendir *)addr;
    return 0;
}

void
ff_reload_dir_sync_enable(int enable)
{
    g_reload_dir_publish = enable ? 1 : 0;
}

/* Local copy of the liveness test: ff_reload.c must stay linkable without
 * the DPDK-dependent directory module (tools and ff_config unit tests pull
 * this object alone). */
static int
epoch_slot_live(struct ff_reload_gendir *d, unsigned i)
{
    uint32_t pid, st;

    st = __atomic_load_n(&d->slot[i].state, __ATOMIC_SEQ_CST);
    if (st != FF_RELOAD_SLOT_LIVE)
        return 0;
    pid = __atomic_load_n(&d->slot[i].master_pid, __ATOMIC_SEQ_CST);
    if (pid == 0)
        return 0;
    return kill((pid_t)pid, 0) == 0 || errno == EPERM;
}

static uint64_t
dir_pack(uint32_t epoch, uint32_t gen)
{
    return (((uint64_t)epoch) << 32) | (uint64_t)gen;
}

static uint64_t
dir_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static int
epoch_live(struct ff_reload_gendir *d, uint32_t epoch)
{
    unsigned i;

    if (d == NULL || epoch == FF_RELOAD_EPOCH_NONE)
        return 0;
    for (i = 0; i < FF_RELOAD_EPOCH_SLOT_MAX; i++) {
        if (__atomic_load_n(&d->slot[i].epoch, __ATOMIC_SEQ_CST) != epoch)
            continue;
        return epoch_slot_live(d, i);
    }
    return 0;
}

/* F-M5-1 (USR2): a slot whose master pid is gone but whose workers still
 * refresh the stamp — the drain window between "old master quit" and
 * "last old worker exited". Workers exit with exit(0) and cannot run any
 * teardown, so the stamp going stale is the only death notice this side
 * gets. Unsigned delta keeps the comparison wrap-safe. */
static int
epoch_slot_draining(struct ff_reload_gendir *d, unsigned i)
{
    uint32_t stamp;

    if (__atomic_load_n(&d->slot[i].state, __ATOMIC_SEQ_CST)
        != FF_RELOAD_SLOT_LIVE)
        return 0;
    stamp = __atomic_load_n(&d->slot[i].pad, __ATOMIC_SEQ_CST);
    return (uint32_t)(dir_now_ms() - stamp) < FF_RELOAD_SLOT_STALE_MS;
}

/* C-NR-501/M5: the anonymous block is master-private, so the directory can
 * only be updated by a process that inherited it — a worker. Two rules keep
 * that safe: inside our own epoch we simply follow our master's flip, and
 * an epoch we do not own may only be displaced once it is dead. */
void
ff_reload_dir_sync(void)
{
    struct ff_reload_gendir *d = g_reload_gendir;
    uint64_t cur, next;
    uint32_t bep, bgen, bstop, oe;
    int owner_gen;

    if (d == NULL || !g_reload_dir_publish)
        return;

    if (g_reload_state == NULL) {
        bep = g_reload_epoch;
        bgen = (uint32_t)ff_reload_gen();
        bstop = 0;
    } else {
        owner_gen = ff_reload_rx_owner_gen();
        bgen = (uint32_t)(owner_gen < 0 ? ff_reload_gen() : owner_gen);
        bstop = (uint32_t)(ff_reload_rx_stopped() ? 1 : 0);
        bep = __atomic_load_n(&g_reload_state->reserved[4],
            __ATOMIC_SEQ_CST);
        if (bep == 0)
            bep = g_reload_epoch;
    }

    /* F-M5-1: keep our own slot stamp fresh (throttled: one shared-line
     * write per second is enough for the FF_RELOAD_SLOT_STALE_MS window)
     * and publish the peer coordinate into the block BEFORE the ownership
     * gate below — a worker parked behind a foreign live owner returns
     * early there, and its master's block (and its per-packet mirror
     * view) must still learn that the peer exists. */
    {
        static uint64_t last_stamp_ms;
        uint64_t now = dir_now_ms();
        unsigned i;

        if (g_reload_state != NULL) {
            uint32_t pe;
            int pg;

            ff_reload_peer_coord(&pe, &pg);
            if (__atomic_load_n(&g_reload_state->peer_epoch, __ATOMIC_SEQ_CST)
                != pe)
                __atomic_store_n(&g_reload_state->peer_epoch, pe,
                    __ATOMIC_SEQ_CST);
            if (__atomic_load_n(&g_reload_state->peer_gen, __ATOMIC_SEQ_CST)
                != (uint32_t)pg)
                __atomic_store_n(&g_reload_state->peer_gen, (uint32_t)pg,
                    __ATOMIC_SEQ_CST);
        }

        if (now - last_stamp_ms >= FF_RELOAD_SLOT_STALE_MS / 2) {
            last_stamp_ms = now;
            for (i = 0; i < FF_RELOAD_EPOCH_SLOT_MAX; i++) {
                if (__atomic_load_n(&d->slot[i].epoch, __ATOMIC_SEQ_CST)
                    == g_reload_epoch) {
                    __atomic_store_n(&d->slot[i].pad, (uint32_t)now,
                        __ATOMIC_SEQ_CST);
                    break;
                }
            }
        }
    }

    cur = __atomic_load_n(&d->rx_owner_word, __ATOMIC_SEQ_CST);
    oe = (uint32_t)(cur >> 32);
    if (oe != g_reload_epoch && oe != FF_RELOAD_EPOCH_NONE
        && epoch_live(d, oe))
        return;

    next = (((uint64_t)bep) << 32) | (uint64_t)bgen;
    if (next != cur)
        __atomic_store_n(&d->rx_owner_word, next, __ATOMIC_SEQ_CST);
    if (__atomic_load_n(&d->rx_stopped, __ATOMIC_SEQ_CST) != bstop)
        __atomic_store_n(&d->rx_stopped, bstop, __ATOMIC_SEQ_CST);

    /* KNI runtime ownership follows the same (epoch, gen) coordinate. */
    {
        uint64_t knew, kcur;
        uint32_t kep = bep;
        uint32_t kg = (uint32_t)ff_reload_kni_owner_gen();

        if (kg >= FF_RELOAD_GEN_MAX)
            kg = (uint32_t)ff_reload_gen();
        knew = (((uint64_t)kep) << 32) | (uint64_t)kg;
        kcur = __atomic_load_n(&d->kni_owner_word, __ATOMIC_SEQ_CST);
        if (kcur != knew)
            __atomic_store_n(&d->kni_owner_word, knew, __ATOMIC_SEQ_CST);
    }

    /* Active generation: same source and same gate as the rx owner, so the
     * directory cannot end up pointing at a master that no longer serves
     * (a stale owner would keep answering tool probes after the handover).
     * Without this the word only ever carries FF_RELOAD_EPOCH_NONE — the
     * master cannot write it (no EAL) — and the primary would answer every
     * probe with its own epoch 0, i.e. slot 0, which nobody dequeues. */
    {
        uint64_t acur = __atomic_load_n(&d->active_word, __ATOMIC_SEQ_CST);

        if (acur != next)
            __atomic_store_n(&d->active_word, next, __ATOMIC_SEQ_CST);
    }
}

/* 1 when the directory (if any) agrees that this (epoch, gen) owns the
 * hardware. A directory that has not been claimed yet does not narrow
 * anything, so a stack without one behaves exactly as before M5. */
static int
dir_allows_hw(void)
{
    struct ff_reload_gendir *d = g_reload_gendir;
    uint64_t w;

    if (d == NULL)
        return 1;
    w = __atomic_load_n(&d->rx_owner_word, __ATOMIC_SEQ_CST);
    if ((uint32_t)(w >> 32) == FF_RELOAD_EPOCH_NONE)
        return 1;
    if ((uint32_t)(w >> 32) != g_reload_epoch)
        return 0;
    if ((uint32_t)w != (uint32_t)ff_reload_gen())
        return 0;
    return __atomic_load_n(&d->rx_stopped, __ATOMIC_SEQ_CST) == 0;
}

int
ff_reload_kni_owner_match(void)
{
    struct ff_reload_gendir *d = g_reload_gendir;
    uint64_t w;

    if (d == NULL)
        return ff_reload_gen() == ff_reload_active_gen();
    w = __atomic_load_n(&d->kni_owner_word, __ATOMIC_SEQ_CST);
    if ((uint32_t)(w >> 32) == FF_RELOAD_EPOCH_NONE)
        return ff_reload_gen() == ff_reload_active_gen();
    return (uint32_t)(w >> 32) == g_reload_epoch
        && (uint32_t)w == (uint32_t)ff_reload_gen();
}

void
ff_reload_peer_coord(uint32_t *epoch, int *gen)
{
    struct ff_reload_gendir *d = g_reload_gendir;
    uint32_t best_epoch = FF_RELOAD_EPOCH_NONE;
    uint32_t best_gen = 0;
    unsigned i;

    /* F-M5-1: while THIS master runs its own reload window the peer is the
     * intra-master generation pair (the fallback below), never a foreign
     * epoch — a coexisting master's slot must not capture the drain rings
     * of an M4 round. Outside a window (steady state, USR2 handover) the
     * newest foreign epoch is the peer. */
    if (d != NULL && !ff_reload_hw_locked()) {
        for (i = 0; i < FF_RELOAD_EPOCH_SLOT_MAX; i++) {
            uint32_t e, g, fl;

            fl = __atomic_load_n(&d->slot[i].flags, __ATOMIC_SEQ_CST);
            /* The resident primary holds slot 0 / epoch 0 forever and runs
             * no stack instance, so it is never a drain peer: selecting it
             * would send flow-map misses into a ring nobody dequeues. */
            if (fl & FF_RELOAD_SLOT_PRIMARY)
                continue;
            e = __atomic_load_n(&d->slot[i].epoch, __ATOMIC_SEQ_CST);
            if (e == g_reload_epoch || e == FF_RELOAD_EPOCH_NONE)
                continue;
            if (!epoch_slot_live(d, i) && !epoch_slot_draining(d, i))
                continue;
            g = __atomic_load_n(&d->slot[i].gen, __ATOMIC_SEQ_CST);
            if (best_epoch != FF_RELOAD_EPOCH_NONE && e <= best_epoch)
                continue;
            best_epoch = e;
            best_gen = g;
        }
    }

    if (best_epoch == FF_RELOAD_EPOCH_NONE) {
        best_epoch = g_reload_epoch;
        best_gen = (uint32_t)((ff_reload_gen() + 1) % FF_RELOAD_GEN_MAX);
    }
    if (epoch)
        *epoch = best_epoch;
    if (gen)
        *gen = (int)best_gen;
}

int
ff_reload_peer_draining(void)
{
    uint32_t pe;
    int pg;

    ff_reload_peer_coord(&pe, &pg);
    return pe != FF_RELOAD_EPOCH_NONE && pe != g_reload_epoch;
}

int
ff_reload_peer_mirror_draining(void)
{
    uint32_t pe, pg;

    if (g_reload_state == NULL)
        return 0;
    ff_reload_peer_block(&pe, &pg);
    return pe != 0 && pe != FF_RELOAD_EPOCH_NONE && pe != g_reload_epoch
        && pg < FF_RELOAD_GEN_MAX;
}

void
ff_reload_peer_block(uint32_t *epoch, uint32_t *gen)
{
    if (epoch)
        *epoch = 0;
    if (gen)
        *gen = 0;
    if (g_reload_state == NULL)
        return;
    if (epoch)
        *epoch = __atomic_load_n(&g_reload_state->peer_epoch,
            __ATOMIC_SEQ_CST);
    if (gen)
        *gen = __atomic_load_n(&g_reload_state->peer_gen, __ATOMIC_SEQ_CST);
}

int
ff_reload_gendir_active(uint32_t *epoch, uint32_t *gen)
{
    struct ff_reload_gendir *d = g_reload_gendir;
    uint64_t w;

    if (d == NULL)
        return -1;
    w = __atomic_load_n(&d->active_word, __ATOMIC_SEQ_CST);
    if (epoch)
        *epoch = (uint32_t)(w >> 32);
    if (gen)
        *gen = (uint32_t)w;
    return 0;
}

void
ff_reload_gendir_active_set(uint32_t epoch, uint32_t gen)
{
    struct ff_reload_gendir *d = g_reload_gendir;

    if (d == NULL)
        return;
    __atomic_store_n(&d->active_word, dir_pack(epoch, gen),
        __ATOMIC_SEQ_CST);
}

int
ff_reload_gendir_rx_owner(uint32_t *epoch, uint32_t *gen, uint32_t *stopped)
{
    struct ff_reload_gendir *d = g_reload_gendir;
    uint64_t w;

    if (d == NULL)
        return -1;
    w = __atomic_load_n(&d->rx_owner_word, __ATOMIC_SEQ_CST);
    if (epoch)
        *epoch = (uint32_t)(w >> 32);
    if (gen)
        *gen = (uint32_t)w;
    if (stopped)
        *stopped = __atomic_load_n(&d->rx_stopped, __ATOMIC_SEQ_CST);
    return 0;
}

int
ff_reload_gendir_kni_owner(uint32_t *epoch, uint32_t *gen)
{
    struct ff_reload_gendir *d = g_reload_gendir;
    uint64_t w;

    if (d == NULL)
        return -1;
    w = __atomic_load_n(&d->kni_owner_word, __ATOMIC_SEQ_CST);
    if (epoch)
        *epoch = (uint32_t)(w >> 32);
    if (gen)
        *gen = (uint32_t)w;
    return 0;
}

void
ff_reload_gendir_kni_owner_set(uint32_t epoch, uint32_t gen)
{
    struct ff_reload_gendir *d = g_reload_gendir;

    if (d == NULL)
        return;
    __atomic_store_n(&d->kni_owner_word, dir_pack(epoch, gen),
        __ATOMIC_SEQ_CST);
}

int
ff_reload_gendir_rx_release(uint32_t to_epoch, uint32_t to_gen)
{
    struct ff_reload_gendir *d = g_reload_gendir;
    uint64_t mine, next;

    if (d == NULL)
        return FF_RELOAD_HANDOVER_INVAL;
    if (to_gen >= FF_RELOAD_GEN_MAX)
        return FF_RELOAD_HANDOVER_INVAL;

    mine = dir_pack(ff_reload_epoch(), (uint32_t)ff_reload_gen());
    next = dir_pack(to_epoch, to_gen);

    /* Park first, then transfer: a reader sampling in between still sees
     * rx_stopped and stays off the hardware. */
    __atomic_store_n(&d->rx_stopped, 1u, __ATOMIC_SEQ_CST);
    if (!__atomic_compare_exchange_n(&d->rx_owner_word, &mine, next, 0,
            __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        if (__atomic_load_n(&d->rx_owner_word, __ATOMIC_SEQ_CST) != next)
            __atomic_store_n(&d->rx_stopped, 0u, __ATOMIC_SEQ_CST);
        return FF_RELOAD_HANDOVER_BUSY;
    }
    return FF_RELOAD_HANDOVER_OK;
}

int
ff_reload_gendir_rx_claim(uint32_t from_epoch, uint32_t from_gen,
    uint32_t to_epoch, uint32_t to_gen, unsigned timeout_ms)
{
    struct ff_reload_gendir *d = g_reload_gendir;
    uint64_t from, to;
    uint64_t deadline;

    if (d == NULL)
        return FF_RELOAD_HANDOVER_INVAL;
    if (to_gen >= FF_RELOAD_GEN_MAX)
        return FF_RELOAD_HANDOVER_INVAL;

    from = dir_pack(from_epoch, from_gen);
    to = dir_pack(to_epoch, to_gen);

    if (__atomic_load_n(&d->rx_owner_word, __ATOMIC_SEQ_CST) == to) {
        __atomic_store_n(&d->rx_stopped, 0u, __ATOMIC_SEQ_CST);
        return FF_RELOAD_HANDOVER_OK;
    }
    /* Never steal the hardware from a third coordinate. */
    if (__atomic_load_n(&d->rx_owner_word, __ATOMIC_SEQ_CST) != from)
        return FF_RELOAD_HANDOVER_BUSY;

    if (timeout_ms == 0)
        timeout_ms = FF_RELOAD_HANDOVER_TIMEOUT_MS_DEFAULT;
    deadline = dir_now_ms() + timeout_ms;

    for (;;) {
        if (__atomic_load_n(&d->rx_owner_word, __ATOMIC_SEQ_CST) == to) {
            __atomic_store_n(&d->rx_stopped, 0u, __ATOMIC_SEQ_CST);
            return FF_RELOAD_HANDOVER_OK;
        }
        if (dir_now_ms() >= deadline)
            return FF_RELOAD_HANDOVER_TIMEOUT;
        sched_yield();
    }
}

int
ff_reload_gendir_rx_reclaim(uint32_t my_epoch, uint32_t my_gen)
{
    struct ff_reload_gendir *d = g_reload_gendir;
    uint64_t cur, next;

    if (d == NULL)
        return FF_RELOAD_HANDOVER_INVAL;
    if (my_gen >= FF_RELOAD_GEN_MAX)
        return FF_RELOAD_HANDOVER_INVAL;

    next = dir_pack(my_epoch, my_gen);
    cur = __atomic_load_n(&d->rx_owner_word, __ATOMIC_SEQ_CST);
    if (cur == next) {
        __atomic_store_n(&d->rx_stopped, 0u, __ATOMIC_SEQ_CST);
        return FF_RELOAD_HANDOVER_OK;
    }
    /* M4 DR6(1) / RT-04b: only a dead owner may be displaced. */
    if (epoch_live(d, (uint32_t)(cur >> 32)))
        return FF_RELOAD_HANDOVER_BUSY;
    if (!__atomic_compare_exchange_n(&d->rx_owner_word, &cur, next, 0,
            __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
        return FF_RELOAD_HANDOVER_BUSY;
    __atomic_store_n(&d->rx_stopped, 0u, __ATOMIC_SEQ_CST);
    return FF_RELOAD_HANDOVER_OK;
}

int
ff_reload_active_gen(void)
{
    if (g_reload_state == NULL)
        return 0;
    return (int)__atomic_load_n(&g_reload_state->active_gen,
        __ATOMIC_SEQ_CST);
}

int
ff_reload_target_gen(void)
{
    if (g_reload_state == NULL)
        return 0;
    return (int)__atomic_load_n(&g_reload_state->target_gen,
        __ATOMIC_SEQ_CST);
}

int
ff_reload_kni_owner_gen(void)
{
    if (g_reload_state == NULL)
        return 0;
    return (int)__atomic_load_n(&g_reload_state->kni_owner_gen,
        __ATOMIC_SEQ_CST);
}

int
ff_reload_worker_gen(void)
{
    if (g_reload_state == NULL)
        return 0;
    if (__atomic_load_n(&g_reload_state->reload_active, __ATOMIC_SEQ_CST))
        return ff_reload_target_gen();
    return ff_reload_active_gen();
}

int
ff_reload_hw_locked(void)
{
    if (g_reload_state == NULL)
        return 0;
    return __atomic_load_n(&g_reload_state->reload_active,
        __ATOMIC_SEQ_CST) != 0;
}

/* ---- rx handover (C-NR-302) -------------------------------------------- */

/* Monotonic clock in ms for the handover deadline. */
static uint64_t
reload_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

int
ff_reload_rx_owner_gen(void)
{
    if (g_reload_state == NULL)
        return -1;
    return (int)__atomic_load_n(&g_reload_state->rx_owner_gen,
        __ATOMIC_SEQ_CST);
}

void
ff_reload_rx_owner_gen_set(int gen)
{
    if (g_reload_state == NULL)
        return;
    if (gen < 0 || gen >= FF_RELOAD_GEN_MAX)
        return;
    __atomic_store_n(&g_reload_state->rx_owner_gen, (uint32_t)gen,
        __ATOMIC_SEQ_CST);
}

int
ff_reload_rx_stopped(void)
{
    if (g_reload_state == NULL)
        return 0;
    return __atomic_load_n(&g_reload_state->rx_stopped,
        __ATOMIC_SEQ_CST) != 0;
}

void
ff_reload_rx_stopped_set(int stopped)
{
    if (g_reload_state == NULL)
        return;
    __atomic_store_n(&g_reload_state->rx_stopped, stopped ? 1u : 0u,
        __ATOMIC_SEQ_CST);
}

int
ff_no_hw_mode(void)
{
    int owner, stopped;

    if (!ff_global_cfg.dpdk.graceful_reload)
        return 0;

    /* M5: publish this master's decision into the cross-master directory
     * before deciding. It can only ever narrow the verdict below, never
     * widen it, so a directory lag costs one parked pass at most. */
    ff_reload_dir_sync();

    /* P1-b: read rx_stopped BEFORE rx_owner_gen. The two loads are
     * separate atomics, so a preemption between them can pair values that
     * never coexisted. With this order the dangerous verdict (owner ==
     * my gen && stopped == 0, i.e. unparked) can only be built while the
     * flip is still in the future: owner == my gen means the owner load
     * preceded the ownership flip, and a stopped load taken after the
     * park order was issued reads 1 and parks us instead. A pass that
     * still reads stopped == 0 therefore read it before the park order
     * even existed, and the T2 barrier covers exactly that pass: the
     * master only flips after this worker has acked from a LATER parked
     * pass, so the unparked pass has finished its rx_burst before the
     * new owner can start polling. Fails safe: the worst outcome of a
     * stale pairing is one extra parked pass. */
    stopped = ff_reload_rx_stopped();
    owner = ff_reload_rx_owner_gen();
    if (owner < 0)
        return !dir_allows_hw();
    if (owner != ff_reload_gen())
        return 1;
    if (stopped)
        return 1;
    /* M5: the directory is the cross-master authority — two masters with
     * the same gen must never both come back "unparked" here. */
    return !dir_allows_hw();
}

int
ff_is_drain_generation(void)
{
    int owner = ff_reload_rx_owner_gen();

    if (owner < 0)
        return !dir_allows_hw();
    if (owner != ff_reload_gen())
        return 1;
    return !dir_allows_hw();
}

int
ff_reload_rx_release(int to_gen)
{
#ifdef FF_RELOAD_FAULT_INJECTION
    /* RT-07 test hook: forced ownership-flip failure (markers untouched,
     * so the master's abort rollback stays consistent). */
    if (ff_reload_fault_is("flip_fail")) {
        return FF_RELOAD_HANDOVER_TIMEOUT;
    }
#endif
    if (g_reload_state == NULL)
        return FF_RELOAD_HANDOVER_INVAL;
    if (to_gen < 0 || to_gen >= FF_RELOAD_GEN_MAX)
        return FF_RELOAD_HANDOVER_INVAL;

    /* Order matters: park first, then transfer. A main_loop that samples the
     * marker between the two stores still sees rx_stopped and stops polling,
     * so no window exists where two generations poll the same queue. */
    ff_reload_rx_stopped_set(1);
    ff_reload_rx_owner_gen_set(to_gen);
    return FF_RELOAD_HANDOVER_OK;
}

int
ff_reload_rx_release_epoch(uint32_t to_epoch, int to_gen)
{
    int rc;

    if (g_reload_state == NULL)
        return FF_RELOAD_HANDOVER_INVAL;
    if (to_gen < 0 || to_gen >= FF_RELOAD_GEN_MAX)
        return FF_RELOAD_HANDOVER_INVAL;

    /* reserved[4] carries the epoch the hardware is handed to (0 == our
     * own), so the workers that mirror the block into the directory can
     * move ownership to another master's generation (M5/USR2). */
    __atomic_store_n(&g_reload_state->reserved[4], to_epoch,
        __ATOMIC_SEQ_CST);
    ff_reload_rx_stopped_set(1);
    ff_reload_rx_owner_gen_set(to_gen);

    rc = ff_reload_gendir_rx_release(to_epoch, (uint32_t)to_gen);
    if (rc == FF_RELOAD_HANDOVER_INVAL)
        rc = FF_RELOAD_HANDOVER_OK;   /* no directory: block-only, as M4 */
    return rc;
}

int
ff_queue_handover_mutex(uint16_t port_id, uint16_t queue_id,
    int from_gen, int to_gen, unsigned timeout_ms)
{
    uint64_t deadline;

    /* The marker is process-wide: F-Stack hands over every queue of a
     * generation in one shot. port/queue are kept in the signature for API
     * compatibility with the spec and for a future per-queue refinement. */
    (void)port_id;
    (void)queue_id;

#ifdef FF_RELOAD_FAULT_INJECTION
    /* RT-07 test hook: forced cross-process handover-mutex timeout. */
    if (ff_reload_fault_is("mutex_timeout")) {
        return FF_RELOAD_HANDOVER_TIMEOUT;
    }
#endif
    if (g_reload_state == NULL)
        return FF_RELOAD_HANDOVER_INVAL;
    if (from_gen == to_gen)
        return FF_RELOAD_HANDOVER_INVAL;
    if (from_gen < 0 || from_gen >= FF_RELOAD_GEN_MAX ||
        to_gen < 0 || to_gen >= FF_RELOAD_GEN_MAX)
        return FF_RELOAD_HANDOVER_INVAL;

    /* Already ours (or a repeated call): just make sure we are not parked. */
    if (ff_reload_rx_owner_gen() == to_gen) {
        ff_reload_rx_stopped_set(0);
        return FF_RELOAD_HANDOVER_OK;
    }
    /* Never steal the hardware: if a third generation owns rx the handover
     * is refused outright. This single check is what makes concurrent
     * rte_eth_rx_burst on one queue impossible. With FF_RELOAD_GEN_MAX == 2
     * it is unreachable (from_gen and to_gen cover every value) and only
     * guards a future widening of the generation count. */
    if (ff_reload_rx_owner_gen() != from_gen)
        return FF_RELOAD_HANDOVER_BUSY;

    if (timeout_ms == 0)
        timeout_ms = FF_RELOAD_HANDOVER_TIMEOUT_MS_DEFAULT;
    deadline = reload_now_ms() + timeout_ms;

    for (;;) {
        if (ff_reload_rx_owner_gen() == to_gen) {
            /* We own the hardware now: clear the parked flag so our own
             * main_loop resumes rx/tx. */
            ff_reload_rx_stopped_set(0);
            return FF_RELOAD_HANDOVER_OK;
        }
        if (reload_now_ms() >= deadline)
            return FF_RELOAD_HANDOVER_TIMEOUT;
        sched_yield();
    }
}

/* ---- T2 park barrier (C-NR-306) ----------------------------------------- */

/* Slot of this process in the shared block; only real workers register one. */
static int g_reload_slot = -1;

void
ff_reload_set_slot(int slot)
{
    if (slot < 0 || slot >= FF_RELOAD_MAX_PROCS)
        return;
    g_reload_slot = slot;
}

void
ff_reload_handover_arm(uint32_t *epoch)
{
    uint32_t e;

    if (g_reload_state == NULL) {
        if (epoch)
            *epoch = 0;
        return;
    }
    e = __atomic_add_fetch(&g_reload_state->handover_epoch, 1,
        __ATOMIC_SEQ_CST);
    if (epoch)
        *epoch = e;
}

int
ff_reload_handover_parked(unsigned slot, uint32_t epoch)
{
    uint64_t word;

    if (g_reload_state == NULL || slot >= FF_RELOAD_MAX_PROCS)
        return 0;
    word = __atomic_load_n(&g_reload_state->rx_parked[slot],
        __ATOMIC_SEQ_CST);
    return word == (((uint64_t)epoch << 32) | 1u);
}

void
ff_reload_handover_ack(void)
{
    uint32_t epoch;
    uint64_t word;

#ifdef FF_RELOAD_FAULT_INJECTION
    /* RT-07 test hook: a wedged worker that never acks the park order. */
    if (ff_reload_fault_is("park_never")) {
        return;
    }
#endif
    if (g_reload_state == NULL || g_reload_slot < 0)
        return;
    /* A racing re-arm between the load and the store can only produce a
     * stale-tagged word: the next round's wait compares full epoch-tagged
     * words, so it ignores it and this worker re-acks on its next pass. */
    epoch = __atomic_load_n(&g_reload_state->handover_epoch,
        __ATOMIC_SEQ_CST);
    word = ((uint64_t)epoch << 32) | 1u;
    __atomic_store_n(&g_reload_state->rx_parked[g_reload_slot], word,
        __ATOMIC_SEQ_CST);
}

/* ---- drain reporting (M4: C-NR-402/403/406) ---------------------------- */

static struct ff_reload_drain_state *g_drain_state;

int
ff_reload_drain_attach(void *block, size_t len)
{
    struct ff_reload_drain_state *d = block;
    uintptr_t addr;

    if (block == NULL) {
        return -1;
    }
    if (len < sizeof(*d) || d->magic != FF_RELOAD_DRAIN_MAGIC
        || d->len != sizeof(*d)) {
        fprintf(stderr, "ff_reload: invalid drain state block ignored\n");
        return -1;
    }

    g_drain_state = d;

    /* Self-describing: a tool holding only the main block can follow to
     * the extension. The master writes this before any fork; children
     * re-attach defensively with the same value. */
    if (g_reload_state != NULL) {
        addr = (uintptr_t)d;
        __atomic_store_n(&g_reload_state->reserved[0],
            (uint32_t)(addr & 0xffffffffu), __ATOMIC_SEQ_CST);
        __atomic_store_n(&g_reload_state->reserved[1],
            (uint32_t)(addr >> 32), __ATOMIC_SEQ_CST);
    }
    return 0;
}

int
ff_reload_slot(void)
{
    return g_reload_slot;
}

uint32_t
ff_reload_shared_epoch(void)
{
    if (g_reload_state == NULL) {
        return 0;
    }
    return __atomic_load_n(&g_reload_state->epoch, __ATOMIC_SEQ_CST);
}

void
ff_reload_drain_publish(unsigned slot, uint32_t epoch, uint32_t conns,
    uint64_t snd_pending, uint64_t syncache)
{
    struct ff_reload_drain_report *r;
    struct timespec ts;
    uint64_t now_ms;

    if (g_drain_state == NULL) {
        return;
    }
    if (slot >= FF_RELOAD_MAX_PROCS) {
        /* same bound as ready[] in ff_reload_publish_ready */
        fprintf(stderr, "ff_reload: worker slot %u >= %d, "
            "drain report dropped\n", slot, FF_RELOAD_MAX_PROCS);
        return;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        now_ms = 0;
    } else {
        now_ms = (uint64_t)ts.tv_sec * 1000u
            + (uint64_t)(ts.tv_nsec / 1000000);
    }

    r = &g_drain_state->slot[slot];
    /* word first: a racing reader sees either the old pair or the new
     * epoch + count together, never a mix */
    __atomic_store_n(&r->word, ((uint64_t)epoch << 32) | conns,
        __ATOMIC_SEQ_CST);
    __atomic_store_n(&r->snd_pending, snd_pending, __ATOMIC_SEQ_CST);
    __atomic_store_n(&r->syncache, syncache, __ATOMIC_SEQ_CST);
    __atomic_store_n(&r->last_active_ms, now_ms, __ATOMIC_SEQ_CST);
}

int
ff_reload_drain_report(unsigned slot, uint32_t epoch, uint32_t *conns,
    uint64_t *snd_pending, uint64_t *syncache, uint64_t *last_active_ms)
{
    struct ff_reload_drain_report *r;
    uint64_t word;

    if (g_drain_state == NULL || slot >= FF_RELOAD_MAX_PROCS) {
        return -1;
    }

    r = &g_drain_state->slot[slot];
    word = __atomic_load_n(&r->word, __ATOMIC_SEQ_CST);
    if ((uint32_t)(word >> 32) != epoch) {
        return -1;
    }

    if (conns != NULL) {
        *conns = (uint32_t)word;
    }
    if (snd_pending != NULL) {
        *snd_pending = __atomic_load_n(&r->snd_pending, __ATOMIC_SEQ_CST);
    }
    if (syncache != NULL) {
        *syncache = __atomic_load_n(&r->syncache, __ATOMIC_SEQ_CST);
    }
    if (last_active_ms != NULL) {
        *last_active_ms = __atomic_load_n(&r->last_active_ms,
            __ATOMIC_SEQ_CST);
    }
    return 0;
}

void
ff_reload_drain_reset(void)
{
    if (g_drain_state == NULL) {
        return;
    }
    /* slots need no clearing: reports are epoch-tagged */
    __atomic_store_n(&g_drain_state->rx_fwd, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_drain_state->tx_fwd, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_drain_state->rx_peak, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_drain_state->tx_peak, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_drain_state->reclaim, 0, __ATOMIC_RELAXED);
}

void
ff_reload_drain_fwd_add(int tx, uint64_t n)
{
    if (g_drain_state == NULL || n == 0) {
        return;
    }
    if (tx) {
        __atomic_fetch_add(&g_drain_state->tx_fwd, n, __ATOMIC_RELAXED);
    } else {
        __atomic_fetch_add(&g_drain_state->rx_fwd, n, __ATOMIC_RELAXED);
    }
}

void
ff_reload_drain_peak_max(int tx, uint64_t v)
{
    uint64_t *p, cur;

    if (g_drain_state == NULL) {
        return;
    }
    p = tx ? &g_drain_state->tx_peak : &g_drain_state->rx_peak;
    cur = __atomic_load_n(p, __ATOMIC_RELAXED);
    while (v > cur
        && !__atomic_compare_exchange_n(p, &cur, v, 0,
            __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        /* cur refreshed by the failed CAS */
    }
}

void
ff_reload_drain_counters(uint64_t *rx_fwd, uint64_t *tx_fwd,
    uint64_t *rx_peak, uint64_t *tx_peak)
{
    if (rx_fwd != NULL) {
        *rx_fwd = (g_drain_state == NULL) ? 0
            : __atomic_load_n(&g_drain_state->rx_fwd, __ATOMIC_RELAXED);
    }
    if (tx_fwd != NULL) {
        *tx_fwd = (g_drain_state == NULL) ? 0
            : __atomic_load_n(&g_drain_state->tx_fwd, __ATOMIC_RELAXED);
    }
    if (rx_peak != NULL) {
        *rx_peak = (g_drain_state == NULL) ? 0
            : __atomic_load_n(&g_drain_state->rx_peak, __ATOMIC_RELAXED);
    }
    if (tx_peak != NULL) {
        *tx_peak = (g_drain_state == NULL) ? 0
            : __atomic_load_n(&g_drain_state->tx_peak, __ATOMIC_RELAXED);
    }
}

void
ff_reload_drain_reclaim_mark(void)
{
    if (g_drain_state == NULL) {
        return;
    }
    __atomic_store_n(&g_drain_state->reclaim,
        ((uint64_t)ff_reload_shared_epoch() << 32)
            | (uint32_t)ff_reload_gen(), __ATOMIC_SEQ_CST);
}

int
ff_reload_drain_reclaim(uint32_t *epoch, int *gen)
{
    uint64_t w;

    if (g_drain_state == NULL) {
        return -1;
    }
    w = __atomic_load_n(&g_drain_state->reclaim, __ATOMIC_SEQ_CST);
    if (w == 0) {
        return -1;
    }
    if (epoch != NULL) {
        *epoch = (uint32_t)(w >> 32);
    }
    if (gen != NULL) {
        *gen = (int)(uint32_t)w;
    }
    return 0;
}

void
ff_reload_phase_ms_set(int phase, uint32_t ms)
{
    if (g_reload_state == NULL) {
        return;
    }
    if (phase == FF_RELOAD_PHASE_HANDOVER) {
        __atomic_store_n(&g_reload_state->reserved[2], ms,
            __ATOMIC_SEQ_CST);
    } else if (phase == FF_RELOAD_PHASE_DRAIN) {
        __atomic_store_n(&g_reload_state->reserved[3], ms,
            __ATOMIC_SEQ_CST);
    }
}

uint32_t
ff_reload_phase_ms_get(int phase)
{
    if (g_reload_state == NULL) {
        return 0;
    }
    if (phase == FF_RELOAD_PHASE_HANDOVER) {
        return __atomic_load_n(&g_reload_state->reserved[2],
            __ATOMIC_SEQ_CST);
    }
    if (phase == FF_RELOAD_PHASE_DRAIN) {
        return __atomic_load_n(&g_reload_state->reserved[3],
            __ATOMIC_SEQ_CST);
    }
    return 0;
}

/* ---- master-side orchestration ----------------------------------------- */

void
ff_reload_master_begin(uint32_t *epoch, uint32_t *target_gen)
{
    uint32_t e, t;

    if (g_reload_state == NULL)
        return;

    e = __atomic_add_fetch(&g_reload_state->epoch, 1, __ATOMIC_SEQ_CST);
    t = __atomic_load_n(&g_reload_state->active_gen, __ATOMIC_SEQ_CST) ^ 1;
    __atomic_store_n(&g_reload_state->target_gen, t, __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_reload_state->reload_active, 1, __ATOMIC_SEQ_CST);

    if (epoch)
        *epoch = e;
    if (target_gen)
        *target_gen = t;
}

void
ff_reload_master_abort(void)
{
    uint32_t ag;

    if (g_reload_state == NULL)
        return;
    __atomic_store_n(&g_reload_state->reload_active, 0, __ATOMIC_SEQ_CST);
    /* C-NR-302: an aborted reload must give the hardware back to the
     * generation that is still active (H-12 — the markers are reversible). */
    ag = (uint32_t)ff_reload_active_gen();
    __atomic_store_n(&g_reload_state->reserved[4], g_reload_epoch,
        __ATOMIC_SEQ_CST);
    ff_reload_rx_owner_gen_set((int)ag);
    ff_reload_rx_stopped_set(0);
    /* M5: the directory is only reachable from a process with an EAL (the
     * master has none), so this is a best-effort publish for the callers
     * that do have one — the per-pass ff_reload_dir_sync() is the path that
     * normally keeps it in step. */
    ff_reload_gendir_active_set(g_reload_epoch, ag);
    ff_reload_gendir_kni_owner_set(g_reload_epoch, ag);
}

void
ff_reload_master_complete(void)
{
    uint32_t t;

    if (g_reload_state == NULL)
        return;

    t = __atomic_load_n(&g_reload_state->target_gen, __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_reload_state->active_gen, t, __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_reload_state->kni_owner_gen, t, __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_reload_state->reserved[5], g_reload_epoch,
        __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_reload_state->reserved[4], g_reload_epoch,
        __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_reload_state->reload_active, 0, __ATOMIC_SEQ_CST);
    /* C-NR-302: hardware ownership follows the active generation. */
    ff_reload_rx_owner_gen_set((int)t);
    ff_reload_rx_stopped_set(0);
    /* M5: see ff_reload_master_abort() — best-effort directory publish. */
    ff_reload_gendir_active_set(g_reload_epoch, t);
    ff_reload_gendir_kni_owner_set(g_reload_epoch, t);
}

void
ff_reload_publish_ready(unsigned int slot, uint32_t pid)
{
    uint64_t word;

#ifdef FF_RELOAD_FAULT_INJECTION
    /* RT-05 test hook: suppress or delay this worker's READY report. */
    if (ff_reload_fault_is("ready_never")) {
        return;
    }
    if (ff_reload_fault_is("ready_delay")) {
        ff_reload_fault_delay();
    }
#endif
    if (g_reload_state == NULL)
        return;
    if (slot >= FF_RELOAD_MAX_PROCS) {
        fprintf(stderr, "ff_reload: worker slot %u >= %d, READY dropped\n",
            slot, FF_RELOAD_MAX_PROCS);
        return;
    }

    word = ((uint64_t)__atomic_load_n(&g_reload_state->epoch,
        __ATOMIC_SEQ_CST) << 32) | (uint32_t)pid;
    __atomic_store_n(&g_reload_state->ready[slot], word, __ATOMIC_SEQ_CST);
}

uint64_t
ff_reload_ready_word(unsigned int slot)
{
    if (g_reload_state == NULL || slot >= FF_RELOAD_MAX_PROCS)
        return 0;
    return __atomic_load_n(&g_reload_state->ready[slot], __ATOMIC_SEQ_CST);
}

int
ff_reload_ready_matches(unsigned int slot, uint32_t pid, uint32_t epoch)
{
    uint64_t word;

    if (g_reload_state == NULL || slot >= FF_RELOAD_MAX_PROCS)
        return 0;

    word = __atomic_load_n(&g_reload_state->ready[slot], __ATOMIC_SEQ_CST);
    return word == (((uint64_t)epoch << 32) | (uint32_t)pid);
}

/* ---- FF_RELOAD message helpers ----------------------------------------- */

void
ff_reload_msg_fill(struct ff_msg *msg, int cmd, int gen, int status,
    uint64_t heartbeat)
{
    if (msg == NULL)
        return;

    memset(&msg->reload, 0, sizeof(msg->reload));
    msg->msg_type = FF_RELOAD;
    msg->result = 0;
    msg->reload.cmd = (uint32_t)cmd;
    msg->reload.gen = (uint32_t)gen;
    msg->reload.status = (uint32_t)status;
    msg->reload.active_gen = (uint32_t)ff_reload_active_gen();
    msg->reload.heartbeat = heartbeat;
    /* M5: report the epoch the active generation belongs to, so a tool
     * builds ring names for the master that is actually serving. */
    {
        uint32_t ae, ag;

        if (ff_reload_gendir_active(&ae, &ag) == 0 &&
            ae != FF_RELOAD_EPOCH_NONE) {
            /* epoch and gen must come from the same source: the directory
             * active word tracks the rx owner, the block's active_gen lags
             * it until T5, and mixing the two would name a ring nobody
             * dequeues. */
            msg->reload.epoch = ae;
            msg->reload.active_gen = ag;
        } else if (ff_reload_epoch() == 0) {
            /* This is the resident primary (or a stack without a
             * directory): no worker has mirrored an active generation yet,
             * so fall back to the newest live master epoch in the
             * directory rather than to our own epoch 0 / slot 0. */
            uint32_t pe;
            int pg;

            ff_reload_peer_coord(&pe, &pg);
            if (pe != ff_reload_epoch()) {
                /* epoch and gen from the same source, as above */
                msg->reload.epoch = pe;
                msg->reload.active_gen = (uint32_t)pg;
            } else {
                msg->reload.epoch = 0u;
            }
        } else {
            msg->reload.epoch = ff_reload_epoch();
        }
    }
}

int
ff_reload_msg_parse(const struct ff_msg *msg, int *cmd, int *gen,
    int *status, uint64_t *heartbeat)
{
    if (msg == NULL || msg->msg_type != FF_RELOAD)
        return -1;
    if (msg->reload.cmd < FF_RELOAD_CMD_READY ||
        msg->reload.cmd > FF_RELOAD_CMD_QUERY)
        return -1;

    if (cmd)
        *cmd = (int)msg->reload.cmd;
    if (gen)
        *gen = (int)msg->reload.gen;
    if (status)
        *status = (int)msg->reload.status;
    if (heartbeat)
        *heartbeat = msg->reload.heartbeat;
    return 0;
}

/* ---- main_loop hooks ---------------------------------------------------- */

void
ff_reload_heartbeat_set_timeout(uint64_t timeout_tsc)
{
    g_hb_timeout_tsc = timeout_tsc;
    g_hb_last_cnt = 0;
    g_hb_last_advance = 0;
    g_hb_inited = 1;
}

void
ff_reload_heartbeat_tick(void)
{
    if (g_reload_state == NULL)
        return;
    if (!__atomic_load_n(&g_reload_state->reload_active, __ATOMIC_SEQ_CST))
        return;
    if (g_reload_gen !=
        (int)__atomic_load_n(&g_reload_state->target_gen, __ATOMIC_SEQ_CST))
        return;

    __atomic_add_fetch(&g_reload_state->heartbeat, 1, __ATOMIC_SEQ_CST);
}

uint64_t
ff_reload_heartbeat_counter(void)
{
    if (g_reload_state == NULL)
        return 0;
    return __atomic_load_n(&g_reload_state->heartbeat, __ATOMIC_SEQ_CST);
}

int
ff_reload_heartbeat_sample(uint64_t cur_tsc)
{
    uint64_t cur_cnt;
    int alive;

    if (g_reload_state == NULL || !g_hb_inited)
        return 0;
    if (!__atomic_load_n(&g_reload_state->reload_active, __ATOMIC_SEQ_CST))
        return 0;
    if (g_reload_gen ==
        (int)__atomic_load_n(&g_reload_state->target_gen, __ATOMIC_SEQ_CST))
        return 0;

    if (!g_hb_last_advance)
        g_hb_last_advance = cur_tsc;

    cur_cnt = __atomic_load_n(&g_reload_state->heartbeat, __ATOMIC_SEQ_CST);
    alive = ff_reload_heartbeat_eval(g_hb_last_cnt, cur_cnt, cur_tsc,
        &g_hb_last_advance, g_hb_timeout_tsc);
    g_hb_last_cnt = cur_cnt;

    if (alive)
        return 0;

    /* stalled episode: count once and rebase so the next report only comes
     * after another full timeout if the owner is still dead.
     * Rx return to G_old (DR6-1) is wired in M3/M4 (C-NR-309/316):
     * under M2 G_old still owns rx, so detection is observability only. */
    __atomic_add_fetch(&g_reload_state->heartbeat_stalls, 1,
        __ATOMIC_SEQ_CST);
    g_hb_last_advance = cur_tsc;
    return 1;
}
