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

/* M5: cross-master generation directory — DPDK half.
 *
 * The resident slim primary is the only F-Stack process that survives an
 * nginx USR2 exec, so it owns the directory (a hugepage memzone) and every
 * secondary looks it up: the same "primary creates / secondary looks up"
 * shape ff_dpdk_if.c already uses for ff_nb_dev_ports.
 *
 * Everything that only touches the directory CONTENT lives in ff_reload.c
 * instead: that object must stay linkable without DPDK (ff_config unit
 * tests and the compat tools link it on its own), so this translation unit
 * is limited to reserving/looking up the memzone and to epoch bookkeeping.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#include <rte_eal.h>
#include <rte_memzone.h>

#include "ff_reload.h"
#include "ff_config.h"
#include "ff_log.h"

static struct ff_reload_gendir *g_dir;
static int g_dir_slot = -1;     /* this process's slot in the directory */
static uint32_t g_dir_epoch;    /* full epoch of that slot */
/* 1 when this process displaced a dead master from its slot: the rings of
 * that slot still hold the previous owner's messages/mbufs. */
static int g_dir_reset_pending;

static uint64_t
gendir_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static uint64_t
pack_coord(uint32_t epoch, uint32_t gen)
{
    return ((uint64_t)epoch << 32) | (uint64_t)gen;
}

static int
pid_alive(uint32_t pid)
{
    if (pid == 0)
        return 0;
    /* A zombie still answers kill(0), but by then nginx has already reaped
     * its master; treat "exists" as live. */
    return kill((pid_t)pid, 0) == 0 || errno == EPERM;
}

int
ff_reload_gendir_present(void)
{
    return g_dir != NULL;
}

void
ff_reload_gendir_detach(void)
{
    ff_reload_gendir_retire();
    g_dir = NULL;
    g_dir_slot = -1;
    g_dir_epoch = 0;
    ff_reload_set_epoch(0);
    ff_reload_gendir_install(NULL, 0);
}

/* Claim a free slot for 'pid'. Slot 0 belongs to the resident primary, so
 * masters cycle through 1..SLOT_MAX-1 and a slot whose master pid is gone
 * is recycled — that is what keeps an USR2 chain from leaking one ring set
 * per round (DPDK never frees a memzone on process exit). Liveness is the
 * pid alone, the same authority epoch_live() uses: an nginx master has no
 * EAL and can never retire its own slot, so a dead master's state stays
 * LIVE forever and a state-based gate would never recycle it. master_pid
 * is the CAS gate and is published last, after the slot content is in
 * place. */
static int
slot_acquire(struct ff_reload_gendir *d, uint32_t epoch, uint32_t pid,
    int gen, int is_primary, unsigned *slot_out)
{
    unsigned i, start;

    if (is_primary) {
        i = 0;
    } else {
        start = ff_reload_epoch_slot_of(epoch);
        if (start == 0)
            start = 1;
        i = start;
    }

    for (;;) {
        struct ff_reload_epoch_slot *s = &d->slot[i];
        uint32_t owner = __atomic_load_n(&s->master_pid, __ATOMIC_SEQ_CST);
        uint32_t expect = owner;

        if (owner == 0 || !pid_alive(owner)) {
            if (__atomic_compare_exchange_n(&s->master_pid, &expect, pid,
                    0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
                /* Recycled slot: whatever the previous owner left in these
                 * rings is garbage for us. Only the CAS winner gets here,
                 * so exactly one process performs the drain. */
                if (owner != 0)
                    g_dir_reset_pending = 1;
                __atomic_store_n(&s->epoch, epoch, __ATOMIC_SEQ_CST);
                __atomic_store_n(&s->gen, (uint32_t)gen, __ATOMIC_SEQ_CST);
                __atomic_store_n(&s->flags,
                    is_primary ? FF_RELOAD_SLOT_PRIMARY : 0u,
                    __ATOMIC_SEQ_CST);
                __atomic_store_n(&s->since_ms, gendir_now_ms(),
                    __ATOMIC_SEQ_CST);
                __atomic_store_n(&s->state, FF_RELOAD_SLOT_LIVE,
                    __ATOMIC_SEQ_CST);
                if (slot_out)
                    *slot_out = i;
                return 0;
            }
        }

        if (is_primary)
            return -1;
        i++;
        if (i >= FF_RELOAD_EPOCH_SLOT_MAX)
            i = 1;
        if (i == start)
            return -1;
    }
}

/* Register this process's master epoch. Workers key on getppid() (the nginx
 * master); the resident primary is reparented to init by its double fork,
 * so it keys on its own pid and always takes slot 0 / epoch 0. */
static void
gendir_register_self(struct ff_reload_gendir *d)
{
    int is_primary = rte_eal_process_type() == RTE_PROC_PRIMARY;
    uint32_t pid;
    unsigned i;

    if (is_primary) {
        pid = (uint32_t)getpid();
        __atomic_store_n(&d->primary_pid, pid, __ATOMIC_SEQ_CST);
    } else {
        pid = (uint32_t)getppid();
    }

    for (i = 0; i < FF_RELOAD_EPOCH_SLOT_MAX; i++) {
        struct ff_reload_epoch_slot *s = &d->slot[i];

        if (__atomic_load_n(&s->master_pid, __ATOMIC_SEQ_CST) != pid)
            continue;

        __atomic_store_n(&s->gen, (uint32_t)ff_reload_gen(),
            __ATOMIC_SEQ_CST);
        if (is_primary) {
            __atomic_store_n(&s->epoch, 0u, __ATOMIC_SEQ_CST);
            __atomic_store_n(&s->flags, FF_RELOAD_SLOT_PRIMARY,
                __ATOMIC_SEQ_CST);
        }
        __atomic_store_n(&s->state, FF_RELOAD_SLOT_LIVE, __ATOMIC_SEQ_CST);
        g_dir_slot = (int)i;
        g_dir_epoch = __atomic_load_n(&s->epoch, __ATOMIC_SEQ_CST);
        ff_reload_set_epoch(g_dir_epoch);
        return;
    }

    {
        uint32_t epoch;
        unsigned slot = 0;

        epoch = is_primary ? 0u
            : __atomic_add_fetch(&d->next_epoch, 1, __ATOMIC_SEQ_CST);
        if (slot_acquire(d, epoch, pid, ff_reload_gen(), is_primary,
                &slot) != 0) {
            ff_log(FF_LOG_ERR, FF_LOGTYPE_FSTACK_LIB,
                "generation directory: no free epoch slot for pid %u, "
                "keeping the pre-M5 identity\n", pid);
            g_dir_slot = 0;
            g_dir_epoch = 0;
            ff_reload_set_epoch(0);
            return;
        }
        g_dir_slot = (int)slot;
        g_dir_epoch = epoch;
        ff_reload_set_epoch(epoch);
    }
}

void
ff_reload_gendir_attach(void)
{
    const struct rte_memzone *mz;
    struct ff_reload_gendir *d;

    if (!ff_global_cfg.dpdk.graceful_reload)
        return;
    if (g_dir != NULL)
        return;

    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        mz = rte_memzone_reserve(FF_RELOAD_GENDIR_NAME,
            sizeof(struct ff_reload_gendir), SOCKET_ID_ANY, 0);
        if (mz == NULL) {
            /* Already there (a previous init in this process, or a
             * re-attached primary): reuse it instead of failing. */
            mz = rte_memzone_lookup(FF_RELOAD_GENDIR_NAME);
        }
    } else {
        mz = rte_memzone_lookup(FF_RELOAD_GENDIR_NAME);
    }
    if (mz == NULL) {
        ff_log(FF_LOG_WARNING, FF_LOGTYPE_FSTACK_LIB,
            "generation directory unavailable, cross-master epoch "
            "isolation disabled\n");
        return;
    }

    d = (struct ff_reload_gendir *)mz->addr;
    if (rte_eal_process_type() == RTE_PROC_PRIMARY &&
        d->magic != FF_RELOAD_GENDIR_MAGIC) {
        memset(d, 0, sizeof(*d));
        d->magic = FF_RELOAD_GENDIR_MAGIC;
        d->version = FF_RELOAD_GENDIR_VERSION;
        d->len = (uint32_t)sizeof(*d);
        d->slot_max = FF_RELOAD_EPOCH_SLOT_MAX;
        d->gen_max = FF_RELOAD_GEN_MAX;
        d->next_epoch = 1;
        d->active_word = pack_coord(FF_RELOAD_EPOCH_NONE, 0);
        d->rx_owner_word = pack_coord(FF_RELOAD_EPOCH_NONE, 0);
        d->kni_owner_word = pack_coord(FF_RELOAD_EPOCH_NONE, 0);
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
    }

    if (ff_reload_gendir_install(d, sizeof(*d)) != 0)
        return;
    g_dir = d;
    gendir_register_self(g_dir);
    /* Only a secondary ever owns a queue, so only a secondary may publish
     * an ownership claim — otherwise the resident primary (epoch 0) would
     * win the initial claim against the workers of the first master. */
    ff_reload_dir_sync_enable(rte_eal_process_type() == RTE_PROC_SECONDARY);
    ff_log(FF_LOG_INFO, FF_LOGTYPE_FSTACK_LIB,
        "generation directory attached: epoch %u slot %u pid %u\n",
        g_dir_epoch, (unsigned)(g_dir_slot < 0 ? 0 : g_dir_slot),
        (unsigned)getpid());
}

int
ff_reload_gendir_epoch_live(uint32_t epoch)
{
    struct ff_reload_gendir *d = g_dir;
    unsigned i;

    if (d == NULL || epoch == FF_RELOAD_EPOCH_NONE)
        return 0;
    for (i = 0; i < FF_RELOAD_EPOCH_SLOT_MAX; i++) {
        if (__atomic_load_n(&d->slot[i].epoch, __ATOMIC_SEQ_CST) != epoch)
            continue;
        if (__atomic_load_n(&d->slot[i].state, __ATOMIC_SEQ_CST)
            != FF_RELOAD_SLOT_LIVE)
            return 0;
        return pid_alive(__atomic_load_n(&d->slot[i].master_pid,
            __ATOMIC_SEQ_CST));
    }
    return 0;
}

int
ff_reload_gendir_mint(uint32_t *epoch, unsigned *slot, int gen, uint32_t pid)
{
    struct ff_reload_gendir *d = g_dir;
    uint32_t e;

    if (d == NULL)
        return -1;
    e = __atomic_add_fetch(&d->next_epoch, 1, __ATOMIC_SEQ_CST);
    if (slot_acquire(d, e, pid, gen, 0, slot) != 0)
        return -1;
    if (epoch)
        *epoch = e;
    return 0;
}

int
ff_reload_gendir_reset_pending(void)
{
    int pending = g_dir_reset_pending;

    g_dir_reset_pending = 0;
    return pending;
}

void
ff_reload_gendir_retire(void)
{
    struct ff_reload_gendir *d = g_dir;
    uint32_t owner;

    if (d == NULL || g_dir_slot < 0)
        return;
    /* A worker exits on every reload round while its master stays up; only
     * the process that registered the slot under its own pid (the resident
     * primary) or the last one of a dead master may release it. */
    owner = __atomic_load_n(&d->slot[g_dir_slot].master_pid,
        __ATOMIC_SEQ_CST);
    if (owner != (uint32_t)getpid() && pid_alive(owner))
        return;
    __atomic_store_n(&d->slot[g_dir_slot].state, FF_RELOAD_SLOT_DEAD,
        __ATOMIC_SEQ_CST);
    g_dir_slot = -1;
}
