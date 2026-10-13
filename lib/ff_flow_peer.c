/*
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

/*
 * One table per (proc_id, epoch slot, gen), in a memzone the worker of that
 * coordinate reserves at attach. Single writer (the worker of that
 * coordinate, recording all the time), single reader (the new generation's
 * worker of the same proc_id, while the writer drains). Entries are never
 * cleared after attach: a reader stops a probe at an unused slot, and the
 * writer only reuses an idle one (last_ms before fp).
 */

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_memzone.h>

#include "ff_api.h"
#include "ff_config.h"
#include "ff_flow_map.h"
#include "ff_flow_peer.h"
#include "ff_log.h"
#include "ff_reload.h"

#define FP_MAGIC        FF_FLOW_PEER_MAGIC
#define FP_NONE         FF_FLOW_PEER_NONE
#define FP_PUBLISHING   FF_FLOW_PEER_PUBLISHING
#define FP_HANDED       FF_FLOW_PEER_HANDED
#define FP_MODE_HUP     FF_FLOW_PEER_MODE_HUP
#define FP_MODE_USR2    FF_FLOW_PEER_MODE_USR2

static int      g_on;
static uint32_t g_now;
static uint32_t g_idle = FF_RELOAD_UDP_IDLE_MS_DEFAULT;
static void   (*g_snap_fn)(void);

/* writer */
static struct ff_flow_peer_tab *g_own;
static int      g_rec;
static int      g_pub;
static uint64_t g_noted;
static uint64_t g_full;
static int      g_stopped;
static uint32_t g_pub_mode;
static uint64_t g_pub_wid;
static uint32_t g_active;
static uint32_t g_active_ms;

/* reader */
static struct ff_flow_peer_tab *g_rd;
static int      g_rd_armed;
static int      g_rd_dead;
static uint32_t g_rd_e = FF_RELOAD_EPOCH_NONE;
static int      g_rd_g = -1;
static uint32_t g_rd_mode;
static uint64_t g_rd_wid;
static uint32_t g_rd_retry_ms;
static uint64_t g_rd_cnt[4];

static uint32_t
fp_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return g_now;
    return (uint32_t)((uint64_t)ts.tv_sec * 1000u + ts.tv_nsec / 1000000);
}

static int
fp_aged(uint32_t now, uint32_t last, uint32_t idle)
{
    return (int32_t)(now - last) > (int32_t)idle;
}

uint64_t
ff_flow_peer_fp(const struct ff_flow_key *key)
{
    uint32_t w[sizeof(*key) / 4];
    uint64_t h = 0x9e3779b97f4a7c15ull;
    unsigned i;

    memcpy(w, key, sizeof(w));
    for (i = 0; i < sizeof(w) / 4; i++) {
        h = (h ^ w[i]) * 0xff51afd7ed558ccdull;
        h ^= h >> 29;
    }
    h *= 0xc4ceb9fe1a85ec53ull;
    h ^= h >> 32;
    return h ? h : 1;
}

int
ff_flow_peer_tab_note(struct ff_flow_peer_ent *t, uint32_t cap, uint64_t fp,
    uint32_t now, uint32_t idle)
{
    struct ff_flow_peer_ent *e, *cand = NULL;
    uint64_t f;
    uint32_t i;

    for (i = 0; i < FF_FLOW_PEER_PROBE; i++) {
        e = &t[(fp + i) & (cap - 1)];
        f = __atomic_load_n(&e->fp, __ATOMIC_RELAXED);
        if (f == fp) {
            if (__atomic_load_n(&e->last_ms, __ATOMIC_RELAXED) != now)
                __atomic_store_n(&e->last_ms, now, __ATOMIC_RELAXED);
            return 1;
        }
        if (f == 0) {
            if (cand == NULL)
                cand = e;
            break;
        }
        if (cand == NULL
            && fp_aged(now, __atomic_load_n(&e->last_ms, __ATOMIC_RELAXED),
                idle))
            cand = e;
    }
    if (cand == NULL)
        return -1;
    __atomic_store_n(&cand->last_ms, now, __ATOMIC_RELAXED);
    __atomic_store_n(&cand->fp, fp, __ATOMIC_RELEASE);
    return 0;
}

int
ff_flow_peer_tab_find(const struct ff_flow_peer_ent *t, uint32_t cap,
    uint64_t fp, uint32_t now, uint32_t idle)
{
    const struct ff_flow_peer_ent *e;
    uint64_t f;
    uint32_t i;

    for (i = 0; i < FF_FLOW_PEER_PROBE; i++) {
        e = &t[(fp + i) & (cap - 1)];
        f = __atomic_load_n(&e->fp, __ATOMIC_ACQUIRE);
        if (f == 0)
            break;
        if (f == fp)
            return fp_aged(now,
                __atomic_load_n(&e->last_ms, __ATOMIC_RELAXED), idle) ?
                FF_FLOW_PEER_TAB_AGED : FF_FLOW_PEER_TAB_LIVE;
    }
    return FF_FLOW_PEER_TAB_MISS;
}

uint32_t
ff_flow_peer_tab_active(const struct ff_flow_peer_ent *t, uint32_t cap,
    uint32_t now, uint32_t idle)
{
    uint32_t i, n = 0;

    for (i = 0; i < cap; i++)
        if (t[i].fp != 0 && !fp_aged(now, t[i].last_ms, idle))
            n++;
    return n;
}

/* wider than RTE_MEMZONE_NAMESIZE on purpose, checked before use */
static int
fp_name(char *buf, size_t len, unsigned slot, int gen)
{
    int n = snprintf(buf, len, "ff_fpeer_p%d_e%u_g%d",
        ff_global_cfg.dpdk.proc_id, slot, gen);

    return n > 0 && n < RTE_MEMZONE_NAMESIZE ? 0 : -1;
}

static int
fp_pid_dead(int32_t pid)
{
    return pid > 0 && kill((pid_t)pid, 0) != 0 && errno == ESRCH;
}

static void
fp_atexit(void)
{
    ff_flow_peer_stop();
}

void
ff_flow_peer_attach(void)
{
    const struct rte_memzone *mz = NULL;
    char name[64];

    if (!ff_global_cfg.dpdk.graceful_reload
        || rte_eal_process_type() != RTE_PROC_SECONDARY
        || ff_global_cfg.dpdk.proc_id < 0)
        return;
    if (ff_global_cfg.dpdk.reload_udp_idle_ms)
        g_idle = ff_global_cfg.dpdk.reload_udp_idle_ms;
    g_now = fp_now_ms();
    g_on = 1;

    if (fp_name(name, sizeof(name), ff_reload_epoch_slot(),
            ff_reload_gen()) == 0) {
        mz = rte_memzone_lookup(name);
        if (mz == NULL)
            mz = rte_memzone_reserve(name, sizeof(struct ff_flow_peer_tab),
                SOCKET_ID_ANY, 0);
        if (mz == NULL && rte_errno == EEXIST)
            mz = rte_memzone_lookup(name);
    }
    if (mz == NULL || mz->len < sizeof(struct ff_flow_peer_tab)) {
        ff_log(FF_LOG_WARNING, FF_LOGTYPE_FSTACK_LIB,
            "reload: UDP peer table %s unavailable, this generation will "
            "not publish its UDP flows\n", name);
        return;
    }
    g_own = mz->addr;
    if (g_own->h.magic == FP_MAGIC && g_own->h.pid != (int32_t)getpid()
        && __atomic_load_n(&g_own->h.state, __ATOMIC_ACQUIRE) != FP_HANDED
        && !fp_pid_dead(g_own->h.pid)) {
        ff_log(FF_LOG_WARNING, FF_LOGTYPE_FSTACK_LIB,
            "reload: UDP peer table %s still used by pid %d, this "
            "generation will not publish its UDP flows\n", name,
            (int)g_own->h.pid);
        g_own = NULL;
        return;
    }
    __atomic_store_n(&g_own->h.state, FP_NONE, __ATOMIC_RELEASE);
    memset(g_own->e, 0, sizeof(g_own->e));
    g_own->h.magic = FP_MAGIC;
    g_own->h.cap = FF_FLOW_PEER_CAP;
    g_own->h.pid = (int32_t)getpid();
    g_rec = 1;
    atexit(fp_atexit);
}

int
ff_flow_peer_recording(void)
{
    return g_rec;
}

void
ff_flow_peer_note(const struct ff_flow_key *key)
{
    if (!g_rec)
        return;
    if (ff_flow_peer_tab_note(g_own->e, FF_FLOW_PEER_CAP,
            ff_flow_peer_fp(key), g_now, g_idle) < 0)
        g_full++;
    else
        g_noted++;
}

void
ff_flow_peer_publish(const ff_flow_key_t *key)
{
    ff_flow_peer_note(key);
}

void
ff_flow_peer_snapshot_regist(void (*fn)(void))
{
    g_snap_fn = fn;
}

static void
fp_start(uint32_t mode, uint64_t wid)
{
    struct ff_flow_peer_hdr *h = &g_own->h;

    /* recorded flows stay: they are what this generation serves */
    __atomic_store_n(&h->state, FP_NONE, __ATOMIC_RELEASE);
    h->idle_ms = g_idle;
    h->mode = mode;
    h->wid = wid;
    h->pid = (int32_t)getpid();
    g_noted = 0;
    g_full = 0;
    __atomic_store_n(&h->state, FP_PUBLISHING, __ATOMIC_RELEASE);
    g_pub = 1;
    g_pub_mode = mode;
    g_pub_wid = wid;

    ff_udp_flow_peer_snapshot();
    if (g_snap_fn != NULL)
        g_snap_fn();
    g_active_ms = g_now - 1000;
    ff_log(FF_LOG_NOTICE, FF_LOGTYPE_FSTACK_LIB,
        "reload: publishing UDP flows (%s), %d in the snapshot\n",
        mode == FP_MODE_HUP ? "HUP" : "USR2", ff_flow_peer_active_flows());
}

void
ff_flow_peer_stop(void)
{
    g_rec = 0;
    g_stopped = 1;
    if (!g_pub)
        return;
    g_own->h.noted = g_noted;
    g_own->h.full = g_full;
    __atomic_store_n(&g_own->h.state, FP_HANDED, __ATOMIC_RELEASE);
    g_pub = 0;
    ff_log(FF_LOG_NOTICE, FF_LOGTYPE_FSTACK_LIB,
        "reload: UDP flows handed over (%lu noted, %lu not recorded)\n",
        (unsigned long)g_noted, (unsigned long)g_full);
}

/* a fresh count at most every 100 ms: the drain report must not see a
 * value from before the flows were noted */
int
ff_flow_peer_active_flows(void)
{
    if (!g_pub)
        return 0;
    if ((uint32_t)(g_now - g_active_ms) >= 100) {
        g_active = ff_flow_peer_tab_active(g_own->e, FF_FLOW_PEER_CAP,
            g_now, g_idle);
        g_active_ms = g_now;
    }
    return (int)g_active;
}

int
ff_flow_peer_linger(void)
{
    return g_pub && g_pub_mode == FP_MODE_USR2
        && !ff_reload_hw_locked() && ff_is_drain_generation()
        && ff_flow_peer_active_flows() > 0;
}

/* the window this process drains in, if any */
static uint32_t
fp_writer_window(uint64_t *wid)
{
    uint32_t pe, pg, own = ff_reload_epoch();

    if (ff_reload_hw_locked()) {
        if (ff_reload_gen() == ff_reload_target_gen())
            return 0;
        *wid = ((uint64_t)own << 32) | ff_reload_shared_epoch();
        return FP_MODE_HUP;
    }
    /* refreshed by this pass's directory sync, read by the master too */
    ff_reload_peer_block(&pe, &pg);
    if (pe == 0 || pe == FF_RELOAD_EPOCH_NONE || pe <= own)
        return 0;
    *wid = ((uint64_t)pe << 32) | own;
    return FP_MODE_USR2;
}

static void
fp_writer_tick(void)
{
    uint64_t wid = 0;
    uint32_t mode;
    int owner;

    if (g_own == NULL || g_stopped)
        return;
    mode = fp_writer_window(&wid);
    if (!g_pub) {
        /* a park order alone does not hand rx over: start until the flip */
        owner = ff_reload_rx_owner_gen();
        if (mode != 0 && ff_reload_slot() >= 0
            && (owner < 0 || owner == ff_reload_gen()))
            fp_start(mode, wid);
        return;
    }
    if ((mode != g_pub_mode || wid != g_pub_wid) && !ff_is_drain_generation()) {
        /* the round was given up and rx stayed here */
        __atomic_store_n(&g_own->h.state, FP_NONE, __ATOMIC_RELEASE);
        g_pub = 0;
        ff_log(FF_LOG_NOTICE, FF_LOGTYPE_FSTACK_LIB,
            "reload: UDP flow publishing withdrawn (round abandoned)\n");
    }
}

static void
fp_reader_tick(void)
{
    const struct rte_memzone *mz;
    char name[64];
    uint32_t e, ug, own = ff_reload_epoch();
    int g, armed;

    armed = ff_reload_state_attached()
        && ff_reload_gen() == ff_reload_target_gen()
        && (ff_reload_hw_locked() || ff_reload_peer_mirror_draining());
    if (!armed) {
        if (g_rd_armed && (g_rd_cnt[0] | g_rd_cnt[1] | g_rd_cnt[2]
                | g_rd_cnt[3]))
            ff_log(FF_LOG_NOTICE, FF_LOGTYPE_FSTACK_LIB,
                "reload: UDP dispatch: %lu forwarded, %lu kept, %lu taken "
                "over, %lu without a peer table\n",
                (unsigned long)g_rd_cnt[FF_FLOW_PEER_FWD],
                (unsigned long)g_rd_cnt[FF_FLOW_PEER_LOCAL],
                (unsigned long)g_rd_cnt[FF_FLOW_PEER_LEARN],
                (unsigned long)g_rd_cnt[FF_FLOW_PEER_LEGACY]);
        memset(g_rd_cnt, 0, sizeof(g_rd_cnt));
        g_rd_armed = 0;
        g_rd = NULL;
        g_rd_e = FF_RELOAD_EPOCH_NONE;
        return;
    }
    g_rd_armed = 1;

    if (ff_reload_hw_locked()) {
        ff_reload_peer_coord(&e, &g);
        g_rd_mode = FP_MODE_HUP;
        g_rd_wid = ((uint64_t)own << 32) | ff_reload_shared_epoch();
    } else {
        ff_reload_peer_block(&e, &ug);
        g = (int)ug;
        g_rd_mode = FP_MODE_USR2;
        g_rd_wid = ((uint64_t)own << 32) | e;
    }
    if (e != g_rd_e || g != g_rd_g) {
        g_rd_e = e;
        g_rd_g = g;
        g_rd = NULL;
        g_rd_retry_ms = g_now;
    }
    if ((int32_t)(g_now - g_rd_retry_ms) < 0)
        return;
    g_rd_retry_ms = g_now + 1000;

    if (g_rd == NULL && g >= 0 && g < FF_RELOAD_GEN_MAX
        && fp_name(name, sizeof(name), ff_reload_epoch_slot_of(e), g) == 0) {
        mz = rte_memzone_lookup(name);
        if (mz != NULL && mz->len >= sizeof(struct ff_flow_peer_tab)
            && ((struct ff_flow_peer_tab *)mz->addr)->h.magic == FP_MAGIC)
            g_rd = mz->addr;
    }
    if (g_rd != NULL)
        g_rd_dead = fp_pid_dead(g_rd->h.pid);
}

void
ff_flow_peer_tick(void)
{
    if (!g_on)
        return;
    g_now = fp_now_ms();
    fp_writer_tick();
    fp_reader_tick();
}

int
ff_flow_peer_classify(const ff_flow_key_t *key)
{
    struct ff_flow_peer_tab *t = g_rd;
    uint32_t st;
    int r;

    if (t == NULL) {
        r = FF_FLOW_PEER_LEGACY;
        goto out;
    }
    st = __atomic_load_n(&t->h.state, __ATOMIC_ACQUIRE);
    if (st == FP_NONE || t->h.wid != g_rd_wid || t->h.mode != g_rd_mode) {
        r = FF_FLOW_PEER_LEGACY;
        goto out;
    }
    if (st != FP_PUBLISHING || g_rd_dead) {
        r = FF_FLOW_PEER_LOCAL;
        goto out;
    }
    switch (ff_flow_peer_tab_find(t->e, FF_FLOW_PEER_CAP,
        ff_flow_peer_fp(key), g_now, t->h.idle_ms)) {
    case FF_FLOW_PEER_TAB_LIVE:
        r = FF_FLOW_PEER_FWD;
        break;
    case FF_FLOW_PEER_TAB_AGED:
        r = FF_FLOW_PEER_LEARN;
        break;
    default:
        r = FF_FLOW_PEER_LOCAL;
        break;
    }
out:
    g_rd_cnt[r]++;
    return r;
}
