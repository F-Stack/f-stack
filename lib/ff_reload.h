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

#ifndef _FF_RELOAD_H_
#define _FF_RELOAD_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* C-NR-313/C-NR-316: shared reload control block.
 *
 * The block is created by the nginx master as an anonymous MAP_SHARED
 * mapping before any child is forked; the resident slim primary and every
 * worker inherit it through fork(), so no name lookup is needed. Apps not
 * driven by the nginx master (examples, tools) simply never attach and all
 * graceful extras degrade to no-ops.
 *
 * All fields written by one process and read by another MUST be accessed
 * through the __atomic helpers below (__ATOMIC_SEQ_CST), never plain
 * volatile reads (cross-process, potentially cross-core). */

#define FF_RELOAD_STATE_MAGIC       0x46524C4DU  /* "FRLM" */
#define FF_RELOAD_STATE_VERSION     1U

/* generation count: gen0/gen1 ping-pong across reload rounds. Must stay in
 * sync with FF_MBUF_GEN_MAX (compile-checked in ff_dpdk_if.c). */
#define FF_RELOAD_GEN_MAX           2

/* ready[] slots; sized to cover nginx NGX_MAX_PROCESSES. */
#define FF_RELOAD_MAX_PROCS         128

/* Heartbeat stall threshold default (ms). timeout==0 disables stall
 * detection, but it is NOT expressible through the config: ff_config.c
 * remaps 0 and negative values to this default (P3-1/P3-5). */
#define FF_RELOAD_HEARTBEAT_TIMEOUT_MS_DEFAULT  1000U

struct ff_reload_state {
    uint32_t magic;
    uint32_t version;
    uint32_t len;               /* sizeof(struct ff_reload_state) */
    uint32_t epoch;             /* bumped by the master per reload attempt */

    uint32_t active_gen;        /* generation currently serving traffic */
    uint32_t target_gen;        /* generation being spawned (reload window) */
    uint32_t reload_active;     /* 1 during T1..T5, 0 in steady state */
    uint32_t kni_owner_gen;     /* KNI runtime-owner generation (== active) */

    uint64_t heartbeat;         /* per-loop increment by the rx-owner gen */
    uint64_t heartbeat_stalls;  /* sampling-side detected stalls */

    /* per-worker-slot READY word: (epoch << 32) | pid, written by the
     * worker after ff stack + listening sockets are up. */
    uint64_t ready[FF_RELOAD_MAX_PROCS];

    /* Reserved for C-NR-302 (rx handover mutex, DR4: same shared block). */
    uint32_t rx_owner_gen;
    uint32_t rx_stopped;

    /* master FSM state mirrored for observability (reported by the
     * FF_RELOAD msg handler running in any worker). */
    uint32_t fsm_state;

    uint32_t reserved[7];
};

struct ff_msg;

/* ---- pure helpers (no global state; unit-testable) --------------------- */

/* Validate a candidate block created elsewhere (magic/version/len). */
int ff_reload_state_valid(const void *block, size_t len);

/* msg ring name for a (proc_id, generation) pair.
 * graceful=0 reproduces the legacy names byte-for-byte:
 *   msg_type < 0 : "<base><proc_id>"
 *   msg_type >= 0: "<base><proc_id>_<msg_type>"
 * graceful=1 appends "_g<gen>" so two generations with the same proc_id
 * never share an SC ring (C-NR-313, P0-6).
 * Returns 0 on success, -1 on truncation. */
int ff_reload_msg_ring_name(char *buf, unsigned int buflen,
    const char *base, unsigned int proc_id, int msg_type, int gen,
    int graceful);

/* Heartbeat liveness evaluation (C-NR-316, DR6-1).
 * The sampler keeps (last_cnt, last_advance). Each call:
 *  - counter advanced            -> refresh both, return 1 (alive)
 *  - not advanced and
 *      now - last_advance < timeout -> return 1 (alive, within window)
 *      now - last_advance >= timeout -> return 0 (stalled)
 *  - timeout == 0 disables the check (always alive).
 * Returns -1 on invalid arguments (NULL last_advance). */
int ff_reload_heartbeat_eval(uint64_t prev_cnt, uint64_t cur_cnt,
    uint64_t now, uint64_t *last_advance, uint64_t timeout);

/* ---- lifecycle / generation -------------------------------------------- */

/* Attach the inherited shared block (validated; invalid block is ignored). */
void ff_reload_attach_state(void *block);
int  ff_reload_state_attached(void);

/* Generation of this process; set before ff_init by the app (nginx worker)
 * so init_msg_ring / app mempool selection pick the right generation.
 * Out-of-range values are ignored; default 0. */
void ff_reload_set_gen(int gen);
int  ff_reload_gen(void);

/* Views of the attached block; all 0 / -1 when not attached. */
int  ff_reload_active_gen(void);
int  ff_reload_target_gen(void);
int  ff_reload_kni_owner_gen(void);
int  ff_reload_worker_gen(void);   /* reload_active ? target : active */

/* ENV-1 (C-NR-201): 1 while the reload window is active — RSS / MQ /
 * dev_configure renegotiation must be refused in that case. */
int  ff_reload_hw_locked(void);

/* ---- master-side orchestration helpers (nginx master only) ------------- */

/* Open the reload window: bump epoch, target = active ^ 1, reload_active=1. */
void ff_reload_master_begin(uint32_t *epoch, uint32_t *target_gen);
/* Close the window without flipping generations (reload aborted). */
void ff_reload_master_abort(void);
/* Close the window flipping active = target (and KNI owner follows active). */
void ff_reload_master_complete(void);

/* READY bookkeeping (workers publish, master correlates slot+pid+epoch). */
void     ff_reload_publish_ready(unsigned int slot, uint32_t pid);
uint64_t ff_reload_ready_word(unsigned int slot);
int      ff_reload_ready_matches(unsigned int slot, uint32_t pid,
             uint32_t epoch);

/* ---- FF_RELOAD message helpers (C-NR-202, transported over msg_ring) --- */

void ff_reload_msg_fill(struct ff_msg *msg, int cmd, int gen, int status,
    uint64_t heartbeat);
int  ff_reload_msg_parse(const struct ff_msg *msg, int *cmd, int *gen,
    int *status, uint64_t *heartbeat);

/* ---- main_loop hooks (C-NR-316; called from ff_dpdk_if.c) -------------- */

/* Set the heartbeat timeout in TSC (computed by the caller, which owns
 * rte_get_tsc_hz; kept out of this TU so it links without DPDK libs). */
void ff_reload_heartbeat_set_timeout(uint64_t timeout_tsc);
/* rx-owner generation increments once per loop pass. */
void ff_reload_heartbeat_tick(void);
/* Current heartbeat counter value (0 when not attached). */
uint64_t ff_reload_heartbeat_counter(void);
/* Non-owner generation samples; returns 1 when a stall episode is detected
 * (caller logs), 0 otherwise. Increments heartbeat_stalls on detection and
 * rebases the window so one episode reports once. */
int  ff_reload_heartbeat_sample(uint64_t cur_tsc);

#ifdef __cplusplus
}
#endif

#endif /* _FF_RELOAD_H_ */
