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

/* M5: master-epoch identity.
 *
 * reload_active/target/kni_owner live in the master's ANONYMOUS block, so
 * two masters (USR2) each hold a private copy and every per-proc_id name
 * space they share collides. The epoch is minted from the generation
 * directory below (a hugepage memzone owned by the resident primary, i.e.
 * the only entity that survives exec) and is inherited by fork() exactly
 * like the generation, so every process of one master agrees on it.
 *
 * Ring names carry the epoch SLOT, not the monotonic epoch: a ring name is
 * capped at 28 bytes (RTE_RING_NAMESIZE-1) and a uint32 epoch would not
 * fit. Slot 0 is the directory-less / primary identity (names stay exactly
 * as they were before M5), slots 1..SLOT_MAX-1 are handed to masters. */
#define FF_RELOAD_EPOCH_SLOT_MAX    4
#define FF_RELOAD_EPOCH_NONE        0xFFFFFFFFu

#define FF_RELOAD_SLOT_FREE         0
#define FF_RELOAD_SLOT_LIVE         1
#define FF_RELOAD_SLOT_DEAD         2
#define FF_RELOAD_SLOT_PRIMARY      0x1u   /* slot flags: resident primary */

#define FF_RELOAD_GENDIR_MAGIC      0x46524744U   /* "FRGD" */
#define FF_RELOAD_GENDIR_VERSION    1U
#define FF_RELOAD_GENDIR_NAME       "ff_reload_gendir"

/* F-M5-1 (USR2): a slot whose master pid is gone still counts as a drain
 * counterpart while its workers refresh the slot stamp at least this
 * often. Covers the window between "old master quit" and "last old worker
 * exited" — an nginx worker leaves with exit(0) and cannot run any
 * teardown, so the stamp going stale IS the death notice. */
#define FF_RELOAD_SLOT_STALE_MS     2000U

/* Heartbeat stall threshold default (ms). timeout==0 disables stall
 * detection, but it is NOT expressible through the config: ff_config.c
 * remaps 0 and negative values to this default (P3-1/P3-5). */
#define FF_RELOAD_HEARTBEAT_TIMEOUT_MS_DEFAULT  1000U

/* C-NR-302: how long the acquiring generation waits for the current rx owner
 * to park before the handover is declared failed (ms). Calibrated by RV3. */
#define FF_RELOAD_HANDOVER_TIMEOUT_MS_DEFAULT   100U

/* ff_queue_handover_mutex() results. Deliberately not errno values: the
 * function is also called from contexts that do not want to touch errno. */
#define FF_RELOAD_HANDOVER_OK        0
#define FF_RELOAD_HANDOVER_INVAL   (-1)  /* bad args / no shared block */
#define FF_RELOAD_HANDOVER_BUSY    (-2)  /* a third generation owns rx */
#define FF_RELOAD_HANDOVER_TIMEOUT (-3)  /* owner never parked in time */

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

    /* C-NR-306 (M3 Batch B): T2 park barrier. The master arms a fresh
     * handover epoch and orders the owner generation to park
     * (rx_stopped=1); each of its workers acks with (epoch << 32) | 1
     * from the main loop pass that will skip rx/tx. Only after every
     * live old-generation slot has acked does the master flip
     * rx_owner_gen — that is what rules out an in-flight rx_burst racing
     * the new owner. Epoch-tagging makes stale acks from an aborted
     * round harmless without any clearing pass. */
    uint32_t handover_epoch;
    uint64_t rx_parked[FF_RELOAD_MAX_PROCS];

    /* M4 (C-NR-402/403/406) reserved-word assignment:
     *   reserved[0..1]: pointer to the drain extension block below,
     *                   written once by the master before any fork
     *   reserved[2]:    handover duration ms (T2 park -> owner flip)
     *   reserved[3]:    drain duration ms (T3 entry -> DRAIN_DONE)
     *   reserved[4]:    M5: rx_owner epoch (pair of rx_owner_gen below)
     *   reserved[5]:    M5: kni_owner epoch (pair of kni_owner_gen above)
     *   reserved[6]:    spare
     * Accessed only through the helpers below, never directly. */
    uint32_t reserved[7];

    /* M5: newest live (epoch, gen) OTHER than this master's, mirrored from
     * the generation directory by the workers. The master has no EAL and
     * cannot read the directory, so this is how it learns the coordinate it
     * must hand the hardware over to (and the one RT-04b reclaims from).
     * FF_RELOAD_EPOCH_NONE when there is no peer. */
    uint32_t peer_epoch;
    uint32_t peer_gen;
    uint32_t _pad[2];
};

/* M5: cross-master generation directory.
 *
 * A hugepage memzone created by the resident slim primary (the only process
 * that survives an nginx USR2 exec) and looked up by every secondary. It is
 * the single authority for three things the per-master anonymous block
 * cannot express:
 *   1. the epoch -> slot mapping (ring-name coordinate of every master),
 *   2. the one live hardware/KNI owner coordinate (rx_owner / kni_owner),
 *   3. liveness of every registered master epoch (ring recycling).
 *
 * grace_reload=0 (or no resident primary) => no directory at all and every
 * consumer keeps its pre-M5 behaviour.
 *
 * Owner coordinates are packed into one 64-bit word ((epoch << 32) | gen)
 * so a transfer is a single CAS: two masters must never both match. */
struct ff_reload_epoch_slot {
    uint32_t epoch;        /* monotonic epoch owning this slot */
    uint32_t gen;          /* last generation registered by that master */
    uint32_t master_pid;   /* 0 == unused; CAS gate for registration */
    uint32_t state;        /* FF_RELOAD_SLOT_* */
    uint32_t flags;        /* FF_RELOAD_SLOT_PRIMARY for the resident primary */
    uint32_t pad;          /* F-M5-1: liveness stamp, low 32 bits of
                            * CLOCK_MONOTONIC ms; workers refresh it once
                            * per main-loop pass (throttled), so a dead
                            * master's still-draining workers keep the slot
                            * alive. Wrap-safe by unsigned delta. */
    uint64_t since_ms;
};

struct ff_reload_gendir {
    uint32_t magic;
    uint32_t version;
    uint32_t len;
    uint32_t slot_max;
    uint32_t gen_max;
    uint32_t primary_pid;
    uint32_t next_epoch;
    uint32_t pad0;
    uint64_t _rsv0[4];

    /* one cache line: the arbitration words */
    uint64_t active_word;      /* (epoch << 32) | gen serving traffic */
    uint64_t rx_owner_word;    /* (epoch << 32) | gen owning rx/tx */
    uint64_t kni_owner_word;   /* (epoch << 32) | gen owning KNI runtime */
    uint32_t rx_stopped;
    uint32_t pad1;
    uint64_t _rsv1[3];

    struct ff_reload_epoch_slot slot[FF_RELOAD_EPOCH_SLOT_MAX];
};

/* Drain reporting extension (M4: C-NR-402/403/406): a second anonymous
 * MAP_SHARED block created by the master right after the main block, so
 * every child inherits both the mapping and the lib-side pointer through
 * fork(). Carries the per-worker drain progress the master polls during
 * T3 (D-M4-1: shared words, not msg_ring — the master runs no ff loop)
 * plus cumulative drain-plane counters for the completion summary. */
#define FF_RELOAD_DRAIN_MAGIC  0x46524C44U  /* "FRLD" */

struct ff_reload_drain_report {
    /* (epoch << 32) | connection count, like ready[]/rx_parked[]: a
     * stale report from an aborted round never parses as fresh */
    uint64_t word;
    uint64_t snd_pending;    /* bytes queued in so_snd (F-M3-1) */
    uint64_t syncache;       /* half-open syncache entries (F-M4-6) */
    uint64_t last_active_ms; /* CLOCK_MONOTONIC ms of the last publish */
};

struct ff_reload_drain_state {
    uint32_t magic;
    uint32_t len;
    struct ff_reload_drain_report slot[FF_RELOAD_MAX_PROCS];
    /* per-round cumulative counters (master resets, RELAXED ops) */
    uint64_t rx_fwd;         /* packets forwarded via drain_ring_rx */
    uint64_t tx_fwd;         /* packets relayed via drain_ring_tx */
    uint64_t rx_peak;        /* peak drain_rx ring occupancy */
    uint64_t tx_peak;        /* peak drain_tx ring occupancy */
    uint64_t reclaim;        /* DR6: (epoch << 32) | gen that took rx back */
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

/* M5: same, with the master epoch. epoch == 0 (slot 0, i.e. no directory)
 * reproduces ff_reload_msg_ring_name() byte-for-byte; every other epoch
 * appends "_e<slot>". graceful=0 is untouched in both (P0-6). */
int ff_reload_msg_ring_name_e(char *buf, unsigned int buflen,
    const char *base, unsigned int proc_id, int msg_type, int gen,
    uint32_t epoch, int graceful);

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

/* M5: master epoch of this process. Set once (from the generation
 * directory) before any epoch-named resource is created and inherited by
 * fork() like the generation. 0 (== slot 0) is the pre-M5 identity. */
void     ff_reload_set_epoch(uint32_t epoch);
uint32_t ff_reload_epoch(void);
/* Ring-name coordinate of an epoch: slot 0 for 0 / no directory.
 * Inline because tools/compat/ff_ipc.c mirrors the ring-name builder
 * byte-for-byte and must resolve the same slot without linking this TU. */
static inline unsigned
ff_reload_epoch_slot_of(uint32_t epoch)
{
    if (epoch == 0 || epoch == FF_RELOAD_EPOCH_NONE)
        return 0;
    return 1u + ((epoch - 1u) % (FF_RELOAD_EPOCH_SLOT_MAX - 1u));
}

unsigned ff_reload_epoch_slot(void);
/* The generation this process hands packets to / reads drain_tx from:
 * the newest live epoch other than ours, else our own peer generation. */
void     ff_reload_peer_coord(uint32_t *epoch, int *gen);

/* M5: the same coordinate as mirrored into the anonymous block by
 * ff_reload_dir_sync(). The nginx master has no EAL and cannot read the
 * directory, so this is its only way to learn the (epoch, gen) it must hand
 * the hardware to across a USR2. 0 means "no peer registered yet". */
void     ff_reload_peer_block(uint32_t *epoch, uint32_t *gen);

/* F-M5-1 (USR2): 1 while another master's epoch is a live or still-draining
 * counterpart in the directory — the directory equivalent of the per-master
 * reload window (which a fresh master's block never opens). 0 without a
 * directory (=0, tools) and for a lone master (M4 steady state). Full
 * scan, for init / 1 Hz / miss-path callers only. */
int      ff_reload_peer_draining(void);
/* Same verdict from the block mirror (refreshed once per main-loop pass by
 * ff_reload_dir_sync), for per-packet callers: the full scan costs a
 * kill(2) per slot and must stay off the datapath. */
int      ff_reload_peer_mirror_draining(void);

/* Views of the attached block; all 0 / -1 when not attached. */
int  ff_reload_active_gen(void);
int  ff_reload_target_gen(void);
int  ff_reload_kni_owner_gen(void);
int  ff_reload_worker_gen(void);   /* reload_active ? target : active */

/* ENV-1 (C-NR-201): 1 while the reload window is active — RSS / MQ /
 * dev_configure renegotiation must be refused in that case. */
int  ff_reload_hw_locked(void);

/* ---- M5: generation directory (lib/ff_reload_gendir.c) ----------------- */
/* The directory lives in a hugepage memzone, so every entry point below is
 * only callable from a process that ran rte_eal_init() (the resident
 * primary and every worker). The nginx master never does, which is why the
 * master keeps deciding through the anonymous block and the workers mirror
 * the decision into the directory (ff_reload_dir_sync()). */

/* Create (primary) / look up (secondary) the directory and register this
 * process's master epoch in it. No-op unless graceful_reload=1. */
void ff_reload_gendir_attach(void);
/* Mark this process's epoch registration dead and drop the mapping. */
void ff_reload_gendir_detach(void);
int  ff_reload_gendir_present(void);

/* Install the mapped directory (called by ff_reload_gendir_attach).
 * Returns 0 on success, -1 when the block is missing or incompatible. */
int ff_reload_gendir_install(void *addr, size_t len);

/* 1 while 'epoch' still has a registered live master. */
int  ff_reload_gendir_epoch_live(uint32_t epoch);

/* Directory views; return 0 and zero the outputs when there is no
 * directory. */
int  ff_reload_gendir_active(uint32_t *epoch, uint32_t *gen);
void ff_reload_gendir_active_set(uint32_t epoch, uint32_t gen);
int  ff_reload_gendir_rx_owner(uint32_t *epoch, uint32_t *gen,
         uint32_t *stopped);
int  ff_reload_gendir_kni_owner(uint32_t *epoch, uint32_t *gen);
void ff_reload_gendir_kni_owner_set(uint32_t epoch, uint32_t gen);

/* Park and hand the hardware to (to_epoch, to_gen). Only the current owner
 * may transfer; everyone else gets FF_RELOAD_HANDOVER_BUSY. */
int  ff_reload_gendir_rx_release(uint32_t to_epoch, uint32_t to_gen);
/* Take the hardware from (from_epoch, from_gen), waiting at most
 * timeout_ms. Never steals: a third coordinate yields BUSY. */
int  ff_reload_gendir_rx_claim(uint32_t from_epoch, uint32_t from_gen,
         uint32_t to_epoch, uint32_t to_gen, unsigned timeout_ms);
/* M4 DR6(1) / RT-04b: take the hardware back from an owner whose epoch is
 * no longer live (crashed or retired master). */
int  ff_reload_gendir_rx_reclaim(uint32_t my_epoch, uint32_t my_gen);

/* Reserve the next epoch for a master (pid) and register it. Returns 0, or
 * -1 when every slot is held by a live master. */
int  ff_reload_gendir_mint(uint32_t *epoch, unsigned *slot, int gen,
         uint32_t pid);
/* Retire this process's master epoch (state = DEAD): its epoch stops
 * counting as live even while the pid lingers (zombie). Slot recycling
 * itself keys on pid liveness — an nginx master has no EAL and never
 * calls this. */
void ff_reload_gendir_retire(void);
/* 1 (once) when this process took its slot over from a dead master: its
 * rings may still hold that master's messages/mbufs and must be drained
 * before use. Only the process that won the slot CAS ever sees 1, so the
 * drain has exactly one actor. */
int  ff_reload_gendir_reset_pending(void);
/* Newest live (epoch, gen) other than this process's; 0 when there is
 * none. */
int  ff_reload_gendir_peer(uint32_t *epoch, uint32_t *gen);

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

/* ---- rx handover (C-NR-302) ------------------------------------------- */
/* Cross-process rx/tx ownership arbitration, living on the two words the
 * block already reserves for it (rx_owner_gen / rx_stopped). No hugepage
 * memzone and no control channel: every field is a plain uint32 that the
 * master, the old generation and the new generation all map through fork().
 *
 * Protocol (one reload round, old=0 new=1):
 *   1. old, having drained its in-flight burst, calls ff_reload_rx_release(1):
 *      it stores rx_stopped=1 first, then rx_owner_gen=1. In between, its own
 *      main_loop already sees rx_stopped and skips rx/tx.
 *   2. new calls ff_queue_handover_mutex(..., from=0, to=1, timeout_ms) and
 *      returns 0 only once rx_owner_gen==1, then clears rx_stopped.
 * The markers are ordinary read/write words — C-NR-316 hands rx back by
 * writing the old generation into rx_owner_gen (H-12: fully reversible).
 */

/* Generation that currently owns the hardware rx/tx path (-1 when no block
 * is attached). */
int  ff_reload_rx_owner_gen(void);
void ff_reload_rx_owner_gen_set(int gen);

/* 1 once the owning generation has parked (no rx burst, no tx drain). */
int  ff_reload_rx_stopped(void);
void ff_reload_rx_stopped_set(int stopped);

/* C-NR-316 / C-NR-309 seam: 1 while this process must not touch the hardware.
 * Reversible — it is derived from rx_owner_gen/rx_stopped, never latched. */
int  ff_no_hw_mode(void);

/* Yielding side: park, then hand the hardware to gen. Returns 0 on success,
 * FF_RELOAD_HANDOVER_INVAL on bad arguments. */
int  ff_reload_rx_release(int to_gen);

/* M5: same, handing the hardware to a generation of a possibly different
 * master epoch (USR2). Only the current owner may do it. */
int  ff_reload_rx_release_epoch(uint32_t to_epoch, int to_gen);

/* Acquiring side: wait (bounded by timeout_ms) until rx ownership has moved
 * from from_gen to to_gen. Never steals the hardware: if a third generation
 * owns rx it returns FF_RELOAD_HANDOVER_BUSY, which is what keeps two
 * processes from polling the same queue at the same time. */
int ff_queue_handover_mutex(uint16_t port_id, uint16_t queue_id,
    int from_gen, int to_gen, unsigned timeout_ms);

/* ---- T2 park barrier (C-NR-306) ---------------------------------------- */
/* Confirmation layer under ff_queue_handover_mutex: the mutex only observes
 * the ownership word, so the master needs positive proof that every
 * old-generation worker finished its last hardware pass before flipping it.
 * Each worker publishes one epoch-tagged ack from the parked pass itself;
 * an ack therefore implies "no rx_burst of this process is in flight". */

/* Worker: slot index in the shared block (nginx ngx_process_slot). Set once
 * during worker init; processes without a slot (primary, helpers) never ack. */
void ff_reload_set_slot(int slot);

/* Master: arm a fresh handover epoch and return it. */
void ff_reload_handover_arm(uint32_t *epoch);

/* Master: 1 once 'slot' has acked 'epoch'. A dead worker never acks — the
 * master's own liveness probes treat it as parked instead. */
int  ff_reload_handover_parked(unsigned slot, uint32_t epoch);

/* Worker (main loop, parked pass): ack the current epoch. No-op when no
 * slot is registered or no block is attached. */
void ff_reload_handover_ack(void);

/* ---- drain reporting (M4: C-NR-402/403/406) ----------------------------- */

/* Phase-duration words in ff_reload_state.reserved (observability). */
#define FF_RELOAD_PHASE_HANDOVER  0
#define FF_RELOAD_PHASE_DRAIN     1

/* Attach (validate + remember) the extension block; also publishes its
 * address through the main block's reserved[0..1] (idempotent, same value
 * written by the master before any fork). Returns 0 on success. */
int  ff_reload_drain_attach(void *block, size_t len);

/* Slot / shared-epoch views used by the worker-side publisher. */
int      ff_reload_slot(void);
uint32_t ff_reload_shared_epoch(void);

/* Worker: publish this slot's drain progress (SEQ_CST, ~1 Hz). */
void ff_reload_drain_publish(unsigned slot, uint32_t epoch, uint32_t conns,
    uint64_t snd_pending, uint64_t syncache);

/* Master: 0 plus fresh values when 'slot' published under 'epoch'. */
int  ff_reload_drain_report(unsigned slot, uint32_t epoch, uint32_t *conns,
    uint64_t *snd_pending, uint64_t *syncache, uint64_t *last_active_ms);

/* Master: reset the per-round counters (call at window open). */
void ff_reload_drain_reset(void);

/* Cumulative drain-plane counters (RELAXED; observability only). */
void ff_reload_drain_fwd_add(int tx, uint64_t n);
void ff_reload_drain_peak_max(int tx, uint64_t v);
void ff_reload_drain_counters(uint64_t *rx_fwd, uint64_t *tx_fwd,
    uint64_t *rx_peak, uint64_t *tx_peak);

/* DR6 (C-NR-404): the draining generation marks the block after taking rx
 * back from a stalled owner; the master polls the word and aborts. */
void ff_reload_drain_reclaim_mark(void);
int  ff_reload_drain_reclaim(uint32_t *epoch, int *gen);

/* Phase durations (C-NR-406), stored in ff_reload_state.reserved. */
void     ff_reload_phase_ms_set(int phase, uint32_t ms);
uint32_t ff_reload_phase_ms_get(int phase);

/* M5: 1 when this (epoch, gen) is the KNI runtime owner. Falls back to the
 * generation-only comparison when no directory is attached. */
int  ff_reload_kni_owner_match(void);

/* M5: mirror the anonymous block's arbitration words into the directory.
 * Called once per main-loop pass (and from every handover primitive) so
 * that the master's decision — which only its own children can see — is
 * visible to the other master. Idempotent, and only ever narrows. */
void ff_reload_dir_sync(void);
/* Only secondaries publish (the primary holds no queue and must never win
 * the initial ownership claim). */
void ff_reload_dir_sync_enable(int enable);

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
