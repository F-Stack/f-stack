
/*
 * Copyright (C) 2026 F-Stack project
 */

/* C-NR-205: graceful reload orchestration state machine, master side.
 *
 * Division of labour (the nginx process statics force the split): the
 * spawn/signal/READY-wait sequencing lives in ngx_process_cycle.c (it needs
 * ngx_start_worker_processes / ngx_signal_worker_processes / ngx_processes[]
 * / the master-loop `live` local), while this module owns:
 *   - creation of the shared reload control block (anonymous MAP_SHARED,
 *     inherited by the slim primary and every worker through fork());
 *   - the side-effectful FSM wrapper (transition logging + per-state
 *     counters + shared-state updates on window open/abort/complete);
 *   - the READY publish entry point used by workers.
 * The transition table itself is pure: ngx_ff_reload_fsm.h (UT-NR-10).
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_process.h>
#include <ngx_process_cycle.h>

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <ngx_auto_config.h>
#include "ff_api.h"
#include "ff_reload.h"       /* lib reload helpers (C-NR-313/316) */

#include "ngx_ff_reload_fsm.h"

#if (NGX_HAVE_FSTACK)

/* inherited by every forked child (slim primary + workers) */
struct ff_reload_state *ngx_ff_reload_shm = NULL;

static int      ff_reload_fsm_state = NGX_FF_RELOAD_T0_IDLE;
static ngx_msec_t ff_reload_t_start;
static ngx_log_t *ff_reload_log;
static uint32_t  ff_reload_cur_epoch;

/* per-state entry counters + re-entry rejections (stage observability) */
static uint64_t  ff_reload_state_hits[NGX_FF_RELOAD_T_MAX];
static uint64_t  ff_reload_hup_rejected;
static uint64_t  ff_reload_transitions;

static void
ngx_ff_reload_fsm_set(int st)
{
    ff_reload_fsm_state = st;
    if (ngx_ff_reload_shm) {
        __atomic_store_n(&ngx_ff_reload_shm->fsm_state, (uint32_t)st,
            __ATOMIC_SEQ_CST);
    }
}

int
ngx_ff_reload_fsm_state(void)
{
    return ff_reload_fsm_state;
}

uint64_t
ngx_ff_reload_fsm_transitions(void)
{
    return ff_reload_transitions;
}

uint64_t
ngx_ff_reload_hup_rejected_count(void)
{
    return ff_reload_hup_rejected;
}

uint32_t
ngx_ff_reload_epoch(void)
{
    return ff_reload_cur_epoch;
}

uint64_t
ngx_ff_reload_state_hits(int state)
{
    if (state < 0 || state >= NGX_FF_RELOAD_T_MAX) {
        return 0;
    }
    return ff_reload_state_hits[state];
}

/* Advance the FSM by one event; logs every transition and applies the
 * shared-state side effects at window open / abort / completion. Returns
 * the new state, or NGX_FF_RELOAD_T_MAX when the transition is illegal. */
int
ngx_ff_reload_fsm_event(int event)
{
    int  prev, next;

    prev = ff_reload_fsm_state;
    next = ngx_ff_reload_fsm_next(prev, event);
    if (next == NGX_FF_RELOAD_T_MAX) {
        if (ff_reload_log) {
            ngx_log_error(NGX_LOG_ALERT, ff_reload_log, 0,
                          "graceful reload fsm: illegal event %d in state %s",
                          event, ngx_ff_reload_fsm_state_name(prev));
        }
        return NGX_FF_RELOAD_T_MAX;
    }

    if (event == NGX_FF_RELOAD_EV_HUP) {
        uint32_t epoch, target;

        ff_reload_master_begin(&epoch, &target);
        ff_reload_cur_epoch = epoch;
        ff_reload_t_start = ngx_current_msec;
        ngx_log_error(NGX_LOG_NOTICE, ff_reload_log, 0,
                      "graceful reload: spawning new generation %uD "
                      "(epoch %uD)", target, epoch);
    }

    ff_reload_state_hits[next]++;
    ff_reload_transitions++;
    ngx_ff_reload_fsm_set(next);

    switch (next) {

    case NGX_FF_RELOAD_T_ERROR:
        ff_reload_master_abort();
        break;

    case NGX_FF_RELOAD_T0_IDLE:
        /* arriving from T5: flip generations (KNI owner follows active);
         * arriving from T_ERROR: window already closed by the abort above */
        if (event == NGX_FF_RELOAD_EV_GOLD_EXITED) {
            ff_reload_master_complete();
        }
        break;

    default:
        break;
    }

    if (ff_reload_log) {
        ngx_log_error(NGX_LOG_NOTICE, ff_reload_log, 0,
                      "graceful reload fsm: %s -> %s (transition %uL, "
                      "elapsed %M ms)",
                      ngx_ff_reload_fsm_state_name(prev),
                      ngx_ff_reload_fsm_state_name(next),
                      ff_reload_transitions, ngx_current_msec - ff_reload_t_start);
    }

    return next;
}

/* Master startup: create the shared reload control block before any child
 * (slim primary first, then workers) is forked. graceful_reload only. */
ngx_int_t
ngx_ff_reload_state_create(ngx_cycle_t *cycle)
{
    void  *p;

    if (!ngx_ff_graceful_reload) {
        return NGX_OK;
    }

    if (ngx_ff_reload_shm != NULL) {
        return NGX_OK;
    }

    ff_reload_log = cycle->log;

    p = mmap(NULL, sizeof(struct ff_reload_state),
             PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "graceful reload: mmap shared state failed");
        return NGX_ERROR;
    }

    memset(p, 0, sizeof(struct ff_reload_state));
    ngx_ff_reload_shm = (struct ff_reload_state *) p;
    ngx_ff_reload_shm->magic = FF_RELOAD_STATE_MAGIC;
    ngx_ff_reload_shm->version = FF_RELOAD_STATE_VERSION;
    ngx_ff_reload_shm->len = sizeof(struct ff_reload_state);
    ngx_ff_reload_shm->active_gen = 0;
    ngx_ff_reload_shm->target_gen = 0;
    ngx_ff_reload_shm->reload_active = 0;
    ngx_ff_reload_shm->kni_owner_gen = 0;

    /* lib-side attach: this process (master) never runs ff_init, but the
     * master_begin/abort/complete helpers operate on the lib-attached
     * block, so attach it here; children inherit both the mapping and the
     * lib pointer state (re-attached defensively in ff_mod_init). */
    ff_reload_attach_state(ngx_ff_reload_shm);

    return NGX_OK;
}

/* Worker: publish FF_RELOAD_READY for this worker slot. The master
 * correlates (slot, pid, epoch). Called at the end of worker init, after
 * the ff stack and listening sockets are up. */
void
ngx_ff_reload_worker_ready(void)
{
    if (!ngx_ff_graceful_reload || ngx_ff_reload_shm == NULL) {
        return;
    }

    ff_reload_attach_state(ngx_ff_reload_shm);
    ff_reload_publish_ready((unsigned) ngx_process_slot, (uint32_t) ngx_pid);
}

/* Convenience views used by ngx_process_cycle.c / ngx_ff_module.c. */
int
ngx_ff_reload_gen_for_worker(void)
{
    if (ngx_ff_reload_shm == NULL) {
        return 0;
    }
    ff_reload_attach_state(ngx_ff_reload_shm);
    return ff_reload_worker_gen();
}

void
ngx_ff_reload_note_hup_rejected(void)
{
    ff_reload_hup_rejected++;
}

/* F4: rebind the FSM transition log. The log bound at state_create belongs
 * to a cycle that a later ngx_init_cycle destroys (pool freed, fd closed);
 * the orchestrator calls this at reload entry (old cycle still live) and
 * right after a successful init_cycle (new cycle log). */
void
ngx_ff_reload_set_log(ngx_log_t *log)
{
    if (log != NULL) {
        ff_reload_log = log;
    }
}

uint64_t
ngx_ff_reload_elapsed_ms(void)
{
    return ngx_current_msec - ff_reload_t_start;
}

#else /* !NGX_HAVE_FSTACK */

/* keep the translation unit non-empty for non-FSTACK builds */
typedef int ngx_ff_reload_dummy_t;

#endif /* NGX_HAVE_FSTACK */
