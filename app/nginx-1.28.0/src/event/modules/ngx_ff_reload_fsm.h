
/*
 * Copyright (C) 2026 F-Stack project
 */

/* C-NR-205: T0-T5 graceful reload orchestration state machine, PURE part.
 *
 * This header must stay free of nginx dependencies (only stdint) so the
 * unit tests can include it directly (UT-NR-10). The side-effectful
 * wrapper (logging, shared-state updates, spawn/signal sequencing) lives
 * in ngx_ff_reload.c and ngx_process_cycle.c; the transition legality and
 * the next-state computation are defined here only.
 *
 * M3 (C-NR-306): the T2 handover is real (park barrier + rx ownership
 * flip, driven from ngx_process_cycle.c); T3 side effects on the worker
 * side (flow-map callback, drain rings) were armed at G_new init. The
 * T3 -> T4 drain confirmation remains a placeholder until M4
 * (C-NR-402/403/405).
 */

#ifndef _NGX_FF_RELOAD_FSM_H_INCLUDED_
#define _NGX_FF_RELOAD_FSM_H_INCLUDED_

#include <stdint.h>

#define NGX_FF_RELOAD_FSM_VERSION  1

typedef enum {
    NGX_FF_RELOAD_T0_IDLE = 0,      /* steady state; HUP accepted */
    NGX_FF_RELOAD_T1_GNEW_SPAWN,    /* G_new forked, waiting READY */
    NGX_FF_RELOAD_T2_HANDOVER,      /* same-era handover (M3) */
    NGX_FF_RELOAD_T3_DRAIN,         /* G_old drain (M4) */
    NGX_FF_RELOAD_T4_DRAIN_DONE,    /* drain confirmed, about to quit G_old */
    NGX_FF_RELOAD_T5_GOLD_QUIT,     /* QUIT sent to G_old, waiting exits */
    NGX_FF_RELOAD_T_ERROR,          /* failure; rollback in progress */
    NGX_FF_RELOAD_T_MAX
} ngx_ff_reload_state_t;

typedef enum {
    NGX_FF_RELOAD_EV_NONE = 0,
    NGX_FF_RELOAD_EV_HUP,           /* T0 -> T1: reload requested */
    NGX_FF_RELOAD_EV_ALL_READY,     /* T1 -> T2: every G_new worker READY */
    NGX_FF_RELOAD_EV_READY_TIMEOUT, /* T1 -> T_ERROR */
    NGX_FF_RELOAD_EV_GNEW_DIED,     /* T1 -> T_ERROR */
    NGX_FF_RELOAD_EV_ABORT,         /* T2|T3|T4 -> T_ERROR */
    NGX_FF_RELOAD_EV_HANDOVER_DONE, /* T2 -> T3 (M3) */
    NGX_FF_RELOAD_EV_DRAIN_DONE,    /* T3 -> T4 (M4) */
    NGX_FF_RELOAD_EV_QUIT_GOLD,     /* T4 -> T5 */
    NGX_FF_RELOAD_EV_GOLD_EXITED,   /* T5 -> T0: all G_old exited */
    NGX_FF_RELOAD_EV_RESET,         /* T_ERROR -> T0 */
    NGX_FF_RELOAD_EV_MAX
} ngx_ff_reload_event_t;

/* Pure transition table: returns the next state for (state, event), or
 * NGX_FF_RELOAD_T_MAX when the transition is illegal. Re-entry protection
 * (semantics 6) falls out of the table: EV_HUP is only legal in T0. */
static inline int
ngx_ff_reload_fsm_next(int state, int event)
{
    switch (state) {

    case NGX_FF_RELOAD_T0_IDLE:
        if (event == NGX_FF_RELOAD_EV_HUP)
            return NGX_FF_RELOAD_T1_GNEW_SPAWN;
        return NGX_FF_RELOAD_T_MAX;

    case NGX_FF_RELOAD_T1_GNEW_SPAWN:
        if (event == NGX_FF_RELOAD_EV_ALL_READY)
            return NGX_FF_RELOAD_T2_HANDOVER;
        if (event == NGX_FF_RELOAD_EV_READY_TIMEOUT
            || event == NGX_FF_RELOAD_EV_GNEW_DIED)
            return NGX_FF_RELOAD_T_ERROR;
        return NGX_FF_RELOAD_T_MAX;

    case NGX_FF_RELOAD_T2_HANDOVER:
        if (event == NGX_FF_RELOAD_EV_HANDOVER_DONE)
            return NGX_FF_RELOAD_T3_DRAIN;
        if (event == NGX_FF_RELOAD_EV_ABORT)
            return NGX_FF_RELOAD_T_ERROR;
        return NGX_FF_RELOAD_T_MAX;

    case NGX_FF_RELOAD_T3_DRAIN:
        if (event == NGX_FF_RELOAD_EV_DRAIN_DONE)
            return NGX_FF_RELOAD_T4_DRAIN_DONE;
        if (event == NGX_FF_RELOAD_EV_ABORT)
            return NGX_FF_RELOAD_T_ERROR;
        return NGX_FF_RELOAD_T_MAX;

    case NGX_FF_RELOAD_T4_DRAIN_DONE:
        if (event == NGX_FF_RELOAD_EV_QUIT_GOLD)
            return NGX_FF_RELOAD_T5_GOLD_QUIT;
        if (event == NGX_FF_RELOAD_EV_ABORT)
            return NGX_FF_RELOAD_T_ERROR;
        return NGX_FF_RELOAD_T_MAX;

    case NGX_FF_RELOAD_T5_GOLD_QUIT:
        if (event == NGX_FF_RELOAD_EV_GOLD_EXITED)
            return NGX_FF_RELOAD_T0_IDLE;
        return NGX_FF_RELOAD_T_MAX;

    case NGX_FF_RELOAD_T_ERROR:
        if (event == NGX_FF_RELOAD_EV_RESET)
            return NGX_FF_RELOAD_T0_IDLE;
        return NGX_FF_RELOAD_T_MAX;

    default:
        return NGX_FF_RELOAD_T_MAX;
    }
}

/* State name for logging/observability. */
static inline const char *
ngx_ff_reload_fsm_state_name(int state)
{
    switch (state) {
    case NGX_FF_RELOAD_T0_IDLE:      return "T0_IDLE";
    case NGX_FF_RELOAD_T1_GNEW_SPAWN: return "T1_GNEW_SPAWN";
    case NGX_FF_RELOAD_T2_HANDOVER:  return "T2_HANDOVER";
    case NGX_FF_RELOAD_T3_DRAIN:     return "T3_DRAIN";
    case NGX_FF_RELOAD_T4_DRAIN_DONE: return "T4_DRAIN_DONE";
    case NGX_FF_RELOAD_T5_GOLD_QUIT: return "T5_GOLD_QUIT";
    case NGX_FF_RELOAD_T_ERROR:      return "T_ERROR";
    default:                         return "T_INVALID";
    }
}

#endif /* _NGX_FF_RELOAD_FSM_H_INCLUDED_ */
