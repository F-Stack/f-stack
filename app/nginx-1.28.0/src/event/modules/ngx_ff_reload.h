
/*
 * Copyright (C) 2026 F-Stack project
 */

#ifndef _NGX_FF_RELOAD_H_INCLUDED_
#define _NGX_FF_RELOAD_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#if (NGX_HAVE_FSTACK)

/* shared reload control block; created by the master (anonymous MAP_SHARED)
 * before any child is forked, inherited through fork() */
struct ff_reload_state;
extern struct ff_reload_state *ngx_ff_reload_shm;

/* FSM (pure table in ngx_ff_reload_fsm.h); wrapper in ngx_ff_reload.c */
int ngx_ff_reload_fsm_state(void);
int ngx_ff_reload_fsm_event(int event);
uint64_t ngx_ff_reload_fsm_transitions(void);
uint64_t ngx_ff_reload_hup_rejected_count(void);
uint64_t ngx_ff_reload_state_hits(int state);
uint64_t ngx_ff_reload_elapsed_ms(void);
uint32_t ngx_ff_reload_epoch(void);

/* master startup: create + publish the shared state (graceful only) */
ngx_int_t ngx_ff_reload_state_create(ngx_cycle_t *cycle);

/* worker: publish FF_RELOAD_READY for this slot (end of worker init) */
void ngx_ff_reload_worker_ready(void);

/* worker: generation to bind before ff_init (target while the reload
 * window is open, active otherwise) */
int ngx_ff_reload_gen_for_worker(void);

/* re-entry bookkeeping (semantics 6) */
void ngx_ff_reload_note_hup_rejected(void);

/* F4: rebind the FSM transition log (cycle logs die with their cycle) */
void ngx_ff_reload_set_log(ngx_log_t *log);

#endif /* NGX_HAVE_FSTACK */


#endif /* _NGX_FF_RELOAD_H_INCLUDED_ */
