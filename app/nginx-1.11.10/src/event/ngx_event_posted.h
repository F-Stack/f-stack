
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_POSTED_H_INCLUDED_
#define _NGX_EVENT_POSTED_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (NGX_HAVE_FSTACK)
#define ngx_post_event(ev, q)                                                 \
                                                                              \
    if (!(ev)->posted) {                                                      \
        (ev)->posted = 1;                                                     \
        if (1 == (ev)->belong_to_host) {                                      \
            if (q == &ngx_posted_events) {                                    \
                ngx_queue_insert_tail(                                        \
                    &ngx_posted_events_of_aeds, &(ev)->queue);                \
            } else if (q == &ngx_posted_accept_events) {                      \
                ngx_queue_insert_tail(                                        \
                    &ngx_posted_accept_events_of_aeds, &(ev)->queue);         \
            } else {                                                          \
                ngx_log_error(NGX_LOG_EMERG, (ev)->log, 0,                    \
                          "ngx_post_event: unkowned posted queue");           \
                exit(1);                                                      \
            }                                                                 \
        } else {                                                              \
            ngx_queue_insert_tail(q, &(ev)->queue);                           \
        }                                                                     \
                                                                              \
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, (ev)->log, 0, "post event %p", ev);\
                                                                              \
    } else  {                                                                 \
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, (ev)->log, 0,                      \
                       "update posted event %p", ev);                         \
    }
#else
#define ngx_post_event(ev, q)                                                 \
                                                                              \
    if (!(ev)->posted) {                                                      \
        (ev)->posted = 1;                                                     \
        ngx_queue_insert_tail(q, &(ev)->queue);                               \
                                                                              \
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, (ev)->log, 0, "post event %p", ev);\
                                                                              \
    } else  {                                                                 \
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, (ev)->log, 0,                      \
                       "update posted event %p", ev);                         \
    }
#endif


#define ngx_delete_posted_event(ev)                                           \
                                                                              \
    (ev)->posted = 0;                                                         \
    ngx_queue_remove(&(ev)->queue);                                           \
                                                                              \
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, (ev)->log, 0,                          \
                   "delete posted event %p", ev);



void ngx_event_process_posted(ngx_cycle_t *cycle, ngx_queue_t *posted);


extern ngx_queue_t  ngx_posted_accept_events;
extern ngx_queue_t  ngx_posted_events;

#if (NGX_HAVE_FSTACK)
extern ngx_queue_t  ngx_posted_accept_events_of_aeds;
extern ngx_queue_t  ngx_posted_events_of_aeds;
#endif

#endif /* _NGX_EVENT_POSTED_H_INCLUDED_ */
