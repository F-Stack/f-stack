 /*
 * Copyright (C) 2017 THL A29 Limited, a Tencent company.
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
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_channel.h>
#include <ngx_cycle.h>

#include <pthread.h>

#if (NGX_HAVE_FSTACK)
static void * ngx_ff_host_event_create_conf(ngx_cycle_t *cycle);
static char * ngx_ff_host_event_init_conf(ngx_cycle_t *cycle,
    void *conf);
static ngx_int_t ngx_ff_host_event_init_process(ngx_cycle_t *cycle);
static void ngx_ff_host_event_exit_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_ff_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer);
static ngx_int_t ngx_ff_epoll_add_event(ngx_event_t *ev,
    ngx_int_t event, ngx_uint_t flags);
static ngx_int_t ngx_ff_epoll_del_event(ngx_event_t *ev,
    ngx_int_t event, ngx_uint_t flags);
static ngx_int_t ngx_ff_epoll_process_events(ngx_cycle_t *cycle,
    ngx_msec_t timer, ngx_uint_t flags);
static ngx_int_t ngx_ff_create_connection(ngx_cycle_t *cycle);
static void ngx_ff_delete_connection();
static void ngx_ff_worker_channel_handler(ngx_event_t *ev);
static void *ngx_ff_host_event_thread_main(void *args);
static ngx_int_t ngx_ff_add_channel_event(ngx_cycle_t *cycle,
    ngx_fd_t fd, ngx_int_t event, ngx_event_handler_pt handler);
static void ngx_ff_process_events_and_timers(ngx_cycle_t *cycle);

ngx_int_t ngx_ff_start_worker_channel(ngx_cycle_t *cycle,
    ngx_fd_t fd, ngx_int_t event);
    
void ngx_aeds_cancel_timers(void);
void ngx_aeds_expire_timers(void);
ngx_msec_t ngx_aeds_find_timer(void);
void ngx_aeds_cancel_timers(void);

struct channel_thread_args {
    ngx_cycle_t *cycle;
    ngx_fd_t fd;
    ngx_int_t event;
    ngx_event_handler_pt handler;
};

static pthread_t channel_thread;
static int thread_quit;

static int ep = -1;
static struct epoll_event *event_list;
static ngx_uint_t nevents;
static ngx_connection_t *channel_connection;

#include <semaphore.h>
static sem_t sem;

typedef struct {
    ngx_uint_t  events;
} ngx_ff_host_event_conf_t;


static ngx_command_t  ngx_ff_host_event_commands[] = {
    ngx_null_command
};

ngx_core_module_t  ngx_ff_host_event_module_ctx = {
    ngx_string("ff_host_event"),
    ngx_ff_host_event_create_conf,          /* create configuration */
    ngx_ff_host_event_init_conf,            /* init configuration */
};

ngx_module_t  ngx_ff_host_event_module = {
    NGX_MODULE_V1,
    &ngx_ff_host_event_module_ctx,          /* module context */
    ngx_ff_host_event_commands,             /* module directives */
    NGX_CORE_MODULE,                     /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    ngx_ff_host_event_init_process,         /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    ngx_ff_host_event_exit_process,         /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_ff_host_event_create_conf(ngx_cycle_t *cycle)
{
    ngx_ff_host_event_conf_t  *cf;
    cf = ngx_palloc(cycle->pool, sizeof(ngx_ff_host_event_conf_t));
    if (cf == NULL) {
        return NULL;    
    }
    cf->events = NGX_CONF_UNSET;
    return cf;
}

static char *
ngx_ff_host_event_init_conf(ngx_cycle_t *cycle, void *conf)
{   
    ngx_ff_host_event_conf_t *cf = conf;
    cf->events = 1;
    return NGX_CONF_OK;
}


static ngx_int_t ngx_ff_host_event_init_process(ngx_cycle_t *cycle)
{
    if (sem_init(&sem, 0, 0) != 0)  
    {  
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void ngx_ff_host_event_exit_process(ngx_cycle_t *cycle)
{
    struct timespec ts;

    if (clock_gettime( CLOCK_REALTIME,&ts ) < 0)
        return;

    //5s
    ts.tv_sec  += 4;

    (void) sem_timedwait(&sem, &ts);
}


static ngx_int_t
ngx_ff_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer)
{
    if (ep == -1) {
        ep = epoll_create(1);

        if (ep == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "epoll_create() failed");
            return NGX_ERROR;
        }
    }

    if (event_list) {
        ngx_free(event_list);
    }

    event_list = ngx_alloc(sizeof(struct epoll_event), cycle->log);
    if (event_list == NULL) {
        return NGX_ERROR;
    }

    nevents = 1;
    channel_connection = NULL;

    return NGX_OK;
}

static ngx_int_t
ngx_ff_epoll_add_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags)
{
    int                  op;
    uint32_t             events, prev;
    ngx_event_t         *e;
    ngx_connection_t    *c;
    struct epoll_event   ee;

    c = ev->data;

    events = (uint32_t) event;

    if (event == NGX_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;
#if (NGX_READ_EVENT != EPOLLIN|EPOLLRDHUP)
        events = EPOLLIN|EPOLLRDHUP;
#endif

    } else {
        e = c->read;
        prev = EPOLLIN|EPOLLRDHUP;
#if (NGX_WRITE_EVENT != EPOLLOUT)
        events = EPOLLOUT;
#endif
    }

    if (e->active) {
        op = EPOLL_CTL_MOD;
        events |= prev;

    } else {
        op = EPOLL_CTL_ADD;
    }

    ee.events = events | (uint32_t) flags;
    ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll add event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    ev->active = 1;
#if 0
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1 : 0;
#endif

    return NGX_OK;
}

static ngx_int_t
ngx_ff_epoll_del_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags)
{
    int                  op;
    uint32_t             prev;
    ngx_event_t         *e;
    ngx_connection_t    *c;
    struct epoll_event   ee;

    /*
     * when the file descriptor is closed, the epoll automatically deletes
     * it from its queue, so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

    if (flags & NGX_CLOSE_EVENT) {
        ev->active = 0;
        return NGX_OK;
    }

    c = ev->data;

    if (event == NGX_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;

    } else {
        e = c->read;
        prev = EPOLLIN|EPOLLRDHUP;
    }

    if (e->active) {
        op = EPOLL_CTL_MOD;
        ee.events = prev | (uint32_t) flags;
        ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    } else {
        op = EPOLL_CTL_DEL;
        ee.events = 0;
        ee.data.ptr = NULL;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll del event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    ev->active = 0;

    return NGX_OK;
}

#if 0
static ngx_int_t
ngx_ff_epoll_add_connection(ngx_connection_t *c)
{
    struct epoll_event  ee;

    ee.events = EPOLLIN|EPOLLOUT|EPOLLET|EPOLLRDHUP;
    ee.data.ptr = (void *) ((uintptr_t) c | c->read->instance);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll add connection: fd:%d ev:%08XD", c->fd, ee.events);

    if (epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "epoll_ctl(EPOLL_CTL_ADD, %d) failed", c->fd);
        return NGX_ERROR;
    }

    c->read->active = 1;
    c->write->active = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_ff_epoll_del_connection(ngx_connection_t *c, ngx_uint_t flags)
{
    int                 op;
    struct epoll_event  ee;

    /*
     * when the file descriptor is closed the epoll automatically deletes
     * it from its queue so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

    if (flags & NGX_CLOSE_EVENT) {
        c->read->active = 0;
        c->write->active = 0;
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll del connection: fd:%d", c->fd);

    op = EPOLL_CTL_DEL;
    ee.events = 0;
    ee.data.ptr = NULL;

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    c->read->active = 0;
    c->write->active = 0;

    return NGX_OK;
}
#endif

static ngx_int_t
ngx_ff_epoll_process_events(ngx_cycle_t *cycle,
    ngx_msec_t timer, ngx_uint_t flags)
{
    int                events;
    uint32_t           revents;
    ngx_int_t          instance, i;
    ngx_uint_t         level;
    ngx_err_t          err;
    ngx_event_t       *rev, *wev;
    ngx_connection_t  *c;

    /* NGX_TIMER_INFINITE == INFTIM */

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "epoll timer: %M", timer);

    events = epoll_wait(ep, event_list, (int) nevents, timer);

    err = (events == -1) ? ngx_errno : 0;

    if (flags & NGX_UPDATE_TIME || ngx_event_timer_alarm) {
        ngx_time_update();
    }

    if (err) {
        if (err == NGX_EINTR) {
            level = NGX_LOG_INFO;
        } else {
            level = NGX_LOG_ALERT;
        }

        ngx_log_error(level, cycle->log, err, "epoll_wait() failed");
        return NGX_ERROR;
    }

    if (events == 0) {
        if (timer != NGX_TIMER_INFINITE) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "epoll_wait() returned no events without timeout");
        return NGX_ERROR;
    }

    for (i = 0; i < events; i++) {
        c = event_list[i].data.ptr;

        instance = (uintptr_t) c & 1;
        c = (ngx_connection_t *) ((uintptr_t) c & (uintptr_t) ~1);

        rev = c->read;

        if (c->fd == -1 || rev->instance != instance) {

            /*
             * the stale event from a file descriptor
             * that was just closed in this iteration
             */

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll: stale event %p", c);
            continue;
        }

        revents = event_list[i].events;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "epoll: fd:%d ev:%04XD d:%p",
                       c->fd, revents, event_list[i].data.ptr);

        if (revents & (EPOLLERR|EPOLLHUP)) {
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll_wait() error on fd:%d ev:%04XD",
                           c->fd, revents);

            /*
             * if the error events were returned, add EPOLLIN and EPOLLOUT
             * to handle the events at least in one active handler
             */

            revents |= EPOLLIN|EPOLLOUT;
        }

        if ((revents & EPOLLIN) && rev->active) {
            rev->ready = 1;
            rev->available = 1;
            rev->handler(rev);
        }

        wev = c->write;

        if ((revents & EPOLLOUT) && wev->active) {

            if (c->fd == -1 || wev->instance != instance) {

                /*
                 * the stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "epoll: stale event %p", c);
                continue;
            }

            wev->ready = 1;
#if (NGX_THREADS)
            wev->complete = 1;
#endif
            wev->handler(wev);
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_ff_create_connection(ngx_cycle_t *cycle)
{
    ngx_event_t *rev, *wev;
    ngx_connection_t *c;
    c = ngx_calloc(sizeof(ngx_connection_t), cycle->log);
    if (c == NULL) {
        return NGX_ERROR;
    }

    rev = ngx_calloc(sizeof(ngx_event_t), cycle->log);
    if (rev == NULL) {
        ngx_free(c);
        return NGX_ERROR;
    }
    rev->index = NGX_INVALID_INDEX;
    rev->data = c;
    rev->log = cycle->log;

    wev = ngx_calloc(sizeof(ngx_event_t), cycle->log);
    if (wev == NULL) {
        ngx_free(c);
        ngx_free(rev);
        return NGX_ERROR;
    }
    wev->index = NGX_INVALID_INDEX;
    wev->write = 1;
    wev->data = c;
    wev->log = cycle->log;

    c->pool = cycle->pool;
    c->data = NULL;
    c->read = rev;
    c->write = wev;
    c->fd = (ngx_socket_t) -1;
    c->log = cycle->log;

    channel_connection = c;

    return NGX_OK;
}

static void
ngx_ff_delete_connection()
{
    ngx_connection_t *c = channel_connection;
    if (c == NULL) {
        return;
    }

    if (c->read) {
        ngx_free(c->read);
    }

    if (c->write) {
        ngx_free(c->write);
    }

    ngx_free(c);
    channel_connection = NULL;
}

static ngx_int_t
ngx_ff_add_channel_event(ngx_cycle_t *cycle, ngx_fd_t fd,
    ngx_int_t event, ngx_event_handler_pt handler)
{
    ngx_connection_t *c;
    ngx_event_t *ev, *rev, *wev;

    if (channel_connection != NULL) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                              "add channel event failed: already added");
        return NGX_ERROR;
    }

    if (ngx_ff_create_connection(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    c = channel_connection;

    c->fd = fd;
    rev = c->read;
    wev = c->write;

    rev->channel = 1;
    wev->channel = 1;

    rev->belong_to_host = wev->belong_to_host = 1;

    ev = (event == NGX_READ_EVENT) ? rev : wev;
    ev->handler = handler;

    if (ngx_ff_epoll_add_event(ev, event, 0) == NGX_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void
ngx_ff_worker_channel_handler(ngx_event_t *ev)
{
    ngx_int_t          n;
    ngx_channel_t      ch;
    ngx_connection_t  *c;

    if (ev->timedout) {
        ev->timedout = 0;
        return;
    }

    c = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "worker channel handler");

    for ( ;; ) {

        n = ngx_read_channel(c->fd, &ch, sizeof(ngx_channel_t), ev->log);

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0, "channel: %i", n);

        if (n == NGX_ERROR) {
            ngx_ff_epoll_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
            close(c->fd);
            ngx_ff_delete_connection();
            thread_quit = 1;
            return;
        }

        if (n == NGX_AGAIN) {
            return;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,
                       "channel command: %ui", ch.command);

        switch (ch.command) {

        case NGX_CMD_QUIT:
            ngx_quit = 1;
            thread_quit = 1;
            break;

        case NGX_CMD_TERMINATE:
            ngx_terminate = 1;
            thread_quit = 1;
            break;

        case NGX_CMD_REOPEN:
            ngx_reopen = 1;
            break;

        case NGX_CMD_OPEN_CHANNEL:

            ngx_log_debug3(NGX_LOG_DEBUG_CORE, ev->log, 0,
                           "get channel s:%i pid:%P fd:%d",
                           ch.slot, ch.pid, ch.fd);

            ngx_processes[ch.slot].pid = ch.pid;
            ngx_processes[ch.slot].channel[0] = ch.fd;
            break;

        case NGX_CMD_CLOSE_CHANNEL:

            ngx_log_debug4(NGX_LOG_DEBUG_CORE, ev->log, 0,
                           "close channel s:%i pid:%P our:%P fd:%d",
                           ch.slot, ch.pid, ngx_processes[ch.slot].pid,
                           ngx_processes[ch.slot].channel[0]);

            if (close(ngx_processes[ch.slot].channel[0]) == -1) {
                ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                              "close() channel failed");
            }

            ngx_processes[ch.slot].channel[0] = -1;
            break;
        }
    }
}

static void *
ngx_ff_host_event_thread_main(void *args)
{
    struct channel_thread_args *cta = args;
    ngx_cycle_t *cycle = cta->cycle;

    if (ngx_ff_add_channel_event(cycle, cta->fd, cta->event,
            cta->handler) != NGX_OK) {
        return NULL;
    }

    for (;;) {
        ngx_ff_process_events_and_timers(cycle);
        if (thread_quit) {
            break;
        }
    }

    ngx_aeds_cancel_timers();

    ngx_free(cta);

    return NULL;
}

static void
ngx_ff_process_events_and_timers(ngx_cycle_t *cycle)
{
    ngx_uint_t  flags;
    ngx_msec_t  timer, delta;

    timer = ngx_aeds_find_timer();
    flags = NGX_UPDATE_TIME;

    /* handle signals from master in case of network inactivity */

    if (timer == NGX_TIMER_INFINITE || timer > 500) {
        timer = 500;
    }

    delta = ngx_current_msec;

    (void) ngx_ff_epoll_process_events(cycle, timer, flags);

    delta = ngx_current_msec - delta;

    ngx_event_process_posted(cycle, &ngx_posted_accept_events_of_aeds);

    if (delta) {
        ngx_aeds_expire_timers();
    }

    ngx_event_process_posted(cycle, &ngx_posted_events_of_aeds);

}

ngx_int_t
ngx_ff_start_worker_channel(ngx_cycle_t *cycle, ngx_fd_t fd,
    ngx_int_t event)
{
    int ret;
    struct channel_thread_args *cta;

    cta = ngx_alloc(sizeof(struct channel_thread_args), cycle->log);
    if (cta == NULL) {
        return NGX_ERROR;
    }

    cta->cycle = cycle;
    cta->fd = fd;
    cta->event = event;
    cta->handler = ngx_ff_worker_channel_handler;

    ret = pthread_create(&channel_thread, NULL,
			ngx_ff_host_event_thread_main, (void *)cta);
    if (ret != 0) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "pthread_create() failed");
        return NGX_ERROR;
    }

    pthread_detach(channel_thread);

    return NGX_OK;
}

ngx_event_actions_t   ngx_event_actions_dy = {
    ngx_ff_epoll_add_event,             /* add an event */
    ngx_ff_epoll_del_event,             /* delete an event */
    ngx_ff_epoll_add_event,             /* enable an event */
    ngx_ff_epoll_add_event,             /* disable an event */
    NULL,                               /* add an connection */
    NULL,                               /* delete an connection */
    NULL,                               /* trigger a notify */
    ngx_ff_epoll_process_events,        /* process the events */
    ngx_ff_epoll_init,                  /* init the events */
    NULL,                               /* done the events */
};

#endif
