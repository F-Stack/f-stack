
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_rbtree_t              ngx_event_timer_rbtree;
static ngx_rbtree_node_t  ngx_event_timer_sentinel;

#if (NGX_HAVE_FSTACK)
ngx_rbtree_t              ngx_event_timer_rbtree_of_host;
static ngx_rbtree_node_t  ngx_event_timer_sentinel_of_host;
#endif

/*
 * the event timer rbtree may contain the duplicate keys, however,
 * it should not be a problem, because we use the rbtree to find
 * a minimum timer value only
 */

ngx_int_t
ngx_event_timer_init(ngx_log_t *log)
{
    ngx_rbtree_init(&ngx_event_timer_rbtree, &ngx_event_timer_sentinel,
                    ngx_rbtree_insert_timer_value);

#if (NGX_HAVE_FSTACK)

    ngx_rbtree_init(&ngx_event_timer_rbtree_of_host, &ngx_event_timer_sentinel_of_host,
                    ngx_rbtree_insert_timer_value);

#endif

    return NGX_OK;
}


#if (NGX_HAVE_FSTACK)

ngx_msec_t
ngx_event_find_timer_internal(
    ngx_rbtree_t *rbtree, ngx_rbtree_node_t *sentinel);
ngx_msec_t
ngx_event_find_timer(void)
{
    return ngx_event_find_timer_internal(&ngx_event_timer_rbtree, &ngx_event_timer_sentinel);
}

ngx_msec_t
ngx_event_find_timer_of_host(void)
{
    return ngx_event_find_timer_internal(&ngx_event_timer_rbtree_of_host, &ngx_event_timer_sentinel_of_host);
}

ngx_msec_t
ngx_event_find_timer_internal(
    ngx_rbtree_t *rbtree, ngx_rbtree_node_t *rbtree_sentinel)
{
#else
ngx_msec_t
ngx_event_find_timer(void)
{
    ngx_rbtree_t * rbtree = &ngx_event_timer_rbtree;
    ngx_rbtree_node_t *rbtree_sentinel = &ngx_event_timer_sentinel;
#endif
    ngx_msec_int_t      timer;
    ngx_rbtree_node_t  *node, *root, *sentinel;

    if (rbtree->root == rbtree_sentinel) {
        return NGX_TIMER_INFINITE;
    }

    root = rbtree->root;
    sentinel = rbtree->sentinel;

    node = ngx_rbtree_min(root, sentinel);

    timer = (ngx_msec_int_t) (node->key - ngx_current_msec);

    return (ngx_msec_t) (timer > 0 ? timer : 0);
}


#if (NGX_HAVE_FSTACK)

void
ngx_event_expire_timers_internal(ngx_rbtree_t *rbtree);

void
ngx_event_expire_timers(void)
{
    ngx_event_expire_timers_internal(&ngx_event_timer_rbtree);
}

void
ngx_event_expire_timers_of_host(void)
{
    ngx_event_expire_timers_internal(&ngx_event_timer_rbtree_of_host);
}

void
ngx_event_expire_timers_internal(ngx_rbtree_t *rbtree)
{
#else
void
ngx_event_expire_timers(void)
{
    ngx_rbtree_t * rbtree = &ngx_event_timer_rbtree;
#endif
    ngx_event_t        *ev;
    ngx_rbtree_node_t  *node, *root, *sentinel;

    sentinel = rbtree->sentinel;

    for ( ;; ) {
        root = rbtree->root;

        if (root == sentinel) {
            return;
        }

        node = ngx_rbtree_min(root, sentinel);

        /* node->key > ngx_current_time */

        if ((ngx_msec_int_t) (node->key - ngx_current_msec) > 0) {
            return;
        }

        ev = (ngx_event_t *) ((char *) node - offsetof(ngx_event_t, timer));

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "event timer del: %d: %M",
                       ngx_event_ident(ev->data), ev->timer.key);

        ngx_rbtree_delete(rbtree, &ev->timer);

#if (NGX_DEBUG)
        ev->timer.left = NULL;
        ev->timer.right = NULL;
        ev->timer.parent = NULL;
#endif

        ev->timer_set = 0;

        ev->timedout = 1;

        ev->handler(ev);
    }
}


#if (NGX_HAVE_FSTACK)

void
ngx_event_cancel_timers_internal(ngx_rbtree_t *rbtree);

void
ngx_event_cancel_timers(void)
{
    ngx_event_cancel_timers_internal(&ngx_event_timer_rbtree);
}

void
ngx_event_cancel_timers_of_host(void)
{
    ngx_event_cancel_timers_internal(&ngx_event_timer_rbtree_of_host);
}

void
ngx_event_cancel_timers_internal(ngx_rbtree_t *rbtree)
{
#else
void
ngx_event_cancel_timers(void)
{
    ngx_rbtree_t * rbtree = &ngx_event_timer_rbtree;
#endif
    ngx_event_t        *ev;
    ngx_rbtree_node_t  *node, *root, *sentinel;

    sentinel = rbtree->sentinel;

    for ( ;; ) {
        root = rbtree->root;

        if (root == sentinel) {
            return;
        }

        node = ngx_rbtree_min(root, sentinel);

        ev = (ngx_event_t *) ((char *) node - offsetof(ngx_event_t, timer));

        if (!ev->cancelable) {
            return;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "event timer cancel: %d: %M",
                       ngx_event_ident(ev->data), ev->timer.key);

        ngx_rbtree_delete(rbtree, &ev->timer);

#if (NGX_DEBUG)
        ev->timer.left = NULL;
        ev->timer.right = NULL;
        ev->timer.parent = NULL;
#endif

        ev->timer_set = 0;

        ev->handler(ev);
    }
}
