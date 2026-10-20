/*
 * ff_ring_ipc.c — Lock-free ring IPC helper functions.
 *
 * Shared by both fstack (primary) and libff_syscall.so (LD_PRELOAD).
 * Split from ff_socket_ops.c to avoid dragging ff_* API symbols into
 * the LD_PRELOAD library.
 */

#include <errno.h>
#include <sched.h>
#include <unistd.h>

#include <rte_ring.h>
#include <rte_cycles.h>

#include "ff_socket_ops.h"

#ifdef FF_USE_RING_IPC

/*
 * Batch dequeue requests from req_ring and invoke handler for each.
 */
uint16_t
ff_ring_process_requests(struct ff_sc_ring_zone *ring_zone,
                         void (*handler)(struct ff_so_context *),
                         uint16_t max_burst)
{
    void *objs[SOCKET_OPS_CONTEXT_MAX_NUM];
    unsigned int nb, i;

    if (ring_zone == NULL || ring_zone->req_ring == NULL) {
        return 0;
    }

    nb = rte_ring_sc_dequeue_burst(ring_zone->req_ring,
        objs, max_burst, NULL);

    for (i = 0; i < nb; i++) {
        handler((struct ff_so_context *)objs[i]);
    }

    return (uint16_t)nb;
}

/*
 * Enqueue processed sc to response ring.
 * If eventfd mode, also write to eventfd to wake up APP.
 */
int
ff_ring_send_response(struct ff_sc_ring_zone *ring_zone,
                      struct ff_so_context *sc)
{
    /* v3.3 H23 fix (D2): notify APP via sc->completion (same cache line as
     * sc->status/result) instead of rsp_ring enqueue. Eliminates the
     * cross-core write to rsp_ring->prod.tail (Self 3.33% in baseline). */
    if (sc == NULL) {
        return -1;
    }

    /* Release: ensure sc->result/error/etc. are visible before completion=1. */
    __atomic_store_n(&sc->completion, 1, __ATOMIC_RELEASE);

    /* EVENTFD mode still needs eventfd write for epoll_wait wakeup,
     * but the rsp_ring enqueue is no longer required for YIELD/BUSY poll. */
    if (ring_zone != NULL &&
        ring_zone->wait_mode == FF_RING_WAIT_EVENTFD &&
        ring_zone->eventfd_rsp >= 0) {
        uint64_t val = 1;
        if (write(ring_zone->eventfd_rsp, &val, sizeof(val)) < 0) {
            ERR_LOG("eventfd_rsp write failed, errno:%d\n", errno);
        }
    }

    return 0;
}

/*
 * Timeout-aware ring dequeue using rte_rdtsc for high-precision timing.
 * Returns 0 on success, -ETIMEDOUT on timeout.
 */
int
ff_ring_dequeue_wait(struct rte_ring *ring, void **obj_p,
                     int64_t timeout_us, uint8_t wait_mode)
{
    uint64_t tsc_hz, timeout_tsc, start_tsc;
    uint32_t spin_count = 0;

    if (ring == NULL || obj_p == NULL) {
        return -EINVAL;
    }

    tsc_hz = rte_get_tsc_hz();
    start_tsc = rte_rdtsc();

    if (timeout_us > 0) {
        timeout_tsc = (uint64_t)timeout_us * tsc_hz / 1000000ULL;
    } else if (timeout_us == 0) {
        /* Non-blocking: single try */
        if (rte_ring_sc_dequeue(ring, obj_p) == 0) {
            return 0;
        }
        return -ETIMEDOUT;
    } else {
        timeout_tsc = UINT64_MAX; /* -1 = wait forever */
    }

    while (rte_ring_sc_dequeue(ring, obj_p) != 0) {
        if (rte_rdtsc() - start_tsc >= timeout_tsc) {
            return -ETIMEDOUT;
        }

        switch (wait_mode) {
        case FF_RING_WAIT_BUSY_POLL:
            rte_pause();
            break;
        case FF_RING_WAIT_YIELD_POLL:
            if ((++spin_count & 0xFF) == 0) {
                sched_yield();
            } else {
                rte_pause();
            }
            break;
        case FF_RING_WAIT_EVENTFD:
            /* Eventfd handled by caller */
            rte_pause();
            break;
        default:
            rte_pause();
            break;
        }
    }

    return 0;
}

/*
 * Wakeup APP by enqueuing a sentinel to rsp_ring.
 * Replaces alarm_event_sem() in ring mode.
 */
void
ff_ring_alarm_wakeup(struct ff_sc_ring_zone *ring_zone,
                     struct ff_so_context *sc)
{
    if (ring_zone == NULL || ring_zone->rsp_ring == NULL || sc == NULL) {
        return;
    }

    /* v3.3 H23 fix (D2): wakeup via sc->completion since APP no longer
     * dequeues rsp_ring. The rsp_ring enqueue below is kept as a no-op
     * fallback for any legacy path that might still poll rsp_ring. */
    __atomic_store_n(&sc->completion, 1, __ATOMIC_RELEASE);

    /* Enqueue sc as sentinel — APP will dequeue and check */
    rte_ring_sp_enqueue(ring_zone->rsp_ring, sc);

    if (ring_zone->wait_mode == FF_RING_WAIT_EVENTFD &&
        ring_zone->eventfd_rsp >= 0) {
        uint64_t val = 1;
        write(ring_zone->eventfd_rsp, &val, sizeof(val));
    }
}

#endif /* FF_USE_RING_IPC */
