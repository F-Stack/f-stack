#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#include "ff_api.h"
#include "ff_errno.h"
#ifdef FF_KERNEL_COEXIST
#include "ff_host_interface.h"

/*
 * Kernel-stack coexistence for native epoll (FR-6: unified event loop).
 *
 * ff_epoll_create() still returns an F-Stack kqueue fd. When a managed kernel
 * fd (ff_is_kernel_fd()) is added to such an epoll, a host epoll instance is
 * lazily created and paired with that kqueue fd; kernel fds are registered on
 * the host epoll. ff_epoll_wait() then polls the host epoll non-blocking and
 * merges those events with the F-Stack kqueue events, so a single loop serves
 * both stacks. When no kernel fd is registered, behaviour is unchanged
 * (zero regression).
 */
#define FF_EPOLL_COEXIST_MAX 4
static struct { int kq; int host_ep; } ff_epoll_pairs[FF_EPOLL_COEXIST_MAX];

/* Return the host epoll fd paired with kqueue fd kq; create it lazily when
 * 'create' is non-zero. Returns -1 if none (and create==0) or on failure.
 * Shared with ff_kevent (ff_syscall_wrapper.c) so both event APIs use one
 * host epoll per kqueue. */
int
ff_epoll_host_ep(int kq, int create)
{
    int i, slot = -1, ep = -1;

    for (i = 0; i < FF_EPOLL_COEXIST_MAX; i++) {
        if (ff_epoll_pairs[i].host_ep > 0) {
            if (ff_epoll_pairs[i].kq == kq)
                return ff_epoll_pairs[i].host_ep;
        } else if (slot < 0) {
            slot = i;
        }
    }
    if (create && slot >= 0) {
        ep = ff_host_epoll_create1(0);
        if (ep > 0) {
            ff_epoll_pairs[slot].kq = kq;
            ff_epoll_pairs[slot].host_ep = ep;
        }
    }
    return (ep > 0) ? ep : -1;
}

/* Close and release the host epoll paired with kqueue fd kq (called from
 * ff_close). No-op when there is no pair. */
void
ff_epoll_close_pair(int kq)
{
    int i;

    for (i = 0; i < FF_EPOLL_COEXIST_MAX; i++) {
        if (ff_epoll_pairs[i].host_ep > 0 && ff_epoll_pairs[i].kq == kq) {
            ff_host_close(ff_epoll_pairs[i].host_ep);
            ff_epoll_pairs[i].host_ep = 0;
            ff_epoll_pairs[i].kq = 0;
            break;
        }
    }
}
#endif /* FF_KERNEL_COEXIST */


int
ff_epoll_create(int size __attribute__((__unused__)))
{
    return ff_kqueue();
}

int
ff_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    /*
     * Since kqueue uses EVFILT_READ and EVFILT_WRITE filters to
     * handle read/write events, so we need two kevents.
     */
    const int changes = 2;
    struct kevent kev[changes];
    int flags = 0;
    int read_flags, write_flags;

    if ((!event && op != EPOLL_CTL_DEL) ||
        (op != EPOLL_CTL_ADD &&
         op != EPOLL_CTL_MOD &&
         op != EPOLL_CTL_DEL)) {
        errno = EINVAL;
        return -1;
    }

#ifdef FF_KERNEL_COEXIST
    /*
     * Managed kernel fd: route to the host epoll paired with this kqueue
     * (created lazily on ADD/MOD). The F-Stack path below is unchanged.
     */
    if (ff_is_kernel_fd(fd)) {
        int host_ep = ff_epoll_host_ep(epfd,
            op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD);
        if (host_ep < 0) {
            if (op == EPOLL_CTL_DEL)
                return 0;
            errno = ENOMEM;
            return -1;
        }
        return ff_host_epoll_ctl(host_ep, op, ff_kernel_fd_real(fd), event);
    }

    /*
     * Dual-stack fd: also (un)register the paired host kernel fd on the host
     * epoll, then fall through to register on the F-Stack kqueue below.
     */
    {
        int hfd = ff_native_map_get(fd);
        if (hfd > 0) {
            int host_ep = ff_epoll_host_ep(epfd,
                op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD);
            if (host_ep > 0)
                ff_host_epoll_ctl(host_ep, op, hfd, event);
        }
    }
#endif /* FF_KERNEL_COEXIST */

    /*
     * EPOLL_CTL_DEL doesn't need to care for event->events.
     */
    if (op == EPOLL_CTL_DEL) {
        EV_SET(&kev[0], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        EV_SET(&kev[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);

#ifdef FF_KERNEL_COEXIST
        /* Host (un)registration handled above; bypass coexist-aware ff_kevent. */
        return ff_kevent_do_each(epfd, kev, changes, NULL, 0, NULL, NULL);
#else
        return ff_kevent(epfd, kev, changes, NULL, 0, NULL);
#endif
    }

    /*
     * FIXME:
     *
     * Kqueue doesn't have edge-triggered mode that exactly
     * same with epoll, the most similar way is setting EV_CLEAR
     * or EV_DISPATCH flag, but there are still some differences.
     *
     * EV_CLEAR:after the event is retrieved by the user,
     *    its state is reset.
     * EV_DISPATCH: disable the event source immediately
     *    after delivery of an event.
     *
     * Here we use EV_CLEAR temporarily.
     *
     */
    if (event->events & EPOLLET) {
        flags |= EV_CLEAR;
    }

    if (event->events & EPOLLONESHOT) {
        flags |= EV_ONESHOT;
    }

    if (op == EPOLL_CTL_ADD) {
        flags |= EV_ADD;
    }

    read_flags = write_flags = flags | EV_DISABLE;

    if (event->events & EPOLLIN) {
        read_flags &= ~EV_DISABLE;
        read_flags |= EV_ENABLE;
    }

    if (event->events & EPOLLOUT) {
        write_flags &= ~EV_DISABLE;
        write_flags |= EV_ENABLE;
    }

    // Fix #124: set user data
    EV_SET(&kev[0], fd, EVFILT_READ, read_flags, 0, 0, event->data.ptr);
    EV_SET(&kev[1], fd, EVFILT_WRITE, write_flags, 0, 0, event->data.ptr);

#ifdef FF_KERNEL_COEXIST
    /* Host (un)registration handled above; bypass coexist-aware ff_kevent. */
    return ff_kevent_do_each(epfd, kev, changes, NULL, 0, NULL, NULL);
#else
    return ff_kevent(epfd, kev, changes, NULL, 0, NULL);
#endif
}

static void
ff_event_to_epoll(void **ev, struct kevent *kev)
{
    unsigned int event_one = 0;
    struct epoll_event **ppev = (struct epoll_event **)ev;

    if (kev->filter == EVFILT_READ) {
        if (kev->data || !(kev->flags & EV_EOF)) {
            event_one |= EPOLLIN;
        }
    } else if (kev->filter == EVFILT_WRITE) {
        event_one |= EPOLLOUT;
    }

    if (kev->flags & EV_ERROR) {
        event_one |= EPOLLERR;
    }

    if (kev->flags & EV_EOF) {
        event_one |= EPOLLHUP;

        if (kev->fflags) {
            event_one |= EPOLLERR;
        }

        if (kev->filter == EVFILT_READ) {
            event_one |= EPOLLIN;
        } else if (kev->filter == EVFILT_WRITE) {
            event_one |= EPOLLERR;
        }
    }

    (*ppev)->events   = event_one;
    // Fix #124: get user data
    if (kev->udata != NULL)
        (*ppev)->data.ptr  = kev->udata;
    else
        (*ppev)->data.fd = kev->ident;
    (*ppev)++;
}

int
ff_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
#ifdef FF_KERNEL_COEXIST
    int kn = 0, host_ep, rc;
#endif
    (void)timeout;
    if (!events || maxevents < 1) {
        errno = EINVAL;
        return -1;
    }

#ifdef FF_KERNEL_COEXIST
    /*
     * Coexistence: if a host epoll is paired with this kqueue, poll the
     * kernel-stack events non-blocking first, then merge the F-Stack kqueue
     * events into the remaining slots. When no kernel fd was registered
     * (host_ep < 0), this degrades to the original kqueue-only behaviour.
     */
    host_ep = ff_epoll_host_ep(epfd, 0);
    if (host_ep > 0) {
        kn = ff_host_epoll_wait(host_ep, events, maxevents, 0);
        if (kn < 0)
            kn = 0;
        if (kn >= maxevents)
            return kn;
    }

    rc = ff_kevent_do_each(epfd, NULL, 0, events + kn, maxevents - kn, NULL,
        ff_event_to_epoll);
    if (rc < 0)
        return kn > 0 ? kn : -1;

    return kn + rc;
#else
    return ff_kevent_do_each(epfd, NULL, 0, events, maxevents, NULL,
        ff_event_to_epoll);
#endif /* FF_KERNEL_COEXIST */
}

