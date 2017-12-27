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

    /*
     * EPOLL_CTL_DEL doesn't need to care for event->events.
     */
    if (op == EPOLL_CTL_DEL) {
        EV_SET(&kev[0], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        EV_SET(&kev[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);

        return ff_kevent(epfd, kev, changes, NULL, 0, NULL);
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

    return ff_kevent(epfd, kev, changes, NULL, 0, NULL);
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
    int i, ret;
    if (!events || maxevents < 1) {
        errno = EINVAL;
        return -1;
    }

    return ff_kevent_do_each(epfd, NULL, 0, events, maxevents, NULL, ff_event_to_epoll);
}

