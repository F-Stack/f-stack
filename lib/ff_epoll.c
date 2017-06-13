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
    struct kevent kev[3];

    if (!event && op != EPOLL_CTL_DEL) {
        errno = EINVAL;
        return -1;
    }

    if (op == EPOLL_CTL_ADD){
        EV_SET(&kev[0], fd, EVFILT_READ,
            EV_ADD | (event->events & EPOLLIN ? 0 : EV_DISABLE), 0, 0, NULL);
        EV_SET(&kev[1], fd, EVFILT_WRITE,
            EV_ADD | (event->events & EPOLLOUT ? 0 : EV_DISABLE), 0, 0, NULL);
        EV_SET(&kev[2], fd, EVFILT_USER, EV_ADD,
                event->events & EPOLLRDHUP ? 1 : 0, 0, NULL);        
    } else if (op == EPOLL_CTL_DEL) {
        EV_SET(&kev[0], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        EV_SET(&kev[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        EV_SET(&kev[2], fd, EVFILT_USER, EV_DELETE, 0, 0, NULL);
    } else if (op == EPOLL_CTL_MOD) {
        EV_SET(&kev[0], fd, EVFILT_READ,
            event->events & EPOLLIN ? EV_ENABLE : EV_DISABLE, 0, 0, NULL);
        EV_SET(&kev[1], fd, EVFILT_WRITE,
            event->events & EPOLLOUT ? EV_ENABLE : EV_DISABLE, 0, 0, NULL);
        EV_SET(&kev[2], fd, EVFILT_USER, 0,
            NOTE_FFCOPY | (event->events & EPOLLRDHUP ? 1 : 0), 0, NULL);        
    } else {
        errno = EINVAL;
        return -1;
    }

    return ff_kevent(epfd, kev, 3, NULL, 0, NULL);
}

static void 
ff_event_to_epoll(void **ev, struct kevent *kev)
{
    unsigned int event_one = 0;
    struct epoll_event **ppev = (struct epoll_event **)ev;

    if (kev->filter & EVFILT_READ) {
        event_one |= EPOLLIN;
    } 
    if (kev->filter & EVFILT_WRITE) {
        event_one |= EPOLLOUT;
    }

    if (kev->flags & EV_ERROR) {
        event_one |= EPOLLERR;
    }

    if (kev->flags & EV_EOF) {
        event_one |= EPOLLIN;        
    }

    (*ppev)->events   = event_one;
    (*ppev)->data.fd  = kev->ident;
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

