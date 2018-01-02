#ifndef _FF_EPOLL_H
#define _FF_EPOLL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/epoll.h>

int ff_epoll_create(int size);
int ff_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int ff_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);

#ifdef __cplusplus
}
#endif

#endif

