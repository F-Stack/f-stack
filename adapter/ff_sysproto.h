#ifndef _FF_SYSPROTO_H_
#define _FF_SYSPROTO_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <time.h>

struct ff_socket_args {
    int domain;
    int type;
    int protocol;
};

struct ff_bind_args {
    int fd;
    void *addr;
    int addrlen;
};

struct ff_listen_args {
    int fd;
    int backlog;
};

struct ff_shutdown_args {
    int fd;
    int how;
};

struct ff_getpeername_args {
    int fd;
    void *name;
    socklen_t *namelen;
};

struct ff_getsockname_args {
    int fd;
    void *name;
    socklen_t *namelen;
};

struct ff_setsockopt_args {
    int fd;
    int level;
    int name;
    void *optval;
    socklen_t optlen;
};

struct ff_getsockopt_args {
    int fd;
    int level;
    int name;
    void *optval;
    socklen_t *optlen;
};

struct ff_accept_args {
    int fd;
    void *addr;
    socklen_t *addrlen;
};

struct ff_accept4_args {
    int fd;
    void *addr;
    socklen_t *addrlen;
    int flags;
};

struct ff_connect_args {
    int fd;
    void *addr;
    int addrlen;
};

struct ff_recv_args {
    int fd;
    void *buf;
    size_t len;
    int flags;
};

struct ff_recvfrom_args {
    int fd;
    void *buf;
    size_t len;
    int flags;
    void *from;
    socklen_t *fromlen;
};

struct ff_recvmsg_args {
    int fd;
    struct msghdr *msg;
    int flags;
};

struct ff_read_args {
    int fd;
    void *buf;
    size_t len;
};

struct ff_readv_args {
    int fd;
    struct iovec *iov;
    int iovcnt;
};

struct ff_send_args {
    int fd;
    void *buf;
    size_t len;
    int flags;
};

struct ff_sendto_args {
    int fd;
    void *buf;
    size_t len;
    int flags;
    void *to;
    int tolen;
};

struct ff_sendmsg_args {
    int fd;
    struct msghdr * msg;
    int flags;
};

struct ff_write_args {
    int fd;
    void *buf;
    size_t len;
};

struct ff_writev_args {
    int fd;
    struct iovec *iov;
    int iovcnt;
};

struct ff_close_args {
    int fd;
};

struct ff_ioctl_args {
    int fd;
    unsigned long com;
    void *data;
};

struct ff_fcntl_args {
    int fd;
    int cmd;
    long data;
};

struct ff_epoll_create_args {
    int size;
};

struct ff_epoll_ctl_args {
    int epfd;
    int op;
    int fd;
    struct epoll_event *event;
};

struct ff_epoll_wait_args {
    int epfd;
    struct epoll_event *events;
    int maxevents;
    int timeout;
};

struct ff_kqueue_args {

};

struct ff_kevent_args {
    int kq;
    struct kevent *changelist;
    int nchanges;
    struct kevent *eventlist;
    int nevents;
    struct timespec *timeout;
};

struct ff_fork_args {

};

#endif
