#include <rte_memcpy.h>
#include <rte_spinlock.h>

#include "ff_socket_ops.h"
#include "ff_sysproto.h"
#include "ff_api.h"
#include "ff_epoll.h"
#include "ff_config.h"

#undef FF_SYSCALL_DECL
#define FF_SYSCALL_DECL(ret, fn, none) \
    static ret ff_sys_##fn(struct ff_##fn##_args *args);
#include <ff_declare_syscalls.h>
static int ff_sys_kqueue(struct ff_kqueue_args *args);
static int ff_sys_kevent(struct ff_kevent_args *args);

#define FF_MAX_BOUND_NUM 8

/* Where to call sem_post in kevent or epoll_wait */
static int sem_flag = 0;

/*
 * The event num kevent or epoll_wait returned.
 * Use for burst process event in one F-Stack loop to improve performance.
 */
#define EVENT_LOOP_TIMES    32
static int ff_event_loop_nb = 0;
//static int ff_next_event_flag = 0;

struct ff_bound_info {
    int fd;
    struct sockaddr addr;
};

static struct ff_bound_info ff_bound_fds[FF_MAX_BOUND_NUM];

static int
sockaddr_cmp(struct sockaddr *a, struct sockaddr *b)
{
    struct sockaddr_in *sina, *sinb;
    sina = (struct sockaddr_in *)a;
    sinb = (struct sockaddr_in *)b;

    if (sina->sin_family != sinb->sin_family) {
        return 1;
    }

    if (sina->sin_port != sinb->sin_port) {
        return 1;
    }

    if (sina->sin_addr.s_addr != sinb->sin_addr.s_addr) {
        return 1;
    }

    return 0;
}

static int
sockaddr_is_bound(struct sockaddr *addr)
{
    int i;

    for (i = 0; i < FF_MAX_BOUND_NUM; i++) {
        struct ff_bound_info *info = &ff_bound_fds[i];
        if (info->fd == 0) {
            continue;
        }

        if (sockaddr_cmp(&info->addr, addr) == 0) {
            return info->fd;
        }
    }

    return 0;
}

static int
sockaddr_bind(int fd, struct sockaddr *addr)
{
    int i;

    for (i = 0; i < FF_MAX_BOUND_NUM; i++) {
        struct ff_bound_info *info = &ff_bound_fds[i];
        if (info->fd != 0) {
            continue;
        }

        info->fd = fd;
        rte_memcpy(&info->addr, addr, sizeof(struct sockaddr));

        return 0;
    }

    return -1;
}

static int
sockaddr_unbind(int fd)
{
    int i;

    for (i = 0; i < FF_MAX_BOUND_NUM; i++) {
        struct ff_bound_info *info = &ff_bound_fds[i];
        if (info->fd != fd) {
            continue;
        }

        info->fd = 0;

        return 0;
    }

    return -1;
}

static int
ff_sys_socket(struct ff_socket_args *args)
{
    return ff_socket(args->domain, args->type, args->protocol);
}

static int
ff_sys_bind(struct ff_bind_args *args)
{
    int bound_fd;
    int ret;

    bound_fd = sockaddr_is_bound(args->addr);
    if (bound_fd != 0 && bound_fd != args->fd) {
        return ff_dup2(bound_fd, args->fd);
    }

    ret = ff_bind(args->fd, args->addr, args->addrlen);
    if (ret == 0) {
        sockaddr_bind(args->fd, args->addr);
    }

    return ret;
}

static int
ff_sys_listen(struct ff_listen_args *args)
{
    return ff_listen(args->fd, args->backlog);
}

static int
ff_sys_shutdown(struct ff_shutdown_args *args)
{
    return ff_shutdown(args->fd, args->how);
}

static int
ff_sys_getsockname(struct ff_getsockname_args *args)
{
    return ff_getsockname(args->fd, args->name, args->namelen);
}

static int
ff_sys_getpeername(struct ff_getpeername_args *args)
{
    return ff_getpeername(args->fd, args->name, args->namelen);
}

static int
ff_sys_getsockopt(struct ff_getsockopt_args *args)
{
    return ff_getsockopt(args->fd, args->level, args->name,
        args->optval, args->optlen);
}

static int
ff_sys_setsockopt(struct ff_setsockopt_args *args)
{
    return ff_setsockopt(args->fd, args->level, args->name,
        args->optval, args->optlen);
}

static int
ff_sys_accept(struct ff_accept_args *args)
{
    return ff_accept(args->fd, args->addr, args->addrlen);
}

static int
ff_sys_accept4(struct ff_accept4_args *args)
{
    errno = ENOSYS;
    return -1;
}

static int
ff_sys_connect(struct ff_connect_args *args)
{
    return ff_connect(args->fd, args->addr, args->addrlen);
}

static ssize_t
ff_sys_recv(struct ff_recv_args *args)
{
    return ff_recv(args->fd, args->buf, args->len, args->flags);
}

static ssize_t
ff_sys_recvfrom(struct ff_recvfrom_args *args)
{
    return ff_recvfrom(args->fd, args->buf, args->len, args->flags,
        args->from, args->fromlen);
}

static ssize_t
ff_sys_recvmsg(struct ff_recvmsg_args *args)
{
    return ff_recvmsg(args->fd, args->msg, args->flags);
}

static ssize_t
ff_sys_read(struct ff_read_args *args)
{
    DEBUG_LOG("ff_sys_read, fd:%d, len:%lu\n", args->fd, args->len);
    return ff_read(args->fd, args->buf, args->len);
}

static ssize_t
ff_sys_readv(struct ff_readv_args *args)
{
    return ff_readv(args->fd, args->iov, args->iovcnt);
}

static ssize_t
ff_sys_send(struct ff_send_args *args)
{
    return ff_send(args->fd, args->buf, args->len, args->flags);
}

static ssize_t
ff_sys_sendto(struct ff_sendto_args *args)
{
    return ff_sendto(args->fd, args->buf, args->len, args->flags,
        args->to, args->tolen);
}

static ssize_t
ff_sys_sendmsg(struct ff_sendmsg_args *args)
{
    return ff_sendmsg(args->fd, args->msg, args->flags);
}

static ssize_t
ff_sys_write(struct ff_write_args *args)
{
    DEBUG_LOG("ff_sys_write, fd:%d, len:%lu\n", args->fd, args->len);
    return ff_write(args->fd, args->buf, args->len);
}

static ssize_t
ff_sys_writev(struct ff_writev_args *args)
{
    return ff_writev(args->fd, args->iov, args->iovcnt);
}

static int
ff_sys_close(struct ff_close_args *args)
{
    DEBUG_LOG("ff_sys_close, fd:%d\n", args->fd);
    sockaddr_unbind(args->fd);
    return ff_close(args->fd);
}

static int
ff_sys_ioctl(struct ff_ioctl_args *args)
{
    return ff_ioctl(args->fd, args->com, args->data);
}

static int
ff_sys_fcntl(struct ff_fcntl_args *args)
{
    return ff_fcntl(args->fd, args->cmd, args->data);
}

static int
ff_sys_epoll_create(struct ff_epoll_create_args *args)
{
    DEBUG_LOG("to run ff_epoll_create, size:%d\n", args->size);
    return ff_epoll_create(args->size);
}

static int
ff_sys_epoll_ctl(struct ff_epoll_ctl_args *args)
{
    DEBUG_LOG("to run ff_epoll_ctl, epfd:%d, op:%d, fd:%d\n",
        args->epfd, args->op, args->fd);
    return ff_epoll_ctl(args->epfd, args->op, args->fd,
        args->event);
}

static int
ff_sys_epoll_wait(struct ff_epoll_wait_args *args)
{
    int ret;

    DEBUG_LOG("to run ff_epoll_wait, epfd:%d, maxevents:%d, timeout:%d\n",
        args->epfd, args->maxevents, args->timeout);
    ret = ff_epoll_wait(args->epfd, args->events,
        args->maxevents, args->timeout);

    /*
     * If timeout is 0, and no event triggered,
     * no post sem, and next loop will continue to call ff_sys_epoll_wait,
     * until some event triggered
     */
    if (args->timeout == 0 && ret == 0 && args->maxevents != 0) {
        sem_flag = 0;
    } else {
        sem_flag = 1;
    }

    return ret;
}

static int
ff_sys_kqueue(struct ff_kqueue_args *args)
{
    return ff_kqueue();
}

static int
ff_sys_kevent(struct ff_kevent_args *args)
{
    int ret;

    ret = ff_kevent(args->kq, args->changelist, args->nchanges,
        args->eventlist, args->nevents, args->timeout);

    if (args->nchanges) {
        args->nchanges = 0;
    }

    /*
     * If timeout is NULL, and no event triggered,
     * no post sem, and next loop will continue to call ff_sys_kevent,
     * until some event triggered
     */
    if (args->timeout == NULL && ret == 0 && args->nevents != 0) {
        sem_flag = 0;
    } else {
        sem_flag = 1;
    }

    return ret;
}

static pid_t
ff_sys_fork(struct ff_fork_args *args)
{
    errno = ENOSYS;
    return -1;
}

static int
ff_so_handler(int ops, void *args)
{
    DEBUG_LOG("ff_so_handler ops:%d, epoll create ops:%d\n", ops, FF_SO_EPOLL_CREATE);
    switch(ops) {
        case FF_SO_SOCKET:
            return ff_sys_socket((struct ff_socket_args *)args);
        case FF_SO_BIND:
            return ff_sys_bind((struct ff_bind_args *)args);
        case FF_SO_LISTEN:
            return ff_sys_listen((struct ff_listen_args *)args);
        case FF_SO_CONNECT:
            return ff_sys_connect((struct ff_connect_args *)args);
        case FF_SO_SHUTDOWN:
            return ff_sys_shutdown((struct ff_shutdown_args *)args);
        case FF_SO_GETSOCKNAME:
            return ff_sys_getsockname((struct ff_getsockname_args *)args);
        case FF_SO_GETPEERNAME:
            return ff_sys_getpeername((struct ff_getpeername_args *)args);
        case FF_SO_GETSOCKOPT:
            return ff_sys_getsockopt((struct ff_getsockopt_args *)args);
        case FF_SO_SETSOCKOPT:
            return ff_sys_setsockopt((struct ff_setsockopt_args *)args);
        case FF_SO_ACCEPT:
            return ff_sys_accept((struct ff_accept_args *)args);
        case FF_SO_ACCEPT4:
            return ff_sys_accept4((struct ff_accept4_args *)args);
        case FF_SO_RECV:
            return ff_sys_recv((struct ff_recv_args *)args);
        case FF_SO_RECVFROM:
            return ff_sys_recvfrom((struct ff_recvfrom_args *)args);
        case FF_SO_RECVMSG:
            return ff_sys_recvmsg((struct ff_recvmsg_args *)args);
        case FF_SO_READ:
            return ff_sys_read((struct ff_read_args *)args);
        case FF_SO_READV:
            return ff_sys_readv((struct ff_readv_args *)args);
        case FF_SO_SEND:
            return ff_sys_send((struct ff_send_args *)args);
        case FF_SO_SENDTO:
            return ff_sys_sendto((struct ff_sendto_args *)args);
        case FF_SO_SENDMSG:
            return ff_sys_sendmsg((struct ff_sendmsg_args *)args);
        case FF_SO_WRITE:
            return ff_sys_write((struct ff_write_args *)args);
        case FF_SO_WRITEV:
            return ff_sys_writev((struct ff_writev_args *)args);
        case FF_SO_CLOSE:
            return ff_sys_close((struct ff_close_args *)args);
        case FF_SO_IOCTL:
            return ff_sys_ioctl((struct ff_ioctl_args *)args);
        case FF_SO_FCNTL:
            return ff_sys_fcntl((struct ff_fcntl_args *)args);
        case FF_SO_EPOLL_CREATE:
            return ff_sys_epoll_create((struct ff_epoll_create_args *)args);
        case FF_SO_EPOLL_CTL:
            return ff_sys_epoll_ctl((struct ff_epoll_ctl_args *)args);
        case FF_SO_EPOLL_WAIT:
            return ff_sys_epoll_wait((struct ff_epoll_wait_args *)args);
        case FF_SO_KQUEUE:
            return ff_sys_kqueue((struct ff_kqueue_args *)args);
        case FF_SO_KEVENT:
            return ff_sys_kevent((struct ff_kevent_args *)args);
        case FF_SO_FORK:
            return ff_sys_fork((struct ff_fork_args *)args);
        default:
            break;
    }

    errno = EINVAL;
    DEBUG_LOG("ff_so_handler error:%d, ops:%d\n", errno, ops);
    return (-1);
}

static inline void
ff_handle_socket_ops(struct ff_so_context *sc)
{
    if (!rte_spinlock_trylock(&sc->lock)) {
        return;
    }

    if (sc->status != FF_SC_REQ) {
        rte_spinlock_unlock(&sc->lock);
        return;
    }

    DEBUG_LOG("ff_handle_socket_ops sc:%p, status:%d, ops:%d\n", sc, sc->status, sc->ops);

    errno = 0;
    sc->result = ff_so_handler(sc->ops, sc->args);
    sc->error = errno;
    DEBUG_LOG("ff_handle_socket_ops error:%d, ops:%d, result:%d\n", errno, sc->ops, sc->result);

    if (sc->ops == FF_SO_EPOLL_WAIT || sc->ops == FF_SO_KEVENT) {
        /*DEBUG_LOG("ff_event_loop_nb:%d, ff_next_event_flag:%d\n",
                   ff_event_loop_nb, ff_next_event_flag);
        if (ff_event_loop_nb > 0) {
            ff_next_event_flag = 1;
        } else {
            ff_next_event_flag = 0;
        }

        if (sc->result > 0) {
            ff_event_loop_nb = (sc->result * EVENT_LOOP_TIMES);
        } else {
            ff_event_loop_nb = 0;
        }*/

        if (sem_flag == 1) {
            sc->status = FF_SC_REP;
            sem_post(&sc->wait_sem);
        } else {
            // do nothing with this sc
        }
    } else {
        sc->status = FF_SC_REP;
    }

    rte_spinlock_unlock(&sc->lock);
}

void
ff_handle_each_context()
{
    uint16_t i, nb_handled, tmp;
    static uint64_t loop_count = 0;
    static uint64_t cur_tsc, diff_tsc, drain_tsc = 0;

    if (unlikely(drain_tsc == 0 && ff_global_cfg.dpdk.pkt_tx_delay)) {
        drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * ff_global_cfg.dpdk.pkt_tx_delay;
        ERR_LOG("ff_global_cfg.dpdk.handle_sc_delay%d, drain_tsc:%lu\n",
                        ff_global_cfg.dpdk.pkt_tx_delay, drain_tsc);
    }

    ff_event_loop_nb = 0;

    cur_tsc = rte_rdtsc();

    rte_spinlock_lock(&ff_so_zone->lock);

    assert(ff_so_zone->count >= ff_so_zone->free);
    tmp = nb_handled = ff_so_zone->count - ff_so_zone->free;

    while(1) {
        nb_handled = tmp;
        if (nb_handled) {
            for (i = 0; i < ff_so_zone->count; i++) {
                struct ff_so_context *sc = &ff_so_zone->sc[i];

                if ((loop_count & 1048575) == 0) {
                    DEBUG_LOG("so:%p, so->count:%d,%p, sc:%p, sc->inuse:%d,%p, i:%d, nb:%d, all_nb:%d\n",
                        ff_so_zone, ff_so_zone->count, &ff_so_zone->count,
                        sc, ff_so_zone->inuse[i], &ff_so_zone->inuse[i], i, nb_handled, tmp);
                }

                if (ff_so_zone->inuse[i] == 0) {
                    continue;
                }

                /* Dirty read first, and then try to lock sc and real read. */
                if (sc->status == FF_SC_REQ) {
                    ff_handle_socket_ops(sc);
                }

                nb_handled--;
                if (!nb_handled) {
                    break;
                }
            }
        }

        /*if (--ff_event_loop_nb <= 0 || ff_next_event_flag == 1) {
            break;
        }*/
        diff_tsc = rte_rdtsc() - cur_tsc;
        DEBUG_LOG("cur_tsc:%lu, diff_tsc:%lu, drain_tsc:%lu\n", cur_tsc, diff_tsc, drain_tsc);
        if (diff_tsc >= drain_tsc) {
            break;
        }

        rte_pause();
    }

    rte_spinlock_unlock(&ff_so_zone->lock);

    loop_count++;

    DEBUG_LOG("loop_count:%lu, nb:%d, all_nb:%d\n",
        loop_count, nb_handled, tmp/*, ff_event_loop_nb, ff_next_event_flag*/);
    //, ff_event_loop_nb:%d, ff_next_event_flag:%d
}

