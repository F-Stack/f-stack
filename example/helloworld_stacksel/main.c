/*
 * helloworld_stacksel -- demonstrate F-Stack + host kernel-stack COEXISTENCE
 * in native ff_api mode.
 *
 * Correct paradigm (v4): the application runs ON F-Stack. Business sockets use
 * the F-Stack user-space stack (default / SOCK_FSTACK). A socket created with
 * SOCK_KERNEL (when [stack] kernel_coexist=1) additionally uses the host Linux
 * kernel stack, so local ping/curl can reach it and the app can connect() to
 * local/external kernel-stack services. Both stacks coexist in the SAME
 * process and a single ff_epoll loop. F-Stack is NEVER bypassed.
 *
 * Modes:
 *   (no args)        selftest: kernel-stack loopback server+client via
 *                    ff_socket(SOCK_KERNEL). This exercises the native managed
 *                    kernel-fd path (ff_socket/bind/listen/accept/connect/
 *                    send/recv/close) and needs NO DPDK/EAL runtime, so it can
 *                    run anywhere.
 *   bench <port>     kernel-stack HTTP keep-alive server returning a fixed
 *                    preset body, driven by host epoll (ff_host_epoll_*), for
 *                    the PERF-3 kernel-side throughput baseline. Also EAL-free.
 *
 * Full coexistence (F-Stack business listener + SOCK_KERNEL kernel listener +
 * merged ff_epoll) additionally requires ff_init()/ff_run() and a working DPDK
 * data plane (NIC/hugepages); see docs/kernel_event_support_spec for the
 * design and the integration-test plan.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <stdint.h>

#include "ff_api.h"      /* ff_socket + SOCK_KERNEL / SOCK_FSTACK markers */
#include "ff_config.h"   /* ff_global_cfg: enable coexistence without ff_init */
#include "ff_host_interface.h" /* ff_host_epoll_* + managed kernel-fd encode/real */
#include "ff_epoll.h"    /* ff_epoll_* for the dualstack (ff_init/ff_run) demo */

#define KPORT 18399

/* Create a kernel-stack socket via the single F-Stack API + SOCK_KERNEL.
 * Returns a managed kernel fd (opaque; use only with ff_* calls). */
static int
ksock(void)
{
    int fd = ff_socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0);
    if (fd < 0)
        perror("ff_socket(SOCK_KERNEL)");
    return fd;
}

static void
fill_loopback(struct sockaddr_in *sa, int port)
{
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa->sin_port = htons((unsigned short)port);
}

/* Child: kernel-stack client connecting to the loopback server. */
static int
run_client(int port)
{
    struct sockaddr_in sa;
    char buf[64];
    int c = ksock();
    if (c < 0)
        return 1;

    fill_loopback(&sa, port);
    if (ff_connect(c, (struct linux_sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("ff_connect");
        ff_close(c);
        return 1;
    }

    /* R8: exercise getpeername/getsockname on the kernel fd. */
    struct sockaddr_in pn;
    socklen_t pnlen = sizeof(pn);
    if (ff_getpeername(c, (struct linux_sockaddr *)&pn, &pnlen) < 0 ||
        ntohs(pn.sin_port) != (unsigned short)port) {
        fprintf(stderr, "client: ff_getpeername mismatch\n");
        ff_close(c);
        return 1;
    }
    pnlen = sizeof(pn);
    if (ff_getsockname(c, (struct linux_sockaddr *)&pn, &pnlen) < 0) {
        perror("ff_getsockname");
        ff_close(c);
        return 1;
    }

    /* R8: send via ff_sendmsg. */
    struct iovec io = { (void *)"ping", 4 };
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov = &io;
    mh.msg_iovlen = 1;
    if (ff_sendmsg(c, &mh, 0) != 4) {
        perror("ff_sendmsg");
        ff_close(c);
        return 1;
    }
    ssize_t n = ff_recv(c, buf, sizeof(buf), 0);
    ff_close(c);
    if (n == 4 && memcmp(buf, "pong", 4) == 0)
        return 0;
    fprintf(stderr, "client: unexpected reply (n=%zd)\n", n);
    return 1;
}

/* Parent: kernel-stack server, accept one connection and echo ping->pong. */
static int
run_server_once(int lfd)
{
    char buf[64];
    int c = ff_accept(lfd, NULL, NULL);
    if (c < 0) {
        perror("ff_accept");
        return 1;
    }

    /* R8: getpeername/getsockname on the accepted kernel fd. */
    struct sockaddr_in pn;
    socklen_t pnlen = sizeof(pn);
    if (ff_getpeername(c, (struct linux_sockaddr *)&pn, &pnlen) < 0 ||
        ff_getsockname(c, (struct linux_sockaddr *)&pn, &pnlen) < 0) {
        perror("ff_get*name");
        ff_close(c);
        return 1;
    }

    /* R8: receive via ff_recvmsg. */
    struct iovec io = { buf, sizeof(buf) };
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov = &io;
    mh.msg_iovlen = 1;
    ssize_t n = ff_recvmsg(c, &mh, 0);
    if (n == 4 && memcmp(buf, "ping", 4) == 0)
        ff_send(c, "pong", 4, 0);

    /* R8: half-close the write side via ff_shutdown. */
    ff_shutdown(c, SHUT_WR);
    ff_close(c);
    return (n == 4) ? 0 : 1;
}

static int
do_selftest(void)
{
    struct sockaddr_in sa;
    int on = 1;
    int lfd, rc;
    pid_t pid;

    /* Enable kernel-stack coexistence for this process (in a real deployment
     * this comes from config.ini [stack] kernel_coexist=1 via ff_init). */
    ff_global_cfg.stack.kernel_coexist = 1;

    lfd = ksock();
    if (lfd < 0)
        return 1;
    ff_setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    fill_loopback(&sa, KPORT);
    if (ff_bind(lfd, (struct linux_sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("ff_bind");
        ff_close(lfd);
        return 1;
    }
    if (ff_listen(lfd, 8) < 0) {
        perror("ff_listen");
        ff_close(lfd);
        return 1;
    }

    pid = fork();
    if (pid == 0) {
        /* child: give the parent a moment to reach accept() */
        usleep(100 * 1000);
        _exit(run_client(KPORT));
    }

    rc = run_server_once(lfd);
    ff_close(lfd);

    int cstatus = 1;
    if (pid > 0) {
        int st;
        waitpid(pid, &st, 0);
        if (WIFEXITED(st))
            cstatus = WEXITSTATUS(st);
    }

    if (rc == 0 && cstatus == 0) {
        printf("COEXIST SELFTEST PASS: native ff_socket(SOCK_KERNEL) "
               "kernel-stack server+client over loopback\n");
        return 0;
    }
    printf("COEXIST SELFTEST FAIL: server_rc=%d client_rc=%d\n", rc, cstatus);
    return 1;
}

/* Preset HTTP/1.1 keep-alive response, fixed 15-byte body. */
static char http_resp[] =
"HTTP/1.1 200 OK\r\n"
"Server: F-Stack-kernel-coexist\r\n"
"Content-Type: text/plain\r\n"
"Content-Length: 15\r\n"
"Connection: keep-alive\r\n"
"\r\n"
"kernel-coexist\n";

static int
set_nonblock(int fd)
{
    int fl = ff_fcntl(fd, F_GETFL, 0);
    if (fl < 0)
        return -1;
    return ff_fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* PERF-3 kernel-side bench: SOCK_KERNEL listener + host-epoll event loop,
 * HTTP keep-alive returning the preset body. No ff_init / EAL. */
static int
do_bench(int port)
{
    struct sockaddr_in sa;
    struct epoll_event ev, evs[512];
    int on = 1;
    int lfd, epfd, rlfd, i;

    ff_global_cfg.stack.kernel_coexist = 1;

    lfd = ksock();
    if (lfd < 0)
        return 1;
    ff_setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons((unsigned short)port);
    if (ff_bind(lfd, (struct linux_sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("ff_bind");
        ff_close(lfd);
        return 1;
    }
    if (ff_listen(lfd, 1024) < 0) {
        perror("ff_listen");
        ff_close(lfd);
        return 1;
    }
    set_nonblock(lfd);

    epfd = ff_host_epoll_create1(0);
    if (epfd < 0) {
        perror("ff_host_epoll_create1");
        ff_close(lfd);
        return 1;
    }
    rlfd = ff_kernel_fd_real(lfd);
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = rlfd;
    ff_host_epoll_ctl(epfd, EPOLL_CTL_ADD, rlfd, &ev);

    printf("COEXIST BENCH: kernel-stack HTTP keep-alive server on 0.0.0.0:%d\n", port);
    fflush(stdout);

    for (;;) {
        int n = ff_host_epoll_wait(epfd, evs, 512, -1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            perror("ff_host_epoll_wait");
            break;
        }
        for (i = 0; i < n; i++) {
            int rfd = evs[i].data.fd;
            if (rfd == rlfd) {
                for (;;) {
                    int c = ff_accept(lfd, NULL, NULL);
                    if (c < 0)
                        break;
                    set_nonblock(c);
                    memset(&ev, 0, sizeof(ev));
                    ev.events = EPOLLIN;
                    ev.data.fd = ff_kernel_fd_real(c);
                    ff_host_epoll_ctl(epfd, EPOLL_CTL_ADD, ev.data.fd, &ev);
                }
            } else if (evs[i].events & (EPOLLHUP | EPOLLERR)) {
                ff_host_epoll_ctl(epfd, EPOLL_CTL_DEL, rfd, NULL);
                ff_close(ff_kernel_fd_encode(rfd));
            } else {
                char buf[2048];
                int cfd = ff_kernel_fd_encode(rfd);
                ssize_t r = ff_recv(cfd, buf, sizeof(buf), 0);
                if (r > 0) {
                    ff_send(cfd, http_resp, sizeof(http_resp) - 1, 0);
                } else if (r == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
                    ff_host_epoll_ctl(epfd, EPOLL_CTL_DEL, rfd, NULL);
                    ff_close(cfd);
                }
            }
        }
    }

    ff_close(lfd);
    return 0;
}

/*
 * Dualstack demo (needs ff_init + a working DPDK data plane). A single plain
 * listen socket (no marker) is, with [stack] kernel_coexist=1 and the lib built
 * with FF_KERNEL_COEXIST, served on BOTH the F-Stack user-space stack (via the
 * DPDK NIC) and the host Linux kernel stack (reachable via 127.0.0.1) from the
 * same ff_epoll loop. Port comes from $FF_DUALSTACK_PORT.
 */
static int g_dual_lfd;
static int g_dual_epfd;

static int
dual_loop(void *arg)
{
    struct epoll_event evs[512];
    int n, i;

    (void)arg;
    n = ff_epoll_wait(g_dual_epfd, evs, 512, 0);
    for (i = 0; i < n; i++) {
        if (evs[i].data.fd == g_dual_lfd) {
            for (;;) {
                int c = ff_accept(g_dual_lfd, NULL, NULL);
                struct epoll_event ce;
                if (c < 0)
                    break;
                set_nonblock(c);
                memset(&ce, 0, sizeof(ce));
                ce.events = EPOLLIN;
                ce.data.fd = c;
                ff_epoll_ctl(g_dual_epfd, EPOLL_CTL_ADD, c, &ce);
            }
        } else {
            int cfd = evs[i].data.fd;
            char buf[2048];
            ssize_t r = ff_recv(cfd, buf, sizeof(buf), 0);
            if (r > 0) {
                ff_send(cfd, http_resp, sizeof(http_resp) - 1, 0);
            } else if (r == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
                ff_epoll_ctl(g_dual_epfd, EPOLL_CTL_DEL, cfd, NULL);
                ff_close(cfd);
            }
        }
    }
    return 0;
}

static int
do_dualstack(int argc, char **argv, int port)
{
    struct sockaddr_in sa;
    struct epoll_event ev;
    int on = 1;

    ff_init(argc, argv);

    g_dual_lfd = ff_socket(AF_INET, SOCK_STREAM, 0);   /* no marker -> dual stack */
    if (g_dual_lfd < 0) {
        perror("ff_socket");
        return 1;
    }
    ff_setsockopt(g_dual_lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    set_nonblock(g_dual_lfd);

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons((unsigned short)port);
    if (ff_bind(g_dual_lfd, (struct linux_sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("ff_bind");
        return 1;
    }
    if (ff_listen(g_dual_lfd, 1024) < 0) {
        perror("ff_listen");
        return 1;
    }

    g_dual_epfd = ff_epoll_create(1);
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = g_dual_lfd;
    ff_epoll_ctl(g_dual_epfd, EPOLL_CTL_ADD, g_dual_lfd, &ev);

    printf("COEXIST DUALSTACK: single listen on :%d served by F-Stack + kernel\n", port);
    fflush(stdout);

    ff_run(dual_loop, NULL);
    return 0;
}

int
main(int argc, char **argv)
{
    char *p;

    if (argc >= 3 && strcmp(argv[1], "bench") == 0)
        return do_bench(atoi(argv[2]));
    p = getenv("FF_DUALSTACK_PORT");
    if (p != NULL)
        return do_dualstack(argc, argv, atoi(p));
    return do_selftest();
}
