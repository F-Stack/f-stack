/*
 * helloworld_stacksel — demonstrate connection-level stack selection.
 *
 * It uses the SINGLE F-Stack API (ff_socket) plus the standardized
 * SOCK_KERNEL / SOCK_FSTACK markers to choose, per socket, whether a fd
 * lives on the host Linux kernel stack or the F-Stack user-space stack.
 *
 * Sockets created with SOCK_KERNEL go to the host kernel (via ff_host_socket),
 * so they need NO DPDK/EAL initialization and are reachable by local ping/curl,
 * and the app can connect() to local/external kernel-stack services. The
 * returned fd is a host kernel fd and is used with normal libc syscalls
 * (bind/listen/accept/connect/...), as documented in
 * docs/kernel_event_support_spec/zh_cn (native ff_api mode).
 *
 * Modes:
 *   (no args)            self-test: in-process kernel-stack server+client
 *   server <port>        one-shot HTTP/1.1 server on the kernel stack
 *   client <ip> <port>   connect to a kernel-stack service and print reply
 *   bench <port>         single-thread epoll keep-alive HTTP server (wrk target)
 *
 * A/B build switch (perf baseline):
 *   USE_FF_KERNEL=1 (default)  ksock() -> ff_socket(SOCK_KERNEL)  [feature path A]
 *   USE_FF_KERNEL=0            ksock() -> libc socket()           [pure-kernel ref B]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ff_api.h"   /* ff_socket + SOCK_KERNEL / SOCK_FSTACK markers */

#ifndef USE_FF_KERNEL
#define USE_FF_KERNEL 1
#endif

static int
ksock(void)
{
#if USE_FF_KERNEL
    /* A (feature path): connection-level stack selection via marker. */
    int fd = ff_socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0);
    if (fd < 0)
        perror("ff_socket(SOCK_KERNEL)");
#else
    /* B (pure-kernel reference): raw libc kernel socket. */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        perror("socket()");
#endif
    return fd;
}

static int
do_server(int port, int oneshot)
{
    int sfd = ksock();
    if (sfd < 0)
        return -1;

    int on = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((unsigned short)port);

    if (bind(sfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        close(sfd);
        return -1;
    }
    if (listen(sfd, 16) < 0) {
        perror("listen");
        close(sfd);
        return -1;
    }
    printf("[server] kernel-stack listening on 127.0.0.1:%d\n", port);

    do {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) {
            perror("accept");
            break;
        }
        char buf[1024];
        ssize_t n = recv(cfd, buf, sizeof(buf) - 1, 0);
        if (n > 0)
            buf[n] = '\0';
        const char *body = "hello-stacksel\n";
        char resp[256];
        int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n"
            "Connection: close\r\n\r\n%s", strlen(body), body);
        send(cfd, resp, (size_t)len, 0);
        close(cfd);
    } while (!oneshot);

    close(sfd);
    return 0;
}

static int
do_client(const char *ip, int port)
{
    int fd = ksock();
    if (fd < 0)
        return -1;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        fprintf(stderr, "bad ip: %s\n", ip);
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }
    const char *req = "GET / HTTP/1.0\r\n\r\n";
    send(fd, req, strlen(req), 0);

    char buf[1024];
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n > 0) {
        buf[n] = '\0';
        printf("[client] connected via kernel stack, reply:\n%s\n", buf);
    }
    close(fd);
    return (n > 0) ? 0 : -1;
}

/*
 * Self-test: fork a child client that connects over the loopback to a
 * kernel-stack server in the parent. Proves FR-1 (kernel listen), FR-3
 * (client connect to local kernel service) and M4 (native ff_socket marker)
 * end to end on the host kernel — no DPDK NIC needed.
 */
static int
do_selftest(void)
{
    int sfd = ksock();
    if (sfd < 0)
        return 1;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0; /* ephemeral */
    if (bind(sfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        return 1;
    }
    socklen_t slen = sizeof(sa);
    if (getsockname(sfd, (struct sockaddr *)&sa, &slen) < 0) {
        perror("getsockname");
        return 1;
    }
    int port = ntohs(sa.sin_port);
    if (listen(sfd, 16) < 0) {
        perror("listen");
        return 1;
    }
    printf("[selftest] kernel-stack server on 127.0.0.1:%d\n", port);

    pid_t pid = fork();
    if (pid == 0) {
        /* child: client */
        close(sfd);
        int cfd = ksock();
        if (cfd < 0)
            _exit(2);
        struct sockaddr_in da;
        memset(&da, 0, sizeof(da));
        da.sin_family = AF_INET;
        da.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        da.sin_port = htons((unsigned short)port);
        if (connect(cfd, (struct sockaddr *)&da, sizeof(da)) < 0) {
            perror("[client] connect");
            _exit(3);
        }
        send(cfd, "PING", 4, 0);
        char b[16];
        ssize_t n = recv(cfd, b, sizeof(b), 0);
        close(cfd);
        if (n == 4 && memcmp(b, "PONG", 4) == 0) {
            printf("[client] got PONG over kernel stack\n");
            _exit(0);
        }
        _exit(4);
    }

    /* parent: server */
    int afd = accept(sfd, NULL, NULL);
    if (afd < 0) {
        perror("accept");
        return 1;
    }
    char b[16];
    ssize_t n = recv(afd, b, sizeof(b), 0);
    if (n == 4 && memcmp(b, "PING", 4) == 0)
        send(afd, "PONG", 4, 0);
    close(afd);
    close(sfd);

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("INTEGRATION PASS: kernel-stack server+client over loopback\n");
        return 0;
    }
    printf("INTEGRATION FAIL: child status=%d\n", status);
    return 1;
}

static int
set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    return (fl < 0) ? -1 : fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/*
 * Single-threaded epoll keep-alive HTTP server (mode "bench <port>") — the wrk
 * performance-baseline target. One thread, one epoll loop multiplexing the
 * listen fd and all accepted keep-alive connections (same single-loop
 * event-driven model as the F-Stack helloworld_epoll baseline). All fds come
 * from ksock(): SOCK_KERNEL host fds (A) or raw libc fds (B); the rest of the
 * path (bind/listen/accept/epoll/recv/send) is identical, so the A/B delta
 * isolates only the per-connection ff_socket->ff_host_socket indirection.
 */
static int
do_bench(int port)
{
    static const char resp[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 15\r\n"
        "Connection: keep-alive\r\n\r\nhello-stacksel\n";
    const size_t resp_len = sizeof(resp) - 1;

    int sfd = ksock();
    if (sfd < 0)
        return 1;
    int on = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((unsigned short)port);
    if (bind(sfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(sfd, 1024) < 0) {
        perror("listen");
        return 1;
    }
    set_nonblock(sfd);

    int ep = epoll_create1(0);
    if (ep < 0) {
        perror("epoll_create1");
        return 1;
    }
    struct epoll_event ev, evs[1024];
    ev.events = EPOLLIN;
    ev.data.fd = sfd;
    epoll_ctl(ep, EPOLL_CTL_ADD, sfd, &ev);

    printf("[bench] %s keep-alive server on 127.0.0.1:%d (single-thread epoll)\n",
           (USE_FF_KERNEL ? "ff_socket(SOCK_KERNEL)" : "libc socket()"), port);
    fflush(stdout);

    for (;;) {
        int n = epoll_wait(ep, evs, 1024, -1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            perror("epoll_wait");
            break;
        }
        for (int i = 0; i < n; i++) {
            int fd = evs[i].data.fd;
            if (fd == sfd) {
                for (;;) {
                    int cfd = accept(sfd, NULL, NULL);
                    if (cfd < 0)
                        break;  /* EAGAIN: backlog drained */
                    set_nonblock(cfd);
                    ev.events = EPOLLIN;
                    ev.data.fd = cfd;
                    epoll_ctl(ep, EPOLL_CTL_ADD, cfd, &ev);
                }
            } else {
                char buf[2048];
                ssize_t r = recv(fd, buf, sizeof(buf), 0);
                if (r > 0) {
                    ssize_t off = 0;
                    while (off < (ssize_t)resp_len) {
                        ssize_t w = send(fd, resp + off, resp_len - off, 0);
                        if (w <= 0)
                            break;
                        off += w;
                    }
                } else if (r == 0 ||
                           (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                    epoll_ctl(ep, EPOLL_CTL_DEL, fd, NULL);
                    close(fd);
                }
            }
        }
    }
    close(ep);
    close(sfd);
    return 0;
}

int
main(int argc, char **argv)
{
    if (argc >= 3 && strcmp(argv[1], "server") == 0)
        return do_server(atoi(argv[2]), /*oneshot*/0) == 0 ? 0 : 1;
    if (argc >= 4 && strcmp(argv[1], "serveronce") == 0)
        return do_server(atoi(argv[2]), /*oneshot*/atoi(argv[3])) == 0 ? 0 : 1;
    if (argc >= 4 && strcmp(argv[1], "client") == 0)
        return do_client(argv[2], atoi(argv[3])) == 0 ? 0 : 1;
    if (argc >= 3 && strcmp(argv[1], "bench") == 0)
        return do_bench(atoi(argv[2]));
    return do_selftest();
}
