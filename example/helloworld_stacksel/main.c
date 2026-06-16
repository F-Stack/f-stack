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
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ff_api.h"      /* ff_socket + SOCK_KERNEL / SOCK_FSTACK markers */
#include "ff_config.h"   /* ff_global_cfg: enable coexistence without ff_init */

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
    if (ff_send(c, "ping", 4, 0) != 4) {
        perror("ff_send");
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
    ssize_t n = ff_recv(c, buf, sizeof(buf), 0);
    if (n == 4 && memcmp(buf, "ping", 4) == 0)
        ff_send(c, "pong", 4, 0);
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

int
main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return do_selftest();
}
