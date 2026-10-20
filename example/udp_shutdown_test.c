/*
 * Issue #631 test: ff_shutdown() on UDP sockets.
 * Tests SHUT_RD / SHUT_WR / SHUT_RDWR on F-Stack UDP sockets.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>

#include "ff_config.h"
#include "ff_api.h"
#include "ff_event.h"

#define SERVER_PORT 15310
#define PKT_SIZE 64
#define PKTS_BEFORE_SHUTDOWN 3
#define PKTS_AFTER_SHUTDOWN 5
#define RECV_BUF_SIZE 2048

static int sockfd;
static int shutdown_how = SHUT_RD;
static int use_connect = 0;
static int recv_count = 0;
static int post_shutdown_recv_count = 0;
static int send_after_shutdown = 0;
static int phase = 0; /* 0=counting, 1=post-shutdown, 2=done */
static int shutdown_ret = -999;
static int shutdown_errno = 0;
static struct sockaddr_in client_addr;
static socklen_t client_addrlen;

static int loop_count = 0;
static int post_shutdown_idle_count = 0;

static int
loop(void *arg)
{
    char buf[RECV_BUF_SIZE];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    ssize_t n;

    if (phase == 2)
        return 0;

    loop_count++;
    n = ff_recvfrom(sockfd, buf, RECV_BUF_SIZE, 0,
        (struct linux_sockaddr *)&from, &fromlen);

    if (n > 0) {
        recv_count++;
        if (phase == 1) {
            post_shutdown_recv_count++;
            printf("[POST-SHUTDOWN] received %zd bytes after shutdown (total post=%d)\n",
                n, post_shutdown_recv_count);
            if (post_shutdown_recv_count >= PKTS_AFTER_SHUTDOWN) {
                printf("[RESULT] FAIL: still receiving data after shutdown(how=%d)\n",
                    shutdown_how);
                phase = 2;
            }
        } else {
            printf("[RECV] pkt #%d: %zd bytes (loop=%d)\n", recv_count, n, loop_count);
            if (recv_count == PKTS_BEFORE_SHUTDOWN) {
                printf("[SHUTDOWN] calling ff_shutdown(sockfd, %d)...\n", shutdown_how);
                shutdown_ret = ff_shutdown(sockfd, shutdown_how);
                shutdown_errno = errno;
                printf("[SHUTDOWN] ret=%d errno=%d (%s)\n",
                    shutdown_ret, shutdown_errno, strerror(shutdown_errno));
                phase = 1;

                if (shutdown_how == SHUT_WR || shutdown_how == SHUT_RDWR) {
                    send_after_shutdown = 1;
                    ssize_t s = ff_sendto(sockfd, buf, n, 0,
                        (struct linux_sockaddr *)&from, fromlen);
                    printf("[SEND-POST-SHUTDOWN] sendto ret=%zd errno=%d (%s)\n",
                        s, errno, strerror(errno));
                }
            }
        }
    } else if (n == 0) {
        printf("[EOF] recvfrom returned 0 (loop=%d phase=%d)\n", loop_count, phase);
        if (phase == 1) {
            printf("[RESULT] PASS: recvfrom returned 0 (EOF) after shutdown(how=%d)\n",
                shutdown_how);
            phase = 2;
        }
    } else if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (phase == 1) {
                post_shutdown_idle_count++;
                if (post_shutdown_idle_count >= 5000) {
                    printf("[RESULT] PASS: no data received after %d idle loops (shutdown(how=%d) effective)\n",
                        post_shutdown_idle_count, shutdown_how);
                    phase = 2;
                }
            }
            return 0;
        }
        printf("[RECV-ERR] ret=%zd errno=%d (%s) loop=%d phase=%d\n",
            n, errno, strerror(errno), loop_count, phase);
        if (phase == 1) {
            printf("[RESULT] recvfrom returned error after shutdown(how=%d)\n",
                shutdown_how);
            phase = 2;
        }
    }

    return 0;
}

int
main(int argc, char *argv[])
{
    int i, j;

    /* Parse and strip custom args before ff_init (DPDK EAL doesn't know them) */
    for (i = 1, j = 1; i < argc; i++) {
        if (strncmp(argv[i], "--how=", 6) == 0) {
            shutdown_how = atoi(argv[i] + 6);
        } else if (strcmp(argv[i], "--connect") == 0) {
            use_connect = 1;
        } else {
            argv[j++] = argv[i];
        }
    }
    argc = j;

    ff_init(argc, argv);

    printf("[MAIN] shutdown_how=%d use_connect=%d\n", shutdown_how, use_connect);

    sockfd = ff_socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("[MAIN] ff_socket failed: %s\n", strerror(errno));
        exit(1);
    }
    int nonblock = 1;
    ff_ioctl(sockfd, FIONBIO, &nonblock);
    printf("[MAIN] sockfd=%d\n", sockfd);

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, "9.134.214.176", &srv.sin_addr);

    int rc = ff_bind(sockfd, (struct linux_sockaddr *)&srv, sizeof(srv));
    if (rc < 0) {
        printf("[MAIN] ff_bind failed: %s\n", strerror(errno));
        exit(1);
    }
    printf("[MAIN] bound to 9.134.214.176:%d\n", SERVER_PORT);

    if (use_connect) {
        memset(&client_addr, 0, sizeof(client_addr));
        client_addr.sin_family = AF_INET;
        client_addr.sin_port = htons(SERVER_PORT);
        inet_pton(AF_INET, "9.134.211.87", &client_addr.sin_addr);
        rc = ff_connect(sockfd, (struct linux_sockaddr *)&client_addr, sizeof(client_addr));
        printf("[MAIN] ff_connect ret=%d errno=%d\n", rc, errno);
    }

    printf("[MAIN] waiting for %d packets before shutdown...\n", PKTS_BEFORE_SHUTDOWN);

    ff_run(loop, NULL);
    return 0;
}
