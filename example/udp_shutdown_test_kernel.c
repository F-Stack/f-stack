/*
 * Issue #631 kernel-stack baseline: shutdown() on UDP sockets.
 * Uses standard Linux socket API for comparison with F-Stack behavior.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>

#define SERVER_PORT 15310
#define PKT_SIZE 64
#define PKTS_BEFORE_SHUTDOWN 3
#define PKTS_AFTER_SHUTDOWN 5
#define RECV_BUF_SIZE 2048
#define TIMEOUT_MS 15000

int
main(int argc, char *argv[])
{
    int sockfd, shutdown_how = SHUT_RD;
    int recv_count = 0, post_shutdown_recv_count = 0;
    int phase = 0; /* 0=counting, 1=post-shutdown, 2=done */
    int i;

    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--how=", 6) == 0)
            shutdown_how = atoi(argv[i] + 6);
    }

    printf("[MAIN] kernel-stack test, shutdown_how=%d\n", shutdown_how);

    sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (sockfd < 0) {
        printf("[MAIN] socket failed: %s\n", strerror(errno));
        exit(1);
    }

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(SERVER_PORT);
    srv.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        printf("[MAIN] bind failed: %s\n", strerror(errno));
        exit(1);
    }
    printf("[MAIN] bound to 0.0.0.0:%d\n", SERVER_PORT);

    while (phase != 2) {
        struct pollfd pfd = { .fd = sockfd, .events = POLLIN };
        int pr = poll(&pfd, 1, 200);
        if (pr <= 0) {
            if (phase == 1 && post_shutdown_recv_count == 0) {
                printf("[RESULT] PASS: no data received after %dms (shutdown(how=%d) effective)\n",
                    TIMEOUT_MS, shutdown_how);
                phase = 2;
            }
            continue;
        }

        char buf[RECV_BUF_SIZE];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(sockfd, buf, RECV_BUF_SIZE, MSG_DONTWAIT,
            (struct sockaddr *)&from, &fromlen);

        if (n > 0) {
            recv_count++;
            if (phase == 1) {
                post_shutdown_recv_count++;
                printf("[POST-SHUTDOWN] received %zd bytes after shutdown (post=%d)\n",
                    n, post_shutdown_recv_count);
                if (post_shutdown_recv_count >= PKTS_AFTER_SHUTDOWN) {
                    printf("[RESULT] FAIL: still receiving data after shutdown(how=%d)\n",
                        shutdown_how);
                    phase = 2;
                }
            } else {
                printf("[RECV] pkt #%d: %zd bytes\n", recv_count, n);
                if (recv_count == PKTS_BEFORE_SHUTDOWN) {
                    printf("[SHUTDOWN] calling shutdown(sockfd, %d)...\n", shutdown_how);
                    int ret = shutdown(sockfd, shutdown_how);
                    printf("[SHUTDOWN] ret=%d errno=%d (%s)\n",
                        ret, errno, ret < 0 ? strerror(errno) : "OK");
                    phase = 1;

                    if (shutdown_how == SHUT_WR || shutdown_how == SHUT_RDWR) {
                        ssize_t s = sendto(sockfd, buf, n, 0,
                            (struct sockaddr *)&from, fromlen);
                        printf("[SEND-POST-SHUTDOWN] sendto ret=%zd errno=%d (%s)\n",
                            s, errno, s < 0 ? strerror(errno) : "OK");
                    }
                }
            }
        } else if (n == 0) {
            if (phase == 1) {
                printf("[RESULT] PASS: recvfrom returned 0 (EOF) after shutdown(how=%d)\n",
                    shutdown_how);
                phase = 2;
            }
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            printf("[RECV-ERR] ret=%zd errno=%d (%s)\n", n, errno, strerror(errno));
            if (phase == 1) {
                printf("[RESULT] recvfrom returned error after shutdown(how=%d)\n",
                    shutdown_how);
                phase = 2;
            }
        }
    }

    close(sockfd);
    return 0;
}
