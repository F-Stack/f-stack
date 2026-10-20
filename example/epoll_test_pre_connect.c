/*
 * Test: ff_epoll with EPOLLOUT registered BEFORE ff_connect.
 * This matches the original issue #842 test scenario.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include "ff_config.h"
#include "ff_api.h"
#include "ff_event.h"
#include "ff_epoll.h"

#define MAX_EVENTS 10
#define BUFFER_SIZE 4096

static int epfd;
static int sockfd;
static int request_sent = 0;
static int64_t br = 0;
static int64_t buffer_reads = 0;
static struct timespec t0;

static int loop(void *arg)
{
    struct epoll_event events[MAX_EVENTS];
    int n = ff_epoll_wait(epfd, events, MAX_EVENTS, 0);

    for (int i = 0; i < n; i++) {
        if ((events[i].events & EPOLLOUT) && !request_sent) {
            int sent = ff_send(sockfd,
                "GET / HTTP/1.1\r\nHost: 9.134.211.87\r\nConnection: keep-alive\r\n\r\n", 62, 0);
            if (sent > 0) {
                request_sent = 1;
                struct epoll_event ev;
                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = sockfd;
                ff_epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
            }
        }
        if ((events[i].events & EPOLLIN) && request_sent) {
            char buffer[BUFFER_SIZE];
            int bytes_read;
            while ((bytes_read = ff_recv(sockfd, buffer, sizeof(buffer) - 1, 0)) > 0) {
                br += bytes_read;
                ++buffer_reads;
            }
            if (bytes_read == 0) {
                struct timespec t1;
                clock_gettime(CLOCK_MONOTONIC, &t1);
                double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
                printf("buffer_reads: %ld\n", buffer_reads);
                printf("bytes_read: %ld\n", br);
                printf("total_time_s: %.3f\n", elapsed);
                fflush(stdout);
                ff_close(sockfd);
                ff_close(epfd);
                exit(0);
            } else if (bytes_read == -1 && errno != EAGAIN) {
                printf("recv_error: %s\n", strerror(errno));
                printf("buffer_reads: %ld\n", buffer_reads);
                printf("bytes_read: %ld\n", br);
                fflush(stdout);
                ff_close(sockfd);
                ff_close(epfd);
                exit(1);
            }
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    ff_init(argc, argv);

    clock_gettime(CLOCK_MONOTONIC, &t0);

    sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("ff_socket"); exit(1); }

    int opt = 1;
    ff_ioctl(sockfd, FIONBIO, &opt);

    /* Register EPOLLOUT BEFORE connect — matches original #842 scenario */
    epfd = ff_epoll_create(10);
    struct epoll_event ev;
    ev.events = EPOLLOUT | EPOLLET;
    ev.data.fd = sockfd;
    ff_epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);
    fprintf(stderr, "[main] EPOLLOUT registered before connect\n");

    /* Now connect */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo("9.134.211.87", "12373", &hints, &res) != 0) {
        perror("getaddrinfo"); exit(1);
    }

    int rc = ff_connect(sockfd, (struct linux_sockaddr *)res->ai_addr, res->ai_addrlen);
    fprintf(stderr, "[main] ff_connect=%d errno=%d\n", rc, errno);
    freeaddrinfo(res);

    if (rc == -1 && errno != EINPROGRESS) {
        perror("ff_connect"); exit(1);
    }

    ff_run(loop, NULL);
    return 0;
}
