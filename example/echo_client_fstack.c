/*
 * F-Stack TCP client for issue #842 reproduction.
 * Uses kqueue (F-Stack native event mechanism) instead of ff_epoll to
 * avoid EPOLLOUT translation gaps on connect completion.
 * Compile with -O2.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <time.h>

#include "ff_config.h"
#include "ff_api.h"
#include "ff_event.h"

#define MAX_EVENTS 10
#define BUFFER_SIZE 4096

static struct kevent events[MAX_EVENTS];
static int kq;
static int sockfd;
static int request_sent = 0;

static int64_t br = 0;
static int64_t buffer_reads = 0;
static int64_t last_latency = 0;
static int64_t first_latency = 0;
static struct timespec t0;

static int64_t get_time_difference(const char *buffer, size_t bytes_read)
{
    if (bytes_read < 20)
        return -1;

    int64_t d = strtoll(buffer + (bytes_read - 20), NULL, 10);

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int64_t now = (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;

    return now - d;
}

static int set_nonblocking(int fd)
{
    int opt = 1;
    if (ff_ioctl(fd, FIONBIO, &opt)) {
        perror("ioctl FIONBIO");
        return -1;
    }
    return 0;
}

static int loop(void *arg)
{
    int n = ff_kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
    for (int i = 0; i < n; i++) {
        if (!request_sent) {
            int sent = ff_send(sockfd, "GET / HTTP/1.1\r\nHost: 9.134.211.87\r\nConnection: keep-alive\r\n\r\n", 62, 0);
            if (sent > 0) {
                request_sent = 1;
                struct kevent change;
                EV_SET(&change, sockfd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
                ff_kevent(kq, &change, 1, NULL, 0, NULL);
            }
        }
        if (events[i].filter == EVFILT_READ && request_sent) {
            char buffer[BUFFER_SIZE];
            int bytes_read;
            while ((bytes_read = ff_recv(sockfd, buffer, sizeof(buffer) - 1, 0)) > 0) {
                br += bytes_read;
                ++buffer_reads;
                buffer[bytes_read] = '\0';
                last_latency = get_time_difference(buffer, bytes_read);
                if (first_latency < 10 || first_latency > 10000000000LL)
                    first_latency = last_latency;
            }
            if (bytes_read == 0) {
                struct timespec t1;
                clock_gettime(CLOCK_MONOTONIC, &t1);
                double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

                float avg_bytes = buffer_reads > 0 ? (float)br / (float)buffer_reads : 0;
                printf("avg_bytes: %.2f\n", avg_bytes);
                printf("buffer_reads: %ld\n", buffer_reads);
                printf("bytes_read: %ld\n", br);
                printf("first_latency_ns: %ld\n", first_latency);
                printf("last_latency_ns: %ld\n", last_latency);
                printf("lat_diff_ns: %ld\n", last_latency - first_latency);
                printf("total_time_s: %.3f\n", elapsed);
                fflush(stdout);
                ff_close(sockfd);
                ff_close(kq);
                exit(0);
            } else if (bytes_read == -1 && errno != EAGAIN) {
                struct timespec t1;
                clock_gettime(CLOCK_MONOTONIC, &t1);
                double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
                float avg_bytes = buffer_reads > 0 ? (float)br / (float)buffer_reads : 0;
                printf("avg_bytes: %.2f\n", avg_bytes);
                printf("buffer_reads: %ld\n", buffer_reads);
                printf("bytes_read: %ld\n", br);
                printf("first_latency_ns: %ld\n", first_latency);
                printf("last_latency_ns: %ld\n", last_latency);
                printf("lat_diff_ns: %ld\n", last_latency - first_latency);
                printf("total_time_s: %.3f\n", elapsed);
                printf("recv_error: %s\n", strerror(errno));
                fflush(stdout);
                ff_close(sockfd);
                ff_close(kq);
                exit(1);
            }
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    const char *hostname = "9.134.211.87";
    const char *port = "12373";

    ff_init(argc, argv);

    clock_gettime(CLOCK_MONOTONIC, &t0);

    sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("ff_socket"); exit(EXIT_FAILURE); }

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, port, &hints, &res) != 0) {
        perror("getaddrinfo");
        ff_close(sockfd);
        exit(EXIT_FAILURE);
    }

    if (set_nonblocking(sockfd) == -1) {
        ff_close(sockfd);
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }

    int connect_status = ff_connect(sockfd, (struct linux_sockaddr *)res->ai_addr, res->ai_addrlen);
    if (connect_status == -1 && errno != EINPROGRESS) { perror("ff_connect"); ff_close(sockfd); freeaddrinfo(res); exit(EXIT_FAILURE); }

    freeaddrinfo(res);

    kq = ff_kqueue();
    if (kq == -1) { perror("ff_kqueue"); ff_close(sockfd); exit(EXIT_FAILURE); }

    struct kevent change[2];
    EV_SET(&change[0], sockfd, EVFILT_READ, EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, NULL);
    EV_SET(&change[1], sockfd, EVFILT_WRITE, EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, NULL);
    if (ff_kevent(kq, change, 2, NULL, 0, NULL) == -1) {
        perror("ff_kevent add");
        ff_close(sockfd);
        ff_close(kq);
        exit(EXIT_FAILURE);
    }

    ff_run(loop, NULL);
    return 0;
}
