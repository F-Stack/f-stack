/*
 * Kernel TCP client for issue #842 reproduction.
 * Receives 1M timestamp messages, measures first/last latency.
 * Compile with -O2.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <time.h>

#define MAX_EVENTS 10
#define BUFFER_SIZE 4096

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

static int set_nonblocking(int sockfd)
{
    int opt = 1;
    if (ioctl(sockfd, FIONBIO, &opt)) {
        perror("ioctl FIONBIO");
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    const char *hostname = "9.134.211.87";
    const char *port = "12373";

    if (argc > 1)
        hostname = argv[1];
    if (argc > 2)
        port = argv[2];

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, port, &hints, &res) != 0) {
        perror("getaddrinfo");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    if (set_nonblocking(sockfd) == -1) {
        close(sockfd);
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }

    int connect_status = connect(sockfd, res->ai_addr, res->ai_addrlen);
    if (connect_status == -1 && errno != EINPROGRESS) {
        perror("connect");
        close(sockfd);
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create1");
        close(sockfd);
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLOUT | EPOLLIN | EPOLLET;
    ev.data.fd = sockfd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
        perror("epoll_ctl");
        close(sockfd);
        close(epoll_fd);
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }

    char request[512];
    snprintf(request, sizeof(request),
             "GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n",
             hostname);

    int64_t br = 0;
    int64_t buffer_reads = 0;
    int64_t last_latency = 0;
    int64_t first_latency = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    int done = 0;
    while (!done) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for (int i = 0; i < n; i++) {
            if (events[i].events & EPOLLOUT) {
                send(sockfd, request, strlen(request), 0);
                ev.events = EPOLLIN | EPOLLET;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, sockfd, &ev);
            } else if (events[i].events & EPOLLIN) {
                char buffer[BUFFER_SIZE];
                int bytes_read;
                while ((bytes_read = recv(sockfd, buffer, sizeof(buffer) - 1, 0)) > 0) {
                    br += bytes_read;
                    ++buffer_reads;
                    buffer[bytes_read] = '\0';
                    last_latency = get_time_difference(buffer, bytes_read);
                    if (first_latency < 10 || first_latency > 10000000000LL)
                        first_latency = last_latency;
                }
                if (bytes_read == 0) {
                    done = 1;
                } else if (bytes_read == -1 && errno != EAGAIN) {
                    perror("recv");
                    done = 1;
                }
            }
        }
    }

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

    close(sockfd);
    close(epoll_fd);
    freeaddrinfo(res);
    return 0;
}
