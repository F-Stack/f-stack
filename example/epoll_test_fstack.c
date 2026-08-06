/*
 * Focused test for ff_epoll EPOLLOUT on connect completion.
 * Compares ff_epoll vs kqueue native API side by side.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include <sys/epoll.h>
#include <sys/ioctl.h>

#include "ff_config.h"
#include "ff_api.h"
#include "ff_event.h"
#include "ff_epoll.h"

#define MAX_EVENTS 10

static int epfd;
static int kq;
static int sockfd;
static int request_sent = 0;
static int epoll_ev_count = 0;
static int kqueue_ev_count = 0;

static int loop(void *arg)
{
    /* Poll ff_epoll */
    struct epoll_event ep_events[MAX_EVENTS];
    int en = ff_epoll_wait(epfd, ep_events, MAX_EVENTS, 0);
    if (en > 0) {
        epoll_ev_count++;
        fprintf(stderr, "[epoll] n=%d ev[0]=0x%x (count=%d)\n",
                en, ep_events[0].events, epoll_ev_count);
        for (int i = 0; i < en; i++) {
            if ((ep_events[i].events & EPOLLOUT) && !request_sent) {
                fprintf(stderr, "[epoll] got EPOLLOUT, sending request\n");
                int sent = ff_send(sockfd,
                    "GET / HTTP/1.1\r\nHost: 9.134.211.87\r\nConnection: keep-alive\r\n\r\n", 62, 0);
                fprintf(stderr, "[epoll] ff_send=%d\n", sent);
                if (sent > 0) {
                    request_sent = 1;
                    struct epoll_event ev;
                    ev.events = EPOLLIN | EPOLLET;
                    ev.data.fd = sockfd;
                    ff_epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
                }
            }
            if ((ep_events[i].events & EPOLLIN) && request_sent) {
                char buf[4096];
                int r;
                while ((r = ff_recv(sockfd, buf, sizeof(buf) - 1, 0)) > 0) {
                    /* drain */
                }
                if (r == 0) {
                    fprintf(stderr, "[epoll] EOF\n");
                    ff_close(sockfd);
                    ff_close(epfd);
                    ff_close(kq);
                    exit(0);
                }
            }
        }
    }

    /* Poll kqueue (on the same socket for comparison) */
    struct kevent kev_events[MAX_EVENTS];
    int kn = ff_kevent(kq, NULL, 0, kev_events, MAX_EVENTS, NULL);
    if (kn > 0) {
        kqueue_ev_count++;
        for (int i = 0; i < kn; i++) {
            fprintf(stderr, "[kqueue] filter=%d flags=0x%x data=%lld (count=%d)\n",
                    kev_events[i].filter, kev_events[i].flags,
                    (long long)kev_events[i].data, kqueue_ev_count);
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    ff_init(argc, argv);

    sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("ff_socket"); exit(1); }

    int opt = 1;
    ff_ioctl(sockfd, FIONBIO, &opt);

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

    /* Register on ff_epoll with EPOLLOUT|EPOLLET */
    epfd = ff_epoll_create(10);
    struct epoll_event ev;
    ev.events = EPOLLOUT | EPOLLET;
    ev.data.fd = sockfd;
    ff_epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);
    fprintf(stderr, "[main] ff_epoll ADD EPOLLOUT|EPOLLET done\n");

    /* Also register on kqueue for side-by-side comparison */
    kq = ff_kqueue();
    struct kevent change[2];
    EV_SET(&change[0], sockfd, EVFILT_READ, EV_ADD | EV_CLEAR | EV_DISABLE, 0, 0, NULL);
    EV_SET(&change[1], sockfd, EVFILT_WRITE, EV_ADD | EV_CLEAR | EV_ENABLE, 0, 0, NULL);
    ff_kevent(kq, change, 2, NULL, 0, NULL);
    fprintf(stderr, "[main] kqueue ADD EVFILT_WRITE done\n");

    ff_run(loop, NULL);
    return 0;
}
