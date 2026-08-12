# 01 — Implementation Plan and Code

## Design

Following the code style and architecture pattern of `main_stack_epoll.c`, a new UDP echo server example is added.

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Socket type | `SOCK_DGRAM` | UDP is connectionless |
| Port | 9000 | Non-privileged port, avoids conflict with TCP example (port 80) |
| Event-driven | epoll | Consistent with existing epoll examples, demonstrates F-Stack epoll support for UDP |
| I/O interface | `recvfrom`/`sendto` | Demonstrates UDP connectionless nature (get/use source address) |
| Linking | No `-lff_syscall` | Consistent with epoll series examples, LD_PRELOAD at runtime |
| Buffer size | 1472 bytes | Standard MTU 1500 - IP header 20 - UDP header 8 |
| Response | Echo received data directly | Simple, consistent with echo server semantics |

### Differences from TCP epoll Example

| Element | main_stack_epoll.c (TCP) | main_stack_udp.c (UDP) |
|---------|--------------------------|------------------------|
| Socket type | `SOCK_STREAM` | `SOCK_DGRAM` |
| listen() | Yes | No (UDP is connectionless) |
| accept() | Yes | No |
| I/O interface | `read()`/`write()` | `recvfrom()`/`sendto()` |
| Response content | Fixed HTML page | Echo received data |
| Port | 80 | 9000 |

## Code Listing

### New File: `adapter/syscall/main_stack_udp.c`

```c
#include <stdio.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#define MAX_WORKERS 128
pthread_t hworker[MAX_WORKERS];

#define MAX_EVENTS 512
struct epoll_event ev;
struct epoll_event events[MAX_EVENTS];
int epfd;
int sockfd;

static int exit_flag = 0;

#define BUF_SIZE 1472

void sig_term(int sig)
{
    printf("we caught signal %d, to exit helloworld\n", sig);
    exit_flag = 1;
    return;
}

void *loop(void *arg)
{
    char buf[BUF_SIZE];
    struct sockaddr_in client_addr;
    socklen_t addr_len;

    while (!exit_flag) {
        int nevents = epoll_wait(epfd, events, MAX_EVENTS, 100);
        int i;

        if (nevents <= 0) {
            if (nevents) {
                printf("hello world epoll wait ret %d, errno:%d, %s\n",
                    nevents, errno, strerror(errno));
                break;
            }
            sleep(1);
        }

        for (i = 0; i < nevents; ++i) {
            if (events[i].events & EPOLLERR) {
                epoll_ctl(epfd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                close(events[i].data.fd);
            } else if (events[i].events & EPOLLIN) {
                addr_len = sizeof(client_addr);
                ssize_t recvlen = recvfrom(events[i].data.fd, buf, sizeof(buf), 0,
                    (struct sockaddr *)&client_addr, &addr_len);
                if (recvlen > 0) {
                    ssize_t sendlen = sendto(events[i].data.fd, buf, recvlen, 0,
                        (struct sockaddr *)&client_addr, addr_len);
                    if (sendlen < 0) {
                        printf("sendto failed, recvlen:%lu, sendlen:%lu, errno:%d, %s\n",
                            (unsigned long)recvlen, (unsigned long)sendlen,
                            errno, strerror(errno));
                    }
                } else if (recvlen < 0) {
                    printf("recvfrom failed, errno:%d, %s\n",
                        errno, strerror(errno));
                }
            } else {
                printf("unknown event: %d:%8.8X\n", i, events[i].events);
            }
        }
    }

    return NULL;
}

int main(int argc, char * argv[])
{
    int i, worker_num = 1;

    signal(SIGINT, sig_term);
    signal(SIGTERM, sig_term);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    printf("sockfd:%d\n", sockfd);
    if (sockfd < 0) {
        printf("socket failed\n");
        return -1;
    }

    int on = 1;
    ioctl(sockfd, FIONBIO, &on);

    struct sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(9000);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int ret = bind(sockfd, (const struct sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) {
        printf("bind failed, errno:%d, %s\n", errno, strerror(errno));
        close(sockfd);
        return -1;
    }

    epfd = epoll_create(512);
    printf("epfd:%d\n", epfd);
    if (epfd <= 0) {
        printf("epoll_create failed, errno:%d, %s\n",
            errno, strerror(errno));
        close(sockfd);
        return -1;
    }

    ev.data.fd = sockfd;
    ev.events = EPOLLIN;
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);
    if (ret < 0) {
        printf("epoll_ctl failed, errno:%d, %s\n", errno, strerror(errno));
        close(epfd);
        close(sockfd);
        return -1;
    }

    for (i = 0; i < worker_num; i++) {
        if(pthread_create(&hworker[i], NULL, loop, (void *)&i) < 0) {
            printf("create loop thread failed, errno:%d/%s\n",
                errno, strerror(errno));
            close(epfd);
            close(sockfd);
            return -1;
        }
    }

    for (i = 0; i < worker_num; i++) {
        pthread_join(hworker[i], NULL);
    }

    close(epfd);
    close(sockfd);

    return 0;
}
```

### Makefile Change

Add one line at the end of the `example` target (consistent with epoll series examples, no `-lff_syscall` linking):

```makefile
cc ${CFLAGS} -I ${FF_PATH}/adapter/syscall -o helloworld_stack_udp main_stack_udp.c ${LIBS}
```

## Code Style Alignment

The new file is highly consistent with the `main_stack_epoll.c` template:

- Same header file include order (15 standard POSIX headers)
- Consistent global variable naming (`epfd`, `sockfd`, `events`, `ev`, `exit_flag`, `hworker`)
- Consistent `sig_term()` signal handler
- Consistent `main()` structure (signal → socket → ioctl → bind → epoll → pthread → join → close)
- Consistent error handling pattern (`printf` + `return -1`)
- Consistent `loop()` thread function pattern

Only minimal deviations for UDP semantics: removed `listen`/`accept`/`html`, replaced with `recvfrom`/`sendto`.
