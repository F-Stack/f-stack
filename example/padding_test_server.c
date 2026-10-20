/*
 * Issue #481 test: Detect Ethernet padding bytes in received TCP data.
 * Listens on a TCP port, prints byte count and hex dump of each recv.
 * If padding is not stripped, extra bytes will appear in recv output.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "ff_api.h"
#include "ff_config.h"
#include "ff_log.h"

#define MAX_EVENTS 64
#define RECV_BUF 2048
#define TEST_PORT 15320

static int kq = -1;
static int listen_fd = -1;

static void
print_hex(const char *label, const char *data, int len)
{
    int i;
    printf("%s len=%d hex=", label, len);
    for (i = 0; i < len && i < 64; i++)
        printf("%02x", (unsigned char)data[i]);
    if (len > 64)
        printf("...(truncated)");
    printf("\n");
}

static int
loop(void *arg)
{
    struct kevent events[MAX_EVENTS];
    int nevents = ff_kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
    int i;

    for (i = 0; i < nevents; i++) {
        int fd = events[i].ident;

        if (fd == listen_fd) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int conn_fd = ff_accept(listen_fd,
                (struct linux_sockaddr *)&client_addr, &addr_len);
            if (conn_fd >= 0) {
                EV_SET(&events[0], conn_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
                ff_kevent(kq, &events[0], 1, NULL, 0, NULL);
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
                printf("[ACCEPT] connection from %s:%d fd=%d\n",
                    ip, ntohs(client_addr.sin_port), conn_fd);
            }
        } else {
            if (events[i].flags & EV_EOF) {
                printf("[CLOSE] fd=%d\n", fd);
                ff_close(fd);
                continue;
            }

            char buf[RECV_BUF];
            ssize_t n = ff_recv(fd, buf, RECV_BUF, 0);
            if (n > 0) {
                print_hex("[RECV]", buf, (int)n);
                ff_send(fd, buf, n, 0);
            } else if (n == 0) {
                printf("[EOF] fd=%d\n", fd);
                ff_close(fd);
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                printf("[RECV-ERR] fd=%d ret=%zd errno=%d (%s)\n",
                    fd, n, errno, strerror(errno));
                ff_close(fd);
            }
        }
    }
    return 0;
}

int
main(int argc, char *argv[])
{
    ff_init(argc, argv);

    kq = ff_kqueue();
    if (kq < 0) {
        printf("[MAIN] ff_kqueue failed: %s\n", strerror(errno));
        exit(1);
    }

    listen_fd = ff_socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        printf("[MAIN] ff_socket failed: %s\n", strerror(errno));
        exit(1);
    }

    int opt = 1;
    ff_setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TEST_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (ff_bind(listen_fd, (struct linux_sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("[MAIN] ff_bind failed: %s\n", strerror(errno));
        exit(1);
    }

    if (ff_listen(listen_fd, 10) < 0) {
        printf("[MAIN] ff_listen failed: %s\n", strerror(errno));
        exit(1);
    }

    printf("[MAIN] listening on port %d fd=%d\n", TEST_PORT, listen_fd);

    struct kevent kevSet;
    EV_SET(&kevSet, listen_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    ff_kevent(kq, &kevSet, 1, NULL, 0, NULL);

    ff_run(loop, NULL);
    return 0;
}
