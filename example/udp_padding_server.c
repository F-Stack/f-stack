/*
 * Issue #481 UDP test: Detect Ethernet padding bytes in received UDP data.
 * Receives UDP packets and prints byte count and hex dump.
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

#define RECV_BUF 2048
#define TEST_PORT 15321

static int sockfd = -1;
static int recv_count = 0;

static int
loop(void *arg)
{
    char buf[RECV_BUF];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);

    ssize_t n = ff_recvfrom(sockfd, buf, RECV_BUF, 0,
        (struct linux_sockaddr *)&from, &fromlen);

    if (n > 0) {
        recv_count++;
        int i;
        printf("[RECV] pkt #%d: %zd bytes hex=", recv_count, n);
        for (i = 0; i < n && i < 64; i++)
            printf("%02x", (unsigned char)buf[i]);
        if (n > 64)
            printf("...(truncated)");
        printf("\n");

        ff_sendto(sockfd, buf, n, 0,
            (struct linux_sockaddr *)&from, fromlen);
    }

    return 0;
}

int
main(int argc, char *argv[])
{
    ff_init(argc, argv);

    sockfd = ff_socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("[MAIN] ff_socket failed: %s\n", strerror(errno));
        exit(1);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TEST_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (ff_bind(sockfd, (struct linux_sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("[MAIN] ff_bind failed: %s\n", strerror(errno));
        exit(1);
    }

    printf("[MAIN] UDP server listening on port %d fd=%d\n", TEST_PORT, sockfd);

    ff_run(loop, NULL);
    return 0;
}
