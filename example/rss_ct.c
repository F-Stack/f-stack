/*
 * rss_ct.c - RSS connect test (self-check carrier for RSS lport selection).
 *
 * Purpose: example/ has only servers; in_pcb_lport_dest RSS lport selection
 * (0.1/0.3/0.2) only fires on connect(). This minimal F-Stack app issues N
 * connects to a given dst and prints the locally selected source ports plus
 * this process's RSS queue info, so the deployer can verify each process's
 * connect-selected sport hashes onto its own RSS queue.
 *
 * Usage:
 *   ./rss_ct <EAL/ff args...> --dst=<ip>:<port> [--dst6=<ip6>:<port>] [--num=N]
 *   --dst / --dst6 / --num are app args, stripped before ff_init() so they do
 *   not collide with EAL parsing. At least one of --dst/--dst6 is required.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "ff_config.h"
#include "ff_api.h"
#include "ff_log.h"

#define RSS_CT_DEFAULT_NUM  200
#define RSS_CT_MAX_NUM      4096

static char rss_ct_dst4[64];
static char rss_ct_dst6[128];
static int rss_ct_num = RSS_CT_DEFAULT_NUM;
static int rss_ct_done = 0;

/* Split "addr:port" at the LAST ':' (so IPv6 colons stay in addr). */
static int
parse_addr_port(const char *s, char *addr_out, size_t addr_sz, uint16_t *port_out)
{
    const char *colon = strrchr(s, ':');
    size_t alen;

    if (colon == NULL)
        return -1;
    alen = (size_t)(colon - s);
    if (alen == 0 || alen >= addr_sz)
        return -1;
    memcpy(addr_out, s, alen);
    addr_out[alen] = '\0';
    *port_out = (uint16_t)atoi(colon + 1);
    if (*port_out == 0)
        return -1;
    return 0;
}

/*
 * Strip app args (--dst=, --dst6=, --num=) from argv so the remaining argv is
 * pure EAL/ff args for ff_init. Returns the trimmed argc.
 */
static int
extract_app_args(int argc, char **argv)
{
    int i, n = 0;

    for (i = 0; i < argc; i++) {
        if (strncmp(argv[i], "--dst=", 6) == 0) {
            snprintf(rss_ct_dst4, sizeof(rss_ct_dst4), "%s", argv[i] + 6);
        } else if (strncmp(argv[i], "--dst6=", 7) == 0) {
            snprintf(rss_ct_dst6, sizeof(rss_ct_dst6), "%s", argv[i] + 7);
        } else if (strncmp(argv[i], "--num=", 6) == 0) {
            rss_ct_num = atoi(argv[i] + 6);
            if (rss_ct_num <= 0 || rss_ct_num > RSS_CT_MAX_NUM)
                rss_ct_num = RSS_CT_DEFAULT_NUM;
        } else {
            argv[n++] = argv[i];
        }
    }
    argv[n] = NULL;
    return n;
}

static void
run_connects4(uint16_t proc_id)
{
    char addr[64];
    uint16_t dport;
    int i;

    if (parse_addr_port(rss_ct_dst4, addr, sizeof(addr), &dport) != 0) {
        ff_log(FF_LOG_ERR, FF_LOGTYPE_FSTACK_APP,
            "rss_ct: bad --dst=%s\n", rss_ct_dst4);
        return;
    }

    printf("rss_ct v4: proc=%u dst=%s:%u num=%d sports:", proc_id, addr, dport,
        rss_ct_num);

    for (i = 0; i < rss_ct_num; i++) {
        int fd, on = 1;
        struct sockaddr_in sin;
        struct sockaddr_in local;
        socklen_t llen = sizeof(local);

        fd = ff_socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            continue;
        ff_ioctl(fd, FIONBIO, &on);

        bzero(&sin, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(dport);
        inet_pton(AF_INET, addr, &sin.sin_addr);

        /* connect may return EINPROGRESS; lport is already selected by then. */
        ff_connect(fd, (struct linux_sockaddr *)&sin, sizeof(sin));

        bzero(&local, sizeof(local));
        if (ff_getsockname(fd, (struct linux_sockaddr *)&local, &llen) == 0)
            printf(" %u", ntohs(local.sin_port));

        ff_close(fd);
    }
    printf("\n");
}

#ifdef INET6
static void
run_connects6(uint16_t proc_id)
{
    char addr[128];
    uint16_t dport;
    int i;

    if (parse_addr_port(rss_ct_dst6, addr, sizeof(addr), &dport) != 0) {
        ff_log(FF_LOG_ERR, FF_LOGTYPE_FSTACK_APP,
            "rss_ct: bad --dst6=%s\n", rss_ct_dst6);
        return;
    }

    printf("rss_ct v6: proc=%u dst=[%s]:%u num=%d sports:", proc_id, addr,
        dport, rss_ct_num);

    for (i = 0; i < rss_ct_num; i++) {
        int fd, on = 1;
        struct sockaddr_in6 sin6;
        struct sockaddr_in6 local6;
        socklen_t llen = sizeof(local6);

        fd = ff_socket(AF_INET6, SOCK_STREAM, 0);
        if (fd < 0)
            continue;
        ff_ioctl(fd, FIONBIO, &on);

        bzero(&sin6, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = htons(dport);
        inet_pton(AF_INET6, addr, &sin6.sin6_addr);

        ff_connect(fd, (struct linux_sockaddr *)&sin6, sizeof(sin6));

        bzero(&local6, sizeof(local6));
        if (ff_getsockname(fd, (struct linux_sockaddr *)&local6, &llen) == 0)
            printf(" %u", ntohs(local6.sin6_port));

        ff_close(fd);
    }
    printf("\n");
}
#endif

static int
loop(void *arg)
{
    uint16_t proc_id = 0, queueid = 0, nb_queues = 0, reta_size = 0;

    if (rss_ct_done)
        return 0;
    rss_ct_done = 1;

    if (ff_rss_self_queue_info(&proc_id, &queueid, &nb_queues, &reta_size) != 0) {
        ff_log(FF_LOG_ERR, FF_LOGTYPE_FSTACK_APP,
            "rss_ct: ff_rss_self_queue_info failed\n");
        return 0;
    }

    printf("rss_ct info: proc=%u queueid=%u nb_queues=%u reta_size=%u\n",
        proc_id, queueid, nb_queues, reta_size);

    if (rss_ct_dst4[0] != '\0')
        run_connects4(proc_id);
#ifdef INET6
    if (rss_ct_dst6[0] != '\0')
        run_connects6(proc_id);
#endif

    printf("rss_ct done: proc=%u (verify each sport hashes to queueid=%u)\n",
        proc_id, queueid);
    fflush(stdout);

    return 0;
}

int
main(int argc, char *argv[])
{
    argc = extract_app_args(argc, argv);

    if (rss_ct_dst4[0] == '\0' && rss_ct_dst6[0] == '\0') {
        fprintf(stderr,
            "rss_ct: need --dst=<ip>:<port> and/or --dst6=<ip6>:<port>\n");
        return 1;
    }

    ff_init(argc, argv);
    ff_run(loop, NULL);

    return 0;
}
