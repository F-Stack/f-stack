/*
 * Copyright (C) 2017-2021 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_config.h>
#include <rte_eal.h>
#include <rte_pci.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_lcore.h>
#include <rte_launch.h>
#include <rte_ethdev.h>
#include <rte_debug.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_thash.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_eth_bond.h>
#include <rte_eth_bond_8023ad.h>

#include "ff_dpdk_if.h"
#include "ff_dpdk_pcap.h"
#include "ff_dpdk_kni.h"
#include "ff_config.h"
#include "ff_veth.h"
#include "ff_host_interface.h"
#include "ff_msg.h"
#include "ff_api.h"
#include "ff_memory.h"

#ifdef FF_KNI
#define KNI_MBUF_MAX 2048
#define KNI_QUEUE_SIZE 2048

int enable_kni;
static int kni_accept;
static int knictl_action = FF_KNICTL_ACTION_DEFAULT;
#endif

static int numa_on;

static unsigned idle_sleep;
static unsigned pkt_tx_delay;
static uint64_t usr_cb_tsc;

static struct rte_timer freebsd_clock;

// Mellanox Linux's driver key
static uint8_t default_rsskey_40bytes[40] = {
    0xd1, 0x81, 0xc6, 0x2c, 0xf7, 0xf4, 0xdb, 0x5b,
    0x19, 0x83, 0xa2, 0xfc, 0x94, 0x3e, 0x1a, 0xdb,
    0xd9, 0x38, 0x9e, 0x6b, 0xd1, 0x03, 0x9c, 0x2c,
    0xa7, 0x44, 0x99, 0xad, 0x59, 0x3d, 0x56, 0xd9,
    0xf3, 0x25, 0x3c, 0x06, 0x2a, 0xdc, 0x1f, 0xfc
};

static uint8_t default_rsskey_52bytes[52] = {
    0x44, 0x39, 0x79, 0x6b, 0xb5, 0x4c, 0x50, 0x23,
    0xb6, 0x75, 0xea, 0x5b, 0x12, 0x4f, 0x9f, 0x30,
    0xb8, 0xa2, 0xc0, 0x3d, 0xdf, 0xdc, 0x4d, 0x02,
    0xa0, 0x8c, 0x9b, 0x33, 0x4a, 0xf6, 0x4a, 0x4c,
    0x05, 0xc6, 0xfa, 0x34, 0x39, 0x58, 0xd8, 0x55,
    0x7d, 0x99, 0x58, 0x3a, 0xe1, 0x38, 0xc9, 0x2e,
    0x81, 0x15, 0x03, 0x66
};

static uint8_t symmetric_rsskey[52] = {
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a
};

static int rsskey_len = sizeof(default_rsskey_40bytes);
static uint8_t *rsskey = default_rsskey_40bytes;

struct lcore_conf lcore_conf;

struct rte_mempool *pktmbuf_pool[NB_SOCKETS];

static pcblddr_func_t pcblddr_fun;

static struct rte_ring **dispatch_ring[RTE_MAX_ETHPORTS];
static dispatch_func_t packet_dispatcher;

static uint16_t rss_reta_size[RTE_MAX_ETHPORTS];

#define BOND_DRIVER_NAME    "net_bonding"

static inline int send_single_packet(struct rte_mbuf *m, uint8_t port);

struct ff_msg_ring {
    char ring_name[FF_MSG_NUM][RTE_RING_NAMESIZE];
    /* ring[0] for lcore recv msg, other send */
    /* ring[1] for lcore send msg, other read */
    struct rte_ring *ring[FF_MSG_NUM];
} __rte_cache_aligned;

static struct ff_msg_ring msg_ring[RTE_MAX_LCORE];
static struct rte_mempool *message_pool;
static struct ff_dpdk_if_context *veth_ctx[RTE_MAX_ETHPORTS];

static struct ff_top_args ff_top_status;
static struct ff_traffic_args ff_traffic;
extern void ff_hardclock(void);

static void
ff_hardclock_job(__rte_unused struct rte_timer *timer,
    __rte_unused void *arg) {
    ff_hardclock();
    ff_update_current_ts();
}

struct ff_dpdk_if_context *
ff_dpdk_register_if(void *sc, void *ifp, struct ff_port_cfg *cfg)
{
    struct ff_dpdk_if_context *ctx;

    ctx = calloc(1, sizeof(struct ff_dpdk_if_context));
    if (ctx == NULL)
        return NULL;

    ctx->sc = sc;
    ctx->ifp = ifp;
    ctx->port_id = cfg->port_id;
    ctx->hw_features = cfg->hw_features;

    return ctx;
}

void
ff_dpdk_deregister_if(struct ff_dpdk_if_context *ctx)
{
    free(ctx);
}

static void
check_all_ports_link_status(void)
{
    #define CHECK_INTERVAL 100 /* 100ms */
    #define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */

    uint16_t portid;
    uint8_t count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;

    printf("\nChecking link status");
    fflush(stdout);

    int i, nb_ports;
    nb_ports = ff_global_cfg.dpdk.nb_ports;
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        all_ports_up = 1;
        for (i = 0; i < nb_ports; i++) {
            uint16_t portid = ff_global_cfg.dpdk.portid_list[i];
            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(portid, &link);

            /* print link status if flag set */
            if (print_flag == 1) {
                if (link.link_status) {
                    printf("Port %d Link Up - speed %u "
                        "Mbps - %s\n", (int)portid,
                        (unsigned)link.link_speed,
                        (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                        ("full-duplex") : ("half-duplex\n"));
                } else {
                    printf("Port %d Link Down\n", (int)portid);
                }
                continue;
            }
            /* clear all_ports_up flag if any link down */
            if (link.link_status == 0) {
                all_ports_up = 0;
                break;
            }
        }

        /* after finally printing all link status, get out */
        if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            printf("done\n");
        }
    }
}

static int
init_lcore_conf(void)
{
    uint8_t nb_dev_ports = rte_eth_dev_count_avail();
    if (nb_dev_ports == 0) {
        rte_exit(EXIT_FAILURE, "No probed ethernet devices\n");
    }

    if (ff_global_cfg.dpdk.max_portid >= nb_dev_ports) {
        rte_exit(EXIT_FAILURE, "this machine doesn't have port %d.\n",
                 ff_global_cfg.dpdk.max_portid);
    }

    lcore_conf.port_cfgs = ff_global_cfg.dpdk.port_cfgs;
    lcore_conf.proc_id = ff_global_cfg.dpdk.proc_id;

    uint16_t socket_id = 0;
    if (numa_on) {
        socket_id = rte_lcore_to_socket_id(rte_lcore_id());
    }

    lcore_conf.socket_id = socket_id;

    uint16_t lcore_id = ff_global_cfg.dpdk.proc_lcore[lcore_conf.proc_id];
    if (!rte_lcore_is_enabled(lcore_id)) {
        rte_exit(EXIT_FAILURE, "lcore %u unavailable\n", lcore_id);
    }

    int j;
    for (j = 0; j < ff_global_cfg.dpdk.nb_ports; ++j) {
        uint16_t port_id = ff_global_cfg.dpdk.portid_list[j];
        struct ff_port_cfg *pconf = &ff_global_cfg.dpdk.port_cfgs[port_id];

        int queueid = -1;
        int i;
        for (i = 0; i < pconf->nb_lcores; i++) {
            if (pconf->lcore_list[i] == lcore_id) {
                queueid = i;
            }
        }
        if (queueid < 0) {
            continue;
        }
        printf("lcore: %u, port: %u, queue: %u\n", lcore_id, port_id, queueid);
        uint16_t nb_rx_queue = lcore_conf.nb_rx_queue;
        lcore_conf.rx_queue_list[nb_rx_queue].port_id = port_id;
        lcore_conf.rx_queue_list[nb_rx_queue].queue_id = queueid;
        lcore_conf.nb_rx_queue++;

        lcore_conf.tx_queue_id[port_id] = queueid;
        lcore_conf.tx_port_id[lcore_conf.nb_tx_port] = port_id;
        lcore_conf.nb_tx_port++;

        /* Enable pcap dump */
        if (ff_global_cfg.pcap.enable) {
            ff_enable_pcap(ff_global_cfg.pcap.save_path, ff_global_cfg.pcap.snap_len);
        }

        lcore_conf.nb_queue_list[port_id] = pconf->nb_lcores;
    }

    if (lcore_conf.nb_rx_queue == 0) {
        rte_exit(EXIT_FAILURE, "lcore %u has nothing to do\n", lcore_id);
    }

    return 0;
}

static int
init_mem_pool(void)
{
    uint8_t nb_ports = ff_global_cfg.dpdk.nb_ports;
    uint32_t nb_lcores = ff_global_cfg.dpdk.nb_procs;
    uint32_t nb_tx_queue = nb_lcores;
    uint32_t nb_rx_queue = lcore_conf.nb_rx_queue * nb_lcores;
    uint16_t max_portid = ff_global_cfg.dpdk.max_portid;

    unsigned nb_mbuf = RTE_ALIGN_CEIL (
        (nb_rx_queue * (max_portid + 1) * 2 * RX_QUEUE_SIZE          +
        nb_ports * (max_portid + 1) * 2 * nb_lcores * MAX_PKT_BURST    +
        nb_ports * (max_portid + 1) * 2 * nb_tx_queue * TX_QUEUE_SIZE  +
        nb_lcores * MEMPOOL_CACHE_SIZE +
#ifdef FF_KNI
        nb_ports * KNI_MBUF_MAX +
        nb_ports * KNI_QUEUE_SIZE +
#endif
        nb_lcores * nb_ports * DISPATCH_RING_SIZE),
        (unsigned)8192);

    unsigned socketid = 0;
    uint16_t i, lcore_id;
    char s[64];

    for (i = 0; i < ff_global_cfg.dpdk.nb_procs; i++) {
        lcore_id = ff_global_cfg.dpdk.proc_lcore[i];
        if (numa_on) {
            socketid = rte_lcore_to_socket_id(lcore_id);
        }

        if (socketid >= NB_SOCKETS) {
            rte_exit(EXIT_FAILURE, "Socket %d of lcore %u is out of range %d\n",
                socketid, i, NB_SOCKETS);
        }

        if (pktmbuf_pool[socketid] != NULL) {
            continue;
        }

        if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
            snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
            pktmbuf_pool[socketid] =
                rte_pktmbuf_pool_create(s, nb_mbuf,
                    MEMPOOL_CACHE_SIZE, 0,
                    RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
        } else {
            snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
            pktmbuf_pool[socketid] = rte_mempool_lookup(s);
        }

        if (pktmbuf_pool[socketid] == NULL) {
            rte_exit(EXIT_FAILURE, "Cannot create mbuf pool on socket %d\n", socketid);
        } else {
            printf("create mbuf pool on socket %d\n", socketid);
        }

#ifdef FF_USE_PAGE_ARRAY
        nb_mbuf = RTE_ALIGN_CEIL (
            nb_ports*nb_lcores*MAX_PKT_BURST    +
            nb_ports*nb_tx_queue*TX_QUEUE_SIZE  +
            nb_lcores*MEMPOOL_CACHE_SIZE,
            (unsigned)4096);
        ff_init_ref_pool(nb_mbuf, socketid);
#endif
    }

    return 0;
}

static struct rte_ring *
create_ring(const char *name, unsigned count, int socket_id, unsigned flags)
{
    struct rte_ring *ring;

    if (name == NULL) {
        rte_exit(EXIT_FAILURE, "create ring failed, no name!\n");
    }

    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        ring = rte_ring_create(name, count, socket_id, flags);
    } else {
        ring = rte_ring_lookup(name);
    }

    if (ring == NULL) {
        rte_exit(EXIT_FAILURE, "create ring:%s failed!\n", name);
    }

    return ring;
}

static int
init_dispatch_ring(void)
{
    int j;
    char name_buf[RTE_RING_NAMESIZE];
    int queueid;

    unsigned socketid = lcore_conf.socket_id;

    /* Create ring according to ports actually being used. */
    int nb_ports = ff_global_cfg.dpdk.nb_ports;
    for (j = 0; j < nb_ports; j++) {
        uint16_t portid = ff_global_cfg.dpdk.portid_list[j];
        struct ff_port_cfg *pconf = &ff_global_cfg.dpdk.port_cfgs[portid];
        int nb_queues = pconf->nb_lcores;
        if (dispatch_ring[portid] == NULL) {
            snprintf(name_buf, RTE_RING_NAMESIZE, "ring_ptr_p%d", portid);

            dispatch_ring[portid] = rte_zmalloc(name_buf,
                sizeof(struct rte_ring *) * nb_queues,
                RTE_CACHE_LINE_SIZE);
            if (dispatch_ring[portid] == NULL) {
                rte_exit(EXIT_FAILURE, "rte_zmalloc(%s (struct rte_ring*)) "
                    "failed\n", name_buf);
            }
        }

        for(queueid = 0; queueid < nb_queues; ++queueid) {
            snprintf(name_buf, RTE_RING_NAMESIZE, "dispatch_ring_p%d_q%d",
                portid, queueid);
            dispatch_ring[portid][queueid] = create_ring(name_buf,
                DISPATCH_RING_SIZE, socketid, RING_F_SC_DEQ);

            if (dispatch_ring[portid][queueid] == NULL)
                rte_panic("create ring:%s failed!\n", name_buf);

            printf("create ring:%s success, %u ring entries are now free!\n",
                name_buf, rte_ring_free_count(dispatch_ring[portid][queueid]));
        }
    }

    return 0;
}

static void
ff_msg_init(struct rte_mempool *mp,
    __attribute__((unused)) void *opaque_arg,
    void *obj, __attribute__((unused)) unsigned i)
{
    struct ff_msg *msg = (struct ff_msg *)obj;
    msg->msg_type = FF_UNKNOWN;
    msg->buf_addr = (char *)msg + sizeof(struct ff_msg);
    msg->buf_len = mp->elt_size - sizeof(struct ff_msg);
    msg->original_buf = NULL;
    msg->original_buf_len = 0;
}

static int
init_msg_ring(void)
{
    uint16_t i, j;
    uint16_t nb_procs = ff_global_cfg.dpdk.nb_procs;
    unsigned socketid = lcore_conf.socket_id;

    /* Create message buffer pool */
    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        message_pool = rte_mempool_create(FF_MSG_POOL,
           MSG_RING_SIZE * 2 * nb_procs,
           MAX_MSG_BUF_SIZE, MSG_RING_SIZE / 2, 0,
           NULL, NULL, ff_msg_init, NULL,
           socketid, 0);
    } else {
        message_pool = rte_mempool_lookup(FF_MSG_POOL);
    }

    if (message_pool == NULL) {
        rte_panic("Create msg mempool failed\n");
    }

    for(i = 0; i < nb_procs; ++i) {
        snprintf(msg_ring[i].ring_name[0], RTE_RING_NAMESIZE,
            "%s%u", FF_MSG_RING_IN, i);
        msg_ring[i].ring[0] = create_ring(msg_ring[i].ring_name[0],
            MSG_RING_SIZE, socketid, RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (msg_ring[i].ring[0] == NULL)
            rte_panic("create ring::%s failed!\n", msg_ring[i].ring_name[0]);

        for (j = FF_SYSCTL; j < FF_MSG_NUM; j++) {
            snprintf(msg_ring[i].ring_name[j], RTE_RING_NAMESIZE,
                "%s%u_%u", FF_MSG_RING_OUT, i, j);
            msg_ring[i].ring[j] = create_ring(msg_ring[i].ring_name[j],
                MSG_RING_SIZE, socketid, RING_F_SP_ENQ | RING_F_SC_DEQ);
            if (msg_ring[i].ring[j] == NULL)
                rte_panic("create ring::%s failed!\n", msg_ring[i].ring_name[j]);
        }
    }

    return 0;
}

#ifdef FF_KNI

static enum FF_KNICTL_CMD get_kni_action(const char *c){
    if (!c)
        return FF_KNICTL_ACTION_DEFAULT;
    if (0 == strcasecmp(c, "alltokni")){
        return FF_KNICTL_ACTION_ALL_TO_KNI;
    } else  if (0 == strcasecmp(c, "alltoff")){
        return FF_KNICTL_ACTION_ALL_TO_FF;
    } else if (0 == strcasecmp(c, "default")){
        return FF_KNICTL_ACTION_DEFAULT;
    } else {
        return FF_KNICTL_ACTION_DEFAULT;
    }
}

static int
init_kni(void)
{
    int nb_ports = rte_eth_dev_count_avail();
    kni_accept = 0;
    if(strcasecmp(ff_global_cfg.kni.method, "accept") == 0)
        kni_accept = 1;

    knictl_action = get_kni_action(ff_global_cfg.kni.kni_action);

    ff_kni_init(nb_ports, ff_global_cfg.kni.tcp_port,
        ff_global_cfg.kni.udp_port);

    unsigned socket_id = lcore_conf.socket_id;
    struct rte_mempool *mbuf_pool = pktmbuf_pool[socket_id];

    nb_ports = ff_global_cfg.dpdk.nb_ports;
    int i, ret;
    for (i = 0; i < nb_ports; i++) {
        uint16_t port_id = ff_global_cfg.dpdk.portid_list[i];
        ff_kni_alloc(port_id, socket_id, mbuf_pool, KNI_QUEUE_SIZE);
    }

    return 0;
}
#endif

//RSS reta update will failed when enable flow isolate
#ifndef FF_FLOW_ISOLATE
static void
set_rss_table(uint16_t port_id, uint16_t reta_size, uint16_t nb_queues)
{
    if (reta_size == 0) {
        return;
    }

    int reta_conf_size = RTE_MAX(1, reta_size / RTE_RETA_GROUP_SIZE);
    struct rte_eth_rss_reta_entry64 reta_conf[reta_conf_size];

    /* config HW indirection table */
    unsigned i, j, hash=0;
    for (i = 0; i < reta_conf_size; i++) {
        reta_conf[i].mask = ~0ULL;
        for (j = 0; j < RTE_RETA_GROUP_SIZE; j++) {
            reta_conf[i].reta[j] = hash++ % nb_queues;
        }
    }

    if (rte_eth_dev_rss_reta_update(port_id, reta_conf, reta_size)) {
        rte_exit(EXIT_FAILURE, "port[%d], failed to update rss table\n",
            port_id);
    }
}
#endif

static int
init_port_start(void)
{
    int nb_ports = ff_global_cfg.dpdk.nb_ports;
    unsigned socketid = 0;
    struct rte_mempool *mbuf_pool;
    uint16_t i, j;

    for (i = 0; i < nb_ports; i++) {
        uint16_t port_id, u_port_id = ff_global_cfg.dpdk.portid_list[i];
        struct ff_port_cfg *pconf = &ff_global_cfg.dpdk.port_cfgs[u_port_id];
        uint16_t nb_queues = pconf->nb_lcores;

        if (pconf->nb_slaves > 0) {
            rte_eth_bond_8023ad_dedicated_queues_enable(u_port_id);
        }
        for (j=0; j<=pconf->nb_slaves; j++) {
            if (j < pconf->nb_slaves) {
                port_id = pconf->slave_portid_list[j];
                printf("To init %s's %d'st slave port[%d]\n",
                        ff_global_cfg.dpdk.bond_cfgs->name,
                        j, port_id);
            } else {
                port_id = u_port_id;
            }

            struct rte_eth_dev_info dev_info;
            struct rte_eth_conf port_conf = {0};
            struct rte_eth_rxconf rxq_conf;
            struct rte_eth_txconf txq_conf;

            int ret = rte_eth_dev_info_get(port_id, &dev_info);
            if (ret != 0)
                rte_exit(EXIT_FAILURE,
                    "Error during getting device (port %u) info: %s\n",
                    port_id, strerror(-ret));

            if (nb_queues > dev_info.max_rx_queues) {
                rte_exit(EXIT_FAILURE, "num_procs[%d] bigger than max_rx_queues[%d]\n",
                    nb_queues,
                    dev_info.max_rx_queues);
            }

            if (nb_queues > dev_info.max_tx_queues) {
                rte_exit(EXIT_FAILURE, "num_procs[%d] bigger than max_tx_queues[%d]\n",
                    nb_queues,
                    dev_info.max_tx_queues);
            }

            struct rte_ether_addr addr;
            rte_eth_macaddr_get(port_id, &addr);
            printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
                       " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
                    (unsigned)port_id,
                    addr.addr_bytes[0], addr.addr_bytes[1],
                    addr.addr_bytes[2], addr.addr_bytes[3],
                    addr.addr_bytes[4], addr.addr_bytes[5]);

            rte_memcpy(pconf->mac,
                addr.addr_bytes, RTE_ETHER_ADDR_LEN);

            /* Set RSS mode */
            uint64_t default_rss_hf = ETH_RSS_PROTO_MASK;
            port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
            port_conf.rx_adv_conf.rss_conf.rss_hf = default_rss_hf;
            if (dev_info.hash_key_size == 52) {
                rsskey = default_rsskey_52bytes;
                rsskey_len = 52;
            }
            if (ff_global_cfg.dpdk.symmetric_rss) {
                printf("Use symmetric Receive-side Scaling(RSS) key\n");
                rsskey = symmetric_rsskey;
            }
            port_conf.rx_adv_conf.rss_conf.rss_key = rsskey;
            port_conf.rx_adv_conf.rss_conf.rss_key_len = rsskey_len;
            port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
            if (port_conf.rx_adv_conf.rss_conf.rss_hf !=
                    ETH_RSS_PROTO_MASK) {
                printf("Port %u modified RSS hash function based on hardware support,"
                        "requested:%#"PRIx64" configured:%#"PRIx64"\n",
                        port_id, default_rss_hf,
                        port_conf.rx_adv_conf.rss_conf.rss_hf);
            }

            if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE) {
                port_conf.txmode.offloads |=
                    DEV_TX_OFFLOAD_MBUF_FAST_FREE;
            }

            /* Set Rx VLAN stripping */
            if (ff_global_cfg.dpdk.vlan_strip) {
                if (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_VLAN_STRIP) {
                    port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_VLAN_STRIP;
                }
            }

            /* Enable HW CRC stripping */
            port_conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_KEEP_CRC;

            /* FIXME: Enable TCP LRO ?*/
            #if 0
            if (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_TCP_LRO) {
                printf("LRO is supported\n");
                port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_TCP_LRO;
                pconf->hw_features.rx_lro = 1;
            }
            #endif

            /* Set Rx checksum checking */
            if ((dev_info.rx_offload_capa & DEV_RX_OFFLOAD_IPV4_CKSUM) &&
                (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_UDP_CKSUM) &&
                (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_TCP_CKSUM)) {
                printf("RX checksum offload supported\n");
                port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_CHECKSUM;
                pconf->hw_features.rx_csum = 1;
            }

            if (ff_global_cfg.dpdk.tx_csum_offoad_skip == 0) {
                if ((dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM)) {
                    printf("TX ip checksum offload supported\n");
                    port_conf.txmode.offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM;
                    pconf->hw_features.tx_csum_ip = 1;
                }

                if ((dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM) &&
                    (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM)) {
                    printf("TX TCP&UDP checksum offload supported\n");
                    port_conf.txmode.offloads |= DEV_TX_OFFLOAD_UDP_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM;
                    pconf->hw_features.tx_csum_l4 = 1;
                }
            } else {
                printf("TX checksum offoad is disabled\n");
            }

            if (ff_global_cfg.dpdk.tso) {
                if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_TSO) {
                    printf("TSO is supported\n");
                    port_conf.txmode.offloads |= DEV_TX_OFFLOAD_TCP_TSO;
                    pconf->hw_features.tx_tso = 1;
                }
            } else {
                printf("TSO is disabled\n");
            }

            if (dev_info.reta_size) {
                /* reta size must be power of 2 */
                assert((dev_info.reta_size & (dev_info.reta_size - 1)) == 0);

                rss_reta_size[port_id] = dev_info.reta_size;
                printf("port[%d]: rss table size: %d\n", port_id,
                    dev_info.reta_size);
            }

            if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
                continue;
            }

            ret = rte_eth_dev_configure(port_id, nb_queues, nb_queues, &port_conf);
            if (ret != 0) {
                return ret;
            }

            static uint16_t nb_rxd = RX_QUEUE_SIZE;
            static uint16_t nb_txd = TX_QUEUE_SIZE;
            ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
            if (ret < 0)
                printf("Could not adjust number of descriptors "
                        "for port%u (%d)\n", (unsigned)port_id, ret);

            uint16_t q;
            for (q = 0; q < nb_queues; q++) {
                if (numa_on) {
                    uint16_t lcore_id = lcore_conf.port_cfgs[u_port_id].lcore_list[q];
                    socketid = rte_lcore_to_socket_id(lcore_id);
                }
                mbuf_pool = pktmbuf_pool[socketid];

                txq_conf = dev_info.default_txconf;
                txq_conf.offloads = port_conf.txmode.offloads;
                ret = rte_eth_tx_queue_setup(port_id, q, nb_txd,
                    socketid, &txq_conf);
                if (ret < 0) {
                    return ret;
                }

                rxq_conf = dev_info.default_rxconf;
                rxq_conf.offloads = port_conf.rxmode.offloads;
                ret = rte_eth_rx_queue_setup(port_id, q, nb_rxd,
                    socketid, &rxq_conf, mbuf_pool);
                if (ret < 0) {
                    return ret;
                }
            }


            if (strncmp(dev_info.driver_name, BOND_DRIVER_NAME,
                    strlen(dev_info.driver_name)) == 0) {

                rte_eth_macaddr_get(port_id, &addr);
                printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
                           " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
                        (unsigned)port_id,
                        addr.addr_bytes[0], addr.addr_bytes[1],
                        addr.addr_bytes[2], addr.addr_bytes[3],
                        addr.addr_bytes[4], addr.addr_bytes[5]);

                rte_memcpy(pconf->mac,
                    addr.addr_bytes, RTE_ETHER_ADDR_LEN);

                int mode, count, x;
                uint16_t slaves[RTE_MAX_ETHPORTS], len = RTE_MAX_ETHPORTS;

                mode = rte_eth_bond_mode_get(port_id);
                printf("Port %u, bond mode:%d\n", port_id, mode);

                count = rte_eth_bond_slaves_get(port_id, slaves, len);
                printf("Port %u, %s's slave ports count:%d\n", port_id,
                            ff_global_cfg.dpdk.bond_cfgs->name, count);
                for (x=0; x<count; x++) {
                    printf("Port %u, %s's slave port[%u]\n", port_id,
                            ff_global_cfg.dpdk.bond_cfgs->name, slaves[x]);
                }
            }

            ret = rte_eth_dev_start(port_id);
            if (ret < 0) {
                return ret;
            }
    //RSS reta update will failed when enable flow isolate
    #ifndef FF_FLOW_ISOLATE
            if (nb_queues > 1) {
                /*
                 * FIXME: modify RSS set to FDIR
                 */
                set_rss_table(port_id, dev_info.reta_size, nb_queues);
            }
    #endif

            /* Enable RX in promiscuous mode for the Ethernet device. */
            if (ff_global_cfg.dpdk.promiscuous) {
                ret = rte_eth_promiscuous_enable(port_id);
                if (ret == 0) {
                    printf("set port %u to promiscuous mode ok\n", port_id);
                } else {
                    printf("set port %u to promiscuous mode error\n", port_id);
                }
            }
        }
    }

    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        check_all_ports_link_status();
    }

    return 0;
}

static int
init_clock(void)
{
    rte_timer_subsystem_init();
    uint64_t hz = rte_get_timer_hz();
    uint64_t intrs = US_PER_S / ff_global_cfg.freebsd.hz;
    uint64_t tsc = (hz + US_PER_S - 1) / US_PER_S * intrs;

    rte_timer_init(&freebsd_clock);
    rte_timer_reset(&freebsd_clock, tsc, PERIODICAL,
        rte_lcore_id(), &ff_hardclock_job, NULL);

    ff_update_current_ts();

    return 0;
}

#if defined(FF_FLOW_ISOLATE) || defined(FF_FDIR)
/** Print a message out of a flow error. */
static int
port_flow_complain(struct rte_flow_error *error)
{
    static const char *const errstrlist[] = {
        [RTE_FLOW_ERROR_TYPE_NONE] = "no error",
        [RTE_FLOW_ERROR_TYPE_UNSPECIFIED] = "cause unspecified",
        [RTE_FLOW_ERROR_TYPE_HANDLE] = "flow rule (handle)",
        [RTE_FLOW_ERROR_TYPE_ATTR_GROUP] = "group field",
        [RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY] = "priority field",
        [RTE_FLOW_ERROR_TYPE_ATTR_INGRESS] = "ingress field",
        [RTE_FLOW_ERROR_TYPE_ATTR_EGRESS] = "egress field",
        [RTE_FLOW_ERROR_TYPE_ATTR_TRANSFER] = "transfer field",
        [RTE_FLOW_ERROR_TYPE_ATTR] = "attributes structure",
        [RTE_FLOW_ERROR_TYPE_ITEM_NUM] = "pattern length",
        [RTE_FLOW_ERROR_TYPE_ITEM_SPEC] = "item specification",
        [RTE_FLOW_ERROR_TYPE_ITEM_LAST] = "item specification range",
        [RTE_FLOW_ERROR_TYPE_ITEM_MASK] = "item specification mask",
        [RTE_FLOW_ERROR_TYPE_ITEM] = "specific pattern item",
        [RTE_FLOW_ERROR_TYPE_ACTION_NUM] = "number of actions",
        [RTE_FLOW_ERROR_TYPE_ACTION_CONF] = "action configuration",
        [RTE_FLOW_ERROR_TYPE_ACTION] = "specific action",
    };
    const char *errstr;
    char buf[32];
    int err = rte_errno;

    if ((unsigned int)error->type >= RTE_DIM(errstrlist) ||
        !errstrlist[error->type])
        errstr = "unknown type";
    else
        errstr = errstrlist[error->type];
    printf("Caught error type %d (%s): %s%s: %s\n",
           error->type, errstr,
           error->cause ? (snprintf(buf, sizeof(buf), "cause: %p, ",
                                    error->cause), buf) : "",
           error->message ? error->message : "(no stated reason)",
           rte_strerror(err));
    return -err;
}
#endif


#ifdef FF_FLOW_ISOLATE
static int
port_flow_isolate(uint16_t port_id, int set)
{
    struct rte_flow_error error;
    /* Poisoning to make sure PMDs update it in case of error. */
    memset(&error, 0x66, sizeof(error));
    if (rte_flow_isolate(port_id, set, &error))
        return port_flow_complain(&error);
    printf("Ingress traffic on port %u is %s to the defined flow rules\n",
           port_id,
           set ? "now restricted" : "not restricted anymore");
    return 0;
}

static int
create_tcp_flow(uint16_t port_id, uint16_t tcp_port, uint32_t ip) {
  struct rte_flow_attr attr = {.ingress = 1};
  struct ff_port_cfg *pconf = &ff_global_cfg.dpdk.port_cfgs[port_id];
  int nb_queues = pconf->nb_lcores;
  uint16_t queue[RTE_MAX_QUEUES_PER_PORT];
  int i = 0, j = 0;
  for (i = 0, j = 0; i < nb_queues; ++i)
   queue[j++] = i;
  struct rte_flow_action_rss rss = {
   .types = ETH_RSS_NONFRAG_IPV4_TCP,
   .key_len = rsskey_len,
   .key = rsskey,
   .queue_num = j,
   .queue = queue,
  };

  struct rte_eth_dev_info dev_info;
  int ret = rte_eth_dev_info_get(port_id, &dev_info);
  if (ret != 0)
    rte_exit(EXIT_FAILURE, "Error during getting device (port %u) info: %s\n", port_id, strerror(-ret));

  struct rte_flow_item pattern[3];
  struct rte_flow_action action[2];
  struct rte_flow_item_tcp tcp_spec;
  struct rte_flow_item_tcp tcp_mask = {
          .hdr = {
                  .src_port = RTE_BE16(0x0000),
                  .dst_port = RTE_BE16(0xffff),
          },
  };
  struct rte_flow_error error;
  struct rte_flow_item_ipv4 ipv4_spec = {
       .hdr = { .dst_addr = rte_cpu_to_le_32(ip) }
  };
  struct rte_flow_item_ipv4 ipv4_mask = {
       .hdr = { .dst_addr = 0xFFFFFFFF }
  };

  memset(pattern, 0, sizeof(pattern));
  memset(action, 0, sizeof(action));

  /* set the dst ipv4 packet to the required value */
  pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
  pattern[0].spec = &ipv4_spec;
  pattern[0].mask = &ipv4_mask;

  memset(&tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
  tcp_spec.hdr.dst_port = rte_cpu_to_be_16(tcp_port);
  pattern[1].type = RTE_FLOW_ITEM_TYPE_TCP;
  pattern[1].spec = &tcp_spec;
  pattern[1].mask = &tcp_mask;

  /* end the pattern array */
  pattern[2].type = RTE_FLOW_ITEM_TYPE_END;

  /* create the action */
  action[0].type = RTE_FLOW_ACTION_TYPE_RSS;
  action[0].conf = &rss;
  action[1].type = RTE_FLOW_ACTION_TYPE_END;

  struct rte_flow *flow;
  /* validate and create the flow rule */
  if (!rte_flow_validate(port_id, &attr, pattern, action, &error)) {
      flow = rte_flow_create(port_id, &attr, pattern, action, &error);
      if (!flow) {
          return port_flow_complain(&error);
      }
  }

  memset(pattern, 0, sizeof(pattern));

  /* set the dst ipv4 packet to the required value */
  struct rte_flow_item_ipv4 ipv4_spec2 = {
       .hdr = { .src_addr = rte_cpu_to_le_32(ip) }
  };
  struct rte_flow_item_ipv4 ipv4_mask2 = {
       .hdr = { .src_addr = 0xFFFFFFFF }
  };
  pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
  pattern[0].spec = &ipv4_spec2;
  pattern[0].mask = &ipv4_mask2;

  struct rte_flow_item_tcp tcp_src_mask = {
          .hdr = {
                  .src_port = RTE_BE16(0xffff),
                  .dst_port = RTE_BE16(0x0000),
          },
  };

  memset(&tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
  tcp_spec.hdr.src_port = rte_cpu_to_be_16(tcp_port);
  pattern[1].type = RTE_FLOW_ITEM_TYPE_TCP;
  pattern[1].spec = &tcp_spec;
  pattern[1].mask = &tcp_src_mask;

  /* end the pattern array */
  pattern[2].type = RTE_FLOW_ITEM_TYPE_END;

  /* validate and create the flow rule */
  if (!rte_flow_validate(port_id, &attr, pattern, action, &error)) {
      flow = rte_flow_create(port_id, &attr, pattern, action, &error);
      if (!flow) {
          return port_flow_complain(&error);
      }
  }

  return 1;
}

static int
init_flow(uint16_t port_id, uint16_t tcp_port, uint32_t ip) {

  if(!create_tcp_flow(port_id, tcp_port, ip)) {
      rte_exit(EXIT_FAILURE, "create tcp flow failed\n");
      return -1;
  }

  /*  ARP rule */
  struct rte_flow_attr attr = {.ingress = 1};
  struct rte_flow_action_queue queue = {.index = 0};

  struct rte_flow_item pattern_[3];
  struct rte_flow_action action[2];

  memset(pattern_, 0, sizeof(pattern_));
  memset(action, 0, sizeof(action));
  
  uint32_t ip_addr = rte_cpu_to_le_32(ip);
  struct rte_flow_item_eth  item_eth_mask = {};
    struct rte_flow_item_eth  item_eth_spec = {};
    struct rte_flow_item_raw  raw_spec = {
        .relative = 0,
        .search = 0,
        .offset = 38,
        .limit = 0,
        .length = 4,
        .pattern = (uint8_t*)&ip_addr
    };

    item_eth_spec.hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
    item_eth_mask.hdr.ether_type = rte_cpu_to_be_16(0xFFFF);

    pattern_[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern_[0].mask = &item_eth_mask;
    pattern_[0].spec = &item_eth_spec;

    pattern_[1].type = RTE_FLOW_ITEM_TYPE_RAW;
    pattern_[1].spec = &raw_spec;

  pattern_[1].type = RTE_FLOW_ITEM_TYPE_END;

  /* create the action */
  action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
  action[0].conf = &queue;
  action[1].type = RTE_FLOW_ACTION_TYPE_END;

  struct rte_flow *flow;
  struct rte_flow_error error;
  /* validate and create the flow rule */
  if (!rte_flow_validate(port_id, &attr, pattern_, action, &error)) {
      flow = rte_flow_create(port_id, &attr, pattern_, action, &error);
      if (!flow) {
          return port_flow_complain(&error);
      }
  } else {
    return port_flow_complain(&error);
  }

  return 1;
}

#endif

#ifdef FF_FDIR
/*
 * Flow director allows the traffic to specific port to be processed on the
 * specific queue. Unlike FF_FLOW_ISOLATE, the FF_FDIR implementation uses
 * general flow rule so that most FDIR supported NIC will support. The best
 * using case of FDIR is (but not limited to), using multiple processes to
 * listen on different ports.
 *
 * This function can be called either in FSTACK or in end-application. 
 *
 * Example:
 *  Given 2 fstack instances A and B. Instance A listens on port 80, and
 *  instance B listens on port 81. We want to process the traffic to port 80
 *  on rx queue 0, and the traffic to port 81 on rx queue 1. 
 *  // port 80 rx queue 0
 *  ret = fdir_add_tcp_flow(port_id, 0, FF_FLOW_INGRESS, 0, 80);
 *  // port 81 rx queue 1
 *  ret = fdir_add_tcp_flow(port_id, 1, FF_FLOW_INGRESS, 0, 81);
 */
#define FF_FLOW_EGRESS		1
#define FF_FLOW_INGRESS		2
/**
 * Create a flow rule that moves packets with matching src and dest tcp port 
 * to the target queue. 
 * 
 * This function uses general flow rules and doesn't rely on the flow_isolation
 * that not all the FDIR capable NIC support.
 *
 * @param port_id
 *   The selected port.
 * @param queue 
 *   The target queue.
 * @param dir 
 *   The direction of the traffic. 
 *   1 for egress, 2 for ingress and sum(1+2) for both. 
 * @param tcp_sport 
 *   The src tcp port to match.
 * @param tcp_dport
 *   The dest tcp port to match.
 *
 */
static int
fdir_add_tcp_flow(uint16_t port_id, uint16_t queue, uint16_t dir, 
		uint16_t tcp_sport, uint16_t tcp_dport)
{
    struct rte_flow_attr attr;
    struct rte_flow_item flow_pattern[4];
    struct rte_flow_action flow_action[2];
    struct rte_flow *flow = NULL;
    struct rte_flow_action_queue flow_action_queue = { .index = queue };
    struct rte_flow_item_tcp tcp_spec;
    struct rte_flow_item_tcp tcp_mask;
    struct rte_flow_error rfe;
    int res;

    memset(flow_pattern, 0, sizeof(flow_pattern));
    memset(flow_action, 0, sizeof(flow_action));

    /*
     * set the rule attribute.
     */
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.ingress = ((dir & FF_FLOW_INGRESS) > 0);
    attr.egress = ((dir & FF_FLOW_EGRESS) > 0); 

    /*
     * create the action sequence.
     * one action only, move packet to queue
     */
    flow_action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    flow_action[0].conf = &flow_action_queue;
    flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;

    flow_pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    flow_pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;

    /*
     * set the third level of the pattern (TCP).
     */
    memset(&tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
    memset(&tcp_mask, 0, sizeof(struct rte_flow_item_tcp));
    tcp_spec.hdr.src_port = htons(tcp_sport);
    tcp_mask.hdr.src_port = (tcp_sport == 0 ? 0: 0xffff); 
    tcp_spec.hdr.dst_port = htons(tcp_dport);
    tcp_mask.hdr.dst_port = (tcp_dport == 0 ? 0: 0xffff);
    flow_pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    flow_pattern[2].spec = &tcp_spec;
    flow_pattern[2].mask = &tcp_mask;

    flow_pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

    res = rte_flow_validate(port_id, &attr, flow_pattern, flow_action, &rfe);
    if (res)
	return (1);

    flow = rte_flow_create(port_id, &attr, flow_pattern, flow_action, &rfe);
    if (!flow) 
	return port_flow_complain(&rfe);

    return (0);
}

#endif

int
ff_dpdk_init(int argc, char **argv)
{
    if (ff_global_cfg.dpdk.nb_procs < 1 ||
        ff_global_cfg.dpdk.nb_procs > RTE_MAX_LCORE ||
        ff_global_cfg.dpdk.proc_id >= ff_global_cfg.dpdk.nb_procs ||
        ff_global_cfg.dpdk.proc_id < 0) {
        printf("param num_procs[%d] or proc_id[%d] error!\n",
            ff_global_cfg.dpdk.nb_procs,
            ff_global_cfg.dpdk.proc_id);
        exit(1);
    }

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    numa_on = ff_global_cfg.dpdk.numa_on;

    idle_sleep = ff_global_cfg.dpdk.idle_sleep;
    pkt_tx_delay = ff_global_cfg.dpdk.pkt_tx_delay > BURST_TX_DRAIN_US ? \
        BURST_TX_DRAIN_US : ff_global_cfg.dpdk.pkt_tx_delay;

    init_lcore_conf();

    init_mem_pool();

    init_dispatch_ring();

    init_msg_ring();

#ifdef FF_KNI
    enable_kni = ff_global_cfg.kni.enable;
    if (enable_kni) {
        init_kni();
    }
#endif

#ifdef FF_USE_PAGE_ARRAY
    ff_mmap_init();
#endif

#ifdef FF_FLOW_ISOLATE
    // run once in primary process
    if (0 == lcore_conf.tx_queue_id[0]){
        ret = port_flow_isolate(0, 1);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "init_port_isolate failed\n");
    }
#endif

    ret = init_port_start();
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "init_port_start failed\n");
    }

    init_clock();
#ifdef FF_FLOW_ISOLATE
    uint16_t port_id = 0;
    uint16_t network_port = 80;
    char* ip_addr = ff_global_cfg.dpdk.port_cfgs[0].addr;
    uint32_t ip = 0;
    ret = inet_pton(AF_INET, ip_addr, &ip);
    if (ret != 1) {
        rte_exit(EXIT_FAILURE, "Error converting IP address %s\n", ip_addr);
    } else {
        printf("Creating flow for %s (%x) on port %d\n", ip_addr, ip, network_port);
    }

    ret = init_flow(port_id, network_port, ip);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "init_port_flow failed\n");
    }
#endif

#ifdef FF_FDIR
    /*
     * Refer function header section for usage.
     */
    ret = fdir_add_tcp_flow(0, 0, FF_FLOW_INGRESS, 0, 80);
    if (ret)
	rte_exit(EXIT_FAILURE, "fdir_add_tcp_flow failed\n");
#endif

    return 0;
}

static void
ff_veth_input(const struct ff_dpdk_if_context *ctx, struct rte_mbuf *pkt)
{
    uint8_t rx_csum = ctx->hw_features.rx_csum;
    if (rx_csum) {
        if (pkt->ol_flags & (RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD)) {
            rte_pktmbuf_free(pkt);
            return;
        }
    }

    void *data = rte_pktmbuf_mtod(pkt, void*);
    uint16_t len = rte_pktmbuf_data_len(pkt);

    void *hdr = ff_mbuf_gethdr(pkt, pkt->pkt_len, data, len, rx_csum);
    if (hdr == NULL) {
        rte_pktmbuf_free(pkt);
        return;
    }

    if (pkt->ol_flags & RTE_MBUF_F_RX_VLAN_STRIPPED) {
        ff_mbuf_set_vlan_info(hdr, pkt->vlan_tci);
    }

    struct rte_mbuf *pn = pkt->next;
    void *prev = hdr;
    while(pn != NULL) {
        data = rte_pktmbuf_mtod(pn, void*);
        len = rte_pktmbuf_data_len(pn);

        void *mb = ff_mbuf_get(prev, pn, data, len);
        if (mb == NULL) {
            ff_mbuf_free(hdr);
            rte_pktmbuf_free(pkt);
            return;
        }
        pn = pn->next;
        prev = mb;
    }

    ff_veth_process_packet(ctx->ifp, hdr);
}

static enum FilterReturn
protocol_filter(const void *data, uint16_t len)
{
    if(len < RTE_ETHER_ADDR_LEN)
        return FILTER_UNKNOWN;

    const struct rte_ether_hdr *hdr;
    const struct rte_vlan_hdr *vlanhdr;
    hdr = (const struct rte_ether_hdr *)data;
    uint16_t ether_type = rte_be_to_cpu_16(hdr->ether_type);
    data += RTE_ETHER_HDR_LEN;
    len -= RTE_ETHER_HDR_LEN;

    if (ether_type == RTE_ETHER_TYPE_VLAN) {
        vlanhdr = (struct rte_vlan_hdr *)data;
        ether_type = rte_be_to_cpu_16(vlanhdr->eth_proto);
        data += sizeof(struct rte_vlan_hdr);
        len -= sizeof(struct rte_vlan_hdr);
    }

    if(ether_type == RTE_ETHER_TYPE_ARP)
        return FILTER_ARP;

#if (!defined(__FreeBSD__) && defined(INET6) ) || \
    ( defined(__FreeBSD__) && defined(INET6) && defined(FF_KNI))
    if (ether_type == RTE_ETHER_TYPE_IPV6) {
        return ff_kni_proto_filter(data,
            len, ether_type);
    }
#endif

#ifndef FF_KNI
    return FILTER_UNKNOWN;
#else
    if (!enable_kni) {
        return FILTER_UNKNOWN;
    }

    if(ether_type != RTE_ETHER_TYPE_IPV4)
        return FILTER_UNKNOWN;

    return ff_kni_proto_filter(data,
        len, ether_type);
#endif
}

static inline void
pktmbuf_deep_attach(struct rte_mbuf *mi, const struct rte_mbuf *m)
{
    struct rte_mbuf *md;
    void *src, *dst;

    dst = rte_pktmbuf_mtod(mi, void *);
    src = rte_pktmbuf_mtod(m, void *);

    mi->data_len = m->data_len;
    rte_memcpy(dst, src, m->data_len);

    mi->port = m->port;
    mi->vlan_tci = m->vlan_tci;
    mi->vlan_tci_outer = m->vlan_tci_outer;
    mi->tx_offload = m->tx_offload;
    mi->hash = m->hash;
    mi->ol_flags = m->ol_flags;
    mi->packet_type = m->packet_type;
}

/* copied from rte_pktmbuf_clone */
static inline struct rte_mbuf *
pktmbuf_deep_clone(const struct rte_mbuf *md,
    struct rte_mempool *mp)
{
    struct rte_mbuf *mc, *mi, **prev;
    uint32_t pktlen;
    uint8_t nseg;

    if (unlikely ((mc = rte_pktmbuf_alloc(mp)) == NULL))
        return NULL;

    mi = mc;
    prev = &mi->next;
    pktlen = md->pkt_len;
    nseg = 0;

    do {
        nseg++;
        pktmbuf_deep_attach(mi, md);
        *prev = mi;
        prev = &mi->next;
    } while ((md = md->next) != NULL &&
        (mi = rte_pktmbuf_alloc(mp)) != NULL);

    *prev = NULL;
    mc->nb_segs = nseg;
    mc->pkt_len = pktlen;

    /* Allocation of new indirect segment failed */
    if (unlikely (mi == NULL)) {
        rte_pktmbuf_free(mc);
        return NULL;
    }

    __rte_mbuf_sanity_check(mc, 1);
    return mc;
}

static inline void
process_packets(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **bufs,
    uint16_t count, const struct ff_dpdk_if_context *ctx, int pkts_from_ring)
{
    struct lcore_conf *qconf = &lcore_conf;
    uint16_t nb_queues = qconf->nb_queue_list[port_id];

    uint16_t i;
    for (i = 0; i < count; i++) {
        struct rte_mbuf *rtem = bufs[i];

        if (unlikely( ff_global_cfg.pcap.enable)) {
            if (!pkts_from_ring) {
                ff_dump_packets( ff_global_cfg.pcap.save_path, rtem, ff_global_cfg.pcap.snap_len, ff_global_cfg.pcap.save_len);
            }
        }

        void *data = rte_pktmbuf_mtod(rtem, void*);
        uint16_t len = rte_pktmbuf_data_len(rtem);

        if (!pkts_from_ring) {
            ff_traffic.rx_packets += rtem->nb_segs;
            ff_traffic.rx_bytes += rte_pktmbuf_pkt_len(rtem);
        }

        if (!pkts_from_ring && packet_dispatcher) {
            uint64_t cur_tsc = rte_rdtsc();
            int ret = (*packet_dispatcher)(data, &len, queue_id, nb_queues);
            usr_cb_tsc += rte_rdtsc() - cur_tsc;
            if (ret == FF_DISPATCH_RESPONSE) {
                rte_pktmbuf_pkt_len(rtem) = rte_pktmbuf_data_len(rtem) = len;

                /*
                 * We have not support vlan out strip
                 */
                if (rtem->vlan_tci) {
                    data = rte_pktmbuf_prepend(rtem, sizeof(struct rte_vlan_hdr));
                    if (data != NULL) {
                        memmove(data, data + sizeof(struct rte_vlan_hdr), RTE_ETHER_HDR_LEN);
                        struct rte_ether_hdr *etherhdr = (struct rte_ether_hdr *)data;
                        struct rte_vlan_hdr *vlanhdr = (struct rte_vlan_hdr *)(data + RTE_ETHER_HDR_LEN);
                        vlanhdr->vlan_tci = rte_cpu_to_be_16(rtem->vlan_tci);
                        vlanhdr->eth_proto = etherhdr->ether_type;
                        etherhdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
                    }
                }
                send_single_packet(rtem, port_id);
                continue;
            }

            if (ret == FF_DISPATCH_ERROR || ret >= nb_queues) {
                rte_pktmbuf_free(rtem);
                continue;
            }

            if (ret != queue_id) {
                ret = rte_ring_enqueue(dispatch_ring[port_id][ret], rtem);
                if (ret < 0)
                    rte_pktmbuf_free(rtem);

                continue;
            }
        }

        enum FilterReturn filter = protocol_filter(data, len);
#ifdef INET6
        if (filter == FILTER_ARP || filter == FILTER_NDP) {
#else
        if (filter == FILTER_ARP) {
#endif
            struct rte_mempool *mbuf_pool;
            struct rte_mbuf *mbuf_clone;
            if (!pkts_from_ring) {
                uint16_t j;
                for(j = 0; j < nb_queues; ++j) {
                    if(j == queue_id)
                        continue;

                    unsigned socket_id = 0;
                    if (numa_on) {
                        uint16_t lcore_id = qconf->port_cfgs[port_id].lcore_list[j];
                        socket_id = rte_lcore_to_socket_id(lcore_id);
                    }
                    mbuf_pool = pktmbuf_pool[socket_id];
                    mbuf_clone = pktmbuf_deep_clone(rtem, mbuf_pool);
                    if(mbuf_clone) {
                        int ret = rte_ring_enqueue(dispatch_ring[port_id][j],
                            mbuf_clone);
                        if (ret < 0)
                            rte_pktmbuf_free(mbuf_clone);
                    }
                }
            }

#ifdef FF_KNI
            if (enable_kni && rte_eal_process_type() == RTE_PROC_PRIMARY) {
                mbuf_pool = pktmbuf_pool[qconf->socket_id];
                mbuf_clone = pktmbuf_deep_clone(rtem, mbuf_pool);
                if(mbuf_clone) {
                    ff_kni_enqueue(port_id, mbuf_clone);
                }
            }
#endif
            ff_veth_input(ctx, rtem);
#ifdef FF_KNI
        } else if (enable_kni) {
            if (knictl_action == FF_KNICTL_ACTION_ALL_TO_KNI){
                ff_kni_enqueue(port_id, rtem);
            } else if (knictl_action == FF_KNICTL_ACTION_ALL_TO_FF){
                ff_veth_input(ctx, rtem);
            } else if (knictl_action == FF_KNICTL_ACTION_DEFAULT){
                if (enable_kni &&
                        ((filter == FILTER_KNI && kni_accept) ||
                        (filter == FILTER_UNKNOWN && !kni_accept)) ) {
                        ff_kni_enqueue(port_id, rtem);
                } else {
                    ff_veth_input(ctx, rtem);
                }
            } else {
                ff_veth_input(ctx, rtem);
            }
#endif
        } else {
            ff_veth_input(ctx, rtem);
        }
    }
}

static inline int
process_dispatch_ring(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, const struct ff_dpdk_if_context *ctx)
{
    /* read packet from ring buf and to process */
    uint16_t nb_rb;
    nb_rb = rte_ring_dequeue_burst(dispatch_ring[port_id][queue_id],
        (void **)pkts_burst, MAX_PKT_BURST, NULL);

    if(nb_rb > 0) {
        process_packets(port_id, queue_id, pkts_burst, nb_rb, ctx, 1);
    }

    return nb_rb;
}

static inline void
handle_sysctl_msg(struct ff_msg *msg)
{
    int ret = ff_sysctl(msg->sysctl.name, msg->sysctl.namelen,
        msg->sysctl.old, msg->sysctl.oldlenp, msg->sysctl.new,
        msg->sysctl.newlen);

    if (ret < 0) {
        msg->result = errno;
    } else {
        msg->result = 0;
    }
}

static inline void
handle_ioctl_msg(struct ff_msg *msg)
{
    int fd, ret;
#ifdef INET6
    if (msg->msg_type == FF_IOCTL6) {
        fd = ff_socket(AF_INET6, SOCK_DGRAM, 0);
    } else
#endif
        fd = ff_socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0) {
        ret = -1;
        goto done;
    }

    ret = ff_ioctl_freebsd(fd, msg->ioctl.cmd, msg->ioctl.data);

    ff_close(fd);

done:
    if (ret < 0) {
        msg->result = errno;
    } else {
        msg->result = 0;
    }
}

static inline void
handle_route_msg(struct ff_msg *msg)
{
    int ret = ff_rtioctl(msg->route.fib, msg->route.data,
        &msg->route.len, msg->route.maxlen);
    if (ret < 0) {
        msg->result = errno;
    } else {
        msg->result = 0;
    }
}

static inline void
handle_top_msg(struct ff_msg *msg)
{
    msg->top = ff_top_status;
    msg->result = 0;
}

#ifdef FF_NETGRAPH
static inline void
handle_ngctl_msg(struct ff_msg *msg)
{
    int ret = ff_ngctl(msg->ngctl.cmd, msg->ngctl.data);
    if (ret < 0) {
        msg->result = errno;
    } else {
        msg->result = 0;
        msg->ngctl.ret = ret;
    }
}
#endif

#ifdef FF_IPFW
static inline void
handle_ipfw_msg(struct ff_msg *msg)
{
    int fd, ret;
    fd = ff_socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
        ret = -1;
        goto done;
    }

    switch (msg->ipfw.cmd) {
        case FF_IPFW_GET:
            ret = ff_getsockopt_freebsd(fd, msg->ipfw.level,
                msg->ipfw.optname, msg->ipfw.optval,
                msg->ipfw.optlen);
            break;
        case FF_IPFW_SET:
            ret = ff_setsockopt_freebsd(fd, msg->ipfw.level,
                msg->ipfw.optname, msg->ipfw.optval,
                *(msg->ipfw.optlen));
            break;
        default:
            ret = -1;
            errno = ENOTSUP;
            break;
    }

    ff_close(fd);

done:
    if (ret < 0) {
        msg->result = errno;
    } else {
        msg->result = 0;
    }
}
#endif

static inline void
handle_traffic_msg(struct ff_msg *msg)
{
    msg->traffic = ff_traffic;
    msg->result = 0;
}

#ifdef FF_KNI
static inline void
handle_knictl_msg(struct ff_msg *msg)
{
    if (msg->knictl.kni_cmd == FF_KNICTL_CMD_SET){
        switch (msg->knictl.kni_action){
            case FF_KNICTL_ACTION_ALL_TO_FF: knictl_action = FF_KNICTL_ACTION_ALL_TO_FF; msg->result = 0; printf("new kni action: alltoff\n"); break;
            case FF_KNICTL_ACTION_ALL_TO_KNI: knictl_action = FF_KNICTL_ACTION_ALL_TO_KNI; msg->result = 0; printf("new kni action: alltokni\n"); break;
            case FF_KNICTL_ACTION_DEFAULT: knictl_action = FF_KNICTL_ACTION_DEFAULT; msg->result = 0; printf("new kni action: default\n"); break;
            default: msg->result = -1;
        }
    }
    else if (msg->knictl.kni_cmd == FF_KNICTL_CMD_GET){
        msg->knictl.kni_action = knictl_action;
    } else {
        msg->result = -2;
    }
}
#endif

static inline void
handle_default_msg(struct ff_msg *msg)
{
    msg->result = ENOTSUP;
}

static inline void
handle_msg(struct ff_msg *msg, uint16_t proc_id)
{
    switch (msg->msg_type) {
        case FF_SYSCTL:
            handle_sysctl_msg(msg);
            break;
        case FF_IOCTL:
#ifdef INET6
        case FF_IOCTL6:
#endif
            handle_ioctl_msg(msg);
            break;
        case FF_ROUTE:
            handle_route_msg(msg);
            break;
        case FF_TOP:
            handle_top_msg(msg);
            break;
#ifdef FF_NETGRAPH
        case FF_NGCTL:
            handle_ngctl_msg(msg);
            break;
#endif
#ifdef FF_IPFW
        case FF_IPFW_CTL:
            handle_ipfw_msg(msg);
            break;
#endif
        case FF_TRAFFIC:
            handle_traffic_msg(msg);
            break;
#ifdef FF_KNI
        case FF_KNICTL:
            handle_knictl_msg(msg);
            break;
#endif
        default:
            handle_default_msg(msg);
            break;
    }
    if (rte_ring_enqueue(msg_ring[proc_id].ring[msg->msg_type], msg) < 0) {
        if (msg->original_buf) {
            rte_free(msg->buf_addr);
            msg->buf_addr = msg->original_buf;
            msg->buf_len = msg->original_buf_len;
            msg->original_buf = NULL;
        }

        rte_mempool_put(message_pool, msg);
    }
}

static inline int
process_msg_ring(uint16_t proc_id, struct rte_mbuf **pkts_burst)
{
    /* read msg from ring buf and to process */
    uint16_t nb_rb;
    int i;

    nb_rb = rte_ring_dequeue_burst(msg_ring[proc_id].ring[0],
        (void **)pkts_burst, MAX_PKT_BURST, NULL);

    if (likely(nb_rb == 0))
        return 0;

    for (i = 0; i < nb_rb; ++i) {
        handle_msg((struct ff_msg *)pkts_burst[i], proc_id);
    }

    return 0;
}

/* Send burst of packets on an output interface */
static inline int
send_burst(struct lcore_conf *qconf, uint16_t n, uint8_t port)
{
    struct rte_mbuf **m_table;
    int ret;
    uint16_t queueid;

    queueid = qconf->tx_queue_id[port];
    m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;

    if (unlikely(ff_global_cfg.pcap.enable)) {
        uint16_t i;
        for (i = 0; i < n; i++) {
            ff_dump_packets( ff_global_cfg.pcap.save_path, m_table[i],
               ff_global_cfg.pcap.snap_len, ff_global_cfg.pcap.save_len);
        }
    }

    ret = rte_eth_tx_burst(port, queueid, m_table, n);
    ff_traffic.tx_packets += ret;
    uint16_t i;
    for (i = 0; i < ret; i++) {
        ff_traffic.tx_bytes += rte_pktmbuf_pkt_len(m_table[i]);
#ifdef FF_USE_PAGE_ARRAY
        if (qconf->tx_mbufs[port].bsd_m_table[i])
            ff_enq_tx_bsdmbuf(port, qconf->tx_mbufs[port].bsd_m_table[i], m_table[i]->nb_segs);
#endif
    }
    if (unlikely(ret < n)) {
        do {
            rte_pktmbuf_free(m_table[ret]);
#ifdef FF_USE_PAGE_ARRAY
            if ( qconf->tx_mbufs[port].bsd_m_table[ret] )
                ff_mbuf_free(qconf->tx_mbufs[port].bsd_m_table[ret]);
#endif
        } while (++ret < n);
    }
    return 0;
}

/* Enqueue a single packet, and send burst if queue is filled */
static inline int
send_single_packet(struct rte_mbuf *m, uint8_t port)
{
    uint16_t len;
    struct lcore_conf *qconf;

    qconf = &lcore_conf;
    len = qconf->tx_mbufs[port].len;
    qconf->tx_mbufs[port].m_table[len] = m;
    len++;

    /* enough pkts to be sent */
    if (unlikely(len == MAX_PKT_BURST)) {
        send_burst(qconf, MAX_PKT_BURST, port);
        len = 0;
    }

    qconf->tx_mbufs[port].len = len;
    return 0;
}

int
ff_dpdk_if_send(struct ff_dpdk_if_context *ctx, void *m,
    int total)
{
#ifdef FF_USE_PAGE_ARRAY
    struct lcore_conf *qconf = &lcore_conf;
    int    len = 0;

    len = ff_if_send_onepkt(ctx, m,total);
    if (unlikely(len == MAX_PKT_BURST)) {
        send_burst(qconf, MAX_PKT_BURST, ctx->port_id);
        len = 0;
    }
    qconf->tx_mbufs[ctx->port_id].len = len;
    return 0;
#endif
    struct rte_mempool *mbuf_pool = pktmbuf_pool[lcore_conf.socket_id];
    struct rte_mbuf *head = rte_pktmbuf_alloc(mbuf_pool);
    if (head == NULL) {
        ff_mbuf_free(m);
        return -1;
    }

    head->pkt_len = total;
    head->nb_segs = 0;

    int off = 0;
    struct rte_mbuf *cur = head, *prev = NULL;
    while(total > 0) {
        if (cur == NULL) {
            cur = rte_pktmbuf_alloc(mbuf_pool);
            if (cur == NULL) {
                rte_pktmbuf_free(head);
                ff_mbuf_free(m);
                return -1;
            }
        }

        if (prev != NULL) {
            prev->next = cur;
        }
        head->nb_segs++;

        prev = cur;
        void *data = rte_pktmbuf_mtod(cur, void*);
        int len = total > RTE_MBUF_DEFAULT_DATAROOM ? RTE_MBUF_DEFAULT_DATAROOM : total;
        int ret = ff_mbuf_copydata(m, data, off, len);
        if (ret < 0) {
            rte_pktmbuf_free(head);
            ff_mbuf_free(m);
            return -1;
        }


        cur->data_len = len;
        off += len;
        total -= len;
        cur = NULL;
    }

    struct ff_tx_offload offload = {0};
    ff_mbuf_tx_offload(m, &offload);

    void *data = rte_pktmbuf_mtod(head, void*);

    if (offload.ip_csum) {
        /* ipv6 not supported yet */
        struct rte_ipv4_hdr *iph;
        int iph_len;
        iph = (struct rte_ipv4_hdr *)(data + RTE_ETHER_HDR_LEN);
        iph_len = (iph->version_ihl & 0x0f) << 2;

        head->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
        head->l2_len = RTE_ETHER_HDR_LEN;
        head->l3_len = iph_len;
    }

    if (ctx->hw_features.tx_csum_l4) {
        struct rte_ipv4_hdr *iph;
        int iph_len;
        iph = (struct rte_ipv4_hdr *)(data + RTE_ETHER_HDR_LEN);
        iph_len = (iph->version_ihl & 0x0f) << 2;

        if (offload.tcp_csum) {
            head->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
            head->l2_len = RTE_ETHER_HDR_LEN;
            head->l3_len = iph_len;
        }

        /*
         *  TCP segmentation offload.
         *
         *  - set the PKT_TX_TCP_SEG flag in mbuf->ol_flags (this flag
         *    implies PKT_TX_TCP_CKSUM)
         *  - set the flag PKT_TX_IPV4 or PKT_TX_IPV6
         *  - if it's IPv4, set the PKT_TX_IP_CKSUM flag and
         *    write the IP checksum to 0 in the packet
         *  - fill the mbuf offload information: l2_len,
         *    l3_len, l4_len, tso_segsz
         *  - calculate the pseudo header checksum without taking ip_len
         *    in account, and set it in the TCP header. Refer to
         *    rte_ipv4_phdr_cksum() and rte_ipv6_phdr_cksum() that can be
         *    used as helpers.
         */
        if (offload.tso_seg_size) {
            struct rte_tcp_hdr *tcph;
            int tcph_len;
            tcph = (struct rte_tcp_hdr *)((char *)iph + iph_len);
            tcph_len = (tcph->data_off & 0xf0) >> 2;
            tcph->cksum = rte_ipv4_phdr_cksum(iph, RTE_MBUF_F_TX_TCP_SEG);

            head->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;
            head->l4_len = tcph_len;
            head->tso_segsz = offload.tso_seg_size;
        }

        if (offload.udp_csum) {
            head->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
            head->l2_len = RTE_ETHER_HDR_LEN;
            head->l3_len = iph_len;
        }
    }

    ff_mbuf_free(m);

    return send_single_packet(head, ctx->port_id);
}

static int
main_loop(void *arg)
{
    struct loop_routine *lr = (struct loop_routine *)arg;

    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    uint64_t prev_tsc, diff_tsc, cur_tsc, usch_tsc, div_tsc, usr_tsc, sys_tsc, end_tsc, idle_sleep_tsc;
    int i, j, nb_rx, idle;
    uint16_t port_id, queue_id;
    struct lcore_conf *qconf;
    uint64_t drain_tsc = 0;
    struct ff_dpdk_if_context *ctx;

    if (pkt_tx_delay) {
        drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * pkt_tx_delay;
    }

    prev_tsc = 0;
    usch_tsc = 0;

    qconf = &lcore_conf;

    while (1) {
        cur_tsc = rte_rdtsc();
        if (unlikely(freebsd_clock.expire < cur_tsc)) {
            rte_timer_manage();
        }

        idle = 1;
        sys_tsc = 0;
        usr_tsc = 0;
        usr_cb_tsc = 0;

        /*
         * TX burst queue drain
         */
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc >= drain_tsc)) {
            for (i = 0; i < qconf->nb_tx_port; i++) {
                port_id = qconf->tx_port_id[i];
                if (qconf->tx_mbufs[port_id].len == 0)
                    continue;

                idle = 0;

                send_burst(qconf,
                    qconf->tx_mbufs[port_id].len,
                    port_id);
                qconf->tx_mbufs[port_id].len = 0;
            }

            prev_tsc = cur_tsc;
        }

        /*
         * Read packet from RX queues
         */
        for (i = 0; i < qconf->nb_rx_queue; ++i) {
            port_id = qconf->rx_queue_list[i].port_id;
            queue_id = qconf->rx_queue_list[i].queue_id;
            ctx = veth_ctx[port_id];

#ifdef FF_KNI
            if (enable_kni && rte_eal_process_type() == RTE_PROC_PRIMARY) {
                ff_kni_process(port_id, queue_id, pkts_burst, MAX_PKT_BURST);
            }
#endif

            idle &= !process_dispatch_ring(port_id, queue_id, pkts_burst, ctx);

            nb_rx = rte_eth_rx_burst(port_id, queue_id, pkts_burst,
                MAX_PKT_BURST);
            if (nb_rx == 0)
                continue;

            idle = 0;

            /* Prefetch first packets */
            for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++) {
                rte_prefetch0(rte_pktmbuf_mtod(
                        pkts_burst[j], void *));
            }

            /* Prefetch and handle already prefetched packets */
            for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
                rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[
                        j + PREFETCH_OFFSET], void *));
                process_packets(port_id, queue_id, &pkts_burst[j], 1, ctx, 0);
            }

            /* Handle remaining prefetched packets */
            for (; j < nb_rx; j++) {
                process_packets(port_id, queue_id, &pkts_burst[j], 1, ctx, 0);
            }
        }

        process_msg_ring(qconf->proc_id, pkts_burst);

        div_tsc = rte_rdtsc();

        if (likely(lr->loop != NULL && (!idle || cur_tsc - usch_tsc >= drain_tsc))) {
            usch_tsc = cur_tsc;
            lr->loop(lr->arg);
        }

        idle_sleep_tsc = rte_rdtsc();
        if (likely(idle && idle_sleep)) {
            usleep(idle_sleep);
            end_tsc = rte_rdtsc();
        } else {
            end_tsc = idle_sleep_tsc;
        }

        usr_tsc = usr_cb_tsc;
        if (usch_tsc == cur_tsc) {
            usr_tsc += idle_sleep_tsc - div_tsc;
        }

        if (!idle) {
            sys_tsc = div_tsc - cur_tsc - usr_cb_tsc;
            ff_top_status.sys_tsc += sys_tsc;
        }

        ff_top_status.usr_tsc += usr_tsc;
        ff_top_status.work_tsc += end_tsc - cur_tsc;
        ff_top_status.idle_tsc += end_tsc - cur_tsc - usr_tsc - sys_tsc;

        ff_top_status.loops++;
    }

    return 0;
}

int
ff_dpdk_if_up(void) {
    int i;
    struct lcore_conf *qconf = &lcore_conf;
    for (i = 0; i < qconf->nb_tx_port; i++) {
        uint16_t port_id = qconf->tx_port_id[i];

        struct ff_port_cfg *pconf = &qconf->port_cfgs[port_id];
        veth_ctx[port_id] = ff_veth_attach(pconf);
        if (veth_ctx[port_id] == NULL) {
            rte_exit(EXIT_FAILURE, "ff_veth_attach failed");
        }
    }

    return 0;
}

void
ff_dpdk_run(loop_func_t loop, void *arg) {
    struct loop_routine *lr = rte_malloc(NULL,
        sizeof(struct loop_routine), 0);
    lr->loop = loop;
    lr->arg = arg;
    rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN);
    rte_eal_mp_wait_lcore();
    rte_free(lr);
}

void
ff_dpdk_pktmbuf_free(void *m)
{
    rte_pktmbuf_free_seg((struct rte_mbuf *)m);
}

static uint32_t
toeplitz_hash(unsigned keylen, const uint8_t *key,
    unsigned datalen, const uint8_t *data)
{
    uint32_t hash = 0, v;
    u_int i, b;

    /* XXXRW: Perhaps an assertion about key length vs. data length? */

    v = (key[0]<<24) + (key[1]<<16) + (key[2] <<8) + key[3];
    for (i = 0; i < datalen; i++) {
        for (b = 0; b < 8; b++) {
            if (data[i] & (1<<(7-b)))
                hash ^= v;
            v <<= 1;
            if ((i + 4) < keylen &&
                (key[i+4] & (1<<(7-b))))
                v |= 1;
        }
    }
    return (hash);
}

int
ff_in_pcbladdr(uint16_t family, void *faddr, uint16_t fport, void *laddr)
{
    int ret = 0;
    uint16_t fa;

    if (!pcblddr_fun)
        return ret;

    if (family == AF_INET)
        fa = AF_INET;
    else if (family == AF_INET6_FREEBSD)
        fa = AF_INET6_LINUX;
    else
        return EADDRNOTAVAIL;

    ret = (*pcblddr_fun)(fa, faddr, fport, laddr);

    return ret;
}

void
ff_regist_pcblddr_fun(pcblddr_func_t func)
{
    pcblddr_fun = func;
}

int
ff_rss_check(void *softc, uint32_t saddr, uint32_t daddr,
    uint16_t sport, uint16_t dport)
{
    struct lcore_conf *qconf = &lcore_conf;
    struct ff_dpdk_if_context *ctx = ff_veth_softc_to_hostc(softc);
    uint16_t nb_queues = qconf->nb_queue_list[ctx->port_id];

    if (nb_queues <= 1) {
        return 1;
    }

    uint16_t reta_size = rss_reta_size[ctx->port_id];
    uint16_t queueid = qconf->tx_queue_id[ctx->port_id];

    uint8_t data[sizeof(saddr) + sizeof(daddr) + sizeof(sport) +
        sizeof(dport)];

    unsigned datalen = 0;

    bcopy(&saddr, &data[datalen], sizeof(saddr));
    datalen += sizeof(saddr);

    bcopy(&daddr, &data[datalen], sizeof(daddr));
    datalen += sizeof(daddr);

    bcopy(&sport, &data[datalen], sizeof(sport));
    datalen += sizeof(sport);

    bcopy(&dport, &data[datalen], sizeof(dport));
    datalen += sizeof(dport);

    uint32_t hash = 0;
    hash = toeplitz_hash(rsskey_len, rsskey, datalen, data);

    return ((hash & (reta_size - 1)) % nb_queues) == queueid;
}

void
ff_regist_packet_dispatcher(dispatch_func_t func)
{
    packet_dispatcher = func;
}

uint64_t
ff_get_tsc_ns()
{
    uint64_t cur_tsc = rte_rdtsc();
    uint64_t hz = rte_get_tsc_hz();
    return ((double)cur_tsc/(double)hz) * NS_PER_S;
}

