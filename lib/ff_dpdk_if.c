/*
 * Copyright (C) 2017 THL A29 Limited, a Tencent company.
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

#include "ff_dpdk_if.h"
#include "ff_dpdk_pcap.h"
#include "ff_dpdk_kni.h"
#include "ff_config.h"
#include "ff_veth.h"
#include "ff_host_interface.h"
#include "ff_msg.h"
#include "ff_api.h"

#define MEMPOOL_CACHE_SIZE 256

#define ARP_RING_SIZE 2048

#define MSG_RING_SIZE 32

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RX_QUEUE_SIZE 512
#define TX_QUEUE_SIZE 256

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

/*
 * Try to avoid TX buffering if we have at least MAX_TX_BURST packets to send.
 */
#define MAX_TX_BURST    (MAX_PKT_BURST / 2)

#define NB_SOCKETS 8

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET    3

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

#define BITS_PER_HEX 4

#define KNI_MBUF_MAX 2048
#define KNI_QUEUE_SIZE 2048

static int enable_kni;
static int kni_accept;

static struct rte_timer freebsd_clock;

// Mellanox Linux's driver key
static uint8_t default_rsskey_40bytes[40] = {
    0xd1, 0x81, 0xc6, 0x2c, 0xf7, 0xf4, 0xdb, 0x5b,
    0x19, 0x83, 0xa2, 0xfc, 0x94, 0x3e, 0x1a, 0xdb,
    0xd9, 0x38, 0x9e, 0x6b, 0xd1, 0x03, 0x9c, 0x2c,
    0xa7, 0x44, 0x99, 0xad, 0x59, 0x3d, 0x56, 0xd9,
    0xf3, 0x25, 0x3c, 0x06, 0x2a, 0xdc, 0x1f, 0xfc
};

static struct rte_eth_conf default_port_conf = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS,
        .max_rx_pkt_len = ETHER_MAX_LEN,
        .split_hdr_size = 0, /**< hdr buf size */
        .header_split   = 0, /**< Header Split disabled */
        .hw_ip_checksum = 0, /**< IP checksum offload disabled */
        .hw_vlan_filter = 0, /**< VLAN filtering disabled */
        .hw_vlan_strip  = 0, /**< VLAN strip disabled. */
        .hw_vlan_extend = 0, /**< Extended VLAN disabled. */
        .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
        .hw_strip_crc   = 0, /**< CRC stripped by hardware */
        .enable_lro     = 0, /**< LRO disabled */
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = default_rsskey_40bytes,
            .rss_key_len = 40,
            .rss_hf = ETH_RSS_PROTO_MASK,
        },
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

struct mbuf_table {
    uint16_t len;
    struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct lcore_rx_queue {
    uint8_t port_id;
    uint8_t queue_id;
} __rte_cache_aligned;

struct lcore_conf {
    uint16_t proc_id;
    uint16_t nb_procs;
    uint16_t socket_id;
    uint16_t nb_rx_queue;
    uint16_t *lcore_proc;
    struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
    uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
    struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
    char *pcap[RTE_MAX_ETHPORTS];
} __rte_cache_aligned;

static struct lcore_conf lcore_conf;

static struct rte_mempool *pktmbuf_pool[NB_SOCKETS];

static struct rte_ring **arp_ring[RTE_MAX_LCORE];

struct ff_msg_ring {
    char ring_name[2][RTE_RING_NAMESIZE];
    /* ring[0] for lcore recv msg, other send */
    /* ring[1] for lcore send msg, other read */
    struct rte_ring *ring[2];
} __rte_cache_aligned;

static struct ff_msg_ring msg_ring[RTE_MAX_LCORE];
static struct rte_mempool *message_pool;

struct ff_dpdk_if_context {
    void *sc;
    void *ifp;
    uint16_t port_id;
    struct ff_hw_features hw_features;
} __rte_cache_aligned;

static struct ff_dpdk_if_context *veth_ctx[RTE_MAX_ETHPORTS];

extern void ff_hardclock(void);

static void
freebsd_hardclock_job(__rte_unused struct rte_timer *timer,
    __rte_unused void *arg) {
    ff_hardclock();
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

    uint8_t portid, count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;

    printf("\nChecking link status");
    fflush(stdout);

    int i, nb_ports;
    nb_ports = ff_global_cfg.dpdk.nb_ports;
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        all_ports_up = 1;
        for (i = 0; i < nb_ports; i++) {
            uint8_t portid = ff_global_cfg.dpdk.port_cfgs[i].port_id;
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
xdigit2val(unsigned char c)
{
    int val;

    if (isdigit(c))
        val = c - '0';
    else if (isupper(c))
        val = c - 'A' + 10;
    else
        val = c - 'a' + 10;
    return val;
}

static int
parse_lcore_mask(const char *coremask, uint16_t *lcore_proc,
    uint16_t nb_procs)
{
    int i, j, idx = 0;
    unsigned count = 0;
    char c;
    int val;

    if (coremask == NULL)
        return -1;

    /* Remove all blank characters ahead and after.
     * Remove 0x/0X if exists.
     */
    while (isblank(*coremask))
        coremask++;
    if (coremask[0] == '0' && ((coremask[1] == 'x')
        || (coremask[1] == 'X')))
        coremask += 2;

    i = strlen(coremask);
    while ((i > 0) && isblank(coremask[i - 1]))
        i--;

    if (i == 0)
        return -1;

    for (i = i - 1; i >= 0 && idx < RTE_MAX_LCORE && count < nb_procs; i--) {
        c = coremask[i];
        if (isxdigit(c) == 0) {
            return -1;
        }
        val = xdigit2val(c);
        for (j = 0; j < BITS_PER_HEX && idx < RTE_MAX_LCORE && count < nb_procs;
            j++, idx++) {
            if ((1 << j) & val) {
                if (!lcore_config[idx].detected) {
                    RTE_LOG(ERR, EAL, "lcore %u unavailable\n", idx);
                    return -1;
                }
                lcore_proc[count] = idx;
                count++;
            }
        }
    }

    for (; i >= 0; i--)
        if (coremask[i] != '0')
            return -1;

    if (count < nb_procs)
        return -1;

    return 0;
}

static int
init_lcore_conf(void)
{
    uint8_t nb_ports = rte_eth_dev_count();
    if (nb_ports == 0) {
        rte_exit(EXIT_FAILURE, "No probed ethernet devices\n");
    }

    lcore_conf.proc_id = ff_global_cfg.dpdk.proc_id;
    lcore_conf.nb_procs = ff_global_cfg.dpdk.nb_procs;
    lcore_conf.lcore_proc = rte_zmalloc(NULL,
        sizeof(uint16_t)*lcore_conf.nb_procs, 0);
    if (lcore_conf.lcore_proc == NULL) {
        rte_exit(EXIT_FAILURE, "rte_zmalloc lcore_proc failed\n");
    }

    int ret = parse_lcore_mask(ff_global_cfg.dpdk.lcore_mask,
        lcore_conf.lcore_proc, lcore_conf.nb_procs);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "parse_lcore_mask failed:%s\n",
            ff_global_cfg.dpdk.lcore_mask);
    }

    uint16_t socket_id = 0;
    if (ff_global_cfg.dpdk.numa_on) {
        socket_id = rte_lcore_to_socket_id(rte_lcore_id());
    }

    lcore_conf.socket_id = socket_id;

    /* Currently, proc id 1:1 map to rx/tx queue id per port. */
    uint8_t port_id, enabled_ports = 0;
    for (port_id = 0; port_id < nb_ports; port_id++) {
        if (ff_global_cfg.dpdk.port_mask &&
            (ff_global_cfg.dpdk.port_mask & (1 << port_id)) == 0) {
            printf("\nSkipping disabled port %d\n", port_id);
            continue;
        }

        if (port_id >= ff_global_cfg.dpdk.nb_ports) {
            printf("\nSkipping non-configured port %d\n", port_id);
            break;
        }

        uint16_t nb_rx_queue = lcore_conf.nb_rx_queue;
        lcore_conf.rx_queue_list[nb_rx_queue].port_id = port_id;
        lcore_conf.rx_queue_list[nb_rx_queue].queue_id = lcore_conf.proc_id;
        lcore_conf.nb_rx_queue++;

        lcore_conf.tx_queue_id[port_id] = lcore_conf.proc_id;
        lcore_conf.pcap[port_id] = ff_global_cfg.dpdk.port_cfgs[enabled_ports].pcap;

        ff_global_cfg.dpdk.port_cfgs[enabled_ports].port_id = port_id;

        enabled_ports++;
    }

    ff_global_cfg.dpdk.nb_ports = enabled_ports;

    return 0;
}

static int
init_mem_pool(void)
{
    uint8_t nb_ports = ff_global_cfg.dpdk.nb_ports;
    uint32_t nb_lcores = ff_global_cfg.dpdk.nb_procs;
    uint32_t nb_tx_queue = nb_lcores;
    uint32_t nb_rx_queue = lcore_conf.nb_rx_queue * nb_lcores;

    unsigned nb_mbuf = RTE_MAX (
        (nb_rx_queue*RX_QUEUE_SIZE          +
        nb_ports*nb_lcores*MAX_PKT_BURST    +
        nb_ports*nb_tx_queue*TX_QUEUE_SIZE  +
        nb_lcores*MEMPOOL_CACHE_SIZE +
        nb_ports*KNI_MBUF_MAX +
        nb_ports*KNI_QUEUE_SIZE +
        nb_lcores*nb_ports*ARP_RING_SIZE),
        (unsigned)8192);

    unsigned socketid = 0;
    uint16_t i, lcore_id;
    char s[64];
    int numa_on = ff_global_cfg.dpdk.numa_on;

    for (i = 0; i < lcore_conf.nb_procs; i++) {
        lcore_id = lcore_conf.lcore_proc[i];
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
    }

    return 0;
}

static struct rte_ring *
create_ring(const char *name, unsigned count, int socket_id, unsigned flags)
{
    struct rte_ring *ring;

    if (name == NULL)
        return NULL;

    /* If already create, just attached it */
    if (likely((ring = rte_ring_lookup(name)) != NULL))
        return ring;

    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        return rte_ring_create(name, count, socket_id, flags);
    } else {
        return rte_ring_lookup(name);
    }
}

static int
init_arp_ring(void)
{
    int i, j, ret;
    char name_buf[RTE_RING_NAMESIZE];
    int nb_procs = ff_global_cfg.dpdk.nb_procs;
    int proc_id = ff_global_cfg.dpdk.proc_id;

    /* Allocate arp ring ptr according to eth dev count. */
    int nb_ports = rte_eth_dev_count();
    for(i = 0; i < nb_procs; ++i) {
        snprintf(name_buf, RTE_RING_NAMESIZE, "ring_ptr_%d_%d",
            proc_id, i);

        arp_ring[i] = rte_zmalloc(name_buf,
            sizeof(struct rte_ring *) * nb_ports,
             RTE_CACHE_LINE_SIZE);
        if (arp_ring[i] == NULL) {
            rte_exit(EXIT_FAILURE, "rte_zmalloc(%s (struct rte_ring*)) "
                "failed\n", name_buf);
        }
    }

    unsigned socketid = lcore_conf.socket_id;

    /* Create ring according to ports actually being used. */
    nb_ports = ff_global_cfg.dpdk.nb_ports;
    for (j = 0; j < nb_ports; j++) {
        uint8_t port_id = ff_global_cfg.dpdk.port_cfgs[j].port_id;

        for(i = 0; i < nb_procs; ++i) {
            snprintf(name_buf, RTE_RING_NAMESIZE, "arp_ring_%d_%d", i, port_id);
            arp_ring[i][port_id] = create_ring(name_buf, ARP_RING_SIZE,
                socketid, RING_F_SC_DEQ);

            if (arp_ring[i][port_id] == NULL)
                rte_panic("create ring:%s failed!\n", name_buf);

            printf("create ring:%s success, %u ring entries are now free!\n",
                name_buf, rte_ring_free_count(arp_ring[i][port_id]));
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
}

static int
init_msg_ring(void)
{
    uint16_t i;
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
        snprintf(msg_ring[i].ring_name[1], RTE_RING_NAMESIZE,
            "%s%u", FF_MSG_RING_OUT, i);

        msg_ring[i].ring[0] = create_ring(msg_ring[i].ring_name[0],
            MSG_RING_SIZE, socketid, RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (msg_ring[i].ring[0] == NULL)
            rte_panic("create ring::%s failed!\n", msg_ring[i].ring_name[0]);

        msg_ring[i].ring[1] = create_ring(msg_ring[i].ring_name[1],
            MSG_RING_SIZE, socketid, RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (msg_ring[i].ring[1] == NULL)
            rte_panic("create ring::%s failed!\n", msg_ring[i].ring_name[0]);
    }

    return 0;
}

static int
init_kni(void)
{
    int nb_ports = rte_eth_dev_count();
    kni_accept = 0;
    if(strcasecmp(ff_global_cfg.kni.method, "accept") == 0)
        kni_accept = 1;

    ff_kni_init(nb_ports, ff_global_cfg.kni.tcp_port,
        ff_global_cfg.kni.udp_port);

    unsigned socket_id = lcore_conf.socket_id;
    struct rte_mempool *mbuf_pool = pktmbuf_pool[socket_id];

    nb_ports = ff_global_cfg.dpdk.nb_ports;
    int i, ret;
    for (i = 0; i < nb_ports; i++) {
        uint8_t port_id = ff_global_cfg.dpdk.port_cfgs[i].port_id;
        ff_kni_alloc(port_id, socket_id, mbuf_pool, KNI_QUEUE_SIZE);
    }

    return 0;
}

static int
init_port_start(void)
{
    int nb_ports = ff_global_cfg.dpdk.nb_ports;
    uint16_t nb_procs = ff_global_cfg.dpdk.nb_procs;
    unsigned socketid = rte_lcore_to_socket_id(rte_lcore_id());
    struct rte_mempool *mbuf_pool = pktmbuf_pool[socketid];
    uint16_t i;

    for (i = 0; i < nb_ports; i++) {
        uint8_t port_id = ff_global_cfg.dpdk.port_cfgs[i].port_id;

        struct rte_eth_dev_info dev_info;
        rte_eth_dev_info_get(port_id, &dev_info);

        if (nb_procs > dev_info.max_rx_queues) {
            rte_exit(EXIT_FAILURE, "num_procs[%d] bigger than max_rx_queues[%d]\n",
                nb_procs,
                dev_info.max_rx_queues);
        }

        if (nb_procs > dev_info.max_tx_queues) {
            rte_exit(EXIT_FAILURE, "num_procs[%d] bigger than max_tx_queues[%d]\n",
                nb_procs,
                dev_info.max_tx_queues);
        }

        struct ether_addr addr;
        rte_eth_macaddr_get(port_id, &addr);
        printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
                   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
                (unsigned)port_id,
                addr.addr_bytes[0], addr.addr_bytes[1],
                addr.addr_bytes[2], addr.addr_bytes[3],
                addr.addr_bytes[4], addr.addr_bytes[5]);

        rte_memcpy(ff_global_cfg.dpdk.port_cfgs[i].mac,
            addr.addr_bytes, ETHER_ADDR_LEN);

        /* Clear txq_flags - we do not need multi-mempool and refcnt */
        dev_info.default_txconf.txq_flags = ETH_TXQ_FLAGS_NOMULTMEMP |
            ETH_TXQ_FLAGS_NOREFCOUNT;

        /* Disable features that are not supported by port's HW */
        if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM)) {
            dev_info.default_txconf.txq_flags |= ETH_TXQ_FLAGS_NOXSUMUDP;
        }

        if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM)) {
            dev_info.default_txconf.txq_flags |= ETH_TXQ_FLAGS_NOXSUMTCP;
        }

        if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_SCTP_CKSUM)) {
            dev_info.default_txconf.txq_flags |= ETH_TXQ_FLAGS_NOXSUMSCTP;
        }

        if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_VLAN_INSERT)) {
            dev_info.default_txconf.txq_flags |= ETH_TXQ_FLAGS_NOVLANOFFL;
        }

        if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_VLAN_INSERT)) {
            dev_info.default_txconf.txq_flags |= ETH_TXQ_FLAGS_NOVLANOFFL;
        }

        if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_TSO) &&
            !(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_TSO)) {
            dev_info.default_txconf.txq_flags |= ETH_TXQ_FLAGS_NOMULTSEGS;
        }

        struct rte_eth_conf port_conf = {0};

        /* Set RSS mode */
        port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
        port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_PROTO_MASK;
        port_conf.rx_adv_conf.rss_conf.rss_key = default_rsskey_40bytes;
        port_conf.rx_adv_conf.rss_conf.rss_key_len = 40;

        /* Set Rx VLAN stripping */
        if (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_VLAN_STRIP) {
            port_conf.rxmode.hw_vlan_strip = 1;
        }

        /* Enable HW CRC stripping */
        port_conf.rxmode.hw_strip_crc = 1;

        /* FIXME: Enable TCP LRO ?*/
        #if 0
        if (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_TCP_LRO) {
            printf("LRO is supported\n");
            port_conf.rxmode.enable_lro = 1;
            ff_global_cfg.dpdk.port_cfgs[i].hw_features.rx_lro = 1;
        }
        #endif

        /* Set Rx checksum checking */
        if ((dev_info.rx_offload_capa & DEV_RX_OFFLOAD_IPV4_CKSUM) &&
            (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_UDP_CKSUM) &&
            (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_TCP_CKSUM)) {
            printf("RX checksum offload supported\n");
            port_conf.rxmode.hw_ip_checksum = 1;
            ff_global_cfg.dpdk.port_cfgs[i].hw_features.rx_csum = 1;
        }

        if ((dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM)) {
            printf("TX ip checksum offload supported\n");
            ff_global_cfg.dpdk.port_cfgs[i].hw_features.tx_csum_ip = 1;
        }

        if ((dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM) &&
            (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM)) {
            printf("TX TCP&UDP checksum offload supported\n");
            ff_global_cfg.dpdk.port_cfgs[i].hw_features.tx_csum_l4 = 1;
        }

        if (ff_global_cfg.dpdk.tso) {
            if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_TSO) {
                printf("TSO is supported\n");
                ff_global_cfg.dpdk.port_cfgs[i].hw_features.tx_tso = 1;
            }
        } else {
            printf("TSO is disabled\n");
        }

        if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
            continue;
        }

        /* Currently, proc id 1:1 map to queue id per port. */
        int ret = rte_eth_dev_configure(port_id, nb_procs, nb_procs, &port_conf);
        if (ret != 0) {
            return ret;
        }

        uint16_t q;
        for (q = 0; q < nb_procs; q++) {
            ret = rte_eth_tx_queue_setup(port_id, q, TX_QUEUE_SIZE,
                socketid, &dev_info.default_txconf);
            if (ret < 0) {
                return ret;
            }

            ret = rte_eth_rx_queue_setup(port_id, q, RX_QUEUE_SIZE,
                socketid, &dev_info.default_rxconf, mbuf_pool);
            if (ret < 0) {
                return ret;
            }
        }

        ret = rte_eth_dev_start(port_id);
        if (ret < 0) {
            return ret;
        }

        /* Enable RX in promiscuous mode for the Ethernet device. */
        if (ff_global_cfg.dpdk.promiscuous) {
            rte_eth_promiscuous_enable(port_id);
            ret = rte_eth_promiscuous_get(port_id);
            if (ret == 1) {
                printf("set port %u to promiscuous mode ok\n", port_id);
            } else {
                printf("set port %u to promiscuous mode error\n", port_id);
            }
        }

        /* Enable pcap dump */
        if (ff_global_cfg.dpdk.port_cfgs[i].pcap) {
            ff_enable_pcap(ff_global_cfg.dpdk.port_cfgs[i].pcap);
        }
    }

    return 0;
}

static int
init_freebsd_clock(void)
{
    rte_timer_subsystem_init();
    uint64_t hz = rte_get_timer_hz();
    uint64_t intrs = MS_PER_S/ff_global_cfg.freebsd.hz;
    uint64_t tsc = (hz + MS_PER_S - 1) / MS_PER_S*intrs;

    rte_timer_init(&freebsd_clock);
    rte_timer_reset(&freebsd_clock, tsc, PERIODICAL,
        rte_lcore_id(), &freebsd_hardclock_job, NULL);

    return 0;
}

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

    init_lcore_conf();

    init_mem_pool();

    init_arp_ring();

    init_msg_ring();

    enable_kni = ff_global_cfg.kni.enable;
    if (enable_kni) {
        init_kni();
    }

    ret = init_port_start();
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "init_port_start failed\n");
    }

    check_all_ports_link_status();

    init_freebsd_clock();

    return 0;
}

static void
ff_veth_input(const struct ff_dpdk_if_context *ctx, struct rte_mbuf *pkt)
{
    uint8_t rx_csum = ctx->hw_features.rx_csum;
    if (rx_csum) {
        if (pkt->ol_flags & (PKT_RX_IP_CKSUM_BAD | PKT_RX_L4_CKSUM_BAD)) {
            return;
        }
    }

    /* 
     * FIXME: should we save pkt->vlan_tci
     * if (pkt->ol_flags & PKT_RX_VLAN_PKT)
     */

    void *data = rte_pktmbuf_mtod(pkt, void*);
    uint16_t len = rte_pktmbuf_data_len(pkt);

    void *hdr = ff_mbuf_gethdr(pkt, pkt->pkt_len, data, len, rx_csum);
    if (hdr == NULL) {
        rte_pktmbuf_free(pkt);
        return;
    }

    struct rte_mbuf *pn = pkt->next;
    void *prev = hdr;
    while(pn != NULL) {
        data = rte_pktmbuf_mtod(pkt, void*);
        len = rte_pktmbuf_data_len(pkt);

        void *mb = ff_mbuf_get(prev, data, len);
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
    if(len < sizeof(struct ether_hdr))
        return FILTER_UNKNOWN;

    const struct ether_hdr *hdr;
    hdr = (const struct ether_hdr *)data;

    if(ntohs(hdr->ether_type) == ETHER_TYPE_ARP)
        return FILTER_ARP;

    if (!enable_kni) {
        return FILTER_UNKNOWN;
    }

    if(ntohs(hdr->ether_type) != ETHER_TYPE_IPv4)
        return FILTER_UNKNOWN;

    return ff_kni_proto_filter(data + sizeof(struct ether_hdr),
        len - sizeof(struct ether_hdr));
}

static inline void
process_packets(uint8_t port_id, uint16_t queue_id, struct rte_mbuf **bufs,
    uint16_t count, const struct ff_dpdk_if_context *ctx, int pkts_from_ring)
{
    struct lcore_conf *qconf = &lcore_conf;

    uint16_t i;
    for (i = 0; i < count; i++) {
        struct rte_mbuf *rtem = bufs[i];

        if (unlikely(qconf->pcap[port_id] != NULL)) {
            ff_dump_packets(qconf->pcap[port_id], rtem);
        }

        void *data = rte_pktmbuf_mtod(rtem, void*);
        uint16_t len = rte_pktmbuf_data_len(rtem);

        enum FilterReturn filter = protocol_filter(data, len);
        if (filter == FILTER_ARP) {
            struct rte_mempool *mbuf_pool;
            struct rte_mbuf *mbuf_clone;
            if (pkts_from_ring == 0) {
                uint16_t i;
                for(i = 0; i < qconf->nb_procs; ++i) {
                    if(i == queue_id)
                        continue;

                    mbuf_pool = pktmbuf_pool[rte_lcore_to_socket_id(qconf->lcore_proc[i])];
                    mbuf_clone = rte_pktmbuf_clone(rtem, mbuf_pool);
                    if(mbuf_clone) {
                        int ret = rte_ring_enqueue(arp_ring[i][port_id], mbuf_clone);
                        if (ret < 0)
                            rte_pktmbuf_free(mbuf_clone);
                    }
                }
            }

            if (enable_kni && rte_eal_process_type() == RTE_PROC_PRIMARY) {
                mbuf_pool = pktmbuf_pool[qconf->socket_id];
                mbuf_clone = rte_pktmbuf_clone(rtem, mbuf_pool);
                if(mbuf_clone) {
                    ff_kni_enqueue(port_id, rtem);
                }
            }

            ff_veth_input(ctx, rtem);
        } else if (enable_kni && ((filter == FILTER_KNI && kni_accept) ||
            (filter == FILTER_UNKNOWN && !kni_accept)) ) {
            ff_kni_enqueue(port_id, rtem);
        } else {
            ff_veth_input(ctx, rtem);
        }
    }
}

static inline int
process_arp_ring(uint8_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, const struct ff_dpdk_if_context *ctx)
{
    /* read packet from ring buf and to process */
    uint16_t nb_rb;
    nb_rb = rte_ring_dequeue_burst(arp_ring[queue_id][port_id],
        (void **)pkts_burst, MAX_PKT_BURST);

    if(nb_rb > 0) {
        process_packets(port_id, queue_id, pkts_burst, nb_rb, ctx, 1);
    }

    return 0;
}

static inline void
handle_sysctl_msg(struct ff_msg *msg, uint16_t proc_id)
{
    int ret = ff_sysctl(msg->sysctl.name, msg->sysctl.namelen,
        msg->sysctl.old, msg->sysctl.oldlenp, msg->sysctl.new,
        msg->sysctl.newlen);

    if (ret < 0) {
        msg->result = errno;
    } else {
        msg->result = 0;
    }

    rte_ring_enqueue(msg_ring[proc_id].ring[1], msg);
}

static inline void
handle_ioctl_msg(struct ff_msg *msg, uint16_t proc_id)
{
    int fd, ret;
    fd = ff_socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        ret = -1;
        goto done;
    }

    ret = ff_ioctl(fd, msg->ioctl.cmd, msg->ioctl.data);

    ff_close(fd);

done:
    if (ret < 0) {
        msg->result = errno;
    } else {
        msg->result = 0;
    }

    rte_ring_enqueue(msg_ring[proc_id].ring[1], msg);
}

static inline void
handle_route_msg(struct ff_msg *msg, uint16_t proc_id)
{
    msg->result = ff_rtioctl(msg->route.fib, msg->route.data,
        &msg->route.len, msg->route.maxlen);

    rte_ring_enqueue(msg_ring[proc_id].ring[1], msg);
}

static inline void
handle_default_msg(struct ff_msg *msg, uint16_t proc_id)
{
    msg->result = EINVAL;
    rte_ring_enqueue(msg_ring[proc_id].ring[1], msg);
}

static inline void
handle_msg(struct ff_msg *msg, uint16_t proc_id)
{
    switch (msg->msg_type) {
        case FF_SYSCTL:
            handle_sysctl_msg(msg, proc_id);
            break;
        case FF_IOCTL:
            handle_ioctl_msg(msg, proc_id);
            break;
        case FF_ROUTE:
            handle_route_msg(msg, proc_id);
            break;
        default:
            handle_default_msg(msg, proc_id);
            break;
    }
}

static inline int
process_msg_ring(uint16_t proc_id)
{
    void *msg;
    int ret = rte_ring_dequeue(msg_ring[proc_id].ring[0], &msg);

    if (unlikely(ret == 0)) {
        handle_msg((struct ff_msg *)msg, proc_id);
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

    if (unlikely(qconf->pcap[port] != NULL)) {
        uint16_t i;
        for (i = 0; i < n; i++) {
            ff_dump_packets(qconf->pcap[port], m_table[i]);
        }
    }

    ret = rte_eth_tx_burst(port, queueid, m_table, n);
    if (unlikely(ret < n)) {
        do {
            rte_pktmbuf_free(m_table[ret]);
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

        void *data = rte_pktmbuf_mtod(cur, void*);
        int len = total > RTE_MBUF_DEFAULT_DATAROOM ? RTE_MBUF_DEFAULT_DATAROOM : total;
        int ret = ff_mbuf_copydata(m, data, off, len);
        if (ret < 0) {
            rte_pktmbuf_free(head);
            ff_mbuf_free(m);
            return -1;
        }

        if (prev != NULL) {
            prev->next = cur;
        }
        prev = cur;

        cur->data_len = len;
        off += len;
        total -= len;
        head->nb_segs++;
        cur = NULL;
    }

    struct ff_tx_offload offload = {0};
    ff_mbuf_tx_offload(m, &offload);

    if (offload.ip_csum) {
        head->ol_flags |= PKT_TX_IP_CKSUM;
        head->l2_len = sizeof(struct ether_hdr);
        head->l3_len = sizeof(struct ipv4_hdr);
    }

    if (ctx->hw_features.tx_csum_l4) {
        if (offload.tcp_csum) {
            head->ol_flags |= PKT_TX_TCP_CKSUM;
            head->l2_len = sizeof(struct ether_hdr);
            head->l3_len = sizeof(struct ipv4_hdr);
        }

        if (offload.tso_seg_size) {
            head->ol_flags |= PKT_TX_TCP_SEG;
            head->l4_len = sizeof(struct tcp_hdr);
            head->tso_segsz = offload.tso_seg_size;
        }

        if (offload.udp_csum) {
            head->ol_flags |= PKT_TX_UDP_CKSUM;
            head->l2_len = sizeof(struct ether_hdr);
            head->l3_len = sizeof(struct ipv4_hdr);
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
    unsigned lcore_id;
    uint64_t prev_tsc, diff_tsc, cur_tsc;
    int i, j, nb_rx;
    uint8_t port_id, queue_id;
    struct lcore_conf *qconf;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
        US_PER_S * BURST_TX_DRAIN_US;
    struct ff_dpdk_if_context *ctx;

    prev_tsc = 0;

    lcore_id = rte_lcore_id();
    qconf = &lcore_conf;

    if (qconf->nb_rx_queue == 0) {
        printf("lcore %u has nothing to do\n", lcore_id);
        return 0;
    }

    while (1) {
        cur_tsc = rte_rdtsc();
        if (unlikely(freebsd_clock.expire < cur_tsc)) {
            rte_timer_manage();
        }

        /*
         * TX burst queue drain
         */
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            /*
             * This could be optimized (use queueid instead of
             * portid), but it is not called so often
             */
            for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
                if (qconf->tx_mbufs[port_id].len == 0)
                    continue;
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

            if (enable_kni && rte_eal_process_type() == RTE_PROC_PRIMARY) {
                ff_kni_process(port_id, queue_id, pkts_burst, MAX_PKT_BURST);
            }

            process_arp_ring(port_id, queue_id, pkts_burst, ctx);

            nb_rx = rte_eth_rx_burst(port_id, queue_id, pkts_burst,
                MAX_PKT_BURST);
            if (nb_rx == 0)
                continue;

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

        process_msg_ring(qconf->proc_id);

        if (likely(lr->loop != NULL)) {
            lr->loop(lr->arg);
        }
    }
}

int
ff_dpdk_if_up(void) {
    int nb_ports = ff_global_cfg.dpdk.nb_ports;
    int i;
    for (i = 0; i < nb_ports; i++) {
        uint8_t port_id = ff_global_cfg.dpdk.port_cfgs[i].port_id;
        veth_ctx[port_id] = ff_veth_attach(ff_global_cfg.dpdk.port_cfgs + i);
        if (veth_ctx[port_id] == NULL) {
            rte_exit(EXIT_FAILURE, "ff_veth_attach failed");
        }
    }

    return 0;
}

void
ff_dpdk_run(loop_func_t loop, void *arg) {
    struct loop_routine *lr = malloc(sizeof(struct loop_routine));
    lr->loop = loop;
    lr->arg = arg;
    rte_eal_mp_remote_launch(main_loop, lr, CALL_MASTER);
    rte_eal_mp_wait_lcore();
    free(lr);
}

void
ff_dpdk_pktmbuf_free(void *m)
{
    rte_pktmbuf_free((struct rte_mbuf *)m);
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
ff_rss_check(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport)
{
    struct lcore_conf *qconf = &lcore_conf;

    if (qconf->nb_procs == 1) {
        return 1;
    }

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

    uint32_t hash = toeplitz_hash(sizeof(default_rsskey_40bytes), default_rsskey_40bytes, datalen, data);

    return (hash % qconf->nb_procs) == qconf->proc_id;
}


