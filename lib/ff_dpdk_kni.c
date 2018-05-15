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

#include <stdlib.h>
#include <arpa/inet.h>

#include <rte_config.h>
#include <rte_ether.h>
#include <rte_bus_pci.h>
#include <rte_ethdev.h>
#include <rte_kni.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "ff_dpdk_kni.h"
#include "ff_config.h"

/* Callback for request of changing MTU */
/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

#define set_bit(n, m)   (n | magic_bits[m])
#define clear_bit(n, m) (n & (~magic_bits[m]))
#define get_bit(n, m)   (n & magic_bits[m])

static const int magic_bits[8] = {
    0x80, 0x40, 0x20, 0x10,
    0x8, 0x4, 0x2, 0x1
};

static unsigned char *udp_port_bitmap = NULL;
static unsigned char *tcp_port_bitmap = NULL;

/* Structure type for recording kni interface specific stats */
struct kni_interface_stats {
    struct rte_kni *kni;

    /* number of pkts received from NIC, and sent to KNI */
    uint64_t rx_packets;

    /* number of pkts received from NIC, but failed to send to KNI */
    uint64_t rx_dropped;

    /* number of pkts received from KNI, and sent to NIC */
    uint64_t tx_packets;

    /* number of pkts received from KNI, but failed to send to NIC */
    uint64_t tx_dropped;
};

struct rte_ring **kni_rp;
struct kni_interface_stats **kni_stat;

static void
set_bitmap(uint16_t port, unsigned char *bitmap)
{
    port = htons(port);
    unsigned char *p = bitmap + port/8;
    *p = set_bit(*p, port % 8);
}

static int
get_bitmap(uint16_t port, unsigned char *bitmap)
{
    unsigned char *p = bitmap + port/8;
    return get_bit(*p, port % 8) > 0 ? 1 : 0;
}

static void
kni_set_bitmap(const char *p, unsigned char *port_bitmap)
{
    int i;
    const char *head, *tail, *tail_num;
    if(!p)
        return;

    head = p;
    while (1) {
        tail = strstr(head, ",");
        tail_num = strstr(head, "-");
        if(tail_num && (!tail || tail_num < tail - 1)) {
            for(i = atoi(head); i <= atoi(tail_num + 1); ++i) {
                set_bitmap(i, port_bitmap);
            }
        } else {
            set_bitmap(atoi(head), port_bitmap);
        }

        if(!tail)
            break;

        head = tail + 1;
    }
}

/* Currently we don't support change mtu. */
static int
kni_change_mtu(uint16_t port_id, unsigned new_mtu)
{
    return 0;
}

static int
kni_config_network_interface(uint16_t port_id, uint8_t if_up)
{
    int ret = 0;

    if (port_id >= rte_eth_dev_count() || port_id >= RTE_MAX_ETHPORTS) {
        printf("Invalid port id %d\n", port_id);
        return -EINVAL;
    }

    printf("Configure network interface of %d %s\n",
            port_id, if_up ? "up" : "down");

    ret = (if_up) ?
        rte_eth_dev_set_link_up(port_id) :
        rte_eth_dev_set_link_down(port_id);

    if(-ENOTSUP == ret) {
        if (if_up != 0) {
            /* Configure network interface up */
            rte_eth_dev_stop(port_id);
            ret = rte_eth_dev_start(port_id);
        } else {
            /* Configure network interface down */
            rte_eth_dev_stop(port_id);
            ret = 0;
        }
    }

    if (ret < 0)
        printf("Failed to Configure network interface of %d %s\n", 
            port_id, if_up ? "up" : "down");

    return ret;
}

static int
kni_process_tx(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, unsigned count)
{
    /* read packet from kni ring(phy port) and transmit to kni */
    uint16_t nb_tx, nb_kni_tx;
    nb_tx = rte_ring_dequeue_burst(kni_rp[port_id], (void **)pkts_burst, count, NULL);

    /* NB.
     * if nb_tx is 0,it must call rte_kni_tx_burst
     * must Call regularly rte_kni_tx_burst(kni, NULL, 0).
     * detail https://embedded.communities.intel.com/thread/6668
     */
    nb_kni_tx = rte_kni_tx_burst(kni_stat[port_id]->kni, pkts_burst, nb_tx);
    rte_kni_handle_request(kni_stat[port_id]->kni);
    if(nb_kni_tx < nb_tx) {
        uint16_t i;
        for(i = nb_kni_tx; i < nb_tx; ++i)
            rte_pktmbuf_free(pkts_burst[i]);

        kni_stat[port_id]->rx_dropped += (nb_tx - nb_kni_tx);
    }

    kni_stat[port_id]->rx_packets += nb_kni_tx;
    return 0;
}

static int
kni_process_rx(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, unsigned count)
{
    uint16_t nb_kni_rx, nb_rx;

    /* read packet from kni, and transmit to phy port */
    nb_kni_rx = rte_kni_rx_burst(kni_stat[port_id]->kni, pkts_burst, count);
    if (nb_kni_rx > 0) {
        nb_rx = rte_eth_tx_burst(port_id, queue_id, pkts_burst, nb_kni_rx);
        if (nb_rx < nb_kni_rx) {
            uint16_t i;
            for(i = nb_rx; i < nb_kni_rx; ++i)
                rte_pktmbuf_free(pkts_burst[i]);

            kni_stat[port_id]->tx_dropped += (nb_kni_rx - nb_rx);
        }

        kni_stat[port_id]->tx_packets += nb_rx;
    }
    return 0;
}

static enum FilterReturn
protocol_filter_l4(uint16_t port, unsigned char *bitmap)
{
    if(get_bitmap(port, bitmap)) {
        return FILTER_KNI;
    }

    return FILTER_UNKNOWN;
}

static enum FilterReturn
protocol_filter_tcp(const void *data, uint16_t len)
{
    if (len < sizeof(struct tcp_hdr))
        return FILTER_UNKNOWN;

    const struct tcp_hdr *hdr;
    hdr = (const struct tcp_hdr *)data;

    return protocol_filter_l4(hdr->dst_port, tcp_port_bitmap);
}

static enum FilterReturn
protocol_filter_udp(const void* data,uint16_t len)
{
    if (len < sizeof(struct udp_hdr))
        return FILTER_UNKNOWN;

    const struct udp_hdr *hdr;
    hdr = (const struct udp_hdr *)data;

    return protocol_filter_l4(hdr->dst_port, udp_port_bitmap);
}

static enum FilterReturn
protocol_filter_ip(const void *data, uint16_t len)
{
    if(len < sizeof(struct ipv4_hdr))
        return FILTER_UNKNOWN;

    const struct ipv4_hdr *hdr;
    hdr = (const struct ipv4_hdr *)data;

    int hdr_len = (hdr->version_ihl & 0x0f) << 2;
    if (len < hdr_len)
        return FILTER_UNKNOWN;

    void *next = (void *)data + hdr_len;
    uint16_t next_len = len - hdr_len;

    switch (hdr->next_proto_id) {
        case IPPROTO_TCP:
            return protocol_filter_tcp(next, next_len);
        case IPPROTO_UDP:
            return protocol_filter_udp(next, next_len);
        case IPPROTO_IPIP:
            return protocol_filter_ip(next, next_len);
    }

    return FILTER_UNKNOWN;
}

enum FilterReturn
ff_kni_proto_filter(const void *data, uint16_t len)
{
    return protocol_filter_ip(data, len);
}

void
ff_kni_init(uint16_t nb_ports, const char *tcp_ports, const char *udp_ports)
{
    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        kni_stat = rte_zmalloc("kni:stat",
            sizeof(struct kni_interface_stats *) * nb_ports,
            RTE_CACHE_LINE_SIZE);
        if (kni_stat == NULL)
            rte_exit(EXIT_FAILURE, "rte_zmalloc(1 (struct netio_kni_stat *)) "
                "failed\n");

        rte_kni_init(nb_ports);
    }

    uint16_t lcoreid = rte_lcore_id();
    char name_buf[RTE_RING_NAMESIZE];
    snprintf(name_buf, RTE_RING_NAMESIZE, "kni::ring_%d", lcoreid);
    kni_rp = rte_zmalloc(name_buf,
            sizeof(struct rte_ring *) * nb_ports,
            RTE_CACHE_LINE_SIZE);
    if (kni_rp == NULL) {
        rte_exit(EXIT_FAILURE, "rte_zmalloc(%s (struct rte_ring*)) "
                "failed\n", name_buf);
    }

    snprintf(name_buf, RTE_RING_NAMESIZE, "kni:tcp_port_bitmap_%d", lcoreid);
    tcp_port_bitmap = rte_zmalloc("kni:tcp_port_bitmap", 8192,
        RTE_CACHE_LINE_SIZE);
    if (tcp_port_bitmap == NULL) {
        rte_exit(EXIT_FAILURE, "rte_zmalloc(%s (tcp_port_bitmap)) "
                "failed\n", name_buf);
    }

    snprintf(name_buf, RTE_RING_NAMESIZE, "kni:udp_port_bitmap_%d", lcoreid);
    udp_port_bitmap = rte_zmalloc("kni:udp_port_bitmap", 8192,
        RTE_CACHE_LINE_SIZE);
    if (udp_port_bitmap == NULL) {
        rte_exit(EXIT_FAILURE, "rte_zmalloc(%s (udp_port_bitmap)) "
                "failed\n",name_buf);
    }

    memset(tcp_port_bitmap, 0, 8192);
    memset(udp_port_bitmap, 0, 8192);

    kni_set_bitmap(tcp_ports, tcp_port_bitmap);
    kni_set_bitmap(udp_ports, udp_port_bitmap);
}

void
ff_kni_alloc(uint16_t port_id, unsigned socket_id,
    struct rte_mempool *mbuf_pool, unsigned ring_queue_size)
{
    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        struct rte_kni_conf conf;
        struct rte_kni_ops ops;
        struct rte_eth_dev_info dev_info;

        kni_stat[port_id] = (struct kni_interface_stats*)rte_zmalloc(
            "kni:stat_lcore",
            sizeof(struct kni_interface_stats),
            RTE_CACHE_LINE_SIZE);

        if (kni_stat[port_id] == NULL)
            rte_panic("rte_zmalloc kni_interface_stats failed\n");

        /* only support one kni */
        memset(&conf, 0, sizeof(conf));
        snprintf(conf.name, RTE_KNI_NAMESIZE, "veth%u", port_id);
        conf.core_id = rte_lcore_id();
        conf.force_bind = 1;
        conf.group_id = port_id;
        uint16_t mtu;
        rte_eth_dev_get_mtu(port_id, &mtu);
        conf.mbuf_size = mtu + KNI_ENET_HEADER_SIZE + KNI_ENET_FCS_SIZE;

        memset(&dev_info, 0, sizeof(dev_info));
        rte_eth_dev_info_get(port_id, &dev_info);
        conf.addr = dev_info.pci_dev->addr;
        conf.id = dev_info.pci_dev->id;

        memset(&ops, 0, sizeof(ops));
        ops.port_id = port_id;
        ops.change_mtu = kni_change_mtu;
        ops.config_network_if = kni_config_network_interface;

        kni_stat[port_id]->kni = rte_kni_alloc(mbuf_pool, &conf, &ops);
        if (kni_stat[port_id]->kni == NULL)
            rte_panic("create kni on port %u failed!\n", port_id);
        else
            printf("create kni on port %u success!\n", port_id);

        kni_stat[port_id]->rx_packets = 0;
        kni_stat[port_id]->rx_dropped = 0;
        kni_stat[port_id]->tx_packets = 0;
        kni_stat[port_id]->tx_dropped = 0;
    }

    char ring_name[RTE_KNI_NAMESIZE];
    snprintf((char*)ring_name, RTE_KNI_NAMESIZE, "kni_ring_%u", port_id);

    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        kni_rp[port_id] = rte_ring_create(ring_name, ring_queue_size, 
            socket_id, RING_F_SC_DEQ);

        if (rte_ring_lookup(ring_name) != kni_rp[port_id])
            rte_panic("lookup kni ring failed!\n");
    } else {
        kni_rp[port_id] = rte_ring_lookup(ring_name);
    }

    if (kni_rp[port_id] == NULL)
        rte_panic("create kni ring failed!\n");

    printf("create kni ring success, %u ring entries are now free!\n",
        rte_ring_free_count(kni_rp[port_id]));
}


void
ff_kni_process(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, unsigned count)
{
    kni_process_tx(port_id, queue_id, pkts_burst, count);
    kni_process_rx(port_id, queue_id, pkts_burst, count);
}

/* enqueue the packet, and own it */
int
ff_kni_enqueue(uint16_t port_id, struct rte_mbuf *pkt)
{
    int ret = rte_ring_enqueue(kni_rp[port_id], pkt);
    if (ret < 0)
        rte_pktmbuf_free(pkt);

    return 0;
}

