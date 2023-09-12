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

#ifndef __FSTACK_CONFIG_H
#define __FSTACK_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

// dpdk argc, argv, max argc: 16, member of dpdk_config
#define DPDK_CONFIG_NUM 16
#define DPDK_CONFIG_MAXLEN 256
#define DPDK_MAX_LCORE 128
#define PCAP_SNAP_MINLEN 94
#define PCAP_SAVE_MINLEN (2<<22)

extern int dpdk_argc;
extern char *dpdk_argv[DPDK_CONFIG_NUM + 1];

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

#define VIP_MAX_NUM 64

struct ff_hw_features {
    uint8_t rx_csum;
    uint8_t rx_lro;
    uint8_t tx_csum_ip;
    uint8_t tx_csum_l4;
    uint8_t tx_tso;
};

struct ff_port_cfg {
    char *name;
    char *ifname;
    uint8_t port_id;
    uint8_t mac[6];
    struct ff_hw_features hw_features;
    char *addr;
    char *netmask;
    char *broadcast;
    char *gateway;

    char *vip_ifname;
    char *vip_addr_str;
    char **vip_addr_array;
    uint32_t nb_vip;

#ifdef INET6
    char *addr6_str;
    char *gateway6_str;
    uint8_t prefix_len;

    char *vip_addr6_str;
    char **vip_addr6_array;
    uint32_t nb_vip6;
    uint8_t vip_prefix_len;
#endif

    int nb_lcores;
    int nb_slaves;
    uint16_t lcore_list[DPDK_MAX_LCORE];
    uint16_t *slave_portid_list;
};

struct ff_vdev_cfg {
    char *name;
    char *iface;
    char *path;
    char *mac;
    uint8_t vdev_id;
    uint8_t nb_queues;
    uint8_t nb_cq;
    uint16_t queue_size;
};

struct ff_bond_cfg {
    char *name;
    char *slave;
    char *primary;
    char *bond_mac;
    char *xmit_policy;
    uint8_t bond_id;
    uint8_t mode;
    uint8_t socket_id;
    uint8_t lsc_poll_period_ms;
    uint16_t up_delay;
    uint16_t down_delay;
};

struct ff_freebsd_cfg {
    char *name;
    char *str;
    void *value;
    size_t vlen;
    struct ff_freebsd_cfg *next;
};

struct ff_config {
    char *filename;
    struct {
        char *proc_type;
        /* mask of enabled lcores */
        char *lcore_mask;
        /* mask of current proc on all lcores */
        char *proc_mask;

        /* specify base virtual address to map. */
        char *base_virtaddr;

        /* allow processes that do not want to co-operate to have different memory regions */
        char *file_prefix;

        /* load an external driver */
        char *pci_whitelist;

        int nb_channel;
        int memory;
        int no_huge;
        int nb_procs;
        int proc_id;
        int promiscuous;
        int nb_vdev;
        int nb_bond;
        int numa_on;
        int tso;
        int tx_csum_offoad_skip;
        int vlan_strip;
        int symmetric_rss;

        /* sleep x microseconds when no pkts incomming */
        unsigned idle_sleep;

        /* TX burst queue drain nodelay dalay time */
        unsigned pkt_tx_delay;

        /* list of proc-lcore */
        uint16_t *proc_lcore;

        int nb_ports;
        uint16_t max_portid;
        uint16_t *portid_list;

        // load dpdk log level
        uint16_t log_level;
        // MAP(portid => struct ff_port_cfg*)
        struct ff_port_cfg *port_cfgs;
        struct ff_vdev_cfg *vdev_cfgs;
        struct ff_bond_cfg *bond_cfgs;
    } dpdk;

    struct {
        int enable;
        char *kni_action;
        char *method;
        char *tcp_port;
        char *udp_port;
    } kni;

    struct {
        int level;
        const char *dir;
    } log;

    struct {
        struct ff_freebsd_cfg *boot;
        struct ff_freebsd_cfg *sysctl;
        long physmem;
        int hz;
        int fd_reserve;
        int mem_size;
    } freebsd;

    struct {
        uint16_t enable;
        uint16_t snap_len;
        uint32_t save_len;
        char*	 save_path;
    } pcap;
};

extern struct ff_config ff_global_cfg;

int ff_load_config(int argc, char * const argv[]);

#ifdef __cplusplus
}
#endif

#endif /* ifndef __FSTACK_CONFIG_H */
