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
#define DPDK_MAX_VLAN_FILTER 128
#define PCAP_SNAP_MINLEN 94
#define PCAP_SAVE_MINLEN (2<<22)
/*
 * KNI ratelimit default value.
 * The total speed limit for a single process entering the kni ring is 10,000 QPS,
 * 1000 QPS for general packets, 9000 QPS for console packets (ospf/arp, etc.)
 * The total speed limit for kni forwarding to the kernel is 20,000 QPS.
 */
#define KNI_RATELIMT_PROCESS  (10000)
#define KNI_RATELIMT_GENERAL (1000)
#define KNI_RATELIMT_CONSOLE    (KNI_RATELIMT_PROCESS - KNI_RATELIMT_GENERAL)
#define KNI_RATELIMT_KERNEL (KNI_RATELIMT_PROCESS * 2)

extern int dpdk_argc;
extern char *dpdk_argv[DPDK_CONFIG_NUM + 1];

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

#define VIP_MAX_NUM 64

/* exception path(KNI) type */
#define KNI_TYPE_KNI        0
#define KNI_TYPE_VIRTIO     1

/* ff_rss_check table args */
/* remote IP:PORT */
#define FF_RSS_TBL_MAX_SADDR        (4)
#define FF_RSS_TBL_MAX_SPORT        (4)
#define FF_RSS_TBL_MAX_SADDR_MASK   (FF_RSS_TBL_MAX_SADDR - 1)
#define FF_RSS_TBL_MAX_SPORT_MASK   (FF_RSS_TBL_MAX_SPORT - 1)
/* local IP:PORT */
#define FF_RSS_TBL_MAX_DADDR        (4)
#define FF_RSS_TBL_MAX_DPORT        (65536)
#define FF_RSS_TBL_MAX_DIP_MASK     (FF_RSS_TBL_MAX_DADDR - 1)
#define FF_RSS_TBL_MAX_DPORT_MASK   (FF_RSS_TBL_MAX_DPORT - 1)

#define FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES      (FF_RSS_TBL_MAX_SADDR * FF_RSS_TBL_MAX_SPORT)
#define FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES_MASK (FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES - 1)

#define FF_RSS_TBL_MAX_ENTRIES      (FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES * FF_RSS_TBL_MAX_DADDR)
#define FF_RSS_TBL_MAX_ENTRIES_MASK (FF_RSS_TBL_MAX_ENTRIES - 1)

#ifndef NIPQUAD
#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NIPQUAD(addr)                       \
    (unsigned)((unsigned char *)&addr)[0],  \
    (unsigned)((unsigned char *)&addr)[1],  \
    (unsigned)((unsigned char *)&addr)[2],  \
    (unsigned)((unsigned char *)&addr)[3]
#endif

#ifndef NIP6
#define NIP6_FMT "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define NIP6(addr)                          \
    (unsigned)((addr).s6_addr[0]),          \
    (unsigned)((addr).s6_addr[1]),          \
    (unsigned)((addr).s6_addr[2]),          \
    (unsigned)((addr).s6_addr[3]),          \
    (unsigned)((addr).s6_addr[4]),          \
    (unsigned)((addr).s6_addr[5]),          \
    (unsigned)((addr).s6_addr[6]),          \
    (unsigned)((addr).s6_addr[7]),          \
    (unsigned)((addr).s6_addr[8]),          \
    (unsigned)((addr).s6_addr[9]),          \
    (unsigned)((addr).s6_addr[10]),         \
    (unsigned)((addr).s6_addr[11]),         \
    (unsigned)((addr).s6_addr[12]),         \
    (unsigned)((addr).s6_addr[13]),         \
    (unsigned)((addr).s6_addr[14]),         \
    (unsigned)((addr).s6_addr[15])
#endif

struct ff_hw_features {
    uint8_t rx_csum;
    uint8_t rx_lro;
    uint8_t tx_csum_ip;
    uint8_t tx_csum_l4;
    uint8_t tx_tso;
};

#ifdef FF_IPFW
struct ff_ipfw_pr_cfg {
    //uint32_t rule_num;
    //uint32_t fib_num; /* Use portN or vlanN's idx * 100 */
    char *addr;
    char *netmask;
};
#endif

struct ff_vlan_cfg {
    char *name;
    char *ifname;
    /* global vlan idx, also use for route table's fib num */
    int vlan_idx;
    uint16_t vlan_id;
    uint16_t port_id;

    char *addr;
    char *netmask;
    char *broadcast;
    char *gateway;

    char *vip_ifname;
    char *vip_addr_str;
    char **vip_addr_array;
    uint32_t nb_vip;

    /* simple policy routing, only need rule num(100/200/300/400), ip/mask,fib num(0/1/2/3/4)  */
    char *pr_addr_str;

#ifdef FF_IPFW
    struct ff_ipfw_pr_cfg *pr_cfg;
    uint32_t nb_pr;
#endif

#ifdef INET6
    char *addr6_str;
    char *gateway6_str;
    uint8_t prefix_len;

    char *vip_addr6_str;
    char **vip_addr6_array;
    uint32_t nb_vip6;
    uint8_t vip_prefix_len;
#endif
};

struct ff_port_cfg {
    char *name;
    char *ifname;
    uint16_t port_id;
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

#ifdef FF_IPFW
    char *pr_addr_str;
    struct ff_ipfw_pr_cfg *pr_cfg;
    uint32_t nb_pr;
#endif

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

    int nb_vlan;
    struct ff_vlan_cfg *vlan_cfgs[DPDK_MAX_VLAN_FILTER];
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

struct ff_rss_tbl_cfg {
    uint16_t port_id;
    uint16_t sport;
    uint32_t daddr; /* local */
    uint32_t saddr; /* remote */
};

struct ff_rss_check_cfg {
    int enable;
    int nb_rss_tbl;
    char *rss_tbl_str;
    struct ff_rss_tbl_cfg rss_tbl_cfgs[FF_RSS_TBL_MAX_ENTRIES];
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
        int nb_vlan_filter;
        uint16_t vlan_filter_id[DPDK_MAX_VLAN_FILTER];
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
        struct ff_vlan_cfg *vlan_cfgs;
        struct ff_vdev_cfg *vdev_cfgs;
        struct ff_bond_cfg *bond_cfgs;
        struct ff_rss_check_cfg *rss_check_cfgs;
    } dpdk;

    struct {
        int enable;
        int type;
        int console_packets_ratelimit;
        int general_packets_ratelimit;
        int kernel_packets_ratelimit;
        char *kni_action;
        char *method;
        char *tcp_port;
        char *udp_port;
    } kni;

    struct {
        int level;
        const char *dir;
        void *f; /* FILE * */
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
