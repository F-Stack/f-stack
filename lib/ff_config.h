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

#ifndef __FSTACK_CONFIG_H
#define __FSTACK_CONFIG_H

// dpdk argc, argv, max argc: 4, member of dpdk_config
#define DPDK_CONFIG_NUM 4
#define DPDK_CONFIG_MAXLEN 64

extern int dpdk_argc;
extern char *dpdk_argv[DPDK_CONFIG_NUM + 1];

struct ff_hw_features {
    uint8_t rx_csum;
    uint8_t rx_lro;
    uint8_t tx_csum_ip;
    uint8_t tx_csum_l4;
    uint8_t tx_tso;
};

struct ff_port_cfg {
    char *name;
    uint8_t port_id;
    uint8_t mac[6];
    struct ff_hw_features hw_features;
    char *addr;
    char *netmask;
    char *broadcast;
    char *gateway;
    char *pcap;
};

struct ff_freebsd_cfg {
    char *name;
    char *str;
    void *value;
    size_t vlen;
    struct ff_freebsd_cfg *next;
};

struct ff_config {
    struct {
        /* mask of enabled lcores */
        char *lcore_mask;
        /* mask of current proc on all lcores */
        char *proc_mask;
        /* mask of enabled ports
         * use uint32_t because num of max ports is 32
         */
        uint32_t port_mask;
        int nb_channel;
        int memory;
        int no_huge;
        int nb_procs;
        int proc_id;
        int nb_ports;
        int promiscuous;
        int numa_on;
        int tso;
        struct ff_port_cfg *port_cfgs;
    } dpdk;

    struct {
        int enable;
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
    } freebsd;
};

extern struct ff_config ff_global_cfg;

int ff_load_config(const char *conf, int argc, char * const argv[]);

#endif /* ifndef __FSTACK_CONFIG_H */
