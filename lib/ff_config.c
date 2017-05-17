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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include "ff_config.h"
#include "ff_ini_parser.h"

struct ff_config ff_global_cfg;
int dpdk_argc;
char *dpdk_argv[DPDK_CONFIG_NUM + 1];

int dpdk_argc_arg;
char *dpdk_argv_arg[DPDK_CONFIG_NUM + 1];

char* const short_options = "c:";  
struct option long_options[] = {  
    { "proc-type", 1, NULL, 0 },  
    { "num-procs", 1, NULL, 0 },  
    { "proc-id", 1, NULL, 0 },  
    { 0, 0, 0, 0},  
};

static int
is_integer(const char *s)
{
    if (*s == '-' || *s == '+')
        s++;
    if (*s < '0' || '9' < *s)
        return 0;
    s++;
    while ('0' <= *s && *s <= '9')
        s++;
    return (*s == '\0');
}

static int
freebsd_conf_handler(struct ff_config *cfg, const char *section,
    const char *name, const char *value)
{
    struct ff_freebsd_cfg *newconf, **cur;
    newconf = (struct ff_freebsd_cfg *)malloc(sizeof(struct ff_freebsd_cfg));
    if (newconf == NULL) {
        fprintf(stderr, "freebsd conf malloc failed\n");
        return 0;
    }

    newconf->name = strdup(name);
    newconf->str = strdup(value);

    if (strcmp(section, "boot") == 0) {
        cur = &cfg->freebsd.boot;

        newconf->value = (void *)newconf->str;
        newconf->vlen = strlen(value);
    } else if (strcmp(section, "sysctl") == 0) {
        cur = &cfg->freebsd.sysctl;

        if (is_integer(value)) {
            int *p = (int *)malloc(sizeof(int));
            *p = atoi(value);
            newconf->value = (void *)p;
            newconf->vlen = sizeof(*p);
        } else {
            newconf->value = (void *)newconf->str;
            newconf->vlen = strlen(value);
        }
    } else {
        fprintf(stderr, "freebsd conf section[%s] error\n", section);
        return 0;
    }

    if (*cur == NULL) {
        *cur = newconf;
    } else {
        (*cur)->next = newconf;
        newconf->next = NULL;
    }

    return 1;
}

static int
port_cfg_handler(struct ff_config *cfg, const char *section,
    const char *name, const char *value) {

    if (cfg->dpdk.nb_ports == 0) {
        fprintf(stderr, "port_cfg_handler: must config dpdk.nb_ports first\n");
        return 0;
    }

    if (cfg->dpdk.port_cfgs == NULL) {
        struct ff_port_cfg *pc = calloc(cfg->dpdk.nb_ports, sizeof(struct ff_port_cfg));
        if (pc == NULL) {
            fprintf(stderr, "port_cfg_handler malloc failed\n");
            return 0;
        }

        cfg->dpdk.port_cfgs = pc;
    }

    int portid;
    int ret = sscanf(section, "port%d", &portid);
    if (ret != 1) {
        fprintf(stderr, "port_cfg_handler section[%s] error\n", section);
        return 0;
    }

    /* just return true if portid >= nb_ports because it has no effect */
    if (portid >= cfg->dpdk.nb_ports) {
        fprintf(stderr, "port_cfg_handler section[%s] max than nb_ports\n", section);
        return 1;
    }

    struct ff_port_cfg *cur = &cfg->dpdk.port_cfgs[portid];
    if (cur->name == NULL) {
        cur->name = strdup(section);
        cur->port_id = portid;
    }

    if (strcmp(name, "addr") == 0) {
        cur->addr = strdup(value);
    } else if (strcmp(name, "netmask") == 0) {
        cur->netmask = strdup(value);
    } else if (strcmp(name, "broadcast") == 0) {
        cur->broadcast = strdup(value);
    } else if (strcmp(name, "gateway") == 0) {
        cur->gateway = strdup(value);
    } else if (strcmp(name, "pcap") == 0) {
        cur->pcap = strdup(value);
    }

    return 1;
}

static int
handler(void* user, const char* section, const char* name,
    const char* value)
{
    struct ff_config* pconfig = (struct ff_config*)user;

    printf("[%s]: %s=%s\n", section, name, value);

    #define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
    if (MATCH("dpdk", "channel")) {
        pconfig->dpdk.nb_channel = atoi(value);
    } else if (MATCH("dpdk", "memory")) {
        pconfig->dpdk.memory = atoi(value);
    } else if (MATCH("dpdk", "no_huge")) {
        pconfig->dpdk.no_huge = atoi(value);
    } else if (MATCH("dpdk", "lcore_mask")) {
        pconfig->dpdk.lcore_mask = strdup(value);
    } else if (MATCH("dpdk", "port_mask")) {
        pconfig->dpdk.port_mask = atoi(value);
    } else if (MATCH("dpdk", "nb_ports")) {
        pconfig->dpdk.nb_ports = atoi(value);
    } else if (MATCH("dpdk", "promiscuous")) {
        pconfig->dpdk.promiscuous = atoi(value);
    } else if (MATCH("dpdk", "numa_on")) {
        pconfig->dpdk.numa_on = atoi(value);
    } else if (MATCH("dpdk", "tso")) {
        pconfig->dpdk.tso = atoi(value);
    } else if (MATCH("kni", "enable")) {
        pconfig->kni.enable= atoi(value);
    } else if (MATCH("kni", "method")) {
        pconfig->kni.method= strdup(value);
    } else if (MATCH("kni", "tcp_port")) {
        pconfig->kni.tcp_port = strdup(value);
    } else if (MATCH("kni", "udp_port")) {
        pconfig->kni.udp_port= strdup(value);
    } else if (strcmp(section, "freebsd.boot") == 0) {
        if (strcmp(name, "hz") == 0) {
            pconfig->freebsd.hz = atoi(value);
        } else if (strcmp(name, "physmem") == 0) {
            pconfig->freebsd.physmem = atol(value);
        } else {
            return freebsd_conf_handler(pconfig, "boot", name, value);
        }
    } else if (strcmp(section, "freebsd.sysctl") == 0) {
        return freebsd_conf_handler(pconfig, "sysctl", name, value);
    } else if (strncmp(section, "port", 4) == 0) {
        return port_cfg_handler(pconfig, section, name, value);
    }

    return 1;
}

static int
dpdk_argc_argv_setup(struct ff_config *cfg)
{
    int n = 0, i;
    dpdk_argv[n++] = strdup("f-stack");
    char temp[DPDK_CONFIG_MAXLEN] = {0};

    if (cfg->dpdk.no_huge) {
        dpdk_argv[n++] = strdup("--no-huge");
    }
    if (cfg->dpdk.proc_mask) {
        sprintf(temp, "-c%s", cfg->dpdk.proc_mask);
        dpdk_argv[n++] = strdup(temp);
    }
    if (cfg->dpdk.nb_channel) {
        sprintf(temp, "-n%d", cfg->dpdk.nb_channel);
        dpdk_argv[n++] = strdup(temp);
    }
    if (cfg->dpdk.memory) {
        sprintf(temp, "-m%d", cfg->dpdk.memory);
        dpdk_argv[n++] = strdup(temp);
    }

    for(i = 0; i < dpdk_argc_arg; ++i) {
        dpdk_argv[n++] = dpdk_argv_arg[i];
    }

    dpdk_argc = n;

    return n;
}

static void
ff_load_arg(struct ff_config *cfg, int argc, char *const argv[])
{
    dpdk_argc_arg = 0;
    int c;
    int index = 0;
    while((c = getopt_long(argc, argv, short_options, long_options, &index)) != -1) {
        switch (c) {
            case 'c':
                cfg->dpdk.proc_mask = strdup(optarg);
                break;
            case 0:
                if (0 == strcmp(long_options[index].name, "num-procs")) {
                    cfg->dpdk.nb_procs = atoi(optarg);
                } else if(0 == strcmp(long_options[index].name, "proc-id")) {
                    cfg->dpdk.proc_id = atoi(optarg);
                } else if(0 == strcmp(long_options[index].name, "proc-type")) {
                    char temp[DPDK_CONFIG_MAXLEN] = {0};
                    sprintf(temp, "--proc-type=%s",optarg);
                    dpdk_argv_arg[dpdk_argc_arg++] = strdup(temp);
                }
                break;
            default:
                break;
        }
    }
    return;
}

static int
ff_check_config(struct ff_config *cfg)
{
    if(cfg->kni.enable && !cfg->kni.method) {
        fprintf(stderr, "conf dpdk.method is necessary\n");
        return -1;
    }

    if(cfg->kni.method) {
        if(strcasecmp(cfg->kni.method,"accept") &&
            strcasecmp(cfg->kni.method,"reject")) {
            fprintf(stderr, "conf kni.method[accept|reject] is error(%s)\n",
                cfg->kni.method);
            return -1;
        }
    }

    #define CHECK_VALID(n) \
        do { \
            if (!pc->n) { \
                fprintf(stderr, "port%d if config error: no %s\n", \
                    pc->port_id, #n); \
                return -1; \
            } \
        } while (0)

    int i;
    for (i = 0; i < cfg->dpdk.nb_ports; i++) {
        struct ff_port_cfg *pc = &cfg->dpdk.port_cfgs[i];
        CHECK_VALID(addr);
        CHECK_VALID(netmask);
        CHECK_VALID(broadcast);
        CHECK_VALID(gateway);
    }

    return 0;
}

static void
ff_default_config(struct ff_config *cfg)
{
    memset(cfg, 0, sizeof(struct ff_config));

    cfg->dpdk.numa_on = 1;
    cfg->dpdk.promiscuous = 1;

    cfg->freebsd.hz = 100;
    cfg->freebsd.physmem = 1048576*256;
}

int
ff_load_config(const char *conf, int argc, char * const argv[])
{
    ff_default_config(&ff_global_cfg);
    
    int ret = ini_parse(conf, handler, &ff_global_cfg);
    if (ret != 0) {
        printf("parse %s failed on line %d\n", conf, ret);
        return -1;
    }

    if (ff_check_config(&ff_global_cfg)) {
        return -1;
    }

    ff_load_arg(&ff_global_cfg, argc, argv);
    if (dpdk_argc_argv_setup(&ff_global_cfg) <= 0) {
        return -1;
    }

    return 0;
}

