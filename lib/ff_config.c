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
#include <ctype.h>
#include <rte_config.h>
#include <rte_string_fns.h>

#include "ff_config.h"
#include "ff_ini_parser.h"

#define DEFAULT_CONFIG_FILE   "config.ini"

#define BITS_PER_HEX 4

struct ff_config ff_global_cfg;
int dpdk_argc;
char *dpdk_argv[DPDK_CONFIG_NUM + 1];

char* const short_options = "c:t:p:";
struct option long_options[] = {
    { "conf", 1, NULL, 'c'},
    { "proc-type", 1, NULL, 't'},
    { "proc-id", 1, NULL, 'p'},
    { 0, 0, 0, 0},
};

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
parse_lcore_mask(struct ff_config *cfg, const char *coremask)
{
    int i, j, idx = 0;
    unsigned count = 0;
    char c;
    int val;
    uint16_t *proc_lcore;
    char buf[RTE_MAX_LCORE] = {0};

    if (coremask == NULL)
        return 0;

    cfg->dpdk.proc_lcore = (uint16_t *)calloc(RTE_MAX_LCORE, sizeof(uint16_t));
    if (cfg->dpdk.proc_lcore == NULL) {
        fprintf(stderr, "parse_lcore_mask malloc failed\n");
        return 0;
    }
    proc_lcore = cfg->dpdk.proc_lcore;

    /*
     * Remove all blank characters ahead and after.
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
        return 0;

    for (i = i - 1; i >= 0 && idx < RTE_MAX_LCORE; i--) {
        c = coremask[i];
        if (isxdigit(c) == 0) {
            return 0;
        }
        val = xdigit2val(c);
        for (j = 0; j < BITS_PER_HEX && idx < RTE_MAX_LCORE; j++, idx++) {
            if ((1 << j) & val) {
                proc_lcore[count] = idx;
                if (cfg->dpdk.proc_id == count) {
                    sprintf(buf, "%x", 1<<idx);
                    cfg->dpdk.proc_mask = strdup(buf);
                }
                count++;
            }
        }
    }

    for (; i >= 0; i--)
        if (coremask[i] != '0')
            return 0;

    if (cfg->dpdk.proc_id >= count)
        return 0;

    cfg->dpdk.nb_procs = count;

    return 1;
}

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

int uint16_cmp (const void * a, const void * b)
{
    return ( *(uint16_t*)a - *(uint16_t*)b );
}

static inline void
sort_uint16_array(uint16_t arr[], int n)
{
    qsort(arr, n, sizeof(uint16_t), uint16_cmp);
}

static inline char *
__strstrip(char *s)
{
    char *end = s + strlen(s) - 1;
    while(*s == ' ') s++;
    for (; end >= s; --end) {
        if (*end != ' ') break;
    }
    *(++end) = '\0';
    return s;
}

static int
parse_port_lcore_list(struct ff_port_cfg *cfg, const char *lcore_list)
{
    char input[4096];
    char *tokens[128];
    int nTokens = 0;
    char *endptr;
    uint16_t *cores = cfg->lcore_list;
    int nr_cores = 0;
    int max_cores = DPDK_MAX_LCORE;

    strncpy(input, lcore_list, 4096);
    nTokens = rte_strsplit(input, sizeof(input), tokens, 128, ',');
    for (int i = 0; i < nTokens; i++) {
        char *tok = tokens[i];
        char *middle = strchr(tok, '-');
        if (middle == NULL) {
            tok = __strstrip(tok);
            long v = strtol(tok, &endptr, 10);
            if (*endptr != '\0') {
                fprintf(stderr, "%s is not a integer.", tok);
                return 0;
            }
            if (nr_cores > max_cores) {
                fprintf(stderr, "too many cores\n");
                return 0;
            }
            cores[nr_cores++] = (uint16_t)v;
        } else {
            *middle = '\0';
            char *lbound = __strstrip(tok);
            char *rbound = __strstrip(middle+1);
            long lv = strtol(lbound, &endptr, 10);
            if (*endptr != '\0') {
                fprintf(stderr, "%s is not a integer.", lbound);
                return 0;
            }
            long rv = strtol(rbound, &endptr, 10);
            if (*endptr != '\0') {
                fprintf(stderr, "%s is not a integer.", rbound);
                return 0;
            }
            for (int j = lv; j <= rv; ++j) {
                if (nr_cores > max_cores) {
                    fprintf(stderr, "too many cores\n");
                    return 0;
                }
                cores[nr_cores++] = (uint16_t)j;
            }
        }
    }
    if (nr_cores <= 0) {
        fprintf(stderr, "lcore list is empty\n");
        return 0;
    }
    cfg->nb_lcores = nr_cores;
    sort_uint16_array(cores, nr_cores);
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
        // initialize lcore list and nb_lcores
        for (int i = 0; i < cfg->dpdk.nb_ports; ++i) {
            struct ff_port_cfg *pconf = &pc[i];
            pconf->nb_lcores = ff_global_cfg.dpdk.nb_procs;
            memcpy(pconf->lcore_list, ff_global_cfg.dpdk.proc_lcore,
                   pconf->nb_lcores*sizeof(uint16_t));
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
    } else if (strcmp(name, "lcore_list") == 0) {
        return parse_port_lcore_list(cur, value);
    }

    return 1;
}

static int
ini_parse_handler(void* user, const char* section, const char* name,
    const char* value)
{
    struct ff_config *pconfig = (struct ff_config*)user;

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
        return parse_lcore_mask(pconfig, pconfig->dpdk.lcore_mask);
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
    } else if (MATCH("dpdk", "vlan_strip")) {
        pconfig->dpdk.vlan_strip = atoi(value);
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
        } else if (strcmp(name, "fd_reserve") == 0) {
            pconfig->freebsd.fd_reserve = atoi(value);
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
dpdk_args_setup(struct ff_config *cfg)
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
    if (cfg->dpdk.proc_type) {
        sprintf(temp, "--proc-type=%s", cfg->dpdk.proc_type);
        dpdk_argv[n++] = strdup(temp);
    }

    dpdk_argc = n;

    return n;
}

static int
ff_parse_args(struct ff_config *cfg, int argc, char *const argv[])
{
    int c;
    int index = 0;
    optind = 1;
    while((c = getopt_long(argc, argv, short_options, long_options, &index)) != -1) {
        switch (c) {
            case 'c':
                cfg->filename = strdup(optarg);
                break;
            case 'p':
                cfg->dpdk.proc_id = atoi(optarg);
                break;
            case 't':
                cfg->dpdk.proc_type = strdup(optarg);
                break;
            default:
                return -1;
        }
    }

    if (cfg->dpdk.proc_type == NULL ||
        (strcmp(cfg->dpdk.proc_type, "primary") &&
        strcmp(cfg->dpdk.proc_type, "secondary"))) {
        printf("invalid proc-type\n");
        return -1;
    }

    if ((uint16_t)cfg->dpdk.proc_id > RTE_MAX_LCORE) {
        printf("proc_id:%d is too large\n", cfg->dpdk.proc_id);
        return -1;
    }

    return 0;
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

    cfg->filename = DEFAULT_CONFIG_FILE;

    cfg->dpdk.proc_id = -1;
    cfg->dpdk.numa_on = 1;
    cfg->dpdk.promiscuous = 1;

    cfg->freebsd.hz = 100;
    cfg->freebsd.physmem = 1048576*256;
    cfg->freebsd.fd_reserve = 0;
}

int
ff_load_config(int argc, char *const argv[])
{
    ff_default_config(&ff_global_cfg);

    int ret = ff_parse_args(&ff_global_cfg, argc, argv);
    if (ret < 0) {
        return ret;
    }

    ret = ini_parse(ff_global_cfg.filename, ini_parse_handler,
        &ff_global_cfg);
    if (ret != 0) {
        printf("parse %s failed on line %d\n", ff_global_cfg.filename, ret);
        return -1;
    }

    if (ff_check_config(&ff_global_cfg)) {
        return -1;
    }

    if (dpdk_args_setup(&ff_global_cfg) <= 0) {
        return -1;
    }

    return 0;
}
