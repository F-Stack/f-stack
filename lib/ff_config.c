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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <rte_config.h>
#include <rte_string_fns.h>

#include "ff_config.h"
#include "ff_ini_parser.h"
#include "ff_log.h"

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
    int i, j, idx = 0, shift = 0, zero_num = 0;
    int count = 0;
    char c;
    int val;
    uint16_t *proc_lcore;
    char buf[RTE_MAX_LCORE] = {0};
    char zero[RTE_MAX_LCORE] = {0};

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
                    zero_num = idx >> 2;
                    shift = idx & 0x3;
                    memset(zero,'0',zero_num);
                    snprintf(buf, sizeof(buf) - 1, "%llx%s",
                        (unsigned long long)1<<shift, zero);
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
            if (strcmp(name, "kern.ipc.maxsockbuf") == 0) {
                long *p = (long *)malloc(sizeof(long));
                *p = atol(value);
                newconf->value = (void *)p;
                newconf->vlen = sizeof(*p);
            } else {
                 int *p = (int *)malloc(sizeof(int));
                 *p = atoi(value);
                 newconf->value = (void *)p;
                 newconf->vlen = sizeof(*p);
            }
        } else {
            newconf->value = (void *)newconf->str;
            newconf->vlen = strlen(value);
        }
    } else {
        fprintf(stderr, "freebsd conf section[%s] error\n", section);
        free(newconf);
        return 0;
    }

    if (*cur == NULL) {
        newconf->next = NULL;
        *cur = newconf;
    } else {
        newconf->next = (*cur)->next;
        (*cur)->next = newconf;
    }

    return 1;
}
// A recursive binary search function. It returns location of x in
// given array arr[l..r] is present, otherwise -1
static int
uint16_binary_search(uint16_t arr[], int l, int r, uint16_t x)
{
    if (r >= l) {
        int mid = l + (r - l)/2;

        // If the element is present at the middle itself
        if (arr[mid] == x)  return mid;

        // If element is smaller than mid, then it can only be present
        // in left subarray
        if (arr[mid] > x) return uint16_binary_search(arr, l, mid-1, x);

        // Else the element can only be present in right subarray
        return uint16_binary_search(arr, mid+1, r, x);
    }

    // We reach here when element is not present in array
    return -1;
}

static int
uint16_cmp (const void * a, const void * b)
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
__parse_config_list(uint16_t *arr, int *sz, const char *value) {
    int i, j;
    char input[4096];
    char *tokens[128];
    int nTokens = 0;
    char *endptr;
    int nr_ele = 0;
    int max_ele = *sz;

    strncpy(input, value, sizeof(input) - 1);
    nTokens = rte_strsplit(input, sizeof(input), tokens, 128, ',');
    for (i = 0; i < nTokens; i++) {
        char *tok = tokens[i];
        char *middle = strchr(tok, '-');
        if (middle == NULL) {
            tok = __strstrip(tok);
            long v = strtol(tok, &endptr, 10);
            if (*endptr != '\0') {
                fprintf(stderr, "%s is not a integer.", tok);
                return 0;
            }
            if (nr_ele > max_ele) {
                fprintf(stderr, "too many elements in list %s\n", value);
                return 0;
            }
            arr[nr_ele++] = (uint16_t)v;
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
            for (j = lv; j <= rv; ++j) {
                if (nr_ele > max_ele) {
                    fprintf(stderr, "too many elements in list %s.\n", value);
                    return 0;
                }
                arr[nr_ele++] = (uint16_t)j;
            }
        }
    }
    if (nr_ele <= 0) {
        fprintf(stderr, "list %s is empty\n", value);
        return 1;
    }
    sort_uint16_array(arr, nr_ele);
    *sz = nr_ele;
    return 1;
}

static int
parse_port_lcore_list(struct ff_port_cfg *cfg, const char *v_str)
{
    cfg->nb_lcores = DPDK_MAX_LCORE;
    uint16_t *cores = cfg->lcore_list;
    return __parse_config_list(cores, &cfg->nb_lcores, v_str);
}

static int
parse_port_list(struct ff_config *cfg, const char *v_str)
{
    int res;
    uint16_t ports[RTE_MAX_ETHPORTS];
    int sz = RTE_MAX_ETHPORTS;

    res = __parse_config_list(ports, &sz, v_str);
    if (! res) return res;

    uint16_t *portid_list = malloc(sizeof(uint16_t)*sz);

    if (portid_list == NULL) {
        fprintf(stderr, "parse_port_list malloc failed\n");
        return 0;
    }
    memcpy(portid_list, ports, sz*sizeof(uint16_t));

    cfg->dpdk.portid_list = portid_list;
    cfg->dpdk.nb_ports = sz;
    cfg->dpdk.max_portid = portid_list[sz-1];
    return res;
}

static int
parse_port_slave_list(struct ff_port_cfg *cfg, const char *v_str)
{
    int res;
    uint16_t ports[RTE_MAX_ETHPORTS];
    int sz = RTE_MAX_ETHPORTS;

    res = __parse_config_list(ports, &sz, v_str);
    if (! res) return res;

    uint16_t *portid_list = malloc(sizeof(uint16_t)*sz);

    if (portid_list == NULL) {
        fprintf(stderr, "parse_port_slave_list malloc failed\n");
        return 0;
    }
    memcpy(portid_list, ports, sz*sizeof(uint16_t));

    cfg->slave_portid_list = portid_list;
    cfg->nb_slaves = sz;

    return res;
}

static int
parse_vlan_filter_list(struct ff_config *cfg, const char *v_str)
{
    cfg->dpdk.nb_vlan_filter = DPDK_MAX_VLAN_FILTER;
    uint16_t *vlan_filter = cfg->dpdk.vlan_filter_id;
    return __parse_config_list(vlan_filter, &cfg->dpdk.nb_vlan_filter, v_str);
}

static int
vip_cfg_handler(struct ff_port_cfg *cur_port_cfg, struct ff_vlan_cfg *cur_vlan_cfg)
{
    //vip cfg
    int ret, nb_vip;
    char *vip_addr_array[VIP_MAX_NUM], *vip_addr_str;
    char **vip_addr_array_p;

    if (cur_port_cfg) {
        vip_addr_str = cur_port_cfg->vip_addr_str;
    } else if (cur_vlan_cfg) {
        vip_addr_str = cur_vlan_cfg->vip_addr_str;
    } else {
        fprintf(stdout, "vip_cfg_handler cur_port_cfg and cur_vlan_cfg both NULL, not set vip_addr\n");
        return 1;
    }

    ret = rte_strsplit(vip_addr_str, strlen(vip_addr_str), &vip_addr_array[0], VIP_MAX_NUM, ';');
    if (ret <= 0) {
        fprintf(stdout, "vip_cfg_handler nb_vip is 0, not set vip_addr or set invalid vip_addr %s\n",
            vip_addr_str);
        return 1;
    }

    nb_vip = ret;

    vip_addr_array_p = (char **)calloc(nb_vip, sizeof(char *));
    if (vip_addr_array_p == NULL) {
        fprintf(stderr, "vip_cfg_handler malloc failed\n");
        goto err;
    }

    memcpy(vip_addr_array_p, vip_addr_array, nb_vip * sizeof(char *));

    if (cur_port_cfg) {
        cur_port_cfg->nb_vip = nb_vip;
        cur_port_cfg->vip_addr_array = vip_addr_array_p;
    } else if (cur_vlan_cfg) {
        cur_vlan_cfg->nb_vip = nb_vip;
        cur_vlan_cfg->vip_addr_array = vip_addr_array_p;
    }

    return 1;

err:
    return 0;
}

#ifdef INET6
static int
vip6_cfg_handler(struct ff_port_cfg *cur_port_cfg, struct ff_vlan_cfg *cur_vlan_cfg)
{
    //vip6 cfg
    int ret, nb_vip6;
    char *vip_addr6_array[VIP_MAX_NUM], *vip_addr6_str;
    char **vip_addr6_array_p;

    if (cur_port_cfg) {
        vip_addr6_str = cur_port_cfg->vip_addr6_str;
    } else if (cur_vlan_cfg) {
        vip_addr6_str = cur_vlan_cfg->vip_addr6_str;
    } else {
        fprintf(stdout, "vip6_cfg_handler cur_port_cfg and cur_vlan_cfg both NULL, not set vip_addr\n");
        return 1;
    }

    ret = rte_strsplit(vip_addr6_str, strlen(vip_addr6_str),
                                    &vip_addr6_array[0], VIP_MAX_NUM, ';');
    if (ret == 0) {
        fprintf(stdout, "vip6_cfg_handler nb_vip6 is 0, not set vip_addr6 or set invalid vip_addr6 %s\n",
            vip_addr6_str);
        return 1;
    }

    nb_vip6 = ret;

    vip_addr6_array_p = (char **) calloc(nb_vip6, sizeof(char *));
    if (vip_addr6_array_p == NULL) {
        fprintf(stderr, "vip6_cfg_handler malloc failed\n");
        goto err;
    }

    memcpy(vip_addr6_array_p, vip_addr6_array, nb_vip6 * sizeof(char *));

    if (cur_port_cfg) {
        cur_port_cfg->nb_vip6 = nb_vip6;
        cur_port_cfg->vip_addr6_array = vip_addr6_array_p;
    } else if (cur_vlan_cfg) {
        cur_vlan_cfg->nb_vip6 = nb_vip6;
        cur_vlan_cfg->vip_addr6_array = vip_addr6_array_p;
    }

    return 1;

err:
    return 0;
}
#endif

#ifdef FF_IPFW
static int
ipfw_pr_cfg_handler(struct ff_port_cfg *cur_port_cfg, struct ff_vlan_cfg *cur_vlan_cfg)
{
    //vip cfg
    int ret, nb_vip, i;
    char *vip_addr_array[VIP_MAX_NUM], *vip_addr_mask_array[2], *vip_addr_str;
    struct ff_ipfw_pr_cfg *vipfw_pr_cfg_p;

    if (cur_port_cfg) {
        vip_addr_str = cur_port_cfg->pr_addr_str;
    } else if (cur_vlan_cfg) {
        vip_addr_str = cur_vlan_cfg->pr_addr_str;
    } else {
        fprintf(stdout, "ipfw_pr_cfg_handlercur_port_cfg and cur_vlan_cfg both NULL, not set vip_addr\n");
        return 1;
    }

    ret = rte_strsplit(vip_addr_str, strlen(vip_addr_str), &vip_addr_array[0], VIP_MAX_NUM, ';');
    if (ret <= 0) {
        fprintf(stdout, "ipfw_pr_cfg_handler nb_vip is 0, not set vip_addr or set invalid vip_addr %s\n",
            vip_addr_str);
        return 1;
    }

    nb_vip = ret;

    vipfw_pr_cfg_p = (struct ff_ipfw_pr_cfg *)calloc(nb_vip, sizeof(struct ff_ipfw_pr_cfg));
    if (vipfw_pr_cfg_p == NULL) {
        fprintf(stderr, "ipfw_pr_cfg_handler malloc failed\n");
        goto err;
    }

    for (i = 0; i < nb_vip; i++) {
        vip_addr_str = vip_addr_array[i];
        ret = rte_strsplit(vip_addr_str, strlen(vip_addr_str), &vip_addr_mask_array[0], 2, ' ');
        if (ret != 2) {
            fprintf(stdout, "ipfw_pr_cfg_handler addr and netmask format error %s\n",
                vip_addr_str);
            free(vipfw_pr_cfg_p);
            return 1;
        }

        vipfw_pr_cfg_p[i].addr = vip_addr_mask_array[0];
        vipfw_pr_cfg_p[i].netmask = vip_addr_mask_array[1];
    }

    if (cur_port_cfg) {
        cur_port_cfg->nb_pr = nb_vip;
        cur_port_cfg->pr_cfg = vipfw_pr_cfg_p;
    } else if (cur_vlan_cfg) {
        cur_vlan_cfg->nb_pr = nb_vip;
        cur_vlan_cfg->pr_cfg = vipfw_pr_cfg_p;
    }

    return 1;

err:
    return 0;
}
#endif

static int
port_cfg_handler(struct ff_config *cfg, const char *section,
    const char *name, const char *value) {

    if (cfg->dpdk.nb_ports == 0) {
        fprintf(stderr, "port_cfg_handler: must config dpdk.port_list first\n");
        return 0;
    }

    if (cfg->dpdk.port_cfgs == NULL) {
        struct ff_port_cfg *pc = calloc(RTE_MAX_ETHPORTS, sizeof(struct ff_port_cfg));
        if (pc == NULL) {
            fprintf(stderr, "port_cfg_handler malloc failed\n");
            return 0;
        }
        // initialize lcore list and nb_lcores
        int i;
        for (i = 0; i < cfg->dpdk.nb_ports; ++i) {
            uint16_t portid = cfg->dpdk.portid_list[i];

            struct ff_port_cfg *pconf = &pc[portid];
            pconf->port_id = portid;
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
    if (portid > cfg->dpdk.max_portid) {
        fprintf(stderr, "port_cfg_handler section[%s] bigger than max port id\n", section);
        return 1;
    }

    struct ff_port_cfg *cur = &cfg->dpdk.port_cfgs[portid];
    if (cur->name == NULL) {
        cur->name = strdup(section);
        cur->port_id = portid;
    }

    if (strcmp(name, "if_name") == 0) {
        cur->ifname = strdup(value);
    } else if (strcmp(name, "addr") == 0) {
        cur->addr = strdup(value);
    } else if (strcmp(name, "netmask") == 0) {
        cur->netmask = strdup(value);
    } else if (strcmp(name, "broadcast") == 0) {
        cur->broadcast = strdup(value);
    } else if (strcmp(name, "gateway") == 0) {
        cur->gateway = strdup(value);
    } else if (strcmp(name, "lcore_list") == 0) {
        return parse_port_lcore_list(cur, value);
    } else if (strcmp(name, "slave_port_list") == 0) {
        return parse_port_slave_list(cur, value);
    } else if (strcmp(name, "vip_addr") == 0) {
        cur->vip_addr_str = strdup(value);
        if (cur->vip_addr_str) {
            return vip_cfg_handler(cur, NULL);
        }
    } else if (strcmp(name, "vip_ifname") == 0) {
        cur->vip_ifname = strdup(value);
    }

#ifdef FF_IPFW
    else if (strcmp(name, "ipfw_pr") == 0) {
        cur->pr_addr_str = strdup(value);
        if (cur->pr_addr_str) {
            return ipfw_pr_cfg_handler(cur, NULL);
        }
    }
#endif

#ifdef INET6
    else if (0 == strcmp(name, "addr6")) {
        cur->addr6_str = strdup(value);
    } else if (0 == strcmp(name, "prefix_len")) {
        cur->prefix_len = atoi(value);
    } else if (0 == strcmp(name, "gateway6")) {
        cur->gateway6_str = strdup(value);
    } else if (strcmp(name, "vip_addr6") == 0) {
        cur->vip_addr6_str = strdup(value);
        if (cur->vip_addr6_str) {
            return vip6_cfg_handler(cur, NULL);
        }
    } else if (0 == strcmp(name, "vip_prefix_len")) {
        cur->vip_prefix_len = atoi(value);
    }
#endif

    return 1;
}

static int
vlan_cfg_handler(struct ff_config *cfg, const char *section,
    const char *name, const char *value) {
    int vlanid, vlan_index, portid;
    int ret;

    if (cfg->dpdk.nb_vlan_filter == 0) {
        fprintf(stderr, "vlan_cfg_handler: must config dpdk.vlan_filter first\n");
        return 0;
    }

    if (cfg->dpdk.vlan_cfgs == NULL) {
        struct ff_vlan_cfg *vc = calloc(DPDK_MAX_VLAN_FILTER, sizeof(struct ff_vlan_cfg));
        if (vc == NULL) {
            fprintf(stderr, "vlan_cfg_handler malloc failed\n");
            return 0;
        }
        cfg->dpdk.vlan_cfgs = vc;
    }

    ret = sscanf(section, "vlan%d", &vlanid);
    if (ret != 1) {
        fprintf(stderr, "vlan_cfg_handler section[%s] error\n", section);
        return 0;
    }

    /* just return true if vlanid not in vlan_filter */
    for (vlan_index = 0; vlan_index < cfg->dpdk.nb_vlan_filter; vlan_index ++) {
        if (vlanid == cfg->dpdk.vlan_filter_id[vlan_index]) {
            break;
        }

        if (vlan_index >= cfg->dpdk.nb_vlan_filter) {
            fprintf(stderr, "vlan_cfg_handler section[%s] mot match vlan filter, ignore it\n", section);
            return 1;
        }
    }

    struct ff_vlan_cfg *cur = &cfg->dpdk.vlan_cfgs[vlan_index];
    if (cur->name == NULL) {
        cur->name = strdup(section);
        cur->vlan_id = vlanid;
        cur->vlan_idx = vlan_index;
    }

    /* vlan not need `if_name`, should use [portN]'s `if_name` */
    /*if (strcmp(name, "if_name") == 0) {
        cur->ifname = strdup(value);
    } else */
    if (strcmp(name, "portid") == 0) {
        portid = atoi(value);
        if (portid > cfg->dpdk.max_portid) {
            fprintf(stderr, "vlan_cfg_handler portid %d bigger than max port id\n", portid);
            return 1;
        }
        struct ff_port_cfg *pc = &cfg->dpdk.port_cfgs[portid];
        cur->port_id = portid;
        pc->vlan_cfgs[pc->nb_vlan] = cur;
        pc->nb_vlan++;
    } else if (strcmp(name, "addr") == 0) {
        cur->addr = strdup(value);
    } else if (strcmp(name, "netmask") == 0) {
        cur->netmask = strdup(value);
    } else if (strcmp(name, "broadcast") == 0) {
        cur->broadcast = strdup(value);
    } else if (strcmp(name, "gateway") == 0) {
        cur->gateway = strdup(value);
    } else if (strcmp(name, "vip_addr") == 0) {
        cur->vip_addr_str = strdup(value);
        if (cur->vip_addr_str) {
            return vip_cfg_handler(NULL, cur);
        }
    /*} else if (strcmp(name, "vip_ifname") == 0) {
        cur->vip_ifname = strdup(value);*/
    }

#ifdef FF_IPFW
    else if (strcmp(name, "ipfw_pr") == 0) {
        cur->pr_addr_str = strdup(value);
        if (cur->pr_addr_str) {
            return ipfw_pr_cfg_handler(NULL, cur);
        }
    }
#endif

#ifdef INET6
    else if (0 == strcmp(name, "addr6")) {
        cur->addr6_str = strdup(value);
    } else if (0 == strcmp(name, "prefix_len")) {
        cur->prefix_len = atoi(value);
    } else if (0 == strcmp(name, "gateway6")) {
        cur->gateway6_str = strdup(value);
    } else if (strcmp(name, "vip_addr6") == 0) {
        cur->vip_addr6_str = strdup(value);
        if (cur->vip_addr6_str) {
            return vip6_cfg_handler(NULL, cur);
        }
    } else if (0 == strcmp(name, "vip_prefix_len")) {
        cur->vip_prefix_len = atoi(value);
    }
#endif

    return 1;
}

static int
vdev_cfg_handler(struct ff_config *cfg, const char *section,
    const char *name, const char *value) {

    if (cfg->dpdk.nb_vdev == 0) {
        fprintf(stderr, "vdev_cfg_handler: must config dpdk.nb_vdev first\n");
        return 0;
    }

    if (cfg->dpdk.vdev_cfgs == NULL) {
        struct ff_vdev_cfg *vc = calloc(RTE_MAX_ETHPORTS, sizeof(struct ff_vdev_cfg));
        if (vc == NULL) {
            fprintf(stderr, "vdev_cfg_handler malloc failed\n");
            return 0;
        }
        cfg->dpdk.vdev_cfgs = vc;
    }

    int vdevid;
    int ret = sscanf(section, "vdev%d", &vdevid);
    if (ret != 1) {
        fprintf(stderr, "vdev_cfg_handler section[%s] error\n", section);
        return 0;
    }

    /* just return true if vdevid >= nb_vdev because it has no effect */
    if (vdevid > cfg->dpdk.nb_vdev) {
        fprintf(stderr, "vdev_cfg_handler section[%s] bigger than max vdev id\n", section);
        return 1;
    }

    struct ff_vdev_cfg *cur = &cfg->dpdk.vdev_cfgs[vdevid];
    if (cur->name == NULL) {
        cur->name = strdup(section);
        cur->vdev_id = vdevid;
    }

    if (strcmp(name, "iface") == 0) {
        cur->iface = strdup(value);
    } else if (strcmp(name, "path") == 0) {
        cur->path = strdup(value);
    } else if (strcmp(name, "queues") == 0) {
        cur->nb_queues = atoi(value);
    } else if (strcmp(name, "queue_size") == 0) {
        cur->queue_size = atoi(value);
    } else if (strcmp(name, "mac") == 0) {
        cur->mac = strdup(value);
    } else if (strcmp(name, "cq") == 0) {
        cur->nb_cq = atoi(value);
    }

    return 1;
}

static int
bond_cfg_handler(struct ff_config *cfg, const char *section,
    const char *name, const char *value) {

    if (cfg->dpdk.nb_bond == 0) {
        fprintf(stderr, "bond_cfg_handler: must config dpdk.nb_bond first\n");
        return 0;
    }

    if (cfg->dpdk.bond_cfgs == NULL) {
        struct ff_bond_cfg *vc = calloc(RTE_MAX_ETHPORTS, sizeof(struct ff_bond_cfg));
        if (vc == NULL) {
            fprintf(stderr, "ff_bond_cfg malloc failed\n");
            return 0;
        }
        cfg->dpdk.bond_cfgs = vc;
    }

    int bondid;
    int ret = sscanf(section, "bond%d", &bondid);
    if (ret != 1) {
        fprintf(stderr, "bond_cfg_handler section[%s] error\n", section);
        return 0;
    }

    /* just return true if bondid >= nb_vdev because it has no effect */
    if (bondid > cfg->dpdk.nb_bond) {
        fprintf(stderr, "bond_cfg_handler section[%s] bigger than max bond id\n", section);
        return 1;
    }

    struct ff_bond_cfg *cur = &cfg->dpdk.bond_cfgs[bondid];
    if (cur->name == NULL) {
        cur->name = strdup(section);
        cur->bond_id = bondid;
    }

    if (strcmp(name, "mode") == 0) {
        cur->mode = atoi(value);
    } else if (strcmp(name, "slave") == 0) {
        cur->slave = strdup(value);
    } else if (strcmp(name, "primary") == 0) {
        cur->primary = strdup(value);
    } else if (strcmp(name, "socket_id") == 0) {
        cur->socket_id = atoi(value);
    } else if (strcmp(name, "mac") == 0) {
        cur->bond_mac = strdup(value);
    } else if (strcmp(name, "xmit_policy") == 0) {
        cur->xmit_policy = strdup(value);
    } else if (strcmp(name, "lsc_poll_period_ms") == 0) {
        cur->lsc_poll_period_ms = atoi(value);
    } else if (strcmp(name, "up_delay") == 0) {
        cur->up_delay = atoi(value);
    } else if (strcmp(name, "down_delay") == 0) {
        cur->down_delay = atoi(value);
    }

    return 1;
}

static int
rss_tbl_cfg_handler(struct ff_rss_check_cfg *cur)
{
    //vip cfg
    int ret, nb_rss_tbl, i, j, k;
    char *rss_tbl_array[FF_RSS_TBL_MAX_ENTRIES], *rss_tbl_4tuble_array[4], *rss_tbl_str;
    struct ff_rss_tbl_cfg *rss_tbl_cfg_p;

    rss_tbl_str = cur->rss_tbl_str;

    ret = rte_strsplit(rss_tbl_str, strlen(rss_tbl_str), &rss_tbl_array[0], FF_RSS_TBL_MAX_ENTRIES, ';');
    if (ret <= 0) {
        fprintf(stdout, "rss_tbl_cfg_handler nb_rss_tbl is 0, not set rss_tbl or set invalid rss_tbl %s\n",
            rss_tbl_str);
        return 1;
    }

    nb_rss_tbl = ret;

    rss_tbl_cfg_p = &cur->rss_tbl_cfgs[0];

    for (i = 0; i < nb_rss_tbl; i++) {
        rss_tbl_str = rss_tbl_array[i];
        /* port_id, daddr(local), saddr(remote), sport */
        ret = rte_strsplit(rss_tbl_str, strlen(rss_tbl_str), &rss_tbl_4tuble_array[0], 4, ' ');
        if (ret != 4) {
            fprintf(stdout, "rss_tbl_cfg_handler daddr/saddr/sport format error %s\n",
                rss_tbl_str);
            return 1;
        }

        /* Note: daddr must be include by port_id's addr or vip_addr, but here not check it now */
        rss_tbl_cfg_p[i].port_id = atoi(rss_tbl_4tuble_array[0]);
        inet_pton(AF_INET, rss_tbl_4tuble_array[1], (void *)&(rss_tbl_cfg_p[i].daddr));
        inet_pton(AF_INET, rss_tbl_4tuble_array[2], (void *)&(rss_tbl_cfg_p[i].saddr));
        rss_tbl_cfg_p[i].sport = htons(atoi(rss_tbl_4tuble_array[3]));
    }

    cur->nb_rss_tbl = nb_rss_tbl;

    return 1;
}

static int
rss_check_cfg_handler(struct ff_config *cfg, __rte_unused const char *section,
    const char *name, const char *value)
{
    if (cfg->dpdk.port_cfgs == NULL && cfg->dpdk.vlan_cfgs == NULL) {
        fprintf(stderr, "rss_check_cfg_handler: must config dpdk.port or dpdk.vlan first\n");
        return 0;
    }

    if (cfg->dpdk.rss_check_cfgs == NULL) {
        struct ff_rss_check_cfg *rcc = calloc(1, sizeof(struct ff_rss_check_cfg));
        if (rcc == NULL) {
            fprintf(stderr, "rss_check_cfg_handler malloc failed\n");
            return 0;
        }
        cfg->dpdk.rss_check_cfgs = rcc;
    }

    struct ff_rss_check_cfg *cur = cfg->dpdk.rss_check_cfgs;

    if (strcmp(name, "enable") == 0) {
        cur->enable = atoi(value);
    } else if (strcmp(name, "rss_tbl") == 0) {
        cur->rss_tbl_str = strdup(value);
        if (cur->rss_tbl_str) {
            return rss_tbl_cfg_handler(cur);
        }
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
    if (MATCH("dpdk", "log_level")) {
        pconfig->dpdk.log_level = atoi(value);
    } else if (MATCH("dpdk", "fstack_log_level")) {
        pconfig->log.level = atoi(value);
    } else if (MATCH("dpdk", "fstack_log_file_prefix")) {
        pconfig->log.dir = strdup(value);
    } else if (MATCH("dpdk", "channel")) {
        pconfig->dpdk.nb_channel = atoi(value);
    } else if (MATCH("dpdk", "memory")) {
        pconfig->dpdk.memory = atoi(value);
    } else if (MATCH("dpdk", "no_huge")) {
        pconfig->dpdk.no_huge = atoi(value);
    } else if (MATCH("dpdk", "lcore_mask")) {
        pconfig->dpdk.lcore_mask = strdup(value);
        return parse_lcore_mask(pconfig, pconfig->dpdk.lcore_mask);
    } else if (MATCH("dpdk", "base_virtaddr")) {
        pconfig->dpdk.base_virtaddr= strdup(value);
    } else if (MATCH("dpdk", "file_prefix")) {
        pconfig->dpdk.file_prefix = strdup(value);
    } else if (MATCH("dpdk", "pci_whitelist")) {
        pconfig->dpdk.pci_whitelist = strdup(value);
    } else if (MATCH("dpdk", "port_list")) {
        return parse_port_list(pconfig, value);
    } else if (MATCH("dpdk", "nb_vdev")) {
        pconfig->dpdk.nb_vdev = atoi(value);
    } else if (MATCH("dpdk", "nb_bond")) {
        pconfig->dpdk.nb_bond = atoi(value);
    } else if (MATCH("dpdk", "promiscuous")) {
        pconfig->dpdk.promiscuous = atoi(value);
    } else if (MATCH("dpdk", "numa_on")) {
        pconfig->dpdk.numa_on = atoi(value);
    } else if (MATCH("dpdk", "tso")) {
        pconfig->dpdk.tso = atoi(value);
    } else if (MATCH("dpdk", "tx_csum_offoad_skip")) {
        pconfig->dpdk.tx_csum_offoad_skip = atoi(value);
    } else if (MATCH("dpdk", "vlan_strip")) {
        pconfig->dpdk.vlan_strip = atoi(value);
    } else if (MATCH("dpdk", "vlan_filter")) {
        return parse_vlan_filter_list(pconfig, value);
    } else if (MATCH("dpdk", "idle_sleep")) {
        pconfig->dpdk.idle_sleep = atoi(value);
    } else if (MATCH("dpdk", "pkt_tx_delay")) {
        pconfig->dpdk.pkt_tx_delay = atoi(value);
    } else if (MATCH("dpdk", "symmetric_rss")) {
        pconfig->dpdk.symmetric_rss = atoi(value);
    } else if (MATCH("kni", "enable")) {
        pconfig->kni.enable= atoi(value);
    } else if (MATCH("kni", "type")) {
        pconfig->kni.type= atoi(value);
    } else if (MATCH("kni", "console_packets_ratelimit")) {
        pconfig->kni.console_packets_ratelimit= atoi(value);
    } else if (MATCH("kni", "general_packets_ratelimit")) {
        pconfig->kni.general_packets_ratelimit= atoi(value);
    } else if (MATCH("kni", "kernel_packets_ratelimit")) {
        pconfig->kni.kernel_packets_ratelimit= atoi(value);
    } else if (MATCH("kni", "kni_action")) {
        pconfig->kni.kni_action= strdup(value);
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
        } else if (strcmp(name, "memsz_MB") == 0) {
            pconfig->freebsd.mem_size = atoi(value);
        } else {
            return freebsd_conf_handler(pconfig, "boot", name, value);
        }
    } else if (strcmp(section, "freebsd.sysctl") == 0) {
        return freebsd_conf_handler(pconfig, "sysctl", name, value);
    } else if (strncmp(section, "port", 4) == 0) {
        return port_cfg_handler(pconfig, section, name, value);
    } else if (strncmp(section, "vlan", 4) == 0) {
        return vlan_cfg_handler(pconfig, section, name, value);
    } else if (strncmp(section, "vdev", 4) == 0) {
        return vdev_cfg_handler(pconfig, section, name, value);
    } else if (strncmp(section, "bond", 4) == 0) {
        return bond_cfg_handler(pconfig, section, name, value);
    } else if (strcmp(section, "pcap") == 0) {
        if (strcmp(name, "snaplen") == 0) {
            pconfig->pcap.snap_len = (uint16_t)atoi(value);
        } else if (strcmp(name, "savelen") == 0) {
            pconfig->pcap.save_len = (uint32_t)atoi(value);
        } else if (strcmp(name, "enable") == 0) {
            pconfig->pcap.enable = (uint16_t)atoi(value);
        } else if (strcmp(name, "savepath") == 0) {
            pconfig->pcap.save_path = strdup(value);
        }
    } else if (strcmp(section, "rss_check") == 0) {
        return rss_check_cfg_handler(pconfig, section, name, value);
    }

    return 1;
}

static int
dpdk_args_setup(struct ff_config *cfg)
{
    int n = 0, i;
    dpdk_argv[n++] = strdup("f-stack");
    char temp[DPDK_CONFIG_MAXLEN] = {0}, temp2[DPDK_CONFIG_MAXLEN] = {0};

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
    if (cfg->dpdk.log_level) {
        sprintf(temp, "--log-level=%d", cfg->dpdk.log_level);
        dpdk_argv[n++] = strdup(temp);
    }
    if (cfg->dpdk.proc_type) {
        sprintf(temp, "--proc-type=%s", cfg->dpdk.proc_type);
        dpdk_argv[n++] = strdup(temp);
    }
    if (cfg->dpdk.base_virtaddr) {
        sprintf(temp, "--base-virtaddr=%s", cfg->dpdk.base_virtaddr);
        dpdk_argv[n++] = strdup(temp);
    }
    if (cfg->dpdk.file_prefix) {
        sprintf(temp, "--file-prefix=container-%s", cfg->dpdk.file_prefix);
        dpdk_argv[n++] = strdup(temp);
    }
    if (cfg->dpdk.pci_whitelist) {
        char* token;
        char* rest = cfg->dpdk.pci_whitelist;

        while ((token = strtok_r(rest, ",", &rest))){
            sprintf(temp, "--pci-whitelist=%s", token);
            dpdk_argv[n++] = strdup(temp);
        }
    }

    if (cfg->dpdk.nb_vdev) {
        for (i=0; i<cfg->dpdk.nb_vdev; i++) {
            sprintf(temp, "--vdev=virtio_user%d,path=%s",
                cfg->dpdk.vdev_cfgs[i].vdev_id,
                cfg->dpdk.vdev_cfgs[i].path);
            if (cfg->dpdk.vdev_cfgs[i].nb_queues) {
                sprintf(temp2, ",queues=%u",
                    cfg->dpdk.vdev_cfgs[i].nb_queues);
                strcat(temp, temp2);
            }
            if (cfg->dpdk.vdev_cfgs[i].nb_cq) {
                sprintf(temp2, ",cq=%u",
                    cfg->dpdk.vdev_cfgs[i].nb_cq);
                strcat(temp, temp2);
            }
            if (cfg->dpdk.vdev_cfgs[i].queue_size) {
                sprintf(temp2, ",queue_size=%u",
                    cfg->dpdk.vdev_cfgs[i].queue_size);
                strcat(temp, temp2);
            }
            if (cfg->dpdk.vdev_cfgs[i].mac) {
                sprintf(temp2, ",mac=%s",
                    cfg->dpdk.vdev_cfgs[i].mac);
                strcat(temp, temp2);
            }
            dpdk_argv[n++] = strdup(temp);
        }
        sprintf(temp, "--no-pci");
        dpdk_argv[n++] = strdup(temp);
        if (!cfg->dpdk.file_prefix) {
            sprintf(temp, "--file-prefix=container");
            dpdk_argv[n++] = strdup(temp);
        }
    }

    if (cfg->dpdk.nb_bond) {
        for (i=0; i<cfg->dpdk.nb_bond; i++) {
            sprintf(temp, "--vdev");
            dpdk_argv[n++] = strdup(temp);
            sprintf(temp, "net_bonding%d,mode=%d,slave=%s",
                cfg->dpdk.bond_cfgs[i].bond_id,
                cfg->dpdk.bond_cfgs[i].mode,
                cfg->dpdk.bond_cfgs[i].slave);

                if (cfg->dpdk.bond_cfgs[i].primary) {
                    sprintf(temp2, ",primary=%s",
                        cfg->dpdk.bond_cfgs[i].primary);
                    strcat(temp, temp2);
                }

                if (cfg->dpdk.bond_cfgs[i].socket_id) {
                    sprintf(temp2, ",socket_id=%d",
                        cfg->dpdk.bond_cfgs[i].socket_id);
                    strcat(temp, temp2);
                }

                if (cfg->dpdk.bond_cfgs[i].bond_mac) {
                    sprintf(temp2, ",mac=%s",
                        cfg->dpdk.bond_cfgs[i].bond_mac);
                    strcat(temp, temp2);
                }

                if (cfg->dpdk.bond_cfgs[i].xmit_policy) {
                    sprintf(temp2, ",xmit_policy=%s",
                        cfg->dpdk.bond_cfgs[i].xmit_policy);
                    strcat(temp, temp2);
                }

                if (cfg->dpdk.bond_cfgs[i].lsc_poll_period_ms) {
                    sprintf(temp2, ",lsc_poll_period_ms=%d",
                        cfg->dpdk.bond_cfgs[i].lsc_poll_period_ms);
                    strcat(temp, temp2);
                }

                if (cfg->dpdk.bond_cfgs[i].up_delay) {
                    sprintf(temp2, ",up_delay=%d",
                        cfg->dpdk.bond_cfgs[i].up_delay);
                    strcat(temp, temp2);
                }

                if (cfg->dpdk.bond_cfgs[i].down_delay) {
                    sprintf(temp2, ",down_delay=%d",
                        cfg->dpdk.bond_cfgs[i].down_delay);
                    strcat(temp, temp2);
                }
                dpdk_argv[n++] = strdup(temp);
        }
    }

    dpdk_argc = n;

    for (i=0; i<n; i++)
        printf("%s ", dpdk_argv[i]);
    printf("\n");

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

    if (cfg->dpdk.proc_type == NULL) {
        cfg->dpdk.proc_type = strdup("auto");
    }

    if (strcmp(cfg->dpdk.proc_type, "primary") &&
        strcmp(cfg->dpdk.proc_type, "secondary") &&
        strcmp(cfg->dpdk.proc_type, "auto")) {
        printf("invalid proc-type:%s\n", cfg->dpdk.proc_type);
        return -1;
    }

    if ((uint16_t)cfg->dpdk.proc_id > RTE_MAX_LCORE) {
        printf("invalid proc_id:%d, use default 0\n", cfg->dpdk.proc_id);
        cfg->dpdk.proc_id = 0;
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

    if(cfg->kni.kni_action) {
        if (strcasecmp(cfg->kni.kni_action,"alltokni") &&
            strcasecmp(cfg->kni.kni_action,"alltoff") &&
            strcasecmp(cfg->kni.kni_action,"default")){
                fprintf(stderr, "conf kni.kni_action[alltokni|alltoff|default] is error(%s)\n",
                cfg->kni.kni_action);
                return -1;
        }
    }

    if (cfg->pcap.save_len < PCAP_SAVE_MINLEN)
        cfg->pcap.save_len = PCAP_SAVE_MINLEN;
    if (cfg->pcap.snap_len < PCAP_SNAP_MINLEN)
        cfg->pcap.snap_len = PCAP_SNAP_MINLEN;
    if (cfg->pcap.save_path==NULL || strlen(cfg->pcap.save_path) ==0)
        cfg->pcap.save_path = strdup(".");

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
        uint16_t portid = cfg->dpdk.portid_list[i];
        struct ff_port_cfg *pc = &cfg->dpdk.port_cfgs[portid];
        CHECK_VALID(addr);
        CHECK_VALID(netmask);
        CHECK_VALID(broadcast);
        CHECK_VALID(gateway);
        // check if the lcores in lcore_list are enabled.
        int k;
        for (k = 0; k < pc->nb_lcores; k++) {
            uint16_t lcore_id = pc->lcore_list[k];
            if (uint16_binary_search(cfg->dpdk.proc_lcore, 0,
                                     cfg->dpdk.nb_procs-1, lcore_id) < 0) {
                fprintf(stderr, "lcore %d is not enabled.\n", lcore_id);
                return -1;
            }
        }
        /*
         * only primary process process KNI, so if KNI enabled,
         * primary lcore must stay in every enabled ports' lcore_list
         */
        if (cfg->kni.enable &&
            strcmp(cfg->dpdk.proc_type, "primary") == 0) {
            int found = 0;
            int j;
            uint16_t lcore_id = cfg->dpdk.proc_lcore[cfg->dpdk.proc_id];
            for (j = 0; j < pc->nb_lcores; j++) {
                if (pc->lcore_list[j] == lcore_id) {
                    found = 1;
                }
            }
            if (! found) {
                fprintf(stderr,
                         "primary lcore %d should stay in port %d's lcore_list.\n",
                         lcore_id, pc->port_id);
                return -1;
            }

            if (cfg->kni.type != KNI_TYPE_KNI && cfg->kni.type != KNI_TYPE_VIRTIO) {
                fprintf(stderr,
                         "kni type value must be 0 or 1, now is:%d\n", cfg->kni.type);
                return -1;
            }
        }
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
    cfg->dpdk.pkt_tx_delay = BURST_TX_DRAIN_US;

    /* KNI ratelimit default disabled */
    //cfg->kni.console_packets_ratelimit = KNI_RATELIMT_CONSOLE;
    //cfg->kni.general_packets_ratelimit = KNI_RATELIMT_GENERAL;
    //cfg->kni.kernel_packets_ratelimit = KNI_RATELIMT_KERNEL;

    cfg->freebsd.hz = 100;
    cfg->freebsd.physmem = 1048576*256;
    cfg->freebsd.fd_reserve = 0;
    cfg->freebsd.mem_size = 256;

    cfg->log.level = FF_LOG_DISABLE;
    cfg->log.dir = FF_LOG_FILENAME_PREFIX;
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
        switch(ret) {
            case -1:
                printf("failed to open file %s\n", ff_global_cfg.filename);
                break;
            case -2:
                printf("failed to allocate memory for config parsing\n");
                break;
            default:
                printf("parse %s failed on line %d\n", ff_global_cfg.filename, ret);
        }
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
