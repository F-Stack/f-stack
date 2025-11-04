/*
 * Copyright (c) 2010 Kip Macy. All rights reserved.
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
 * Derived in part from libplebnet's pn_veth.c.
 *
 */

#include <sys/ctype.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/sched.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if_tap.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/if_clone.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/nd6.h>
#ifdef FF_IPFW
#include <netinet/ip_fw.h>
#endif

#include <machine/atomic.h>

#include "ff_veth.h"
#include "ff_config.h"
#include "ff_dpdk_if.h"

struct ff_veth_softc {
    struct ifnet *ifp;
    uint8_t mac[ETHER_ADDR_LEN];
    char host_ifname[IF_NAMESIZE];

    in_addr_t ip;
    in_addr_t netmask;
    in_addr_t broadcast;
    in_addr_t gateway;

    uint8_t nb_vip;
    in_addr_t vip[VIP_MAX_NUM];

#ifdef INET6
    struct in6_addr ip6;
    struct in6_addr gateway6;
    uint8_t prefix_length;

    uint8_t nb_vip6;
    uint8_t vip_prefix_length;
    struct in6_addr vip6[VIP_MAX_NUM];
#endif /* INET6 */

    struct ff_dpdk_if_context *host_ctx;
};

static int
ff_veth_config(struct ff_veth_softc *sc, struct ff_port_cfg *cfg)
{
    int i, j;

    memcpy(sc->mac, cfg->mac, ETHER_ADDR_LEN);
    inet_pton(AF_INET, cfg->addr, &sc->ip);
    inet_pton(AF_INET, cfg->netmask, &sc->netmask);
    inet_pton(AF_INET, cfg->broadcast, &sc->broadcast);
    inet_pton(AF_INET, cfg->gateway, &sc->gateway);

    if (cfg->nb_vip) {
        for (i = 0, j = 0; i < cfg->nb_vip; ++i) {
            if (inet_pton(AF_INET, cfg->vip_addr_array[i], &sc->vip[j])) {
                j++;
            } else {
                printf("ff_veth_config inet_pton vip %s failed.\n", cfg->vip_addr_array[i]);
            }
        }

        sc->nb_vip = j;
    }

#ifdef INET6
    if (cfg->addr6_str) {
        inet_pton(AF_INET6_LINUX, cfg->addr6_str, &sc->ip6);
        printf("%s: Addr6: %s\n", sc->host_ifname, cfg->addr6_str);

        if (cfg->gateway6_str) {
            inet_pton(AF_INET6_LINUX, cfg->gateway6_str, &sc->gateway6);
            printf("%s: Gateway6: %s\n", sc->host_ifname, cfg->gateway6_str);
        } else {
            printf("%s: No gateway6 config found.\n", sc->host_ifname);
        }

        sc->prefix_length = cfg->prefix_len == 0 ? 64 : cfg->prefix_len;
    } else {
        printf("%s: No addr6 config found.\n", sc->host_ifname);
    }

    if (cfg->nb_vip6) {
        for (i = 0, j = 0; i < cfg->nb_vip6; ++i) {
            if (inet_pton(AF_INET6_LINUX, cfg->vip_addr6_array[i], &sc->vip6[j])) {
                j++;
            } else {
                printf("ff_veth_config inet_pton vip6 %s failed.\n", cfg->vip_addr6_array[i]);
            }
        }

        sc->nb_vip6 = j;
        sc->vip_prefix_length = cfg->vip_prefix_len == 0 ? 64 : cfg->vip_prefix_len;
    }
#endif /* INET6 */

    return 0;
}

static int
ff_veth_vlan_config(struct ff_veth_softc *sc, struct ff_vlan_cfg *cfg)
{
    int i, j;

    inet_pton(AF_INET, cfg->addr, &sc->ip);
    inet_pton(AF_INET, cfg->netmask, &sc->netmask);
    inet_pton(AF_INET, cfg->broadcast, &sc->broadcast);
    inet_pton(AF_INET, cfg->gateway, &sc->gateway);

    if (cfg->nb_vip) {
        for (i = 0, j = 0; i < cfg->nb_vip; ++i) {
            if (inet_pton(AF_INET, cfg->vip_addr_array[i], &sc->vip[j])) {
                j++;
            } else {
                printf("ff_veth_vlan_config inet_pton vip %s failed.\n", cfg->vip_addr_array[i]);
            }
        }

        sc->nb_vip = j;
    }

#ifdef INET6
    if (cfg->addr6_str) {
        inet_pton(AF_INET6_LINUX, cfg->addr6_str, &sc->ip6);
        printf("%s: Addr6: %s\n", sc->host_ifname, cfg->addr6_str);

        if (cfg->gateway6_str) {
            inet_pton(AF_INET6_LINUX, cfg->gateway6_str, &sc->gateway6);
            printf("%s: Gateway6: %s\n", sc->host_ifname, cfg->gateway6_str);
        } else {
            printf("%s: No gateway6 config found.\n", sc->host_ifname);
        }

        sc->prefix_length = cfg->prefix_len == 0 ? 64 : cfg->prefix_len;
    } else {
        printf("%s: No addr6 config found.\n", sc->host_ifname);
    }

    if (cfg->nb_vip6) {
        for (i = 0, j = 0; i < cfg->nb_vip6; ++i) {
            if (inet_pton(AF_INET6_LINUX, cfg->vip_addr6_array[i], &sc->vip6[j])) {
                j++;
            } else {
                printf("ff_veth_vlan_config inet_pton vip6 %s failed.\n", cfg->vip_addr6_array[i]);
            }
        }

        sc->nb_vip6 = j;
        sc->vip_prefix_length = cfg->vip_prefix_len == 0 ? 64 : cfg->vip_prefix_len;
    }
#endif /* INET6 */

    return 0;
}


static void
ff_veth_init(void *arg)
{
    struct ff_veth_softc *sc = arg;
    struct ifnet *ifp = sc->ifp;

    ifp->if_drv_flags |= IFF_DRV_RUNNING;
    ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
    ifp->if_flags |= IFF_UP;
}

static void
ff_veth_start(struct ifnet *ifp)
{
    /* nothing to do */
}

static void
ff_veth_stop(struct ff_veth_softc *sc)
{
    struct ifnet *ifp = sc->ifp;

    ifp->if_drv_flags &= ~(IFF_DRV_RUNNING|IFF_DRV_OACTIVE);
    ifp->if_flags &= ~IFF_UP;
}

static int
ff_veth_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
    int error = 0;
    struct ff_veth_softc *sc = ifp->if_softc;

    switch (cmd) {
    case SIOCSIFFLAGS:
        if (ifp->if_flags & IFF_UP) {
            ff_veth_init(sc);
        } else if (ifp->if_drv_flags & IFF_DRV_RUNNING)
            ff_veth_stop(sc);
        break;
    default:
        error = ether_ioctl(ifp, cmd, data);
        break;
    }

    return (error);
}

int
ff_mbuf_copydata(void *m, void *data, int off, int len)
{
    int ret;
    struct mbuf *mb = (struct mbuf *)m;

    if (off + len > mb->m_pkthdr.len) {
        return -1;
    }

    m_copydata(mb, off, len, data);

    return 0;
}

void
ff_mbuf_tx_offload(void *m, struct ff_tx_offload *offload)
{
    struct mbuf *mb = (struct mbuf *)m;
    if (mb->m_pkthdr.csum_flags & CSUM_IP) {
        offload->ip_csum = 1;
    }

    if (mb->m_pkthdr.csum_flags & CSUM_TCP) {
        offload->tcp_csum = 1;
    }

    if (mb->m_pkthdr.csum_flags & CSUM_UDP) {
        offload->udp_csum = 1;
    }

    if (mb->m_pkthdr.csum_flags & CSUM_SCTP) {
        offload->sctp_csum = 1;
    }

    if (mb->m_pkthdr.csum_flags & CSUM_TSO) {
        offload->tso_seg_size = mb->m_pkthdr.tso_segsz;
    }
}

void
ff_mbuf_free(void *m)
{
    m_freem((struct mbuf *)m);
}

static void
ff_mbuf_ext_free(struct mbuf *m, void *arg1, void *arg2)
{
    ff_dpdk_pktmbuf_free(arg1);
}

int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len) {
    struct mbuf *mb;

    if (m == NULL) {
        return -1;
    }

    mb = m_getm2(NULL, max(len, 1), M_WAITOK, MT_DATA, 0);
    if (mb == NULL) {
        return -1;
    }

    m->bsd_mbuf = m->bsd_mbuf_off = mb;
    m->off = 0;
    m->len = len;

    return 0;
}

int
ff_zc_mbuf_write(struct ff_zc_mbuf *zm, const char *data, int len)
{
    int ret, length, progress = 0;
    struct mbuf *m, *mb;

    if (zm == NULL) {
        return -1;
    }
    m = (struct mbuf *)zm->bsd_mbuf_off;

    if (zm->off + len > zm->len) {
        return -1;
    }

    for (mb = m; mb != NULL; mb = mb->m_next) {
        length = min(M_TRAILINGSPACE(mb), len - progress);
        bcopy(data + progress, mtod(mb, char *) + mb->m_len, length);

        mb->m_len += length;
        progress += length;
        if (len == progress) {
            break;
        }
        //if (flags & M_PKTHDR)
        //    m->m_pkthdr.len += length;
    }
    zm->off += len;
    zm->bsd_mbuf_off = mb;

    return len;
}

int
ff_zc_mbuf_read(struct ff_zc_mbuf *m, const char *data, int len)
{
    // DOTO: Support read zero copy
    return 0;
}

void *
ff_mbuf_gethdr(void *pkt, uint16_t total, void *data,
    uint16_t len, uint8_t rx_csum)
{
    struct mbuf *m = m_gethdr(M_NOWAIT, MT_DATA);
    if (m == NULL) {
        return NULL;
    }

    if (m_pkthdr_init(m, M_NOWAIT) != 0) {
        return NULL;
    }

    m_extadd(m, data, len, ff_mbuf_ext_free, pkt, NULL, 0, EXT_DISPOSABLE);

    m->m_pkthdr.len = total;
    m->m_len = len;
    m->m_next = NULL;
    m->m_nextpkt = NULL;

    if (rx_csum) {
        m->m_pkthdr.csum_flags = CSUM_IP_CHECKED | CSUM_IP_VALID |
            CSUM_DATA_VALID | CSUM_PSEUDO_HDR;
        m->m_pkthdr.csum_data = 0xffff;
    }
    return (void *)m;
}

void *
ff_mbuf_get(void *p, void *m, void *data, uint16_t len)
{
    struct mbuf *prev = (struct mbuf *)p;
    struct mbuf *mb = m_get(M_NOWAIT, MT_DATA);

    if (mb == NULL) {
        return NULL;
    }

    m_extadd(mb, data, len, ff_mbuf_ext_free, m, NULL, 0, EXT_DISPOSABLE);

    mb->m_next = NULL;
    mb->m_nextpkt = NULL;
    mb->m_len = len;

    if (prev != NULL) {
        prev->m_next = mb;
    }

    return (void *)mb;
}

void
ff_veth_process_packet(void *arg, void *m)
{
    struct ifnet *ifp = (struct ifnet *)arg;
    struct mbuf *mb = (struct mbuf *)m;

    mb->m_pkthdr.rcvif = ifp;

    ifp->if_input(ifp, mb);
}

static int
ff_veth_transmit(struct ifnet *ifp, struct mbuf *m)
{
    struct ff_veth_softc *sc = (struct ff_veth_softc *)ifp->if_softc;
    return ff_dpdk_if_send(sc->host_ctx, (void*)m, m->m_pkthdr.len);
}

static void
ff_veth_qflush(struct ifnet *ifp)
{

}

static int
ff_veth_setaddr(struct ff_veth_softc *sc, const char *if_name)
{
    struct in_aliasreq req;
    bzero(&req, sizeof req);

    if (if_name) {
        strcpy(req.ifra_name, if_name);
    } else {
        strcpy(req.ifra_name, sc->ifp->if_dname);
    }

    struct sockaddr_in sa;
    bzero(&sa, sizeof(sa));
    sa.sin_len = sizeof(sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = sc->ip;
    bcopy(&sa, &req.ifra_addr, sizeof(sa));

    sa.sin_addr.s_addr = sc->netmask;
    bcopy(&sa, &req.ifra_mask, sizeof(sa));

    sa.sin_addr.s_addr = sc->broadcast;
    bcopy(&sa, &req.ifra_broadaddr, sizeof(sa));

    struct socket *so = NULL;
    socreate(AF_INET, &so, SOCK_DGRAM, 0, curthread->td_ucred, curthread);
    int ret = ifioctl(so, SIOCAIFADDR, (caddr_t)&req, curthread);

    soclose(so);

    return ret;
}

static int
ff_veth_set_gateway(struct ff_veth_softc *sc, uint32_t fib_num)
{
    struct sockaddr_in gw;
    bzero(&gw, sizeof(gw));
    gw.sin_len = sizeof(gw);
    gw.sin_family = AF_INET;
    gw.sin_addr.s_addr = sc->gateway;

    struct sockaddr_in dst;
    bzero(&dst, sizeof(dst));
    dst.sin_len = sizeof(dst);
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = 0;

    struct sockaddr_in nm;
    bzero(&nm, sizeof(nm));
    nm.sin_len = sizeof(nm);
    nm.sin_family = AF_INET;
    nm.sin_addr.s_addr = 0;

    return rtrequest_fib(RTM_ADD, (struct sockaddr *)&dst, (struct sockaddr *)&gw,
        (struct sockaddr *)&nm, RTF_GATEWAY, NULL, fib_num);
}

static int
ff_veth_setvaddr(struct ff_veth_softc *sc, struct ff_port_cfg *cfg, const char *if_name)
{
    struct in_aliasreq req;
    bzero(&req, sizeof req);

    if (if_name) {
        strlcpy(req.ifra_name, if_name, IFNAMSIZ);
    } else if (cfg->vip_ifname) {
        strlcpy(req.ifra_name, cfg->vip_ifname, IFNAMSIZ);
    } else {
        strlcpy(req.ifra_name, sc->ifp->if_dname, IFNAMSIZ);
    }

    struct sockaddr_in sa;
    bzero(&sa, sizeof(sa));
    sa.sin_len = sizeof(sa);
    sa.sin_family = AF_INET;

    int i, ret;
    struct socket *so = NULL;
    socreate(AF_INET, &so, SOCK_DGRAM, 0, curthread->td_ucred, curthread);

    for (i = 0; i < sc->nb_vip; ++i) {
        sa.sin_addr.s_addr = sc->vip[i];
        bcopy(&sa, &req.ifra_addr, sizeof(sa));

        // Only support '255.255.255.255' netmask now
        sa.sin_addr.s_addr = 0xFFFFFFFF;
        bcopy(&sa, &req.ifra_mask, sizeof(sa));

        // Only support 'x.x.x.x' broadaddr now
        sa.sin_addr.s_addr = sc->vip[i] /*| 0xFF000000*/;
        bcopy(&sa, &req.ifra_broadaddr, sizeof(sa));

        ret = ifioctl(so, SIOCAIFADDR, (caddr_t)&req, curthread);
        if (ret < 0) {
            printf("ff_veth_setvaddr ifioctl SIOCAIFADDR error\n");
            goto done;
        }
    }

done:
    soclose(so);

    return ret;
}

#ifdef FF_IPFW
/*
 * Only supports the simplest policy routing settings, like:
 * `ff_ipfw -P 0 add 100 setfib 0 ip from 125.94.59.0/24 to any out`
 * `from 125.94.59.0/24` need set addr is '125.94.59.0', netmask is '255.255.255.0'
 *
 * More policy routing settings should use tool `ff_ipfw`.
 */
static int
ff_ipfw_add_simple_v4(struct ff_port_cfg *port_cfg, struct ff_vlan_cfg *vlan_cfg, uint32_t fib_num)
{
    struct ff_ipfw_pr_cfg *pr_cfg;
    uint32_t nb_pr;
    int ret = -1, fd, i;
    int level = IPPROTO_IP, optname;
    uint32_t rulebuf[1024];
    socklen_t sz;
    ip_fw3_opheader *op3;
    ipfw_obj_ctlv *ctlv;
    struct ip_fw_rule *rule;
    ipfw_insn *cmd;
    ipfw_insn *action;
    ipfw_insn_ip *cmd_ip;
    int rule_len, ctlv_count = 1, cmd_count = 5, act_ofs = 4, cmd_ip_count = 3, action_count = 1;
    uint32_t rule_num;

    if (port_cfg) {
        pr_cfg = port_cfg->pr_cfg;
        nb_pr = port_cfg->nb_pr;
    } else if (vlan_cfg) {
        pr_cfg = vlan_cfg->pr_cfg;
        nb_pr = vlan_cfg->nb_pr;
    } else {
        return -1;
    }

    fd = ff_socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
        printf("ff_set_ipfw ff_socket error\n");
        goto done;
    }

    memset(rulebuf, 0, sizeof(rulebuf));
    /* Because `struct ip_fw_rule` has 1 cmd(`ipfw_insn`), so should (cmd_count - 1), and then routeup2 8 bytes */
    rule_len = sizeof(struct ip_fw_rule) + (cmd_count - 1) * sizeof(ipfw_insn);
    rule_len = roundup2(rule_len, sizeof(uint64_t));
    sz = sizeof(ip_fw3_opheader) + sizeof(ipfw_obj_ctlv) + rule_len;

    op3 = (ip_fw3_opheader *)rulebuf;
    op3->opcode = IP_FW_XADD;

    /*
     * {head = {type = 3, flags = 0, length = 56}, count = 1, objsize = 0, version = 0 '\000', flags = 0 '\000'}
     * type:IPFW_TLV_RULE_LIST(3), length:ctlv header length + rule total length
     */
    ctlv = (ipfw_obj_ctlv *)(op3 + 1);
    ctlv->head.type = IPFW_TLV_RULE_LIST;
    ctlv->head.length = sizeof(ipfw_obj_ctlv) + rule_len;
    ctlv->count = ctlv_count;
    //rule->rulenum = rule_num;
    rule = (struct ip_fw_rule *)(ctlv + 1);


    /* Need rule num(100/200/300/400), ip/mask,fib num(0/1/2/3/4) */
    /* $124 = {act_ofs = 4, cmd_len = 5, spare = 0, set = 0 '\000', flags = 0 '\000', rulenum = 200, id = 0, cmd = {{opcode = 2 '\002', len = 3 '\003', arg1 = 0}}}
     * act_ofs is 4 means jump four cmd, it's point to the first action's index,
     * cmd_len means total nums of cmd and action, per 4 bytes(sizeof(ipfw_insn)).
     */
    rule->act_ofs = act_ofs;
    rule->cmd_len = cmd_count;

    /*
     * cmd: 3 + 1
     * src IP:
        cmd[0] {opcode = 2 '\002', len = 3 '\003', arg1 = 0}
            opcode is 2(O_IP_SRC_MASK),
            len = 3 means three 4 bytes,

        [0] means cmd itself.
            (gdb) p *(ipfw_insn_ip *)cmd
            $61 = {o = {opcode = 2 '\002', len = 3 '\003', arg1 = 0}, addr = {s_addr = 373155}, mask = {s_addr = 16777215}}

        [1] means `IP & mask`'s' value.
        [2] means netmask, sucn as /24 is 0xffffff00
            (gdb) x/12x cmd
            0xe74860 <cmdbuf.7188>: 0x02    0x03    0x00    0x00    0xa3    0xb1    0x05    0x00
            0xe74868 <cmdbuf.7188+8>:       0xff    0xff    0xff    0x00
     *
     * out:
        cmd[3]
            i = 40 // TOK_OUT
            cmd->len ^= F_NOT;
                cmd->len = 128
            {opcode = 15 '\017', len = 129 '\201', arg1 = 0}
                opcode is 15(O_IN none),
                len=129 & 3f = 1, just jump one 4 bytes.
                    Although len is 129, but just have one header, no actual data.
     */
    cmd_ip = (ipfw_insn_ip *)((ipfw_insn *)(rule + 1) - 1);
    cmd_ip->o.opcode = O_IP_SRC_MASK;
    cmd_ip->o.len = cmd_ip_count;
    //inet_pton(AF_INET, addr, (void *)&(cmd_ip->addr));
    //inet_pton(AF_INET, netmask, (void *)&(cmd_ip->mask));

    cmd = (ipfw_insn *)(cmd_ip + 1);
    cmd->opcode = O_IN;
    cmd->len ^= F_NOT;
    cmd->len =  ((cmd->len | 0) & (F_NOT | F_OR)) | 1; // flags = 0

    /*
     * action:1
     * setfib 0: // action[0]
        i = TOK_SETFIB	// 120
        action->len = 1;
        action->opcode = O_SETFIB; // 82
        action->arg1 = strtoul(*av, NULL, 10); // fib num: 0、1、2、3
        action->arg1 |= 0x8000;  // 32768 + fib num

        (gdb) p *action
        $34 = {opcode = 82 'R', len = 1 '\001', arg1 = 32769}

        (gdb) x/4b actbuf
        0xe74460 <actbuf.7187>: 0x52    0x01    0x01    0x80
     */
    action = (ipfw_insn *)(cmd + 1);
    action->opcode = O_SETFIB;
    action->len = action_count;
    //action->arg1 = fib_num;
    //action->arg1 |= 0x8000;

    for (i = 0; i < nb_pr; i++) {
        rule_num = (fib_num + 1) * 10;
        rule->rulenum = rule_num;
        inet_pton(AF_INET, pr_cfg[i].addr, (void *)&(cmd_ip->addr));
        inet_pton(AF_INET, pr_cfg[i].netmask, (void *)&(cmd_ip->mask));
        action->arg1 = fib_num;
        action->arg1 |= 0x8000;

        ret = ff_getsockopt(fd, IPPROTO_IP, IP_FW3, (void *)op3, (socklen_t *)&sz);
        if (ret < 0) {
            printf("ff_set_ipfw kern_getsockopt error\n");
            goto done;
        }
    }

done:
    if (fd > 0) {
        ff_close(fd);
    }

    return ret;
}
#endif

#ifdef INET6
static int
ff_veth_setaddr6(struct ff_veth_softc *sc, const char *if_name)
{
    struct in6_aliasreq ifr6;
    bzero(&ifr6, sizeof(ifr6));

    if (if_name) {
        strcpy(ifr6.ifra_name, if_name);
    } else {
        strcpy(ifr6.ifra_name, sc->ifp->if_dname);
    }

    ifr6.ifra_addr.sin6_len = sizeof ifr6.ifra_addr;
    ifr6.ifra_addr.sin6_family = AF_INET6;
    ifr6.ifra_addr.sin6_addr = sc->ip6;

    ifr6.ifra_prefixmask.sin6_len = sizeof ifr6.ifra_prefixmask;
    memset(&ifr6.ifra_prefixmask.sin6_addr, 0xff, sc->prefix_length / 8);
    uint8_t mask_size_mod = sc->prefix_length % 8;
    if (mask_size_mod)
    {
        ifr6.ifra_prefixmask.sin6_addr.__u6_addr.__u6_addr8[sc->prefix_length / 8] = \
            ((1 << mask_size_mod) - 1) << (8 - mask_size_mod);
    }

    ifr6.ifra_lifetime.ia6t_pltime = ifr6.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;

    ifr6.ifra_flags |= IN6_IFF_AUTOCONF;

    struct socket *so = NULL;
    socreate(AF_INET6, &so, SOCK_DGRAM, 0, curthread->td_ucred, curthread);
    int ret = ifioctl(so, SIOCAIFADDR_IN6, (caddr_t)&ifr6, curthread);

    soclose(so);

    return ret;
}

static int
ff_veth_set_gateway6(struct ff_veth_softc *sc, uint32_t fib_num)
{
    struct sockaddr_in6 gw, dst, nm;

    bzero(&gw, sizeof(gw));
    bzero(&dst, sizeof(dst));
    bzero(&nm, sizeof(nm));

    gw.sin6_len = dst.sin6_len = nm.sin6_len = sizeof(struct sockaddr_in6);
    gw.sin6_family = dst.sin6_family = AF_INET6;

    gw.sin6_addr = sc->gateway6;
    //dst.sin6_addr = nm.sin6_addr = 0;

    return rtrequest_fib(RTM_ADD, (struct sockaddr *)&dst, (struct sockaddr *)&gw,
        (struct sockaddr *)&nm, RTF_GATEWAY, NULL, fib_num);
}

static int
ff_veth_setvaddr6(struct ff_veth_softc *sc, struct ff_port_cfg *cfg, const char *if_name)
{
    struct in6_aliasreq ifr6;
    bzero(&ifr6, sizeof(ifr6));

    if (if_name) {
        strlcpy(ifr6.ifra_name, if_name, IFNAMSIZ);
    } else if (cfg->vip_ifname) {
        strlcpy(ifr6.ifra_name, cfg->vip_ifname, IFNAMSIZ);
    } else {
        strlcpy(ifr6.ifra_name, sc->ifp->if_dname, IFNAMSIZ);
    }

    ifr6.ifra_addr.sin6_len = sizeof ifr6.ifra_addr;
    ifr6.ifra_addr.sin6_family = AF_INET6;

    ifr6.ifra_prefixmask.sin6_len = sizeof ifr6.ifra_prefixmask;
    memset(&ifr6.ifra_prefixmask.sin6_addr, 0xff, sc->prefix_length / 8);
    uint8_t mask_size_mod = sc->prefix_length % 8;
    if (mask_size_mod)
    {
        ifr6.ifra_prefixmask.sin6_addr.__u6_addr.__u6_addr8[sc->prefix_length / 8] = \
            ((1 << mask_size_mod) - 1) << (8 - mask_size_mod);
    }

    ifr6.ifra_lifetime.ia6t_pltime = ifr6.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;

    ifr6.ifra_flags |= IN6_IFF_AUTOCONF;

    struct socket *so = NULL;
    socreate(AF_INET6, &so, SOCK_DGRAM, 0, curthread->td_ucred, curthread);

    int i, ret;
    for (i = 0; i < sc->nb_vip6; ++i) {
        ifr6.ifra_addr.sin6_addr = sc->vip6[i];

        ret = ifioctl(so, SIOCAIFADDR_IN6, (caddr_t)&ifr6, curthread);
        if (ret < 0) {
            printf("ff_veth_setvaddr6 ifioctl SIOCAIFADDR error\n");
            goto done;
        }
    }

done:
    soclose(so);

    return ret;
}
#endif /* INET6 */

static int
ff_veth_setup_interface(struct ff_veth_softc *sc, struct ff_port_cfg *cfg)
{
    struct ifnet *ifp;
    int ret;
    uint32_t fib_num = RT_DEFAULT_FIB;

    ifp = sc->ifp = if_alloc(IFT_ETHER);

    ifp->if_init = ff_veth_init;
    ifp->if_softc = sc;

    if_initname(ifp, sc->host_ifname, IF_DUNIT_NONE);
    ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
    ifp->if_ioctl = ff_veth_ioctl;
    ifp->if_start = ff_veth_start;
    ifp->if_transmit = ff_veth_transmit;
    ifp->if_qflush = ff_veth_qflush;
    ether_ifattach(ifp, sc->mac);

    if (cfg->hw_features.rx_csum) {
        ifp->if_capabilities |= IFCAP_RXCSUM;
    }
    if (cfg->hw_features.tx_csum_ip) {
        ifp->if_capabilities |= IFCAP_TXCSUM;
        ifp->if_hwassist |= CSUM_IP;
    }
    if (cfg->hw_features.tx_csum_l4) {
        ifp->if_hwassist |= CSUM_DELAY_DATA;
    }
    if (cfg->hw_features.tx_tso) {
        ifp->if_capabilities |= IFCAP_TSO;
        ifp->if_hwassist |= CSUM_TSO;
    }

    ifp->if_capenable = ifp->if_capabilities;

    sc->host_ctx = ff_dpdk_register_if((void *)sc, (void *)sc->ifp, cfg);
    if (sc->host_ctx == NULL) {
        printf("%s: Failed to register dpdk interface\n", sc->host_ifname);
        return -1;
    } else {
        printf("%s: Successed to register dpdk interface\n", sc->host_ifname);
    }

    /* if vlan_flag is true, all port's addrs/vips will not to set, just create the iface */
    if (cfg->nb_vlan == 0) {
        // Set IP
        ret = ff_veth_setaddr(sc, NULL);
        if (ret != 0) {
            printf("%s: ff_veth_setaddr failed\n", sc->host_ifname);
        }

        fib_num = cfg->port_id;
        ret = ff_veth_set_gateway(sc, fib_num);
        if (ret != 0) {
            printf("%s: ff_veth_set_gateway failed\n", sc->host_ifname);
        }

        if (sc->nb_vip) {
            ret = ff_veth_setvaddr(sc, cfg, NULL);
        }

#ifdef FF_IPFW
        if (cfg->nb_pr) {
            ff_ipfw_add_simple_v4(cfg, NULL, fib_num);
        }
#endif

#ifdef INET6
        // Set IPv6
        if (cfg->addr6_str) {
            ret = ff_veth_setaddr6(sc, NULL);
            if (ret != 0) {
                printf("%s: ff_veth_setaddr6 failed\n", sc->host_ifname);
            }

            if (cfg->gateway6_str) {
                /*
                 * IPv6 not support set multi route fib now, just use RT_DEFAULT_FIB.
                 * And you can set multi fib use tool 'ff_route' a
                 */
                fib_num = RT_DEFAULT_FIB;
                ret = ff_veth_set_gateway6(sc, fib_num);
                if (ret != 0) {
                    printf("%s: ff_veth_set_gateway6 failed\n", sc->host_ifname);
                }
            }
        }

        if (sc->nb_vip6) {
            ret = ff_veth_setvaddr6(sc, cfg, NULL);
        }
#endif /* INET6 */
    }else {
        char vlan_if_name[IFNAMSIZ];
        int idx;
        struct ff_vlan_cfg *vlan_cfg;
        struct ff_veth_softc vlan_sc;

        ff_veth_init(sc);

        for (idx = 0; idx < cfg->nb_vlan; idx++) {
            /* create vlan interface */
            vlan_cfg = cfg->vlan_cfgs[idx];
            snprintf(vlan_if_name, IFNAMSIZ, "%s.%d", sc->host_ifname, vlan_cfg->vlan_id);
            ret = if_clone_create(vlan_if_name, IFNAMSIZ, NULL);
            if (0 != ret) {
                printf("%s: Failed to if_clone_create vlan interface\n", vlan_if_name);
                return -1;
            } else {
                printf("%s: Successed to if_clone_create vlan interface\n", vlan_if_name);
            }

            // Set vlan IP
            memset(&vlan_sc, 0, sizeof(vlan_sc));
            ret = ff_veth_vlan_config(&vlan_sc, vlan_cfg);
            if (0 != ret) {
                printf("%s: Failed to ff_veth_vlan_config\n", vlan_if_name);
                return -1;
            }

            ret = ff_veth_setaddr(&vlan_sc, vlan_if_name);
            if (ret != 0) {
                printf("%s: ff_veth_setaddr failed\n", vlan_if_name);
            }

            fib_num = vlan_cfg->vlan_idx;
            ret = ff_veth_set_gateway(&vlan_sc, fib_num);
            if (ret != 0) {
                printf("%s: ff_veth_set_gateway of fib %u failed\n", vlan_if_name, fib_num);
            }

            if (vlan_sc.nb_vip) {
                ret = ff_veth_setvaddr(&vlan_sc, cfg, vlan_if_name);
            }

#ifdef FF_IPFW
            if (vlan_cfg->nb_pr) {
                ff_ipfw_add_simple_v4(NULL, vlan_cfg, fib_num);
            }
#endif

#ifdef INET6
            // Set vlan IPv6
            if (vlan_cfg->addr6_str) {
                ret = ff_veth_setaddr6(&vlan_sc, vlan_if_name);
                if (ret != 0) {
                    printf("%s: ff_veth_setaddr6 failed\n", vlan_if_name);
                }

                if (vlan_cfg->gateway6_str) {
                    /*
                     * IPv6 not support set multi route fib now, just use RT_DEFAULT_FIB.
                     * And you can set multi fib use tool 'ff_route' a
                     */
                    fib_num = RT_DEFAULT_FIB;
                    ret = ff_veth_set_gateway6(&vlan_sc, fib_num);
                    if (ret != 0) {
                        printf("%s: ff_veth_set_gateway6 of fib %u failed\n", vlan_if_name, fib_num);
                    }
                }
            }

            if (vlan_sc.nb_vip6) {
                ret = ff_veth_setvaddr6(&vlan_sc, cfg, vlan_if_name);
            }
#endif /* INET6 */
        }
    }

    return (0);
}

void *
ff_veth_attach(struct ff_port_cfg *cfg)
{
    struct ff_veth_softc *sc = NULL;
    int error;

    sc = malloc(sizeof(struct ff_veth_softc), M_DEVBUF, M_WAITOK);
    if (NULL == sc) {
        printf("ff_veth_softc allocation failed\n");
        goto fail;
    }
    memset(sc, 0, sizeof(struct ff_veth_softc));

    if(cfg->ifname){
        snprintf(sc->host_ifname, sizeof(sc->host_ifname), "%s", cfg->ifname);
    } else {
        snprintf(sc->host_ifname, sizeof(sc->host_ifname), ff_IF_NAME, cfg->port_id);
    }

    error = ff_veth_config(sc, cfg);
    if (0 != error) {
        goto fail;
    }

    if (0 != ff_veth_setup_interface(sc, cfg)) {
        goto fail;
    }

    return sc->host_ctx;

fail:
    if (sc) {
        if (sc->host_ctx)
            ff_dpdk_deregister_if(sc->host_ctx);

        free(sc, M_DEVBUF);
    }

    return NULL;
}

int
ff_veth_detach(void *arg)
{
    struct ff_veth_softc *sc = (struct ff_veth_softc *)arg;
    if (sc) {
        ff_dpdk_deregister_if(sc->host_ctx);
        free(sc, M_DEVBUF);
    }

    return (0);
}

void *
ff_veth_softc_to_hostc(void *softc)
{
    struct ff_veth_softc *sc = (struct ff_veth_softc *)softc;
    return (void *)sc->host_ctx;
}

void *
ff_veth_get_softc(void *host_ctx)
{
    struct ff_veth_softc *sc = NULL;

    sc = malloc(sizeof(struct ff_veth_softc), M_DEVBUF, M_WAITOK);
    if (NULL == sc) {
        printf("ff_veth_softc allocation failed\n");
        return NULL;
    }
    memset(sc, 0, sizeof(struct ff_veth_softc));

    sc->host_ctx = host_ctx;

    return sc;
}

void
ff_veth_free_softc(void *softc)
{
    if (softc)
        free(softc, M_DEVBUF);
}

/********************
*  get next mbuf's addr, current mbuf's data and datalen.
*
********************/
int ff_next_mbuf(void **mbuf_bsd, void **data, unsigned *len)
{
    struct mbuf *mb = *(struct mbuf **)mbuf_bsd;

    *len = mb->m_len;
    *data = mb->m_data;

    if (mb->m_next)
        *mbuf_bsd = mb->m_next;
    else
        *mbuf_bsd = NULL;
    return 0;
}

void * ff_mbuf_mtod(void* bsd_mbuf)
{
    if ( !bsd_mbuf )
        return NULL;
    return (void*)((struct mbuf *)bsd_mbuf)->m_data;
}

// get source rte_mbuf from ext cluster, which carry rte_mbuf while recving pkt, such as arp.
void* ff_rte_frm_extcl(void* mbuf)
{
    struct mbuf *bsd_mbuf = mbuf;

    if ( (bsd_mbuf->m_flags & M_EXT) &&
        bsd_mbuf->m_ext.ext_type == EXT_DISPOSABLE && bsd_mbuf->m_ext.ext_free == ff_mbuf_ext_free ) {
        return bsd_mbuf->m_ext.ext_arg1;
    }
    else
        return NULL;
}

void
ff_mbuf_set_vlan_info(void *hdr, uint16_t vlan_tci) {
    struct mbuf *m = (struct mbuf *)hdr;
    m->m_pkthdr.ether_vtag = vlan_tci;
    m->m_flags |= M_VLANTAG;
    return;
}

