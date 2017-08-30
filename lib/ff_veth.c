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

#include <netinet/in.h>
#include <netinet/in_var.h>

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

    struct ff_dpdk_if_context *host_ctx;
};

static int
ff_veth_config(struct ff_veth_softc *sc, struct ff_port_cfg *cfg)
{
    memcpy(sc->mac, cfg->mac, ETHER_ADDR_LEN);
    inet_pton(AF_INET, cfg->addr, &sc->ip);
    inet_pton(AF_INET, cfg->netmask, &sc->netmask);
    inet_pton(AF_INET, cfg->broadcast, &sc->broadcast);
    inet_pton(AF_INET, cfg->gateway, &sc->gateway);

    return 0;
}

static void
ff_veth_init(void *arg)
{
    struct ff_veth_softc *sc = arg;
    struct ifnet *ifp = sc->ifp;

    ifp->if_drv_flags |= IFF_DRV_RUNNING;
    ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
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
ff_mbuf_get(void *m, void *data, uint16_t len)
{
    struct mbuf *prev = (struct mbuf *)m;
    struct mbuf *mb = m_get(M_NOWAIT, MT_DATA);

    if (mb == NULL) {
        return NULL; 
    }

    m_extadd(mb, data, len, NULL, NULL, NULL, 0, 0);

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
ff_veth_setaddr(struct ff_veth_softc *sc)
{
    struct in_aliasreq req;
    bzero(&req, sizeof req);
    strcpy(req.ifra_name, sc->ifp->if_dname);

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

    sofree(so);

    return ret;
}

static int
ff_veth_set_gateway(struct ff_veth_softc *sc)
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
        (struct sockaddr *)&nm, RTF_GATEWAY, NULL, RT_DEFAULT_FIB);
}

static int
ff_veth_setup_interface(struct ff_veth_softc *sc, struct ff_port_cfg *cfg)
{
    struct ifnet *ifp;

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
    }

    //set ip
    int ret = ff_veth_setaddr(sc);
    if (ret != 0) {
        printf("ff_veth_setaddr failed\n");
    }
    ret = ff_veth_set_gateway(sc);
    if (ret != 0) {
        printf("ff_veth_set_gateway failed\n");
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
        printf("%s: ff_veth_softc allocation failed\n", sc->host_ifname);
        goto fail;
    }
    memset(sc, 0, sizeof(struct ff_veth_softc));

    snprintf(sc->host_ifname, sizeof(sc->host_ifname), ff_IF_NAME, cfg->port_id);

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

