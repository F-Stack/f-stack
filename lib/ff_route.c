/*
 * Copyright (c) 1988, 1991, 1993
 *  The Regents of the University of California.  All rights reserved.
 * Copyright (C) 2017 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Copied part from FreeBSD rtsock.c.
 *
 */

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/domain.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/if_llatbl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/route_var.h>
#include <netinet/if_ether.h>

#include "ff_api.h"
#include "ff_host_interface.h"

#ifndef _SOCKADDR_UNION_DEFINED
#define _SOCKADDR_UNION_DEFINED
/*
 * The union of all possible address formats we handle.
 */
union sockaddr_union {
    struct sockaddr     sa;
    struct sockaddr_in  sin;
    struct sockaddr_in6 sin6;
};
#endif /* _SOCKADDR_UNION_DEFINED */

static struct sockaddr sa_zero = { sizeof(sa_zero), AF_INET, };

struct walkarg {
    int w_tmemsize;
    int w_op, w_arg;
    caddr_t w_tmem;
    struct sysctl_req *w_req;
};

static int
rtm_get_jailed(struct rt_addrinfo *info, struct ifnet *ifp,
    struct rtentry *rt, union sockaddr_union *saun, struct ucred *cred)
{

    /* First, see if the returned address is part of the jail. */
    if (prison_if(cred, rt->rt_ifa->ifa_addr) == 0) {
        info->rti_info[RTAX_IFA] = rt->rt_ifa->ifa_addr;
        return (0);
    }

    switch (info->rti_info[RTAX_DST]->sa_family) {
#ifdef INET
    case AF_INET:
    {
        struct in_addr ia;
        struct ifaddr *ifa;
        int found;

        found = 0;
        /*
         * Try to find an address on the given outgoing interface
         * that belongs to the jail.
         */
        IF_ADDR_RLOCK(ifp);
        TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
            struct sockaddr *sa;
            sa = ifa->ifa_addr;
            if (sa->sa_family != AF_INET)
                continue;
            ia = ((struct sockaddr_in *)sa)->sin_addr;
            if (prison_check_ip4(cred, &ia) == 0) {
                found = 1;
                break;
            }
        }
        IF_ADDR_RUNLOCK(ifp);
        if (!found) {
            /*
             * As a last resort return the 'default' jail address.
             */
            ia = ((struct sockaddr_in *)rt->rt_ifa->ifa_addr)->
                sin_addr;
            if (prison_get_ip4(cred, &ia) != 0)
                return (ESRCH);
        }
        bzero(&saun->sin, sizeof(struct sockaddr_in));
        saun->sin.sin_len = sizeof(struct sockaddr_in);
        saun->sin.sin_family = AF_INET;
        saun->sin.sin_addr.s_addr = ia.s_addr;
        info->rti_info[RTAX_IFA] = (struct sockaddr *)&saun->sin;
        break;
    }
#endif
#ifdef INET6
    case AF_INET6:
    {
        struct in6_addr ia6;
        struct ifaddr *ifa;
        int found;

        found = 0;
        /*
         * Try to find an address on the given outgoing interface
         * that belongs to the jail.
         */
        IF_ADDR_RLOCK(ifp);
        TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
            struct sockaddr *sa;
            sa = ifa->ifa_addr;
            if (sa->sa_family != AF_INET6)
                continue;
            bcopy(&((struct sockaddr_in6 *)sa)->sin6_addr,
                &ia6, sizeof(struct in6_addr));
            if (prison_check_ip6(cred, &ia6) == 0) {
                found = 1;
                break;
            }
        }
        IF_ADDR_RUNLOCK(ifp);
        if (!found) {
            /*
             * As a last resort return the 'default' jail address.
             */
            ia6 = ((struct sockaddr_in6 *)rt->rt_ifa->ifa_addr)->
                sin6_addr;
            if (prison_get_ip6(cred, &ia6) != 0)
                return (ESRCH);
        }
        bzero(&saun->sin6, sizeof(struct sockaddr_in6));
        saun->sin6.sin6_len = sizeof(struct sockaddr_in6);
        saun->sin6.sin6_family = AF_INET6;
        bcopy(&ia6, &saun->sin6.sin6_addr, sizeof(struct in6_addr));
        if (sa6_recoverscope(&saun->sin6) != 0)
            return (ESRCH);
        info->rti_info[RTAX_IFA] = (struct sockaddr *)&saun->sin6;
        break;
    }
#endif
    default:
        return (ESRCH);
    }
    return (0);
}

/*
 * Extract the addresses of the passed sockaddrs.
 * Do a little sanity checking so as to avoid bad memory references.
 * This data is derived straight from userland.
 */
static int
rt_xaddrs(caddr_t cp, caddr_t cplim, struct rt_addrinfo *rtinfo)
{
    struct sockaddr *sa;
    int i;

    for (i = 0; i < RTAX_MAX && cp < cplim; i++) {
        if ((rtinfo->rti_addrs & (1 << i)) == 0)
            continue;
        sa = (struct sockaddr *)cp;
        /*
         * It won't fit.
         */
        if (cp + sa->sa_len > cplim)
            return (EINVAL);
        /*
         * there are no more.. quit now
         * If there are more bits, they are in error.
         * I've seen this. route(1) can evidently generate these. 
         * This causes kernel to core dump.
         * for compatibility, If we see this, point to a safe address.
         */
        if (sa->sa_len == 0) {
            rtinfo->rti_info[i] = &sa_zero;
            return (0); /* should be EINVAL but for compat */
        }
        /* accept it */
#ifdef INET6
        if (sa->sa_family == AF_INET6)
            sa6_embedscope((struct sockaddr_in6 *)sa,
                V_ip6_use_defzone);
#endif
        rtinfo->rti_info[i] = sa;
        cp += SA_SIZE(sa);
    }
    return (0);
}

/*
 * Writes information related to @rtinfo object to preallocated buffer.
 * Stores needed size in @plen. If @w is NULL, calculates size without
 * writing.
 * Used for sysctl dumps and rtsock answers (RTM_DEL/RTM_GET) generation.
 *
 * Returns 0 on success.
 *
 */
static int
rtsock_msg_buffer(int type, struct rt_addrinfo *rtinfo, struct walkarg *w, int *plen)
{
    int i;
    int len, buflen = 0, dlen;
    caddr_t cp = NULL;
    struct rt_msghdr *rtm = NULL;
#ifdef INET6
    struct sockaddr_storage ss;
    struct sockaddr_in6 *sin6;
#endif

    switch (type) {

    case RTM_DELADDR:
    case RTM_NEWADDR:
        if (w != NULL && w->w_op == NET_RT_IFLISTL) {
#ifdef COMPAT_FREEBSD32
            if (w->w_req->flags & SCTL_MASK32)
                len = sizeof(struct ifa_msghdrl32);
            else
#endif
                len = sizeof(struct ifa_msghdrl);
        } else
            len = sizeof(struct ifa_msghdr);
        break;

    case RTM_IFINFO:
#ifdef COMPAT_FREEBSD32
        if (w != NULL && w->w_req->flags & SCTL_MASK32) {
            if (w->w_op == NET_RT_IFLISTL)
                len = sizeof(struct if_msghdrl32);
            else
                len = sizeof(struct if_msghdr32);
            break;
        }
#endif
        if (w != NULL && w->w_op == NET_RT_IFLISTL)
            len = sizeof(struct if_msghdrl);
        else
            len = sizeof(struct if_msghdr);
        break;

    case RTM_NEWMADDR:
        len = sizeof(struct ifma_msghdr);
        break;

    default:
        len = sizeof(struct rt_msghdr);
    }

    if (w != NULL) {
        rtm = (struct rt_msghdr *)w->w_tmem;
        buflen = w->w_tmemsize - len;
        cp = (caddr_t)w->w_tmem + len;
    }

    rtinfo->rti_addrs = 0;
    for (i = 0; i < RTAX_MAX; i++) {
        struct sockaddr *sa;

        if ((sa = rtinfo->rti_info[i]) == NULL)
            continue;
        rtinfo->rti_addrs |= (1 << i);
        dlen = SA_SIZE(sa);
        if (cp != NULL && buflen >= dlen) {
#ifdef INET6
            if (V_deembed_scopeid && sa->sa_family == AF_INET6) {
                sin6 = (struct sockaddr_in6 *)&ss;
                bcopy(sa, sin6, sizeof(*sin6));
                if (sa6_recoverscope(sin6) == 0)
                    sa = (struct sockaddr *)sin6;
            }
#endif
            bcopy((caddr_t)sa, cp, (unsigned)dlen);
            cp += dlen;
            buflen -= dlen;
        } else if (cp != NULL) {
            /*
             * Buffer too small. Count needed size
             * and return with error.
             */
            cp = NULL;
        }

        len += dlen;
    }

    if (cp != NULL) {
        dlen = ALIGN(len) - len;
        if (buflen < dlen)
            cp = NULL;
        else
            buflen -= dlen;
    }
    len = ALIGN(len);

    if (cp != NULL) {
        /* fill header iff buffer is large enough */
        rtm->rtm_version = RTM_VERSION;
        rtm->rtm_type = type;
        rtm->rtm_msglen = len;
    }

    *plen = len;

    if (w != NULL && cp == NULL)
        return (ENOBUFS);

    return (0);
}

/*
 * Fill in @dmask with valid netmask leaving original @smask
 * intact. Mostly used with radix netmasks.
 */
static struct sockaddr *
rtsock_fix_netmask(struct sockaddr *dst, struct sockaddr *smask,
    struct sockaddr_storage *dmask)
{
    if (dst == NULL || smask == NULL)
        return (NULL);

    memset(dmask, 0, dst->sa_len);
    memcpy(dmask, smask, smask->sa_len);
    dmask->ss_len = dst->sa_len;
    dmask->ss_family = dst->sa_family;

    return ((struct sockaddr *)dmask);
}

static void
rt_getmetrics(const struct rtentry *rt, struct rt_metrics *out)
{

    bzero(out, sizeof(*out));
    out->rmx_mtu = rt->rt_mtu;
    out->rmx_weight = rt->rt_weight;
    out->rmx_pksent = counter_u64_fetch(rt->rt_pksent);
    /* Kernel -> userland timebase conversion. */
    out->rmx_expire = rt->rt_expire ?
        rt->rt_expire - time_uptime + time_second : 0;
}

int
ff_rtioctl(int fibnum, void *data, unsigned *plen, unsigned maxlen)
{
    struct rt_msghdr *rtm = NULL;
    struct rtentry *rt = NULL;
    struct rib_head *rnh;
    struct rt_addrinfo info;
    union sockaddr_union saun;
    sa_family_t saf = AF_UNSPEC;
    struct sockaddr_storage ss;
    struct walkarg w;
    int error = 0, alloc_len = 0, len;
    struct ifnet *ifp = NULL;

#ifdef INET6
    struct sockaddr_in6 *sin6;
    int i, rti_need_deembed = 0;
#endif

#define senderr(e) { error = e; goto flush;}

    len = *plen;
    /*
     * Most of current messages are in range 200-240 bytes,
     * minimize possible re-allocation on reply using larger size
     * buffer aligned on 1k boundaty.
     */
    alloc_len = roundup2(len, 1024);
    if ((rtm = malloc(alloc_len, M_TEMP, M_NOWAIT)) == NULL)
        senderr(ENOBUFS);
    bcopy(data, (caddr_t)rtm, len);

    if (len < sizeof(*rtm) || len != rtm->rtm_msglen)
        senderr(EINVAL);

    bzero(&info, sizeof(info));
    bzero(&w, sizeof(w));

    if (rtm->rtm_version != RTM_VERSION)
        senderr(EPROTONOSUPPORT);

    /*
     * Starting from here, it is possible
     * to alter original message and insert
     * caller PID and error value.
     */

    rtm->rtm_pid = curproc->p_pid;
    info.rti_addrs = rtm->rtm_addrs;

    info.rti_mflags = rtm->rtm_inits;
    info.rti_rmx = &rtm->rtm_rmx;

    /*
     * rt_xaddrs() performs s6_addr[2] := sin6_scope_id for AF_INET6
     * link-local address because rtrequest requires addresses with
     * embedded scope id.
     */
    if (rt_xaddrs((caddr_t)(rtm + 1), len + (caddr_t)rtm, &info))
        senderr(EINVAL);

    info.rti_flags = rtm->rtm_flags;
    if (info.rti_info[RTAX_DST] == NULL ||
        info.rti_info[RTAX_DST]->sa_family >= AF_MAX ||
        (info.rti_info[RTAX_GATEWAY] != NULL &&
         info.rti_info[RTAX_GATEWAY]->sa_family >= AF_MAX))
        senderr(EINVAL);
    saf = info.rti_info[RTAX_DST]->sa_family;

    /*
     * The given gateway address may be an interface address.
     * For example, issuing a "route change" command on a route
     * entry that was created from a tunnel, and the gateway
     * address given is the local end point. In this case the 
     * RTF_GATEWAY flag must be cleared or the destination will
     * not be reachable even though there is no error message.
     */
    if (info.rti_info[RTAX_GATEWAY] != NULL &&
        info.rti_info[RTAX_GATEWAY]->sa_family != AF_LINK) {
        struct rt_addrinfo ginfo;
        struct sockaddr *gdst;

        bzero(&ginfo, sizeof(ginfo));
        bzero(&ss, sizeof(ss));
        ss.ss_len = sizeof(ss);

        ginfo.rti_info[RTAX_GATEWAY] = (struct sockaddr *)&ss;
        gdst = info.rti_info[RTAX_GATEWAY];

        /* 
         * A host route through the loopback interface is 
         * installed for each interface adddress. In pre 8.0
         * releases the interface address of a PPP link type
         * is not reachable locally. This behavior is fixed as 
         * part of the new L2/L3 redesign and rewrite work. The
         * signature of this interface address route is the
         * AF_LINK sa_family type of the rt_gateway, and the
         * rt_ifp has the IFF_LOOPBACK flag set.
         */
        if (rib_lookup_info(fibnum, gdst, NHR_REF, 0, &ginfo) == 0) {
            if (ss.ss_family == AF_LINK &&
                ginfo.rti_ifp->if_flags & IFF_LOOPBACK) {
                info.rti_flags &= ~RTF_GATEWAY;
                info.rti_flags |= RTF_GWFLAG_COMPAT;
            }
            rib_free_info(&ginfo);
        }
    }

    switch (rtm->rtm_type) {
        struct rtentry *saved_nrt;

    case RTM_ADD:
    case RTM_CHANGE:
        if (info.rti_info[RTAX_GATEWAY] == NULL)
            senderr(EINVAL);
        saved_nrt = NULL;

        /* support for new ARP code */
        if (info.rti_info[RTAX_GATEWAY]->sa_family == AF_LINK &&
            (rtm->rtm_flags & RTF_LLDATA) != 0) {
            error = lla_rt_output(rtm, &info);
#ifdef INET6
            if (error == 0)
                rti_need_deembed = (V_deembed_scopeid) ? 1 : 0;
#endif
            break;
        }
        error = rtrequest1_fib(rtm->rtm_type, &info, &saved_nrt,
            fibnum);
        if (error == 0 && saved_nrt != NULL) {
#ifdef INET6
            rti_need_deembed = (V_deembed_scopeid) ? 1 : 0;
#endif
            RT_LOCK(saved_nrt);
            rtm->rtm_index = saved_nrt->rt_ifp->if_index;
            RT_REMREF(saved_nrt);
            RT_UNLOCK(saved_nrt);
        }
        break;

    case RTM_DELETE:
        saved_nrt = NULL;
        /* support for new ARP code */
        if (info.rti_info[RTAX_GATEWAY] && 
            (info.rti_info[RTAX_GATEWAY]->sa_family == AF_LINK) &&
            (rtm->rtm_flags & RTF_LLDATA) != 0) {
            error = lla_rt_output(rtm, &info);
#ifdef INET6
            if (error == 0)
                rti_need_deembed = (V_deembed_scopeid) ? 1 : 0;
#endif
            break;
        }
        error = rtrequest1_fib(RTM_DELETE, &info, &saved_nrt, fibnum);
        if (error == 0) {
            RT_LOCK(saved_nrt);
            rt = saved_nrt;
            goto report;
        }
#ifdef INET6
        /* rt_msg2() will not be used when RTM_DELETE fails. */
        rti_need_deembed = (V_deembed_scopeid) ? 1 : 0;
#endif
        break;

    case RTM_GET:
        rnh = rt_tables_get_rnh(fibnum, saf);
        if (rnh == NULL)
            senderr(EAFNOSUPPORT);

        RIB_RLOCK(rnh);

        if (info.rti_info[RTAX_NETMASK] == NULL &&
            rtm->rtm_type == RTM_GET) {
            /*
             * Provide logest prefix match for
             * address lookup (no mask).
             * 'route -n get addr'
             */
            rt = (struct rtentry *) rnh->rnh_matchaddr(
                info.rti_info[RTAX_DST], &rnh->head);
        } else
            rt = (struct rtentry *) rnh->rnh_lookup(
                info.rti_info[RTAX_DST],
                info.rti_info[RTAX_NETMASK], &rnh->head);

        if (rt == NULL) {
            RIB_RUNLOCK(rnh);
            senderr(ESRCH);
        }
#ifdef RADIX_MPATH
        /*
         * for RTM_CHANGE/LOCK, if we got multipath routes,
         * we require users to specify a matching RTAX_GATEWAY.
         *
         * for RTM_GET, gate is optional even with multipath.
         * if gate == NULL the first match is returned.
         * (no need to call rt_mpath_matchgate if gate == NULL)
         */
        if (rt_mpath_capable(rnh) &&
            (rtm->rtm_type != RTM_GET || info.rti_info[RTAX_GATEWAY])) {
            rt = rt_mpath_matchgate(rt, info.rti_info[RTAX_GATEWAY]);
            if (!rt) {
                RIB_RUNLOCK(rnh);
                senderr(ESRCH);
            }
        }
#endif
        /*
         * If performing proxied L2 entry insertion, and
         * the actual PPP host entry is found, perform
         * another search to retrieve the prefix route of
         * the local end point of the PPP link.
         */
        if (rtm->rtm_flags & RTF_ANNOUNCE) {
            struct sockaddr laddr;

            if (rt->rt_ifp != NULL && 
                rt->rt_ifp->if_type == IFT_PROPVIRTUAL) {
                struct ifaddr *ifa;

                ifa = ifa_ifwithnet(info.rti_info[RTAX_DST], 1,
                        RT_ALL_FIBS);
                if (ifa != NULL)
                    rt_maskedcopy(ifa->ifa_addr,
                              &laddr,
                              ifa->ifa_netmask);
            } else
                rt_maskedcopy(rt->rt_ifa->ifa_addr,
                          &laddr,
                          rt->rt_ifa->ifa_netmask);
            /* 
             * refactor rt and no lock operation necessary
             */
            rt = (struct rtentry *)rnh->rnh_matchaddr(&laddr,
                &rnh->head);
            if (rt == NULL) {
                RIB_RUNLOCK(rnh);
                senderr(ESRCH);
            }
        } 
        RT_LOCK(rt);
        RT_ADDREF(rt);
        RIB_RUNLOCK(rnh);

report:
        RT_LOCK_ASSERT(rt);
        if ((rt->rt_flags & RTF_HOST) == 0
            ? jailed_without_vnet(curthread->td_ucred)
            : prison_if(curthread->td_ucred,
            rt_key(rt)) != 0) {
            RT_UNLOCK(rt);
            senderr(ESRCH);
        }
        info.rti_info[RTAX_DST] = rt_key(rt);
        info.rti_info[RTAX_GATEWAY] = rt->rt_gateway;
        info.rti_info[RTAX_NETMASK] = rtsock_fix_netmask(rt_key(rt),
            rt_mask(rt), &ss);
        info.rti_info[RTAX_GENMASK] = 0;
        if (rtm->rtm_addrs & (RTA_IFP | RTA_IFA)) {
            ifp = rt->rt_ifp;
            if (ifp) {
                info.rti_info[RTAX_IFP] =
                    ifp->if_addr->ifa_addr;
                error = rtm_get_jailed(&info, ifp, rt,
                    &saun, curthread->td_ucred);
                if (error != 0) {
                    RT_UNLOCK(rt);
                    senderr(error);
                }
                if (ifp->if_flags & IFF_POINTOPOINT)
                    info.rti_info[RTAX_BRD] =
                        rt->rt_ifa->ifa_dstaddr;
                rtm->rtm_index = ifp->if_index;
            } else {
                info.rti_info[RTAX_IFP] = NULL;
                info.rti_info[RTAX_IFA] = NULL;
            }
        } else if ((ifp = rt->rt_ifp) != NULL) {
            rtm->rtm_index = ifp->if_index;
        }

        /* Check if we need to realloc storage */
        rtsock_msg_buffer(rtm->rtm_type, &info, NULL, &len);
        if (len > maxlen) {
            RT_UNLOCK(rt);
            senderr(ENOBUFS);
        }

        if (len > alloc_len) {
            struct rt_msghdr *new_rtm;
            new_rtm = malloc(len, M_TEMP, M_NOWAIT);
            if (new_rtm == NULL) {
                RT_UNLOCK(rt);
                senderr(ENOBUFS);
            }
            bcopy(rtm, new_rtm, rtm->rtm_msglen);
            free(rtm, M_TEMP);
            rtm = new_rtm;
            alloc_len = len;
        }

        w.w_tmem = (caddr_t)rtm;
        w.w_tmemsize = alloc_len;
        rtsock_msg_buffer(rtm->rtm_type, &info, &w, &len);

        if (rt->rt_flags & RTF_GWFLAG_COMPAT)
            rtm->rtm_flags = RTF_GATEWAY | 
                (rt->rt_flags & ~RTF_GWFLAG_COMPAT);
        else
            rtm->rtm_flags = rt->rt_flags;
        rt_getmetrics(rt, &rtm->rtm_rmx);
        rtm->rtm_addrs = info.rti_addrs;

        RT_UNLOCK(rt);
        break;

    default:
        senderr(EOPNOTSUPP);
    }

flush:
    if (rt != NULL)
        RTFREE(rt);

    if (rtm != NULL) {
#ifdef INET6
        if (rti_need_deembed) {
            /* sin6_scope_id is recovered before sending rtm. */
            sin6 = (struct sockaddr_in6 *)&ss;
            for (i = 0; i < RTAX_MAX; i++) {
                if (info.rti_info[i] == NULL)
                    continue;
                if (info.rti_info[i]->sa_family != AF_INET6)
                    continue;
                bcopy(info.rti_info[i], sin6, sizeof(*sin6));
                if (sa6_recoverscope(sin6) == 0)
                    bcopy(sin6, info.rti_info[i],
                            sizeof(*sin6));
            }
        }
#endif
        if (error != 0)
            rtm->rtm_errno = error;
        else
            rtm->rtm_flags |= RTF_DONE;

        bcopy((caddr_t)rtm, data, rtm->rtm_msglen);
        *plen = rtm->rtm_msglen;
        free(rtm, M_TEMP);
    }

    if (error != 0) {
        ff_os_errno(error);
        return (-1);
    }

    return (error);
}
