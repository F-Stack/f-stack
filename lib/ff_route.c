/*
 * Copyright (c) 1988, 1991, 1993
 *  The Regents of the University of California.  All rights reserved.
 * Copyright (C) 2017-2021 THL A29 Limited, a Tencent company.
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
#include <sys/priv.h>
#include <sys/rmlock.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/if_llatbl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/route/route_var.h>
#include <net/route/route_ctl.h>
#include <net/route/nhgrp_var.h>
#include <netinet/if_ether.h>
#ifdef INET6
#include <netinet6/scope6_var.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_var.h>
#endif

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

static inline void
fill_sockaddr_inet(struct sockaddr_in *sin, struct in_addr addr)
{
    const struct sockaddr_in nsin = {
        .sin_family = AF_INET,
        .sin_len = sizeof(struct sockaddr_in),
        .sin_addr = addr,
    };
    *sin = nsin;
}

#ifdef INET6
static inline void
fill_sockaddr_inet6(struct sockaddr_in6 *sin6, const struct in6_addr *addr6,
    uint32_t scopeid)
{

    const struct sockaddr_in6 nsin6 = {
        .sin6_family = AF_INET6,
        .sin6_len = sizeof(struct sockaddr_in6),
        .sin6_addr = *addr6,
        .sin6_scope_id = scopeid,
    };
    *sin6 = nsin6;
}
#endif

/*
 * Checks if gateway is suitable for lltable operations.
 * Lltable code requires AF_LINK gateway with ifindex
 *  and mac address specified.
 * Returns 0 on success.
 */
static int
cleanup_xaddrs_lladdr(struct rt_addrinfo *info)
{
    struct sockaddr_dl *sdl = (struct sockaddr_dl *)info->rti_info[RTAX_GATEWAY];

    if (sdl->sdl_family != AF_LINK)
        return (EINVAL);

    if (sdl->sdl_index == 0)
        return (EINVAL);

    if (offsetof(struct sockaddr_dl, sdl_data) + sdl->sdl_nlen + sdl->sdl_alen > sdl->sdl_len)
        return (EINVAL);

    return (0);
}

static int
cleanup_xaddrs_gateway(struct rt_addrinfo *info)
{
    struct sockaddr *gw = info->rti_info[RTAX_GATEWAY];

    if (info->rti_flags & RTF_LLDATA)
        return (cleanup_xaddrs_lladdr(info));

    switch (gw->sa_family) {
    case AF_INET:
        {
            struct sockaddr_in *gw_sin = (struct sockaddr_in *)gw;
            if (gw_sin->sin_len < sizeof(struct sockaddr_in)) {
                printf("gw sin_len too small\n");
                return (EINVAL);
            }
            fill_sockaddr_inet(gw_sin, gw_sin->sin_addr);
        }
        break;
#ifdef INET6
    case AF_INET6:
        {
            struct sockaddr_in6 *gw_sin6 = (struct sockaddr_in6 *)gw;
            if (gw_sin6->sin6_len < sizeof(struct sockaddr_in6)) {
                printf("gw sin6_len too small\n");
                return (EINVAL);
            }
            fill_sockaddr_inet6(gw_sin6, &gw_sin6->sin6_addr, 0);
            break;
        }
#endif
    case AF_LINK:
        {
            struct sockaddr_dl_short *gw_sdl;

            gw_sdl = (struct sockaddr_dl_short *)gw;
            if (gw_sdl->sdl_len < sizeof(struct sockaddr_dl_short)) {
                printf("gw sdl_len too small\n");
                return (EINVAL);
            }

            const struct sockaddr_dl_short sdl = {
                .sdl_family = AF_LINK,
                .sdl_len = sizeof(struct sockaddr_dl_short),
                .sdl_index = gw_sdl->sdl_index,
            };
            *gw_sdl = sdl;
            break;
        }
    }

    return (0);
}

static void
remove_netmask(struct rt_addrinfo *info)
{
    info->rti_info[RTAX_NETMASK] = NULL;
    info->rti_flags |= RTF_HOST;
    info->rti_addrs &= ~RTA_NETMASK;
}

static int
cleanup_xaddrs_inet(struct rt_addrinfo *info)
{
    struct sockaddr_in *dst_sa, *mask_sa;

    /* Check & fixup dst/netmask combination first */
    dst_sa = (struct sockaddr_in *)info->rti_info[RTAX_DST];
    mask_sa = (struct sockaddr_in *)info->rti_info[RTAX_NETMASK];

    struct in_addr mask = {
        .s_addr = mask_sa ? mask_sa->sin_addr.s_addr : INADDR_BROADCAST,
    };
    struct in_addr dst = {
        .s_addr = htonl(ntohl(dst_sa->sin_addr.s_addr) & ntohl(mask.s_addr))
    };

    if (dst_sa->sin_len < sizeof(struct sockaddr_in)) {
        printf("dst sin_len too small\n");
        return (EINVAL);
    }
    if (mask_sa && mask_sa->sin_len < sizeof(struct sockaddr_in)) {
        printf("mask sin_len too small\n");
        return (EINVAL);
    }
    fill_sockaddr_inet(dst_sa, dst);

    if (mask.s_addr != INADDR_BROADCAST)
        fill_sockaddr_inet(mask_sa, mask);
    else
        remove_netmask(info);

    /* Check gateway */
    if (info->rti_info[RTAX_GATEWAY] != NULL)
        return (cleanup_xaddrs_gateway(info));

    return (0);
}

#ifdef INET6
static int
cleanup_xaddrs_inet6(struct rt_addrinfo *info)
{
    struct sockaddr_in6 *dst_sa, *mask_sa;
    struct in6_addr mask;

    /* Check & fixup dst/netmask combination first */
    dst_sa = (struct sockaddr_in6 *)info->rti_info[RTAX_DST];
    mask_sa = (struct sockaddr_in6 *)info->rti_info[RTAX_NETMASK];

    mask = mask_sa ? mask_sa->sin6_addr : in6mask128;
    IN6_MASK_ADDR(&dst_sa->sin6_addr, &mask);

    if (dst_sa->sin6_len < sizeof(struct sockaddr_in6)) {
        printf("dst sin6_len too small\n");
        return (EINVAL);
    }
    if (mask_sa && mask_sa->sin6_len < sizeof(struct sockaddr_in6)) {
        printf("mask sin6_len too small\n");
        return (EINVAL);
    }
    fill_sockaddr_inet6(dst_sa, &dst_sa->sin6_addr, 0);

    if (!IN6_ARE_ADDR_EQUAL(&mask, &in6mask128))
        fill_sockaddr_inet6(mask_sa, &mask, 0);
    else
        remove_netmask(info);

    /* Check gateway */
    if (info->rti_info[RTAX_GATEWAY] != NULL)
        return (cleanup_xaddrs_gateway(info));

    return (0);
}
#endif

static int
cleanup_xaddrs(struct rt_addrinfo *info)
{
    int error = EAFNOSUPPORT;

    if (info->rti_info[RTAX_DST] == NULL)
        return (EINVAL);

    if (info->rti_flags & RTF_LLDATA) {
        /*
         * arp(8)/ndp(8) sends RTA_NETMASK for the associated
         * prefix along with the actual address in RTA_DST.
         * Remove netmask to avoid unnecessary address masking.
         */
        remove_netmask(info);
    }

    switch (info->rti_info[RTAX_DST]->sa_family) {
    case AF_INET:
        error = cleanup_xaddrs_inet(info);
        break;
#ifdef INET6
    case AF_INET6:
        error = cleanup_xaddrs_inet6(info);
        break;
#endif
    }

    return (error);
}

static int
rtm_get_jailed(struct rt_addrinfo *info, struct ifnet *ifp,
    struct nhop_object *nh, union sockaddr_union *saun, struct ucred *cred)
{
#if defined(INET) || defined(INET6)
    struct epoch_tracker et;
#endif

    /* First, see if the returned address is part of the jail. */
    if (prison_if(cred, nh->nh_ifa->ifa_addr) == 0) {
        info->rti_info[RTAX_IFA] = nh->nh_ifa->ifa_addr;
        return (0);
    }

    switch (info->rti_info[RTAX_DST]->sa_family) {
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
        NET_EPOCH_ENTER(et);
        CK_STAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
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
        NET_EPOCH_EXIT(et);
        if (!found) {
            /*
             * As a last resort return the 'default' jail address.
             */
            ia = ((struct sockaddr_in *)nh->nh_ifa->ifa_addr)->
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
        NET_EPOCH_ENTER(et);
        CK_STAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
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
        NET_EPOCH_EXIT(et);
        if (!found) {
            /*
             * As a last resort return the 'default' jail address.
             */
            ia6 = ((struct sockaddr_in6 *)nh->nh_ifa->ifa_addr)->
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

static int
fill_blackholeinfo(struct rt_addrinfo *info, union sockaddr_union *saun)
{
    struct ifaddr *ifa;
    sa_family_t saf;

    if (V_loif == NULL) {
        printf("Unable to add blackhole/reject nhop without loopback");
        return (ENOTSUP);
    }
    info->rti_ifp = V_loif;

    saf = info->rti_info[RTAX_DST]->sa_family;

    CK_STAILQ_FOREACH(ifa, &info->rti_ifp->if_addrhead, ifa_link) {
        if (ifa->ifa_addr->sa_family == saf) {
            info->rti_ifa = ifa;
            break;
        }
    }
    if (info->rti_ifa == NULL)
        return (ENOTSUP);

    bzero(saun, sizeof(union sockaddr_union));
    switch (saf) {
    case AF_INET:
        saun->sin.sin_family = AF_INET;
        saun->sin.sin_len = sizeof(struct sockaddr_in);
        saun->sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        break;
#ifdef INET6
    case AF_INET6:
        saun->sin6.sin6_family = AF_INET6;
        saun->sin6.sin6_len = sizeof(struct sockaddr_in6);
        saun->sin6.sin6_addr = in6addr_loopback;
        break;
#endif
    default:
        return (ENOTSUP);
    }
    info->rti_info[RTAX_GATEWAY] = &saun->sa;
    info->rti_flags |= RTF_GATEWAY;

    return (0);
}

/*
 * Fills in @info based on userland-provided @rtm message.
 *
 * Returns 0 on success.
 */
static int
fill_addrinfo(struct rt_msghdr *rtm, int len, u_int fibnum, struct rt_addrinfo *info)
{
    int error;
    sa_family_t saf;

    rtm->rtm_pid = curproc->p_pid;
    info->rti_addrs = rtm->rtm_addrs;

    info->rti_mflags = rtm->rtm_inits;
    info->rti_rmx = &rtm->rtm_rmx;

    /*
     * rt_xaddrs() performs s6_addr[2] := sin6_scope_id for AF_INET6
     * link-local address because rtrequest requires addresses with
     * embedded scope id.
     */
    if (rt_xaddrs((caddr_t)(rtm + 1), len + (caddr_t)rtm, info))
        return (EINVAL);

    if (rtm->rtm_flags & RTF_RNH_LOCKED)
        return (EINVAL);
    info->rti_flags = rtm->rtm_flags;
    error = cleanup_xaddrs(info);
    if (error != 0)
        return (error);
    saf = info->rti_info[RTAX_DST]->sa_family;
    /*
     * Verify that the caller has the appropriate privilege; RTM_GET
     * is the only operation the non-superuser is allowed.
     */
    if (rtm->rtm_type != RTM_GET) {
        error = priv_check(curthread, PRIV_NET_ROUTE);
        if (error != 0)
            return (error);
    }

    /*
     * The given gateway address may be an interface address.
     * For example, issuing a "route change" command on a route
     * entry that was created from a tunnel, and the gateway
     * address given is the local end point. In this case the 
     * RTF_GATEWAY flag must be cleared or the destination will
     * not be reachable even though there is no error message.
     */
    if (info->rti_info[RTAX_GATEWAY] != NULL &&
        info->rti_info[RTAX_GATEWAY]->sa_family != AF_LINK) {
        struct rt_addrinfo ginfo;
        struct sockaddr *gdst;
        struct sockaddr_storage ss;

        bzero(&ginfo, sizeof(ginfo));
        bzero(&ss, sizeof(ss));
        ss.ss_len = sizeof(ss);

        ginfo.rti_info[RTAX_GATEWAY] = (struct sockaddr *)&ss;
        gdst = info->rti_info[RTAX_GATEWAY];

        /* 
         * A host route through the loopback interface is 
         * installed for each interface adddress. In pre 8.0
         * releases the interface address of a PPP link type
         * is not reachable locally. This behavior is fixed as 
         * part of the new L2/L3 redesign and rewrite work. The
         * signature of this interface address route is the
         * AF_LINK sa_family type of the gateway, and the
         * rt_ifp has the IFF_LOOPBACK flag set.
         */
        if (rib_lookup_info(fibnum, gdst, NHR_REF, 0, &ginfo) == 0) {
            if (ss.ss_family == AF_LINK &&
                ginfo.rti_ifp->if_flags & IFF_LOOPBACK) {
                info->rti_flags &= ~RTF_GATEWAY;
                info->rti_flags |= RTF_GWFLAG_COMPAT;
            }
            rib_free_info(&ginfo);
        }
    }

    return (0);
}

/*
 * Returns pointer to array of nexthops with weights for
 * given @nhg. Stores number of items in the array into @pnum_nhops.
 */
struct weightened_nhop *
nhgrp_get_nhops(struct nhgrp_object *nhg, uint32_t *pnum_nhops)
{
	struct nhgrp_priv *nhg_priv;

	KASSERT(((nhg->nhg_flags & MPF_MULTIPATH) != 0), ("nhop is not mpath"));

	nhg_priv = NHGRP_PRIV(nhg);
	*pnum_nhops = nhg_priv->nhg_nh_count;

	return (nhg_priv->nhg_nh_weights);
}

static struct nhop_object *
select_nhop(struct nhop_object *nh, const struct sockaddr *gw)
{
	if (!NH_IS_NHGRP(nh))
		return (nh);
#ifdef ROUTE_MPATH
	struct weightened_nhop *wn;
	uint32_t num_nhops;
	wn = nhgrp_get_nhops((struct nhgrp_object *)nh, &num_nhops);
	if (gw == NULL)
		return (wn[0].nh);
	for (int i = 0; i < num_nhops; i++) {
		if (match_nhop_gw(wn[i].nh, gw))
			return (wn[i].nh);
	}
#endif
	return (NULL);
}

/*
 * Handles RTM_GET message from routing socket, returning matching rt.
 *
 * Returns:
 * 0 on success, with locked and referenced matching rt in @rt_nrt
 * errno of failure
 */
static int
handle_rtm_get(struct rt_addrinfo *info, u_int fibnum,
    struct rt_msghdr *rtm, struct rib_cmd_info *rc)
{
	RIB_RLOCK_TRACKER;
	struct rib_head *rnh;
	struct nhop_object *nh;
	sa_family_t saf;

	saf = info->rti_info[RTAX_DST]->sa_family;

	rnh = rt_tables_get_rnh(fibnum, saf);
	if (rnh == NULL)
		return (EAFNOSUPPORT);

	RIB_RLOCK(rnh);

	/*
	 * By (implicit) convention host route (one without netmask)
	 * means longest-prefix-match request and the route with netmask
	 * means exact-match lookup.
	 * As cleanup_xaddrs() cleans up info flags&addrs for the /32,/128
	 * prefixes, use original data to check for the netmask presence.
	 */
	if ((rtm->rtm_addrs & RTA_NETMASK) == 0) {
		/*
		 * Provide longest prefix match for
		 * address lookup (no mask).
		 * 'route -n get addr'
		 */
		rc->rc_rt = (struct rtentry *) rnh->rnh_matchaddr(
		    info->rti_info[RTAX_DST], &rnh->head);
	} else
		rc->rc_rt = (struct rtentry *) rnh->rnh_lookup(
		    info->rti_info[RTAX_DST],
		    info->rti_info[RTAX_NETMASK], &rnh->head);

	if (rc->rc_rt == NULL) {
		RIB_RUNLOCK(rnh);
		return (ESRCH);
	}

	nh = select_nhop(rt_get_raw_nhop(rc->rc_rt), info->rti_info[RTAX_GATEWAY]);
	if (nh == NULL) {
		RIB_RUNLOCK(rnh);
		return (ESRCH);
	}
	/*
	 * If performing proxied L2 entry insertion, and
	 * the actual PPP host entry is found, perform
	 * another search to retrieve the prefix route of
	 * the local end point of the PPP link.
	 * TODO: move this logic to userland.
	 */
	if (rtm->rtm_flags & RTF_ANNOUNCE) {
		struct sockaddr laddr;

		if (nh->nh_ifp != NULL &&
		    nh->nh_ifp->if_type == IFT_PROPVIRTUAL) {
			struct ifaddr *ifa;

			ifa = ifa_ifwithnet(info->rti_info[RTAX_DST], 1,
					RT_ALL_FIBS);
			if (ifa != NULL)
				rt_maskedcopy(ifa->ifa_addr,
					      &laddr,
					      ifa->ifa_netmask);
		} else
			rt_maskedcopy(nh->nh_ifa->ifa_addr,
				      &laddr,
				      nh->nh_ifa->ifa_netmask);
		/* 
		 * refactor rt and no lock operation necessary
		 */
		rc->rc_rt = (struct rtentry *)rnh->rnh_matchaddr(&laddr,
		    &rnh->head);
		if (rc->rc_rt == NULL) {
			RIB_RUNLOCK(rnh);
			return (ESRCH);
		}
		nh = select_nhop(rt_get_raw_nhop(rc->rc_rt), info->rti_info[RTAX_GATEWAY]);
		if (nh == NULL) {
			RIB_RUNLOCK(rnh);
			return (ESRCH);
		}
	}
	rc->rc_nh_new = nh;
	rc->rc_nh_weight = rc->rc_rt->rt_weight;
	RIB_RUNLOCK(rnh);

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
            if (sa->sa_family == AF_INET6) {
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

#if 0
/*
 * Fill in @dmask with valid netmask leaving original @smask
 * intact. Mostly used with radix netmasks.
 */
struct sockaddr *
rtsock_fix_netmask(const struct sockaddr *dst, const struct sockaddr *smask,
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
#endif

static void
rt_getmetrics(const struct rtentry *rt, const struct nhop_object *nh,
    struct rt_metrics *out)
{

    bzero(out, sizeof(*out));
    out->rmx_mtu = nh->nh_mtu;
    out->rmx_weight = rt->rt_weight;
    out->rmx_nhidx = nhop_get_idx(nh);
    /* Kernel -> userland timebase conversion. */
    out->rmx_expire = rt->rt_expire ?
        rt->rt_expire - time_uptime + time_second : 0;
}

static void
init_sockaddrs_family(int family, struct sockaddr *dst, struct sockaddr *mask)
{
    if (family == AF_INET) {
        struct sockaddr_in *dst4 = (struct sockaddr_in *)dst;
        struct sockaddr_in *mask4 = (struct sockaddr_in *)mask;

        bzero(dst4, sizeof(struct sockaddr_in));
        bzero(mask4, sizeof(struct sockaddr_in));

        dst4->sin_family = AF_INET;
        dst4->sin_len = sizeof(struct sockaddr_in);
        mask4->sin_family = AF_INET;
        mask4->sin_len = sizeof(struct sockaddr_in);
    }
#ifdef INET6
    if (family == AF_INET6) {
        struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)dst;
        struct sockaddr_in6 *mask6 = (struct sockaddr_in6 *)mask;

        bzero(dst6, sizeof(struct sockaddr_in6));
        bzero(mask6, sizeof(struct sockaddr_in6));

        dst6->sin6_family = AF_INET6;
        dst6->sin6_len = sizeof(struct sockaddr_in6);
        mask6->sin6_family = AF_INET6;
        mask6->sin6_len = sizeof(struct sockaddr_in6);
    }
#endif
}

static void
export_rtaddrs(const struct rtentry *rt, struct sockaddr *dst,
    struct sockaddr *mask)
{
    if (dst->sa_family == AF_INET) {
        struct sockaddr_in *dst4 = (struct sockaddr_in *)dst;
        struct sockaddr_in *mask4 = (struct sockaddr_in *)mask;
        uint32_t scopeid = 0;
        rt_get_inet_prefix_pmask(rt, &dst4->sin_addr, &mask4->sin_addr,
            &scopeid);
        return;
    }
#ifdef INET6
    if (dst->sa_family == AF_INET6) {
        struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)dst;
        struct sockaddr_in6 *mask6 = (struct sockaddr_in6 *)mask;
        uint32_t scopeid = 0;
        rt_get_inet6_prefix_pmask(rt, &dst6->sin6_addr,
            &mask6->sin6_addr, &scopeid);
        dst6->sin6_scope_id = scopeid;
        return;
    }
#endif
}

static int
update_rtm_from_rc(struct rt_addrinfo *info, struct rt_msghdr **prtm,
    int alloc_len, struct rib_cmd_info *rc, struct nhop_object *nh, unsigned maxlen)
{
    struct walkarg w;
    union sockaddr_union saun;
    struct rt_msghdr *rtm, *orig_rtm = NULL;
    struct ifnet *ifp;
    int error, len;

    rtm = *prtm;
    union sockaddr_union sa_dst, sa_mask;
    int family = info->rti_info[RTAX_DST]->sa_family;
    init_sockaddrs_family(family, &sa_dst.sa, &sa_mask.sa);
    export_rtaddrs(rc->rc_rt, &sa_dst.sa, &sa_mask.sa);

    info->rti_info[RTAX_DST] = &sa_dst.sa;
    info->rti_info[RTAX_NETMASK] = rt_is_host(rc->rc_rt) ? NULL : &sa_mask.sa;
    info->rti_info[RTAX_GATEWAY] = &nh->gw_sa;
    info->rti_info[RTAX_GENMASK] = 0;
    ifp = nh->nh_ifp;
    if (rtm->rtm_addrs & (RTA_IFP | RTA_IFA)) {
        if (ifp) {
            info->rti_info[RTAX_IFP] =
                ifp->if_addr->ifa_addr;
            error = rtm_get_jailed(info, ifp, nh,
                &saun, curthread->td_ucred);
            if (error != 0)
                return (error);
            if (ifp->if_flags & IFF_POINTOPOINT)
                info->rti_info[RTAX_BRD] =
                    nh->nh_ifa->ifa_dstaddr;
            rtm->rtm_index = ifp->if_index;
        } else {
            info->rti_info[RTAX_IFP] = NULL;
            info->rti_info[RTAX_IFA] = NULL;
        }
    } else if (ifp != NULL)
        rtm->rtm_index = ifp->if_index;

    /* Check if we need to realloc storage */
    rtsock_msg_buffer(rtm->rtm_type, info, NULL, &len);
    if (len > maxlen) {
        return (ENOBUFS);
    }

    if (len > alloc_len) {
        struct rt_msghdr *tmp_rtm;

        tmp_rtm = malloc(len, M_TEMP, M_NOWAIT);
        if (tmp_rtm == NULL)
            return (ENOBUFS);
        bcopy(rtm, tmp_rtm, rtm->rtm_msglen);
        orig_rtm = rtm;
        rtm = tmp_rtm;
        alloc_len = len;

        /*
         * Delay freeing original rtm as info contains
         * data referencing it.
         */
    }

    w.w_tmem = (caddr_t)rtm;
    w.w_tmemsize = alloc_len;
    rtsock_msg_buffer(rtm->rtm_type, info, &w, &len);

    rtm->rtm_flags = rc->rc_rt->rte_flags | nhop_get_rtflags(nh);
    if (rtm->rtm_flags & RTF_GWFLAG_COMPAT)
        rtm->rtm_flags = RTF_GATEWAY | 
            (rtm->rtm_flags & ~RTF_GWFLAG_COMPAT);
    rt_getmetrics(rc->rc_rt, nh, &rtm->rtm_rmx);
    rtm->rtm_rmx.rmx_weight = rc->rc_nh_weight;
    rtm->rtm_addrs = info->rti_addrs;

    if (orig_rtm != NULL)
        free(orig_rtm, M_TEMP);
    *prtm = rtm;

    return (0);
}

/*
 * Checks if rte can be exported v.r.t jails/vnets.
 *
 * Returns 1 if it can, 0 otherwise.
 */
static bool
can_export_rte(struct ucred *td_ucred, bool rt_is_host,
    const struct sockaddr *rt_dst)
{

    if ((!rt_is_host) ? jailed_without_vnet(td_ucred)
        : prison_if(td_ucred, rt_dst) != 0)
        return (false);
    return (true);
}

int
ff_rtioctl(int fibnum, void *data, unsigned *plen, unsigned maxlen)
{
    struct rt_msghdr *rtm = NULL;
    struct rtentry *rt = NULL;
    struct rt_addrinfo info;
    struct epoch_tracker et;
#ifdef INET6
    struct sockaddr_storage ss;
    struct sockaddr_in6 *sin6;
    int i, rti_need_deembed = 0;
#endif
    int alloc_len = 0, len, error = 0;
    sa_family_t saf = AF_UNSPEC;
    struct rib_cmd_info rc;
    struct nhop_object *nh;

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
    nh = NULL;

    if (rtm->rtm_version != RTM_VERSION) {
        /* Do not touch message since format is unknown */
        free(rtm, M_TEMP);
        rtm = NULL;
        senderr(EPROTONOSUPPORT);
    }

    /*
     * Starting from here, it is possible
     * to alter original message and insert
     * caller PID and error value.
     */

    if ((error = fill_addrinfo(rtm, len, fibnum, &info)) != 0) {
        senderr(error);
    }

    saf = info.rti_info[RTAX_DST]->sa_family;

    /* support for new ARP code */
    if (rtm->rtm_flags & RTF_LLDATA) {
        error = lla_rt_output(rtm, &info);
#ifdef INET6
        if (error == 0)
            rti_need_deembed = 1;
#endif
        goto flush;
    }

    union sockaddr_union gw_saun;
    int blackhole_flags = rtm->rtm_flags & (RTF_BLACKHOLE|RTF_REJECT);
    if (blackhole_flags != 0) {
        if (blackhole_flags != (RTF_BLACKHOLE | RTF_REJECT))
            error = fill_blackholeinfo(&info, &gw_saun);
        else
            error = EINVAL;
        if (error != 0)
            senderr(error);
        /* TODO: rebuild rtm from scratch */
    }

    switch (rtm->rtm_type) {
    case RTM_ADD:
    case RTM_CHANGE:
        if (rtm->rtm_type == RTM_ADD) {
            if (info.rti_info[RTAX_GATEWAY] == NULL)
                senderr(EINVAL);
        }
        error = rib_action(fibnum, rtm->rtm_type, &info, &rc);
        if (error == 0) {
#ifdef INET6
            rti_need_deembed = 1;
#endif
#ifdef ROUTE_MPATH
            if (NH_IS_NHGRP(rc.rc_nh_new) ||
                (rc.rc_nh_old && NH_IS_NHGRP(rc.rc_nh_old))) {
                struct rib_cmd_info rc_simple = {};
                rib_decompose_notification(&rc,
                    save_add_notification, (void *)&rc_simple);
                rc = rc_simple;
            }
#endif
            nh = rc.rc_nh_new;
            rtm->rtm_index = nh->nh_ifp->if_index;
            rtm->rtm_flags = rc.rc_rt->rte_flags | nhop_get_rtflags(nh);
        }
        break;

    case RTM_DELETE:
        error = rib_action(fibnum, RTM_DELETE, &info, &rc);
        if (error == 0) {
#ifdef ROUTE_MPATH
            if (NH_IS_NHGRP(rc.rc_nh_old) ||
                (rc.rc_nh_new && NH_IS_NHGRP(rc.rc_nh_new))) {
                struct rib_cmd_info rc_simple = {};
                rib_decompose_notification(&rc,
                    save_del_notification, (void *)&rc_simple);
                rc = rc_simple;
            }
#endif
            nh = rc.rc_nh_old;
            goto report;
        }
#ifdef INET6
        /* rt_msg2() will not be used when RTM_DELETE fails. */
        rti_need_deembed = 1;
#endif
        break;

    case RTM_GET:
        error = handle_rtm_get(&info, fibnum, rtm, &rc);
        if (error != 0)
            senderr(error);
        nh = rc.rc_nh_new;

report:
        if (!can_export_rte(curthread->td_ucred,
            info.rti_info[RTAX_NETMASK] == NULL,
            info.rti_info[RTAX_DST])) {
            senderr(ESRCH);
        }

        error = update_rtm_from_rc(&info, &rtm, alloc_len, &rc, nh, maxlen);
        /*
         * Note that some sockaddr pointers may have changed to
         * point to memory outsize @rtm. Some may be pointing
         * to the on-stack variables.
         * Given that, any pointer in @info CANNOT BE USED.
         */

        /*
         * scopeid deembedding has been performed while
         * writing updated rtm in rtsock_msg_buffer().
         * With that in mind, skip deembedding procedure below.
         */
#ifdef INET6
        rti_need_deembed = 0;
#endif
        if (error != 0)
            senderr(error);
        break;

    default:
        senderr(EOPNOTSUPP);
    }

flush:
    NET_EPOCH_EXIT(et);
    rt = NULL;

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

#if 0
int
ff_rtioctl_old(int fibnum, void *data, unsigned *plen, unsigned maxlen)
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
#endif
