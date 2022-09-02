/*
 * Copyright (c) 2010 Kip Macy All rights reserved.
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
 * Derived in part from libplebnet's pn_init.c.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/pcpu.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/vmmeter.h>
#include <sys/cpuset.h>
#include <sys/sysctl.h>
#include <sys/filedesc.h>

#include <vm/uma.h>
#include <vm/uma_int.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>

#include "ff_host_interface.h"
#include "ff_api.h"
#include "ff_config.h"

#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <net/if_var.h>
#include <netinet/in_var.h>

int lo_set_defaultaddr(void);

int ff_freebsd_init(void);

extern void mutex_init(void);
extern void mi_startup(void);
extern void uma_startup(void *, int);
extern void uma_startup2(void);

extern void ff_init_thread0(void);

struct sx proctree_lock;
struct pcpu *pcpup;
struct uma_page_head *uma_page_slab_hash;
int uma_page_mask;
extern cpuset_t all_cpus;

long physmem;

extern void uma_startup1(vm_offset_t);

int lo_set_defaultaddr(void)
{
    struct in_aliasreq req;
    char *addr="127.0.0.1";
    char *netmask="255.0.0.0";
    struct ifnet *ifp=NULL;
    int ret;

    IFNET_WLOCK();
    CK_STAILQ_FOREACH(ifp, &V_ifnet, if_link)
        if ( (ifp->if_flags & IFF_LOOPBACK) != 0 )
            break;
    IFNET_WUNLOCK();

    if(ifp == NULL)
        return -1;

    bzero(&req, sizeof req);
    strcpy(req.ifra_name, ifp->if_xname);

    struct sockaddr_in sa;
    bzero(&sa, sizeof(sa));

    sa.sin_len = sizeof(sa);
    sa.sin_family = AF_INET;

    inet_pton(AF_INET, addr, &sa.sin_addr.s_addr);
    bcopy(&sa, &req.ifra_addr, sizeof(sa));

    inet_pton(AF_INET, netmask, &sa.sin_addr.s_addr);
    bcopy(&sa, &req.ifra_mask, sizeof(sa));

    //sa.sin_addr.s_addr = sc->broadcast;
    //bcopy(&sa, &req.ifra_broadaddr, sizeof(sa));

    struct socket *so = NULL;
    ret = socreate(AF_INET, &so, SOCK_DGRAM, 0, curthread->td_ucred, curthread);
    if(ret != 0)
        return ret;

    ret = ifioctl(so, SIOCAIFADDR, (caddr_t)&req, curthread);
    sofree(so);

    return ret;
}

int
ff_freebsd_init(void)
{
    int boot_pages;
    unsigned int num_hash_buckets;
    char tmpbuf[32] = {0};
    void *bootmem;
    int error;

    snprintf(tmpbuf, sizeof(tmpbuf), "%u", ff_global_cfg.freebsd.hz);
    error = kern_setenv("kern.hz", tmpbuf);
    if (error != 0) {
        panic("kern_setenv failed: kern.hz=%s\n", tmpbuf);
    }

    struct ff_freebsd_cfg *cur;
    cur = ff_global_cfg.freebsd.boot;
    while (cur) {
        error = kern_setenv(cur->name, cur->str);
        if (error != 0) {
            printf("kern_setenv failed: %s=%s\n", cur->name, cur->str);
        }

        cur = cur->next;
    }

    physmem = ff_global_cfg.freebsd.physmem;

    pcpup = malloc(sizeof(struct pcpu), M_DEVBUF, M_ZERO);
    pcpu_init(pcpup, 0, sizeof(struct pcpu));
    PCPU_SET(prvspace, pcpup);
    CPU_SET(0, &all_cpus);

    ff_init_thread0();

    boot_pages = 16;
    bootmem = (void *)kmem_malloc(boot_pages*PAGE_SIZE, M_ZERO);
    //uma_startup(bootmem, boot_pages);
    uma_startup1((vm_offset_t)bootmem);
    uma_startup2();

    num_hash_buckets = 8192;
    uma_page_slab_hash = (struct uma_page_head *)kmem_malloc(sizeof(struct uma_page)*num_hash_buckets, M_ZERO);
    uma_page_mask = num_hash_buckets - 1;

    mutex_init();
    mi_startup();
    sx_init(&proctree_lock, "proctree");
    ff_fdused_range(ff_global_cfg.freebsd.fd_reserve);

    cur = ff_global_cfg.freebsd.sysctl;
    while (cur) {
        error = kernel_sysctlbyname(curthread, cur->name, NULL, NULL,
            cur->value, cur->vlen, NULL, 0);

        if (error != 0) {
            printf("kernel_sysctlbyname failed: %s=%s, error:%d\n",
                cur->name, cur->str, error);
        }

        cur = cur->next;
    }

    error = lo_set_defaultaddr();
    if(error != 0)
        printf("set loopback port default addr failed!");

    return (0);
}
