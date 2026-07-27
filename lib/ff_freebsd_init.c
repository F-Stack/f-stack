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
#include <net/if_private.h>
#include <net/vnet.h>
#include <netinet/in_var.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>

int lo_set_defaultaddr(void);

int ff_freebsd_init(void);

extern void mutex_init(void);
extern void mi_startup(void);
extern void uma_startup(void *, int);
extern void uma_startup2(void);

extern void ff_init_thread0(void);

void ff_pcpu_thread_init(void);
extern void ff_callout_thread_init(void);
void ff_stack_thread_init(void);

/* Per-thread guard: main thread completes its per-thread init inside
 * ff_freebsd_init (CM4 path), so ff_stack_thread_init skips it (zero
 * regression at thread_mode=0). thread_mode=1 workers start with 0. */
static __thread int ff_stack_inited;

struct sx proctree_lock;
__thread struct pcpu *pcpup;
struct uma_page_head *uma_page_slab_hash;
int uma_page_mask;
extern cpuset_t all_cpus;

long physmem;

extern void uma_startup1(vm_offset_t);

/* Per-thread pcpu bootstrap. CM3: main thread calls it once (behaviour
 * unchanged). Worker per-thread invocation is wired in CM5. */
void
ff_pcpu_thread_init(void)
{
    pcpup = malloc(sizeof(struct pcpu), M_DEVBUF, M_ZERO);
    pcpu_init(pcpup, 0, sizeof(struct pcpu));
    PCPU_SET(prvspace, pcpup);
}

/*
 * Per-thread stack-instance init. CM5-A: main thread is already initialized
 * inside ff_freebsd_init (ff_stack_inited set there), so it skips here and
 * thread_mode=0 stays byte-equivalent to CM4. The body below is the
 * CM5-B multi-thread worker path (each worker builds its own pcpu/vnet/
 * callout); at stage A it is compiled but never executed (no real workers
 * are launched) and is not runtime-verified yet.
 */
void
ff_stack_thread_init(void)
{
    struct vnet *v;

    if (ff_stack_inited)
        return;
    ff_stack_inited = 1;

    ff_pcpu_thread_init();
    ff_init_thread0();          /* TODO(CM5-B): thread0_i per-thread (workers must not share one thread0) */

    v = vnet_alloc();           /* also runs this vnet's VNET_SYSINIT */
    curthread->td_vnet = v;     /* vnet_alloc restores curvnet on return, so bind explicitly */

    ff_callout_thread_init();
}

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
    soclose(so);

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

    ff_pcpu_thread_init();
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

    /*
     * CM4 PoC: vnet_init_done clears curvnet at boot end (FreeBSD design).
     * Under VIMAGE all V_* go through curvnet, so pin the main thread to
     * vnet0 for the whole thread_mode=0 single-thread path (sysctl loop,
     * lo_set_defaultaddr, ff_run/main_loop). Per-thread td_vnet is CM5.
     */
    curthread->td_vnet = vnet0;

    /*
     * ECN switch (default off for zero-regression vs CM0-3). Real tcp_ecn.c
     * defaults V_tcp_do_ecn=2 (passive ECN); apply the config value here,
     * after td_vnet=vnet0 so V_* resolves. 0=off, 1=passive(=2).
     */
    V_tcp_do_ecn = ff_global_cfg.freebsd.tcp_ecn ? 2 : 0;

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

    /* Main thread's per-thread init (pcpu/thread0/td_vnet=vnet0/callout) is
     * done by now; mark it so ff_stack_thread_init() in main_loop skips it. */
    ff_stack_inited = 1;

    return (0);
}
