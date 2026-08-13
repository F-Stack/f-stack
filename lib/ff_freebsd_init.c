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
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/vmmeter.h>
#include <sys/cpuset.h>
#include <sys/smp.h>
#include <sys/sysctl.h>
#include <sys/filedesc.h>
#include <sys/jail.h>

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

/* Dense stack-instance index of the calling thread, from lcore_conf[]. */
extern int ff_cur_proc_id(void);

extern void ff_init_thread0(void);

void ff_pcpu_thread_init(int cpuid);
extern void ff_callout_thread_init(void);
extern void *ff_adapt_user_thread_add(void *parent);
void ff_stack_thread_init(int cpuid);

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

/*
 * Dense per-thread cpuid keeps each thread's UMA/SMR per-cpu slots disjoint.
 * The bound check is needed because subr_pcpu.c's KASSERT is compiled out
 * (no INVARIANTS), so a bad cpuid would silently overrun cpuid_to_pcpu[].
 */
void
ff_pcpu_thread_init(int cpuid)
{
    if (cpuid < 0 || (u_int)cpuid > mp_maxid)
        panic("ff_pcpu_thread_init: cpuid %d out of range [0, %u]\n",
            cpuid, mp_maxid);

    pcpup = malloc(sizeof(struct pcpu), M_DEVBUF, M_ZERO);
    pcpu_init(pcpup, cpuid, sizeof(struct pcpu));
    PCPU_SET(prvspace, pcpup);
}

/*
 * Sockets and ifioctl derive their vnet from the cred's prison
 * (CRED_TO_VNET), not from curvnet. Sharing the global prison0 would pin every
 * worker socket and SIOCAIFADDR to vnet0, so each worker gets an isolated
 * prison pointing at its own vnet. Deliberately not linked into allprison or
 * prison0's children.
 */
static void
ff_worker_prison_init(struct thread *td, struct vnet *v)
{
    struct prison *pr;

    pr = malloc(sizeof(struct prison), M_DEVBUF, M_ZERO | M_WAITOK);
    if (pr == NULL)
        return;

    pr->pr_id = -1;
    pr->pr_parent = pr;
    pr->pr_ref = 1;
    pr->pr_uref = 1;
    pr->pr_state = PRISON_STATE_ALIVE;
    pr->pr_flags = prison0.pr_flags | PR_HOST | PR_VNET;
    pr->pr_allow = prison0.pr_allow;
    pr->pr_securelevel = prison0.pr_securelevel;
    pr->pr_childmax = prison0.pr_childmax;
    pr->pr_enforce_statfs = prison0.pr_enforce_statfs;
    pr->pr_devfs_rsnum = prison0.pr_devfs_rsnum;
    pr->pr_osreldate = prison0.pr_osreldate;
    pr->pr_hostid = prison0.pr_hostid;
    pr->pr_cpuset = prison0.pr_cpuset;
    pr->pr_root = prison0.pr_root;
    strlcpy(pr->pr_name, prison0.pr_name, sizeof(pr->pr_name));
    strlcpy(pr->pr_path, prison0.pr_path, sizeof(pr->pr_path));
    strlcpy(pr->pr_hostname, prison0.pr_hostname, sizeof(pr->pr_hostname));
    strlcpy(pr->pr_domainname, prison0.pr_domainname,
        sizeof(pr->pr_domainname));
    strlcpy(pr->pr_hostuuid, prison0.pr_hostuuid, sizeof(pr->pr_hostuuid));
    strlcpy(pr->pr_osrelease, prison0.pr_osrelease,
        sizeof(pr->pr_osrelease));
    LIST_INIT(&pr->pr_children);
    LIST_INIT(&pr->pr_proclist);
    LIST_INIT(&pr->pr_descs);
    mtx_init(&pr->pr_mtx, "jail mutex", NULL, MTX_DEF);

    pr->pr_vnet = v;

    if (td->td_proc != NULL && td->td_proc->p_ucred != NULL)
        td->td_proc->p_ucred->cr_prison = pr;
    if (td->td_ucred != NULL)
        td->td_ucred->cr_prison = pr;
}

/*
 * Per-thread stack-instance init. thread_mode=0 main thread is already
 * initialized inside ff_freebsd_init (ff_stack_inited set there) and skips
 * here, so single-thread stays byte-equivalent to CM5-A. The body below is
 * the CM5-B worker path: each worker builds its own pcpu / thread_i (with an
 * independent proc_i) / vnet_i / callout, giving per-thread stack isolation.
 */
void
ff_stack_thread_init(int cpuid)
{
    struct thread *td_i;
    struct vnet *v;
    static volatile int init_lock = 0;

    if (ff_stack_inited)
        return;
    ff_stack_inited = 1;

    /*
     * pcpu_init() touches the global cpuid_to_pcpu[] and cpuhead, so keep it
     * inside the init lock together with the rest of the worker bring-up.
     */
    while (__sync_lock_test_and_set(&init_lock, 1))
        ;
    ff_pcpu_thread_init(cpuid);

    /*
     * Temporarily point curthread at the global thread0 so Giant/malloc have
     * a valid thread context, then build this worker's own (proc_i, thread_i)
     * via the existing ff_adapt_user_thread_add path (uses thread0 only as a
     * read-only template; ff_adapt_user_proc_add is GIANT_REQUIRED).
     */
    ff_init_thread0();
    td_i = ff_adapt_user_thread_add(&thread0);
    if (td_i != NULL)
        pcurthread = td_i;

    /*
     * Build this worker's callwheel BEFORE vnet_alloc: vnet_alloc runs the
     * vnet's VNET_SYSINIT (syncache_init -> callout_reset), which touches
     * cc_cpu. This mirrors the main thread order where callwheel_init
     * (SI_SUB_CPU) precedes vnet0 (SI_SUB_VNET). Needs pcpu (cpuid) and
     * curthread already set, satisfied above.
     */
    ff_callout_thread_init();

    v = vnet_alloc();
    curthread->td_vnet = v;
    /* Must precede lo_set_defaultaddr(): it socreate()s, whose vnet comes
     * from the cred's prison. */
    if (td_i != NULL)
        ff_worker_prison_init(td_i, v);
    lo_set_defaultaddr();
    __sync_lock_release(&init_lock);
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
    int nb_cpus, i;

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

    nb_cpus = ff_global_cfg.dpdk.thread_mode ?
        ff_global_cfg.dpdk.nb_threads : 1;
    if (nb_cpus < 1)
        nb_cpus = 1;
    if (nb_cpus > MAXCPU)
        panic("nb_threads %d exceeds MAXCPU %d\n", nb_cpus, MAXCPU);

    /*
     * mp_ncpus/mp_maxid/all_cpus must be final before uma_startup1(): UMA
     * sizes each zone by mp_maxid there once and for all, and CPU_FOREACH
     * consumers (ip_fw_dynamic.c) size their arrays by mp_ncpus.
     */
    mp_ncpus = nb_cpus;
    mp_maxid = nb_cpus - 1;
    for (i = 0; i < nb_cpus; i++)
        CPU_SET(i, &all_cpus);

    /* Main thread is itself an EAL lcore worker (CALL_MAIN), so it takes its
     * own dense slot; thread_mode=0 has one stack per process -> slot 0. */
    ff_pcpu_thread_init(ff_global_cfg.dpdk.thread_mode ? ff_cur_proc_id() : 0);

    ff_init_thread0();

    /*
     * Must precede uma_startup1(): once mp_maxid > 0 the zone-of-zones grows
     * past the single-page slab threshold, which sets UMA_ZFLAG_VTOSLAB and
     * makes keg_alloc_slab() call vsetzoneslab() during uma_startup1().
     */
    num_hash_buckets = 8192;
    uma_page_slab_hash = (struct uma_page_head *)kmem_malloc(sizeof(struct uma_page)*num_hash_buckets, M_ZERO);
    uma_page_mask = num_hash_buckets - 1;

    boot_pages = 16;
    bootmem = (void *)kmem_malloc(boot_pages*PAGE_SIZE, M_ZERO);
    //uma_startup(bootmem, boot_pages);
    uma_startup1((vm_offset_t)bootmem);
    uma_startup2();

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
        if (strcmp(cur->name, "net.isr.dispatch") == 0) {
            printf("net.isr.dispatch must stay direct (hybrid/deferred "
                "silently drop packets); ignoring requested value\n");
            cur = cur->next;
            continue;
        }
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
