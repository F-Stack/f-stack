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
 * Derived in part from libplebnet's pn_glue.c.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/event.h>
#include <sys/jail.h>
#include <sys/limits.h>
#include <sys/malloc.h>
#include <sys/refcount.h>
#include <sys/resourcevar.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/priv.h>
#include <sys/time.h>
#include <sys/ucred.h>
#include <sys/uio.h>
#include <sys/param.h>
#include <sys/bus.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/vmem.h>
#include <sys/mbuf.h>
#include <sys/smp.h>
#include <sys/sched.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_object.h>
#include <vm/vm_map.h>
#include <vm/vm_extern.h>

#include "ff_host_interface.h"

int kstack_pages = KSTACK_PAGES;
SYSCTL_INT(_kern, OID_AUTO, kstack_pages, CTLFLAG_RD, &kstack_pages, 0,
    "Kernel stack size in pages");

int bootverbose;

SYSCTL_ROOT_NODE(0, sysctl, CTLFLAG_RW, 0, "Sysctl internal magic");

SYSCTL_ROOT_NODE(CTL_VFS, vfs, CTLFLAG_RW, 0, "File system");

SYSCTL_ROOT_NODE(CTL_KERN, kern, CTLFLAG_RW, 0, "High kernel, proc, limits &c");

SYSCTL_ROOT_NODE(CTL_NET, net, CTLFLAG_RW, 0, "Network, (see socket.h)");

SYSCTL_ROOT_NODE(CTL_MACHDEP, machdep, CTLFLAG_RW, 0, "machine dependent");

SYSCTL_ROOT_NODE(CTL_VM, vm, CTLFLAG_RW, 0, "Virtual memory");

SYSCTL_ROOT_NODE(CTL_DEBUG, debug, CTLFLAG_RW, 0, "Debugging");

SYSCTL_ROOT_NODE(OID_AUTO, security, CTLFLAG_RW, 0, "Security");

SYSCTL_NODE(_kern, OID_AUTO, features, CTLFLAG_RD, 0, "Kernel Features");

SYSCTL_NODE(_kern, KERN_PROC, proc, CTLFLAG_RD,  0, "Process table");

MALLOC_DEFINE(M_DEVBUF, "devbuf", "device driver memory");
MALLOC_DEFINE(M_TEMP, "temp", "misc temporary data buffers");
static MALLOC_DEFINE(M_CRED, "cred", "credentials");
static MALLOC_DEFINE(M_PLIMIT, "plimit", "plimit structures");

MALLOC_DEFINE(M_IP6OPT, "ip6opt", "IPv6 options");
MALLOC_DEFINE(M_IP6NDP, "ip6ndp", "IPv6 Neighbor Discovery");

static void configure_final(void *dummy);

SYSINIT(configure3, SI_SUB_CONFIGURE, SI_ORDER_ANY, configure_final, NULL);

volatile int ticks;
int cpu_disable_deep_sleep;

static int sysctl_kern_smp_active(SYSCTL_HANDLER_ARGS);

/* This is used in modules that need to work in both SMP and UP. */
cpuset_t all_cpus;

int mp_ncpus = 1;
/* export this for libkvm consumers. */
int mp_maxcpus = MAXCPU;

volatile int smp_started;
u_int mp_maxid;

static SYSCTL_NODE(_kern, OID_AUTO, smp, CTLFLAG_RD|CTLFLAG_CAPRD, NULL,
    "Kernel SMP");

SYSCTL_INT(_kern_smp, OID_AUTO, maxid, CTLFLAG_RD|CTLFLAG_CAPRD, &mp_maxid, 0,
    "Max CPU ID.");

SYSCTL_INT(_kern_smp, OID_AUTO, maxcpus, CTLFLAG_RD|CTLFLAG_CAPRD, &mp_maxcpus,
    0, "Max number of CPUs that the system was compiled for.");

SYSCTL_PROC(_kern_smp, OID_AUTO, active, CTLFLAG_RD | CTLTYPE_INT, NULL, 0,
    sysctl_kern_smp_active, "I", "Indicates system is running in SMP mode");

int smp_disabled = 0;	/* has smp been disabled? */
SYSCTL_INT(_kern_smp, OID_AUTO, disabled, CTLFLAG_RDTUN|CTLFLAG_CAPRD,
    &smp_disabled, 0, "SMP has been disabled from the loader");

int smp_cpus = 1;	/* how many cpu's running */
SYSCTL_INT(_kern_smp, OID_AUTO, cpus, CTLFLAG_RD|CTLFLAG_CAPRD, &smp_cpus, 0,
    "Number of CPUs online");

int smp_topology = 0;	/* Which topology we're using. */
SYSCTL_INT(_kern_smp, OID_AUTO, topology, CTLFLAG_RDTUN, &smp_topology, 0,
    "Topology override setting; 0 is default provided by hardware.");


long first_page = 0;

struct vmmeter vm_cnt;
vm_map_t kernel_map=0;
vm_map_t kmem_map=0;

vmem_t *kernel_arena = NULL;
vmem_t *kmem_arena = NULL;

struct vm_object kernel_object_store;
struct vm_object kmem_object_store;

struct filterops fs_filtops;
struct filterops sig_filtops;

int cold = 1;

int unmapped_buf_allowed = 1;

int cpu_deepest_sleep = 0;    /* Deepest Cx state available. */
int cpu_disable_c2_sleep = 0; /* Timer dies in C2. */
int cpu_disable_c3_sleep = 0; /* Timer dies in C3. */

static void timevalfix(struct timeval *);

/* Extra care is taken with this sysctl because the data type is volatile */
static int
sysctl_kern_smp_active(SYSCTL_HANDLER_ARGS)
{
	int error, active;

	active = smp_started;
	error = SYSCTL_OUT(req, &active, sizeof(active));
	return (error);
}

void
procinit()
{
    sx_init(&allproc_lock, "allproc");
    LIST_INIT(&allproc);
}


/*
 * Find a prison that is a descendant of mypr.  Returns a locked prison or NULL.
 */
struct prison *
prison_find_child(struct prison *mypr, int prid)
{
    return (NULL);
}

void
prison_free(struct prison *pr)
{

}

void
prison_hold_locked(struct prison *pr)
{

}

int
prison_if(struct ucred *cred, struct sockaddr *sa)
{
    return (0);
}

int
prison_check_af(struct ucred *cred, int af)
{
    return (0);
}

int
prison_check_ip4(const struct ucred *cred, const struct in_addr *ia)
{
    return (0);
}

int
prison_equal_ip4(struct prison *pr1, struct prison *pr2)
{
    return (1);
}

#ifdef INET6
int
prison_check_ip6(struct ucred *cred, struct in6_addr *ia)
{
    return (0);
}

int
prison_equal_ip6(struct prison *pr1, struct prison *pr2)
{
    return (1);
}
#endif

/*
 * See if a prison has the specific flag set.
 */
int
prison_flag(struct ucred *cred, unsigned flag)
{
    /* This is an atomic read, so no locking is necessary. */
    return (flag & PR_HOST);
}

int
prison_get_ip4(struct ucred *cred, struct in_addr *ia)
{
    return (0);
}

int
prison_local_ip4(struct ucred *cred, struct in_addr *ia)
{
    return (0);
}

int
prison_remote_ip4(struct ucred *cred, struct in_addr *ia)
{
    return (0);
}

#ifdef INET6
int
prison_get_ip6(struct ucred *cred, struct in6_addr *ia)
{
    return (0);
}

int
prison_local_ip6(struct ucred *cred, struct in6_addr *ia, int other)
{
    return (0);
}

int
prison_remote_ip6(struct ucred *cred, struct in6_addr *ia)
{
    return (0);
}
#endif

int 
prison_saddrsel_ip4(struct ucred *cred, struct in_addr *ia)
{
    /* not jailed */
    return (1);
}

#ifdef INET6
int 
prison_saddrsel_ip6(struct ucred *cred, struct in6_addr *ia)
{
    /* not jailed */
    return (1);
}
#endif

int
jailed(struct ucred *cred)
{
    return (0);
}

/*
 * Return 1 if the passed credential is in a jail and that jail does not
 * have its own virtual network stack, otherwise 0.
 */
int
jailed_without_vnet(struct ucred *cred)
{
    return (0);
}

int
priv_check(struct thread *td, int priv)
{
    return (0);
}

int
priv_check_cred(struct ucred *cred, int priv, int flags)
{
    return (0);
}


int
vslock(void *addr, size_t len)
{
    return (0);
}

void
vsunlock(void *addr, size_t len)
{

}


/*
 * Check that a proposed value to load into the .it_value or
 * .it_interval part of an interval timer is acceptable, and
 * fix it to have at least minimal value (i.e. if it is less
 * than the resolution of the clock, round it up.)
 */
int
itimerfix(struct timeval *tv)
{

    if (tv->tv_sec < 0 || tv->tv_usec < 0 || tv->tv_usec >= 1000000)
        return (EINVAL);
    if (tv->tv_sec == 0 && tv->tv_usec != 0 && tv->tv_usec < tick)
        tv->tv_usec = tick;
    return (0);
}

/*
 * Decrement an interval timer by a specified number
 * of microseconds, which must be less than a second,
 * i.e. < 1000000.  If the timer expires, then reload
 * it.  In this case, carry over (usec - old value) to
 * reduce the value reloaded into the timer so that
 * the timer does not drift.  This routine assumes
 * that it is called in a context where the timers
 * on which it is operating cannot change in value.
 */
int
itimerdecr(struct itimerval *itp, int usec)
{
    if (itp->it_value.tv_usec < usec) {
        if (itp->it_value.tv_sec == 0) {
            /* expired, and already in next interval */
            usec -= itp->it_value.tv_usec;
            goto expire;
        }
        itp->it_value.tv_usec += 1000000;
        itp->it_value.tv_sec--;
    }
    itp->it_value.tv_usec -= usec;
    usec = 0;
    if (timevalisset(&itp->it_value))
        return (1);
    /* expired, exactly at end of interval */
expire:
    if (timevalisset(&itp->it_interval)) {
        itp->it_value = itp->it_interval;
        itp->it_value.tv_usec -= usec;
        if (itp->it_value.tv_usec < 0) {
            itp->it_value.tv_usec += 1000000;
            itp->it_value.tv_sec--;
        }
    } else
        itp->it_value.tv_usec = 0;        /* sec is already 0 */
    return (0);
}

/*
 * Add and subtract routines for timevals.
 * N.B.: subtract routine doesn't deal with
 * results which are before the beginning,
 * it just gets very confused in this case.
 * Caveat emptor.
 */
void
timevaladd(struct timeval *t1, const struct timeval *t2)
{
    t1->tv_sec += t2->tv_sec;
    t1->tv_usec += t2->tv_usec;
    timevalfix(t1);
}

void
timevalsub(struct timeval *t1, const struct timeval *t2)
{
    t1->tv_sec -= t2->tv_sec;
    t1->tv_usec -= t2->tv_usec;
    timevalfix(t1);
}

static void
timevalfix(struct timeval *t1)
{
    if (t1->tv_usec < 0) {
        t1->tv_sec--;
        t1->tv_usec += 1000000;
    }
    if (t1->tv_usec >= 1000000) {
        t1->tv_sec++;
        t1->tv_usec -= 1000000;
    }
}

/*
 * ratecheck(): simple time-based rate-limit checking.
 */
int
ratecheck(struct timeval *lasttime, const struct timeval *mininterval)
{
    struct timeval tv, delta;
    int rv = 0;

    getmicrouptime(&tv);        /* NB: 10ms precision */
    delta = tv;
    timevalsub(&delta, lasttime);

    /*
     * check for 0,0 is so that the message will be seen at least once,
     * even if interval is huge.
     */
    if (timevalcmp(&delta, mininterval, >=) ||
        (lasttime->tv_sec == 0 && lasttime->tv_usec == 0)) {
        *lasttime = tv;
        rv = 1;
    }

    return (rv);
}

/*
 * ppsratecheck(): packets (or events) per second limitation.
 *
 * Return 0 if the limit is to be enforced (e.g. the caller
 * should drop a packet because of the rate limitation).
 *
 * maxpps of 0 always causes zero to be returned.  maxpps of -1
 * always causes 1 to be returned; this effectively defeats rate
 * limiting.
 *
 * Note that we maintain the struct timeval for compatibility
 * with other bsd systems.  We reuse the storage and just monitor
 * clock ticks for minimal overhead.  
 */
int
ppsratecheck(struct timeval *lasttime, int *curpps, int maxpps)
{
    int now;

    /*
     * Reset the last time and counter if this is the first call
     * or more than a second has passed since the last update of
     * lasttime.
     */
    now = ticks;
    if (lasttime->tv_sec == 0 || (u_int)(now - lasttime->tv_sec) >= hz) {
        lasttime->tv_sec = now;
        *curpps = 1;
        return (maxpps != 0);
    } else {
        (*curpps)++;        /* NB: ignore potential overflow */
        return (maxpps < 0 || *curpps < maxpps);
    }
}

/*
 * Compute number of ticks in the specified amount of time.
 */
int
tvtohz(tv)
    struct timeval *tv;
{
    register unsigned long ticks;
    register long sec, usec;

    /*
     * If the number of usecs in the whole seconds part of the time
     * difference fits in a long, then the total number of usecs will
     * fit in an unsigned long.  Compute the total and convert it to
     * ticks, rounding up and adding 1 to allow for the current tick
     * to expire.  Rounding also depends on unsigned long arithmetic
     * to avoid overflow.
     *
     * Otherwise, if the number of ticks in the whole seconds part of
     * the time difference fits in a long, then convert the parts to
     * ticks separately and add, using similar rounding methods and
     * overflow avoidance.  This method would work in the previous
     * case but it is slightly slower and assumes that hz is integral.
     *
     * Otherwise, round the time difference down to the maximum
     * representable value.
     *
     * If ints have 32 bits, then the maximum value for any timeout in
     * 10ms ticks is 248 days.
     */
    sec = tv->tv_sec;
    usec = tv->tv_usec;
    if (usec < 0) {
        sec--;
        usec += 1000000;
    }
    if (sec < 0) {
#ifdef DIAGNOSTIC
        if (usec > 0) {
            sec++;
            usec -= 1000000;
        }
        printf("tvotohz: negative time difference %ld sec %ld usec\n",
               sec, usec);
#endif
        ticks = 1;
    } else if (sec <= LONG_MAX / 1000000)
        ticks = (sec * 1000000 + (unsigned long)usec + (tick - 1))
            / tick + 1;
    else if (sec <= LONG_MAX / hz)
        ticks = sec * hz
            + ((unsigned long)usec + (tick - 1)) / tick + 1;
    else
        ticks = LONG_MAX;
    if (ticks > INT_MAX)
        ticks = INT_MAX;
    return ((int)ticks);
}

int
copyin(const void *uaddr, void *kaddr, size_t len)
{
    memcpy(kaddr, uaddr, len);
    return (0);
}

int
copyout(const void *kaddr, void *uaddr, size_t len)
{
    memcpy(uaddr, kaddr, len);
    return (0);
}

int
copystr(const void *kfaddr, void *kdaddr, size_t len, size_t *done)
{
    size_t bytes;

    bytes = strlcpy(kdaddr, kfaddr, len);
    if (done != NULL)
        *done = bytes;

    return (0);
}



int
copyinstr(const void *uaddr, void *kaddr, size_t len, size_t *done)
{    
    size_t bytes;

    bytes = strlcpy(kaddr, uaddr, len);
    if (done != NULL)
        *done = bytes;

    return (0);
}

int
copyiniov(const struct iovec *iovp, u_int iovcnt, struct iovec **iov, int error)
{
    u_int iovlen;

    *iov = NULL;
    if (iovcnt > UIO_MAXIOV)
        return (error);
    iovlen = iovcnt * sizeof (struct iovec);
    *iov = malloc(iovlen, M_IOV, M_WAITOK);
    error = copyin(iovp, *iov, iovlen);
    if (error) {
        free(*iov, M_IOV);
        *iov = NULL;
    }
    return (error);
}

int
subyte(volatile void *base, int byte)
{
    *(volatile char *)base = (uint8_t)byte;
    return (0);
}

static inline int
chglimit(struct uidinfo *uip, long *limit, int diff, rlim_t max, const char *name)
{
    /* Don't allow them to exceed max, but allow subtraction. */
    if (diff > 0 && max != 0) {
        if (atomic_fetchadd_long(limit, (long)diff) + diff > max) {
            atomic_subtract_long(limit, (long)diff);
            return (0);
        }
    } else {
        atomic_add_long(limit, (long)diff);
        if (*limit < 0)
            printf("negative %s for uid = %d\n", name, uip->ui_uid);
    }
    return (1);
}

/*
 * Change the count associated with number of processes
 * a given user is using.  When 'max' is 0, don't enforce a limit
 */
int
chgproccnt(struct uidinfo *uip, int diff, rlim_t max)
{
    return (chglimit(uip, &uip->ui_proccnt, diff, max, "proccnt"));
}

/*
 * Change the total socket buffer size a user has used.
 */
int
chgsbsize(struct uidinfo *uip, u_int *hiwat, u_int to, rlim_t max)
{
    int diff, rv;

    diff = to - *hiwat;
    if (diff > 0 && max == 0) {
        rv = 0;
    } else {
        rv = chglimit(uip, &uip->ui_sbsize, diff, max, "sbsize");
        if (rv != 0)
            *hiwat = to;
    }
    return (rv);
}

/*
 * Change the count associated with number of pseudo-terminals
 * a given user is using.  When 'max' is 0, don't enforce a limit
 */
int
chgptscnt(struct uidinfo *uip, int diff, rlim_t max)
{
    return (chglimit(uip, &uip->ui_ptscnt, diff, max, "ptscnt"));
}

int
chgkqcnt(struct uidinfo *uip, int diff, rlim_t max)
{
    return (chglimit(uip, &uip->ui_kqcnt, diff, max, "kqcnt"));
}

int
chgumtxcnt(struct uidinfo *uip, int diff, rlim_t max)
{
    return (chglimit(uip, &uip->ui_umtxcnt, diff, max, "umtxcnt"));
}

/*
 * Allocate a new resource limits structure and initialize its
 * reference count and mutex pointer.
 */
struct plimit *
lim_alloc()
{
    struct plimit *limp;

    limp = malloc(sizeof(struct plimit), M_PLIMIT, M_WAITOK);
    refcount_init(&limp->pl_refcnt, 1);
    return (limp);
}

struct plimit *
lim_hold(struct plimit *limp)
{
    refcount_acquire(&limp->pl_refcnt);
    return (limp);
}

/*
 * Return the current (soft) limit for a particular system resource.
 * The which parameter which specifies the index into the rlimit array
 */
rlim_t
lim_cur(struct thread *td, int which)
{
    struct rlimit rl;

    lim_rlimit(td, which, &rl);
    return (rl.rlim_cur);
}

rlim_t
lim_cur_proc(struct proc *p, int which)
{
    struct rlimit rl;

    lim_rlimit_proc(p, which, &rl);
    return (rl.rlim_cur);
}

/*
 * Return a copy of the entire rlimit structure for the system limit
 * specified by 'which' in the rlimit structure pointed to by 'rlp'.
 */
void
lim_rlimit(struct thread *td, int which, struct rlimit *rlp)
{
    struct proc *p = td->td_proc;

    MPASS(td == curthread);
    KASSERT(which >= 0 && which < RLIM_NLIMITS,
        ("request for invalid resource limit"));
    *rlp = p->p_limit->pl_rlimit[which];
    if (p->p_sysent->sv_fixlimit != NULL)
        p->p_sysent->sv_fixlimit(rlp, which);
}

void
lim_rlimit_proc(struct proc *p, int which, struct rlimit *rlp)
{
    PROC_LOCK_ASSERT(p, MA_OWNED);
    KASSERT(which >= 0 && which < RLIM_NLIMITS,
        ("request for invalid resource limit"));
    *rlp = p->p_limit->pl_rlimit[which];
    if (p->p_sysent->sv_fixlimit != NULL)
        p->p_sysent->sv_fixlimit(rlp, which);
}

int
useracc(void *addr, int len, int rw)
{
    return (1);
}

struct pgrp *
pgfind(pid_t pgid)
{
    return (NULL); 
}
       
struct proc *
zpfind(pid_t pid)
{
    return (NULL);
}


int
p_cansee(struct thread *td, struct proc *p)
{
    return (0);
}

struct proc *
pfind(pid_t pid)
{
    return (NULL);
}

int
pget(pid_t pid, int flags, struct proc **pp)
{
    return (ESRCH);
}

struct uidinfo uid0;

struct uidinfo *
uifind(uid_t uid)
{
    return (&uid0);
}

/*
 * Allocate a zeroed cred structure.
 */
struct ucred *
crget(void)
{
    register struct ucred *cr;

    cr = malloc(sizeof(*cr), M_CRED, M_WAITOK | M_ZERO);
    refcount_init(&cr->cr_ref, 1);

    return (cr);
}

/*
 * Claim another reference to a ucred structure.
 */
struct ucred *
crhold(struct ucred *cr)
{
    refcount_acquire(&cr->cr_ref);
    return (cr);
}

/*
 * Free a cred structure.  Throws away space when ref count gets to 0.
 */
void
crfree(struct ucred *cr)
{
    KASSERT(cr->cr_ref > 0, ("bad ucred refcount: %d", cr->cr_ref));
    KASSERT(cr->cr_ref != 0xdeadc0de, ("dangling reference to ucred"));
    if (refcount_release(&cr->cr_ref)) {

        free(cr, M_CRED);
    }
}

/*
 * Fill in a struct xucred based on a struct ucred.
 */

void
cru2x(struct ucred *cr, struct xucred *xcr)
{
#if 0
    int ngroups;

    bzero(xcr, sizeof(*xcr));
    xcr->cr_version = XUCRED_VERSION;
    xcr->cr_uid = cr->cr_uid;

    ngroups = MIN(cr->cr_ngroups, XU_NGROUPS);
    xcr->cr_ngroups = ngroups;
    bcopy(cr->cr_groups, xcr->cr_groups,
        ngroups * sizeof(*cr->cr_groups));
#endif
}


int
cr_cansee(struct ucred *u1, struct ucred *u2)
{
    return (0);
}

int
cr_canseesocket(struct ucred *cred, struct socket *so)
{
    return (0);
}

int
cr_canseeinpcb(struct ucred *cred, struct inpcb *inp)
{
    return (0);
}

int
securelevel_gt(struct ucred *cr, int level)
{
    return (0);
}

int
securelevel_ge(struct ucred *cr, int level)
{
        return (0);
}

/**
 * @brief Send a 'notification' to userland, using standard ways
 */
void
devctl_notify(const char *system, const char *subsystem, const char *type,
    const char *data)
{

}

void
cpu_pcpu_init(struct pcpu *pcpu, int cpuid, size_t size)
{

}

static void
configure_final(void *dummy)
{
    cold = 0;
}

/*
 * Send a SIGIO or SIGURG signal to a process or process group using stored
 * credentials rather than those of the current process.
 */
void
pgsigio(sigiop, sig, checkctty)
    struct sigio **sigiop;
    int sig, checkctty;
{
    panic("SIGIO not supported yet\n");
#ifdef notyet
    ksiginfo_t ksi;
    struct sigio *sigio;

    ksiginfo_init(&ksi);
    ksi.ksi_signo = sig;
    ksi.ksi_code = SI_KERNEL;

    SIGIO_LOCK();
    sigio = *sigiop;
    if (sigio == NULL) {
        SIGIO_UNLOCK();
        return;
    }
    if (sigio->sio_pgid > 0) {
        PROC_LOCK(sigio->sio_proc);
        if (CANSIGIO(sigio->sio_ucred, sigio->sio_proc->p_ucred))
            psignal(sigio->sio_proc, sig);
        PROC_UNLOCK(sigio->sio_proc);
    } else if (sigio->sio_pgid < 0) {
        struct proc *p;

        PGRP_LOCK(sigio->sio_pgrp);
        LIST_FOREACH(p, &sigio->sio_pgrp->pg_members, p_pglist) {
            PROC_LOCK(p);
            if (CANSIGIO(sigio->sio_ucred, p->p_ucred) &&
                (checkctty == 0 || (p->p_flag & P_CONTROLT)))
                psignal(p, sig);
            PROC_UNLOCK(p);
        }
        PGRP_UNLOCK(sigio->sio_pgrp);
    }
    SIGIO_UNLOCK();
#endif
}

void
kproc_exit(int ecode)
{
    panic("kproc_exit unsupported");
}

vm_offset_t
kmem_malloc(struct vmem *vmem, vm_size_t bytes, int flags)
{
    void *alloc = ff_mmap(NULL, bytes, ff_PROT_READ|ff_PROT_WRITE, ff_MAP_ANON|ff_MAP_PRIVATE, -1, 0);
    if ((flags & M_ZERO) && alloc != NULL)
        bzero(alloc, bytes);
    return ((vm_offset_t)alloc);
}

void
kmem_free(struct vmem *vmem, vm_offset_t addr, vm_size_t size)
{
    ff_munmap((void *)addr, size);
}

vm_offset_t
kmem_alloc_contig(struct vmem *vmem, vm_size_t size, int flags, vm_paddr_t low,
    vm_paddr_t high, u_long alignment, vm_paddr_t boundary, vm_memattr_t memattr)
{
    return (kmem_malloc(vmem, size, flags));
}

void
malloc_init(void *data)
{
    /* Nothing to do here */ 
}


void
malloc_uninit(void *data)
{
    /* Nothing to do here */ 
}


void *
malloc(unsigned long size, struct malloc_type *type, int flags)
{
    void *alloc;

    do {
        alloc = ff_malloc(size);
        if (alloc || !(flags & M_WAITOK))
            break;

        pause("malloc", hz/100);
    } while (alloc == NULL);

    if ((flags & M_ZERO) && alloc != NULL)
        bzero(alloc, size);
    return (alloc);
}

void
free(void *addr, struct malloc_type *type)
{
    ff_free(addr);
}


void *
realloc(void *addr, unsigned long size, struct malloc_type *type,
    int flags)
{
    return (ff_realloc(addr, size));
}

void *
reallocf(void *addr, unsigned long size, struct malloc_type *type,
     int flags)
{
    void *mem;

    if ((mem = ff_realloc(addr, size)) == NULL)
        ff_free(addr);

    return (mem);
}

void
DELAY(int delay)
{
    struct timespec rqt;

    if (delay < 1000)
        return;
    
    rqt.tv_nsec = 1000*((unsigned long)delay);
    rqt.tv_sec = 0;
    /*
     * FIXME: We shouldn't sleep in dpdk apps.
     */
    //nanosleep(&rqt, NULL);
}

void 
bwillwrite(void) 
{

}

off_t
foffset_lock(struct file *fp, int flags)
{
    struct mtx *mtxp;
    off_t res;

    KASSERT((flags & FOF_OFFSET) == 0, ("FOF_OFFSET passed"));

#if OFF_MAX <= LONG_MAX
    /*
     * Caller only wants the current f_offset value.  Assume that
     * the long and shorter integer types reads are atomic.
     */
    if ((flags & FOF_NOLOCK) != 0)
        return (fp->f_offset);
#endif

    /*
     * According to McKusick the vn lock was protecting f_offset here.
     * It is now protected by the FOFFSET_LOCKED flag.
     */
    mtxp = mtx_pool_find(mtxpool_sleep, fp);
    mtx_lock(mtxp);
    /*
    if ((flags & FOF_NOLOCK) == 0) {
        while (fp->f_vnread_flags & FOFFSET_LOCKED) {
            fp->f_vnread_flags |= FOFFSET_LOCK_WAITING;
            msleep(&fp->f_vnread_flags, mtxp, PUSER -1,
                "vofflock", 0);
        }
        fp->f_vnread_flags |= FOFFSET_LOCKED;
    }
    */
    res = fp->f_offset;
    mtx_unlock(mtxp);
    return (res);
}

void
sf_ext_free(void *arg1, void *arg2)
{
    panic("sf_ext_free not implemented.\n");
}

void
sf_ext_free_nocache(void *arg1, void *arg2)
{
    panic("sf_ext_free_nocache not implemented.\n");
}

void
sched_bind(struct thread *td, int cpu)
{

}

void
sched_unbind(struct thread* td)
{

}

void
getcredhostid(struct ucred *cred, unsigned long *hostid)
{
    *hostid = 0;
}

/*
 * Check if gid is a member of the group set.
 */
int
groupmember(gid_t gid, struct ucred *cred)
{
	int l;
	int h;
	int m;

	if (cred->cr_groups[0] == gid)
		return(1);

	/*
	 * If gid was not our primary group, perform a binary search
	 * of the supplemental groups.  This is possible because we
	 * sort the groups in crsetgroups().
	 */
	l = 1;
	h = cred->cr_ngroups;
	while (l < h) {
		m = l + ((h - l) / 2);
		if (cred->cr_groups[m] < gid)
			l = m + 1; 
		else
			h = m; 
	}
	if ((l < cred->cr_ngroups) && (cred->cr_groups[l] == gid))
		return (1);

	return (0);
}

