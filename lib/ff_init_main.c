/*-
 * Copyright (c) 1995 Terrence R. Lambert
 * All rights reserved.
 *
 * Copyright (c) 1982, 1986, 1989, 1991, 1992, 1993
 *  The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *  This product includes software developed by the University of
 *  California, Berkeley and its contributors.
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
 *  @(#)init_main.c 8.9 (Berkeley) 1/21/94
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_ddb.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/exec.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/jail.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/systm.h>
#include <sys/signalvar.h>
#include <sys/sysent.h>
#include <sys/reboot.h>
#include <sys/sched.h>
#include <sys/sx.h>
#include <sys/sysproto.h>
#include <sys/vmmeter.h>
#include <sys/unistd.h>
#include <sys/malloc.h>
#include <sys/conf.h>
#include <sys/cpuset.h>
#include <sys/eventhandler.h>

#include <machine/cpu.h>

#include <security/audit/audit.h>
#include <security/mac/mac_framework.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <sys/copyright.h>

#include <ddb/ddb.h>
#include <ddb/db_sym.h>

void mi_startup(void); /* Should be elsewhere */

/* Components of the first process -- never freed. */
struct proc proc0;
struct prison prison0;
struct thread0_storage thread0_st __aligned(16);
struct vmspace vmspace0;
struct proc *initproc;
#if 0
int    boothowto = 0;        /* initialized so that it can be patched */
SYSCTL_INT(_debug, OID_AUTO, boothowto, CTLFLAG_RD, &boothowto, 0, "");
int    bootverbose;
SYSCTL_INT(_debug, OID_AUTO, bootverbose, CTLFLAG_RW, &bootverbose, 0, "");
#endif

//#define VERBOSE_SYSINIT


/*
 * This ensures that there is at least one entry so that the sysinit_set
 * symbol is not undefined.  A sybsystem ID of SI_SUB_DUMMY is never
 * executed.
 */
SYSINIT(placeholder, SI_SUB_DUMMY, SI_ORDER_ANY, NULL, NULL);

/*
 * The sysinit table itself.  Items are checked off as the are run.
 * If we want to register new sysinit types, add them to newsysinit.
 */
SET_DECLARE(sysinit_set, struct sysinit);
struct sysinit **sysinit, **sysinit_end;
struct sysinit **newsysinit, **newsysinit_end;

/*
 * Merge a new sysinit set into the current set, reallocating it if
 * necessary.  This can only be called after malloc is running.
 */
void
sysinit_add(struct sysinit **set, struct sysinit **set_end)
{
    struct sysinit **newset;
    struct sysinit **sipp;
    struct sysinit **xipp;
    int count;

    count = set_end - set;
    if (newsysinit)
        count += newsysinit_end - newsysinit;
    else
        count += sysinit_end - sysinit;
    newset = malloc(count * sizeof(*sipp), M_TEMP, M_NOWAIT);
    if (newset == NULL)
        panic("cannot malloc for sysinit");
    xipp = newset;
    if (newsysinit)
        for (sipp = newsysinit; sipp < newsysinit_end; sipp++)
            *xipp++ = *sipp;
    else
        for (sipp = sysinit; sipp < sysinit_end; sipp++)
            *xipp++ = *sipp;
    for (sipp = set; sipp < set_end; sipp++)
        *xipp++ = *sipp;
    if (newsysinit)
        free(newsysinit, M_TEMP);
    newsysinit = newset;
    newsysinit_end = newset + count;
}


/*
 * System startup; initialize the world, create process 0, mount root
 * filesystem, and fork to create init and pagedaemon.  Most of the
 * hard work is done in the lower-level initialization routines including
 * startup(), which does memory initialization and autoconfiguration.
 *
 * This allows simple addition of new kernel subsystems that require
 * boot time initialization.  It also allows substitution of subsystem
 * (for instance, a scheduler, kernel profiler, or VM system) by object
 * module.  Finally, it allows for optional "kernel threads".
 */
void
mi_startup(void)
{

    register struct sysinit **sipp;        /* system initialization*/
    register struct sysinit **xipp;        /* interior loop of sort*/
    register struct sysinit *save;        /* bubble*/
    struct sysinit **temp;
    int size;

#ifdef VERBOSE_SYSINIT
    int last;
    int verbose;
#endif

    if (sysinit == NULL) {        
        sysinit = SET_BEGIN(sysinit_set);
        sysinit_end = SET_LIMIT(sysinit_set);
        size = (uintptr_t)sysinit_end - (uintptr_t)sysinit;
        temp = malloc(size, M_DEVBUF, M_WAITOK);
        memcpy(temp, sysinit, size);
        sysinit = temp;
        sysinit_end = (struct sysinit **)(((uint8_t *)sysinit) + size);
    }

restart:
    /*
     * Perform a bubble sort of the system initialization objects by
     * their subsystem (primary key) and order (secondary key).
     */
    for (sipp = sysinit; sipp < sysinit_end; sipp++) {
        for (xipp = sipp + 1; xipp < sysinit_end; xipp++) {
            if ((*sipp)->subsystem < (*xipp)->subsystem ||
                 ((*sipp)->subsystem == (*xipp)->subsystem &&
                  (*sipp)->order <= (*xipp)->order))
                continue;    /* skip*/
            save = *sipp;
            *sipp = *xipp;
            *xipp = save;
        }
    }

#ifdef VERBOSE_SYSINIT
    last = SI_SUB_COPYRIGHT;
    verbose = 0;
#ifndef DDB
    printf("VERBOSE_SYSINIT: DDB not enabled, symbol lookups disabled.\n");
#endif
#endif

    /*
     * Traverse the (now) ordered list of system initialization tasks.
     * Perform each task, and continue on to the next task.
     *
     * The last item on the list is expected to be the scheduler,
     * which will not return.
     */
    for (sipp = sysinit; sipp < sysinit_end; sipp++) {

        if ((*sipp)->subsystem == SI_SUB_DUMMY)
            continue;    /* skip dummy task(s)*/

        if ((*sipp)->subsystem == SI_SUB_DONE)
            continue;

#ifdef VERBOSE_SYSINIT
        if ((*sipp)->subsystem > last) {
            verbose = 1;
            last = (*sipp)->subsystem;
            printf("subsystem %x\n", last);
        }
        if (verbose) {
#ifdef DDB
            const char *name;
            c_db_sym_t sym;
            db_expr_t  offset;

            sym = db_search_symbol((vm_offset_t)(*sipp)->func,
                DB_STGY_PROC, &offset);
            db_symbol_values(sym, &name, NULL);
            if (name != NULL)
                printf("   %s(%p)... ", name, (*sipp)->udata);
            else
#endif
                printf("   %p(%p)... ", (*sipp)->func,
                    (*sipp)->udata);
        }
#endif

        /* Call function */
        (*((*sipp)->func))((*sipp)->udata);

#ifdef VERBOSE_SYSINIT
        if (verbose)
            printf("done.\n");
#endif

        /* Check off the one we're just done */
        (*sipp)->subsystem = SI_SUB_DONE;

        /* Check if we've installed more sysinit items via KLD */
        if (newsysinit != NULL) {
            if (sysinit != SET_BEGIN(sysinit_set))
                free(sysinit, M_TEMP);
            sysinit = newsysinit;
            sysinit_end = newsysinit_end;
            newsysinit = NULL;
            newsysinit_end = NULL;
            goto restart;
        }
    }

}

static int
null_fetch_syscall_args(struct thread *td __unused)
{

    panic("null_fetch_syscall_args");
}

static void
null_set_syscall_retval(struct thread *td __unused, int error __unused)
{

    panic("null_set_syscall_retval");
}

struct sysentvec null_sysvec = {
    .sv_size    = 0,
    .sv_table    = NULL,
    .sv_transtrap    = NULL,
    .sv_fixup    = NULL,
    .sv_sendsig    = NULL,
    .sv_sigcode    = NULL,
    .sv_szsigcode    = NULL,
    .sv_name    = "null",
    .sv_coredump    = NULL,
    .sv_imgact_try    = NULL,
    .sv_minsigstksz    = 0,
    .sv_minuser    = VM_MIN_ADDRESS,
    .sv_maxuser    = VM_MAXUSER_ADDRESS,
    .sv_usrstack    = USRSTACK,
    .sv_psstrings    = PS_STRINGS,
    .sv_stackprot    = VM_PROT_ALL,
    .sv_copyout_strings    = NULL,
    .sv_setregs    = NULL,
    .sv_fixlimit    = NULL,
    .sv_maxssiz    = NULL,
    .sv_flags    = 0,
    .sv_set_syscall_retval = null_set_syscall_retval,
    .sv_fetch_syscall_args = null_fetch_syscall_args,
    .sv_syscallnames = NULL,
    .sv_schedtail    = NULL,
    .sv_thread_detach = NULL,
    .sv_trap    = NULL,

};

/*
 ***************************************************************************
 ****
 **** The two following SYSINIT's are proc0 specific glue code.  I am not
 **** convinced that they can not be safely combined, but their order of
 **** operation has been maintained as the same as the original init_main.c
 **** for right now.
 ****
 **** These probably belong in init_proc.c or kern_proc.c, since they
 **** deal with proc0 (the fork template process).
 ****
 ***************************************************************************
 */
/* ARGSUSED*/
static void
proc0_init(void *dummy __unused)
{
    struct proc *p;
    struct thread *td;

    vm_paddr_t pageablemem;
    int i;

    GIANT_REQUIRED;

    p = &proc0;
    td = &thread0;
    init_param1();
    init_param2(physmem);

    /*
     * Initialize magic number and osrel.
     */
    p->p_magic = P_MAGIC;

#if 0
    p->p_osrel = osreldate;


    /*
     * Initialize thread and process structures.
     */
    procinit();    /* set up proc zone */
    threadinit();    /* set up UMA zones */

    /*
     * Initialise scheduler resources.
     * Add scheduler specific parts to proc, thread as needed.
     */
    schedinit();    /* scheduler gets its house in order */
    /*
     * Initialize sleep queue hash table
     */
    sleepinit();

    /*
     * additional VM structures
     */
    vm_init2();

    /*
     * Create process 0 (the swapper).
     */
    LIST_INSERT_HEAD(&allproc, p, p_list);
    LIST_INSERT_HEAD(PIDHASH(0), p, p_hash);
    mtx_init(&pgrp0.pg_mtx, "process group", NULL, MTX_DEF | MTX_DUPOK);
    p->p_pgrp = &pgrp0;
    LIST_INSERT_HEAD(PGRPHASH(0), &pgrp0, pg_hash);
    LIST_INIT(&pgrp0.pg_members);
    LIST_INSERT_HEAD(&pgrp0.pg_members, p, p_pglist);

    pgrp0.pg_session = &session0;

    mtx_init(&session0.s_mtx, "session", NULL, MTX_DEF);
    refcount_init(&session0.s_count, 1);
    session0.s_leader = p;
#endif
    p->p_sysent = &null_sysvec;
    p->p_flag = P_SYSTEM | P_INMEM;
    p->p_state = PRS_NORMAL;
    p->p_klist = knlist_alloc(&p->p_mtx);
    STAILQ_INIT(&p->p_ktr);
    p->p_nice = NZERO;
    td->td_tid = PID_MAX + 1;
#if 0
    LIST_INSERT_HEAD(TIDHASH(td->td_tid), td, td_hash);
#endif
    td->td_state = TDS_RUNNING;
    td->td_pri_class = PRI_TIMESHARE;
    td->td_user_pri = PUSER;
    td->td_base_user_pri = PUSER;
    td->td_priority = PVM;
    td->td_base_pri = PUSER;
    td->td_oncpu = 0;
    td->td_flags = TDF_INMEM|TDP_KTHREAD;
    td->td_proc = p;
#if 0
    td->td_cpuset = cpuset_thread0();
    prison0.pr_cpuset = cpuset_ref(td->td_cpuset);
#endif
    p->p_peers = 0;
    p->p_leader = p;


    strncpy(p->p_comm, "kernel", sizeof (p->p_comm));
    strncpy(td->td_name, "swapper", sizeof (td->td_name));

    callout_init(&p->p_itcallout, CALLOUT_MPSAFE);
    callout_init_mtx(&p->p_limco, &p->p_mtx, 0);
    callout_init(&td->td_slpcallout, CALLOUT_MPSAFE);

    /* Create credentials. */
    p->p_ucred = crget();
    p->p_ucred->cr_ngroups = 1;    /* group 0 */
    p->p_ucred->cr_uidinfo = uifind(0);
    p->p_ucred->cr_ruidinfo = uifind(0);
    p->p_ucred->cr_prison = &prison0;

#ifdef AUDIT
    audit_cred_kproc0(p->p_ucred);
#endif
#ifdef MAC
    mac_cred_create_swapper(p->p_ucred);
#endif

    td->td_ucred = crhold(p->p_ucred);
#if 0

    /* Create sigacts. */
    p->p_sigacts = sigacts_alloc();

    /* Initialize signal state for process 0. */
    siginit(&proc0);
#endif

    /* Create the file descriptor table. */
    p->p_fd = fdinit(NULL, false, NULL);
    p->p_fdtol = NULL;


    /* Create the limits structures. */
    p->p_limit = lim_alloc();
    for (i = 0; i < RLIM_NLIMITS; i++)
        p->p_limit->pl_rlimit[i].rlim_cur =
            p->p_limit->pl_rlimit[i].rlim_max = RLIM_INFINITY;
    p->p_limit->pl_rlimit[RLIMIT_NOFILE].rlim_cur =
        p->p_limit->pl_rlimit[RLIMIT_NOFILE].rlim_max = maxfiles;
    p->p_limit->pl_rlimit[RLIMIT_NPROC].rlim_cur =
        p->p_limit->pl_rlimit[RLIMIT_NPROC].rlim_max = maxproc;
    p->p_limit->pl_rlimit[RLIMIT_DATA].rlim_cur = dfldsiz;
    p->p_limit->pl_rlimit[RLIMIT_DATA].rlim_max = maxdsiz;
    p->p_limit->pl_rlimit[RLIMIT_STACK].rlim_cur = dflssiz;
    p->p_limit->pl_rlimit[RLIMIT_STACK].rlim_max = maxssiz;
    /* Cast to avoid overflow on i386/PAE. */
    pageablemem = ptoa((vm_paddr_t)vm_free_count());
    p->p_limit->pl_rlimit[RLIMIT_RSS].rlim_cur =
        p->p_limit->pl_rlimit[RLIMIT_RSS].rlim_max = pageablemem;
    p->p_limit->pl_rlimit[RLIMIT_MEMLOCK].rlim_cur = pageablemem / 3;
    p->p_limit->pl_rlimit[RLIMIT_MEMLOCK].rlim_max = pageablemem;
    p->p_cpulimit = RLIM_INFINITY;

#if 0
    p->p_stats = pstats_alloc();

    /* Allocate a prototype map so we have something to fork. */
    pmap_pinit0(vmspace_pmap(&vmspace0));
    p->p_vmspace = &vmspace0;
    vmspace0.vm_refcnt = 1;

    /*
     * proc0 is not expected to enter usermode, so there is no special
     * handling for sv_minuser here, like is done for exec_new_vmspace().
     */
    vm_map_init(&vmspace0.vm_map, vmspace_pmap(&vmspace0),
        p->p_sysent->sv_minuser, p->p_sysent->sv_maxuser);
#endif

    /*
     * Call the init and ctor for the new thread and proc.  We wait
     * to do this until all other structures are fairly sane.
     */
    EVENTHANDLER_INVOKE(process_init, p);
    EVENTHANDLER_INVOKE(thread_init, td);
    EVENTHANDLER_INVOKE(process_ctor, p);
    EVENTHANDLER_INVOKE(thread_ctor, td);

#if 0
    /*
     * Charge root for one process.
     */
    (void)chgproccnt(p->p_ucred->cr_ruidinfo, 1, 0);
#endif
}
SYSINIT(p0init, SI_SUB_INTRINSIC, SI_ORDER_FIRST, proc0_init, NULL);

/* ARGSUSED*/
static void
proc0_post(void *dummy __unused)
{
#if 0
    struct timespec ts;
    /*
     * Give the ``random'' number generator a thump.
     */
    nanotime(&ts);
    srandom(ts.tv_sec ^ ts.tv_nsec);
#endif
}
SYSINIT(p0post, SI_SUB_INTRINSIC_POST, SI_ORDER_FIRST, proc0_post, NULL);
