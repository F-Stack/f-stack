/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
 *	The Regents of the University of California. All Rights Reserved.
 * Copyright (c) 2004-2009 Robert N. M. Watson All Rights Reserved.
 * Copyright (c) 2018 Matthew Macy
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
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
 *	From: @(#)uipc_usrreq.c	8.3 (Berkeley) 1/4/94
 */

/*
 * UNIX Domain (Local) Sockets
 *
 * This is an implementation of UNIX (local) domain sockets.  Each socket has
 * an associated struct unpcb (UNIX protocol control block).  Stream sockets
 * may be connected to 0 or 1 other socket.  Datagram sockets may be
 * connected to 0, 1, or many other sockets.  Sockets may be created and
 * connected in pairs (socketpair(2)), or bound/connected to using the file
 * system name space.  For most purposes, only the receive socket buffer is
 * used, as sending on one socket delivers directly to the receive socket
 * buffer of a second socket.
 *
 * The implementation is substantially complicated by the fact that
 * "ancillary data", such as file descriptors or credentials, may be passed
 * across UNIX domain sockets.  The potential for passing UNIX domain sockets
 * over other UNIX domain sockets requires the implementation of a simple
 * garbage collector to find and tear down cycles of disconnected sockets.
 *
 * TODO:
 *	RDM
 *	rethink name space problems
 *	need a proper out-of-band
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_ddb.h"

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/domain.h>
#include <sys/eventhandler.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/queue.h>
#include <sys/resourcevar.h>
#include <sys/rwlock.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/signalvar.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/taskqueue.h>
#include <sys/un.h>
#include <sys/unpcb.h>
#include <sys/vnode.h>

#include <net/vnet.h>

#ifdef DDB
#include <ddb/ddb.h>
#endif

#include <security/mac/mac_framework.h>

#include <vm/uma.h>

MALLOC_DECLARE(M_FILECAPS);

/*
 * See unpcb.h for the locking key.
 */

static uma_zone_t	unp_zone;
static unp_gen_t	unp_gencnt;	/* (l) */
static u_int		unp_count;	/* (l) Count of local sockets. */
static ino_t		unp_ino;	/* Prototype for fake inode numbers. */
static int		unp_rights;	/* (g) File descriptors in flight. */
static struct unp_head	unp_shead;	/* (l) List of stream sockets. */
static struct unp_head	unp_dhead;	/* (l) List of datagram sockets. */
static struct unp_head	unp_sphead;	/* (l) List of seqpacket sockets. */

struct unp_defer {
	SLIST_ENTRY(unp_defer) ud_link;
	struct file *ud_fp;
};
static SLIST_HEAD(, unp_defer) unp_defers;
static int unp_defers_count;

static const struct sockaddr	sun_noname = { sizeof(sun_noname), AF_LOCAL };

/*
 * Garbage collection of cyclic file descriptor/socket references occurs
 * asynchronously in a taskqueue context in order to avoid recursion and
 * reentrance in the UNIX domain socket, file descriptor, and socket layer
 * code.  See unp_gc() for a full description.
 */
static struct timeout_task unp_gc_task;

/*
 * The close of unix domain sockets attached as SCM_RIGHTS is
 * postponed to the taskqueue, to avoid arbitrary recursion depth.
 * The attached sockets might have another sockets attached.
 */
static struct task	unp_defer_task;

/*
 * Both send and receive buffers are allocated PIPSIZ bytes of buffering for
 * stream sockets, although the total for sender and receiver is actually
 * only PIPSIZ.
 *
 * Datagram sockets really use the sendspace as the maximum datagram size,
 * and don't really want to reserve the sendspace.  Their recvspace should be
 * large enough for at least one max-size datagram plus address.
 */
#ifndef PIPSIZ
#define	PIPSIZ	8192
#endif
static u_long	unpst_sendspace = PIPSIZ;
static u_long	unpst_recvspace = PIPSIZ;
static u_long	unpdg_sendspace = 2*1024;	/* really max datagram size */
static u_long	unpdg_recvspace = 4*1024;
static u_long	unpsp_sendspace = PIPSIZ;	/* really max datagram size */
static u_long	unpsp_recvspace = PIPSIZ;

static SYSCTL_NODE(_net, PF_LOCAL, local, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Local domain");
static SYSCTL_NODE(_net_local, SOCK_STREAM, stream,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "SOCK_STREAM");
static SYSCTL_NODE(_net_local, SOCK_DGRAM, dgram,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "SOCK_DGRAM");
static SYSCTL_NODE(_net_local, SOCK_SEQPACKET, seqpacket,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "SOCK_SEQPACKET");

SYSCTL_ULONG(_net_local_stream, OID_AUTO, sendspace, CTLFLAG_RW,
	   &unpst_sendspace, 0, "Default stream send space.");
SYSCTL_ULONG(_net_local_stream, OID_AUTO, recvspace, CTLFLAG_RW,
	   &unpst_recvspace, 0, "Default stream receive space.");
SYSCTL_ULONG(_net_local_dgram, OID_AUTO, maxdgram, CTLFLAG_RW,
	   &unpdg_sendspace, 0, "Default datagram send space.");
SYSCTL_ULONG(_net_local_dgram, OID_AUTO, recvspace, CTLFLAG_RW,
	   &unpdg_recvspace, 0, "Default datagram receive space.");
SYSCTL_ULONG(_net_local_seqpacket, OID_AUTO, maxseqpacket, CTLFLAG_RW,
	   &unpsp_sendspace, 0, "Default seqpacket send space.");
SYSCTL_ULONG(_net_local_seqpacket, OID_AUTO, recvspace, CTLFLAG_RW,
	   &unpsp_recvspace, 0, "Default seqpacket receive space.");
SYSCTL_INT(_net_local, OID_AUTO, inflight, CTLFLAG_RD, &unp_rights, 0,
    "File descriptors in flight.");
SYSCTL_INT(_net_local, OID_AUTO, deferred, CTLFLAG_RD,
    &unp_defers_count, 0,
    "File descriptors deferred to taskqueue for close.");

/*
 * Locking and synchronization:
 *
 * Several types of locks exist in the local domain socket implementation:
 * - a global linkage lock
 * - a global connection list lock
 * - the mtxpool lock
 * - per-unpcb mutexes
 *
 * The linkage lock protects the global socket lists, the generation number
 * counter and garbage collector state.
 *
 * The connection list lock protects the list of referring sockets in a datagram
 * socket PCB.  This lock is also overloaded to protect a global list of
 * sockets whose buffers contain socket references in the form of SCM_RIGHTS
 * messages.  To avoid recursion, such references are released by a dedicated
 * thread.
 *
 * The mtxpool lock protects the vnode from being modified while referenced.
 * Lock ordering rules require that it be acquired before any PCB locks.
 *
 * The unpcb lock (unp_mtx) protects the most commonly referenced fields in the
 * unpcb.  This includes the unp_conn field, which either links two connected
 * PCBs together (for connected socket types) or points at the destination
 * socket (for connectionless socket types).  The operations of creating or
 * destroying a connection therefore involve locking multiple PCBs.  To avoid
 * lock order reversals, in some cases this involves dropping a PCB lock and
 * using a reference counter to maintain liveness.
 *
 * UNIX domain sockets each have an unpcb hung off of their so_pcb pointer,
 * allocated in pru_attach() and freed in pru_detach().  The validity of that
 * pointer is an invariant, so no lock is required to dereference the so_pcb
 * pointer if a valid socket reference is held by the caller.  In practice,
 * this is always true during operations performed on a socket.  Each unpcb
 * has a back-pointer to its socket, unp_socket, which will be stable under
 * the same circumstances.
 *
 * This pointer may only be safely dereferenced as long as a valid reference
 * to the unpcb is held.  Typically, this reference will be from the socket,
 * or from another unpcb when the referring unpcb's lock is held (in order
 * that the reference not be invalidated during use).  For example, to follow
 * unp->unp_conn->unp_socket, you need to hold a lock on unp_conn to guarantee
 * that detach is not run clearing unp_socket.
 *
 * Blocking with UNIX domain sockets is a tricky issue: unlike most network
 * protocols, bind() is a non-atomic operation, and connect() requires
 * potential sleeping in the protocol, due to potentially waiting on local or
 * distributed file systems.  We try to separate "lookup" operations, which
 * may sleep, and the IPC operations themselves, which typically can occur
 * with relative atomicity as locks can be held over the entire operation.
 *
 * Another tricky issue is simultaneous multi-threaded or multi-process
 * access to a single UNIX domain socket.  These are handled by the flags
 * UNP_CONNECTING and UNP_BINDING, which prevent concurrent connecting or
 * binding, both of which involve dropping UNIX domain socket locks in order
 * to perform namei() and other file system operations.
 */
static struct rwlock	unp_link_rwlock;
static struct mtx	unp_defers_lock;

#define	UNP_LINK_LOCK_INIT()		rw_init(&unp_link_rwlock,	\
					    "unp_link_rwlock")

#define	UNP_LINK_LOCK_ASSERT()		rw_assert(&unp_link_rwlock,	\
					    RA_LOCKED)
#define	UNP_LINK_UNLOCK_ASSERT()	rw_assert(&unp_link_rwlock,	\
					    RA_UNLOCKED)

#define	UNP_LINK_RLOCK()		rw_rlock(&unp_link_rwlock)
#define	UNP_LINK_RUNLOCK()		rw_runlock(&unp_link_rwlock)
#define	UNP_LINK_WLOCK()		rw_wlock(&unp_link_rwlock)
#define	UNP_LINK_WUNLOCK()		rw_wunlock(&unp_link_rwlock)
#define	UNP_LINK_WLOCK_ASSERT()		rw_assert(&unp_link_rwlock,	\
					    RA_WLOCKED)
#define	UNP_LINK_WOWNED()		rw_wowned(&unp_link_rwlock)

#define	UNP_DEFERRED_LOCK_INIT()	mtx_init(&unp_defers_lock, \
					    "unp_defer", NULL, MTX_DEF)
#define	UNP_DEFERRED_LOCK()		mtx_lock(&unp_defers_lock)
#define	UNP_DEFERRED_UNLOCK()		mtx_unlock(&unp_defers_lock)

#define UNP_REF_LIST_LOCK()		UNP_DEFERRED_LOCK();
#define UNP_REF_LIST_UNLOCK()		UNP_DEFERRED_UNLOCK();

#define UNP_PCB_LOCK_INIT(unp)		mtx_init(&(unp)->unp_mtx,	\
					    "unp", "unp",	\
					    MTX_DUPOK|MTX_DEF)
#define	UNP_PCB_LOCK_DESTROY(unp)	mtx_destroy(&(unp)->unp_mtx)
#define	UNP_PCB_LOCKPTR(unp)		(&(unp)->unp_mtx)
#define	UNP_PCB_LOCK(unp)		mtx_lock(&(unp)->unp_mtx)
#define	UNP_PCB_TRYLOCK(unp)		mtx_trylock(&(unp)->unp_mtx)
#define	UNP_PCB_UNLOCK(unp)		mtx_unlock(&(unp)->unp_mtx)
#define	UNP_PCB_OWNED(unp)		mtx_owned(&(unp)->unp_mtx)
#define	UNP_PCB_LOCK_ASSERT(unp)	mtx_assert(&(unp)->unp_mtx, MA_OWNED)
#define	UNP_PCB_UNLOCK_ASSERT(unp)	mtx_assert(&(unp)->unp_mtx, MA_NOTOWNED)

static int	uipc_connect2(struct socket *, struct socket *);
static int	uipc_ctloutput(struct socket *, struct sockopt *);
static int	unp_connect(struct socket *, struct sockaddr *,
		    struct thread *);
static int	unp_connectat(int, struct socket *, struct sockaddr *,
		    struct thread *);
static int	unp_connect2(struct socket *so, struct socket *so2, int);
static void	unp_disconnect(struct unpcb *unp, struct unpcb *unp2);
static void	unp_dispose(struct socket *so);
static void	unp_dispose_mbuf(struct mbuf *);
static void	unp_shutdown(struct unpcb *);
static void	unp_drop(struct unpcb *);
static void	unp_gc(__unused void *, int);
static void	unp_scan(struct mbuf *, void (*)(struct filedescent **, int));
static void	unp_discard(struct file *);
static void	unp_freerights(struct filedescent **, int);
static void	unp_init(void);
static int	unp_internalize(struct mbuf **, struct thread *);
static void	unp_internalize_fp(struct file *);
static int	unp_externalize(struct mbuf *, struct mbuf **, int);
static int	unp_externalize_fp(struct file *);
static struct mbuf	*unp_addsockcred(struct thread *, struct mbuf *, int);
static void	unp_process_defers(void * __unused, int);

static void
unp_pcb_hold(struct unpcb *unp)
{
	u_int old __unused;

	old = refcount_acquire(&unp->unp_refcount);
	KASSERT(old > 0, ("%s: unpcb %p has no references", __func__, unp));
}

static __result_use_check bool
unp_pcb_rele(struct unpcb *unp)
{
	bool ret;

	UNP_PCB_LOCK_ASSERT(unp);

	if ((ret = refcount_release(&unp->unp_refcount))) {
		UNP_PCB_UNLOCK(unp);
		UNP_PCB_LOCK_DESTROY(unp);
		uma_zfree(unp_zone, unp);
	}
	return (ret);
}

static void
unp_pcb_rele_notlast(struct unpcb *unp)
{
	bool ret __unused;

	ret = refcount_release(&unp->unp_refcount);
	KASSERT(!ret, ("%s: unpcb %p has no references", __func__, unp));
}

static void
unp_pcb_lock_pair(struct unpcb *unp, struct unpcb *unp2)
{
	UNP_PCB_UNLOCK_ASSERT(unp);
	UNP_PCB_UNLOCK_ASSERT(unp2);

	if (unp == unp2) {
		UNP_PCB_LOCK(unp);
	} else if ((uintptr_t)unp2 > (uintptr_t)unp) {
		UNP_PCB_LOCK(unp);
		UNP_PCB_LOCK(unp2);
	} else {
		UNP_PCB_LOCK(unp2);
		UNP_PCB_LOCK(unp);
	}
}

static void
unp_pcb_unlock_pair(struct unpcb *unp, struct unpcb *unp2)
{
	UNP_PCB_UNLOCK(unp);
	if (unp != unp2)
		UNP_PCB_UNLOCK(unp2);
}

/*
 * Try to lock the connected peer of an already locked socket.  In some cases
 * this requires that we unlock the current socket.  The pairbusy counter is
 * used to block concurrent connection attempts while the lock is dropped.  The
 * caller must be careful to revalidate PCB state.
 */
static struct unpcb *
unp_pcb_lock_peer(struct unpcb *unp)
{
	struct unpcb *unp2;

	UNP_PCB_LOCK_ASSERT(unp);
	unp2 = unp->unp_conn;
	if (unp2 == NULL)
		return (NULL);
	if (__predict_false(unp == unp2))
		return (unp);

	UNP_PCB_UNLOCK_ASSERT(unp2);

	if (__predict_true(UNP_PCB_TRYLOCK(unp2)))
		return (unp2);
	if ((uintptr_t)unp2 > (uintptr_t)unp) {
		UNP_PCB_LOCK(unp2);
		return (unp2);
	}
	unp->unp_pairbusy++;
	unp_pcb_hold(unp2);
	UNP_PCB_UNLOCK(unp);

	UNP_PCB_LOCK(unp2);
	UNP_PCB_LOCK(unp);
	KASSERT(unp->unp_conn == unp2 || unp->unp_conn == NULL,
	    ("%s: socket %p was reconnected", __func__, unp));
	if (--unp->unp_pairbusy == 0 && (unp->unp_flags & UNP_WAITING) != 0) {
		unp->unp_flags &= ~UNP_WAITING;
		wakeup(unp);
	}
	if (unp_pcb_rele(unp2)) {
		/* unp2 is unlocked. */
		return (NULL);
	}
	if (unp->unp_conn == NULL) {
		UNP_PCB_UNLOCK(unp2);
		return (NULL);
	}
	return (unp2);
}

/*
 * Definitions of protocols supported in the LOCAL domain.
 */
static struct domain localdomain;
static struct pr_usrreqs uipc_usrreqs_dgram, uipc_usrreqs_stream;
static struct pr_usrreqs uipc_usrreqs_seqpacket;
static struct protosw localsw[] = {
{
	.pr_type =		SOCK_STREAM,
	.pr_domain =		&localdomain,
	.pr_flags =		PR_CONNREQUIRED|PR_WANTRCVD|PR_RIGHTS,
	.pr_ctloutput =		&uipc_ctloutput,
	.pr_usrreqs =		&uipc_usrreqs_stream
},
{
	.pr_type =		SOCK_DGRAM,
	.pr_domain =		&localdomain,
	.pr_flags =		PR_ATOMIC|PR_ADDR|PR_RIGHTS,
	.pr_ctloutput =		&uipc_ctloutput,
	.pr_usrreqs =		&uipc_usrreqs_dgram
},
{
	.pr_type =		SOCK_SEQPACKET,
	.pr_domain =		&localdomain,

	/*
	 * XXXRW: For now, PR_ADDR because soreceive will bump into them
	 * due to our use of sbappendaddr.  A new sbappend variants is needed
	 * that supports both atomic record writes and control data.
	 */
	.pr_flags =		PR_ADDR|PR_ATOMIC|PR_CONNREQUIRED|PR_WANTRCVD|
				    PR_RIGHTS,
	.pr_ctloutput =		&uipc_ctloutput,
	.pr_usrreqs =		&uipc_usrreqs_seqpacket,
},
};

static struct domain localdomain = {
	.dom_family =		AF_LOCAL,
	.dom_name =		"local",
	.dom_init =		unp_init,
	.dom_externalize =	unp_externalize,
	.dom_dispose =		unp_dispose,
	.dom_protosw =		localsw,
	.dom_protoswNPROTOSW =	&localsw[nitems(localsw)]
};
DOMAIN_SET(local);

static void
uipc_abort(struct socket *so)
{
	struct unpcb *unp, *unp2;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_abort: unp == NULL"));
	UNP_PCB_UNLOCK_ASSERT(unp);

	UNP_PCB_LOCK(unp);
	unp2 = unp->unp_conn;
	if (unp2 != NULL) {
		unp_pcb_hold(unp2);
		UNP_PCB_UNLOCK(unp);
		unp_drop(unp2);
	} else
		UNP_PCB_UNLOCK(unp);
}

static int
uipc_accept(struct socket *so, struct sockaddr **nam)
{
	struct unpcb *unp, *unp2;
	const struct sockaddr *sa;

	/*
	 * Pass back name of connected socket, if it was bound and we are
	 * still connected (our peer may have closed already!).
	 */
	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_accept: unp == NULL"));

	*nam = malloc(sizeof(struct sockaddr_un), M_SONAME, M_WAITOK);
	UNP_PCB_LOCK(unp);
	unp2 = unp_pcb_lock_peer(unp);
	if (unp2 != NULL && unp2->unp_addr != NULL)
		sa = (struct sockaddr *)unp2->unp_addr;
	else
		sa = &sun_noname;
	bcopy(sa, *nam, sa->sa_len);
	if (unp2 != NULL)
		unp_pcb_unlock_pair(unp, unp2);
	else
		UNP_PCB_UNLOCK(unp);
	return (0);
}

static int
uipc_attach(struct socket *so, int proto, struct thread *td)
{
	u_long sendspace, recvspace;
	struct unpcb *unp;
	int error;
	bool locked;

	KASSERT(so->so_pcb == NULL, ("uipc_attach: so_pcb != NULL"));
	if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0) {
		switch (so->so_type) {
		case SOCK_STREAM:
			sendspace = unpst_sendspace;
			recvspace = unpst_recvspace;
			break;

		case SOCK_DGRAM:
			sendspace = unpdg_sendspace;
			recvspace = unpdg_recvspace;
			break;

		case SOCK_SEQPACKET:
			sendspace = unpsp_sendspace;
			recvspace = unpsp_recvspace;
			break;

		default:
			panic("uipc_attach");
		}
		error = soreserve(so, sendspace, recvspace);
		if (error)
			return (error);
	}
	unp = uma_zalloc(unp_zone, M_NOWAIT | M_ZERO);
	if (unp == NULL)
		return (ENOBUFS);
	LIST_INIT(&unp->unp_refs);
	UNP_PCB_LOCK_INIT(unp);
	unp->unp_socket = so;
	so->so_pcb = unp;
	refcount_init(&unp->unp_refcount, 1);

	if ((locked = UNP_LINK_WOWNED()) == false)
		UNP_LINK_WLOCK();

	unp->unp_gencnt = ++unp_gencnt;
	unp->unp_ino = ++unp_ino;
	unp_count++;
	switch (so->so_type) {
	case SOCK_STREAM:
		LIST_INSERT_HEAD(&unp_shead, unp, unp_link);
		break;

	case SOCK_DGRAM:
		LIST_INSERT_HEAD(&unp_dhead, unp, unp_link);
		break;

	case SOCK_SEQPACKET:
		LIST_INSERT_HEAD(&unp_sphead, unp, unp_link);
		break;

	default:
		panic("uipc_attach");
	}

	if (locked == false)
		UNP_LINK_WUNLOCK();

	return (0);
}

static int
uipc_bindat(int fd, struct socket *so, struct sockaddr *nam, struct thread *td)
{
	struct sockaddr_un *soun = (struct sockaddr_un *)nam;
	struct vattr vattr;
	int error, namelen;
	struct nameidata nd;
	struct unpcb *unp;
	struct vnode *vp;
	struct mount *mp;
	cap_rights_t rights;
	char *buf;

	if (nam->sa_family != AF_UNIX)
		return (EAFNOSUPPORT);

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_bind: unp == NULL"));

	if (soun->sun_len > sizeof(struct sockaddr_un))
		return (EINVAL);
	namelen = soun->sun_len - offsetof(struct sockaddr_un, sun_path);
	if (namelen <= 0)
		return (EINVAL);

	/*
	 * We don't allow simultaneous bind() calls on a single UNIX domain
	 * socket, so flag in-progress operations, and return an error if an
	 * operation is already in progress.
	 *
	 * Historically, we have not allowed a socket to be rebound, so this
	 * also returns an error.  Not allowing re-binding simplifies the
	 * implementation and avoids a great many possible failure modes.
	 */
	UNP_PCB_LOCK(unp);
	if (unp->unp_vnode != NULL) {
		UNP_PCB_UNLOCK(unp);
		return (EINVAL);
	}
	if (unp->unp_flags & UNP_BINDING) {
		UNP_PCB_UNLOCK(unp);
		return (EALREADY);
	}
	unp->unp_flags |= UNP_BINDING;
	UNP_PCB_UNLOCK(unp);

	buf = malloc(namelen + 1, M_TEMP, M_WAITOK);
	bcopy(soun->sun_path, buf, namelen);
	buf[namelen] = 0;

restart:
	NDINIT_ATRIGHTS(&nd, CREATE, NOFOLLOW | LOCKPARENT | SAVENAME | NOCACHE,
	    UIO_SYSSPACE, buf, fd, cap_rights_init_one(&rights, CAP_BINDAT),
	    td);
/* SHOULD BE ABLE TO ADOPT EXISTING AND wakeup() ALA FIFO's */
	error = namei(&nd);
	if (error)
		goto error;
	vp = nd.ni_vp;
	if (vp != NULL || vn_start_write(nd.ni_dvp, &mp, V_NOWAIT) != 0) {
		NDFREE(&nd, NDF_ONLY_PNBUF);
		if (nd.ni_dvp == vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		if (vp != NULL) {
			vrele(vp);
			error = EADDRINUSE;
			goto error;
		}
		error = vn_start_write(NULL, &mp, V_XSLEEP | PCATCH);
		if (error)
			goto error;
		goto restart;
	}
	VATTR_NULL(&vattr);
	vattr.va_type = VSOCK;
	vattr.va_mode = (ACCESSPERMS & ~td->td_proc->p_pd->pd_cmask);
#ifdef MAC
	error = mac_vnode_check_create(td->td_ucred, nd.ni_dvp, &nd.ni_cnd,
	    &vattr);
#endif
	if (error == 0)
		error = VOP_CREATE(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr);
	NDFREE(&nd, NDF_ONLY_PNBUF);
	if (error) {
		VOP_VPUT_PAIR(nd.ni_dvp, NULL, true);
		vn_finished_write(mp);
		if (error == ERELOOKUP)
			goto restart;
		goto error;
	}
	vp = nd.ni_vp;
	ASSERT_VOP_ELOCKED(vp, "uipc_bind");
	soun = (struct sockaddr_un *)sodupsockaddr(nam, M_WAITOK);

	UNP_PCB_LOCK(unp);
	VOP_UNP_BIND(vp, unp);
	unp->unp_vnode = vp;
	unp->unp_addr = soun;
	unp->unp_flags &= ~UNP_BINDING;
	UNP_PCB_UNLOCK(unp);
	vref(vp);
	VOP_VPUT_PAIR(nd.ni_dvp, &vp, true);
	vn_finished_write(mp);
	free(buf, M_TEMP);
	return (0);

error:
	UNP_PCB_LOCK(unp);
	unp->unp_flags &= ~UNP_BINDING;
	UNP_PCB_UNLOCK(unp);
	free(buf, M_TEMP);
	return (error);
}

static int
uipc_bind(struct socket *so, struct sockaddr *nam, struct thread *td)
{

	return (uipc_bindat(AT_FDCWD, so, nam, td));
}

static int
uipc_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	int error;

	KASSERT(td == curthread, ("uipc_connect: td != curthread"));
	error = unp_connect(so, nam, td);
	return (error);
}

static int
uipc_connectat(int fd, struct socket *so, struct sockaddr *nam,
    struct thread *td)
{
	int error;

	KASSERT(td == curthread, ("uipc_connectat: td != curthread"));
	error = unp_connectat(fd, so, nam, td);
	return (error);
}

static void
uipc_close(struct socket *so)
{
	struct unpcb *unp, *unp2;
	struct vnode *vp = NULL;
	struct mtx *vplock;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_close: unp == NULL"));

	vplock = NULL;
	if ((vp = unp->unp_vnode) != NULL) {
		vplock = mtx_pool_find(mtxpool_sleep, vp);
		mtx_lock(vplock);
	}
	UNP_PCB_LOCK(unp);
	if (vp && unp->unp_vnode == NULL) {
		mtx_unlock(vplock);
		vp = NULL;
	}
	if (vp != NULL) {
		VOP_UNP_DETACH(vp);
		unp->unp_vnode = NULL;
	}
	if ((unp2 = unp_pcb_lock_peer(unp)) != NULL)
		unp_disconnect(unp, unp2);
	else
		UNP_PCB_UNLOCK(unp);
	if (vp) {
		mtx_unlock(vplock);
		vrele(vp);
	}
}

static int
uipc_connect2(struct socket *so1, struct socket *so2)
{
	struct unpcb *unp, *unp2;
	int error;

	unp = so1->so_pcb;
	KASSERT(unp != NULL, ("uipc_connect2: unp == NULL"));
	unp2 = so2->so_pcb;
	KASSERT(unp2 != NULL, ("uipc_connect2: unp2 == NULL"));
	unp_pcb_lock_pair(unp, unp2);
	error = unp_connect2(so1, so2, PRU_CONNECT2);
	unp_pcb_unlock_pair(unp, unp2);
	return (error);
}

static void
uipc_detach(struct socket *so)
{
	struct unpcb *unp, *unp2;
	struct mtx *vplock;
	struct vnode *vp;
	int local_unp_rights;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_detach: unp == NULL"));

	vp = NULL;
	vplock = NULL;

	SOCK_LOCK(so);
	if (!SOLISTENING(so)) {
		/*
		 * Once the socket is removed from the global lists,
		 * uipc_ready() will not be able to locate its socket buffer, so
		 * clear the buffer now.  At this point internalized rights have
		 * already been disposed of.
		 */
		sbrelease(&so->so_rcv, so);
	}
	SOCK_UNLOCK(so);

	UNP_LINK_WLOCK();
	LIST_REMOVE(unp, unp_link);
	if (unp->unp_gcflag & UNPGC_DEAD)
		LIST_REMOVE(unp, unp_dead);
	unp->unp_gencnt = ++unp_gencnt;
	--unp_count;
	UNP_LINK_WUNLOCK();

	UNP_PCB_UNLOCK_ASSERT(unp);
 restart:
	if ((vp = unp->unp_vnode) != NULL) {
		vplock = mtx_pool_find(mtxpool_sleep, vp);
		mtx_lock(vplock);
	}
	UNP_PCB_LOCK(unp);
	if (unp->unp_vnode != vp && unp->unp_vnode != NULL) {
		if (vplock)
			mtx_unlock(vplock);
		UNP_PCB_UNLOCK(unp);
		goto restart;
	}
	if ((vp = unp->unp_vnode) != NULL) {
		VOP_UNP_DETACH(vp);
		unp->unp_vnode = NULL;
	}
	if ((unp2 = unp_pcb_lock_peer(unp)) != NULL)
		unp_disconnect(unp, unp2);
	else
		UNP_PCB_UNLOCK(unp);

	UNP_REF_LIST_LOCK();
	while (!LIST_EMPTY(&unp->unp_refs)) {
		struct unpcb *ref = LIST_FIRST(&unp->unp_refs);

		unp_pcb_hold(ref);
		UNP_REF_LIST_UNLOCK();

		MPASS(ref != unp);
		UNP_PCB_UNLOCK_ASSERT(ref);
		unp_drop(ref);
		UNP_REF_LIST_LOCK();
	}
	UNP_REF_LIST_UNLOCK();

	UNP_PCB_LOCK(unp);
	local_unp_rights = unp_rights;
	unp->unp_socket->so_pcb = NULL;
	unp->unp_socket = NULL;
	free(unp->unp_addr, M_SONAME);
	unp->unp_addr = NULL;
	if (!unp_pcb_rele(unp))
		UNP_PCB_UNLOCK(unp);
	if (vp) {
		mtx_unlock(vplock);
		vrele(vp);
	}
	if (local_unp_rights)
		taskqueue_enqueue_timeout(taskqueue_thread, &unp_gc_task, -1);
}

static int
uipc_disconnect(struct socket *so)
{
	struct unpcb *unp, *unp2;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_disconnect: unp == NULL"));

	UNP_PCB_LOCK(unp);
	if ((unp2 = unp_pcb_lock_peer(unp)) != NULL)
		unp_disconnect(unp, unp2);
	else
		UNP_PCB_UNLOCK(unp);
	return (0);
}

static int
uipc_listen(struct socket *so, int backlog, struct thread *td)
{
	struct unpcb *unp;
	int error;

	if (so->so_type != SOCK_STREAM && so->so_type != SOCK_SEQPACKET)
		return (EOPNOTSUPP);

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_listen: unp == NULL"));

	UNP_PCB_LOCK(unp);
	if (unp->unp_vnode == NULL) {
		/* Already connected or not bound to an address. */
		error = unp->unp_conn != NULL ? EINVAL : EDESTADDRREQ;
		UNP_PCB_UNLOCK(unp);
		return (error);
	}

	SOCK_LOCK(so);
	error = solisten_proto_check(so);
	if (error == 0) {
		cru2xt(td, &unp->unp_peercred);
		solisten_proto(so, backlog);
	}
	SOCK_UNLOCK(so);
	UNP_PCB_UNLOCK(unp);
	return (error);
}

static int
uipc_peeraddr(struct socket *so, struct sockaddr **nam)
{
	struct unpcb *unp, *unp2;
	const struct sockaddr *sa;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_peeraddr: unp == NULL"));

	*nam = malloc(sizeof(struct sockaddr_un), M_SONAME, M_WAITOK);
	UNP_LINK_RLOCK();
	/*
	 * XXX: It seems that this test always fails even when connection is
	 * established.  So, this else clause is added as workaround to
	 * return PF_LOCAL sockaddr.
	 */
	unp2 = unp->unp_conn;
	if (unp2 != NULL) {
		UNP_PCB_LOCK(unp2);
		if (unp2->unp_addr != NULL)
			sa = (struct sockaddr *) unp2->unp_addr;
		else
			sa = &sun_noname;
		bcopy(sa, *nam, sa->sa_len);
		UNP_PCB_UNLOCK(unp2);
	} else {
		sa = &sun_noname;
		bcopy(sa, *nam, sa->sa_len);
	}
	UNP_LINK_RUNLOCK();
	return (0);
}

static int
uipc_rcvd(struct socket *so, int flags)
{
	struct unpcb *unp, *unp2;
	struct socket *so2;
	u_int mbcnt, sbcc;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("%s: unp == NULL", __func__));
	KASSERT(so->so_type == SOCK_STREAM || so->so_type == SOCK_SEQPACKET,
	    ("%s: socktype %d", __func__, so->so_type));

	/*
	 * Adjust backpressure on sender and wakeup any waiting to write.
	 *
	 * The unp lock is acquired to maintain the validity of the unp_conn
	 * pointer; no lock on unp2 is required as unp2->unp_socket will be
	 * static as long as we don't permit unp2 to disconnect from unp,
	 * which is prevented by the lock on unp.  We cache values from
	 * so_rcv to avoid holding the so_rcv lock over the entire
	 * transaction on the remote so_snd.
	 */
	SOCKBUF_LOCK(&so->so_rcv);
	mbcnt = so->so_rcv.sb_mbcnt;
	sbcc = sbavail(&so->so_rcv);
	SOCKBUF_UNLOCK(&so->so_rcv);
	/*
	 * There is a benign race condition at this point.  If we're planning to
	 * clear SB_STOP, but uipc_send is called on the connected socket at
	 * this instant, it might add data to the sockbuf and set SB_STOP.  Then
	 * we would erroneously clear SB_STOP below, even though the sockbuf is
	 * full.  The race is benign because the only ill effect is to allow the
	 * sockbuf to exceed its size limit, and the size limits are not
	 * strictly guaranteed anyway.
	 */
	UNP_PCB_LOCK(unp);
	unp2 = unp->unp_conn;
	if (unp2 == NULL) {
		UNP_PCB_UNLOCK(unp);
		return (0);
	}
	so2 = unp2->unp_socket;
	SOCKBUF_LOCK(&so2->so_snd);
	if (sbcc < so2->so_snd.sb_hiwat && mbcnt < so2->so_snd.sb_mbmax)
		so2->so_snd.sb_flags &= ~SB_STOP;
	sowwakeup_locked(so2);
	UNP_PCB_UNLOCK(unp);
	return (0);
}

static int
uipc_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *nam,
    struct mbuf *control, struct thread *td)
{
	struct unpcb *unp, *unp2;
	struct socket *so2;
	u_int mbcnt, sbcc;
	int freed, error;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("%s: unp == NULL", __func__));
	KASSERT(so->so_type == SOCK_STREAM || so->so_type == SOCK_DGRAM ||
	    so->so_type == SOCK_SEQPACKET,
	    ("%s: socktype %d", __func__, so->so_type));

	freed = error = 0;
	if (flags & PRUS_OOB) {
		error = EOPNOTSUPP;
		goto release;
	}
	if (control != NULL && (error = unp_internalize(&control, td)))
		goto release;

	unp2 = NULL;
	switch (so->so_type) {
	case SOCK_DGRAM:
	{
		const struct sockaddr *from;

		if (nam != NULL) {
			error = unp_connect(so, nam, td);
			if (error != 0)
				break;
		}
		UNP_PCB_LOCK(unp);

		/*
		 * Because connect() and send() are non-atomic in a sendto()
		 * with a target address, it's possible that the socket will
		 * have disconnected before the send() can run.  In that case
		 * return the slightly counter-intuitive but otherwise
		 * correct error that the socket is not connected.
		 */
		unp2 = unp_pcb_lock_peer(unp);
		if (unp2 == NULL) {
			UNP_PCB_UNLOCK(unp);
			error = ENOTCONN;
			break;
		}

		if (unp2->unp_flags & UNP_WANTCRED_MASK)
			control = unp_addsockcred(td, control,
			    unp2->unp_flags);
		if (unp->unp_addr != NULL)
			from = (struct sockaddr *)unp->unp_addr;
		else
			from = &sun_noname;
		so2 = unp2->unp_socket;
		SOCKBUF_LOCK(&so2->so_rcv);
		if (sbappendaddr_locked(&so2->so_rcv, from, m,
		    control)) {
			sorwakeup_locked(so2);
			m = NULL;
			control = NULL;
		} else {
			SOCKBUF_UNLOCK(&so2->so_rcv);
			error = ENOBUFS;
		}
		if (nam != NULL)
			unp_disconnect(unp, unp2);
		else
			unp_pcb_unlock_pair(unp, unp2);
		break;
	}

	case SOCK_SEQPACKET:
	case SOCK_STREAM:
		if ((so->so_state & SS_ISCONNECTED) == 0) {
			if (nam != NULL) {
				error = unp_connect(so, nam, td);
				if (error != 0)
					break;
			} else {
				error = ENOTCONN;
				break;
			}
		}

		UNP_PCB_LOCK(unp);
		if ((unp2 = unp_pcb_lock_peer(unp)) == NULL) {
			UNP_PCB_UNLOCK(unp);
			error = ENOTCONN;
			break;
		} else if (so->so_snd.sb_state & SBS_CANTSENDMORE) {
			unp_pcb_unlock_pair(unp, unp2);
			error = EPIPE;
			break;
		}
		UNP_PCB_UNLOCK(unp);
		if ((so2 = unp2->unp_socket) == NULL) {
			UNP_PCB_UNLOCK(unp2);
			error = ENOTCONN;
			break;
		}
		SOCKBUF_LOCK(&so2->so_rcv);
		if (unp2->unp_flags & UNP_WANTCRED_MASK) {
			/*
			 * Credentials are passed only once on SOCK_STREAM and
			 * SOCK_SEQPACKET (LOCAL_CREDS => WANTCRED_ONESHOT), or
			 * forever (LOCAL_CREDS_PERSISTENT => WANTCRED_ALWAYS).
			 */
			control = unp_addsockcred(td, control, unp2->unp_flags);
			unp2->unp_flags &= ~UNP_WANTCRED_ONESHOT;
		}

		/*
		 * Send to paired receive port and wake up readers.  Don't
		 * check for space available in the receive buffer if we're
		 * attaching ancillary data; Unix domain sockets only check
		 * for space in the sending sockbuf, and that check is
		 * performed one level up the stack.  At that level we cannot
		 * precisely account for the amount of buffer space used
		 * (e.g., because control messages are not yet internalized).
		 */
		switch (so->so_type) {
		case SOCK_STREAM:
			if (control != NULL) {
				sbappendcontrol_locked(&so2->so_rcv, m,
				    control, flags);
				control = NULL;
			} else
				sbappend_locked(&so2->so_rcv, m, flags);
			break;

		case SOCK_SEQPACKET:
			if (sbappendaddr_nospacecheck_locked(&so2->so_rcv,
			    &sun_noname, m, control))
				control = NULL;
			break;
		}

		mbcnt = so2->so_rcv.sb_mbcnt;
		sbcc = sbavail(&so2->so_rcv);
		if (sbcc)
			sorwakeup_locked(so2);
		else
			SOCKBUF_UNLOCK(&so2->so_rcv);

		/*
		 * The PCB lock on unp2 protects the SB_STOP flag.  Without it,
		 * it would be possible for uipc_rcvd to be called at this
		 * point, drain the receiving sockbuf, clear SB_STOP, and then
		 * we would set SB_STOP below.  That could lead to an empty
		 * sockbuf having SB_STOP set
		 */
		SOCKBUF_LOCK(&so->so_snd);
		if (sbcc >= so->so_snd.sb_hiwat || mbcnt >= so->so_snd.sb_mbmax)
			so->so_snd.sb_flags |= SB_STOP;
		SOCKBUF_UNLOCK(&so->so_snd);
		UNP_PCB_UNLOCK(unp2);
		m = NULL;
		break;
	}

	/*
	 * PRUS_EOF is equivalent to pru_send followed by pru_shutdown.
	 */
	if (flags & PRUS_EOF) {
		UNP_PCB_LOCK(unp);
		socantsendmore(so);
		unp_shutdown(unp);
		UNP_PCB_UNLOCK(unp);
	}
	if (control != NULL && error != 0)
		unp_dispose_mbuf(control);

release:
	if (control != NULL)
		m_freem(control);
	/*
	 * In case of PRUS_NOTREADY, uipc_ready() is responsible
	 * for freeing memory.
	 */
	if (m != NULL && (flags & PRUS_NOTREADY) == 0)
		m_freem(m);
	return (error);
}

static bool
uipc_ready_scan(struct socket *so, struct mbuf *m, int count, int *errorp)
{
	struct mbuf *mb, *n;
	struct sockbuf *sb;

	SOCK_LOCK(so);
	if (SOLISTENING(so)) {
		SOCK_UNLOCK(so);
		return (false);
	}
	mb = NULL;
	sb = &so->so_rcv;
	SOCKBUF_LOCK(sb);
	if (sb->sb_fnrdy != NULL) {
		for (mb = sb->sb_mb, n = mb->m_nextpkt; mb != NULL;) {
			if (mb == m) {
				*errorp = sbready(sb, m, count);
				break;
			}
			mb = mb->m_next;
			if (mb == NULL) {
				mb = n;
				if (mb != NULL)
					n = mb->m_nextpkt;
			}
		}
	}
	SOCKBUF_UNLOCK(sb);
	SOCK_UNLOCK(so);
	return (mb != NULL);
}

static int
uipc_ready(struct socket *so, struct mbuf *m, int count)
{
	struct unpcb *unp, *unp2;
	struct socket *so2;
	int error, i;

	unp = sotounpcb(so);

	KASSERT(so->so_type == SOCK_STREAM,
	    ("%s: unexpected socket type for %p", __func__, so));

	UNP_PCB_LOCK(unp);
	if ((unp2 = unp_pcb_lock_peer(unp)) != NULL) {
		UNP_PCB_UNLOCK(unp);
		so2 = unp2->unp_socket;
		SOCKBUF_LOCK(&so2->so_rcv);
		if ((error = sbready(&so2->so_rcv, m, count)) == 0)
			sorwakeup_locked(so2);
		else
			SOCKBUF_UNLOCK(&so2->so_rcv);
		UNP_PCB_UNLOCK(unp2);
		return (error);
	}
	UNP_PCB_UNLOCK(unp);

	/*
	 * The receiving socket has been disconnected, but may still be valid.
	 * In this case, the now-ready mbufs are still present in its socket
	 * buffer, so perform an exhaustive search before giving up and freeing
	 * the mbufs.
	 */
	UNP_LINK_RLOCK();
	LIST_FOREACH(unp, &unp_shead, unp_link) {
		if (uipc_ready_scan(unp->unp_socket, m, count, &error))
			break;
	}
	UNP_LINK_RUNLOCK();

	if (unp == NULL) {
		for (i = 0; i < count; i++)
			m = m_free(m);
		error = ECONNRESET;
	}
	return (error);
}

static int
uipc_sense(struct socket *so, struct stat *sb)
{
	struct unpcb *unp;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_sense: unp == NULL"));

	sb->st_blksize = so->so_snd.sb_hiwat;
	sb->st_dev = NODEV;
	sb->st_ino = unp->unp_ino;
	return (0);
}

static int
uipc_shutdown(struct socket *so)
{
	struct unpcb *unp;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_shutdown: unp == NULL"));

	UNP_PCB_LOCK(unp);
	socantsendmore(so);
	unp_shutdown(unp);
	UNP_PCB_UNLOCK(unp);
	return (0);
}

static int
uipc_sockaddr(struct socket *so, struct sockaddr **nam)
{
	struct unpcb *unp;
	const struct sockaddr *sa;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_sockaddr: unp == NULL"));

	*nam = malloc(sizeof(struct sockaddr_un), M_SONAME, M_WAITOK);
	UNP_PCB_LOCK(unp);
	if (unp->unp_addr != NULL)
		sa = (struct sockaddr *) unp->unp_addr;
	else
		sa = &sun_noname;
	bcopy(sa, *nam, sa->sa_len);
	UNP_PCB_UNLOCK(unp);
	return (0);
}

static struct pr_usrreqs uipc_usrreqs_dgram = {
	.pru_abort = 		uipc_abort,
	.pru_accept =		uipc_accept,
	.pru_attach =		uipc_attach,
	.pru_bind =		uipc_bind,
	.pru_bindat =		uipc_bindat,
	.pru_connect =		uipc_connect,
	.pru_connectat =	uipc_connectat,
	.pru_connect2 =		uipc_connect2,
	.pru_detach =		uipc_detach,
	.pru_disconnect =	uipc_disconnect,
	.pru_listen =		uipc_listen,
	.pru_peeraddr =		uipc_peeraddr,
	.pru_rcvd =		uipc_rcvd,
	.pru_send =		uipc_send,
	.pru_sense =		uipc_sense,
	.pru_shutdown =		uipc_shutdown,
	.pru_sockaddr =		uipc_sockaddr,
	.pru_soreceive =	soreceive_dgram,
	.pru_close =		uipc_close,
};

static struct pr_usrreqs uipc_usrreqs_seqpacket = {
	.pru_abort =		uipc_abort,
	.pru_accept =		uipc_accept,
	.pru_attach =		uipc_attach,
	.pru_bind =		uipc_bind,
	.pru_bindat =		uipc_bindat,
	.pru_connect =		uipc_connect,
	.pru_connectat =	uipc_connectat,
	.pru_connect2 =		uipc_connect2,
	.pru_detach =		uipc_detach,
	.pru_disconnect =	uipc_disconnect,
	.pru_listen =		uipc_listen,
	.pru_peeraddr =		uipc_peeraddr,
	.pru_rcvd =		uipc_rcvd,
	.pru_send =		uipc_send,
	.pru_sense =		uipc_sense,
	.pru_shutdown =		uipc_shutdown,
	.pru_sockaddr =		uipc_sockaddr,
	.pru_soreceive =	soreceive_generic,	/* XXX: or...? */
	.pru_close =		uipc_close,
};

static struct pr_usrreqs uipc_usrreqs_stream = {
	.pru_abort = 		uipc_abort,
	.pru_accept =		uipc_accept,
	.pru_attach =		uipc_attach,
	.pru_bind =		uipc_bind,
	.pru_bindat =		uipc_bindat,
	.pru_connect =		uipc_connect,
	.pru_connectat =	uipc_connectat,
	.pru_connect2 =		uipc_connect2,
	.pru_detach =		uipc_detach,
	.pru_disconnect =	uipc_disconnect,
	.pru_listen =		uipc_listen,
	.pru_peeraddr =		uipc_peeraddr,
	.pru_rcvd =		uipc_rcvd,
	.pru_send =		uipc_send,
	.pru_ready =		uipc_ready,
	.pru_sense =		uipc_sense,
	.pru_shutdown =		uipc_shutdown,
	.pru_sockaddr =		uipc_sockaddr,
	.pru_soreceive =	soreceive_generic,
	.pru_close =		uipc_close,
};

static int
uipc_ctloutput(struct socket *so, struct sockopt *sopt)
{
	struct unpcb *unp;
	struct xucred xu;
	int error, optval;

	if (sopt->sopt_level != SOL_LOCAL)
		return (EINVAL);

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_ctloutput: unp == NULL"));
	error = 0;
	switch (sopt->sopt_dir) {
	case SOPT_GET:
		switch (sopt->sopt_name) {
		case LOCAL_PEERCRED:
			UNP_PCB_LOCK(unp);
			if (unp->unp_flags & UNP_HAVEPC)
				xu = unp->unp_peercred;
			else {
				if (so->so_type == SOCK_STREAM)
					error = ENOTCONN;
				else
					error = EINVAL;
			}
			UNP_PCB_UNLOCK(unp);
			if (error == 0)
				error = sooptcopyout(sopt, &xu, sizeof(xu));
			break;

		case LOCAL_CREDS:
			/* Unlocked read. */
			optval = unp->unp_flags & UNP_WANTCRED_ONESHOT ? 1 : 0;
			error = sooptcopyout(sopt, &optval, sizeof(optval));
			break;

		case LOCAL_CREDS_PERSISTENT:
			/* Unlocked read. */
			optval = unp->unp_flags & UNP_WANTCRED_ALWAYS ? 1 : 0;
			error = sooptcopyout(sopt, &optval, sizeof(optval));
			break;

		case LOCAL_CONNWAIT:
			/* Unlocked read. */
			optval = unp->unp_flags & UNP_CONNWAIT ? 1 : 0;
			error = sooptcopyout(sopt, &optval, sizeof(optval));
			break;

		default:
			error = EOPNOTSUPP;
			break;
		}
		break;

	case SOPT_SET:
		switch (sopt->sopt_name) {
		case LOCAL_CREDS:
		case LOCAL_CREDS_PERSISTENT:
		case LOCAL_CONNWAIT:
			error = sooptcopyin(sopt, &optval, sizeof(optval),
					    sizeof(optval));
			if (error)
				break;

#define	OPTSET(bit, exclusive) do {					\
	UNP_PCB_LOCK(unp);						\
	if (optval) {							\
		if ((unp->unp_flags & (exclusive)) != 0) {		\
			UNP_PCB_UNLOCK(unp);				\
			error = EINVAL;					\
			break;						\
		}							\
		unp->unp_flags |= (bit);				\
	} else								\
		unp->unp_flags &= ~(bit);				\
	UNP_PCB_UNLOCK(unp);						\
} while (0)

			switch (sopt->sopt_name) {
			case LOCAL_CREDS:
				OPTSET(UNP_WANTCRED_ONESHOT, UNP_WANTCRED_ALWAYS);
				break;

			case LOCAL_CREDS_PERSISTENT:
				OPTSET(UNP_WANTCRED_ALWAYS, UNP_WANTCRED_ONESHOT);
				break;

			case LOCAL_CONNWAIT:
				OPTSET(UNP_CONNWAIT, 0);
				break;

			default:
				break;
			}
			break;
#undef	OPTSET
		default:
			error = ENOPROTOOPT;
			break;
		}
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

static int
unp_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
{

	return (unp_connectat(AT_FDCWD, so, nam, td));
}

static int
unp_connectat(int fd, struct socket *so, struct sockaddr *nam,
    struct thread *td)
{
	struct mtx *vplock;
	struct sockaddr_un *soun;
	struct vnode *vp;
	struct socket *so2;
	struct unpcb *unp, *unp2, *unp3;
	struct nameidata nd;
	char buf[SOCK_MAXADDRLEN];
	struct sockaddr *sa;
	cap_rights_t rights;
	int error, len;
	bool connreq;

	if (nam->sa_family != AF_UNIX)
		return (EAFNOSUPPORT);
	if (nam->sa_len > sizeof(struct sockaddr_un))
		return (EINVAL);
	len = nam->sa_len - offsetof(struct sockaddr_un, sun_path);
	if (len <= 0)
		return (EINVAL);
	soun = (struct sockaddr_un *)nam;
	bcopy(soun->sun_path, buf, len);
	buf[len] = 0;

	unp = sotounpcb(so);
	UNP_PCB_LOCK(unp);
	for (;;) {
		/*
		 * Wait for connection state to stabilize.  If a connection
		 * already exists, give up.  For datagram sockets, which permit
		 * multiple consecutive connect(2) calls, upper layers are
		 * responsible for disconnecting in advance of a subsequent
		 * connect(2), but this is not synchronized with PCB connection
		 * state.
		 *
		 * Also make sure that no threads are currently attempting to
		 * lock the peer socket, to ensure that unp_conn cannot
		 * transition between two valid sockets while locks are dropped.
		 */
		if (unp->unp_conn != NULL) {
			UNP_PCB_UNLOCK(unp);
			return (EISCONN);
		}
		if ((unp->unp_flags & UNP_CONNECTING) != 0) {
			UNP_PCB_UNLOCK(unp);
			return (EALREADY);
		}
		if (unp->unp_pairbusy > 0) {
			unp->unp_flags |= UNP_WAITING;
			mtx_sleep(unp, UNP_PCB_LOCKPTR(unp), 0, "unpeer", 0);
			continue;
		}
		break;
	}
	unp->unp_flags |= UNP_CONNECTING;
	UNP_PCB_UNLOCK(unp);

	connreq = (so->so_proto->pr_flags & PR_CONNREQUIRED) != 0;
	if (connreq)
		sa = malloc(sizeof(struct sockaddr_un), M_SONAME, M_WAITOK);
	else
		sa = NULL;
	NDINIT_ATRIGHTS(&nd, LOOKUP, FOLLOW | LOCKSHARED | LOCKLEAF,
	    UIO_SYSSPACE, buf, fd, cap_rights_init_one(&rights, CAP_CONNECTAT),
	    td);
	error = namei(&nd);
	if (error)
		vp = NULL;
	else
		vp = nd.ni_vp;
	ASSERT_VOP_LOCKED(vp, "unp_connect");
	NDFREE_NOTHING(&nd);
	if (error)
		goto bad;

	if (vp->v_type != VSOCK) {
		error = ENOTSOCK;
		goto bad;
	}
#ifdef MAC
	error = mac_vnode_check_open(td->td_ucred, vp, VWRITE | VREAD);
	if (error)
		goto bad;
#endif
	error = VOP_ACCESS(vp, VWRITE, td->td_ucred, td);
	if (error)
		goto bad;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("unp_connect: unp == NULL"));

	vplock = mtx_pool_find(mtxpool_sleep, vp);
	mtx_lock(vplock);
	VOP_UNP_CONNECT(vp, &unp2);
	if (unp2 == NULL) {
		error = ECONNREFUSED;
		goto bad2;
	}
	so2 = unp2->unp_socket;
	if (so->so_type != so2->so_type) {
		error = EPROTOTYPE;
		goto bad2;
	}
	if (connreq) {
		if (so2->so_options & SO_ACCEPTCONN) {
			CURVNET_SET(so2->so_vnet);
			so2 = sonewconn(so2, 0);
			CURVNET_RESTORE();
		} else
			so2 = NULL;
		if (so2 == NULL) {
			error = ECONNREFUSED;
			goto bad2;
		}
		unp3 = sotounpcb(so2);
		unp_pcb_lock_pair(unp2, unp3);
		if (unp2->unp_addr != NULL) {
			bcopy(unp2->unp_addr, sa, unp2->unp_addr->sun_len);
			unp3->unp_addr = (struct sockaddr_un *) sa;
			sa = NULL;
		}

		unp_copy_peercred(td, unp3, unp, unp2);

		UNP_PCB_UNLOCK(unp2);
		unp2 = unp3;

		/*
		 * It is safe to block on the PCB lock here since unp2 is
		 * nascent and cannot be connected to any other sockets.
		 */
		UNP_PCB_LOCK(unp);
#ifdef MAC
		mac_socketpeer_set_from_socket(so, so2);
		mac_socketpeer_set_from_socket(so2, so);
#endif
	} else {
		unp_pcb_lock_pair(unp, unp2);
	}
	KASSERT(unp2 != NULL && so2 != NULL && unp2->unp_socket == so2 &&
	    sotounpcb(so2) == unp2,
	    ("%s: unp2 %p so2 %p", __func__, unp2, so2));
	error = unp_connect2(so, so2, PRU_CONNECT);
	unp_pcb_unlock_pair(unp, unp2);
bad2:
	mtx_unlock(vplock);
bad:
	if (vp != NULL) {
		vput(vp);
	}
	free(sa, M_SONAME);
	UNP_PCB_LOCK(unp);
	KASSERT((unp->unp_flags & UNP_CONNECTING) != 0,
	    ("%s: unp %p has UNP_CONNECTING clear", __func__, unp));
	unp->unp_flags &= ~UNP_CONNECTING;
	UNP_PCB_UNLOCK(unp);
	return (error);
}

/*
 * Set socket peer credentials at connection time.
 *
 * The client's PCB credentials are copied from its process structure.  The
 * server's PCB credentials are copied from the socket on which it called
 * listen(2).  uipc_listen cached that process's credentials at the time.
 */
void
unp_copy_peercred(struct thread *td, struct unpcb *client_unp,
    struct unpcb *server_unp, struct unpcb *listen_unp)
{
	cru2xt(td, &client_unp->unp_peercred);
	client_unp->unp_flags |= UNP_HAVEPC;

	memcpy(&server_unp->unp_peercred, &listen_unp->unp_peercred,
	    sizeof(server_unp->unp_peercred));
	server_unp->unp_flags |= UNP_HAVEPC;
	client_unp->unp_flags |= (listen_unp->unp_flags & UNP_WANTCRED_MASK);
}

static int
unp_connect2(struct socket *so, struct socket *so2, int req)
{
	struct unpcb *unp;
	struct unpcb *unp2;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("unp_connect2: unp == NULL"));
	unp2 = sotounpcb(so2);
	KASSERT(unp2 != NULL, ("unp_connect2: unp2 == NULL"));

	UNP_PCB_LOCK_ASSERT(unp);
	UNP_PCB_LOCK_ASSERT(unp2);
	KASSERT(unp->unp_conn == NULL,
	    ("%s: socket %p is already connected", __func__, unp));

	if (so2->so_type != so->so_type)
		return (EPROTOTYPE);
	unp->unp_conn = unp2;
	unp_pcb_hold(unp2);
	unp_pcb_hold(unp);
	switch (so->so_type) {
	case SOCK_DGRAM:
		UNP_REF_LIST_LOCK();
		LIST_INSERT_HEAD(&unp2->unp_refs, unp, unp_reflink);
		UNP_REF_LIST_UNLOCK();
		soisconnected(so);
		break;

	case SOCK_STREAM:
	case SOCK_SEQPACKET:
		KASSERT(unp2->unp_conn == NULL,
		    ("%s: socket %p is already connected", __func__, unp2));
		unp2->unp_conn = unp;
		if (req == PRU_CONNECT &&
		    ((unp->unp_flags | unp2->unp_flags) & UNP_CONNWAIT))
			soisconnecting(so);
		else
			soisconnected(so);
		soisconnected(so2);
		break;

	default:
		panic("unp_connect2");
	}
	return (0);
}

static void
unp_disconnect(struct unpcb *unp, struct unpcb *unp2)
{
	struct socket *so, *so2;
#ifdef INVARIANTS
	struct unpcb *unptmp;
#endif

	UNP_PCB_LOCK_ASSERT(unp);
	UNP_PCB_LOCK_ASSERT(unp2);
	KASSERT(unp->unp_conn == unp2,
	    ("%s: unpcb %p is not connected to %p", __func__, unp, unp2));

	unp->unp_conn = NULL;
	so = unp->unp_socket;
	so2 = unp2->unp_socket;
	switch (unp->unp_socket->so_type) {
	case SOCK_DGRAM:
		UNP_REF_LIST_LOCK();
#ifdef INVARIANTS
		LIST_FOREACH(unptmp, &unp2->unp_refs, unp_reflink) {
			if (unptmp == unp)
				break;
		}
		KASSERT(unptmp != NULL,
		    ("%s: %p not found in reflist of %p", __func__, unp, unp2));
#endif
		LIST_REMOVE(unp, unp_reflink);
		UNP_REF_LIST_UNLOCK();
		if (so) {
			SOCK_LOCK(so);
			so->so_state &= ~SS_ISCONNECTED;
			SOCK_UNLOCK(so);
		}
		break;

	case SOCK_STREAM:
	case SOCK_SEQPACKET:
		if (so)
			soisdisconnected(so);
		MPASS(unp2->unp_conn == unp);
		unp2->unp_conn = NULL;
		if (so2)
			soisdisconnected(so2);
		break;
	}

	if (unp == unp2) {
		unp_pcb_rele_notlast(unp);
		if (!unp_pcb_rele(unp))
			UNP_PCB_UNLOCK(unp);
	} else {
		if (!unp_pcb_rele(unp))
			UNP_PCB_UNLOCK(unp);
		if (!unp_pcb_rele(unp2))
			UNP_PCB_UNLOCK(unp2);
	}
}

/*
 * unp_pcblist() walks the global list of struct unpcb's to generate a
 * pointer list, bumping the refcount on each unpcb.  It then copies them out
 * sequentially, validating the generation number on each to see if it has
 * been detached.  All of this is necessary because copyout() may sleep on
 * disk I/O.
 */
static int
unp_pcblist(SYSCTL_HANDLER_ARGS)
{
	struct unpcb *unp, **unp_list;
	unp_gen_t gencnt;
	struct xunpgen *xug;
	struct unp_head *head;
	struct xunpcb *xu;
	u_int i;
	int error, n;

	switch ((intptr_t)arg1) {
	case SOCK_STREAM:
		head = &unp_shead;
		break;

	case SOCK_DGRAM:
		head = &unp_dhead;
		break;

	case SOCK_SEQPACKET:
		head = &unp_sphead;
		break;

	default:
		panic("unp_pcblist: arg1 %d", (int)(intptr_t)arg1);
	}

	/*
	 * The process of preparing the PCB list is too time-consuming and
	 * resource-intensive to repeat twice on every request.
	 */
	if (req->oldptr == NULL) {
		n = unp_count;
		req->oldidx = 2 * (sizeof *xug)
			+ (n + n/8) * sizeof(struct xunpcb);
		return (0);
	}

	if (req->newptr != NULL)
		return (EPERM);

	/*
	 * OK, now we're committed to doing something.
	 */
	xug = malloc(sizeof(*xug), M_TEMP, M_WAITOK | M_ZERO);
	UNP_LINK_RLOCK();
	gencnt = unp_gencnt;
	n = unp_count;
	UNP_LINK_RUNLOCK();

	xug->xug_len = sizeof *xug;
	xug->xug_count = n;
	xug->xug_gen = gencnt;
	xug->xug_sogen = so_gencnt;
	error = SYSCTL_OUT(req, xug, sizeof *xug);
	if (error) {
		free(xug, M_TEMP);
		return (error);
	}

	unp_list = malloc(n * sizeof *unp_list, M_TEMP, M_WAITOK);

	UNP_LINK_RLOCK();
	for (unp = LIST_FIRST(head), i = 0; unp && i < n;
	     unp = LIST_NEXT(unp, unp_link)) {
		UNP_PCB_LOCK(unp);
		if (unp->unp_gencnt <= gencnt) {
			if (cr_cansee(req->td->td_ucred,
			    unp->unp_socket->so_cred)) {
				UNP_PCB_UNLOCK(unp);
				continue;
			}
			unp_list[i++] = unp;
			unp_pcb_hold(unp);
		}
		UNP_PCB_UNLOCK(unp);
	}
	UNP_LINK_RUNLOCK();
	n = i;			/* In case we lost some during malloc. */

	error = 0;
	xu = malloc(sizeof(*xu), M_TEMP, M_WAITOK | M_ZERO);
	for (i = 0; i < n; i++) {
		unp = unp_list[i];
		UNP_PCB_LOCK(unp);
		if (unp_pcb_rele(unp))
			continue;

		if (unp->unp_gencnt <= gencnt) {
			xu->xu_len = sizeof *xu;
			xu->xu_unpp = (uintptr_t)unp;
			/*
			 * XXX - need more locking here to protect against
			 * connect/disconnect races for SMP.
			 */
			if (unp->unp_addr != NULL)
				bcopy(unp->unp_addr, &xu->xu_addr,
				      unp->unp_addr->sun_len);
			else
				bzero(&xu->xu_addr, sizeof(xu->xu_addr));
			if (unp->unp_conn != NULL &&
			    unp->unp_conn->unp_addr != NULL)
				bcopy(unp->unp_conn->unp_addr,
				      &xu->xu_caddr,
				      unp->unp_conn->unp_addr->sun_len);
			else
				bzero(&xu->xu_caddr, sizeof(xu->xu_caddr));
			xu->unp_vnode = (uintptr_t)unp->unp_vnode;
			xu->unp_conn = (uintptr_t)unp->unp_conn;
			xu->xu_firstref = (uintptr_t)LIST_FIRST(&unp->unp_refs);
			xu->xu_nextref = (uintptr_t)LIST_NEXT(unp, unp_reflink);
			xu->unp_gencnt = unp->unp_gencnt;
			sotoxsocket(unp->unp_socket, &xu->xu_socket);
			UNP_PCB_UNLOCK(unp);
			error = SYSCTL_OUT(req, xu, sizeof *xu);
		} else {
			UNP_PCB_UNLOCK(unp);
		}
	}
	free(xu, M_TEMP);
	if (!error) {
		/*
		 * Give the user an updated idea of our state.  If the
		 * generation differs from what we told her before, she knows
		 * that something happened while we were processing this
		 * request, and it might be necessary to retry.
		 */
		xug->xug_gen = unp_gencnt;
		xug->xug_sogen = so_gencnt;
		xug->xug_count = unp_count;
		error = SYSCTL_OUT(req, xug, sizeof *xug);
	}
	free(unp_list, M_TEMP);
	free(xug, M_TEMP);
	return (error);
}

SYSCTL_PROC(_net_local_dgram, OID_AUTO, pcblist,
    CTLTYPE_OPAQUE | CTLFLAG_RD | CTLFLAG_MPSAFE,
    (void *)(intptr_t)SOCK_DGRAM, 0, unp_pcblist, "S,xunpcb",
    "List of active local datagram sockets");
SYSCTL_PROC(_net_local_stream, OID_AUTO, pcblist,
    CTLTYPE_OPAQUE | CTLFLAG_RD | CTLFLAG_MPSAFE,
    (void *)(intptr_t)SOCK_STREAM, 0, unp_pcblist, "S,xunpcb",
    "List of active local stream sockets");
SYSCTL_PROC(_net_local_seqpacket, OID_AUTO, pcblist,
    CTLTYPE_OPAQUE | CTLFLAG_RD | CTLFLAG_MPSAFE,
    (void *)(intptr_t)SOCK_SEQPACKET, 0, unp_pcblist, "S,xunpcb",
    "List of active local seqpacket sockets");

static void
unp_shutdown(struct unpcb *unp)
{
	struct unpcb *unp2;
	struct socket *so;

	UNP_PCB_LOCK_ASSERT(unp);

	unp2 = unp->unp_conn;
	if ((unp->unp_socket->so_type == SOCK_STREAM ||
	    (unp->unp_socket->so_type == SOCK_SEQPACKET)) && unp2 != NULL) {
		so = unp2->unp_socket;
		if (so != NULL)
			socantrcvmore(so);
	}
}

static void
unp_drop(struct unpcb *unp)
{
	struct socket *so = unp->unp_socket;
	struct unpcb *unp2;

	/*
	 * Regardless of whether the socket's peer dropped the connection
	 * with this socket by aborting or disconnecting, POSIX requires
	 * that ECONNRESET is returned.
	 */

	UNP_PCB_LOCK(unp);
	if (so)
		so->so_error = ECONNRESET;
	if ((unp2 = unp_pcb_lock_peer(unp)) != NULL) {
		/* Last reference dropped in unp_disconnect(). */
		unp_pcb_rele_notlast(unp);
		unp_disconnect(unp, unp2);
	} else if (!unp_pcb_rele(unp)) {
		UNP_PCB_UNLOCK(unp);
	}
}

static void
unp_freerights(struct filedescent **fdep, int fdcount)
{
	struct file *fp;
	int i;

	KASSERT(fdcount > 0, ("%s: fdcount %d", __func__, fdcount));

	for (i = 0; i < fdcount; i++) {
		fp = fdep[i]->fde_file;
		filecaps_free(&fdep[i]->fde_caps);
		unp_discard(fp);
	}
	free(fdep[0], M_FILECAPS);
}

static int
unp_externalize(struct mbuf *control, struct mbuf **controlp, int flags)
{
	struct thread *td = curthread;		/* XXX */
	struct cmsghdr *cm = mtod(control, struct cmsghdr *);
	int i;
	int *fdp;
	struct filedesc *fdesc = td->td_proc->p_fd;
	struct filedescent **fdep;
	void *data;
	socklen_t clen = control->m_len, datalen;
	int error, newfds;
	u_int newlen;

	UNP_LINK_UNLOCK_ASSERT();

	error = 0;
	if (controlp != NULL) /* controlp == NULL => free control messages */
		*controlp = NULL;
	while (cm != NULL) {
		if (sizeof(*cm) > clen || cm->cmsg_len > clen) {
			error = EINVAL;
			break;
		}
		data = CMSG_DATA(cm);
		datalen = (caddr_t)cm + cm->cmsg_len - (caddr_t)data;
		if (cm->cmsg_level == SOL_SOCKET
		    && cm->cmsg_type == SCM_RIGHTS) {
			newfds = datalen / sizeof(*fdep);
			if (newfds == 0)
				goto next;
			fdep = data;

			/* If we're not outputting the descriptors free them. */
			if (error || controlp == NULL) {
				unp_freerights(fdep, newfds);
				goto next;
			}
			FILEDESC_XLOCK(fdesc);

			/*
			 * Now change each pointer to an fd in the global
			 * table to an integer that is the index to the local
			 * fd table entry that we set up to point to the
			 * global one we are transferring.
			 */
			newlen = newfds * sizeof(int);
			*controlp = sbcreatecontrol(NULL, newlen,
			    SCM_RIGHTS, SOL_SOCKET);
			if (*controlp == NULL) {
				FILEDESC_XUNLOCK(fdesc);
				error = E2BIG;
				unp_freerights(fdep, newfds);
				goto next;
			}

			fdp = (int *)
			    CMSG_DATA(mtod(*controlp, struct cmsghdr *));
			if (fdallocn(td, 0, fdp, newfds) != 0) {
				FILEDESC_XUNLOCK(fdesc);
				error = EMSGSIZE;
				unp_freerights(fdep, newfds);
				m_freem(*controlp);
				*controlp = NULL;
				goto next;
			}
			for (i = 0; i < newfds; i++, fdp++) {
				_finstall(fdesc, fdep[i]->fde_file, *fdp,
				    (flags & MSG_CMSG_CLOEXEC) != 0 ? UF_EXCLOSE : 0,
				    &fdep[i]->fde_caps);
				unp_externalize_fp(fdep[i]->fde_file);
			}

			/*
			 * The new type indicates that the mbuf data refers to
			 * kernel resources that may need to be released before
			 * the mbuf is freed.
			 */
			m_chtype(*controlp, MT_EXTCONTROL);
			FILEDESC_XUNLOCK(fdesc);
			free(fdep[0], M_FILECAPS);
		} else {
			/* We can just copy anything else across. */
			if (error || controlp == NULL)
				goto next;
			*controlp = sbcreatecontrol(NULL, datalen,
			    cm->cmsg_type, cm->cmsg_level);
			if (*controlp == NULL) {
				error = ENOBUFS;
				goto next;
			}
			bcopy(data,
			    CMSG_DATA(mtod(*controlp, struct cmsghdr *)),
			    datalen);
		}
		controlp = &(*controlp)->m_next;

next:
		if (CMSG_SPACE(datalen) < clen) {
			clen -= CMSG_SPACE(datalen);
			cm = (struct cmsghdr *)
			    ((caddr_t)cm + CMSG_SPACE(datalen));
		} else {
			clen = 0;
			cm = NULL;
		}
	}

	m_freem(control);
	return (error);
}

static void
unp_zone_change(void *tag)
{

	uma_zone_set_max(unp_zone, maxsockets);
}

#ifdef INVARIANTS
static void
unp_zdtor(void *mem, int size __unused, void *arg __unused)
{
	struct unpcb *unp;

	unp = mem;

	KASSERT(LIST_EMPTY(&unp->unp_refs),
	    ("%s: unpcb %p has lingering refs", __func__, unp));
	KASSERT(unp->unp_socket == NULL,
	    ("%s: unpcb %p has socket backpointer", __func__, unp));
	KASSERT(unp->unp_vnode == NULL,
	    ("%s: unpcb %p has vnode references", __func__, unp));
	KASSERT(unp->unp_conn == NULL,
	    ("%s: unpcb %p is still connected", __func__, unp));
	KASSERT(unp->unp_addr == NULL,
	    ("%s: unpcb %p has leaked addr", __func__, unp));
}
#endif

static void
unp_init(void)
{
	uma_dtor dtor;

#ifdef VIMAGE
	if (!IS_DEFAULT_VNET(curvnet))
		return;
#endif

#ifdef INVARIANTS
	dtor = unp_zdtor;
#else
	dtor = NULL;
#endif
	unp_zone = uma_zcreate("unpcb", sizeof(struct unpcb), NULL, dtor,
	    NULL, NULL, UMA_ALIGN_CACHE, 0);
	uma_zone_set_max(unp_zone, maxsockets);
	uma_zone_set_warning(unp_zone, "kern.ipc.maxsockets limit reached");
	EVENTHANDLER_REGISTER(maxsockets_change, unp_zone_change,
	    NULL, EVENTHANDLER_PRI_ANY);
	LIST_INIT(&unp_dhead);
	LIST_INIT(&unp_shead);
	LIST_INIT(&unp_sphead);
	SLIST_INIT(&unp_defers);
	TIMEOUT_TASK_INIT(taskqueue_thread, &unp_gc_task, 0, unp_gc, NULL);
	TASK_INIT(&unp_defer_task, 0, unp_process_defers, NULL);
	UNP_LINK_LOCK_INIT();
	UNP_DEFERRED_LOCK_INIT();
}

static void
unp_internalize_cleanup_rights(struct mbuf *control)
{
	struct cmsghdr *cp;
	struct mbuf *m;
	void *data;
	socklen_t datalen;

	for (m = control; m != NULL; m = m->m_next) {
		cp = mtod(m, struct cmsghdr *);
		if (cp->cmsg_level != SOL_SOCKET ||
		    cp->cmsg_type != SCM_RIGHTS)
			continue;
		data = CMSG_DATA(cp);
		datalen = (caddr_t)cp + cp->cmsg_len - (caddr_t)data;
		unp_freerights(data, datalen / sizeof(struct filedesc *));
	}
}

static int
unp_internalize(struct mbuf **controlp, struct thread *td)
{
	struct mbuf *control, **initial_controlp;
	struct proc *p;
	struct filedesc *fdesc;
	struct bintime *bt;
	struct cmsghdr *cm;
	struct cmsgcred *cmcred;
	struct filedescent *fde, **fdep, *fdev;
	struct file *fp;
	struct timeval *tv;
	struct timespec *ts;
	void *data;
	socklen_t clen, datalen;
	int i, j, error, *fdp, oldfds;
	u_int newlen;

	UNP_LINK_UNLOCK_ASSERT();

	p = td->td_proc;
	fdesc = p->p_fd;
	error = 0;
	control = *controlp;
	clen = control->m_len;
	*controlp = NULL;
	initial_controlp = controlp;
	for (cm = mtod(control, struct cmsghdr *); cm != NULL;) {
		if (sizeof(*cm) > clen || cm->cmsg_level != SOL_SOCKET
		    || cm->cmsg_len > clen || cm->cmsg_len < sizeof(*cm)) {
			error = EINVAL;
			goto out;
		}
		data = CMSG_DATA(cm);
		datalen = (caddr_t)cm + cm->cmsg_len - (caddr_t)data;

		switch (cm->cmsg_type) {
		/*
		 * Fill in credential information.
		 */
		case SCM_CREDS:
			*controlp = sbcreatecontrol(NULL, sizeof(*cmcred),
			    SCM_CREDS, SOL_SOCKET);
			if (*controlp == NULL) {
				error = ENOBUFS;
				goto out;
			}
			cmcred = (struct cmsgcred *)
			    CMSG_DATA(mtod(*controlp, struct cmsghdr *));
			cmcred->cmcred_pid = p->p_pid;
			cmcred->cmcred_uid = td->td_ucred->cr_ruid;
			cmcred->cmcred_gid = td->td_ucred->cr_rgid;
			cmcred->cmcred_euid = td->td_ucred->cr_uid;
			cmcred->cmcred_ngroups = MIN(td->td_ucred->cr_ngroups,
			    CMGROUP_MAX);
			for (i = 0; i < cmcred->cmcred_ngroups; i++)
				cmcred->cmcred_groups[i] =
				    td->td_ucred->cr_groups[i];
			break;

		case SCM_RIGHTS:
			oldfds = datalen / sizeof (int);
			if (oldfds == 0)
				break;
			/*
			 * Check that all the FDs passed in refer to legal
			 * files.  If not, reject the entire operation.
			 */
			fdp = data;
			FILEDESC_SLOCK(fdesc);
			for (i = 0; i < oldfds; i++, fdp++) {
				fp = fget_locked(fdesc, *fdp);
				if (fp == NULL) {
					FILEDESC_SUNLOCK(fdesc);
					error = EBADF;
					goto out;
				}
				if (!(fp->f_ops->fo_flags & DFLAG_PASSABLE)) {
					FILEDESC_SUNLOCK(fdesc);
					error = EOPNOTSUPP;
					goto out;
				}
			}

			/*
			 * Now replace the integer FDs with pointers to the
			 * file structure and capability rights.
			 */
			newlen = oldfds * sizeof(fdep[0]);
			*controlp = sbcreatecontrol(NULL, newlen,
			    SCM_RIGHTS, SOL_SOCKET);
			if (*controlp == NULL) {
				FILEDESC_SUNLOCK(fdesc);
				error = E2BIG;
				goto out;
			}
			fdp = data;
			for (i = 0; i < oldfds; i++, fdp++) {
				if (!fhold(fdesc->fd_ofiles[*fdp].fde_file)) {
					fdp = data;
					for (j = 0; j < i; j++, fdp++) {
						fdrop(fdesc->fd_ofiles[*fdp].
						    fde_file, td);
					}
					FILEDESC_SUNLOCK(fdesc);
					error = EBADF;
					goto out;
				}
			}
			fdp = data;
			fdep = (struct filedescent **)
			    CMSG_DATA(mtod(*controlp, struct cmsghdr *));
			fdev = malloc(sizeof(*fdev) * oldfds, M_FILECAPS,
			    M_WAITOK);
			for (i = 0; i < oldfds; i++, fdev++, fdp++) {
				fde = &fdesc->fd_ofiles[*fdp];
				fdep[i] = fdev;
				fdep[i]->fde_file = fde->fde_file;
				filecaps_copy(&fde->fde_caps,
				    &fdep[i]->fde_caps, true);
				unp_internalize_fp(fdep[i]->fde_file);
			}
			FILEDESC_SUNLOCK(fdesc);
			break;

		case SCM_TIMESTAMP:
			*controlp = sbcreatecontrol(NULL, sizeof(*tv),
			    SCM_TIMESTAMP, SOL_SOCKET);
			if (*controlp == NULL) {
				error = ENOBUFS;
				goto out;
			}
			tv = (struct timeval *)
			    CMSG_DATA(mtod(*controlp, struct cmsghdr *));
			microtime(tv);
			break;

		case SCM_BINTIME:
			*controlp = sbcreatecontrol(NULL, sizeof(*bt),
			    SCM_BINTIME, SOL_SOCKET);
			if (*controlp == NULL) {
				error = ENOBUFS;
				goto out;
			}
			bt = (struct bintime *)
			    CMSG_DATA(mtod(*controlp, struct cmsghdr *));
			bintime(bt);
			break;

		case SCM_REALTIME:
			*controlp = sbcreatecontrol(NULL, sizeof(*ts),
			    SCM_REALTIME, SOL_SOCKET);
			if (*controlp == NULL) {
				error = ENOBUFS;
				goto out;
			}
			ts = (struct timespec *)
			    CMSG_DATA(mtod(*controlp, struct cmsghdr *));
			nanotime(ts);
			break;

		case SCM_MONOTONIC:
			*controlp = sbcreatecontrol(NULL, sizeof(*ts),
			    SCM_MONOTONIC, SOL_SOCKET);
			if (*controlp == NULL) {
				error = ENOBUFS;
				goto out;
			}
			ts = (struct timespec *)
			    CMSG_DATA(mtod(*controlp, struct cmsghdr *));
			nanouptime(ts);
			break;

		default:
			error = EINVAL;
			goto out;
		}

		if (*controlp != NULL)
			controlp = &(*controlp)->m_next;
		if (CMSG_SPACE(datalen) < clen) {
			clen -= CMSG_SPACE(datalen);
			cm = (struct cmsghdr *)
			    ((caddr_t)cm + CMSG_SPACE(datalen));
		} else {
			clen = 0;
			cm = NULL;
		}
	}

out:
	if (error != 0 && initial_controlp != NULL)
		unp_internalize_cleanup_rights(*initial_controlp);
	m_freem(control);
	return (error);
}

static struct mbuf *
unp_addsockcred(struct thread *td, struct mbuf *control, int mode)
{
	struct mbuf *m, *n, *n_prev;
	const struct cmsghdr *cm;
	int ngroups, i, cmsgtype;
	size_t ctrlsz;

	ngroups = MIN(td->td_ucred->cr_ngroups, CMGROUP_MAX);
	if (mode & UNP_WANTCRED_ALWAYS) {
		ctrlsz = SOCKCRED2SIZE(ngroups);
		cmsgtype = SCM_CREDS2;
	} else {
		ctrlsz = SOCKCREDSIZE(ngroups);
		cmsgtype = SCM_CREDS;
	}

	m = sbcreatecontrol(NULL, ctrlsz, cmsgtype, SOL_SOCKET);
	if (m == NULL)
		return (control);

	if (mode & UNP_WANTCRED_ALWAYS) {
		struct sockcred2 *sc;

		sc = (void *)CMSG_DATA(mtod(m, struct cmsghdr *));
		sc->sc_version = 0;
		sc->sc_pid = td->td_proc->p_pid;
		sc->sc_uid = td->td_ucred->cr_ruid;
		sc->sc_euid = td->td_ucred->cr_uid;
		sc->sc_gid = td->td_ucred->cr_rgid;
		sc->sc_egid = td->td_ucred->cr_gid;
		sc->sc_ngroups = ngroups;
		for (i = 0; i < sc->sc_ngroups; i++)
			sc->sc_groups[i] = td->td_ucred->cr_groups[i];
	} else {
		struct sockcred *sc;

		sc = (void *)CMSG_DATA(mtod(m, struct cmsghdr *));
		sc->sc_uid = td->td_ucred->cr_ruid;
		sc->sc_euid = td->td_ucred->cr_uid;
		sc->sc_gid = td->td_ucred->cr_rgid;
		sc->sc_egid = td->td_ucred->cr_gid;
		sc->sc_ngroups = ngroups;
		for (i = 0; i < sc->sc_ngroups; i++)
			sc->sc_groups[i] = td->td_ucred->cr_groups[i];
	}

	/*
	 * Unlink SCM_CREDS control messages (struct cmsgcred), since just
	 * created SCM_CREDS control message (struct sockcred) has another
	 * format.
	 */
	if (control != NULL && cmsgtype == SCM_CREDS)
		for (n = control, n_prev = NULL; n != NULL;) {
			cm = mtod(n, struct cmsghdr *);
    			if (cm->cmsg_level == SOL_SOCKET &&
			    cm->cmsg_type == SCM_CREDS) {
    				if (n_prev == NULL)
					control = n->m_next;
				else
					n_prev->m_next = n->m_next;
				n = m_free(n);
			} else {
				n_prev = n;
				n = n->m_next;
			}
		}

	/* Prepend it to the head. */
	m->m_next = control;
	return (m);
}

static struct unpcb *
fptounp(struct file *fp)
{
	struct socket *so;

	if (fp->f_type != DTYPE_SOCKET)
		return (NULL);
	if ((so = fp->f_data) == NULL)
		return (NULL);
	if (so->so_proto->pr_domain != &localdomain)
		return (NULL);
	return sotounpcb(so);
}

static void
unp_discard(struct file *fp)
{
	struct unp_defer *dr;

	if (unp_externalize_fp(fp)) {
		dr = malloc(sizeof(*dr), M_TEMP, M_WAITOK);
		dr->ud_fp = fp;
		UNP_DEFERRED_LOCK();
		SLIST_INSERT_HEAD(&unp_defers, dr, ud_link);
		UNP_DEFERRED_UNLOCK();
		atomic_add_int(&unp_defers_count, 1);
		taskqueue_enqueue(taskqueue_thread, &unp_defer_task);
	} else
		closef_nothread(fp);
}

static void
unp_process_defers(void *arg __unused, int pending)
{
	struct unp_defer *dr;
	SLIST_HEAD(, unp_defer) drl;
	int count;

	SLIST_INIT(&drl);
	for (;;) {
		UNP_DEFERRED_LOCK();
		if (SLIST_FIRST(&unp_defers) == NULL) {
			UNP_DEFERRED_UNLOCK();
			break;
		}
		SLIST_SWAP(&unp_defers, &drl, unp_defer);
		UNP_DEFERRED_UNLOCK();
		count = 0;
		while ((dr = SLIST_FIRST(&drl)) != NULL) {
			SLIST_REMOVE_HEAD(&drl, ud_link);
			closef_nothread(dr->ud_fp);
			free(dr, M_TEMP);
			count++;
		}
		atomic_add_int(&unp_defers_count, -count);
	}
}

static void
unp_internalize_fp(struct file *fp)
{
	struct unpcb *unp;

	UNP_LINK_WLOCK();
	if ((unp = fptounp(fp)) != NULL) {
		unp->unp_file = fp;
		unp->unp_msgcount++;
	}
	unp_rights++;
	UNP_LINK_WUNLOCK();
}

static int
unp_externalize_fp(struct file *fp)
{
	struct unpcb *unp;
	int ret;

	UNP_LINK_WLOCK();
	if ((unp = fptounp(fp)) != NULL) {
		unp->unp_msgcount--;
		ret = 1;
	} else
		ret = 0;
	unp_rights--;
	UNP_LINK_WUNLOCK();
	return (ret);
}

/*
 * unp_defer indicates whether additional work has been defered for a future
 * pass through unp_gc().  It is thread local and does not require explicit
 * synchronization.
 */
static int	unp_marked;

static void
unp_remove_dead_ref(struct filedescent **fdep, int fdcount)
{
	struct unpcb *unp;
	struct file *fp;
	int i;

	/*
	 * This function can only be called from the gc task.
	 */
	KASSERT(taskqueue_member(taskqueue_thread, curthread) != 0,
	    ("%s: not on gc callout", __func__));
	UNP_LINK_LOCK_ASSERT();

	for (i = 0; i < fdcount; i++) {
		fp = fdep[i]->fde_file;
		if ((unp = fptounp(fp)) == NULL)
			continue;
		if ((unp->unp_gcflag & UNPGC_DEAD) == 0)
			continue;
		unp->unp_gcrefs--;
	}
}

static void
unp_restore_undead_ref(struct filedescent **fdep, int fdcount)
{
	struct unpcb *unp;
	struct file *fp;
	int i;

	/*
	 * This function can only be called from the gc task.
	 */
	KASSERT(taskqueue_member(taskqueue_thread, curthread) != 0,
	    ("%s: not on gc callout", __func__));
	UNP_LINK_LOCK_ASSERT();

	for (i = 0; i < fdcount; i++) {
		fp = fdep[i]->fde_file;
		if ((unp = fptounp(fp)) == NULL)
			continue;
		if ((unp->unp_gcflag & UNPGC_DEAD) == 0)
			continue;
		unp->unp_gcrefs++;
		unp_marked++;
	}
}

static void
unp_gc_scan(struct unpcb *unp, void (*op)(struct filedescent **, int))
{
	struct socket *so, *soa;

	so = unp->unp_socket;
	SOCK_LOCK(so);
	if (SOLISTENING(so)) {
		/*
		 * Mark all sockets in our accept queue.
		 */
		TAILQ_FOREACH(soa, &so->sol_comp, so_list) {
			if (sotounpcb(soa)->unp_gcflag & UNPGC_IGNORE_RIGHTS)
				continue;
			SOCKBUF_LOCK(&soa->so_rcv);
			unp_scan(soa->so_rcv.sb_mb, op);
			SOCKBUF_UNLOCK(&soa->so_rcv);
		}
	} else {
		/*
		 * Mark all sockets we reference with RIGHTS.
		 */
		if ((unp->unp_gcflag & UNPGC_IGNORE_RIGHTS) == 0) {
			SOCKBUF_LOCK(&so->so_rcv);
			unp_scan(so->so_rcv.sb_mb, op);
			SOCKBUF_UNLOCK(&so->so_rcv);
		}
	}
	SOCK_UNLOCK(so);
}

static int unp_recycled;
SYSCTL_INT(_net_local, OID_AUTO, recycled, CTLFLAG_RD, &unp_recycled, 0,
    "Number of unreachable sockets claimed by the garbage collector.");

static int unp_taskcount;
SYSCTL_INT(_net_local, OID_AUTO, taskcount, CTLFLAG_RD, &unp_taskcount, 0,
    "Number of times the garbage collector has run.");

SYSCTL_UINT(_net_local, OID_AUTO, sockcount, CTLFLAG_RD, &unp_count, 0,
    "Number of active local sockets.");

static void
unp_gc(__unused void *arg, int pending)
{
	struct unp_head *heads[] = { &unp_dhead, &unp_shead, &unp_sphead,
				    NULL };
	struct unp_head **head;
	struct unp_head unp_deadhead;	/* List of potentially-dead sockets. */
	struct file *f, **unref;
	struct unpcb *unp, *unptmp;
	int i, total, unp_unreachable;

	LIST_INIT(&unp_deadhead);
	unp_taskcount++;
	UNP_LINK_RLOCK();
	/*
	 * First determine which sockets may be in cycles.
	 */
	unp_unreachable = 0;

	for (head = heads; *head != NULL; head++)
		LIST_FOREACH(unp, *head, unp_link) {
			KASSERT((unp->unp_gcflag & ~UNPGC_IGNORE_RIGHTS) == 0,
			    ("%s: unp %p has unexpected gc flags 0x%x",
			    __func__, unp, (unsigned int)unp->unp_gcflag));

			f = unp->unp_file;

			/*
			 * Check for an unreachable socket potentially in a
			 * cycle.  It must be in a queue as indicated by
			 * msgcount, and this must equal the file reference
			 * count.  Note that when msgcount is 0 the file is
			 * NULL.
			 */
			if (f != NULL && unp->unp_msgcount != 0 &&
			    refcount_load(&f->f_count) == unp->unp_msgcount) {
				LIST_INSERT_HEAD(&unp_deadhead, unp, unp_dead);
				unp->unp_gcflag |= UNPGC_DEAD;
				unp->unp_gcrefs = unp->unp_msgcount;
				unp_unreachable++;
			}
		}

	/*
	 * Scan all sockets previously marked as potentially being in a cycle
	 * and remove the references each socket holds on any UNPGC_DEAD
	 * sockets in its queue.  After this step, all remaining references on
	 * sockets marked UNPGC_DEAD should not be part of any cycle.
	 */
	LIST_FOREACH(unp, &unp_deadhead, unp_dead)
		unp_gc_scan(unp, unp_remove_dead_ref);

	/*
	 * If a socket still has a non-negative refcount, it cannot be in a
	 * cycle.  In this case increment refcount of all children iteratively.
	 * Stop the scan once we do a complete loop without discovering
	 * a new reachable socket.
	 */
	do {
		unp_marked = 0;
		LIST_FOREACH_SAFE(unp, &unp_deadhead, unp_dead, unptmp)
			if (unp->unp_gcrefs > 0) {
				unp->unp_gcflag &= ~UNPGC_DEAD;
				LIST_REMOVE(unp, unp_dead);
				KASSERT(unp_unreachable > 0,
				    ("%s: unp_unreachable underflow.",
				    __func__));
				unp_unreachable--;
				unp_gc_scan(unp, unp_restore_undead_ref);
			}
	} while (unp_marked);

	UNP_LINK_RUNLOCK();

	if (unp_unreachable == 0)
		return;

	/*
	 * Allocate space for a local array of dead unpcbs.
	 * TODO: can this path be simplified by instead using the local
	 * dead list at unp_deadhead, after taking out references
	 * on the file object and/or unpcb and dropping the link lock?
	 */
	unref = malloc(unp_unreachable * sizeof(struct file *),
	    M_TEMP, M_WAITOK);

	/*
	 * Iterate looking for sockets which have been specifically marked
	 * as unreachable and store them locally.
	 */
	UNP_LINK_RLOCK();
	total = 0;
	LIST_FOREACH(unp, &unp_deadhead, unp_dead) {
		KASSERT((unp->unp_gcflag & UNPGC_DEAD) != 0,
		    ("%s: unp %p not marked UNPGC_DEAD", __func__, unp));
		unp->unp_gcflag &= ~UNPGC_DEAD;
		f = unp->unp_file;
		if (unp->unp_msgcount == 0 || f == NULL ||
		    refcount_load(&f->f_count) != unp->unp_msgcount ||
		    !fhold(f))
			continue;
		unref[total++] = f;
		KASSERT(total <= unp_unreachable,
		    ("%s: incorrect unreachable count.", __func__));
	}
	UNP_LINK_RUNLOCK();

	/*
	 * Now flush all sockets, free'ing rights.  This will free the
	 * struct files associated with these sockets but leave each socket
	 * with one remaining ref.
	 */
	for (i = 0; i < total; i++) {
		struct socket *so;

		so = unref[i]->f_data;
		CURVNET_SET(so->so_vnet);
		sorflush(so);
		CURVNET_RESTORE();
	}

	/*
	 * And finally release the sockets so they can be reclaimed.
	 */
	for (i = 0; i < total; i++)
		fdrop(unref[i], NULL);
	unp_recycled += total;
	free(unref, M_TEMP);
}

static void
unp_dispose_mbuf(struct mbuf *m)
{

	if (m)
		unp_scan(m, unp_freerights);
}

/*
 * Synchronize against unp_gc, which can trip over data as we are freeing it.
 */
static void
unp_dispose(struct socket *so)
{
	struct unpcb *unp;

	unp = sotounpcb(so);
	UNP_LINK_WLOCK();
	unp->unp_gcflag |= UNPGC_IGNORE_RIGHTS;
	UNP_LINK_WUNLOCK();
	if (!SOLISTENING(so))
		unp_dispose_mbuf(so->so_rcv.sb_mb);
}

static void
unp_scan(struct mbuf *m0, void (*op)(struct filedescent **, int))
{
	struct mbuf *m;
	struct cmsghdr *cm;
	void *data;
	socklen_t clen, datalen;

	while (m0 != NULL) {
		for (m = m0; m; m = m->m_next) {
			if (m->m_type != MT_CONTROL)
				continue;

			cm = mtod(m, struct cmsghdr *);
			clen = m->m_len;

			while (cm != NULL) {
				if (sizeof(*cm) > clen || cm->cmsg_len > clen)
					break;

				data = CMSG_DATA(cm);
				datalen = (caddr_t)cm + cm->cmsg_len
				    - (caddr_t)data;

				if (cm->cmsg_level == SOL_SOCKET &&
				    cm->cmsg_type == SCM_RIGHTS) {
					(*op)(data, datalen /
					    sizeof(struct filedescent *));
				}

				if (CMSG_SPACE(datalen) < clen) {
					clen -= CMSG_SPACE(datalen);
					cm = (struct cmsghdr *)
					    ((caddr_t)cm + CMSG_SPACE(datalen));
				} else {
					clen = 0;
					cm = NULL;
				}
			}
		}
		m0 = m0->m_nextpkt;
	}
}

/*
 * A helper function called by VFS before socket-type vnode reclamation.
 * For an active vnode it clears unp_vnode pointer and decrements unp_vnode
 * use count.
 */
void
vfs_unp_reclaim(struct vnode *vp)
{
	struct unpcb *unp;
	int active;
	struct mtx *vplock;

	ASSERT_VOP_ELOCKED(vp, "vfs_unp_reclaim");
	KASSERT(vp->v_type == VSOCK,
	    ("vfs_unp_reclaim: vp->v_type != VSOCK"));

	active = 0;
	vplock = mtx_pool_find(mtxpool_sleep, vp);
	mtx_lock(vplock);
	VOP_UNP_CONNECT(vp, &unp);
	if (unp == NULL)
		goto done;
	UNP_PCB_LOCK(unp);
	if (unp->unp_vnode == vp) {
		VOP_UNP_DETACH(vp);
		unp->unp_vnode = NULL;
		active = 1;
	}
	UNP_PCB_UNLOCK(unp);
 done:
	mtx_unlock(vplock);
	if (active)
		vunref(vp);
}

#ifdef DDB
static void
db_print_indent(int indent)
{
	int i;

	for (i = 0; i < indent; i++)
		db_printf(" ");
}

static void
db_print_unpflags(int unp_flags)
{
	int comma;

	comma = 0;
	if (unp_flags & UNP_HAVEPC) {
		db_printf("%sUNP_HAVEPC", comma ? ", " : "");
		comma = 1;
	}
	if (unp_flags & UNP_WANTCRED_ALWAYS) {
		db_printf("%sUNP_WANTCRED_ALWAYS", comma ? ", " : "");
		comma = 1;
	}
	if (unp_flags & UNP_WANTCRED_ONESHOT) {
		db_printf("%sUNP_WANTCRED_ONESHOT", comma ? ", " : "");
		comma = 1;
	}
	if (unp_flags & UNP_CONNWAIT) {
		db_printf("%sUNP_CONNWAIT", comma ? ", " : "");
		comma = 1;
	}
	if (unp_flags & UNP_CONNECTING) {
		db_printf("%sUNP_CONNECTING", comma ? ", " : "");
		comma = 1;
	}
	if (unp_flags & UNP_BINDING) {
		db_printf("%sUNP_BINDING", comma ? ", " : "");
		comma = 1;
	}
}

static void
db_print_xucred(int indent, struct xucred *xu)
{
	int comma, i;

	db_print_indent(indent);
	db_printf("cr_version: %u   cr_uid: %u   cr_pid: %d   cr_ngroups: %d\n",
	    xu->cr_version, xu->cr_uid, xu->cr_pid, xu->cr_ngroups);
	db_print_indent(indent);
	db_printf("cr_groups: ");
	comma = 0;
	for (i = 0; i < xu->cr_ngroups; i++) {
		db_printf("%s%u", comma ? ", " : "", xu->cr_groups[i]);
		comma = 1;
	}
	db_printf("\n");
}

static void
db_print_unprefs(int indent, struct unp_head *uh)
{
	struct unpcb *unp;
	int counter;

	counter = 0;
	LIST_FOREACH(unp, uh, unp_reflink) {
		if (counter % 4 == 0)
			db_print_indent(indent);
		db_printf("%p  ", unp);
		if (counter % 4 == 3)
			db_printf("\n");
		counter++;
	}
	if (counter != 0 && counter % 4 != 0)
		db_printf("\n");
}

DB_SHOW_COMMAND(unpcb, db_show_unpcb)
{
	struct unpcb *unp;

        if (!have_addr) {
                db_printf("usage: show unpcb <addr>\n");
                return;
        }
        unp = (struct unpcb *)addr;

	db_printf("unp_socket: %p   unp_vnode: %p\n", unp->unp_socket,
	    unp->unp_vnode);

	db_printf("unp_ino: %ju   unp_conn: %p\n", (uintmax_t)unp->unp_ino,
	    unp->unp_conn);

	db_printf("unp_refs:\n");
	db_print_unprefs(2, &unp->unp_refs);

	/* XXXRW: Would be nice to print the full address, if any. */
	db_printf("unp_addr: %p\n", unp->unp_addr);

	db_printf("unp_gencnt: %llu\n",
	    (unsigned long long)unp->unp_gencnt);

	db_printf("unp_flags: %x (", unp->unp_flags);
	db_print_unpflags(unp->unp_flags);
	db_printf(")\n");

	db_printf("unp_peercred:\n");
	db_print_xucred(2, &unp->unp_peercred);

	db_printf("unp_refcount: %u\n", unp->unp_refcount);
}
#endif
