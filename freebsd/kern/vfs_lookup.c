/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)vfs_lookup.c	8.4 (Berkeley) 2/16/94
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_capsicum.h"
#include "opt_ktrace.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/capsicum.h>
#include <sys/fcntl.h>
#include <sys/jail.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/filedesc.h>
#include <sys/proc.h>
#include <sys/sdt.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#ifdef KTRACE
#include <sys/ktrace.h>
#endif
#ifdef INVARIANTS
#include <machine/_inttypes.h>
#endif

#include <security/audit/audit.h>
#include <security/mac/mac_framework.h>

#include <vm/uma.h>

#define	NAMEI_DIAGNOSTIC 1
#undef NAMEI_DIAGNOSTIC

SDT_PROVIDER_DEFINE(vfs);
SDT_PROBE_DEFINE4(vfs, namei, lookup, entry, "struct vnode *", "char *",
    "unsigned long", "bool");
SDT_PROBE_DEFINE4(vfs, namei, lookup, return, "int", "struct vnode *", "bool",
    "struct nameidata");

/* Allocation zone for namei. */
uma_zone_t namei_zone;

/* Placeholder vnode for mp traversal. */
static struct vnode *vp_crossmp;

static int
crossmp_vop_islocked(struct vop_islocked_args *ap)
{

	return (LK_SHARED);
}

static int
crossmp_vop_lock1(struct vop_lock1_args *ap)
{
	struct vnode *vp;
	struct lock *lk __unused;
	const char *file __unused;
	int flags, line __unused;

	vp = ap->a_vp;
	lk = vp->v_vnlock;
	flags = ap->a_flags;
	file = ap->a_file;
	line = ap->a_line;

	if ((flags & LK_SHARED) == 0)
		panic("invalid lock request for crossmp");

	WITNESS_CHECKORDER(&lk->lock_object, LOP_NEWORDER, file, line,
	    flags & LK_INTERLOCK ? &VI_MTX(vp)->lock_object : NULL);
	WITNESS_LOCK(&lk->lock_object, 0, file, line);
	if ((flags & LK_INTERLOCK) != 0)
		VI_UNLOCK(vp);
	LOCK_LOG_LOCK("SLOCK", &lk->lock_object, 0, 0, ap->a_file, line);
	return (0);
}

static int
crossmp_vop_unlock(struct vop_unlock_args *ap)
{
	struct vnode *vp;
	struct lock *lk __unused;

	vp = ap->a_vp;
	lk = vp->v_vnlock;

	WITNESS_UNLOCK(&lk->lock_object, 0, LOCK_FILE, LOCK_LINE);
	LOCK_LOG_LOCK("SUNLOCK", &lk->lock_object, 0, 0, LOCK_FILE,
	    LOCK_LINE);
	return (0);
}

static struct vop_vector crossmp_vnodeops = {
	.vop_default =		&default_vnodeops,
	.vop_islocked =		crossmp_vop_islocked,
	.vop_lock1 =		crossmp_vop_lock1,
	.vop_unlock =		crossmp_vop_unlock,
};
/*
 * VFS_VOP_VECTOR_REGISTER(crossmp_vnodeops) is not used here since the vnode
 * gets allocated early. See nameiinit for the direct call below.
 */

struct nameicap_tracker {
	struct vnode *dp;
	TAILQ_ENTRY(nameicap_tracker) nm_link;
};

/* Zone for cap mode tracker elements used for dotdot capability checks. */
MALLOC_DEFINE(M_NAMEITRACKER, "namei_tracker", "namei tracking for dotdot");

static void
nameiinit(void *dummy __unused)
{

	namei_zone = uma_zcreate("NAMEI", MAXPATHLEN, NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);
	vfs_vector_op_register(&crossmp_vnodeops);
	getnewvnode("crossmp", NULL, &crossmp_vnodeops, &vp_crossmp);
}
SYSINIT(vfs, SI_SUB_VFS, SI_ORDER_SECOND, nameiinit, NULL);

static int lookup_cap_dotdot = 1;
SYSCTL_INT(_vfs, OID_AUTO, lookup_cap_dotdot, CTLFLAG_RWTUN,
    &lookup_cap_dotdot, 0,
    "enables \"..\" components in path lookup in capability mode");
static int lookup_cap_dotdot_nonlocal = 1;
SYSCTL_INT(_vfs, OID_AUTO, lookup_cap_dotdot_nonlocal, CTLFLAG_RWTUN,
    &lookup_cap_dotdot_nonlocal, 0,
    "enables \"..\" components in path lookup in capability mode "
    "on non-local mount");

static void
nameicap_tracker_add(struct nameidata *ndp, struct vnode *dp)
{
	struct nameicap_tracker *nt;
	struct componentname *cnp;

	if ((ndp->ni_lcf & NI_LCF_CAP_DOTDOT) == 0 || dp->v_type != VDIR)
		return;
	cnp = &ndp->ni_cnd;
	nt = TAILQ_LAST(&ndp->ni_cap_tracker, nameicap_tracker_head);
	if (nt != NULL && nt->dp == dp)
		return;
	nt = malloc(sizeof(*nt), M_NAMEITRACKER, M_WAITOK);
	vhold(dp);
	nt->dp = dp;
	TAILQ_INSERT_TAIL(&ndp->ni_cap_tracker, nt, nm_link);
}

static void
nameicap_cleanup_from(struct nameidata *ndp, struct nameicap_tracker *first)
{
	struct nameicap_tracker *nt, *nt1;

	nt = first;
	TAILQ_FOREACH_FROM_SAFE(nt, &ndp->ni_cap_tracker, nm_link, nt1) {
		TAILQ_REMOVE(&ndp->ni_cap_tracker, nt, nm_link);
		vdrop(nt->dp);
		free(nt, M_NAMEITRACKER);
	}
}

static void
nameicap_cleanup(struct nameidata *ndp)
{
	KASSERT(TAILQ_EMPTY(&ndp->ni_cap_tracker) ||
	    (ndp->ni_lcf & NI_LCF_CAP_DOTDOT) != 0, ("not strictrelative"));
	nameicap_cleanup_from(ndp, NULL);
}

/*
 * For dotdot lookups in capability mode, only allow the component
 * lookup to succeed if the resulting directory was already traversed
 * during the operation.  This catches situations where already
 * traversed directory is moved to different parent, and then we walk
 * over it with dotdots.
 *
 * Also allow to force failure of dotdot lookups for non-local
 * filesystems, where external agents might assist local lookups to
 * escape the compartment.
 */
static int
nameicap_check_dotdot(struct nameidata *ndp, struct vnode *dp)
{
	struct nameicap_tracker *nt;
	struct mount *mp;

	if (dp == NULL || dp->v_type != VDIR || (ndp->ni_lcf &
	    NI_LCF_STRICTRELATIVE) == 0)
		return (0);
	if ((ndp->ni_lcf & NI_LCF_CAP_DOTDOT) == 0)
		return (ENOTCAPABLE);
	mp = dp->v_mount;
	if (lookup_cap_dotdot_nonlocal == 0 && mp != NULL &&
	    (mp->mnt_flag & MNT_LOCAL) == 0)
		return (ENOTCAPABLE);
	TAILQ_FOREACH_REVERSE(nt, &ndp->ni_cap_tracker, nameicap_tracker_head,
	    nm_link) {
		if (dp == nt->dp) {
			nt = TAILQ_NEXT(nt, nm_link);
			if (nt != NULL)
				nameicap_cleanup_from(ndp, nt);
			return (0);
		}
	}
	return (ENOTCAPABLE);
}

static void
namei_cleanup_cnp(struct componentname *cnp)
{

	uma_zfree(namei_zone, cnp->cn_pnbuf);
#ifdef DIAGNOSTIC
	cnp->cn_pnbuf = NULL;
	cnp->cn_nameptr = NULL;
#endif
}

static int
namei_handle_root(struct nameidata *ndp, struct vnode **dpp)
{
	struct componentname *cnp;

	cnp = &ndp->ni_cnd;
	if ((ndp->ni_lcf & NI_LCF_STRICTRELATIVE) != 0) {
#ifdef KTRACE
		if (KTRPOINT(curthread, KTR_CAPFAIL))
			ktrcapfail(CAPFAIL_LOOKUP, NULL, NULL);
#endif
		return (ENOTCAPABLE);
	}
	while (*(cnp->cn_nameptr) == '/') {
		cnp->cn_nameptr++;
		ndp->ni_pathlen--;
	}
	*dpp = ndp->ni_rootdir;
	vrefact(*dpp);
	return (0);
}

static int
namei_setup(struct nameidata *ndp, struct vnode **dpp, struct pwd **pwdp)
{
	struct componentname *cnp;
	struct file *dfp;
	struct thread *td;
	struct pwd *pwd;
	cap_rights_t rights;
	int error;
	bool startdir_used;

	cnp = &ndp->ni_cnd;
	td = cnp->cn_thread;

	startdir_used = false;
	*pwdp = NULL;
	*dpp = NULL;

#ifdef CAPABILITY_MODE
	/*
	 * In capability mode, lookups must be restricted to happen in
	 * the subtree with the root specified by the file descriptor:
	 * - The root must be real file descriptor, not the pseudo-descriptor
	 *   AT_FDCWD.
	 * - The passed path must be relative and not absolute.
	 * - If lookup_cap_dotdot is disabled, path must not contain the
	 *   '..' components.
	 * - If lookup_cap_dotdot is enabled, we verify that all '..'
	 *   components lookups result in the directories which were
	 *   previously walked by us, which prevents an escape from
	 *   the relative root.
	 */
	if (IN_CAPABILITY_MODE(td) && (cnp->cn_flags & NOCAPCHECK) == 0) {
		ndp->ni_lcf |= NI_LCF_STRICTRELATIVE;
		ndp->ni_resflags |= NIRES_STRICTREL;
		if (ndp->ni_dirfd == AT_FDCWD) {
#ifdef KTRACE
			if (KTRPOINT(td, KTR_CAPFAIL))
				ktrcapfail(CAPFAIL_LOOKUP, NULL, NULL);
#endif
			return (ECAPMODE);
		}
	}
#endif
	error = 0;

	/*
	 * Get starting point for the translation.
	 */
	pwd = pwd_hold(td);
	/*
	 * The reference on ni_rootdir is acquired in the block below to avoid
	 * back-to-back atomics for absolute lookups.
	 */
	ndp->ni_rootdir = pwd->pwd_rdir;
	ndp->ni_topdir = pwd->pwd_jdir;

	if (cnp->cn_pnbuf[0] == '/') {
		ndp->ni_resflags |= NIRES_ABS;
		error = namei_handle_root(ndp, dpp);
	} else {
		if (ndp->ni_startdir != NULL) {
			*dpp = ndp->ni_startdir;
			startdir_used = true;
		} else if (ndp->ni_dirfd == AT_FDCWD) {
			*dpp = pwd->pwd_cdir;
			vrefact(*dpp);
		} else {
			rights = *ndp->ni_rightsneeded;
			cap_rights_set_one(&rights, CAP_LOOKUP);

			if (cnp->cn_flags & AUDITVNODE1)
				AUDIT_ARG_ATFD1(ndp->ni_dirfd);
			if (cnp->cn_flags & AUDITVNODE2)
				AUDIT_ARG_ATFD2(ndp->ni_dirfd);
			/*
			 * Effectively inlined fgetvp_rights, because we need to
			 * inspect the file as well as grabbing the vnode.
			 */
			error = fget_cap(td, ndp->ni_dirfd, &rights,
			    &dfp, &ndp->ni_filecaps);
			if (error != 0) {
				/*
				 * Preserve the error; it should either be EBADF
				 * or capability-related, both of which can be
				 * safely returned to the caller.
				 */
			} else {
				if (dfp->f_ops == &badfileops) {
					error = EBADF;
				} else if (dfp->f_vnode == NULL) {
					error = ENOTDIR;
				} else {
					*dpp = dfp->f_vnode;
					vrefact(*dpp);

					if ((dfp->f_flag & FSEARCH) != 0)
						cnp->cn_flags |= NOEXECCHECK;
				}
				fdrop(dfp, td);
			}
#ifdef CAPABILITIES
			/*
			 * If file descriptor doesn't have all rights,
			 * all lookups relative to it must also be
			 * strictly relative.
			 */
			CAP_ALL(&rights);
			if (!cap_rights_contains(&ndp->ni_filecaps.fc_rights,
			    &rights) ||
			    ndp->ni_filecaps.fc_fcntls != CAP_FCNTL_ALL ||
			    ndp->ni_filecaps.fc_nioctls != -1) {
				ndp->ni_lcf |= NI_LCF_STRICTRELATIVE;
				ndp->ni_resflags |= NIRES_STRICTREL;
			}
#endif
		}
		if (error == 0 && (*dpp)->v_type != VDIR)
			error = ENOTDIR;
	}
	if (error == 0 && (cnp->cn_flags & RBENEATH) != 0) {
		if (cnp->cn_pnbuf[0] == '/') {
			error = ENOTCAPABLE;
		} else if ((ndp->ni_lcf & NI_LCF_STRICTRELATIVE) == 0) {
			ndp->ni_lcf |= NI_LCF_STRICTRELATIVE |
			    NI_LCF_CAP_DOTDOT;
		}
	}

	/*
	 * If we are auditing the kernel pathname, save the user pathname.
	 */
	if (cnp->cn_flags & AUDITVNODE1)
		AUDIT_ARG_UPATH1_VP(td, ndp->ni_rootdir, *dpp, cnp->cn_pnbuf);
	if (cnp->cn_flags & AUDITVNODE2)
		AUDIT_ARG_UPATH2_VP(td, ndp->ni_rootdir, *dpp, cnp->cn_pnbuf);
	if (ndp->ni_startdir != NULL && !startdir_used)
		vrele(ndp->ni_startdir);
	if (error != 0) {
		if (*dpp != NULL)
			vrele(*dpp);
		pwd_drop(pwd);
		return (error);
	}
	if ((ndp->ni_lcf & NI_LCF_STRICTRELATIVE) != 0 &&
	    lookup_cap_dotdot != 0)
		ndp->ni_lcf |= NI_LCF_CAP_DOTDOT;
	SDT_PROBE4(vfs, namei, lookup, entry, *dpp, cnp->cn_pnbuf,
	    cnp->cn_flags, false);
	*pwdp = pwd;
	return (0);
}

static int
namei_getpath(struct nameidata *ndp)
{
	struct componentname *cnp;
	int error;

	cnp = &ndp->ni_cnd;

	/*
	 * Get a buffer for the name to be translated, and copy the
	 * name into the buffer.
	 */
	cnp->cn_pnbuf = uma_zalloc(namei_zone, M_WAITOK);
	if (ndp->ni_segflg == UIO_SYSSPACE) {
		error = copystr(ndp->ni_dirp, cnp->cn_pnbuf, MAXPATHLEN,
		    &ndp->ni_pathlen);
	} else {
		error = copyinstr(ndp->ni_dirp, cnp->cn_pnbuf, MAXPATHLEN,
		    &ndp->ni_pathlen);
	}

	if (__predict_false(error != 0)) {
		namei_cleanup_cnp(cnp);
		return (error);
	}

	/*
	 * Don't allow empty pathnames.
	 */
	if (__predict_false(*cnp->cn_pnbuf == '\0')) {
		namei_cleanup_cnp(cnp);
		return (ENOENT);
	}

	cnp->cn_nameptr = cnp->cn_pnbuf;
	return (0);
}

/*
 * Convert a pathname into a pointer to a locked vnode.
 *
 * The FOLLOW flag is set when symbolic links are to be followed
 * when they occur at the end of the name translation process.
 * Symbolic links are always followed for all other pathname
 * components other than the last.
 *
 * The segflg defines whether the name is to be copied from user
 * space or kernel space.
 *
 * Overall outline of namei:
 *
 *	copy in name
 *	get starting directory
 *	while (!done && !error) {
 *		call lookup to search path.
 *		if symbolic link, massage name in buffer and continue
 *	}
 */
int
namei(struct nameidata *ndp)
{
	char *cp;		/* pointer into pathname argument */
	struct vnode *dp;	/* the directory we are searching */
	struct iovec aiov;		/* uio for reading symbolic links */
	struct componentname *cnp;
	struct thread *td;
	struct pwd *pwd;
	struct uio auio;
	int error, linklen;
	enum cache_fpl_status status;

	cnp = &ndp->ni_cnd;
	td = cnp->cn_thread;
#ifdef INVARIANTS
	KASSERT((ndp->ni_debugflags & NAMEI_DBG_CALLED) == 0,
	    ("%s: repeated call to namei without NDREINIT", __func__));
	KASSERT(ndp->ni_debugflags == NAMEI_DBG_INITED,
	    ("%s: bad debugflags %d", __func__, ndp->ni_debugflags));
	ndp->ni_debugflags |= NAMEI_DBG_CALLED;
	if (ndp->ni_startdir != NULL)
		ndp->ni_debugflags |= NAMEI_DBG_HADSTARTDIR;
	if (cnp->cn_flags & FAILIFEXISTS) {
		KASSERT(cnp->cn_nameiop == CREATE,
		    ("%s: FAILIFEXISTS passed for op %d", __func__, cnp->cn_nameiop));
		/*
		 * The limitation below is to restrict hairy corner cases.
		 */
		KASSERT((cnp->cn_flags & (LOCKPARENT | LOCKLEAF)) == LOCKPARENT,
		    ("%s: FAILIFEXISTS must be passed with LOCKPARENT and without LOCKLEAF",
		    __func__));
	}
	/*
	 * For NDVALIDATE.
	 *
	 * While NDINIT may seem like a more natural place to do it, there are
	 * callers which directly modify flags past invoking init.
	 */
	cnp->cn_origflags = cnp->cn_flags;
#endif
	ndp->ni_cnd.cn_cred = ndp->ni_cnd.cn_thread->td_ucred;
	KASSERT(ndp->ni_resflags == 0, ("%s: garbage in ni_resflags: %x\n",
	    __func__, ndp->ni_resflags));
	KASSERT(cnp->cn_cred && td->td_proc, ("namei: bad cred/proc"));
	KASSERT((cnp->cn_flags & NAMEI_INTERNAL_FLAGS) == 0,
	    ("namei: unexpected flags: %" PRIx64 "\n",
	    cnp->cn_flags & NAMEI_INTERNAL_FLAGS));
	if (cnp->cn_flags & NOCACHE)
		KASSERT(cnp->cn_nameiop != LOOKUP,
		    ("%s: NOCACHE passed with LOOKUP", __func__));
	MPASS(ndp->ni_startdir == NULL || ndp->ni_startdir->v_type == VDIR ||
	    ndp->ni_startdir->v_type == VBAD);

	ndp->ni_lcf = 0;
	ndp->ni_loopcnt = 0;
	ndp->ni_vp = NULL;

	error = namei_getpath(ndp);
	if (__predict_false(error != 0)) {
		return (error);
	}

#ifdef KTRACE
	if (KTRPOINT(td, KTR_NAMEI)) {
		KASSERT(cnp->cn_thread == curthread,
		    ("namei not using curthread"));
		ktrnamei(cnp->cn_pnbuf);
	}
#endif

	/*
	 * First try looking up the target without locking any vnodes.
	 *
	 * We may need to start from scratch or pick up where it left off.
	 */
	error = cache_fplookup(ndp, &status, &pwd);
	switch (status) {
	case CACHE_FPL_STATUS_UNSET:
		__assert_unreachable();
		break;
	case CACHE_FPL_STATUS_HANDLED:
		if (error == 0)
			NDVALIDATE(ndp);
		return (error);
	case CACHE_FPL_STATUS_PARTIAL:
		TAILQ_INIT(&ndp->ni_cap_tracker);
		dp = ndp->ni_startdir;
		break;
	case CACHE_FPL_STATUS_DESTROYED:
		ndp->ni_loopcnt = 0;
		error = namei_getpath(ndp);
		if (__predict_false(error != 0)) {
			return (error);
		}
		/* FALLTHROUGH */
	case CACHE_FPL_STATUS_ABORTED:
		TAILQ_INIT(&ndp->ni_cap_tracker);
		MPASS(ndp->ni_lcf == 0);
		error = namei_setup(ndp, &dp, &pwd);
		if (error != 0) {
			namei_cleanup_cnp(cnp);
			return (error);
		}
		break;
	}

	/*
	 * Locked lookup.
	 */
	for (;;) {
		ndp->ni_startdir = dp;
		error = lookup(ndp);
		if (error != 0)
			goto out;

		/*
		 * If not a symbolic link, we're done.
		 */
		if ((cnp->cn_flags & ISSYMLINK) == 0) {
			SDT_PROBE4(vfs, namei, lookup, return, error,
			    (error == 0 ? ndp->ni_vp : NULL), false, ndp);
			if ((cnp->cn_flags & (SAVENAME | SAVESTART)) == 0) {
				namei_cleanup_cnp(cnp);
			} else
				cnp->cn_flags |= HASBUF;
			nameicap_cleanup(ndp);
			pwd_drop(pwd);
			if (error == 0)
				NDVALIDATE(ndp);
			return (error);
		}
		if (ndp->ni_loopcnt++ >= MAXSYMLINKS) {
			error = ELOOP;
			break;
		}
#ifdef MAC
		if ((cnp->cn_flags & NOMACCHECK) == 0) {
			error = mac_vnode_check_readlink(td->td_ucred,
			    ndp->ni_vp);
			if (error != 0)
				break;
		}
#endif
		if (ndp->ni_pathlen > 1)
			cp = uma_zalloc(namei_zone, M_WAITOK);
		else
			cp = cnp->cn_pnbuf;
		aiov.iov_base = cp;
		aiov.iov_len = MAXPATHLEN;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = 0;
		auio.uio_rw = UIO_READ;
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_td = td;
		auio.uio_resid = MAXPATHLEN;
		error = VOP_READLINK(ndp->ni_vp, &auio, cnp->cn_cred);
		if (error != 0) {
			if (ndp->ni_pathlen > 1)
				uma_zfree(namei_zone, cp);
			break;
		}
		linklen = MAXPATHLEN - auio.uio_resid;
		if (linklen == 0) {
			if (ndp->ni_pathlen > 1)
				uma_zfree(namei_zone, cp);
			error = ENOENT;
			break;
		}
		if (linklen + ndp->ni_pathlen > MAXPATHLEN) {
			if (ndp->ni_pathlen > 1)
				uma_zfree(namei_zone, cp);
			error = ENAMETOOLONG;
			break;
		}
		if (ndp->ni_pathlen > 1) {
			bcopy(ndp->ni_next, cp + linklen, ndp->ni_pathlen);
			uma_zfree(namei_zone, cnp->cn_pnbuf);
			cnp->cn_pnbuf = cp;
		} else
			cnp->cn_pnbuf[linklen] = '\0';
		ndp->ni_pathlen += linklen;
		vput(ndp->ni_vp);
		dp = ndp->ni_dvp;
		/*
		 * Check if root directory should replace current directory.
		 */
		cnp->cn_nameptr = cnp->cn_pnbuf;
		if (*(cnp->cn_nameptr) == '/') {
			vrele(dp);
			error = namei_handle_root(ndp, &dp);
			if (error != 0)
				goto out;
		}
	}
	vput(ndp->ni_vp);
	ndp->ni_vp = NULL;
	vrele(ndp->ni_dvp);
out:
	MPASS(error != 0);
	SDT_PROBE4(vfs, namei, lookup, return, error, NULL, false, ndp);
	namei_cleanup_cnp(cnp);
	nameicap_cleanup(ndp);
	pwd_drop(pwd);
	return (error);
}

static int
compute_cn_lkflags(struct mount *mp, int lkflags, int cnflags)
{

	if (mp == NULL || ((lkflags & LK_SHARED) &&
	    (!(mp->mnt_kern_flag & MNTK_LOOKUP_SHARED) ||
	    ((cnflags & ISDOTDOT) &&
	    (mp->mnt_kern_flag & MNTK_LOOKUP_EXCL_DOTDOT))))) {
		lkflags &= ~LK_SHARED;
		lkflags |= LK_EXCLUSIVE;
	}
	lkflags |= LK_NODDLKTREAT;
	return (lkflags);
}

static __inline int
needs_exclusive_leaf(struct mount *mp, int flags)
{

	/*
	 * Intermediate nodes can use shared locks, we only need to
	 * force an exclusive lock for leaf nodes.
	 */
	if ((flags & (ISLASTCN | LOCKLEAF)) != (ISLASTCN | LOCKLEAF))
		return (0);

	/* Always use exclusive locks if LOCKSHARED isn't set. */
	if (!(flags & LOCKSHARED))
		return (1);

	/*
	 * For lookups during open(), if the mount point supports
	 * extended shared operations, then use a shared lock for the
	 * leaf node, otherwise use an exclusive lock.
	 */
	if ((flags & ISOPEN) != 0)
		return (!MNT_EXTENDED_SHARED(mp));

	/*
	 * Lookup requests outside of open() that specify LOCKSHARED
	 * only need a shared lock on the leaf vnode.
	 */
	return (0);
}

/*
 * Search a pathname.
 * This is a very central and rather complicated routine.
 *
 * The pathname is pointed to by ni_ptr and is of length ni_pathlen.
 * The starting directory is taken from ni_startdir. The pathname is
 * descended until done, or a symbolic link is encountered. The variable
 * ni_more is clear if the path is completed; it is set to one if a
 * symbolic link needing interpretation is encountered.
 *
 * The flag argument is LOOKUP, CREATE, RENAME, or DELETE depending on
 * whether the name is to be looked up, created, renamed, or deleted.
 * When CREATE, RENAME, or DELETE is specified, information usable in
 * creating, renaming, or deleting a directory entry may be calculated.
 * If flag has LOCKPARENT or'ed into it, the parent directory is returned
 * locked. If flag has WANTPARENT or'ed into it, the parent directory is
 * returned unlocked. Otherwise the parent directory is not returned. If
 * the target of the pathname exists and LOCKLEAF is or'ed into the flag
 * the target is returned locked, otherwise it is returned unlocked.
 * When creating or renaming and LOCKPARENT is specified, the target may not
 * be ".".  When deleting and LOCKPARENT is specified, the target may be ".".
 *
 * Overall outline of lookup:
 *
 * dirloop:
 *	identify next component of name at ndp->ni_ptr
 *	handle degenerate case where name is null string
 *	if .. and crossing mount points and on mounted filesys, find parent
 *	call VOP_LOOKUP routine for next component name
 *	    directory vnode returned in ni_dvp, unlocked unless LOCKPARENT set
 *	    component vnode returned in ni_vp (if it exists), locked.
 *	if result vnode is mounted on and crossing mount points,
 *	    find mounted on vnode
 *	if more components of name, do next level at dirloop
 *	return the answer in ni_vp, locked if LOCKLEAF set
 *	    if LOCKPARENT set, return locked parent in ni_dvp
 *	    if WANTPARENT set, return unlocked parent in ni_dvp
 */
int
lookup(struct nameidata *ndp)
{
	char *cp;			/* pointer into pathname argument */
	char *prev_ni_next;		/* saved ndp->ni_next */
	struct vnode *dp = NULL;	/* the directory we are searching */
	struct vnode *tdp;		/* saved dp */
	struct mount *mp;		/* mount table entry */
	struct prison *pr;
	size_t prev_ni_pathlen;		/* saved ndp->ni_pathlen */
	int docache;			/* == 0 do not cache last component */
	int wantparent;			/* 1 => wantparent or lockparent flag */
	int rdonly;			/* lookup read-only flag bit */
	int error = 0;
	int dpunlocked = 0;		/* dp has already been unlocked */
	int relookup = 0;		/* do not consume the path component */
	struct componentname *cnp = &ndp->ni_cnd;
	int lkflags_save;
	int ni_dvp_unlocked;

	/*
	 * Setup: break out flag bits into variables.
	 */
	ni_dvp_unlocked = 0;
	wantparent = cnp->cn_flags & (LOCKPARENT | WANTPARENT);
	KASSERT(cnp->cn_nameiop == LOOKUP || wantparent,
	    ("CREATE, DELETE, RENAME require LOCKPARENT or WANTPARENT."));
	/*
	 * When set to zero, docache causes the last component of the
	 * pathname to be deleted from the cache and the full lookup
	 * of the name to be done (via VOP_CACHEDLOOKUP()). Often
	 * filesystems need some pre-computed values that are made
	 * during the full lookup, for instance UFS sets dp->i_offset.
	 *
	 * The docache variable is set to zero when requested by the
	 * NOCACHE flag and for all modifying operations except CREATE.
	 */
	docache = (cnp->cn_flags & NOCACHE) ^ NOCACHE;
	if (cnp->cn_nameiop == DELETE ||
	    (wantparent && cnp->cn_nameiop != CREATE &&
	     cnp->cn_nameiop != LOOKUP))
		docache = 0;
	rdonly = cnp->cn_flags & RDONLY;
	cnp->cn_flags &= ~ISSYMLINK;
	ndp->ni_dvp = NULL;
	/*
	 * We use shared locks until we hit the parent of the last cn then
	 * we adjust based on the requesting flags.
	 */
	cnp->cn_lkflags = LK_SHARED;
	dp = ndp->ni_startdir;
	ndp->ni_startdir = NULLVP;
	vn_lock(dp,
	    compute_cn_lkflags(dp->v_mount, cnp->cn_lkflags | LK_RETRY,
	    cnp->cn_flags));

dirloop:
	/*
	 * Search a new directory.
	 *
	 * The last component of the filename is left accessible via
	 * cnp->cn_nameptr for callers that need the name. Callers needing
	 * the name set the SAVENAME flag. When done, they assume
	 * responsibility for freeing the pathname buffer.
	 */
	for (cp = cnp->cn_nameptr; *cp != 0 && *cp != '/'; cp++)
		continue;
	cnp->cn_namelen = cp - cnp->cn_nameptr;
	if (cnp->cn_namelen > NAME_MAX) {
		error = ENAMETOOLONG;
		goto bad;
	}
#ifdef NAMEI_DIAGNOSTIC
	{ char c = *cp;
	*cp = '\0';
	printf("{%s}: ", cnp->cn_nameptr);
	*cp = c; }
#endif
	prev_ni_pathlen = ndp->ni_pathlen;
	ndp->ni_pathlen -= cnp->cn_namelen;
	KASSERT(ndp->ni_pathlen <= PATH_MAX,
	    ("%s: ni_pathlen underflow to %zd\n", __func__, ndp->ni_pathlen));
	prev_ni_next = ndp->ni_next;
	ndp->ni_next = cp;

	/*
	 * Replace multiple slashes by a single slash and trailing slashes
	 * by a null.  This must be done before VOP_LOOKUP() because some
	 * fs's don't know about trailing slashes.  Remember if there were
	 * trailing slashes to handle symlinks, existing non-directories
	 * and non-existing files that won't be directories specially later.
	 */
	while (*cp == '/' && (cp[1] == '/' || cp[1] == '\0')) {
		cp++;
		ndp->ni_pathlen--;
		if (*cp == '\0') {
			*ndp->ni_next = '\0';
			cnp->cn_flags |= TRAILINGSLASH;
		}
	}
	ndp->ni_next = cp;

	cnp->cn_flags |= MAKEENTRY;
	if (*cp == '\0' && docache == 0)
		cnp->cn_flags &= ~MAKEENTRY;
	if (cnp->cn_namelen == 2 &&
	    cnp->cn_nameptr[1] == '.' && cnp->cn_nameptr[0] == '.')
		cnp->cn_flags |= ISDOTDOT;
	else
		cnp->cn_flags &= ~ISDOTDOT;
	if (*ndp->ni_next == 0)
		cnp->cn_flags |= ISLASTCN;
	else
		cnp->cn_flags &= ~ISLASTCN;

	if ((cnp->cn_flags & ISLASTCN) != 0 &&
	    cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.' &&
	    (cnp->cn_nameiop == DELETE || cnp->cn_nameiop == RENAME)) {
		error = EINVAL;
		goto bad;
	}

	nameicap_tracker_add(ndp, dp);

	/*
	 * Check for degenerate name (e.g. / or "")
	 * which is a way of talking about a directory,
	 * e.g. like "/." or ".".
	 */
	if (cnp->cn_nameptr[0] == '\0') {
		if (dp->v_type != VDIR) {
			error = ENOTDIR;
			goto bad;
		}
		if (cnp->cn_nameiop != LOOKUP) {
			error = EISDIR;
			goto bad;
		}
		if (wantparent) {
			ndp->ni_dvp = dp;
			VREF(dp);
		}
		ndp->ni_vp = dp;

		if (cnp->cn_flags & AUDITVNODE1)
			AUDIT_ARG_VNODE1(dp);
		else if (cnp->cn_flags & AUDITVNODE2)
			AUDIT_ARG_VNODE2(dp);

		if (!(cnp->cn_flags & (LOCKPARENT | LOCKLEAF)))
			VOP_UNLOCK(dp);
		/* XXX This should probably move to the top of function. */
		if (cnp->cn_flags & SAVESTART)
			panic("lookup: SAVESTART");
		goto success;
	}

	/*
	 * Handle "..": five special cases.
	 * 0. If doing a capability lookup and lookup_cap_dotdot is
	 *    disabled, return ENOTCAPABLE.
	 * 1. Return an error if this is the last component of
	 *    the name and the operation is DELETE or RENAME.
	 * 2. If at root directory (e.g. after chroot)
	 *    or at absolute root directory
	 *    then ignore it so can't get out.
	 * 3. If this vnode is the root of a mounted
	 *    filesystem, then replace it with the
	 *    vnode which was mounted on so we take the
	 *    .. in the other filesystem.
	 * 4. If the vnode is the top directory of
	 *    the jail or chroot, don't let them out.
	 * 5. If doing a capability lookup and lookup_cap_dotdot is
	 *    enabled, return ENOTCAPABLE if the lookup would escape
	 *    from the initial file descriptor directory.  Checks are
	 *    done by ensuring that namei() already traversed the
	 *    result of dotdot lookup.
	 */
	if (cnp->cn_flags & ISDOTDOT) {
		if ((ndp->ni_lcf & (NI_LCF_STRICTRELATIVE | NI_LCF_CAP_DOTDOT))
		    == NI_LCF_STRICTRELATIVE) {
#ifdef KTRACE
			if (KTRPOINT(curthread, KTR_CAPFAIL))
				ktrcapfail(CAPFAIL_LOOKUP, NULL, NULL);
#endif
			error = ENOTCAPABLE;
			goto bad;
		}
		if ((cnp->cn_flags & ISLASTCN) != 0 &&
		    (cnp->cn_nameiop == DELETE || cnp->cn_nameiop == RENAME)) {
			error = EINVAL;
			goto bad;
		}
		for (;;) {
			for (pr = cnp->cn_cred->cr_prison; pr != NULL;
			     pr = pr->pr_parent)
				if (dp == pr->pr_root)
					break;
			if (dp == ndp->ni_rootdir ||
			    dp == ndp->ni_topdir ||
			    dp == rootvnode ||
			    pr != NULL ||
			    ((dp->v_vflag & VV_ROOT) != 0 &&
			     (cnp->cn_flags & NOCROSSMOUNT) != 0)) {
				ndp->ni_dvp = dp;
				ndp->ni_vp = dp;
				VREF(dp);
				goto nextname;
			}
			if ((dp->v_vflag & VV_ROOT) == 0)
				break;
			if (VN_IS_DOOMED(dp)) {	/* forced unmount */
				error = ENOENT;
				goto bad;
			}
			tdp = dp;
			dp = dp->v_mount->mnt_vnodecovered;
			VREF(dp);
			vput(tdp);
			vn_lock(dp,
			    compute_cn_lkflags(dp->v_mount, cnp->cn_lkflags |
			    LK_RETRY, ISDOTDOT));
			error = nameicap_check_dotdot(ndp, dp);
			if (error != 0) {
#ifdef KTRACE
				if (KTRPOINT(curthread, KTR_CAPFAIL))
					ktrcapfail(CAPFAIL_LOOKUP, NULL, NULL);
#endif
				goto bad;
			}
		}
	}

	/*
	 * We now have a segment name to search for, and a directory to search.
	 */
unionlookup:
#ifdef MAC
	error = mac_vnode_check_lookup(cnp->cn_thread->td_ucred, dp, cnp);
	if (error)
		goto bad;
#endif
	ndp->ni_dvp = dp;
	ndp->ni_vp = NULL;
	ASSERT_VOP_LOCKED(dp, "lookup");
	/*
	 * If we have a shared lock we may need to upgrade the lock for the
	 * last operation.
	 */
	if ((cnp->cn_flags & LOCKPARENT) && (cnp->cn_flags & ISLASTCN) &&
	    dp != vp_crossmp && VOP_ISLOCKED(dp) == LK_SHARED)
		vn_lock(dp, LK_UPGRADE|LK_RETRY);
	if (VN_IS_DOOMED(dp)) {
		error = ENOENT;
		goto bad;
	}
	/*
	 * If we're looking up the last component and we need an exclusive
	 * lock, adjust our lkflags.
	 */
	if (needs_exclusive_leaf(dp->v_mount, cnp->cn_flags))
		cnp->cn_lkflags = LK_EXCLUSIVE;
#ifdef NAMEI_DIAGNOSTIC
	vn_printf(dp, "lookup in ");
#endif
	lkflags_save = cnp->cn_lkflags;
	cnp->cn_lkflags = compute_cn_lkflags(dp->v_mount, cnp->cn_lkflags,
	    cnp->cn_flags);
	error = VOP_LOOKUP(dp, &ndp->ni_vp, cnp);
	cnp->cn_lkflags = lkflags_save;
	if (error != 0) {
		KASSERT(ndp->ni_vp == NULL, ("leaf should be empty"));
#ifdef NAMEI_DIAGNOSTIC
		printf("not found\n");
#endif
		if ((error == ENOENT) &&
		    (dp->v_vflag & VV_ROOT) && (dp->v_mount != NULL) &&
		    (dp->v_mount->mnt_flag & MNT_UNION)) {
			tdp = dp;
			dp = dp->v_mount->mnt_vnodecovered;
			VREF(dp);
			vput(tdp);
			vn_lock(dp,
			    compute_cn_lkflags(dp->v_mount, cnp->cn_lkflags |
			    LK_RETRY, cnp->cn_flags));
			nameicap_tracker_add(ndp, dp);
			goto unionlookup;
		}

		if (error == ERELOOKUP) {
			vref(dp);
			ndp->ni_vp = dp;
			error = 0;
			relookup = 1;
			goto good;
		}

		if (error != EJUSTRETURN)
			goto bad;
		/*
		 * At this point, we know we're at the end of the
		 * pathname.  If creating / renaming, we can consider
		 * allowing the file or directory to be created / renamed,
		 * provided we're not on a read-only filesystem.
		 */
		if (rdonly) {
			error = EROFS;
			goto bad;
		}
		/* trailing slash only allowed for directories */
		if ((cnp->cn_flags & TRAILINGSLASH) &&
		    !(cnp->cn_flags & WILLBEDIR)) {
			error = ENOENT;
			goto bad;
		}
		if ((cnp->cn_flags & LOCKPARENT) == 0)
			VOP_UNLOCK(dp);
		/*
		 * We return with ni_vp NULL to indicate that the entry
		 * doesn't currently exist, leaving a pointer to the
		 * (possibly locked) directory vnode in ndp->ni_dvp.
		 */
		if (cnp->cn_flags & SAVESTART) {
			ndp->ni_startdir = ndp->ni_dvp;
			VREF(ndp->ni_startdir);
		}
		goto success;
	}

good:
#ifdef NAMEI_DIAGNOSTIC
	printf("found\n");
#endif
	dp = ndp->ni_vp;

	/*
	 * Check to see if the vnode has been mounted on;
	 * if so find the root of the mounted filesystem.
	 */
	while (dp->v_type == VDIR && (mp = dp->v_mountedhere) &&
	       (cnp->cn_flags & NOCROSSMOUNT) == 0) {
		if (vfs_busy(mp, 0))
			continue;
		vput(dp);
		if (dp != ndp->ni_dvp)
			vput(ndp->ni_dvp);
		else
			vrele(ndp->ni_dvp);
		vrefact(vp_crossmp);
		ndp->ni_dvp = vp_crossmp;
		error = VFS_ROOT(mp, compute_cn_lkflags(mp, cnp->cn_lkflags,
		    cnp->cn_flags), &tdp);
		vfs_unbusy(mp);
		if (vn_lock(vp_crossmp, LK_SHARED | LK_NOWAIT))
			panic("vp_crossmp exclusively locked or reclaimed");
		if (error) {
			dpunlocked = 1;
			goto bad2;
		}
		ndp->ni_vp = dp = tdp;
	}

	/*
	 * Check for symbolic link
	 */
	if ((dp->v_type == VLNK) &&
	    ((cnp->cn_flags & FOLLOW) || (cnp->cn_flags & TRAILINGSLASH) ||
	     *ndp->ni_next == '/')) {
		cnp->cn_flags |= ISSYMLINK;
		if (VN_IS_DOOMED(dp)) {
			/*
			 * We can't know whether the directory was mounted with
			 * NOSYMFOLLOW, so we can't follow safely.
			 */
			error = ENOENT;
			goto bad2;
		}
		if (dp->v_mount->mnt_flag & MNT_NOSYMFOLLOW) {
			error = EACCES;
			goto bad2;
		}
		/*
		 * Symlink code always expects an unlocked dvp.
		 */
		if (ndp->ni_dvp != ndp->ni_vp) {
			VOP_UNLOCK(ndp->ni_dvp);
			ni_dvp_unlocked = 1;
		}
		goto success;
	}

nextname:
	/*
	 * Not a symbolic link that we will follow.  Continue with the
	 * next component if there is any; otherwise, we're done.
	 */
	KASSERT((cnp->cn_flags & ISLASTCN) || *ndp->ni_next == '/',
	    ("lookup: invalid path state."));
	if (relookup) {
		relookup = 0;
		ndp->ni_pathlen = prev_ni_pathlen;
		ndp->ni_next = prev_ni_next;
		if (ndp->ni_dvp != dp)
			vput(ndp->ni_dvp);
		else
			vrele(ndp->ni_dvp);
		goto dirloop;
	}
	if (cnp->cn_flags & ISDOTDOT) {
		error = nameicap_check_dotdot(ndp, ndp->ni_vp);
		if (error != 0) {
#ifdef KTRACE
			if (KTRPOINT(curthread, KTR_CAPFAIL))
				ktrcapfail(CAPFAIL_LOOKUP, NULL, NULL);
#endif
			goto bad2;
		}
	}
	if (*ndp->ni_next == '/') {
		cnp->cn_nameptr = ndp->ni_next;
		while (*cnp->cn_nameptr == '/') {
			cnp->cn_nameptr++;
			ndp->ni_pathlen--;
		}
		if (ndp->ni_dvp != dp)
			vput(ndp->ni_dvp);
		else
			vrele(ndp->ni_dvp);
		goto dirloop;
	}
	/*
	 * If we're processing a path with a trailing slash,
	 * check that the end result is a directory.
	 */
	if ((cnp->cn_flags & TRAILINGSLASH) && dp->v_type != VDIR) {
		error = ENOTDIR;
		goto bad2;
	}
	/*
	 * Disallow directory write attempts on read-only filesystems.
	 */
	if (rdonly &&
	    (cnp->cn_nameiop == DELETE || cnp->cn_nameiop == RENAME)) {
		error = EROFS;
		goto bad2;
	}
	if (cnp->cn_flags & SAVESTART) {
		ndp->ni_startdir = ndp->ni_dvp;
		VREF(ndp->ni_startdir);
	}
	if (!wantparent) {
		ni_dvp_unlocked = 2;
		if (ndp->ni_dvp != dp)
			vput(ndp->ni_dvp);
		else
			vrele(ndp->ni_dvp);
	} else if ((cnp->cn_flags & LOCKPARENT) == 0 && ndp->ni_dvp != dp) {
		VOP_UNLOCK(ndp->ni_dvp);
		ni_dvp_unlocked = 1;
	}

	if (cnp->cn_flags & AUDITVNODE1)
		AUDIT_ARG_VNODE1(dp);
	else if (cnp->cn_flags & AUDITVNODE2)
		AUDIT_ARG_VNODE2(dp);

	if ((cnp->cn_flags & LOCKLEAF) == 0)
		VOP_UNLOCK(dp);
success:
	/*
	 * FIXME: for lookups which only cross a mount point to fetch the
	 * root vnode, ni_dvp will be set to vp_crossmp. This can be a problem
	 * if either WANTPARENT or LOCKPARENT is set.
	 */
	/*
	 * Because of shared lookup we may have the vnode shared locked, but
	 * the caller may want it to be exclusively locked.
	 */
	if (needs_exclusive_leaf(dp->v_mount, cnp->cn_flags) &&
	    VOP_ISLOCKED(dp) != LK_EXCLUSIVE) {
		vn_lock(dp, LK_UPGRADE | LK_RETRY);
		if (VN_IS_DOOMED(dp)) {
			error = ENOENT;
			goto bad2;
		}
	}
	if (ndp->ni_vp != NULL) {
		if ((cnp->cn_flags & ISDOTDOT) == 0)
			nameicap_tracker_add(ndp, ndp->ni_vp);
		if ((cnp->cn_flags & (FAILIFEXISTS | ISSYMLINK)) == FAILIFEXISTS)
			goto bad_eexist;
	}
	return (0);

bad2:
	if (ni_dvp_unlocked != 2) {
		if (dp != ndp->ni_dvp && !ni_dvp_unlocked)
			vput(ndp->ni_dvp);
		else
			vrele(ndp->ni_dvp);
	}
bad:
	if (!dpunlocked)
		vput(dp);
	ndp->ni_vp = NULL;
	return (error);
bad_eexist:
	/*
	 * FAILIFEXISTS handling.
	 *
	 * XXX namei called with LOCKPARENT but not LOCKLEAF has the strange
	 * behaviour of leaving the vnode unlocked if the target is the same
	 * vnode as the parent.
	 */
	MPASS((cnp->cn_flags & ISSYMLINK) == 0);
	if (ndp->ni_vp == ndp->ni_dvp)
		vrele(ndp->ni_dvp);
	else
		vput(ndp->ni_dvp);
	vrele(ndp->ni_vp);
	ndp->ni_dvp = NULL;
	ndp->ni_vp = NULL;
	NDFREE(ndp, NDF_ONLY_PNBUF);
	return (EEXIST);
}

/*
 * relookup - lookup a path name component
 *    Used by lookup to re-acquire things.
 */
int
relookup(struct vnode *dvp, struct vnode **vpp, struct componentname *cnp)
{
	struct vnode *dp = NULL;		/* the directory we are searching */
	int rdonly;			/* lookup read-only flag bit */
	int error = 0;

	KASSERT(cnp->cn_flags & ISLASTCN,
	    ("relookup: Not given last component."));
	/*
	 * Setup: break out flag bits into variables.
	 */
	KASSERT((cnp->cn_flags & (LOCKPARENT | WANTPARENT)) != 0,
	    ("relookup: parent not wanted"));
	rdonly = cnp->cn_flags & RDONLY;
	cnp->cn_flags &= ~ISSYMLINK;
	dp = dvp;
	cnp->cn_lkflags = LK_EXCLUSIVE;
	vn_lock(dp, LK_EXCLUSIVE | LK_RETRY);

	/*
	 * Search a new directory.
	 *
	 * The last component of the filename is left accessible via
	 * cnp->cn_nameptr for callers that need the name. Callers needing
	 * the name set the SAVENAME flag. When done, they assume
	 * responsibility for freeing the pathname buffer.
	 */
#ifdef NAMEI_DIAGNOSTIC
	printf("{%s}: ", cnp->cn_nameptr);
#endif

	/*
	 * Check for "" which represents the root directory after slash
	 * removal.
	 */
	if (cnp->cn_nameptr[0] == '\0') {
		/*
		 * Support only LOOKUP for "/" because lookup()
		 * can't succeed for CREATE, DELETE and RENAME.
		 */
		KASSERT(cnp->cn_nameiop == LOOKUP, ("nameiop must be LOOKUP"));
		KASSERT(dp->v_type == VDIR, ("dp is not a directory"));

		if (!(cnp->cn_flags & LOCKLEAF))
			VOP_UNLOCK(dp);
		*vpp = dp;
		/* XXX This should probably move to the top of function. */
		if (cnp->cn_flags & SAVESTART)
			panic("lookup: SAVESTART");
		return (0);
	}

	if (cnp->cn_flags & ISDOTDOT)
		panic ("relookup: lookup on dot-dot");

	/*
	 * We now have a segment name to search for, and a directory to search.
	 */
#ifdef NAMEI_DIAGNOSTIC
	vn_printf(dp, "search in ");
#endif
	if ((error = VOP_LOOKUP(dp, vpp, cnp)) != 0) {
		KASSERT(*vpp == NULL, ("leaf should be empty"));
		if (error != EJUSTRETURN)
			goto bad;
		/*
		 * If creating and at end of pathname, then can consider
		 * allowing file to be created.
		 */
		if (rdonly) {
			error = EROFS;
			goto bad;
		}
		/* ASSERT(dvp == ndp->ni_startdir) */
		if (cnp->cn_flags & SAVESTART)
			VREF(dvp);
		if ((cnp->cn_flags & LOCKPARENT) == 0)
			VOP_UNLOCK(dp);
		/*
		 * We return with ni_vp NULL to indicate that the entry
		 * doesn't currently exist, leaving a pointer to the
		 * (possibly locked) directory vnode in ndp->ni_dvp.
		 */
		return (0);
	}

	dp = *vpp;

	/*
	 * Disallow directory write attempts on read-only filesystems.
	 */
	if (rdonly &&
	    (cnp->cn_nameiop == DELETE || cnp->cn_nameiop == RENAME)) {
		if (dvp == dp)
			vrele(dvp);
		else
			vput(dvp);
		error = EROFS;
		goto bad;
	}
	/*
	 * Set the parent lock/ref state to the requested state.
	 */
	if ((cnp->cn_flags & LOCKPARENT) == 0 && dvp != dp)
		VOP_UNLOCK(dvp);
	/*
	 * Check for symbolic link
	 */
	KASSERT(dp->v_type != VLNK || !(cnp->cn_flags & FOLLOW),
	    ("relookup: symlink found.\n"));

	/* ASSERT(dvp == ndp->ni_startdir) */
	if (cnp->cn_flags & SAVESTART)
		VREF(dvp);

	if ((cnp->cn_flags & LOCKLEAF) == 0)
		VOP_UNLOCK(dp);
	return (0);
bad:
	vput(dp);
	*vpp = NULL;
	return (error);
}

/*
 * Free data allocated by namei(); see namei(9) for details.
 */
void
NDFREE_PNBUF(struct nameidata *ndp)
{

	if ((ndp->ni_cnd.cn_flags & HASBUF) != 0) {
		MPASS((ndp->ni_cnd.cn_flags & (SAVENAME | SAVESTART)) != 0);
		uma_zfree(namei_zone, ndp->ni_cnd.cn_pnbuf);
		ndp->ni_cnd.cn_flags &= ~HASBUF;
	}
}

/*
 * NDFREE_PNBUF replacement for callers that know there is no buffer.
 *
 * This is a hack. Preferably the VFS layer would not produce anything more
 * than it was asked to do. Unfortunately several non-LOOKUP cases can add the
 * HASBUF flag to the result. Even then an interface could be implemented where
 * the caller specifies what they expected to see in the result and what they
 * are going to take care of.
 *
 * In the meantime provide this kludge as a trivial replacement for NDFREE_PNBUF
 * calls scattered throughout the kernel where we know for a fact the flag must not
 * be seen.
 */
#ifdef INVARIANTS
void
NDFREE_NOTHING(struct nameidata *ndp)
{
	struct componentname *cnp;

	cnp = &ndp->ni_cnd;
	KASSERT(cnp->cn_nameiop == LOOKUP, ("%s: got non-LOOKUP op %d\n",
	    __func__, cnp->cn_nameiop));
	KASSERT((cnp->cn_flags & (SAVENAME | HASBUF)) == 0,
	    ("%s: bad flags \%" PRIx64 "\n", __func__, cnp->cn_flags));
}
#endif

void
(NDFREE)(struct nameidata *ndp, const u_int flags)
{
	int unlock_dvp;
	int unlock_vp;

	unlock_dvp = 0;
	unlock_vp = 0;

	if (!(flags & NDF_NO_FREE_PNBUF)) {
		NDFREE_PNBUF(ndp);
	}
	if (!(flags & NDF_NO_VP_UNLOCK) &&
	    (ndp->ni_cnd.cn_flags & LOCKLEAF) && ndp->ni_vp)
		unlock_vp = 1;
	if (!(flags & NDF_NO_DVP_UNLOCK) &&
	    (ndp->ni_cnd.cn_flags & LOCKPARENT) &&
	    ndp->ni_dvp != ndp->ni_vp)
		unlock_dvp = 1;
	if (!(flags & NDF_NO_VP_RELE) && ndp->ni_vp) {
		if (unlock_vp) {
			vput(ndp->ni_vp);
			unlock_vp = 0;
		} else
			vrele(ndp->ni_vp);
		ndp->ni_vp = NULL;
	}
	if (unlock_vp)
		VOP_UNLOCK(ndp->ni_vp);
	if (!(flags & NDF_NO_DVP_RELE) &&
	    (ndp->ni_cnd.cn_flags & (LOCKPARENT|WANTPARENT))) {
		if (unlock_dvp) {
			vput(ndp->ni_dvp);
			unlock_dvp = 0;
		} else
			vrele(ndp->ni_dvp);
		ndp->ni_dvp = NULL;
	}
	if (unlock_dvp)
		VOP_UNLOCK(ndp->ni_dvp);
	if (!(flags & NDF_NO_STARTDIR_RELE) &&
	    (ndp->ni_cnd.cn_flags & SAVESTART)) {
		vrele(ndp->ni_startdir);
		ndp->ni_startdir = NULL;
	}
}

#ifdef INVARIANTS
/*
 * Validate the final state of ndp after the lookup.
 *
 * Historically filesystems were allowed to modify cn_flags. Most notably they
 * can add SAVENAME to the request, resulting in HASBUF and pushing subsequent
 * clean up to the consumer. In practice this seems to only concern != LOOKUP
 * operations.
 *
 * As a step towards stricter API contract this routine validates the state to
 * clean up. Note validation is a work in progress with the intent of becoming
 * stricter over time.
 */
#define NDMODIFYINGFLAGS (LOCKLEAF | LOCKPARENT | WANTPARENT | SAVENAME | SAVESTART | HASBUF)
void
NDVALIDATE(struct nameidata *ndp)
{
	struct componentname *cnp;
	u_int64_t used, orig;

	cnp = &ndp->ni_cnd;
	orig = cnp->cn_origflags;
	used = cnp->cn_flags;
	switch (cnp->cn_nameiop) {
	case LOOKUP:
		/*
		 * For plain lookup we require strict conformance -- nothing
		 * to clean up if it was not requested by the caller.
		 */
		orig &= NDMODIFYINGFLAGS;
		used &= NDMODIFYINGFLAGS;
		if ((orig & (SAVENAME | SAVESTART)) != 0)
			orig |= HASBUF;
		if (orig != used) {
			goto out_mismatch;
		}
		break;
	case CREATE:
	case DELETE:
	case RENAME:
		/*
		 * Some filesystems set SAVENAME to provoke HASBUF, accomodate
		 * for it until it gets fixed.
		 */
		orig &= NDMODIFYINGFLAGS;
		orig |= (SAVENAME | HASBUF);
		used &= NDMODIFYINGFLAGS;
		used |= (SAVENAME | HASBUF);
		if (orig != used) {
			goto out_mismatch;
		}
		break;
	}
	return;
out_mismatch:
	panic("%s: mismatched flags for op %d: added %" PRIx64 ", "
	    "removed %" PRIx64" (%" PRIx64" != %" PRIx64"; stored %" PRIx64" != %" PRIx64")",
	    __func__, cnp->cn_nameiop, used & ~orig, orig &~ used,
	    orig, used, cnp->cn_origflags, cnp->cn_flags);
}
#endif

/*
 * Determine if there is a suitable alternate filename under the specified
 * prefix for the specified path.  If the create flag is set, then the
 * alternate prefix will be used so long as the parent directory exists.
 * This is used by the various compatibility ABIs so that Linux binaries prefer
 * files under /compat/linux for example.  The chosen path (whether under
 * the prefix or under /) is returned in a kernel malloc'd buffer pointed
 * to by pathbuf.  The caller is responsible for free'ing the buffer from
 * the M_TEMP bucket if one is returned.
 */
int
kern_alternate_path(struct thread *td, const char *prefix, const char *path,
    enum uio_seg pathseg, char **pathbuf, int create, int dirfd)
{
	struct nameidata nd, ndroot;
	char *ptr, *buf, *cp;
	size_t len, sz;
	int error;

	buf = (char *) malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
	*pathbuf = buf;

	/* Copy the prefix into the new pathname as a starting point. */
	len = strlcpy(buf, prefix, MAXPATHLEN);
	if (len >= MAXPATHLEN) {
		*pathbuf = NULL;
		free(buf, M_TEMP);
		return (EINVAL);
	}
	sz = MAXPATHLEN - len;
	ptr = buf + len;

	/* Append the filename to the prefix. */
	if (pathseg == UIO_SYSSPACE)
		error = copystr(path, ptr, sz, &len);
	else
		error = copyinstr(path, ptr, sz, &len);

	if (error) {
		*pathbuf = NULL;
		free(buf, M_TEMP);
		return (error);
	}

	/* Only use a prefix with absolute pathnames. */
	if (*ptr != '/') {
		error = EINVAL;
		goto keeporig;
	}

	if (dirfd != AT_FDCWD) {
		/*
		 * We want the original because the "prefix" is
		 * included in the already opened dirfd.
		 */
		bcopy(ptr, buf, len);
		return (0);
	}

	/*
	 * We know that there is a / somewhere in this pathname.
	 * Search backwards for it, to find the file's parent dir
	 * to see if it exists in the alternate tree. If it does,
	 * and we want to create a file (cflag is set). We don't
	 * need to worry about the root comparison in this case.
	 */

	if (create) {
		for (cp = &ptr[len] - 1; *cp != '/'; cp--);
		*cp = '\0';

		NDINIT(&nd, LOOKUP, NOFOLLOW, UIO_SYSSPACE, buf, td);
		error = namei(&nd);
		*cp = '/';
		if (error != 0)
			goto keeporig;
	} else {
		NDINIT(&nd, LOOKUP, NOFOLLOW, UIO_SYSSPACE, buf, td);

		error = namei(&nd);
		if (error != 0)
			goto keeporig;

		/*
		 * We now compare the vnode of the prefix to the one
		 * vnode asked. If they resolve to be the same, then we
		 * ignore the match so that the real root gets used.
		 * This avoids the problem of traversing "../.." to find the
		 * root directory and never finding it, because "/" resolves
		 * to the emulation root directory. This is expensive :-(
		 */
		NDINIT(&ndroot, LOOKUP, FOLLOW, UIO_SYSSPACE, prefix,
		    td);

		/* We shouldn't ever get an error from this namei(). */
		error = namei(&ndroot);
		if (error == 0) {
			if (nd.ni_vp == ndroot.ni_vp)
				error = ENOENT;

			NDFREE(&ndroot, NDF_ONLY_PNBUF);
			vrele(ndroot.ni_vp);
		}
	}

	NDFREE(&nd, NDF_ONLY_PNBUF);
	vrele(nd.ni_vp);

keeporig:
	/* If there was an error, use the original path name. */
	if (error)
		bcopy(ptr, buf, len);
	return (error);
}
