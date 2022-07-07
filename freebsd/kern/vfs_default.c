/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed
 * to Berkeley by John Heidemann of the UCLA Ficus project.
 *
 * Source: * @(#)i405_init.c 2.10 92/04/27 UCLA Ficus project
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/event.h>
#include <sys/filio.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/lockf.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/rwlock.h>
#include <sys/fcntl.h>
#include <sys/unistd.h>
#include <sys/vnode.h>
#include <sys/dirent.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <security/audit/audit.h>
#include <sys/priv.h>

#include <security/mac/mac_framework.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/vnode_pager.h>

static int	vop_nolookup(struct vop_lookup_args *);
static int	vop_norename(struct vop_rename_args *);
static int	vop_nostrategy(struct vop_strategy_args *);
static int	get_next_dirent(struct vnode *vp, struct dirent **dpp,
				char *dirbuf, int dirbuflen, off_t *off,
				char **cpos, int *len, int *eofflag,
				struct thread *td);
static int	dirent_exists(struct vnode *vp, const char *dirname,
			      struct thread *td);

#define DIRENT_MINSIZE (sizeof(struct dirent) - (MAXNAMLEN+1) + 4)

static int vop_stdis_text(struct vop_is_text_args *ap);
static int vop_stdunset_text(struct vop_unset_text_args *ap);
static int vop_stdadd_writecount(struct vop_add_writecount_args *ap);
static int vop_stdcopy_file_range(struct vop_copy_file_range_args *ap);
static int vop_stdfdatasync(struct vop_fdatasync_args *ap);
static int vop_stdgetpages_async(struct vop_getpages_async_args *ap);
static int vop_stdread_pgcache(struct vop_read_pgcache_args *ap);
static int vop_stdstat(struct vop_stat_args *ap);
static int vop_stdvput_pair(struct vop_vput_pair_args *ap);

/*
 * This vnode table stores what we want to do if the filesystem doesn't
 * implement a particular VOP.
 *
 * If there is no specific entry here, we will return EOPNOTSUPP.
 *
 * Note that every filesystem has to implement either vop_access
 * or vop_accessx; failing to do so will result in immediate crash
 * due to stack overflow, as vop_stdaccess() calls vop_stdaccessx(),
 * which calls vop_stdaccess() etc.
 */

struct vop_vector default_vnodeops = {
	.vop_default =		NULL,
	.vop_bypass =		VOP_EOPNOTSUPP,

	.vop_access =		vop_stdaccess,
	.vop_accessx =		vop_stdaccessx,
	.vop_advise =		vop_stdadvise,
	.vop_advlock =		vop_stdadvlock,
	.vop_advlockasync =	vop_stdadvlockasync,
	.vop_advlockpurge =	vop_stdadvlockpurge,
	.vop_allocate =		vop_stdallocate,
	.vop_bmap =		vop_stdbmap,
	.vop_close =		VOP_NULL,
	.vop_fsync =		VOP_NULL,
	.vop_stat =		vop_stdstat,
	.vop_fdatasync =	vop_stdfdatasync,
	.vop_getpages =		vop_stdgetpages,
	.vop_getpages_async =	vop_stdgetpages_async,
	.vop_getwritemount = 	vop_stdgetwritemount,
	.vop_inactive =		VOP_NULL,
	.vop_need_inactive =	vop_stdneed_inactive,
	.vop_ioctl =		vop_stdioctl,
	.vop_kqfilter =		vop_stdkqfilter,
	.vop_islocked =		vop_stdislocked,
	.vop_lock1 =		vop_stdlock,
	.vop_lookup =		vop_nolookup,
	.vop_open =		VOP_NULL,
	.vop_pathconf =		VOP_EINVAL,
	.vop_poll =		vop_nopoll,
	.vop_putpages =		vop_stdputpages,
	.vop_readlink =		VOP_EINVAL,
	.vop_read_pgcache =	vop_stdread_pgcache,
	.vop_rename =		vop_norename,
	.vop_revoke =		VOP_PANIC,
	.vop_strategy =		vop_nostrategy,
	.vop_unlock =		vop_stdunlock,
	.vop_vptocnp =		vop_stdvptocnp,
	.vop_vptofh =		vop_stdvptofh,
	.vop_unp_bind =		vop_stdunp_bind,
	.vop_unp_connect =	vop_stdunp_connect,
	.vop_unp_detach =	vop_stdunp_detach,
	.vop_is_text =		vop_stdis_text,
	.vop_set_text =		vop_stdset_text,
	.vop_unset_text =	vop_stdunset_text,
	.vop_add_writecount =	vop_stdadd_writecount,
	.vop_copy_file_range =	vop_stdcopy_file_range,
	.vop_vput_pair =	vop_stdvput_pair,
};
VFS_VOP_VECTOR_REGISTER(default_vnodeops);

/*
 * Series of placeholder functions for various error returns for
 * VOPs.
 */

int
vop_eopnotsupp(struct vop_generic_args *ap)
{
	/*
	printf("vop_notsupp[%s]\n", ap->a_desc->vdesc_name);
	*/

	return (EOPNOTSUPP);
}

int
vop_ebadf(struct vop_generic_args *ap)
{

	return (EBADF);
}

int
vop_enotty(struct vop_generic_args *ap)
{

	return (ENOTTY);
}

int
vop_einval(struct vop_generic_args *ap)
{

	return (EINVAL);
}

int
vop_enoent(struct vop_generic_args *ap)
{

	return (ENOENT);
}

int
vop_eagain(struct vop_generic_args *ap)
{

	return (EAGAIN);
}

int
vop_null(struct vop_generic_args *ap)
{

	return (0);
}

/*
 * Helper function to panic on some bad VOPs in some filesystems.
 */
int
vop_panic(struct vop_generic_args *ap)
{

	panic("filesystem goof: vop_panic[%s]", ap->a_desc->vdesc_name);
}

/*
 * vop_std<something> and vop_no<something> are default functions for use by
 * filesystems that need the "default reasonable" implementation for a
 * particular operation.
 *
 * The documentation for the operations they implement exists (if it exists)
 * in the VOP_<SOMETHING>(9) manpage (all uppercase).
 */

/*
 * Default vop for filesystems that do not support name lookup
 */
static int
vop_nolookup(ap)
	struct vop_lookup_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
	} */ *ap;
{

	*ap->a_vpp = NULL;
	return (ENOTDIR);
}

/*
 * vop_norename:
 *
 * Handle unlock and reference counting for arguments of vop_rename
 * for filesystems that do not implement rename operation.
 */
static int
vop_norename(struct vop_rename_args *ap)
{

	vop_rename_fail(ap);
	return (EOPNOTSUPP);
}

/*
 *	vop_nostrategy:
 *
 *	Strategy routine for VFS devices that have none.
 *
 *	BIO_ERROR and B_INVAL must be cleared prior to calling any strategy
 *	routine.  Typically this is done for a BIO_READ strategy call.
 *	Typically B_INVAL is assumed to already be clear prior to a write
 *	and should not be cleared manually unless you just made the buffer
 *	invalid.  BIO_ERROR should be cleared either way.
 */

static int
vop_nostrategy (struct vop_strategy_args *ap)
{
	printf("No strategy for buffer at %p\n", ap->a_bp);
	vn_printf(ap->a_vp, "vnode ");
	ap->a_bp->b_ioflags |= BIO_ERROR;
	ap->a_bp->b_error = EOPNOTSUPP;
	bufdone(ap->a_bp);
	return (EOPNOTSUPP);
}

static int
get_next_dirent(struct vnode *vp, struct dirent **dpp, char *dirbuf,
		int dirbuflen, off_t *off, char **cpos, int *len,
		int *eofflag, struct thread *td)
{
	int error, reclen;
	struct uio uio;
	struct iovec iov;
	struct dirent *dp;

	KASSERT(VOP_ISLOCKED(vp), ("vp %p is not locked", vp));
	KASSERT(vp->v_type == VDIR, ("vp %p is not a directory", vp));

	if (*len == 0) {
		iov.iov_base = dirbuf;
		iov.iov_len = dirbuflen;

		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = *off;
		uio.uio_resid = dirbuflen;
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_rw = UIO_READ;
		uio.uio_td = td;

		*eofflag = 0;

#ifdef MAC
		error = mac_vnode_check_readdir(td->td_ucred, vp);
		if (error == 0)
#endif
			error = VOP_READDIR(vp, &uio, td->td_ucred, eofflag,
		    		NULL, NULL);
		if (error)
			return (error);

		*off = uio.uio_offset;

		*cpos = dirbuf;
		*len = (dirbuflen - uio.uio_resid);

		if (*len == 0)
			return (ENOENT);
	}

	dp = (struct dirent *)(*cpos);
	reclen = dp->d_reclen;
	*dpp = dp;

	/* check for malformed directory.. */
	if (reclen < DIRENT_MINSIZE)
		return (EINVAL);

	*cpos += reclen;
	*len -= reclen;

	return (0);
}

/*
 * Check if a named file exists in a given directory vnode.
 */
static int
dirent_exists(struct vnode *vp, const char *dirname, struct thread *td)
{
	char *dirbuf, *cpos;
	int error, eofflag, dirbuflen, len, found;
	off_t off;
	struct dirent *dp;
	struct vattr va;

	KASSERT(VOP_ISLOCKED(vp), ("vp %p is not locked", vp));
	KASSERT(vp->v_type == VDIR, ("vp %p is not a directory", vp));

	found = 0;

	error = VOP_GETATTR(vp, &va, td->td_ucred);
	if (error)
		return (found);

	dirbuflen = DEV_BSIZE;
	if (dirbuflen < va.va_blocksize)
		dirbuflen = va.va_blocksize;
	dirbuf = (char *)malloc(dirbuflen, M_TEMP, M_WAITOK);

	off = 0;
	len = 0;
	do {
		error = get_next_dirent(vp, &dp, dirbuf, dirbuflen, &off,
					&cpos, &len, &eofflag, td);
		if (error)
			goto out;

		if (dp->d_type != DT_WHT && dp->d_fileno != 0 &&
		    strcmp(dp->d_name, dirname) == 0) {
			found = 1;
			goto out;
		}
	} while (len > 0 || !eofflag);

out:
	free(dirbuf, M_TEMP);
	return (found);
}

int
vop_stdaccess(struct vop_access_args *ap)
{

	KASSERT((ap->a_accmode & ~(VEXEC | VWRITE | VREAD | VADMIN |
	    VAPPEND)) == 0, ("invalid bit in accmode"));

	return (VOP_ACCESSX(ap->a_vp, ap->a_accmode, ap->a_cred, ap->a_td));
}

int
vop_stdaccessx(struct vop_accessx_args *ap)
{
	int error;
	accmode_t accmode = ap->a_accmode;

	error = vfs_unixify_accmode(&accmode);
	if (error != 0)
		return (error);

	if (accmode == 0)
		return (0);

	return (VOP_ACCESS(ap->a_vp, accmode, ap->a_cred, ap->a_td));
}

/*
 * Advisory record locking support
 */
int
vop_stdadvlock(struct vop_advlock_args *ap)
{
	struct vnode *vp;
	struct vattr vattr;
	int error;

	vp = ap->a_vp;
	if (ap->a_fl->l_whence == SEEK_END) {
		/*
		 * The NFSv4 server must avoid doing a vn_lock() here, since it
		 * can deadlock the nfsd threads, due to a LOR.  Fortunately
		 * the NFSv4 server always uses SEEK_SET and this code is
		 * only required for the SEEK_END case.
		 */
		vn_lock(vp, LK_SHARED | LK_RETRY);
		error = VOP_GETATTR(vp, &vattr, curthread->td_ucred);
		VOP_UNLOCK(vp);
		if (error)
			return (error);
	} else
		vattr.va_size = 0;

	return (lf_advlock(ap, &(vp->v_lockf), vattr.va_size));
}

int
vop_stdadvlockasync(struct vop_advlockasync_args *ap)
{
	struct vnode *vp;
	struct vattr vattr;
	int error;

	vp = ap->a_vp;
	if (ap->a_fl->l_whence == SEEK_END) {
		/* The size argument is only needed for SEEK_END. */
		vn_lock(vp, LK_SHARED | LK_RETRY);
		error = VOP_GETATTR(vp, &vattr, curthread->td_ucred);
		VOP_UNLOCK(vp);
		if (error)
			return (error);
	} else
		vattr.va_size = 0;

	return (lf_advlockasync(ap, &(vp->v_lockf), vattr.va_size));
}

int
vop_stdadvlockpurge(struct vop_advlockpurge_args *ap)
{
	struct vnode *vp;

	vp = ap->a_vp;
	lf_purgelocks(vp, &vp->v_lockf);
	return (0);
}

/*
 * vop_stdpathconf:
 *
 * Standard implementation of POSIX pathconf, to get information about limits
 * for a filesystem.
 * Override per filesystem for the case where the filesystem has smaller
 * limits.
 */
int
vop_stdpathconf(ap)
	struct vop_pathconf_args /* {
	struct vnode *a_vp;
	int a_name;
	int *a_retval;
	} */ *ap;
{

	switch (ap->a_name) {
		case _PC_ASYNC_IO:
			*ap->a_retval = _POSIX_ASYNCHRONOUS_IO;
			return (0);
		case _PC_PATH_MAX:
			*ap->a_retval = PATH_MAX;
			return (0);
		case _PC_ACL_EXTENDED:
		case _PC_ACL_NFS4:
		case _PC_CAP_PRESENT:
		case _PC_INF_PRESENT:
		case _PC_MAC_PRESENT:
			*ap->a_retval = 0;
			return (0);
		default:
			return (EINVAL);
	}
	/* NOTREACHED */
}

/*
 * Standard lock, unlock and islocked functions.
 */
int
vop_stdlock(ap)
	struct vop_lock1_args /* {
		struct vnode *a_vp;
		int a_flags;
		char *file;
		int line;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct mtx *ilk;

	ilk = VI_MTX(vp);
	return (lockmgr_lock_flags(vp->v_vnlock, ap->a_flags,
	    &ilk->lock_object, ap->a_file, ap->a_line));
}

/* See above. */
int
vop_stdunlock(ap)
	struct vop_unlock_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;

	return (lockmgr_unlock(vp->v_vnlock));
}

/* See above. */
int
vop_stdislocked(ap)
	struct vop_islocked_args /* {
		struct vnode *a_vp;
	} */ *ap;
{

	return (lockstatus(ap->a_vp->v_vnlock));
}

/*
 * Variants of the above set.
 *
 * Differences are:
 * - shared locking disablement is not supported
 * - v_vnlock pointer is not honored
 */
int
vop_lock(ap)
	struct vop_lock1_args /* {
		struct vnode *a_vp;
		int a_flags;
		char *file;
		int line;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	int flags = ap->a_flags;
	struct mtx *ilk;

	MPASS(vp->v_vnlock == &vp->v_lock);

	if (__predict_false((flags & ~(LK_TYPE_MASK | LK_NODDLKTREAT | LK_RETRY)) != 0))
		goto other;

	switch (flags & LK_TYPE_MASK) {
	case LK_SHARED:
		return (lockmgr_slock(&vp->v_lock, flags, ap->a_file, ap->a_line));
	case LK_EXCLUSIVE:
		return (lockmgr_xlock(&vp->v_lock, flags, ap->a_file, ap->a_line));
	}
other:
	ilk = VI_MTX(vp);
	return (lockmgr_lock_flags(&vp->v_lock, flags,
	    &ilk->lock_object, ap->a_file, ap->a_line));
}

int
vop_unlock(ap)
	struct vop_unlock_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;

	MPASS(vp->v_vnlock == &vp->v_lock);

	return (lockmgr_unlock(&vp->v_lock));
}

int
vop_islocked(ap)
	struct vop_islocked_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;

	MPASS(vp->v_vnlock == &vp->v_lock);

	return (lockstatus(&vp->v_lock));
}

/*
 * Return true for select/poll.
 */
int
vop_nopoll(ap)
	struct vop_poll_args /* {
		struct vnode *a_vp;
		int  a_events;
		struct ucred *a_cred;
		struct thread *a_td;
	} */ *ap;
{

	if (ap->a_events & ~POLLSTANDARD)
		return (POLLNVAL);
	return (ap->a_events & (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM));
}

/*
 * Implement poll for local filesystems that support it.
 */
int
vop_stdpoll(ap)
	struct vop_poll_args /* {
		struct vnode *a_vp;
		int  a_events;
		struct ucred *a_cred;
		struct thread *a_td;
	} */ *ap;
{
	if (ap->a_events & ~POLLSTANDARD)
		return (vn_pollrecord(ap->a_vp, ap->a_td, ap->a_events));
	return (ap->a_events & (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM));
}

/*
 * Return our mount point, as we will take charge of the writes.
 */
int
vop_stdgetwritemount(ap)
	struct vop_getwritemount_args /* {
		struct vnode *a_vp;
		struct mount **a_mpp;
	} */ *ap;
{
	struct mount *mp;
	struct mount_pcpu *mpcpu;
	struct vnode *vp;

	/*
	 * Note that having a reference does not prevent forced unmount from
	 * setting ->v_mount to NULL after the lock gets released. This is of
	 * no consequence for typical consumers (most notably vn_start_write)
	 * since in this case the vnode is VIRF_DOOMED. Unmount might have
	 * progressed far enough that its completion is only delayed by the
	 * reference obtained here. The consumer only needs to concern itself
	 * with releasing it.
	 */
	vp = ap->a_vp;
	mp = vp->v_mount;
	if (mp == NULL) {
		*(ap->a_mpp) = NULL;
		return (0);
	}
	if (vfs_op_thread_enter(mp, mpcpu)) {
		if (mp == vp->v_mount) {
			vfs_mp_count_add_pcpu(mpcpu, ref, 1);
			vfs_op_thread_exit(mp, mpcpu);
		} else {
			vfs_op_thread_exit(mp, mpcpu);
			mp = NULL;
		}
	} else {
		MNT_ILOCK(mp);
		if (mp == vp->v_mount) {
			MNT_REF(mp);
			MNT_IUNLOCK(mp);
		} else {
			MNT_IUNLOCK(mp);
			mp = NULL;
		}
	}
	*(ap->a_mpp) = mp;
	return (0);
}

/*
 * If the file system doesn't implement VOP_BMAP, then return sensible defaults:
 * - Return the vnode's bufobj instead of any underlying device's bufobj
 * - Calculate the physical block number as if there were equal size
 *   consecutive blocks, but
 * - Report no contiguous runs of blocks.
 */
int
vop_stdbmap(ap)
	struct vop_bmap_args /* {
		struct vnode *a_vp;
		daddr_t  a_bn;
		struct bufobj **a_bop;
		daddr_t *a_bnp;
		int *a_runp;
		int *a_runb;
	} */ *ap;
{

	if (ap->a_bop != NULL)
		*ap->a_bop = &ap->a_vp->v_bufobj;
	if (ap->a_bnp != NULL)
		*ap->a_bnp = ap->a_bn * btodb(ap->a_vp->v_mount->mnt_stat.f_iosize);
	if (ap->a_runp != NULL)
		*ap->a_runp = 0;
	if (ap->a_runb != NULL)
		*ap->a_runb = 0;
	return (0);
}

int
vop_stdfsync(ap)
	struct vop_fsync_args /* {
		struct vnode *a_vp;
		int a_waitfor;
		struct thread *a_td;
	} */ *ap;
{

	return (vn_fsync_buf(ap->a_vp, ap->a_waitfor));
}

static int
vop_stdfdatasync(struct vop_fdatasync_args *ap)
{

	return (VOP_FSYNC(ap->a_vp, MNT_WAIT, ap->a_td));
}

int
vop_stdfdatasync_buf(struct vop_fdatasync_args *ap)
{

	return (vn_fsync_buf(ap->a_vp, MNT_WAIT));
}

/* XXX Needs good comment and more info in the manpage (VOP_GETPAGES(9)). */
int
vop_stdgetpages(ap)
	struct vop_getpages_args /* {
		struct vnode *a_vp;
		vm_page_t *a_m;
		int a_count;
		int *a_rbehind;
		int *a_rahead;
	} */ *ap;
{

	return vnode_pager_generic_getpages(ap->a_vp, ap->a_m,
	    ap->a_count, ap->a_rbehind, ap->a_rahead, NULL, NULL);
}

static int
vop_stdgetpages_async(struct vop_getpages_async_args *ap)
{
	int error;

	error = VOP_GETPAGES(ap->a_vp, ap->a_m, ap->a_count, ap->a_rbehind,
	    ap->a_rahead);
	if (ap->a_iodone != NULL)
		ap->a_iodone(ap->a_arg, ap->a_m, ap->a_count, error);
	return (error);
}

int
vop_stdkqfilter(struct vop_kqfilter_args *ap)
{
	return vfs_kqfilter(ap);
}

/* XXX Needs good comment and more info in the manpage (VOP_PUTPAGES(9)). */
int
vop_stdputpages(ap)
	struct vop_putpages_args /* {
		struct vnode *a_vp;
		vm_page_t *a_m;
		int a_count;
		int a_sync;
		int *a_rtvals;
	} */ *ap;
{

	return vnode_pager_generic_putpages(ap->a_vp, ap->a_m, ap->a_count,
	     ap->a_sync, ap->a_rtvals);
}

int
vop_stdvptofh(struct vop_vptofh_args *ap)
{
	return (EOPNOTSUPP);
}

int
vop_stdvptocnp(struct vop_vptocnp_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct vnode **dvp = ap->a_vpp;
	struct ucred *cred;
	char *buf = ap->a_buf;
	size_t *buflen = ap->a_buflen;
	char *dirbuf, *cpos;
	int i, error, eofflag, dirbuflen, flags, locked, len, covered;
	off_t off;
	ino_t fileno;
	struct vattr va;
	struct nameidata nd;
	struct thread *td;
	struct dirent *dp;
	struct vnode *mvp;

	i = *buflen;
	error = 0;
	covered = 0;
	td = curthread;
	cred = td->td_ucred;

	if (vp->v_type != VDIR)
		return (ENOENT);

	error = VOP_GETATTR(vp, &va, cred);
	if (error)
		return (error);

	VREF(vp);
	locked = VOP_ISLOCKED(vp);
	VOP_UNLOCK(vp);
	NDINIT_ATVP(&nd, LOOKUP, FOLLOW | LOCKSHARED | LOCKLEAF, UIO_SYSSPACE,
	    "..", vp, td);
	flags = FREAD;
	error = vn_open_cred(&nd, &flags, 0, VN_OPEN_NOAUDIT, cred, NULL);
	if (error) {
		vn_lock(vp, locked | LK_RETRY);
		return (error);
	}
	NDFREE(&nd, NDF_ONLY_PNBUF);

	mvp = *dvp = nd.ni_vp;

	if (vp->v_mount != (*dvp)->v_mount &&
	    ((*dvp)->v_vflag & VV_ROOT) &&
	    ((*dvp)->v_mount->mnt_flag & MNT_UNION)) {
		*dvp = (*dvp)->v_mount->mnt_vnodecovered;
		VREF(mvp);
		VOP_UNLOCK(mvp);
		vn_close(mvp, FREAD, cred, td);
		VREF(*dvp);
		vn_lock(*dvp, LK_SHARED | LK_RETRY);
		covered = 1;
	}

	fileno = va.va_fileid;

	dirbuflen = DEV_BSIZE;
	if (dirbuflen < va.va_blocksize)
		dirbuflen = va.va_blocksize;
	dirbuf = (char *)malloc(dirbuflen, M_TEMP, M_WAITOK);

	if ((*dvp)->v_type != VDIR) {
		error = ENOENT;
		goto out;
	}

	off = 0;
	len = 0;
	do {
		/* call VOP_READDIR of parent */
		error = get_next_dirent(*dvp, &dp, dirbuf, dirbuflen, &off,
					&cpos, &len, &eofflag, td);
		if (error)
			goto out;

		if ((dp->d_type != DT_WHT) &&
		    (dp->d_fileno == fileno)) {
			if (covered) {
				VOP_UNLOCK(*dvp);
				vn_lock(mvp, LK_SHARED | LK_RETRY);
				if (dirent_exists(mvp, dp->d_name, td)) {
					error = ENOENT;
					VOP_UNLOCK(mvp);
					vn_lock(*dvp, LK_SHARED | LK_RETRY);
					goto out;
				}
				VOP_UNLOCK(mvp);
				vn_lock(*dvp, LK_SHARED | LK_RETRY);
			}
			i -= dp->d_namlen;

			if (i < 0) {
				error = ENOMEM;
				goto out;
			}
			if (dp->d_namlen == 1 && dp->d_name[0] == '.') {
				error = ENOENT;
			} else {
				bcopy(dp->d_name, buf + i, dp->d_namlen);
				error = 0;
			}
			goto out;
		}
	} while (len > 0 || !eofflag);
	error = ENOENT;

out:
	free(dirbuf, M_TEMP);
	if (!error) {
		*buflen = i;
		vref(*dvp);
	}
	if (covered) {
		vput(*dvp);
		vrele(mvp);
	} else {
		VOP_UNLOCK(mvp);
		vn_close(mvp, FREAD, cred, td);
	}
	vn_lock(vp, locked | LK_RETRY);
	return (error);
}

int
vop_stdallocate(struct vop_allocate_args *ap)
{
#ifdef __notyet__
	struct statfs *sfs;
	off_t maxfilesize = 0;
#endif
	struct iovec aiov;
	struct vattr vattr, *vap;
	struct uio auio;
	off_t fsize, len, cur, offset;
	uint8_t *buf;
	struct thread *td;
	struct vnode *vp;
	size_t iosize;
	int error;

	buf = NULL;
	error = 0;
	td = curthread;
	vap = &vattr;
	vp = ap->a_vp;
	len = *ap->a_len;
	offset = *ap->a_offset;

	error = VOP_GETATTR(vp, vap, td->td_ucred);
	if (error != 0)
		goto out;
	fsize = vap->va_size;
	iosize = vap->va_blocksize;
	if (iosize == 0)
		iosize = BLKDEV_IOSIZE;
	if (iosize > maxphys)
		iosize = maxphys;
	buf = malloc(iosize, M_TEMP, M_WAITOK);

#ifdef __notyet__
	/*
	 * Check if the filesystem sets f_maxfilesize; if not use
	 * VOP_SETATTR to perform the check.
	 */
	sfs = malloc(sizeof(struct statfs), M_STATFS, M_WAITOK);
	error = VFS_STATFS(vp->v_mount, sfs, td);
	if (error == 0)
		maxfilesize = sfs->f_maxfilesize;
	free(sfs, M_STATFS);
	if (error != 0)
		goto out;
	if (maxfilesize) {
		if (offset > maxfilesize || len > maxfilesize ||
		    offset + len > maxfilesize) {
			error = EFBIG;
			goto out;
		}
	} else
#endif
	if (offset + len > vap->va_size) {
		/*
		 * Test offset + len against the filesystem's maxfilesize.
		 */
		VATTR_NULL(vap);
		vap->va_size = offset + len;
		error = VOP_SETATTR(vp, vap, td->td_ucred);
		if (error != 0)
			goto out;
		VATTR_NULL(vap);
		vap->va_size = fsize;
		error = VOP_SETATTR(vp, vap, td->td_ucred);
		if (error != 0)
			goto out;
	}

	for (;;) {
		/*
		 * Read and write back anything below the nominal file
		 * size.  There's currently no way outside the filesystem
		 * to know whether this area is sparse or not.
		 */
		cur = iosize;
		if ((offset % iosize) != 0)
			cur -= (offset % iosize);
		if (cur > len)
			cur = len;
		if (offset < fsize) {
			aiov.iov_base = buf;
			aiov.iov_len = cur;
			auio.uio_iov = &aiov;
			auio.uio_iovcnt = 1;
			auio.uio_offset = offset;
			auio.uio_resid = cur;
			auio.uio_segflg = UIO_SYSSPACE;
			auio.uio_rw = UIO_READ;
			auio.uio_td = td;
			error = VOP_READ(vp, &auio, 0, td->td_ucred);
			if (error != 0)
				break;
			if (auio.uio_resid > 0) {
				bzero(buf + cur - auio.uio_resid,
				    auio.uio_resid);
			}
		} else {
			bzero(buf, cur);
		}

		aiov.iov_base = buf;
		aiov.iov_len = cur;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = offset;
		auio.uio_resid = cur;
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_rw = UIO_WRITE;
		auio.uio_td = td;

		error = VOP_WRITE(vp, &auio, 0, td->td_ucred);
		if (error != 0)
			break;

		len -= cur;
		offset += cur;
		if (len == 0)
			break;
		if (should_yield())
			break;
	}

 out:
	*ap->a_len = len;
	*ap->a_offset = offset;
	free(buf, M_TEMP);
	return (error);
}

int
vop_stdadvise(struct vop_advise_args *ap)
{
	struct vnode *vp;
	struct bufobj *bo;
	daddr_t startn, endn;
	off_t bstart, bend, start, end;
	int bsize, error;

	vp = ap->a_vp;
	switch (ap->a_advice) {
	case POSIX_FADV_WILLNEED:
		/*
		 * Do nothing for now.  Filesystems should provide a
		 * custom method which starts an asynchronous read of
		 * the requested region.
		 */
		error = 0;
		break;
	case POSIX_FADV_DONTNEED:
		error = 0;
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
		if (VN_IS_DOOMED(vp)) {
			VOP_UNLOCK(vp);
			break;
		}

		/*
		 * Round to block boundaries (and later possibly further to
		 * page boundaries).  Applications cannot reasonably be aware
		 * of the boundaries, and the rounding must be to expand at
		 * both extremities to cover enough.  It still doesn't cover
		 * read-ahead.  For partial blocks, this gives unnecessary
		 * discarding of buffers but is efficient enough since the
		 * pages usually remain in VMIO for some time.
		 */
		bsize = vp->v_bufobj.bo_bsize;
		bstart = rounddown(ap->a_start, bsize);
		bend = roundup(ap->a_end, bsize);

		/*
		 * Deactivate pages in the specified range from the backing VM
		 * object.  Pages that are resident in the buffer cache will
		 * remain wired until their corresponding buffers are released
		 * below.
		 */
		if (vp->v_object != NULL) {
			start = trunc_page(bstart);
			end = round_page(bend);
			VM_OBJECT_RLOCK(vp->v_object);
			vm_object_page_noreuse(vp->v_object, OFF_TO_IDX(start),
			    OFF_TO_IDX(end));
			VM_OBJECT_RUNLOCK(vp->v_object);
		}

		bo = &vp->v_bufobj;
		BO_RLOCK(bo);
		startn = bstart / bsize;
		endn = bend / bsize;
		error = bnoreuselist(&bo->bo_clean, bo, startn, endn);
		if (error == 0)
			error = bnoreuselist(&bo->bo_dirty, bo, startn, endn);
		BO_RUNLOCK(bo);
		VOP_UNLOCK(vp);
		break;
	default:
		error = EINVAL;
		break;
	}
	return (error);
}

int
vop_stdunp_bind(struct vop_unp_bind_args *ap)
{

	ap->a_vp->v_unpcb = ap->a_unpcb;
	return (0);
}

int
vop_stdunp_connect(struct vop_unp_connect_args *ap)
{

	*ap->a_unpcb = ap->a_vp->v_unpcb;
	return (0);
}

int
vop_stdunp_detach(struct vop_unp_detach_args *ap)
{

	ap->a_vp->v_unpcb = NULL;
	return (0);
}

static int
vop_stdis_text(struct vop_is_text_args *ap)
{

	return (ap->a_vp->v_writecount < 0);
}

int
vop_stdset_text(struct vop_set_text_args *ap)
{
	struct vnode *vp;
	struct mount *mp;
	int error;

	vp = ap->a_vp;
	VI_LOCK(vp);
	if (vp->v_writecount > 0) {
		error = ETXTBSY;
	} else {
		/*
		 * If requested by fs, keep a use reference to the
		 * vnode until the last text reference is released.
		 */
		mp = vp->v_mount;
		if (mp != NULL && (mp->mnt_kern_flag & MNTK_TEXT_REFS) != 0 &&
		    vp->v_writecount == 0) {
			VNPASS((vp->v_iflag & VI_TEXT_REF) == 0, vp);
			vp->v_iflag |= VI_TEXT_REF;
			vrefl(vp);
		}

		vp->v_writecount--;
		error = 0;
	}
	VI_UNLOCK(vp);
	return (error);
}

static int
vop_stdunset_text(struct vop_unset_text_args *ap)
{
	struct vnode *vp;
	int error;
	bool last;

	vp = ap->a_vp;
	last = false;
	VI_LOCK(vp);
	if (vp->v_writecount < 0) {
		if ((vp->v_iflag & VI_TEXT_REF) != 0 &&
		    vp->v_writecount == -1) {
			last = true;
			vp->v_iflag &= ~VI_TEXT_REF;
		}
		vp->v_writecount++;
		error = 0;
	} else {
		error = EINVAL;
	}
	VI_UNLOCK(vp);
	if (last)
		vunref(vp);
	return (error);
}

static int
vop_stdadd_writecount(struct vop_add_writecount_args *ap)
{
	struct vnode *vp;
	struct mount *mp;
	int error;

	vp = ap->a_vp;
	VI_LOCK_FLAGS(vp, MTX_DUPOK);
	if (vp->v_writecount < 0) {
		error = ETXTBSY;
	} else {
		VNASSERT(vp->v_writecount + ap->a_inc >= 0, vp,
		    ("neg writecount increment %d", ap->a_inc));
		if (vp->v_writecount == 0) {
			mp = vp->v_mount;
			if (mp != NULL && (mp->mnt_kern_flag & MNTK_NOMSYNC) == 0)
				vlazy(vp);
		}
		vp->v_writecount += ap->a_inc;
		error = 0;
	}
	VI_UNLOCK(vp);
	return (error);
}

int
vop_stdneed_inactive(struct vop_need_inactive_args *ap)
{

	return (1);
}

int
vop_stdioctl(struct vop_ioctl_args *ap)
{
	struct vnode *vp;
	struct vattr va;
	off_t *offp;
	int error;

	switch (ap->a_command) {
	case FIOSEEKDATA:
	case FIOSEEKHOLE:
		vp = ap->a_vp;
		error = vn_lock(vp, LK_SHARED);
		if (error != 0)
			return (EBADF);
		if (vp->v_type == VREG)
			error = VOP_GETATTR(vp, &va, ap->a_cred);
		else
			error = ENOTTY;
		if (error == 0) {
			offp = ap->a_data;
			if (*offp < 0 || *offp >= va.va_size)
				error = ENXIO;
			else if (ap->a_command == FIOSEEKHOLE)
				*offp = va.va_size;
		}
		VOP_UNLOCK(vp);
		break;
	default:
		error = ENOTTY;
		break;
	}
	return (error);
}

/*
 * vfs default ops
 * used to fill the vfs function table to get reasonable default return values.
 */
int
vfs_stdroot (mp, flags, vpp)
	struct mount *mp;
	int flags;
	struct vnode **vpp;
{

	return (EOPNOTSUPP);
}

int
vfs_stdstatfs (mp, sbp)
	struct mount *mp;
	struct statfs *sbp;
{

	return (EOPNOTSUPP);
}

int
vfs_stdquotactl (mp, cmds, uid, arg)
	struct mount *mp;
	int cmds;
	uid_t uid;
	void *arg;
{

	return (EOPNOTSUPP);
}

int
vfs_stdsync(mp, waitfor)
	struct mount *mp;
	int waitfor;
{
	struct vnode *vp, *mvp;
	struct thread *td;
	int error, lockreq, allerror = 0;

	td = curthread;
	lockreq = LK_EXCLUSIVE | LK_INTERLOCK;
	if (waitfor != MNT_WAIT)
		lockreq |= LK_NOWAIT;
	/*
	 * Force stale buffer cache information to be flushed.
	 */
loop:
	MNT_VNODE_FOREACH_ALL(vp, mp, mvp) {
		if (vp->v_bufobj.bo_dirty.bv_cnt == 0) {
			VI_UNLOCK(vp);
			continue;
		}
		if ((error = vget(vp, lockreq)) != 0) {
			if (error == ENOENT) {
				MNT_VNODE_FOREACH_ALL_ABORT(mp, mvp);
				goto loop;
			}
			continue;
		}
		error = VOP_FSYNC(vp, waitfor, td);
		if (error)
			allerror = error;
		vput(vp);
	}
	return (allerror);
}

int
vfs_stdnosync (mp, waitfor)
	struct mount *mp;
	int waitfor;
{

	return (0);
}

static int
vop_stdcopy_file_range(struct vop_copy_file_range_args *ap)
{
	int error;

	error = vn_generic_copy_file_range(ap->a_invp, ap->a_inoffp,
	    ap->a_outvp, ap->a_outoffp, ap->a_lenp, ap->a_flags, ap->a_incred,
	    ap->a_outcred, ap->a_fsizetd);
	return (error);
}

int
vfs_stdvget (mp, ino, flags, vpp)
	struct mount *mp;
	ino_t ino;
	int flags;
	struct vnode **vpp;
{

	return (EOPNOTSUPP);
}

int
vfs_stdfhtovp (mp, fhp, flags, vpp)
	struct mount *mp;
	struct fid *fhp;
	int flags;
	struct vnode **vpp;
{

	return (EOPNOTSUPP);
}

int
vfs_stdinit (vfsp)
	struct vfsconf *vfsp;
{

	return (0);
}

int
vfs_stduninit (vfsp)
	struct vfsconf *vfsp;
{

	return(0);
}

int
vfs_stdextattrctl(mp, cmd, filename_vp, attrnamespace, attrname)
	struct mount *mp;
	int cmd;
	struct vnode *filename_vp;
	int attrnamespace;
	const char *attrname;
{

	if (filename_vp != NULL)
		VOP_UNLOCK(filename_vp);
	return (EOPNOTSUPP);
}

int
vfs_stdsysctl(mp, op, req)
	struct mount *mp;
	fsctlop_t op;
	struct sysctl_req *req;
{

	return (EOPNOTSUPP);
}

static vop_bypass_t *
bp_by_off(struct vop_vector *vop, struct vop_generic_args *a)
{

	return (*(vop_bypass_t **)((char *)vop + a->a_desc->vdesc_vop_offset));
}

int
vop_sigdefer(struct vop_vector *vop, struct vop_generic_args *a)
{
	vop_bypass_t *bp;
	int prev_stops, rc;

	bp = bp_by_off(vop, a);
	MPASS(bp != NULL);

	prev_stops = sigdeferstop(SIGDEFERSTOP_SILENT);
	rc = bp(a);
	sigallowstop(prev_stops);
	return (rc);
}

static int
vop_stdstat(struct vop_stat_args *a)
{
	struct vattr vattr;
	struct vattr *vap;
	struct vnode *vp;
	struct stat *sb;
	int error;
	u_short mode;

	vp = a->a_vp;
	sb = a->a_sb;

	error = vop_stat_helper_pre(a);
	if (error != 0)
		return (error);

	vap = &vattr;

	/*
	 * Initialize defaults for new and unusual fields, so that file
	 * systems which don't support these fields don't need to know
	 * about them.
	 */
	vap->va_birthtime.tv_sec = -1;
	vap->va_birthtime.tv_nsec = 0;
	vap->va_fsid = VNOVAL;
	vap->va_rdev = NODEV;

	error = VOP_GETATTR(vp, vap, a->a_active_cred);
	if (error)
		goto out;

	/*
	 * Zero the spare stat fields
	 */
	bzero(sb, sizeof *sb);

	/*
	 * Copy from vattr table
	 */
	if (vap->va_fsid != VNOVAL)
		sb->st_dev = vap->va_fsid;
	else
		sb->st_dev = vp->v_mount->mnt_stat.f_fsid.val[0];
	sb->st_ino = vap->va_fileid;
	mode = vap->va_mode;
	switch (vap->va_type) {
	case VREG:
		mode |= S_IFREG;
		break;
	case VDIR:
		mode |= S_IFDIR;
		break;
	case VBLK:
		mode |= S_IFBLK;
		break;
	case VCHR:
		mode |= S_IFCHR;
		break;
	case VLNK:
		mode |= S_IFLNK;
		break;
	case VSOCK:
		mode |= S_IFSOCK;
		break;
	case VFIFO:
		mode |= S_IFIFO;
		break;
	default:
		error = EBADF;
		goto out;
	}
	sb->st_mode = mode;
	sb->st_nlink = vap->va_nlink;
	sb->st_uid = vap->va_uid;
	sb->st_gid = vap->va_gid;
	sb->st_rdev = vap->va_rdev;
	if (vap->va_size > OFF_MAX) {
		error = EOVERFLOW;
		goto out;
	}
	sb->st_size = vap->va_size;
	sb->st_atim.tv_sec = vap->va_atime.tv_sec;
	sb->st_atim.tv_nsec = vap->va_atime.tv_nsec;
	sb->st_mtim.tv_sec = vap->va_mtime.tv_sec;
	sb->st_mtim.tv_nsec = vap->va_mtime.tv_nsec;
	sb->st_ctim.tv_sec = vap->va_ctime.tv_sec;
	sb->st_ctim.tv_nsec = vap->va_ctime.tv_nsec;
	sb->st_birthtim.tv_sec = vap->va_birthtime.tv_sec;
	sb->st_birthtim.tv_nsec = vap->va_birthtime.tv_nsec;

	/*
	 * According to www.opengroup.org, the meaning of st_blksize is
	 *   "a filesystem-specific preferred I/O block size for this
	 *    object.  In some filesystem types, this may vary from file
	 *    to file"
	 * Use minimum/default of PAGE_SIZE (e.g. for VCHR).
	 */

	sb->st_blksize = max(PAGE_SIZE, vap->va_blocksize);
	sb->st_flags = vap->va_flags;
	sb->st_blocks = vap->va_bytes / S_BLKSIZE;
	sb->st_gen = vap->va_gen;
out:
	return (vop_stat_helper_post(a, error));
}

static int
vop_stdread_pgcache(struct vop_read_pgcache_args *ap __unused)
{
	return (EJUSTRETURN);
}

static int
vop_stdvput_pair(struct vop_vput_pair_args *ap)
{
	struct vnode *dvp, *vp, **vpp;

	dvp = ap->a_dvp;
	vpp = ap->a_vpp;
	vput(dvp);
	if (vpp != NULL && ap->a_unlock_vp && (vp = *vpp) != NULL)
		vput(vp);
	return (0);
}
