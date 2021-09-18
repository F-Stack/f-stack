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
 */

#ifndef _FSTACK_SYS_VNODE_H_
#define _FSTACK_SYS_VNODE_H_

#include <sys/uio.h>
#include <sys/namei.h>

/*
 * Vnode types.  VNON means no type.
 */
enum vtype {
    VNON, VREG, VDIR, VBLK, VCHR,
    VLNK, VSOCK, VFIFO, VBAD, VMARKER
};

struct nameidata;
struct stat;
struct nstat;
struct vnode {
    enum vtype v_type;
    struct mount *v_mount;  /* u ptr to vfs we are in */
    u_long v_vflag;         /* v vnode flags */
    int v_fd;               /* file descriptor */
};

#define VOP_ADVLOCK(a, b, c, d, e) (0)
#define VOP_UNLOCK(a)
static __inline int
vn_lock(struct vnode *vp, int flags)
{
    return (0);
}

static __inline int
vrefcnt(struct vnode *vp)
{
    return (0);
}

#define VREF(vp) vref(vp)
static __inline void
vref(struct vnode *vp)
{

}

static __inline void
vrele(struct vnode *vp)
{

}

extern struct vnode *rootvnode;
/* 0 or POSIX version of AIO i'face */
extern int async_io_version;

static __inline int
vn_fullpath(struct thread *td, struct vnode *vp,
    char **retbuf, char **freebuf)
{
    return (0);
}

static __inline void
cvtnstat(struct stat *sb, struct nstat *nsb)
{

}

struct vattr {
    enum vtype va_type;/* vnode type (for create) */
    u_short va_mode;   /* files access mode and type */
    dev_t va_fsid;     /* filesystem id */
    struct timespec va_mtime;
    dev_t va_rdev;     /* device the special file represents */
    u_quad_t va_size;  /* file size in bytes */
    long va_fileid;    /* file id */
};

/* underlying node already locked */
#define IO_NODELOCKED    0x0008

#define VNOVAL    (-1)

/*
 * Convert between vnode types and inode formats (since POSIX.1
 * defines mode word of stat structure in terms of inode formats).
 */
extern enum vtype iftovt_tab[];
extern int vttoif_tab[];
#define IFTOVT(mode)    (iftovt_tab[((mode) & S_IFMT) >> 12])
#define VTTOIF(indx)    (vttoif_tab[(int)(indx)])
#define MAKEIMODE(indx, mode)    (int)(VTTOIF(indx) | (mode))

#define    VV_PROCDEP    0x0100    /* vnode is process dependent */

static __inline int
VOP_PATHCONF(struct vnode *vp, int name, register_t *retval)
{
    return (0);
}

static __inline int
VOP_GETATTR(struct vnode *vp, struct vattr *vap, struct ucred *cred)
{
    bzero(vap, sizeof(struct vattr));
    return (0);
}

int vn_open(struct nameidata *ndp, int *flagp, int cmode, struct file *fp);
int vn_close(struct vnode *vp, int flags, struct ucred *file_cred,
    struct thread *td);

int vn_rdwr(enum uio_rw rw, struct vnode *vp, void *base,
    int len, off_t offset, enum uio_seg segflg, int ioflg,
    struct ucred *active_cred, struct ucred *file_cred, ssize_t *aresid,
    struct thread *td);

#define VFS_SMR_DECLARE     \
        extern smr_t vfs_smr

#define VFS_SMR()    vfs_smr
#define vfs_smr_enter()    smr_enter(VFS_SMR())
#define vfs_smr_exit()    smr_exit(VFS_SMR())
#define vfs_smr_entered_load(ptr)    smr_entered_load((ptr), VFS_SMR())
#define VFS_SMR_ASSERT_ENTERED()    SMR_ASSERT_ENTERED(VFS_SMR())

static __inline void
vrefact(struct vnode *vp)
{

}

#define IO_SEQMAX   0x7F        /* seq heuristic max value */

extern	u_int vn_lock_pair_pause_max;

#endif    /* _FSTACK_SYS_VNODE_H_ */
