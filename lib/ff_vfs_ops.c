/*
 * Copyright (c) 2011 Kip Macy. All rights reserved.
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
 * Derived in part from libplebnet's pn_vfs_ops.c.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/limits.h>
#include <sys/malloc.h>
#include <sys/namei.h>
#include <sys/refcount.h>
#include <sys/resourcevar.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/priv.h>
#include <sys/time.h>
#include <sys/ucred.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/capsicum.h>

__read_frequently smr_t vfs_smr;

void
NDFREE(struct nameidata *ndp, const u_int flags)
{

}

int
vn_open(struct nameidata *ndp, int *flagp, int cmode, struct file *fp)
{
    panic("vn_open not implemented");

    return (0);
}


int
vn_close(struct vnode *vp,
        int flags, struct ucred *file_cred, struct thread *td)
{
    panic("vn_close not implemented");

    return (0);
}


int
vn_rdwr(enum uio_rw rw, struct vnode *vp, void *base,
        int len, off_t offset, enum uio_seg segflg, int ioflg,
        struct ucred *active_cred, struct ucred *file_cred, ssize_t *aresid,
        struct thread *td)
{
    panic("vn_rdwr not implemented");

    return (0);
}

int
vn_fill_kinfo_vnode(struct vnode *vp, struct kinfo_file *kif)
{
    panic("vn_fill_kinfo_vnode not implemented");

    return (0);
}

#if 0
void
NDINIT_ALL(struct nameidata *ndp, u_long op, u_long flags, enum uio_seg segflg,
    const char *namep, int dirfd, struct vnode *startdir, cap_rights_t *rightsp,
    struct thread *td)
{

    ndp->ni_cnd.cn_nameiop = op;
    ndp->ni_cnd.cn_flags = flags;
    ndp->ni_segflg = segflg;
    ndp->ni_dirp = namep;
    ndp->ni_dirfd = dirfd;
    ndp->ni_startdir = startdir;
    ndp->ni_strictrelative = 0;
    if (rightsp != NULL)
        ndp->ni_rightsneeded = *rightsp;
    else
        cap_rights_init(&ndp->ni_rightsneeded);
    filecaps_init(&ndp->ni_filecaps);
    ndp->ni_cnd.cn_thread = td;
}
#endif

