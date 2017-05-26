/*
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
 * 
 *  Copied from FreeBSD's header files.
 */

#ifndef _COMPAT_SYSCTL_H
#define _COMPAT_SYSCTL_H

#include <sys/types.h>
#include <inttypes.h>

/*
 * Definitions for sysctl call.  The sysctl call uses a hierarchical name
 * for objects that can be examined or modified.  The name is expressed as
 * a sequence of integers.  Like a file path name, the meaning of each
 * component depends on its place in the hierarchy.  The top-level and kern
 * identifiers are defined here, and other identifiers are defined in the
 * respective subsystem header files.
 */

#define CTL_MAXNAME       24    /* largest number of components supported */

#define CTLTYPE           0xf    /* mask for the type */
#define CTLTYPE_NODE      1    /* name is a node */
#define CTLTYPE_INT       2    /* name describes an integer */
#define CTLTYPE_STRING    3    /* name describes a string */
#define CTLTYPE_S64       4    /* name describes a signed 64-bit number */
#define CTLTYPE_OPAQUE    5    /* name describes a structure */
#define CTLTYPE_STRUCT    CTLTYPE_OPAQUE    /* name describes a structure */
#define CTLTYPE_UINT      6    /* name describes an unsigned integer */
#define CTLTYPE_LONG      7    /* name describes a long */
#define CTLTYPE_ULONG     8    /* name describes an unsigned long */
#define CTLTYPE_U64       9    /* name describes an unsigned 64-bit number */
#define CTLTYPE_U8        0xa  /* name describes an unsigned 8-bit number */
#define CTLTYPE_U16       0xb  /* name describes an unsigned 16-bit number */
#define CTLTYPE_S8        0xc  /* name describes a signed 8-bit number */
#define CTLTYPE_S16       0xd  /* name describes a signed 16-bit number */
#define CTLTYPE_S32       0xe  /* name describes a signed 32-bit number */
#define CTLTYPE_U32       0xf  /* name describes an unsigned 32-bit number */

#define CTLFLAG_RD        0x80000000    /* Allow reads of variable */
#define CTLFLAG_WR        0x40000000    /* Allow writes to the variable */
#define CTLFLAG_RW        (CTLFLAG_RD|CTLFLAG_WR)
#define CTLFLAG_ANYBODY   0x10000000    /* All users can set this var */
#define CTLFLAG_SECURE    0x08000000    /* Permit set only if securelevel<=0 */
#define CTLFLAG_PRISON    0x04000000    /* Prisoned roots can fiddle */
#define CTLFLAG_DYN       0x02000000    /* Dynamic oid - can be freed */
#define CTLFLAG_SKIP      0x01000000    /* Skip this sysctl when listing */
#define CTLMASK_SECURE    0x00F00000    /* Secure level */
#define CTLFLAG_TUN       0x00080000    /* Default value is loaded from getenv() */
#define CTLFLAG_RDTUN     (CTLFLAG_RD|CTLFLAG_TUN)
#define CTLFLAG_RWTUN     (CTLFLAG_RW|CTLFLAG_TUN)
#define CTLFLAG_MPSAFE    0x00040000    /* Handler is MP safe */
#define CTLFLAG_VNET      0x00020000    /* Prisons with vnet can fiddle */
#define CTLFLAG_DYING     0x00010000    /* Oid is being removed */
#define CTLFLAG_CAPRD     0x00008000    /* Can be read in capability mode */
#define CTLFLAG_CAPWR     0x00004000    /* Can be written in capability mode */
#define CTLFLAG_STATS     0x00002000    /* Statistics, not a tuneable */
#define CTLFLAG_NOFETCH   0x00001000    /* Don't fetch tunable from getenv() */
#define CTLFLAG_CAPRW    (CTLFLAG_CAPRD|CTLFLAG_CAPWR)

struct clockinfo {
    int hz;        /* clock frequency */
    int tick;      /* micro-seconds per hz tick */
    int spare;
    int stathz;    /* statistics clock frequency */
    int profhz;    /* profiling clock frequency */
};

struct loadavg {
    __uint32_t ldavg[3];
    long fscale;
};

/* Structure extended to include extended attribute field in ACPI 3.0. */
struct bios_smap_xattr {
    u_int64_t base;
    u_int64_t length;
    u_int32_t type;
    u_int32_t xattr;
} __packed;

/* systemwide totals computed every five seconds */
struct vmtotal {
    int16_t t_rq;        /* length of the run queue */
    int16_t t_dw;        /* jobs in ``disk wait'' (neg priority) */
    int16_t t_pw;        /* jobs in page wait */
    int16_t t_sl;        /* jobs sleeping in core */
    int16_t t_sw;        /* swapped out runnable/short block jobs */
    int32_t t_vm;        /* total virtual memory */
    int32_t t_avm;       /* active virtual memory */
    int32_t t_rm;        /* total real memory in use */
    int32_t t_arm;       /* active real memory */
    int32_t t_vmshr;     /* shared virtual memory */
    int32_t t_avmshr;    /* active shared virtual memory */
    int32_t t_rmshr;     /* shared real memory */
    int32_t t_armshr;    /* active shared real memory */
    int32_t t_free;      /* free memory pages */
};

struct efi_md {
    uint32_t md_type;
#define EFI_MD_TYPE_NULL    0
#define EFI_MD_TYPE_CODE    1   /* Loader text. */
#define EFI_MD_TYPE_DATA    2   /* Loader data. */
#define EFI_MD_TYPE_BS_CODE 3   /* Boot services text. */
#define EFI_MD_TYPE_BS_DATA 4   /* Boot services data. */
#define EFI_MD_TYPE_RT_CODE 5   /* Runtime services text. */
#define EFI_MD_TYPE_RT_DATA 6   /* Runtime services data. */
#define EFI_MD_TYPE_FREE    7   /* Unused/free memory. */
#define EFI_MD_TYPE_BAD     8   /* Bad memory */
#define EFI_MD_TYPE_RECLAIM 9   /* ACPI reclaimable memory. */
#define EFI_MD_TYPE_FIRMWARE    10  /* ACPI NV memory */
#define EFI_MD_TYPE_IOMEM   11  /* Memory-mapped I/O. */
#define EFI_MD_TYPE_IOPORT  12  /* I/O port space. */
#define EFI_MD_TYPE_PALCODE 13  /* PAL */
    uint32_t __pad;
    uint64_t md_phys;
    void *md_virt;
    uint64_t md_pages;
    uint64_t md_attr;
#define EFI_MD_ATTR_UC      0x0000000000000001UL
#define EFI_MD_ATTR_WC      0x0000000000000002UL
#define EFI_MD_ATTR_WT      0x0000000000000004UL
#define EFI_MD_ATTR_WB      0x0000000000000008UL
#define EFI_MD_ATTR_UCE     0x0000000000000010UL
#define EFI_MD_ATTR_WP      0x0000000000001000UL
#define EFI_MD_ATTR_RP      0x0000000000002000UL
#define EFI_MD_ATTR_XP      0x0000000000004000UL
#define EFI_MD_ATTR_RT      0x8000000000000000UL
};

struct efi_map_header {
    uint64_t memory_size;
    uint64_t descriptor_size;
    uint32_t descriptor_version;
};

#endif
