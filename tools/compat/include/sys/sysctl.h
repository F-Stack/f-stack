/*
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
 * 
 *  Copied from FreeBSD's header files.
 */

#ifndef _COMPAT_SYS_SYSCTL_H
#define _COMPAT_SYS_SYSCTL_H

#include <sys/queue.h>
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

/*
 * Each subsystem defined by sysctl defines a list of variables
 * for that subsystem. Each name is either a node with further
 * levels defined below it, or it is a leaf of some particular
 * type given below. Each sysctl level defines a set of name/type
 * pairs to be used by sysctl(8) in manipulating the subsystem.
 */
struct ctlname {
    char    *ctl_name;  /* subsystem name */
    int  ctl_type;  /* type of name */
};

#define CTLTYPE     0xf /* mask for the type */
#define CTLTYPE_NODE    1   /* name is a node */
#define CTLTYPE_INT 2   /* name describes an integer */
#define CTLTYPE_STRING  3   /* name describes a string */
#define CTLTYPE_S64 4   /* name describes a signed 64-bit number */
#define CTLTYPE_OPAQUE  5   /* name describes a structure */
#define CTLTYPE_STRUCT  CTLTYPE_OPAQUE  /* name describes a structure */
#define CTLTYPE_UINT    6   /* name describes an unsigned integer */
#define CTLTYPE_LONG    7   /* name describes a long */
#define CTLTYPE_ULONG   8   /* name describes an unsigned long */
#define CTLTYPE_U64 9   /* name describes an unsigned 64-bit number */
#define CTLTYPE_U8  0xa /* name describes an unsigned 8-bit number */
#define CTLTYPE_U16 0xb /* name describes an unsigned 16-bit number */
#define CTLTYPE_S8  0xc /* name describes a signed 8-bit number */
#define CTLTYPE_S16 0xd /* name describes a signed 16-bit number */
#define CTLTYPE_S32 0xe /* name describes a signed 32-bit number */
#define CTLTYPE_U32 0xf /* name describes an unsigned 32-bit number */

#define CTLFLAG_RD  0x80000000  /* Allow reads of variable */
#define CTLFLAG_WR  0x40000000  /* Allow writes to the variable */
#define CTLFLAG_RW  (CTLFLAG_RD|CTLFLAG_WR)
#define CTLFLAG_ANYBODY 0x10000000  /* All users can set this var */
#define CTLFLAG_SECURE  0x08000000  /* Permit set only if securelevel<=0 */
#define CTLFLAG_PRISON  0x04000000  /* Prisoned roots can fiddle */
#define CTLFLAG_DYN 0x02000000  /* Dynamic oid - can be freed */
#define CTLFLAG_SKIP    0x01000000  /* Skip this sysctl when listing */
#define CTLMASK_SECURE  0x00F00000  /* Secure level */
#define CTLFLAG_TUN 0x00080000  /* Default value is loaded from getenv() */
#define CTLFLAG_RDTUN   (CTLFLAG_RD|CTLFLAG_TUN)
#define CTLFLAG_RWTUN   (CTLFLAG_RW|CTLFLAG_TUN)
#define CTLFLAG_MPSAFE  0x00040000  /* Handler is MP safe */
#define CTLFLAG_VNET    0x00020000  /* Prisons with vnet can fiddle */
#define CTLFLAG_DYING   0x00010000  /* Oid is being removed */
#define CTLFLAG_CAPRD   0x00008000  /* Can be read in capability mode */
#define CTLFLAG_CAPWR   0x00004000  /* Can be written in capability mode */
#define CTLFLAG_STATS   0x00002000  /* Statistics, not a tuneable */
#define CTLFLAG_NOFETCH 0x00001000  /* Don't fetch tunable from getenv() */
#define CTLFLAG_CAPRW   (CTLFLAG_CAPRD|CTLFLAG_CAPWR)

/*
 * Secure level.   Note that CTLFLAG_SECURE == CTLFLAG_SECURE1.
 *
 * Secure when the securelevel is raised to at least N.
 */
#define CTLSHIFT_SECURE 20
#define CTLFLAG_SECURE1 (CTLFLAG_SECURE | (0 << CTLSHIFT_SECURE))
#define CTLFLAG_SECURE2 (CTLFLAG_SECURE | (1 << CTLSHIFT_SECURE))
#define CTLFLAG_SECURE3 (CTLFLAG_SECURE | (2 << CTLSHIFT_SECURE))

/*
 * USE THIS instead of a hardwired number from the categories below
 * to get dynamically assigned sysctl entries using the linker-set
 * technology. This is the way nearly all new sysctl variables should
 * be implemented.
 * e.g. SYSCTL_INT(_parent, OID_AUTO, name, CTLFLAG_RW, &variable, 0, "");
 */
#define OID_AUTO    (-1)

/*
 * The starting number for dynamically-assigned entries.  WARNING!
 * ALL static sysctl entries should have numbers LESS than this!
 */
#define CTL_AUTO_START  0x100

/*
 * Top-level identifiers
 */
#define CTL_UNSPEC  0       /* unused */
#define CTL_KERN    1       /* "high kernel": proc, limits */
#define CTL_VM      2       /* virtual memory */
#define CTL_VFS     3       /* filesystem, mount type is next */
#define CTL_NET     4       /* network, see socket.h */
#define CTL_DEBUG   5       /* debugging parameters */
#define CTL_HW      6       /* generic cpu/io */
#define CTL_MACHDEP 7       /* machine dependent */
#define CTL_USER    8       /* user-level */
#define CTL_P1003_1B    9       /* POSIX 1003.1B */

/*
 * CTL_KERN identifiers
 */
#define KERN_OSTYPE      1  /* string: system version */
#define KERN_OSRELEASE       2  /* string: system release */
#define KERN_OSREV       3  /* int: system revision */
#define KERN_VERSION         4  /* string: compile time info */
#define KERN_MAXVNODES       5  /* int: max vnodes */
#define KERN_MAXPROC         6  /* int: max processes */
#define KERN_MAXFILES        7  /* int: max open files */
#define KERN_ARGMAX      8  /* int: max arguments to exec */
#define KERN_SECURELVL       9  /* int: system security level */
#define KERN_HOSTNAME       10  /* string: hostname */
#define KERN_HOSTID     11  /* int: host identifier */
#define KERN_CLOCKRATE      12  /* struct: struct clockrate */
#define KERN_VNODE      13  /* struct: vnode structures */
#define KERN_PROC       14  /* struct: process entries */
#define KERN_FILE       15  /* struct: file entries */
#define KERN_PROF       16  /* node: kernel profiling info */
#define KERN_POSIX1     17  /* int: POSIX.1 version */
#define KERN_NGROUPS        18  /* int: # of supplemental group ids */
#define KERN_JOB_CONTROL    19  /* int: is job control available */
#define KERN_SAVED_IDS      20  /* int: saved set-user/group-ID */
#define KERN_BOOTTIME       21  /* struct: time kernel was booted */
#define KERN_NISDOMAINNAME  22  /* string: YP domain name */
#define KERN_UPDATEINTERVAL 23  /* int: update process sleep time */
#define KERN_OSRELDATE      24  /* int: kernel release date */
#define KERN_NTP_PLL        25  /* node: NTP PLL control */
#define KERN_BOOTFILE       26  /* string: name of booted kernel */
#define KERN_MAXFILESPERPROC    27  /* int: max open files per proc */
#define KERN_MAXPROCPERUID  28  /* int: max processes per uid */
#define KERN_DUMPDEV        29  /* struct cdev *: device to dump on */
#define KERN_IPC        30  /* node: anything related to IPC */
#define KERN_DUMMY      31  /* unused */
#define KERN_PS_STRINGS     32  /* int: address of PS_STRINGS */
#define KERN_USRSTACK       33  /* int: address of USRSTACK */
#define KERN_LOGSIGEXIT     34  /* int: do we log sigexit procs? */
#define KERN_IOV_MAX        35  /* int: value of UIO_MAXIOV */
#define KERN_HOSTUUID       36  /* string: host UUID identifier */
#define KERN_ARND       37  /* int: from arc4rand() */
/*
 * KERN_PROC subtypes
 */
#define KERN_PROC_ALL       0   /* everything */
#define KERN_PROC_PID       1   /* by process id */
#define KERN_PROC_PGRP      2   /* by process group id */
#define KERN_PROC_SESSION   3   /* by session of pid */
#define KERN_PROC_TTY       4   /* by controlling tty */
#define KERN_PROC_UID       5   /* by effective uid */
#define KERN_PROC_RUID      6   /* by real uid */
#define KERN_PROC_ARGS      7   /* get/set arguments/proctitle */
#define KERN_PROC_PROC      8   /* only return procs */
#define KERN_PROC_SV_NAME   9   /* get syscall vector name */
#define KERN_PROC_RGID      10  /* by real group id */
#define KERN_PROC_GID       11  /* by effective group id */
#define KERN_PROC_PATHNAME  12  /* path to executable */
#define KERN_PROC_OVMMAP    13  /* Old VM map entries for process */
#define KERN_PROC_OFILEDESC 14  /* Old file descriptors for process */
#define KERN_PROC_KSTACK    15  /* Kernel stacks for process */
#define KERN_PROC_INC_THREAD    0x10    /*
                     * modifier for pid, pgrp, tty,
                     * uid, ruid, gid, rgid and proc
                     * This effectively uses 16-31
                     */
#define KERN_PROC_VMMAP     32  /* VM map entries for process */
#define KERN_PROC_FILEDESC  33  /* File descriptors for process */
#define KERN_PROC_GROUPS    34  /* process groups */
#define KERN_PROC_ENV       35  /* get environment */
#define KERN_PROC_AUXV      36  /* get ELF auxiliary vector */
#define KERN_PROC_RLIMIT    37  /* process resource limits */
#define KERN_PROC_PS_STRINGS    38  /* get ps_strings location */
#define KERN_PROC_UMASK     39  /* process umask */
#define KERN_PROC_OSREL     40  /* osreldate for process binary */
#define KERN_PROC_SIGTRAMP  41  /* signal trampoline location */
#define KERN_PROC_CWD       42  /* process current working directory */
#define KERN_PROC_NFDS      43  /* number of open file descriptors */

/*
 * KERN_IPC identifiers
 */
#define KIPC_MAXSOCKBUF     1   /* int: max size of a socket buffer */
#define KIPC_SOCKBUF_WASTE  2   /* int: wastage factor in sockbuf */
#define KIPC_SOMAXCONN      3   /* int: max length of connection q */
#define KIPC_MAX_LINKHDR    4   /* int: max length of link header */
#define KIPC_MAX_PROTOHDR   5   /* int: max length of network header */
#define KIPC_MAX_HDR        6   /* int: max total length of headers */
#define KIPC_MAX_DATALEN    7   /* int: max length of data? */

/*
 * CTL_HW identifiers
 */
#define HW_MACHINE   1      /* string: machine class */
#define HW_MODEL     2      /* string: specific machine model */
#define HW_NCPU      3      /* int: number of cpus */
#define HW_BYTEORDER     4      /* int: machine byte order */
#define HW_PHYSMEM   5      /* int: total memory */
#define HW_USERMEM   6      /* int: non-kernel memory */
#define HW_PAGESIZE  7      /* int: software page size */
#define HW_DISKNAMES     8      /* strings: disk drive names */
#define HW_DISKSTATS     9      /* struct: diskstats[] */
#define HW_FLOATINGPT   10      /* int: has HW floating point? */
#define HW_MACHINE_ARCH 11      /* string: machine architecture */
#define HW_REALMEM  12      /* int: 'real' memory */

/*
 * CTL_USER definitions
 */
#define USER_CS_PATH         1  /* string: _CS_PATH */
#define USER_BC_BASE_MAX     2  /* int: BC_BASE_MAX */
#define USER_BC_DIM_MAX      3  /* int: BC_DIM_MAX */
#define USER_BC_SCALE_MAX    4  /* int: BC_SCALE_MAX */
#define USER_BC_STRING_MAX   5  /* int: BC_STRING_MAX */
#define USER_COLL_WEIGHTS_MAX    6  /* int: COLL_WEIGHTS_MAX */
#define USER_EXPR_NEST_MAX   7  /* int: EXPR_NEST_MAX */
#define USER_LINE_MAX        8  /* int: LINE_MAX */
#define USER_RE_DUP_MAX      9  /* int: RE_DUP_MAX */
#define USER_POSIX2_VERSION 10  /* int: POSIX2_VERSION */
#define USER_POSIX2_C_BIND  11  /* int: POSIX2_C_BIND */
#define USER_POSIX2_C_DEV   12  /* int: POSIX2_C_DEV */
#define USER_POSIX2_CHAR_TERM   13  /* int: POSIX2_CHAR_TERM */
#define USER_POSIX2_FORT_DEV    14  /* int: POSIX2_FORT_DEV */
#define USER_POSIX2_FORT_RUN    15  /* int: POSIX2_FORT_RUN */
#define USER_POSIX2_LOCALEDEF   16  /* int: POSIX2_LOCALEDEF */
#define USER_POSIX2_SW_DEV  17  /* int: POSIX2_SW_DEV */
#define USER_POSIX2_UPE     18  /* int: POSIX2_UPE */
#define USER_STREAM_MAX     19  /* int: POSIX2_STREAM_MAX */
#define USER_TZNAME_MAX     20  /* int: POSIX2_TZNAME_MAX */

#define CTL_P1003_1B_ASYNCHRONOUS_IO        1   /* boolean */
#define CTL_P1003_1B_MAPPED_FILES       2   /* boolean */
#define CTL_P1003_1B_MEMLOCK            3   /* boolean */
#define CTL_P1003_1B_MEMLOCK_RANGE      4   /* boolean */
#define CTL_P1003_1B_MEMORY_PROTECTION      5   /* boolean */
#define CTL_P1003_1B_MESSAGE_PASSING        6   /* boolean */
#define CTL_P1003_1B_PRIORITIZED_IO     7   /* boolean */
#define CTL_P1003_1B_PRIORITY_SCHEDULING    8   /* boolean */
#define CTL_P1003_1B_REALTIME_SIGNALS       9   /* boolean */
#define CTL_P1003_1B_SEMAPHORES         10  /* boolean */
#define CTL_P1003_1B_FSYNC          11  /* boolean */
#define CTL_P1003_1B_SHARED_MEMORY_OBJECTS  12  /* boolean */
#define CTL_P1003_1B_SYNCHRONIZED_IO        13  /* boolean */
#define CTL_P1003_1B_TIMERS         14  /* boolean */
#define CTL_P1003_1B_AIO_LISTIO_MAX     15  /* int */
#define CTL_P1003_1B_AIO_MAX            16  /* int */
#define CTL_P1003_1B_AIO_PRIO_DELTA_MAX     17  /* int */
#define CTL_P1003_1B_DELAYTIMER_MAX     18  /* int */
#define CTL_P1003_1B_MQ_OPEN_MAX        19  /* int */
#define CTL_P1003_1B_PAGESIZE           20  /* int */
#define CTL_P1003_1B_RTSIG_MAX          21  /* int */
#define CTL_P1003_1B_SEM_NSEMS_MAX      22  /* int */
#define CTL_P1003_1B_SEM_VALUE_MAX      23  /* int */
#define CTL_P1003_1B_SIGQUEUE_MAX       24  /* int */
#define CTL_P1003_1B_TIMER_MAX          25  /* int */

#define CTL_P1003_1B_MAXID      26

int sysctl(const int *, u_int, void *, size_t *, const void *, size_t);
int sysctlbyname(const char *, void *, size_t *, const void *, size_t);
int sysctlnametomib(const char *, int *, size_t *);

#endif
