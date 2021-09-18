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
 */

#ifndef _FSTACK_ERRNO_H
#define _FSTACK_ERRNO_H

#define ff_EPERM         1        /* Operation not permitted */
#define ff_ENOENT        2        /* No such file or directory */
#define ff_ESRCH         3        /* No such process */
#define ff_EINTR         4        /* Interrupted system call */
#define ff_EIO           5        /* Input/output error */
#define ff_ENXIO         6        /* Device not configured */
#define ff_E2BIG         7        /* Argument list too long */
#define ff_ENOEXEC       8        /* Exec format error */
#define ff_EBADF         9        /* Bad file descriptor */
#define ff_ECHILD        10        /* No child processes */
#define ff_EDEADLK       11        /* Resource deadlock avoided */
#define ff_ENOMEM        12        /* Cannot allocate memory */
#define ff_EACCES        13        /* Permission denied */
#define ff_EFAULT        14        /* Bad address */
#define ff_ENOTBLK       15        /* Block device required */
#define ff_EBUSY         16        /* Device busy */
#define ff_EEXIST        17        /* File exists */
#define ff_EXDEV         18        /* Cross-device link */
#define ff_ENODEV        19        /* Operation not supported by device */
#define ff_ENOTDIR       20        /* Not a directory */
#define ff_EISDIR        21        /* Is a directory */
#define ff_EINVAL        22        /* Invalid argument */
#define ff_ENFILE        23        /* Too many open files in system */
#define ff_EMFILE        24        /* Too many open files */
#define ff_ENOTTY        25        /* Inappropriate ioctl for device */
#define ff_ETXTBSY       26        /* Text file busy */
#define ff_EFBIG         27        /* File too large */
#define ff_ENOSPC        28        /* No space left on device */
#define ff_ESPIPE        29        /* Illegal seek */
#define ff_EROFS         30        /* Read-only filesystem */
#define ff_EMLINK        31        /* Too many links */
#define ff_EPIPE         32        /* Broken pipe */

/* math software */
#define ff_EDOM          33        /* Numerical argument out of domain */
#define ff_ERANGE        34        /* Result too large */

/* non-blocking and interrupt i/o */
#define ff_EAGAIN        35        /* Resource temporarily unavailable */
#define ff_EWOULDBLOCK   ff_EAGAIN        /* Operation would block */
#define ff_EINPROGRESS   36        /* Operation now in progress */
#define ff_EALREADY      37        /* Operation already in progress */

/* ipc/network software -- argument errors */
#define ff_ENOTSOCK      38        /* Socket operation on non-socket */
#define ff_EDESTADDRREQ  39        /* Destination address required */
#define ff_EMSGSIZE      40        /* Message too long */
#define ff_EPROTOTYPE    41        /* Protocol wrong type for socket */
#define ff_ENOPROTOOPT   42        /* Protocol not available */
#define ff_EPROTONOSUPPORT    43        /* Protocol not supported */
#define ff_ESOCKTNOSUPPORT    44        /* Socket type not supported */
#define ff_EOPNOTSUPP         45        /* Operation not supported */
#define ff_ENOTSUP        ff_EOPNOTSUPP    /* Operation not supported */
#define ff_EPFNOSUPPORT       46        /* Protocol family not supported */
#define ff_EAFNOSUPPORT       47        /* Address family not supported by protocol family */
#define ff_EADDRINUSE         48        /* Address already in use */
#define ff_EADDRNOTAVAIL      49        /* Can't assign requested address */

/* ipc/network software -- operational errors */
#define ff_ENETDOWN       50        /* Network is down */
#define ff_ENETUNREACH    51        /* Network is unreachable */
#define ff_ENETRESET      52        /* Network dropped connection on reset */
#define ff_ECONNABORTED   53        /* Software caused connection abort */
#define ff_ECONNRESET     54        /* Connection reset by peer */
#define ff_ENOBUFS        55        /* No buffer space available */
#define ff_EISCONN        56        /* Socket is already connected */
#define ff_ENOTCONN       57        /* Socket is not connected */
#define ff_ESHUTDOWN      58        /* Can't send after socket shutdown */
#define ff_ETOOMANYREFS   59        /* Too many references: can't splice */
#define ff_ETIMEDOUT      60        /* Operation timed out */
#define ff_ECONNREFUSED   61        /* Connection refused */

#define ff_ELOOP          62        /* Too many levels of symbolic links */
#define ff_ENAMETOOLONG   63        /* File name too long */

/* should be rearranged */
#define ff_EHOSTDOWN      64        /* Host is down */
#define ff_EHOSTUNREACH   65        /* No route to host */
#define ff_ENOTEMPTY      66        /* Directory not empty */

/* quotas & mush */
#define ff_EPROCLIM       67        /* Too many processes */
#define ff_EUSERS         68        /* Too many users */
#define ff_EDQUOT         69        /* Disc quota exceeded */

#define ff_ESTALE         70        /* Stale NFS file handle */
#define ff_EREMOTE        71        /* Too many levels of remote in path */
#define ff_EBADRPC        72        /* RPC struct is bad */
#define ff_ERPCMISMATCH   73        /* RPC version wrong */
#define ff_EPROGUNAVAIL   74        /* RPC prog. not avail */
#define ff_EPROGMISMATCH  75        /* Program version wrong */
#define ff_EPROCUNAVAIL   76        /* Bad procedure for program */

#define ff_ENOLCK         77        /* No locks available */
#define ff_ENOSYS         78        /* Function not implemented */

#define ff_EFTYPE         79        /* Inappropriate file type or format */
#define ff_EAUTH          80        /* Authentication error */
#define ff_ENEEDAUTH      81        /* Need authenticator */
#define ff_EIDRM          82        /* Identifier removed */
#define ff_ENOMSG         83        /* No message of desired type */
#define ff_EOVERFLOW      84        /* Value too large to be stored in data type */
#define ff_ECANCELED      85        /* Operation canceled */
#define ff_EILSEQ         86        /* Illegal byte sequence */
#define ff_ENOATTR        87        /* Attribute not found */

#define ff_EDOOFUS        88        /* Programming error */

#define ff_EBADMSG        89        /* Bad message */
#define ff_EMULTIHOP      90        /* Multihop attempted */
#define ff_ENOLINK        91        /* Link has been severed */
#define ff_EPROTO         92        /* Protocol error */

#define ff_ENOTCAPABLE    93        /* Capabilities insufficient */
#define ff_ECAPMODE       94        /* Not permitted in capability mode */
#define ff_ENOTRECOVERABLE 95        /* State not recoverable */
#define ff_EOWNERDEAD      96        /* Previous owner died */

#endif

