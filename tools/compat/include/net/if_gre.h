/*-
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * Copyright (c) 2014 Andrey V. Elsukov <ae@FreeBSD.org>
 * All rights reserved
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Heiko W.Rupp <hwr@pilhuhn.de>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $NetBSD: if_gre.h,v 1.13 2003/11/10 08:51:52 wiz Exp $
 * $FreeBSD$
 */

#ifndef _NET_IF_GRE_H_
#define _NET_IF_GRE_H_

#define GRESADDRS	_IOW('i', 101, struct ifreq)
#define GRESADDRD	_IOW('i', 102, struct ifreq)
#define GREGADDRS	_IOWR('i', 103, struct ifreq)
#define GREGADDRD	_IOWR('i', 104, struct ifreq)
#define GRESPROTO	_IOW('i' , 105, struct ifreq)
#define GREGPROTO	_IOWR('i', 106, struct ifreq)

#define	GREGKEY		_IOWR('i', 107, struct ifreq)
#define	GRESKEY		_IOW('i', 108, struct ifreq)
#define	GREGOPTS	_IOWR('i', 109, struct ifreq)
#define	GRESOPTS	_IOW('i', 110, struct ifreq)

#define	GRE_ENABLE_CSUM		0x0001
#define	GRE_ENABLE_SEQ		0x0002
#define	GRE_OPTMASK		(GRE_ENABLE_CSUM|GRE_ENABLE_SEQ)

#endif /* _NET_IF_GRE_H_ */
