# $FreeBSD$

TOPDIR?=${CURDIR}/../..
include ${TOPDIR}/tools/opts.mk

PACKAGE=ipfw
PROG=	ipfw
SRCS=	ipfw2.c ipv6.c main.c nat.c tables.c compat.c
SRCS+=	nat64clat.c nat64lsn.c nat64stl.c nptv6.c

ifneq (${MK_DUMMYNET},"no")
SRCS+=  dummynet.c
CFLAGS+= -DDUMMYNET
endif

ifneq (${MK_PF},"no")
SRCS+=  altq.c
CFLAGS+=-DPF
endif

ifneq (${MK_INET6_SUPPORT},"no")
CFLAGS+= -DINET6
endif

LIBADD=	util
MAN=	ipfw.8

include ${TOPDIR}/tools/prog.mk

CWARNFLAGS+= -Wno-cast-align
