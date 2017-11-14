# $FreeBSD$

TOPDIR?=${CURDIR}/../..
include ${TOPDIR}/tools/opts.mk

PACKAGE=ipfw
PROG=	ipfw
SRCS=	ipfw2.c ipv6.c main.c nat.c tables.c compat.c
WARNS?=	2

ifneq (${MK_DUMMYNET},"no")
SRCS+=  dummynet.c
CFLAGS+= -DDUMMYNET
endif

ifneq (${MK_PF},"no")
SRCS+=  altq.c
CFLAGS+=-DPF
endif

LIBADD=	util
MAN=	ipfw.8

include ${TOPDIR}/tools/prog.mk

