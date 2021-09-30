# $FreeBSD$
# $Whistle: Makefile,v 1.4 1999/01/17 03:41:02 julian Exp $

TOPDIR?=${CURDIR}/../..

ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found, maybe you shuld export environment variable `PKG_CONFIG_PATH`")
endif

PACKAGE=lib${LIB}
LIB=		netgraph
WARNS?=		3
MAN=		netgraph.3

SHLIB_MAJOR=	4

PKGCONF ?= pkg-config

DPDK_CFLAGS= -g -Wall -Werror $(shell $(PKGCONF) --cflags libdpdk)

CFLAGS+= ${DPDK_CFLAGS}
CFLAGS+= -I${TOPDIR}/lib

SRCS=		sock.c msg.c debug.c compat.c
INCS=		netgraph.h

MLINKS+=	netgraph.3 NgMkSockNode.3
MLINKS+=	netgraph.3 NgNameNode.3
MLINKS+=	netgraph.3 NgSendMsg.3
MLINKS+=	netgraph.3 NgSendAsciiMsg.3
MLINKS+=	netgraph.3 NgSendReplyMsg.3
MLINKS+=	netgraph.3 NgRecvMsg.3
MLINKS+=	netgraph.3 NgAllocRecvMsg.3
MLINKS+=	netgraph.3 NgRecvAsciiMsg.3
MLINKS+=	netgraph.3 NgAllocRecvAsciiMsg.3
MLINKS+=	netgraph.3 NgSendData.3
MLINKS+=	netgraph.3 NgRecvData.3
MLINKS+=	netgraph.3 NgAllocRecvData.3
MLINKS+=	netgraph.3 NgSetDebug.3
MLINKS+=	netgraph.3 NgSetErrLog.3

include ${TOPDIR}/tools/lib.mk
