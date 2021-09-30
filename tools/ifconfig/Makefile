#	From: @(#)Makefile	8.1 (Berkeley) 6/5/93
# $FreeBSD$

PROG=	ifconfig

SRCS=	ifconfig.c		# base support

TOPDIR?=${CURDIR}/../..
include ${TOPDIR}/tools/opts.mk

#
# NB: The order here defines the order in which the constructors
#     are called.  This in turn defines the default order in which
#     status is displayed.  Probably should add a priority mechanism
#     to the registration process so we don't depend on this aspect
#     of the toolchain.
#
SRCS+=	af_link.c		# LLC support
ifneq (${MK_INET_SUPPORT},"no")
SRCS+=	af_inet.c		# IPv4 support
endif
ifneq (${MK_INET6_SUPPORT},"no")
SRCS+=	af_inet6.c		# IPv6 support
endif
ifneq (${MK_INET6_SUPPORT},"no")
SRCS+=	af_nd6.c		# ND6 support
endif

SRCS+=	ifclone.c		# clone device support

ifneq (${MK_MAC_SUPPORT},"no")
SRCS+=	ifmac.c			# MAC support
endif

ifneq (${MK_IFMEDIA_SUPPORT},"no")
SRCS+=	ifmedia.c			# SIOC[GS]IFMEDIA support
endif

SRCS+=	iffib.c			# non-default FIB support
SRCS+=	ifvlan.c		# SIOC[GS]ETVLAN support
SRCS+=	ifvxlan.c		# VXLAN support
SRCS+=	ifgre.c			# GRE keys etc
SRCS+=	ifgif.c			# GIF reversed header workaround

ifneq (${MK_SFP_SUPPORT},"no")
SRCS+=	ifipsec.c		# IPsec VTI
endif

ifneq (${MK_SFP_SUPPORT},"no")
SRCS+=	sfp.c			# SFP/SFP+ information
LIBADD+=	m
endif

ifneq (${MK_IEEE80211_SUPPORT},"no")
SRCS+=	ifieee80211.c   # SIOC[GS]IEEE80211 support
LIBADD+=	80211
endif

SRCS+=	carp.c			# SIOC[GS]VH support
SRCS+=	ifgroup.c		# ...
ifneq (${MK_PF},"no")
SRCS+=	ifpfsync.c		# pfsync(4) support
endif

SRCS+=	ifbridge.c		# bridge support
ifneq (${MK_LAGG_SUPPORT},"no")
SRCS+=	iflagg.c   # lagg support
endif

ifneq (${MK_EXPERIMENTAL},"no")
CFLAGS+= -DDRAFT_IETF_6MAN_IPV6ONLY_FLAG
CFLAGS+= -DEXPERIMENTAL
endif
ifneq (${MK_INET6_SUPPORT},"no")
CFLAGS+= -DINET6
endif
ifneq (${MK_INET_SUPPORT},"no")
CFLAGS+= -DINET
endif
ifneq (${MK_JAIL},"no")
ifndef (RESCUE)
CFLAGS+= -DJAIL
LIBADD+=	jail
endif
endif

MAN=	ifconfig.8

CFLAGS+= -Wall -Wmissing-prototypes -Wcast-qual -Wwrite-strings -Wnested-externs
WARNS?=	2

include ${TOPDIR}/tools/prog.mk

