#	@(#)Makefile	8.1 (Berkeley) 6/5/93
# $FreeBSD$

TOPDIR?=${CURDIR}/../..
include ${TOPDIR}/tools/opts.mk

PROG=	route
MAN=	route.8
SRCS=	route.c keywords.h
WARNS?=	3
CLEANFILES+=keywords.h

CFLAGS+= -DNS
ifneq (${MK_INET_SUPPORT},"no")
CFLAGS+= -DINET
endif
ifneq (${MK_INET6_SUPPORT},"no")
CFLAGS+= -DINET6
endif
CFLAGS+= -I.

include ${TOPDIR}/tools/prog.mk

keywords.h: keywords
	LC_ALL=C awk '!/^#|^$$/ { \
		printf "#define\tK_%s\t%d\n\t{\"%s\", K_%s},\n", \
		    toupper($$1), ++L, $$1, toupper($$1); \
	}' < ${CURDIR}/keywords > $@

