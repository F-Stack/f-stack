#	@(#)Makefile	8.1 (Berkeley) 6/12/93
# $FreeBSD$

PROG=	netstat
SRCS=	if.c inet.c main.c mbuf.c mroute.c netisr.c nl_symbols.c route.c \
	unix.c mroute6.c ipsec.c bpf.c pfkey.c sctp.c common.c nhops.c nhgrp.c \
	nl_defs.h

TOPDIR?=${CURDIR}/../..
include ${TOPDIR}/tools/opts.mk

CLEANFILES+=	nl_symbols.c nl_defs.h

LIBADD=util memstat xo

WARNS?=	3
CFLAGS+=-fno-strict-aliasing

ifneq (${MK_IPSEC_SUPPORT},"no")
CFLAGS+=-DIPSEC
endif
CFLAGS+=-DSCTP

ifneq (${MK_INET_SUPPORT},"no")
CFLAGS+=-DINET
endif

ifneq (${MK_INET6_SUPPORT},"no")
SRCS+=	inet6.c
CFLAGS+=-DINET6
endif

ifneq (${MK_OFED},"no")
CFLAGS+=-DSDP
endif

ifneq (${MK_PF},"no")
CFLAGS+=-DPF
endif

BINGRP=	kmem
BINMODE=2555

ifneq (${MK_NETGRAPH_SUPPORT},"no")
SRCS+=	netgraph.c
LIBADD+=	netgraph
CFLAGS+=-DNETGRAPH
endif

include ${TOPDIR}/tools/prog.mk

nl_symbols.c: nlist_symbols
	awk '\
	    BEGIN { \
		print "#include <sys/param.h>"; \
		print "#include <nlist.h>"; \
		print "struct nlist nl[] = {"; \
	    } \
	    !/^\#/ { printf("\t{ .n_name = \"%s\" },\n", $$2); } \
	    END { print "\t{ .n_name = NULL },\n};" } \
	    ' < $^ > $@

nl_defs.h: nlist_symbols
	awk '\
	    BEGIN { \
		print "#include <nlist.h>"; \
		print "extern struct nlist nl[];"; \
		i = 0; \
	    } \
	    !/^\#/ { printf("\#define\tN%s\t%s\n", toupper($$2), i++); }' \
            < $^ > $@

