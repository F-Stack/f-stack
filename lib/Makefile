# 
# Copyright (c) 2013 Patrick Kelsey. All rights reserved.
# Copyright (C) 2017 THL A29 Limited, a Tencent company.
# All rights reserved.
#
# Derived in part from libuinet's Makefile.
#
# Derived from FreeBSD auto-generated kernel Makefile and
# machine-specific Makefile templates
#

TOPDIR?=${CURDIR}/..
S=${TOPDIR}/freebsd
MACHINE_INCLUDES_ROOT:=${CURDIR}/machine_include
OVERRIDE_INCLUDES_ROOT:=${CURDIR}/include
X86_INCLUDES=0

HOST_OS:=$(shell uname -s)
#DEBUG=-O0 -gdwarf-2 -g3
#FF_NETGRAPH=1
#FF_IPFW=1

ifeq ($(FF_DPDK),)
    FF_DPDK=${TOPDIR}/dpdk/x86_64-native-linuxapp-gcc
endif

DPDK_CFLAGS= -Wall -Werror -include ${FF_DPDK}/include/rte_config.h
DPDK_CFLAGS+= -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3
DPDK_CFLAGS+= -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2
DPDK_CFLAGS+= -DRTE_COMPILE_TIME_CPUFLAGS=RTE_CPUFLAG_SSE,RTE_CPUFLAG_SSE2,RTE_CPUFLAG_SSE3,RTE_CPUFLAG_SSSE3,RTE_CPUFLAG_SSE4_1,RTE_CPUFLAG_SSE4_2
DPDK_CFLAGS+= -I${FF_DPDK}/include

include ${TOPDIR}/mk/kern.pre.mk

KERNPREINCLUDES:= ${INCLUDES}
INCLUDES= -I${OVERRIDE_INCLUDES_ROOT} ${KERNPREINCLUDES}
INCLUDES+= -I./machine_include
INCLUDES+= -I./opt

# Include search path for files that only include host OS headers
HOST_INCLUDES= -I.
ifndef DEBUG
HOST_CFLAGS = -O2 -frename-registers  -funswitch-loops -fweb
else
HOST_CFLAGS = ${DEBUG} 
endif

HOST_CFLAGS+= ${DPDK_CFLAGS}
HOST_CFLAGS+= ${CONF_CFLAGS}

ifdef FF_NETGRAPH
HOST_CFLAGS+= -DFF_NETGRAPH
endif

ifdef FF_IPFW
HOST_CFLAGS+= -DFF_IPFW
endif

HOST_C= ${CC} -c $(HOST_CFLAGS) ${HOST_INCLUDES} ${WERROR} ${PROF} $<


ifneq ($(filter amd64 i386,${MACHINE_CPUARCH}),)
X86_INCLUDES=1
endif


#
# Distilled from FreeBSD src/sys/conf/Makefile.amd64
#
ifeq (${MACHINE_CPUARCH},amd64)
endif

#
# Distilled from FreeBSD src/sys/conf/Makefile.arm
#
ifeq (${MACHINE_CPUARCH},arm)

ifneq (${COMPILER_TYPE},clang)
CFLAGS += -mno-thumb-interwork
endif

endif


#
# Distilled from FreeBSD src/sys/conf/Makefile.i386
#
ifeq (${MACHINE_CPUARCH},i386)
MACHINE=i386
endif


#
# Distilled from FreeBSD src/sys/conf/Makefile.mips
#
ifeq (${MACHINE_CPUARCH},mips)

# We default to the MIPS32 ISA, if none specified in the
# kernel configuration file.
ARCH_FLAGS?=-march=mips32

HACK_EXTRA_FLAGS=-shared

CFLAGS+=${EXTRA_FLAGS} $(ARCH_FLAGS)
HACK_EXTRA_FLAGS+=${EXTRA_FLAGS} $(ARCH_FLAGS)
endif

CFLAGS+= -DFSTACK

# add for LVS tcp option toa, disabled by default
# CFLAGS+= -DLVS_TCPOPT_TOA

VPATH+= $S/${MACHINE_CPUARCH}/${MACHINE_CPUARCH}
VPATH+= $S/kern
VPATH+= $S/crypto
VPATH+= $S/crypto/aesni
VPATH+= $S/crypto/blowfish
VPATH+= $S/crypto/camellia
VPATH+= $S/crypto/des
VPATH+= $S/crypto/rijndael
VPATH+= $S/crypto/sha2
VPATH+= $S/crypto/siphash
VPATH+= $S/net
ifdef FF_NETGRAPH
VPATH+= $S/netgraph
endif
VPATH+= $S/netinet
VPATH+= $S/netinet/libalias
VPATH+= $S/netinet/cc
VPATH+= $S/netipsec
ifdef FF_IPFW
VPATH+= $S/netpfil/ipfw
endif
VPATH+= $S/opencrypto
VPATH+= $S/vm
VPATH+= $S/libkern


FF_SRCS+=                     \
	ff_compat.c           \
	ff_glue.c             \
	ff_freebsd_init.c     \
	ff_init_main.c        \
	ff_kern_condvar.c     \
	ff_kern_environment.c \
	ff_kern_intr.c        \
	ff_kern_subr.c        \
	ff_kern_synch.c       \
	ff_kern_timeout.c     \
	ff_lock.c             \
	ff_syscall_wrapper.c  \
	ff_subr_prf.c         \
	ff_vfs_ops.c          \
	ff_veth.c             \
	ff_route.c

ifdef FF_NETGRAPH
FF_SRCS+=                   \
        ff_ng_base.c        \
        ff_ngctl.c
endif

FF_HOST_SRCS+=              \
	ff_host_interface.c \
	ff_config.c         \
	ff_ini_parser.c     \
	ff_dpdk_if.c        \
	ff_dpdk_kni.c       \
	ff_dpdk_pcap.c      \
	ff_epoll.c          \
	ff_init.c

ifdef FF_IPSEC
CRYPTO_ASM_SRCS+=                       \
	aesencdec_${MACHINE_CPUARCH}.S  \
	aeskeys_${MACHINE_CPUARCH}.S

CRYPTO_SRCS+=               \
	aesni.c	            \
	aesni_wrap.c        \
	bf_ecb.c            \
	bf_enc.c            \
	bf_skey.c           \
	camellia.c          \
	camellia-api.c      \
	des_ecb.c           \
	des_enc.c           \
	des_setkey.c        \
	rijndael-alg-fst.c  \
	rijndael-api.c      \
	sha1.c              \
	sha256c.c           \
	sha512c.c           \
	siphash.c
else
CRYPTO_SRCS+=               \
	sha1.c              \
	siphash.c
endif

KERN_SRCS+=                 \
	kern_descrip.c      \
	kern_event.c        \
	kern_fail.c         \
	kern_khelp.c        \
	kern_hhook.c        \
	kern_linker.c       \
	kern_mbuf.c         \
	kern_module.c       \
	kern_mtxpool.c      \
	kern_ntptime.c      \
	kern_osd.c          \
	kern_sysctl.c       \
	kern_tc.c           \
	kern_uuid.c         \
	link_elf.c          \
	md5c.c              \
	subr_capability.c   \
	subr_counter.c      \
	subr_eventhandler.c \
	subr_kobj.c         \
	subr_lock.c         \
	subr_module.c       \
	subr_param.c        \
	subr_pcpu.c         \
	subr_sbuf.c         \
	subr_taskqueue.c    \
	subr_unit.c         \
	sys_capability.c    \
	sys_generic.c       \
	sys_socket.c        \
	uipc_accf.c         \
	uipc_mbuf.c         \
	uipc_mbuf2.c        \
	uipc_domain.c       \
	uipc_sockbuf.c      \
	uipc_socket.c       \
	uipc_syscalls.c


KERN_MHEADERS+=		\
	bus_if.m	\
	device_if.m	\
	linker_if.m


KERN_MSRCS+=		\
	linker_if.m


LIBKERN_SRCS+=		 \
	bcd.c		 \
	crc32.c          \
	inet_ntoa.c	 \
	jenkins_hash.c   \
	strlcpy.c	 \
	strnlen.c        \
	zlib.c


MACHINE_SRCS+=		 \
	in_cksum.c


NET_SRCS+=		 \
	bpf.c		 \
	bridgestp.c      \
	if.c		 \
	if_bridge.c      \
	if_clone.c	 \
	if_dead.c	 \
	if_ethersubr.c	 \
	if_loop.c	 \
	if_llatbl.c	 \
	if_media.c       \
	if_spppfr.c      \
	if_spppsubr.c    \
	if_vlan.c        \
	if_vxlan.c       \
	in_fib.c	 \
	in_gif.c         \
	ip_reass.c	 \
	netisr.c	 \
	pfil.c		 \
	radix.c		 \
	raw_cb.c	 \
	raw_usrreq.c	 \
	route.c		 \
	rtsock.c         \
	slcompress.c

ifdef FF_NETGRAPH
NETGRAPH_SRCS +=         \
	ng_async.c       \
	ng_atmllc.c      \
	ng_bridge.c      \
	ng_car.c         \
	ng_cisco.c       \
	ng_deflate.c     \
	ng_echo.c        \
	ng_eiface.c      \
	ng_etf.c         \
	ng_ether.c       \
	ng_ether_echo.c  \
	ng_frame_relay.c \
	ng_gif.c         \
	ng_gif_demux.c   \
	ng_hole.c        \
	ng_hub.c         \
	ng_iface.c       \
	ng_ip_input.c    \
	ng_ipfw.c        \
	ng_ksocket.c     \
	ng_l2tp.c        \
	ng_lmi.c         \
	ng_nat.c         \
	ng_one2many.c    \
	ng_parse.c       \
	ng_patch.c       \
	ng_pipe.c        \
	ng_ppp.c         \
	ng_pppoe.c       \
	ng_pptpgre.c     \
	ng_pred1.c       \
	ng_rfc1490.c     \
	ng_sample.c      \
	ng_socket.c      \
	ng_source.c      \
	ng_split.c       \
	ng_sppp.c        \
	ng_tag.c         \
	ng_tcpmss.c      \
	ng_tee.c         \
	ng_UI.c          \
	ng_vjc.c         \
	ng_vlan.c
endif

NETINET_SRCS+=		\
	if_ether.c	\
	if_gif.c        \
	igmp.c		\
	in.c		\
	in_mcast.c	\
	in_pcb.c	\
	in_proto.c	\
	in_rmx.c	\
	ip_carp.c	\
	ip_divert.c     \
	ip_ecn.c        \
	ip_encap.c	\
	ip_fastfwd.c	\
	ip_icmp.c	\
	ip_id.c		\
	ip_input.c	\
	ip_mroute.c     \
	ip_options.c	\
	ip_output.c	\
	raw_ip.c	\
	tcp_debug.c	\
	tcp_fastopen.c	\
	tcp_hostcache.c	\
	tcp_input.c	\
	tcp_lro.c	\
	tcp_offload.c	\
	tcp_output.c	\
	tcp_reass.c	\
	tcp_sack.c	\
	tcp_subr.c	\
	tcp_syncache.c	\
	tcp_timer.c	\
	tcp_timewait.c	\
	tcp_usrreq.c	\
	udp_usrreq.c	\
	cc.c		\
	cc_newreno.c    \
	cc_htcp.c       \
	cc_cubic.c      \
	alias.c         \
	alias_db.c      \
	alias_mod.c     \
	alias_proxy.c   \
	alias_sctp.c    \
	alias_util.c

ifdef FF_IPFW
NETIPFW_SRCS+=             \
	ip_fw_dynamic.c \
	ip_fw_eaction.c \
	ip_fw_iface.c   \
	ip_fw_log.c     \
	ip_fw_nat.c     \
	ip_fw_pfil.c    \
	ip_fw_sockopt.c \
	ip_fw_table.c   \
	ip_fw_table_algo.c  \
	ip_fw_table_value.c \
	ip_fw2.c
endif

ifdef FF_IPSEC
NETINET_SRCS+=		\
	ip_ipsec.c
endif


ifdef FF_IPSEC
NETIPSEC_SRCS+=		\
	ipsec.c		\
	ipsec_input.c	\
	ipsec_mbuf.c	\
	ipsec_output.c	\
	key.c		\
	key_debug.c	\
	keysock.c	\
	xform_ah.c	\
	xform_esp.c	\
	xform_ipcomp.c
endif

# only if TCP_SIGNTAURE is defined
#xform_tcp.c

NETINET6_SRCS+=


ifdef FF_IPSEC
OPENCRYPTO_SRCS+=	\
	cast.c		\
	criov.c		\
	crypto.c	\
	cryptosoft.c	\
	deflate.c	\
	rmd160.c	\
	skipjack.c	\
	xform.c
endif

#	cryptodev.c

OPENCRYPTO_MHEADERS= cryptodev_if.m
OPENCRYPTO_MSRCS= cryptodev_if.m

VM_SRCS+=		\
	uma_core.c


MHEADERS= $(patsubst %.m,%.h,${KERN_MHEADERS})
MHEADERS+= vnode_if.h vnode_if_newproto.h vnode_if_typedef.h
MHEADERS+= $(patsubst %.m,%.h,${OPENCRYPTO_MHEADERS})

MSRCS= $(patsubst %.m,%.c,${KERN_MSRCS})
MSRCS+= $(patsubst %.m,%.c,${OPENCRYPTO_MSRCS})

ASM_SRCS = ${CRYPTO_ASM_SRCS}

SRCS=  ${FF_SRCS} ${CRYPTO_SRCS} ${KERN_SRCS} ${LIBKERN_SRCS} ${MACHINE_SRCS}
SRCS+= ${MSRCS} ${NET_SRCS} ${NETGRAPH_SRCS} ${NETINET_SRCS} ${NETINET6_SRCS}
SRCS+= ${NETIPSEC_SRCS} ${NETIPFW_SRCS} ${OPENCRYPTO_SRCS} ${VM_SRCS}

# If witness is enabled.
# SRCS+= ${KERN_WITNESS_SRCS}

# Extra FreeBSD kernel module srcs.
SRCS+= ${KMOD_SRCS}

HOST_SRCS = ${FF_HOST_SRCS}

ASM_OBJS+= $(patsubst %.S,%.o,${ASM_SRCS})
OBJS+= $(patsubst %.c,%.o,${SRCS})
HOST_OBJS+= $(patsubst %.c,%.o,${HOST_SRCS})

all: libfstack.a

#
# The library is built by first incrementally linking all the object
# to resolve internal references.  Then, all symbols are made local.
# Then, only the symbols that are part of the  API are made
# externally available.
#
libfstack.a: machine_includes ff_api.symlist ${MHEADERS} ${MSRCS} ${HOST_OBJS} ${ASM_OBJS} ${OBJS}
	${LD} -d -r -o $*.ro ${ASM_OBJS} ${OBJS}
	nm $*.ro  | grep -v ' U ' | cut -d ' ' -f 3 > $*_localize_list.tmp
	objcopy --localize-symbols=$*_localize_list.tmp $*.ro 
	rm $*_localize_list.tmp
	objcopy --globalize-symbols=ff_api.symlist $*.ro
	rm -f $@
	ar -cqs $@ $*.ro ${HOST_OBJS}
	rm -f $*.ro

${HOST_OBJS}: %.o: %.c
	${HOST_C}

${ASM_OBJS}: %.o: %.S ${IMACROS_FILE}
	${NORMAL_S}

${OBJS}: %.o: %.c ${IMACROS_FILE}
	${NORMAL_C}


.SUFFIXES: .m

.m.c:
	${AWK} -f $S/tools/makeobjops.awk $< -c

.m.h:
	${AWK} -f $S/tools/makeobjops.awk $< -h

.PHONY: clean
clean:
	rm -f libfstack.a
	rm -f ${MHEADERS} ${MSRCS} ${HOST_OBJS} ${ASM_OBJS} ${OBJS} ${PROGRAM} ${IMACROS_FILE}
	rm -rf ${MACHINE_INCLUDES_ROOT}


.PHONY: machine_includes
machine_includes:
	@rm -rf ${MACHINE_INCLUDES_ROOT}
	@mkdir -p ${MACHINE_INCLUDES_ROOT}/machine
	@cp -r $S/${MACHINE_CPUARCH}/include/* ${MACHINE_INCLUDES_ROOT}/machine
	@if [ "${X86_INCLUDES}" != "0" ]; then 				\
		mkdir -p ${MACHINE_INCLUDES_ROOT}/x86;			\
		cp -r $S/x86/include/* ${MACHINE_INCLUDES_ROOT}/x86;	\
	fi

#
# Distilled from FreeBSD src/sys/conf/kern.post.mk
#
vnode_if.h vnode_if_newproto.h vnode_if_typedef.h: $S/tools/vnode_if.awk \
    $S/kern/vnode_if.src
vnode_if.h: vnode_if_newproto.h vnode_if_typedef.h
	${AWK} -f $S/tools/vnode_if.awk $S/kern/vnode_if.src -h
vnode_if_newproto.h:
	${AWK} -f $S/tools/vnode_if.awk $S/kern/vnode_if.src -p
vnode_if_typedef.h:
	${AWK} -f $S/tools/vnode_if.awk $S/kern/vnode_if.src -q

include ${TOPDIR}/mk/kern.mk

