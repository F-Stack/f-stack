#
# Derived from FreeBSD src/share/mk/bsd.prog.mk
#

ifdef DEBUG_FLAGS
CFLAGS+=${DEBUG_FLAGS}
CXXFLAGS+=${DEBUG_FLAGS}
endif

ifdef NO_SHARED
ifneq (${NO_SHARED},no)
ifneq (${NO_SHARED},NO)
LDFLAGS+= -static
endif
endif
endif

ifdef PROG_CXX
PROG=   ${PROG_CXX}
endif

ifndef PROG
$(error  PROG or PROG_CXX must be defined.)
endif

ifndef TOPDIR
$(error TOPDIR must be defined.)
endif

ifndef SRCS
ifdef PROG_CXX
SRCS=   ${PROG}.cc
else
SRCS=   ${PROG}.c
endif
endif

OBJS+= $(patsubst %.cc,%.o,$(patsubst %.c,%.o,${SRCS}))

ifeq ($(FF_DPDK),)
	FF_DPDK=${TOPDIR}/dpdk/x86_64-native-linuxapp-gcc
endif

FF_PROG_CFLAGS:= -g -Wall -Werror -DFSTACK -std=gnu99
FF_PROG_CFLAGS+= -I${TOPDIR}/lib -I${TOPDIR}/tools/compat
FF_PROG_CFLAGS+= -I${TOPDIR}/tools/compat/include -D__BSD_VISIBLE
FF_PROG_CFLAGS+= -include ${FF_DPDK}/include/rte_config.h
FF_PROG_CFLAGS+= -I${FF_DPDK}/include

FF_PROG_LIBS:= -L${TOPDIR}/tools/compat -Wl,--whole-archive -lffcompat
FF_PROG_LIBS+= -Wl,--no-whole-archive -L${FF_DPDK}/lib
FF_PROG_LIBS+= -Wl,--whole-archive -lrte_eal -lrte_mempool -lrte_ring
FF_PROG_LIBS+= -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -pthread

CFLAGS+= ${FF_PROG_CFLAGS}
CXXFLAGS+= ${FF_PROG_CFLAGS}

LIBS+= ${FF_PROG_LIBS}

${PROG}: ${OBJS}
ifdef PROG_CXX
	${CXX} ${CXXFLAGS} ${LDFLAGS} -o $@ ${OBJS} ${LIBS} 
else
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ ${OBJS} ${LIBS}
endif

clean:
	@rm -f ${PROG} ${OBJS}

all: ${PROG}
