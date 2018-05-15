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

HEADERS+= $(filter %.h,${SRCS})
OBJS+= $(patsubst %.c,%.o, $(filter %.c,${SRCS}))
OBJS+= $(patsubst %.cc,%.o, $(filter %.cc,${SRCS}))

ifeq ($(FF_DPDK),)
	FF_DPDK=${TOPDIR}/dpdk/x86_64-native-linuxapp-gcc
endif

FF_PROG_CFLAGS:= -g -Wall -Werror -DFSTACK -std=gnu99
FF_PROG_CFLAGS+= -I${TOPDIR}/lib -I${TOPDIR}/tools/compat
FF_PROG_CFLAGS+= -include${TOPDIR}/tools/compat/compat.h
FF_PROG_CFLAGS+= -I${TOPDIR}/tools/compat/include -D__BSD_VISIBLE
FF_PROG_CFLAGS+= -include ${FF_DPDK}/include/rte_config.h
FF_PROG_CFLAGS+= -I${FF_DPDK}/include

FF_PROG_LIBS:= -L${TOPDIR}/tools/compat -Wl,--whole-archive,-lffcompat,--no-whole-archive
FF_PROG_LIBS+= -L${FF_DPDK}/lib -Wl,--whole-archive,-ldpdk,--no-whole-archive
FF_PROG_LIBS+= -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -lpthread -lnuma

CFLAGS+= -Wno-unused-but-set-variable -Wno-unused-variable
CFLAGS+= ${FF_PROG_CFLAGS}
CXXFLAGS+= ${FF_PROG_CFLAGS}

LIBS+= ${FF_PROG_LIBS}

CFLAGS+= $(foreach n,${LIBADD},-I${TOPDIR}/tools/lib${n})
LIBS+= $(foreach n,${LIBADD},-L${TOPDIR}/tools/lib${n} -l${n})

CLEANFILES+= ${PROG} ${OBJS}

${PROG}: ${HEADERS} ${OBJS}
ifdef PROG_CXX
	${CXX} ${CXXFLAGS} ${LDFLAGS} -o $@ ${OBJS} ${LIBS} 
else
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ ${OBJS} ${LIBS}
endif

clean:
	@rm -f ${CLEANFILES}

all: ${PROG}
