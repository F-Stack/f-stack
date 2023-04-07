TOPDIR=..

ifeq ($(FF_PATH),)
	FF_PATH=${TOPDIR}
endif

ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
	$(error "No installation of DPDK found, maybe you should export environment variable `PKG_CONFIG_PATH`")
endif

DEBUG=-O0 -gdwarf-2 -g3

# Per thread separate initialization dpdk lib and attach sc when needed,
# such as listen same port in different threads, and socket can use in own thread.
# Default disable.
#
# If disable it, one socket can use in all threads.
#FF_THREAD_SOCKET=1

PKGCONF ?= pkg-config

ifndef DEBUG
	CFLAGS+= -g -O2 -DNDEBUG
else
	CFLAGS+= ${DEBUG}
endif

ifdef FF_THREAD_SOCKET
	CFLAGS+= -DFF_THREAD_SOCKET
endif

CFLAGS += -fPIC -Wall -Werror $(shell $(PKGCONF) --cflags libdpdk)

INCLUDES= -I. -I${FF_PATH}/lib

FF_LIBS= -L${FF_PATH}/lib -Wl,--whole-archive,-lfstack,--no-whole-archive

DPDK_LIBS+= $(shell $(PKGCONF) --static --libs libdpdk)
DPDK_LIBS+= -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -pthread -lnuma

#DPDK_CFLAGS= -Wall -Werror -include ${FF_DPDK}/include/rte_config.h
#DPDK_CFLAGS+= -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3
#DPDK_CFLAGS+= -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2
#DPDK_CFLAGS+= -DRTE_COMPILE_TIME_CPUFLAGS=RTE_CPUFLAG_SSE,RTE_CPUFLAG_SSE2,RTE_CPUFLAG_SSE3,RTE_CPUFLAG_SSSE3,RTE_CPUFLAG_SSE4_1,RTE_CPUFLAG_SSE4_2
#DPDK_CFLAGS+= -I${FF_DPDK}/include

CFLAGS+= ${INCLUDES} ${DPDK_CFLAGS}

FSTACK_LIBS= ${FF_LIBS} ${DPDK_LIBS}
FF_SYSCALL_LIBS=

FSTACK_SRCS=                  \
	fstack.c                  \
	ff_so_zone.c              \
	ff_socket_ops.c

FF_SYSCALL_SRCS=              \
	ff_so_zone.c              \
	ff_hook_syscall.c         \
	ff_linux_syscall.c

FSTACK_OBJS= $(patsubst %.c,%.o,${FSTACK_SRCS})

FF_SYSCALL_OBJS= $(patsubst %.c,%.o,${FF_SYSCALL_SRCS})

#TARGET= fstack libff_syscall.a
TARGET= fstack libff_syscall.so

all: ${TARGET}

fstack: ${FSTACK_OBJS}
	cc -o $@ $^ ${FSTACK_LIBS}

#libff_syscall.a: ${FF_SYSCALL_OBJS}
libff_syscall.so: ${FF_SYSCALL_OBJS}
	#ar -rcs $@ $^ ${FF_SYSCALL_LIBS}
	${CC} -fPIC -shared -o $@ $^ ${FF_SYSCALL_LIBS}

${FSTACK_OBJS}: %.o: %.c
	${CC} -c $(CFLAGS) ${PROF} $<

${FF_SYSCALL_OBJS}: %.o: %.c
	${CC} -c $(CFLAGS) ${PROF} $<

.PHONY: clean
clean:
	rm -f *.o ${TARGET}
