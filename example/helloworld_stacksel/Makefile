TOPDIR=../..

ifeq ($(FF_PATH),)
	FF_PATH=${TOPDIR}
endif

ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "No installation of DPDK found, maybe you should export environment variable `PKG_CONFIG_PATH`")
endif

PKGCONF ?= pkg-config

CFLAGS += -O0 -g -gdwarf-2 -I${FF_PATH}/lib $(shell $(PKGCONF) --cflags libdpdk)

LIBS+= $(shell $(PKGCONF) --static --libs libdpdk)
LIBS+= -L${FF_PATH}/lib -Wl,--whole-archive,-lfstack,--no-whole-archive
LIBS+= -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -lz -pthread -lnuma

TARGET=helloworld_stacksel
TARGET_FFK=helloworld_stacksel_ffk
TARGET_LIBC=helloworld_stacksel_libc

# Perf-baseline binaries are built at -O2 (same flags for A and B so the
# measured A/B delta isolates only the ksock() difference).
BENCH_CFLAGS=-O2 -g -I${FF_PATH}/lib $(shell $(PKGCONF) --cflags libdpdk)

all:
	cc ${CFLAGS} -o ${TARGET} main.c ${LIBS}

# A/B perf-baseline targets from the SAME main.c (only ksock() differs):
#   _ffk  : USE_FF_KERNEL=1 -> ff_socket(SOCK_KERNEL)  (feature path A)
#   _libc : USE_FF_KERNEL=0 -> libc socket()           (pure-kernel ref B)
.PHONY: bench
bench: ${TARGET_FFK} ${TARGET_LIBC}

${TARGET_FFK}:
	cc ${BENCH_CFLAGS} -DUSE_FF_KERNEL=1 -o ${TARGET_FFK} main.c ${LIBS}

${TARGET_LIBC}:
	cc ${BENCH_CFLAGS} -DUSE_FF_KERNEL=0 -o ${TARGET_LIBC} main.c ${LIBS}

.PHONY: clean
clean:
	/data/workspace/rm_tmp_file.sh $(CURDIR)/${TARGET} $(CURDIR)/${TARGET_FFK} $(CURDIR)/${TARGET_LIBC} $(CURDIR)/main.o
