TOPDIR=../..

ifeq ($(FF_PATH),)
	FF_PATH=${TOPDIR}
endif

ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "No installation of DPDK found, maybe you should export environment variable `PKG_CONFIG_PATH`")
endif

PKGCONF ?= pkg-config

CFLAGS += -O0 -g -gdwarf-2 -DFF_KERNEL_COEXIST -I${FF_PATH}/lib $(shell $(PKGCONF) --cflags libdpdk)

LIBS+= $(shell $(PKGCONF) --static --libs libdpdk)
LIBS+= -L${FF_PATH}/lib -Wl,--whole-archive,-lfstack,--no-whole-archive
LIBS+= -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -lz -pthread -lnuma

TARGET=helloworld_stacksel

# main.c uses the ff_host_epoll_* wrappers, which libfstack.a only contains
# when the library is built with FF_KERNEL_COEXIST=1. Probe the archive and
# skip with a hint instead of failing at link time (same pattern as the
# helloworld_zc / ff_zc_send probe in ../Makefile).
COEXIST_SUPPORTED := $(shell nm ${FF_PATH}/lib/libfstack.a 2>/dev/null | grep -q "T ff_host_epoll_ctl" && echo 1)

all:
ifeq ($(COEXIST_SUPPORTED),1)
	cc ${CFLAGS} -o ${TARGET} main.c ${LIBS}
else
	@echo "[skip] libfstack.a built without FF_KERNEL_COEXIST - skipping ${TARGET}; rebuild the library with 'make FF_KERNEL_COEXIST=1' to build it"
endif

.PHONY: clean
clean:
	/data/workspace/rm_tmp_file.sh $(CURDIR)/${TARGET} $(CURDIR)/main.o
