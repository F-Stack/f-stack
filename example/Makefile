TOPDIR=..

ifeq ($(FF_PATH),)
	FF_PATH=${TOPDIR}
endif

ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "No installation of DPDK found, maybe you should export environment variable `PKG_CONFIG_PATH`")
endif

PKGCONF ?= pkg-config

CFLAGS += -O0 -g -gdwarf-2 $(shell $(PKGCONF) --cflags libdpdk)

LIBS+= $(shell $(PKGCONF) --static --libs libdpdk)
LIBS+= -L${FF_PATH}/lib -Wl,--whole-archive,-lfstack,--no-whole-archive
LIBS+= -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -lz -pthread -lnuma

TARGET="helloworld"

# M10: helloworld_zc requires libfstack.a built with FF_ZC_SEND=1
# (it depends on ff_zc_send / ff_zc_mbuf_*). Probe the archive and
# only build the ZC binary when the symbol is exported, so that
# milestones which disable ZC for isolation (e.g. M10 FF_FLOW_IPIP)
# still produce the other binaries successfully.
ZC_SUPPORTED := $(shell nm ${FF_PATH}/lib/libfstack.a 2>/dev/null | grep -q "T ff_zc_send" && echo 1)

all:
	cc ${CFLAGS} -DINET6 -o ${TARGET} main.c ${LIBS}
	cc ${CFLAGS} -o ${TARGET}_epoll main_epoll.c ${LIBS}
ifeq ($(ZC_SUPPORTED),1)
	cc ${CFLAGS} -DINET6 -DFSTACK_ZC_SEND -o ${TARGET}_zc main_zc.c ${LIBS}
else
	@echo "[M10 skip] libfstack.a built without FF_ZC_SEND — skipping ${TARGET}_zc"
endif

.PHONY: clean
clean:
	rm -f *.o ${TARGET} ${TARGET}_epoll ${TARGET}_zc
