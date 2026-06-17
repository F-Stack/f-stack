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

all:
	cc ${CFLAGS} -o ${TARGET} main.c ${LIBS}

.PHONY: clean
clean:
	/data/workspace/rm_tmp_file.sh $(CURDIR)/${TARGET} $(CURDIR)/main.o
