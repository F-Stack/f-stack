TOPDIR=../..

ifeq ($(FF_PATH),)
	FF_PATH=${TOPDIR}
endif

ifeq ($(FF_DPDK),)
	FF_DPDK=${TOPDIR}/dpdk/x86_64-native-linuxapp-gcc
endif

LIBS+= -L${FF_PATH}/lib -Wl,--whole-archive,-lfstack,--no-whole-archive
LIBS+= -L${FF_DPDK}/lib -Wl,--whole-archive,-ldpdk,--no-whole-archive
LIBS+= -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -pthread -lnuma

TARGET=helloworld_stacksel
all:
	cc -O -gdwarf-2 -DFF_KERNEL_COEXIST -I${FF_PATH}/lib -DINET6 -o ${TARGET} main.c ${LIBS}

.PHONY: clean
clean:
	/data/workspace/rm_tmp_file.sh $(CURDIR)/${TARGET}
