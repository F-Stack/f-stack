TOPDIR=..

ifeq ($(FF_PATH),)
	FF_PATH=${TOPDIR}
endif

ifeq ($(FF_DPDK),)
	FF_DPDK=${TOPDIR}/dpdk/x86_64-native-linuxapp-gcc
endif

LIBS+= -L${FF_PATH}/lib -L${FF_DPDK}/lib -Wl,--whole-archive,-lfstack,--no-whole-archive
LIBS+= -Wl,--whole-archive -lrte_pmd_vmxnet3_uio -lrte_pmd_i40e -lrte_pmd_ixgbe -lrte_pmd_e1000 -lrte_pmd_ring
LIBS+= -Wl,--whole-archive -lrte_hash -lrte_kvargs -Wl,-lrte_mbuf -lethdev -lrte_eal -Wl,-lrte_mempool
LIBS+= -lrte_ring -lrte_cmdline -lrte_cfgfile -lrte_kni -lrte_timer -Wl,-lrte_pmd_virtio
LIBS+= -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -pthread

TARGET="helloworld"
all:
	cc -O -gdwarf-2  -I../lib -o ${TARGET} main.c ${LIBS}
	cc -O -gdwarf-2  -I../lib -o ${TARGET}_epoll main_epoll.c ${LIBS}

.PHONY: clean
clean:
	rm -f *.o ${TARGET}
