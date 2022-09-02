# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

env_objs = []
env_headers = files(
		'include/rte_os.h',
)
env_sources = files('eal_alarm.c',
		'eal_cpuflags.c',
		'eal_debug.c',
		'eal_hugepage_info.c',
		'eal_interrupts.c',
		'eal_lcore.c',
		'eal_memalloc.c',
		'eal_thread.c',
		'eal_timer.c',
		'eal.c',
		'eal_memory.c',
		'eal_dev.c'
)

deps += ['kvargs']

# test for version of cpuset macros
cpuset_test_code = '''
        #include <sys/types.h>
        #include <sys/cpuset.h>
        void cpu_test_or(cpuset_t *s) { CPU_OR(s, s, s); }
'''

if not cc.compiles(cpuset_test_code, name: 'Detect argument count for CPU_OR')
    dpdk_conf.set('RTE_EAL_FREEBSD_CPUSET_LEGACY', 1)
endif
