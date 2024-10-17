/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sched.h>
#include <pthread_np.h>
#include <sys/queue.h>
#include <sys/thr.h>

#include <rte_debug.h>
#include <rte_atomic.h>
#include <rte_launch.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_per_lcore.h>
#include <rte_eal.h>
#include <rte_lcore.h>

#include "eal_private.h"
#include "eal_thread.h"

/* require calling thread tid by gettid() */
int rte_sys_gettid(void)
{
	long lwpid;
	thr_self(&lwpid);
	return (int)lwpid;
}

int rte_thread_setname(pthread_t id, const char *name)
{
	/* this BSD function returns no error */
	pthread_set_name_np(id, name);
	return 0;
}

int rte_thread_getname(pthread_t id, char *name, size_t len)
{
	RTE_SET_USED(id);
	RTE_SET_USED(name);
	RTE_SET_USED(len);

	return -ENOTSUP;
}
