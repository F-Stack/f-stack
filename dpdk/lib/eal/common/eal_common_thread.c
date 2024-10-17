/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <assert.h>
#include <string.h>

#include <rte_eal_trace.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_trace_point.h>

#include "eal_internal_cfg.h"
#include "eal_private.h"
#include "eal_thread.h"
#include "eal_trace.h"

RTE_DEFINE_PER_LCORE(unsigned int, _lcore_id) = LCORE_ID_ANY;
RTE_DEFINE_PER_LCORE(int, _thread_id) = -1;
static RTE_DEFINE_PER_LCORE(unsigned int, _socket_id) =
	(unsigned int)SOCKET_ID_ANY;
static RTE_DEFINE_PER_LCORE(rte_cpuset_t, _cpuset);

unsigned rte_socket_id(void)
{
	return RTE_PER_LCORE(_socket_id);
}

static int
eal_cpuset_socket_id(rte_cpuset_t *cpusetp)
{
	unsigned cpu = 0;
	int socket_id = SOCKET_ID_ANY;
	int sid;

	if (cpusetp == NULL)
		return SOCKET_ID_ANY;

	do {
		if (!CPU_ISSET(cpu, cpusetp))
			continue;

		if (socket_id == SOCKET_ID_ANY)
			socket_id = eal_cpu_socket_id(cpu);

		sid = eal_cpu_socket_id(cpu);
		if (socket_id != sid) {
			socket_id = SOCKET_ID_ANY;
			break;
		}

	} while (++cpu < CPU_SETSIZE);

	return socket_id;
}

static void
thread_update_affinity(rte_cpuset_t *cpusetp)
{
	unsigned int lcore_id = rte_lcore_id();

	/* store socket_id in TLS for quick access */
	RTE_PER_LCORE(_socket_id) =
		eal_cpuset_socket_id(cpusetp);

	/* store cpuset in TLS for quick access */
	memmove(&RTE_PER_LCORE(_cpuset), cpusetp,
		sizeof(rte_cpuset_t));

	if (lcore_id != (unsigned)LCORE_ID_ANY) {
		/* EAL thread will update lcore_config */
		lcore_config[lcore_id].socket_id = RTE_PER_LCORE(_socket_id);
		memmove(&lcore_config[lcore_id].cpuset, cpusetp,
			sizeof(rte_cpuset_t));
	}
}

int
rte_thread_set_affinity(rte_cpuset_t *cpusetp)
{
	if (pthread_setaffinity_np(pthread_self(), sizeof(rte_cpuset_t),
			cpusetp) != 0) {
		RTE_LOG(ERR, EAL, "pthread_setaffinity_np failed\n");
		return -1;
	}

	thread_update_affinity(cpusetp);
	return 0;
}

void
rte_thread_get_affinity(rte_cpuset_t *cpusetp)
{
	assert(cpusetp);
	memmove(cpusetp, &RTE_PER_LCORE(_cpuset),
		sizeof(rte_cpuset_t));
}

int
eal_thread_dump_affinity(rte_cpuset_t *cpuset, char *str, unsigned int size)
{
	unsigned cpu;
	int ret;
	unsigned int out = 0;

	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (!CPU_ISSET(cpu, cpuset))
			continue;

		ret = snprintf(str + out,
			       size - out, "%u,", cpu);
		if (ret < 0 || (unsigned)ret >= size - out) {
			/* string will be truncated */
			ret = -1;
			goto exit;
		}

		out += ret;
	}

	ret = 0;
exit:
	/* remove the last separator */
	if (out > 0)
		str[out - 1] = '\0';

	return ret;
}

int
eal_thread_dump_current_affinity(char *str, unsigned int size)
{
	rte_cpuset_t cpuset;

	rte_thread_get_affinity(&cpuset);
	return eal_thread_dump_affinity(&cpuset, str, size);
}

void
__rte_thread_init(unsigned int lcore_id, rte_cpuset_t *cpuset)
{
	/* set the lcore ID in per-lcore memory area */
	RTE_PER_LCORE(_lcore_id) = lcore_id;

	/* acquire system unique id */
	rte_gettid();

	thread_update_affinity(cpuset);

	__rte_trace_mem_per_thread_alloc();
}

void
__rte_thread_uninit(void)
{
	trace_mem_per_thread_free();

	RTE_PER_LCORE(_lcore_id) = LCORE_ID_ANY;
}

/* main loop of threads */
__rte_noreturn void *
eal_thread_loop(void *arg)
{
	unsigned int lcore_id = (uintptr_t)arg;
	char cpuset[RTE_CPU_AFFINITY_STR_LEN];
	int ret;

	__rte_thread_init(lcore_id, &lcore_config[lcore_id].cpuset);

	ret = eal_thread_dump_current_affinity(cpuset, sizeof(cpuset));
	RTE_LOG(DEBUG, EAL, "lcore %u is ready (tid=%zx;cpuset=[%s%s])\n",
		lcore_id, (uintptr_t)pthread_self(), cpuset,
		ret == 0 ? "" : "...");

	rte_eal_trace_thread_lcore_ready(lcore_id, cpuset);

	/* read on our pipe to get commands */
	while (1) {
		lcore_function_t *f;
		void *fct_arg;

		eal_thread_wait_command();

		/* Set the state to 'RUNNING'. Use release order
		 * since 'state' variable is used as the guard variable.
		 */
		__atomic_store_n(&lcore_config[lcore_id].state, RUNNING,
			__ATOMIC_RELEASE);

		eal_thread_ack_command();

		/* Load 'f' with acquire order to ensure that
		 * the memory operations from the main thread
		 * are accessed only after update to 'f' is visible.
		 * Wait till the update to 'f' is visible to the worker.
		 */
		while ((f = __atomic_load_n(&lcore_config[lcore_id].f,
				__ATOMIC_ACQUIRE)) == NULL)
			rte_pause();

		/* call the function and store the return value */
		fct_arg = lcore_config[lcore_id].arg;
		ret = f(fct_arg);
		lcore_config[lcore_id].ret = ret;
		lcore_config[lcore_id].f = NULL;
		lcore_config[lcore_id].arg = NULL;

		/* Store the state with release order to ensure that
		 * the memory operations from the worker thread
		 * are completed before the state is updated.
		 * Use 'state' as the guard variable.
		 */
		__atomic_store_n(&lcore_config[lcore_id].state, WAIT,
			__ATOMIC_RELEASE);
	}

	/* never reached */
	/* pthread_exit(NULL); */
	/* return NULL; */
}

enum __rte_ctrl_thread_status {
	CTRL_THREAD_LAUNCHING, /* Yet to call pthread_create function */
	CTRL_THREAD_RUNNING, /* Control thread is running successfully */
	CTRL_THREAD_ERROR /* Control thread encountered an error */
};

struct rte_thread_ctrl_params {
	void *(*start_routine)(void *);
	void *arg;
	int ret;
	/* Control thread status.
	 * If the status is CTRL_THREAD_ERROR, 'ret' has the error code.
	 */
	enum __rte_ctrl_thread_status ctrl_thread_status;
};

static void *ctrl_thread_init(void *arg)
{
	struct internal_config *internal_conf =
		eal_get_internal_configuration();
	rte_cpuset_t *cpuset = &internal_conf->ctrl_cpuset;
	struct rte_thread_ctrl_params *params = arg;
	void *(*start_routine)(void *) = params->start_routine;
	void *routine_arg = params->arg;

	__rte_thread_init(rte_lcore_id(), cpuset);
	params->ret = pthread_setaffinity_np(pthread_self(), sizeof(*cpuset),
		cpuset);
	if (params->ret != 0) {
		__atomic_store_n(&params->ctrl_thread_status,
			CTRL_THREAD_ERROR, __ATOMIC_RELEASE);
		return NULL;
	}

	__atomic_store_n(&params->ctrl_thread_status,
		CTRL_THREAD_RUNNING, __ATOMIC_RELEASE);

	return start_routine(routine_arg);
}

int
rte_ctrl_thread_create(pthread_t *thread, const char *name,
		const pthread_attr_t *attr,
		void *(*start_routine)(void *), void *arg)
{
	struct rte_thread_ctrl_params *params;
	enum __rte_ctrl_thread_status ctrl_thread_status;
	int ret;

	params = malloc(sizeof(*params));
	if (!params)
		return -ENOMEM;

	params->start_routine = start_routine;
	params->arg = arg;
	params->ret = 0;
	params->ctrl_thread_status = CTRL_THREAD_LAUNCHING;

	ret = pthread_create(thread, attr, ctrl_thread_init, (void *)params);
	if (ret != 0) {
		free(params);
		return -ret;
	}

	if (name != NULL) {
		ret = rte_thread_setname(*thread, name);
		if (ret < 0)
			RTE_LOG(DEBUG, EAL,
				"Cannot set name for ctrl thread\n");
	}

	/* Wait for the control thread to initialize successfully */
	while ((ctrl_thread_status =
			__atomic_load_n(&params->ctrl_thread_status,
			__ATOMIC_ACQUIRE)) == CTRL_THREAD_LAUNCHING) {
		/* Yield the CPU. Using sched_yield call requires maintaining
		 * another implementation for Windows as sched_yield is not
		 * supported on Windows.
		 */
		rte_delay_us_sleep(1);
	}

	/* Check if the control thread encountered an error */
	if (ctrl_thread_status == CTRL_THREAD_ERROR) {
		/* ctrl thread is exiting */
		pthread_join(*thread, NULL);
	}

	ret = params->ret;
	free(params);

	return -ret;
}

int
rte_thread_register(void)
{
	unsigned int lcore_id;
	rte_cpuset_t cpuset;

	/* EAL init flushes all lcores, we can't register before. */
	if (eal_get_internal_configuration()->init_complete != 1) {
		RTE_LOG(DEBUG, EAL, "Called %s before EAL init.\n", __func__);
		rte_errno = EINVAL;
		return -1;
	}
	if (!rte_mp_disable()) {
		RTE_LOG(ERR, EAL, "Multiprocess in use, registering non-EAL threads is not supported.\n");
		rte_errno = EINVAL;
		return -1;
	}
	if (pthread_getaffinity_np(pthread_self(), sizeof(cpuset),
			&cpuset) != 0)
		CPU_ZERO(&cpuset);
	lcore_id = eal_lcore_non_eal_allocate();
	if (lcore_id >= RTE_MAX_LCORE)
		lcore_id = LCORE_ID_ANY;
	__rte_thread_init(lcore_id, &cpuset);
	if (lcore_id == LCORE_ID_ANY) {
		rte_errno = ENOMEM;
		return -1;
	}
	RTE_LOG(DEBUG, EAL, "Registered non-EAL thread as lcore %u.\n",
		lcore_id);
	return 0;
}

void
rte_thread_unregister(void)
{
	unsigned int lcore_id = rte_lcore_id();

	if (lcore_id != LCORE_ID_ANY)
		eal_lcore_non_eal_release(lcore_id);
	__rte_thread_uninit();
	if (lcore_id != LCORE_ID_ANY)
		RTE_LOG(DEBUG, EAL, "Unregistered non-EAL thread (was lcore %u).\n",
			lcore_id);
}

int
rte_thread_attr_init(rte_thread_attr_t *attr)
{
	if (attr == NULL)
		return EINVAL;

	CPU_ZERO(&attr->cpuset);
	attr->priority = RTE_THREAD_PRIORITY_NORMAL;

	return 0;
}

int
rte_thread_attr_set_priority(rte_thread_attr_t *thread_attr,
		enum rte_thread_priority priority)
{
	if (thread_attr == NULL)
		return EINVAL;

	thread_attr->priority = priority;

	return 0;
}

int
rte_thread_attr_set_affinity(rte_thread_attr_t *thread_attr,
		rte_cpuset_t *cpuset)
{
	if (thread_attr == NULL)
		return EINVAL;

	if (cpuset == NULL)
		return EINVAL;

	thread_attr->cpuset = *cpuset;

	return 0;
}

int
rte_thread_attr_get_affinity(rte_thread_attr_t *thread_attr,
		rte_cpuset_t *cpuset)
{
	if (thread_attr == NULL)
		return EINVAL;

	if (cpuset == NULL)
		return EINVAL;

	*cpuset = thread_attr->cpuset;

	return 0;
}
