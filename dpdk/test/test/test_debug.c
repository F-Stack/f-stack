/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>

#include <rte_debug.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_service_component.h>

#include "test.h"

/*
 * Debug test
 * ==========
 */

/* use fork() to test rte_panic() */
static int
test_panic(void)
{
	int pid;
	int status;

	pid = fork();

	if (pid == 0)
		rte_panic("Test Debug\n");
	else if (pid < 0){
		printf("Fork Failed\n");
		return -1;
	}
	wait(&status);
	if(status == 0){
		printf("Child process terminated normally!\n");
		return -1;
	} else
		printf("Child process terminated as expected - Test passed!\n");

	return 0;
}

/* use fork() to test rte_exit() */
static int
test_exit_val(int exit_val)
{
	int pid;
	int status;

	/* manually cleanup EAL memory, as the fork() below would otherwise
	 * cause the same hugepages to be free()-ed multiple times.
	 */
	rte_service_finalize();

	pid = fork();

	if (pid == 0)
		rte_exit(exit_val, __func__);
	else if (pid < 0){
		printf("Fork Failed\n");
		return -1;
	}
	wait(&status);
	printf("Child process status: %d\n", status);
#ifndef RTE_EAL_ALWAYS_PANIC_ON_ERROR
	if(!WIFEXITED(status) || WEXITSTATUS(status) != (uint8_t)exit_val){
		printf("Child process terminated with incorrect status (expected = %d)!\n",
				exit_val);
		return -1;
	}
#endif
	return 0;
}

static int
test_exit(void)
{
	int test_vals[] = { 0, 1, 2, 255, -1 };
	unsigned i;
	for (i = 0; i < sizeof(test_vals) / sizeof(test_vals[0]); i++){
		if (test_exit_val(test_vals[i]) < 0)
			return -1;
	}
	printf("%s Passed\n", __func__);
	return 0;
}

static void
dummy_app_usage(const char *progname)
{
	RTE_SET_USED(progname);
}

static int
test_usage(void)
{
	if (rte_set_application_usage_hook(dummy_app_usage) != NULL) {
		printf("Non-NULL value returned for initial usage hook\n");
		return -1;
	}
	if (rte_set_application_usage_hook(NULL) != dummy_app_usage) {
		printf("Incorrect value returned for application usage hook\n");
		return -1;
	}
	return 0;
}

static int
test_debug(void)
{
	rte_dump_stack();
	rte_dump_registers();
	if (test_panic() < 0)
		return -1;
	if (test_exit() < 0)
		return -1;
	if (test_usage() < 0)
		return -1;
	return 0;
}

REGISTER_TEST_COMMAND(debug_autotest, test_debug);
