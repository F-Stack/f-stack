/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <limits.h>

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_errno.h>
#include <rte_fbarray.h>

#include "test.h"

struct fbarray_testsuite_params {
	struct rte_fbarray arr;
	int start;
	int end;
};

static struct fbarray_testsuite_params param;

#define FBARRAY_TEST_ARR_NAME "fbarray_autotest"
#define FBARRAY_TEST_LEN 256
#define FBARRAY_TEST_ELT_SZ (sizeof(int))

static int autotest_setup(void)
{
	return rte_fbarray_init(&param.arr, FBARRAY_TEST_ARR_NAME,
			FBARRAY_TEST_LEN, FBARRAY_TEST_ELT_SZ);
}

static void autotest_teardown(void)
{
	rte_fbarray_destroy(&param.arr);
}

static int init_array(void)
{
	int i;
	for (i = param.start; i <= param.end; i++) {
		if (rte_fbarray_set_used(&param.arr, i))
			return -1;
	}
	return 0;
}

static void reset_array(void)
{
	int i;
	for (i = 0; i < FBARRAY_TEST_LEN; i++)
		rte_fbarray_set_free(&param.arr, i);
}

static int first_msk_test_setup(void)
{
	/* put all within first mask */
	param.start = 3;
	param.end = 10;
	return init_array();
}

static int cross_msk_test_setup(void)
{
	/* put all within second and third mask */
	param.start = 70;
	param.end = 160;
	return init_array();
}

static int multi_msk_test_setup(void)
{
	/* put all within first and last mask */
	param.start = 3;
	param.end = FBARRAY_TEST_LEN - 20;
	return init_array();
}

static int last_msk_test_setup(void)
{
	/* put all within last mask */
	param.start = FBARRAY_TEST_LEN - 20;
	param.end = FBARRAY_TEST_LEN - 1;
	return init_array();
}

static int full_msk_test_setup(void)
{
	/* fill entire mask */
	param.start = 0;
	param.end = FBARRAY_TEST_LEN - 1;
	return init_array();
}

static int empty_msk_test_setup(void)
{
	/* do not fill anything in */
	reset_array();
	return 0;
}

static int test_invalid(void)
{
	struct rte_fbarray dummy;

	/* invalid parameters */
	TEST_ASSERT_FAIL(rte_fbarray_attach(NULL),
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT_FAIL(rte_fbarray_detach(NULL),
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT_FAIL(rte_fbarray_destroy(NULL),
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno valuey\n");
	TEST_ASSERT_FAIL(rte_fbarray_init(NULL, "fail", 16, 16),
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT_FAIL(rte_fbarray_init(&dummy, NULL, 16, 16),
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT_FAIL(rte_fbarray_init(&dummy, "fail", 0, 16),
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT_FAIL(rte_fbarray_init(&dummy, "fail", 16, 0),
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	/* len must not be greater than INT_MAX */
	TEST_ASSERT_FAIL(rte_fbarray_init(&dummy, "fail", INT_MAX + 1U, 16),
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT_NULL(rte_fbarray_get(NULL, 0),
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_idx(NULL, 0) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_set_free(NULL, 0),
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_set_used(NULL, 0),
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_contig_free(NULL, 0) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_contig_used(NULL, 0) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_rev_contig_free(NULL, 0) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_rev_contig_used(NULL, 0) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_next_free(NULL, 0) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_next_used(NULL, 0) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_prev_free(NULL, 0) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_prev_used(NULL, 0) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_next_n_free(NULL, 0, 0) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_next_n_used(NULL, 0, 0) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_prev_n_free(NULL, 0, 0) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_prev_n_used(NULL, 0, 0) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_is_used(NULL, 0) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT_SUCCESS(rte_fbarray_init(&dummy, "success",
			FBARRAY_TEST_LEN, 8),
			"Failed to initialize valid fbarray\n");

	/* test API for handling invalid parameters with a valid fbarray */
	TEST_ASSERT_NULL(rte_fbarray_get(&dummy, FBARRAY_TEST_LEN),
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT(rte_fbarray_find_idx(&dummy, NULL) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT(rte_fbarray_set_free(&dummy, FBARRAY_TEST_LEN),
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT(rte_fbarray_set_used(&dummy, FBARRAY_TEST_LEN),
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT(rte_fbarray_find_contig_free(&dummy, FBARRAY_TEST_LEN) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT(rte_fbarray_find_contig_used(&dummy, FBARRAY_TEST_LEN) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT(rte_fbarray_find_rev_contig_free(&dummy,
			FBARRAY_TEST_LEN) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT(rte_fbarray_find_rev_contig_used(&dummy,
			FBARRAY_TEST_LEN) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT(rte_fbarray_find_next_free(&dummy, FBARRAY_TEST_LEN) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT(rte_fbarray_find_next_used(&dummy, FBARRAY_TEST_LEN) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT(rte_fbarray_find_prev_free(&dummy, FBARRAY_TEST_LEN) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT(rte_fbarray_find_prev_used(&dummy, FBARRAY_TEST_LEN) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT(rte_fbarray_find_next_n_free(&dummy,
			FBARRAY_TEST_LEN, 1) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_next_n_free(&dummy, 0,
			FBARRAY_TEST_LEN + 1) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_next_n_free(&dummy, 0, 0) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT(rte_fbarray_find_next_n_used(&dummy,
			FBARRAY_TEST_LEN, 1) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_next_n_used(&dummy, 0,
			FBARRAY_TEST_LEN + 1) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_next_n_used(&dummy, 0, 0) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT(rte_fbarray_find_prev_n_free(&dummy,
			FBARRAY_TEST_LEN, 1) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_prev_n_free(&dummy, 0,
			FBARRAY_TEST_LEN + 1) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_prev_n_free(&dummy, 0, 0) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT(rte_fbarray_find_prev_n_used(&dummy,
			FBARRAY_TEST_LEN, 1) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_prev_n_used(&dummy, 0,
			FBARRAY_TEST_LEN + 1) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_prev_n_used(&dummy, 0, 0) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT(rte_fbarray_is_used(&dummy, FBARRAY_TEST_LEN) < 0,
			"Call succeeded with invalid parameters\n");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL, "Wrong errno value\n");

	TEST_ASSERT_SUCCESS(rte_fbarray_destroy(&dummy),
			"Failed to destroy valid fbarray\n");

	return TEST_SUCCESS;
}

static int check_free(void)
{
	const int idx = 0;
	const int last_idx = FBARRAY_TEST_LEN - 1;

	/* ensure we can find a free spot */
	TEST_ASSERT_EQUAL(rte_fbarray_find_next_free(&param.arr, idx), idx,
			"Free space not found where expected\n");
	TEST_ASSERT_EQUAL(rte_fbarray_find_next_n_free(&param.arr, idx, 1), idx,
			"Free space not found where expected\n");
	TEST_ASSERT_EQUAL(rte_fbarray_find_contig_free(&param.arr, idx),
			FBARRAY_TEST_LEN,
			"Free space not found where expected\n");

	TEST_ASSERT_EQUAL(rte_fbarray_find_prev_free(&param.arr, idx), idx,
			"Free space not found where expected\n");
	TEST_ASSERT_EQUAL(rte_fbarray_find_prev_n_free(&param.arr, idx, 1), idx,
			"Free space not found where expected\n");
	TEST_ASSERT_EQUAL(rte_fbarray_find_rev_contig_free(&param.arr, idx), 1,
			"Free space not found where expected\n");

	TEST_ASSERT_EQUAL(rte_fbarray_find_prev_free(&param.arr, last_idx),
			last_idx, "Free space not found where expected\n");
	TEST_ASSERT_EQUAL(rte_fbarray_find_prev_n_free(&param.arr, last_idx, 1),
			last_idx, "Free space not found where expected\n");
	TEST_ASSERT_EQUAL(rte_fbarray_find_rev_contig_free(&param.arr,
			last_idx), FBARRAY_TEST_LEN,
			"Free space not found where expected\n");

	/* ensure we can't find any used spots */
	TEST_ASSERT(rte_fbarray_find_next_used(&param.arr, idx) < 0,
			"Used space found where none was expected\n");
	TEST_ASSERT_EQUAL(rte_errno, ENOENT, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_next_n_used(&param.arr, idx, 1) < 0,
			"Used space found where none was expected\n");
	TEST_ASSERT_EQUAL(rte_errno, ENOENT, "Wrong errno value\n");
	TEST_ASSERT_EQUAL(rte_fbarray_find_contig_used(&param.arr, idx), 0,
			"Used space found where none was expected\n");

	TEST_ASSERT(rte_fbarray_find_prev_used(&param.arr, last_idx) < 0,
			"Used space found where none was expected\n");
	TEST_ASSERT_EQUAL(rte_errno, ENOENT, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_prev_n_used(&param.arr, last_idx, 1) < 0,
			"Used space found where none was expected\n");
	TEST_ASSERT_EQUAL(rte_errno, ENOENT, "Wrong errno value\n");
	TEST_ASSERT_EQUAL(rte_fbarray_find_rev_contig_used(&param.arr,
			last_idx), 0,
			"Used space found where none was expected\n");

	return 0;
}

static int check_used_one(void)
{
	const int idx = 0;
	const int last_idx = FBARRAY_TEST_LEN - 1;

	/* check that we can find used spots now */
	TEST_ASSERT_EQUAL(rte_fbarray_find_next_used(&param.arr, idx), idx,
			"Used space not found where expected\n");
	TEST_ASSERT_EQUAL(rte_fbarray_find_next_n_used(&param.arr, idx, 1), idx,
			"Used space not found where expected\n");
	TEST_ASSERT_EQUAL(rte_fbarray_find_contig_used(&param.arr, idx), 1,
			"Used space not found where expected\n");

	TEST_ASSERT_EQUAL(rte_fbarray_find_prev_used(&param.arr, last_idx), idx,
			"Used space not found where expected\n");
	TEST_ASSERT_EQUAL(rte_fbarray_find_prev_n_used(&param.arr, last_idx, 1),
			idx, "Used space not found where expected\n");
	TEST_ASSERT_EQUAL(rte_fbarray_find_rev_contig_used(&param.arr, idx), 1,
			"Used space not found where expected\n");
	TEST_ASSERT_EQUAL(rte_fbarray_find_rev_contig_used(&param.arr,
			last_idx), idx,
			"Used space not found where expected\n");

	/* check if further indices are still free */
	TEST_ASSERT(rte_fbarray_find_next_used(&param.arr, idx + 1) < 0,
			"Used space not found where none was expected\n");
	TEST_ASSERT_EQUAL(rte_errno, ENOENT, "Wrong errno value\n");
	TEST_ASSERT(rte_fbarray_find_next_n_used(&param.arr, idx + 1, 1) < 0,
			"Used space not found where none was expected\n");
	TEST_ASSERT_EQUAL(rte_errno, ENOENT, "Wrong errno value\n");
	TEST_ASSERT_EQUAL(rte_fbarray_find_contig_used(&param.arr, idx + 1), 0,
			"Used space not found where none was expected\n");
	TEST_ASSERT_EQUAL(rte_fbarray_find_contig_free(&param.arr, idx + 1),
			FBARRAY_TEST_LEN - 1,
			"Used space not found where none was expected\n");

	TEST_ASSERT_EQUAL(rte_fbarray_find_prev_used(&param.arr, last_idx), 0,
			"Used space not found where none was expected\n");
	TEST_ASSERT_EQUAL(rte_fbarray_find_prev_n_used(&param.arr, last_idx, 1),
			0, "Used space not found where none was expected\n");
	TEST_ASSERT_EQUAL(rte_fbarray_find_rev_contig_used(&param.arr,
			last_idx), 0,
			"Used space not found where none was expected\n");
	TEST_ASSERT_EQUAL(rte_fbarray_find_rev_contig_free(&param.arr,
			last_idx), FBARRAY_TEST_LEN - 1,
			"Used space not found where none was expected\n");

	return 0;
}

static int test_basic(void)
{
	const int idx = 0;
	int i;

	/* check array count */
	TEST_ASSERT_EQUAL(param.arr.count, 0, "Wrong element count\n");

	/* ensure we can find a free spot */
	if (check_free())
		return TEST_FAILED;

	/* check if used */
	TEST_ASSERT_EQUAL(rte_fbarray_is_used(&param.arr, idx), 0,
			"Used space found where not expected\n");

	/* mark as used */
	TEST_ASSERT_SUCCESS(rte_fbarray_set_used(&param.arr, idx),
			"Failed to set as used\n");

	/* check if used again */
	TEST_ASSERT_NOT_EQUAL(rte_fbarray_is_used(&param.arr, idx), 0,
			"Used space not found where expected\n");

	if (check_used_one())
		return TEST_FAILED;

	/* check array count */
	TEST_ASSERT_EQUAL(param.arr.count, 1, "Wrong element count\n");

	/* check if getting pointers works for every element */
	for (i = 0; i < FBARRAY_TEST_LEN; i++) {
		void *td = rte_fbarray_get(&param.arr, i);
		TEST_ASSERT_NOT_NULL(td, "Invalid pointer returned\n");
		TEST_ASSERT_EQUAL(rte_fbarray_find_idx(&param.arr, td), i,
				"Wrong index returned\n");
	}

	/* mark as free */
	TEST_ASSERT_SUCCESS(rte_fbarray_set_free(&param.arr, idx),
			"Failed to set as free\n");

	/* check array count */
	TEST_ASSERT_EQUAL(param.arr.count, 0, "Wrong element count\n");

	/* check if used */
	TEST_ASSERT_EQUAL(rte_fbarray_is_used(&param.arr, idx), 0,
			"Used space found where not expected\n");

	if (check_free())
		return TEST_FAILED;

	reset_array();

	return TEST_SUCCESS;
}

static int ensure_correct(struct rte_fbarray *arr, int first, int last,
		bool used)
{
	int i, len = last - first + 1;
	for (i = 0; i < len; i++) {
		int cur = first + i;
		int cur_len = len - i;

		if (used) {
			TEST_ASSERT_EQUAL(rte_fbarray_find_contig_used(arr,
					cur), cur_len,
					"Used space length is wrong\n");
			TEST_ASSERT_EQUAL(rte_fbarray_find_rev_contig_used(arr,
					last), len,
					"Used space length is wrong\n");
			TEST_ASSERT_EQUAL(rte_fbarray_find_rev_contig_used(arr,
					cur), i + 1,
					"Used space length is wrong\n");

			TEST_ASSERT_EQUAL(rte_fbarray_find_next_used(arr, cur),
					cur,
					"Used space not found where expected\n");
			TEST_ASSERT_EQUAL(rte_fbarray_find_next_n_used(arr,
					cur, 1), cur,
					"Used space not found where expected\n");
			TEST_ASSERT_EQUAL(rte_fbarray_find_next_n_used(arr, cur,
					cur_len), cur,
					"Used space not found where expected\n");

			TEST_ASSERT_EQUAL(rte_fbarray_find_prev_used(arr, cur),
					cur,
					"Used space not found where expected\n");
			TEST_ASSERT_EQUAL(rte_fbarray_find_prev_n_used(arr,
					last, cur_len), cur,
					"Used space not found where expected\n");
		} else {
			TEST_ASSERT_EQUAL(rte_fbarray_find_contig_free(arr,
					cur), cur_len,
					"Free space length is wrong\n");
			TEST_ASSERT_EQUAL(rte_fbarray_find_rev_contig_free(arr,
					last), len,
					"Free space length is wrong\n");
			TEST_ASSERT_EQUAL(rte_fbarray_find_rev_contig_free(arr,
					cur), i + 1,
					"Free space length is wrong\n");

			TEST_ASSERT_EQUAL(rte_fbarray_find_next_free(arr, cur),
					cur,
					"Free space not found where expected\n");
			TEST_ASSERT_EQUAL(rte_fbarray_find_next_n_free(arr, cur,
					1), cur,
					"Free space not found where expected\n");
			TEST_ASSERT_EQUAL(rte_fbarray_find_next_n_free(arr, cur,
					cur_len), cur,
					"Free space not found where expected\n");

			TEST_ASSERT_EQUAL(rte_fbarray_find_prev_free(arr, cur),
					cur,
					"Free space not found where expected\n");
			TEST_ASSERT_EQUAL(rte_fbarray_find_prev_n_free(arr,
					last, cur_len), cur,
					"Free space not found where expected\n");
		}
	}
	return 0;
}

static int test_find(void)
{
	TEST_ASSERT_EQUAL((int)param.arr.count, param.end - param.start + 1,
			"Wrong element count\n");
	/* ensure space is free before start */
	if (ensure_correct(&param.arr, 0, param.start - 1, false))
		return TEST_FAILED;
	/* ensure space is occupied where it's supposed to be */
	if (ensure_correct(&param.arr, param.start, param.end, true))
		return TEST_FAILED;
	/* ensure space after end is free as well */
	if (ensure_correct(&param.arr, param.end + 1, FBARRAY_TEST_LEN - 1,
			false))
		return TEST_FAILED;
	return TEST_SUCCESS;
}

static int test_empty(void)
{
	TEST_ASSERT_EQUAL((int)param.arr.count, 0, "Wrong element count\n");
	/* ensure space is free */
	if (ensure_correct(&param.arr, 0, FBARRAY_TEST_LEN - 1, false))
		return TEST_FAILED;
	return TEST_SUCCESS;
}


static struct unit_test_suite fbarray_test_suite = {
	.suite_name = "fbarray autotest",
	.setup = autotest_setup,
	.teardown = autotest_teardown,
	.unit_test_cases = {
		TEST_CASE(test_invalid),
		TEST_CASE(test_basic),
		TEST_CASE_ST(first_msk_test_setup, reset_array, test_find),
		TEST_CASE_ST(cross_msk_test_setup, reset_array, test_find),
		TEST_CASE_ST(multi_msk_test_setup, reset_array, test_find),
		TEST_CASE_ST(last_msk_test_setup, reset_array, test_find),
		TEST_CASE_ST(full_msk_test_setup, reset_array, test_find),
		TEST_CASE_ST(empty_msk_test_setup, reset_array, test_empty),
		TEST_CASES_END()
	}
};

static int
test_fbarray(void)
{
	return unit_test_suite_runner(&fbarray_test_suite);
}

REGISTER_TEST_COMMAND(fbarray_autotest, test_fbarray);
