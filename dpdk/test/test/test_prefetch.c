/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>

#include <rte_prefetch.h>

#include "test.h"

/*
 * Prefetch test
 * =============
 *
 * - Just test that the macro can be called and validate the compilation.
 *   The test always return success.
 */

static int
test_prefetch(void)
{
	int a;

	rte_prefetch0(&a);
	rte_prefetch1(&a);
	rte_prefetch2(&a);

	return 0;
}

REGISTER_TEST_COMMAND(prefetch_autotest, test_prefetch);
