/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include "oob_monitor.h"

void branch_monitor_exit(void)
{
}

__attribute__((unused)) static float
apply_policy(__attribute__((unused)) int core)
{
	return 0.0;
}

int
add_core_to_monitor(__attribute__((unused)) int core)
{
	return 0;
}

int
remove_core_from_monitor(__attribute__((unused)) int core)
{
	return 0;
}

int
branch_monitor_init(void)
{
	return 0;
}

void
run_branch_monitor(void)
{
}
