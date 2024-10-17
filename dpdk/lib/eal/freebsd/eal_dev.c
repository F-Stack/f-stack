/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include <rte_log.h>
#include <rte_dev.h>

int
rte_dev_event_monitor_start(void)
{
	RTE_LOG(ERR, EAL, "Device event is not supported for FreeBSD\n");
	return -1;
}

int
rte_dev_event_monitor_stop(void)
{
	RTE_LOG(ERR, EAL, "Device event is not supported for FreeBSD\n");
	return -1;
}

int
rte_dev_hotplug_handle_enable(void)
{
	RTE_LOG(ERR, EAL, "Device event is not supported for FreeBSD\n");
	return -1;
}

int
rte_dev_hotplug_handle_disable(void)
{
	RTE_LOG(ERR, EAL, "Device event is not supported for FreeBSD\n");
	return -1;
}
