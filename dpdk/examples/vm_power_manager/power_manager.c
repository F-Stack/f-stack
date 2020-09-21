/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

#include <sys/sysinfo.h>
#include <sys/types.h>

#include <rte_log.h>
#include <rte_power.h>
#include <rte_spinlock.h>

#include "channel_manager.h"
#include "power_manager.h"
#include "oob_monitor.h"

#define POWER_SCALE_CORE(DIRECTION, core_num , ret) do { \
	if (core_num >= ci.core_count) \
		return -1; \
	if (!(ci.cd[core_num].global_enabled_cpus)) \
		return -1; \
	rte_spinlock_lock(&global_core_freq_info[core_num].power_sl); \
	ret = rte_power_freq_##DIRECTION(core_num); \
	rte_spinlock_unlock(&global_core_freq_info[core_num].power_sl); \
} while (0)

#define POWER_SCALE_MASK(DIRECTION, core_mask, ret) do { \
	int i; \
	for (i = 0; core_mask; core_mask &= ~(1 << i++)) { \
		if ((core_mask >> i) & 1) { \
			if (!(ci.cd[i].global_enabled_cpus)) \
				continue; \
			rte_spinlock_lock(&global_core_freq_info[i].power_sl); \
			if (rte_power_freq_##DIRECTION(i) != 1) \
				ret = -1; \
			rte_spinlock_unlock(&global_core_freq_info[i].power_sl); \
		} \
	} \
} while (0)

struct freq_info {
	rte_spinlock_t power_sl;
	uint32_t freqs[RTE_MAX_LCORE_FREQS];
	unsigned num_freqs;
} __rte_cache_aligned;

static struct freq_info global_core_freq_info[POWER_MGR_MAX_CPUS];

struct core_info ci;

#define SYSFS_CPU_PATH "/sys/devices/system/cpu/cpu%u/topology/core_id"

struct core_info *
get_core_info(void)
{
	return &ci;
}

int
core_info_init(void)
{
	struct core_info *ci;
	int i;

	ci = get_core_info();

	ci->core_count = get_nprocs_conf();
	ci->branch_ratio_threshold = BRANCH_RATIO_THRESHOLD;
	ci->cd = malloc(ci->core_count * sizeof(struct core_details));
	if (!ci->cd) {
		RTE_LOG(ERR, POWER_MANAGER, "Failed to allocate memory for core info.");
		return -1;
	}
	for (i = 0; i < ci->core_count; i++) {
		ci->cd[i].global_enabled_cpus = 1;
		ci->cd[i].oob_enabled = 0;
		ci->cd[i].msr_fd = 0;
	}
	printf("%d cores in system\n", ci->core_count);
	return 0;
}

int
power_manager_init(void)
{
	unsigned int i, num_cpus = 0, num_freqs = 0;
	int ret = 0;
	struct core_info *ci;
	unsigned int max_core_num;

	rte_power_set_env(PM_ENV_ACPI_CPUFREQ);

	ci = get_core_info();
	if (!ci) {
		RTE_LOG(ERR, POWER_MANAGER,
				"Failed to get core info!\n");
		return -1;
	}

	if (ci->core_count > POWER_MGR_MAX_CPUS)
		max_core_num = POWER_MGR_MAX_CPUS;
	else
		max_core_num = ci->core_count;

	for (i = 0; i < max_core_num; i++) {
		if (ci->cd[i].global_enabled_cpus) {
			if (rte_power_init(i) < 0)
				RTE_LOG(ERR, POWER_MANAGER,
						"Unable to initialize power manager "
						"for core %u\n", i);
			num_cpus++;
			num_freqs = rte_power_freqs(i,
					global_core_freq_info[i].freqs,
					RTE_MAX_LCORE_FREQS);
			if (num_freqs == 0) {
				RTE_LOG(ERR, POWER_MANAGER,
					"Unable to get frequency list for core %u\n",
					i);
				ci->cd[i].oob_enabled = 0;
				ret = -1;
			}
			global_core_freq_info[i].num_freqs = num_freqs;

			rte_spinlock_init(&global_core_freq_info[i].power_sl);
		}
		if (ci->cd[i].oob_enabled)
			add_core_to_monitor(i);
	}
	RTE_LOG(INFO, POWER_MANAGER, "Managing %u cores out of %u available host cores\n",
			num_cpus, ci->core_count);
	return ret;

}

uint32_t
power_manager_get_current_frequency(unsigned core_num)
{
	uint32_t freq, index;

	if (core_num >= POWER_MGR_MAX_CPUS) {
		RTE_LOG(ERR, POWER_MANAGER, "Core(%u) is out of range 0...%d\n",
				core_num, POWER_MGR_MAX_CPUS-1);
		return -1;
	}
	if (!(ci.cd[core_num].global_enabled_cpus))
		return 0;

	rte_spinlock_lock(&global_core_freq_info[core_num].power_sl);
	index = rte_power_get_freq(core_num);
	rte_spinlock_unlock(&global_core_freq_info[core_num].power_sl);
	if (index >= RTE_MAX_LCORE_FREQS)
		freq = 0;
	else
		freq = global_core_freq_info[core_num].freqs[index];

	return freq;
}

int
power_manager_exit(void)
{
	unsigned int i;
	int ret = 0;
	struct core_info *ci;
	unsigned int max_core_num;

	ci = get_core_info();
	if (!ci) {
		RTE_LOG(ERR, POWER_MANAGER,
				"Failed to get core info!\n");
		return -1;
	}

	if (ci->core_count > POWER_MGR_MAX_CPUS)
		max_core_num = POWER_MGR_MAX_CPUS;
	else
		max_core_num = ci->core_count;

	for (i = 0; i < max_core_num; i++) {
		if (ci->cd[i].global_enabled_cpus) {
			if (rte_power_exit(i) < 0) {
				RTE_LOG(ERR, POWER_MANAGER, "Unable to shutdown power manager "
						"for core %u\n", i);
				ret = -1;
			}
			ci->cd[i].global_enabled_cpus = 0;
		}
		remove_core_from_monitor(i);
	}
	return ret;
}

int
power_manager_scale_mask_up(uint64_t core_mask)
{
	int ret = 0;

	POWER_SCALE_MASK(up, core_mask, ret);
	return ret;
}

int
power_manager_scale_mask_down(uint64_t core_mask)
{
	int ret = 0;

	POWER_SCALE_MASK(down, core_mask, ret);
	return ret;
}

int
power_manager_scale_mask_min(uint64_t core_mask)
{
	int ret = 0;

	POWER_SCALE_MASK(min, core_mask, ret);
	return ret;
}

int
power_manager_scale_mask_max(uint64_t core_mask)
{
	int ret = 0;

	POWER_SCALE_MASK(max, core_mask, ret);
	return ret;
}

int
power_manager_enable_turbo_mask(uint64_t core_mask)
{
	int ret = 0;

	POWER_SCALE_MASK(enable_turbo, core_mask, ret);
	return ret;
}

int
power_manager_disable_turbo_mask(uint64_t core_mask)
{
	int ret = 0;

	POWER_SCALE_MASK(disable_turbo, core_mask, ret);
	return ret;
}

int
power_manager_scale_core_up(unsigned core_num)
{
	int ret = 0;

	POWER_SCALE_CORE(up, core_num, ret);
	return ret;
}

int
power_manager_scale_core_down(unsigned core_num)
{
	int ret = 0;

	POWER_SCALE_CORE(down, core_num, ret);
	return ret;
}

int
power_manager_scale_core_min(unsigned core_num)
{
	int ret = 0;

	POWER_SCALE_CORE(min, core_num, ret);
	return ret;
}

int
power_manager_scale_core_max(unsigned core_num)
{
	int ret = 0;

	POWER_SCALE_CORE(max, core_num, ret);
	return ret;
}

int
power_manager_enable_turbo_core(unsigned int core_num)
{
	int ret = 0;

	POWER_SCALE_CORE(enable_turbo, core_num, ret);
	return ret;
}

int
power_manager_disable_turbo_core(unsigned int core_num)
{
	int ret = 0;

	POWER_SCALE_CORE(disable_turbo, core_num, ret);
	return ret;
}

int
power_manager_scale_core_med(unsigned int core_num)
{
	int ret = 0;
	struct core_info *ci;

	ci = get_core_info();
	if (core_num >= POWER_MGR_MAX_CPUS)
		return -1;
	if (!(ci->cd[core_num].global_enabled_cpus))
		return -1;
	rte_spinlock_lock(&global_core_freq_info[core_num].power_sl);
	ret = rte_power_set_freq(core_num,
				global_core_freq_info[core_num].num_freqs / 2);
	rte_spinlock_unlock(&global_core_freq_info[core_num].power_sl);
	return ret;
}
