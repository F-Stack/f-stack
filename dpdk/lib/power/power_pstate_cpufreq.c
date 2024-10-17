/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <inttypes.h>

#include <rte_memcpy.h>

#include "rte_power_pmd_mgmt.h"
#include "power_pstate_cpufreq.h"
#include "power_common.h"

/* macros used for rounding frequency to nearest 100000 */
#define FREQ_ROUNDING_DELTA 50000
#define ROUND_FREQ_TO_N_100000 100000

#define BUS_FREQ     100000

#define POWER_GOVERNOR_PERF "performance"
#define POWER_SYSFILE_MAX_FREQ \
		"/sys/devices/system/cpu/cpu%u/cpufreq/scaling_max_freq"
#define POWER_SYSFILE_MIN_FREQ  \
		"/sys/devices/system/cpu/cpu%u/cpufreq/scaling_min_freq"
#define POWER_SYSFILE_CUR_FREQ  \
		"/sys/devices/system/cpu/cpu%u/cpufreq/scaling_cur_freq"
#define POWER_SYSFILE_BASE_MAX_FREQ \
		"/sys/devices/system/cpu/cpu%u/cpufreq/cpuinfo_max_freq"
#define POWER_SYSFILE_BASE_MIN_FREQ  \
		"/sys/devices/system/cpu/cpu%u/cpufreq/cpuinfo_min_freq"
#define POWER_SYSFILE_BASE_FREQ  \
		"/sys/devices/system/cpu/cpu%u/cpufreq/base_frequency"
#define POWER_SYSFILE_TURBO_PCT  \
		"/sys/devices/system/cpu/intel_pstate/turbo_pct"
#define POWER_PSTATE_DRIVER "intel_pstate"


enum power_state {
	POWER_IDLE = 0,
	POWER_ONGOING,
	POWER_USED,
	POWER_UNKNOWN
};

struct pstate_power_info {
	unsigned int lcore_id;               /**< Logical core id */
	uint32_t freqs[RTE_MAX_LCORE_FREQS]; /**< Frequency array */
	uint32_t nb_freqs;                   /**< number of available freqs */
	FILE *f_cur_min;                     /**< FD of scaling_min */
	FILE *f_cur_max;                     /**< FD of scaling_max */
	char governor_ori[32];               /**< Original governor name */
	uint32_t curr_idx;                   /**< Freq index in freqs array */
	uint32_t non_turbo_max_ratio;        /**< Non Turbo Max ratio  */
	uint32_t sys_max_freq;               /**< system wide max freq  */
	uint32_t core_base_freq;             /**< core base freq  */
	uint32_t state;                      /**< Power in use state */
	uint16_t turbo_available;            /**< Turbo Boost available */
	uint16_t turbo_enable;               /**< Turbo Boost enable/disable */
	uint16_t priority_core;              /**< High Performance core */
} __rte_cache_aligned;


static struct pstate_power_info lcore_power_info[RTE_MAX_LCORE];

/**
 * It is to read the turbo mode percentage from sysfs
 */
static int32_t
power_read_turbo_pct(uint64_t *outVal)
{
	int fd, ret;
	char val[4] = {0};
	char *endptr;

	fd = open(POWER_SYSFILE_TURBO_PCT, O_RDONLY);

	if (fd < 0) {
		RTE_LOG(ERR, POWER, "Error opening '%s': %s\n", POWER_SYSFILE_TURBO_PCT,
				 strerror(errno));
		return fd;
	}

	ret = read(fd, val, sizeof(val));

	if (ret < 0) {
		RTE_LOG(ERR, POWER, "Error reading '%s': %s\n", POWER_SYSFILE_TURBO_PCT,
				 strerror(errno));
		goto out;
	}

	errno = 0;
	*outVal = (uint64_t) strtol(val, &endptr, 10);
	if (errno != 0 || (*endptr != 0 && *endptr != '\n')) {
		RTE_LOG(ERR, POWER, "Error converting str to digits, read from %s: %s\n",
				 POWER_SYSFILE_TURBO_PCT, strerror(errno));
		ret = -1;
		goto out;
	}

	POWER_DEBUG_TRACE("power turbo pct: %"PRIu64"\n", *outVal);

out:	close(fd);
	return ret;
}

/**
 * It is to fopen the sys file for the future setting the lcore frequency.
 */
static int
power_init_for_setting_freq(struct pstate_power_info *pi)
{
	FILE *f_base = NULL, *f_base_min = NULL, *f_base_max = NULL,
	     *f_min = NULL, *f_max = NULL;
	uint32_t base_ratio, base_min_ratio, base_max_ratio;
	uint64_t max_non_turbo;
	int ret;

	/* open all files we expect to have open */
	open_core_sysfs_file(&f_base_max, "r", POWER_SYSFILE_BASE_MAX_FREQ,
			pi->lcore_id);
	if (f_base_max == NULL) {
		RTE_LOG(ERR, POWER, "failed to open %s\n",
				POWER_SYSFILE_BASE_MAX_FREQ);
		goto err;
	}

	open_core_sysfs_file(&f_base_min, "r", POWER_SYSFILE_BASE_MIN_FREQ,
			pi->lcore_id);
	if (f_base_min == NULL) {
		RTE_LOG(ERR, POWER, "failed to open %s\n",
				POWER_SYSFILE_BASE_MIN_FREQ);
		goto err;
	}

	open_core_sysfs_file(&f_min, "rw+", POWER_SYSFILE_MIN_FREQ,
			pi->lcore_id);
	if (f_min == NULL) {
		RTE_LOG(ERR, POWER, "failed to open %s\n",
				POWER_SYSFILE_MIN_FREQ);
		goto err;
	}

	open_core_sysfs_file(&f_max, "rw+", POWER_SYSFILE_MAX_FREQ,
			pi->lcore_id);
	if (f_max == NULL) {
		RTE_LOG(ERR, POWER, "failed to open %s\n",
				POWER_SYSFILE_MAX_FREQ);
		goto err;
	}

	open_core_sysfs_file(&f_base, "r", POWER_SYSFILE_BASE_FREQ,
			pi->lcore_id);
	/* base ratio file may not exist in some kernels, so no error check */

	/* read base max ratio */
	ret = read_core_sysfs_u32(f_base_max, &base_max_ratio);
	if (ret < 0) {
		RTE_LOG(ERR, POWER, "Failed to read %s\n",
				POWER_SYSFILE_BASE_MAX_FREQ);
		goto err;
	}

	/* read base min ratio */
	ret = read_core_sysfs_u32(f_base_min, &base_min_ratio);
	if (ret < 0) {
		RTE_LOG(ERR, POWER, "Failed to read %s\n",
				POWER_SYSFILE_BASE_MIN_FREQ);
		goto err;
	}

	/* base ratio may not exist */
	if (f_base != NULL) {
		ret = read_core_sysfs_u32(f_base, &base_ratio);
		if (ret < 0) {
			RTE_LOG(ERR, POWER, "Failed to read %s\n",
					POWER_SYSFILE_BASE_FREQ);
			goto err;
		}
	} else {
		base_ratio = 0;
	}

	/* convert ratios to bins */
	base_max_ratio /= BUS_FREQ;
	base_min_ratio /= BUS_FREQ;
	base_ratio /= BUS_FREQ;

	/* assign file handles */
	pi->f_cur_min = f_min;
	pi->f_cur_max = f_max;

	/* try to get turbo from global sysfs entry for less privileges than from MSR */
	if (power_read_turbo_pct(&max_non_turbo) < 0)
		goto err;
	/* no errors after this point */

	max_non_turbo = base_min_ratio
		      + (100 - max_non_turbo) * (base_max_ratio - base_min_ratio) / 100;

	POWER_DEBUG_TRACE("no turbo perf %"PRIu64"\n", max_non_turbo);

	pi->non_turbo_max_ratio = (uint32_t)max_non_turbo;

	/*
	 * If base_frequency is reported as greater than the maximum
	 * turbo frequency, that's a known issue with some kernels.
	 * Set base_frequency to max_non_turbo as a workaround.
	 */
	if (base_ratio > base_max_ratio) {
		/* base_ratio is greater than max turbo. Kernel bug. */
		pi->priority_core = 0;
		goto out;
	}

	/*
	 * If base_frequency is reported as greater than the maximum
	 * non-turbo frequency, then mark it as a high priority core.
	 */
	if (base_ratio > max_non_turbo)
		pi->priority_core = 1;
	else
		pi->priority_core = 0;
	pi->core_base_freq = base_ratio * BUS_FREQ;

out:
	if (f_base != NULL)
		fclose(f_base);
	fclose(f_base_max);
	fclose(f_base_min);
	/* f_min and f_max are stored, no need to close */
	return 0;

err:
	if (f_base != NULL)
		fclose(f_base);
	if (f_base_min != NULL)
		fclose(f_base_min);
	if (f_base_max != NULL)
		fclose(f_base_max);
	if (f_min != NULL)
		fclose(f_min);
	if (f_max != NULL)
		fclose(f_max);
	return -1;
}

static int
set_freq_internal(struct pstate_power_info *pi, uint32_t idx)
{
	uint32_t target_freq = 0;

	if (idx >= RTE_MAX_LCORE_FREQS || idx >= pi->nb_freqs) {
		RTE_LOG(ERR, POWER, "Invalid frequency index %u, which "
				"should be less than %u\n", idx, pi->nb_freqs);
		return -1;
	}

	/* Check if it is the same as current */
	if (idx == pi->curr_idx)
		return 0;

	/* Because Intel Pstate Driver only allow user change min/max hint
	 * User need change the min/max as same value.
	 */
	if (fseek(pi->f_cur_min, 0, SEEK_SET) < 0) {
		RTE_LOG(ERR, POWER, "Fail to set file position indicator to 0 "
				"for setting frequency for lcore %u\n",
				pi->lcore_id);
		return -1;
	}

	if (fseek(pi->f_cur_max, 0, SEEK_SET) < 0) {
		RTE_LOG(ERR, POWER, "Fail to set file position indicator to 0 "
				"for setting frequency for lcore %u\n",
				pi->lcore_id);
		return -1;
	}

	/* Turbo is available and enabled, first freq bucket is sys max freq */
	if (pi->turbo_available && idx == 0) {
		if (pi->turbo_enable)
			target_freq = pi->sys_max_freq;
		else {
			RTE_LOG(ERR, POWER, "Turbo is off, frequency can't be scaled up more %u\n",
					pi->lcore_id);
			return -1;
		}
	} else
		target_freq = pi->freqs[idx];

	/* Decrease freq, the min freq should be updated first */
	if (idx  >  pi->curr_idx) {

		if (fprintf(pi->f_cur_min, "%u", target_freq) < 0) {
			RTE_LOG(ERR, POWER, "Fail to write new frequency for "
					"lcore %u\n", pi->lcore_id);
			return -1;
		}

		if (fprintf(pi->f_cur_max, "%u", target_freq) < 0) {
			RTE_LOG(ERR, POWER, "Fail to write new frequency for "
					"lcore %u\n", pi->lcore_id);
			return -1;
		}

		POWER_DEBUG_TRACE("Frequency '%u' to be set for lcore %u\n",
				  target_freq, pi->lcore_id);

		fflush(pi->f_cur_min);
		fflush(pi->f_cur_max);

	}

	/* Increase freq, the max freq should be updated first */
	if (idx  <  pi->curr_idx) {

		if (fprintf(pi->f_cur_max, "%u", target_freq) < 0) {
			RTE_LOG(ERR, POWER, "Fail to write new frequency for "
					"lcore %u\n", pi->lcore_id);
			return -1;
		}

		if (fprintf(pi->f_cur_min, "%u", target_freq) < 0) {
			RTE_LOG(ERR, POWER, "Fail to write new frequency for "
					"lcore %u\n", pi->lcore_id);
			return -1;
		}

		POWER_DEBUG_TRACE("Frequency '%u' to be set for lcore %u\n",
				  target_freq, pi->lcore_id);

		fflush(pi->f_cur_max);
		fflush(pi->f_cur_min);
	}

	pi->curr_idx = idx;

	return 1;
}

/**
 * It is to check the current scaling governor by reading sys file, and then
 * set it into 'performance' if it is not by writing the sys file. The original
 * governor will be saved for rolling back.
 */
static int
power_set_governor_performance(struct pstate_power_info *pi)
{
	return power_set_governor(pi->lcore_id, POWER_GOVERNOR_PERF,
			pi->governor_ori, sizeof(pi->governor_ori));
}

/**
 * It is to check the governor and then set the original governor back if
 * needed by writing the sys file.
 */
static int
power_set_governor_original(struct pstate_power_info *pi)
{
	return power_set_governor(pi->lcore_id, pi->governor_ori, NULL, 0);
}

/**
 * It is to get the available frequencies of the specific lcore by reading the
 * sys file.
 */
static int
power_get_available_freqs(struct pstate_power_info *pi)
{
	FILE *f_min = NULL, *f_max = NULL;
	int ret = -1;
	uint32_t sys_min_freq = 0, sys_max_freq = 0, base_max_freq = 0;
	int config_min_freq, config_max_freq;
	uint32_t i, num_freqs = 0;

	/* open all files */
	open_core_sysfs_file(&f_max, "r", POWER_SYSFILE_BASE_MAX_FREQ,
			pi->lcore_id);
	if (f_max == NULL) {
		RTE_LOG(ERR, POWER, "failed to open %s\n",
				POWER_SYSFILE_BASE_MAX_FREQ);
		goto out;
	}

	open_core_sysfs_file(&f_min, "r", POWER_SYSFILE_BASE_MIN_FREQ,
			pi->lcore_id);
	if (f_min == NULL) {
		RTE_LOG(ERR, POWER, "failed to open %s\n",
				POWER_SYSFILE_BASE_MIN_FREQ);
		goto out;
	}

	/* read base ratios */
	ret = read_core_sysfs_u32(f_max, &sys_max_freq);
	if (ret < 0) {
		RTE_LOG(ERR, POWER, "Failed to read %s\n",
				POWER_SYSFILE_BASE_MAX_FREQ);
		goto out;
	}

	ret = read_core_sysfs_u32(f_min, &sys_min_freq);
	if (ret < 0) {
		RTE_LOG(ERR, POWER, "Failed to read %s\n",
				POWER_SYSFILE_BASE_MIN_FREQ);
		goto out;
	}

	/* check for config set by user or application to limit frequency range */
	config_min_freq = rte_power_pmd_mgmt_get_scaling_freq_min(pi->lcore_id);
	if (config_min_freq < 0)
		goto out;
	config_max_freq = rte_power_pmd_mgmt_get_scaling_freq_max(pi->lcore_id);
	if (config_max_freq < 0)
		goto out;

	sys_min_freq = RTE_MAX(sys_min_freq, (uint32_t)config_min_freq);
	if (config_max_freq > 0) /* Only use config_max_freq if a value has been set */
		sys_max_freq = RTE_MIN(sys_max_freq, (uint32_t)config_max_freq);

	if (sys_max_freq < sys_min_freq)
		goto out;

	pi->sys_max_freq = sys_max_freq;

	if (pi->priority_core == 1)
		base_max_freq = pi->core_base_freq;
	else
		base_max_freq = pi->non_turbo_max_ratio * BUS_FREQ;

	POWER_DEBUG_TRACE("sys min %u, sys max %u, base_max %u\n",
			sys_min_freq,
			sys_max_freq,
			base_max_freq);

	if (base_max_freq < sys_max_freq)
		pi->turbo_available = 1;
	else
		pi->turbo_available = 0;

	/* If turbo is available then there is one extra freq bucket
	 * to store the sys max freq which value is base_max +1
	 */
	num_freqs = (RTE_MIN(base_max_freq, sys_max_freq) - sys_min_freq) / BUS_FREQ
			+ 1 + pi->turbo_available;
	if (num_freqs >= RTE_MAX_LCORE_FREQS) {
		RTE_LOG(ERR, POWER, "Too many available frequencies: %d\n",
				num_freqs);
		goto out;
	}

	/* Generate the freq bucket array.
	 * If turbo is available the freq bucket[0] value is base_max +1
	 * the bucket[1] is base_max, bucket[2] is base_max - BUS_FREQ
	 * and so on.
	 * If turbo is not available bucket[0] is base_max and so on
	 */
	for (i = 0, pi->nb_freqs = 0; i < num_freqs; i++) {
		if ((i == 0) && pi->turbo_available)
			pi->freqs[pi->nb_freqs++] = RTE_MIN(base_max_freq, sys_max_freq) + 1;
		else
			pi->freqs[pi->nb_freqs++] = RTE_MIN(base_max_freq, sys_max_freq) -
					(i - pi->turbo_available) * BUS_FREQ;
	}

	ret = 0;

	POWER_DEBUG_TRACE("%d frequency(s) of lcore %u are available\n",
			num_freqs, pi->lcore_id);

out:
	if (f_min != NULL)
		fclose(f_min);
	if (f_max != NULL)
		fclose(f_max);

	return ret;
}

static int
power_get_cur_idx(struct pstate_power_info *pi)
{
	FILE *f_cur;
	int ret = -1;
	uint32_t sys_cur_freq = 0;
	unsigned int i;

	open_core_sysfs_file(&f_cur, "r", POWER_SYSFILE_CUR_FREQ,
			pi->lcore_id);
	if (f_cur == NULL) {
		RTE_LOG(ERR, POWER, "failed to open %s\n",
				POWER_SYSFILE_CUR_FREQ);
		goto fail;
	}

	ret = read_core_sysfs_u32(f_cur, &sys_cur_freq);
	if (ret < 0) {
		RTE_LOG(ERR, POWER, "Failed to read %s\n",
				POWER_SYSFILE_CUR_FREQ);
		goto fail;
	}

	/* convert the frequency to nearest 100000 value
	 * Ex: if sys_cur_freq=1396789 then freq_conv=1400000
	 * Ex: if sys_cur_freq=800030 then freq_conv=800000
	 * Ex: if sys_cur_freq=800030 then freq_conv=800000
	 */
	unsigned int freq_conv = 0;
	freq_conv = (sys_cur_freq + FREQ_ROUNDING_DELTA)
				/ ROUND_FREQ_TO_N_100000;
	freq_conv = freq_conv * ROUND_FREQ_TO_N_100000;

	for (i = 0; i < pi->nb_freqs; i++) {
		if (freq_conv == pi->freqs[i]) {
			pi->curr_idx = i;
			break;
		}
	}

	ret = 0;
fail:
	if (f_cur != NULL)
		fclose(f_cur);
	return ret;
}

int
power_pstate_cpufreq_check_supported(void)
{
	return cpufreq_check_scaling_driver(POWER_PSTATE_DRIVER);
}

int
power_pstate_cpufreq_init(unsigned int lcore_id)
{
	struct pstate_power_info *pi;
	uint32_t exp_state;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Lcore id %u can not exceed %u\n",
				lcore_id, RTE_MAX_LCORE - 1U);
		return -1;
	}

	pi = &lcore_power_info[lcore_id];
	exp_state = POWER_IDLE;
	/* The power in use state works as a guard variable between
	 * the CPU frequency control initialization and exit process.
	 * The ACQUIRE memory ordering here pairs with the RELEASE
	 * ordering below as lock to make sure the frequency operations
	 * in the critical section are done under the correct state.
	 */
	if (!__atomic_compare_exchange_n(&(pi->state), &exp_state,
					POWER_ONGOING, 0,
					__ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		RTE_LOG(INFO, POWER, "Power management of lcore %u is "
				"in use\n", lcore_id);
		return -1;
	}

	pi->lcore_id = lcore_id;
	/* Check and set the governor */
	if (power_set_governor_performance(pi) < 0) {
		RTE_LOG(ERR, POWER, "Cannot set governor of lcore %u to "
				"performance\n", lcore_id);
		goto fail;
	}
	/* Init for setting lcore frequency */
	if (power_init_for_setting_freq(pi) < 0) {
		RTE_LOG(ERR, POWER, "Cannot init for setting frequency for "
				"lcore %u\n", lcore_id);
		goto fail;
	}

	/* Get the available frequencies */
	if (power_get_available_freqs(pi) < 0) {
		RTE_LOG(ERR, POWER, "Cannot get available frequencies of "
				"lcore %u\n", lcore_id);
		goto fail;
	}

	if (power_get_cur_idx(pi) < 0) {
		RTE_LOG(ERR, POWER, "Cannot get current frequency "
				"index of lcore %u\n", lcore_id);
		goto fail;
	}

	/* Set freq to max by default */
	if (power_pstate_cpufreq_freq_max(lcore_id) < 0) {
		RTE_LOG(ERR, POWER, "Cannot set frequency of lcore %u "
				"to max\n", lcore_id);
		goto fail;
	}

	RTE_LOG(INFO, POWER, "Initialized successfully for lcore %u "
			"power management\n", lcore_id);
	exp_state = POWER_ONGOING;
	__atomic_compare_exchange_n(&(pi->state), &exp_state, POWER_USED,
				    0, __ATOMIC_RELEASE, __ATOMIC_RELAXED);

	return 0;

fail:
	exp_state = POWER_ONGOING;
	__atomic_compare_exchange_n(&(pi->state), &exp_state, POWER_UNKNOWN,
				    0, __ATOMIC_RELEASE, __ATOMIC_RELAXED);

	return -1;
}

int
power_pstate_cpufreq_exit(unsigned int lcore_id)
{
	struct pstate_power_info *pi;
	uint32_t exp_state;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Lcore id %u can not exceeds %u\n",
				lcore_id, RTE_MAX_LCORE - 1U);
		return -1;
	}
	pi = &lcore_power_info[lcore_id];

	exp_state = POWER_USED;
	/* The power in use state works as a guard variable between
	 * the CPU frequency control initialization and exit process.
	 * The ACQUIRE memory ordering here pairs with the RELEASE
	 * ordering below as lock to make sure the frequency operations
	 * in the critical section are under done the correct state.
	 */
	if (!__atomic_compare_exchange_n(&(pi->state), &exp_state,
					POWER_ONGOING, 0,
					__ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		RTE_LOG(INFO, POWER, "Power management of lcore %u is "
				"not used\n", lcore_id);
		return -1;
	}

	/* Close FD of setting freq */
	fclose(pi->f_cur_min);
	fclose(pi->f_cur_max);
	pi->f_cur_min = NULL;
	pi->f_cur_max = NULL;

	/* Set the governor back to the original */
	if (power_set_governor_original(pi) < 0) {
		RTE_LOG(ERR, POWER, "Cannot set the governor of %u back "
				"to the original\n", lcore_id);
		goto fail;
	}

	RTE_LOG(INFO, POWER, "Power management of lcore %u has exited from "
			"'performance' mode and been set back to the "
			"original\n", lcore_id);
	exp_state = POWER_ONGOING;
	__atomic_compare_exchange_n(&(pi->state), &exp_state, POWER_IDLE,
				    0, __ATOMIC_RELEASE, __ATOMIC_RELAXED);

	return 0;

fail:
	exp_state = POWER_ONGOING;
	__atomic_compare_exchange_n(&(pi->state), &exp_state, POWER_UNKNOWN,
				    0, __ATOMIC_RELEASE, __ATOMIC_RELAXED);

	return -1;
}


uint32_t
power_pstate_cpufreq_freqs(unsigned int lcore_id, uint32_t *freqs, uint32_t num)
{
	struct pstate_power_info *pi;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return 0;
	}

	if (freqs == NULL) {
		RTE_LOG(ERR, POWER, "NULL buffer supplied\n");
		return 0;
	}

	pi = &lcore_power_info[lcore_id];
	if (num < pi->nb_freqs) {
		RTE_LOG(ERR, POWER, "Buffer size is not enough\n");
		return 0;
	}
	rte_memcpy(freqs, pi->freqs, pi->nb_freqs * sizeof(uint32_t));

	return pi->nb_freqs;
}

uint32_t
power_pstate_cpufreq_get_freq(unsigned int lcore_id)
{
	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return RTE_POWER_INVALID_FREQ_INDEX;
	}

	return lcore_power_info[lcore_id].curr_idx;
}


int
power_pstate_cpufreq_set_freq(unsigned int lcore_id, uint32_t index)
{
	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return -1;
	}

	return set_freq_internal(&(lcore_power_info[lcore_id]), index);
}

int
power_pstate_cpufreq_freq_up(unsigned int lcore_id)
{
	struct pstate_power_info *pi;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return -1;
	}

	pi = &lcore_power_info[lcore_id];
	if (pi->curr_idx == 0 ||
	    (pi->curr_idx == 1 && pi->turbo_available && !pi->turbo_enable))
		return 0;

	/* Frequencies in the array are from high to low. */
	return set_freq_internal(pi, pi->curr_idx - 1);
}

int
power_pstate_cpufreq_freq_down(unsigned int lcore_id)
{
	struct pstate_power_info *pi;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return -1;
	}

	pi = &lcore_power_info[lcore_id];
	if (pi->curr_idx + 1 == pi->nb_freqs)
		return 0;

	/* Frequencies in the array are from high to low. */
	return set_freq_internal(pi, pi->curr_idx + 1);
}

int
power_pstate_cpufreq_freq_max(unsigned int lcore_id)
{
	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return -1;
	}

	/* Frequencies in the array are from high to low. */
	if (lcore_power_info[lcore_id].turbo_available) {
		if (lcore_power_info[lcore_id].turbo_enable)
			/* Set to Turbo */
			return set_freq_internal(
					&lcore_power_info[lcore_id], 0);
		else
			/* Set to max non-turbo */
			return set_freq_internal(
					&lcore_power_info[lcore_id], 1);
	} else
		return set_freq_internal(&lcore_power_info[lcore_id], 0);
}


int
power_pstate_cpufreq_freq_min(unsigned int lcore_id)
{
	struct pstate_power_info *pi;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return -1;
	}

	pi = &lcore_power_info[lcore_id];

	/* Frequencies in the array are from high to low. */
	return set_freq_internal(pi, pi->nb_freqs - 1);
}


int
power_pstate_turbo_status(unsigned int lcore_id)
{
	struct pstate_power_info *pi;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return -1;
	}

	pi = &lcore_power_info[lcore_id];

	return pi->turbo_enable;
}

int
power_pstate_enable_turbo(unsigned int lcore_id)
{
	struct pstate_power_info *pi;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return -1;
	}

	pi = &lcore_power_info[lcore_id];

	if (pi->turbo_available)
		pi->turbo_enable = 1;
	else {
		pi->turbo_enable = 0;
		RTE_LOG(ERR, POWER,
			"Failed to enable turbo on lcore %u\n",
			lcore_id);
			return -1;
	}

	return 0;
}


int
power_pstate_disable_turbo(unsigned int lcore_id)
{
	struct pstate_power_info *pi;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return -1;
	}

	pi = &lcore_power_info[lcore_id];

	pi->turbo_enable = 0;

	if (pi->turbo_available && pi->curr_idx <= 1) {
		/* Try to set freq to max by default coming out of turbo */
		if (power_pstate_cpufreq_freq_max(lcore_id) < 0) {
			RTE_LOG(ERR, POWER,
				"Failed to set frequency of lcore %u to max\n",
				lcore_id);
			return -1;
		}
	}

	return 0;
}


int power_pstate_get_capabilities(unsigned int lcore_id,
		struct rte_power_core_capabilities *caps)
{
	struct pstate_power_info *pi;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return -1;
	}
	if (caps == NULL) {
		RTE_LOG(ERR, POWER, "Invalid argument\n");
		return -1;
	}

	pi = &lcore_power_info[lcore_id];
	caps->capabilities = 0;
	caps->turbo = !!(pi->turbo_available);
	caps->priority = pi->priority_core;

	return 0;
}
