/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>
#ifdef USE_JANSSON
#include <jansson.h>
#else
#pragma message "Jansson dev libs unavailable, not including JSON parsing"
#endif
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_malloc.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_pmd_i40e.h>

#include <libvirt/libvirt.h>
#include "channel_monitor.h"
#include "channel_commands.h"
#include "channel_manager.h"
#include "power_manager.h"
#include "oob_monitor.h"

#define RTE_LOGTYPE_CHANNEL_MONITOR RTE_LOGTYPE_USER1

#define MAX_EVENTS 256

uint64_t vsi_pkt_count_prev[384];
uint64_t rdtsc_prev[384];
#define MAX_JSON_STRING_LEN 1024
char json_data[MAX_JSON_STRING_LEN];

double time_period_ms = 1;
static volatile unsigned run_loop = 1;
static int global_event_fd;
static unsigned int policy_is_set;
static struct epoll_event *global_events_list;
static struct policy policies[MAX_CLIENTS];

#ifdef USE_JANSSON

union PFID {
	struct ether_addr addr;
	uint64_t pfid;
};

static int
str_to_ether_addr(const char *a, struct ether_addr *ether_addr)
{
	int i;
	char *end;
	unsigned long o[ETHER_ADDR_LEN];

	i = 0;
	do {
		errno = 0;
		o[i] = strtoul(a, &end, 16);
		if (errno != 0 || end == a || (end[0] != ':' && end[0] != 0))
			return -1;
		a = end + 1;
	} while (++i != RTE_DIM(o) / sizeof(o[0]) && end[0] != 0);

	/* Junk at the end of line */
	if (end[0] != 0)
		return -1;

	/* Support the format XX:XX:XX:XX:XX:XX */
	if (i == ETHER_ADDR_LEN) {
		while (i-- != 0) {
			if (o[i] > UINT8_MAX)
				return -1;
			ether_addr->addr_bytes[i] = (uint8_t)o[i];
		}
	/* Support the format XXXX:XXXX:XXXX */
	} else if (i == ETHER_ADDR_LEN / 2) {
		while (i-- != 0) {
			if (o[i] > UINT16_MAX)
				return -1;
			ether_addr->addr_bytes[i * 2] =
					(uint8_t)(o[i] >> 8);
			ether_addr->addr_bytes[i * 2 + 1] =
					(uint8_t)(o[i] & 0xff);
		}
	/* unknown format */
	} else
		return -1;

	return 0;
}

static int
set_policy_mac(struct channel_packet *pkt, int idx, char *mac)
{
	union PFID pfid;
	int ret;

	/* Use port MAC address as the vfid */
	ret = str_to_ether_addr(mac, &pfid.addr);

	if (ret != 0) {
		RTE_LOG(ERR, CHANNEL_MONITOR,
			"Invalid mac address received in JSON\n");
		pkt->vfid[idx] = 0;
		return -1;
	}

	printf("Received MAC Address: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":"
			"%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
			pfid.addr.addr_bytes[0], pfid.addr.addr_bytes[1],
			pfid.addr.addr_bytes[2], pfid.addr.addr_bytes[3],
			pfid.addr.addr_bytes[4], pfid.addr.addr_bytes[5]);

	pkt->vfid[idx] = pfid.pfid;
	return 0;
}


static int
parse_json_to_pkt(json_t *element, struct channel_packet *pkt)
{
	const char *key;
	json_t *value;
	int ret;

	memset(pkt, 0, sizeof(struct channel_packet));

	pkt->nb_mac_to_monitor = 0;
	pkt->t_boost_status.tbEnabled = false;
	pkt->workload = LOW;
	pkt->policy_to_use = TIME;
	pkt->command = PKT_POLICY;
	pkt->core_type = CORE_TYPE_PHYSICAL;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "policy")) {
			/* Recurse in to get the contents of profile */
			ret = parse_json_to_pkt(value, pkt);
			if (ret)
				return ret;
		} else if (!strcmp(key, "instruction")) {
			/* Recurse in to get the contents of instruction */
			ret = parse_json_to_pkt(value, pkt);
			if (ret)
				return ret;
		} else if (!strcmp(key, "name")) {
			strlcpy(pkt->vm_name, json_string_value(value),
					sizeof(pkt->vm_name));
		} else if (!strcmp(key, "command")) {
			char command[32];
			snprintf(command, 32, "%s", json_string_value(value));
			if (!strcmp(command, "power")) {
				pkt->command = CPU_POWER;
			} else if (!strcmp(command, "create")) {
				pkt->command = PKT_POLICY;
			} else if (!strcmp(command, "destroy")) {
				pkt->command = PKT_POLICY_REMOVE;
			} else {
				RTE_LOG(ERR, CHANNEL_MONITOR,
					"Invalid command received in JSON\n");
				return -1;
			}
		} else if (!strcmp(key, "policy_type")) {
			char command[32];
			snprintf(command, 32, "%s", json_string_value(value));
			if (!strcmp(command, "TIME")) {
				pkt->policy_to_use = TIME;
			} else if (!strcmp(command, "TRAFFIC")) {
				pkt->policy_to_use = TRAFFIC;
			} else if (!strcmp(command, "WORKLOAD")) {
				pkt->policy_to_use = WORKLOAD;
			} else if (!strcmp(command, "BRANCH_RATIO")) {
				pkt->policy_to_use = BRANCH_RATIO;
			} else {
				RTE_LOG(ERR, CHANNEL_MONITOR,
					"Wrong policy_type received in JSON\n");
				return -1;
			}
		} else if (!strcmp(key, "workload")) {
			char command[32];
			snprintf(command, 32, "%s", json_string_value(value));
			if (!strcmp(command, "HIGH")) {
				pkt->workload = HIGH;
			} else if (!strcmp(command, "MEDIUM")) {
				pkt->workload = MEDIUM;
			} else if (!strcmp(command, "LOW")) {
				pkt->workload = LOW;
			} else {
				RTE_LOG(ERR, CHANNEL_MONITOR,
					"Wrong workload received in JSON\n");
				return -1;
			}
		} else if (!strcmp(key, "busy_hours")) {
			unsigned int i;
			size_t size = json_array_size(value);

			for (i = 0; i < size; i++) {
				int hour = (int)json_integer_value(
						json_array_get(value, i));
				pkt->timer_policy.busy_hours[i] = hour;
			}
		} else if (!strcmp(key, "quiet_hours")) {
			unsigned int i;
			size_t size = json_array_size(value);

			for (i = 0; i < size; i++) {
				int hour = (int)json_integer_value(
						json_array_get(value, i));
				pkt->timer_policy.quiet_hours[i] = hour;
			}
		} else if (!strcmp(key, "core_list")) {
			unsigned int i;
			size_t size = json_array_size(value);

			for (i = 0; i < size; i++) {
				int core = (int)json_integer_value(
						json_array_get(value, i));
				pkt->vcpu_to_control[i] = core;
			}
			pkt->num_vcpu = size;
		} else if (!strcmp(key, "mac_list")) {
			unsigned int i;
			size_t size = json_array_size(value);

			for (i = 0; i < size; i++) {
				char mac[32];
				snprintf(mac, 32, "%s", json_string_value(
						json_array_get(value, i)));
				set_policy_mac(pkt, i, mac);
			}
			pkt->nb_mac_to_monitor = size;
		} else if (!strcmp(key, "avg_packet_thresh")) {
			pkt->traffic_policy.avg_max_packet_thresh =
					(uint32_t)json_integer_value(value);
		} else if (!strcmp(key, "max_packet_thresh")) {
			pkt->traffic_policy.max_max_packet_thresh =
					(uint32_t)json_integer_value(value);
		} else if (!strcmp(key, "unit")) {
			char unit[32];
			snprintf(unit, 32, "%s", json_string_value(value));
			if (!strcmp(unit, "SCALE_UP")) {
				pkt->unit = CPU_POWER_SCALE_UP;
			} else if (!strcmp(unit, "SCALE_DOWN")) {
				pkt->unit = CPU_POWER_SCALE_DOWN;
			} else if (!strcmp(unit, "SCALE_MAX")) {
				pkt->unit = CPU_POWER_SCALE_MAX;
			} else if (!strcmp(unit, "SCALE_MIN")) {
				pkt->unit = CPU_POWER_SCALE_MIN;
			} else if (!strcmp(unit, "ENABLE_TURBO")) {
				pkt->unit = CPU_POWER_ENABLE_TURBO;
			} else if (!strcmp(unit, "DISABLE_TURBO")) {
				pkt->unit = CPU_POWER_DISABLE_TURBO;
			} else {
				RTE_LOG(ERR, CHANNEL_MONITOR,
					"Invalid command received in JSON\n");
				return -1;
			}
		} else if (!strcmp(key, "resource_id")) {
			pkt->resource_id = (uint32_t)json_integer_value(value);
		} else {
			RTE_LOG(ERR, CHANNEL_MONITOR,
				"Unknown key received in JSON string: %s\n",
				key);
		}
	}
	return 0;
}
#endif

void channel_monitor_exit(void)
{
	run_loop = 0;
	rte_free(global_events_list);
}

static void
core_share(int pNo, int z, int x, int t)
{
	if (policies[pNo].core_share[z].pcpu == lvm_info[x].pcpus[t]) {
		if (strcmp(policies[pNo].pkt.vm_name,
				lvm_info[x].vm_name) != 0) {
			policies[pNo].core_share[z].status = 1;
			power_manager_scale_core_max(
					policies[pNo].core_share[z].pcpu);
		}
	}
}

static void
core_share_status(int pNo)
{

	int noVms = 0, noVcpus = 0, z, x, t;

	get_all_vm(&noVms, &noVcpus);

	/* Reset Core Share Status. */
	for (z = 0; z < noVcpus; z++)
		policies[pNo].core_share[z].status = 0;

	/* Foreach vcpu in a policy. */
	for (z = 0; z < policies[pNo].pkt.num_vcpu; z++) {
		/* Foreach VM on the platform. */
		for (x = 0; x < noVms; x++) {
			/* Foreach vcpu of VMs on platform. */
			for (t = 0; t < lvm_info[x].num_cpus; t++)
				core_share(pNo, z, x, t);
		}
	}
}


static int
pcpu_monitor(struct policy *pol, struct core_info *ci, int pcpu, int count)
{
	int ret = 0;

	if (pol->pkt.policy_to_use == BRANCH_RATIO) {
		ci->cd[pcpu].oob_enabled = 1;
		ret = add_core_to_monitor(pcpu);
		if (ret == 0)
			RTE_LOG(INFO, CHANNEL_MONITOR,
					"Monitoring pcpu %d OOB for %s\n",
					pcpu, pol->pkt.vm_name);
		else
			RTE_LOG(ERR, CHANNEL_MONITOR,
					"Error monitoring pcpu %d OOB for %s\n",
					pcpu, pol->pkt.vm_name);

	} else {
		pol->core_share[count].pcpu = pcpu;
		RTE_LOG(INFO, CHANNEL_MONITOR,
				"Monitoring pcpu %d for %s\n",
				pcpu, pol->pkt.vm_name);
	}
	return ret;
}

static void
get_pcpu_to_control(struct policy *pol)
{

	/* Convert vcpu to pcpu. */
	struct vm_info info;
	int pcpu, count;
	uint64_t mask_u64b;
	struct core_info *ci;

	ci = get_core_info();

	RTE_LOG(DEBUG, CHANNEL_MONITOR,
			"Looking for pcpu for %s\n", pol->pkt.vm_name);

	/*
	 * So now that we're handling virtual and physical cores, we need to
	 * differenciate between them when adding them to the branch monitor.
	 * Virtual cores need to be converted to physical cores.
	 */
	if (pol->pkt.core_type == CORE_TYPE_VIRTUAL) {
		/*
		 * If the cores in the policy are virtual, we need to map them
		 * to physical core. We look up the vm info and use that for
		 * the mapping.
		 */
		get_info_vm(pol->pkt.vm_name, &info);
		for (count = 0; count < pol->pkt.num_vcpu; count++) {
			mask_u64b =
				info.pcpu_mask[pol->pkt.vcpu_to_control[count]];
			for (pcpu = 0; mask_u64b;
					mask_u64b &= ~(1ULL << pcpu++)) {
				if ((mask_u64b >> pcpu) & 1)
					pcpu_monitor(pol, ci, pcpu, count);
			}
		}
	} else {
		/*
		 * If the cores in the policy are physical, we just use
		 * those core id's directly.
		 */
		for (count = 0; count < pol->pkt.num_vcpu; count++) {
			pcpu = pol->pkt.vcpu_to_control[count];
			pcpu_monitor(pol, ci, pcpu, count);
		}
	}
}

static int
get_pfid(struct policy *pol)
{

	int i, x, ret = 0;

	for (i = 0; i < pol->pkt.nb_mac_to_monitor; i++) {

		RTE_ETH_FOREACH_DEV(x) {
			ret = rte_pmd_i40e_query_vfid_by_mac(x,
				(struct ether_addr *)&(pol->pkt.vfid[i]));
			if (ret != -EINVAL) {
				pol->port[i] = x;
				break;
			}
		}
		if (ret == -EINVAL || ret == -ENOTSUP || ret == ENODEV) {
			RTE_LOG(INFO, CHANNEL_MONITOR,
				"Error with Policy. MAC not found on "
				"attached ports ");
			pol->enabled = 0;
			return ret;
		}
		pol->pfid[i] = ret;
	}
	return 1;
}

static int
update_policy(struct channel_packet *pkt)
{

	unsigned int updated = 0;
	int i;


	RTE_LOG(INFO, CHANNEL_MONITOR,
			"Applying policy for %s\n", pkt->vm_name);

	for (i = 0; i < MAX_CLIENTS; i++) {
		if (strcmp(policies[i].pkt.vm_name, pkt->vm_name) == 0) {
			/* Copy the contents of *pkt into the policy.pkt */
			policies[i].pkt = *pkt;
			get_pcpu_to_control(&policies[i]);
			if (get_pfid(&policies[i]) == -1) {
				updated = 1;
				break;
			}
			core_share_status(i);
			policies[i].enabled = 1;
			updated = 1;
		}
	}
	if (!updated) {
		for (i = 0; i < MAX_CLIENTS; i++) {
			if (policies[i].enabled == 0) {
				policies[i].pkt = *pkt;
				get_pcpu_to_control(&policies[i]);
				if (get_pfid(&policies[i]) == -1)
					break;
				core_share_status(i);
				policies[i].enabled = 1;
				break;
			}
		}
	}
	return 0;
}

static int
remove_policy(struct channel_packet *pkt __rte_unused)
{
	int i;

	/*
	 * Disabling the policy is simply a case of setting
	 * enabled to 0
	 */
	for (i = 0; i < MAX_CLIENTS; i++) {
		if (strcmp(policies[i].pkt.vm_name, pkt->vm_name) == 0) {
			policies[i].enabled = 0;
			return 0;
		}
	}
	return -1;
}

static uint64_t
get_pkt_diff(struct policy *pol)
{

	uint64_t vsi_pkt_count,
		vsi_pkt_total = 0,
		vsi_pkt_count_prev_total = 0;
	double rdtsc_curr, rdtsc_diff, diff;
	int x;
	struct rte_eth_stats vf_stats;

	for (x = 0; x < pol->pkt.nb_mac_to_monitor; x++) {

		/*Read vsi stats*/
		if (rte_pmd_i40e_get_vf_stats(x, pol->pfid[x], &vf_stats) == 0)
			vsi_pkt_count = vf_stats.ipackets;
		else
			vsi_pkt_count = -1;

		vsi_pkt_total += vsi_pkt_count;

		vsi_pkt_count_prev_total += vsi_pkt_count_prev[pol->pfid[x]];
		vsi_pkt_count_prev[pol->pfid[x]] = vsi_pkt_count;
	}

	rdtsc_curr = rte_rdtsc_precise();
	rdtsc_diff = rdtsc_curr - rdtsc_prev[pol->pfid[x-1]];
	rdtsc_prev[pol->pfid[x-1]] = rdtsc_curr;

	diff = (vsi_pkt_total - vsi_pkt_count_prev_total) *
			((double)rte_get_tsc_hz() / rdtsc_diff);

	return diff;
}

static void
apply_traffic_profile(struct policy *pol)
{

	int count;
	uint64_t diff = 0;

	diff = get_pkt_diff(pol);

	if (diff >= (pol->pkt.traffic_policy.max_max_packet_thresh)) {
		for (count = 0; count < pol->pkt.num_vcpu; count++) {
			if (pol->core_share[count].status != 1)
				power_manager_scale_core_max(
						pol->core_share[count].pcpu);
		}
	} else if (diff >= (pol->pkt.traffic_policy.avg_max_packet_thresh)) {
		for (count = 0; count < pol->pkt.num_vcpu; count++) {
			if (pol->core_share[count].status != 1)
				power_manager_scale_core_med(
						pol->core_share[count].pcpu);
		}
	} else if (diff < (pol->pkt.traffic_policy.avg_max_packet_thresh)) {
		for (count = 0; count < pol->pkt.num_vcpu; count++) {
			if (pol->core_share[count].status != 1)
				power_manager_scale_core_min(
						pol->core_share[count].pcpu);
		}
	}
}

static void
apply_time_profile(struct policy *pol)
{

	int count, x;
	struct timeval tv;
	struct tm *ptm;
	char time_string[40];

	/* Obtain the time of day, and convert it to a tm struct. */
	gettimeofday(&tv, NULL);
	ptm = localtime(&tv.tv_sec);
	/* Format the date and time, down to a single second. */
	strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S", ptm);

	for (x = 0; x < HOURS; x++) {

		if (ptm->tm_hour == pol->pkt.timer_policy.busy_hours[x]) {
			for (count = 0; count < pol->pkt.num_vcpu; count++) {
				if (pol->core_share[count].status != 1) {
					power_manager_scale_core_max(
						pol->core_share[count].pcpu);
				}
			}
			break;
		} else if (ptm->tm_hour ==
				pol->pkt.timer_policy.quiet_hours[x]) {
			for (count = 0; count < pol->pkt.num_vcpu; count++) {
				if (pol->core_share[count].status != 1) {
					power_manager_scale_core_min(
						pol->core_share[count].pcpu);
			}
		}
			break;
		} else if (ptm->tm_hour ==
			pol->pkt.timer_policy.hours_to_use_traffic_profile[x]) {
			apply_traffic_profile(pol);
			break;
		}
	}
}

static void
apply_workload_profile(struct policy *pol)
{

	int count;

	if (pol->pkt.workload == HIGH) {
		for (count = 0; count < pol->pkt.num_vcpu; count++) {
			if (pol->core_share[count].status != 1)
				power_manager_scale_core_max(
						pol->core_share[count].pcpu);
		}
	} else if (pol->pkt.workload == MEDIUM) {
		for (count = 0; count < pol->pkt.num_vcpu; count++) {
			if (pol->core_share[count].status != 1)
				power_manager_scale_core_med(
						pol->core_share[count].pcpu);
		}
	} else if (pol->pkt.workload == LOW) {
		for (count = 0; count < pol->pkt.num_vcpu; count++) {
			if (pol->core_share[count].status != 1)
				power_manager_scale_core_min(
						pol->core_share[count].pcpu);
		}
	}
}

static void
apply_policy(struct policy *pol)
{

	struct channel_packet *pkt = &pol->pkt;

	/*Check policy to use*/
	if (pkt->policy_to_use == TRAFFIC)
		apply_traffic_profile(pol);
	else if (pkt->policy_to_use == TIME)
		apply_time_profile(pol);
	else if (pkt->policy_to_use == WORKLOAD)
		apply_workload_profile(pol);
}

static int
process_request(struct channel_packet *pkt, struct channel_info *chan_info)
{
	uint64_t core_mask;

	if (chan_info == NULL)
		return -1;

	if (rte_atomic32_cmpset(&(chan_info->status), CHANNEL_MGR_CHANNEL_CONNECTED,
			CHANNEL_MGR_CHANNEL_PROCESSING) == 0)
		return -1;

	if (pkt->command == CPU_POWER) {
		core_mask = get_pcpus_mask(chan_info, pkt->resource_id);
		if (core_mask == 0) {
			/*
			 * Core mask will be 0 in the case where
			 * hypervisor is not available so we're working in
			 * the host, so use the core as the mask.
			 */
			core_mask = 1ULL << pkt->resource_id;
		}
		if (__builtin_popcountll(core_mask) == 1) {

			unsigned core_num = __builtin_ffsll(core_mask) - 1;

			switch (pkt->unit) {
			case(CPU_POWER_SCALE_MIN):
					power_manager_scale_core_min(core_num);
			break;
			case(CPU_POWER_SCALE_MAX):
					power_manager_scale_core_max(core_num);
			break;
			case(CPU_POWER_SCALE_DOWN):
					power_manager_scale_core_down(core_num);
			break;
			case(CPU_POWER_SCALE_UP):
					power_manager_scale_core_up(core_num);
			break;
			case(CPU_POWER_ENABLE_TURBO):
				power_manager_enable_turbo_core(core_num);
			break;
			case(CPU_POWER_DISABLE_TURBO):
				power_manager_disable_turbo_core(core_num);
			break;
			default:
				break;
			}
		} else {
			switch (pkt->unit) {
			case(CPU_POWER_SCALE_MIN):
					power_manager_scale_mask_min(core_mask);
			break;
			case(CPU_POWER_SCALE_MAX):
					power_manager_scale_mask_max(core_mask);
			break;
			case(CPU_POWER_SCALE_DOWN):
					power_manager_scale_mask_down(core_mask);
			break;
			case(CPU_POWER_SCALE_UP):
					power_manager_scale_mask_up(core_mask);
			break;
			case(CPU_POWER_ENABLE_TURBO):
				power_manager_enable_turbo_mask(core_mask);
			break;
			case(CPU_POWER_DISABLE_TURBO):
				power_manager_disable_turbo_mask(core_mask);
			break;
			default:
				break;
			}

		}
	}

	if (pkt->command == PKT_POLICY) {
		RTE_LOG(INFO, CHANNEL_MONITOR, "Processing policy request %s\n",
				pkt->vm_name);
		update_policy(pkt);
		policy_is_set = 1;
	}

	if (pkt->command == PKT_POLICY_REMOVE) {
		RTE_LOG(INFO, CHANNEL_MONITOR,
				 "Removing policy %s\n", pkt->vm_name);
		remove_policy(pkt);
	}

	/*
	 * Return is not checked as channel status may have been set to DISABLED
	 * from management thread
	 */
	rte_atomic32_cmpset(&(chan_info->status), CHANNEL_MGR_CHANNEL_PROCESSING,
			CHANNEL_MGR_CHANNEL_CONNECTED);
	return 0;

}

int
add_channel_to_monitor(struct channel_info **chan_info)
{
	struct channel_info *info = *chan_info;
	struct epoll_event event;

	event.events = EPOLLIN;
	event.data.ptr = info;
	if (epoll_ctl(global_event_fd, EPOLL_CTL_ADD, info->fd, &event) < 0) {
		RTE_LOG(ERR, CHANNEL_MONITOR, "Unable to add channel '%s' "
				"to epoll\n", info->channel_path);
		return -1;
	}
	RTE_LOG(ERR, CHANNEL_MONITOR, "Added channel '%s' "
			"to monitor\n", info->channel_path);
	return 0;
}

int
remove_channel_from_monitor(struct channel_info *chan_info)
{
	if (epoll_ctl(global_event_fd, EPOLL_CTL_DEL,
			chan_info->fd, NULL) < 0) {
		RTE_LOG(ERR, CHANNEL_MONITOR, "Unable to remove channel '%s' "
				"from epoll\n", chan_info->channel_path);
		return -1;
	}
	return 0;
}

int
channel_monitor_init(void)
{
	global_event_fd = epoll_create1(0);
	if (global_event_fd == 0) {
		RTE_LOG(ERR, CHANNEL_MONITOR,
				"Error creating epoll context with error %s\n",
				strerror(errno));
		return -1;
	}
	global_events_list = rte_malloc("epoll_events",
			sizeof(*global_events_list)
			* MAX_EVENTS, RTE_CACHE_LINE_SIZE);
	if (global_events_list == NULL) {
		RTE_LOG(ERR, CHANNEL_MONITOR, "Unable to rte_malloc for "
				"epoll events\n");
		return -1;
	}
	return 0;
}

static void
read_binary_packet(struct channel_info *chan_info)
{
	struct channel_packet pkt;
	void *buffer = &pkt;
	int buffer_len = sizeof(pkt);
	int n_bytes, err = 0;

	while (buffer_len > 0) {
		n_bytes = read(chan_info->fd,
				buffer, buffer_len);
		if (n_bytes == buffer_len)
			break;
		if (n_bytes == -1) {
			err = errno;
			RTE_LOG(DEBUG, CHANNEL_MONITOR,
				"Received error on "
				"channel '%s' read: %s\n",
				chan_info->channel_path,
				strerror(err));
			remove_channel(&chan_info);
			break;
		}
		buffer = (char *)buffer + n_bytes;
		buffer_len -= n_bytes;
	}
	if (!err)
		process_request(&pkt, chan_info);
}

#ifdef USE_JANSSON
static void
read_json_packet(struct channel_info *chan_info)
{
	struct channel_packet pkt;
	int n_bytes, ret;
	json_t *root;
	json_error_t error;

	/* read opening brace to closing brace */
	do {
		int idx = 0;
		int indent = 0;
		do {
			n_bytes = read(chan_info->fd, &json_data[idx], 1);
			if (n_bytes == 0)
				break;
			if (json_data[idx] == '{')
				indent++;
			if (json_data[idx] == '}')
				indent--;
			if ((indent > 0) || (idx > 0))
				idx++;
			if (indent <= 0)
				json_data[idx] = 0;
			if (idx >= MAX_JSON_STRING_LEN-1)
				break;
		} while (indent > 0);

		json_data[idx] = '\0';

		if (strlen(json_data) == 0)
			continue;

		printf("got [%s]\n", json_data);

		root = json_loads(json_data, 0, &error);

		if (root) {
			/*
			 * Because our data is now in the json
			 * object, we can overwrite the pkt
			 * with a channel_packet struct, using
			 * parse_json_to_pkt()
			 */
			ret = parse_json_to_pkt(root, &pkt);
			json_decref(root);
			if (ret) {
				RTE_LOG(ERR, CHANNEL_MONITOR,
					"Error validating JSON profile data\n");
				break;
			}
			process_request(&pkt, chan_info);
		} else {
			RTE_LOG(ERR, CHANNEL_MONITOR,
					"JSON error on line %d: %s\n",
					error.line, error.text);
		}
	} while (n_bytes > 0);
}
#endif

void
run_channel_monitor(void)
{
	while (run_loop) {
		int n_events, i;

		n_events = epoll_wait(global_event_fd, global_events_list,
				MAX_EVENTS, 1);
		if (!run_loop)
			break;
		for (i = 0; i < n_events; i++) {
			struct channel_info *chan_info = (struct channel_info *)
					global_events_list[i].data.ptr;
			if ((global_events_list[i].events & EPOLLERR) ||
				(global_events_list[i].events & EPOLLHUP)) {
				RTE_LOG(INFO, CHANNEL_MONITOR,
						"Remote closed connection for "
						"channel '%s'\n",
						chan_info->channel_path);
				remove_channel(&chan_info);
				continue;
			}
			if (global_events_list[i].events & EPOLLIN) {

				switch (chan_info->type) {
				case CHANNEL_TYPE_BINARY:
					read_binary_packet(chan_info);
					break;
#ifdef USE_JANSSON
				case CHANNEL_TYPE_JSON:
					read_json_packet(chan_info);
					break;
#endif
				default:
					break;
				}
			}
		}
		rte_delay_us(time_period_ms*1000);
		if (policy_is_set) {
			int j;

			for (j = 0; j < MAX_CLIENTS; j++) {
				if (policies[j].enabled == 1)
					apply_policy(&policies[j]);
			}
		}
	}
}
