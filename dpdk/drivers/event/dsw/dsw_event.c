/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Ericsson AB
 */

#include "dsw_evdev.h"

#ifdef DSW_SORT_DEQUEUED
#include "dsw_sort.h"
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <rte_cycles.h>
#include <rte_memcpy.h>
#include <rte_random.h>

static bool
dsw_port_acquire_credits(struct dsw_evdev *dsw, struct dsw_port *port,
			 int32_t credits)
{
	int32_t inflight_credits = port->inflight_credits;
	int32_t missing_credits = credits - inflight_credits;
	int32_t total_on_loan;
	int32_t available;
	int32_t acquired_credits;
	int32_t new_total_on_loan;

	if (likely(missing_credits <= 0)) {
		port->inflight_credits -= credits;
		return true;
	}

	total_on_loan =
		__atomic_load_n(&dsw->credits_on_loan, __ATOMIC_RELAXED);
	available = dsw->max_inflight - total_on_loan;
	acquired_credits = RTE_MAX(missing_credits, DSW_PORT_MIN_CREDITS);

	if (available < acquired_credits)
		return false;

	/* This is a race, no locks are involved, and thus some other
	 * thread can allocate tokens in between the check and the
	 * allocation.
	 */
	new_total_on_loan =
	    __atomic_add_fetch(&dsw->credits_on_loan, acquired_credits,
			       __ATOMIC_RELAXED);

	if (unlikely(new_total_on_loan > dsw->max_inflight)) {
		/* Some other port took the last credits */
		__atomic_sub_fetch(&dsw->credits_on_loan, acquired_credits,
				   __ATOMIC_RELAXED);
		return false;
	}

	DSW_LOG_DP_PORT(DEBUG, port->id, "Acquired %d tokens from pool.\n",
			acquired_credits);

	port->inflight_credits += acquired_credits;
	port->inflight_credits -= credits;

	return true;
}

static void
dsw_port_return_credits(struct dsw_evdev *dsw, struct dsw_port *port,
			int32_t credits)
{
	port->inflight_credits += credits;

	if (unlikely(port->inflight_credits > DSW_PORT_MAX_CREDITS)) {
		int32_t leave_credits = DSW_PORT_MIN_CREDITS;
		int32_t return_credits =
			port->inflight_credits - leave_credits;

		port->inflight_credits = leave_credits;

		__atomic_sub_fetch(&dsw->credits_on_loan, return_credits,
				   __ATOMIC_RELAXED);

		DSW_LOG_DP_PORT(DEBUG, port->id,
				"Returned %d tokens to pool.\n",
				return_credits);
	}
}

static void
dsw_port_enqueue_stats(struct dsw_port *port, uint16_t num_new,
		       uint16_t num_forward, uint16_t num_release)
{
	port->new_enqueued += num_new;
	port->forward_enqueued += num_forward;
	port->release_enqueued += num_release;
}

static void
dsw_port_queue_enqueue_stats(struct dsw_port *source_port, uint8_t queue_id)
{
	source_port->queue_enqueued[queue_id]++;
}

static void
dsw_port_dequeue_stats(struct dsw_port *port, uint16_t num)
{
	port->dequeued += num;
}

static void
dsw_port_queue_dequeued_stats(struct dsw_port *source_port, uint8_t queue_id)
{
	source_port->queue_dequeued[queue_id]++;
}

static void
dsw_port_load_record(struct dsw_port *port, unsigned int dequeued)
{
	if (dequeued > 0 && port->busy_start == 0)
		/* work period begins */
		port->busy_start = rte_get_timer_cycles();
	else if (dequeued == 0 && port->busy_start > 0) {
		/* work period ends */
		uint64_t work_period =
			rte_get_timer_cycles() - port->busy_start;
		port->busy_cycles += work_period;
		port->busy_start = 0;
	}
}

static int16_t
dsw_port_load_close_period(struct dsw_port *port, uint64_t now)
{
	uint64_t passed = now - port->measurement_start;
	uint64_t busy_cycles = port->busy_cycles;

	if (port->busy_start > 0) {
		busy_cycles += (now - port->busy_start);
		port->busy_start = now;
	}

	int16_t load = (DSW_MAX_LOAD * busy_cycles) / passed;

	port->measurement_start = now;
	port->busy_cycles = 0;

	port->total_busy_cycles += busy_cycles;

	return load;
}

static void
dsw_port_load_update(struct dsw_port *port, uint64_t now)
{
	int16_t old_load;
	int16_t period_load;
	int16_t new_load;

	old_load = __atomic_load_n(&port->load, __ATOMIC_RELAXED);

	period_load = dsw_port_load_close_period(port, now);

	new_load = (period_load + old_load*DSW_OLD_LOAD_WEIGHT) /
		(DSW_OLD_LOAD_WEIGHT+1);

	__atomic_store_n(&port->load, new_load, __ATOMIC_RELAXED);

	/* The load of the recently immigrated flows should hopefully
	 * be reflected the load estimate by now.
	 */
	__atomic_store_n(&port->immigration_load, 0, __ATOMIC_RELAXED);
}

static void
dsw_port_consider_load_update(struct dsw_port *port, uint64_t now)
{
	if (now < port->next_load_update)
		return;

	port->next_load_update = now + port->load_update_interval;

	dsw_port_load_update(port, now);
}

static void
dsw_port_ctl_enqueue(struct dsw_port *port, struct dsw_ctl_msg *msg)
{
	/* there's always room on the ring */
	while (rte_ring_enqueue_elem(port->ctl_in_ring, msg, sizeof(*msg)) != 0)
		rte_pause();
}

static int
dsw_port_ctl_dequeue(struct dsw_port *port, struct dsw_ctl_msg *msg)
{
	return rte_ring_dequeue_elem(port->ctl_in_ring, msg, sizeof(*msg));
}

static void
dsw_port_ctl_broadcast(struct dsw_evdev *dsw, struct dsw_port *source_port,
		       uint8_t type, struct dsw_queue_flow *qfs,
		       uint8_t qfs_len)
{
	uint16_t port_id;
	struct dsw_ctl_msg msg = {
		.type = type,
		.originating_port_id = source_port->id,
		.qfs_len = qfs_len
	};

	memcpy(msg.qfs, qfs, sizeof(struct dsw_queue_flow) * qfs_len);

	for (port_id = 0; port_id < dsw->num_ports; port_id++)
		if (port_id != source_port->id)
			dsw_port_ctl_enqueue(&dsw->ports[port_id], &msg);
}

static __rte_always_inline bool
dsw_is_queue_flow_in_ary(const struct dsw_queue_flow *qfs, uint16_t qfs_len,
			 uint8_t queue_id, uint16_t flow_hash)
{
	uint16_t i;

	for (i = 0; i < qfs_len; i++)
		if (qfs[i].queue_id == queue_id &&
		    qfs[i].flow_hash == flow_hash)
			return true;

	return false;
}

static __rte_always_inline bool
dsw_port_is_flow_paused(struct dsw_port *port, uint8_t queue_id,
			uint16_t flow_hash)
{
	return dsw_is_queue_flow_in_ary(port->paused_flows,
					port->paused_flows_len,
					queue_id, flow_hash);
}

static __rte_always_inline bool
dsw_port_is_flow_migrating(struct dsw_port *port, uint8_t queue_id,
			   uint16_t flow_hash)
{
	return dsw_is_queue_flow_in_ary(port->emigration_target_qfs,
					port->emigration_targets_len,
					queue_id, flow_hash);
}

static void
dsw_port_add_paused_flows(struct dsw_port *port, struct dsw_queue_flow *qfs,
			  uint8_t qfs_len)
{
	uint8_t i;

	for (i = 0; i < qfs_len; i++) {
		struct dsw_queue_flow *qf = &qfs[i];

		DSW_LOG_DP_PORT(DEBUG, port->id,
				"Pausing queue_id %d flow_hash %d.\n",
				qf->queue_id, qf->flow_hash);

		port->paused_flows[port->paused_flows_len] = *qf;
		port->paused_flows_len++;
	};
}

static void
dsw_port_remove_paused_flow(struct dsw_port *port,
			    struct dsw_queue_flow *target_qf)
{
	uint16_t i;

	for (i = 0; i < port->paused_flows_len; i++) {
		struct dsw_queue_flow *qf = &port->paused_flows[i];

		if (qf->queue_id == target_qf->queue_id &&
		    qf->flow_hash == target_qf->flow_hash) {
			uint16_t last_idx = port->paused_flows_len-1;
			if (i != last_idx)
				port->paused_flows[i] =
					port->paused_flows[last_idx];
			port->paused_flows_len--;

			DSW_LOG_DP_PORT(DEBUG, port->id,
					"Unpausing queue_id %d flow_hash %d.\n",
					target_qf->queue_id,
					target_qf->flow_hash);

			return;
		}
	}

	DSW_LOG_DP_PORT(ERR, port->id,
			"Failed to unpause queue_id %d flow_hash %d.\n",
			target_qf->queue_id, target_qf->flow_hash);
}

static void
dsw_port_remove_paused_flows(struct dsw_port *port,
			     struct dsw_queue_flow *qfs, uint8_t qfs_len)
{
	uint8_t i;

	for (i = 0; i < qfs_len; i++)
		dsw_port_remove_paused_flow(port, &qfs[i]);
}

static void
dsw_port_flush_out_buffers(struct dsw_evdev *dsw, struct dsw_port *source_port);

static void
dsw_port_handle_pause_flows(struct dsw_evdev *dsw, struct dsw_port *port,
			    uint8_t originating_port_id,
			    struct dsw_queue_flow *paused_qfs,
			    uint8_t qfs_len)
{
	struct dsw_ctl_msg cfm = {
		.type = DSW_CTL_CFM,
		.originating_port_id = port->id
	};

	/* There might be already-scheduled events belonging to the
	 * paused flow in the output buffers.
	 */
	dsw_port_flush_out_buffers(dsw, port);

	dsw_port_add_paused_flows(port, paused_qfs, qfs_len);

	/* Make sure any stores to the original port's in_ring is seen
	 * before the ctl message.
	 */
	rte_smp_wmb();

	dsw_port_ctl_enqueue(&dsw->ports[originating_port_id], &cfm);
}

struct dsw_queue_flow_burst {
	struct dsw_queue_flow queue_flow;
	uint16_t count;
};

#define DSW_QF_TO_INT(_qf)					\
	((int)((((_qf)->queue_id)<<16)|((_qf)->flow_hash)))

static inline int
dsw_cmp_qf(const void *v_qf_a, const void *v_qf_b)
{
	const struct dsw_queue_flow *qf_a = v_qf_a;
	const struct dsw_queue_flow *qf_b = v_qf_b;

	return DSW_QF_TO_INT(qf_a) - DSW_QF_TO_INT(qf_b);
}

static uint16_t
dsw_sort_qfs_to_bursts(struct dsw_queue_flow *qfs, uint16_t qfs_len,
		       struct dsw_queue_flow_burst *bursts)
{
	uint16_t i;
	struct dsw_queue_flow_burst *current_burst = NULL;
	uint16_t num_bursts = 0;

	/* We don't need the stable property, and the list is likely
	 * large enough for qsort() to outperform dsw_stable_sort(),
	 * so we use qsort() here.
	 */
	qsort(qfs, qfs_len, sizeof(qfs[0]), dsw_cmp_qf);

	/* arrange the (now-consecutive) events into bursts */
	for (i = 0; i < qfs_len; i++) {
		if (i == 0 ||
		    dsw_cmp_qf(&qfs[i], &current_burst->queue_flow) != 0) {
			current_burst = &bursts[num_bursts];
			current_burst->queue_flow = qfs[i];
			current_burst->count = 0;
			num_bursts++;
		}
		current_burst->count++;
	}

	return num_bursts;
}

static bool
dsw_retrieve_port_loads(struct dsw_evdev *dsw, int16_t *port_loads,
			int16_t load_limit)
{
	bool below_limit = false;
	uint16_t i;

	for (i = 0; i < dsw->num_ports; i++) {
		int16_t measured_load =
			__atomic_load_n(&dsw->ports[i].load, __ATOMIC_RELAXED);
		int32_t immigration_load =
			__atomic_load_n(&dsw->ports[i].immigration_load,
					__ATOMIC_RELAXED);
		int32_t load = measured_load + immigration_load;

		load = RTE_MIN(load, DSW_MAX_LOAD);

		if (load < load_limit)
			below_limit = true;
		port_loads[i] = load;
	}
	return below_limit;
}

static int16_t
dsw_flow_load(uint16_t num_events, int16_t port_load)
{
	return ((int32_t)port_load * (int32_t)num_events) /
		DSW_MAX_EVENTS_RECORDED;
}

static int16_t
dsw_evaluate_migration(int16_t source_load, int16_t target_load,
		       int16_t flow_load)
{
	int32_t res_target_load;
	int32_t imbalance;

	if (target_load > DSW_MAX_TARGET_LOAD_FOR_MIGRATION)
		return -1;

	imbalance = source_load - target_load;

	if (imbalance < DSW_REBALANCE_THRESHOLD)
		return -1;

	res_target_load = target_load + flow_load;

	/* If the estimated load of the target port will be higher
	 * than the source port's load, it doesn't make sense to move
	 * the flow.
	 */
	if (res_target_load > source_load)
		return -1;

	/* The more idle the target will be, the better. This will
	 * make migration prefer moving smaller flows, and flows to
	 * lightly loaded ports.
	 */
	return DSW_MAX_LOAD - res_target_load;
}

static bool
dsw_is_serving_port(struct dsw_evdev *dsw, uint8_t port_id, uint8_t queue_id)
{
	struct dsw_queue *queue = &dsw->queues[queue_id];
	uint16_t i;

	for (i = 0; i < queue->num_serving_ports; i++)
		if (queue->serving_ports[i] == port_id)
			return true;

	return false;
}

static bool
dsw_select_emigration_target(struct dsw_evdev *dsw,
			     struct dsw_port *source_port,
			     struct dsw_queue_flow_burst *bursts,
			     uint16_t num_bursts,
			     int16_t *port_loads, uint16_t num_ports,
			     uint8_t *target_port_ids,
			     struct dsw_queue_flow *target_qfs,
			     uint8_t *targets_len)
{
	int16_t source_port_load = port_loads[source_port->id];
	struct dsw_queue_flow *candidate_qf = NULL;
	uint8_t candidate_port_id = 0;
	int16_t candidate_weight = -1;
	int16_t candidate_flow_load = -1;
	uint16_t i;

	if (source_port_load < DSW_MIN_SOURCE_LOAD_FOR_MIGRATION)
		return false;

	for (i = 0; i < num_bursts; i++) {
		struct dsw_queue_flow_burst *burst = &bursts[i];
		struct dsw_queue_flow *qf = &burst->queue_flow;
		int16_t flow_load;
		uint16_t port_id;

		if (dsw_is_queue_flow_in_ary(target_qfs, *targets_len,
					     qf->queue_id, qf->flow_hash))
			continue;

		flow_load = dsw_flow_load(burst->count, source_port_load);

		for (port_id = 0; port_id < num_ports; port_id++) {
			int16_t weight;

			if (port_id == source_port->id)
				continue;

			if (!dsw_is_serving_port(dsw, port_id, qf->queue_id))
				continue;

			weight = dsw_evaluate_migration(source_port_load,
							port_loads[port_id],
							flow_load);

			if (weight > candidate_weight) {
				candidate_qf = qf;
				candidate_port_id = port_id;
				candidate_weight = weight;
				candidate_flow_load = flow_load;
			}
		}
	}

	if (candidate_weight < 0)
		return false;

	DSW_LOG_DP_PORT(DEBUG, source_port->id, "Selected queue_id %d "
			"flow_hash %d (with flow load %d) for migration "
			"to port %d.\n", candidate_qf->queue_id,
			candidate_qf->flow_hash,
			DSW_LOAD_TO_PERCENT(candidate_flow_load),
			candidate_port_id);

	port_loads[candidate_port_id] += candidate_flow_load;
	port_loads[source_port->id] -= candidate_flow_load;

	target_port_ids[*targets_len] = candidate_port_id;
	target_qfs[*targets_len] = *candidate_qf;
	(*targets_len)++;

	__atomic_add_fetch(&dsw->ports[candidate_port_id].immigration_load,
			   candidate_flow_load, __ATOMIC_RELAXED);

	return true;
}

static void
dsw_select_emigration_targets(struct dsw_evdev *dsw,
			      struct dsw_port *source_port,
			      struct dsw_queue_flow_burst *bursts,
			      uint16_t num_bursts, int16_t *port_loads)
{
	struct dsw_queue_flow *target_qfs = source_port->emigration_target_qfs;
	uint8_t *target_port_ids = source_port->emigration_target_port_ids;
	uint8_t *targets_len = &source_port->emigration_targets_len;
	uint16_t i;

	for (i = 0; i < DSW_MAX_FLOWS_PER_MIGRATION; i++) {
		bool found;

		found = dsw_select_emigration_target(dsw, source_port,
						     bursts, num_bursts,
						     port_loads, dsw->num_ports,
						     target_port_ids,
						     target_qfs,
						     targets_len);
		if (!found)
			break;
	}

	if (*targets_len == 0)
		DSW_LOG_DP_PORT(DEBUG, source_port->id,
				"For the %d flows considered, no target port "
				"was found.\n", num_bursts);
}

static uint8_t
dsw_schedule(struct dsw_evdev *dsw, uint8_t queue_id, uint16_t flow_hash)
{
	struct dsw_queue *queue = &dsw->queues[queue_id];
	uint8_t port_id;

	if (queue->num_serving_ports > 1)
		port_id = queue->flow_to_port_map[flow_hash];
	else
		/* A single-link queue, or atomic/ordered/parallel but
		 * with just a single serving port.
		 */
		port_id = queue->serving_ports[0];

	DSW_LOG_DP(DEBUG, "Event with queue_id %d flow_hash %d is scheduled "
		   "to port %d.\n", queue_id, flow_hash, port_id);

	return port_id;
}

static void
dsw_port_transmit_buffered(struct dsw_evdev *dsw, struct dsw_port *source_port,
			   uint8_t dest_port_id)
{
	struct dsw_port *dest_port = &(dsw->ports[dest_port_id]);
	uint16_t *buffer_len = &source_port->out_buffer_len[dest_port_id];
	struct rte_event *buffer = source_port->out_buffer[dest_port_id];
	uint16_t enqueued = 0;

	if (*buffer_len == 0)
		return;

	/* The rings are dimensioned to fit all in-flight events (even
	 * on a single ring), so looping will work.
	 */
	do {
		enqueued +=
			rte_event_ring_enqueue_burst(dest_port->in_ring,
						     buffer+enqueued,
						     *buffer_len-enqueued,
						     NULL);
	} while (unlikely(enqueued != *buffer_len));

	(*buffer_len) = 0;
}

static uint16_t
dsw_port_get_parallel_flow_id(struct dsw_port *port)
{
	uint16_t flow_id = port->next_parallel_flow_id;

	port->next_parallel_flow_id =
		(port->next_parallel_flow_id + 1) % DSW_PARALLEL_FLOWS;

	return flow_id;
}

static void
dsw_port_buffer_paused(struct dsw_port *port,
		       const struct rte_event *paused_event)
{
	port->paused_events[port->paused_events_len] = *paused_event;
	port->paused_events_len++;
}


static void
dsw_port_buffer_non_paused(struct dsw_evdev *dsw, struct dsw_port *source_port,
			   uint8_t dest_port_id, const struct rte_event *event)
{
	struct rte_event *buffer = source_port->out_buffer[dest_port_id];
	uint16_t *buffer_len = &source_port->out_buffer_len[dest_port_id];

	if (*buffer_len == DSW_MAX_PORT_OUT_BUFFER)
		dsw_port_transmit_buffered(dsw, source_port, dest_port_id);

	buffer[*buffer_len] = *event;

	(*buffer_len)++;
}

#define DSW_FLOW_ID_BITS (24)
static uint16_t
dsw_flow_id_hash(uint32_t flow_id)
{
	uint16_t hash = 0;
	uint16_t offset = 0;

	do {
		hash ^= ((flow_id >> offset) & DSW_MAX_FLOWS_MASK);
		offset += DSW_MAX_FLOWS_BITS;
	} while (offset < DSW_FLOW_ID_BITS);

	return hash;
}

static void
dsw_port_buffer_parallel(struct dsw_evdev *dsw, struct dsw_port *source_port,
			 struct rte_event event)
{
	uint8_t dest_port_id;

	event.flow_id = dsw_port_get_parallel_flow_id(source_port);

	dest_port_id = dsw_schedule(dsw, event.queue_id,
				    dsw_flow_id_hash(event.flow_id));

	dsw_port_buffer_non_paused(dsw, source_port, dest_port_id, &event);
}

static void
dsw_port_buffer_event(struct dsw_evdev *dsw, struct dsw_port *source_port,
		      const struct rte_event *event)
{
	uint16_t flow_hash;
	uint8_t dest_port_id;

	if (unlikely(dsw->queues[event->queue_id].schedule_type ==
		     RTE_SCHED_TYPE_PARALLEL)) {
		dsw_port_buffer_parallel(dsw, source_port, *event);
		return;
	}

	flow_hash = dsw_flow_id_hash(event->flow_id);

	if (unlikely(dsw_port_is_flow_paused(source_port, event->queue_id,
					     flow_hash))) {
		dsw_port_buffer_paused(source_port, event);
		return;
	}

	dest_port_id = dsw_schedule(dsw, event->queue_id, flow_hash);

	dsw_port_buffer_non_paused(dsw, source_port, dest_port_id, event);
}

static void
dsw_port_flush_no_longer_paused_events(struct dsw_evdev *dsw,
				       struct dsw_port *source_port)
{
	uint16_t paused_events_len = source_port->paused_events_len;
	struct rte_event paused_events[paused_events_len];
	uint16_t i;

	if (paused_events_len == 0)
		return;

	rte_memcpy(paused_events, source_port->paused_events,
		   paused_events_len * sizeof(struct rte_event));

	source_port->paused_events_len = 0;

	for (i = 0; i < paused_events_len; i++) {
		struct rte_event *event = &paused_events[i];
		uint16_t flow_hash;

		flow_hash = dsw_flow_id_hash(event->flow_id);

		if (dsw_port_is_flow_paused(source_port, event->queue_id,
					    flow_hash))
			dsw_port_buffer_paused(source_port, event);
		else {
			uint8_t dest_port_id;

			dest_port_id = dsw_schedule(dsw, event->queue_id,
						    flow_hash);

			dsw_port_buffer_non_paused(dsw, source_port,
						   dest_port_id, event);
		}
	}
}

static void
dsw_port_emigration_stats(struct dsw_port *port, uint8_t finished)
{
	uint64_t flow_migration_latency;

	flow_migration_latency =
		(rte_get_timer_cycles() - port->emigration_start);
	port->emigration_latency += (flow_migration_latency * finished);
	port->emigrations += finished;
}

static void
dsw_port_end_emigration(struct dsw_evdev *dsw, struct dsw_port *port,
			uint8_t schedule_type)
{
	uint8_t i;
	struct dsw_queue_flow left_qfs[DSW_MAX_FLOWS_PER_MIGRATION];
	uint8_t left_port_ids[DSW_MAX_FLOWS_PER_MIGRATION];
	uint8_t left_qfs_len = 0;
	uint8_t finished;

	for (i = 0; i < port->emigration_targets_len; i++) {
		struct dsw_queue_flow *qf = &port->emigration_target_qfs[i];
		uint8_t queue_id = qf->queue_id;
		uint8_t queue_schedule_type =
			dsw->queues[queue_id].schedule_type;
		uint16_t flow_hash = qf->flow_hash;

		if (queue_schedule_type != schedule_type) {
			left_port_ids[left_qfs_len] =
				port->emigration_target_port_ids[i];
			left_qfs[left_qfs_len] = *qf;
			left_qfs_len++;
			continue;
		}

		DSW_LOG_DP_PORT(DEBUG, port->id, "Migration completed for "
				"queue_id %d flow_hash %d.\n", queue_id,
				flow_hash);
	}

	finished = port->emigration_targets_len - left_qfs_len;

	if (finished > 0)
		dsw_port_emigration_stats(port, finished);

	for (i = 0; i < left_qfs_len; i++) {
		port->emigration_target_port_ids[i] = left_port_ids[i];
		port->emigration_target_qfs[i] = left_qfs[i];
	}
	port->emigration_targets_len = left_qfs_len;

	if (port->emigration_targets_len == 0) {
		port->migration_state = DSW_MIGRATION_STATE_IDLE;
		port->seen_events_len = 0;
	}
}

static void
dsw_port_move_parallel_flows(struct dsw_evdev *dsw,
			     struct dsw_port *source_port)
{
	uint8_t i;

	for (i = 0; i < source_port->emigration_targets_len; i++) {
		struct dsw_queue_flow *qf =
			&source_port->emigration_target_qfs[i];
		uint8_t queue_id = qf->queue_id;

		if (dsw->queues[queue_id].schedule_type ==
		    RTE_SCHED_TYPE_PARALLEL) {
			uint8_t dest_port_id =
				source_port->emigration_target_port_ids[i];
			uint16_t flow_hash = qf->flow_hash;

			/* Single byte-sized stores are always atomic. */
			dsw->queues[queue_id].flow_to_port_map[flow_hash] =
				dest_port_id;
		}
	}

	rte_smp_wmb();

	dsw_port_end_emigration(dsw, source_port, RTE_SCHED_TYPE_PARALLEL);
}

static void
dsw_port_consider_emigration(struct dsw_evdev *dsw,
			     struct dsw_port *source_port,
			     uint64_t now)
{
	bool any_port_below_limit;
	struct dsw_queue_flow *seen_events = source_port->seen_events;
	uint16_t seen_events_len = source_port->seen_events_len;
	struct dsw_queue_flow_burst bursts[DSW_MAX_EVENTS_RECORDED];
	uint16_t num_bursts;
	int16_t source_port_load;
	int16_t port_loads[dsw->num_ports];

	if (now < source_port->next_emigration)
		return;

	if (dsw->num_ports == 1)
		return;

	DSW_LOG_DP_PORT(DEBUG, source_port->id, "Considering emigration.\n");

	if (seen_events_len < DSW_MAX_EVENTS_RECORDED) {
		DSW_LOG_DP_PORT(DEBUG, source_port->id, "Not enough events "
				"are recorded to allow for a migration.\n");
		return;
	}

	/* A flow migration cannot be initiated if there are paused
	 * events, since some/all of those events may be have been
	 * produced as a result of processing the flow(s) selected for
	 * migration. Moving such a flow would potentially introduced
	 * reordering, since processing the migrated flow on the
	 * receiving flow may commence before the to-be-enqueued-to

	 * flows are unpaused, leading to paused events on the second
	 * port as well, destined for the same paused flow(s). When
	 * those flows are unpaused, the resulting events are
	 * delivered the owning port in an undefined order.
	 */
	if (source_port->paused_events_len > 0) {
		DSW_LOG_DP_PORT(DEBUG, source_port->id, "There are "
				"events in the paus buffer.\n");
		return;
	}

	/* Randomize interval to avoid having all threads considering
	 * emigration at the same in point in time, which might lead
	 * to all choosing the same target port.
	 */
	source_port->next_emigration = now +
		source_port->migration_interval / 2 +
		rte_rand() % source_port->migration_interval;

	if (source_port->migration_state != DSW_MIGRATION_STATE_IDLE) {
		DSW_LOG_DP_PORT(DEBUG, source_port->id,
				"Emigration already in progress.\n");
		return;
	}

	/* For simplicity, avoid migration in the unlikely case there
	 * is still events to consume in the in_buffer (from the last
	 * emigration).
	 */
	if (source_port->in_buffer_len > 0) {
		DSW_LOG_DP_PORT(DEBUG, source_port->id, "There are still "
				"events in the input buffer.\n");
		return;
	}

	source_port_load =
		__atomic_load_n(&source_port->load, __ATOMIC_RELAXED);
	if (source_port_load < DSW_MIN_SOURCE_LOAD_FOR_MIGRATION) {
		DSW_LOG_DP_PORT(DEBUG, source_port->id,
		      "Load %d is below threshold level %d.\n",
		      DSW_LOAD_TO_PERCENT(source_port_load),
		      DSW_LOAD_TO_PERCENT(DSW_MIN_SOURCE_LOAD_FOR_MIGRATION));
		return;
	}

	/* Avoid starting any expensive operations (sorting etc), in
	 * case of a scenario with all ports above the load limit.
	 */
	any_port_below_limit =
		dsw_retrieve_port_loads(dsw, port_loads,
					DSW_MAX_TARGET_LOAD_FOR_MIGRATION);
	if (!any_port_below_limit) {
		DSW_LOG_DP_PORT(DEBUG, source_port->id,
				"Candidate target ports are all too highly "
				"loaded.\n");
		return;
	}

	num_bursts = dsw_sort_qfs_to_bursts(seen_events, seen_events_len,
					    bursts);

	/* For non-big-little systems, there's no point in moving the
	 * only (known) flow.
	 */
	if (num_bursts < 2) {
		DSW_LOG_DP_PORT(DEBUG, source_port->id, "Only a single flow "
				"queue_id %d flow_hash %d has been seen.\n",
				bursts[0].queue_flow.queue_id,
				bursts[0].queue_flow.flow_hash);
		return;
	}

	dsw_select_emigration_targets(dsw, source_port, bursts, num_bursts,
				      port_loads);

	if (source_port->emigration_targets_len == 0)
		return;

	source_port->migration_state = DSW_MIGRATION_STATE_PAUSING;
	source_port->emigration_start = rte_get_timer_cycles();

	/* No need to go through the whole pause procedure for
	 * parallel queues, since atomic/ordered semantics need not to
	 * be maintained.
	 */
	dsw_port_move_parallel_flows(dsw, source_port);

	/* All flows were on PARALLEL queues. */
	if (source_port->migration_state == DSW_MIGRATION_STATE_IDLE)
		return;

	/* There might be 'loopback' events already scheduled in the
	 * output buffers.
	 */
	dsw_port_flush_out_buffers(dsw, source_port);

	dsw_port_add_paused_flows(source_port,
				  source_port->emigration_target_qfs,
				  source_port->emigration_targets_len);

	dsw_port_ctl_broadcast(dsw, source_port, DSW_CTL_PAUS_REQ,
			       source_port->emigration_target_qfs,
			       source_port->emigration_targets_len);
	source_port->cfm_cnt = 0;
}

static void
dsw_port_flush_no_longer_paused_events(struct dsw_evdev *dsw,
				       struct dsw_port *source_port);

static void
dsw_port_handle_unpause_flows(struct dsw_evdev *dsw, struct dsw_port *port,
			      uint8_t originating_port_id,
			      struct dsw_queue_flow *paused_qfs,
			      uint8_t qfs_len)
{
	uint16_t i;
	struct dsw_ctl_msg cfm = {
		.type = DSW_CTL_CFM,
		.originating_port_id = port->id
	};

	dsw_port_remove_paused_flows(port, paused_qfs, qfs_len);

	rte_smp_rmb();

	dsw_port_ctl_enqueue(&dsw->ports[originating_port_id], &cfm);

	for (i = 0; i < qfs_len; i++) {
		struct dsw_queue_flow *qf = &paused_qfs[i];

		if (dsw_schedule(dsw, qf->queue_id, qf->flow_hash) == port->id)
			port->immigrations++;
	}

	dsw_port_flush_no_longer_paused_events(dsw, port);
}

static void
dsw_port_buffer_in_buffer(struct dsw_port *port,
			  const struct rte_event *event)

{
	RTE_ASSERT(port->in_buffer_start == 0);

	port->in_buffer[port->in_buffer_len] = *event;
	port->in_buffer_len++;
}

static void
dsw_port_forward_emigrated_event(struct dsw_evdev *dsw,
				 struct dsw_port *source_port,
				 struct rte_event *event)
{
	uint16_t i;

	for (i = 0; i < source_port->emigration_targets_len; i++) {
		struct dsw_queue_flow *qf =
			&source_port->emigration_target_qfs[i];
		uint8_t dest_port_id =
			source_port->emigration_target_port_ids[i];
		struct dsw_port *dest_port = &dsw->ports[dest_port_id];

		if (event->queue_id == qf->queue_id &&
		    dsw_flow_id_hash(event->flow_id) == qf->flow_hash) {
			/* No need to care about bursting forwarded
			 * events (to the destination port's in_ring),
			 * since migration doesn't happen very often,
			 * and also the majority of the dequeued
			 * events will likely *not* be forwarded.
			 */
			while (rte_event_ring_enqueue_burst(dest_port->in_ring,
							    event, 1,
							    NULL) != 1)
				rte_pause();
			return;
		}
	}

	/* Event did not belong to the emigrated flows */
	dsw_port_buffer_in_buffer(source_port, event);
}

static void
dsw_port_stash_migrating_event(struct dsw_port *port,
			       const struct rte_event *event)
{
	port->emigrating_events[port->emigrating_events_len] = *event;
	port->emigrating_events_len++;
}

#define DRAIN_DEQUEUE_BURST_SIZE (32)

static void
dsw_port_drain_in_ring(struct dsw_port *source_port)
{
	uint16_t num_events;
	uint16_t dequeued;

	/* Control ring message should been seen before the ring count
	 * is read on the port's in_ring.
	 */
	rte_smp_rmb();

	num_events = rte_event_ring_count(source_port->in_ring);

	for (dequeued = 0; dequeued < num_events; ) {
		uint16_t burst_size = RTE_MIN(DRAIN_DEQUEUE_BURST_SIZE,
					      num_events - dequeued);
		struct rte_event events[burst_size];
		uint16_t len;
		uint16_t i;

		len = rte_event_ring_dequeue_burst(source_port->in_ring,
						   events, burst_size,
						   NULL);

		for (i = 0; i < len; i++) {
			struct rte_event *event = &events[i];
			uint16_t flow_hash;

			flow_hash = dsw_flow_id_hash(event->flow_id);

			if (unlikely(dsw_port_is_flow_migrating(source_port,
								event->queue_id,
								flow_hash)))
				dsw_port_stash_migrating_event(source_port,
							       event);
			else
				dsw_port_buffer_in_buffer(source_port, event);
		}

		dequeued += len;
	}
}

static void
dsw_port_forward_emigrated_flows(struct dsw_evdev *dsw,
				 struct dsw_port *source_port)
{
	uint16_t i;

	for (i = 0; i < source_port->emigrating_events_len; i++) {
		struct rte_event *event = &source_port->emigrating_events[i];

		dsw_port_forward_emigrated_event(dsw, source_port, event);
	}
	source_port->emigrating_events_len = 0;
}

static void
dsw_port_move_emigrating_flows(struct dsw_evdev *dsw,
			       struct dsw_port *source_port)
{
	uint8_t i;

	dsw_port_flush_out_buffers(dsw, source_port);

	for (i = 0; i < source_port->emigration_targets_len; i++) {
		struct dsw_queue_flow *qf =
			&source_port->emigration_target_qfs[i];
		uint8_t dest_port_id =
			source_port->emigration_target_port_ids[i];

		dsw->queues[qf->queue_id].flow_to_port_map[qf->flow_hash] =
		    dest_port_id;
	}

	rte_smp_wmb();

	dsw_port_drain_in_ring(source_port);
	dsw_port_forward_emigrated_flows(dsw, source_port);

	dsw_port_remove_paused_flows(source_port,
				     source_port->emigration_target_qfs,
				     source_port->emigration_targets_len);

	dsw_port_flush_no_longer_paused_events(dsw, source_port);

	/* Flow table update and migration destination port's enqueues
	 * must be seen before the control message.
	 */
	rte_smp_wmb();

	dsw_port_ctl_broadcast(dsw, source_port, DSW_CTL_UNPAUS_REQ,
			       source_port->emigration_target_qfs,
			       source_port->emigration_targets_len);
	source_port->cfm_cnt = 0;
	source_port->migration_state = DSW_MIGRATION_STATE_UNPAUSING;
}

static void
dsw_port_handle_confirm(struct dsw_evdev *dsw, struct dsw_port *port)
{
	port->cfm_cnt++;

	if (port->cfm_cnt == (dsw->num_ports-1)) {
		switch (port->migration_state) {
		case DSW_MIGRATION_STATE_PAUSING:
			dsw_port_move_emigrating_flows(dsw, port);
			break;
		case DSW_MIGRATION_STATE_UNPAUSING:
			dsw_port_end_emigration(dsw, port,
						RTE_SCHED_TYPE_ATOMIC);
			break;
		default:
			RTE_ASSERT(0);
			break;
		}
	}
}

static void
dsw_port_ctl_process(struct dsw_evdev *dsw, struct dsw_port *port)
{
	struct dsw_ctl_msg msg;

	if (dsw_port_ctl_dequeue(port, &msg) == 0) {
		switch (msg.type) {
		case DSW_CTL_PAUS_REQ:
			dsw_port_handle_pause_flows(dsw, port,
						    msg.originating_port_id,
						    msg.qfs, msg.qfs_len);
			break;
		case DSW_CTL_UNPAUS_REQ:
			dsw_port_handle_unpause_flows(dsw, port,
						      msg.originating_port_id,
						      msg.qfs, msg.qfs_len);
			break;
		case DSW_CTL_CFM:
			dsw_port_handle_confirm(dsw, port);
			break;
		}
	}
}

static void
dsw_port_note_op(struct dsw_port *port, uint16_t num_events)
{
	port->ops_since_bg_task += (num_events+1);
}

static void
dsw_port_bg_process(struct dsw_evdev *dsw, struct dsw_port *port)
{
	/* For simplicity (in the migration logic), avoid all
	 * background processing in case event processing is in
	 * progress.
	 */
	if (port->pending_releases > 0)
		return;

	/* Polling the control ring is relatively inexpensive, and
	 * polling it often helps bringing down migration latency, so
	 * do this for every iteration.
	 */
	dsw_port_ctl_process(dsw, port);

	/* To avoid considering migration and flushing output buffers
	 * on every dequeue/enqueue call, the scheduler only performs
	 * such 'background' tasks every nth
	 * (i.e. DSW_MAX_PORT_OPS_PER_BG_TASK) operation.
	 */
	if (unlikely(port->ops_since_bg_task >= DSW_MAX_PORT_OPS_PER_BG_TASK)) {
		uint64_t now;

		now = rte_get_timer_cycles();

		port->last_bg = now;

		/* Logic to avoid having events linger in the output
		 * buffer too long.
		 */
		dsw_port_flush_out_buffers(dsw, port);

		dsw_port_consider_load_update(port, now);

		dsw_port_consider_emigration(dsw, port, now);

		port->ops_since_bg_task = 0;
	}
}

static void
dsw_port_flush_out_buffers(struct dsw_evdev *dsw, struct dsw_port *source_port)
{
	uint16_t dest_port_id;

	for (dest_port_id = 0; dest_port_id < dsw->num_ports; dest_port_id++)
		dsw_port_transmit_buffered(dsw, source_port, dest_port_id);
}

uint16_t
dsw_event_enqueue(void *port, const struct rte_event *ev)
{
	return dsw_event_enqueue_burst(port, ev, unlikely(ev == NULL) ? 0 : 1);
}

static __rte_always_inline uint16_t
dsw_event_enqueue_burst_generic(struct dsw_port *source_port,
				const struct rte_event events[],
				uint16_t events_len, bool op_types_known,
				uint16_t num_new, uint16_t num_release,
				uint16_t num_non_release)
{
	struct dsw_evdev *dsw = source_port->dsw;
	bool enough_credits;
	uint16_t i;

	DSW_LOG_DP_PORT(DEBUG, source_port->id, "Attempting to enqueue %d "
			"events.\n", events_len);

	dsw_port_bg_process(dsw, source_port);

	/* XXX: For performance (=ring efficiency) reasons, the
	 * scheduler relies on internal non-ring buffers instead of
	 * immediately sending the event to the destination ring. For
	 * a producer that doesn't intend to produce or consume any
	 * more events, the scheduler provides a way to flush the
	 * buffer, by means of doing an enqueue of zero events. In
	 * addition, a port cannot be left "unattended" (e.g. unused)
	 * for long periods of time, since that would stall
	 * migration. Eventdev API extensions to provide a cleaner way
	 * to archive both of these functions should be
	 * considered.
	 */
	if (unlikely(events_len == 0)) {
		dsw_port_note_op(source_port, DSW_MAX_PORT_OPS_PER_BG_TASK);
		dsw_port_flush_out_buffers(dsw, source_port);
		return 0;
	}

	dsw_port_note_op(source_port, events_len);

	if (!op_types_known)
		for (i = 0; i < events_len; i++) {
			switch (events[i].op) {
			case RTE_EVENT_OP_RELEASE:
				num_release++;
				break;
			case RTE_EVENT_OP_NEW:
				num_new++;
				/* Falls through. */
			default:
				num_non_release++;
				break;
			}
		}

	/* Technically, we could allow the non-new events up to the
	 * first new event in the array into the system, but for
	 * simplicity reasons, we deny the whole burst if the port is
	 * above the water mark.
	 */
	if (unlikely(num_new > 0 &&
		     __atomic_load_n(&dsw->credits_on_loan, __ATOMIC_RELAXED) >
		     source_port->new_event_threshold))
		return 0;

	enough_credits = dsw_port_acquire_credits(dsw, source_port,
						  num_non_release);
	if (unlikely(!enough_credits))
		return 0;

	source_port->pending_releases -= num_release;

	dsw_port_enqueue_stats(source_port, num_new,
			       num_non_release-num_new, num_release);

	for (i = 0; i < events_len; i++) {
		const struct rte_event *event = &events[i];

		if (likely(num_release == 0 ||
			   event->op != RTE_EVENT_OP_RELEASE))
			dsw_port_buffer_event(dsw, source_port, event);
		dsw_port_queue_enqueue_stats(source_port, event->queue_id);
	}

	DSW_LOG_DP_PORT(DEBUG, source_port->id, "%d non-release events "
			"accepted.\n", num_non_release);

	return (num_non_release + num_release);
}

uint16_t
dsw_event_enqueue_burst(void *port, const struct rte_event events[],
			uint16_t events_len)
{
	struct dsw_port *source_port = port;

	if (unlikely(events_len > source_port->enqueue_depth))
		events_len = source_port->enqueue_depth;

	return dsw_event_enqueue_burst_generic(source_port, events,
					       events_len, false, 0, 0, 0);
}

uint16_t
dsw_event_enqueue_new_burst(void *port, const struct rte_event events[],
			    uint16_t events_len)
{
	struct dsw_port *source_port = port;

	if (unlikely(events_len > source_port->enqueue_depth))
		events_len = source_port->enqueue_depth;

	return dsw_event_enqueue_burst_generic(source_port, events,
					       events_len, true, events_len,
					       0, events_len);
}

uint16_t
dsw_event_enqueue_forward_burst(void *port, const struct rte_event events[],
				uint16_t events_len)
{
	struct dsw_port *source_port = port;

	if (unlikely(events_len > source_port->enqueue_depth))
		events_len = source_port->enqueue_depth;

	return dsw_event_enqueue_burst_generic(source_port, events,
					       events_len, true, 0, 0,
					       events_len);
}

uint16_t
dsw_event_dequeue(void *port, struct rte_event *events, uint64_t wait)
{
	return dsw_event_dequeue_burst(port, events, 1, wait);
}

static void
dsw_port_record_seen_events(struct dsw_port *port, struct rte_event *events,
			    uint16_t num)
{
	uint16_t i;

	dsw_port_dequeue_stats(port, num);

	for (i = 0; i < num; i++) {
		uint16_t l_idx = port->seen_events_idx;
		struct dsw_queue_flow *qf = &port->seen_events[l_idx];
		struct rte_event *event = &events[i];
		qf->queue_id = event->queue_id;
		qf->flow_hash = dsw_flow_id_hash(event->flow_id);

		port->seen_events_idx = (l_idx+1) % DSW_MAX_EVENTS_RECORDED;

		dsw_port_queue_dequeued_stats(port, event->queue_id);
	}

	if (unlikely(port->seen_events_len != DSW_MAX_EVENTS_RECORDED))
		port->seen_events_len =
			RTE_MIN(port->seen_events_len + num,
				DSW_MAX_EVENTS_RECORDED);
}

#ifdef DSW_SORT_DEQUEUED

#define DSW_EVENT_TO_INT(_event)				\
	((int)((((_event)->queue_id)<<16)|((_event)->flow_id)))

static inline int
dsw_cmp_event(const void *v_event_a, const void *v_event_b)
{
	const struct rte_event *event_a = v_event_a;
	const struct rte_event *event_b = v_event_b;

	return DSW_EVENT_TO_INT(event_a) - DSW_EVENT_TO_INT(event_b);
}
#endif

static uint16_t
dsw_port_dequeue_burst(struct dsw_port *port, struct rte_event *events,
		       uint16_t num)
{
	if (unlikely(port->in_buffer_len > 0)) {
		uint16_t dequeued = RTE_MIN(num, port->in_buffer_len);

		rte_memcpy(events, &port->in_buffer[port->in_buffer_start],
			   dequeued * sizeof(struct rte_event));

		port->in_buffer_start += dequeued;
		port->in_buffer_len -= dequeued;

		if (port->in_buffer_len == 0)
			port->in_buffer_start = 0;

		return dequeued;
	}

	return rte_event_ring_dequeue_burst(port->in_ring, events, num, NULL);
}

static void
dsw_port_stash_migrating_events(struct dsw_port *port,
				struct rte_event *events, uint16_t *num)
{
	uint16_t i;

	/* The assumption here - performance-wise - is that events
	 * belonging to migrating flows are relatively rare.
	 */
	for (i = 0; i < (*num); ) {
		struct rte_event *event = &events[i];
		uint16_t flow_hash;

		flow_hash = dsw_flow_id_hash(event->flow_id);

		if (unlikely(dsw_port_is_flow_migrating(port, event->queue_id,
							flow_hash))) {
			uint16_t left;

			dsw_port_stash_migrating_event(port, event);

			(*num)--;
			left = *num - i;

			if (left > 0)
				memmove(event, event + 1,
					left * sizeof(struct rte_event));
		} else
			i++;
	}
}

uint16_t
dsw_event_dequeue_burst(void *port, struct rte_event *events, uint16_t num,
			uint64_t wait __rte_unused)
{
	struct dsw_port *source_port = port;
	struct dsw_evdev *dsw = source_port->dsw;
	uint16_t dequeued;

	source_port->pending_releases = 0;

	dsw_port_bg_process(dsw, source_port);

	if (unlikely(num > source_port->dequeue_depth))
		num = source_port->dequeue_depth;

	dequeued = dsw_port_dequeue_burst(source_port, events, num);

	if (unlikely(source_port->migration_state ==
		     DSW_MIGRATION_STATE_PAUSING))
		dsw_port_stash_migrating_events(source_port, events,
						&dequeued);

	source_port->pending_releases = dequeued;

	dsw_port_load_record(source_port, dequeued);

	dsw_port_note_op(source_port, dequeued);

	if (dequeued > 0) {
		DSW_LOG_DP_PORT(DEBUG, source_port->id, "Dequeued %d events.\n",
				dequeued);

		dsw_port_return_credits(dsw, source_port, dequeued);

		/* One potential optimization one might think of is to
		 * add a migration state (prior to 'pausing'), and
		 * only record seen events when the port is in this
		 * state (and transit to 'pausing' when enough events
		 * have been gathered). However, that schema doesn't
		 * seem to improve performance.
		 */
		dsw_port_record_seen_events(port, events, dequeued);
	} else /* Zero-size dequeue means a likely idle port, and thus
		* we can afford trading some efficiency for a slightly
		* reduced event wall-time latency.
		*/
		dsw_port_flush_out_buffers(dsw, port);

#ifdef DSW_SORT_DEQUEUED
	dsw_stable_sort(events, dequeued, sizeof(events[0]), dsw_cmp_event);
#endif

	return dequeued;
}

void dsw_event_maintain(void *port, int op)
{
	struct dsw_port *source_port = port;
	struct dsw_evdev *dsw = source_port->dsw;

	dsw_port_note_op(source_port, 0);
	dsw_port_bg_process(dsw, source_port);

	if (op & RTE_EVENT_DEV_MAINT_OP_FLUSH)
		dsw_port_flush_out_buffers(dsw, source_port);
}
