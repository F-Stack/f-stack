/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Cavium, Inc
 */

#include "test_perf_common.h"

/* See http://doc.dpdk.org/guides/tools/testeventdev.html for test details */

static inline int
perf_queue_nb_event_queues(struct evt_options *opt)
{
	/* nb_queues = number of producers * number of stages */
	uint8_t nb_prod = opt->prod_type == EVT_PROD_TYPE_ETH_RX_ADPTR ?
		rte_eth_dev_count_avail() : evt_nr_active_lcores(opt->plcores);
	return nb_prod * opt->nb_stages;
}

static inline __attribute__((always_inline)) void
mark_fwd_latency(struct rte_event *const ev,
		const uint8_t nb_stages)
{
	if (unlikely((ev->queue_id % nb_stages) == 0)) {
		struct perf_elt *const m = ev->event_ptr;

		m->timestamp = rte_get_timer_cycles();
	}
}

static inline __attribute__((always_inline)) void
fwd_event(struct rte_event *const ev, uint8_t *const sched_type_list,
		const uint8_t nb_stages)
{
	ev->queue_id++;
	ev->sched_type = sched_type_list[ev->queue_id % nb_stages];
	ev->op = RTE_EVENT_OP_FORWARD;
	ev->event_type = RTE_EVENT_TYPE_CPU;
}

static int
perf_queue_worker(void *arg, const int enable_fwd_latency)
{
	PERF_WORKER_INIT;
	struct rte_event ev;

	while (t->done == false) {
		uint16_t event = rte_event_dequeue_burst(dev, port, &ev, 1, 0);

		if (!event) {
			rte_pause();
			continue;
		}
		if (enable_fwd_latency && !prod_timer_type)
		/* first q in pipeline, mark timestamp to compute fwd latency */
			mark_fwd_latency(&ev, nb_stages);

		/* last stage in pipeline */
		if (unlikely((ev.queue_id % nb_stages) == laststage)) {
			if (enable_fwd_latency)
				cnt = perf_process_last_stage_latency(pool,
					&ev, w, bufs, sz, cnt);
			else
				cnt = perf_process_last_stage(pool,
					&ev, w, bufs, sz, cnt);
		} else {
			fwd_event(&ev, sched_type_list, nb_stages);
			while (rte_event_enqueue_burst(dev, port, &ev, 1) != 1)
				rte_pause();
		}
	}
	return 0;
}

static int
perf_queue_worker_burst(void *arg, const int enable_fwd_latency)
{
	PERF_WORKER_INIT;
	uint16_t i;
	/* +1 to avoid prefetch out of array check */
	struct rte_event ev[BURST_SIZE + 1];

	while (t->done == false) {
		uint16_t const nb_rx = rte_event_dequeue_burst(dev, port, ev,
				BURST_SIZE, 0);

		if (!nb_rx) {
			rte_pause();
			continue;
		}

		for (i = 0; i < nb_rx; i++) {
			if (enable_fwd_latency && !prod_timer_type) {
				rte_prefetch0(ev[i+1].event_ptr);
				/* first queue in pipeline.
				 * mark time stamp to compute fwd latency
				 */
				mark_fwd_latency(&ev[i], nb_stages);
			}
			/* last stage in pipeline */
			if (unlikely((ev[i].queue_id % nb_stages) ==
						 laststage)) {
				if (enable_fwd_latency)
					cnt = perf_process_last_stage_latency(
						pool, &ev[i], w, bufs, sz, cnt);
				else
					cnt = perf_process_last_stage(pool,
						&ev[i], w, bufs, sz, cnt);

				ev[i].op = RTE_EVENT_OP_RELEASE;
			} else {
				fwd_event(&ev[i], sched_type_list, nb_stages);
			}
		}

		uint16_t enq;

		enq = rte_event_enqueue_burst(dev, port, ev, nb_rx);
		while (enq < nb_rx) {
			enq += rte_event_enqueue_burst(dev, port,
							ev + enq, nb_rx - enq);
		}
	}
	return 0;
}

static int
worker_wrapper(void *arg)
{
	struct worker_data *w  = arg;
	struct evt_options *opt = w->t->opt;

	const bool burst = evt_has_burst_mode(w->dev_id);
	const int fwd_latency = opt->fwd_latency;

	/* allow compiler to optimize */
	if (!burst && !fwd_latency)
		return perf_queue_worker(arg, 0);
	else if (!burst && fwd_latency)
		return perf_queue_worker(arg, 1);
	else if (burst && !fwd_latency)
		return perf_queue_worker_burst(arg, 0);
	else if (burst && fwd_latency)
		return perf_queue_worker_burst(arg, 1);

	rte_panic("invalid worker\n");
}

static int
perf_queue_launch_lcores(struct evt_test *test, struct evt_options *opt)
{
	return perf_launch_lcores(test, opt, worker_wrapper);
}

static int
perf_queue_eventdev_setup(struct evt_test *test, struct evt_options *opt)
{
	uint8_t queue;
	int nb_stages = opt->nb_stages;
	int ret;
	int nb_ports;
	int nb_queues;
	struct rte_event_dev_info dev_info;

	nb_ports = evt_nr_active_lcores(opt->wlcores);
	nb_ports += opt->prod_type == EVT_PROD_TYPE_ETH_RX_ADPTR ||
		 opt->prod_type == EVT_PROD_TYPE_EVENT_TIMER_ADPTR ? 0 :
		evt_nr_active_lcores(opt->plcores);

	nb_queues = perf_queue_nb_event_queues(opt);

	memset(&dev_info, 0, sizeof(struct rte_event_dev_info));
	ret = rte_event_dev_info_get(opt->dev_id, &dev_info);
	if (ret) {
		evt_err("failed to get eventdev info %d", opt->dev_id);
		return ret;
	}

	const struct rte_event_dev_config config = {
			.nb_event_queues = nb_queues,
			.nb_event_ports = nb_ports,
			.nb_events_limit  = dev_info.max_num_events,
			.nb_event_queue_flows = opt->nb_flows,
			.nb_event_port_dequeue_depth =
				dev_info.max_event_port_dequeue_depth,
			.nb_event_port_enqueue_depth =
				dev_info.max_event_port_enqueue_depth,
	};

	ret = rte_event_dev_configure(opt->dev_id, &config);
	if (ret) {
		evt_err("failed to configure eventdev %d", opt->dev_id);
		return ret;
	}

	struct rte_event_queue_conf q_conf = {
			.priority = RTE_EVENT_DEV_PRIORITY_NORMAL,
			.nb_atomic_flows = opt->nb_flows,
			.nb_atomic_order_sequences = opt->nb_flows,
	};
	/* queue configurations */
	for (queue = 0; queue < nb_queues; queue++) {
		q_conf.schedule_type =
			(opt->sched_type_list[queue % nb_stages]);

		if (opt->q_priority) {
			uint8_t stage_pos = queue % nb_stages;
			/* Configure event queues(stage 0 to stage n) with
			 * RTE_EVENT_DEV_PRIORITY_LOWEST to
			 * RTE_EVENT_DEV_PRIORITY_HIGHEST.
			 */
			uint8_t step = RTE_EVENT_DEV_PRIORITY_LOWEST /
					(nb_stages - 1);
			/* Higher prio for the queues closer to last stage */
			q_conf.priority = RTE_EVENT_DEV_PRIORITY_LOWEST -
					(step * stage_pos);
		}
		ret = rte_event_queue_setup(opt->dev_id, queue, &q_conf);
		if (ret) {
			evt_err("failed to setup queue=%d", queue);
			return ret;
		}
	}

	if (opt->wkr_deq_dep > dev_info.max_event_port_dequeue_depth)
		opt->wkr_deq_dep = dev_info.max_event_port_dequeue_depth;

	/* port configuration */
	const struct rte_event_port_conf p_conf = {
			.dequeue_depth = opt->wkr_deq_dep,
			.enqueue_depth = dev_info.max_event_port_dequeue_depth,
			.new_event_threshold = dev_info.max_num_events,
	};

	ret = perf_event_dev_port_setup(test, opt, nb_stages /* stride */,
					nb_queues, &p_conf);
	if (ret)
		return ret;

	if (!evt_has_distributed_sched(opt->dev_id)) {
		uint32_t service_id;
		rte_event_dev_service_id_get(opt->dev_id, &service_id);
		ret = evt_service_setup(service_id);
		if (ret) {
			evt_err("No service lcore found to run event dev.");
			return ret;
		}
	}

	ret = rte_event_dev_start(opt->dev_id);
	if (ret) {
		evt_err("failed to start eventdev %d", opt->dev_id);
		return ret;
	}

	return 0;
}

static void
perf_queue_opt_dump(struct evt_options *opt)
{
	evt_dump_fwd_latency(opt);
	perf_opt_dump(opt, perf_queue_nb_event_queues(opt));
}

static int
perf_queue_opt_check(struct evt_options *opt)
{
	return perf_opt_check(opt, perf_queue_nb_event_queues(opt));
}

static bool
perf_queue_capability_check(struct evt_options *opt)
{
	struct rte_event_dev_info dev_info;

	rte_event_dev_info_get(opt->dev_id, &dev_info);
	if (dev_info.max_event_queues < perf_queue_nb_event_queues(opt) ||
			dev_info.max_event_ports < perf_nb_event_ports(opt)) {
		evt_err("not enough eventdev queues=%d/%d or ports=%d/%d",
			perf_queue_nb_event_queues(opt),
			dev_info.max_event_queues,
			perf_nb_event_ports(opt), dev_info.max_event_ports);
	}

	return true;
}

static const struct evt_test_ops perf_queue =  {
	.cap_check          = perf_queue_capability_check,
	.opt_check          = perf_queue_opt_check,
	.opt_dump           = perf_queue_opt_dump,
	.test_setup         = perf_test_setup,
	.mempool_setup      = perf_mempool_setup,
	.ethdev_setup	    = perf_ethdev_setup,
	.eventdev_setup     = perf_queue_eventdev_setup,
	.launch_lcores      = perf_queue_launch_lcores,
	.eventdev_destroy   = perf_eventdev_destroy,
	.mempool_destroy    = perf_mempool_destroy,
	.ethdev_destroy	    = perf_ethdev_destroy,
	.test_result        = perf_test_result,
	.test_destroy       = perf_test_destroy,
};

EVT_TEST_REGISTER(perf_queue);
