/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Cavium, Inc
 */

#include "test_perf_common.h"

/* See http://doc.dpdk.org/guides/tools/testeventdev.html for test details */

static inline int
atq_nb_event_queues(struct evt_options *opt)
{
	/* nb_queues = number of producers */
	return opt->prod_type == EVT_PROD_TYPE_ETH_RX_ADPTR ?
		rte_eth_dev_count_avail() : evt_nr_active_lcores(opt->plcores);
}

static __rte_always_inline void
atq_fwd_event(struct rte_event *const ev, uint8_t *const sched_type_list,
		const uint8_t nb_stages)
{
	ev->sub_event_type++;
	ev->sched_type = sched_type_list[ev->sub_event_type % nb_stages];
	ev->op = RTE_EVENT_OP_FORWARD;
	ev->event_type = RTE_EVENT_TYPE_CPU;
}

static int
perf_atq_worker(void *arg, const int enable_fwd_latency)
{
	struct perf_elt *pe = NULL;
	uint16_t enq = 0, deq = 0;
	struct rte_event ev;
	PERF_WORKER_INIT;
	uint8_t stage;

	while (t->done == false) {
		deq = rte_event_dequeue_burst(dev, port, &ev, 1, 0);

		if (!deq) {
			rte_pause();
			continue;
		}

		if (prod_crypto_type && (ev.event_type == RTE_EVENT_TYPE_CRYPTODEV)) {
			if (perf_handle_crypto_ev(&ev, &pe, enable_fwd_latency))
				continue;
		}

		stage = ev.sub_event_type % nb_stages;
		if (enable_fwd_latency && !prod_timer_type && stage == 0)
		/* first stage in pipeline, mark ts to compute fwd latency */
			perf_mark_fwd_latency(ev.event_ptr);

		/* last stage in pipeline */
		if (unlikely(stage == laststage)) {
			if (enable_fwd_latency)
				cnt = perf_process_last_stage_latency(pool, prod_crypto_type,
					&ev, w, bufs, sz, cnt);
			else
				cnt = perf_process_last_stage(pool, prod_crypto_type, &ev, w,
					 bufs, sz, cnt);
		} else {
			atq_fwd_event(&ev, sched_type_list, nb_stages);
			do {
				enq = rte_event_enqueue_burst(dev, port, &ev,
							      1);
			} while (!enq && !t->done);
		}
	}

	perf_worker_cleanup(pool, dev, port, &ev, enq, deq);

	return 0;
}

static int
perf_atq_worker_burst(void *arg, const int enable_fwd_latency)
{
	/* +1 to avoid prefetch out of array check */
	struct rte_event ev[BURST_SIZE + 1];
	uint16_t enq = 0, nb_rx = 0;
	struct perf_elt *pe = NULL;
	PERF_WORKER_INIT;
	uint8_t stage;
	uint16_t i;

	while (t->done == false) {
		nb_rx = rte_event_dequeue_burst(dev, port, ev, BURST_SIZE, 0);

		if (!nb_rx) {
			rte_pause();
			continue;
		}

		for (i = 0; i < nb_rx; i++) {
			if (prod_crypto_type && (ev[i].event_type == RTE_EVENT_TYPE_CRYPTODEV)) {
				if (perf_handle_crypto_ev(&ev[i], &pe, enable_fwd_latency))
					continue;
			}

			stage = ev[i].sub_event_type % nb_stages;
			if (enable_fwd_latency && !prod_timer_type && stage == 0) {
				rte_prefetch0(ev[i+1].event_ptr);
				/* first stage in pipeline.
				 * mark time stamp to compute fwd latency
				 */
				perf_mark_fwd_latency(ev[i].event_ptr);
			}
			/* last stage in pipeline */
			if (unlikely(stage == laststage)) {
				if (enable_fwd_latency)
					cnt = perf_process_last_stage_latency(pool,
						prod_crypto_type, &ev[i], w, bufs, sz, cnt);
				else
					cnt = perf_process_last_stage(pool, prod_crypto_type,
						&ev[i], w, bufs, sz, cnt);

				ev[i].op = RTE_EVENT_OP_RELEASE;
			} else {
				atq_fwd_event(&ev[i], sched_type_list,
						nb_stages);
			}
		}

		enq = rte_event_enqueue_burst(dev, port, ev, nb_rx);
		while ((enq < nb_rx) && !t->done) {
			enq += rte_event_enqueue_burst(dev, port,
							ev + enq, nb_rx - enq);
		}
	}

	perf_worker_cleanup(pool, dev, port, ev, enq, nb_rx);

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
		return perf_atq_worker(arg, 0);
	else if (!burst && fwd_latency)
		return perf_atq_worker(arg, 1);
	else if (burst && !fwd_latency)
		return perf_atq_worker_burst(arg, 0);
	else if (burst && fwd_latency)
		return perf_atq_worker_burst(arg, 1);

	rte_panic("invalid worker\n");
}

static int
perf_atq_launch_lcores(struct evt_test *test, struct evt_options *opt)
{
	return perf_launch_lcores(test, opt, worker_wrapper);
}

static int
perf_atq_eventdev_setup(struct evt_test *test, struct evt_options *opt)
{
	int ret;
	uint8_t queue;
	uint8_t nb_queues;
	uint8_t nb_ports;
	uint16_t prod;
	struct rte_event_dev_info dev_info;
	struct test_perf *t = evt_test_priv(test);

	nb_ports = evt_nr_active_lcores(opt->wlcores);
	nb_ports += (opt->prod_type == EVT_PROD_TYPE_ETH_RX_ADPTR ||
			opt->prod_type == EVT_PROD_TYPE_EVENT_TIMER_ADPTR) ? 0 :
		evt_nr_active_lcores(opt->plcores);

	nb_queues = atq_nb_event_queues(opt);

	ret = rte_event_dev_info_get(opt->dev_id, &dev_info);
	if (ret) {
		evt_err("failed to get eventdev info %d", opt->dev_id);
		return ret;
	}

	ret = evt_configure_eventdev(opt, nb_queues, nb_ports);
	if (ret) {
		evt_err("failed to configure eventdev %d", opt->dev_id);
		return ret;
	}

	struct rte_event_queue_conf q_conf = {
			.priority = RTE_EVENT_DEV_PRIORITY_NORMAL,
			.event_queue_cfg = RTE_EVENT_QUEUE_CFG_ALL_TYPES,
			.nb_atomic_flows = opt->nb_flows,
			.nb_atomic_order_sequences = opt->nb_flows,
	};
	/* queue configurations */
	for (queue = 0; queue < nb_queues; queue++) {
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

	ret = perf_event_dev_port_setup(test, opt, 1 /* stride */, nb_queues,
			&p_conf);
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

	if (opt->prod_type == EVT_PROD_TYPE_ETH_RX_ADPTR) {
		RTE_ETH_FOREACH_DEV(prod) {
			ret = rte_eth_dev_start(prod);
			if (ret) {
				evt_err("Ethernet dev [%d] failed to start. Using synthetic producer",
						prod);
				return ret;
			}

			ret = rte_event_eth_rx_adapter_start(prod);
			if (ret) {
				evt_err("Rx adapter[%d] start failed", prod);
				return ret;
			}
			printf("%s: Port[%d] using Rx adapter[%d] started\n",
					__func__, prod, prod);
		}
	} else if (opt->prod_type == EVT_PROD_TYPE_EVENT_TIMER_ADPTR) {
		for (prod = 0; prod < opt->nb_timer_adptrs; prod++) {
			ret = rte_event_timer_adapter_start(
					t->timer_adptr[prod]);
			if (ret) {
				evt_err("failed to Start event timer adapter %d"
						, prod);
				return ret;
			}
		}
	} else if (opt->prod_type == EVT_PROD_TYPE_EVENT_CRYPTO_ADPTR) {
		uint8_t cdev_id, cdev_count;

		cdev_count = rte_cryptodev_count();
		for (cdev_id = 0; cdev_id < cdev_count; cdev_id++) {
			ret = rte_cryptodev_start(cdev_id);
			if (ret) {
				evt_err("Failed to start cryptodev %u",
					cdev_id);
				return ret;
			}
		}
	}

	return 0;
}

static void
perf_atq_opt_dump(struct evt_options *opt)
{
	perf_opt_dump(opt, atq_nb_event_queues(opt));
}

static int
perf_atq_opt_check(struct evt_options *opt)
{
	return perf_opt_check(opt, atq_nb_event_queues(opt));
}

static bool
perf_atq_capability_check(struct evt_options *opt)
{
	struct rte_event_dev_info dev_info;

	rte_event_dev_info_get(opt->dev_id, &dev_info);
	if (dev_info.max_event_queues < atq_nb_event_queues(opt) ||
			dev_info.max_event_ports < perf_nb_event_ports(opt)) {
		evt_err("not enough eventdev queues=%d/%d or ports=%d/%d",
			atq_nb_event_queues(opt), dev_info.max_event_queues,
			perf_nb_event_ports(opt), dev_info.max_event_ports);
	}
	if (!evt_has_all_types_queue(opt->dev_id))
		return false;

	return true;
}

static const struct evt_test_ops perf_atq =  {
	.cap_check          = perf_atq_capability_check,
	.opt_check          = perf_atq_opt_check,
	.opt_dump           = perf_atq_opt_dump,
	.test_setup         = perf_test_setup,
	.ethdev_setup       = perf_ethdev_setup,
	.cryptodev_setup    = perf_cryptodev_setup,
	.ethdev_rx_stop     = perf_ethdev_rx_stop,
	.mempool_setup      = perf_mempool_setup,
	.eventdev_setup     = perf_atq_eventdev_setup,
	.launch_lcores      = perf_atq_launch_lcores,
	.eventdev_destroy   = perf_eventdev_destroy,
	.mempool_destroy    = perf_mempool_destroy,
	.ethdev_destroy     = perf_ethdev_destroy,
	.cryptodev_destroy  = perf_cryptodev_destroy,
	.test_result        = perf_test_result,
	.test_destroy       = perf_test_destroy,
};

EVT_TEST_REGISTER(perf_atq);
