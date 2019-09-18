/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2016 Intel Corporation.
 * Copyright 2017 Cavium, Inc.
 */

#include "pipeline_common.h"

static __rte_always_inline int
worker_generic(void *arg)
{
	struct rte_event ev;

	struct worker_data *data = (struct worker_data *)arg;
	uint8_t dev_id = data->dev_id;
	uint8_t port_id = data->port_id;
	size_t sent = 0, received = 0;
	unsigned int lcore_id = rte_lcore_id();

	while (!fdata->done) {

		if (fdata->cap.scheduler)
			fdata->cap.scheduler(lcore_id);

		if (!fdata->worker_core[lcore_id]) {
			rte_pause();
			continue;
		}

		const uint16_t nb_rx = rte_event_dequeue_burst(dev_id, port_id,
				&ev, 1, 0);

		if (nb_rx == 0) {
			rte_pause();
			continue;
		}
		received++;

		/* The first worker stage does classification */
		if (ev.queue_id == cdata.qid[0])
			ev.flow_id = ev.mbuf->hash.rss
						% cdata.num_fids;

		ev.queue_id = cdata.next_qid[ev.queue_id];
		ev.op = RTE_EVENT_OP_FORWARD;
		ev.sched_type = cdata.queue_type;

		work();

		while (rte_event_enqueue_burst(dev_id, port_id, &ev, 1) != 1)
			rte_pause();
		sent++;
	}

	if (!cdata.quiet)
		printf("  worker %u thread done. RX=%zu TX=%zu\n",
				rte_lcore_id(), received, sent);

	return 0;
}

static int
worker_generic_burst(void *arg)
{
	struct rte_event events[BATCH_SIZE];

	struct worker_data *data = (struct worker_data *)arg;
	uint8_t dev_id = data->dev_id;
	uint8_t port_id = data->port_id;
	size_t sent = 0, received = 0;
	unsigned int lcore_id = rte_lcore_id();

	while (!fdata->done) {
		uint16_t i;

		if (fdata->cap.scheduler)
			fdata->cap.scheduler(lcore_id);

		if (!fdata->worker_core[lcore_id]) {
			rte_pause();
			continue;
		}

		const uint16_t nb_rx = rte_event_dequeue_burst(dev_id, port_id,
				events, RTE_DIM(events), 0);

		if (nb_rx == 0) {
			rte_pause();
			continue;
		}
		received += nb_rx;

		for (i = 0; i < nb_rx; i++) {

			/* The first worker stage does classification */
			if (events[i].queue_id == cdata.qid[0])
				events[i].flow_id = events[i].mbuf->hash.rss
							% cdata.num_fids;

			events[i].queue_id = cdata.next_qid[events[i].queue_id];
			events[i].op = RTE_EVENT_OP_FORWARD;
			events[i].sched_type = cdata.queue_type;

			work();
		}
		uint16_t nb_tx = rte_event_enqueue_burst(dev_id, port_id,
				events, nb_rx);
		while (nb_tx < nb_rx && !fdata->done)
			nb_tx += rte_event_enqueue_burst(dev_id, port_id,
							events + nb_tx,
							nb_rx - nb_tx);
		sent += nb_tx;
	}

	if (!cdata.quiet)
		printf("  worker %u thread done. RX=%zu TX=%zu\n",
				rte_lcore_id(), received, sent);

	return 0;
}

static int
setup_eventdev_generic(struct worker_data *worker_data)
{
	const uint8_t dev_id = 0;
	/* +1 stages is for a SINGLE_LINK TX stage */
	const uint8_t nb_queues = cdata.num_stages + 1;
	const uint8_t nb_ports = cdata.num_workers;
	struct rte_event_dev_config config = {
			.nb_event_queues = nb_queues,
			.nb_event_ports = nb_ports,
			.nb_events_limit  = 4096,
			.nb_event_queue_flows = 1024,
			.nb_event_port_dequeue_depth = 128,
			.nb_event_port_enqueue_depth = 128,
	};
	struct rte_event_port_conf wkr_p_conf = {
			.dequeue_depth = cdata.worker_cq_depth,
			.enqueue_depth = 64,
			.new_event_threshold = 4096,
	};
	struct rte_event_queue_conf wkr_q_conf = {
			.schedule_type = cdata.queue_type,
			.priority = RTE_EVENT_DEV_PRIORITY_NORMAL,
			.nb_atomic_flows = 1024,
		.nb_atomic_order_sequences = 1024,
	};
	struct rte_event_queue_conf tx_q_conf = {
			.priority = RTE_EVENT_DEV_PRIORITY_HIGHEST,
			.event_queue_cfg = RTE_EVENT_QUEUE_CFG_SINGLE_LINK,
	};

	struct port_link worker_queues[MAX_NUM_STAGES];
	uint8_t disable_implicit_release;
	unsigned int i;

	int ret, ndev = rte_event_dev_count();
	if (ndev < 1) {
		printf("%d: No Eventdev Devices Found\n", __LINE__);
		return -1;
	}

	struct rte_event_dev_info dev_info;
	ret = rte_event_dev_info_get(dev_id, &dev_info);
	printf("\tEventdev %d: %s\n", dev_id, dev_info.driver_name);

	disable_implicit_release = (dev_info.event_dev_cap &
			RTE_EVENT_DEV_CAP_IMPLICIT_RELEASE_DISABLE);

	wkr_p_conf.disable_implicit_release = disable_implicit_release;

	if (dev_info.max_event_port_dequeue_depth <
			config.nb_event_port_dequeue_depth)
		config.nb_event_port_dequeue_depth =
				dev_info.max_event_port_dequeue_depth;
	if (dev_info.max_event_port_enqueue_depth <
			config.nb_event_port_enqueue_depth)
		config.nb_event_port_enqueue_depth =
				dev_info.max_event_port_enqueue_depth;

	ret = rte_event_dev_configure(dev_id, &config);
	if (ret < 0) {
		printf("%d: Error configuring device\n", __LINE__);
		return -1;
	}

	/* Q creation - one load balanced per pipeline stage*/
	printf("  Stages:\n");
	for (i = 0; i < cdata.num_stages; i++) {
		if (rte_event_queue_setup(dev_id, i, &wkr_q_conf) < 0) {
			printf("%d: error creating qid %d\n", __LINE__, i);
			return -1;
		}
		cdata.qid[i] = i;
		cdata.next_qid[i] = i+1;
		worker_queues[i].queue_id = i;
		if (cdata.enable_queue_priorities) {
			/* calculate priority stepping for each stage, leaving
			 * headroom of 1 for the SINGLE_LINK TX below
			 */
			const uint32_t prio_delta =
				(RTE_EVENT_DEV_PRIORITY_LOWEST-1) /  nb_queues;

			/* higher priority for queues closer to tx */
			wkr_q_conf.priority =
				RTE_EVENT_DEV_PRIORITY_LOWEST - prio_delta * i;
		}

		const char *type_str = "Atomic";
		switch (wkr_q_conf.schedule_type) {
		case RTE_SCHED_TYPE_ORDERED:
			type_str = "Ordered";
			break;
		case RTE_SCHED_TYPE_PARALLEL:
			type_str = "Parallel";
			break;
		}
		printf("\tStage %d, Type %s\tPriority = %d\n", i, type_str,
				wkr_q_conf.priority);
	}
	printf("\n");

	/* final queue for sending to TX core */
	if (rte_event_queue_setup(dev_id, i, &tx_q_conf) < 0) {
		printf("%d: error creating qid %d\n", __LINE__, i);
		return -1;
	}
	cdata.tx_queue_id = i;

	if (wkr_p_conf.dequeue_depth > config.nb_event_port_dequeue_depth)
		wkr_p_conf.dequeue_depth = config.nb_event_port_dequeue_depth;
	if (wkr_p_conf.enqueue_depth > config.nb_event_port_enqueue_depth)
		wkr_p_conf.enqueue_depth = config.nb_event_port_enqueue_depth;

	/* set up one port per worker, linking to all stage queues */
	for (i = 0; i < cdata.num_workers; i++) {
		struct worker_data *w = &worker_data[i];
		w->dev_id = dev_id;
		if (rte_event_port_setup(dev_id, i, &wkr_p_conf) < 0) {
			printf("Error setting up port %d\n", i);
			return -1;
		}

		uint32_t s;
		for (s = 0; s < cdata.num_stages; s++) {
			if (rte_event_port_link(dev_id, i,
						&worker_queues[s].queue_id,
						&worker_queues[s].priority,
						1) != 1) {
				printf("%d: error creating link for port %d\n",
						__LINE__, i);
				return -1;
			}
		}
		w->port_id = i;
	}

	ret = rte_event_dev_service_id_get(dev_id,
				&fdata->evdev_service_id);
	if (ret != -ESRCH && ret != 0) {
		printf("Error getting the service ID for sw eventdev\n");
		return -1;
	}
	rte_service_runstate_set(fdata->evdev_service_id, 1);
	rte_service_set_runstate_mapped_check(fdata->evdev_service_id, 0);

	return dev_id;
}

static void
init_adapters(uint16_t nb_ports)
{
	int i;
	int ret;
	uint8_t tx_port_id = 0;
	uint8_t evdev_id = 0;
	struct rte_event_dev_info dev_info;

	ret = rte_event_dev_info_get(evdev_id, &dev_info);

	struct rte_event_port_conf adptr_p_conf = {
		.dequeue_depth = cdata.worker_cq_depth,
		.enqueue_depth = 64,
		.new_event_threshold = 4096,
	};

	if (adptr_p_conf.dequeue_depth > dev_info.max_event_port_dequeue_depth)
		adptr_p_conf.dequeue_depth =
			dev_info.max_event_port_dequeue_depth;
	if (adptr_p_conf.enqueue_depth > dev_info.max_event_port_enqueue_depth)
		adptr_p_conf.enqueue_depth =
			dev_info.max_event_port_enqueue_depth;

	/* Create one adapter for all the ethernet ports. */
	ret = rte_event_eth_rx_adapter_create(cdata.rx_adapter_id, evdev_id,
			&adptr_p_conf);
	if (ret)
		rte_exit(EXIT_FAILURE, "failed to create rx adapter[%d]",
				cdata.rx_adapter_id);

	ret = rte_event_eth_tx_adapter_create(cdata.tx_adapter_id, evdev_id,
			&adptr_p_conf);
	if (ret)
		rte_exit(EXIT_FAILURE, "failed to create tx adapter[%d]",
				cdata.tx_adapter_id);

	struct rte_event_eth_rx_adapter_queue_conf queue_conf;
	memset(&queue_conf, 0, sizeof(queue_conf));
	queue_conf.ev.sched_type = cdata.queue_type;
	queue_conf.ev.queue_id = cdata.qid[0];

	for (i = 0; i < nb_ports; i++) {
		ret = rte_event_eth_rx_adapter_queue_add(cdata.rx_adapter_id, i,
				-1, &queue_conf);
		if (ret)
			rte_exit(EXIT_FAILURE,
					"Failed to add queues to Rx adapter");

		ret = rte_event_eth_tx_adapter_queue_add(cdata.tx_adapter_id, i,
				-1);
		if (ret)
			rte_exit(EXIT_FAILURE,
					"Failed to add queues to Tx adapter");
	}

	ret = rte_event_eth_tx_adapter_event_port_get(cdata.tx_adapter_id,
			&tx_port_id);
	if (ret)
		rte_exit(EXIT_FAILURE,
				"Failed to get Tx adapter port id");
	ret = rte_event_port_link(evdev_id, tx_port_id, &cdata.tx_queue_id,
			NULL, 1);
	if (ret != 1)
		rte_exit(EXIT_FAILURE,
				"Unable to link Tx adapter port to Tx queue");

	ret = rte_event_eth_rx_adapter_service_id_get(cdata.rx_adapter_id,
				&fdata->rxadptr_service_id);
	if (ret != -ESRCH && ret != 0) {
		rte_exit(EXIT_FAILURE,
			"Error getting the service ID for Rx adapter\n");
	}
	rte_service_runstate_set(fdata->rxadptr_service_id, 1);
	rte_service_set_runstate_mapped_check(fdata->rxadptr_service_id, 0);

	ret = rte_event_eth_tx_adapter_service_id_get(cdata.tx_adapter_id,
				&fdata->txadptr_service_id);
	if (ret != -ESRCH && ret != 0) {
		rte_exit(EXIT_FAILURE,
			"Error getting the service ID for Tx adapter\n");
	}
	rte_service_runstate_set(fdata->txadptr_service_id, 1);
	rte_service_set_runstate_mapped_check(fdata->txadptr_service_id, 0);

	ret = rte_event_eth_rx_adapter_start(cdata.rx_adapter_id);
	if (ret)
		rte_exit(EXIT_FAILURE, "Rx adapter[%d] start failed",
				cdata.rx_adapter_id);

	ret = rte_event_eth_tx_adapter_start(cdata.tx_adapter_id);
	if (ret)
		rte_exit(EXIT_FAILURE, "Tx adapter[%d] start failed",
				cdata.tx_adapter_id);

	if (rte_event_dev_start(evdev_id) < 0)
		rte_exit(EXIT_FAILURE, "Error starting eventdev");
}

static void
generic_opt_check(void)
{
	int i;
	int ret;
	uint32_t cap = 0;
	uint8_t rx_needed = 0;
	uint8_t sched_needed = 0;
	struct rte_event_dev_info eventdev_info;

	memset(&eventdev_info, 0, sizeof(struct rte_event_dev_info));
	rte_event_dev_info_get(0, &eventdev_info);

	if (cdata.all_type_queues && !(eventdev_info.event_dev_cap &
				RTE_EVENT_DEV_CAP_QUEUE_ALL_TYPES))
		rte_exit(EXIT_FAILURE,
				"Event dev doesn't support all type queues\n");
	sched_needed = !(eventdev_info.event_dev_cap &
		RTE_EVENT_DEV_CAP_DISTRIBUTED_SCHED);

	RTE_ETH_FOREACH_DEV(i) {
		ret = rte_event_eth_rx_adapter_caps_get(0, i, &cap);
		if (ret)
			rte_exit(EXIT_FAILURE,
				"failed to get event rx adapter capabilities");
		rx_needed |=
			!(cap & RTE_EVENT_ETH_RX_ADAPTER_CAP_INTERNAL_PORT);
	}

	if (cdata.worker_lcore_mask == 0 ||
			(rx_needed && cdata.rx_lcore_mask == 0) ||
			(cdata.tx_lcore_mask == 0) ||
			(sched_needed && cdata.sched_lcore_mask == 0)) {
		printf("Core part of pipeline was not assigned any cores. "
			"This will stall the pipeline, please check core masks "
			"(use -h for details on setting core masks):\n"
			"\trx: %"PRIu64"\n\ttx: %"PRIu64"\n\tsched: %"PRIu64
			"\n\tworkers: %"PRIu64"\n",
			cdata.rx_lcore_mask, cdata.tx_lcore_mask,
			cdata.sched_lcore_mask,
			cdata.worker_lcore_mask);
		rte_exit(-1, "Fix core masks\n");
	}

	if (!sched_needed)
		memset(fdata->sched_core, 0,
				sizeof(unsigned int) * MAX_NUM_CORE);
	if (!rx_needed)
		memset(fdata->rx_core, 0,
				sizeof(unsigned int) * MAX_NUM_CORE);
}

void
set_worker_generic_setup_data(struct setup_data *caps, bool burst)
{
	if (burst) {
		caps->worker = worker_generic_burst;
	} else {
		caps->worker = worker_generic;
	}

	caps->adptr_setup = init_adapters;
	caps->scheduler = schedule_devices;
	caps->evdev_setup = setup_eventdev_generic;
	caps->check_opt = generic_opt_check;
}
