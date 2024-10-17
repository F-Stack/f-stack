/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Cavium, Inc
 */

#ifndef _TEST_PERF_COMMON_
#define _TEST_PERF_COMMON_

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

#include <rte_cryptodev.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_event_crypto_adapter.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_event_eth_tx_adapter.h>
#include <rte_event_timer_adapter.h>
#include <rte_eventdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_prefetch.h>

#include "evt_common.h"
#include "evt_options.h"
#include "evt_test.h"

#define TEST_PERF_CA_ID 0

struct test_perf;

struct worker_data {
	uint64_t processed_pkts;
	uint64_t latency;
	uint8_t dev_id;
	uint8_t port_id;
	struct test_perf *t;
} __rte_cache_aligned;

struct crypto_adptr_data {
	uint8_t cdev_id;
	uint16_t cdev_qp_id;
	void **crypto_sess;
};
struct prod_data {
	uint8_t dev_id;
	uint8_t port_id;
	uint8_t queue_id;
	struct crypto_adptr_data ca;
	struct test_perf *t;
} __rte_cache_aligned;

struct test_perf {
	/* Don't change the offset of "done". Signal handler use this memory
	 * to terminate all lcores work.
	 */
	int done;
	uint64_t outstand_pkts;
	uint8_t nb_workers;
	enum evt_test_result result;
	uint32_t nb_flows;
	uint64_t nb_pkts;
	struct rte_mempool *pool;
	struct prod_data prod[EVT_MAX_PORTS];
	struct worker_data worker[EVT_MAX_PORTS];
	struct evt_options *opt;
	uint8_t sched_type_list[EVT_MAX_STAGES] __rte_cache_aligned;
	struct rte_event_timer_adapter *timer_adptr[
		RTE_EVENT_TIMER_ADAPTER_NUM_MAX] __rte_cache_aligned;
	struct rte_mempool *ca_op_pool;
	struct rte_mempool *ca_sess_pool;
	struct rte_mempool *ca_asym_sess_pool;
} __rte_cache_aligned;

struct perf_elt {
	union {
		struct rte_event_timer tim;
		struct {
			char pad[offsetof(struct rte_event_timer, user_meta)];
			uint64_t timestamp;
		};
	};
} __rte_cache_aligned;

#define BURST_SIZE 16
#define MAX_PROD_ENQ_BURST_SIZE 128

#define PERF_WORKER_INIT\
	struct worker_data *w  = arg;\
	struct test_perf *t = w->t;\
	struct evt_options *opt = t->opt;\
	const uint8_t dev = w->dev_id;\
	const uint8_t port = w->port_id;\
	const uint8_t prod_timer_type = \
		opt->prod_type == EVT_PROD_TYPE_EVENT_TIMER_ADPTR;\
	const uint8_t prod_crypto_type = \
		opt->prod_type == EVT_PROD_TYPE_EVENT_CRYPTO_ADPTR;\
	uint8_t *const sched_type_list = &t->sched_type_list[0];\
	struct rte_mempool *const pool = t->pool;\
	const uint8_t nb_stages = t->opt->nb_stages;\
	const uint8_t laststage = nb_stages - 1;\
	uint8_t cnt = 0;\
	void *bufs[16] __rte_cache_aligned;\
	int const sz = RTE_DIM(bufs);\
	if (opt->verbose_level > 1)\
		printf("%s(): lcore %d dev_id %d port=%d\n", __func__,\
				rte_lcore_id(), dev, port)

static __rte_always_inline void
perf_mark_fwd_latency(struct perf_elt *const pe)
{
	pe->timestamp = rte_get_timer_cycles();
}

static __rte_always_inline int
perf_handle_crypto_ev(struct rte_event *ev, struct perf_elt **pe, int enable_fwd_latency)
{
	struct rte_crypto_op *op = ev->event_ptr;
	struct rte_mbuf *m;


	if (unlikely(op->status != RTE_CRYPTO_OP_STATUS_SUCCESS)) {
		rte_crypto_op_free(op);
		return op->status;
	}

	/* Forward latency not enabled - perf data will not be accessed */
	if (!enable_fwd_latency)
		return 0;

	/* Get pointer to perf data */
	if (op->type == RTE_CRYPTO_OP_TYPE_SYMMETRIC) {
		if (op->sym->m_dst == NULL)
			m = op->sym->m_src;
		else
			m = op->sym->m_dst;
		*pe = rte_pktmbuf_mtod(m, struct perf_elt *);
	} else {
		*pe = RTE_PTR_ADD(op->asym->modex.result.data, op->asym->modex.result.length);
	}

	return 0;
}


static __rte_always_inline int
perf_process_last_stage(struct rte_mempool *const pool, uint8_t prod_crypto_type,
		struct rte_event *const ev, struct worker_data *const w,
		void *bufs[], int const buf_sz, uint8_t count)
{
	void *to_free_in_bulk;

	/* release fence here ensures event_prt is
	 * stored before updating the number of
	 * processed packets for worker lcores
	 */
	rte_atomic_thread_fence(__ATOMIC_RELEASE);
	w->processed_pkts++;

	if (prod_crypto_type) {
		struct rte_crypto_op *op = ev->event_ptr;
		struct rte_mbuf *m;

		if (op->type == RTE_CRYPTO_OP_TYPE_SYMMETRIC) {
			if (op->sym->m_dst == NULL)
				m = op->sym->m_src;
			else
				m = op->sym->m_dst;

			to_free_in_bulk = m;
		} else {
			to_free_in_bulk = op->asym->modex.result.data;
		}
		rte_crypto_op_free(op);
	} else {
		to_free_in_bulk = ev->event_ptr;
	}

	bufs[count++] = to_free_in_bulk;
	if (unlikely(count == buf_sz)) {
		count = 0;
		rte_mempool_put_bulk(pool, bufs, buf_sz);
	}

	return count;
}

static __rte_always_inline uint8_t
perf_process_last_stage_latency(struct rte_mempool *const pool, uint8_t prod_crypto_type,
		struct rte_event *const ev, struct worker_data *const w,
		void *bufs[], int const buf_sz, uint8_t count)
{
	uint64_t latency;
	struct perf_elt *pe;
	void *to_free_in_bulk;

	/* release fence here ensures event_prt is
	 * stored before updating the number of
	 * processed packets for worker lcores
	 */
	rte_atomic_thread_fence(__ATOMIC_RELEASE);
	w->processed_pkts++;

	if (prod_crypto_type) {
		struct rte_crypto_op *op = ev->event_ptr;
		struct rte_mbuf *m;

		if (op->type == RTE_CRYPTO_OP_TYPE_SYMMETRIC) {
			if (op->sym->m_dst == NULL)
				m = op->sym->m_src;
			else
				m = op->sym->m_dst;

			to_free_in_bulk = m;
			pe = rte_pktmbuf_mtod(m, struct perf_elt *);
		} else {
			pe = RTE_PTR_ADD(op->asym->modex.result.data,
					 op->asym->modex.result.length);
			to_free_in_bulk = op->asym->modex.result.data;
		}
		rte_crypto_op_free(op);
	} else {
		pe = ev->event_ptr;
		to_free_in_bulk = pe;
	}

	latency = rte_get_timer_cycles() - pe->timestamp;
	w->latency += latency;

	bufs[count++] = to_free_in_bulk;
	if (unlikely(count == buf_sz)) {
		count = 0;
		rte_mempool_put_bulk(pool, bufs, buf_sz);
	}

	return count;
}


static inline int
perf_nb_event_ports(struct evt_options *opt)
{
	return evt_nr_active_lcores(opt->wlcores) +
			evt_nr_active_lcores(opt->plcores);
}

int perf_test_result(struct evt_test *test, struct evt_options *opt);
int perf_opt_check(struct evt_options *opt, uint64_t nb_queues);
int perf_test_setup(struct evt_test *test, struct evt_options *opt);
int perf_ethdev_setup(struct evt_test *test, struct evt_options *opt);
int perf_cryptodev_setup(struct evt_test *test, struct evt_options *opt);
int perf_mempool_setup(struct evt_test *test, struct evt_options *opt);
int perf_event_dev_port_setup(struct evt_test *test, struct evt_options *opt,
				uint8_t stride, uint8_t nb_queues,
				const struct rte_event_port_conf *port_conf);
int perf_event_dev_service_setup(uint8_t dev_id);
int perf_launch_lcores(struct evt_test *test, struct evt_options *opt,
		int (*worker)(void *));
void perf_opt_dump(struct evt_options *opt, uint8_t nb_queues);
void perf_test_destroy(struct evt_test *test, struct evt_options *opt);
void perf_eventdev_destroy(struct evt_test *test, struct evt_options *opt);
void perf_cryptodev_destroy(struct evt_test *test, struct evt_options *opt);
void perf_ethdev_destroy(struct evt_test *test, struct evt_options *opt);
void perf_ethdev_rx_stop(struct evt_test *test, struct evt_options *opt);
void perf_mempool_destroy(struct evt_test *test, struct evt_options *opt);
void perf_worker_cleanup(struct rte_mempool *const pool, uint8_t dev_id,
			 uint8_t port_id, struct rte_event events[],
			 uint16_t nb_enq, uint16_t nb_deq);

#endif /* _TEST_PERF_COMMON_ */
