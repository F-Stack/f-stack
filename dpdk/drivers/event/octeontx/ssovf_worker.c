/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Cavium, Inc
 */

#include "ssovf_worker.h"

static __rte_always_inline void
ssows_new_event(struct ssows *ws, const struct rte_event *ev)
{
	const uint64_t event_ptr = ev->u64;
	const uint32_t tag = (uint32_t)ev->event;
	const uint8_t new_tt = ev->sched_type;
	const uint8_t grp = ev->queue_id;

	ssows_add_work(ws, event_ptr, tag, new_tt, grp);
}

static __rte_always_inline void
ssows_fwd_swtag(struct ssows *ws, const struct rte_event *ev, const uint8_t grp)
{
	const uint8_t cur_tt = ws->cur_tt;
	const uint8_t new_tt = ev->sched_type;
	const uint32_t tag = (uint32_t)ev->event;
	/*
	 * cur_tt/new_tt     SSO_SYNC_ORDERED SSO_SYNC_ATOMIC SSO_SYNC_UNTAGGED
	 *
	 * SSO_SYNC_ORDERED        norm           norm             untag
	 * SSO_SYNC_ATOMIC         norm           norm		   untag
	 * SSO_SYNC_UNTAGGED       full           full             NOOP
	 */
	if (unlikely(cur_tt == SSO_SYNC_UNTAGGED)) {
		if (new_tt != SSO_SYNC_UNTAGGED) {
			ssows_swtag_full(ws, ev->u64, tag,
				new_tt, grp);
		}
	} else {
		if (likely(new_tt != SSO_SYNC_UNTAGGED))
			ssows_swtag_norm(ws, tag, new_tt);
		else
			ssows_swtag_untag(ws);
	}
	ws->swtag_req = 1;
}

#define OCT_EVENT_TYPE_GRP_FWD (RTE_EVENT_TYPE_MAX - 1)

static __rte_always_inline void
ssows_fwd_group(struct ssows *ws, const struct rte_event *ev, const uint8_t grp)
{
	const uint64_t event_ptr = ev->u64;
	const uint32_t tag = (uint32_t)ev->event;
	const uint8_t cur_tt = ws->cur_tt;
	const uint8_t new_tt = ev->sched_type;

	if (cur_tt == SSO_SYNC_ORDERED) {
		/* Create unique tag based on custom event type and new grp */
		uint32_t newtag = OCT_EVENT_TYPE_GRP_FWD << 28;

		newtag |= grp << 20;
		newtag |= tag;
		ssows_swtag_norm(ws, newtag, SSO_SYNC_ATOMIC);
		rte_smp_wmb();
		ssows_swtag_wait(ws);
	} else {
		rte_smp_wmb();
	}
	ssows_add_work(ws, event_ptr, tag, new_tt, grp);
}

static __rte_always_inline void
ssows_forward_event(struct ssows *ws, const struct rte_event *ev)
{
	const uint8_t grp = ev->queue_id;

	/* Group hasn't changed, Use SWTAG to forward the event */
	if (ws->cur_grp == grp)
		ssows_fwd_swtag(ws, ev, grp);
	else
	/*
	 * Group has been changed for group based work pipelining,
	 * Use deschedule/add_work operation to transfer the event to
	 * new group/core
	 */
		ssows_fwd_group(ws, ev, grp);
}

static __rte_always_inline void
ssows_release_event(struct ssows *ws)
{
	if (likely(ws->cur_tt != SSO_SYNC_UNTAGGED))
		ssows_swtag_untag(ws);
}

__rte_always_inline uint16_t __hot
ssows_deq(void *port, struct rte_event *ev, uint64_t timeout_ticks)
{
	struct ssows *ws = port;

	RTE_SET_USED(timeout_ticks);

	if (ws->swtag_req) {
		ws->swtag_req = 0;
		ssows_swtag_wait(ws);
		return 1;
	} else {
		return ssows_get_work(ws, ev);
	}
}

__rte_always_inline uint16_t __hot
ssows_deq_timeout(void *port, struct rte_event *ev, uint64_t timeout_ticks)
{
	struct ssows *ws = port;
	uint64_t iter;
	uint16_t ret = 1;

	if (ws->swtag_req) {
		ws->swtag_req = 0;
		ssows_swtag_wait(ws);
	} else {
		ret = ssows_get_work(ws, ev);
		for (iter = 1; iter < timeout_ticks && (ret == 0); iter++)
			ret = ssows_get_work(ws, ev);
	}
	return ret;
}

uint16_t __hot
ssows_deq_burst(void *port, struct rte_event ev[], uint16_t nb_events,
		uint64_t timeout_ticks)
{
	RTE_SET_USED(nb_events);

	return ssows_deq(port, ev, timeout_ticks);
}

uint16_t __hot
ssows_deq_timeout_burst(void *port, struct rte_event ev[], uint16_t nb_events,
			uint64_t timeout_ticks)
{
	RTE_SET_USED(nb_events);

	return ssows_deq_timeout(port, ev, timeout_ticks);
}

__rte_always_inline uint16_t __hot
ssows_enq(void *port, const struct rte_event *ev)
{
	struct ssows *ws = port;
	uint16_t ret = 1;

	switch (ev->op) {
	case RTE_EVENT_OP_NEW:
		rte_smp_wmb();
		ssows_new_event(ws, ev);
		break;
	case RTE_EVENT_OP_FORWARD:
		ssows_forward_event(ws, ev);
		break;
	case RTE_EVENT_OP_RELEASE:
		ssows_release_event(ws);
		break;
	default:
		ret = 0;
	}
	return ret;
}

uint16_t __hot
ssows_enq_burst(void *port, const struct rte_event ev[], uint16_t nb_events)
{
	RTE_SET_USED(nb_events);
	return ssows_enq(port, ev);
}

uint16_t __hot
ssows_enq_new_burst(void *port, const struct rte_event ev[], uint16_t nb_events)
{
	uint16_t i;
	struct ssows *ws = port;

	rte_smp_wmb();
	for (i = 0; i < nb_events; i++)
		ssows_new_event(ws,  &ev[i]);

	return nb_events;
}

uint16_t __hot
ssows_enq_fwd_burst(void *port, const struct rte_event ev[], uint16_t nb_events)
{
	struct ssows *ws = port;
	RTE_SET_USED(nb_events);

	ssows_forward_event(ws,  ev);

	return 1;
}

void
ssows_flush_events(struct ssows *ws, uint8_t queue_id,
				ssows_handle_event_t fn, void *arg)
{
	uint32_t reg_off;
	struct rte_event ev;
	uint64_t enable, aq_cnt = 1, cq_ds_cnt = 1;
	uint64_t get_work0, get_work1;
	uint64_t sched_type_queue;
	uint8_t *base = ssovf_bar(OCTEONTX_SSO_GROUP, queue_id, 0);

	enable = ssovf_read64(base + SSO_VHGRP_QCTL);
	if (!enable)
		return;

	reg_off = SSOW_VHWS_OP_GET_WORK0;
	reg_off |= 1 << 17; /* Grouped */
	reg_off |= 1 << 16; /* WAIT */
	reg_off |= queue_id << 4; /* INDEX_GGRP_MASK(group number) */
	while (aq_cnt || cq_ds_cnt) {
		aq_cnt = ssovf_read64(base + SSO_VHGRP_AQ_CNT);
		cq_ds_cnt = ssovf_read64(base + SSO_VHGRP_INT_CNT);
		/* Extract cq and ds count */
		cq_ds_cnt &= 0x1FFF1FFF0000;

		ssovf_load_pair(get_work0, get_work1, ws->base + reg_off);

		sched_type_queue = (get_work0 >> 32) & 0xfff;
		ws->cur_tt = sched_type_queue & 0x3;
		ws->cur_grp = sched_type_queue >> 2;
		sched_type_queue = sched_type_queue << 38;
		ev.event = sched_type_queue | (get_work0 & 0xffffffff);
		if (get_work1 && ev.event_type == RTE_EVENT_TYPE_ETHDEV)
			ev.mbuf = ssovf_octeontx_wqe_to_pkt(get_work1,
					(ev.event >> 20) & 0x7F);
		else
			ev.u64 = get_work1;

		if (fn != NULL && ev.u64 != 0)
			fn(arg, ev);
	}
}

void
ssows_reset(struct ssows *ws)
{
	uint64_t tag;
	uint64_t pend_tag;
	uint8_t pend_tt;
	uint8_t tt;

	tag = ssovf_read64(ws->base + SSOW_VHWS_TAG);
	pend_tag = ssovf_read64(ws->base + SSOW_VHWS_PENDTAG);

	if (pend_tag & (1ULL << 63)) { /* Tagswitch pending */
		pend_tt = (pend_tag >> 32) & 0x3;
		if (pend_tt == SSO_SYNC_ORDERED || pend_tt == SSO_SYNC_ATOMIC)
			ssows_desched(ws);
	} else {
		tt = (tag >> 32) & 0x3;
		if (tt == SSO_SYNC_ORDERED || tt == SSO_SYNC_ATOMIC)
			ssows_swtag_untag(ws);
	}
}

uint16_t
sso_event_tx_adapter_enqueue(void *port,
		struct rte_event ev[], uint16_t nb_events)
{
	uint16_t port_id;
	uint16_t queue_id;
	struct rte_mbuf *m;
	struct rte_eth_dev *ethdev;
	struct ssows *ws = port;
	struct octeontx_txq *txq;
	octeontx_dq_t *dq;

	RTE_SET_USED(nb_events);
	switch (ev->sched_type) {
	case SSO_SYNC_ORDERED:
		ssows_swtag_norm(ws, ev->event, SSO_SYNC_ATOMIC);
		rte_cio_wmb();
		ssows_swtag_wait(ws);
		break;
	case SSO_SYNC_UNTAGGED:
		ssows_swtag_full(ws, ev->u64, ev->event, SSO_SYNC_ATOMIC,
				ev->queue_id);
		rte_cio_wmb();
		ssows_swtag_wait(ws);
		break;
	case SSO_SYNC_ATOMIC:
		rte_cio_wmb();
		break;
	}

	m = ev[0].mbuf;
	port_id = m->port;
	queue_id = rte_event_eth_tx_adapter_txq_get(m);
	ethdev = &rte_eth_devices[port_id];
	txq = ethdev->data->tx_queues[queue_id];
	dq = &txq->dq;

	if (__octeontx_xmit_pkts(dq->lmtline_va, dq->ioreg_va, dq->fc_status_va,
				m) < 0)
		return 0;

	return 1;
}
