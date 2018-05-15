/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdint.h>

#include <rte_mbuf.h>

#include "virtqueue.h"
#include "virtio_logs.h"
#include "virtio_pci.h"
#include "virtio_rxtx_simple.h"

/*
 * Two types of mbuf to be cleaned:
 * 1) mbuf that has been consumed by backend but not used by virtio.
 * 2) mbuf that hasn't been consued by backend.
 */
struct rte_mbuf *
virtqueue_detatch_unused(struct virtqueue *vq)
{
	struct rte_mbuf *cookie;
	struct virtio_hw *hw;
	uint16_t start, end;
	int type, idx;

	if (vq == NULL)
		return NULL;

	hw = vq->hw;
	type = virtio_get_queue_type(hw, vq->vq_queue_index);
	start = vq->vq_avail_idx & (vq->vq_nentries - 1);
	end = (vq->vq_avail_idx + vq->vq_free_cnt) & (vq->vq_nentries - 1);

	for (idx = 0; idx < vq->vq_nentries; idx++) {
		if (hw->use_simple_rx && type == VTNET_RQ) {
			if (start <= end && idx >= start && idx < end)
				continue;
			if (start > end && (idx >= start || idx < end))
				continue;
			cookie = vq->sw_ring[idx];
			if (cookie != NULL) {
				vq->sw_ring[idx] = NULL;
				return cookie;
			}
		} else {
			cookie = vq->vq_descx[idx].cookie;
			if (cookie != NULL) {
				vq->vq_descx[idx].cookie = NULL;
				return cookie;
			}
		}
	}

	return NULL;
}

/* Flush the elements in the used ring. */
void
virtqueue_rxvq_flush(struct virtqueue *vq)
{
	struct virtnet_rx *rxq = &vq->rxq;
	struct virtio_hw *hw = vq->hw;
	struct vring_used_elem *uep;
	struct vq_desc_extra *dxp;
	uint16_t used_idx, desc_idx;
	uint16_t nb_used, i;

	nb_used = VIRTQUEUE_NUSED(vq);

	for (i = 0; i < nb_used; i++) {
		used_idx = vq->vq_used_cons_idx & (vq->vq_nentries - 1);
		uep = &vq->vq_ring.used->ring[used_idx];
		if (hw->use_simple_rx) {
			desc_idx = used_idx;
			rte_pktmbuf_free(vq->sw_ring[desc_idx]);
			vq->vq_free_cnt++;
		} else {
			desc_idx = (uint16_t)uep->id;
			dxp = &vq->vq_descx[desc_idx];
			if (dxp->cookie != NULL) {
				rte_pktmbuf_free(dxp->cookie);
				dxp->cookie = NULL;
			}
			vq_ring_free_chain(vq, desc_idx);
		}
		vq->vq_used_cons_idx++;
	}

	if (hw->use_simple_rx) {
		while (vq->vq_free_cnt >= RTE_VIRTIO_VPMD_RX_REARM_THRESH) {
			virtio_rxq_rearm_vec(rxq);
			if (virtqueue_kick_prepare(vq))
				virtqueue_notify(vq);
		}
	}
}
