/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation.
 * Copyright(c) 2016-2018, Linaro Limited.
 */

#include <stdint.h>
#include <ethdev_driver.h>
#include <rte_malloc.h>
#include <rte_vect.h>

#include "base/i40e_prototype.h"
#include "base/i40e_type.h"
#include "i40e_ethdev.h"
#include "i40e_rxtx.h"
#include "i40e_rxtx_vec_common.h"


#pragma GCC diagnostic ignored "-Wcast-qual"

static inline void
i40e_rxq_rearm(struct i40e_rx_queue *rxq)
{
	int i;
	uint16_t rx_id;
	volatile union i40e_rx_desc *rxdp;
	struct i40e_rx_entry *rxep = &rxq->sw_ring[rxq->rxrearm_start];
	struct rte_mbuf *mb0, *mb1;
	uint64x2_t dma_addr0, dma_addr1;
	uint64x2_t zero = vdupq_n_u64(0);
	uint64_t paddr;

	rxdp = rxq->rx_ring + rxq->rxrearm_start;

	/* Pull 'n' more MBUFs into the software ring */
	if (unlikely(rte_mempool_get_bulk(rxq->mp,
					  (void *)rxep,
					  RTE_I40E_RXQ_REARM_THRESH) < 0)) {
		if (rxq->rxrearm_nb + RTE_I40E_RXQ_REARM_THRESH >=
		    rxq->nb_rx_desc) {
			for (i = 0; i < RTE_I40E_DESCS_PER_LOOP; i++) {
				rxep[i].mbuf = &rxq->fake_mbuf;
				vst1q_u64((uint64_t *)&rxdp[i].read, zero);
			}
		}
		rte_eth_devices[rxq->port_id].data->rx_mbuf_alloc_failed +=
			RTE_I40E_RXQ_REARM_THRESH;
		return;
	}

	/* Initialize the mbufs in vector, process 2 mbufs in one loop */
	for (i = 0; i < RTE_I40E_RXQ_REARM_THRESH; i += 2, rxep += 2) {
		mb0 = rxep[0].mbuf;
		mb1 = rxep[1].mbuf;

		paddr = mb0->buf_iova + RTE_PKTMBUF_HEADROOM;
		dma_addr0 = vdupq_n_u64(paddr);

		/* flush desc with pa dma_addr */
		vst1q_u64((uint64_t *)&rxdp++->read, dma_addr0);

		paddr = mb1->buf_iova + RTE_PKTMBUF_HEADROOM;
		dma_addr1 = vdupq_n_u64(paddr);
		vst1q_u64((uint64_t *)&rxdp++->read, dma_addr1);
	}

	rxq->rxrearm_start += RTE_I40E_RXQ_REARM_THRESH;
	if (rxq->rxrearm_start >= rxq->nb_rx_desc)
		rxq->rxrearm_start = 0;

	rxq->rxrearm_nb -= RTE_I40E_RXQ_REARM_THRESH;

	rx_id = (uint16_t)((rxq->rxrearm_start == 0) ?
			     (rxq->nb_rx_desc - 1) : (rxq->rxrearm_start - 1));

	rte_io_wmb();
	/* Update the tail pointer on the NIC */
	I40E_PCI_REG_WRITE_RELAXED(rxq->qrx_tail, rx_id);
}

#ifndef RTE_LIBRTE_I40E_16BYTE_RX_DESC
/* NEON version of FDIR mark extraction for 4 32B descriptors at a time */
static inline uint32x4_t
descs_to_fdir_32b(volatile union i40e_rx_desc *rxdp, struct rte_mbuf **rx_pkt)
{
	/* 32B descriptors: Load 2nd half of descriptors for FDIR ID data */
	uint64x2_t desc0_qw23, desc1_qw23, desc2_qw23, desc3_qw23;
	desc0_qw23 = vld1q_u64((uint64_t *)&(rxdp + 0)->wb.qword2);
	desc1_qw23 = vld1q_u64((uint64_t *)&(rxdp + 1)->wb.qword2);
	desc2_qw23 = vld1q_u64((uint64_t *)&(rxdp + 2)->wb.qword2);
	desc3_qw23 = vld1q_u64((uint64_t *)&(rxdp + 3)->wb.qword2);

	/* FDIR ID data: move last u32 of each desc to 4 u32 lanes */
	uint32x4_t v_unpack_02, v_unpack_13;
	v_unpack_02 = vzipq_u32(vreinterpretq_u32_u64(desc0_qw23),
				vreinterpretq_u32_u64(desc2_qw23)).val[1];
	v_unpack_13 = vzipq_u32(vreinterpretq_u32_u64(desc1_qw23),
				vreinterpretq_u32_u64(desc3_qw23)).val[1];
	uint32x4_t v_fdir_ids = vzipq_u32(v_unpack_02, v_unpack_13).val[1];

	/* Extended Status: extract from each lower 32 bits, to u32 lanes */
	v_unpack_02 = vzipq_u32(vreinterpretq_u32_u64(desc0_qw23),
				vreinterpretq_u32_u64(desc2_qw23)).val[0];
	v_unpack_13 = vzipq_u32(vreinterpretq_u32_u64(desc1_qw23),
				vreinterpretq_u32_u64(desc3_qw23)).val[0];
	uint32x4_t v_flt_status = vzipq_u32(v_unpack_02, v_unpack_13).val[0];

	/* Shift u32 left and right to "mask away" bits not required.
	 * Data required is 4:5 (zero based), so left shift by 26 (32-6)
	 * and then right shift by 30 (32 - 2 bits required).
	 */
	v_flt_status = vshlq_n_u32(v_flt_status, 26);
	v_flt_status = vshrq_n_u32(v_flt_status, 30);

	/* Generate constant 1 in all u32 lanes */
	RTE_BUILD_BUG_ON(I40E_RX_DESC_EXT_STATUS_FLEXBH_FD_ID != 1);
	uint32x4_t v_u32_one = vdupq_n_u32(1);

	/* Per desc mask, bits set if FDIR ID is valid */
	uint32x4_t v_fd_id_mask = vceqq_u32(v_flt_status, v_u32_one);

	/* Mask ID data to zero if the FD_ID bit not set in desc */
	v_fdir_ids = vandq_u32(v_fdir_ids, v_fd_id_mask);

	/* Store data to fdir.hi in mbuf */
	rx_pkt[0]->hash.fdir.hi = vgetq_lane_u32(v_fdir_ids, 0);
	rx_pkt[1]->hash.fdir.hi = vgetq_lane_u32(v_fdir_ids, 1);
	rx_pkt[2]->hash.fdir.hi = vgetq_lane_u32(v_fdir_ids, 2);
	rx_pkt[3]->hash.fdir.hi = vgetq_lane_u32(v_fdir_ids, 3);

	/* Convert fdir_id_mask into a single bit, then shift as required for
	 * correct location in the mbuf->olflags
	 */
	RTE_BUILD_BUG_ON(RTE_MBUF_F_RX_FDIR_ID != (1 << 13));
	v_fd_id_mask = vshrq_n_u32(v_fd_id_mask, 31);
	v_fd_id_mask = vshlq_n_u32(v_fd_id_mask, 13);

	/* The returned value must be combined into each mbuf. This is already
	 * being done for RSS and VLAN mbuf olflags, so return bits to OR in.
	 */
	return v_fd_id_mask;
}

#else /* 32 or 16B FDIR ID handling */

/* Handle 16B descriptor FDIR ID flag setting based on FLM(bit11). See scalar driver
 * for scalar implementation of the same functionality.
 */
static inline uint32x4_t
descs_to_fdir_16b(uint32x4_t fltstat, uint64x2_t descs[4], struct rte_mbuf **rx_pkt)
{
	/* Unpack filter-status data from descriptors */
	uint32x4_t v_tmp_02 = vzipq_u32(vreinterpretq_u32_u64(descs[0]),
					vreinterpretq_u32_u64(descs[2])).val[0];
	uint32x4_t v_tmp_13 = vzipq_u32(vreinterpretq_u32_u64(descs[1]),
					vreinterpretq_u32_u64(descs[3])).val[0];
	uint32x4_t v_fdir_ids = vzipq_u32(v_tmp_02, v_tmp_13).val[1];

	/* Generate 111 and 11 in each u32 lane */
	uint32x4_t v_111_mask = vdupq_n_u32(7);
	uint32x4_t v_11_mask = vdupq_n_u32(3);

	/* Compare and mask away FDIR ID data if bit not set */
	uint32x4_t v_u32_bits = vandq_u32(v_111_mask, fltstat);
	uint32x4_t v_fdir_id_mask = vceqq_u32(v_u32_bits, v_11_mask);
	v_fdir_ids = vandq_u32(v_fdir_id_mask, v_fdir_ids);

	/* Store data to fdir.hi in mbuf */
	rx_pkt[0]->hash.fdir.hi = vgetq_lane_u32(v_fdir_ids, 0);
	rx_pkt[1]->hash.fdir.hi = vgetq_lane_u32(v_fdir_ids, 1);
	rx_pkt[2]->hash.fdir.hi = vgetq_lane_u32(v_fdir_ids, 2);
	rx_pkt[3]->hash.fdir.hi = vgetq_lane_u32(v_fdir_ids, 3);

	/* Top lane ones mask for FDIR isolation */
	uint32x4_t v_desc_fdir_mask = {0, UINT32_MAX, 0, 0};

	/* Move fdir_id_mask to correct lane, zero RSS in mbuf if fdir hits */
	uint32x4_t v_zeros = {0, 0, 0, 0};
	uint32x4_t v_desc3_shift = vextq_u32(v_fdir_id_mask, v_zeros, 2);
	uint32x4_t v_desc3_mask = vandq_u32(v_desc_fdir_mask, v_desc3_shift);
	descs[3] = vreinterpretq_u64_u32(vbslq_u32(v_desc3_mask, v_zeros,
				vreinterpretq_u32_u64(descs[3])));

	uint32x4_t v_desc2_shift = vextq_u32(v_fdir_id_mask, v_zeros, 1);
	uint32x4_t v_desc2_mask = vandq_u32(v_desc_fdir_mask, v_desc2_shift);
	descs[2] = vreinterpretq_u64_u32(vbslq_u32(v_desc2_mask, v_zeros,
				vreinterpretq_u32_u64(descs[2])));

	uint32x4_t v_desc1_shift = v_fdir_id_mask;
	uint32x4_t v_desc1_mask = vandq_u32(v_desc_fdir_mask, v_desc1_shift);
	descs[1] = vreinterpretq_u64_u32(vbslq_u32(v_desc1_mask, v_zeros,
				vreinterpretq_u32_u64(descs[1])));

	uint32x4_t v_desc0_shift = vextq_u32(v_zeros, v_fdir_id_mask, 3);
	uint32x4_t v_desc0_mask = vandq_u32(v_desc_fdir_mask, v_desc0_shift);
	descs[0] = vreinterpretq_u64_u32(vbslq_u32(v_desc0_mask, v_zeros,
				vreinterpretq_u32_u64(descs[0])));

	/* Shift to 1 or 0 bit per u32 lane, then to RTE_MBUF_F_RX_FDIR_ID offset */
	RTE_BUILD_BUG_ON(RTE_MBUF_F_RX_FDIR_ID != (1 << 13));
	uint32x4_t v_mask_one_bit = vshrq_n_u32(v_fdir_id_mask, 31);
	return vshlq_n_u32(v_mask_one_bit, 13);
}
#endif

static inline void
desc_to_olflags_v(struct i40e_rx_queue *rxq, volatile union i40e_rx_desc *rxdp,
		  uint64x2_t descs[4], struct rte_mbuf **rx_pkts)
{
	uint32x4_t vlan0, vlan1, rss, l3_l4e;
	const uint64x2_t mbuf_init = {rxq->mbuf_initializer, 0};
	uint64x2_t rearm0, rearm1, rearm2, rearm3;

	/* mask everything except RSS, flow director and VLAN flags
	 * bit2 is for VLAN tag, bit11 for flow director indication
	 * bit13:12 for RSS indication.
	 */
	const uint32x4_t rss_vlan_msk = {
			0x1c03804, 0x1c03804, 0x1c03804, 0x1c03804};

	const uint32x4_t cksum_mask = {
			RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_IP_CKSUM_BAD |
			RTE_MBUF_F_RX_L4_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD |
			RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD,
			RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_IP_CKSUM_BAD |
			RTE_MBUF_F_RX_L4_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD |
			RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD,
			RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_IP_CKSUM_BAD |
			RTE_MBUF_F_RX_L4_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD |
			RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD,
			RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_IP_CKSUM_BAD |
			RTE_MBUF_F_RX_L4_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD |
			RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD};

	/* map rss and vlan type to rss hash and vlan flag */
	const uint8x16_t vlan_flags = {
			0, 0, 0, 0,
			RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0};

	const uint8x16_t rss_flags = {
			0, RTE_MBUF_F_RX_FDIR, 0, 0,
			0, 0, RTE_MBUF_F_RX_RSS_HASH, RTE_MBUF_F_RX_RSS_HASH | RTE_MBUF_F_RX_FDIR,
			0, 0, 0, 0,
			0, 0, 0, 0};

	const uint8x16_t l3_l4e_flags = {
			(RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
			RTE_MBUF_F_RX_IP_CKSUM_BAD >> 1,
			(RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
			(RTE_MBUF_F_RX_L4_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_BAD) >> 1,
			(RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD) >> 1,
			(RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_BAD) >> 1,
			(RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD |
			 RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
			(RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD |
			 RTE_MBUF_F_RX_IP_CKSUM_BAD) >> 1,
			0, 0, 0, 0, 0, 0, 0, 0};

	vlan0 = vzipq_u32(vreinterpretq_u32_u64(descs[0]),
			  vreinterpretq_u32_u64(descs[2])).val[1];
	vlan1 = vzipq_u32(vreinterpretq_u32_u64(descs[1]),
			  vreinterpretq_u32_u64(descs[3])).val[1];
	vlan0 = vzipq_u32(vlan0, vlan1).val[0];

	vlan1 = vandq_u32(vlan0, rss_vlan_msk);
	vlan0 = vreinterpretq_u32_u8(vqtbl1q_u8(vlan_flags,
						vreinterpretq_u8_u32(vlan1)));

	const uint32x4_t desc_fltstat = vshrq_n_u32(vlan1, 11);
	rss = vreinterpretq_u32_u8(vqtbl1q_u8(rss_flags,
					      vreinterpretq_u8_u32(desc_fltstat)));

	l3_l4e = vshrq_n_u32(vlan1, 22);
	l3_l4e = vreinterpretq_u32_u8(vqtbl1q_u8(l3_l4e_flags,
					      vreinterpretq_u8_u32(l3_l4e)));
	/* then we shift left 1 bit */
	l3_l4e = vshlq_n_u32(l3_l4e, 1);
	/* we need to mask out the redundant bits */
	l3_l4e = vandq_u32(l3_l4e, cksum_mask);

	vlan0 = vorrq_u32(vlan0, rss);
	vlan0 = vorrq_u32(vlan0, l3_l4e);

	/* Extract FDIR ID only if FDIR is enabled to avoid useless work */
	if (rxq->fdir_enabled) {
#ifndef RTE_LIBRTE_I40E_16BYTE_RX_DESC
		uint32x4_t v_fdir_ol_flags = descs_to_fdir_32b(rxdp, rx_pkts);
#else
		(void)rxdp; /* rxdp not required for 16B desc mode */
		uint32x4_t v_fdir_ol_flags = descs_to_fdir_16b(desc_fltstat, descs, rx_pkts);
#endif
		/* OR in ol_flag bits after descriptor specific extraction */
		vlan0 = vorrq_u32(vlan0, v_fdir_ol_flags);
	}

	rearm0 = vsetq_lane_u64(vgetq_lane_u32(vlan0, 0), mbuf_init, 1);
	rearm1 = vsetq_lane_u64(vgetq_lane_u32(vlan0, 1), mbuf_init, 1);
	rearm2 = vsetq_lane_u64(vgetq_lane_u32(vlan0, 2), mbuf_init, 1);
	rearm3 = vsetq_lane_u64(vgetq_lane_u32(vlan0, 3), mbuf_init, 1);

	vst1q_u64((uint64_t *)&rx_pkts[0]->rearm_data, rearm0);
	vst1q_u64((uint64_t *)&rx_pkts[1]->rearm_data, rearm1);
	vst1q_u64((uint64_t *)&rx_pkts[2]->rearm_data, rearm2);
	vst1q_u64((uint64_t *)&rx_pkts[3]->rearm_data, rearm3);
}

#define PKTLEN_SHIFT     10
#define I40E_UINT16_BIT (CHAR_BIT * sizeof(uint16_t))

static inline void
desc_to_ptype_v(uint64x2_t descs[4], struct rte_mbuf **__rte_restrict rx_pkts,
		uint32_t *__rte_restrict ptype_tbl)
{
	int i;
	uint8_t ptype;
	uint8x16_t tmp;

	for (i = 0; i < 4; i++) {
		tmp = vreinterpretq_u8_u64(vshrq_n_u64(descs[i], 30));
		ptype = vgetq_lane_u8(tmp, 8);
		rx_pkts[i]->packet_type = ptype_tbl[ptype];
	}

}

/**
 * vPMD raw receive routine, only accept(nb_pkts >= RTE_I40E_DESCS_PER_LOOP)
 *
 * Notice:
 * - nb_pkts < RTE_I40E_DESCS_PER_LOOP, just return no packet
 * - floor align nb_pkts to a RTE_I40E_DESCS_PER_LOOP power-of-two
 */
static inline uint16_t
_recv_raw_pkts_vec(struct i40e_rx_queue *__rte_restrict rxq,
		   struct rte_mbuf **__rte_restrict rx_pkts,
		   uint16_t nb_pkts, uint8_t *split_packet)
{
	volatile union i40e_rx_desc *rxdp;
	struct i40e_rx_entry *sw_ring;
	uint16_t nb_pkts_recd;
	int pos;
	uint32_t *ptype_tbl = rxq->vsi->adapter->ptype_tbl;

	/* mask to shuffle from desc. to mbuf */
	uint8x16_t shuf_msk = {
		0xFF, 0xFF,   /* pkt_type set as unknown */
		0xFF, 0xFF,   /* pkt_type set as unknown */
		14, 15,       /* octet 15~14, low 16 bits pkt_len */
		0xFF, 0xFF,   /* skip high 16 bits pkt_len, zero out */
		14, 15,       /* octet 15~14, 16 bits data_len */
		2, 3,         /* octet 2~3, low 16 bits vlan_macip */
		4, 5, 6, 7    /* octet 4~7, 32bits rss */
		};

	uint8x16_t eop_check = {
		0x02, 0x00, 0x02, 0x00,
		0x02, 0x00, 0x02, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00
		};

	uint16x8_t crc_adjust = {
		0, 0,         /* ignore pkt_type field */
		rxq->crc_len, /* sub crc on pkt_len */
		0,            /* ignore high-16bits of pkt_len */
		rxq->crc_len, /* sub crc on data_len */
		0, 0, 0       /* ignore non-length fields */
		};

	/* nb_pkts has to be floor-aligned to RTE_I40E_DESCS_PER_LOOP */
	nb_pkts = RTE_ALIGN_FLOOR(nb_pkts, RTE_I40E_DESCS_PER_LOOP);

	/* Just the act of getting into the function from the application is
	 * going to cost about 7 cycles
	 */
	rxdp = rxq->rx_ring + rxq->rx_tail;

	rte_prefetch_non_temporal(rxdp);

	/* See if we need to rearm the RX queue - gives the prefetch a bit
	 * of time to act
	 */
	if (rxq->rxrearm_nb > RTE_I40E_RXQ_REARM_THRESH)
		i40e_rxq_rearm(rxq);

	/* Before we start moving massive data around, check to see if
	 * there is actually a packet available
	 */
	if (!(rxdp->wb.qword1.status_error_len &
			rte_cpu_to_le_32(1 << I40E_RX_DESC_STATUS_DD_SHIFT)))
		return 0;

	/* Cache is empty -> need to scan the buffer rings, but first move
	 * the next 'n' mbufs into the cache
	 */
	sw_ring = &rxq->sw_ring[rxq->rx_tail];

	/* A. load 4 packet in one loop
	 * [A*. mask out 4 unused dirty field in desc]
	 * B. copy 4 mbuf point from swring to rx_pkts
	 * C. calc the number of DD bits among the 4 packets
	 * [C*. extract the end-of-packet bit, if requested]
	 * D. fill info. from desc to mbuf
	 */

	for (pos = 0, nb_pkts_recd = 0; pos < nb_pkts;
			pos += RTE_I40E_DESCS_PER_LOOP,
			rxdp += RTE_I40E_DESCS_PER_LOOP) {
		uint64x2_t descs[RTE_I40E_DESCS_PER_LOOP];
		uint8x16_t pkt_mb1, pkt_mb2, pkt_mb3, pkt_mb4;
		uint16x8x2_t sterr_tmp1, sterr_tmp2;
		uint64x2_t mbp1, mbp2;
		uint16x8_t staterr;
		uint16x8_t tmp;
		uint64_t stat;

		int32x4_t len_shl = {0, 0, 0, PKTLEN_SHIFT};

		/* A.1 load desc[3-0] */
		descs[3] =  vld1q_u64((uint64_t *)(rxdp + 3));
		descs[2] =  vld1q_u64((uint64_t *)(rxdp + 2));
		descs[1] =  vld1q_u64((uint64_t *)(rxdp + 1));
		descs[0] =  vld1q_u64((uint64_t *)(rxdp));

		/* Use acquire fence to order loads of descriptor qwords */
		rte_atomic_thread_fence(__ATOMIC_ACQUIRE);
		/* A.2 reload qword0 to make it ordered after qword1 load */
		descs[3] = vld1q_lane_u64((uint64_t *)(rxdp + 3), descs[3], 0);
		descs[2] = vld1q_lane_u64((uint64_t *)(rxdp + 2), descs[2], 0);
		descs[1] = vld1q_lane_u64((uint64_t *)(rxdp + 1), descs[1], 0);
		descs[0] = vld1q_lane_u64((uint64_t *)(rxdp), descs[0], 0);

		/* B.1 load 4 mbuf point */
		mbp1 = vld1q_u64((uint64_t *)&sw_ring[pos]);
		mbp2 = vld1q_u64((uint64_t *)&sw_ring[pos + 2]);

		/* B.2 copy 4 mbuf point into rx_pkts  */
		vst1q_u64((uint64_t *)&rx_pkts[pos], mbp1);
		vst1q_u64((uint64_t *)&rx_pkts[pos + 2], mbp2);

		if (split_packet) {
			rte_mbuf_prefetch_part2(rx_pkts[pos]);
			rte_mbuf_prefetch_part2(rx_pkts[pos + 1]);
			rte_mbuf_prefetch_part2(rx_pkts[pos + 2]);
			rte_mbuf_prefetch_part2(rx_pkts[pos + 3]);
		}

		/* pkts shift the pktlen field to be 16-bit aligned*/
		uint32x4_t len3 = vshlq_u32(vreinterpretq_u32_u64(descs[3]),
					    len_shl);
		descs[3] = vreinterpretq_u64_u16(vsetq_lane_u16
				(vgetq_lane_u16(vreinterpretq_u16_u32(len3), 7),
				 vreinterpretq_u16_u64(descs[3]),
				 7));
		uint32x4_t len2 = vshlq_u32(vreinterpretq_u32_u64(descs[2]),
					    len_shl);
		descs[2] = vreinterpretq_u64_u16(vsetq_lane_u16
				(vgetq_lane_u16(vreinterpretq_u16_u32(len2), 7),
				 vreinterpretq_u16_u64(descs[2]),
				 7));
		uint32x4_t len1 = vshlq_u32(vreinterpretq_u32_u64(descs[1]),
					    len_shl);
		descs[1] = vreinterpretq_u64_u16(vsetq_lane_u16
				(vgetq_lane_u16(vreinterpretq_u16_u32(len1), 7),
				 vreinterpretq_u16_u64(descs[1]),
				 7));
		uint32x4_t len0 = vshlq_u32(vreinterpretq_u32_u64(descs[0]),
					    len_shl);
		descs[0] = vreinterpretq_u64_u16(vsetq_lane_u16
				(vgetq_lane_u16(vreinterpretq_u16_u32(len0), 7),
				 vreinterpretq_u16_u64(descs[0]),
				 7));

		desc_to_olflags_v(rxq, rxdp, descs, &rx_pkts[pos]);

		/* D.1 pkts convert format from desc to pktmbuf */
		pkt_mb4 = vqtbl1q_u8(vreinterpretq_u8_u64(descs[3]), shuf_msk);
		pkt_mb3 = vqtbl1q_u8(vreinterpretq_u8_u64(descs[2]), shuf_msk);
		pkt_mb2 = vqtbl1q_u8(vreinterpretq_u8_u64(descs[1]), shuf_msk);
		pkt_mb1 = vqtbl1q_u8(vreinterpretq_u8_u64(descs[0]), shuf_msk);

		/* D.2 pkts set in_port/nb_seg and remove crc */
		tmp = vsubq_u16(vreinterpretq_u16_u8(pkt_mb4), crc_adjust);
		pkt_mb4 = vreinterpretq_u8_u16(tmp);
		tmp = vsubq_u16(vreinterpretq_u16_u8(pkt_mb3), crc_adjust);
		pkt_mb3 = vreinterpretq_u8_u16(tmp);
		tmp = vsubq_u16(vreinterpretq_u16_u8(pkt_mb2), crc_adjust);
		pkt_mb2 = vreinterpretq_u8_u16(tmp);
		tmp = vsubq_u16(vreinterpretq_u16_u8(pkt_mb1), crc_adjust);
		pkt_mb1 = vreinterpretq_u8_u16(tmp);

		/* D.3 copy final data to rx_pkts */
		vst1q_u8((void *)&rx_pkts[pos + 3]->rx_descriptor_fields1,
				pkt_mb4);
		vst1q_u8((void *)&rx_pkts[pos + 2]->rx_descriptor_fields1,
				pkt_mb3);
		vst1q_u8((void *)&rx_pkts[pos + 1]->rx_descriptor_fields1,
				pkt_mb2);
		vst1q_u8((void *)&rx_pkts[pos]->rx_descriptor_fields1,
				pkt_mb1);

		desc_to_ptype_v(descs, &rx_pkts[pos], ptype_tbl);

		if (likely(pos + RTE_I40E_DESCS_PER_LOOP < nb_pkts)) {
			rte_prefetch_non_temporal(rxdp + RTE_I40E_DESCS_PER_LOOP);
		}

		/* C.1 4=>2 filter staterr info only */
		sterr_tmp2 = vzipq_u16(vreinterpretq_u16_u64(descs[1]),
				       vreinterpretq_u16_u64(descs[3]));
		sterr_tmp1 = vzipq_u16(vreinterpretq_u16_u64(descs[0]),
				       vreinterpretq_u16_u64(descs[2]));

		/* C.2 get 4 pkts staterr value  */
		staterr = vzipq_u16(sterr_tmp1.val[1],
				    sterr_tmp2.val[1]).val[0];

		/* C* extract and record EOP bit */
		if (split_packet) {
			uint8x16_t eop_shuf_mask = {
					0x00, 0x02, 0x04, 0x06,
					0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF};
			uint8x16_t eop_bits;

			/* and with mask to extract bits, flipping 1-0 */
			eop_bits = vmvnq_u8(vreinterpretq_u8_u16(staterr));
			eop_bits = vandq_u8(eop_bits, eop_check);
			/* the staterr values are not in order, as the count
			 * of dd bits doesn't care. However, for end of
			 * packet tracking, we do care, so shuffle. This also
			 * compresses the 32-bit values to 8-bit
			 */
			eop_bits = vqtbl1q_u8(eop_bits, eop_shuf_mask);

			/* store the resulting 32-bit value */
			vst1q_lane_u32((uint32_t *)split_packet,
				       vreinterpretq_u32_u8(eop_bits), 0);
			split_packet += RTE_I40E_DESCS_PER_LOOP;

			/* zero-out next pointers */
			rx_pkts[pos]->next = NULL;
			rx_pkts[pos + 1]->next = NULL;
			rx_pkts[pos + 2]->next = NULL;
			rx_pkts[pos + 3]->next = NULL;
		}

		staterr = vshlq_n_u16(staterr, I40E_UINT16_BIT - 1);
		staterr = vreinterpretq_u16_s16(
				vshrq_n_s16(vreinterpretq_s16_u16(staterr),
					    I40E_UINT16_BIT - 1));
		stat = ~vgetq_lane_u64(vreinterpretq_u64_u16(staterr), 0);

		/* C.4 calc available number of desc */
		if (unlikely(stat == 0)) {
			nb_pkts_recd += RTE_I40E_DESCS_PER_LOOP;
		} else {
			nb_pkts_recd += __builtin_ctzl(stat) / I40E_UINT16_BIT;
			break;
		}
	}

	/* Update our internal tail pointer */
	rxq->rx_tail = (uint16_t)(rxq->rx_tail + nb_pkts_recd);
	rxq->rx_tail = (uint16_t)(rxq->rx_tail & (rxq->nb_rx_desc - 1));
	rxq->rxrearm_nb = (uint16_t)(rxq->rxrearm_nb + nb_pkts_recd);

	return nb_pkts_recd;
}

 /*
 * Notice:
 * - nb_pkts < RTE_I40E_DESCS_PER_LOOP, just return no packet
 */
uint16_t
i40e_recv_pkts_vec(void *__rte_restrict rx_queue,
		struct rte_mbuf **__rte_restrict rx_pkts, uint16_t nb_pkts)
{
	return _recv_raw_pkts_vec(rx_queue, rx_pkts, nb_pkts, NULL);
}

/**
 * vPMD receive routine that reassembles single burst of 32 scattered packets
 *
 * Notice:
 * - nb_pkts < RTE_I40E_DESCS_PER_LOOP, just return no packet
 */
static uint16_t
i40e_recv_scattered_burst_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
			      uint16_t nb_pkts)
{

	struct i40e_rx_queue *rxq = rx_queue;
	uint8_t split_flags[RTE_I40E_VPMD_RX_BURST] = {0};

	/* get some new buffers */
	uint16_t nb_bufs = _recv_raw_pkts_vec(rxq, rx_pkts, nb_pkts,
			split_flags);
	if (nb_bufs == 0)
		return 0;

	/* happy day case, full burst + no packets to be joined */
	const uint64_t *split_fl64 = (uint64_t *)split_flags;

	if (rxq->pkt_first_seg == NULL &&
			split_fl64[0] == 0 && split_fl64[1] == 0 &&
			split_fl64[2] == 0 && split_fl64[3] == 0)
		return nb_bufs;

	/* reassemble any packets that need reassembly*/
	unsigned i = 0;

	if (rxq->pkt_first_seg == NULL) {
		/* find the first split flag, and only reassemble then*/
		while (i < nb_bufs && !split_flags[i])
			i++;
		if (i == nb_bufs)
			return nb_bufs;
		rxq->pkt_first_seg = rx_pkts[i];
	}
	return i + reassemble_packets(rxq, &rx_pkts[i], nb_bufs - i,
		&split_flags[i]);
}

/**
 * vPMD receive routine that reassembles scattered packets.
 */
uint16_t
i40e_recv_scattered_pkts_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
			     uint16_t nb_pkts)
{
	uint16_t retval = 0;

	while (nb_pkts > RTE_I40E_VPMD_RX_BURST) {
		uint16_t burst;

		burst = i40e_recv_scattered_burst_vec(rx_queue,
						      rx_pkts + retval,
						      RTE_I40E_VPMD_RX_BURST);
		retval += burst;
		nb_pkts -= burst;
		if (burst < RTE_I40E_VPMD_RX_BURST)
			return retval;
	}

	return retval + i40e_recv_scattered_burst_vec(rx_queue,
						      rx_pkts + retval,
						      nb_pkts);
}

static inline void
vtx1(volatile struct i40e_tx_desc *txdp,
		struct rte_mbuf *pkt, uint64_t flags)
{
	uint64_t high_qw = (I40E_TX_DESC_DTYPE_DATA |
			((uint64_t)flags  << I40E_TXD_QW1_CMD_SHIFT) |
			((uint64_t)pkt->data_len << I40E_TXD_QW1_TX_BUF_SZ_SHIFT));

	uint64x2_t descriptor = {pkt->buf_iova + pkt->data_off, high_qw};
	vst1q_u64((uint64_t *)txdp, descriptor);
}

static inline void
vtx(volatile struct i40e_tx_desc *txdp, struct rte_mbuf **pkt,
		uint16_t nb_pkts,  uint64_t flags)
{
	int i;

	for (i = 0; i < nb_pkts; ++i, ++txdp, ++pkt)
		vtx1(txdp, *pkt, flags);
}

uint16_t
i40e_xmit_fixed_burst_vec(void *__rte_restrict tx_queue,
	struct rte_mbuf **__rte_restrict tx_pkts, uint16_t nb_pkts)
{
	struct i40e_tx_queue *txq = (struct i40e_tx_queue *)tx_queue;
	volatile struct i40e_tx_desc *txdp;
	struct i40e_tx_entry *txep;
	uint16_t n, nb_commit, tx_id;
	uint64_t flags = I40E_TD_CMD;
	uint64_t rs = I40E_TX_DESC_CMD_RS | I40E_TD_CMD;
	int i;

	if (txq->nb_tx_free < txq->tx_free_thresh)
		i40e_tx_free_bufs(txq);

	nb_commit = nb_pkts = (uint16_t)RTE_MIN(txq->nb_tx_free, nb_pkts);
	if (unlikely(nb_pkts == 0))
		return 0;

	tx_id = txq->tx_tail;
	txdp = &txq->tx_ring[tx_id];
	txep = &txq->sw_ring[tx_id];

	txq->nb_tx_free = (uint16_t)(txq->nb_tx_free - nb_pkts);

	n = (uint16_t)(txq->nb_tx_desc - tx_id);
	if (nb_commit >= n) {
		tx_backlog_entry(txep, tx_pkts, n);

		for (i = 0; i < n - 1; ++i, ++tx_pkts, ++txdp)
			vtx1(txdp, *tx_pkts, flags);

		vtx1(txdp, *tx_pkts++, rs);

		nb_commit = (uint16_t)(nb_commit - n);

		tx_id = 0;
		txq->tx_next_rs = (uint16_t)(txq->tx_rs_thresh - 1);

		/* avoid reach the end of ring */
		txdp = &txq->tx_ring[tx_id];
		txep = &txq->sw_ring[tx_id];
	}

	tx_backlog_entry(txep, tx_pkts, nb_commit);

	vtx(txdp, tx_pkts, nb_commit, flags);

	tx_id = (uint16_t)(tx_id + nb_commit);
	if (tx_id > txq->tx_next_rs) {
		txq->tx_ring[txq->tx_next_rs].cmd_type_offset_bsz |=
			rte_cpu_to_le_64(((uint64_t)I40E_TX_DESC_CMD_RS) <<
						I40E_TXD_QW1_CMD_SHIFT);
		txq->tx_next_rs =
			(uint16_t)(txq->tx_next_rs + txq->tx_rs_thresh);
	}

	txq->tx_tail = tx_id;

	rte_io_wmb();
	I40E_PCI_REG_WRITE_RELAXED(txq->qtx_tail, tx_id);

	return nb_pkts;
}

void __rte_cold
i40e_rx_queue_release_mbufs_vec(struct i40e_rx_queue *rxq)
{
	_i40e_rx_queue_release_mbufs_vec(rxq);
}

int __rte_cold
i40e_rxq_vec_setup(struct i40e_rx_queue *rxq)
{
	return i40e_rxq_vec_setup_default(rxq);
}

int __rte_cold
i40e_txq_vec_setup(struct i40e_tx_queue __rte_unused *txq)
{
	return 0;
}

int __rte_cold
i40e_rx_vec_dev_conf_condition_check(struct rte_eth_dev *dev)
{
	return i40e_rx_vec_dev_conf_condition_check_default(dev);
}
