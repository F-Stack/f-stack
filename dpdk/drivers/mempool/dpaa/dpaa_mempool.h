/* SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright 2017,2019 NXP
 *
 */
#ifndef __DPAA_MEMPOOL_H__
#define __DPAA_MEMPOOL_H__

/* System headers */
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>

#include <rte_mempool.h>

#include <bus_dpaa_driver.h>
#include <rte_dpaa_logs.h>

#include <fsl_usd.h>
#include <fsl_bman.h>

#define CPU_SPIN_BACKOFF_CYCLES               512

/* total number of bpools on SoC */
#define DPAA_MAX_BPOOLS	256

/* Maximum release/acquire from BMAN */
#define DPAA_MBUF_MAX_ACQ_REL  8

/* Buffers are allocated from single mem segment i.e. phys contiguous */
#define DPAA_MPOOL_SINGLE_SEGMENT  0x01

struct dpaa_bp_info {
	struct rte_mempool *mp;
	struct bman_pool *bp;
	uint32_t bpid;
	uint32_t size;
	uint32_t meta_data_size;
	int32_t dpaa_ops_index;
	int64_t ptov_off;
	uint8_t flags;
};

static inline void *
DPAA_MEMPOOL_PTOV(struct dpaa_bp_info *bp_info __rte_unused, uint64_t addr)
{
	return rte_dpaa_mem_ptov(addr);
}

#define DPAA_MEMPOOL_TO_POOL_INFO(__mp) \
	((struct dpaa_bp_info *)__mp->pool_data)

#define DPAA_MEMPOOL_TO_BPID(__mp) \
	(((struct dpaa_bp_info *)__mp->pool_data)->bpid)

extern struct dpaa_bp_info *rte_dpaa_bpid_info;

#define DPAA_BPID_TO_POOL_INFO(__bpid) (&rte_dpaa_bpid_info[__bpid])

/* Mempool related logs */

#define DPAA_MEMPOOL_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, dpaa_logtype_mempool, "%s(): " fmt "\n", \
		__func__, ##args)

#define MEMPOOL_INIT_FUNC_TRACE() DPAA_MEMPOOL_LOG(DEBUG, " >>")

#define DPAA_MEMPOOL_DPDEBUG(fmt, args...) \
	RTE_LOG_DP(DEBUG, PMD, fmt, ## args)
#define DPAA_MEMPOOL_DEBUG(fmt, args...) \
	DPAA_MEMPOOL_LOG(DEBUG, fmt, ## args)
#define DPAA_MEMPOOL_ERR(fmt, args...) \
	DPAA_MEMPOOL_LOG(ERR, fmt, ## args)
#define DPAA_MEMPOOL_INFO(fmt, args...) \
	DPAA_MEMPOOL_LOG(INFO, fmt, ## args)
#define DPAA_MEMPOOL_WARN(fmt, args...) \
	DPAA_MEMPOOL_LOG(WARNING, fmt, ## args)

#endif
