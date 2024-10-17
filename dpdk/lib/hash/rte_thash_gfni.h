/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#ifndef _RTE_THASH_GFNI_H_
#define _RTE_THASH_GFNI_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_compat.h>
#include <rte_log.h>

#ifdef RTE_ARCH_X86

#include <rte_thash_x86_gfni.h>

#endif

#ifndef RTE_THASH_GFNI_DEFINED

/**
 * Calculate Toeplitz hash.
 * Dummy implementation.
 *
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * @param m
 *  Pointer to the matrices generated from the corresponding
 *  RSS hash key using rte_thash_complete_matrix().
 * @param tuple
 *  Pointer to the data to be hashed. Data must be in network byte order.
 * @param len
 *  Length of the data to be hashed.
 * @return
 *  Calculated Toeplitz hash value.
 */
__rte_experimental
static inline uint32_t
rte_thash_gfni(const uint64_t *mtrx __rte_unused,
	const uint8_t *key __rte_unused, int len __rte_unused)
{
	RTE_LOG(ERR, HASH, "%s is undefined under given arch\n", __func__);
	return 0;
}

/**
 * Bulk implementation for Toeplitz hash.
 * Dummy implementation.
 *
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * @param m
 *  Pointer to the matrices generated from the corresponding
 *  RSS hash key using rte_thash_complete_matrix().
 * @param len
 *  Length of the largest data buffer to be hashed.
 * @param tuple
 *  Array of the pointers on data to be hashed.
 *  Data must be in network byte order.
 * @param val
 *  Array of uint32_t where to put calculated Toeplitz hash values
 * @param num
 *  Number of tuples to hash.
 */
__rte_experimental
static inline void
rte_thash_gfni_bulk(const uint64_t *mtrx __rte_unused,
	int len __rte_unused, uint8_t *tuple[] __rte_unused,
	uint32_t val[], uint32_t num)
{
	unsigned int i;

	RTE_LOG(ERR, HASH, "%s is undefined under given arch\n", __func__);
	for (i = 0; i < num; i++)
		val[i] = 0;
}

#endif /* RTE_THASH_GFNI_DEFINED */

#ifdef __cplusplus
}
#endif

#endif /* _RTE_THASH_GFNI_H_ */
