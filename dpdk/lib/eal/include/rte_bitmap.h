/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef __INCLUDE_RTE_BITMAP_H__
#define __INCLUDE_RTE_BITMAP_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * RTE Bitmap
 *
 * The bitmap component provides a mechanism to manage large arrays of bits
 * through bit get/set/clear and bit array scan operations.
 *
 * The bitmap scan operation is optimized for 64-bit CPUs using 64/128 byte cache
 * lines. The bitmap is hierarchically organized using two arrays (array1 and
 * array2), with each bit in array1 being associated with a full cache line
 * (512/1024 bits) of bitmap bits, which are stored in array2: the bit in array1
 * is set only when there is at least one bit set within its associated array2
 * bits, otherwise the bit in array1 is cleared. The read and write operations
 * for array1 and array2 are always done in slabs of 64 bits.
 *
 * This bitmap is not thread safe. For lock free operation on a specific bitmap
 * instance, a single writer thread performing bit set/clear operations is
 * allowed, only the writer thread can do bitmap scan operations, while there
 * can be several reader threads performing bit get operations in parallel with
 * the writer thread. When the use of locking primitives is acceptable, the
 * serialization of the bit set/clear and bitmap scan operations needs to be
 * enforced by the caller, while the bit get operation does not require locking
 * the bitmap.
 *
 ***/

#include <string.h>
#include <rte_compat.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_debug.h>
#include <rte_memory.h>
#include <rte_branch_prediction.h>
#include <rte_prefetch.h>

/* Slab */
#define RTE_BITMAP_SLAB_BIT_SIZE                 64
#define RTE_BITMAP_SLAB_BIT_SIZE_LOG2            6
#define RTE_BITMAP_SLAB_BIT_MASK                 (RTE_BITMAP_SLAB_BIT_SIZE - 1)

/* Cache line (CL) */
#define RTE_BITMAP_CL_BIT_SIZE                   (RTE_CACHE_LINE_SIZE * 8)
#define RTE_BITMAP_CL_BIT_SIZE_LOG2              (RTE_CACHE_LINE_SIZE_LOG2 + 3)
#define RTE_BITMAP_CL_BIT_MASK                   (RTE_BITMAP_CL_BIT_SIZE - 1)

#define RTE_BITMAP_CL_SLAB_SIZE                  (RTE_BITMAP_CL_BIT_SIZE / RTE_BITMAP_SLAB_BIT_SIZE)
#define RTE_BITMAP_CL_SLAB_SIZE_LOG2             (RTE_BITMAP_CL_BIT_SIZE_LOG2 - RTE_BITMAP_SLAB_BIT_SIZE_LOG2)
#define RTE_BITMAP_CL_SLAB_MASK                  (RTE_BITMAP_CL_SLAB_SIZE - 1)

/** Bitmap data structure */
struct rte_bitmap {
	/* Context for array1 and array2 */
	uint64_t *array1;                        /**< Bitmap array1 */
	uint64_t *array2;                        /**< Bitmap array2 */
	uint32_t array1_size;                    /**< Number of 64-bit slabs in array1 that are actually used */
	uint32_t array2_size;                    /**< Number of 64-bit slabs in array2 */

	/* Context for the "scan next" operation */
	uint32_t index1;  /**< Bitmap scan: Index of current array1 slab */
	uint32_t offset1; /**< Bitmap scan: Offset of current bit within current array1 slab */
	uint32_t index2;  /**< Bitmap scan: Index of current array2 slab */
	uint32_t go2;     /**< Bitmap scan: Go/stop condition for current array2 cache line */

	/* Storage space for array1 and array2 */
	uint8_t memory[];
};

static inline void
__rte_bitmap_index1_inc(struct rte_bitmap *bmp)
{
	bmp->index1 = (bmp->index1 + 1) & (bmp->array1_size - 1);
}

static inline uint64_t
__rte_bitmap_mask1_get(struct rte_bitmap *bmp)
{
	return (~1llu) << bmp->offset1;
}

static inline void
__rte_bitmap_index2_set(struct rte_bitmap *bmp)
{
	bmp->index2 = (((bmp->index1 << RTE_BITMAP_SLAB_BIT_SIZE_LOG2) + bmp->offset1) << RTE_BITMAP_CL_SLAB_SIZE_LOG2);
}

static inline uint32_t
__rte_bitmap_get_memory_footprint(uint32_t n_bits,
	uint32_t *array1_byte_offset, uint32_t *array1_slabs,
	uint32_t *array2_byte_offset, uint32_t *array2_slabs)
{
	uint32_t n_slabs_context, n_slabs_array1, n_cache_lines_context_and_array1;
	uint32_t n_cache_lines_array2;
	uint32_t n_bytes_total;

	n_cache_lines_array2 = (n_bits + RTE_BITMAP_CL_BIT_SIZE - 1) / RTE_BITMAP_CL_BIT_SIZE;
	n_slabs_array1 = (n_cache_lines_array2 + RTE_BITMAP_SLAB_BIT_SIZE - 1) / RTE_BITMAP_SLAB_BIT_SIZE;
	n_slabs_array1 = rte_align32pow2(n_slabs_array1);
	n_slabs_context = (sizeof(struct rte_bitmap) + (RTE_BITMAP_SLAB_BIT_SIZE / 8) - 1) / (RTE_BITMAP_SLAB_BIT_SIZE / 8);
	n_cache_lines_context_and_array1 = (n_slabs_context + n_slabs_array1 + RTE_BITMAP_CL_SLAB_SIZE - 1) / RTE_BITMAP_CL_SLAB_SIZE;
	n_bytes_total = (n_cache_lines_context_and_array1 + n_cache_lines_array2) * RTE_CACHE_LINE_SIZE;

	if (array1_byte_offset) {
		*array1_byte_offset = n_slabs_context * (RTE_BITMAP_SLAB_BIT_SIZE / 8);
	}
	if (array1_slabs) {
		*array1_slabs = n_slabs_array1;
	}
	if (array2_byte_offset) {
		*array2_byte_offset = n_cache_lines_context_and_array1 * RTE_CACHE_LINE_SIZE;
	}
	if (array2_slabs) {
		*array2_slabs = n_cache_lines_array2 * RTE_BITMAP_CL_SLAB_SIZE;
	}

	return n_bytes_total;
}

static inline void
__rte_bitmap_scan_init(struct rte_bitmap *bmp)
{
	bmp->index1 = bmp->array1_size - 1;
	bmp->offset1 = RTE_BITMAP_SLAB_BIT_SIZE - 1;
	__rte_bitmap_index2_set(bmp);
	bmp->index2 += RTE_BITMAP_CL_SLAB_SIZE;

	bmp->go2 = 0;
}

/**
 * Bitmap memory footprint calculation
 *
 * @param n_bits
 *   Number of bits in the bitmap
 * @return
 *   Bitmap memory footprint measured in bytes on success, 0 on error
 */
static inline uint32_t
rte_bitmap_get_memory_footprint(uint32_t n_bits) {
	/* Check input arguments */
	if (n_bits == 0) {
		return 0;
	}

	return __rte_bitmap_get_memory_footprint(n_bits, NULL, NULL, NULL, NULL);
}

/**
 * Bitmap initialization
 *
 * @param n_bits
 *   Number of pre-allocated bits in array2.
 * @param mem
 *   Base address of array1 and array2.
 * @param mem_size
 *   Minimum expected size of bitmap.
 * @return
 *   Handle to bitmap instance.
 */
static inline struct rte_bitmap *
rte_bitmap_init(uint32_t n_bits, uint8_t *mem, uint32_t mem_size)
{
	struct rte_bitmap *bmp;
	uint32_t array1_byte_offset, array1_slabs, array2_byte_offset, array2_slabs;
	uint32_t size;

	/* Check input arguments */
	if (n_bits == 0) {
		return NULL;
	}

	if ((mem == NULL) || (((uintptr_t) mem) & RTE_CACHE_LINE_MASK)) {
		return NULL;
	}

	size = __rte_bitmap_get_memory_footprint(n_bits,
		&array1_byte_offset, &array1_slabs,
		&array2_byte_offset, &array2_slabs);
	if (size > mem_size)
		return NULL;

	/* Setup bitmap */
	memset(mem, 0, size);
	bmp = (struct rte_bitmap *) mem;

	bmp->array1 = (uint64_t *) &mem[array1_byte_offset];
	bmp->array1_size = array1_slabs;
	bmp->array2 = (uint64_t *) &mem[array2_byte_offset];
	bmp->array2_size = array2_slabs;

	__rte_bitmap_scan_init(bmp);

	return bmp;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Bitmap clear slab overhead bits.
 *
 * @param slabs
 *   Slab array.
 * @param slab_size
 *   Number of 64-bit slabs in the slabs array.
 * @param pos
 *   The start bit position in the slabs to be cleared.
 */
__rte_experimental
static inline void
__rte_bitmap_clear_slab_overhead_bits(uint64_t *slabs, uint32_t slab_size,
				      uint32_t pos)
{
	uint32_t i;
	uint32_t index = pos / RTE_BITMAP_SLAB_BIT_SIZE;
	uint32_t offset = pos & RTE_BITMAP_SLAB_BIT_MASK;

	if (offset) {
		for (i = offset; i < RTE_BITMAP_SLAB_BIT_SIZE; i++)
			slabs[index] &= ~(1llu << i);
		index++;
	}
	if (index < slab_size)
		memset(&slabs[index], 0, sizeof(slabs[0]) *
		       (slab_size - index));
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Bitmap initialization with all bits set
 *
 * @param n_bits
 *   Number of pre-allocated bits in array2.
 * @param mem
 *   Base address of array1 and array2.
 * @param mem_size
 *   Minimum expected size of bitmap.
 * @return
 *   Handle to bitmap instance.
 */
__rte_experimental
static inline struct rte_bitmap *
rte_bitmap_init_with_all_set(uint32_t n_bits, uint8_t *mem, uint32_t mem_size)
{
	struct rte_bitmap *bmp;
	uint32_t array1_byte_offset, array1_slabs;
	uint32_t array2_byte_offset, array2_slabs;
	uint32_t size;

	/* Check input arguments */
	if (!n_bits || !mem || (((uintptr_t) mem) & RTE_CACHE_LINE_MASK))
		return NULL;

	size = __rte_bitmap_get_memory_footprint(n_bits,
		&array1_byte_offset, &array1_slabs,
		&array2_byte_offset, &array2_slabs);
	if (size < mem_size)
		return NULL;

	/* Setup bitmap */
	bmp = (struct rte_bitmap *) mem;
	bmp->array1 = (uint64_t *) &mem[array1_byte_offset];
	bmp->array1_size = array1_slabs;
	bmp->array2 = (uint64_t *) &mem[array2_byte_offset];
	bmp->array2_size = array2_slabs;

	__rte_bitmap_scan_init(bmp);

	memset(bmp->array1, 0xff, bmp->array1_size * sizeof(bmp->array1[0]));
	memset(bmp->array2, 0xff, bmp->array2_size * sizeof(bmp->array2[0]));
	/* Clear overhead bits. */
	__rte_bitmap_clear_slab_overhead_bits(bmp->array1, bmp->array1_size,
			bmp->array2_size >> RTE_BITMAP_CL_SLAB_SIZE_LOG2);
	__rte_bitmap_clear_slab_overhead_bits(bmp->array2, bmp->array2_size,
			n_bits);
	return bmp;
}

/**
 * Bitmap free
 *
 * @param bmp
 *   Handle to bitmap instance
 * @return
 *   0 upon success, error code otherwise
 */
static inline int
rte_bitmap_free(struct rte_bitmap *bmp)
{
	/* Check input arguments */
	if (bmp == NULL) {
		return -1;
	}

	return 0;
}

/**
 * Bitmap reset
 *
 * @param bmp
 *   Handle to bitmap instance
 */
static inline void
rte_bitmap_reset(struct rte_bitmap *bmp)
{
	memset(bmp->array1, 0, bmp->array1_size * sizeof(uint64_t));
	memset(bmp->array2, 0, bmp->array2_size * sizeof(uint64_t));
	__rte_bitmap_scan_init(bmp);
}

/**
 * Bitmap location prefetch into CPU L1 cache
 *
 * @param bmp
 *   Handle to bitmap instance
 * @param pos
 *   Bit position
 */
static inline void
rte_bitmap_prefetch0(struct rte_bitmap *bmp, uint32_t pos)
{
	uint64_t *slab2;
	uint32_t index2;

	index2 = pos >> RTE_BITMAP_SLAB_BIT_SIZE_LOG2;
	slab2 = bmp->array2 + index2;
	rte_prefetch0((void *) slab2);
}

/**
 * Bitmap bit get
 *
 * @param bmp
 *   Handle to bitmap instance
 * @param pos
 *   Bit position
 * @return
 *   0 when bit is cleared, non-zero when bit is set
 */
static inline uint64_t
rte_bitmap_get(struct rte_bitmap *bmp, uint32_t pos)
{
	uint64_t *slab2;
	uint32_t index2, offset2;

	index2 = pos >> RTE_BITMAP_SLAB_BIT_SIZE_LOG2;
	offset2 = pos & RTE_BITMAP_SLAB_BIT_MASK;
	slab2 = bmp->array2 + index2;
	return (*slab2) & (1llu << offset2);
}

/**
 * Bitmap bit set
 *
 * @param bmp
 *   Handle to bitmap instance
 * @param pos
 *   Bit position
 */
static inline void
rte_bitmap_set(struct rte_bitmap *bmp, uint32_t pos)
{
	uint64_t *slab1, *slab2;
	uint32_t index1, index2, offset1, offset2;

	/* Set bit in array2 slab and set bit in array1 slab */
	index2 = pos >> RTE_BITMAP_SLAB_BIT_SIZE_LOG2;
	offset2 = pos & RTE_BITMAP_SLAB_BIT_MASK;
	index1 = pos >> (RTE_BITMAP_SLAB_BIT_SIZE_LOG2 + RTE_BITMAP_CL_BIT_SIZE_LOG2);
	offset1 = (pos >> RTE_BITMAP_CL_BIT_SIZE_LOG2) & RTE_BITMAP_SLAB_BIT_MASK;
	slab2 = bmp->array2 + index2;
	slab1 = bmp->array1 + index1;

	*slab2 |= 1llu << offset2;
	*slab1 |= 1llu << offset1;
}

/**
 * Bitmap slab set
 *
 * @param bmp
 *   Handle to bitmap instance
 * @param pos
 *   Bit position identifying the array2 slab
 * @param slab
 *   Value to be assigned to the 64-bit slab in array2
 */
static inline void
rte_bitmap_set_slab(struct rte_bitmap *bmp, uint32_t pos, uint64_t slab)
{
	uint64_t *slab1, *slab2;
	uint32_t index1, index2, offset1;

	/* Set bits in array2 slab and set bit in array1 slab */
	index2 = pos >> RTE_BITMAP_SLAB_BIT_SIZE_LOG2;
	index1 = pos >> (RTE_BITMAP_SLAB_BIT_SIZE_LOG2 + RTE_BITMAP_CL_BIT_SIZE_LOG2);
	offset1 = (pos >> RTE_BITMAP_CL_BIT_SIZE_LOG2) & RTE_BITMAP_SLAB_BIT_MASK;
	slab2 = bmp->array2 + index2;
	slab1 = bmp->array1 + index1;

	*slab2 |= slab;
	*slab1 |= 1llu << offset1;
}

#if RTE_BITMAP_CL_SLAB_SIZE == 8
static inline uint64_t
__rte_bitmap_line_not_empty(uint64_t *slab2)
{
	uint64_t v1, v2, v3, v4;

	v1 = slab2[0] | slab2[1];
	v2 = slab2[2] | slab2[3];
	v3 = slab2[4] | slab2[5];
	v4 = slab2[6] | slab2[7];
	v1 |= v2;
	v3 |= v4;

	return v1 | v3;
}

#elif RTE_BITMAP_CL_SLAB_SIZE == 16
static inline uint64_t
__rte_bitmap_line_not_empty(uint64_t *slab2)
{
	uint64_t v1, v2, v3, v4, v5, v6, v7, v8;

	v1 = slab2[0] | slab2[1];
	v2 = slab2[2] | slab2[3];
	v3 = slab2[4] | slab2[5];
	v4 = slab2[6] | slab2[7];
	v5 = slab2[8] | slab2[9];
	v6 = slab2[10] | slab2[11];
	v7 = slab2[12] | slab2[13];
	v8 = slab2[14] | slab2[15];
	v1 |= v2;
	v3 |= v4;
	v5 |= v6;
	v7 |= v8;

	return v1 | v3 | v5 | v7;
}

#endif /* RTE_BITMAP_CL_SLAB_SIZE */

/**
 * Bitmap bit clear
 *
 * @param bmp
 *   Handle to bitmap instance
 * @param pos
 *   Bit position
 */
static inline void
rte_bitmap_clear(struct rte_bitmap *bmp, uint32_t pos)
{
	uint64_t *slab1, *slab2;
	uint32_t index1, index2, offset1, offset2;

	/* Clear bit in array2 slab */
	index2 = pos >> RTE_BITMAP_SLAB_BIT_SIZE_LOG2;
	offset2 = pos & RTE_BITMAP_SLAB_BIT_MASK;
	slab2 = bmp->array2 + index2;

	/* Return if array2 slab is not all-zeros */
	*slab2 &= ~(1llu << offset2);
	if (*slab2){
		return;
	}

	/* Check the entire cache line of array2 for all-zeros */
	index2 &= ~ RTE_BITMAP_CL_SLAB_MASK;
	slab2 = bmp->array2 + index2;
	if (__rte_bitmap_line_not_empty(slab2)) {
		return;
	}

	/* The array2 cache line is all-zeros, so clear bit in array1 slab */
	index1 = pos >> (RTE_BITMAP_SLAB_BIT_SIZE_LOG2 + RTE_BITMAP_CL_BIT_SIZE_LOG2);
	offset1 = (pos >> RTE_BITMAP_CL_BIT_SIZE_LOG2) & RTE_BITMAP_SLAB_BIT_MASK;
	slab1 = bmp->array1 + index1;
	*slab1 &= ~(1llu << offset1);

	return;
}

static inline int
__rte_bitmap_scan_search(struct rte_bitmap *bmp)
{
	uint64_t value1;
	uint32_t i;

	/* Check current array1 slab */
	value1 = bmp->array1[bmp->index1];
	value1 &= __rte_bitmap_mask1_get(bmp);

	if (rte_bsf64_safe(value1, &bmp->offset1))
		return 1;

	__rte_bitmap_index1_inc(bmp);
	bmp->offset1 = 0;

	/* Look for another array1 slab */
	for (i = 0; i < bmp->array1_size; i ++, __rte_bitmap_index1_inc(bmp)) {
		value1 = bmp->array1[bmp->index1];

		if (rte_bsf64_safe(value1, &bmp->offset1))
			return 1;
	}

	return 0;
}

static inline void
__rte_bitmap_scan_read_init(struct rte_bitmap *bmp)
{
	__rte_bitmap_index2_set(bmp);
	bmp->go2 = 1;
	rte_prefetch1((void *)(bmp->array2 + bmp->index2 + 8));
}

static inline int
__rte_bitmap_scan_read(struct rte_bitmap *bmp, uint32_t *pos, uint64_t *slab)
{
	uint64_t *slab2;

	slab2 = bmp->array2 + bmp->index2;
	for ( ; bmp->go2 ; bmp->index2 ++, slab2 ++, bmp->go2 = bmp->index2 & RTE_BITMAP_CL_SLAB_MASK) {
		if (*slab2) {
			*pos = bmp->index2 << RTE_BITMAP_SLAB_BIT_SIZE_LOG2;
			*slab = *slab2;

			bmp->index2 ++;
			slab2 ++;
			bmp->go2 = bmp->index2 & RTE_BITMAP_CL_SLAB_MASK;
			return 1;
		}
	}

	return 0;
}

/**
 * Bitmap scan (with automatic wrap-around)
 *
 * @param bmp
 *   Handle to bitmap instance
 * @param pos
 *   When function call returns 1, pos contains the position of the next set
 *   bit, otherwise not modified
 * @param slab
 *   When function call returns 1, slab contains the value of the entire 64-bit
 *   slab where the bit indicated by pos is located. Slabs are always 64-bit
 *   aligned, so the position of the first bit of the slab (this bit is not
 *   necessarily set) is pos / 64. Once a slab has been returned by the bitmap
 *   scan operation, the internal pointers of the bitmap are updated to point
 *   after this slab, so the same slab will not be returned again if it
 *   contains more than one bit which is set. When function call returns 0,
 *   slab is not modified.
 * @return
 *   0 if there is no bit set in the bitmap, 1 otherwise
 */
static inline int
rte_bitmap_scan(struct rte_bitmap *bmp, uint32_t *pos, uint64_t *slab)
{
	/* Return data from current array2 line if available */
	if (__rte_bitmap_scan_read(bmp, pos, slab)) {
		return 1;
	}

	/* Look for non-empty array2 line */
	if (__rte_bitmap_scan_search(bmp)) {
		__rte_bitmap_scan_read_init(bmp);
		__rte_bitmap_scan_read(bmp, pos, slab);
		return 1;
	}

	/* Empty bitmap */
	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_RTE_BITMAP_H__ */
