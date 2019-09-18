/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#ifndef _RTE_VECT_X86_H_
#define _RTE_VECT_X86_H_

/**
 * @file
 *
 * RTE SSE/AVX related header.
 */

#include <stdint.h>
#include <rte_config.h>
#include "generic/rte_vect.h"

#if (defined(__ICC) || (__GNUC__ == 4 &&  __GNUC_MINOR__ < 4))

#include <smmintrin.h> /* SSE4 */

#if defined(__AVX__)
#include <immintrin.h>
#endif

#else

#include <x86intrin.h>

#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef __m128i xmm_t;

#define	XMM_SIZE	(sizeof(xmm_t))
#define	XMM_MASK	(XMM_SIZE - 1)

typedef union rte_xmm {
	xmm_t    x;
	uint8_t  u8[XMM_SIZE / sizeof(uint8_t)];
	uint16_t u16[XMM_SIZE / sizeof(uint16_t)];
	uint32_t u32[XMM_SIZE / sizeof(uint32_t)];
	uint64_t u64[XMM_SIZE / sizeof(uint64_t)];
	double   pd[XMM_SIZE / sizeof(double)];
} rte_xmm_t;

#ifdef __AVX__

typedef __m256i ymm_t;

#define	YMM_SIZE	(sizeof(ymm_t))
#define	YMM_MASK	(YMM_SIZE - 1)

typedef union rte_ymm {
	ymm_t    y;
	xmm_t    x[YMM_SIZE / sizeof(xmm_t)];
	uint8_t  u8[YMM_SIZE / sizeof(uint8_t)];
	uint16_t u16[YMM_SIZE / sizeof(uint16_t)];
	uint32_t u32[YMM_SIZE / sizeof(uint32_t)];
	uint64_t u64[YMM_SIZE / sizeof(uint64_t)];
	double   pd[YMM_SIZE / sizeof(double)];
} rte_ymm_t;

#endif /* __AVX__ */

#ifdef RTE_ARCH_I686
#define _mm_cvtsi128_si64(a)    \
__extension__ ({                \
	rte_xmm_t m;            \
	m.x = (a);              \
	(m.u64[0]);             \
})
#endif

/*
 * Prior to version 12.1 icc doesn't support _mm_set_epi64x.
 */
#if (defined(__ICC) && __ICC < 1210)
#define _mm_set_epi64x(a, b)     \
__extension__ ({                 \
	rte_xmm_t m;             \
	m.u64[0] = b;            \
	m.u64[1] = a;            \
	(m.x);                   \
})
#endif /* (defined(__ICC) && __ICC < 1210) */

#ifdef __cplusplus
}
#endif

#endif /* _RTE_VECT_X86_H_ */
