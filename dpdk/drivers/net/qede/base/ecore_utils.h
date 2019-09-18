/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016 - 2018 Cavium Inc.
 * All rights reserved.
 * www.cavium.com
 */

#ifndef __ECORE_UTILS_H__
#define __ECORE_UTILS_H__

/* dma_addr_t manip */
/* Suppress "right shift count >= width of type" warning when that quantity is
 * 32-bits rquires the >> 16) >> 16)
 */
#define PTR_LO(x)		((u32)(((osal_uintptr_t)(x)) & 0xffffffff))
#define PTR_HI(x)		((u32)((((osal_uintptr_t)(x)) >> 16) >> 16))

#define DMA_LO(x)		((u32)(((dma_addr_t)(x)) & 0xffffffff))
#define DMA_HI(x)		((u32)(((dma_addr_t)(x)) >> 32))

#define DMA_LO_LE(x)		OSAL_CPU_TO_LE32(DMA_LO(x))
#define DMA_HI_LE(x)		OSAL_CPU_TO_LE32(DMA_HI(x))

/* It's assumed that whoever includes this has previously included an hsi
 * file defining the regpair.
 */
#define DMA_REGPAIR_LE(x, val)	(x).hi = DMA_HI_LE((val)); \
				(x).lo = DMA_LO_LE((val))

#define HILO_GEN(hi, lo, type)	((((type)(hi)) << 32) + (lo))
#define HILO_DMA(hi, lo)	HILO_GEN(hi, lo, dma_addr_t)
#define HILO_64(hi, lo)		HILO_GEN(hi, lo, u64)
#define HILO_DMA_REGPAIR(regpair)	(HILO_DMA(regpair.hi, regpair.lo))
#define HILO_64_REGPAIR(regpair)	(HILO_64(regpair.hi, regpair.lo))

#endif
