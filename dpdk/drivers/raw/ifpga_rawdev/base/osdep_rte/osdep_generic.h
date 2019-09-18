/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2018 Intel Corporation
 */

#ifndef _OSDEP_RTE_GENERIC_H
#define _OSDEP_RTE_GENERIC_H

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_spinlock.h>
#include <rte_log.h>
#include <rte_io.h>
#include <rte_malloc.h>

#define dev_printf(level, fmt, args...) \
	RTE_LOG(level, PMD, "osdep_rte: " fmt, ## args)

#define osdep_panic(...) rte_panic(...)

#define opae_udelay(x) rte_delay_us(x)

#define opae_readb(addr) rte_read8(addr)
#define opae_readw(addr) rte_read16(addr)
#define opae_readl(addr) rte_read32(addr)
#define opae_readq(addr) rte_read64(addr)
#define opae_writeb(value, addr) rte_write8(value, addr)
#define opae_writew(value, addr) rte_write16(value, addr)
#define opae_writel(value, addr) rte_write32(value, addr)
#define opae_writeq(value, addr) rte_write64(value, addr)

#define opae_malloc(size) rte_malloc(NULL, size, 0)
#define opae_zmalloc(size) rte_zmalloc(NULL, size, 0)
#define opae_free(addr) rte_free(addr)

#define ARRAY_SIZE(arr) RTE_DIM(arr)

#define min(a, b) RTE_MIN(a, b)
#define max(a, b) RTE_MAX(a, b)

#define spinlock_t rte_spinlock_t
#define spinlock_init(x) rte_spinlock_init(x)
#define spinlock_lock(x) rte_spinlock_lock(x)
#define spinlock_unlock(x) rte_spinlock_unlock(x)

#endif
