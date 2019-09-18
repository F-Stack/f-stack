/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2018 Intel Corporation
 */

#ifndef _RTE_ETHDEV_PROFILE_H_
#define _RTE_ETHDEV_PROFILE_H_

#include "rte_ethdev.h"

/**
 * Initialization of the Ethernet device profiling.
 * Implementation of this function depends on chosen profiling method,
 * defined in configs.
 *
 * @param port_id
 *  The port identifier of the Ethernet device.
 * @param dev
 *  Pointer to struct rte_eth_dev corresponding to given port_id.
 *
 * @return
 *  - On success, zero.
 *  - On failure, a negative value.
 */
int
__rte_eth_dev_profile_init(uint16_t port_id, struct rte_eth_dev *dev);

#endif
