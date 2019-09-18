/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef __INCLUDE_RTE_MTR_DRIVER_H__
#define __INCLUDE_RTE_MTR_DRIVER_H__

/**
 * @file
 * RTE Generic Traffic Metering and Policing API (Driver Side)
 *
 * This file provides implementation helpers for internal use by PMDs, they
 * are not intended to be exposed to applications and are not subject to ABI
 * versioning.
 */

#include <stdint.h>

#include <rte_errno.h>
#include "rte_ethdev.h"
#include "rte_mtr.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*rte_mtr_capabilities_get_t)(struct rte_eth_dev *dev,
	struct rte_mtr_capabilities *cap,
	struct rte_mtr_error *error);
/**< @internal MTR capabilities get */

typedef int (*rte_mtr_meter_profile_add_t)(struct rte_eth_dev *dev,
	uint32_t meter_profile_id,
	struct rte_mtr_meter_profile *profile,
	struct rte_mtr_error *error);
/**< @internal MTR meter profile add */

typedef int (*rte_mtr_meter_profile_delete_t)(struct rte_eth_dev *dev,
	uint32_t meter_profile_id,
	struct rte_mtr_error *error);
/**< @internal MTR meter profile delete */

typedef int (*rte_mtr_create_t)(struct rte_eth_dev *dev,
	uint32_t mtr_id,
	struct rte_mtr_params *params,
	int shared,
	struct rte_mtr_error *error);
/**< @internal MTR object create */

typedef int (*rte_mtr_destroy_t)(struct rte_eth_dev *dev,
	uint32_t mtr_id,
	struct rte_mtr_error *error);
/**< @internal MTR object destroy */

typedef int (*rte_mtr_meter_enable_t)(struct rte_eth_dev *dev,
	uint32_t mtr_id,
	struct rte_mtr_error *error);
/**< @internal MTR object meter enable */

typedef int (*rte_mtr_meter_disable_t)(struct rte_eth_dev *dev,
	uint32_t mtr_id,
	struct rte_mtr_error *error);
/**< @internal MTR object meter disable */

typedef int (*rte_mtr_meter_profile_update_t)(struct rte_eth_dev *dev,
	uint32_t mtr_id,
	uint32_t meter_profile_id,
	struct rte_mtr_error *error);
/**< @internal MTR object meter profile update */

typedef int (*rte_mtr_meter_dscp_table_update_t)(struct rte_eth_dev *dev,
	uint32_t mtr_id,
	enum rte_mtr_color *dscp_table,
	struct rte_mtr_error *error);
/**< @internal MTR object meter DSCP table update */

typedef int (*rte_mtr_policer_actions_update_t)(struct rte_eth_dev *dev,
	uint32_t mtr_id,
	uint32_t action_mask,
	enum rte_mtr_policer_action *actions,
	struct rte_mtr_error *error);
/**< @internal MTR object policer action update*/

typedef int (*rte_mtr_stats_update_t)(struct rte_eth_dev *dev,
	uint32_t mtr_id,
	uint64_t stats_mask,
	struct rte_mtr_error *error);
/**< @internal MTR object enabled stats update */

typedef int (*rte_mtr_stats_read_t)(struct rte_eth_dev *dev,
	uint32_t mtr_id,
	struct rte_mtr_stats *stats,
	uint64_t *stats_mask,
	int clear,
	struct rte_mtr_error *error);
/**< @internal MTR object stats read */

struct rte_mtr_ops {
	/** MTR capabilities get */
	rte_mtr_capabilities_get_t capabilities_get;

	/** MTR meter profile add */
	rte_mtr_meter_profile_add_t meter_profile_add;

	/** MTR meter profile delete */
	rte_mtr_meter_profile_delete_t meter_profile_delete;

	/** MTR object create */
	rte_mtr_create_t create;

	/** MTR object destroy */
	rte_mtr_destroy_t destroy;

	/** MTR object meter enable */
	rte_mtr_meter_enable_t meter_enable;

	/** MTR object meter disable */
	rte_mtr_meter_disable_t meter_disable;

	/** MTR object meter profile update */
	rte_mtr_meter_profile_update_t meter_profile_update;

	/** MTR object meter DSCP table update */
	rte_mtr_meter_dscp_table_update_t meter_dscp_table_update;

	/** MTR object policer action update */
	rte_mtr_policer_actions_update_t policer_actions_update;

	/** MTR object enabled stats update */
	rte_mtr_stats_update_t stats_update;

	/** MTR object stats read */
	rte_mtr_stats_read_t stats_read;
};

/**
 * Initialize generic error structure.
 *
 * This function also sets rte_errno to a given value.
 *
 * @param[out] error
 *   Pointer to error structure (may be NULL).
 * @param[in] code
 *   Related error code (rte_errno).
 * @param[in] type
 *   Cause field and error type.
 * @param[in] cause
 *   Object responsible for the error.
 * @param[in] message
 *   Human-readable error message.
 *
 * @return
 *   Error code.
 */
static inline int
rte_mtr_error_set(struct rte_mtr_error *error,
		   int code,
		   enum rte_mtr_error_type type,
		   const void *cause,
		   const char *message)
{
	if (error) {
		*error = (struct rte_mtr_error){
			.type = type,
			.cause = cause,
			.message = message,
		};
	}
	rte_errno = code;
	return code;
}

/**
 * Get generic traffic metering and policing operations structure from a port
 *
 * @param[in] port_id
 *   The port identifier of the Ethernet device.
 * @param[out] error
 *   Error details
 *
 * @return
 *   The traffic metering and policing operations structure associated with
 *   port_id on success, NULL otherwise.
 */
const struct rte_mtr_ops *
rte_mtr_ops_get(uint16_t port_id, struct rte_mtr_error *error);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_RTE_MTR_DRIVER_H__ */
