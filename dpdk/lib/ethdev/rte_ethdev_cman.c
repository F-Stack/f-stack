/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell International Ltd.
 */

#include <stdint.h>

#include <rte_errno.h>
#include "rte_ethdev.h"
#include "ethdev_driver.h"
#include "ethdev_private.h"

/* Get congestion management information for a port */
int
rte_eth_cman_info_get(uint16_t port_id, struct rte_eth_cman_info *info)
{
	struct rte_eth_dev *dev;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);
	dev = &rte_eth_devices[port_id];

	if (info == NULL) {
		RTE_ETHDEV_LOG(ERR, "congestion management info is NULL\n");
		return -EINVAL;
	}

	if (dev->dev_ops->cman_info_get == NULL) {
		RTE_ETHDEV_LOG(ERR, "Function not implemented\n");
		return -ENOTSUP;
	}

	memset(info, 0, sizeof(struct rte_eth_cman_info));
	return eth_err(port_id, (*dev->dev_ops->cman_info_get)(dev, info));
}

/* Initialize congestion management structure with default values */
int
rte_eth_cman_config_init(uint16_t port_id, struct rte_eth_cman_config *config)
{
	struct rte_eth_dev *dev;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);
	dev = &rte_eth_devices[port_id];

	if (config == NULL) {
		RTE_ETHDEV_LOG(ERR, "congestion management config is NULL\n");
		return -EINVAL;
	}

	if (dev->dev_ops->cman_config_init == NULL) {
		RTE_ETHDEV_LOG(ERR, "Function not implemented\n");
		return -ENOTSUP;
	}

	memset(config, 0, sizeof(struct rte_eth_cman_config));
	return eth_err(port_id, (*dev->dev_ops->cman_config_init)(dev, config));
}

/* Configure congestion management on a port */
int
rte_eth_cman_config_set(uint16_t port_id, const struct rte_eth_cman_config *config)
{
	struct rte_eth_dev *dev;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);
	dev = &rte_eth_devices[port_id];

	if (config == NULL) {
		RTE_ETHDEV_LOG(ERR, "congestion management config is NULL\n");
		return -EINVAL;
	}

	if (dev->dev_ops->cman_config_set == NULL) {
		RTE_ETHDEV_LOG(ERR, "Function not implemented\n");
		return -ENOTSUP;
	}

	return eth_err(port_id, (*dev->dev_ops->cman_config_set)(dev, config));
}

/* Retrieve congestion management configuration of a port */
int
rte_eth_cman_config_get(uint16_t port_id, struct rte_eth_cman_config *config)
{
	struct rte_eth_dev *dev;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);
	dev = &rte_eth_devices[port_id];

	if (config == NULL) {
		RTE_ETHDEV_LOG(ERR, "congestion management config is NULL\n");
		return -EINVAL;
	}

	if (dev->dev_ops->cman_config_get == NULL) {
		RTE_ETHDEV_LOG(ERR, "Function not implemented\n");
		return -ENOTSUP;
	}

	memset(config, 0, sizeof(struct rte_eth_cman_config));
	return eth_err(port_id, (*dev->dev_ops->cman_config_get)(dev, config));
}
