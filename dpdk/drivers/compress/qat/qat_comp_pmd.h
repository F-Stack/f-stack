/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2018 Intel Corporation
 */

#ifndef _QAT_COMP_PMD_H_
#define _QAT_COMP_PMD_H_

#ifdef RTE_LIBRTE_COMPRESSDEV

#include <rte_compressdev.h>
#include <rte_compressdev_pmd.h>

#include "qat_device.h"

/**< Intel(R) QAT Compression PMD driver name */
#define COMPRESSDEV_NAME_QAT_PMD	compress_qat

/** private data structure for a QAT compression device.
 * This QAT device is a device offering only a compression service,
 * there can be one of these on each qat_pci_device (VF).
 */
struct qat_comp_dev_private {
	struct qat_pci_device *qat_dev;
	/**< The qat pci device hosting the service */
	struct rte_compressdev *compressdev;
	/**< The pointer to this compression device structure */
	const struct rte_compressdev_capabilities *qat_dev_capabilities;
	/* QAT device compression capabilities */
	const struct rte_memzone *interm_buff_mz;
	/**< The device's memory for intermediate buffers */
	struct rte_mempool *xformpool;
	/**< The device's pool for qat_comp_xforms */
};

int
qat_comp_dev_create(struct qat_pci_device *qat_pci_dev);

int
qat_comp_dev_destroy(struct qat_pci_device *qat_pci_dev);

#endif
#endif /* _QAT_COMP_PMD_H_ */
