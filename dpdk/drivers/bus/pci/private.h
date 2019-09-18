/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 6WIND S.A.
 */

#ifndef _PCI_PRIVATE_H_
#define _PCI_PRIVATE_H_

#include <stdbool.h>
#include <stdio.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>

extern struct rte_pci_bus rte_pci_bus;

struct rte_pci_driver;
struct rte_pci_device;

extern struct rte_pci_bus rte_pci_bus;

/**
 * Probe the PCI bus
 *
 * @return
 *   - 0 on success.
 *   - !0 on error.
 */
int
rte_pci_probe(void);

/**
 * Scan the content of the PCI bus, and the devices in the devices
 * list
 *
 * @return
 *  0 on success, negative on error
 */
int rte_pci_scan(void);

/**
 * Find the name of a PCI device.
 */
void
pci_name_set(struct rte_pci_device *dev);

/**
 * Add a PCI device to the PCI Bus (append to PCI Device list). This function
 * also updates the bus references of the PCI Device (and the generic device
 * object embedded within.
 *
 * @param pci_dev
 *	PCI device to add
 * @return void
 */
void rte_pci_add_device(struct rte_pci_device *pci_dev);

/**
 * Insert a PCI device in the PCI Bus at a particular location in the device
 * list. It also updates the PCI Bus reference of the new devices to be
 * inserted.
 *
 * @param exist_pci_dev
 *	Existing PCI device in PCI Bus
 * @param new_pci_dev
 *	PCI device to be added before exist_pci_dev
 * @return void
 */
void rte_pci_insert_device(struct rte_pci_device *exist_pci_dev,
		struct rte_pci_device *new_pci_dev);

/**
 * Update a pci device object by asking the kernel for the latest information.
 *
 * This function is private to EAL.
 *
 * @param addr
 *	The PCI Bus-Device-Function address to look for
 * @return
 *   - 0 on success.
 *   - negative on error.
 */
int pci_update_device(const struct rte_pci_addr *addr);

/**
 * Map the PCI resource of a PCI device in virtual memory
 *
 * This function is private to EAL.
 *
 * @return
 *   0 on success, negative on error
 */
int pci_uio_map_resource(struct rte_pci_device *dev);

/**
 * Unmap the PCI resource of a PCI device
 *
 * This function is private to EAL.
 */
void pci_uio_unmap_resource(struct rte_pci_device *dev);

/**
 * Allocate uio resource for PCI device
 *
 * This function is private to EAL.
 *
 * @param dev
 *   PCI device to allocate uio resource
 * @param uio_res
 *   Pointer to uio resource.
 *   If the function returns 0, the pointer will be filled.
 * @return
 *   0 on success, negative on error
 */
int pci_uio_alloc_resource(struct rte_pci_device *dev,
		struct mapped_pci_resource **uio_res);

/**
 * Free uio resource for PCI device
 *
 * This function is private to EAL.
 *
 * @param dev
 *   PCI device to free uio resource
 * @param uio_res
 *   Pointer to uio resource.
 */
void pci_uio_free_resource(struct rte_pci_device *dev,
		struct mapped_pci_resource *uio_res);

/**
 * Remap the PCI resource of a PCI device in anonymous virtual memory.
 *
 * @param dev
 *   Point to the struct rte pci device.
 * @return
 *   - On success, zero.
 *   - On failure, a negative value.
 */
int
pci_uio_remap_resource(struct rte_pci_device *dev);

/**
 * Map device memory to uio resource
 *
 * This function is private to EAL.
 *
 * @param dev
 *   PCI device that has memory information.
 * @param res_idx
 *   Memory resource index of the PCI device.
 * @param uio_res
 *  uio resource that will keep mapping information.
 * @param map_idx
 *   Mapping information index of the uio resource.
 * @return
 *   0 on success, negative on error
 */
int pci_uio_map_resource_by_index(struct rte_pci_device *dev, int res_idx,
		struct mapped_pci_resource *uio_res, int map_idx);

/*
 * Match the PCI Driver and Device using the ID Table
 *
 * @param pci_drv
 *      PCI driver from which ID table would be extracted
 * @param pci_dev
 *      PCI device to match against the driver
 * @return
 *      1 for successful match
 *      0 for unsuccessful match
 */
int
rte_pci_match(const struct rte_pci_driver *pci_drv,
	      const struct rte_pci_device *pci_dev);

/**
 * Get iommu class of PCI devices on the bus.
 * And return their preferred iova mapping mode.
 *
 * @return
 *   - enum rte_iova_mode.
 */
enum rte_iova_mode
rte_pci_get_iommu_class(void);

/*
 * Iterate over internal devices,
 * matching any device against the provided
 * string.
 *
 * @param start
 *   Iteration starting point.
 *
 * @param str
 *   Device string to match against.
 *
 * @param it
 *   (unused) iterator structure.
 *
 * @return
 *   A pointer to the next matching device if any.
 *   NULL otherwise.
 */
void *
rte_pci_dev_iterate(const void *start,
		    const char *str,
		    const struct rte_dev_iterator *it);

#endif /* _PCI_PRIVATE_H_ */
