/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <rte_eal.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_tailq.h>
#include <rte_log.h>
#include <rte_malloc.h>

#include "private.h"

static struct rte_tailq_elem rte_uio_tailq = {
	.name = "UIO_RESOURCE_LIST",
};
EAL_REGISTER_TAILQ(rte_uio_tailq)

static int
pci_uio_map_secondary(struct rte_pci_device *dev)
{
	int fd, i = 0, j, res_idx;
	struct mapped_pci_resource *uio_res;
	struct mapped_pci_res_list *uio_res_list =
			RTE_TAILQ_CAST(rte_uio_tailq.head, mapped_pci_res_list);

	TAILQ_FOREACH(uio_res, uio_res_list, next) {

		/* skip this element if it doesn't match our PCI address */
		if (rte_pci_addr_cmp(&uio_res->pci_addr, &dev->addr))
			continue;

		/* Map all BARs */
		for (res_idx = 0; res_idx != PCI_MAX_RESOURCE; res_idx++) {
			/* skip empty BAR */
			if (dev->mem_resource[res_idx].phys_addr == 0)
				continue;

			if (i >= uio_res->nb_maps)
				return -1;

			/*
			 * open devname, to mmap it
			 */
			fd = open(uio_res->maps[i].path, O_RDWR);
			if (fd < 0) {
				RTE_LOG(ERR, EAL, "Cannot open %s: %s\n",
					uio_res->maps[i].path, strerror(errno));
				return -1;
			}

			void *mapaddr = pci_map_resource(uio_res->maps[i].addr,
					fd, (off_t)uio_res->maps[i].offset,
					(size_t)uio_res->maps[i].size, 0);

			/* fd is not needed in secondary process, close it */
			close(fd);
			if (mapaddr != uio_res->maps[i].addr) {
				RTE_LOG(ERR, EAL,
					"Cannot mmap device resource file %s to address: %p\n",
					uio_res->maps[i].path,
					uio_res->maps[i].addr);
				if (mapaddr != NULL) {
					/* unmap addrs correctly mapped */
					for (j = 0; j < i; j++)
						pci_unmap_resource(
							uio_res->maps[j].addr,
							(size_t)uio_res->maps[j].size);
					/* unmap addr wrongly mapped */
					pci_unmap_resource(mapaddr,
						(size_t)uio_res->maps[i].size);
				}
				return -1;
			}
			dev->mem_resource[res_idx].addr = mapaddr;

			i++;
		}
		return 0;
	}

	RTE_LOG(ERR, EAL, "Cannot find resource for device\n");
	return 1;
}

/* map the PCI resource of a PCI device in virtual memory */
int
pci_uio_map_resource(struct rte_pci_device *dev)
{
	int i, map_idx = 0, ret;
	uint64_t phaddr;
	struct mapped_pci_resource *uio_res = NULL;
	struct mapped_pci_res_list *uio_res_list =
		RTE_TAILQ_CAST(rte_uio_tailq.head, mapped_pci_res_list);

	if (rte_intr_fd_set(dev->intr_handle, -1))
		return -1;

	if (rte_intr_dev_fd_set(dev->intr_handle, -1))
		return -1;

	/* allocate uio resource */
	ret = pci_uio_alloc_resource(dev, &uio_res);
	if (ret)
		return ret;

	/* secondary processes - use already recorded details */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return pci_uio_map_secondary(dev);

	/* Map all BARs */
	for (i = 0; i != PCI_MAX_RESOURCE; i++) {
		/* skip empty BAR */
		phaddr = dev->mem_resource[i].phys_addr;
		if (phaddr == 0)
			continue;

		ret = pci_uio_map_resource_by_index(dev, i,
				uio_res, map_idx);
		if (ret)
			goto error;

		map_idx++;
	}

	uio_res->nb_maps = map_idx;

	TAILQ_INSERT_TAIL(uio_res_list, uio_res, next);

	return 0;
error:
	for (i = 0; i < map_idx; i++) {
		pci_unmap_resource(uio_res->maps[i].addr,
				(size_t)uio_res->maps[i].size);
		rte_free(uio_res->maps[i].path);
	}
	pci_uio_free_resource(dev, uio_res);
	return -1;
}

static void
pci_uio_unmap(struct mapped_pci_resource *uio_res)
{
	int i;

	if (uio_res == NULL)
		return;

	for (i = 0; i != uio_res->nb_maps; i++) {
		pci_unmap_resource(uio_res->maps[i].addr,
				(size_t)uio_res->maps[i].size);
		if (rte_eal_process_type() == RTE_PROC_PRIMARY)
			rte_free(uio_res->maps[i].path);
	}
}

/* remap the PCI resource of a PCI device in anonymous virtual memory */
int
pci_uio_remap_resource(struct rte_pci_device *dev)
{
	int i;
	void *map_address;

	if (dev == NULL)
		return -1;

	/* Remap all BARs */
	for (i = 0; i != PCI_MAX_RESOURCE; i++) {
		/* skip empty BAR */
		if (dev->mem_resource[i].phys_addr == 0)
			continue;
		map_address = mmap(dev->mem_resource[i].addr,
				(size_t)dev->mem_resource[i].len,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		if (map_address == MAP_FAILED) {
			RTE_LOG(ERR, EAL,
				"Cannot remap resource for device %s\n",
				dev->name);
			return -1;
		}
		RTE_LOG(INFO, EAL,
			"Successful remap resource for device %s\n",
			dev->name);
	}

	return 0;
}

static struct mapped_pci_resource *
pci_uio_find_resource(struct rte_pci_device *dev)
{
	struct mapped_pci_resource *uio_res;
	struct mapped_pci_res_list *uio_res_list =
			RTE_TAILQ_CAST(rte_uio_tailq.head, mapped_pci_res_list);

	if (dev == NULL)
		return NULL;

	TAILQ_FOREACH(uio_res, uio_res_list, next) {

		/* skip this element if it doesn't match our PCI address */
		if (!rte_pci_addr_cmp(&uio_res->pci_addr, &dev->addr))
			return uio_res;
	}
	return NULL;
}

/* unmap the PCI resource of a PCI device in virtual memory */
void
pci_uio_unmap_resource(struct rte_pci_device *dev)
{
	struct mapped_pci_resource *uio_res;
	struct mapped_pci_res_list *uio_res_list =
			RTE_TAILQ_CAST(rte_uio_tailq.head, mapped_pci_res_list);
	int uio_cfg_fd;

	if (dev == NULL)
		return;

	/* find an entry for the device */
	uio_res = pci_uio_find_resource(dev);
	if (uio_res == NULL)
		return;

	/* close fd */
	if (rte_intr_fd_get(dev->intr_handle) >= 0)
		close(rte_intr_fd_get(dev->intr_handle));
	uio_cfg_fd = rte_intr_dev_fd_get(dev->intr_handle);
	if (uio_cfg_fd >= 0) {
		close(uio_cfg_fd);
		rte_intr_dev_fd_set(dev->intr_handle, -1);
	}

	rte_intr_fd_set(dev->intr_handle, -1);
	rte_intr_type_set(dev->intr_handle, RTE_INTR_HANDLE_UNKNOWN);

	/* secondary processes - just free maps */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return pci_uio_unmap(uio_res);

	TAILQ_REMOVE(uio_res_list, uio_res, next);

	/* unmap all resources */
	pci_uio_unmap(uio_res);

	/* free uio resource */
	rte_free(uio_res);
}
