/* SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright (c) 2015-2016 Freescale Semiconductor, Inc. All rights reserved.
 *   Copyright 2016 NXP
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <libgen.h>
#include <dirent.h>
#include <sys/eventfd.h>

#include <eal_filesystem.h>
#include <rte_mbuf.h>
#include <rte_ethdev_driver.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <rte_dev.h>
#include <rte_bus.h>
#include <rte_eal_memconfig.h>

#include "rte_fslmc.h"
#include "fslmc_vfio.h"
#include "fslmc_logs.h"
#include <mc/fsl_dpmng.h>

#include "portal/dpaa2_hw_pvt.h"
#include "portal/dpaa2_hw_dpio.h"

/** Pathname of FSL-MC devices directory. */
#define SYSFS_FSL_MC_DEVICES "/sys/bus/fsl-mc/devices"

#define FSLMC_CONTAINER_MAX_LEN 8 /**< Of the format dprc.XX */

/* Number of VFIO containers & groups with in */
static struct fslmc_vfio_group vfio_group;
static struct fslmc_vfio_container vfio_container;
static int container_device_fd;
static char *g_container;
static uint32_t *msi_intr_vaddr;
void *(*rte_mcp_ptr_list);

static struct rte_dpaa2_object_list dpaa2_obj_list =
	TAILQ_HEAD_INITIALIZER(dpaa2_obj_list);

/*register a fslmc bus based dpaa2 driver */
void
rte_fslmc_object_register(struct rte_dpaa2_object *object)
{
	RTE_VERIFY(object);

	TAILQ_INSERT_TAIL(&dpaa2_obj_list, object, next);
}

int
fslmc_get_container_group(int *groupid)
{
	int ret;
	char *container;

	if (!g_container) {
		container = getenv("DPRC");
		if (container == NULL) {
			DPAA2_BUS_DEBUG("DPAA2: DPRC not available");
			return -EINVAL;
		}

		if (strlen(container) >= FSLMC_CONTAINER_MAX_LEN) {
			DPAA2_BUS_ERR("Invalid container name: %s", container);
			return -1;
		}

		g_container = strdup(container);
		if (!g_container) {
			DPAA2_BUS_ERR("Mem alloc failure; Container name");
			return -ENOMEM;
		}
	}

	/* get group number */
	ret = rte_vfio_get_group_num(SYSFS_FSL_MC_DEVICES,
				     g_container, groupid);
	if (ret <= 0) {
		DPAA2_BUS_ERR("Unable to find %s IOMMU group", g_container);
		return -1;
	}

	DPAA2_BUS_DEBUG("Container: %s has VFIO iommu group id = %d",
			g_container, *groupid);

	return 0;
}

static int
vfio_connect_container(void)
{
	int fd, ret;

	if (vfio_container.used) {
		DPAA2_BUS_DEBUG("No container available");
		return -1;
	}

	/* Try connecting to vfio container if already created */
	if (!ioctl(vfio_group.fd, VFIO_GROUP_SET_CONTAINER,
		&vfio_container.fd)) {
		DPAA2_BUS_DEBUG(
		    "Container pre-exists with FD[0x%x] for this group",
		    vfio_container.fd);
		vfio_group.container = &vfio_container;
		return 0;
	}

	/* Opens main vfio file descriptor which represents the "container" */
	fd = rte_vfio_get_container_fd();
	if (fd < 0) {
		DPAA2_BUS_ERR("Failed to open VFIO container");
		return -errno;
	}

	/* Check whether support for SMMU type IOMMU present or not */
	if (ioctl(fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
		/* Connect group to container */
		ret = ioctl(vfio_group.fd, VFIO_GROUP_SET_CONTAINER, &fd);
		if (ret) {
			DPAA2_BUS_ERR("Failed to setup group container");
			close(fd);
			return -errno;
		}

		ret = ioctl(fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU);
		if (ret) {
			DPAA2_BUS_ERR("Failed to setup VFIO iommu");
			close(fd);
			return -errno;
		}
	} else {
		DPAA2_BUS_ERR("No supported IOMMU available");
		close(fd);
		return -EINVAL;
	}

	vfio_container.used = 1;
	vfio_container.fd = fd;
	vfio_container.group = &vfio_group;
	vfio_group.container = &vfio_container;

	return 0;
}

static int vfio_map_irq_region(struct fslmc_vfio_group *group)
{
	int ret;
	unsigned long *vaddr = NULL;
	struct vfio_iommu_type1_dma_map map = {
		.argsz = sizeof(map),
		.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
		.vaddr = 0x6030000,
		.iova = 0x6030000,
		.size = 0x1000,
	};

	vaddr = (unsigned long *)mmap(NULL, 0x1000, PROT_WRITE |
		PROT_READ, MAP_SHARED, container_device_fd, 0x6030000);
	if (vaddr == MAP_FAILED) {
		DPAA2_BUS_INFO("Unable to map region (errno = %d)", errno);
		return -errno;
	}

	msi_intr_vaddr = (uint32_t *)((char *)(vaddr) + 64);
	map.vaddr = (unsigned long)vaddr;
	ret = ioctl(group->container->fd, VFIO_IOMMU_MAP_DMA, &map);
	if (ret == 0)
		return 0;

	DPAA2_BUS_ERR("Unable to map DMA address (errno = %d)", errno);
	return -errno;
}

static int fslmc_map_dma(uint64_t vaddr, rte_iova_t iovaddr, size_t len);
static int fslmc_unmap_dma(uint64_t vaddr, rte_iova_t iovaddr, size_t len);

static void
fslmc_memevent_cb(enum rte_mem_event type, const void *addr, size_t len,
		void *arg __rte_unused)
{
	struct rte_memseg_list *msl;
	struct rte_memseg *ms;
	size_t cur_len = 0, map_len = 0;
	uint64_t virt_addr;
	rte_iova_t iova_addr;
	int ret;

	msl = rte_mem_virt2memseg_list(addr);

	while (cur_len < len) {
		const void *va = RTE_PTR_ADD(addr, cur_len);

		ms = rte_mem_virt2memseg(va, msl);
		iova_addr = ms->iova;
		virt_addr = ms->addr_64;
		map_len = ms->len;

		DPAA2_BUS_DEBUG("Request for %s, va=%p, "
				"virt_addr=0x%" PRIx64 ", "
				"iova=0x%" PRIx64 ", map_len=%zu",
				type == RTE_MEM_EVENT_ALLOC ?
					"alloc" : "dealloc",
				va, virt_addr, iova_addr, map_len);

		/* iova_addr may be set to RTE_BAD_IOVA */
		if (iova_addr == RTE_BAD_IOVA) {
			DPAA2_BUS_DEBUG("Segment has invalid iova, skipping\n");
			cur_len += map_len;
			continue;
		}

		if (type == RTE_MEM_EVENT_ALLOC)
			ret = fslmc_map_dma(virt_addr, iova_addr, map_len);
		else
			ret = fslmc_unmap_dma(virt_addr, iova_addr, map_len);

		if (ret != 0) {
			DPAA2_BUS_ERR("DMA Mapping/Unmapping failed. "
					"Map=%d, addr=%p, len=%zu, err:(%d)",
					type, va, map_len, ret);
			return;
		}

		cur_len += map_len;
	}

	if (type == RTE_MEM_EVENT_ALLOC)
		DPAA2_BUS_DEBUG("Total Mapped: addr=%p, len=%zu",
				addr, len);
	else
		DPAA2_BUS_DEBUG("Total Unmapped: addr=%p, len=%zu",
				addr, len);
}

static int
fslmc_map_dma(uint64_t vaddr, rte_iova_t iovaddr __rte_unused, size_t len)
{
	struct fslmc_vfio_group *group;
	struct vfio_iommu_type1_dma_map dma_map = {
		.argsz = sizeof(struct vfio_iommu_type1_dma_map),
		.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
	};
	int ret;

	dma_map.size = len;
	dma_map.vaddr = vaddr;

#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
	dma_map.iova = iovaddr;
#else
	dma_map.iova = dma_map.vaddr;
#endif

	/* SET DMA MAP for IOMMU */
	group = &vfio_group;

	if (!group->container) {
		DPAA2_BUS_ERR("Container is not connected ");
		return -1;
	}

	DPAA2_BUS_DEBUG("--> Map address: 0x%"PRIx64", size: %"PRIu64"",
			(uint64_t)dma_map.vaddr, (uint64_t)dma_map.size);
	ret = ioctl(group->container->fd, VFIO_IOMMU_MAP_DMA, &dma_map);
	if (ret) {
		DPAA2_BUS_ERR("VFIO_IOMMU_MAP_DMA API(errno = %d)",
				errno);
		return -1;
	}

	return 0;
}

static int
fslmc_unmap_dma(uint64_t vaddr, uint64_t iovaddr __rte_unused, size_t len)
{
	struct fslmc_vfio_group *group;
	struct vfio_iommu_type1_dma_unmap dma_unmap = {
		.argsz = sizeof(struct vfio_iommu_type1_dma_unmap),
		.flags = 0,
	};
	int ret;

	dma_unmap.size = len;
	dma_unmap.iova = vaddr;

	/* SET DMA MAP for IOMMU */
	group = &vfio_group;

	if (!group->container) {
		DPAA2_BUS_ERR("Container is not connected ");
		return -1;
	}

	DPAA2_BUS_DEBUG("--> Unmap address: 0x%"PRIx64", size: %"PRIu64"",
			(uint64_t)dma_unmap.iova, (uint64_t)dma_unmap.size);
	ret = ioctl(group->container->fd, VFIO_IOMMU_UNMAP_DMA, &dma_unmap);
	if (ret) {
		DPAA2_BUS_ERR("VFIO_IOMMU_UNMAP_DMA API(errno = %d)",
				errno);
		return -1;
	}

	return 0;
}

static int
fslmc_dmamap_seg(const struct rte_memseg_list *msl __rte_unused,
		const struct rte_memseg *ms, void *arg)
{
	int *n_segs = arg;
	int ret;

	/* if IOVA address is invalid, skip */
	if (ms->iova == RTE_BAD_IOVA)
		return 0;

	ret = fslmc_map_dma(ms->addr_64, ms->iova, ms->len);
	if (ret)
		DPAA2_BUS_ERR("Unable to VFIO map (addr=%p, len=%zu)",
				ms->addr, ms->len);
	else
		(*n_segs)++;

	return ret;
}

int rte_fslmc_vfio_dmamap(void)
{
	int i = 0, ret;
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	rte_rwlock_t *mem_lock = &mcfg->memory_hotplug_lock;

	/* Lock before parsing and registering callback to memory subsystem */
	rte_rwlock_read_lock(mem_lock);

	if (rte_memseg_walk(fslmc_dmamap_seg, &i) < 0) {
		rte_rwlock_read_unlock(mem_lock);
		return -1;
	}

	ret = rte_mem_event_callback_register("fslmc_memevent_clb",
			fslmc_memevent_cb, NULL);
	if (ret && rte_errno == ENOTSUP)
		DPAA2_BUS_DEBUG("Memory event callbacks not supported");
	else if (ret)
		DPAA2_BUS_DEBUG("Unable to install memory handler");
	else
		DPAA2_BUS_DEBUG("Installed memory callback handler");

	DPAA2_BUS_DEBUG("Total %d segments found.", i);

	/* TODO - This is a W.A. as VFIO currently does not add the mapping of
	 * the interrupt region to SMMU. This should be removed once the
	 * support is added in the Kernel.
	 */
	vfio_map_irq_region(&vfio_group);

	/* Existing segments have been mapped and memory callback for hotplug
	 * has been installed.
	 */
	rte_rwlock_read_unlock(mem_lock);

	return 0;
}

static int64_t vfio_map_mcp_obj(struct fslmc_vfio_group *group, char *mcp_obj)
{
	intptr_t v_addr = (intptr_t)MAP_FAILED;
	int32_t ret, mc_fd;

	struct vfio_device_info d_info = { .argsz = sizeof(d_info) };
	struct vfio_region_info reg_info = { .argsz = sizeof(reg_info) };

	/* getting the mcp object's fd*/
	mc_fd = ioctl(group->fd, VFIO_GROUP_GET_DEVICE_FD, mcp_obj);
	if (mc_fd < 0) {
		DPAA2_BUS_ERR("Error in VFIO get dev %s fd from group %d",
			      mcp_obj, group->fd);
		return v_addr;
	}

	/* getting device info*/
	ret = ioctl(mc_fd, VFIO_DEVICE_GET_INFO, &d_info);
	if (ret < 0) {
		DPAA2_BUS_ERR("Error in VFIO getting DEVICE_INFO");
		goto MC_FAILURE;
	}

	/* getting device region info*/
	ret = ioctl(mc_fd, VFIO_DEVICE_GET_REGION_INFO, &reg_info);
	if (ret < 0) {
		DPAA2_BUS_ERR("Error in VFIO getting REGION_INFO");
		goto MC_FAILURE;
	}

	v_addr = (size_t)mmap(NULL, reg_info.size,
		PROT_WRITE | PROT_READ, MAP_SHARED,
		mc_fd, reg_info.offset);

MC_FAILURE:
	close(mc_fd);

	return v_addr;
}

#define IRQ_SET_BUF_LEN  (sizeof(struct vfio_irq_set) + sizeof(int))

int rte_dpaa2_intr_enable(struct rte_intr_handle *intr_handle, int index)
{
	int len, ret;
	char irq_set_buf[IRQ_SET_BUF_LEN];
	struct vfio_irq_set *irq_set;
	int *fd_ptr;

	len = sizeof(irq_set_buf);

	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = len;
	irq_set->count = 1;
	irq_set->flags =
		VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = index;
	irq_set->start = 0;
	fd_ptr = (int *)&irq_set->data;
	*fd_ptr = intr_handle->fd;

	ret = ioctl(intr_handle->vfio_dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (ret) {
		DPAA2_BUS_ERR("Error:dpaa2 SET IRQs fd=%d, err = %d(%s)",
			      intr_handle->fd, errno, strerror(errno));
		return ret;
	}

	return ret;
}

int rte_dpaa2_intr_disable(struct rte_intr_handle *intr_handle, int index)
{
	struct vfio_irq_set *irq_set;
	char irq_set_buf[IRQ_SET_BUF_LEN];
	int len, ret;

	len = sizeof(struct vfio_irq_set);

	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = len;
	irq_set->flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = index;
	irq_set->start = 0;
	irq_set->count = 0;

	ret = ioctl(intr_handle->vfio_dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (ret)
		DPAA2_BUS_ERR(
			"Error disabling dpaa2 interrupts for fd %d",
			intr_handle->fd);

	return ret;
}

/* set up interrupt support (but not enable interrupts) */
int
rte_dpaa2_vfio_setup_intr(struct rte_intr_handle *intr_handle,
			  int vfio_dev_fd,
			  int num_irqs)
{
	int i, ret;

	/* start from MSI-X interrupt type */
	for (i = 0; i < num_irqs; i++) {
		struct vfio_irq_info irq_info = { .argsz = sizeof(irq_info) };
		int fd = -1;

		irq_info.index = i;

		ret = ioctl(vfio_dev_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq_info);
		if (ret < 0) {
			DPAA2_BUS_ERR("Cannot get IRQ(%d) info, error %i (%s)",
				      i, errno, strerror(errno));
			return -1;
		}

		/* if this vector cannot be used with eventfd,
		 * fail if we explicitly
		 * specified interrupt type, otherwise continue
		 */
		if ((irq_info.flags & VFIO_IRQ_INFO_EVENTFD) == 0)
			continue;

		/* set up an eventfd for interrupts */
		fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
		if (fd < 0) {
			DPAA2_BUS_ERR("Cannot set up eventfd, error %i (%s)",
				      errno, strerror(errno));
			return -1;
		}

		intr_handle->fd = fd;
		intr_handle->type = RTE_INTR_HANDLE_VFIO_MSI;
		intr_handle->vfio_dev_fd = vfio_dev_fd;

		return 0;
	}

	/* if we're here, we haven't found a suitable interrupt vector */
	return -1;
}

/*
 * fslmc_process_iodevices for processing only IO (ETH, CRYPTO, and possibly
 * EVENT) devices.
 */
static int
fslmc_process_iodevices(struct rte_dpaa2_device *dev)
{
	int dev_fd;
	struct vfio_device_info device_info = { .argsz = sizeof(device_info) };
	struct rte_dpaa2_object *object = NULL;

	dev_fd = ioctl(vfio_group.fd, VFIO_GROUP_GET_DEVICE_FD,
		       dev->device.name);
	if (dev_fd <= 0) {
		DPAA2_BUS_ERR("Unable to obtain device FD for device:%s",
			      dev->device.name);
		return -1;
	}

	if (ioctl(dev_fd, VFIO_DEVICE_GET_INFO, &device_info)) {
		DPAA2_BUS_ERR("Unable to obtain information for device:%s",
			      dev->device.name);
		return -1;
	}

	switch (dev->dev_type) {
	case DPAA2_ETH:
		rte_dpaa2_vfio_setup_intr(&dev->intr_handle, dev_fd,
					  device_info.num_irqs);
		break;
	case DPAA2_CON:
	case DPAA2_IO:
	case DPAA2_CI:
	case DPAA2_BPOOL:
		TAILQ_FOREACH(object, &dpaa2_obj_list, next) {
			if (dev->dev_type == object->dev_type)
				object->create(dev_fd, &device_info,
					       dev->object_id);
			else
				continue;
		}
		break;
	default:
		break;
	}

	DPAA2_BUS_LOG(DEBUG, "Device (%s) abstracted from VFIO",
		      dev->device.name);
	return 0;
}

static int
fslmc_process_mcp(struct rte_dpaa2_device *dev)
{
	int ret;
	intptr_t v_addr;
	char *dev_name = NULL;
	struct fsl_mc_io dpmng  = {0};
	struct mc_version mc_ver_info = {0};

	rte_mcp_ptr_list = malloc(sizeof(void *) * 1);
	if (!rte_mcp_ptr_list) {
		DPAA2_BUS_ERR("Unable to allocate MC portal memory");
		ret = -ENOMEM;
		goto cleanup;
	}

	dev_name = strdup(dev->device.name);
	if (!dev_name) {
		DPAA2_BUS_ERR("Unable to allocate MC device name memory");
		ret = -ENOMEM;
		goto cleanup;
	}

	v_addr = vfio_map_mcp_obj(&vfio_group, dev_name);
	if (v_addr == (intptr_t)MAP_FAILED) {
		DPAA2_BUS_ERR("Error mapping region (errno = %d)", errno);
		ret = -1;
		goto cleanup;
	}

	/* check the MC version compatibility */
	dpmng.regs = (void *)v_addr;
	if (mc_get_version(&dpmng, CMD_PRI_LOW, &mc_ver_info)) {
		DPAA2_BUS_ERR("Unable to obtain MC version");
		ret = -1;
		goto cleanup;
	}

	if ((mc_ver_info.major != MC_VER_MAJOR) ||
	    (mc_ver_info.minor < MC_VER_MINOR)) {
		DPAA2_BUS_ERR("DPAA2 MC version not compatible!"
			      " Expected %d.%d.x, Detected %d.%d.%d",
			      MC_VER_MAJOR, MC_VER_MINOR,
			      mc_ver_info.major, mc_ver_info.minor,
			      mc_ver_info.revision);
		ret = -1;
		goto cleanup;
	}
	rte_mcp_ptr_list[0] = (void *)v_addr;

	free(dev_name);
	return 0;

cleanup:
	if (dev_name)
		free(dev_name);

	if (rte_mcp_ptr_list) {
		free(rte_mcp_ptr_list);
		rte_mcp_ptr_list = NULL;
	}

	return ret;
}

int
fslmc_vfio_process_group(void)
{
	int ret;
	int found_mportal = 0;
	struct rte_dpaa2_device *dev, *dev_temp;

	/* Search the MCP as that should be initialized first. */
	TAILQ_FOREACH_SAFE(dev, &rte_fslmc_bus.device_list, next, dev_temp) {
		if (dev->dev_type == DPAA2_MPORTAL) {
			ret = fslmc_process_mcp(dev);
			if (ret) {
				DPAA2_BUS_ERR("Unable to map MC Portal");
				return -1;
			}
			if (!found_mportal)
				found_mportal = 1;

			TAILQ_REMOVE(&rte_fslmc_bus.device_list, dev, next);
			free(dev);
			dev = NULL;
			/* Ideally there is only a single dpmcp, but in case
			 * multiple exists, looping on remaining devices.
			 */
		}
	}

	/* Cannot continue if there is not even a single mportal */
	if (!found_mportal) {
		DPAA2_BUS_ERR("No MC Portal device found. Not continuing");
		return -1;
	}

	TAILQ_FOREACH_SAFE(dev, &rte_fslmc_bus.device_list, next, dev_temp) {
		switch (dev->dev_type) {
		case DPAA2_ETH:
		case DPAA2_CRYPTO:
		case DPAA2_QDMA:
			ret = fslmc_process_iodevices(dev);
			if (ret) {
				DPAA2_BUS_DEBUG("Dev (%s) init failed",
						dev->device.name);
				return ret;
			}
			break;
		case DPAA2_CON:
		case DPAA2_IO:
		case DPAA2_CI:
		case DPAA2_BPOOL:
			/* Call the object creation routine and remove the
			 * device entry from device list
			 */
			ret = fslmc_process_iodevices(dev);
			if (ret) {
				DPAA2_BUS_DEBUG("Dev (%s) init failed",
						dev->device.name);
				return -1;
			}

			/* This device is not required to be in the DPDK
			 * exposed device list.
			 */
			TAILQ_REMOVE(&rte_fslmc_bus.device_list, dev, next);
			free(dev);
			dev = NULL;
			break;
		case DPAA2_UNKNOWN:
		default:
			/* Unknown - ignore */
			DPAA2_BUS_DEBUG("Found unknown device (%s)",
					dev->device.name);
			TAILQ_REMOVE(&rte_fslmc_bus.device_list, dev, next);
			free(dev);
			dev = NULL;
		}
	}

	return 0;
}

int
fslmc_vfio_setup_group(void)
{
	int groupid;
	int ret;
	struct vfio_group_status status = { .argsz = sizeof(status) };

	/* if already done once */
	if (container_device_fd)
		return 0;

	ret = fslmc_get_container_group(&groupid);
	if (ret)
		return ret;

	/* In case this group was already opened, continue without any
	 * processing.
	 */
	if (vfio_group.groupid == groupid) {
		DPAA2_BUS_ERR("groupid already exists %d", groupid);
		return 0;
	}

	/* Get the actual group fd */
	ret = rte_vfio_get_group_fd(groupid);
	if (ret < 0)
		return ret;
	vfio_group.fd = ret;

	/* Check group viability */
	ret = ioctl(vfio_group.fd, VFIO_GROUP_GET_STATUS, &status);
	if (ret) {
		DPAA2_BUS_ERR("VFIO error getting group status");
		close(vfio_group.fd);
		rte_vfio_clear_group(vfio_group.fd);
		return ret;
	}

	if (!(status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		DPAA2_BUS_ERR("VFIO group not viable");
		close(vfio_group.fd);
		rte_vfio_clear_group(vfio_group.fd);
		return -EPERM;
	}
	/* Since Group is VIABLE, Store the groupid */
	vfio_group.groupid = groupid;

	/* check if group does not have a container yet */
	if (!(status.flags & VFIO_GROUP_FLAGS_CONTAINER_SET)) {
		/* Now connect this IOMMU group to given container */
		ret = vfio_connect_container();
		if (ret) {
			DPAA2_BUS_ERR(
				"Error connecting container with groupid %d",
				groupid);
			close(vfio_group.fd);
			rte_vfio_clear_group(vfio_group.fd);
			return ret;
		}
	}

	/* Get Device information */
	ret = ioctl(vfio_group.fd, VFIO_GROUP_GET_DEVICE_FD, g_container);
	if (ret < 0) {
		DPAA2_BUS_ERR("Error getting device %s fd from group %d",
			      g_container, vfio_group.groupid);
		close(vfio_group.fd);
		rte_vfio_clear_group(vfio_group.fd);
		return ret;
	}
	container_device_fd = ret;
	DPAA2_BUS_DEBUG("VFIO Container FD is [0x%X]",
			container_device_fd);

	return 0;
}
