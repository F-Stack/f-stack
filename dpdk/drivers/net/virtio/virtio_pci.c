/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */
#include <stdint.h>

#ifdef RTE_EXEC_ENV_LINUXAPP
 #include <dirent.h>
 #include <fcntl.h>
#endif

#include <rte_io.h>
#include <rte_bus.h>

#include "virtio_pci.h"
#include "virtio_logs.h"
#include "virtqueue.h"

/*
 * Following macros are derived from linux/pci_regs.h, however,
 * we can't simply include that header here, as there is no such
 * file for non-Linux platform.
 */
#define PCI_CAPABILITY_LIST	0x34
#define PCI_CAP_ID_VNDR		0x09
#define PCI_CAP_ID_MSIX		0x11

/*
 * The remaining space is defined by each driver as the per-driver
 * configuration space.
 */
#define VIRTIO_PCI_CONFIG(hw) \
		(((hw)->use_msix == VIRTIO_MSIX_ENABLED) ? 24 : 20)

static inline int
check_vq_phys_addr_ok(struct virtqueue *vq)
{
	/* Virtio PCI device VIRTIO_PCI_QUEUE_PF register is 32bit,
	 * and only accepts 32 bit page frame number.
	 * Check if the allocated physical memory exceeds 16TB.
	 */
	if ((vq->vq_ring_mem + vq->vq_ring_size - 1) >>
			(VIRTIO_PCI_QUEUE_ADDR_SHIFT + 32)) {
		PMD_INIT_LOG(ERR, "vring address shouldn't be above 16TB!");
		return 0;
	}

	return 1;
}

/*
 * Since we are in legacy mode:
 * http://ozlabs.org/~rusty/virtio-spec/virtio-0.9.5.pdf
 *
 * "Note that this is possible because while the virtio header is PCI (i.e.
 * little) endian, the device-specific region is encoded in the native endian of
 * the guest (where such distinction is applicable)."
 *
 * For powerpc which supports both, qemu supposes that cpu is big endian and
 * enforces this for the virtio-net stuff.
 */
static void
legacy_read_dev_config(struct virtio_hw *hw, size_t offset,
		       void *dst, int length)
{
#ifdef RTE_ARCH_PPC_64
	int size;

	while (length > 0) {
		if (length >= 4) {
			size = 4;
			rte_pci_ioport_read(VTPCI_IO(hw), dst, size,
				VIRTIO_PCI_CONFIG(hw) + offset);
			*(uint32_t *)dst = rte_be_to_cpu_32(*(uint32_t *)dst);
		} else if (length >= 2) {
			size = 2;
			rte_pci_ioport_read(VTPCI_IO(hw), dst, size,
				VIRTIO_PCI_CONFIG(hw) + offset);
			*(uint16_t *)dst = rte_be_to_cpu_16(*(uint16_t *)dst);
		} else {
			size = 1;
			rte_pci_ioport_read(VTPCI_IO(hw), dst, size,
				VIRTIO_PCI_CONFIG(hw) + offset);
		}

		dst = (char *)dst + size;
		offset += size;
		length -= size;
	}
#else
	rte_pci_ioport_read(VTPCI_IO(hw), dst, length,
		VIRTIO_PCI_CONFIG(hw) + offset);
#endif
}

static void
legacy_write_dev_config(struct virtio_hw *hw, size_t offset,
			const void *src, int length)
{
#ifdef RTE_ARCH_PPC_64
	union {
		uint32_t u32;
		uint16_t u16;
	} tmp;
	int size;

	while (length > 0) {
		if (length >= 4) {
			size = 4;
			tmp.u32 = rte_cpu_to_be_32(*(const uint32_t *)src);
			rte_pci_ioport_write(VTPCI_IO(hw), &tmp.u32, size,
				VIRTIO_PCI_CONFIG(hw) + offset);
		} else if (length >= 2) {
			size = 2;
			tmp.u16 = rte_cpu_to_be_16(*(const uint16_t *)src);
			rte_pci_ioport_write(VTPCI_IO(hw), &tmp.u16, size,
				VIRTIO_PCI_CONFIG(hw) + offset);
		} else {
			size = 1;
			rte_pci_ioport_write(VTPCI_IO(hw), src, size,
				VIRTIO_PCI_CONFIG(hw) + offset);
		}

		src = (const char *)src + size;
		offset += size;
		length -= size;
	}
#else
	rte_pci_ioport_write(VTPCI_IO(hw), src, length,
		VIRTIO_PCI_CONFIG(hw) + offset);
#endif
}

static uint64_t
legacy_get_features(struct virtio_hw *hw)
{
	uint32_t dst;

	rte_pci_ioport_read(VTPCI_IO(hw), &dst, 4, VIRTIO_PCI_HOST_FEATURES);
	return dst;
}

static void
legacy_set_features(struct virtio_hw *hw, uint64_t features)
{
	if ((features >> 32) != 0) {
		PMD_DRV_LOG(ERR,
			"only 32 bit features are allowed for legacy virtio!");
		return;
	}
	rte_pci_ioport_write(VTPCI_IO(hw), &features, 4,
		VIRTIO_PCI_GUEST_FEATURES);
}

static uint8_t
legacy_get_status(struct virtio_hw *hw)
{
	uint8_t dst;

	rte_pci_ioport_read(VTPCI_IO(hw), &dst, 1, VIRTIO_PCI_STATUS);
	return dst;
}

static void
legacy_set_status(struct virtio_hw *hw, uint8_t status)
{
	rte_pci_ioport_write(VTPCI_IO(hw), &status, 1, VIRTIO_PCI_STATUS);
}

static uint8_t
legacy_get_isr(struct virtio_hw *hw)
{
	uint8_t dst;

	rte_pci_ioport_read(VTPCI_IO(hw), &dst, 1, VIRTIO_PCI_ISR);
	return dst;
}

/* Enable one vector (0) for Link State Intrerrupt */
static uint16_t
legacy_set_config_irq(struct virtio_hw *hw, uint16_t vec)
{
	uint16_t dst;

	rte_pci_ioport_write(VTPCI_IO(hw), &vec, 2, VIRTIO_MSI_CONFIG_VECTOR);
	rte_pci_ioport_read(VTPCI_IO(hw), &dst, 2, VIRTIO_MSI_CONFIG_VECTOR);
	return dst;
}

static uint16_t
legacy_set_queue_irq(struct virtio_hw *hw, struct virtqueue *vq, uint16_t vec)
{
	uint16_t dst;

	rte_pci_ioport_write(VTPCI_IO(hw), &vq->vq_queue_index, 2,
		VIRTIO_PCI_QUEUE_SEL);
	rte_pci_ioport_write(VTPCI_IO(hw), &vec, 2, VIRTIO_MSI_QUEUE_VECTOR);
	rte_pci_ioport_read(VTPCI_IO(hw), &dst, 2, VIRTIO_MSI_QUEUE_VECTOR);
	return dst;
}

static uint16_t
legacy_get_queue_num(struct virtio_hw *hw, uint16_t queue_id)
{
	uint16_t dst;

	rte_pci_ioport_write(VTPCI_IO(hw), &queue_id, 2, VIRTIO_PCI_QUEUE_SEL);
	rte_pci_ioport_read(VTPCI_IO(hw), &dst, 2, VIRTIO_PCI_QUEUE_NUM);
	return dst;
}

static int
legacy_setup_queue(struct virtio_hw *hw, struct virtqueue *vq)
{
	uint32_t src;

	if (!check_vq_phys_addr_ok(vq))
		return -1;

	rte_pci_ioport_write(VTPCI_IO(hw), &vq->vq_queue_index, 2,
		VIRTIO_PCI_QUEUE_SEL);
	src = vq->vq_ring_mem >> VIRTIO_PCI_QUEUE_ADDR_SHIFT;
	rte_pci_ioport_write(VTPCI_IO(hw), &src, 4, VIRTIO_PCI_QUEUE_PFN);

	return 0;
}

static void
legacy_del_queue(struct virtio_hw *hw, struct virtqueue *vq)
{
	uint32_t src = 0;

	rte_pci_ioport_write(VTPCI_IO(hw), &vq->vq_queue_index, 2,
		VIRTIO_PCI_QUEUE_SEL);
	rte_pci_ioport_write(VTPCI_IO(hw), &src, 4, VIRTIO_PCI_QUEUE_PFN);
}

static void
legacy_notify_queue(struct virtio_hw *hw, struct virtqueue *vq)
{
	rte_pci_ioport_write(VTPCI_IO(hw), &vq->vq_queue_index, 2,
		VIRTIO_PCI_QUEUE_NOTIFY);
}

const struct virtio_pci_ops legacy_ops = {
	.read_dev_cfg	= legacy_read_dev_config,
	.write_dev_cfg	= legacy_write_dev_config,
	.get_status	= legacy_get_status,
	.set_status	= legacy_set_status,
	.get_features	= legacy_get_features,
	.set_features	= legacy_set_features,
	.get_isr	= legacy_get_isr,
	.set_config_irq	= legacy_set_config_irq,
	.set_queue_irq  = legacy_set_queue_irq,
	.get_queue_num	= legacy_get_queue_num,
	.setup_queue	= legacy_setup_queue,
	.del_queue	= legacy_del_queue,
	.notify_queue	= legacy_notify_queue,
};

static inline void
io_write64_twopart(uint64_t val, uint32_t *lo, uint32_t *hi)
{
	rte_write32(val & ((1ULL << 32) - 1), lo);
	rte_write32(val >> 32,		     hi);
}

static void
modern_read_dev_config(struct virtio_hw *hw, size_t offset,
		       void *dst, int length)
{
	int i;
	uint8_t *p;
	uint8_t old_gen, new_gen;

	do {
		old_gen = rte_read8(&hw->common_cfg->config_generation);

		p = dst;
		for (i = 0;  i < length; i++)
			*p++ = rte_read8((uint8_t *)hw->dev_cfg + offset + i);

		new_gen = rte_read8(&hw->common_cfg->config_generation);
	} while (old_gen != new_gen);
}

static void
modern_write_dev_config(struct virtio_hw *hw, size_t offset,
			const void *src, int length)
{
	int i;
	const uint8_t *p = src;

	for (i = 0;  i < length; i++)
		rte_write8((*p++), (((uint8_t *)hw->dev_cfg) + offset + i));
}

static uint64_t
modern_get_features(struct virtio_hw *hw)
{
	uint32_t features_lo, features_hi;

	rte_write32(0, &hw->common_cfg->device_feature_select);
	features_lo = rte_read32(&hw->common_cfg->device_feature);

	rte_write32(1, &hw->common_cfg->device_feature_select);
	features_hi = rte_read32(&hw->common_cfg->device_feature);

	return ((uint64_t)features_hi << 32) | features_lo;
}

static void
modern_set_features(struct virtio_hw *hw, uint64_t features)
{
	rte_write32(0, &hw->common_cfg->guest_feature_select);
	rte_write32(features & ((1ULL << 32) - 1),
		    &hw->common_cfg->guest_feature);

	rte_write32(1, &hw->common_cfg->guest_feature_select);
	rte_write32(features >> 32,
		    &hw->common_cfg->guest_feature);
}

static uint8_t
modern_get_status(struct virtio_hw *hw)
{
	return rte_read8(&hw->common_cfg->device_status);
}

static void
modern_set_status(struct virtio_hw *hw, uint8_t status)
{
	rte_write8(status, &hw->common_cfg->device_status);
}

static uint8_t
modern_get_isr(struct virtio_hw *hw)
{
	return rte_read8(hw->isr);
}

static uint16_t
modern_set_config_irq(struct virtio_hw *hw, uint16_t vec)
{
	rte_write16(vec, &hw->common_cfg->msix_config);
	return rte_read16(&hw->common_cfg->msix_config);
}

static uint16_t
modern_set_queue_irq(struct virtio_hw *hw, struct virtqueue *vq, uint16_t vec)
{
	rte_write16(vq->vq_queue_index, &hw->common_cfg->queue_select);
	rte_write16(vec, &hw->common_cfg->queue_msix_vector);
	return rte_read16(&hw->common_cfg->queue_msix_vector);
}

static uint16_t
modern_get_queue_num(struct virtio_hw *hw, uint16_t queue_id)
{
	rte_write16(queue_id, &hw->common_cfg->queue_select);
	return rte_read16(&hw->common_cfg->queue_size);
}

static int
modern_setup_queue(struct virtio_hw *hw, struct virtqueue *vq)
{
	uint64_t desc_addr, avail_addr, used_addr;
	uint16_t notify_off;

	if (!check_vq_phys_addr_ok(vq))
		return -1;

	desc_addr = vq->vq_ring_mem;
	avail_addr = desc_addr + vq->vq_nentries * sizeof(struct vring_desc);
	used_addr = RTE_ALIGN_CEIL(avail_addr + offsetof(struct vring_avail,
							 ring[vq->vq_nentries]),
				   VIRTIO_PCI_VRING_ALIGN);

	rte_write16(vq->vq_queue_index, &hw->common_cfg->queue_select);

	io_write64_twopart(desc_addr, &hw->common_cfg->queue_desc_lo,
				      &hw->common_cfg->queue_desc_hi);
	io_write64_twopart(avail_addr, &hw->common_cfg->queue_avail_lo,
				       &hw->common_cfg->queue_avail_hi);
	io_write64_twopart(used_addr, &hw->common_cfg->queue_used_lo,
				      &hw->common_cfg->queue_used_hi);

	notify_off = rte_read16(&hw->common_cfg->queue_notify_off);
	vq->notify_addr = (void *)((uint8_t *)hw->notify_base +
				notify_off * hw->notify_off_multiplier);

	rte_write16(1, &hw->common_cfg->queue_enable);

	PMD_INIT_LOG(DEBUG, "queue %u addresses:", vq->vq_queue_index);
	PMD_INIT_LOG(DEBUG, "\t desc_addr: %" PRIx64, desc_addr);
	PMD_INIT_LOG(DEBUG, "\t aval_addr: %" PRIx64, avail_addr);
	PMD_INIT_LOG(DEBUG, "\t used_addr: %" PRIx64, used_addr);
	PMD_INIT_LOG(DEBUG, "\t notify addr: %p (notify offset: %u)",
		vq->notify_addr, notify_off);

	return 0;
}

static void
modern_del_queue(struct virtio_hw *hw, struct virtqueue *vq)
{
	rte_write16(vq->vq_queue_index, &hw->common_cfg->queue_select);

	io_write64_twopart(0, &hw->common_cfg->queue_desc_lo,
				  &hw->common_cfg->queue_desc_hi);
	io_write64_twopart(0, &hw->common_cfg->queue_avail_lo,
				  &hw->common_cfg->queue_avail_hi);
	io_write64_twopart(0, &hw->common_cfg->queue_used_lo,
				  &hw->common_cfg->queue_used_hi);

	rte_write16(0, &hw->common_cfg->queue_enable);
}

static void
modern_notify_queue(struct virtio_hw *hw __rte_unused, struct virtqueue *vq)
{
	rte_write16(vq->vq_queue_index, vq->notify_addr);
}

const struct virtio_pci_ops modern_ops = {
	.read_dev_cfg	= modern_read_dev_config,
	.write_dev_cfg	= modern_write_dev_config,
	.get_status	= modern_get_status,
	.set_status	= modern_set_status,
	.get_features	= modern_get_features,
	.set_features	= modern_set_features,
	.get_isr	= modern_get_isr,
	.set_config_irq	= modern_set_config_irq,
	.set_queue_irq  = modern_set_queue_irq,
	.get_queue_num	= modern_get_queue_num,
	.setup_queue	= modern_setup_queue,
	.del_queue	= modern_del_queue,
	.notify_queue	= modern_notify_queue,
};


void
vtpci_read_dev_config(struct virtio_hw *hw, size_t offset,
		      void *dst, int length)
{
	VTPCI_OPS(hw)->read_dev_cfg(hw, offset, dst, length);
}

void
vtpci_write_dev_config(struct virtio_hw *hw, size_t offset,
		       const void *src, int length)
{
	VTPCI_OPS(hw)->write_dev_cfg(hw, offset, src, length);
}

uint64_t
vtpci_negotiate_features(struct virtio_hw *hw, uint64_t host_features)
{
	uint64_t features;

	/*
	 * Limit negotiated features to what the driver, virtqueue, and
	 * host all support.
	 */
	features = host_features & hw->guest_features;
	VTPCI_OPS(hw)->set_features(hw, features);

	return features;
}

void
vtpci_reset(struct virtio_hw *hw)
{
	VTPCI_OPS(hw)->set_status(hw, VIRTIO_CONFIG_STATUS_RESET);
	/* flush status write */
	VTPCI_OPS(hw)->get_status(hw);
}

void
vtpci_reinit_complete(struct virtio_hw *hw)
{
	vtpci_set_status(hw, VIRTIO_CONFIG_STATUS_DRIVER_OK);
}

void
vtpci_set_status(struct virtio_hw *hw, uint8_t status)
{
	if (status != VIRTIO_CONFIG_STATUS_RESET)
		status |= VTPCI_OPS(hw)->get_status(hw);

	VTPCI_OPS(hw)->set_status(hw, status);
}

uint8_t
vtpci_get_status(struct virtio_hw *hw)
{
	return VTPCI_OPS(hw)->get_status(hw);
}

uint8_t
vtpci_isr(struct virtio_hw *hw)
{
	return VTPCI_OPS(hw)->get_isr(hw);
}

static void *
get_cfg_addr(struct rte_pci_device *dev, struct virtio_pci_cap *cap)
{
	uint8_t  bar    = cap->bar;
	uint32_t length = cap->length;
	uint32_t offset = cap->offset;
	uint8_t *base;

	if (bar >= PCI_MAX_RESOURCE) {
		PMD_INIT_LOG(ERR, "invalid bar: %u", bar);
		return NULL;
	}

	if (offset + length < offset) {
		PMD_INIT_LOG(ERR, "offset(%u) + length(%u) overflows",
			offset, length);
		return NULL;
	}

	if (offset + length > dev->mem_resource[bar].len) {
		PMD_INIT_LOG(ERR,
			"invalid cap: overflows bar space: %u > %" PRIu64,
			offset + length, dev->mem_resource[bar].len);
		return NULL;
	}

	base = dev->mem_resource[bar].addr;
	if (base == NULL) {
		PMD_INIT_LOG(ERR, "bar %u base addr is NULL", bar);
		return NULL;
	}

	return base + offset;
}

#define PCI_MSIX_ENABLE 0x8000

static int
virtio_read_caps(struct rte_pci_device *dev, struct virtio_hw *hw)
{
	uint8_t pos;
	struct virtio_pci_cap cap;
	int ret;

	if (rte_pci_map_device(dev)) {
		PMD_INIT_LOG(DEBUG, "failed to map pci device!");
		return -1;
	}

	ret = rte_pci_read_config(dev, &pos, 1, PCI_CAPABILITY_LIST);
	if (ret != 1) {
		PMD_INIT_LOG(DEBUG,
			     "failed to read pci capability list, ret %d", ret);
		return -1;
	}

	while (pos) {
		ret = rte_pci_read_config(dev, &cap, 2, pos);
		if (ret != 2) {
			PMD_INIT_LOG(DEBUG,
				     "failed to read pci cap at pos: %x ret %d",
				     pos, ret);
			break;
		}

		if (cap.cap_vndr == PCI_CAP_ID_MSIX) {
			/* Transitional devices would also have this capability,
			 * that's why we also check if msix is enabled.
			 * 1st byte is cap ID; 2nd byte is the position of next
			 * cap; next two bytes are the flags.
			 */
			uint16_t flags;

			ret = rte_pci_read_config(dev, &flags, sizeof(flags),
					pos + 2);
			if (ret != sizeof(flags)) {
				PMD_INIT_LOG(DEBUG,
					     "failed to read pci cap at pos:"
					     " %x ret %d", pos + 2, ret);
				break;
			}

			if (flags & PCI_MSIX_ENABLE)
				hw->use_msix = VIRTIO_MSIX_ENABLED;
			else
				hw->use_msix = VIRTIO_MSIX_DISABLED;
		}

		if (cap.cap_vndr != PCI_CAP_ID_VNDR) {
			PMD_INIT_LOG(DEBUG,
				"[%2x] skipping non VNDR cap id: %02x",
				pos, cap.cap_vndr);
			goto next;
		}

		ret = rte_pci_read_config(dev, &cap, sizeof(cap), pos);
		if (ret != sizeof(cap)) {
			PMD_INIT_LOG(DEBUG,
				     "failed to read pci cap at pos: %x ret %d",
				     pos, ret);
			break;
		}

		PMD_INIT_LOG(DEBUG,
			"[%2x] cfg type: %u, bar: %u, offset: %04x, len: %u",
			pos, cap.cfg_type, cap.bar, cap.offset, cap.length);

		switch (cap.cfg_type) {
		case VIRTIO_PCI_CAP_COMMON_CFG:
			hw->common_cfg = get_cfg_addr(dev, &cap);
			break;
		case VIRTIO_PCI_CAP_NOTIFY_CFG:
			ret = rte_pci_read_config(dev,
					&hw->notify_off_multiplier,
					4, pos + sizeof(cap));
			if (ret != 4)
				PMD_INIT_LOG(DEBUG,
					"failed to read notify_off_multiplier, ret %d",
					ret);
			else
				hw->notify_base = get_cfg_addr(dev, &cap);
			break;
		case VIRTIO_PCI_CAP_DEVICE_CFG:
			hw->dev_cfg = get_cfg_addr(dev, &cap);
			break;
		case VIRTIO_PCI_CAP_ISR_CFG:
			hw->isr = get_cfg_addr(dev, &cap);
			break;
		}

next:
		pos = cap.cap_next;
	}

	if (hw->common_cfg == NULL || hw->notify_base == NULL ||
	    hw->dev_cfg == NULL    || hw->isr == NULL) {
		PMD_INIT_LOG(INFO, "no modern virtio pci device found.");
		return -1;
	}

	PMD_INIT_LOG(INFO, "found modern virtio pci device.");

	PMD_INIT_LOG(DEBUG, "common cfg mapped at: %p", hw->common_cfg);
	PMD_INIT_LOG(DEBUG, "device cfg mapped at: %p", hw->dev_cfg);
	PMD_INIT_LOG(DEBUG, "isr cfg mapped at: %p", hw->isr);
	PMD_INIT_LOG(DEBUG, "notify base: %p, notify off multiplier: %u",
		hw->notify_base, hw->notify_off_multiplier);

	return 0;
}

/*
 * Return -1:
 *   if there is error mapping with VFIO/UIO.
 *   if port map error when driver type is KDRV_NONE.
 *   if whitelisted but driver type is KDRV_UNKNOWN.
 * Return 1 if kernel driver is managing the device.
 * Return 0 on success.
 */
int
vtpci_init(struct rte_pci_device *dev, struct virtio_hw *hw)
{
	/*
	 * Try if we can succeed reading virtio pci caps, which exists
	 * only on modern pci device. If failed, we fallback to legacy
	 * virtio handling.
	 */
	if (virtio_read_caps(dev, hw) == 0) {
		PMD_INIT_LOG(INFO, "modern virtio pci detected.");
		virtio_hw_internal[hw->port_id].vtpci_ops = &modern_ops;
		hw->modern = 1;
		return 0;
	}

	PMD_INIT_LOG(INFO, "trying with legacy virtio pci.");
	if (rte_pci_ioport_map(dev, 0, VTPCI_IO(hw)) < 0) {
		rte_pci_unmap_device(dev);
		if (dev->kdrv == RTE_KDRV_UNKNOWN &&
		    (!dev->device.devargs ||
		     dev->device.devargs->bus !=
		     rte_bus_find_by_name("pci"))) {
			PMD_INIT_LOG(INFO,
				"skip kernel managed virtio device.");
			return 1;
		}
		return -1;
	}

	virtio_hw_internal[hw->port_id].vtpci_ops = &legacy_ops;
	hw->modern   = 0;

	return 0;
}

enum virtio_msix_status
vtpci_msix_detect(struct rte_pci_device *dev)
{
	uint8_t pos;
	int ret;

	ret = rte_pci_read_config(dev, &pos, 1, PCI_CAPABILITY_LIST);
	if (ret != 1) {
		PMD_INIT_LOG(DEBUG,
			     "failed to read pci capability list, ret %d", ret);
		return VIRTIO_MSIX_NONE;
	}

	while (pos) {
		uint8_t cap[2];

		ret = rte_pci_read_config(dev, cap, sizeof(cap), pos);
		if (ret != sizeof(cap)) {
			PMD_INIT_LOG(DEBUG,
				     "failed to read pci cap at pos: %x ret %d",
				     pos, ret);
			break;
		}

		if (cap[0] == PCI_CAP_ID_MSIX) {
			uint16_t flags;

			ret = rte_pci_read_config(dev, &flags, sizeof(flags),
					pos + sizeof(cap));
			if (ret != sizeof(flags)) {
				PMD_INIT_LOG(DEBUG,
					     "failed to read pci cap at pos:"
					     " %x ret %d", pos + 2, ret);
				break;
			}

			if (flags & PCI_MSIX_ENABLE)
				return VIRTIO_MSIX_ENABLED;
			else
				return VIRTIO_MSIX_DISABLED;
		}

		pos = cap[1];
	}

	return VIRTIO_MSIX_NONE;
}
