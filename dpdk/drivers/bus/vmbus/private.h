/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018, Microsoft Corporation.
 * All Rights Reserved.
 */

#ifndef _VMBUS_PRIVATE_H_
#define _VMBUS_PRIVATE_H_

#include <stdbool.h>
#include <sys/uio.h>
#include <rte_log.h>
#include <rte_vmbus_reg.h>
#include <rte_bus_vmbus.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE	4096
#endif

extern struct rte_vmbus_bus rte_vmbus_bus;

extern int vmbus_logtype_bus;
#define VMBUS_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, vmbus_logtype_bus, "%s(): " fmt "\n", \
		__func__, ##args)

struct vmbus_br {
	struct vmbus_bufring *vbr;
	uint32_t	dsize;
	uint32_t	windex; /* next available location */
};

#define UIO_NAME_MAX 64

struct vmbus_map {
	void *addr;	/* user mmap of resource */
	uint64_t size;	/* length */
};

/*
 * For multi-process we need to reproduce all vmbus mappings in secondary
 * processes, so save them in a tailq.
 */
struct mapped_vmbus_resource {
	TAILQ_ENTRY(mapped_vmbus_resource) next;

	rte_uuid_t id;
	int nb_maps;
	struct vmbus_channel *primary;
	struct vmbus_map maps[VMBUS_MAX_RESOURCE];
	char path[PATH_MAX];
};

TAILQ_HEAD(mapped_vmbus_res_list, mapped_vmbus_resource);

#define HV_MON_TRIG_LEN	32
#define HV_MON_TRIG_MAX	4

struct vmbus_channel {
	STAILQ_HEAD(, vmbus_channel) subchannel_list;
	STAILQ_ENTRY(vmbus_channel) next;
	const struct rte_vmbus_device *device;

	struct vmbus_br rxbr;
	struct vmbus_br txbr;

	uint16_t relid;
	uint16_t subchannel_id;
	uint8_t monitor_id;
};

#define VMBUS_MAX_CHANNELS	64

struct rte_devargs *
vmbus_devargs_lookup(struct rte_vmbus_device *dev);

int vmbus_chan_create(const struct rte_vmbus_device *device,
		      uint16_t relid, uint16_t subid, uint8_t monitor_id,
		      struct vmbus_channel **new_chan);

void vmbus_add_device(struct rte_vmbus_device *vmbus_dev);
void vmbus_insert_device(struct rte_vmbus_device *exist_vmbus_dev,
			 struct rte_vmbus_device *new_vmbus_dev);
void vmbus_remove_device(struct rte_vmbus_device *vmbus_device);

void vmbus_uio_irq_control(struct rte_vmbus_device *dev, int32_t onoff);
int vmbus_uio_irq_read(struct rte_vmbus_device *dev);

int vmbus_uio_map_resource(struct rte_vmbus_device *dev);
void vmbus_uio_unmap_resource(struct rte_vmbus_device *dev);

int vmbus_uio_alloc_resource(struct rte_vmbus_device *dev,
		struct mapped_vmbus_resource **uio_res);
void vmbus_uio_free_resource(struct rte_vmbus_device *dev,
		struct mapped_vmbus_resource *uio_res);

struct mapped_vmbus_resource *
vmbus_uio_find_resource(const struct rte_vmbus_device *dev);
int vmbus_uio_map_resource_by_index(struct rte_vmbus_device *dev, int res_idx,
				    struct mapped_vmbus_resource *uio_res,
				    int flags);

void *vmbus_map_resource(void *requested_addr, int fd, off_t offset,
		size_t size, int additional_flags);
void vmbus_unmap_resource(void *requested_addr, size_t size);

bool vmbus_uio_subchannels_supported(const struct rte_vmbus_device *dev,
				     const struct vmbus_channel *chan);
int vmbus_uio_get_subchan(struct vmbus_channel *primary,
			  struct vmbus_channel **subchan);
int vmbus_uio_map_rings(struct vmbus_channel *chan);
int vmbus_uio_map_secondary_subchan(const struct rte_vmbus_device *dev,
				    const struct vmbus_channel *chan);

void vmbus_br_setup(struct vmbus_br *br, void *buf, unsigned int blen);

/* Amount of space available for write */
static inline uint32_t
vmbus_br_availwrite(const struct vmbus_br *br, uint32_t windex)
{
	uint32_t rindex = br->vbr->rindex;

	if (windex >= rindex)
		return br->dsize - (windex - rindex);
	else
		return rindex - windex;
}

static inline uint32_t
vmbus_br_availread(const struct vmbus_br *br)
{
	return br->dsize - vmbus_br_availwrite(br, br->vbr->windex);
}

int vmbus_txbr_write(struct vmbus_br *tbr, const struct iovec iov[], int iovlen,
		     bool *need_sig);

int vmbus_rxbr_peek(const struct vmbus_br *rbr, void *data, size_t dlen);

int vmbus_rxbr_read(struct vmbus_br *rbr, void *data, size_t dlen, size_t hlen);

#endif /* _VMBUS_PRIVATE_H_ */
