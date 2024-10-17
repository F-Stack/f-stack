/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <sys/queue.h>

#include <rte_windows.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_eal.h>
#include <rte_memory.h>
#include <rte_bus_pci.h>

#include "private.h"
#include "pci_netuio.h"

#include <devpkey.h>
#include <regstr.h>

#if defined RTE_TOOLCHAIN_GCC && (__MINGW64_VERSION_MAJOR < 8)
#include <devpropdef.h>
DEFINE_DEVPROPKEY(DEVPKEY_Device_Numa_Node, 0x540b947e, 0x8b40, 0x45bc,
	0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2, 3);
#endif

/*
 * This code is used to simulate a PCI probe by parsing information in
 * the registry hive for PCI devices.
 */

/* Class ID consists of hexadecimal digits */
#define RTE_PCI_DRV_CLASSID_DIGIT "0123456789abcdefABCDEF"

/* Some of the functions below are not implemented on Windows,
 * but need to be defined for compilation purposes
 */

/* Map pci device */
int
rte_pci_map_device(struct rte_pci_device *dev)
{
	/* Only return success for devices bound to netuio.
	 * Devices that are bound to netuio are mapped at
	 * the bus probing stage.
	 */
	if (dev->kdrv == RTE_PCI_KDRV_NET_UIO)
		return 0;
	else
		return -1;
}

/* Unmap pci device */
void
rte_pci_unmap_device(struct rte_pci_device *dev __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
}

/* Read PCI config space. */
int
rte_pci_read_config(const struct rte_pci_device *dev __rte_unused,
	void *buf __rte_unused, size_t len __rte_unused,
	off_t offset __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
	return 0;
}

/* Write PCI config space. */
int
rte_pci_write_config(const struct rte_pci_device *dev __rte_unused,
	const void *buf __rte_unused, size_t len __rte_unused,
	off_t offset __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
	return 0;
}

enum rte_iova_mode
pci_device_iova_mode(const struct rte_pci_driver *pdrv __rte_unused,
		const struct rte_pci_device *pdev __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
	return RTE_IOVA_DC;
}

int
rte_pci_ioport_map(struct rte_pci_device *dev __rte_unused,
	int bar __rte_unused, struct rte_pci_ioport *p __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
	return -1;
}


void
rte_pci_ioport_read(struct rte_pci_ioport *p __rte_unused,
	void *data __rte_unused, size_t len __rte_unused,
	off_t offset __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
}

int
rte_pci_ioport_unmap(struct rte_pci_ioport *p __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
	return -1;
}

bool
pci_device_iommu_support_va(const struct rte_pci_device *dev __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
	return false;
}

void
rte_pci_ioport_write(struct rte_pci_ioport *p __rte_unused,
		const void *data __rte_unused, size_t len __rte_unused,
		off_t offset __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
}

/* remap the PCI resource of a PCI device in anonymous virtual memory */
int
pci_uio_remap_resource(struct rte_pci_device *dev __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
	return -1;
}

static int
get_device_pci_address(HDEVINFO dev_info,
	PSP_DEVINFO_DATA device_info_data, struct rte_pci_addr *addr)
{
	BOOL  res;
	ULONG bus_num, dev_and_func;

	res = SetupDiGetDeviceRegistryProperty(dev_info, device_info_data,
		SPDRP_BUSNUMBER, NULL, (PBYTE)&bus_num, sizeof(bus_num), NULL);
	if (!res) {
		RTE_LOG_WIN32_ERR(
			"SetupDiGetDeviceRegistryProperty(SPDRP_BUSNUMBER)");
		return -1;
	}

	res = SetupDiGetDeviceRegistryProperty(dev_info, device_info_data,
		SPDRP_ADDRESS, NULL, (PBYTE)&dev_and_func, sizeof(dev_and_func),
		NULL);
	if (!res) {
		RTE_LOG_WIN32_ERR(
			"SetupDiGetDeviceRegistryProperty(SPDRP_ADDRESS)");
		return -1;
	}

	addr->domain = (bus_num >> 8) & 0xffff;
	addr->bus = bus_num & 0xff;
	addr->devid = dev_and_func >> 16;
	addr->function = dev_and_func & 0xffff;
	return 0;
}

static int
get_device_resource_info(HDEVINFO dev_info,
	PSP_DEVINFO_DATA dev_info_data, struct rte_pci_device *dev)
{
	DEVPROPTYPE property_type;
	DWORD numa_node;
	BOOL  res;
	int ret;

	switch (dev->kdrv) {
	case RTE_PCI_KDRV_UNKNOWN:
		/* bifurcated driver case - mem_resource is unneeded */
		dev->mem_resource[0].phys_addr = 0;
		dev->mem_resource[0].len = 0;
		dev->mem_resource[0].addr = NULL;
		break;
	case RTE_PCI_KDRV_NET_UIO:
		/* get device info from NetUIO kernel driver */
		ret = get_netuio_device_info(dev_info, dev_info_data, dev);
		if (ret != 0) {
			RTE_LOG(DEBUG, EAL,
				"Could not retrieve device info for PCI device "
				PCI_PRI_FMT,
				dev->addr.domain, dev->addr.bus,
				dev->addr.devid, dev->addr.function);
			return ret;
		}
		break;
	default:
		/* kernel driver type is unsupported */
		RTE_LOG(DEBUG, EAL,
			"Kernel driver type for PCI device " PCI_PRI_FMT ","
			" is unsupported",
			dev->addr.domain, dev->addr.bus,
			dev->addr.devid, dev->addr.function);
		return -1;
	}

	/* Get NUMA node using DEVPKEY_Device_Numa_Node */
	dev->device.numa_node = SOCKET_ID_ANY;
	res = SetupDiGetDevicePropertyW(dev_info, dev_info_data,
		&DEVPKEY_Device_Numa_Node, &property_type,
		(BYTE *)&numa_node, sizeof(numa_node), NULL, 0);
	if (!res) {
		DWORD error = GetLastError();
		if (error == ERROR_NOT_FOUND) {
			/* On older CPUs, NUMA is not bound to PCIe locality. */
			return ERROR_SUCCESS;
		}
		RTE_LOG_WIN32_ERR("SetupDiGetDevicePropertyW"
			"(DEVPKEY_Device_Numa_Node)");
		return -1;
	}
	dev->device.numa_node = numa_node;

	return ERROR_SUCCESS;
}

/*
 * get string that contains the list of hardware IDs for a device
 */
static int
get_pci_hardware_id(HDEVINFO dev_info, PSP_DEVINFO_DATA device_info_data,
	char *pci_device_info, size_t pci_device_info_len)
{
	BOOL  res;

	/* Retrieve PCI device IDs */
	res = SetupDiGetDeviceRegistryPropertyA(dev_info, device_info_data,
			SPDRP_HARDWAREID, NULL, (BYTE *)pci_device_info,
			pci_device_info_len, NULL);
	if (!res) {
		RTE_LOG_WIN32_ERR(
			"SetupDiGetDeviceRegistryPropertyA(SPDRP_HARDWAREID)");
		return -1;
	}

	return 0;
}

/*
 * parse the SPDRP_HARDWAREID output and assign to rte_pci_id
 *
 * A list of the device identification string formats can be found at:
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/install/identifiers-for-pci-devices
 */
static int
parse_pci_hardware_id(const char *buf, struct rte_pci_id *pci_id)
{
	int ids = 0;
	uint16_t vendor_id, device_id;
	uint32_t subvendor_id = 0, class_id = 0;
	const char *cp;

	ids = sscanf_s(buf, "PCI\\VEN_%" PRIx16 "&DEV_%" PRIx16 "&SUBSYS_%"
		PRIx32, &vendor_id, &device_id, &subvendor_id);
	if (ids != 3)
		return -1;

	/* Try and find PCI class ID */
	for (cp = buf; !(cp[0] == 0 && cp[1] == 0); cp++)
		if (*cp == '&' && sscanf_s(cp,
				"&CC_%" PRIx32, &class_id) == 1) {
			/*
			 * If the Programming Interface code is not specified,
			 * assume that it is zero.
			 */
			if (strspn(cp + 4, RTE_PCI_DRV_CLASSID_DIGIT) == 4)
				class_id <<= 8;
			break;
		}

	pci_id->vendor_id = vendor_id;
	pci_id->device_id = device_id;
	pci_id->subsystem_device_id = subvendor_id >> 16;
	pci_id->subsystem_vendor_id = subvendor_id & 0xffff;
	pci_id->class_id = class_id;
	return 0;
}

static void
set_kernel_driver_type(PSP_DEVINFO_DATA device_info_data,
	struct rte_pci_device *dev)
{
	/* set kernel driver type based on device class */
	if (IsEqualGUID(&(device_info_data->ClassGuid), &GUID_DEVCLASS_NETUIO))
		dev->kdrv = RTE_PCI_KDRV_NET_UIO;
	else
		dev->kdrv = RTE_PCI_KDRV_UNKNOWN;
}

static int
pci_scan_one(HDEVINFO dev_info, PSP_DEVINFO_DATA device_info_data)
{
	struct rte_pci_device *dev = NULL;
	int ret = -1;
	char  pci_device_info[REGSTR_VAL_MAX_HCID_LEN];
	struct rte_pci_addr addr;
	struct rte_pci_id pci_id;

	ret = get_device_pci_address(dev_info, device_info_data, &addr);
	if (ret != 0)
		goto end;

	if (rte_pci_ignore_device(&addr)) {
		/*
		 * We won't add this device, but we want to continue
		 * looking for supported devices
		 */
		ret = ERROR_CONTINUE;
		goto end;
	}

	ret = get_pci_hardware_id(dev_info, device_info_data,
		pci_device_info, sizeof(pci_device_info));
	if (ret != 0)
		goto end;

	ret = parse_pci_hardware_id((const char *)&pci_device_info, &pci_id);
	if (ret != 0) {
		/*
		 * We won't add this device, but we want to continue
		 * looking for supported devices
		 */
		ret = ERROR_CONTINUE;
		goto end;
	}

	dev = malloc(sizeof(*dev));
	if (dev == NULL)
		goto end;

	memset(dev, 0, sizeof(*dev));

	dev->device.bus = &rte_pci_bus.bus;
	dev->addr = addr;
	dev->id = pci_id;
	dev->max_vfs = 0; /* TODO: get max_vfs */

	pci_common_set(dev);

	set_kernel_driver_type(device_info_data, dev);

	/* get resources */
	if (get_device_resource_info(dev_info, device_info_data, dev)
			!= ERROR_SUCCESS) {
		goto end;
	}

	/* device is valid, add in list (sorted) */
	if (TAILQ_EMPTY(&rte_pci_bus.device_list)) {
		rte_pci_add_device(dev);
	} else {
		struct rte_pci_device *dev2 = NULL;
		int ret;

		TAILQ_FOREACH(dev2, &rte_pci_bus.device_list, next) {
			ret = rte_pci_addr_cmp(&dev->addr, &dev2->addr);
			if (ret > 0) {
				continue;
			} else if (ret < 0) {
				rte_pci_insert_device(dev2, dev);
			} else { /* already registered */
				dev2->kdrv = dev->kdrv;
				dev2->max_vfs = dev->max_vfs;
				memmove(dev2->mem_resource, dev->mem_resource,
					sizeof(dev->mem_resource));
				pci_free(dev);
			}
			return 0;
		}
		rte_pci_add_device(dev);
	}

	return 0;
end:
	pci_free(dev);
	return ret;
}

/*
 * Scan the contents of the PCI bus
 * and add all network class devices into the devices list.
 */
int
rte_pci_scan(void)
{
	int   ret = -1;
	DWORD device_index = 0, found_device = 0;
	HDEVINFO dev_info;
	SP_DEVINFO_DATA device_info_data;

	/* for debug purposes, PCI can be disabled */
	if (!rte_eal_has_pci())
		return 0;

	dev_info = SetupDiGetClassDevs(NULL, TEXT("PCI"), NULL,
		DIGCF_PRESENT | DIGCF_ALLCLASSES);
	if (dev_info == INVALID_HANDLE_VALUE) {
		RTE_LOG_WIN32_ERR("SetupDiGetClassDevs(pci_scan)");
		RTE_LOG(ERR, EAL, "Unable to enumerate PCI devices.\n");
		goto end;
	}

	device_info_data.cbSize = sizeof(SP_DEVINFO_DATA);
	device_index = 0;

	while (SetupDiEnumDeviceInfo(dev_info, device_index,
	    &device_info_data)) {
		device_index++;
		/* we only want to enumerate net & netuio class devices */
		if (IsEqualGUID(&(device_info_data.ClassGuid),
			    &GUID_DEVCLASS_NET) ||
			IsEqualGUID(&(device_info_data.ClassGuid),
			    &GUID_DEVCLASS_NETUIO)) {
			ret = pci_scan_one(dev_info, &device_info_data);
			if (ret == ERROR_SUCCESS)
				found_device++;
			else if (ret != ERROR_CONTINUE)
				goto end;
		}
		memset(&device_info_data, 0, sizeof(SP_DEVINFO_DATA));
		device_info_data.cbSize = sizeof(SP_DEVINFO_DATA);
	}

	RTE_LOG(DEBUG, EAL, "PCI scan found %lu devices\n", found_device);
	ret = 0;
end:
	if (dev_info != INVALID_HANDLE_VALUE)
		SetupDiDestroyDeviceInfoList(dev_info);

	return ret;
}
