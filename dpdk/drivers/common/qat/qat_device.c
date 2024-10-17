/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Intel Corporation
 */

#include <rte_string_fns.h>
#include <rte_devargs.h>
#include <ctype.h>

#include "qat_device.h"
#include "adf_transport_access_macros.h"
#include "qat_sym.h"
#include "qat_comp_pmd.h"
#include "adf_pf2vf_msg.h"
#include "qat_pf2vf.h"

/* Hardware device information per generation */
struct qat_gen_hw_data qat_gen_config[QAT_N_GENS];
struct qat_dev_hw_spec_funcs *qat_dev_hw_spec[QAT_N_GENS];

/* per-process array of device data */
struct qat_device_info qat_pci_devs[RTE_PMD_QAT_MAX_PCI_DEVICES];
static int qat_nb_pci_devices;

/*
 * The set of PCI devices this driver supports
 */

static const struct rte_pci_id pci_id_qat_map[] = {
		{
			RTE_PCI_DEVICE(0x8086, 0x0443),
		},
		{
			RTE_PCI_DEVICE(0x8086, 0x37c9),
		},
		{
			RTE_PCI_DEVICE(0x8086, 0x19e3),
		},
		{
			RTE_PCI_DEVICE(0x8086, 0x6f55),
		},
		{
			RTE_PCI_DEVICE(0x8086, 0x18ef),
		},
		{
			RTE_PCI_DEVICE(0x8086, 0x18a1),
		},
		{
			RTE_PCI_DEVICE(0x8086, 0x4941),
		},
		{
			RTE_PCI_DEVICE(0x8086, 0x4943),
		},
		{.device_id = 0},
};

static int
qat_pci_get_extra_size(enum qat_device_gen qat_dev_gen)
{
	struct qat_dev_hw_spec_funcs *ops_hw =
		qat_dev_hw_spec[qat_dev_gen];
	if (ops_hw->qat_dev_get_extra_size == NULL)
		return -ENOTSUP;
	return ops_hw->qat_dev_get_extra_size();
}

static struct qat_pci_device *
qat_pci_get_named_dev(const char *name)
{
	unsigned int i;

	if (name == NULL)
		return NULL;

	for (i = 0; i < RTE_PMD_QAT_MAX_PCI_DEVICES; i++) {
		if (qat_pci_devs[i].mz &&
				(strcmp(((struct qat_pci_device *)
				qat_pci_devs[i].mz->addr)->name, name)
				== 0))
			return (struct qat_pci_device *)
				qat_pci_devs[i].mz->addr;
	}

	return NULL;
}

static uint8_t
qat_pci_find_free_device_index(void)
{
		uint8_t dev_id;

		for (dev_id = 0; dev_id < RTE_PMD_QAT_MAX_PCI_DEVICES;
				dev_id++) {
			if (qat_pci_devs[dev_id].mz == NULL)
				break;
		}
		return dev_id;
}

struct qat_pci_device *
qat_get_qat_dev_from_pci_dev(struct rte_pci_device *pci_dev)
{
	char name[QAT_DEV_NAME_MAX_LEN];

	rte_pci_device_name(&pci_dev->addr, name, sizeof(name));

	return qat_pci_get_named_dev(name);
}

static void
qat_dev_parse_cmd(const char *str, struct qat_dev_cmd_param
		*qat_dev_cmd_param)
{
	int i = 0;
	const char *param;

	while (1) {
		char value_str[4] = { };

		param = qat_dev_cmd_param[i].name;
		if (param == NULL)
			return;
		long value = 0;
		const char *arg = strstr(str, param);
		const char *arg2 = NULL;

		if (arg) {
			arg2 = arg + strlen(param);
			if (*arg2 != '=') {
				QAT_LOG(DEBUG, "parsing error '=' sign"
						" should immediately follow %s",
						param);
				arg2 = NULL;
			} else
				arg2++;
		} else {
			QAT_LOG(DEBUG, "%s not provided", param);
		}
		if (arg2) {
			int iter = 0;
			while (iter < 2) {
				if (!isdigit(*(arg2 + iter)))
					break;
				iter++;
			}
			if (!iter) {
				QAT_LOG(DEBUG, "parsing error %s"
					       " no number provided",
					       param);
			} else {
				memcpy(value_str, arg2, iter);
				value = strtol(value_str, NULL, 10);
				if (value > MAX_QP_THRESHOLD_SIZE) {
					QAT_LOG(DEBUG, "Exceeded max size of"
						" threshold, setting to %d",
						MAX_QP_THRESHOLD_SIZE);
					value = MAX_QP_THRESHOLD_SIZE;
				}
				QAT_LOG(DEBUG, "parsing %s = %ld",
						param, value);
			}
		}
		qat_dev_cmd_param[i].val = value;
		i++;
	}
}

struct qat_pci_device *
qat_pci_device_allocate(struct rte_pci_device *pci_dev,
		struct qat_dev_cmd_param *qat_dev_cmd_param)
{
	struct qat_pci_device *qat_dev;
	enum qat_device_gen qat_dev_gen;
	uint8_t qat_dev_id = 0;
	char name[QAT_DEV_NAME_MAX_LEN];
	struct rte_devargs *devargs = pci_dev->device.devargs;
	struct qat_dev_hw_spec_funcs *ops_hw;
	struct rte_mem_resource *mem_resource;
	const struct rte_memzone *qat_dev_mz;
	int qat_dev_size, extra_size;

	rte_pci_device_name(&pci_dev->addr, name, sizeof(name));
	snprintf(name+strlen(name), QAT_DEV_NAME_MAX_LEN-strlen(name), "_qat");

	switch (pci_dev->id.device_id) {
	case 0x0443:
		qat_dev_gen = QAT_GEN1;
		break;
	case 0x37c9:
	case 0x19e3:
	case 0x6f55:
	case 0x18ef:
		qat_dev_gen = QAT_GEN2;
		break;
	case 0x18a1:
		qat_dev_gen = QAT_GEN3;
		break;
	case 0x4941:
	case 0x4943:
		qat_dev_gen = QAT_GEN4;
		break;
	default:
		QAT_LOG(ERR, "Invalid dev_id, can't determine generation");
		return NULL;
	}

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		const struct rte_memzone *mz = rte_memzone_lookup(name);

		if (mz == NULL) {
			QAT_LOG(ERR,
				"Secondary can't find %s mz, did primary create device?",
				name);
			return NULL;
		}
		qat_dev = mz->addr;
		qat_pci_devs[qat_dev->qat_dev_id].mz = mz;
		qat_pci_devs[qat_dev->qat_dev_id].pci_dev = pci_dev;
		qat_nb_pci_devices++;
		QAT_LOG(DEBUG, "QAT device %d found, name %s, total QATs %d",
			qat_dev->qat_dev_id, qat_dev->name, qat_nb_pci_devices);
		return qat_dev;
	}

	if (qat_pci_get_named_dev(name) != NULL) {
		QAT_LOG(ERR, "QAT device with name %s already allocated!",
				name);
		return NULL;
	}

	qat_dev_id = qat_pci_find_free_device_index();
	if (qat_dev_id == RTE_PMD_QAT_MAX_PCI_DEVICES) {
		QAT_LOG(ERR, "Reached maximum number of QAT devices");
		return NULL;
	}

	extra_size = qat_pci_get_extra_size(qat_dev_gen);
	if (extra_size < 0) {
		QAT_LOG(ERR, "QAT internal error: no pci pointer for gen %d",
			qat_dev_gen);
		return NULL;
	}

	qat_dev_size = sizeof(struct qat_pci_device) + extra_size;
	qat_dev_mz = rte_memzone_reserve(name, qat_dev_size,
		rte_socket_id(), 0);

	if (qat_dev_mz == NULL) {
		QAT_LOG(ERR, "Error when allocating memzone for QAT_%d",
			qat_dev_id);
		return NULL;
	}

	qat_dev = qat_dev_mz->addr;
	memset(qat_dev, 0, qat_dev_size);
	qat_dev->dev_private = qat_dev + 1;
	strlcpy(qat_dev->name, name, QAT_DEV_NAME_MAX_LEN);
	qat_dev->qat_dev_id = qat_dev_id;
	qat_pci_devs[qat_dev_id].pci_dev = pci_dev;
	qat_dev->qat_dev_gen = qat_dev_gen;

	ops_hw = qat_dev_hw_spec[qat_dev->qat_dev_gen];
	if (ops_hw->qat_dev_get_misc_bar == NULL) {
		QAT_LOG(ERR, "qat_dev_get_misc_bar function pointer not set");
		rte_memzone_free(qat_dev_mz);
		return NULL;
	}
	if (ops_hw->qat_dev_get_misc_bar(&mem_resource, pci_dev) == 0) {
		if (mem_resource->addr == NULL) {
			QAT_LOG(ERR, "QAT cannot get access to VF misc bar");
			rte_memzone_free(qat_dev_mz);
			return NULL;
		}
		qat_dev->misc_bar_io_addr = mem_resource->addr;
	} else
		qat_dev->misc_bar_io_addr = NULL;

	if (devargs && devargs->drv_str)
		qat_dev_parse_cmd(devargs->drv_str, qat_dev_cmd_param);

	if (qat_read_qp_config(qat_dev)) {
		QAT_LOG(ERR,
			"Cannot acquire ring configuration for QAT_%d",
			qat_dev_id);
			rte_memzone_free(qat_dev_mz);
		return NULL;
	}

	/* No errors when allocating, attach memzone with
	 * qat_dev to list of devices
	 */
	qat_pci_devs[qat_dev_id].mz = qat_dev_mz;

	rte_spinlock_init(&qat_dev->arb_csr_lock);
	qat_nb_pci_devices++;

	QAT_LOG(DEBUG, "QAT device %d found, name %s, total QATs %d",
			qat_dev->qat_dev_id, qat_dev->name, qat_nb_pci_devices);

	return qat_dev;
}

static int
qat_pci_device_release(struct rte_pci_device *pci_dev)
{
	struct qat_pci_device *qat_dev;
	char name[QAT_DEV_NAME_MAX_LEN];
	int busy = 0;

	if (pci_dev == NULL)
		return -EINVAL;

	rte_pci_device_name(&pci_dev->addr, name, sizeof(name));
	snprintf(name+strlen(name), QAT_DEV_NAME_MAX_LEN-strlen(name), "_qat");
	qat_dev = qat_pci_get_named_dev(name);
	if (qat_dev != NULL) {

		struct qat_device_info *inst =
				&qat_pci_devs[qat_dev->qat_dev_id];
		/* Check that there are no service devs still on pci device */

		if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
			if (qat_dev->sym_dev != NULL) {
				QAT_LOG(DEBUG, "QAT sym device %s is busy",
					name);
				busy = 1;
			}
			if (qat_dev->asym_dev != NULL) {
				QAT_LOG(DEBUG, "QAT asym device %s is busy",
					name);
				busy = 1;
			}
			if (qat_dev->comp_dev != NULL) {
				QAT_LOG(DEBUG, "QAT comp device %s is busy",
					name);
				busy = 1;
			}
			if (busy)
				return -EBUSY;
			rte_memzone_free(inst->mz);
		}
		memset(inst, 0, sizeof(struct qat_device_info));
		qat_nb_pci_devices--;
		QAT_LOG(DEBUG, "QAT device %s released, total QATs %d",
					name, qat_nb_pci_devices);
	}
	return 0;
}

static int
qat_pci_dev_destroy(struct qat_pci_device *qat_pci_dev,
		struct rte_pci_device *pci_dev)
{
	qat_sym_dev_destroy(qat_pci_dev);
	qat_comp_dev_destroy(qat_pci_dev);
	qat_asym_dev_destroy(qat_pci_dev);
	return qat_pci_device_release(pci_dev);
}

static int qat_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		struct rte_pci_device *pci_dev)
{
	int sym_ret = 0, asym_ret = 0, comp_ret = 0;
	int num_pmds_created = 0;
	uint32_t capa = 0;
	struct qat_pci_device *qat_pci_dev;
	struct qat_dev_hw_spec_funcs *ops_hw;
	struct qat_dev_cmd_param qat_dev_cmd_param[] = {
			{ QAT_IPSEC_MB_LIB, 0 },
			{ SYM_ENQ_THRESHOLD_NAME, 0 },
			{ ASYM_ENQ_THRESHOLD_NAME, 0 },
			{ COMP_ENQ_THRESHOLD_NAME, 0 },
			[QAT_CMD_SLICE_MAP_POS] = { QAT_CMD_SLICE_MAP, 0},
			{ NULL, 0 },
	};

	QAT_LOG(DEBUG, "Found QAT device at %02x:%02x.%x",
			pci_dev->addr.bus,
			pci_dev->addr.devid,
			pci_dev->addr.function);

	qat_pci_dev = qat_pci_device_allocate(pci_dev, qat_dev_cmd_param);
	if (qat_pci_dev == NULL)
		return -ENODEV;

	ops_hw = qat_dev_hw_spec[qat_pci_dev->qat_dev_gen];
	if (ops_hw->qat_dev_reset_ring_pairs == NULL)
		return -ENOTSUP;
	if (ops_hw->qat_dev_reset_ring_pairs(qat_pci_dev)) {
		QAT_LOG(ERR,
			"Cannot reset ring pairs, does pf driver supports pf2vf comms?"
			);
		return -ENODEV;
	}

	if (ops_hw->qat_dev_get_slice_map(&capa, pci_dev) < 0) {
		RTE_LOG(ERR, EAL,
			"Cannot read slice configuration\n");
		return -1;
	}
	qat_dev_cmd_param[QAT_CMD_SLICE_MAP_POS].val = capa;

	sym_ret = qat_sym_dev_create(qat_pci_dev, qat_dev_cmd_param);
	if (sym_ret == 0) {
		num_pmds_created++;
	}
	else
		QAT_LOG(WARNING,
				"Failed to create QAT SYM PMD on device %s",
				qat_pci_dev->name);

	comp_ret = qat_comp_dev_create(qat_pci_dev, qat_dev_cmd_param);
	if (comp_ret == 0)
		num_pmds_created++;
	else
		QAT_LOG(WARNING,
				"Failed to create QAT COMP PMD on device %s",
				qat_pci_dev->name);

	asym_ret = qat_asym_dev_create(qat_pci_dev, qat_dev_cmd_param);
	if (asym_ret == 0)
		num_pmds_created++;
	else
		QAT_LOG(WARNING,
				"Failed to create QAT ASYM PMD on device %s",
				qat_pci_dev->name);

	if (num_pmds_created == 0)
		qat_pci_dev_destroy(qat_pci_dev, pci_dev);

	return 0;
}

static int
qat_pci_remove(struct rte_pci_device *pci_dev)
{
	struct qat_pci_device *qat_pci_dev;

	if (pci_dev == NULL)
		return -EINVAL;

	qat_pci_dev = qat_get_qat_dev_from_pci_dev(pci_dev);
	if (qat_pci_dev == NULL)
		return 0;

	return qat_pci_dev_destroy(qat_pci_dev, pci_dev);
}

static struct rte_pci_driver rte_qat_pmd = {
	.id_table = pci_id_qat_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = qat_pci_probe,
	.remove = qat_pci_remove
};

__rte_weak int
qat_sym_dev_create(struct qat_pci_device *qat_pci_dev __rte_unused,
		struct qat_dev_cmd_param *qat_dev_cmd_param __rte_unused)
{
	return 0;
}

__rte_weak int
qat_asym_dev_create(struct qat_pci_device *qat_pci_dev __rte_unused,
		const struct qat_dev_cmd_param *qat_dev_cmd_param __rte_unused)
{
	return 0;
}

__rte_weak int
qat_sym_dev_destroy(struct qat_pci_device *qat_pci_dev __rte_unused)
{
	return 0;
}

__rte_weak int
qat_asym_dev_destroy(struct qat_pci_device *qat_pci_dev __rte_unused)
{
	return 0;
}

__rte_weak int
qat_comp_dev_create(struct qat_pci_device *qat_pci_dev __rte_unused,
		struct qat_dev_cmd_param *qat_dev_cmd_param __rte_unused)
{
	return 0;
}

__rte_weak int
qat_comp_dev_destroy(struct qat_pci_device *qat_pci_dev __rte_unused)
{
	return 0;
}

RTE_PMD_REGISTER_PCI(QAT_PCI_NAME, rte_qat_pmd);
RTE_PMD_REGISTER_PCI_TABLE(QAT_PCI_NAME, pci_id_qat_map);
RTE_PMD_REGISTER_KMOD_DEP(QAT_PCI_NAME, "* igb_uio | uio_pci_generic | vfio-pci");
