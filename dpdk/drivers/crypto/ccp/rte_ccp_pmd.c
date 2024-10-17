/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2018 Advanced Micro Devices, Inc. All rights reserved.
 */

#include <rte_string_fns.h>
#include <bus_pci_driver.h>
#include <bus_vdev_driver.h>
#include <rte_common.h>
#include <rte_cryptodev.h>
#include <cryptodev_pmd.h>
#include <rte_pci.h>
#include <dev_driver.h>
#include <rte_malloc.h>

#include "ccp_crypto.h"
#include "ccp_dev.h"
#include "ccp_pmd_private.h"

/**
 * Global static parameter used to find if CCP device is already initialized.
 */
static unsigned int ccp_pmd_init_done;
uint8_t ccp_cryptodev_driver_id;
uint8_t cryptodev_cnt;

struct ccp_pmd_init_params {
	struct rte_cryptodev_pmd_init_params def_p;
	bool auth_opt;
};

#define CCP_CRYPTODEV_PARAM_NAME		("name")
#define CCP_CRYPTODEV_PARAM_SOCKET_ID		("socket_id")
#define CCP_CRYPTODEV_PARAM_MAX_NB_QP		("max_nb_queue_pairs")
#define CCP_CRYPTODEV_PARAM_AUTH_OPT		("ccp_auth_opt")

const char *ccp_pmd_valid_params[] = {
	CCP_CRYPTODEV_PARAM_NAME,
	CCP_CRYPTODEV_PARAM_SOCKET_ID,
	CCP_CRYPTODEV_PARAM_MAX_NB_QP,
	CCP_CRYPTODEV_PARAM_AUTH_OPT,
};

/** ccp pmd auth option */
enum ccp_pmd_auth_opt {
	CCP_PMD_AUTH_OPT_CCP = 0,
	CCP_PMD_AUTH_OPT_CPU,
};

static struct ccp_session *
get_ccp_session(struct ccp_qp *qp, struct rte_crypto_op *op)
{
	struct ccp_session *sess = NULL;

	if (op->sess_type == RTE_CRYPTO_OP_WITH_SESSION) {
		if (unlikely(op->sym->session == NULL))
			return NULL;

		sess = CRYPTODEV_GET_SYM_SESS_PRIV(op->sym->session);
	} else if (op->sess_type == RTE_CRYPTO_OP_SESSIONLESS) {
		struct rte_cryptodev_sym_session *_sess;
		struct ccp_private *internals;

		if (rte_mempool_get(qp->sess_mp, (void **)&_sess))
			return NULL;

		sess = (void *)_sess->driver_priv_data;

		internals = (struct ccp_private *)qp->dev->data->dev_private;
		if (unlikely(ccp_set_session_parameters(sess, op->sym->xform,
							internals) != 0)) {
			rte_mempool_put(qp->sess_mp, _sess);
			sess = NULL;
		}
		op->sym->session = _sess;
	}

	return sess;
}

static uint16_t
ccp_pmd_enqueue_burst(void *queue_pair, struct rte_crypto_op **ops,
		      uint16_t nb_ops)
{
	struct ccp_session *sess = NULL;
	struct ccp_qp *qp = queue_pair;
	struct ccp_queue *cmd_q;
	struct rte_cryptodev *dev = qp->dev;
	uint16_t i, enq_cnt = 0, slots_req = 0;
	uint16_t tmp_ops = nb_ops, b_idx, cur_ops = 0;

	if (nb_ops == 0)
		return 0;

	if (unlikely(rte_ring_full(qp->processed_pkts) != 0))
		return 0;
	if (tmp_ops >= cryptodev_cnt)
		cur_ops = nb_ops / cryptodev_cnt + (nb_ops)%cryptodev_cnt;
	else
		cur_ops = tmp_ops;
	while (tmp_ops)	{
		b_idx = nb_ops - tmp_ops;
		slots_req = 0;
		if (cur_ops <= tmp_ops) {
			tmp_ops -= cur_ops;
		} else {
			cur_ops = tmp_ops;
			tmp_ops = 0;
		}
		for (i = 0; i < cur_ops; i++) {
			sess = get_ccp_session(qp, ops[i + b_idx]);
			if (unlikely(sess == NULL) && (i == 0)) {
				qp->qp_stats.enqueue_err_count++;
				return 0;
			} else if (sess == NULL) {
				cur_ops = i;
				break;
			}
			slots_req += ccp_compute_slot_count(sess);
		}

		cmd_q = ccp_allot_queue(dev, slots_req);
		if (unlikely(cmd_q == NULL))
			return 0;
		enq_cnt += process_ops_to_enqueue(qp, ops, cmd_q, cur_ops,
				nb_ops, slots_req, b_idx);
		i++;
	}

	qp->qp_stats.enqueued_count += enq_cnt;
	return enq_cnt;
}

static uint16_t
ccp_pmd_dequeue_burst(void *queue_pair, struct rte_crypto_op **ops,
		uint16_t nb_ops)
{
	struct ccp_qp *qp = queue_pair;
	uint16_t nb_dequeued = 0, i, total_nb_ops;

	nb_dequeued = process_ops_to_dequeue(qp, ops, nb_ops, &total_nb_ops);

	if (total_nb_ops) {
		while (nb_dequeued != total_nb_ops) {
			nb_dequeued = process_ops_to_dequeue(qp,
					ops, nb_ops, &total_nb_ops);
		}
	}

	/* Free session if a session-less crypto op */
	for (i = 0; i < nb_dequeued; i++)
		if (unlikely(ops[i]->sess_type ==
			     RTE_CRYPTO_OP_SESSIONLESS)) {
			struct ccp_session *sess =
				CRYPTODEV_GET_SYM_SESS_PRIV(ops[i]->sym->session);

			memset(sess, 0, sizeof(*sess));
			rte_mempool_put(qp->sess_mp,
					ops[i]->sym->session);
			ops[i]->sym->session = NULL;
		}
	qp->qp_stats.dequeued_count += nb_dequeued;

	return nb_dequeued;
}

/*
 * The set of PCI devices this driver supports
 */
static struct rte_pci_id ccp_pci_id[] = {
	{ RTE_PCI_DEVICE(AMD_PCI_VENDOR_ID, AMD_PCI_CCP_5A), },
	{ RTE_PCI_DEVICE(AMD_PCI_VENDOR_ID, AMD_PCI_CCP_5B), },
	{ RTE_PCI_DEVICE(AMD_PCI_VENDOR_ID, AMD_PCI_CCP_RV), },
	{.device_id = 0},
};

/** Remove ccp pmd */
static int
cryptodev_ccp_remove(struct rte_pci_device *pci_dev)
{
	char name[RTE_CRYPTODEV_NAME_MAX_LEN];
	struct rte_cryptodev *dev;

	if (pci_dev == NULL)
		return -EINVAL;

	rte_pci_device_name(&pci_dev->addr, name, sizeof(name));

	if (name[0] == '\0')
		return -EINVAL;

	dev = rte_cryptodev_pmd_get_named_dev(name);
	if (dev == NULL)
		return -ENODEV;

	ccp_pmd_init_done = 0;

	RTE_LOG(INFO, PMD, "Closing ccp device %s on numa socket %u\n",
			name, rte_socket_id());

	return rte_cryptodev_pmd_destroy(dev);
}

/** Create crypto device */
static int
cryptodev_ccp_create(const char *name,
		     struct rte_pci_device *pci_dev,
		     struct ccp_pmd_init_params *init_params,
		     struct rte_pci_driver *pci_drv)
{
	struct rte_cryptodev *dev;
	struct ccp_private *internals;

	if (init_params->def_p.name[0] == '\0')
		strlcpy(init_params->def_p.name, name,
			sizeof(init_params->def_p.name));

	dev = rte_cryptodev_pmd_create(init_params->def_p.name,
				       &pci_dev->device,
				       &init_params->def_p);
	if (dev == NULL) {
		CCP_LOG_ERR("failed to create cryptodev vdev");
		goto init_error;
	}

	if (ccp_probe_device(pci_dev) != 0) {
		CCP_LOG_ERR("failed to detect CCP crypto device");
		goto init_error;
	}
	cryptodev_cnt++;

	CCP_LOG_DBG("CCP : Crypto device count = %d\n", cryptodev_cnt);
	dev->device = &pci_dev->device;
	dev->device->driver = &pci_drv->driver;
	dev->driver_id = ccp_cryptodev_driver_id;

	/* register rx/tx burst functions for data path */
	dev->dev_ops = ccp_pmd_ops;
	dev->enqueue_burst = ccp_pmd_enqueue_burst;
	dev->dequeue_burst = ccp_pmd_dequeue_burst;

	dev->feature_flags = RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO |
			RTE_CRYPTODEV_FF_HW_ACCELERATED |
			RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING |
			RTE_CRYPTODEV_FF_SYM_SESSIONLESS;

	internals = dev->data->dev_private;

	internals->max_nb_qpairs = init_params->def_p.max_nb_queue_pairs;
	internals->auth_opt = init_params->auth_opt;
	internals->crypto_num_dev = cryptodev_cnt;

	rte_cryptodev_pmd_probing_finish(dev);

	return 0;

init_error:
	CCP_LOG_ERR("driver %s: %s() failed",
		    init_params->def_p.name, __func__);
	cryptodev_ccp_remove(pci_dev);

	return -EFAULT;
}

/** Probe ccp pmd */
static int
cryptodev_ccp_probe(struct rte_pci_driver *pci_drv __rte_unused,
	struct rte_pci_device *pci_dev)
{
	int rc = 0;
	char name[RTE_CRYPTODEV_NAME_MAX_LEN];
	struct ccp_pmd_init_params init_params = {
		.def_p = {
			"",
			sizeof(struct ccp_private),
			rte_socket_id(),
			CCP_PMD_MAX_QUEUE_PAIRS
		},
		.auth_opt = CCP_PMD_AUTH_OPT_CCP,
	};

	if (ccp_pmd_init_done) {
		RTE_LOG(INFO, PMD, "CCP PMD already initialized\n");
		return -EFAULT;
	}
	rte_pci_device_name(&pci_dev->addr, name, sizeof(name));
	if (name[0] == '\0')
		return -EINVAL;

	init_params.def_p.max_nb_queue_pairs = CCP_PMD_MAX_QUEUE_PAIRS;

	RTE_LOG(INFO, PMD, "Initialising %s on NUMA node %d\n", name,
		init_params.def_p.socket_id);
	RTE_LOG(INFO, PMD, "Max number of queue pairs = %d\n",
		init_params.def_p.max_nb_queue_pairs);
	RTE_LOG(INFO, PMD, "Authentication offload to %s\n",
		((init_params.auth_opt == 0) ? "CCP" : "CPU"));

	rte_pci_device_name(&pci_dev->addr, name, sizeof(name));

	rc = cryptodev_ccp_create(name, pci_dev, &init_params, pci_drv);
	if (rc)
		return rc;
	ccp_pmd_init_done = 1;
	return 0;
}

static struct rte_pci_driver cryptodev_ccp_pmd_drv = {
	.id_table = ccp_pci_id,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = cryptodev_ccp_probe,
	.remove = cryptodev_ccp_remove
};

static struct cryptodev_driver ccp_crypto_drv;

RTE_PMD_REGISTER_PCI(CRYPTODEV_NAME_CCP_PMD, cryptodev_ccp_pmd_drv);
RTE_PMD_REGISTER_KMOD_DEP(CRYPTODEV_NAME_CCP_PMD, "* igb_uio | uio_pci_generic | vfio-pci");
RTE_PMD_REGISTER_PARAM_STRING(CRYPTODEV_NAME_CCP_PMD,
	"max_nb_queue_pairs=<int> "
	"socket_id=<int> "
	"ccp_auth_opt=<int>");
RTE_PMD_REGISTER_CRYPTO_DRIVER(ccp_crypto_drv, cryptodev_ccp_pmd_drv.driver,
			       ccp_cryptodev_driver_id);
