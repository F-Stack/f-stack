/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Cavium, Inc
 */

#include <rte_alarm.h>
#include <rte_bus_pci.h>
#include <rte_cryptodev.h>
#include <rte_cryptodev_pmd.h>
#include <rte_malloc.h>

#include "cpt_pmd_logs.h"
#include "cpt_pmd_ops_helper.h"
#include "cpt_ucode.h"
#include "cpt_request_mgr.h"

#include "otx_cryptodev.h"
#include "otx_cryptodev_capabilities.h"
#include "otx_cryptodev_hw_access.h"
#include "otx_cryptodev_ops.h"

static int otx_cryptodev_probe_count;
static rte_spinlock_t otx_probe_count_lock = RTE_SPINLOCK_INITIALIZER;

static struct rte_mempool *otx_cpt_meta_pool;
static int otx_cpt_op_mlen;
static int otx_cpt_op_sb_mlen;

/* Forward declarations */

static int
otx_cpt_que_pair_release(struct rte_cryptodev *dev, uint16_t que_pair_id);

/*
 * Initializes global variables used by fast-path code
 *
 * @return
 *   - 0 on success, errcode on error
 */
static int
init_global_resources(void)
{
	/* Get meta len for scatter gather mode */
	otx_cpt_op_mlen = cpt_pmd_ops_helper_get_mlen_sg_mode();

	/* Extra 4B saved for future considerations */
	otx_cpt_op_mlen += 4 * sizeof(uint64_t);

	otx_cpt_meta_pool = rte_mempool_create("cpt_metabuf-pool", 4096 * 16,
					       otx_cpt_op_mlen, 512, 0,
					       NULL, NULL, NULL, NULL,
					       SOCKET_ID_ANY, 0);
	if (!otx_cpt_meta_pool) {
		CPT_LOG_ERR("cpt metabuf pool not created");
		return -ENOMEM;
	}

	/* Get meta len for direct mode */
	otx_cpt_op_sb_mlen = cpt_pmd_ops_helper_get_mlen_direct_mode();

	/* Extra 4B saved for future considerations */
	otx_cpt_op_sb_mlen += 4 * sizeof(uint64_t);

	return 0;
}

void
cleanup_global_resources(void)
{
	/* Take lock */
	rte_spinlock_lock(&otx_probe_count_lock);

	/* Decrement the cryptodev count */
	otx_cryptodev_probe_count--;

	/* Free buffers */
	if (otx_cpt_meta_pool && otx_cryptodev_probe_count == 0)
		rte_mempool_free(otx_cpt_meta_pool);

	/* Free lock */
	rte_spinlock_unlock(&otx_probe_count_lock);
}

/* Alarm routines */

static void
otx_cpt_alarm_cb(void *arg)
{
	struct cpt_vf *cptvf = arg;
	otx_cpt_poll_misc(cptvf);
	rte_eal_alarm_set(CPT_INTR_POLL_INTERVAL_MS * 1000,
			  otx_cpt_alarm_cb, cptvf);
}

static int
otx_cpt_periodic_alarm_start(void *arg)
{
	return rte_eal_alarm_set(CPT_INTR_POLL_INTERVAL_MS * 1000,
				 otx_cpt_alarm_cb, arg);
}

static int
otx_cpt_periodic_alarm_stop(void *arg)
{
	return rte_eal_alarm_cancel(otx_cpt_alarm_cb, arg);
}

/* PMD ops */

static int
otx_cpt_dev_config(struct rte_cryptodev *dev __rte_unused,
		   struct rte_cryptodev_config *config __rte_unused)
{
	CPT_PMD_INIT_FUNC_TRACE();
	return 0;
}

static int
otx_cpt_dev_start(struct rte_cryptodev *c_dev)
{
	void *cptvf = c_dev->data->dev_private;

	CPT_PMD_INIT_FUNC_TRACE();

	return otx_cpt_start_device(cptvf);
}

static void
otx_cpt_dev_stop(struct rte_cryptodev *c_dev)
{
	void *cptvf = c_dev->data->dev_private;

	CPT_PMD_INIT_FUNC_TRACE();

	otx_cpt_stop_device(cptvf);
}

static int
otx_cpt_dev_close(struct rte_cryptodev *c_dev)
{
	void *cptvf = c_dev->data->dev_private;
	int i, ret;

	CPT_PMD_INIT_FUNC_TRACE();

	for (i = 0; i < c_dev->data->nb_queue_pairs; i++) {
		ret = otx_cpt_que_pair_release(c_dev, i);
		if (ret)
			return ret;
	}

	otx_cpt_periodic_alarm_stop(cptvf);
	otx_cpt_deinit_device(cptvf);

	return 0;
}

static void
otx_cpt_dev_info_get(struct rte_cryptodev *dev, struct rte_cryptodev_info *info)
{
	CPT_PMD_INIT_FUNC_TRACE();
	if (info != NULL) {
		info->max_nb_queue_pairs = CPT_NUM_QS_PER_VF;
		info->feature_flags = dev->feature_flags;
		info->capabilities = otx_get_capabilities();
		info->sym.max_nb_sessions = 0;
		info->driver_id = otx_cryptodev_driver_id;
		info->min_mbuf_headroom_req = OTX_CPT_MIN_HEADROOM_REQ;
		info->min_mbuf_tailroom_req = OTX_CPT_MIN_TAILROOM_REQ;
	}
}

static void
otx_cpt_stats_get(struct rte_cryptodev *dev __rte_unused,
		  struct rte_cryptodev_stats *stats __rte_unused)
{
	CPT_PMD_INIT_FUNC_TRACE();
}

static void
otx_cpt_stats_reset(struct rte_cryptodev *dev __rte_unused)
{
	CPT_PMD_INIT_FUNC_TRACE();
}

static int
otx_cpt_que_pair_setup(struct rte_cryptodev *dev,
		       uint16_t que_pair_id,
		       const struct rte_cryptodev_qp_conf *qp_conf,
		       int socket_id __rte_unused,
		       struct rte_mempool *session_pool __rte_unused)
{
	void *cptvf = dev->data->dev_private;
	struct cpt_instance *instance = NULL;
	struct rte_pci_device *pci_dev;
	int ret = -1;

	CPT_PMD_INIT_FUNC_TRACE();

	if (dev->data->queue_pairs[que_pair_id] != NULL) {
		ret = otx_cpt_que_pair_release(dev, que_pair_id);
		if (ret)
			return ret;
	}

	if (qp_conf->nb_descriptors > DEFAULT_CMD_QLEN) {
		CPT_LOG_INFO("Number of descriptors too big %d, using default "
			     "queue length of %d", qp_conf->nb_descriptors,
			     DEFAULT_CMD_QLEN);
	}

	pci_dev = RTE_DEV_TO_PCI(dev->device);

	if (pci_dev->mem_resource[0].addr == NULL) {
		CPT_LOG_ERR("PCI mem address null");
		return -EIO;
	}

	ret = otx_cpt_get_resource(cptvf, 0, &instance);
	if (ret != 0 || instance == NULL) {
		CPT_LOG_ERR("Error getting instance handle from device %s : "
			    "ret = %d", dev->data->name, ret);
		return ret;
	}

	instance->queue_id = que_pair_id;
	dev->data->queue_pairs[que_pair_id] = instance;

	return 0;
}

static int
otx_cpt_que_pair_release(struct rte_cryptodev *dev, uint16_t que_pair_id)
{
	struct cpt_instance *instance = dev->data->queue_pairs[que_pair_id];
	int ret;

	CPT_PMD_INIT_FUNC_TRACE();

	ret = otx_cpt_put_resource(instance);
	if (ret != 0) {
		CPT_LOG_ERR("Error putting instance handle of device %s : "
			    "ret = %d", dev->data->name, ret);
		return ret;
	}

	dev->data->queue_pairs[que_pair_id] = NULL;

	return 0;
}

static unsigned int
otx_cpt_get_session_size(struct rte_cryptodev *dev __rte_unused)
{
	return cpt_get_session_size();
}

static void
otx_cpt_session_init(void *sym_sess, uint8_t driver_id)
{
	struct rte_cryptodev_sym_session *sess = sym_sess;
	struct cpt_sess_misc *cpt_sess =
	 (struct cpt_sess_misc *) get_sym_session_private_data(sess, driver_id);

	CPT_PMD_INIT_FUNC_TRACE();
	cpt_sess->ctx_dma_addr = rte_mempool_virt2iova(cpt_sess) +
			sizeof(struct cpt_sess_misc);
}

static int
otx_cpt_session_cfg(struct rte_cryptodev *dev,
		    struct rte_crypto_sym_xform *xform,
		    struct rte_cryptodev_sym_session *sess,
		    struct rte_mempool *mempool)
{
	struct rte_crypto_sym_xform *chain;
	void *sess_private_data = NULL;

	CPT_PMD_INIT_FUNC_TRACE();

	if (cpt_is_algo_supported(xform))
		goto err;

	if (unlikely(sess == NULL)) {
		CPT_LOG_ERR("invalid session struct");
		return -EINVAL;
	}

	if (rte_mempool_get(mempool, &sess_private_data)) {
		CPT_LOG_ERR("Could not allocate sess_private_data");
		return -ENOMEM;
	}

	chain = xform;
	while (chain) {
		switch (chain->type) {
		case RTE_CRYPTO_SYM_XFORM_AEAD:
			if (fill_sess_aead(chain, sess_private_data))
				goto err;
			break;
		case RTE_CRYPTO_SYM_XFORM_CIPHER:
			if (fill_sess_cipher(chain, sess_private_data))
				goto err;
			break;
		case RTE_CRYPTO_SYM_XFORM_AUTH:
			if (chain->auth.algo == RTE_CRYPTO_AUTH_AES_GMAC) {
				if (fill_sess_gmac(chain, sess_private_data))
					goto err;
			} else {
				if (fill_sess_auth(chain, sess_private_data))
					goto err;
			}
			break;
		default:
			CPT_LOG_ERR("Invalid crypto xform type");
			break;
		}
		chain = chain->next;
	}
	set_sym_session_private_data(sess, dev->driver_id, sess_private_data);
	otx_cpt_session_init(sess, dev->driver_id);
	return 0;

err:
	if (sess_private_data)
		rte_mempool_put(mempool, sess_private_data);
	return -EPERM;
}

static void
otx_cpt_session_clear(struct rte_cryptodev *dev,
		  struct rte_cryptodev_sym_session *sess)
{
	void *sess_priv = get_sym_session_private_data(sess, dev->driver_id);

	CPT_PMD_INIT_FUNC_TRACE();
	if (sess_priv) {
		memset(sess_priv, 0, otx_cpt_get_session_size(dev));
		struct rte_mempool *sess_mp = rte_mempool_from_obj(sess_priv);
		set_sym_session_private_data(sess, dev->driver_id, NULL);
		rte_mempool_put(sess_mp, sess_priv);
	}
}

static uint16_t
otx_cpt_pkt_enqueue(void *qptr, struct rte_crypto_op **ops, uint16_t nb_ops)
{
	struct cpt_instance *instance = (struct cpt_instance *)qptr;
	uint16_t count = 0;
	int ret;
	struct cpt_vf *cptvf = (struct cpt_vf *)instance;
	struct pending_queue *pqueue = &cptvf->pqueue;

	count = DEFAULT_CMD_QLEN - pqueue->pending_count;
	if (nb_ops > count)
		nb_ops = count;

	count = 0;
	while (likely(count < nb_ops)) {
		ret = cpt_pmd_crypto_operation(instance, ops[count], pqueue,
						otx_cryptodev_driver_id);
		if (unlikely(ret))
			break;
		count++;
	}
	otx_cpt_ring_dbell(instance, count);
	return count;
}

static uint16_t
otx_cpt_pkt_dequeue(void *qptr, struct rte_crypto_op **ops, uint16_t nb_ops)
{
	struct cpt_instance *instance = (struct cpt_instance *)qptr;
	struct cpt_vf *cptvf = (struct cpt_vf *)instance;
	struct pending_queue *pqueue = &cptvf->pqueue;
	uint16_t nb_completed, i = 0;
	uint8_t compcode[nb_ops];

	nb_completed = cpt_dequeue_burst(instance, nb_ops,
					 (void **)ops, compcode, pqueue);
	while (likely(i < nb_completed)) {
		struct rte_crypto_op *cop;
		void *metabuf;
		uintptr_t *rsp;
		uint8_t status;

		rsp = (void *)ops[i];
		status = compcode[i];
		if (likely((i + 1) < nb_completed))
			rte_prefetch0(ops[i+1]);
		metabuf = (void *)rsp[0];
		cop = (void *)rsp[1];

		ops[i] = cop;

		if (likely(status == 0)) {
			if (likely(!rsp[2]))
				cop->status =
					RTE_CRYPTO_OP_STATUS_SUCCESS;
			else
				compl_auth_verify(cop, (uint8_t *)rsp[2],
						  rsp[3]);
		} else if (status == ERR_GC_ICV_MISCOMPARE) {
			/*auth data mismatch */
			cop->status = RTE_CRYPTO_OP_STATUS_AUTH_FAILED;
		} else {
			cop->status = RTE_CRYPTO_OP_STATUS_ERROR;
		}
		free_op_meta(metabuf, cptvf->meta_info.cptvf_meta_pool);
		i++;
	}
	return nb_completed;
}

static struct rte_cryptodev_ops cptvf_ops = {
	/* Device related operations */
	.dev_configure = otx_cpt_dev_config,
	.dev_start = otx_cpt_dev_start,
	.dev_stop = otx_cpt_dev_stop,
	.dev_close = otx_cpt_dev_close,
	.dev_infos_get = otx_cpt_dev_info_get,

	.stats_get = otx_cpt_stats_get,
	.stats_reset = otx_cpt_stats_reset,
	.queue_pair_setup = otx_cpt_que_pair_setup,
	.queue_pair_release = otx_cpt_que_pair_release,
	.queue_pair_count = NULL,

	/* Crypto related operations */
	.sym_session_get_size = otx_cpt_get_session_size,
	.sym_session_configure = otx_cpt_session_cfg,
	.sym_session_clear = otx_cpt_session_clear
};

static void
otx_cpt_common_vars_init(struct cpt_vf *cptvf)
{
	cptvf->meta_info.cptvf_meta_pool = otx_cpt_meta_pool;
	cptvf->meta_info.cptvf_op_mlen = otx_cpt_op_mlen;
	cptvf->meta_info.cptvf_op_sb_mlen = otx_cpt_op_sb_mlen;
}

int
otx_cpt_dev_create(struct rte_cryptodev *c_dev)
{
	struct rte_pci_device *pdev = RTE_DEV_TO_PCI(c_dev->device);
	struct cpt_vf *cptvf = NULL;
	void *reg_base;
	char dev_name[32];
	int ret;

	if (pdev->mem_resource[0].phys_addr == 0ULL)
		return -EIO;

	/* for secondary processes, we don't initialise any further as primary
	 * has already done this work.
	 */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	cptvf = rte_zmalloc_socket("otx_cryptodev_private_mem",
			sizeof(struct cpt_vf), RTE_CACHE_LINE_SIZE,
			rte_socket_id());

	if (cptvf == NULL) {
		CPT_LOG_ERR("Cannot allocate memory for device private data");
		return -ENOMEM;
	}

	snprintf(dev_name, 32, "%02x:%02x.%x",
			pdev->addr.bus, pdev->addr.devid, pdev->addr.function);

	reg_base = pdev->mem_resource[0].addr;
	if (!reg_base) {
		CPT_LOG_ERR("Failed to map BAR0 of %s", dev_name);
		ret = -ENODEV;
		goto fail;
	}

	ret = otx_cpt_hw_init(cptvf, pdev, reg_base, dev_name);
	if (ret) {
		CPT_LOG_ERR("Failed to init cptvf %s", dev_name);
		ret = -EIO;
		goto fail;
	}

	/* Start off timer for mailbox interrupts */
	otx_cpt_periodic_alarm_start(cptvf);

	rte_spinlock_lock(&otx_probe_count_lock);
	if (!otx_cryptodev_probe_count) {
		ret = init_global_resources();
		if (ret) {
			rte_spinlock_unlock(&otx_probe_count_lock);
			goto init_fail;
		}
	}
	otx_cryptodev_probe_count++;
	rte_spinlock_unlock(&otx_probe_count_lock);

	/* Initialize data path variables used by common code */
	otx_cpt_common_vars_init(cptvf);

	c_dev->dev_ops = &cptvf_ops;

	c_dev->enqueue_burst = otx_cpt_pkt_enqueue;
	c_dev->dequeue_burst = otx_cpt_pkt_dequeue;

	c_dev->feature_flags = RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO |
			RTE_CRYPTODEV_FF_HW_ACCELERATED |
			RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING |
			RTE_CRYPTODEV_FF_IN_PLACE_SGL |
			RTE_CRYPTODEV_FF_OOP_SGL_IN_LB_OUT |
			RTE_CRYPTODEV_FF_OOP_SGL_IN_SGL_OUT;

	/* Save dev private data */
	c_dev->data->dev_private = cptvf;

	return 0;

init_fail:
	otx_cpt_periodic_alarm_stop(cptvf);
	otx_cpt_deinit_device(cptvf);

fail:
	if (cptvf) {
		/* Free private data allocated */
		rte_free(cptvf);
	}

	return ret;
}
