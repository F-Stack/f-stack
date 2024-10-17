/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Cavium, Inc
 */

#include <string.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <cryptodev_pmd.h>

#include "armv8_pmd_private.h"

static const struct rte_cryptodev_capabilities
	armv8_crypto_pmd_capabilities[] = {
	{	/* SHA1 HMAC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
			{.sym = {
				.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
				{.auth = {
					.algo = RTE_CRYPTO_AUTH_SHA1_HMAC,
					.block_size = 64,
					.key_size = {
						.min = 1,
						.max = 64,
						.increment = 1
					},
					.digest_size = {
						.min = 1,
						.max = 20,
						.increment = 1
					},
					.iv_size = { 0 }
				}, }
			}, }
	},
	{	/* SHA256 HMAC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
			{.sym = {
				.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
				{.auth = {
					.algo = RTE_CRYPTO_AUTH_SHA256_HMAC,
					.block_size = 64,
					.key_size = {
						.min = 1,
						.max = 64,
						.increment = 1
					},
					.digest_size = {
						.min = 1,
						.max = 32,
						.increment = 1
					},
					.iv_size = { 0 }
				}, }
			}, }
	},
	{	/* AES CBC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
			{.sym = {
				.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
				{.cipher = {
					.algo = RTE_CRYPTO_CIPHER_AES_CBC,
					.block_size = 16,
					.key_size = {
						.min = 16,
						.max = 16,
						.increment = 0
					},
					.iv_size = {
						.min = 16,
						.max = 16,
						.increment = 0
					}
				}, }
			}, }
	},

	RTE_CRYPTODEV_END_OF_CAPABILITIES_LIST()
};


/** Configure device */
static int
armv8_crypto_pmd_config(__rte_unused struct rte_cryptodev *dev,
		__rte_unused struct rte_cryptodev_config *config)
{
	return 0;
}

/** Start device */
static int
armv8_crypto_pmd_start(__rte_unused struct rte_cryptodev *dev)
{
	return 0;
}

/** Stop device */
static void
armv8_crypto_pmd_stop(__rte_unused struct rte_cryptodev *dev)
{
}

/** Close device */
static int
armv8_crypto_pmd_close(__rte_unused struct rte_cryptodev *dev)
{
	return 0;
}


/** Get device statistics */
static void
armv8_crypto_pmd_stats_get(struct rte_cryptodev *dev,
		struct rte_cryptodev_stats *stats)
{
	int qp_id;

	for (qp_id = 0; qp_id < dev->data->nb_queue_pairs; qp_id++) {
		struct armv8_crypto_qp *qp = dev->data->queue_pairs[qp_id];

		stats->enqueued_count += qp->stats.enqueued_count;
		stats->dequeued_count += qp->stats.dequeued_count;

		stats->enqueue_err_count += qp->stats.enqueue_err_count;
		stats->dequeue_err_count += qp->stats.dequeue_err_count;
	}
}

/** Reset device statistics */
static void
armv8_crypto_pmd_stats_reset(struct rte_cryptodev *dev)
{
	int qp_id;

	for (qp_id = 0; qp_id < dev->data->nb_queue_pairs; qp_id++) {
		struct armv8_crypto_qp *qp = dev->data->queue_pairs[qp_id];

		memset(&qp->stats, 0, sizeof(qp->stats));
	}
}


/** Get device info */
static void
armv8_crypto_pmd_info_get(struct rte_cryptodev *dev,
		struct rte_cryptodev_info *dev_info)
{
	struct armv8_crypto_private *internals = dev->data->dev_private;

	if (dev_info != NULL) {
		dev_info->driver_id = dev->driver_id;
		dev_info->feature_flags = dev->feature_flags;
		dev_info->capabilities = armv8_crypto_pmd_capabilities;
		dev_info->max_nb_queue_pairs = internals->max_nb_qpairs;
		/* No limit of number of sessions */
		dev_info->sym.max_nb_sessions = 0;
	}
}

/** Release queue pair */
static int
armv8_crypto_pmd_qp_release(struct rte_cryptodev *dev, uint16_t qp_id)
{

	if (dev->data->queue_pairs[qp_id] != NULL) {
		rte_free(dev->data->queue_pairs[qp_id]);
		dev->data->queue_pairs[qp_id] = NULL;
	}

	return 0;
}

/** set a unique name for the queue pair based on it's name, dev_id and qp_id */
static int
armv8_crypto_pmd_qp_set_unique_name(struct rte_cryptodev *dev,
		struct armv8_crypto_qp *qp)
{
	unsigned int n;

	n = snprintf(qp->name, sizeof(qp->name), "armv8_crypto_pmd_%u_qp_%u",
			dev->data->dev_id, qp->id);

	if (n >= sizeof(qp->name))
		return -1;

	return 0;
}


/** Create a ring to place processed operations on */
static struct rte_ring *
armv8_crypto_pmd_qp_create_processed_ops_ring(struct armv8_crypto_qp *qp,
		unsigned int ring_size, int socket_id)
{
	struct rte_ring *r;

	r = rte_ring_lookup(qp->name);
	if (r) {
		if (rte_ring_get_size(r) >= ring_size) {
			ARMV8_CRYPTO_LOG_INFO(
				"Reusing existing ring %s for processed ops",
				 qp->name);
			return r;
		}

		ARMV8_CRYPTO_LOG_ERR(
			"Unable to reuse existing ring %s for processed ops",
			 qp->name);
		return NULL;
	}

	return rte_ring_create(qp->name, ring_size, socket_id,
			RING_F_SP_ENQ | RING_F_SC_DEQ);
}


/** Setup a queue pair */
static int
armv8_crypto_pmd_qp_setup(struct rte_cryptodev *dev, uint16_t qp_id,
		const struct rte_cryptodev_qp_conf *qp_conf,
		int socket_id)
{
	struct armv8_crypto_qp *qp = NULL;

	/* Free memory prior to re-allocation if needed. */
	if (dev->data->queue_pairs[qp_id] != NULL)
		armv8_crypto_pmd_qp_release(dev, qp_id);

	/* Allocate the queue pair data structure. */
	qp = rte_zmalloc_socket("ARMv8 PMD Queue Pair", sizeof(*qp),
					RTE_CACHE_LINE_SIZE, socket_id);
	if (qp == NULL)
		return -ENOMEM;

	qp->id = qp_id;
	dev->data->queue_pairs[qp_id] = qp;

	if (armv8_crypto_pmd_qp_set_unique_name(dev, qp) != 0)
		goto qp_setup_cleanup;

	qp->processed_ops = armv8_crypto_pmd_qp_create_processed_ops_ring(qp,
			qp_conf->nb_descriptors, socket_id);
	if (qp->processed_ops == NULL)
		goto qp_setup_cleanup;

	qp->sess_mp = qp_conf->mp_session;

	memset(&qp->stats, 0, sizeof(qp->stats));

	return 0;

qp_setup_cleanup:
	rte_free(qp);

	return -1;
}

/** Returns the size of the session structure */
static unsigned
armv8_crypto_pmd_sym_session_get_size(struct rte_cryptodev *dev __rte_unused)
{
	return sizeof(struct armv8_crypto_session);
}

/** Configure the session from a crypto xform chain */
static int
armv8_crypto_pmd_sym_session_configure(struct rte_cryptodev *dev __rte_unused,
		struct rte_crypto_sym_xform *xform,
		struct rte_cryptodev_sym_session *sess)
{
	void *sess_private_data;
	int ret;

	if (unlikely(sess == NULL)) {
		ARMV8_CRYPTO_LOG_ERR("invalid session struct");
		return -EINVAL;
	}

	sess_private_data = sess->driver_priv_data;

	ret = armv8_crypto_set_session_parameters(sess_private_data, xform);
	if (ret != 0) {
		ARMV8_CRYPTO_LOG_ERR("failed configure session parameters");
		return ret;
	}

	return 0;
}

/** Clear the memory of session so it doesn't leave key material behind */
static void
armv8_crypto_pmd_sym_session_clear(struct rte_cryptodev *dev __rte_unused,
		struct rte_cryptodev_sym_session *sess __rte_unused)
{}

struct rte_cryptodev_ops armv8_crypto_pmd_ops = {
		.dev_configure		= armv8_crypto_pmd_config,
		.dev_start		= armv8_crypto_pmd_start,
		.dev_stop		= armv8_crypto_pmd_stop,
		.dev_close		= armv8_crypto_pmd_close,

		.stats_get		= armv8_crypto_pmd_stats_get,
		.stats_reset		= armv8_crypto_pmd_stats_reset,

		.dev_infos_get		= armv8_crypto_pmd_info_get,

		.queue_pair_setup	= armv8_crypto_pmd_qp_setup,
		.queue_pair_release	= armv8_crypto_pmd_qp_release,

		.sym_session_get_size	= armv8_crypto_pmd_sym_session_get_size,
		.sym_session_configure	= armv8_crypto_pmd_sym_session_configure,
		.sym_session_clear	= armv8_crypto_pmd_sym_session_clear
};

struct rte_cryptodev_ops *rte_armv8_crypto_pmd_ops = &armv8_crypto_pmd_ops;
