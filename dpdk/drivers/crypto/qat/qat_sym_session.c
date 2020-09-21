/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright(c) 2015-2018 Intel Corporation
 */

#include <openssl/sha.h>	/* Needed to calculate pre-compute values */
#include <openssl/aes.h>	/* Needed to calculate pre-compute values */
#include <openssl/md5.h>	/* Needed to calculate pre-compute values */
#include <openssl/evp.h>	/* Needed for bpi runt block processing */

#include <rte_memcpy.h>
#include <rte_common.h>
#include <rte_spinlock.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_crypto_sym.h>

#include "qat_logs.h"
#include "qat_sym_session.h"
#include "qat_sym_pmd.h"

/** Frees a context previously created
 *  Depends on openssl libcrypto
 */
static void
bpi_cipher_ctx_free(void *bpi_ctx)
{
	if (bpi_ctx != NULL)
		EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)bpi_ctx);
}

/** Creates a context in either AES or DES in ECB mode
 *  Depends on openssl libcrypto
 */
static int
bpi_cipher_ctx_init(enum rte_crypto_cipher_algorithm cryptodev_algo,
		enum rte_crypto_cipher_operation direction __rte_unused,
		uint8_t *key, void **ctx)
{
	const EVP_CIPHER *algo = NULL;
	int ret;
	*ctx = EVP_CIPHER_CTX_new();

	if (*ctx == NULL) {
		ret = -ENOMEM;
		goto ctx_init_err;
	}

	if (cryptodev_algo == RTE_CRYPTO_CIPHER_DES_DOCSISBPI)
		algo = EVP_des_ecb();
	else
		algo = EVP_aes_128_ecb();

	/* IV will be ECB encrypted whether direction is encrypt or decrypt*/
	if (EVP_EncryptInit_ex(*ctx, algo, NULL, key, 0) != 1) {
		ret = -EINVAL;
		goto ctx_init_err;
	}

	return 0;

ctx_init_err:
	if (*ctx != NULL)
		EVP_CIPHER_CTX_free(*ctx);
	return ret;
}

static int
qat_is_cipher_alg_supported(enum rte_crypto_cipher_algorithm algo,
		struct qat_sym_dev_private *internals)
{
	int i = 0;
	const struct rte_cryptodev_capabilities *capability;

	while ((capability = &(internals->qat_dev_capabilities[i++]))->op !=
			RTE_CRYPTO_OP_TYPE_UNDEFINED) {
		if (capability->op != RTE_CRYPTO_OP_TYPE_SYMMETRIC)
			continue;

		if (capability->sym.xform_type != RTE_CRYPTO_SYM_XFORM_CIPHER)
			continue;

		if (capability->sym.cipher.algo == algo)
			return 1;
	}
	return 0;
}

static int
qat_is_auth_alg_supported(enum rte_crypto_auth_algorithm algo,
		struct qat_sym_dev_private *internals)
{
	int i = 0;
	const struct rte_cryptodev_capabilities *capability;

	while ((capability = &(internals->qat_dev_capabilities[i++]))->op !=
			RTE_CRYPTO_OP_TYPE_UNDEFINED) {
		if (capability->op != RTE_CRYPTO_OP_TYPE_SYMMETRIC)
			continue;

		if (capability->sym.xform_type != RTE_CRYPTO_SYM_XFORM_AUTH)
			continue;

		if (capability->sym.auth.algo == algo)
			return 1;
	}
	return 0;
}

void
qat_sym_session_clear(struct rte_cryptodev *dev,
		struct rte_cryptodev_sym_session *sess)
{
	uint8_t index = dev->driver_id;
	void *sess_priv = get_sym_session_private_data(sess, index);
	struct qat_sym_session *s = (struct qat_sym_session *)sess_priv;

	if (sess_priv) {
		if (s->bpi_ctx)
			bpi_cipher_ctx_free(s->bpi_ctx);
		memset(s, 0, qat_sym_session_get_private_size(dev));
		struct rte_mempool *sess_mp = rte_mempool_from_obj(sess_priv);

		set_sym_session_private_data(sess, index, NULL);
		rte_mempool_put(sess_mp, sess_priv);
	}
}

static int
qat_get_cmd_id(const struct rte_crypto_sym_xform *xform)
{
	/* Cipher Only */
	if (xform->type == RTE_CRYPTO_SYM_XFORM_CIPHER && xform->next == NULL)
		return ICP_QAT_FW_LA_CMD_CIPHER;

	/* Authentication Only */
	if (xform->type == RTE_CRYPTO_SYM_XFORM_AUTH && xform->next == NULL)
		return ICP_QAT_FW_LA_CMD_AUTH;

	/* AEAD */
	if (xform->type == RTE_CRYPTO_SYM_XFORM_AEAD) {
		/* AES-GCM and AES-CCM works with different direction
		 * GCM first encrypts and generate hash where AES-CCM
		 * first generate hash and encrypts. Similar relation
		 * applies to decryption.
		 */
		if (xform->aead.op == RTE_CRYPTO_AEAD_OP_ENCRYPT)
			if (xform->aead.algo == RTE_CRYPTO_AEAD_AES_GCM)
				return ICP_QAT_FW_LA_CMD_CIPHER_HASH;
			else
				return ICP_QAT_FW_LA_CMD_HASH_CIPHER;
		else
			if (xform->aead.algo == RTE_CRYPTO_AEAD_AES_GCM)
				return ICP_QAT_FW_LA_CMD_HASH_CIPHER;
			else
				return ICP_QAT_FW_LA_CMD_CIPHER_HASH;
	}

	if (xform->next == NULL)
		return -1;

	/* Cipher then Authenticate */
	if (xform->type == RTE_CRYPTO_SYM_XFORM_CIPHER &&
			xform->next->type == RTE_CRYPTO_SYM_XFORM_AUTH)
		return ICP_QAT_FW_LA_CMD_CIPHER_HASH;

	/* Authenticate then Cipher */
	if (xform->type == RTE_CRYPTO_SYM_XFORM_AUTH &&
			xform->next->type == RTE_CRYPTO_SYM_XFORM_CIPHER)
		return ICP_QAT_FW_LA_CMD_HASH_CIPHER;

	return -1;
}

static struct rte_crypto_auth_xform *
qat_get_auth_xform(struct rte_crypto_sym_xform *xform)
{
	do {
		if (xform->type == RTE_CRYPTO_SYM_XFORM_AUTH)
			return &xform->auth;

		xform = xform->next;
	} while (xform);

	return NULL;
}

static struct rte_crypto_cipher_xform *
qat_get_cipher_xform(struct rte_crypto_sym_xform *xform)
{
	do {
		if (xform->type == RTE_CRYPTO_SYM_XFORM_CIPHER)
			return &xform->cipher;

		xform = xform->next;
	} while (xform);

	return NULL;
}

int
qat_sym_session_configure_cipher(struct rte_cryptodev *dev,
		struct rte_crypto_sym_xform *xform,
		struct qat_sym_session *session)
{
	struct qat_sym_dev_private *internals = dev->data->dev_private;
	struct rte_crypto_cipher_xform *cipher_xform = NULL;
	int ret;

	/* Get cipher xform from crypto xform chain */
	cipher_xform = qat_get_cipher_xform(xform);

	session->cipher_iv.offset = cipher_xform->iv.offset;
	session->cipher_iv.length = cipher_xform->iv.length;

	switch (cipher_xform->algo) {
	case RTE_CRYPTO_CIPHER_AES_CBC:
		if (qat_sym_validate_aes_key(cipher_xform->key.length,
				&session->qat_cipher_alg) != 0) {
			QAT_LOG(ERR, "Invalid AES cipher key size");
			ret = -EINVAL;
			goto error_out;
		}
		session->qat_mode = ICP_QAT_HW_CIPHER_CBC_MODE;
		break;
	case RTE_CRYPTO_CIPHER_AES_CTR:
		if (qat_sym_validate_aes_key(cipher_xform->key.length,
				&session->qat_cipher_alg) != 0) {
			QAT_LOG(ERR, "Invalid AES cipher key size");
			ret = -EINVAL;
			goto error_out;
		}
		session->qat_mode = ICP_QAT_HW_CIPHER_CTR_MODE;
		break;
	case RTE_CRYPTO_CIPHER_SNOW3G_UEA2:
		if (qat_sym_validate_snow3g_key(cipher_xform->key.length,
					&session->qat_cipher_alg) != 0) {
			QAT_LOG(ERR, "Invalid SNOW 3G cipher key size");
			ret = -EINVAL;
			goto error_out;
		}
		session->qat_mode = ICP_QAT_HW_CIPHER_ECB_MODE;
		break;
	case RTE_CRYPTO_CIPHER_NULL:
		session->qat_cipher_alg = ICP_QAT_HW_CIPHER_ALGO_NULL;
		session->qat_mode = ICP_QAT_HW_CIPHER_CTR_MODE;
		break;
	case RTE_CRYPTO_CIPHER_KASUMI_F8:
		if (qat_sym_validate_kasumi_key(cipher_xform->key.length,
					&session->qat_cipher_alg) != 0) {
			QAT_LOG(ERR, "Invalid KASUMI cipher key size");
			ret = -EINVAL;
			goto error_out;
		}
		session->qat_mode = ICP_QAT_HW_CIPHER_F8_MODE;
		break;
	case RTE_CRYPTO_CIPHER_3DES_CBC:
		if (qat_sym_validate_3des_key(cipher_xform->key.length,
				&session->qat_cipher_alg) != 0) {
			QAT_LOG(ERR, "Invalid 3DES cipher key size");
			ret = -EINVAL;
			goto error_out;
		}
		session->qat_mode = ICP_QAT_HW_CIPHER_CBC_MODE;
		break;
	case RTE_CRYPTO_CIPHER_DES_CBC:
		if (qat_sym_validate_des_key(cipher_xform->key.length,
				&session->qat_cipher_alg) != 0) {
			QAT_LOG(ERR, "Invalid DES cipher key size");
			ret = -EINVAL;
			goto error_out;
		}
		session->qat_mode = ICP_QAT_HW_CIPHER_CBC_MODE;
		break;
	case RTE_CRYPTO_CIPHER_3DES_CTR:
		if (qat_sym_validate_3des_key(cipher_xform->key.length,
				&session->qat_cipher_alg) != 0) {
			QAT_LOG(ERR, "Invalid 3DES cipher key size");
			ret = -EINVAL;
			goto error_out;
		}
		session->qat_mode = ICP_QAT_HW_CIPHER_CTR_MODE;
		break;
	case RTE_CRYPTO_CIPHER_DES_DOCSISBPI:
		ret = bpi_cipher_ctx_init(
					cipher_xform->algo,
					cipher_xform->op,
					cipher_xform->key.data,
					&session->bpi_ctx);
		if (ret != 0) {
			QAT_LOG(ERR, "failed to create DES BPI ctx");
			goto error_out;
		}
		if (qat_sym_validate_des_key(cipher_xform->key.length,
				&session->qat_cipher_alg) != 0) {
			QAT_LOG(ERR, "Invalid DES cipher key size");
			ret = -EINVAL;
			goto error_out;
		}
		session->qat_mode = ICP_QAT_HW_CIPHER_CBC_MODE;
		break;
	case RTE_CRYPTO_CIPHER_AES_DOCSISBPI:
		ret = bpi_cipher_ctx_init(
					cipher_xform->algo,
					cipher_xform->op,
					cipher_xform->key.data,
					&session->bpi_ctx);
		if (ret != 0) {
			QAT_LOG(ERR, "failed to create AES BPI ctx");
			goto error_out;
		}
		if (qat_sym_validate_aes_docsisbpi_key(cipher_xform->key.length,
				&session->qat_cipher_alg) != 0) {
			QAT_LOG(ERR, "Invalid AES DOCSISBPI key size");
			ret = -EINVAL;
			goto error_out;
		}
		session->qat_mode = ICP_QAT_HW_CIPHER_CBC_MODE;
		break;
	case RTE_CRYPTO_CIPHER_ZUC_EEA3:
		if (!qat_is_cipher_alg_supported(
			cipher_xform->algo, internals)) {
			QAT_LOG(ERR, "%s not supported on this device",
				rte_crypto_cipher_algorithm_strings
					[cipher_xform->algo]);
			ret = -ENOTSUP;
			goto error_out;
		}
		if (qat_sym_validate_zuc_key(cipher_xform->key.length,
				&session->qat_cipher_alg) != 0) {
			QAT_LOG(ERR, "Invalid ZUC cipher key size");
			ret = -EINVAL;
			goto error_out;
		}
		session->qat_mode = ICP_QAT_HW_CIPHER_ECB_MODE;
		break;
	case RTE_CRYPTO_CIPHER_3DES_ECB:
	case RTE_CRYPTO_CIPHER_AES_ECB:
	case RTE_CRYPTO_CIPHER_AES_F8:
	case RTE_CRYPTO_CIPHER_AES_XTS:
	case RTE_CRYPTO_CIPHER_ARC4:
		QAT_LOG(ERR, "Crypto QAT PMD: Unsupported Cipher alg %u",
				cipher_xform->algo);
		ret = -ENOTSUP;
		goto error_out;
	default:
		QAT_LOG(ERR, "Crypto: Undefined Cipher specified %u\n",
				cipher_xform->algo);
		ret = -EINVAL;
		goto error_out;
	}

	if (cipher_xform->op == RTE_CRYPTO_CIPHER_OP_ENCRYPT)
		session->qat_dir = ICP_QAT_HW_CIPHER_ENCRYPT;
	else
		session->qat_dir = ICP_QAT_HW_CIPHER_DECRYPT;

	if (qat_sym_session_aead_create_cd_cipher(session,
						cipher_xform->key.data,
						cipher_xform->key.length)) {
		ret = -EINVAL;
		goto error_out;
	}

	return 0;

error_out:
	if (session->bpi_ctx) {
		bpi_cipher_ctx_free(session->bpi_ctx);
		session->bpi_ctx = NULL;
	}
	return ret;
}

int
qat_sym_session_configure(struct rte_cryptodev *dev,
		struct rte_crypto_sym_xform *xform,
		struct rte_cryptodev_sym_session *sess,
		struct rte_mempool *mempool)
{
	void *sess_private_data;
	int ret;

	if (rte_mempool_get(mempool, &sess_private_data)) {
		CDEV_LOG_ERR(
			"Couldn't get object from session mempool");
		return -ENOMEM;
	}

	ret = qat_sym_session_set_parameters(dev, xform, sess_private_data);
	if (ret != 0) {
		QAT_LOG(ERR,
		    "Crypto QAT PMD: failed to configure session parameters");

		/* Return session to mempool */
		rte_mempool_put(mempool, sess_private_data);
		return ret;
	}

	set_sym_session_private_data(sess, dev->driver_id,
		sess_private_data);

	return 0;
}

int
qat_sym_session_set_parameters(struct rte_cryptodev *dev,
		struct rte_crypto_sym_xform *xform, void *session_private)
{
	struct qat_sym_session *session = session_private;
	int ret;
	int qat_cmd_id;

	/* Set context descriptor physical address */
	session->cd_paddr = rte_mempool_virt2iova(session) +
			offsetof(struct qat_sym_session, cd);

	session->min_qat_dev_gen = QAT_GEN1;

	/* Get requested QAT command id */
	qat_cmd_id = qat_get_cmd_id(xform);
	if (qat_cmd_id < 0 || qat_cmd_id >= ICP_QAT_FW_LA_CMD_DELIMITER) {
		QAT_LOG(ERR, "Unsupported xform chain requested");
		return -ENOTSUP;
	}
	session->qat_cmd = (enum icp_qat_fw_la_cmd_id)qat_cmd_id;
	switch (session->qat_cmd) {
	case ICP_QAT_FW_LA_CMD_CIPHER:
		ret = qat_sym_session_configure_cipher(dev, xform, session);
		if (ret < 0)
			return ret;
		break;
	case ICP_QAT_FW_LA_CMD_AUTH:
		ret = qat_sym_session_configure_auth(dev, xform, session);
		if (ret < 0)
			return ret;
		break;
	case ICP_QAT_FW_LA_CMD_CIPHER_HASH:
		if (xform->type == RTE_CRYPTO_SYM_XFORM_AEAD) {
			ret = qat_sym_session_configure_aead(xform,
					session);
			if (ret < 0)
				return ret;
		} else {
			ret = qat_sym_session_configure_cipher(dev,
					xform, session);
			if (ret < 0)
				return ret;
			ret = qat_sym_session_configure_auth(dev,
					xform, session);
			if (ret < 0)
				return ret;
		}
		break;
	case ICP_QAT_FW_LA_CMD_HASH_CIPHER:
		if (xform->type == RTE_CRYPTO_SYM_XFORM_AEAD) {
			ret = qat_sym_session_configure_aead(xform,
					session);
			if (ret < 0)
				return ret;
		} else {
			ret = qat_sym_session_configure_auth(dev,
					xform, session);
			if (ret < 0)
				return ret;
			ret = qat_sym_session_configure_cipher(dev,
					xform, session);
			if (ret < 0)
				return ret;
		}
		break;
	case ICP_QAT_FW_LA_CMD_TRNG_GET_RANDOM:
	case ICP_QAT_FW_LA_CMD_TRNG_TEST:
	case ICP_QAT_FW_LA_CMD_SSL3_KEY_DERIVE:
	case ICP_QAT_FW_LA_CMD_TLS_V1_1_KEY_DERIVE:
	case ICP_QAT_FW_LA_CMD_TLS_V1_2_KEY_DERIVE:
	case ICP_QAT_FW_LA_CMD_MGF1:
	case ICP_QAT_FW_LA_CMD_AUTH_PRE_COMP:
	case ICP_QAT_FW_LA_CMD_CIPHER_PRE_COMP:
	case ICP_QAT_FW_LA_CMD_DELIMITER:
	QAT_LOG(ERR, "Unsupported Service %u",
		session->qat_cmd);
		return -ENOTSUP;
	default:
	QAT_LOG(ERR, "Unsupported Service %u",
		session->qat_cmd);
		return -ENOTSUP;
	}

	return 0;
}

int
qat_sym_session_configure_auth(struct rte_cryptodev *dev,
				struct rte_crypto_sym_xform *xform,
				struct qat_sym_session *session)
{
	struct rte_crypto_auth_xform *auth_xform = qat_get_auth_xform(xform);
	struct qat_sym_dev_private *internals = dev->data->dev_private;
	uint8_t *key_data = auth_xform->key.data;
	uint8_t key_length = auth_xform->key.length;
	session->aes_cmac = 0;

	switch (auth_xform->algo) {
	case RTE_CRYPTO_AUTH_SHA1_HMAC:
		session->qat_hash_alg = ICP_QAT_HW_AUTH_ALGO_SHA1;
		break;
	case RTE_CRYPTO_AUTH_SHA224_HMAC:
		session->qat_hash_alg = ICP_QAT_HW_AUTH_ALGO_SHA224;
		break;
	case RTE_CRYPTO_AUTH_SHA256_HMAC:
		session->qat_hash_alg = ICP_QAT_HW_AUTH_ALGO_SHA256;
		break;
	case RTE_CRYPTO_AUTH_SHA384_HMAC:
		session->qat_hash_alg = ICP_QAT_HW_AUTH_ALGO_SHA384;
		break;
	case RTE_CRYPTO_AUTH_SHA512_HMAC:
		session->qat_hash_alg = ICP_QAT_HW_AUTH_ALGO_SHA512;
		break;
	case RTE_CRYPTO_AUTH_AES_XCBC_MAC:
		session->qat_hash_alg = ICP_QAT_HW_AUTH_ALGO_AES_XCBC_MAC;
		break;
	case RTE_CRYPTO_AUTH_AES_CMAC:
		session->qat_hash_alg = ICP_QAT_HW_AUTH_ALGO_AES_XCBC_MAC;
		session->aes_cmac = 1;
		break;
	case RTE_CRYPTO_AUTH_AES_GMAC:
		if (qat_sym_validate_aes_key(auth_xform->key.length,
				&session->qat_cipher_alg) != 0) {
			QAT_LOG(ERR, "Invalid AES key size");
			return -EINVAL;
		}
		session->qat_mode = ICP_QAT_HW_CIPHER_CTR_MODE;
		session->qat_hash_alg = ICP_QAT_HW_AUTH_ALGO_GALOIS_128;

		break;
	case RTE_CRYPTO_AUTH_SNOW3G_UIA2:
		session->qat_hash_alg = ICP_QAT_HW_AUTH_ALGO_SNOW_3G_UIA2;
		break;
	case RTE_CRYPTO_AUTH_MD5_HMAC:
		session->qat_hash_alg = ICP_QAT_HW_AUTH_ALGO_MD5;
		break;
	case RTE_CRYPTO_AUTH_NULL:
		session->qat_hash_alg = ICP_QAT_HW_AUTH_ALGO_NULL;
		break;
	case RTE_CRYPTO_AUTH_KASUMI_F9:
		session->qat_hash_alg = ICP_QAT_HW_AUTH_ALGO_KASUMI_F9;
		break;
	case RTE_CRYPTO_AUTH_ZUC_EIA3:
		if (!qat_is_auth_alg_supported(auth_xform->algo, internals)) {
			QAT_LOG(ERR, "%s not supported on this device",
				rte_crypto_auth_algorithm_strings
				[auth_xform->algo]);
			return -ENOTSUP;
		}
		session->qat_hash_alg = ICP_QAT_HW_AUTH_ALGO_ZUC_3G_128_EIA3;
		break;
	case RTE_CRYPTO_AUTH_SHA1:
	case RTE_CRYPTO_AUTH_SHA256:
	case RTE_CRYPTO_AUTH_SHA512:
	case RTE_CRYPTO_AUTH_SHA224:
	case RTE_CRYPTO_AUTH_SHA384:
	case RTE_CRYPTO_AUTH_MD5:
	case RTE_CRYPTO_AUTH_AES_CBC_MAC:
		QAT_LOG(ERR, "Crypto: Unsupported hash alg %u",
				auth_xform->algo);
		return -ENOTSUP;
	default:
		QAT_LOG(ERR, "Crypto: Undefined Hash algo %u specified",
				auth_xform->algo);
		return -EINVAL;
	}

	session->auth_iv.offset = auth_xform->iv.offset;
	session->auth_iv.length = auth_xform->iv.length;

	if (auth_xform->algo == RTE_CRYPTO_AUTH_AES_GMAC) {
		if (auth_xform->op == RTE_CRYPTO_AUTH_OP_GENERATE) {
			session->qat_cmd = ICP_QAT_FW_LA_CMD_CIPHER_HASH;
			session->qat_dir = ICP_QAT_HW_CIPHER_ENCRYPT;
			/*
			 * It needs to create cipher desc content first,
			 * then authentication
			 */

			if (qat_sym_session_aead_create_cd_cipher(session,
						auth_xform->key.data,
						auth_xform->key.length))
				return -EINVAL;

			if (qat_sym_session_aead_create_cd_auth(session,
						key_data,
						key_length,
						0,
						auth_xform->digest_length,
						auth_xform->op))
				return -EINVAL;
		} else {
			session->qat_cmd = ICP_QAT_FW_LA_CMD_HASH_CIPHER;
			session->qat_dir = ICP_QAT_HW_CIPHER_DECRYPT;
			/*
			 * It needs to create authentication desc content first,
			 * then cipher
			 */

			if (qat_sym_session_aead_create_cd_auth(session,
					key_data,
					key_length,
					0,
					auth_xform->digest_length,
					auth_xform->op))
				return -EINVAL;

			if (qat_sym_session_aead_create_cd_cipher(session,
						auth_xform->key.data,
						auth_xform->key.length))
				return -EINVAL;
		}
		/* Restore to authentication only only */
		session->qat_cmd = ICP_QAT_FW_LA_CMD_AUTH;
	} else {
		if (qat_sym_session_aead_create_cd_auth(session,
				key_data,
				key_length,
				0,
				auth_xform->digest_length,
				auth_xform->op))
			return -EINVAL;
	}

	session->digest_length = auth_xform->digest_length;
	return 0;
}

int
qat_sym_session_configure_aead(struct rte_crypto_sym_xform *xform,
				struct qat_sym_session *session)
{
	struct rte_crypto_aead_xform *aead_xform = &xform->aead;
	enum rte_crypto_auth_operation crypto_operation;

	/*
	 * Store AEAD IV parameters as cipher IV,
	 * to avoid unnecessary memory usage
	 */
	session->cipher_iv.offset = xform->aead.iv.offset;
	session->cipher_iv.length = xform->aead.iv.length;

	switch (aead_xform->algo) {
	case RTE_CRYPTO_AEAD_AES_GCM:
		if (qat_sym_validate_aes_key(aead_xform->key.length,
				&session->qat_cipher_alg) != 0) {
			QAT_LOG(ERR, "Invalid AES key size");
			return -EINVAL;
		}
		session->qat_mode = ICP_QAT_HW_CIPHER_CTR_MODE;
		session->qat_hash_alg = ICP_QAT_HW_AUTH_ALGO_GALOIS_128;
		break;
	case RTE_CRYPTO_AEAD_AES_CCM:
		if (qat_sym_validate_aes_key(aead_xform->key.length,
				&session->qat_cipher_alg) != 0) {
			QAT_LOG(ERR, "Invalid AES key size");
			return -EINVAL;
		}
		session->qat_mode = ICP_QAT_HW_CIPHER_CTR_MODE;
		session->qat_hash_alg = ICP_QAT_HW_AUTH_ALGO_AES_CBC_MAC;
		break;
	default:
		QAT_LOG(ERR, "Crypto: Undefined AEAD specified %u\n",
				aead_xform->algo);
		return -EINVAL;
	}

	if ((aead_xform->op == RTE_CRYPTO_AEAD_OP_ENCRYPT &&
			aead_xform->algo == RTE_CRYPTO_AEAD_AES_GCM) ||
			(aead_xform->op == RTE_CRYPTO_AEAD_OP_DECRYPT &&
			aead_xform->algo == RTE_CRYPTO_AEAD_AES_CCM)) {
		session->qat_dir = ICP_QAT_HW_CIPHER_ENCRYPT;
		/*
		 * It needs to create cipher desc content first,
		 * then authentication
		 */
		crypto_operation = aead_xform->algo == RTE_CRYPTO_AEAD_AES_GCM ?
			RTE_CRYPTO_AUTH_OP_GENERATE : RTE_CRYPTO_AUTH_OP_VERIFY;

		if (qat_sym_session_aead_create_cd_cipher(session,
					aead_xform->key.data,
					aead_xform->key.length))
			return -EINVAL;

		if (qat_sym_session_aead_create_cd_auth(session,
					aead_xform->key.data,
					aead_xform->key.length,
					aead_xform->aad_length,
					aead_xform->digest_length,
					crypto_operation))
			return -EINVAL;
	} else {
		session->qat_dir = ICP_QAT_HW_CIPHER_DECRYPT;
		/*
		 * It needs to create authentication desc content first,
		 * then cipher
		 */

		crypto_operation = aead_xform->algo == RTE_CRYPTO_AEAD_AES_GCM ?
			RTE_CRYPTO_AUTH_OP_VERIFY : RTE_CRYPTO_AUTH_OP_GENERATE;

		if (qat_sym_session_aead_create_cd_auth(session,
					aead_xform->key.data,
					aead_xform->key.length,
					aead_xform->aad_length,
					aead_xform->digest_length,
					crypto_operation))
			return -EINVAL;

		if (qat_sym_session_aead_create_cd_cipher(session,
					aead_xform->key.data,
					aead_xform->key.length))
			return -EINVAL;
	}

	session->digest_length = aead_xform->digest_length;
	return 0;
}

unsigned int qat_sym_session_get_private_size(
		struct rte_cryptodev *dev __rte_unused)
{
	return RTE_ALIGN_CEIL(sizeof(struct qat_sym_session), 8);
}

/* returns block size in bytes per cipher algo */
int qat_cipher_get_block_size(enum icp_qat_hw_cipher_algo qat_cipher_alg)
{
	switch (qat_cipher_alg) {
	case ICP_QAT_HW_CIPHER_ALGO_DES:
		return ICP_QAT_HW_DES_BLK_SZ;
	case ICP_QAT_HW_CIPHER_ALGO_3DES:
		return ICP_QAT_HW_3DES_BLK_SZ;
	case ICP_QAT_HW_CIPHER_ALGO_AES128:
	case ICP_QAT_HW_CIPHER_ALGO_AES192:
	case ICP_QAT_HW_CIPHER_ALGO_AES256:
		return ICP_QAT_HW_AES_BLK_SZ;
	default:
		QAT_LOG(ERR, "invalid block cipher alg %u", qat_cipher_alg);
		return -EFAULT;
	};
	return -EFAULT;
}

/*
 * Returns size in bytes per hash algo for state1 size field in cd_ctrl
 * This is digest size rounded up to nearest quadword
 */
static int qat_hash_get_state1_size(enum icp_qat_hw_auth_algo qat_hash_alg)
{
	switch (qat_hash_alg) {
	case ICP_QAT_HW_AUTH_ALGO_SHA1:
		return QAT_HW_ROUND_UP(ICP_QAT_HW_SHA1_STATE1_SZ,
						QAT_HW_DEFAULT_ALIGNMENT);
	case ICP_QAT_HW_AUTH_ALGO_SHA224:
		return QAT_HW_ROUND_UP(ICP_QAT_HW_SHA224_STATE1_SZ,
						QAT_HW_DEFAULT_ALIGNMENT);
	case ICP_QAT_HW_AUTH_ALGO_SHA256:
		return QAT_HW_ROUND_UP(ICP_QAT_HW_SHA256_STATE1_SZ,
						QAT_HW_DEFAULT_ALIGNMENT);
	case ICP_QAT_HW_AUTH_ALGO_SHA384:
		return QAT_HW_ROUND_UP(ICP_QAT_HW_SHA384_STATE1_SZ,
						QAT_HW_DEFAULT_ALIGNMENT);
	case ICP_QAT_HW_AUTH_ALGO_SHA512:
		return QAT_HW_ROUND_UP(ICP_QAT_HW_SHA512_STATE1_SZ,
						QAT_HW_DEFAULT_ALIGNMENT);
	case ICP_QAT_HW_AUTH_ALGO_AES_XCBC_MAC:
		return QAT_HW_ROUND_UP(ICP_QAT_HW_AES_XCBC_MAC_STATE1_SZ,
						QAT_HW_DEFAULT_ALIGNMENT);
	case ICP_QAT_HW_AUTH_ALGO_GALOIS_128:
	case ICP_QAT_HW_AUTH_ALGO_GALOIS_64:
		return QAT_HW_ROUND_UP(ICP_QAT_HW_GALOIS_128_STATE1_SZ,
						QAT_HW_DEFAULT_ALIGNMENT);
	case ICP_QAT_HW_AUTH_ALGO_ZUC_3G_128_EIA3:
		return QAT_HW_ROUND_UP(ICP_QAT_HW_ZUC_3G_EIA3_STATE1_SZ,
						QAT_HW_DEFAULT_ALIGNMENT);
	case ICP_QAT_HW_AUTH_ALGO_SNOW_3G_UIA2:
		return QAT_HW_ROUND_UP(ICP_QAT_HW_SNOW_3G_UIA2_STATE1_SZ,
						QAT_HW_DEFAULT_ALIGNMENT);
	case ICP_QAT_HW_AUTH_ALGO_MD5:
		return QAT_HW_ROUND_UP(ICP_QAT_HW_MD5_STATE1_SZ,
						QAT_HW_DEFAULT_ALIGNMENT);
	case ICP_QAT_HW_AUTH_ALGO_KASUMI_F9:
		return QAT_HW_ROUND_UP(ICP_QAT_HW_KASUMI_F9_STATE1_SZ,
						QAT_HW_DEFAULT_ALIGNMENT);
	case ICP_QAT_HW_AUTH_ALGO_AES_CBC_MAC:
		return QAT_HW_ROUND_UP(ICP_QAT_HW_AES_CBC_MAC_STATE1_SZ,
						QAT_HW_DEFAULT_ALIGNMENT);
	case ICP_QAT_HW_AUTH_ALGO_NULL:
		return QAT_HW_ROUND_UP(ICP_QAT_HW_NULL_STATE1_SZ,
						QAT_HW_DEFAULT_ALIGNMENT);
	case ICP_QAT_HW_AUTH_ALGO_DELIMITER:
		/* return maximum state1 size in this case */
		return QAT_HW_ROUND_UP(ICP_QAT_HW_SHA512_STATE1_SZ,
						QAT_HW_DEFAULT_ALIGNMENT);
	default:
		QAT_LOG(ERR, "invalid hash alg %u", qat_hash_alg);
		return -EFAULT;
	};
	return -EFAULT;
}

/* returns digest size in bytes  per hash algo */
static int qat_hash_get_digest_size(enum icp_qat_hw_auth_algo qat_hash_alg)
{
	switch (qat_hash_alg) {
	case ICP_QAT_HW_AUTH_ALGO_SHA1:
		return ICP_QAT_HW_SHA1_STATE1_SZ;
	case ICP_QAT_HW_AUTH_ALGO_SHA224:
		return ICP_QAT_HW_SHA224_STATE1_SZ;
	case ICP_QAT_HW_AUTH_ALGO_SHA256:
		return ICP_QAT_HW_SHA256_STATE1_SZ;
	case ICP_QAT_HW_AUTH_ALGO_SHA384:
		return ICP_QAT_HW_SHA384_STATE1_SZ;
	case ICP_QAT_HW_AUTH_ALGO_SHA512:
		return ICP_QAT_HW_SHA512_STATE1_SZ;
	case ICP_QAT_HW_AUTH_ALGO_MD5:
		return ICP_QAT_HW_MD5_STATE1_SZ;
	case ICP_QAT_HW_AUTH_ALGO_AES_XCBC_MAC:
		return ICP_QAT_HW_AES_XCBC_MAC_STATE1_SZ;
	case ICP_QAT_HW_AUTH_ALGO_DELIMITER:
		/* return maximum digest size in this case */
		return ICP_QAT_HW_SHA512_STATE1_SZ;
	default:
		QAT_LOG(ERR, "invalid hash alg %u", qat_hash_alg);
		return -EFAULT;
	};
	return -EFAULT;
}

/* returns block size in byes per hash algo */
static int qat_hash_get_block_size(enum icp_qat_hw_auth_algo qat_hash_alg)
{
	switch (qat_hash_alg) {
	case ICP_QAT_HW_AUTH_ALGO_SHA1:
		return SHA_CBLOCK;
	case ICP_QAT_HW_AUTH_ALGO_SHA224:
		return SHA256_CBLOCK;
	case ICP_QAT_HW_AUTH_ALGO_SHA256:
		return SHA256_CBLOCK;
	case ICP_QAT_HW_AUTH_ALGO_SHA384:
		return SHA512_CBLOCK;
	case ICP_QAT_HW_AUTH_ALGO_SHA512:
		return SHA512_CBLOCK;
	case ICP_QAT_HW_AUTH_ALGO_GALOIS_128:
		return 16;
	case ICP_QAT_HW_AUTH_ALGO_AES_XCBC_MAC:
		return ICP_QAT_HW_AES_BLK_SZ;
	case ICP_QAT_HW_AUTH_ALGO_MD5:
		return MD5_CBLOCK;
	case ICP_QAT_HW_AUTH_ALGO_DELIMITER:
		/* return maximum block size in this case */
		return SHA512_CBLOCK;
	default:
		QAT_LOG(ERR, "invalid hash alg %u", qat_hash_alg);
		return -EFAULT;
	};
	return -EFAULT;
}

static int partial_hash_sha1(uint8_t *data_in, uint8_t *data_out)
{
	SHA_CTX ctx;

	if (!SHA1_Init(&ctx))
		return -EFAULT;
	SHA1_Transform(&ctx, data_in);
	rte_memcpy(data_out, &ctx, SHA_DIGEST_LENGTH);
	return 0;
}

static int partial_hash_sha224(uint8_t *data_in, uint8_t *data_out)
{
	SHA256_CTX ctx;

	if (!SHA224_Init(&ctx))
		return -EFAULT;
	SHA256_Transform(&ctx, data_in);
	rte_memcpy(data_out, &ctx, SHA256_DIGEST_LENGTH);
	return 0;
}

static int partial_hash_sha256(uint8_t *data_in, uint8_t *data_out)
{
	SHA256_CTX ctx;

	if (!SHA256_Init(&ctx))
		return -EFAULT;
	SHA256_Transform(&ctx, data_in);
	rte_memcpy(data_out, &ctx, SHA256_DIGEST_LENGTH);
	return 0;
}

static int partial_hash_sha384(uint8_t *data_in, uint8_t *data_out)
{
	SHA512_CTX ctx;

	if (!SHA384_Init(&ctx))
		return -EFAULT;
	SHA512_Transform(&ctx, data_in);
	rte_memcpy(data_out, &ctx, SHA512_DIGEST_LENGTH);
	return 0;
}

static int partial_hash_sha512(uint8_t *data_in, uint8_t *data_out)
{
	SHA512_CTX ctx;

	if (!SHA512_Init(&ctx))
		return -EFAULT;
	SHA512_Transform(&ctx, data_in);
	rte_memcpy(data_out, &ctx, SHA512_DIGEST_LENGTH);
	return 0;
}

static int partial_hash_md5(uint8_t *data_in, uint8_t *data_out)
{
	MD5_CTX ctx;

	if (!MD5_Init(&ctx))
		return -EFAULT;
	MD5_Transform(&ctx, data_in);
	rte_memcpy(data_out, &ctx, MD5_DIGEST_LENGTH);

	return 0;
}

static int partial_hash_compute(enum icp_qat_hw_auth_algo hash_alg,
			uint8_t *data_in,
			uint8_t *data_out)
{
	int digest_size;
	uint8_t digest[qat_hash_get_digest_size(
			ICP_QAT_HW_AUTH_ALGO_DELIMITER)];
	uint32_t *hash_state_out_be32;
	uint64_t *hash_state_out_be64;
	int i;

	digest_size = qat_hash_get_digest_size(hash_alg);
	if (digest_size <= 0)
		return -EFAULT;

	hash_state_out_be32 = (uint32_t *)data_out;
	hash_state_out_be64 = (uint64_t *)data_out;

	switch (hash_alg) {
	case ICP_QAT_HW_AUTH_ALGO_SHA1:
		if (partial_hash_sha1(data_in, digest))
			return -EFAULT;
		for (i = 0; i < digest_size >> 2; i++, hash_state_out_be32++)
			*hash_state_out_be32 =
				rte_bswap32(*(((uint32_t *)digest)+i));
		break;
	case ICP_QAT_HW_AUTH_ALGO_SHA224:
		if (partial_hash_sha224(data_in, digest))
			return -EFAULT;
		for (i = 0; i < digest_size >> 2; i++, hash_state_out_be32++)
			*hash_state_out_be32 =
				rte_bswap32(*(((uint32_t *)digest)+i));
		break;
	case ICP_QAT_HW_AUTH_ALGO_SHA256:
		if (partial_hash_sha256(data_in, digest))
			return -EFAULT;
		for (i = 0; i < digest_size >> 2; i++, hash_state_out_be32++)
			*hash_state_out_be32 =
				rte_bswap32(*(((uint32_t *)digest)+i));
		break;
	case ICP_QAT_HW_AUTH_ALGO_SHA384:
		if (partial_hash_sha384(data_in, digest))
			return -EFAULT;
		for (i = 0; i < digest_size >> 3; i++, hash_state_out_be64++)
			*hash_state_out_be64 =
				rte_bswap64(*(((uint64_t *)digest)+i));
		break;
	case ICP_QAT_HW_AUTH_ALGO_SHA512:
		if (partial_hash_sha512(data_in, digest))
			return -EFAULT;
		for (i = 0; i < digest_size >> 3; i++, hash_state_out_be64++)
			*hash_state_out_be64 =
				rte_bswap64(*(((uint64_t *)digest)+i));
		break;
	case ICP_QAT_HW_AUTH_ALGO_MD5:
		if (partial_hash_md5(data_in, data_out))
			return -EFAULT;
		break;
	default:
		QAT_LOG(ERR, "invalid hash alg %u", hash_alg);
		return -EFAULT;
	}

	return 0;
}
#define HMAC_IPAD_VALUE	0x36
#define HMAC_OPAD_VALUE	0x5c
#define HASH_XCBC_PRECOMP_KEY_NUM 3

static const uint8_t AES_CMAC_SEED[ICP_QAT_HW_AES_128_KEY_SZ];

static void aes_cmac_key_derive(uint8_t *base, uint8_t *derived)
{
	int i;

	derived[0] = base[0] << 1;
	for (i = 1; i < ICP_QAT_HW_AES_BLK_SZ ; i++) {
		derived[i] = base[i] << 1;
		derived[i - 1] |= base[i] >> 7;
	}

	if (base[0] & 0x80)
		derived[ICP_QAT_HW_AES_BLK_SZ - 1] ^= QAT_AES_CMAC_CONST_RB;
}

static int qat_sym_do_precomputes(enum icp_qat_hw_auth_algo hash_alg,
				const uint8_t *auth_key,
				uint16_t auth_keylen,
				uint8_t *p_state_buf,
				uint16_t *p_state_len,
				uint8_t aes_cmac)
{
	int block_size;
	uint8_t ipad[qat_hash_get_block_size(ICP_QAT_HW_AUTH_ALGO_DELIMITER)];
	uint8_t opad[qat_hash_get_block_size(ICP_QAT_HW_AUTH_ALGO_DELIMITER)];
	int i;

	if (hash_alg == ICP_QAT_HW_AUTH_ALGO_AES_XCBC_MAC) {

		/* CMAC */
		if (aes_cmac) {
			AES_KEY enc_key;
			uint8_t *in = NULL;
			uint8_t k0[ICP_QAT_HW_AES_128_KEY_SZ];
			uint8_t *k1, *k2;

			auth_keylen = ICP_QAT_HW_AES_128_KEY_SZ;

			in = rte_zmalloc("AES CMAC K1",
					 ICP_QAT_HW_AES_128_KEY_SZ, 16);

			if (in == NULL) {
				QAT_LOG(ERR, "Failed to alloc memory");
				return -ENOMEM;
			}

			rte_memcpy(in, AES_CMAC_SEED,
				   ICP_QAT_HW_AES_128_KEY_SZ);
			rte_memcpy(p_state_buf, auth_key, auth_keylen);

			if (AES_set_encrypt_key(auth_key, auth_keylen << 3,
				&enc_key) != 0) {
				rte_free(in);
				return -EFAULT;
			}

			AES_encrypt(in, k0, &enc_key);

			k1 = p_state_buf + ICP_QAT_HW_AES_XCBC_MAC_STATE1_SZ;
			k2 = k1 + ICP_QAT_HW_AES_XCBC_MAC_STATE1_SZ;

			aes_cmac_key_derive(k0, k1);
			aes_cmac_key_derive(k1, k2);

			memset(k0, 0, ICP_QAT_HW_AES_128_KEY_SZ);
			*p_state_len = ICP_QAT_HW_AES_XCBC_MAC_STATE2_SZ;
			rte_free(in);
			return 0;
		} else {
			static uint8_t qat_aes_xcbc_key_seed[
					ICP_QAT_HW_AES_XCBC_MAC_STATE2_SZ] = {
				0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
				0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
				0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
				0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
			};

			uint8_t *in = NULL;
			uint8_t *out = p_state_buf;
			int x;
			AES_KEY enc_key;

			in = rte_zmalloc("working mem for key",
					ICP_QAT_HW_AES_XCBC_MAC_STATE2_SZ, 16);
			if (in == NULL) {
				QAT_LOG(ERR, "Failed to alloc memory");
				return -ENOMEM;
			}

			rte_memcpy(in, qat_aes_xcbc_key_seed,
					ICP_QAT_HW_AES_XCBC_MAC_STATE2_SZ);
			for (x = 0; x < HASH_XCBC_PRECOMP_KEY_NUM; x++) {
				if (AES_set_encrypt_key(auth_key,
							auth_keylen << 3,
							&enc_key) != 0) {
					rte_free(in -
					  (x * ICP_QAT_HW_AES_XCBC_MAC_KEY_SZ));
					memset(out -
					   (x * ICP_QAT_HW_AES_XCBC_MAC_KEY_SZ),
					  0, ICP_QAT_HW_AES_XCBC_MAC_STATE2_SZ);
					return -EFAULT;
				}
				AES_encrypt(in, out, &enc_key);
				in += ICP_QAT_HW_AES_XCBC_MAC_KEY_SZ;
				out += ICP_QAT_HW_AES_XCBC_MAC_KEY_SZ;
			}
			*p_state_len = ICP_QAT_HW_AES_XCBC_MAC_STATE2_SZ;
			rte_free(in - x*ICP_QAT_HW_AES_XCBC_MAC_KEY_SZ);
			return 0;
		}

	} else if ((hash_alg == ICP_QAT_HW_AUTH_ALGO_GALOIS_128) ||
		(hash_alg == ICP_QAT_HW_AUTH_ALGO_GALOIS_64)) {
		uint8_t *in = NULL;
		uint8_t *out = p_state_buf;
		AES_KEY enc_key;

		memset(p_state_buf, 0, ICP_QAT_HW_GALOIS_H_SZ +
				ICP_QAT_HW_GALOIS_LEN_A_SZ +
				ICP_QAT_HW_GALOIS_E_CTR0_SZ);
		in = rte_zmalloc("working mem for key",
				ICP_QAT_HW_GALOIS_H_SZ, 16);
		if (in == NULL) {
			QAT_LOG(ERR, "Failed to alloc memory");
			return -ENOMEM;
		}

		memset(in, 0, ICP_QAT_HW_GALOIS_H_SZ);
		if (AES_set_encrypt_key(auth_key, auth_keylen << 3,
			&enc_key) != 0) {
			return -EFAULT;
		}
		AES_encrypt(in, out, &enc_key);
		*p_state_len = ICP_QAT_HW_GALOIS_H_SZ +
				ICP_QAT_HW_GALOIS_LEN_A_SZ +
				ICP_QAT_HW_GALOIS_E_CTR0_SZ;
		rte_free(in);
		return 0;
	}

	block_size = qat_hash_get_block_size(hash_alg);
	if (block_size < 0)
		return block_size;
	/* init ipad and opad from key and xor with fixed values */
	memset(ipad, 0, block_size);
	memset(opad, 0, block_size);

	if (auth_keylen > (unsigned int)block_size) {
		QAT_LOG(ERR, "invalid keylen %u", auth_keylen);
		return -EFAULT;
	}
	rte_memcpy(ipad, auth_key, auth_keylen);
	rte_memcpy(opad, auth_key, auth_keylen);

	for (i = 0; i < block_size; i++) {
		uint8_t *ipad_ptr = ipad + i;
		uint8_t *opad_ptr = opad + i;
		*ipad_ptr ^= HMAC_IPAD_VALUE;
		*opad_ptr ^= HMAC_OPAD_VALUE;
	}

	/* do partial hash of ipad and copy to state1 */
	if (partial_hash_compute(hash_alg, ipad, p_state_buf)) {
		memset(ipad, 0, block_size);
		memset(opad, 0, block_size);
		QAT_LOG(ERR, "ipad precompute failed");
		return -EFAULT;
	}

	/*
	 * State len is a multiple of 8, so may be larger than the digest.
	 * Put the partial hash of opad state_len bytes after state1
	 */
	*p_state_len = qat_hash_get_state1_size(hash_alg);
	if (partial_hash_compute(hash_alg, opad, p_state_buf + *p_state_len)) {
		memset(ipad, 0, block_size);
		memset(opad, 0, block_size);
		QAT_LOG(ERR, "opad precompute failed");
		return -EFAULT;
	}

	/*  don't leave data lying around */
	memset(ipad, 0, block_size);
	memset(opad, 0, block_size);
	return 0;
}

static void
qat_sym_session_init_common_hdr(struct icp_qat_fw_comn_req_hdr *header,
		enum qat_sym_proto_flag proto_flags)
{
	header->hdr_flags =
		ICP_QAT_FW_COMN_HDR_FLAGS_BUILD(ICP_QAT_FW_COMN_REQ_FLAG_SET);
	header->service_type = ICP_QAT_FW_COMN_REQ_CPM_FW_LA;
	header->comn_req_flags =
		ICP_QAT_FW_COMN_FLAGS_BUILD(QAT_COMN_CD_FLD_TYPE_64BIT_ADR,
					QAT_COMN_PTR_TYPE_FLAT);
	ICP_QAT_FW_LA_PARTIAL_SET(header->serv_specif_flags,
				  ICP_QAT_FW_LA_PARTIAL_NONE);
	ICP_QAT_FW_LA_CIPH_IV_FLD_FLAG_SET(header->serv_specif_flags,
					   ICP_QAT_FW_CIPH_IV_16BYTE_DATA);

	switch (proto_flags)		{
	case QAT_CRYPTO_PROTO_FLAG_NONE:
		ICP_QAT_FW_LA_PROTO_SET(header->serv_specif_flags,
					ICP_QAT_FW_LA_NO_PROTO);
		break;
	case QAT_CRYPTO_PROTO_FLAG_CCM:
		ICP_QAT_FW_LA_PROTO_SET(header->serv_specif_flags,
					ICP_QAT_FW_LA_CCM_PROTO);
		break;
	case QAT_CRYPTO_PROTO_FLAG_GCM:
		ICP_QAT_FW_LA_PROTO_SET(header->serv_specif_flags,
					ICP_QAT_FW_LA_GCM_PROTO);
		break;
	case QAT_CRYPTO_PROTO_FLAG_SNOW3G:
		ICP_QAT_FW_LA_PROTO_SET(header->serv_specif_flags,
					ICP_QAT_FW_LA_SNOW_3G_PROTO);
		break;
	case QAT_CRYPTO_PROTO_FLAG_ZUC:
		ICP_QAT_FW_LA_ZUC_3G_PROTO_FLAG_SET(header->serv_specif_flags,
			ICP_QAT_FW_LA_ZUC_3G_PROTO);
		break;
	}

	ICP_QAT_FW_LA_UPDATE_STATE_SET(header->serv_specif_flags,
					   ICP_QAT_FW_LA_NO_UPDATE_STATE);
	ICP_QAT_FW_LA_DIGEST_IN_BUFFER_SET(header->serv_specif_flags,
					ICP_QAT_FW_LA_NO_DIGEST_IN_BUFFER);
}

/*
 *	Snow3G and ZUC should never use this function
 *	and set its protocol flag in both cipher and auth part of content
 *	descriptor building function
 */
static enum qat_sym_proto_flag
qat_get_crypto_proto_flag(uint16_t flags)
{
	int proto = ICP_QAT_FW_LA_PROTO_GET(flags);
	enum qat_sym_proto_flag qat_proto_flag =
			QAT_CRYPTO_PROTO_FLAG_NONE;

	switch (proto) {
	case ICP_QAT_FW_LA_GCM_PROTO:
		qat_proto_flag = QAT_CRYPTO_PROTO_FLAG_GCM;
		break;
	case ICP_QAT_FW_LA_CCM_PROTO:
		qat_proto_flag = QAT_CRYPTO_PROTO_FLAG_CCM;
		break;
	}

	return qat_proto_flag;
}

int qat_sym_session_aead_create_cd_cipher(struct qat_sym_session *cdesc,
						uint8_t *cipherkey,
						uint32_t cipherkeylen)
{
	struct icp_qat_hw_cipher_algo_blk *cipher;
	struct icp_qat_fw_la_bulk_req *req_tmpl = &cdesc->fw_req;
	struct icp_qat_fw_comn_req_hdr_cd_pars *cd_pars = &req_tmpl->cd_pars;
	struct icp_qat_fw_comn_req_hdr *header = &req_tmpl->comn_hdr;
	void *ptr = &req_tmpl->cd_ctrl;
	struct icp_qat_fw_cipher_cd_ctrl_hdr *cipher_cd_ctrl = ptr;
	struct icp_qat_fw_auth_cd_ctrl_hdr *hash_cd_ctrl = ptr;
	enum icp_qat_hw_cipher_convert key_convert;
	enum qat_sym_proto_flag qat_proto_flag =
		QAT_CRYPTO_PROTO_FLAG_NONE;
	uint32_t total_key_size;
	uint16_t cipher_offset, cd_size;
	uint32_t wordIndex  = 0;
	uint32_t *temp_key = NULL;

	if (cdesc->qat_cmd == ICP_QAT_FW_LA_CMD_CIPHER) {
		cd_pars->u.s.content_desc_addr = cdesc->cd_paddr;
		ICP_QAT_FW_COMN_CURR_ID_SET(cipher_cd_ctrl,
					ICP_QAT_FW_SLICE_CIPHER);
		ICP_QAT_FW_COMN_NEXT_ID_SET(cipher_cd_ctrl,
					ICP_QAT_FW_SLICE_DRAM_WR);
		ICP_QAT_FW_LA_RET_AUTH_SET(header->serv_specif_flags,
					ICP_QAT_FW_LA_NO_RET_AUTH_RES);
		ICP_QAT_FW_LA_CMP_AUTH_SET(header->serv_specif_flags,
					ICP_QAT_FW_LA_NO_CMP_AUTH_RES);
		cdesc->cd_cur_ptr = (uint8_t *)&cdesc->cd;
	} else if (cdesc->qat_cmd == ICP_QAT_FW_LA_CMD_CIPHER_HASH) {
		cd_pars->u.s.content_desc_addr = cdesc->cd_paddr;
		ICP_QAT_FW_COMN_CURR_ID_SET(cipher_cd_ctrl,
					ICP_QAT_FW_SLICE_CIPHER);
		ICP_QAT_FW_COMN_NEXT_ID_SET(cipher_cd_ctrl,
					ICP_QAT_FW_SLICE_AUTH);
		ICP_QAT_FW_COMN_CURR_ID_SET(hash_cd_ctrl,
					ICP_QAT_FW_SLICE_AUTH);
		ICP_QAT_FW_COMN_NEXT_ID_SET(hash_cd_ctrl,
					ICP_QAT_FW_SLICE_DRAM_WR);
		cdesc->cd_cur_ptr = (uint8_t *)&cdesc->cd;
	} else if (cdesc->qat_cmd != ICP_QAT_FW_LA_CMD_HASH_CIPHER) {
		QAT_LOG(ERR, "Invalid param, must be a cipher command.");
		return -EFAULT;
	}

	if (cdesc->qat_mode == ICP_QAT_HW_CIPHER_CTR_MODE) {
		/*
		 * CTR Streaming ciphers are a special case. Decrypt = encrypt
		 * Overriding default values previously set
		 */
		cdesc->qat_dir = ICP_QAT_HW_CIPHER_ENCRYPT;
		key_convert = ICP_QAT_HW_CIPHER_NO_CONVERT;
	} else if (cdesc->qat_cipher_alg == ICP_QAT_HW_CIPHER_ALGO_SNOW_3G_UEA2
		|| cdesc->qat_cipher_alg ==
			ICP_QAT_HW_CIPHER_ALGO_ZUC_3G_128_EEA3)
		key_convert = ICP_QAT_HW_CIPHER_KEY_CONVERT;
	else if (cdesc->qat_dir == ICP_QAT_HW_CIPHER_ENCRYPT)
		key_convert = ICP_QAT_HW_CIPHER_NO_CONVERT;
	else
		key_convert = ICP_QAT_HW_CIPHER_KEY_CONVERT;

	if (cdesc->qat_cipher_alg == ICP_QAT_HW_CIPHER_ALGO_SNOW_3G_UEA2) {
		total_key_size = ICP_QAT_HW_SNOW_3G_UEA2_KEY_SZ +
			ICP_QAT_HW_SNOW_3G_UEA2_IV_SZ;
		cipher_cd_ctrl->cipher_state_sz =
			ICP_QAT_HW_SNOW_3G_UEA2_IV_SZ >> 3;
		qat_proto_flag = QAT_CRYPTO_PROTO_FLAG_SNOW3G;

	} else if (cdesc->qat_cipher_alg == ICP_QAT_HW_CIPHER_ALGO_KASUMI) {
		total_key_size = ICP_QAT_HW_KASUMI_F8_KEY_SZ;
		cipher_cd_ctrl->cipher_state_sz = ICP_QAT_HW_KASUMI_BLK_SZ >> 3;
		cipher_cd_ctrl->cipher_padding_sz =
					(2 * ICP_QAT_HW_KASUMI_BLK_SZ) >> 3;
	} else if (cdesc->qat_cipher_alg == ICP_QAT_HW_CIPHER_ALGO_3DES) {
		total_key_size = ICP_QAT_HW_3DES_KEY_SZ;
		cipher_cd_ctrl->cipher_state_sz = ICP_QAT_HW_3DES_BLK_SZ >> 3;
		qat_proto_flag =
			qat_get_crypto_proto_flag(header->serv_specif_flags);
	} else if (cdesc->qat_cipher_alg == ICP_QAT_HW_CIPHER_ALGO_DES) {
		total_key_size = ICP_QAT_HW_DES_KEY_SZ;
		cipher_cd_ctrl->cipher_state_sz = ICP_QAT_HW_DES_BLK_SZ >> 3;
		qat_proto_flag =
			qat_get_crypto_proto_flag(header->serv_specif_flags);
	} else if (cdesc->qat_cipher_alg ==
		ICP_QAT_HW_CIPHER_ALGO_ZUC_3G_128_EEA3) {
		total_key_size = ICP_QAT_HW_ZUC_3G_EEA3_KEY_SZ +
			ICP_QAT_HW_ZUC_3G_EEA3_IV_SZ;
		cipher_cd_ctrl->cipher_state_sz =
			ICP_QAT_HW_ZUC_3G_EEA3_IV_SZ >> 3;
		qat_proto_flag = QAT_CRYPTO_PROTO_FLAG_ZUC;
		cdesc->min_qat_dev_gen = QAT_GEN2;
	} else {
		total_key_size = cipherkeylen;
		cipher_cd_ctrl->cipher_state_sz = ICP_QAT_HW_AES_BLK_SZ >> 3;
		qat_proto_flag =
			qat_get_crypto_proto_flag(header->serv_specif_flags);
	}
	cipher_cd_ctrl->cipher_key_sz = total_key_size >> 3;
	cipher_offset = cdesc->cd_cur_ptr-((uint8_t *)&cdesc->cd);
	cipher_cd_ctrl->cipher_cfg_offset = cipher_offset >> 3;

	header->service_cmd_id = cdesc->qat_cmd;
	qat_sym_session_init_common_hdr(header, qat_proto_flag);

	cipher = (struct icp_qat_hw_cipher_algo_blk *)cdesc->cd_cur_ptr;
	cipher->cipher_config.val =
	    ICP_QAT_HW_CIPHER_CONFIG_BUILD(cdesc->qat_mode,
					cdesc->qat_cipher_alg, key_convert,
					cdesc->qat_dir);

	if (cdesc->qat_cipher_alg == ICP_QAT_HW_CIPHER_ALGO_KASUMI) {
		temp_key = (uint32_t *)(cdesc->cd_cur_ptr +
					sizeof(struct icp_qat_hw_cipher_config)
					+ cipherkeylen);
		memcpy(cipher->key, cipherkey, cipherkeylen);
		memcpy(temp_key, cipherkey, cipherkeylen);

		/* XOR Key with KASUMI F8 key modifier at 4 bytes level */
		for (wordIndex = 0; wordIndex < (cipherkeylen >> 2);
								wordIndex++)
			temp_key[wordIndex] ^= KASUMI_F8_KEY_MODIFIER_4_BYTES;

		cdesc->cd_cur_ptr += sizeof(struct icp_qat_hw_cipher_config) +
					cipherkeylen + cipherkeylen;
	} else {
		memcpy(cipher->key, cipherkey, cipherkeylen);
		cdesc->cd_cur_ptr += sizeof(struct icp_qat_hw_cipher_config) +
					cipherkeylen;
	}

	if (total_key_size > cipherkeylen) {
		uint32_t padding_size =  total_key_size-cipherkeylen;
		if ((cdesc->qat_cipher_alg == ICP_QAT_HW_CIPHER_ALGO_3DES)
			&& (cipherkeylen == QAT_3DES_KEY_SZ_OPT2)) {
			/* K3 not provided so use K1 = K3*/
			memcpy(cdesc->cd_cur_ptr, cipherkey, padding_size);
		} else if ((cdesc->qat_cipher_alg == ICP_QAT_HW_CIPHER_ALGO_3DES)
			&& (cipherkeylen == QAT_3DES_KEY_SZ_OPT3)) {
			/* K2 and K3 not provided so use K1 = K2 = K3*/
			memcpy(cdesc->cd_cur_ptr, cipherkey,
				cipherkeylen);
			memcpy(cdesc->cd_cur_ptr+cipherkeylen,
				cipherkey, cipherkeylen);
		} else
			memset(cdesc->cd_cur_ptr, 0, padding_size);

		cdesc->cd_cur_ptr += padding_size;
	}
	cd_size = cdesc->cd_cur_ptr-(uint8_t *)&cdesc->cd;
	cd_pars->u.s.content_desc_params_sz = RTE_ALIGN_CEIL(cd_size, 8) >> 3;

	return 0;
}

int qat_sym_session_aead_create_cd_auth(struct qat_sym_session *cdesc,
						uint8_t *authkey,
						uint32_t authkeylen,
						uint32_t aad_length,
						uint32_t digestsize,
						unsigned int operation)
{
	struct icp_qat_hw_auth_setup *hash;
	struct icp_qat_hw_cipher_algo_blk *cipherconfig;
	struct icp_qat_fw_la_bulk_req *req_tmpl = &cdesc->fw_req;
	struct icp_qat_fw_comn_req_hdr_cd_pars *cd_pars = &req_tmpl->cd_pars;
	struct icp_qat_fw_comn_req_hdr *header = &req_tmpl->comn_hdr;
	void *ptr = &req_tmpl->cd_ctrl;
	struct icp_qat_fw_cipher_cd_ctrl_hdr *cipher_cd_ctrl = ptr;
	struct icp_qat_fw_auth_cd_ctrl_hdr *hash_cd_ctrl = ptr;
	struct icp_qat_fw_la_auth_req_params *auth_param =
		(struct icp_qat_fw_la_auth_req_params *)
		((char *)&req_tmpl->serv_specif_rqpars +
		sizeof(struct icp_qat_fw_la_cipher_req_params));
	uint16_t state1_size = 0, state2_size = 0;
	uint16_t hash_offset, cd_size;
	uint32_t *aad_len = NULL;
	uint32_t wordIndex  = 0;
	uint32_t *pTempKey;
	enum qat_sym_proto_flag qat_proto_flag =
		QAT_CRYPTO_PROTO_FLAG_NONE;

	if (cdesc->qat_cmd == ICP_QAT_FW_LA_CMD_AUTH) {
		ICP_QAT_FW_COMN_CURR_ID_SET(hash_cd_ctrl,
					ICP_QAT_FW_SLICE_AUTH);
		ICP_QAT_FW_COMN_NEXT_ID_SET(hash_cd_ctrl,
					ICP_QAT_FW_SLICE_DRAM_WR);
		cdesc->cd_cur_ptr = (uint8_t *)&cdesc->cd;
	} else if (cdesc->qat_cmd == ICP_QAT_FW_LA_CMD_HASH_CIPHER) {
		ICP_QAT_FW_COMN_CURR_ID_SET(hash_cd_ctrl,
				ICP_QAT_FW_SLICE_AUTH);
		ICP_QAT_FW_COMN_NEXT_ID_SET(hash_cd_ctrl,
				ICP_QAT_FW_SLICE_CIPHER);
		ICP_QAT_FW_COMN_CURR_ID_SET(cipher_cd_ctrl,
				ICP_QAT_FW_SLICE_CIPHER);
		ICP_QAT_FW_COMN_NEXT_ID_SET(cipher_cd_ctrl,
				ICP_QAT_FW_SLICE_DRAM_WR);
		cdesc->cd_cur_ptr = (uint8_t *)&cdesc->cd;
	} else if (cdesc->qat_cmd != ICP_QAT_FW_LA_CMD_CIPHER_HASH) {
		QAT_LOG(ERR, "Invalid param, must be a hash command.");
		return -EFAULT;
	}

	if (operation == RTE_CRYPTO_AUTH_OP_VERIFY) {
		ICP_QAT_FW_LA_RET_AUTH_SET(header->serv_specif_flags,
				ICP_QAT_FW_LA_NO_RET_AUTH_RES);
		ICP_QAT_FW_LA_CMP_AUTH_SET(header->serv_specif_flags,
				ICP_QAT_FW_LA_CMP_AUTH_RES);
		cdesc->auth_op = ICP_QAT_HW_AUTH_VERIFY;
	} else {
		ICP_QAT_FW_LA_RET_AUTH_SET(header->serv_specif_flags,
					   ICP_QAT_FW_LA_RET_AUTH_RES);
		ICP_QAT_FW_LA_CMP_AUTH_SET(header->serv_specif_flags,
					   ICP_QAT_FW_LA_NO_CMP_AUTH_RES);
		cdesc->auth_op = ICP_QAT_HW_AUTH_GENERATE;
	}

	/*
	 * Setup the inner hash config
	 */
	hash_offset = cdesc->cd_cur_ptr-((uint8_t *)&cdesc->cd);
	hash = (struct icp_qat_hw_auth_setup *)cdesc->cd_cur_ptr;
	hash->auth_config.reserved = 0;
	hash->auth_config.config =
			ICP_QAT_HW_AUTH_CONFIG_BUILD(ICP_QAT_HW_AUTH_MODE1,
				cdesc->qat_hash_alg, digestsize);

	if (cdesc->qat_hash_alg == ICP_QAT_HW_AUTH_ALGO_SNOW_3G_UIA2
		|| cdesc->qat_hash_alg == ICP_QAT_HW_AUTH_ALGO_KASUMI_F9
		|| cdesc->qat_hash_alg == ICP_QAT_HW_AUTH_ALGO_ZUC_3G_128_EIA3
		|| cdesc->qat_hash_alg == ICP_QAT_HW_AUTH_ALGO_AES_XCBC_MAC
		|| cdesc->qat_hash_alg == ICP_QAT_HW_AUTH_ALGO_AES_CBC_MAC
		|| cdesc->qat_hash_alg == ICP_QAT_HW_AUTH_ALGO_NULL
			)
		hash->auth_counter.counter = 0;
	else {
		int block_size = qat_hash_get_block_size(cdesc->qat_hash_alg);

		if (block_size < 0)
			return block_size;
		hash->auth_counter.counter = rte_bswap32(block_size);
	}

	cdesc->cd_cur_ptr += sizeof(struct icp_qat_hw_auth_setup);

	/*
	 * cd_cur_ptr now points at the state1 information.
	 */
	switch (cdesc->qat_hash_alg) {
	case ICP_QAT_HW_AUTH_ALGO_SHA1:
		if (qat_sym_do_precomputes(ICP_QAT_HW_AUTH_ALGO_SHA1, authkey,
			authkeylen, cdesc->cd_cur_ptr, &state1_size,
			cdesc->aes_cmac)) {
			QAT_LOG(ERR, "(SHA)precompute failed");
			return -EFAULT;
		}
		state2_size = RTE_ALIGN_CEIL(ICP_QAT_HW_SHA1_STATE2_SZ, 8);
		break;
	case ICP_QAT_HW_AUTH_ALGO_SHA224:
		if (qat_sym_do_precomputes(ICP_QAT_HW_AUTH_ALGO_SHA224, authkey,
			authkeylen, cdesc->cd_cur_ptr, &state1_size,
			cdesc->aes_cmac)) {
			QAT_LOG(ERR, "(SHA)precompute failed");
			return -EFAULT;
		}
		state2_size = ICP_QAT_HW_SHA224_STATE2_SZ;
		break;
	case ICP_QAT_HW_AUTH_ALGO_SHA256:
		if (qat_sym_do_precomputes(ICP_QAT_HW_AUTH_ALGO_SHA256, authkey,
			authkeylen, cdesc->cd_cur_ptr,	&state1_size,
			cdesc->aes_cmac)) {
			QAT_LOG(ERR, "(SHA)precompute failed");
			return -EFAULT;
		}
		state2_size = ICP_QAT_HW_SHA256_STATE2_SZ;
		break;
	case ICP_QAT_HW_AUTH_ALGO_SHA384:
		if (qat_sym_do_precomputes(ICP_QAT_HW_AUTH_ALGO_SHA384, authkey,
			authkeylen, cdesc->cd_cur_ptr, &state1_size,
			cdesc->aes_cmac)) {
			QAT_LOG(ERR, "(SHA)precompute failed");
			return -EFAULT;
		}
		state2_size = ICP_QAT_HW_SHA384_STATE2_SZ;
		break;
	case ICP_QAT_HW_AUTH_ALGO_SHA512:
		if (qat_sym_do_precomputes(ICP_QAT_HW_AUTH_ALGO_SHA512, authkey,
			authkeylen, cdesc->cd_cur_ptr,	&state1_size,
			cdesc->aes_cmac)) {
			QAT_LOG(ERR, "(SHA)precompute failed");
			return -EFAULT;
		}
		state2_size = ICP_QAT_HW_SHA512_STATE2_SZ;
		break;
	case ICP_QAT_HW_AUTH_ALGO_AES_XCBC_MAC:
		state1_size = ICP_QAT_HW_AES_XCBC_MAC_STATE1_SZ;

		if (cdesc->aes_cmac)
			memset(cdesc->cd_cur_ptr, 0, state1_size);
		if (qat_sym_do_precomputes(ICP_QAT_HW_AUTH_ALGO_AES_XCBC_MAC,
			authkey, authkeylen, cdesc->cd_cur_ptr + state1_size,
			&state2_size, cdesc->aes_cmac)) {
			cdesc->aes_cmac ? QAT_LOG(ERR,
						  "(CMAC)precompute failed")
					: QAT_LOG(ERR,
						  "(XCBC)precompute failed");
			return -EFAULT;
		}
		break;
	case ICP_QAT_HW_AUTH_ALGO_GALOIS_128:
	case ICP_QAT_HW_AUTH_ALGO_GALOIS_64:
		qat_proto_flag = QAT_CRYPTO_PROTO_FLAG_GCM;
		state1_size = ICP_QAT_HW_GALOIS_128_STATE1_SZ;
		if (qat_sym_do_precomputes(cdesc->qat_hash_alg, authkey,
			authkeylen, cdesc->cd_cur_ptr + state1_size,
			&state2_size, cdesc->aes_cmac)) {
			QAT_LOG(ERR, "(GCM)precompute failed");
			return -EFAULT;
		}
		/*
		 * Write (the length of AAD) into bytes 16-19 of state2
		 * in big-endian format. This field is 8 bytes
		 */
		auth_param->u2.aad_sz =
				RTE_ALIGN_CEIL(aad_length, 16);
		auth_param->hash_state_sz = (auth_param->u2.aad_sz) >> 3;

		aad_len = (uint32_t *)(cdesc->cd_cur_ptr +
					ICP_QAT_HW_GALOIS_128_STATE1_SZ +
					ICP_QAT_HW_GALOIS_H_SZ);
		*aad_len = rte_bswap32(aad_length);
		cdesc->aad_len = aad_length;
		break;
	case ICP_QAT_HW_AUTH_ALGO_SNOW_3G_UIA2:
		qat_proto_flag = QAT_CRYPTO_PROTO_FLAG_SNOW3G;
		state1_size = qat_hash_get_state1_size(
				ICP_QAT_HW_AUTH_ALGO_SNOW_3G_UIA2);
		state2_size = ICP_QAT_HW_SNOW_3G_UIA2_STATE2_SZ;
		memset(cdesc->cd_cur_ptr, 0, state1_size + state2_size);

		cipherconfig = (struct icp_qat_hw_cipher_algo_blk *)
				(cdesc->cd_cur_ptr + state1_size + state2_size);
		cipherconfig->cipher_config.val =
		ICP_QAT_HW_CIPHER_CONFIG_BUILD(ICP_QAT_HW_CIPHER_ECB_MODE,
			ICP_QAT_HW_CIPHER_ALGO_SNOW_3G_UEA2,
			ICP_QAT_HW_CIPHER_KEY_CONVERT,
			ICP_QAT_HW_CIPHER_ENCRYPT);
		memcpy(cipherconfig->key, authkey, authkeylen);
		memset(cipherconfig->key + authkeylen,
				0, ICP_QAT_HW_SNOW_3G_UEA2_IV_SZ);
		cdesc->cd_cur_ptr += sizeof(struct icp_qat_hw_cipher_config) +
				authkeylen + ICP_QAT_HW_SNOW_3G_UEA2_IV_SZ;
		auth_param->hash_state_sz = ICP_QAT_HW_SNOW_3G_UEA2_IV_SZ >> 3;
		break;
	case ICP_QAT_HW_AUTH_ALGO_ZUC_3G_128_EIA3:
		hash->auth_config.config =
			ICP_QAT_HW_AUTH_CONFIG_BUILD(ICP_QAT_HW_AUTH_MODE0,
				cdesc->qat_hash_alg, digestsize);
		qat_proto_flag = QAT_CRYPTO_PROTO_FLAG_ZUC;
		state1_size = qat_hash_get_state1_size(
				ICP_QAT_HW_AUTH_ALGO_ZUC_3G_128_EIA3);
		state2_size = ICP_QAT_HW_ZUC_3G_EIA3_STATE2_SZ;
		memset(cdesc->cd_cur_ptr, 0, state1_size + state2_size
			+ ICP_QAT_HW_ZUC_3G_EEA3_IV_SZ);

		memcpy(cdesc->cd_cur_ptr + state1_size, authkey, authkeylen);
		cdesc->cd_cur_ptr += state1_size + state2_size
			+ ICP_QAT_HW_ZUC_3G_EEA3_IV_SZ;
		auth_param->hash_state_sz = ICP_QAT_HW_ZUC_3G_EEA3_IV_SZ >> 3;
		cdesc->min_qat_dev_gen = QAT_GEN2;

		break;
	case ICP_QAT_HW_AUTH_ALGO_MD5:
		if (qat_sym_do_precomputes(ICP_QAT_HW_AUTH_ALGO_MD5, authkey,
			authkeylen, cdesc->cd_cur_ptr, &state1_size,
			cdesc->aes_cmac)) {
			QAT_LOG(ERR, "(MD5)precompute failed");
			return -EFAULT;
		}
		state2_size = ICP_QAT_HW_MD5_STATE2_SZ;
		break;
	case ICP_QAT_HW_AUTH_ALGO_NULL:
		state1_size = qat_hash_get_state1_size(
				ICP_QAT_HW_AUTH_ALGO_NULL);
		state2_size = ICP_QAT_HW_NULL_STATE2_SZ;
		break;
	case ICP_QAT_HW_AUTH_ALGO_AES_CBC_MAC:
		qat_proto_flag = QAT_CRYPTO_PROTO_FLAG_CCM;
		state1_size = qat_hash_get_state1_size(
				ICP_QAT_HW_AUTH_ALGO_AES_CBC_MAC);
		state2_size = ICP_QAT_HW_AES_CBC_MAC_KEY_SZ +
				ICP_QAT_HW_AES_CCM_CBC_E_CTR0_SZ;

		if (aad_length > 0) {
			aad_length += ICP_QAT_HW_CCM_AAD_B0_LEN +
			ICP_QAT_HW_CCM_AAD_LEN_INFO;
			auth_param->u2.aad_sz =
			RTE_ALIGN_CEIL(aad_length,
			ICP_QAT_HW_CCM_AAD_ALIGNMENT);
		} else {
			auth_param->u2.aad_sz = ICP_QAT_HW_CCM_AAD_B0_LEN;
		}
		cdesc->aad_len = aad_length;
		hash->auth_counter.counter = 0;

		hash_cd_ctrl->outer_prefix_sz = digestsize;
		auth_param->hash_state_sz = digestsize;

		memcpy(cdesc->cd_cur_ptr + state1_size, authkey, authkeylen);
		break;
	case ICP_QAT_HW_AUTH_ALGO_KASUMI_F9:
		state1_size = qat_hash_get_state1_size(
				ICP_QAT_HW_AUTH_ALGO_KASUMI_F9);
		state2_size = ICP_QAT_HW_KASUMI_F9_STATE2_SZ;
		memset(cdesc->cd_cur_ptr, 0, state1_size + state2_size);
		pTempKey = (uint32_t *)(cdesc->cd_cur_ptr + state1_size
							+ authkeylen);
		/*
		* The Inner Hash Initial State2 block must contain IK
		* (Initialisation Key), followed by IK XOR-ed with KM
		* (Key Modifier): IK||(IK^KM).
		*/
		/* write the auth key */
		memcpy(cdesc->cd_cur_ptr + state1_size, authkey, authkeylen);
		/* initialise temp key with auth key */
		memcpy(pTempKey, authkey, authkeylen);
		/* XOR Key with KASUMI F9 key modifier at 4 bytes level */
		for (wordIndex = 0; wordIndex < (authkeylen >> 2); wordIndex++)
			pTempKey[wordIndex] ^= KASUMI_F9_KEY_MODIFIER_4_BYTES;
		break;
	default:
		QAT_LOG(ERR, "Invalid HASH alg %u", cdesc->qat_hash_alg);
		return -EFAULT;
	}

	/* Request template setup */
	qat_sym_session_init_common_hdr(header, qat_proto_flag);
	header->service_cmd_id = cdesc->qat_cmd;

	/* Auth CD config setup */
	hash_cd_ctrl->hash_cfg_offset = hash_offset >> 3;
	hash_cd_ctrl->hash_flags = ICP_QAT_FW_AUTH_HDR_FLAG_NO_NESTED;
	hash_cd_ctrl->inner_res_sz = digestsize;
	hash_cd_ctrl->final_sz = digestsize;
	hash_cd_ctrl->inner_state1_sz = state1_size;
	auth_param->auth_res_sz = digestsize;

	hash_cd_ctrl->inner_state2_sz  = state2_size;
	hash_cd_ctrl->inner_state2_offset = hash_cd_ctrl->hash_cfg_offset +
			((sizeof(struct icp_qat_hw_auth_setup) +
			 RTE_ALIGN_CEIL(hash_cd_ctrl->inner_state1_sz, 8))
					>> 3);

	cdesc->cd_cur_ptr += state1_size + state2_size;
	cd_size = cdesc->cd_cur_ptr-(uint8_t *)&cdesc->cd;

	cd_pars->u.s.content_desc_addr = cdesc->cd_paddr;
	cd_pars->u.s.content_desc_params_sz = RTE_ALIGN_CEIL(cd_size, 8) >> 3;

	return 0;
}

int qat_sym_validate_aes_key(int key_len, enum icp_qat_hw_cipher_algo *alg)
{
	switch (key_len) {
	case ICP_QAT_HW_AES_128_KEY_SZ:
		*alg = ICP_QAT_HW_CIPHER_ALGO_AES128;
		break;
	case ICP_QAT_HW_AES_192_KEY_SZ:
		*alg = ICP_QAT_HW_CIPHER_ALGO_AES192;
		break;
	case ICP_QAT_HW_AES_256_KEY_SZ:
		*alg = ICP_QAT_HW_CIPHER_ALGO_AES256;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

int qat_sym_validate_aes_docsisbpi_key(int key_len,
		enum icp_qat_hw_cipher_algo *alg)
{
	switch (key_len) {
	case ICP_QAT_HW_AES_128_KEY_SZ:
		*alg = ICP_QAT_HW_CIPHER_ALGO_AES128;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

int qat_sym_validate_snow3g_key(int key_len, enum icp_qat_hw_cipher_algo *alg)
{
	switch (key_len) {
	case ICP_QAT_HW_SNOW_3G_UEA2_KEY_SZ:
		*alg = ICP_QAT_HW_CIPHER_ALGO_SNOW_3G_UEA2;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

int qat_sym_validate_kasumi_key(int key_len, enum icp_qat_hw_cipher_algo *alg)
{
	switch (key_len) {
	case ICP_QAT_HW_KASUMI_KEY_SZ:
		*alg = ICP_QAT_HW_CIPHER_ALGO_KASUMI;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

int qat_sym_validate_des_key(int key_len, enum icp_qat_hw_cipher_algo *alg)
{
	switch (key_len) {
	case ICP_QAT_HW_DES_KEY_SZ:
		*alg = ICP_QAT_HW_CIPHER_ALGO_DES;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

int qat_sym_validate_3des_key(int key_len, enum icp_qat_hw_cipher_algo *alg)
{
	switch (key_len) {
	case QAT_3DES_KEY_SZ_OPT1:
	case QAT_3DES_KEY_SZ_OPT2:
	case QAT_3DES_KEY_SZ_OPT3:
		*alg = ICP_QAT_HW_CIPHER_ALGO_3DES;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

int qat_sym_validate_zuc_key(int key_len, enum icp_qat_hw_cipher_algo *alg)
{
	switch (key_len) {
	case ICP_QAT_HW_ZUC_3G_EEA3_KEY_SZ:
		*alg = ICP_QAT_HW_CIPHER_ALGO_ZUC_3G_128_EEA3;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}
