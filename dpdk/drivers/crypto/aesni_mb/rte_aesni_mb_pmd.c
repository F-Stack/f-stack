/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2017 Intel Corporation
 */

#include <intel-ipsec-mb.h>

#include <rte_common.h>
#include <rte_hexdump.h>
#include <rte_cryptodev.h>
#include <rte_cryptodev_pmd.h>
#include <rte_bus_vdev.h>
#include <rte_malloc.h>
#include <rte_cpuflags.h>

#include "rte_aesni_mb_pmd_private.h"

#define AES_CCM_DIGEST_MIN_LEN 4
#define AES_CCM_DIGEST_MAX_LEN 16
#define HMAC_MAX_BLOCK_SIZE 128
static uint8_t cryptodev_driver_id;

typedef void (*hash_one_block_t)(const void *data, void *digest);
typedef void (*aes_keyexp_t)(const void *key, void *enc_exp_keys, void *dec_exp_keys);

/**
 * Calculate the authentication pre-computes
 *
 * @param one_block_hash	Function pointer to calculate digest on ipad/opad
 * @param ipad			Inner pad output byte array
 * @param opad			Outer pad output byte array
 * @param hkey			Authentication key
 * @param hkey_len		Authentication key length
 * @param blocksize		Block size of selected hash algo
 */
static void
calculate_auth_precomputes(hash_one_block_t one_block_hash,
		uint8_t *ipad, uint8_t *opad,
		uint8_t *hkey, uint16_t hkey_len,
		uint16_t blocksize)
{
	unsigned i, length;

	uint8_t ipad_buf[blocksize] __rte_aligned(16);
	uint8_t opad_buf[blocksize] __rte_aligned(16);

	/* Setup inner and outer pads */
	memset(ipad_buf, HMAC_IPAD_VALUE, blocksize);
	memset(opad_buf, HMAC_OPAD_VALUE, blocksize);

	/* XOR hash key with inner and outer pads */
	length = hkey_len > blocksize ? blocksize : hkey_len;

	for (i = 0; i < length; i++) {
		ipad_buf[i] ^= hkey[i];
		opad_buf[i] ^= hkey[i];
	}

	/* Compute partial hashes */
	(*one_block_hash)(ipad_buf, ipad);
	(*one_block_hash)(opad_buf, opad);

	/* Clean up stack */
	memset(ipad_buf, 0, blocksize);
	memset(opad_buf, 0, blocksize);
}

/** Get xform chain order */
static enum aesni_mb_operation
aesni_mb_get_chain_order(const struct rte_crypto_sym_xform *xform)
{
	if (xform == NULL)
		return AESNI_MB_OP_NOT_SUPPORTED;

	if (xform->type == RTE_CRYPTO_SYM_XFORM_CIPHER) {
		if (xform->next == NULL)
			return AESNI_MB_OP_CIPHER_ONLY;
		if (xform->next->type == RTE_CRYPTO_SYM_XFORM_AUTH)
			return AESNI_MB_OP_CIPHER_HASH;
	}

	if (xform->type == RTE_CRYPTO_SYM_XFORM_AUTH) {
		if (xform->next == NULL)
			return AESNI_MB_OP_HASH_ONLY;
		if (xform->next->type == RTE_CRYPTO_SYM_XFORM_CIPHER)
			return AESNI_MB_OP_HASH_CIPHER;
	}

	if (xform->type == RTE_CRYPTO_SYM_XFORM_AEAD) {
		if (xform->aead.algo == RTE_CRYPTO_AEAD_AES_CCM ||
				xform->aead.algo == RTE_CRYPTO_AEAD_AES_GCM) {
			if (xform->aead.op == RTE_CRYPTO_AEAD_OP_ENCRYPT)
				return AESNI_MB_OP_AEAD_CIPHER_HASH;
			else
				return AESNI_MB_OP_AEAD_HASH_CIPHER;
		}
	}

	return AESNI_MB_OP_NOT_SUPPORTED;
}

/** Set session authentication parameters */
static int
aesni_mb_set_session_auth_parameters(const struct aesni_mb_op_fns *mb_ops,
		struct aesni_mb_session *sess,
		const struct rte_crypto_sym_xform *xform)
{
	hash_one_block_t hash_oneblock_fn;
	unsigned int key_larger_block_size = 0;
	uint8_t hashed_key[HMAC_MAX_BLOCK_SIZE] = { 0 };

	if (xform == NULL) {
		sess->auth.algo = NULL_HASH;
		return 0;
	}

	if (xform->type != RTE_CRYPTO_SYM_XFORM_AUTH) {
		AESNI_MB_LOG(ERR, "Crypto xform struct not of type auth");
		return -1;
	}

	/* Set the request digest size */
	sess->auth.req_digest_len = xform->auth.digest_length;

	/* Select auth generate/verify */
	sess->auth.operation = xform->auth.op;

	/* Set Authentication Parameters */
	if (xform->auth.algo == RTE_CRYPTO_AUTH_AES_XCBC_MAC) {
		sess->auth.algo = AES_XCBC;

		uint16_t xcbc_mac_digest_len =
			get_truncated_digest_byte_length(AES_XCBC);
		if (sess->auth.req_digest_len != xcbc_mac_digest_len) {
			AESNI_MB_LOG(ERR, "Invalid digest size\n");
			return -EINVAL;
		}
		sess->auth.gen_digest_len = sess->auth.req_digest_len;
		(*mb_ops->aux.keyexp.aes_xcbc)(xform->auth.key.data,
				sess->auth.xcbc.k1_expanded,
				sess->auth.xcbc.k2, sess->auth.xcbc.k3);
		return 0;
	}

	if (xform->auth.algo == RTE_CRYPTO_AUTH_AES_CMAC) {
		sess->auth.algo = AES_CMAC;

		uint16_t cmac_digest_len = get_digest_byte_length(AES_CMAC);

		if (sess->auth.req_digest_len > cmac_digest_len) {
			AESNI_MB_LOG(ERR, "Invalid digest size\n");
			return -EINVAL;
		}
		/*
		 * Multi-buffer lib supports digest sizes from 4 to 16 bytes
		 * in version 0.50 and sizes of 12 and 16 bytes,
		 * in version 0.49.
		 * If size requested is different, generate the full digest
		 * (16 bytes) in a temporary location and then memcpy
		 * the requested number of bytes.
		 */
#if IMB_VERSION_NUM >= IMB_VERSION(0, 50, 0)
		if (sess->auth.req_digest_len < 4)
#else
		uint16_t cmac_trunc_digest_len =
				get_truncated_digest_byte_length(AES_CMAC);
		if (sess->auth.req_digest_len != cmac_digest_len &&
				sess->auth.req_digest_len != cmac_trunc_digest_len)
#endif
			sess->auth.gen_digest_len = cmac_digest_len;
		else
			sess->auth.gen_digest_len = sess->auth.req_digest_len;
		(*mb_ops->aux.keyexp.aes_cmac_expkey)(xform->auth.key.data,
				sess->auth.cmac.expkey);

		(*mb_ops->aux.keyexp.aes_cmac_subkey)(sess->auth.cmac.expkey,
				sess->auth.cmac.skey1, sess->auth.cmac.skey2);
		return 0;
	}

	switch (xform->auth.algo) {
	case RTE_CRYPTO_AUTH_MD5_HMAC:
		sess->auth.algo = MD5;
		hash_oneblock_fn = mb_ops->aux.one_block.md5;
		break;
	case RTE_CRYPTO_AUTH_SHA1_HMAC:
		sess->auth.algo = SHA1;
		hash_oneblock_fn = mb_ops->aux.one_block.sha1;
#if IMB_VERSION_NUM >= IMB_VERSION(0, 50, 0)
		if (xform->auth.key.length > get_auth_algo_blocksize(SHA1)) {
			mb_ops->aux.multi_block.sha1(
				xform->auth.key.data,
				xform->auth.key.length,
				hashed_key);
			key_larger_block_size = 1;
		}
#endif
		break;
	case RTE_CRYPTO_AUTH_SHA224_HMAC:
		sess->auth.algo = SHA_224;
		hash_oneblock_fn = mb_ops->aux.one_block.sha224;
#if IMB_VERSION_NUM >= IMB_VERSION(0, 50, 0)
		if (xform->auth.key.length > get_auth_algo_blocksize(SHA_224)) {
			mb_ops->aux.multi_block.sha224(
				xform->auth.key.data,
				xform->auth.key.length,
				hashed_key);
			key_larger_block_size = 1;
		}
#endif
		break;
	case RTE_CRYPTO_AUTH_SHA256_HMAC:
		sess->auth.algo = SHA_256;
		hash_oneblock_fn = mb_ops->aux.one_block.sha256;
#if IMB_VERSION_NUM >= IMB_VERSION(0, 50, 0)
		if (xform->auth.key.length > get_auth_algo_blocksize(SHA_256)) {
			mb_ops->aux.multi_block.sha256(
				xform->auth.key.data,
				xform->auth.key.length,
				hashed_key);
			key_larger_block_size = 1;
		}
#endif
		break;
	case RTE_CRYPTO_AUTH_SHA384_HMAC:
		sess->auth.algo = SHA_384;
		hash_oneblock_fn = mb_ops->aux.one_block.sha384;
#if IMB_VERSION_NUM >= IMB_VERSION(0, 50, 0)
		if (xform->auth.key.length > get_auth_algo_blocksize(SHA_384)) {
			mb_ops->aux.multi_block.sha384(
				xform->auth.key.data,
				xform->auth.key.length,
				hashed_key);
			key_larger_block_size = 1;
		}
#endif
		break;
	case RTE_CRYPTO_AUTH_SHA512_HMAC:
		sess->auth.algo = SHA_512;
		hash_oneblock_fn = mb_ops->aux.one_block.sha512;
#if IMB_VERSION_NUM >= IMB_VERSION(0, 50, 0)
		if (xform->auth.key.length > get_auth_algo_blocksize(SHA_512)) {
			mb_ops->aux.multi_block.sha512(
				xform->auth.key.data,
				xform->auth.key.length,
				hashed_key);
			key_larger_block_size = 1;
		}
#endif
		break;
	default:
		AESNI_MB_LOG(ERR, "Unsupported authentication algorithm selection");
		return -ENOTSUP;
	}
	uint16_t trunc_digest_size =
			get_truncated_digest_byte_length(sess->auth.algo);
	uint16_t full_digest_size =
			get_digest_byte_length(sess->auth.algo);

#if IMB_VERSION_NUM >= IMB_VERSION(0, 50, 0)
	if (sess->auth.req_digest_len > full_digest_size ||
			sess->auth.req_digest_len == 0) {
#else
	if (sess->auth.req_digest_len != trunc_digest_size) {
#endif
		AESNI_MB_LOG(ERR, "Invalid digest size\n");
		return -EINVAL;
	}

	if (sess->auth.req_digest_len != trunc_digest_size &&
			sess->auth.req_digest_len != full_digest_size)
		sess->auth.gen_digest_len = full_digest_size;
	else
		sess->auth.gen_digest_len = sess->auth.req_digest_len;

	/* Calculate Authentication precomputes */
	if (key_larger_block_size) {
		calculate_auth_precomputes(hash_oneblock_fn,
			sess->auth.pads.inner, sess->auth.pads.outer,
			hashed_key,
			xform->auth.key.length,
			get_auth_algo_blocksize(sess->auth.algo));
	} else {
		calculate_auth_precomputes(hash_oneblock_fn,
			sess->auth.pads.inner, sess->auth.pads.outer,
			xform->auth.key.data,
			xform->auth.key.length,
			get_auth_algo_blocksize(sess->auth.algo));
	}

	return 0;
}

/** Set session cipher parameters */
static int
aesni_mb_set_session_cipher_parameters(const struct aesni_mb_op_fns *mb_ops,
		struct aesni_mb_session *sess,
		const struct rte_crypto_sym_xform *xform)
{
	uint8_t is_aes = 0;
	uint8_t is_3DES = 0;
	aes_keyexp_t aes_keyexp_fn;

	if (xform == NULL) {
		sess->cipher.mode = NULL_CIPHER;
		return 0;
	}

	if (xform->type != RTE_CRYPTO_SYM_XFORM_CIPHER) {
		AESNI_MB_LOG(ERR, "Crypto xform struct not of type cipher");
		return -EINVAL;
	}

	/* Select cipher direction */
	switch (xform->cipher.op) {
	case RTE_CRYPTO_CIPHER_OP_ENCRYPT:
		sess->cipher.direction = ENCRYPT;
		break;
	case RTE_CRYPTO_CIPHER_OP_DECRYPT:
		sess->cipher.direction = DECRYPT;
		break;
	default:
		AESNI_MB_LOG(ERR, "Invalid cipher operation parameter");
		return -EINVAL;
	}

	/* Select cipher mode */
	switch (xform->cipher.algo) {
	case RTE_CRYPTO_CIPHER_AES_CBC:
		sess->cipher.mode = CBC;
		is_aes = 1;
		break;
	case RTE_CRYPTO_CIPHER_AES_CTR:
		sess->cipher.mode = CNTR;
		is_aes = 1;
		break;
	case RTE_CRYPTO_CIPHER_AES_DOCSISBPI:
		sess->cipher.mode = DOCSIS_SEC_BPI;
		is_aes = 1;
		break;
	case RTE_CRYPTO_CIPHER_DES_CBC:
		sess->cipher.mode = DES;
		break;
	case RTE_CRYPTO_CIPHER_DES_DOCSISBPI:
		sess->cipher.mode = DOCSIS_DES;
		break;
	case RTE_CRYPTO_CIPHER_3DES_CBC:
		sess->cipher.mode = DES3;
		is_3DES = 1;
		break;
	default:
		AESNI_MB_LOG(ERR, "Unsupported cipher mode parameter");
		return -ENOTSUP;
	}

	/* Set IV parameters */
	sess->iv.offset = xform->cipher.iv.offset;
	sess->iv.length = xform->cipher.iv.length;

	/* Check key length and choose key expansion function for AES */
	if (is_aes) {
		switch (xform->cipher.key.length) {
		case AES_128_BYTES:
			sess->cipher.key_length_in_bytes = AES_128_BYTES;
			aes_keyexp_fn = mb_ops->aux.keyexp.aes128;
			break;
		case AES_192_BYTES:
			sess->cipher.key_length_in_bytes = AES_192_BYTES;
			aes_keyexp_fn = mb_ops->aux.keyexp.aes192;
			break;
		case AES_256_BYTES:
			sess->cipher.key_length_in_bytes = AES_256_BYTES;
			aes_keyexp_fn = mb_ops->aux.keyexp.aes256;
			break;
		default:
			AESNI_MB_LOG(ERR, "Invalid cipher key length");
			return -EINVAL;
		}

		/* Expanded cipher keys */
		(*aes_keyexp_fn)(xform->cipher.key.data,
				sess->cipher.expanded_aes_keys.encode,
				sess->cipher.expanded_aes_keys.decode);

	} else if (is_3DES) {
		uint64_t *keys[3] = {sess->cipher.exp_3des_keys.key[0],
				sess->cipher.exp_3des_keys.key[1],
				sess->cipher.exp_3des_keys.key[2]};

		switch (xform->cipher.key.length) {
		case  24:
			des_key_schedule(keys[0], xform->cipher.key.data);
			des_key_schedule(keys[1], xform->cipher.key.data+8);
			des_key_schedule(keys[2], xform->cipher.key.data+16);

			/* Initialize keys - 24 bytes: [K1-K2-K3] */
			sess->cipher.exp_3des_keys.ks_ptr[0] = keys[0];
			sess->cipher.exp_3des_keys.ks_ptr[1] = keys[1];
			sess->cipher.exp_3des_keys.ks_ptr[2] = keys[2];
			break;
		case 16:
			des_key_schedule(keys[0], xform->cipher.key.data);
			des_key_schedule(keys[1], xform->cipher.key.data+8);

			/* Initialize keys - 16 bytes: [K1=K1,K2=K2,K3=K1] */
			sess->cipher.exp_3des_keys.ks_ptr[0] = keys[0];
			sess->cipher.exp_3des_keys.ks_ptr[1] = keys[1];
			sess->cipher.exp_3des_keys.ks_ptr[2] = keys[0];
			break;
		case 8:
			des_key_schedule(keys[0], xform->cipher.key.data);

			/* Initialize keys - 8 bytes: [K1 = K2 = K3] */
			sess->cipher.exp_3des_keys.ks_ptr[0] = keys[0];
			sess->cipher.exp_3des_keys.ks_ptr[1] = keys[0];
			sess->cipher.exp_3des_keys.ks_ptr[2] = keys[0];
			break;
		default:
			AESNI_MB_LOG(ERR, "Invalid cipher key length");
			return -EINVAL;
		}

#if IMB_VERSION_NUM >= IMB_VERSION(0, 50, 0)
		sess->cipher.key_length_in_bytes = 24;
#else
		sess->cipher.key_length_in_bytes = 8;
#endif
	} else {
		if (xform->cipher.key.length != 8) {
			AESNI_MB_LOG(ERR, "Invalid cipher key length");
			return -EINVAL;
		}
		sess->cipher.key_length_in_bytes = 8;

		des_key_schedule((uint64_t *)sess->cipher.expanded_aes_keys.encode,
				xform->cipher.key.data);
		des_key_schedule((uint64_t *)sess->cipher.expanded_aes_keys.decode,
				xform->cipher.key.data);
	}

	return 0;
}

static int
aesni_mb_set_session_aead_parameters(const struct aesni_mb_op_fns *mb_ops,
		struct aesni_mb_session *sess,
		const struct rte_crypto_sym_xform *xform)
{
	union {
		aes_keyexp_t aes_keyexp_fn;
		aes_gcm_keyexp_t aes_gcm_keyexp_fn;
	} keyexp;

	switch (xform->aead.op) {
	case RTE_CRYPTO_AEAD_OP_ENCRYPT:
		sess->cipher.direction = ENCRYPT;
		sess->auth.operation = RTE_CRYPTO_AUTH_OP_GENERATE;
		break;
	case RTE_CRYPTO_AEAD_OP_DECRYPT:
		sess->cipher.direction = DECRYPT;
		sess->auth.operation = RTE_CRYPTO_AUTH_OP_VERIFY;
		break;
	default:
		AESNI_MB_LOG(ERR, "Invalid aead operation parameter");
		return -EINVAL;
	}

	switch (xform->aead.algo) {
	case RTE_CRYPTO_AEAD_AES_CCM:
		sess->cipher.mode = CCM;
		sess->auth.algo = AES_CCM;

		/* Check key length and choose key expansion function for AES */
		switch (xform->aead.key.length) {
		case AES_128_BYTES:
			sess->cipher.key_length_in_bytes = AES_128_BYTES;
			keyexp.aes_keyexp_fn = mb_ops->aux.keyexp.aes128;
			break;
		default:
			AESNI_MB_LOG(ERR, "Invalid cipher key length");
			return -EINVAL;
		}

		/* Expanded cipher keys */
		(*keyexp.aes_keyexp_fn)(xform->aead.key.data,
				sess->cipher.expanded_aes_keys.encode,
				sess->cipher.expanded_aes_keys.decode);
		break;

	case RTE_CRYPTO_AEAD_AES_GCM:
		sess->cipher.mode = GCM;
		sess->auth.algo = AES_GMAC;

		switch (xform->aead.key.length) {
		case AES_128_BYTES:
			sess->cipher.key_length_in_bytes = AES_128_BYTES;
			keyexp.aes_gcm_keyexp_fn =
					mb_ops->aux.keyexp.aes_gcm_128;
			break;
		case AES_192_BYTES:
			sess->cipher.key_length_in_bytes = AES_192_BYTES;
			keyexp.aes_gcm_keyexp_fn =
					mb_ops->aux.keyexp.aes_gcm_192;
			break;
		case AES_256_BYTES:
			sess->cipher.key_length_in_bytes = AES_256_BYTES;
			keyexp.aes_gcm_keyexp_fn =
					mb_ops->aux.keyexp.aes_gcm_256;
			break;
		default:
			AESNI_MB_LOG(ERR, "Invalid cipher key length");
			return -EINVAL;
		}

		(keyexp.aes_gcm_keyexp_fn)(xform->aead.key.data,
				&sess->cipher.gcm_key);
		break;

	default:
		AESNI_MB_LOG(ERR, "Unsupported aead mode parameter");
		return -ENOTSUP;
	}

	/* Set IV parameters */
	sess->iv.offset = xform->aead.iv.offset;
	sess->iv.length = xform->aead.iv.length;

	sess->auth.req_digest_len = xform->aead.digest_length;
	/* CCM digests must be between 4 and 16 and an even number */
	if (sess->auth.req_digest_len < AES_CCM_DIGEST_MIN_LEN ||
			sess->auth.req_digest_len > AES_CCM_DIGEST_MAX_LEN ||
			(sess->auth.req_digest_len & 1) == 1) {
		AESNI_MB_LOG(ERR, "Invalid digest size\n");
		return -EINVAL;
	}
	sess->auth.gen_digest_len = sess->auth.req_digest_len;

	return 0;
}

/** Parse crypto xform chain and set private session parameters */
int
aesni_mb_set_session_parameters(const struct aesni_mb_op_fns *mb_ops,
		struct aesni_mb_session *sess,
		const struct rte_crypto_sym_xform *xform)
{
	const struct rte_crypto_sym_xform *auth_xform = NULL;
	const struct rte_crypto_sym_xform *cipher_xform = NULL;
	const struct rte_crypto_sym_xform *aead_xform = NULL;
	int ret;

	/* Select Crypto operation - hash then cipher / cipher then hash */
	switch (aesni_mb_get_chain_order(xform)) {
	case AESNI_MB_OP_HASH_CIPHER:
		sess->chain_order = HASH_CIPHER;
		auth_xform = xform;
		cipher_xform = xform->next;
		break;
	case AESNI_MB_OP_CIPHER_HASH:
		sess->chain_order = CIPHER_HASH;
		auth_xform = xform->next;
		cipher_xform = xform;
		break;
	case AESNI_MB_OP_HASH_ONLY:
		sess->chain_order = HASH_CIPHER;
		auth_xform = xform;
		cipher_xform = NULL;
		break;
	case AESNI_MB_OP_CIPHER_ONLY:
		/*
		 * Multi buffer library operates only at two modes,
		 * CIPHER_HASH and HASH_CIPHER. When doing ciphering only,
		 * chain order depends on cipher operation: encryption is always
		 * the first operation and decryption the last one.
		 */
		if (xform->cipher.op == RTE_CRYPTO_CIPHER_OP_ENCRYPT)
			sess->chain_order = CIPHER_HASH;
		else
			sess->chain_order = HASH_CIPHER;
		auth_xform = NULL;
		cipher_xform = xform;
		break;
	case AESNI_MB_OP_AEAD_CIPHER_HASH:
		sess->chain_order = CIPHER_HASH;
		sess->aead.aad_len = xform->aead.aad_length;
		aead_xform = xform;
		break;
	case AESNI_MB_OP_AEAD_HASH_CIPHER:
		sess->chain_order = HASH_CIPHER;
		sess->aead.aad_len = xform->aead.aad_length;
		aead_xform = xform;
		break;
	case AESNI_MB_OP_NOT_SUPPORTED:
	default:
		AESNI_MB_LOG(ERR, "Unsupported operation chain order parameter");
		return -ENOTSUP;
	}

	/* Default IV length = 0 */
	sess->iv.length = 0;

	ret = aesni_mb_set_session_auth_parameters(mb_ops, sess, auth_xform);
	if (ret != 0) {
		AESNI_MB_LOG(ERR, "Invalid/unsupported authentication parameters");
		return ret;
	}

	ret = aesni_mb_set_session_cipher_parameters(mb_ops, sess,
			cipher_xform);
	if (ret != 0) {
		AESNI_MB_LOG(ERR, "Invalid/unsupported cipher parameters");
		return ret;
	}

	if (aead_xform) {
		ret = aesni_mb_set_session_aead_parameters(mb_ops, sess,
				aead_xform);
		if (ret != 0) {
			AESNI_MB_LOG(ERR, "Invalid/unsupported aead parameters");
			return ret;
		}
	}

	return 0;
}

/**
 * burst enqueue, place crypto operations on ingress queue for processing.
 *
 * @param __qp         Queue Pair to process
 * @param ops          Crypto operations for processing
 * @param nb_ops       Number of crypto operations for processing
 *
 * @return
 * - Number of crypto operations enqueued
 */
static uint16_t
aesni_mb_pmd_enqueue_burst(void *__qp, struct rte_crypto_op **ops,
		uint16_t nb_ops)
{
	struct aesni_mb_qp *qp = __qp;

	unsigned int nb_enqueued;

	nb_enqueued = rte_ring_enqueue_burst(qp->ingress_queue,
			(void **)ops, nb_ops, NULL);

	qp->stats.enqueued_count += nb_enqueued;

	return nb_enqueued;
}

/** Get multi buffer session */
static inline struct aesni_mb_session *
get_session(struct aesni_mb_qp *qp, struct rte_crypto_op *op)
{
	struct aesni_mb_session *sess = NULL;

	if (op->sess_type == RTE_CRYPTO_OP_WITH_SESSION) {
		if (likely(op->sym->session != NULL))
			sess = (struct aesni_mb_session *)
					get_sym_session_private_data(
					op->sym->session,
					cryptodev_driver_id);
	} else {
		void *_sess = NULL;
		void *_sess_private_data = NULL;

		if (rte_mempool_get(qp->sess_mp, (void **)&_sess))
			return NULL;

		if (rte_mempool_get(qp->sess_mp, (void **)&_sess_private_data))
			return NULL;

		sess = (struct aesni_mb_session *)_sess_private_data;

		if (unlikely(aesni_mb_set_session_parameters(qp->op_fns,
				sess, op->sym->xform) != 0)) {
			rte_mempool_put(qp->sess_mp, _sess);
			rte_mempool_put(qp->sess_mp, _sess_private_data);
			sess = NULL;
		}
		op->sym->session = (struct rte_cryptodev_sym_session *)_sess;
		set_sym_session_private_data(op->sym->session,
				cryptodev_driver_id, _sess_private_data);
	}

	if (unlikely(sess == NULL))
		op->status = RTE_CRYPTO_OP_STATUS_INVALID_SESSION;

	return sess;
}

/**
 * Process a crypto operation and complete a JOB_AES_HMAC job structure for
 * submission to the multi buffer library for processing.
 *
 * @param	qp	queue pair
 * @param	job	JOB_AES_HMAC structure to fill
 * @param	m	mbuf to process
 *
 * @return
 * - Completed JOB_AES_HMAC structure pointer on success
 * - NULL pointer if completion of JOB_AES_HMAC structure isn't possible
 */
static inline int
set_mb_job_params(JOB_AES_HMAC *job, struct aesni_mb_qp *qp,
		struct rte_crypto_op *op, uint8_t *digest_idx)
{
	struct rte_mbuf *m_src = op->sym->m_src, *m_dst;
	struct aesni_mb_session *session;
	uint16_t m_offset = 0;

	session = get_session(qp, op);
	if (session == NULL) {
		op->status = RTE_CRYPTO_OP_STATUS_INVALID_SESSION;
		return -1;
	}

	/* Set crypto operation */
	job->chain_order = session->chain_order;

	/* Set cipher parameters */
	job->cipher_direction = session->cipher.direction;
	job->cipher_mode = session->cipher.mode;

	job->aes_key_len_in_bytes = session->cipher.key_length_in_bytes;

	/* Set authentication parameters */
	job->hash_alg = session->auth.algo;

	switch (job->hash_alg) {
	case AES_XCBC:
		job->u.XCBC._k1_expanded = session->auth.xcbc.k1_expanded;
		job->u.XCBC._k2 = session->auth.xcbc.k2;
		job->u.XCBC._k3 = session->auth.xcbc.k3;

		job->aes_enc_key_expanded =
				session->cipher.expanded_aes_keys.encode;
		job->aes_dec_key_expanded =
				session->cipher.expanded_aes_keys.decode;
		break;

	case AES_CCM:
		job->u.CCM.aad = op->sym->aead.aad.data + 18;
		job->u.CCM.aad_len_in_bytes = session->aead.aad_len;
		job->aes_enc_key_expanded =
				session->cipher.expanded_aes_keys.encode;
		job->aes_dec_key_expanded =
				session->cipher.expanded_aes_keys.decode;
		break;

	case AES_CMAC:
		job->u.CMAC._key_expanded = session->auth.cmac.expkey;
		job->u.CMAC._skey1 = session->auth.cmac.skey1;
		job->u.CMAC._skey2 = session->auth.cmac.skey2;
		job->aes_enc_key_expanded =
				session->cipher.expanded_aes_keys.encode;
		job->aes_dec_key_expanded =
				session->cipher.expanded_aes_keys.decode;
		break;

	case AES_GMAC:
		job->u.GCM.aad = op->sym->aead.aad.data;
		job->u.GCM.aad_len_in_bytes = session->aead.aad_len;
		job->aes_enc_key_expanded = &session->cipher.gcm_key;
		job->aes_dec_key_expanded = &session->cipher.gcm_key;
		break;

	default:
		job->u.HMAC._hashed_auth_key_xor_ipad = session->auth.pads.inner;
		job->u.HMAC._hashed_auth_key_xor_opad = session->auth.pads.outer;

		if (job->cipher_mode == DES3) {
			job->aes_enc_key_expanded =
				session->cipher.exp_3des_keys.ks_ptr;
			job->aes_dec_key_expanded =
				session->cipher.exp_3des_keys.ks_ptr;
		} else {
			job->aes_enc_key_expanded =
				session->cipher.expanded_aes_keys.encode;
			job->aes_dec_key_expanded =
				session->cipher.expanded_aes_keys.decode;
		}
	}

	/* Mutable crypto operation parameters */
	if (op->sym->m_dst) {
		m_src = m_dst = op->sym->m_dst;

		/* append space for output data to mbuf */
		char *odata = rte_pktmbuf_append(m_dst,
				rte_pktmbuf_data_len(op->sym->m_src));
		if (odata == NULL) {
			AESNI_MB_LOG(ERR, "failed to allocate space in destination "
					"mbuf for source data");
			op->status = RTE_CRYPTO_OP_STATUS_ERROR;
			return -1;
		}

		memcpy(odata, rte_pktmbuf_mtod(op->sym->m_src, void*),
				rte_pktmbuf_data_len(op->sym->m_src));
	} else {
		m_dst = m_src;
		if (job->hash_alg == AES_CCM || job->hash_alg == AES_GMAC)
			m_offset = op->sym->aead.data.offset;
		else
			m_offset = op->sym->cipher.data.offset;
	}

	/* Set digest output location */
	if (job->hash_alg != NULL_HASH &&
			session->auth.operation == RTE_CRYPTO_AUTH_OP_VERIFY) {
		job->auth_tag_output = qp->temp_digests[*digest_idx];
		*digest_idx = (*digest_idx + 1) % MAX_JOBS;
	} else {
		if (job->hash_alg == AES_CCM || job->hash_alg == AES_GMAC)
			job->auth_tag_output = op->sym->aead.digest.data;
		else
			job->auth_tag_output = op->sym->auth.digest.data;

		if (session->auth.req_digest_len != session->auth.gen_digest_len) {
			job->auth_tag_output = qp->temp_digests[*digest_idx];
			*digest_idx = (*digest_idx + 1) % MAX_JOBS;
		}
	}
	/*
	 * Multi-buffer library current only support returning a truncated
	 * digest length as specified in the relevant IPsec RFCs
	 */

	/* Set digest length */
	job->auth_tag_output_len_in_bytes = session->auth.gen_digest_len;

	/* Set IV parameters */
	job->iv_len_in_bytes = session->iv.length;

	/* Data  Parameter */
	job->src = rte_pktmbuf_mtod(m_src, uint8_t *);
	job->dst = rte_pktmbuf_mtod_offset(m_dst, uint8_t *, m_offset);

	switch (job->hash_alg) {
	case AES_CCM:
		job->cipher_start_src_offset_in_bytes =
				op->sym->aead.data.offset;
		job->msg_len_to_cipher_in_bytes = op->sym->aead.data.length;
		job->hash_start_src_offset_in_bytes = op->sym->aead.data.offset;
		job->msg_len_to_hash_in_bytes = op->sym->aead.data.length;

		job->iv = rte_crypto_op_ctod_offset(op, uint8_t *,
			session->iv.offset + 1);
		break;

	case AES_GMAC:
		job->cipher_start_src_offset_in_bytes =
				op->sym->aead.data.offset;
		job->hash_start_src_offset_in_bytes = op->sym->aead.data.offset;
		job->msg_len_to_cipher_in_bytes = op->sym->aead.data.length;
		job->msg_len_to_hash_in_bytes = job->msg_len_to_cipher_in_bytes;
		job->iv = rte_crypto_op_ctod_offset(op, uint8_t *,
				session->iv.offset);
		break;

	default:
		job->cipher_start_src_offset_in_bytes =
				op->sym->cipher.data.offset;
		job->msg_len_to_cipher_in_bytes = op->sym->cipher.data.length;

		job->hash_start_src_offset_in_bytes = op->sym->auth.data.offset;
		job->msg_len_to_hash_in_bytes = op->sym->auth.data.length;

		job->iv = rte_crypto_op_ctod_offset(op, uint8_t *,
			session->iv.offset);
	}

	/* Set user data to be crypto operation data struct */
	job->user_data = op;

	return 0;
}

static inline void
verify_digest(JOB_AES_HMAC *job, struct rte_crypto_op *op,
		struct aesni_mb_session *sess)
{
	/* Verify digest if required */
	if (job->hash_alg == AES_CCM || job->hash_alg == AES_GMAC) {
		if (memcmp(job->auth_tag_output, op->sym->aead.digest.data,
				sess->auth.req_digest_len) != 0)
			op->status = RTE_CRYPTO_OP_STATUS_AUTH_FAILED;
	} else {
		if (memcmp(job->auth_tag_output, op->sym->auth.digest.data,
				sess->auth.req_digest_len) != 0)
			op->status = RTE_CRYPTO_OP_STATUS_AUTH_FAILED;
	}
}

static inline void
generate_digest(JOB_AES_HMAC *job, struct rte_crypto_op *op,
		struct aesni_mb_session *sess)
{
	/* No extra copy neeed */
	if (likely(sess->auth.req_digest_len == sess->auth.gen_digest_len))
		return;

	/*
	 * This can only happen for HMAC, so only digest
	 * for authentication algos is required
	 */
	memcpy(op->sym->auth.digest.data, job->auth_tag_output,
			sess->auth.req_digest_len);
}

/**
 * Process a completed job and return rte_mbuf which job processed
 *
 * @param qp		Queue Pair to process
 * @param job	JOB_AES_HMAC job to process
 *
 * @return
 * - Returns processed crypto operation.
 * - Returns NULL on invalid job
 */
static inline struct rte_crypto_op *
post_process_mb_job(struct aesni_mb_qp *qp, JOB_AES_HMAC *job)
{
	struct rte_crypto_op *op = (struct rte_crypto_op *)job->user_data;
	struct aesni_mb_session *sess = get_sym_session_private_data(
							op->sym->session,
							cryptodev_driver_id);

	if (likely(op->status == RTE_CRYPTO_OP_STATUS_NOT_PROCESSED)) {
		switch (job->status) {
		case STS_COMPLETED:
			op->status = RTE_CRYPTO_OP_STATUS_SUCCESS;

			if (job->hash_alg != NULL_HASH) {
				if (sess->auth.operation ==
						RTE_CRYPTO_AUTH_OP_VERIFY)
					verify_digest(job, op, sess);
				else
					generate_digest(job, op, sess);
			}
			break;
		default:
			op->status = RTE_CRYPTO_OP_STATUS_ERROR;
		}
	}

	/* Free session if a session-less crypto op */
	if (op->sess_type == RTE_CRYPTO_OP_SESSIONLESS) {
		memset(sess, 0, sizeof(struct aesni_mb_session));
		memset(op->sym->session, 0,
				rte_cryptodev_sym_get_header_session_size());
		rte_mempool_put(qp->sess_mp, sess);
		rte_mempool_put(qp->sess_mp, op->sym->session);
		op->sym->session = NULL;
	}

	return op;
}

/**
 * Process a completed JOB_AES_HMAC job and keep processing jobs until
 * get_completed_job return NULL
 *
 * @param qp		Queue Pair to process
 * @param job		JOB_AES_HMAC job
 *
 * @return
 * - Number of processed jobs
 */
static unsigned
handle_completed_jobs(struct aesni_mb_qp *qp, JOB_AES_HMAC *job,
		struct rte_crypto_op **ops, uint16_t nb_ops)
{
	struct rte_crypto_op *op = NULL;
	unsigned processed_jobs = 0;

	while (job != NULL) {
		op = post_process_mb_job(qp, job);

		if (op) {
			ops[processed_jobs++] = op;
			qp->stats.dequeued_count++;
		} else {
			qp->stats.dequeue_err_count++;
			break;
		}
		if (processed_jobs == nb_ops)
			break;

		job = (*qp->op_fns->job.get_completed_job)(qp->mb_mgr);
	}

	return processed_jobs;
}

static inline uint16_t
flush_mb_mgr(struct aesni_mb_qp *qp, struct rte_crypto_op **ops,
		uint16_t nb_ops)
{
	int processed_ops = 0;

	/* Flush the remaining jobs */
	JOB_AES_HMAC *job = (*qp->op_fns->job.flush_job)(qp->mb_mgr);

	if (job)
		processed_ops += handle_completed_jobs(qp, job,
				&ops[processed_ops], nb_ops - processed_ops);

	return processed_ops;
}

static inline JOB_AES_HMAC *
set_job_null_op(JOB_AES_HMAC *job, struct rte_crypto_op *op)
{
	job->chain_order = HASH_CIPHER;
	job->cipher_mode = NULL_CIPHER;
	job->hash_alg = NULL_HASH;
	job->cipher_direction = DECRYPT;

	/* Set user data to be crypto operation data struct */
	job->user_data = op;

	return job;
}

static uint16_t
aesni_mb_pmd_dequeue_burst(void *queue_pair, struct rte_crypto_op **ops,
		uint16_t nb_ops)
{
	struct aesni_mb_qp *qp = queue_pair;

	struct rte_crypto_op *op;
	JOB_AES_HMAC *job;

	int retval, processed_jobs = 0;

	if (unlikely(nb_ops == 0))
		return 0;

	uint8_t digest_idx = qp->digest_idx;
	do {
		/* Get next free mb job struct from mb manager */
		job = (*qp->op_fns->job.get_next)(qp->mb_mgr);
		if (unlikely(job == NULL)) {
			/* if no free mb job structs we need to flush mb_mgr */
			processed_jobs += flush_mb_mgr(qp,
					&ops[processed_jobs],
					nb_ops - processed_jobs);

			if (nb_ops == processed_jobs)
				break;

			job = (*qp->op_fns->job.get_next)(qp->mb_mgr);
		}

		/*
		 * Get next operation to process from ingress queue.
		 * There is no need to return the job to the MB_MGR
		 * if there are no more operations to process, since the MB_MGR
		 * can use that pointer again in next get_next calls.
		 */
		retval = rte_ring_dequeue(qp->ingress_queue, (void **)&op);
		if (retval < 0)
			break;

		retval = set_mb_job_params(job, qp, op, &digest_idx);
		if (unlikely(retval != 0)) {
			qp->stats.dequeue_err_count++;
			set_job_null_op(job, op);
		}

		/* Submit job to multi-buffer for processing */
		job = (*qp->op_fns->job.submit)(qp->mb_mgr);

		/*
		 * If submit returns a processed job then handle it,
		 * before submitting subsequent jobs
		 */
		if (job)
			processed_jobs += handle_completed_jobs(qp, job,
					&ops[processed_jobs],
					nb_ops - processed_jobs);

	} while (processed_jobs < nb_ops);

	qp->digest_idx = digest_idx;

	if (processed_jobs < 1)
		processed_jobs += flush_mb_mgr(qp,
				&ops[processed_jobs],
				nb_ops - processed_jobs);

	return processed_jobs;
}

static int cryptodev_aesni_mb_remove(struct rte_vdev_device *vdev);

static int
cryptodev_aesni_mb_create(const char *name,
			struct rte_vdev_device *vdev,
			struct rte_cryptodev_pmd_init_params *init_params)
{
	struct rte_cryptodev *dev;
	struct aesni_mb_private *internals;
	enum aesni_mb_vector_mode vector_mode;

	/* Check CPU for support for AES instruction set */
	if (!rte_cpu_get_flag_enabled(RTE_CPUFLAG_AES)) {
		AESNI_MB_LOG(ERR, "AES instructions not supported by CPU");
		return -EFAULT;
	}

	dev = rte_cryptodev_pmd_create(name, &vdev->device, init_params);
	if (dev == NULL) {
		AESNI_MB_LOG(ERR, "failed to create cryptodev vdev");
		return -ENODEV;
	}

	/* Check CPU for supported vector instruction set */
	if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512F))
		vector_mode = RTE_AESNI_MB_AVX512;
	else if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX2))
		vector_mode = RTE_AESNI_MB_AVX2;
	else if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX))
		vector_mode = RTE_AESNI_MB_AVX;
	else
		vector_mode = RTE_AESNI_MB_SSE;

	dev->driver_id = cryptodev_driver_id;
	dev->dev_ops = rte_aesni_mb_pmd_ops;

	/* register rx/tx burst functions for data path */
	dev->dequeue_burst = aesni_mb_pmd_dequeue_burst;
	dev->enqueue_burst = aesni_mb_pmd_enqueue_burst;

	dev->feature_flags = RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO |
			RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING |
			RTE_CRYPTODEV_FF_CPU_AESNI;

	switch (vector_mode) {
	case RTE_AESNI_MB_SSE:
		dev->feature_flags |= RTE_CRYPTODEV_FF_CPU_SSE;
		break;
	case RTE_AESNI_MB_AVX:
		dev->feature_flags |= RTE_CRYPTODEV_FF_CPU_AVX;
		break;
	case RTE_AESNI_MB_AVX2:
		dev->feature_flags |= RTE_CRYPTODEV_FF_CPU_AVX2;
		break;
	case RTE_AESNI_MB_AVX512:
		dev->feature_flags |= RTE_CRYPTODEV_FF_CPU_AVX512;
		break;
	default:
		break;
	}

	/* Set vector instructions mode supported */
	internals = dev->data->dev_private;

	internals->vector_mode = vector_mode;
	internals->max_nb_queue_pairs = init_params->max_nb_queue_pairs;

#if IMB_VERSION_NUM >= IMB_VERSION(0, 50, 0)
	AESNI_MB_LOG(INFO, "IPSec Multi-buffer library version used: %s\n",
			imb_get_version_str());
#else
	AESNI_MB_LOG(INFO, "IPSec Multi-buffer library version used: 0.49.0\n");
#endif

	return 0;
}

static int
cryptodev_aesni_mb_probe(struct rte_vdev_device *vdev)
{
	struct rte_cryptodev_pmd_init_params init_params = {
		"",
		sizeof(struct aesni_mb_private),
		rte_socket_id(),
		RTE_CRYPTODEV_PMD_DEFAULT_MAX_NB_QUEUE_PAIRS
	};
	const char *name, *args;
	int retval;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	args = rte_vdev_device_args(vdev);

	retval = rte_cryptodev_pmd_parse_input_args(&init_params, args);
	if (retval) {
		AESNI_MB_LOG(ERR, "Failed to parse initialisation arguments[%s]",
				args);
		return -EINVAL;
	}

	return cryptodev_aesni_mb_create(name, vdev, &init_params);
}

static int
cryptodev_aesni_mb_remove(struct rte_vdev_device *vdev)
{
	struct rte_cryptodev *cryptodev;
	const char *name;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	cryptodev = rte_cryptodev_pmd_get_named_dev(name);
	if (cryptodev == NULL)
		return -ENODEV;

	return rte_cryptodev_pmd_destroy(cryptodev);
}

static struct rte_vdev_driver cryptodev_aesni_mb_pmd_drv = {
	.probe = cryptodev_aesni_mb_probe,
	.remove = cryptodev_aesni_mb_remove
};

static struct cryptodev_driver aesni_mb_crypto_drv;

RTE_PMD_REGISTER_VDEV(CRYPTODEV_NAME_AESNI_MB_PMD, cryptodev_aesni_mb_pmd_drv);
RTE_PMD_REGISTER_ALIAS(CRYPTODEV_NAME_AESNI_MB_PMD, cryptodev_aesni_mb_pmd);
RTE_PMD_REGISTER_PARAM_STRING(CRYPTODEV_NAME_AESNI_MB_PMD,
	"max_nb_queue_pairs=<int> "
	"socket_id=<int>");
RTE_PMD_REGISTER_CRYPTO_DRIVER(aesni_mb_crypto_drv,
		cryptodev_aesni_mb_pmd_drv.driver,
		cryptodev_driver_id);

RTE_INIT(aesni_mb_init_log)
{
	aesni_mb_logtype_driver = rte_log_register("pmd.crypto.aesni_mb");
}
