/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2017 Intel Corporation
 */

#include <rte_common.h>
#include <rte_hexdump.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_pause.h>

#include <rte_crypto.h>
#include <rte_cryptodev.h>

#include "test.h"
#include "test_cryptodev.h"
#include "test_cryptodev_blockcipher.h"
#include "test_cryptodev_aes_test_vectors.h"
#include "test_cryptodev_des_test_vectors.h"
#include "test_cryptodev_hash_test_vectors.h"

static int
verify_algo_support(const struct blockcipher_test_case *t,
		const uint8_t dev_id, const uint32_t digest_len)
{
	int ret = 0;
	const struct blockcipher_test_data *tdata = t->test_data;
	struct rte_cryptodev_sym_capability_idx cap_idx;
	const struct rte_cryptodev_symmetric_capability *capability;

	if (t->op_mask & BLOCKCIPHER_TEST_OP_CIPHER) {
		cap_idx.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
		cap_idx.algo.cipher = tdata->crypto_algo;
		capability = rte_cryptodev_sym_capability_get(dev_id, &cap_idx);
		if (capability == NULL)
			return -1;

		if (cap_idx.algo.cipher != RTE_CRYPTO_CIPHER_NULL &&
				!(t->test_data->wrapped_key))
			ret = rte_cryptodev_sym_capability_check_cipher(capability,
							tdata->cipher_key.len,
							tdata->iv.len);
		if (ret != 0)
			return -1;
	}

	if (t->op_mask & BLOCKCIPHER_TEST_OP_AUTH) {
		cap_idx.type = RTE_CRYPTO_SYM_XFORM_AUTH;
		cap_idx.algo.auth = tdata->auth_algo;
		capability = rte_cryptodev_sym_capability_get(dev_id, &cap_idx);
		if (capability == NULL)
			return -1;

		if (cap_idx.algo.auth != RTE_CRYPTO_AUTH_NULL)
			ret = rte_cryptodev_sym_capability_check_auth(capability,
							tdata->auth_key.len,
							digest_len,
							0);
		if (ret != 0)
			return -1;
	}

	return 0;
}

static int
test_blockcipher_one_case(const struct blockcipher_test_case *t,
	struct rte_mempool *mbuf_pool,
	struct rte_mempool *op_mpool,
	struct rte_mempool *sess_mpool,
	uint8_t dev_id,
	char *test_msg)
{
	struct rte_mbuf *ibuf = NULL;
	struct rte_mbuf *obuf = NULL;
	struct rte_mbuf *iobuf;
	struct rte_crypto_sym_xform *cipher_xform = NULL;
	struct rte_crypto_sym_xform *auth_xform = NULL;
	struct rte_crypto_sym_xform *init_xform = NULL;
	struct rte_crypto_sym_op *sym_op = NULL;
	struct rte_crypto_op *op = NULL;
	struct rte_cryptodev_info dev_info;
	void *sess = NULL;

	int status = TEST_SUCCESS;
	const struct blockcipher_test_data *tdata = t->test_data;
	uint8_t cipher_key[tdata->cipher_key.len];
	uint8_t auth_key[tdata->auth_key.len];
	uint32_t buf_len = tdata->ciphertext.len;
	uint32_t digest_len = tdata->digest.len;
	char *buf_p = NULL;
	uint8_t src_pattern = 0xa5;
	uint8_t dst_pattern = 0xb6;
	uint8_t tmp_src_buf[MBUF_SIZE];
	uint8_t tmp_dst_buf[MBUF_SIZE];
	uint32_t pad_len;

	int nb_segs_in = 1;
	int nb_segs_out = 1;
	uint64_t sgl_type = t->sgl_flag;
	uint32_t nb_iterates = 0;

	rte_cryptodev_info_get(dev_id, &dev_info);
	uint64_t feat_flags = dev_info.feature_flags;

	if (t->feature_mask & BLOCKCIPHER_TEST_FEATURE_SESSIONLESS) {
		if (!(feat_flags & RTE_CRYPTODEV_FF_SYM_SESSIONLESS)) {
			printf("Device doesn't support sessionless operations "
				"Test Skipped.\n");
			snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN,
				"SKIPPED");
			return TEST_SKIPPED;
		}
	}
	if (t->feature_mask & BLOCKCIPHER_TEST_FEATURE_DIGEST_ENCRYPTED) {
		if (!(feat_flags & RTE_CRYPTODEV_FF_DIGEST_ENCRYPTED)) {
			printf("Device doesn't support encrypted digest "
				"Test Skipped.\n");
			snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN,
				"SKIPPED");
			return TEST_SKIPPED;
		}
	}
	if (t->feature_mask & BLOCKCIPHER_TEST_FEATURE_SG) {
		if (sgl_type == 0) {
			if (t->feature_mask & BLOCKCIPHER_TEST_FEATURE_OOP)
				sgl_type = RTE_CRYPTODEV_FF_OOP_SGL_IN_LB_OUT;
			else
				sgl_type = RTE_CRYPTODEV_FF_IN_PLACE_SGL;
		}

		if (!(feat_flags & sgl_type)) {
			printf("Device doesn't support scatter-gather type."
				" Test Skipped.\n");
			snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN,
				"SKIPPED");
			return TEST_SKIPPED;
		}

		if (sgl_type == RTE_CRYPTODEV_FF_OOP_SGL_IN_LB_OUT ||
				sgl_type == RTE_CRYPTODEV_FF_OOP_SGL_IN_SGL_OUT ||
				sgl_type == RTE_CRYPTODEV_FF_IN_PLACE_SGL)
			nb_segs_in = t->sgl_segs == 0 ? 3 : t->sgl_segs;

		if (sgl_type == RTE_CRYPTODEV_FF_OOP_LB_IN_SGL_OUT ||
				sgl_type == RTE_CRYPTODEV_FF_OOP_SGL_IN_SGL_OUT)
			nb_segs_out = t->sgl_segs == 0 ? 3 : t->sgl_segs;
	}

	if (!!(feat_flags & RTE_CRYPTODEV_FF_CIPHER_WRAPPED_KEY) ^
		tdata->wrapped_key) {
		snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN,
			"SKIPPED");
		return TEST_SKIPPED;
	}

	if (global_api_test_type == CRYPTODEV_RAW_API_TEST &&
		!(feat_flags & RTE_CRYPTODEV_FF_SYM_RAW_DP)) {
		printf("Device doesn't support raw data-path APIs. "
			"Test Skipped.\n");
		snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN, "SKIPPED");
		return TEST_SKIPPED;
	}

	if (t->feature_mask & BLOCKCIPHER_TEST_FEATURE_OOP) {
		uint64_t oop_flags = RTE_CRYPTODEV_FF_OOP_LB_IN_LB_OUT |
			RTE_CRYPTODEV_FF_OOP_LB_IN_SGL_OUT |
			RTE_CRYPTODEV_FF_OOP_SGL_IN_LB_OUT |
			RTE_CRYPTODEV_FF_OOP_SGL_IN_SGL_OUT;
		if (!(feat_flags & oop_flags)) {
			printf("Device doesn't support out-of-place operations."
				"Test Skipped.\n");
			snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN,
				"SKIPPED");
			return TEST_SKIPPED;
		}
		if (global_api_test_type == CRYPTODEV_RAW_API_TEST) {
			printf("Raw Data Path APIs do not support OOP, "
				"Test Skipped.\n");
			snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN, "SKIPPED");
			status = TEST_SKIPPED;
			goto error_exit;
		}
	}

	if (tdata->cipher_key.len)
		memcpy(cipher_key, tdata->cipher_key.data,
			tdata->cipher_key.len);
	if (tdata->auth_key.len)
		memcpy(auth_key, tdata->auth_key.data,
			tdata->auth_key.len);

	/* Check if PMD is capable of performing that test */
	if (verify_algo_support(t, dev_id, digest_len) < 0) {
		RTE_LOG(DEBUG, USER1,
			"Device does not support this algorithm."
			"Test Skipped.\n");
		snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN, "SKIPPED");
		return TEST_SKIPPED;
	}

	/* preparing data */
	if (t->op_mask & BLOCKCIPHER_TEST_OP_AUTH)
		buf_len += digest_len;

	pad_len = RTE_ALIGN(buf_len, 16) - buf_len;
	if (t->op_mask & BLOCKCIPHER_TEST_OP_DIGEST_ENCRYPTED)
		buf_len += pad_len;

	/* for contiguous mbuf, nb_segs is 1 */
	ibuf = create_segmented_mbuf(mbuf_pool,
			tdata->ciphertext.len, nb_segs_in, src_pattern);
	if (ibuf == NULL) {
		snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN,
			"line %u FAILED: %s",
			__LINE__, "Cannot create source mbuf");
		status = TEST_FAILED;
		goto error_exit;
	}

	/* only encryption requires plaintext.data input,
	 * decryption/(digest gen)/(digest verify) use ciphertext.data
	 * to be computed
	 */
	if (t->op_mask & BLOCKCIPHER_TEST_OP_ENCRYPT)
		pktmbuf_write(ibuf, 0, tdata->plaintext.len,
				tdata->plaintext.data);
	else
		pktmbuf_write(ibuf, 0, tdata->ciphertext.len,
				tdata->ciphertext.data);

	buf_p = rte_pktmbuf_append(ibuf, digest_len);
	if (t->op_mask & BLOCKCIPHER_TEST_OP_AUTH_VERIFY)
		if (t->op_mask & BLOCKCIPHER_TEST_OP_DIGEST_ENCRYPTED)
			rte_memcpy(buf_p,
				tdata->ciphertext.data + tdata->ciphertext.len,
				 digest_len);
		else
			rte_memcpy(buf_p, tdata->digest.data, digest_len);
	else
		memset(buf_p, 0, digest_len);
	if (t->op_mask & BLOCKCIPHER_TEST_OP_DIGEST_ENCRYPTED) {
		buf_p = rte_pktmbuf_append(ibuf, pad_len);
		if (!buf_p) {
			snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN, "line %u "
				"FAILED: %s", __LINE__,
				"No room to append mbuf");
			status = TEST_FAILED;
			goto error_exit;
		}
		if (t->op_mask & BLOCKCIPHER_TEST_OP_AUTH_VERIFY) {
			const uint8_t *temp_p = tdata->ciphertext.data +
					tdata->ciphertext.len +
					digest_len;
			rte_memcpy(buf_p, temp_p, pad_len);
		} else
			memset(buf_p, 0xa5, pad_len);
	}

	if (t->feature_mask & BLOCKCIPHER_TEST_FEATURE_OOP) {
		obuf = create_segmented_mbuf(mbuf_pool,
			tdata->ciphertext.len, nb_segs_out, dst_pattern);
		if (!obuf) {
			snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN, "line %u "
				"FAILED: %s", __LINE__,
				"Allocation of rte_mbuf failed");
			status = TEST_FAILED;
			goto error_exit;
		}
		memset(obuf->buf_addr, dst_pattern, obuf->buf_len);

		if (t->op_mask & BLOCKCIPHER_TEST_OP_DIGEST_ENCRYPTED)
			buf_p = rte_pktmbuf_append(obuf, buf_len + pad_len);
		else
			buf_p = rte_pktmbuf_append(obuf, buf_len);
		if (!buf_p) {
			snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN, "line %u "
				"FAILED: %s", __LINE__,
				"No room to append mbuf");
			status = TEST_FAILED;
			goto error_exit;
		}
		memset(buf_p, 0, buf_len);
	}

	/* Generate Crypto op data structure */
	op = rte_crypto_op_alloc(op_mpool, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	if (!op) {
		snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN,
			"line %u FAILED: %s",
			__LINE__, "Failed to allocate symmetric crypto "
			"operation struct");
		status = TEST_FAILED;
		goto error_exit;
	}

	sym_op = op->sym;

iterate:
	if (nb_iterates) {
		struct rte_mbuf *tmp_buf = ibuf;

		ibuf = obuf;
		obuf = tmp_buf;

		rte_pktmbuf_reset(ibuf);
		rte_pktmbuf_reset(obuf);

		rte_pktmbuf_append(ibuf, tdata->ciphertext.len);

		/* only encryption requires plaintext.data input,
		 * decryption/(digest gen)/(digest verify) use ciphertext.data
		 * to be computed
		 */
		if (t->op_mask & BLOCKCIPHER_TEST_OP_ENCRYPT)
			pktmbuf_write(ibuf, 0, tdata->plaintext.len,
					tdata->plaintext.data);
		else
			pktmbuf_write(ibuf, 0, tdata->ciphertext.len,
					tdata->ciphertext.data);

		buf_p = rte_pktmbuf_append(ibuf, digest_len);
		if (t->op_mask & BLOCKCIPHER_TEST_OP_AUTH_VERIFY)
			rte_memcpy(buf_p, tdata->digest.data, digest_len);
		else
			memset(buf_p, 0, digest_len);

		memset(obuf->buf_addr, dst_pattern, obuf->buf_len);

		buf_p = rte_pktmbuf_append(obuf, buf_len);
		if (!buf_p) {
			snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN, "line %u "
				"FAILED: %s", __LINE__,
				"No room to append mbuf");
			status = TEST_FAILED;
			goto error_exit;
		}
		memset(buf_p, 0, buf_len);
	}

	sym_op->m_src = ibuf;

	if (t->feature_mask & BLOCKCIPHER_TEST_FEATURE_OOP) {
		sym_op->m_dst = obuf;
		iobuf = obuf;
	} else {
		sym_op->m_dst = NULL;
		iobuf = ibuf;
	}

	/* sessionless op requires allocate xform using
	 * rte_crypto_op_sym_xforms_alloc(), otherwise rte_zmalloc()
	 * is used
	 */
	if (t->feature_mask & BLOCKCIPHER_TEST_FEATURE_SESSIONLESS) {
		uint32_t n_xforms = 0;

		if (t->op_mask & BLOCKCIPHER_TEST_OP_CIPHER)
			n_xforms++;
		if (t->op_mask & BLOCKCIPHER_TEST_OP_AUTH)
			n_xforms++;

		if (rte_crypto_op_sym_xforms_alloc(op, n_xforms)
			== NULL) {
			snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN, "line %u "
				"FAILED: %s", __LINE__, "Failed to "
				"allocate space for crypto transforms");
			status = TEST_FAILED;
			goto error_exit;
		}
	} else {
		cipher_xform = rte_zmalloc(NULL,
			sizeof(struct rte_crypto_sym_xform), 0);

		auth_xform = rte_zmalloc(NULL,
			sizeof(struct rte_crypto_sym_xform), 0);

		if (!cipher_xform || !auth_xform) {
			snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN, "line %u "
				"FAILED: %s", __LINE__, "Failed to "
				"allocate memory for crypto transforms");
			status = TEST_FAILED;
			goto error_exit;
		}
	}

	/* preparing xform, for sessioned op, init_xform is initialized
	 * here and later as param in rte_cryptodev_sym_session_create() call
	 */
	if (t->op_mask == BLOCKCIPHER_TEST_OP_ENC_AUTH_GEN) {
		if (t->feature_mask & BLOCKCIPHER_TEST_FEATURE_SESSIONLESS) {
			cipher_xform = op->sym->xform;
			auth_xform = cipher_xform->next;
			auth_xform->next = NULL;
		} else {
			cipher_xform->next = auth_xform;
			auth_xform->next = NULL;
			init_xform = cipher_xform;
		}
	} else if (t->op_mask == BLOCKCIPHER_TEST_OP_AUTH_VERIFY_DEC) {
		if (t->feature_mask & BLOCKCIPHER_TEST_FEATURE_SESSIONLESS) {
			auth_xform = op->sym->xform;
			cipher_xform = auth_xform->next;
			cipher_xform->next = NULL;
		} else {
			auth_xform->next = cipher_xform;
			cipher_xform->next = NULL;
			init_xform = auth_xform;
		}
	} else if (t->op_mask == BLOCKCIPHER_TEST_OP_AUTH_GEN_ENC) {
		if (t->feature_mask & BLOCKCIPHER_TEST_FEATURE_SESSIONLESS) {
			auth_xform = op->sym->xform;
			cipher_xform = auth_xform->next;
			cipher_xform->next = NULL;
		} else {
			auth_xform->next = cipher_xform;
			cipher_xform->next = NULL;
			init_xform = auth_xform;
		}
	} else if (t->op_mask == BLOCKCIPHER_TEST_OP_DEC_AUTH_VERIFY) {
		if (t->feature_mask & BLOCKCIPHER_TEST_FEATURE_SESSIONLESS) {
			cipher_xform = op->sym->xform;
			auth_xform = cipher_xform->next;
			auth_xform->next = NULL;
		} else {
			cipher_xform->next = auth_xform;
			auth_xform->next = NULL;
			init_xform = cipher_xform;
		}
	} else if ((t->op_mask == BLOCKCIPHER_TEST_OP_ENCRYPT) ||
			(t->op_mask == BLOCKCIPHER_TEST_OP_DECRYPT)) {
		if (t->feature_mask & BLOCKCIPHER_TEST_FEATURE_SESSIONLESS)
			cipher_xform = op->sym->xform;
		else
			init_xform = cipher_xform;
		cipher_xform->next = NULL;
	} else if ((t->op_mask == BLOCKCIPHER_TEST_OP_AUTH_GEN) ||
			(t->op_mask == BLOCKCIPHER_TEST_OP_AUTH_VERIFY)) {
		if (t->feature_mask & BLOCKCIPHER_TEST_FEATURE_SESSIONLESS)
			auth_xform = op->sym->xform;
		else
			init_xform = auth_xform;
		auth_xform->next = NULL;
	} else {
		snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN,
			"line %u FAILED: %s",
			__LINE__, "Unrecognized operation");
		status = TEST_FAILED;
		goto error_exit;
	}

	/*configure xforms & sym_op cipher and auth data*/
	if (t->op_mask & BLOCKCIPHER_TEST_OP_CIPHER) {
		cipher_xform->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
		cipher_xform->cipher.algo = tdata->crypto_algo;
		if (t->op_mask & BLOCKCIPHER_TEST_OP_ENCRYPT)
			cipher_xform->cipher.op =
				RTE_CRYPTO_CIPHER_OP_ENCRYPT;
		else
			cipher_xform->cipher.op =
				RTE_CRYPTO_CIPHER_OP_DECRYPT;
		cipher_xform->cipher.key.data = cipher_key;
		cipher_xform->cipher.key.length = tdata->cipher_key.len;
		cipher_xform->cipher.iv.offset = IV_OFFSET;
		cipher_xform->cipher.dataunit_len = tdata->xts_dataunit_len;

		if (tdata->crypto_algo == RTE_CRYPTO_CIPHER_NULL)
			cipher_xform->cipher.iv.length = 0;
		else
			cipher_xform->cipher.iv.length = tdata->iv.len;

		sym_op->cipher.data.offset = tdata->cipher_offset;
		sym_op->cipher.data.length = tdata->ciphertext.len -
				tdata->cipher_offset;
		if (t->op_mask & BLOCKCIPHER_TEST_OP_DIGEST_ENCRYPTED) {
			sym_op->cipher.data.length += tdata->digest.len;
			sym_op->cipher.data.length += pad_len;
		}
		rte_memcpy(rte_crypto_op_ctod_offset(op, uint8_t *, IV_OFFSET),
				tdata->iv.data,
				tdata->iv.len);
	}

	if (t->op_mask & BLOCKCIPHER_TEST_OP_AUTH) {
		uint32_t digest_offset = tdata->ciphertext.len;

		auth_xform->type = RTE_CRYPTO_SYM_XFORM_AUTH;
		auth_xform->auth.algo = tdata->auth_algo;
		auth_xform->auth.key.length = tdata->auth_key.len;
		auth_xform->auth.key.data = auth_key;
		auth_xform->auth.digest_length = digest_len;

		if (t->op_mask & BLOCKCIPHER_TEST_OP_AUTH_GEN) {
			auth_xform->auth.op = RTE_CRYPTO_AUTH_OP_GENERATE;
			sym_op->auth.digest.data = pktmbuf_mtod_offset
				(iobuf, digest_offset);
			sym_op->auth.digest.phys_addr =
				pktmbuf_iova_offset(iobuf,
					digest_offset);
		} else {
			auth_xform->auth.op = RTE_CRYPTO_AUTH_OP_VERIFY;
			sym_op->auth.digest.data = pktmbuf_mtod_offset
				(sym_op->m_src, digest_offset);
			sym_op->auth.digest.phys_addr =
				pktmbuf_iova_offset(sym_op->m_src,
					digest_offset);
		}

		sym_op->auth.data.offset = tdata->auth_offset;
		sym_op->auth.data.length = tdata->ciphertext.len -
				tdata->auth_offset;
	}

	/**
	 * Create session for sessioned op. For mbuf iteration test,
	 * skip the session creation for the second iteration.
	 */
	if (!(t->feature_mask & BLOCKCIPHER_TEST_FEATURE_SESSIONLESS) &&
			nb_iterates == 0) {
		sess = rte_cryptodev_sym_session_create(dev_id, init_xform,
				sess_mpool);
		if (sess == NULL) {
			snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN, "UNSUPPORTED");
			status = TEST_SKIPPED;
			goto error_exit;
		}
		if (!sess || status < 0) {
			snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN, "line %u "
				"FAILED: %s", __LINE__,
				"Session creation failed");
			status = TEST_FAILED;
			goto error_exit;
		}

		/* attach symmetric crypto session to crypto operations */
		rte_crypto_op_attach_sym_session(op, sess);
	}

	debug_hexdump(stdout, "m_src(before):",
			sym_op->m_src->buf_addr, sym_op->m_src->buf_len);
	rte_memcpy(tmp_src_buf, sym_op->m_src->buf_addr,
						sym_op->m_src->buf_len);
	if (t->feature_mask & BLOCKCIPHER_TEST_FEATURE_OOP) {
		debug_hexdump(stdout, "m_dst(before):",
			sym_op->m_dst->buf_addr, sym_op->m_dst->buf_len);
		rte_memcpy(tmp_dst_buf, sym_op->m_dst->buf_addr,
						sym_op->m_dst->buf_len);
	}

	/* Process crypto operation */
	if (global_api_test_type == CRYPTODEV_RAW_API_TEST) {
		uint8_t is_cipher = 0, is_auth = 0;
		if (t->op_mask & BLOCKCIPHER_TEST_OP_CIPHER)
			is_cipher = 1;
		if (t->op_mask & BLOCKCIPHER_TEST_OP_AUTH)
			is_auth = 1;

		process_sym_raw_dp_op(dev_id, 0, op, is_cipher, is_auth, 0,
				tdata->iv.len);
	} else {
		if (rte_cryptodev_enqueue_burst(dev_id, 0, &op, 1) != 1) {
			snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN,
				"line %u FAILED: %s",
				__LINE__, "Error sending packet for encryption");
			status = TEST_FAILED;
			goto error_exit;
		}

		op = NULL;

		while (rte_cryptodev_dequeue_burst(dev_id, 0, &op, 1) == 0)
			rte_pause();

		if (!op) {
			snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN,
				"line %u FAILED: %s",
				__LINE__, "Failed to process sym crypto op");
			status = TEST_FAILED;
			goto error_exit;
		}
	}

	debug_hexdump(stdout, "m_src(after):",
			sym_op->m_src->buf_addr, sym_op->m_src->buf_len);
	if (t->feature_mask & BLOCKCIPHER_TEST_FEATURE_OOP)
		debug_hexdump(stdout, "m_dst(after):",
			sym_op->m_dst->buf_addr, sym_op->m_dst->buf_len);

	/* Verify results */
	if (op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
		if ((t->op_mask & BLOCKCIPHER_TEST_OP_AUTH_VERIFY) &&
			(op->status == RTE_CRYPTO_OP_STATUS_AUTH_FAILED))
			snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN, "line %u "
				"FAILED: Digest verification failed "
				"(0x%X)", __LINE__, op->status);
		else
			snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN, "line %u "
				"FAILED: Operation failed "
				"(0x%X)", __LINE__, op->status);
		status = TEST_FAILED;
		goto error_exit;
	}

	if (t->op_mask & BLOCKCIPHER_TEST_OP_CIPHER) {
		uint8_t buffer[2048];
		const uint8_t *compare_ref;
		uint32_t compare_len;

		if (t->op_mask & BLOCKCIPHER_TEST_OP_ENCRYPT) {
			compare_ref = tdata->ciphertext.data +
					tdata->cipher_offset;
			compare_len = tdata->ciphertext.len -
					tdata->cipher_offset;
			if (t->op_mask & BLOCKCIPHER_TEST_OP_DIGEST_ENCRYPTED)
				compare_len += tdata->digest.len;
		} else {
			compare_ref = tdata->plaintext.data +
					tdata->cipher_offset;
			compare_len = tdata->plaintext.len -
					tdata->cipher_offset;
		}

		if (memcmp(rte_pktmbuf_read(iobuf, tdata->cipher_offset,
				compare_len, buffer), compare_ref,
				compare_len)) {
			snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN, "line %u "
				"FAILED: %s", __LINE__,
				"Crypto data not as expected");
			status = TEST_FAILED;
			goto error_exit;
		}
	}

	/* Check digest data only in enc-then-auth_gen case.
	 * In auth_gen-then-enc case, cipher text contains both encrypted
	 * plain text and encrypted digest value. If cipher text is correct,
	 * it implies digest is also generated properly.
	 */
	if (!(t->op_mask & BLOCKCIPHER_TEST_OP_DIGEST_ENCRYPTED))
		if (t->op_mask & BLOCKCIPHER_TEST_OP_AUTH_GEN) {
			uint8_t *auth_res = pktmbuf_mtod_offset(iobuf,
						tdata->ciphertext.len);

			if (memcmp(auth_res, tdata->digest.data, digest_len)) {
				snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN, "line %u "
					"FAILED: %s", __LINE__, "Generated "
					"digest data not as expected");
				status = TEST_FAILED;
				goto error_exit;
			}
		}

	/* The only parts that should have changed in the buffer are
	 * plaintext/ciphertext and digest.
	 * In OOP only the dest buffer should change.
	 */
	if (t->feature_mask & BLOCKCIPHER_TEST_FEATURE_OOP) {
		struct rte_mbuf *mbuf;
		uint8_t value;
		uint32_t head_unchanged_len, changed_len = 0;
		uint32_t i;
		uint32_t hdroom_used = 0, tlroom_used = 0;
		uint32_t hdroom = 0;

		mbuf = sym_op->m_src;
		/*
		 * Crypto PMDs specify the headroom & tailroom it would use
		 * when processing the crypto operation. PMD is free to modify
		 * this space, and so the verification check should skip that
		 * block.
		 */
		hdroom_used = dev_info.min_mbuf_headroom_req;
		tlroom_used = dev_info.min_mbuf_tailroom_req;

		/* Get headroom */
		hdroom = rte_pktmbuf_headroom(mbuf);

		head_unchanged_len = mbuf->buf_len;

		for (i = 0; i < mbuf->buf_len; i++) {

			/* Skip headroom used by PMD */
			if (i == hdroom - hdroom_used)
				i += hdroom_used;

			/* Skip tailroom used by PMD */
			if (i == (hdroom + mbuf->data_len))
				i += tlroom_used;

			value = *((uint8_t *)(mbuf->buf_addr)+i);
			if (value != tmp_src_buf[i]) {
				snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN,
	"line %u FAILED: OOP src outer mbuf data (0x%x) not as expected (0x%x)",
					__LINE__, value, tmp_src_buf[i]);
				status = TEST_FAILED;
				goto error_exit;
			}
		}

		mbuf = sym_op->m_dst;
		if (t->op_mask & BLOCKCIPHER_TEST_OP_AUTH) {
			head_unchanged_len = hdroom + sym_op->auth.data.offset;
			changed_len = sym_op->auth.data.length;
			if (t->op_mask & BLOCKCIPHER_TEST_OP_AUTH_GEN)
				changed_len += digest_len;
		} else {
			/* cipher-only */
			head_unchanged_len = hdroom +
					sym_op->cipher.data.offset;
			changed_len = sym_op->cipher.data.length;
		}

		if (t->op_mask & BLOCKCIPHER_TEST_OP_DIGEST_ENCRYPTED)
			changed_len = sym_op->cipher.data.length +
				digest_len + pad_len;

		for (i = 0; i < mbuf->buf_len; i++) {
			if (i == head_unchanged_len)
				i += changed_len;
			value = *((uint8_t *)(mbuf->buf_addr)+i);
			if (value != tmp_dst_buf[i]) {
				snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN,
				"line %u FAILED: OOP dst outer mbuf data "
				"(0x%x) not as expected (0x%x)",
				__LINE__, value, tmp_dst_buf[i]);
				status = TEST_FAILED;
				goto error_exit;
			}
		}

		if (!nb_iterates) {
			nb_iterates++;
			goto iterate;
		}
	} else {
		/* In-place operation */
		struct rte_mbuf *mbuf;
		uint8_t value;
		uint32_t head_unchanged_len = 0, changed_len = 0;
		uint32_t i;
		uint32_t hdroom_used = 0, tlroom_used = 0;
		uint32_t hdroom = 0;

		/*
		 * Crypto PMDs specify the headroom & tailroom it would use
		 * when processing the crypto operation. PMD is free to modify
		 * this space, and so the verification check should skip that
		 * block.
		 */
		hdroom_used = dev_info.min_mbuf_headroom_req;
		tlroom_used = dev_info.min_mbuf_tailroom_req;

		mbuf = sym_op->m_src;

		/* Get headroom */
		hdroom = rte_pktmbuf_headroom(mbuf);

		if (t->op_mask & BLOCKCIPHER_TEST_OP_CIPHER) {
			head_unchanged_len = hdroom +
					sym_op->cipher.data.offset;
			changed_len = sym_op->cipher.data.length;
		} else {
			/* auth-only */
			head_unchanged_len = hdroom +
					sym_op->auth.data.offset +
					sym_op->auth.data.length;
			changed_len = 0;
		}

		if (t->op_mask & BLOCKCIPHER_TEST_OP_AUTH_GEN)
			changed_len += digest_len;

		if (t->op_mask & BLOCKCIPHER_TEST_OP_DIGEST_ENCRYPTED)
			changed_len = sym_op->cipher.data.length;

		for (i = 0; i < mbuf->buf_len; i++) {

			/* Skip headroom used by PMD */
			if (i == hdroom - hdroom_used)
				i += hdroom_used;

			if (i == head_unchanged_len)
				i += changed_len;

			/* Skip tailroom used by PMD */
			if (i == (hdroom + mbuf->data_len))
				i += tlroom_used;

			value = *((uint8_t *)(mbuf->buf_addr)+i);
			if (value != tmp_src_buf[i]) {
				snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN,
				"line %u FAILED: outer mbuf data (0x%x) "
				"not as expected (0x%x)",
				__LINE__, value, tmp_src_buf[i]);
				status = TEST_FAILED;
				goto error_exit;
			}
		}
	}

	snprintf(test_msg, BLOCKCIPHER_TEST_MSG_LEN, "PASS");

error_exit:
	if (!(t->feature_mask & BLOCKCIPHER_TEST_FEATURE_SESSIONLESS)) {
		if (sess)
			rte_cryptodev_sym_session_free(dev_id, sess);
		rte_free(cipher_xform);
		rte_free(auth_xform);
	}

	rte_crypto_op_free(op);

	rte_pktmbuf_free(obuf);

	rte_pktmbuf_free(ibuf);

	return status;
}

static int
blockcipher_test_case_run(const void *data)
{
	const struct blockcipher_test_case *tc_data = data;
	int status;
	char test_msg[BLOCKCIPHER_TEST_MSG_LEN + 1];

	status = test_blockcipher_one_case(tc_data,
			p_testsuite_params->mbuf_pool,
			p_testsuite_params->op_mpool,
			p_testsuite_params->session_mpool,
			p_testsuite_params->valid_devs[0],
			test_msg);
	return status;
}

static int
aes_chain_setup(void)
{
	uint8_t dev_id = p_testsuite_params->valid_devs[0];
	struct rte_cryptodev_info dev_info;
	uint64_t feat_flags;
	const enum rte_crypto_cipher_algorithm ciphers[] = {
		RTE_CRYPTO_CIPHER_NULL,
		RTE_CRYPTO_CIPHER_AES_CTR,
		RTE_CRYPTO_CIPHER_AES_CBC
	};
	const enum rte_crypto_auth_algorithm auths[] = {
		RTE_CRYPTO_AUTH_NULL,
		RTE_CRYPTO_AUTH_SHA1_HMAC,
		RTE_CRYPTO_AUTH_AES_XCBC_MAC,
		RTE_CRYPTO_AUTH_SHA256_HMAC,
		RTE_CRYPTO_AUTH_SHA512_HMAC,
		RTE_CRYPTO_AUTH_SHA224_HMAC,
		RTE_CRYPTO_AUTH_SHA384_HMAC
	};

	rte_cryptodev_info_get(dev_id, &dev_info);
	feat_flags = dev_info.feature_flags;

	if (!(feat_flags & RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO) ||
			((global_api_test_type == CRYPTODEV_RAW_API_TEST) &&
			!(feat_flags & RTE_CRYPTODEV_FF_SYM_RAW_DP))) {
		RTE_LOG(INFO, USER1, "Feature flag requirements for AES Chain "
				"testsuite not met\n");
		return TEST_SKIPPED;
	}

	if (check_cipher_capabilities_supported(ciphers, RTE_DIM(ciphers)) != 0
			&& check_auth_capabilities_supported(auths,
			RTE_DIM(auths)) != 0) {
		RTE_LOG(INFO, USER1, "Capability requirements for AES Chain "
				"testsuite not met\n");
		return TEST_SKIPPED;
	}

	return 0;
}

static int
aes_cipheronly_setup(void)
{
	uint8_t dev_id = p_testsuite_params->valid_devs[0];
	struct rte_cryptodev_info dev_info;
	uint64_t feat_flags;
	const enum rte_crypto_cipher_algorithm ciphers[] = {
		RTE_CRYPTO_CIPHER_NULL,
		RTE_CRYPTO_CIPHER_AES_CTR,
		RTE_CRYPTO_CIPHER_AES_CBC,
		RTE_CRYPTO_CIPHER_AES_ECB,
		RTE_CRYPTO_CIPHER_AES_XTS
	};
	const enum rte_crypto_auth_algorithm auths[] = {
		RTE_CRYPTO_AUTH_NULL,
		RTE_CRYPTO_AUTH_SHA1_HMAC,
		RTE_CRYPTO_AUTH_AES_XCBC_MAC
	};

	rte_cryptodev_info_get(dev_id, &dev_info);
	feat_flags = dev_info.feature_flags;

	if (!(feat_flags & RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO) ||
			((global_api_test_type == CRYPTODEV_RAW_API_TEST) &&
			!(feat_flags & RTE_CRYPTODEV_FF_SYM_RAW_DP))) {
		RTE_LOG(INFO, USER1, "Feature flag requirements for AES Cipheronly "
				"testsuite not met\n");
		return TEST_SKIPPED;
	}

	if (check_cipher_capabilities_supported(ciphers, RTE_DIM(ciphers)) != 0
			&& check_auth_capabilities_supported(auths,
			RTE_DIM(auths)) != 0) {
		RTE_LOG(INFO, USER1, "Capability requirements for AES Cipheronly "
				"testsuite not met\n");
		return TEST_SKIPPED;
	}

	return 0;
}

static int
aes_docsis_setup(void)
{
	uint8_t dev_id = p_testsuite_params->valid_devs[0];
	struct rte_cryptodev_info dev_info;
	uint64_t feat_flags;
	const enum rte_crypto_cipher_algorithm ciphers[] = {
		RTE_CRYPTO_CIPHER_AES_DOCSISBPI
	};

	rte_cryptodev_info_get(dev_id, &dev_info);
	feat_flags = dev_info.feature_flags;

	/* Data-path service does not support DOCSIS yet */
	if (!(feat_flags & RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO) ||
			(global_api_test_type == CRYPTODEV_RAW_API_TEST)) {
		RTE_LOG(INFO, USER1, "Feature flag requirements for AES Docsis "
				"testsuite not met\n");
		return TEST_SKIPPED;
	}

	if (check_cipher_capabilities_supported(ciphers, RTE_DIM(ciphers)) != 0) {
		RTE_LOG(INFO, USER1, "Capability requirements for AES Docsis "
				"testsuite not met\n");
		return TEST_SKIPPED;
	}

	return 0;
}

static int
triple_des_chain_setup(void)
{
	uint8_t dev_id = p_testsuite_params->valid_devs[0];
	struct rte_cryptodev_info dev_info;
	uint64_t feat_flags;
	const enum rte_crypto_cipher_algorithm ciphers[] = {
		RTE_CRYPTO_CIPHER_3DES_CTR,
		RTE_CRYPTO_CIPHER_3DES_CBC
	};
	const enum rte_crypto_auth_algorithm auths[] = {
		RTE_CRYPTO_AUTH_SHA1_HMAC,
		RTE_CRYPTO_AUTH_SHA1
	};

	rte_cryptodev_info_get(dev_id, &dev_info);
	feat_flags = dev_info.feature_flags;

	if (!(feat_flags & RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO) ||
			((global_api_test_type == CRYPTODEV_RAW_API_TEST) &&
			!(feat_flags & RTE_CRYPTODEV_FF_SYM_RAW_DP))) {
		RTE_LOG(INFO, USER1, "Feature flag requirements for 3DES Chain "
				"testsuite not met\n");
		return TEST_SKIPPED;
	}

	if (check_cipher_capabilities_supported(ciphers, RTE_DIM(ciphers)) != 0
			&& check_auth_capabilities_supported(auths,
			RTE_DIM(auths)) != 0) {
		RTE_LOG(INFO, USER1, "Capability requirements for 3DES Chain "
				"testsuite not met\n");
		return TEST_SKIPPED;
	}

	return 0;
}

static int
triple_des_cipheronly_setup(void)
{
	uint8_t dev_id = p_testsuite_params->valid_devs[0];
	struct rte_cryptodev_info dev_info;
	uint64_t feat_flags;
	const enum rte_crypto_cipher_algorithm ciphers[] = {
		RTE_CRYPTO_CIPHER_3DES_CTR,
		RTE_CRYPTO_CIPHER_3DES_CBC
	};

	rte_cryptodev_info_get(dev_id, &dev_info);
	feat_flags = dev_info.feature_flags;

	if (!(feat_flags & RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO) ||
			((global_api_test_type == CRYPTODEV_RAW_API_TEST) &&
			!(feat_flags & RTE_CRYPTODEV_FF_SYM_RAW_DP))) {
		RTE_LOG(INFO, USER1, "Feature flag requirements for 3DES "
				"Cipheronly testsuite not met\n");
		return TEST_SKIPPED;
	}

	if (check_cipher_capabilities_supported(ciphers, RTE_DIM(ciphers)) != 0) {
		RTE_LOG(INFO, USER1, "Capability requirements for 3DES "
				"Cipheronly testsuite not met\n");
		return TEST_SKIPPED;
	}

	return 0;
}

static int
des_cipheronly_setup(void)
{
	uint8_t dev_id = p_testsuite_params->valid_devs[0];
	struct rte_cryptodev_info dev_info;
	uint64_t feat_flags;
	const enum rte_crypto_cipher_algorithm ciphers[] = {
		RTE_CRYPTO_CIPHER_DES_CBC
	};

	rte_cryptodev_info_get(dev_id, &dev_info);
	feat_flags = dev_info.feature_flags;

	if (!(feat_flags & RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO) ||
			((global_api_test_type == CRYPTODEV_RAW_API_TEST) &&
			!(feat_flags & RTE_CRYPTODEV_FF_SYM_RAW_DP))) {
		RTE_LOG(INFO, USER1, "Feature flag requirements for DES "
				"Cipheronly testsuite not met\n");
		return TEST_SKIPPED;
	}

	if (check_cipher_capabilities_supported(ciphers, RTE_DIM(ciphers)) != 0) {
		RTE_LOG(INFO, USER1, "Capability requirements for DES "
				"Cipheronly testsuite not met\n");
		return TEST_SKIPPED;
	}

	return 0;
}

static int
des_docsis_setup(void)
{
	uint8_t dev_id = p_testsuite_params->valid_devs[0];
	struct rte_cryptodev_info dev_info;
	uint64_t feat_flags;
	const enum rte_crypto_cipher_algorithm ciphers[] = {
		RTE_CRYPTO_CIPHER_DES_DOCSISBPI
	};

	rte_cryptodev_info_get(dev_id, &dev_info);
	feat_flags = dev_info.feature_flags;

	/* Data-path service does not support DOCSIS yet */
	if (!(feat_flags & RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO) ||
			(global_api_test_type == CRYPTODEV_RAW_API_TEST)) {
		RTE_LOG(INFO, USER1, "Feature flag requirements for DES Docsis "
				"testsuite not met\n");
		return TEST_SKIPPED;
	}

	if (check_cipher_capabilities_supported(ciphers, RTE_DIM(ciphers)) != 0) {
		RTE_LOG(INFO, USER1, "Capability requirements for DES Docsis "
				"testsuite not met\n");
		return TEST_SKIPPED;
	}

	return 0;
}

static int
authonly_setup(void)
{
	uint8_t dev_id = p_testsuite_params->valid_devs[0];
	struct rte_cryptodev_info dev_info;
	uint64_t feat_flags;
	const enum rte_crypto_auth_algorithm auths[] = {
		RTE_CRYPTO_AUTH_MD5,
		RTE_CRYPTO_AUTH_MD5_HMAC,
		RTE_CRYPTO_AUTH_SHA1,
		RTE_CRYPTO_AUTH_SHA1_HMAC,
		RTE_CRYPTO_AUTH_SHA224,
		RTE_CRYPTO_AUTH_SHA224_HMAC,
		RTE_CRYPTO_AUTH_SHA256,
		RTE_CRYPTO_AUTH_SHA256_HMAC,
		RTE_CRYPTO_AUTH_SHA384,
		RTE_CRYPTO_AUTH_SHA384_HMAC,
		RTE_CRYPTO_AUTH_SHA512,
		RTE_CRYPTO_AUTH_SHA512_HMAC,
		RTE_CRYPTO_AUTH_AES_CMAC,
		RTE_CRYPTO_AUTH_NULL,
		RTE_CRYPTO_AUTH_AES_XCBC_MAC
	};

	rte_cryptodev_info_get(dev_id, &dev_info);
	feat_flags = dev_info.feature_flags;

	if (!(feat_flags & RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO) ||
			((global_api_test_type == CRYPTODEV_RAW_API_TEST) &&
			!(feat_flags & RTE_CRYPTODEV_FF_SYM_RAW_DP))) {
		RTE_LOG(INFO, USER1, "Feature flag requirements for Auth Only "
				"testsuite not met\n");
		return TEST_SKIPPED;
	}

	if (check_auth_capabilities_supported(auths, RTE_DIM(auths)) != 0) {
		RTE_LOG(INFO, USER1, "Capability requirements for Auth Only "
				"testsuite not met\n");
		return TEST_SKIPPED;
	}

	return 0;
}

struct unit_test_suite *
build_blockcipher_test_suite(enum blockcipher_test_type test_type)
{
	int i, n_test_cases = 0;
	struct unit_test_suite *ts;
	const char *ts_name = NULL;
	const struct blockcipher_test_case *blk_tcs;
	struct unit_test_case *tc;
	int (*ts_setup)(void) = NULL;

	switch (test_type) {
	case BLKCIPHER_AES_CHAIN_TYPE:
		n_test_cases = RTE_DIM(aes_chain_test_cases);
		blk_tcs = aes_chain_test_cases;
		ts_name = "AES Chain";
		ts_setup = aes_chain_setup;
		break;
	case BLKCIPHER_AES_CIPHERONLY_TYPE:
		n_test_cases = RTE_DIM(aes_cipheronly_test_cases);
		blk_tcs = aes_cipheronly_test_cases;
		ts_name = "AES Cipher Only";
		ts_setup = aes_cipheronly_setup;
		break;
	case BLKCIPHER_AES_DOCSIS_TYPE:
		n_test_cases = RTE_DIM(aes_docsis_test_cases);
		blk_tcs = aes_docsis_test_cases;
		ts_name = "AES Docsis";
		ts_setup = aes_docsis_setup;
		break;
	case BLKCIPHER_3DES_CHAIN_TYPE:
		n_test_cases = RTE_DIM(triple_des_chain_test_cases);
		blk_tcs = triple_des_chain_test_cases;
		ts_name = "3DES Chain";
		ts_setup = triple_des_chain_setup;
		break;
	case BLKCIPHER_3DES_CIPHERONLY_TYPE:
		n_test_cases = RTE_DIM(triple_des_cipheronly_test_cases);
		blk_tcs = triple_des_cipheronly_test_cases;
		ts_name = "3DES Cipher Only";
		ts_setup = triple_des_cipheronly_setup;
		break;
	case BLKCIPHER_DES_CIPHERONLY_TYPE:
		n_test_cases = RTE_DIM(des_cipheronly_test_cases);
		blk_tcs = des_cipheronly_test_cases;
		ts_name = "DES Cipher Only";
		ts_setup = des_cipheronly_setup;
		break;
	case BLKCIPHER_DES_DOCSIS_TYPE:
		n_test_cases = RTE_DIM(des_docsis_test_cases);
		blk_tcs = des_docsis_test_cases;
		ts_name = "DES Docsis";
		ts_setup = des_docsis_setup;
		break;
	case BLKCIPHER_AUTHONLY_TYPE:
		n_test_cases = RTE_DIM(hash_test_cases);
		blk_tcs = hash_test_cases;
		ts_name = "Auth Only";
		ts_setup = authonly_setup;
		break;
	default:
		return NULL;
	}

	ts = calloc(1, sizeof(struct unit_test_suite) +
			(sizeof(struct unit_test_case) * (n_test_cases + 1)));
	ts->suite_name = ts_name;
	ts->setup = ts_setup;

	for (i = 0; i < n_test_cases; i++) {
		tc = &ts->unit_test_cases[i];
		tc->name = blk_tcs[i].test_descr;
		tc->enabled = 1;
		tc->setup = ut_setup;
		tc->teardown = ut_teardown;
		tc->testcase = NULL;
		tc->testcase_with_data = blockcipher_test_case_run;
		tc->data = &blk_tcs[i];
	}
	tc = &ts->unit_test_cases[i];
	tc->name = NULL;
	tc->enabled = 0;
	tc->setup = NULL;
	tc->teardown = NULL;
	tc->testcase = NULL;
	tc->testcase_with_data = NULL;
	tc->data = NULL;

	return ts;
}

void
free_blockcipher_test_suite(struct unit_test_suite *ts)
{
	free(ts);
}
