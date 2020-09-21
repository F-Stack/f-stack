/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include <sys/stat.h>
#include <getopt.h>
#include <dirent.h>

#include <rte_cryptodev.h>
#include <rte_cryptodev_pmd.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>

#include "fips_validation.h"

#define REQ_FILE_PATH_KEYWORD	"req-file"
#define RSP_FILE_PATH_KEYWORD	"rsp-file"
#define FOLDER_KEYWORD		"path-is-folder"
#define CRYPTODEV_KEYWORD	"cryptodev"
#define CRYPTODEV_ID_KEYWORD	"cryptodev-id"

struct fips_test_vector vec;
struct fips_test_interim_info info;

struct cryptodev_fips_validate_env {
	const char *req_path;
	const char *rsp_path;
	uint32_t is_path_folder;
	uint32_t dev_id;
	struct rte_mempool *mpool;
	struct rte_mempool *op_pool;
	struct rte_mbuf *mbuf;
	struct rte_crypto_op *op;
	struct rte_cryptodev_sym_session *sess;
} env;

static int
cryptodev_fips_validate_app_int(void)
{
	struct rte_cryptodev_config conf = {rte_socket_id(), 1};
	struct rte_cryptodev_qp_conf qp_conf = {128};
	int ret;

	ret = rte_cryptodev_configure(env.dev_id, &conf);
	if (ret < 0)
		return ret;

	env.mpool = rte_pktmbuf_pool_create("FIPS_MEMPOOL", 128, 0, 0,
			UINT16_MAX, rte_socket_id());
	if (!env.mpool)
		return ret;

	ret = rte_cryptodev_queue_pair_setup(env.dev_id, 0, &qp_conf,
			rte_socket_id(), env.mpool);
	if (ret < 0)
		return ret;

	ret = -ENOMEM;

	env.op_pool = rte_crypto_op_pool_create(
			"FIPS_OP_POOL",
			RTE_CRYPTO_OP_TYPE_SYMMETRIC,
			1, 0,
			16,
			rte_socket_id());
	if (!env.op_pool)
		goto error_exit;

	env.mbuf = rte_pktmbuf_alloc(env.mpool);
	if (!env.mbuf)
		goto error_exit;

	env.op = rte_crypto_op_alloc(env.op_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	if (!env.op)
		goto error_exit;

	return 0;

error_exit:
	rte_mempool_free(env.mpool);
	if (env.op_pool)
		rte_mempool_free(env.op_pool);

	return ret;
}

static void
cryptodev_fips_validate_app_uninit(void)
{
	rte_pktmbuf_free(env.mbuf);
	rte_crypto_op_free(env.op);
	rte_cryptodev_sym_session_clear(env.dev_id, env.sess);
	rte_cryptodev_sym_session_free(env.sess);
	rte_mempool_free(env.mpool);
	rte_mempool_free(env.op_pool);
}

static int
fips_test_one_file(void);

static int
parse_cryptodev_arg(char *arg)
{
	int id = rte_cryptodev_get_dev_id(arg);

	if (id < 0) {
		RTE_LOG(ERR, USER1, "Error %i: invalid cryptodev name %s\n",
				id, arg);
		return id;
	}

	env.dev_id = (uint32_t)id;

	return 0;
}

static int
parse_cryptodev_id_arg(char *arg)
{
	uint32_t cryptodev_id;

	if (parser_read_uint32(&cryptodev_id, arg) < 0) {
		RTE_LOG(ERR, USER1, "Error %i: invalid cryptodev id %s\n",
				-EINVAL, arg);
		return -1;
	}


	if (!rte_cryptodev_pmd_is_valid_dev(cryptodev_id)) {
		RTE_LOG(ERR, USER1, "Error %i: invalid cryptodev id %s\n",
				cryptodev_id, arg);
		return -1;
	}

	env.dev_id = (uint32_t)cryptodev_id;

	return 0;
}

static void
cryptodev_fips_validate_usage(const char *prgname)
{
	printf("%s [EAL options] --\n"
		"  --%s: REQUEST-FILE-PATH\n"
		"  --%s: RESPONSE-FILE-PATH\n"
		"  --%s: indicating both paths are folders\n"
		"  --%s: CRYPTODEV-NAME\n"
		"  --%s: CRYPTODEV-ID-NAME\n",
		prgname, REQ_FILE_PATH_KEYWORD, RSP_FILE_PATH_KEYWORD,
		FOLDER_KEYWORD, CRYPTODEV_KEYWORD, CRYPTODEV_ID_KEYWORD);
}

static int
cryptodev_fips_validate_parse_args(int argc, char **argv)
{
	int opt, ret;
	char *prgname = argv[0];
	char **argvopt;
	int option_index;
	struct option lgopts[] = {
			{REQ_FILE_PATH_KEYWORD, required_argument, 0, 0},
			{RSP_FILE_PATH_KEYWORD, required_argument, 0, 0},
			{FOLDER_KEYWORD, no_argument, 0, 0},
			{CRYPTODEV_KEYWORD, required_argument, 0, 0},
			{CRYPTODEV_ID_KEYWORD, required_argument, 0, 0},
			{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "s:",
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		case 0:
			if (strcmp(lgopts[option_index].name,
					REQ_FILE_PATH_KEYWORD) == 0)
				env.req_path = optarg;
			else if (strcmp(lgopts[option_index].name,
					RSP_FILE_PATH_KEYWORD) == 0)
				env.rsp_path = optarg;
			else if (strcmp(lgopts[option_index].name,
					FOLDER_KEYWORD) == 0)
				env.is_path_folder = 1;
			else if (strcmp(lgopts[option_index].name,
					CRYPTODEV_KEYWORD) == 0) {
				ret = parse_cryptodev_arg(optarg);
				if (ret < 0) {
					cryptodev_fips_validate_usage(prgname);
					return -EINVAL;
				}
			} else if (strcmp(lgopts[option_index].name,
					CRYPTODEV_ID_KEYWORD) == 0) {
				ret = parse_cryptodev_id_arg(optarg);
				if (ret < 0) {
					cryptodev_fips_validate_usage(prgname);
					return -EINVAL;
				}
			} else {
				cryptodev_fips_validate_usage(prgname);
				return -EINVAL;
			}
			break;
		default:
			return -1;
		}
	}

	if (env.req_path == NULL || env.rsp_path == NULL ||
			env.dev_id == UINT32_MAX) {
		cryptodev_fips_validate_usage(prgname);
		return -EINVAL;
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		RTE_LOG(ERR, USER1, "Error %i: Failed init\n", ret);
		return -1;
	}

	argc -= ret;
	argv += ret;

	ret = cryptodev_fips_validate_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Failed to parse arguments!\n");

	ret = cryptodev_fips_validate_app_int();
	if (ret < 0) {
		RTE_LOG(ERR, USER1, "Error %i: Failed init\n", ret);
		return -1;
	}

	if (!env.is_path_folder) {
		printf("Processing file %s... ", env.req_path);

		ret = fips_test_init(env.req_path, env.rsp_path,
			rte_cryptodev_name_get(env.dev_id));
		if (ret < 0) {
			RTE_LOG(ERR, USER1, "Error %i: Failed test %s\n",
					ret, env.req_path);
			goto exit;
		}


		ret = fips_test_one_file();
		if (ret < 0) {
			RTE_LOG(ERR, USER1, "Error %i: Failed test %s\n",
					ret, env.req_path);
			goto exit;
		}

		printf("Done\n");

	} else {
		struct dirent *dir;
		DIR *d_req, *d_rsp;
		char req_path[1024];
		char rsp_path[1024];

		d_req = opendir(env.req_path);
		if (!d_req) {
			RTE_LOG(ERR, USER1, "Error %i: Path %s not exist\n",
					-EINVAL, env.req_path);
			goto exit;
		}

		d_rsp = opendir(env.rsp_path);
		if (!d_rsp) {
			ret = mkdir(env.rsp_path, 0700);
			if (ret == 0)
				d_rsp = opendir(env.rsp_path);
			else {
				RTE_LOG(ERR, USER1, "Error %i: Invalid %s\n",
						-EINVAL, env.rsp_path);
				goto exit;
			}
		}
		closedir(d_rsp);

		while ((dir = readdir(d_req)) != NULL) {
			if (strstr(dir->d_name, "req") == NULL)
				continue;

			snprintf(req_path, 1023, "%s/%s", env.req_path,
					dir->d_name);
			snprintf(rsp_path, 1023, "%s/%s", env.rsp_path,
					dir->d_name);
			strlcpy(strstr(rsp_path, "req"), "rsp", 4);

			printf("Processing file %s... ", req_path);

			ret = fips_test_init(req_path, rsp_path,
			rte_cryptodev_name_get(env.dev_id));
			if (ret < 0) {
				RTE_LOG(ERR, USER1, "Error %i: Failed test %s\n",
						ret, req_path);
				break;
			}

			ret = fips_test_one_file();
			if (ret < 0) {
				RTE_LOG(ERR, USER1, "Error %i: Failed test %s\n",
						ret, req_path);
				break;
			}

			printf("Done\n");
		}

		closedir(d_req);
	}


exit:
	fips_test_clear();
	cryptodev_fips_validate_app_uninit();

	return ret;

}

#define IV_OFF (sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op))
#define CRYPTODEV_FIPS_MAX_RETRIES	16

typedef int (*fips_test_one_case_t)(void);
typedef int (*fips_prepare_op_t)(void);
typedef int (*fips_prepare_xform_t)(struct rte_crypto_sym_xform *);

struct fips_test_ops {
	fips_prepare_xform_t prepare_xform;
	fips_prepare_op_t prepare_op;
	fips_test_one_case_t test;
} test_ops;

static int
prepare_cipher_op(void)
{
	struct rte_crypto_sym_op *sym = env.op->sym;
	uint8_t *iv = rte_crypto_op_ctod_offset(env.op, uint8_t *, IV_OFF);

	__rte_crypto_op_reset(env.op, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	rte_pktmbuf_reset(env.mbuf);

	sym->m_src = env.mbuf;
	sym->cipher.data.offset = 0;

	memcpy(iv, vec.iv.val, vec.iv.len);

	if (info.op == FIPS_TEST_ENC_AUTH_GEN) {
		uint8_t *pt;

		if (vec.pt.len > RTE_MBUF_MAX_NB_SEGS) {
			RTE_LOG(ERR, USER1, "PT len %u\n", vec.pt.len);
			return -EPERM;
		}

		pt = (uint8_t *)rte_pktmbuf_append(env.mbuf, vec.pt.len);

		if (!pt) {
			RTE_LOG(ERR, USER1, "Error %i: MBUF too small\n",
					-ENOMEM);
			return -ENOMEM;
		}

		memcpy(pt, vec.pt.val, vec.pt.len);
		sym->cipher.data.length = vec.pt.len;

	} else {
		uint8_t *ct;

		if (vec.ct.len > RTE_MBUF_MAX_NB_SEGS) {
			RTE_LOG(ERR, USER1, "CT len %u\n", vec.ct.len);
			return -EPERM;
		}

		ct = (uint8_t *)rte_pktmbuf_append(env.mbuf, vec.ct.len);

		if (!ct) {
			RTE_LOG(ERR, USER1, "Error %i: MBUF too small\n",
					-ENOMEM);
			return -ENOMEM;
		}

		memcpy(ct, vec.ct.val, vec.ct.len);
		sym->cipher.data.length = vec.ct.len;
	}

	rte_crypto_op_attach_sym_session(env.op, env.sess);

	return 0;
}

static int
prepare_auth_op(void)
{
	struct rte_crypto_sym_op *sym = env.op->sym;

	__rte_crypto_op_reset(env.op, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	rte_pktmbuf_reset(env.mbuf);

	sym->m_src = env.mbuf;
	sym->auth.data.offset = 0;

	if (info.op == FIPS_TEST_ENC_AUTH_GEN) {
		uint8_t *pt;

		if (vec.pt.len > RTE_MBUF_MAX_NB_SEGS) {
			RTE_LOG(ERR, USER1, "PT len %u\n", vec.pt.len);
			return -EPERM;
		}

		pt = (uint8_t *)rte_pktmbuf_append(env.mbuf, vec.pt.len +
				vec.cipher_auth.digest.len);

		if (!pt) {
			RTE_LOG(ERR, USER1, "Error %i: MBUF too small\n",
					-ENOMEM);
			return -ENOMEM;
		}

		memcpy(pt, vec.pt.val, vec.pt.len);
		sym->auth.data.length = vec.pt.len;
		sym->auth.digest.data = pt + vec.pt.len;
		sym->auth.digest.phys_addr = rte_pktmbuf_mtophys_offset(
				env.mbuf, vec.pt.len);

	} else {
		uint8_t *ct;

		if (vec.ct.len > RTE_MBUF_MAX_NB_SEGS) {
			RTE_LOG(ERR, USER1, "CT len %u\n", vec.ct.len);
			return -EPERM;
		}

		ct = (uint8_t *)rte_pktmbuf_append(env.mbuf,
				vec.ct.len + vec.cipher_auth.digest.len);

		if (!ct) {
			RTE_LOG(ERR, USER1, "Error %i: MBUF too small\n",
					-ENOMEM);
			return -ENOMEM;
		}

		memcpy(ct, vec.ct.val, vec.ct.len);
		sym->auth.data.length = vec.ct.len;
		sym->auth.digest.data = vec.cipher_auth.digest.val;
		sym->auth.digest.phys_addr = rte_malloc_virt2iova(
				sym->auth.digest.data);
	}

	rte_crypto_op_attach_sym_session(env.op, env.sess);

	return 0;
}

static int
prepare_aead_op(void)
{
	struct rte_crypto_sym_op *sym = env.op->sym;
	uint8_t *iv = rte_crypto_op_ctod_offset(env.op, uint8_t *, IV_OFF);

	__rte_crypto_op_reset(env.op, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	rte_pktmbuf_reset(env.mbuf);

	if (info.algo == FIPS_TEST_ALGO_AES_CCM)
		memcpy(iv + 1, vec.iv.val, vec.iv.len);
	else
		memcpy(iv, vec.iv.val, vec.iv.len);

	sym->m_src = env.mbuf;
	sym->aead.data.offset = 0;
	sym->aead.aad.data = vec.aead.aad.val;
	sym->aead.aad.phys_addr = rte_malloc_virt2iova(sym->aead.aad.data);

	if (info.op == FIPS_TEST_ENC_AUTH_GEN) {
		uint8_t *pt;

		if (vec.pt.len > RTE_MBUF_MAX_NB_SEGS) {
			RTE_LOG(ERR, USER1, "PT len %u\n", vec.pt.len);
			return -EPERM;
		}

		pt = (uint8_t *)rte_pktmbuf_append(env.mbuf,
				vec.pt.len + vec.aead.digest.len);

		if (!pt) {
			RTE_LOG(ERR, USER1, "Error %i: MBUF too small\n",
					-ENOMEM);
			return -ENOMEM;
		}

		memcpy(pt, vec.pt.val, vec.pt.len);
		sym->aead.data.length = vec.pt.len;
		sym->aead.digest.data = pt + vec.pt.len;
		sym->aead.digest.phys_addr = rte_pktmbuf_mtophys_offset(
				env.mbuf, vec.pt.len);
	} else {
		uint8_t *ct;

		if (vec.ct.len > RTE_MBUF_MAX_NB_SEGS) {
			RTE_LOG(ERR, USER1, "CT len %u\n", vec.ct.len);
			return -EPERM;
		}

		ct = (uint8_t *)rte_pktmbuf_append(env.mbuf, vec.ct.len);

		if (!ct) {
			RTE_LOG(ERR, USER1, "Error %i: MBUF too small\n",
					-ENOMEM);
			return -ENOMEM;
		}

		memcpy(ct, vec.ct.val, vec.ct.len);
		sym->aead.data.length = vec.ct.len;
		sym->aead.digest.data = vec.aead.digest.val;
		sym->aead.digest.phys_addr = rte_malloc_virt2iova(
				sym->aead.digest.data);
	}

	rte_crypto_op_attach_sym_session(env.op, env.sess);

	return 0;
}

static int
prepare_aes_xform(struct rte_crypto_sym_xform *xform)
{
	const struct rte_cryptodev_symmetric_capability *cap;
	struct rte_cryptodev_sym_capability_idx cap_idx;
	struct rte_crypto_cipher_xform *cipher_xform = &xform->cipher;

	xform->type = RTE_CRYPTO_SYM_XFORM_CIPHER;

	cipher_xform->algo = RTE_CRYPTO_CIPHER_AES_CBC;
	cipher_xform->op = (info.op == FIPS_TEST_ENC_AUTH_GEN) ?
			RTE_CRYPTO_CIPHER_OP_ENCRYPT :
			RTE_CRYPTO_CIPHER_OP_DECRYPT;
	cipher_xform->key.data = vec.cipher_auth.key.val;
	cipher_xform->key.length = vec.cipher_auth.key.len;
	cipher_xform->iv.length = vec.iv.len;
	cipher_xform->iv.offset = IV_OFF;

	cap_idx.algo.cipher = RTE_CRYPTO_CIPHER_AES_CBC;
	cap_idx.type = RTE_CRYPTO_SYM_XFORM_CIPHER;

	cap = rte_cryptodev_sym_capability_get(env.dev_id, &cap_idx);
	if (!cap) {
		RTE_LOG(ERR, USER1, "Failed to get capability for cdev %u\n",
				env.dev_id);
		return -EINVAL;
	}

	if (rte_cryptodev_sym_capability_check_cipher(cap,
			cipher_xform->key.length,
			cipher_xform->iv.length) != 0) {
		RTE_LOG(ERR, USER1, "PMD %s key length %u IV length %u\n",
				info.device_name, cipher_xform->key.length,
				cipher_xform->iv.length);
		return -EPERM;
	}

	return 0;
}

static int
prepare_tdes_xform(struct rte_crypto_sym_xform *xform)
{
	const struct rte_cryptodev_symmetric_capability *cap;
	struct rte_cryptodev_sym_capability_idx cap_idx;
	struct rte_crypto_cipher_xform *cipher_xform = &xform->cipher;

	xform->type = RTE_CRYPTO_SYM_XFORM_CIPHER;

	cipher_xform->algo = RTE_CRYPTO_CIPHER_3DES_CBC;
	cipher_xform->op = (info.op == FIPS_TEST_ENC_AUTH_GEN) ?
			RTE_CRYPTO_CIPHER_OP_ENCRYPT :
			RTE_CRYPTO_CIPHER_OP_DECRYPT;
	cipher_xform->key.data = vec.cipher_auth.key.val;
	cipher_xform->key.length = vec.cipher_auth.key.len;
	cipher_xform->iv.length = vec.iv.len;
	cipher_xform->iv.offset = IV_OFF;

	cap_idx.algo.cipher = RTE_CRYPTO_CIPHER_3DES_CBC;
	cap_idx.type = RTE_CRYPTO_SYM_XFORM_CIPHER;

	cap = rte_cryptodev_sym_capability_get(env.dev_id, &cap_idx);
	if (!cap) {
		RTE_LOG(ERR, USER1, "Failed to get capability for cdev %u\n",
				env.dev_id);
		return -EINVAL;
	}

	if (rte_cryptodev_sym_capability_check_cipher(cap,
			cipher_xform->key.length,
			cipher_xform->iv.length) != 0) {
		RTE_LOG(ERR, USER1, "PMD %s key length %u IV length %u\n",
				info.device_name, cipher_xform->key.length,
				cipher_xform->iv.length);
		return -EPERM;
	}

	return 0;
}

static int
prepare_hmac_xform(struct rte_crypto_sym_xform *xform)
{
	const struct rte_cryptodev_symmetric_capability *cap;
	struct rte_cryptodev_sym_capability_idx cap_idx;
	struct rte_crypto_auth_xform *auth_xform = &xform->auth;

	xform->type = RTE_CRYPTO_SYM_XFORM_AUTH;

	auth_xform->algo = info.interim_info.hmac_data.algo;
	auth_xform->op = RTE_CRYPTO_AUTH_OP_GENERATE;
	auth_xform->digest_length = vec.cipher_auth.digest.len;
	auth_xform->key.data = vec.cipher_auth.key.val;
	auth_xform->key.length = vec.cipher_auth.key.len;

	cap_idx.algo.auth = auth_xform->algo;
	cap_idx.type = RTE_CRYPTO_SYM_XFORM_AUTH;

	cap = rte_cryptodev_sym_capability_get(env.dev_id, &cap_idx);
	if (!cap) {
		RTE_LOG(ERR, USER1, "Failed to get capability for cdev %u\n",
				env.dev_id);
		return -EINVAL;
	}

	if (rte_cryptodev_sym_capability_check_auth(cap,
			auth_xform->key.length,
			auth_xform->digest_length, 0) != 0) {
		RTE_LOG(ERR, USER1, "PMD %s key length %u IV length %u\n",
				info.device_name, auth_xform->key.length,
				auth_xform->digest_length);
		return -EPERM;
	}

	return 0;
}

static int
prepare_gcm_xform(struct rte_crypto_sym_xform *xform)
{
	const struct rte_cryptodev_symmetric_capability *cap;
	struct rte_cryptodev_sym_capability_idx cap_idx;
	struct rte_crypto_aead_xform *aead_xform = &xform->aead;

	xform->type = RTE_CRYPTO_SYM_XFORM_AEAD;

	aead_xform->algo = RTE_CRYPTO_AEAD_AES_GCM;
	aead_xform->aad_length = vec.aead.aad.len;
	aead_xform->digest_length = vec.aead.digest.len;
	aead_xform->iv.offset = IV_OFF;
	aead_xform->iv.length = vec.iv.len;
	aead_xform->key.data = vec.aead.key.val;
	aead_xform->key.length = vec.aead.key.len;
	aead_xform->op = (info.op == FIPS_TEST_ENC_AUTH_GEN) ?
			RTE_CRYPTO_AEAD_OP_ENCRYPT :
			RTE_CRYPTO_AEAD_OP_DECRYPT;

	cap_idx.algo.aead = aead_xform->algo;
	cap_idx.type = RTE_CRYPTO_SYM_XFORM_AEAD;

	cap = rte_cryptodev_sym_capability_get(env.dev_id, &cap_idx);
	if (!cap) {
		RTE_LOG(ERR, USER1, "Failed to get capability for cdev %u\n",
				env.dev_id);
		return -EINVAL;
	}

	if (rte_cryptodev_sym_capability_check_aead(cap,
			aead_xform->key.length,
			aead_xform->digest_length, aead_xform->aad_length,
			aead_xform->iv.length) != 0) {
		RTE_LOG(ERR, USER1,
			"PMD %s key_len %u tag_len %u aad_len %u iv_len %u\n",
				info.device_name, aead_xform->key.length,
				aead_xform->digest_length,
				aead_xform->aad_length,
				aead_xform->iv.length);
		return -EPERM;
	}

	return 0;
}

static int
prepare_cmac_xform(struct rte_crypto_sym_xform *xform)
{
	const struct rte_cryptodev_symmetric_capability *cap;
	struct rte_cryptodev_sym_capability_idx cap_idx;
	struct rte_crypto_auth_xform *auth_xform = &xform->auth;

	xform->type = RTE_CRYPTO_SYM_XFORM_AUTH;

	auth_xform->algo = RTE_CRYPTO_AUTH_AES_CMAC;
	auth_xform->op = (info.op == FIPS_TEST_ENC_AUTH_GEN) ?
			RTE_CRYPTO_AUTH_OP_GENERATE : RTE_CRYPTO_AUTH_OP_VERIFY;
	auth_xform->digest_length = vec.cipher_auth.digest.len;
	auth_xform->key.data = vec.cipher_auth.key.val;
	auth_xform->key.length = vec.cipher_auth.key.len;

	cap_idx.algo.auth = auth_xform->algo;
	cap_idx.type = RTE_CRYPTO_SYM_XFORM_AUTH;

	cap = rte_cryptodev_sym_capability_get(env.dev_id, &cap_idx);
	if (!cap) {
		RTE_LOG(ERR, USER1, "Failed to get capability for cdev %u\n",
				env.dev_id);
		return -EINVAL;
	}

	if (rte_cryptodev_sym_capability_check_auth(cap,
			auth_xform->key.length,
			auth_xform->digest_length, 0) != 0) {
		RTE_LOG(ERR, USER1, "PMD %s key length %u IV length %u\n",
				info.device_name, auth_xform->key.length,
				auth_xform->digest_length);
		return -EPERM;
	}

	return 0;
}

static int
prepare_ccm_xform(struct rte_crypto_sym_xform *xform)
{
	const struct rte_cryptodev_symmetric_capability *cap;
	struct rte_cryptodev_sym_capability_idx cap_idx;
	struct rte_crypto_aead_xform *aead_xform = &xform->aead;

	xform->type = RTE_CRYPTO_SYM_XFORM_AEAD;

	aead_xform->algo = RTE_CRYPTO_AEAD_AES_CCM;
	aead_xform->aad_length = vec.aead.aad.len;
	aead_xform->digest_length = vec.aead.digest.len;
	aead_xform->iv.offset = IV_OFF;
	aead_xform->iv.length = vec.iv.len;
	aead_xform->key.data = vec.aead.key.val;
	aead_xform->key.length = vec.aead.key.len;
	aead_xform->op = (info.op == FIPS_TEST_ENC_AUTH_GEN) ?
			RTE_CRYPTO_AEAD_OP_ENCRYPT :
			RTE_CRYPTO_AEAD_OP_DECRYPT;

	cap_idx.algo.aead = aead_xform->algo;
	cap_idx.type = RTE_CRYPTO_SYM_XFORM_AEAD;

	cap = rte_cryptodev_sym_capability_get(env.dev_id, &cap_idx);
	if (!cap) {
		RTE_LOG(ERR, USER1, "Failed to get capability for cdev %u\n",
				env.dev_id);
		return -EINVAL;
	}

	if (rte_cryptodev_sym_capability_check_aead(cap,
			aead_xform->key.length,
			aead_xform->digest_length, aead_xform->aad_length,
			aead_xform->iv.length) != 0) {
		RTE_LOG(ERR, USER1,
			"PMD %s key_len %u tag_len %u aad_len %u iv_len %u\n",
				info.device_name, aead_xform->key.length,
				aead_xform->digest_length,
				aead_xform->aad_length,
				aead_xform->iv.length);
		return -EPERM;
	}

	return 0;
}

static void
get_writeback_data(struct fips_val *val)
{
	val->val = rte_pktmbuf_mtod(env.mbuf, uint8_t *);
	val->len = rte_pktmbuf_pkt_len(env.mbuf);
}

static int
fips_run_test(void)
{
	struct rte_crypto_sym_xform xform = {0};
	uint16_t n_deqd;
	int ret;

	ret = test_ops.prepare_xform(&xform);
	if (ret < 0)
		return ret;

	env.sess = rte_cryptodev_sym_session_create(env.mpool);
	if (!env.sess)
		return -ENOMEM;

	ret = rte_cryptodev_sym_session_init(env.dev_id,
			env.sess, &xform, env.mpool);
	if (ret < 0) {
		RTE_LOG(ERR, USER1, "Error %i: Init session\n",
				ret);
		goto exit;
	}

	ret = test_ops.prepare_op();
	if (ret < 0) {
		RTE_LOG(ERR, USER1, "Error %i: Prepare op\n",
				ret);
		goto exit;
	}

	if (rte_cryptodev_enqueue_burst(env.dev_id, 0, &env.op, 1) < 1) {
		RTE_LOG(ERR, USER1, "Error: Failed enqueue\n");
		ret = -1;
		goto exit;
	}

	do {
		struct rte_crypto_op *deqd_op;

		n_deqd = rte_cryptodev_dequeue_burst(env.dev_id, 0, &deqd_op,
				1);
	} while (n_deqd == 0);

	vec.status = env.op->status;

exit:
	rte_cryptodev_sym_session_clear(env.dev_id, env.sess);
	rte_cryptodev_sym_session_free(env.sess);
	env.sess = NULL;

	return ret;
}

static int
fips_generic_test(void)
{
	struct fips_val val;
	int ret;

	fips_test_write_one_case();

	ret = fips_run_test();
	if (ret < 0) {
		if (ret == -EPERM) {
			fprintf(info.fp_wr, "Bypass\n\n");
			return 0;
		}

		return ret;
	}

	get_writeback_data(&val);

	switch (info.file_type) {
	case FIPS_TYPE_REQ:
	case FIPS_TYPE_RSP:
		if (info.parse_writeback == NULL)
			return -EPERM;
		ret = info.parse_writeback(&val);
		if (ret < 0)
			return ret;
		break;
	case FIPS_TYPE_FAX:
		if (info.kat_check == NULL)
			return -EPERM;
		ret = info.kat_check(&val);
		if (ret < 0)
			return ret;
		break;
	}

	fprintf(info.fp_wr, "\n");

	return 0;
}

static int
fips_mct_tdes_test(void)
{
#define TDES_BLOCK_SIZE		8
#define TDES_EXTERN_ITER	400
#define TDES_INTERN_ITER	10000
	struct fips_val val, val_key;
	uint8_t prev_out[TDES_BLOCK_SIZE] = {0};
	uint8_t prev_prev_out[TDES_BLOCK_SIZE] = {0};
	uint8_t prev_in[TDES_BLOCK_SIZE] = {0};
	uint32_t i, j, k;
	int ret;

	for (i = 0; i < TDES_EXTERN_ITER; i++) {
		if (i != 0)
			update_info_vec(i);

		fips_test_write_one_case();

		for (j = 0; j < TDES_INTERN_ITER; j++) {
			ret = fips_run_test();
			if (ret < 0) {
				if (ret == -EPERM) {
					fprintf(info.fp_wr, "Bypass\n");
					return 0;
				}

				return ret;
			}

			get_writeback_data(&val);

			if (info.op == FIPS_TEST_DEC_AUTH_VERIF)
				memcpy(prev_in, vec.ct.val, TDES_BLOCK_SIZE);

			if (j == 0) {
				memcpy(prev_out, val.val, TDES_BLOCK_SIZE);

				if (info.op == FIPS_TEST_ENC_AUTH_GEN) {
					memcpy(vec.pt.val, vec.iv.val,
							TDES_BLOCK_SIZE);
					memcpy(vec.iv.val, val.val,
							TDES_BLOCK_SIZE);
				} else {
					memcpy(vec.iv.val, vec.ct.val,
							TDES_BLOCK_SIZE);
					memcpy(vec.ct.val, val.val,
							TDES_BLOCK_SIZE);
				}
				continue;
			}

			if (info.op == FIPS_TEST_ENC_AUTH_GEN) {
				memcpy(vec.iv.val, val.val, TDES_BLOCK_SIZE);
				memcpy(vec.pt.val, prev_out, TDES_BLOCK_SIZE);
			} else {
				memcpy(vec.iv.val, vec.ct.val, TDES_BLOCK_SIZE);
				memcpy(vec.ct.val, val.val, TDES_BLOCK_SIZE);
			}

			if (j == TDES_INTERN_ITER - 1)
				continue;

			memcpy(prev_out, val.val, TDES_BLOCK_SIZE);

			if (j == TDES_INTERN_ITER - 3)
				memcpy(prev_prev_out, val.val, TDES_BLOCK_SIZE);
		}

		info.parse_writeback(&val);
		fprintf(info.fp_wr, "\n");

		if (i == TDES_EXTERN_ITER - 1)
			continue;

		/** update key */
		memcpy(&val_key, &vec.cipher_auth.key, sizeof(val_key));

		if (info.interim_info.tdes_data.nb_keys == 0) {
			if (memcmp(val_key.val, val_key.val + 8, 8) == 0)
				info.interim_info.tdes_data.nb_keys = 1;
			else if (memcmp(val_key.val, val_key.val + 16, 8) == 0)
				info.interim_info.tdes_data.nb_keys = 2;
			else
				info.interim_info.tdes_data.nb_keys = 3;

		}

		for (k = 0; k < TDES_BLOCK_SIZE; k++) {

			switch (info.interim_info.tdes_data.nb_keys) {
			case 3:
				val_key.val[k] ^= val.val[k];
				val_key.val[k + 8] ^= prev_out[k];
				val_key.val[k + 16] ^= prev_prev_out[k];
				break;
			case 2:
				val_key.val[k] ^= val.val[k];
				val_key.val[k + 8] ^= prev_out[k];
				val_key.val[k + 16] ^= val.val[k];
				break;
			default: /* case 1 */
				val_key.val[k] ^= val.val[k];
				val_key.val[k + 8] ^= val.val[k];
				val_key.val[k + 16] ^= val.val[k];
				break;
			}

		}

		for (k = 0; k < 24; k++)
			val_key.val[k] = (__builtin_popcount(val_key.val[k]) &
					0x1) ?
					val_key.val[k] : (val_key.val[k] ^ 0x1);

		if (info.op == FIPS_TEST_ENC_AUTH_GEN) {
			memcpy(vec.iv.val, val.val, TDES_BLOCK_SIZE);
			memcpy(vec.pt.val, prev_out, TDES_BLOCK_SIZE);
		} else {
			memcpy(vec.iv.val, prev_out, TDES_BLOCK_SIZE);
			memcpy(vec.ct.val, val.val, TDES_BLOCK_SIZE);
		}
	}

	return 0;
}

static int
fips_mct_aes_test(void)
{
#define AES_BLOCK_SIZE	16
#define AES_EXTERN_ITER	100
#define AES_INTERN_ITER	1000
	struct fips_val val, val_key;
	uint8_t prev_out[AES_BLOCK_SIZE] = {0};
	uint8_t prev_in[AES_BLOCK_SIZE] = {0};
	uint32_t i, j, k;
	int ret;

	for (i = 0; i < AES_EXTERN_ITER; i++) {
		if (i != 0)
			update_info_vec(i);

		fips_test_write_one_case();

		for (j = 0; j < AES_INTERN_ITER; j++) {
			ret = fips_run_test();
			if (ret < 0) {
				if (ret == -EPERM) {
					fprintf(info.fp_wr, "Bypass\n");
					return 0;
				}

				return ret;
			}

			get_writeback_data(&val);

			if (info.op == FIPS_TEST_DEC_AUTH_VERIF)
				memcpy(prev_in, vec.ct.val, AES_BLOCK_SIZE);

			if (j == 0) {
				memcpy(prev_out, val.val, AES_BLOCK_SIZE);

				if (info.op == FIPS_TEST_ENC_AUTH_GEN) {
					memcpy(vec.pt.val, vec.iv.val,
							AES_BLOCK_SIZE);
					memcpy(vec.iv.val, val.val,
							AES_BLOCK_SIZE);
				} else {
					memcpy(vec.ct.val, vec.iv.val,
							AES_BLOCK_SIZE);
					memcpy(vec.iv.val, prev_in,
							AES_BLOCK_SIZE);
				}
				continue;
			}

			if (info.op == FIPS_TEST_ENC_AUTH_GEN) {
				memcpy(vec.iv.val, val.val, AES_BLOCK_SIZE);
				memcpy(vec.pt.val, prev_out, AES_BLOCK_SIZE);
			} else {
				memcpy(vec.iv.val, prev_in, AES_BLOCK_SIZE);
				memcpy(vec.ct.val, prev_out, AES_BLOCK_SIZE);
			}

			if (j == AES_INTERN_ITER - 1)
				continue;

			memcpy(prev_out, val.val, AES_BLOCK_SIZE);
		}

		info.parse_writeback(&val);
		fprintf(info.fp_wr, "\n");

		if (i == AES_EXTERN_ITER - 1)
			continue;

		/** update key */
		memcpy(&val_key, &vec.cipher_auth.key, sizeof(val_key));
		for (k = 0; k < vec.cipher_auth.key.len; k++) {
			switch (vec.cipher_auth.key.len) {
			case 16:
				val_key.val[k] ^= val.val[k];
				break;
			case 24:
				if (k < 8)
					val_key.val[k] ^= prev_out[k + 8];
				else
					val_key.val[k] ^= val.val[k - 8];
				break;
			case 32:
				if (k < 16)
					val_key.val[k] ^= prev_out[k];
				else
					val_key.val[k] ^= val.val[k - 16];
				break;
			default:
				return -1;
			}
		}

		if (info.op == FIPS_TEST_DEC_AUTH_VERIF)
			memcpy(vec.iv.val, val.val, AES_BLOCK_SIZE);
	}

	return 0;
}

static int
init_test_ops(void)
{
	switch (info.algo) {
	case FIPS_TEST_ALGO_AES:
		test_ops.prepare_op = prepare_cipher_op;
		test_ops.prepare_xform  = prepare_aes_xform;
		if (info.interim_info.aes_data.test_type == AESAVS_TYPE_MCT)
			test_ops.test = fips_mct_aes_test;
		else
			test_ops.test = fips_generic_test;
		break;
	case FIPS_TEST_ALGO_HMAC:
		test_ops.prepare_op = prepare_auth_op;
		test_ops.prepare_xform = prepare_hmac_xform;
		test_ops.test = fips_generic_test;
		break;
	case FIPS_TEST_ALGO_TDES:
		test_ops.prepare_op = prepare_cipher_op;
		test_ops.prepare_xform  = prepare_tdes_xform;
		if (info.interim_info.tdes_data.test_type == TDES_MCT)
			test_ops.test = fips_mct_tdes_test;
		else
			test_ops.test = fips_generic_test;
		break;
	case FIPS_TEST_ALGO_AES_GCM:
		test_ops.prepare_op = prepare_aead_op;
		test_ops.prepare_xform = prepare_gcm_xform;
		test_ops.test = fips_generic_test;
		break;
	case FIPS_TEST_ALGO_AES_CMAC:
		test_ops.prepare_op = prepare_auth_op;
		test_ops.prepare_xform = prepare_cmac_xform;
		test_ops.test = fips_generic_test;
		break;
	case FIPS_TEST_ALGO_AES_CCM:
		test_ops.prepare_op = prepare_aead_op;
		test_ops.prepare_xform = prepare_ccm_xform;
		test_ops.test = fips_generic_test;
		break;
	default:
		return -1;
	}

	return 0;
}

static void
print_test_block(void)
{
	uint32_t i;

	for (i = 0; i < info.nb_vec_lines; i++)
		printf("%s\n", info.vec[i]);

	printf("\n");
}

static int
fips_test_one_file(void)
{
	int fetch_ret = 0, ret;


	ret = init_test_ops();
	if (ret < 0) {
		RTE_LOG(ERR, USER1, "Error %i: Init test op\n", ret);
		return ret;
	}

	while (ret >= 0 && fetch_ret == 0) {
		fetch_ret = fips_test_fetch_one_block();
		if (fetch_ret < 0) {
			RTE_LOG(ERR, USER1, "Error %i: Fetch block\n",
					fetch_ret);
			ret = fetch_ret;
			goto error_one_case;
		}

		if (info.nb_vec_lines == 0) {
			if (fetch_ret == -EOF)
				break;

			fprintf(info.fp_wr, "\n");
			continue;
		}

		ret = fips_test_parse_one_case();
		switch (ret) {
		case 0:
			ret = test_ops.test();
			if (ret == 0)
				break;
			RTE_LOG(ERR, USER1, "Error %i: test block\n",
					ret);
			goto error_one_case;
		case 1:
			break;
		default:
			RTE_LOG(ERR, USER1, "Error %i: Parse block\n",
					ret);
			goto error_one_case;
		}

		continue;
error_one_case:
		print_test_block();
	}

	fips_test_clear();

	return ret;

}
