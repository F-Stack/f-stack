/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#include <rte_cryptodev.h>

#include "fips_validation.h"

#define ALGO_PREFIX	"[L = "
#define MSGLEN_STR	"Len = "
#define MSG_STR		"Msg = "
#define MD_STR		"MD = "
#define SEED_STR	"Seed = "
#define MCT_STR		"Monte"

#define ALGO_JSON_STR	"algorithm"
#define TESTTYPE_JSON_STR	"testType"

#define PT_JSON_STR		"msg"

struct plain_hash_size_conversion {
	const char *str;
	enum rte_crypto_auth_algorithm algo;
} phsc[] = {
		{"20", RTE_CRYPTO_AUTH_SHA1},
		{"28", RTE_CRYPTO_AUTH_SHA224},
		{"32", RTE_CRYPTO_AUTH_SHA256},
		{"48", RTE_CRYPTO_AUTH_SHA384},
		{"64", RTE_CRYPTO_AUTH_SHA512},
};

int
parse_test_sha_hash_size(enum rte_crypto_auth_algorithm algo)
{
	int ret = -EINVAL;
	uint8_t i;

	for (i = 0; i < RTE_DIM(phsc); i++) {
		if (phsc[i].algo == algo) {
			ret = atoi(phsc[i].str);
			break;
		}
	}

	return ret;
}

static int
parse_interim_algo(__rte_unused const char *key,
		char *text,
		__rte_unused struct fips_val *val)
{
	uint32_t i;

	for (i = 0; i < RTE_DIM(phsc); i++) {
		if (strstr(text, phsc[i].str)) {
			info.interim_info.sha_data.algo = phsc[i].algo;
			parser_read_uint32_val(ALGO_PREFIX,
				text, &vec.cipher_auth.digest);
			break;
		}
	}

	if (i == RTE_DIM(phsc))
		return -1;

	return 0;
}

struct fips_test_callback sha_tests_vectors[] = {
		{MSGLEN_STR, parser_read_uint32_bit_val, &vec.pt},
		{MSG_STR, parse_uint8_known_len_hex_str, &vec.pt},
		{SEED_STR, parse_uint8_hex_str, &vec.cipher_auth.digest},
		{NULL, NULL, NULL} /**< end pointer */
};

struct fips_test_callback sha_tests_interim_vectors[] = {
		{ALGO_PREFIX, parse_interim_algo, NULL},
		{NULL, NULL, NULL} /**< end pointer */
};

#ifdef USE_JANSSON
static struct {
	uint32_t type;
	const char *desc;
} sha_test_types[] = {
		{SHA_MCT, "MCT"},
		{SHA_AFT, "AFT"},
};

static struct plain_hash_algorithms {
	const char *str;
	enum rte_crypto_auth_algorithm algo;
} json_algorithms[] = {
		{"SHA-1", RTE_CRYPTO_AUTH_SHA1},
		{"SHA2-224", RTE_CRYPTO_AUTH_SHA224},
		{"SHA2-256", RTE_CRYPTO_AUTH_SHA256},
		{"SHA2-384", RTE_CRYPTO_AUTH_SHA384},
		{"SHA2-512", RTE_CRYPTO_AUTH_SHA512},
};

struct fips_test_callback sha_tests_json_vectors[] = {
		{PT_JSON_STR, parse_uint8_hex_str, &vec.pt},
		{NULL, NULL, NULL} /**< end pointer */
};
#endif /* USE_JANSSON */

static int
parse_test_sha_writeback(struct fips_val *val) // !
{
	struct fips_val val_local;

	fprintf(info.fp_wr, "%s", MD_STR);

	val_local.val = val->val + vec.pt.len;
	val_local.len = vec.cipher_auth.digest.len;

	parse_write_hex_str(&val_local);
	return 0;
}

static int
rsp_test_sha_check(struct fips_val *val)
{
	if (memcmp(val->val + vec.pt.len, vec.cipher_auth.digest.val,
			vec.cipher_auth.digest.len) == 0)
		fprintf(info.fp_wr, "Success\n");
	else
		fprintf(info.fp_wr, "Failed\n");

	return 0;
}

int
parse_test_sha_init(void)
{
	uint32_t i;

	info.interim_info.sha_data.test_type = SHA_KAT;
	for (i = 0; i < info.nb_vec_lines; i++) {
		char *line = info.vec[i];
		if (strstr(line, MCT_STR))
			info.interim_info.sha_data.test_type = SHA_MCT;
	}

	info.op = FIPS_TEST_ENC_AUTH_GEN;
	info.parse_writeback = parse_test_sha_writeback;
	info.callbacks = sha_tests_vectors;
	info.interim_callbacks = sha_tests_interim_vectors;
	info.writeback_callbacks = NULL;
	info.kat_check = rsp_test_sha_check;
	return 0;
}

#ifdef USE_JANSSON
static int
parse_test_sha_json_writeback(struct fips_val *val)
{
	struct fips_val val_local;
	json_t *tcId, *md;

	tcId = json_object_get(json_info.json_test_case, "tcId");

	json_info.json_write_case = json_object();
	json_object_set_new(json_info.json_write_case, "tcId", tcId);

	val_local.val = val->val + vec.pt.len;
	val_local.len = vec.cipher_auth.digest.len;

	writeback_hex_str("", info.one_line_text, &val_local);
	md = json_string(info.one_line_text);
	json_object_set_new(json_info.json_write_case, "md", md);

	return 0;
}

static int
parse_test_sha_mct_json_writeback(struct fips_val *val)
{
	json_t *tcId, *md, *resArr, *res;
	struct fips_val val_local;

	tcId = json_object_get(json_info.json_test_case, "tcId");
	if (json_info.json_write_case) {
		json_t *wcId;

		wcId = json_object_get(json_info.json_write_case, "tcId");
		if (!json_equal(tcId, wcId)) {
			json_info.json_write_case = json_object();
			json_object_set_new(json_info.json_write_case, "tcId", tcId);
			json_object_set_new(json_info.json_write_case, "resultsArray",
								json_array());
		}
	} else {
		json_info.json_write_case = json_object();
		json_object_set_new(json_info.json_write_case, "tcId", tcId);
		json_object_set_new(json_info.json_write_case, "resultsArray", json_array());
	}

	resArr = json_object_get(json_info.json_write_case, "resultsArray");
	if (!json_is_array(resArr))
		return -EINVAL;

	res = json_object();

	val_local.val = val->val + vec.pt.len;
	val_local.len = vec.cipher_auth.digest.len;

	writeback_hex_str("", info.one_line_text, &val_local);
	md = json_string(info.one_line_text);
	json_object_set_new(res, "md", md);

	json_array_append_new(resArr, res);
	return 0;
}

int
parse_test_sha_json_algorithm(void)
{
	json_t *algorithm_object;
	const char *algorithm_str;
	uint32_t i;
	int sz;

	algorithm_object = json_object_get(json_info.json_vector_set, "algorithm");
	algorithm_str = json_string_value(algorithm_object);

	for (i = 0; i < RTE_DIM(json_algorithms); i++) {
		if (strstr(algorithm_str, json_algorithms[i].str)) {
			info.interim_info.sha_data.algo = json_algorithms[i].algo;
			break;
		}
	}

	if (i == RTE_DIM(json_algorithms))
		return -1;

	sz = parse_test_sha_hash_size(info.interim_info.sha_data.algo);
	if (sz < 0)
		return -1;

	free(vec.cipher_auth.digest.val);
	vec.cipher_auth.digest.len = sz;
	vec.cipher_auth.digest.val = calloc(1, sz);
	if (vec.cipher_auth.digest.val == NULL)
		return -1;

	return 0;
}

int
parse_test_sha_json_test_type(void)
{
	json_t *type_object;
	const char *type_str;
	uint32_t i;

	type_object = json_object_get(json_info.json_test_group, TESTTYPE_JSON_STR);
	type_str = json_string_value(type_object);

	for (i = 0; i < RTE_DIM(sha_test_types); i++)
		if (strstr(type_str, sha_test_types[i].desc)) {
			info.interim_info.sha_data.test_type =
				sha_test_types[i].type;
			break;
		}

	if (i == RTE_DIM(sha_test_types))
		return -1;

	switch (info.interim_info.sha_data.test_type) {
	case SHA_MCT:
		info.parse_writeback = parse_test_sha_mct_json_writeback;
		break;
	case SHA_AFT:
		info.parse_writeback = parse_test_sha_json_writeback;
		break;
	default:
		info.parse_writeback = NULL;
	}

	if (!info.parse_writeback)
		return -1;

	return 0;
}

int
parse_test_sha_json_init(void)
{
	info.op = FIPS_TEST_ENC_AUTH_GEN;
	info.parse_writeback = parse_test_sha_json_writeback;
	info.callbacks = sha_tests_json_vectors;
	info.writeback_callbacks = NULL;
	info.kat_check = rsp_test_sha_check;
	info.interim_callbacks = NULL;

	if (parse_test_sha_json_algorithm() < 0)
		return -1;

	if (parse_test_sha_json_test_type() < 0)
		return -1;

	return 0;
}
#endif /* USE_JANSSON */
