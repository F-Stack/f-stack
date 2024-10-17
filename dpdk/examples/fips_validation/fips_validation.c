/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_string_fns.h>
#include <rte_cryptodev.h>
#include <rte_malloc.h>

#include "fips_validation.h"

#define skip_white_spaces(pos)			\
({						\
	__typeof__(pos) _p = (pos);		\
	for ( ; isspace(*_p); _p++)		\
		;				\
	_p;					\
})

static int
get_file_line(void)
{
	FILE *fp = info.fp_rd;
	char *line = info.one_line_text;
	int ret;
	uint32_t loc = 0;

	memset(line, 0, MAX_LINE_CHAR);
	while ((ret = fgetc(fp)) != EOF) {
		char c = (char)ret;

		if (loc >= MAX_LINE_CHAR - 1)
			return -ENOMEM;
		if (c == '\n')
			break;
		line[loc++] = c;
	}

	if (ret == EOF)
		return -EOF;

	return 0;
}

int
fips_test_fetch_one_block(void)
{
	size_t size;
	int ret = 0;
	uint32_t i;

	for (i = 0; i < info.nb_vec_lines; i++) {
		free(info.vec[i]);
		info.vec[i] = NULL;
	}

	i = 0;
	do {
		if (i >= MAX_LINE_PER_VECTOR) {
			ret = -ENOMEM;
			goto error_exit;
		}

		ret = get_file_line();
		size = strlen(info.one_line_text);
		if (size == 0)
			break;

		info.vec[i] = calloc(1, size + 5);
		if (info.vec[i] == NULL)
			goto error_exit;

		strlcpy(info.vec[i], info.one_line_text, size + 1);
		i++;
	} while (ret == 0);

	info.nb_vec_lines = i;

	return ret;

error_exit:
	for (i = 0; i < MAX_LINE_PER_VECTOR; i++)
		if (info.vec[i] != NULL) {
			free(info.vec[i]);
			info.vec[i] = NULL;
		}

	info.nb_vec_lines = 0;

	return -ENOMEM;
}

static void
fips_test_parse_version(void)
{
	int len = strlen(info.vec[0]);
	char *ptr = info.vec[0];

	info.version = strtof(ptr + len - 4, NULL);
}

static int
fips_test_parse_header(void)
{
	uint32_t i;
	char *tmp;
	int ret;
	int algo_parsed = 0;
	time_t t = time(NULL);
	struct tm *tm_now = localtime(&t);

	ret = fips_test_fetch_one_block();
	if (ret < 0)
		return ret;

	if (info.nb_vec_lines)
		fips_test_parse_version();

	for (i = 0; i < info.nb_vec_lines; i++) {
		if (!algo_parsed) {
			if (strstr(info.vec[i], "AES")) {
				algo_parsed = 1;
				info.algo = FIPS_TEST_ALGO_AES;
				ret = parse_test_aes_init();
				if (ret < 0)
					return ret;
			} else if (strstr(info.vec[i], "GCM")) {
				algo_parsed = 1;
				info.algo = FIPS_TEST_ALGO_AES_GCM;
				ret = parse_test_gcm_init();
				if (ret < 0)
					return ret;
			} else if (strstr(info.vec[i], "CMAC")) {
				algo_parsed = 1;
				info.algo = FIPS_TEST_ALGO_AES_CMAC;
				ret = parse_test_cmac_init();
				if (ret < 0)
					return 0;
			} else if (strstr(info.vec[i], "CCM")) {
				algo_parsed = 1;
				info.algo = FIPS_TEST_ALGO_AES_CCM;
				ret = parse_test_ccm_init();
				if (ret < 0)
					return 0;
			} else if (strstr(info.vec[i], "HMAC")) {
				algo_parsed = 1;
				info.algo = FIPS_TEST_ALGO_HMAC;
				ret = parse_test_hmac_init();
				if (ret < 0)
					return ret;
			} else if (strstr(info.vec[i], "TDES")) {
				algo_parsed = 1;
				info.algo = FIPS_TEST_ALGO_TDES;
				ret = parse_test_tdes_init();
				if (ret < 0)
					return 0;
			} else if (strstr(info.vec[i], "PERMUTATION")) {
				algo_parsed = 1;
				info.algo = FIPS_TEST_ALGO_TDES;
				ret = parse_test_tdes_init();
				if (ret < 0)
					return 0;
			} else if (strstr(info.vec[i], "VARIABLE")) {
				algo_parsed = 1;
				info.algo = FIPS_TEST_ALGO_TDES;
				ret = parse_test_tdes_init();
				if (ret < 0)
					return 0;
			} else if (strstr(info.vec[i], "SUBSTITUTION")) {
				algo_parsed = 1;
				info.algo = FIPS_TEST_ALGO_TDES;
				ret = parse_test_tdes_init();
				if (ret < 0)
					return 0;
			} else if (strstr(info.vec[i], "SHA-")) {
				algo_parsed = 1;
				info.algo = FIPS_TEST_ALGO_SHA;
				ret = parse_test_sha_init();
				if (ret < 0)
					return ret;
			} else if (strstr(info.vec[i], "XTS")) {
				algo_parsed = 1;
				info.algo = FIPS_TEST_ALGO_AES_XTS;
				ret = parse_test_xts_init();
				if (ret < 0)
					return ret;
			}
		}

		tmp = strstr(info.vec[i], "# Config info for ");
		if (tmp != NULL) {
			fprintf(info.fp_wr, "%s%s\n", "# Config info for DPDK Cryptodev ",
					info.device_name);
			continue;
		}

		tmp = strstr(info.vec[i], "#  HMAC information for ");
		if (tmp != NULL) {
			fprintf(info.fp_wr, "%s%s\n", "#  HMAC information for "
				"DPDK Cryptodev ",
				info.device_name);
			continue;
		}

		tmp = strstr(info.vec[i], "# Config Info for : ");
		if (tmp != NULL) {

			fprintf(info.fp_wr, "%s%s\n", "# Config Info for DPDK Cryptodev : ",
					info.device_name);
			continue;
		}

		tmp = strstr(info.vec[i], "# information for ");
		if (tmp != NULL) {

			char tmp_output[128] = {0};

			strlcpy(tmp_output, info.vec[i], tmp - info.vec[i] + 1);

			fprintf(info.fp_wr, "%s%s%s\n", tmp_output,
					"information for DPDK Cryptodev ",
					info.device_name);
			continue;
		}

		tmp = strstr(info.vec[i], " test information for ");
		if (tmp != NULL) {
			char tmp_output[128] = {0};

			strlcpy(tmp_output, info.vec[i], tmp - info.vec[i] + 1);

			fprintf(info.fp_wr, "%s%s%s\n", tmp_output,
					"test information for DPDK Cryptodev ",
					info.device_name);
			continue;
		}

		tmp = strstr(info.vec[i], "\" information for \"");
		if (tmp != NULL) {
			char tmp_output[128] = {0};

			strlcpy(tmp_output, info.vec[i], tmp - info.vec[i] + 1);

			fprintf(info.fp_wr, "%s%s%s\n", tmp_output,
					"\" information for DPDK Cryptodev ",
					info.device_name);
			continue;
		}

		if (i == info.nb_vec_lines - 1) {
			/** update the time as current time, write to file */
			fprintf(info.fp_wr, "%s%s\n", "# Generated on ",
					asctime(tm_now));
			continue;
		}

		/* to this point, no field need to update,
		 *  only copy to rsp file
		 */
		fprintf(info.fp_wr, "%s\n", info.vec[i]);
	}

	return 0;
}

static int
parse_file_type(const char *path)
{
	const char *tmp = path + strlen(path) - 3;

	if (strstr(tmp, REQ_FILE_PREFIX))
		info.file_type = FIPS_TYPE_REQ;
	else if (strstr(tmp, RSP_FILE_PREFIX))
		info.file_type = FIPS_TYPE_RSP;
	else if (strstr(path, FAX_FILE_PREFIX))
		info.file_type = FIPS_TYPE_FAX;
	else if (strstr(path, JSON_FILE_PREFIX))
		info.file_type = FIPS_TYPE_JSON;
	else
		return -EINVAL;

	return 0;
}

int
fips_test_init(const char *req_file_path, const char *rsp_file_path,
		const char *device_name)
{
	if (strcmp(req_file_path, rsp_file_path) == 0) {
		RTE_LOG(ERR, USER1, "File paths cannot be the same\n");
		return -EINVAL;
	}

	fips_test_clear();

	if (rte_strscpy(info.file_name, req_file_path,
				sizeof(info.file_name)) < 0) {
		RTE_LOG(ERR, USER1, "Path %s too long\n", req_file_path);
		return -EINVAL;
	}
	info.algo = FIPS_TEST_ALGO_MAX;
	if (parse_file_type(req_file_path) < 0) {
		RTE_LOG(ERR, USER1, "File %s type not supported\n",
				req_file_path);
		return -EINVAL;
	}

	info.fp_rd = fopen(req_file_path, "r");
	if (!info.fp_rd) {
		RTE_LOG(ERR, USER1, "Cannot open file %s\n", req_file_path);
		return -EINVAL;
	}

	if (info.file_type == FIPS_TYPE_JSON) {
#ifdef USE_JANSSON
		json_error_t error;
		json_info.json_root = json_loadf(info.fp_rd, 0, &error);
		if (!json_info.json_root) {
			RTE_LOG(ERR, USER1, "Cannot parse json file %s (line %d, column %d)\n",
				req_file_path, error.line, error.column);
			return -EINVAL;
		}
#else /* USE_JANSSON */
		RTE_LOG(ERR, USER1, "No json library configured.\n");
		return -EINVAL;
#endif /* USE_JANSSON */
	}

	info.fp_wr = fopen(rsp_file_path, "w");
	if (!info.fp_wr) {
		RTE_LOG(ERR, USER1, "Cannot open file %s\n", rsp_file_path);
		return -EINVAL;
	}

	info.one_line_text = calloc(1, MAX_LINE_CHAR);
	if (!info.one_line_text) {
		RTE_LOG(ERR, USER1, "Insufficient memory\n");
		return -ENOMEM;
	}

	if (rte_strscpy(info.device_name, device_name,
				sizeof(info.device_name)) < 0) {
		RTE_LOG(ERR, USER1, "Device name %s too long\n", device_name);
		return -EINVAL;
	}

	if (info.file_type == FIPS_TYPE_JSON)
		return 0;

	if (fips_test_parse_header() < 0) {
		RTE_LOG(ERR, USER1, "Failed parsing header\n");
		return -1;
	}

	return 0;
}

void
fips_test_clear(void)
{
	if (info.fp_rd)
		fclose(info.fp_rd);
	if (info.fp_wr)
		fclose(info.fp_wr);
	free(info.one_line_text);
	if (info.nb_vec_lines) {
		uint32_t i;

		for (i = 0; i < info.nb_vec_lines; i++)
			free(info.vec[i]);
	}

	memset(&info, 0, sizeof(info));
}

int
fips_test_parse_one_case(void)
{
	uint32_t i, j = 0;
	uint32_t is_interim;
	uint32_t interim_cnt = 0;
	int ret;

	info.vec_start_off = 0;

	if (info.interim_callbacks) {
		for (i = 0; i < info.nb_vec_lines; i++) {
			is_interim = 0;
			for (j = 0; info.interim_callbacks[j].key != NULL; j++)
				if (strstr(info.vec[i],
					info.interim_callbacks[j].key)) {
					is_interim = 1;

					ret = info.interim_callbacks[j].cb(
						info.interim_callbacks[j].key,
						info.vec[i],
						info.interim_callbacks[j].val);
					if (ret < 0)
						return ret;
				}

			if (is_interim)
				interim_cnt += 1;
		}
	}

	if (interim_cnt) {
		if (info.version == 21.4f) {
			for (i = 0; i < interim_cnt; i++)
				fprintf(info.fp_wr, "%s\n", info.vec[i]);
			fprintf(info.fp_wr, "\n");

			if (info.nb_vec_lines == interim_cnt)
				return 1;
		} else {
			for (i = 0; i < info.nb_vec_lines; i++)
				fprintf(info.fp_wr, "%s\n", info.vec[i]);
			fprintf(info.fp_wr, "\n");
			return 1;
		}
	}

	info.vec_start_off = interim_cnt;

	for (i = info.vec_start_off; i < info.nb_vec_lines; i++) {
		for (j = 0; info.callbacks[j].key != NULL; j++)
			if (strstr(info.vec[i], info.callbacks[j].key)) {
				ret = info.callbacks[j].cb(
					info.callbacks[j].key,
					info.vec[i], info.callbacks[j].val);
				if (ret < 0)
					return ret;
				break;
			}
	}

	return 0;
}

void
fips_test_write_one_case(void)
{
	uint32_t i;

	for (i = info.vec_start_off; i < info.nb_vec_lines; i++)
		fprintf(info.fp_wr, "%s\n", info.vec[i]);
}

#ifdef USE_JANSSON
int
fips_test_parse_one_json_vector_set(void)
{
	json_t *algo_obj = json_object_get(json_info.json_vector_set, "algorithm");
	const char *algo_str = json_string_value(algo_obj);

	/* Vector sets contain the algorithm type, and nothing else we need. */
	if (strstr(algo_str, "AES-GCM"))
		info.algo = FIPS_TEST_ALGO_AES_GCM;
	else if (strstr(algo_str, "AES-GMAC"))
		info.algo = FIPS_TEST_ALGO_AES_GMAC;
	else if (strstr(algo_str, "HMAC"))
		info.algo = FIPS_TEST_ALGO_HMAC;
	else if (strstr(algo_str, "CMAC"))
		info.algo = FIPS_TEST_ALGO_AES_CMAC;
	else if (strstr(algo_str, "AES-CBC"))
		info.algo = FIPS_TEST_ALGO_AES_CBC;
	else if (strstr(algo_str, "AES-XTS"))
		info.algo = FIPS_TEST_ALGO_AES_XTS;
	else if (strstr(algo_str, "AES-CTR"))
		info.algo = FIPS_TEST_ALGO_AES_CTR;
	else if (strstr(algo_str, "SHA"))
		info.algo = FIPS_TEST_ALGO_SHA;
	else if (strstr(algo_str, "TDES-CBC") ||
		strstr(algo_str, "TDES-ECB"))
		info.algo = FIPS_TEST_ALGO_TDES;
	else if (strstr(algo_str, "RSA"))
		info.algo = FIPS_TEST_ALGO_RSA;
	else if (strstr(algo_str, "ECDSA"))
		info.algo = FIPS_TEST_ALGO_ECDSA;
	else
		return -EINVAL;

	return 0;
}

int
fips_test_parse_one_json_group(void)
{
	int ret, i;
	json_t *param;

	if (info.interim_callbacks) {
		char json_value[FIPS_TEST_JSON_BUF_LEN];
		for (i = 0; info.interim_callbacks[i].key != NULL; i++) {
			param = json_object_get(json_info.json_test_group,
					info.interim_callbacks[i].key);
			if (!param)
				continue;

			switch (json_typeof(param)) {
			case JSON_STRING:
				snprintf(json_value, sizeof(json_value), "%s",
						 json_string_value(param));
				break;

			case JSON_INTEGER:
				snprintf(json_value, sizeof(json_value), "%"JSON_INTEGER_FORMAT,
						json_integer_value(param));
				break;

			default:
				return -EINVAL;
			}

			ret = info.interim_callbacks[i].cb(
				info.interim_callbacks[i].key, json_value,
				info.interim_callbacks[i].val
			);
			if (ret < 0)
				return ret;
		}

		if (info.parse_interim_writeback) {
			ret = info.parse_interim_writeback(NULL);
			if (ret < 0)
				return ret;
		}
	}

	return 0;
}

int
fips_test_parse_one_json_case(void)
{
	uint32_t i;
	int ret = 0;
	json_t *param;

	for (i = 0; info.callbacks[i].key != NULL; i++) {
		param = json_object_get(json_info.json_test_case, info.callbacks[i].key);
		if (!param)
			continue;

		switch (json_typeof(param)) {
		case JSON_STRING:
			snprintf(info.one_line_text, MAX_LINE_CHAR, "%s",
					 json_string_value(param));
			break;

		case JSON_INTEGER:
			snprintf(info.one_line_text, MAX_LINE_CHAR, "%"JSON_INTEGER_FORMAT,
					 json_integer_value(param));
			break;

		default:
			return -EINVAL;
		}

		ret = info.callbacks[i].cb(info.callbacks[i].key, info.one_line_text,
				info.callbacks[i].val);
		if (ret < 0)
			return ret;
	}

	return 0;
}
#endif /* USE_JANSSON */

static int
parser_read_uint64_hex(uint64_t *value, const char *p)
{
	char *next;
	uint64_t val;

	p = skip_white_spaces(p);

	val = strtoul(p, &next, 16);
	if (p == next)
		return -EINVAL;

	p = skip_white_spaces(next);
	if (*p != '\0')
		return -EINVAL;

	*value = val;
	return 0;
}

int
parser_read_uint8_hex(uint8_t *value, const char *p)
{
	uint64_t val = 0;
	int ret = parser_read_uint64_hex(&val, p);

	if (ret < 0)
		return ret;

	if (val > UINT8_MAX)
		return -ERANGE;

	*value = val;
	return 0;
}

int
parse_uint8_known_len_hex_str(const char *key, char *src, struct fips_val *val)
{
	struct fips_val tmp_val = {0};
	uint32_t len = val->len;
	int ret;

	if (len == 0) {
		if (val->val != NULL) {
			rte_free(val->val);
			val->val = NULL;
		}

		return 0;
	}

	ret = parse_uint8_hex_str(key, src, &tmp_val);
	if (ret < 0)
		return ret;

	if (tmp_val.len == val->len) {
		val->val = tmp_val.val;
		return 0;
	}

	if (tmp_val.len < val->len) {
		rte_free(tmp_val.val);
		return -EINVAL;
	}

	val->val = rte_zmalloc(NULL, val->len, 0);
	if (!val->val) {
		rte_free(tmp_val.val);
		memset(val, 0, sizeof(*val));
		return -ENOMEM;
	}

	memcpy(val->val, tmp_val.val, val->len);
	rte_free(tmp_val.val);

	return 0;
}

int
parse_uint8_hex_str(const char *key, char *src, struct fips_val *val)
{
	uint32_t len, j;

#ifdef USE_JANSSON
	/*
	 * Offset not applicable in case of JSON test vectors.
	 */
	if (info.file_type == FIPS_TYPE_JSON) {
		RTE_SET_USED(key);
	} else
#endif
		src += strlen(key);

	len = strlen(src) / 2;

	if (val->val) {
		rte_free(val->val);
		val->val = NULL;
	}

	val->val = rte_zmalloc(NULL, len + 1, 0);
	if (!val->val)
		return -ENOMEM;

	for (j = 0; j < len; j++) {
		char byte[3] = {src[j * 2], src[j * 2 + 1], '\0'};

		if (parser_read_uint8_hex(&val->val[j], byte) < 0) {
			rte_free(val->val);
			memset(val, 0, sizeof(*val));
			return -EINVAL;
		}
	}

	val->len = len;

	return 0;
}

int
parser_read_uint32_val(const char *key, char *src, struct fips_val *val)
{
#ifdef USE_JANSSON
	if (info.file_type == FIPS_TYPE_JSON) {
		RTE_SET_USED(key);

		return parser_read_uint32(&val->len, src);
	}
# endif
	char *data = src + strlen(key);
	size_t data_len = strlen(data);
	int ret;

	if (data[data_len - 1] == ']') {
		char *tmp_data = calloc(1, data_len + 1);

		if (tmp_data == NULL)
			return -ENOMEM;

		strlcpy(tmp_data, data, data_len);

		ret = parser_read_uint32(&val->len, tmp_data);

		free(tmp_data);
	} else
		ret = parser_read_uint32(&val->len, data);

	return ret;
}

int
parser_read_uint32_bit_val(const char *key, char *src, struct fips_val *val)
{
	int ret;

	ret = parser_read_uint32_val(key, src, val);

	if (ret < 0)
		return ret;

	val->len /= 8;

	return 0;
}

int
writeback_hex_str(const char *key, char *dst, struct fips_val *val)
{
	char *str = dst;
	uint32_t len;

	str += strlen(key);

	for (len = 0; len < val->len; len++)
		snprintf(str + len * 2, 255, "%02x", val->val[len]);

	return 0;
}

static int
parser_read_uint64(uint64_t *value, const char *p)
{
	char *next;
	uint64_t val;

	p = skip_white_spaces(p);
	if (!isdigit(*p))
		return -EINVAL;

	val = strtoul(p, &next, 10);
	if (p == next)
		return -EINVAL;

	p = next;
	switch (*p) {
	case 'T':
		val *= 1024ULL;
		/* fall through */
	case 'G':
		val *= 1024ULL;
		/* fall through */
	case 'M':
		val *= 1024ULL;
		/* fall through */
	case 'k':
	case 'K':
		val *= 1024ULL;
		p++;
		break;
	}

	p = skip_white_spaces(p);
	if (*p != '\0')
		return -EINVAL;

	*value = val;
	return 0;
}

int
parser_read_uint32(uint32_t *value, char *p)
{
	uint64_t val = 0;
	int ret = parser_read_uint64(&val, p);

	if (ret < 0)
		return ret;

	if (val > UINT32_MAX)
		return -EINVAL;

	*value = val;
	return 0;
}

int
parser_read_uint16(uint16_t *value, const char *p)
{
	uint64_t val = 0;
	int ret = parser_read_uint64(&val, p);

	if (ret < 0)
		return ret;

	if (val > UINT16_MAX)
		return -ERANGE;

	*value = val;
	return 0;
}

void
parse_write_hex_str(struct fips_val *src)
{
	writeback_hex_str("", info.one_line_text, src);

	fprintf(info.fp_wr, "%s\n", info.one_line_text);
}

int
update_info_vec(uint32_t count)
{
	const struct fips_test_callback *cb;
	uint32_t i, j;

	if (!info.writeback_callbacks)
		return -1;

	cb = &info.writeback_callbacks[0];

	if ((info.version == 21.4f) && (!(strstr(info.vec[0], cb->key)))) {
		fprintf(info.fp_wr, "%s%u\n", cb->key, count);
		i = 0;
	} else {
		snprintf(info.vec[0], strlen(info.vec[0]) + 4, "%s%u", cb->key,
				count);
		i = 1;
	}

	for (; i < info.nb_vec_lines; i++) {
		for (j = 1; info.writeback_callbacks[j].key != NULL; j++) {
			cb = &info.writeback_callbacks[j];
			if (strstr(info.vec[i], cb->key)) {
				cb->cb(cb->key, info.vec[i], cb->val);
				break;
			}
		}
	}

	return 0;
}
