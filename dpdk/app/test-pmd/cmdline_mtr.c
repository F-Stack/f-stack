/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>

#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_mtr.h>

#include "testpmd.h"
#include "cmdline_mtr.h"

#define PARSE_DELIMITER				" \f\n\r\t\v"
#define MAX_DSCP_TABLE_ENTRIES		64

/** Display Meter Error Message */
static void
print_err_msg(struct rte_mtr_error *error)
{
	static const char *const errstrlist[] = {
		[RTE_MTR_ERROR_TYPE_NONE] = "no error",
		[RTE_MTR_ERROR_TYPE_UNSPECIFIED] = "cause unspecified",
		[RTE_MTR_ERROR_TYPE_METER_PROFILE_ID] = "meter profile id",
		[RTE_MTR_ERROR_TYPE_METER_PROFILE] = "meter profile null",
		[RTE_MTR_ERROR_TYPE_MTR_ID] = "meter id",
		[RTE_MTR_ERROR_TYPE_MTR_PARAMS] = "meter params null",
		[RTE_MTR_ERROR_TYPE_POLICER_ACTION_GREEN]
			= "policer action(green)",
		[RTE_MTR_ERROR_TYPE_POLICER_ACTION_YELLOW]
			= "policer action(yellow)",
		[RTE_MTR_ERROR_TYPE_POLICER_ACTION_RED]
			= "policer action(red)",
		[RTE_MTR_ERROR_TYPE_STATS_MASK] = "stats mask",
		[RTE_MTR_ERROR_TYPE_STATS] = "stats",
		[RTE_MTR_ERROR_TYPE_SHARED]
			= "shared meter",
	};

	const char *errstr;
	char buf[64];

	if ((unsigned int)error->type >= RTE_DIM(errstrlist) ||
		!errstrlist[error->type])
		errstr = "unknown type";
	else
		errstr = errstrlist[error->type];

	if (error->cause)
		snprintf(buf, sizeof(buf), "cause: %p, ", error->cause);

	printf("%s: %s%s (error %d)\n", errstr, error->cause ? buf : "",
		error->message ? error->message : "(no stated reason)",
		error->type);
}

static int
parse_uint(uint64_t *value, const char *str)
{
	char *next = NULL;
	uint64_t n;

	errno = 0;
	/* Parse number string */
	n = strtol(str, &next, 10);
	if (errno != 0 || str == next || *next != '\0')
		return -1;

	*value = n;

	return 0;
}

static int
parse_dscp_table_entries(char *str, enum rte_mtr_color **dscp_table)
{
	char *token;
	int i = 0;

	token = strtok_r(str, PARSE_DELIMITER, &str);
	if (token == NULL)
		return 0;

	/* Allocate memory for dscp table */
	*dscp_table = (enum rte_mtr_color *)malloc(MAX_DSCP_TABLE_ENTRIES *
		sizeof(enum rte_mtr_color));
	if (*dscp_table == NULL)
		return -1;

	while (1) {
		if (strcmp(token, "G") == 0 ||
			strcmp(token, "g") == 0)
			*dscp_table[i++] = RTE_MTR_GREEN;
		else if (strcmp(token, "Y") == 0 ||
			strcmp(token, "y") == 0)
			*dscp_table[i++] = RTE_MTR_YELLOW;
		else if (strcmp(token, "R") == 0 ||
			strcmp(token, "r") == 0)
			*dscp_table[i++] = RTE_MTR_RED;
		else {
			free(*dscp_table);
			return -1;
		}
		if (i == MAX_DSCP_TABLE_ENTRIES)
			break;

		token = strtok_r(str, PARSE_DELIMITER, &str);
		if (token == NULL) {
			free(*dscp_table);
			return -1;
		}
	}
	return 0;
}

static int
parse_meter_color_str(char *c_str, uint32_t *use_prev_meter_color,
	enum rte_mtr_color **dscp_table)
{
	char *token;
	uint64_t previous_mtr_color = 0;
	int ret;

	/* First token: use previous meter color */
	token = strtok_r(c_str, PARSE_DELIMITER, &c_str);
	if (token ==  NULL)
		return -1;

	ret = parse_uint(&previous_mtr_color, token);
	if (ret != 0)
		return -1;

	/* Check if previous meter color to be used */
	if (previous_mtr_color) {
		*use_prev_meter_color = previous_mtr_color;
		return 0;
	}

	/* Parse dscp table entries */
	ret = parse_dscp_table_entries(c_str, dscp_table);
	if (ret != 0)
		return -1;

	return 0;
}

static int
string_to_policer_action(char *s)
{
	if ((strcmp(s, "G") == 0) || (strcmp(s, "g") == 0))
		return MTR_POLICER_ACTION_COLOR_GREEN;

	if ((strcmp(s, "Y") == 0) || (strcmp(s, "y") == 0))
		return MTR_POLICER_ACTION_COLOR_YELLOW;

	if ((strcmp(s, "R") == 0) || (strcmp(s, "r") == 0))
		return MTR_POLICER_ACTION_COLOR_RED;

	if ((strcmp(s, "D") == 0) || (strcmp(s, "d") == 0))
		return MTR_POLICER_ACTION_DROP;

	return -1;
}

static int
parse_policer_action_string(char *p_str, uint32_t action_mask,
	enum rte_mtr_policer_action actions[])
{
	char *token;
	int count = __builtin_popcount(action_mask);
	int g_color = 0, y_color = 0, action, i;

	for (i = 0; i < count; i++) {
		token = strtok_r(p_str, PARSE_DELIMITER, &p_str);
		if (token ==  NULL)
			return -1;

		action = string_to_policer_action(token);
		if (action == -1)
			return -1;

		if (g_color == 0 && (action_mask & 0x1)) {
			actions[RTE_MTR_GREEN] = action;
			g_color = 1;
		} else if (y_color == 0 && (action_mask & 0x2)) {
			actions[RTE_MTR_YELLOW] = action;
			y_color = 1;
		} else
			actions[RTE_MTR_RED] = action;
	}
	return 0;
}

static int
parse_multi_token_string(char *t_str, uint16_t *port_id,
	uint32_t *mtr_id, enum rte_mtr_color **dscp_table)
{
	char *token;
	uint64_t val;
	int ret;

	/* First token: port id */
	token = strtok_r(t_str, PARSE_DELIMITER, &t_str);
	if (token ==  NULL)
		return -1;

	ret = parse_uint(&val, token);
	if (ret != 0 || val > UINT16_MAX)
		return -1;

	*port_id = val;

	/* Second token: meter id */
	token = strtok_r(t_str, PARSE_DELIMITER, &t_str);
	if (token == NULL)
		return 0;

	ret = parse_uint(&val, token);
	if (ret != 0 || val > UINT32_MAX)
		return -1;

	*mtr_id = val;

	ret = parse_dscp_table_entries(t_str, dscp_table);
	if (ret != 0)
		return -1;

	return 0;
}

/* *** Show Port Meter Capabilities *** */
struct cmd_show_port_meter_cap_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t meter;
	cmdline_fixed_string_t cap;
	uint16_t port_id;
};

cmdline_parse_token_string_t cmd_show_port_meter_cap_show =
	TOKEN_STRING_INITIALIZER(
		struct cmd_show_port_meter_cap_result, show, "show");
cmdline_parse_token_string_t cmd_show_port_meter_cap_port =
	TOKEN_STRING_INITIALIZER(
		struct cmd_show_port_meter_cap_result, port, "port");
cmdline_parse_token_string_t cmd_show_port_meter_cap_meter =
	TOKEN_STRING_INITIALIZER(
		struct cmd_show_port_meter_cap_result, meter, "meter");
cmdline_parse_token_string_t cmd_show_port_meter_cap_cap =
	TOKEN_STRING_INITIALIZER(
		struct cmd_show_port_meter_cap_result, cap, "cap");
cmdline_parse_token_num_t cmd_show_port_meter_cap_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_show_port_meter_cap_result, port_id, UINT16);

static void cmd_show_port_meter_cap_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_show_port_meter_cap_result *res = parsed_result;
	struct rte_mtr_capabilities cap;
	struct rte_mtr_error error;
	uint16_t port_id = res->port_id;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	memset(&cap, 0, sizeof(struct rte_mtr_capabilities));
	ret = rte_mtr_capabilities_get(port_id, &cap, &error);
	if (ret) {
		print_err_msg(&error);
		return;
	}

	printf("\n****   Port Meter Object Capabilities ****\n\n");
	printf("cap.n_max %" PRIu32 "\n", cap.n_max);
	printf("cap.n_shared_max %" PRIu32 "\n", cap.n_shared_max);
	printf("cap.identical %" PRId32 "\n", cap.identical);
	printf("cap.shared_identical %" PRId32 "\n",
		cap.shared_identical);
	printf("cap.shared_n_flows_per_mtr_max %" PRIu32 "\n",
		cap.shared_n_flows_per_mtr_max);
	printf("cap.chaining_n_mtrs_per_flow_max %" PRIu32 "\n",
		cap.chaining_n_mtrs_per_flow_max);
	printf("cap.chaining_use_prev_mtr_color_supported %" PRId32 "\n",
		cap.chaining_use_prev_mtr_color_supported);
	printf("cap.chaining_use_prev_mtr_color_enforced %" PRId32 "\n",
		cap.chaining_use_prev_mtr_color_enforced);
	printf("cap.meter_srtcm_rfc2697_n_max %" PRIu32 "\n",
		cap.meter_srtcm_rfc2697_n_max);
	printf("cap.meter_trtcm_rfc2698_n_max %" PRIu32 "\n",
		cap.meter_trtcm_rfc2698_n_max);
	printf("cap.meter_trtcm_rfc4115_n_max %" PRIu32 "\n",
		cap.meter_trtcm_rfc4115_n_max);
	printf("cap.meter_rate_max %" PRIu64 "\n", cap.meter_rate_max);
	printf("cap.color_aware_srtcm_rfc2697_supported %" PRId32 "\n",
		cap.color_aware_srtcm_rfc2697_supported);
	printf("cap.color_aware_trtcm_rfc2698_supported %" PRId32 "\n",
		cap.color_aware_trtcm_rfc2698_supported);
	printf("cap.color_aware_trtcm_rfc4115_supported %" PRId32 "\n",
		cap.color_aware_trtcm_rfc4115_supported);
	printf("cap.policer_action_recolor_supported %" PRId32 "\n",
		cap.policer_action_recolor_supported);
	printf("cap.policer_action_drop_supported %" PRId32 "\n",
		cap.policer_action_drop_supported);
	printf("cap.stats_mask %" PRIx64 "\n", cap.stats_mask);
}

cmdline_parse_inst_t cmd_show_port_meter_cap = {
	.f = cmd_show_port_meter_cap_parsed,
	.data = NULL,
	.help_str = "Show port meter cap",
	.tokens = {
		(void *)&cmd_show_port_meter_cap_show,
		(void *)&cmd_show_port_meter_cap_port,
		(void *)&cmd_show_port_meter_cap_meter,
		(void *)&cmd_show_port_meter_cap_cap,
		(void *)&cmd_show_port_meter_cap_port_id,
		NULL,
	},
};

/* *** Add Port Meter Profile srtcm_rfc2697 *** */
struct cmd_add_port_meter_profile_srtcm_result {
	cmdline_fixed_string_t add;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t meter;
	cmdline_fixed_string_t profile;
	cmdline_fixed_string_t srtcm_rfc2697;
	uint16_t port_id;
	uint32_t profile_id;
	uint64_t cir;
	uint64_t cbs;
	uint64_t ebs;
};

cmdline_parse_token_string_t cmd_add_port_meter_profile_srtcm_add =
	TOKEN_STRING_INITIALIZER(
		struct cmd_add_port_meter_profile_srtcm_result, add, "add");
cmdline_parse_token_string_t cmd_add_port_meter_profile_srtcm_port =
	TOKEN_STRING_INITIALIZER(
		struct cmd_add_port_meter_profile_srtcm_result,
			port, "port");
cmdline_parse_token_string_t cmd_add_port_meter_profile_srtcm_meter =
	TOKEN_STRING_INITIALIZER(
		struct cmd_add_port_meter_profile_srtcm_result,
			meter, "meter");
cmdline_parse_token_string_t cmd_add_port_meter_profile_srtcm_profile =
	TOKEN_STRING_INITIALIZER(
		struct cmd_add_port_meter_profile_srtcm_result,
			profile, "profile");
cmdline_parse_token_string_t cmd_add_port_meter_profile_srtcm_srtcm_rfc2697 =
	TOKEN_STRING_INITIALIZER(
		struct cmd_add_port_meter_profile_srtcm_result,
			srtcm_rfc2697, "srtcm_rfc2697");
cmdline_parse_token_num_t cmd_add_port_meter_profile_srtcm_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_add_port_meter_profile_srtcm_result,
			port_id, UINT16);
cmdline_parse_token_num_t cmd_add_port_meter_profile_srtcm_profile_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_add_port_meter_profile_srtcm_result,
			profile_id, UINT32);
cmdline_parse_token_num_t cmd_add_port_meter_profile_srtcm_cir =
	TOKEN_NUM_INITIALIZER(
		struct cmd_add_port_meter_profile_srtcm_result,
			cir, UINT64);
cmdline_parse_token_num_t cmd_add_port_meter_profile_srtcm_cbs =
	TOKEN_NUM_INITIALIZER(
		struct cmd_add_port_meter_profile_srtcm_result,
			cbs, UINT64);
cmdline_parse_token_num_t cmd_add_port_meter_profile_srtcm_ebs =
	TOKEN_NUM_INITIALIZER(
		struct cmd_add_port_meter_profile_srtcm_result,
			ebs, UINT64);

static void cmd_add_port_meter_profile_srtcm_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_add_port_meter_profile_srtcm_result *res = parsed_result;
	struct rte_mtr_meter_profile mp;
	struct rte_mtr_error error;
	uint32_t profile_id = res->profile_id;
	uint16_t port_id = res->port_id;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	/* Private shaper profile params */
	memset(&mp, 0, sizeof(struct rte_mtr_meter_profile));
	mp.alg = RTE_MTR_SRTCM_RFC2697;
	mp.srtcm_rfc2697.cir = res->cir;
	mp.srtcm_rfc2697.cbs = res->cbs;
	mp.srtcm_rfc2697.ebs = res->ebs;

	ret = rte_mtr_meter_profile_add(port_id, profile_id, &mp, &error);
	if (ret != 0) {
		print_err_msg(&error);
		return;
	}
}

cmdline_parse_inst_t cmd_add_port_meter_profile_srtcm = {
	.f = cmd_add_port_meter_profile_srtcm_parsed,
	.data = NULL,
	.help_str = "Add port meter profile srtcm (rfc2697)",
	.tokens = {
		(void *)&cmd_add_port_meter_profile_srtcm_add,
		(void *)&cmd_add_port_meter_profile_srtcm_port,
		(void *)&cmd_add_port_meter_profile_srtcm_meter,
		(void *)&cmd_add_port_meter_profile_srtcm_profile,
		(void *)&cmd_add_port_meter_profile_srtcm_srtcm_rfc2697,
		(void *)&cmd_add_port_meter_profile_srtcm_port_id,
		(void *)&cmd_add_port_meter_profile_srtcm_profile_id,
		(void *)&cmd_add_port_meter_profile_srtcm_cir,
		(void *)&cmd_add_port_meter_profile_srtcm_cbs,
		(void *)&cmd_add_port_meter_profile_srtcm_ebs,
		NULL,
	},
};

/* *** Add Port Meter Profile trtcm_rfc2698 *** */
struct cmd_add_port_meter_profile_trtcm_result {
	cmdline_fixed_string_t add;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t meter;
	cmdline_fixed_string_t profile;
	cmdline_fixed_string_t trtcm_rfc2698;
	uint16_t port_id;
	uint32_t profile_id;
	uint64_t cir;
	uint64_t pir;
	uint64_t cbs;
	uint64_t pbs;
};

cmdline_parse_token_string_t cmd_add_port_meter_profile_trtcm_add =
	TOKEN_STRING_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_result, add, "add");
cmdline_parse_token_string_t cmd_add_port_meter_profile_trtcm_port =
	TOKEN_STRING_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_result,
			port, "port");
cmdline_parse_token_string_t cmd_add_port_meter_profile_trtcm_meter =
	TOKEN_STRING_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_result,
			meter, "meter");
cmdline_parse_token_string_t cmd_add_port_meter_profile_trtcm_profile =
	TOKEN_STRING_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_result,
			profile, "profile");
cmdline_parse_token_string_t cmd_add_port_meter_profile_trtcm_trtcm_rfc2698 =
	TOKEN_STRING_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_result,
			trtcm_rfc2698, "trtcm_rfc2698");
cmdline_parse_token_num_t cmd_add_port_meter_profile_trtcm_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_result,
			port_id, UINT16);
cmdline_parse_token_num_t cmd_add_port_meter_profile_trtcm_profile_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_result,
			profile_id, UINT32);
cmdline_parse_token_num_t cmd_add_port_meter_profile_trtcm_cir =
	TOKEN_NUM_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_result,
			cir, UINT64);
cmdline_parse_token_num_t cmd_add_port_meter_profile_trtcm_pir =
	TOKEN_NUM_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_result,
			pir, UINT64);
cmdline_parse_token_num_t cmd_add_port_meter_profile_trtcm_cbs =
	TOKEN_NUM_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_result,
			cbs, UINT64);
cmdline_parse_token_num_t cmd_add_port_meter_profile_trtcm_pbs =
	TOKEN_NUM_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_result,
			pbs, UINT64);

static void cmd_add_port_meter_profile_trtcm_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_add_port_meter_profile_trtcm_result *res = parsed_result;
	struct rte_mtr_meter_profile mp;
	struct rte_mtr_error error;
	uint32_t profile_id = res->profile_id;
	uint16_t port_id = res->port_id;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	/* Private shaper profile params */
	memset(&mp, 0, sizeof(struct rte_mtr_meter_profile));
	mp.alg = RTE_MTR_TRTCM_RFC2698;
	mp.trtcm_rfc2698.cir = res->cir;
	mp.trtcm_rfc2698.pir = res->pir;
	mp.trtcm_rfc2698.cbs = res->cbs;
	mp.trtcm_rfc2698.pbs = res->pbs;

	ret = rte_mtr_meter_profile_add(port_id, profile_id, &mp, &error);
	if (ret != 0) {
		print_err_msg(&error);
		return;
	}
}

cmdline_parse_inst_t cmd_add_port_meter_profile_trtcm = {
	.f = cmd_add_port_meter_profile_trtcm_parsed,
	.data = NULL,
	.help_str = "Add port meter profile trtcm (rfc2698)",
	.tokens = {
		(void *)&cmd_add_port_meter_profile_trtcm_add,
		(void *)&cmd_add_port_meter_profile_trtcm_port,
		(void *)&cmd_add_port_meter_profile_trtcm_meter,
		(void *)&cmd_add_port_meter_profile_trtcm_profile,
		(void *)&cmd_add_port_meter_profile_trtcm_trtcm_rfc2698,
		(void *)&cmd_add_port_meter_profile_trtcm_port_id,
		(void *)&cmd_add_port_meter_profile_trtcm_profile_id,
		(void *)&cmd_add_port_meter_profile_trtcm_cir,
		(void *)&cmd_add_port_meter_profile_trtcm_pir,
		(void *)&cmd_add_port_meter_profile_trtcm_cbs,
		(void *)&cmd_add_port_meter_profile_trtcm_pbs,
		NULL,
	},
};

/* *** Add Port Meter Profile trtcm_rfc4115 *** */
struct cmd_add_port_meter_profile_trtcm_rfc4115_result {
	cmdline_fixed_string_t add;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t meter;
	cmdline_fixed_string_t profile;
	cmdline_fixed_string_t trtcm_rfc4115;
	uint16_t port_id;
	uint32_t profile_id;
	uint64_t cir;
	uint64_t eir;
	uint64_t cbs;
	uint64_t ebs;
};

cmdline_parse_token_string_t cmd_add_port_meter_profile_trtcm_rfc4115_add =
	TOKEN_STRING_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_rfc4115_result, add,
		"add");
cmdline_parse_token_string_t cmd_add_port_meter_profile_trtcm_rfc4115_port =
	TOKEN_STRING_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_rfc4115_result,
			port, "port");
cmdline_parse_token_string_t cmd_add_port_meter_profile_trtcm_rfc4115_meter =
	TOKEN_STRING_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_rfc4115_result,
			meter, "meter");
cmdline_parse_token_string_t cmd_add_port_meter_profile_trtcm_rfc4115_profile =
	TOKEN_STRING_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_rfc4115_result,
			profile, "profile");
cmdline_parse_token_string_t
	cmd_add_port_meter_profile_trtcm_rfc4115_trtcm_rfc4115 =
	TOKEN_STRING_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_rfc4115_result,
			trtcm_rfc4115, "trtcm_rfc4115");
cmdline_parse_token_num_t cmd_add_port_meter_profile_trtcm_rfc4115_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_rfc4115_result,
			port_id, UINT16);
cmdline_parse_token_num_t cmd_add_port_meter_profile_trtcm_rfc4115_profile_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_rfc4115_result,
			profile_id, UINT32);
cmdline_parse_token_num_t cmd_add_port_meter_profile_trtcm_rfc4115_cir =
	TOKEN_NUM_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_rfc4115_result,
			cir, UINT64);
cmdline_parse_token_num_t cmd_add_port_meter_profile_trtcm_rfc4115_eir =
	TOKEN_NUM_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_rfc4115_result,
			eir, UINT64);
cmdline_parse_token_num_t cmd_add_port_meter_profile_trtcm_rfc4115_cbs =
	TOKEN_NUM_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_rfc4115_result,
			cbs, UINT64);
cmdline_parse_token_num_t cmd_add_port_meter_profile_trtcm_rfc4115_ebs =
	TOKEN_NUM_INITIALIZER(
		struct cmd_add_port_meter_profile_trtcm_rfc4115_result,
			ebs, UINT64);

static void cmd_add_port_meter_profile_trtcm_rfc4115_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_add_port_meter_profile_trtcm_rfc4115_result *res =
		parsed_result;
	struct rte_mtr_meter_profile mp;
	struct rte_mtr_error error;
	uint32_t profile_id = res->profile_id;
	uint16_t port_id = res->port_id;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	/* Private shaper profile params */
	memset(&mp, 0, sizeof(struct rte_mtr_meter_profile));
	mp.alg = RTE_MTR_TRTCM_RFC4115;
	mp.trtcm_rfc4115.cir = res->cir;
	mp.trtcm_rfc4115.eir = res->eir;
	mp.trtcm_rfc4115.cbs = res->cbs;
	mp.trtcm_rfc4115.ebs = res->ebs;

	ret = rte_mtr_meter_profile_add(port_id, profile_id, &mp, &error);
	if (ret != 0) {
		print_err_msg(&error);
		return;
	}
}

cmdline_parse_inst_t cmd_add_port_meter_profile_trtcm_rfc4115 = {
	.f = cmd_add_port_meter_profile_trtcm_rfc4115_parsed,
	.data = NULL,
	.help_str = "Add port meter profile trtcm (rfc4115)",
	.tokens = {
		(void *)&cmd_add_port_meter_profile_trtcm_rfc4115_add,
		(void *)&cmd_add_port_meter_profile_trtcm_rfc4115_port,
		(void *)&cmd_add_port_meter_profile_trtcm_rfc4115_meter,
		(void *)&cmd_add_port_meter_profile_trtcm_rfc4115_profile,
		(void *)&cmd_add_port_meter_profile_trtcm_rfc4115_trtcm_rfc4115,
		(void *)&cmd_add_port_meter_profile_trtcm_rfc4115_port_id,
		(void *)&cmd_add_port_meter_profile_trtcm_rfc4115_profile_id,
		(void *)&cmd_add_port_meter_profile_trtcm_rfc4115_cir,
		(void *)&cmd_add_port_meter_profile_trtcm_rfc4115_eir,
		(void *)&cmd_add_port_meter_profile_trtcm_rfc4115_cbs,
		(void *)&cmd_add_port_meter_profile_trtcm_rfc4115_ebs,
		NULL,
	},
};

/* *** Delete Port Meter Profile *** */
struct cmd_del_port_meter_profile_result {
	cmdline_fixed_string_t del;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t meter;
	cmdline_fixed_string_t profile;
	uint16_t port_id;
	uint32_t profile_id;
};

cmdline_parse_token_string_t cmd_del_port_meter_profile_del =
	TOKEN_STRING_INITIALIZER(
		struct cmd_del_port_meter_profile_result, del, "del");
cmdline_parse_token_string_t cmd_del_port_meter_profile_port =
	TOKEN_STRING_INITIALIZER(
		struct cmd_del_port_meter_profile_result,
			port, "port");
cmdline_parse_token_string_t cmd_del_port_meter_profile_meter =
	TOKEN_STRING_INITIALIZER(
		struct cmd_del_port_meter_profile_result,
			meter, "meter");
cmdline_parse_token_string_t cmd_del_port_meter_profile_profile =
	TOKEN_STRING_INITIALIZER(
		struct cmd_del_port_meter_profile_result,
			profile, "profile");
cmdline_parse_token_num_t cmd_del_port_meter_profile_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_del_port_meter_profile_result,
			port_id, UINT16);
cmdline_parse_token_num_t cmd_del_port_meter_profile_profile_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_del_port_meter_profile_result,
			profile_id, UINT32);

static void cmd_del_port_meter_profile_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_del_port_meter_profile_result *res = parsed_result;
	struct rte_mtr_error error;
	uint32_t profile_id = res->profile_id;
	uint16_t port_id = res->port_id;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	/* Delete meter profile */
	ret = rte_mtr_meter_profile_delete(port_id, profile_id, &error);
	if (ret != 0) {
		print_err_msg(&error);
		return;
	}
}

cmdline_parse_inst_t cmd_del_port_meter_profile = {
	.f = cmd_del_port_meter_profile_parsed,
	.data = NULL,
	.help_str = "Delete port meter profile",
	.tokens = {
		(void *)&cmd_del_port_meter_profile_del,
		(void *)&cmd_del_port_meter_profile_port,
		(void *)&cmd_del_port_meter_profile_meter,
		(void *)&cmd_del_port_meter_profile_profile,
		(void *)&cmd_del_port_meter_profile_port_id,
		(void *)&cmd_del_port_meter_profile_profile_id,
		NULL,
	},
};

/* *** Create Port Meter Object *** */
struct cmd_create_port_meter_result {
	cmdline_fixed_string_t create;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t meter;
	uint16_t port_id;
	uint32_t mtr_id;
	uint32_t profile_id;
	cmdline_fixed_string_t meter_enable;
	cmdline_fixed_string_t g_action;
	cmdline_fixed_string_t y_action;
	cmdline_fixed_string_t r_action;
	uint64_t statistics_mask;
	uint32_t shared;
	cmdline_multi_string_t meter_input_color;
};

cmdline_parse_token_string_t cmd_create_port_meter_create =
	TOKEN_STRING_INITIALIZER(
		struct cmd_create_port_meter_result, create, "create");
cmdline_parse_token_string_t cmd_create_port_meter_port =
	TOKEN_STRING_INITIALIZER(
		struct cmd_create_port_meter_result, port, "port");
cmdline_parse_token_string_t cmd_create_port_meter_meter =
	TOKEN_STRING_INITIALIZER(
		struct cmd_create_port_meter_result, meter, "meter");
cmdline_parse_token_num_t cmd_create_port_meter_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_create_port_meter_result, port_id, UINT16);
cmdline_parse_token_num_t cmd_create_port_meter_mtr_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_create_port_meter_result, mtr_id, UINT32);
cmdline_parse_token_num_t cmd_create_port_meter_profile_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_create_port_meter_result, profile_id, UINT32);
cmdline_parse_token_string_t cmd_create_port_meter_meter_enable =
	TOKEN_STRING_INITIALIZER(struct cmd_create_port_meter_result,
		meter_enable, "yes#no");
cmdline_parse_token_string_t cmd_create_port_meter_g_action =
	TOKEN_STRING_INITIALIZER(struct cmd_create_port_meter_result,
		g_action, "R#Y#G#D#r#y#g#d");
cmdline_parse_token_string_t cmd_create_port_meter_y_action =
	TOKEN_STRING_INITIALIZER(struct cmd_create_port_meter_result,
		y_action, "R#Y#G#D#r#y#g#d");
cmdline_parse_token_string_t cmd_create_port_meter_r_action =
	TOKEN_STRING_INITIALIZER(struct cmd_create_port_meter_result,
		r_action, "R#Y#G#D#r#y#g#d");
cmdline_parse_token_num_t cmd_create_port_meter_statistics_mask =
	TOKEN_NUM_INITIALIZER(struct cmd_create_port_meter_result,
		statistics_mask, UINT64);
cmdline_parse_token_num_t cmd_create_port_meter_shared =
	TOKEN_NUM_INITIALIZER(struct cmd_create_port_meter_result,
		shared, UINT32);
cmdline_parse_token_string_t cmd_create_port_meter_input_color =
	TOKEN_STRING_INITIALIZER(struct cmd_create_port_meter_result,
		meter_input_color, TOKEN_STRING_MULTI);

static void cmd_create_port_meter_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_create_port_meter_result *res = parsed_result;
	struct rte_mtr_error error;
	struct rte_mtr_params params;
	uint32_t mtr_id = res->mtr_id;
	uint32_t shared = res->shared;
	uint32_t use_prev_meter_color = 0;
	uint16_t port_id = res->port_id;
	enum rte_mtr_color *dscp_table = NULL;
	char *c_str = res->meter_input_color;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	/* Meter params */
	memset(&params, 0, sizeof(struct rte_mtr_params));
	params.meter_profile_id = res->profile_id;

	/* Parse meter input color string params */
	ret = parse_meter_color_str(c_str, &use_prev_meter_color, &dscp_table);
	if (ret) {
		printf(" Meter input color params string parse error\n");
		return;
	}

	params.use_prev_mtr_color = use_prev_meter_color;
	params.dscp_table = dscp_table;

	if (strcmp(res->meter_enable, "yes") == 0)
		params.meter_enable = 1;
	else
		params.meter_enable = 0;

	params.action[RTE_MTR_GREEN] =
		string_to_policer_action(res->g_action);
	params.action[RTE_MTR_YELLOW] =
		string_to_policer_action(res->y_action);
	params.action[RTE_MTR_RED] =
		string_to_policer_action(res->r_action);
	params.stats_mask = res->statistics_mask;

	ret = rte_mtr_create(port_id, mtr_id, &params, shared, &error);
	if (ret != 0) {
		free(dscp_table);
		print_err_msg(&error);
		return;
	}
}

cmdline_parse_inst_t cmd_create_port_meter = {
	.f = cmd_create_port_meter_parsed,
	.data = NULL,
	.help_str = "Create port meter",
	.tokens = {
		(void *)&cmd_create_port_meter_create,
		(void *)&cmd_create_port_meter_port,
		(void *)&cmd_create_port_meter_meter,
		(void *)&cmd_create_port_meter_port_id,
		(void *)&cmd_create_port_meter_mtr_id,
		(void *)&cmd_create_port_meter_profile_id,
		(void *)&cmd_create_port_meter_meter_enable,
		(void *)&cmd_create_port_meter_g_action,
		(void *)&cmd_create_port_meter_y_action,
		(void *)&cmd_create_port_meter_r_action,
		(void *)&cmd_create_port_meter_statistics_mask,
		(void *)&cmd_create_port_meter_shared,
		(void *)&cmd_create_port_meter_input_color,
		NULL,
	},
};

/* *** Enable Meter of MTR Object  *** */
struct cmd_enable_port_meter_result {
	cmdline_fixed_string_t enable;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t meter;
	uint16_t port_id;
	uint32_t mtr_id;
};

cmdline_parse_token_string_t cmd_enable_port_meter_enable =
	TOKEN_STRING_INITIALIZER(
		struct cmd_enable_port_meter_result, enable, "enable");
cmdline_parse_token_string_t cmd_enable_port_meter_port =
	TOKEN_STRING_INITIALIZER(
		struct cmd_enable_port_meter_result, port, "port");
cmdline_parse_token_string_t cmd_enable_port_meter_meter =
	TOKEN_STRING_INITIALIZER(
		struct cmd_enable_port_meter_result, meter, "meter");
cmdline_parse_token_num_t cmd_enable_port_meter_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_enable_port_meter_result, port_id, UINT16);
cmdline_parse_token_num_t cmd_enable_port_meter_mtr_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_enable_port_meter_result, mtr_id, UINT32);

static void cmd_enable_port_meter_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_enable_port_meter_result *res = parsed_result;
	struct rte_mtr_error error;
	uint32_t mtr_id = res->mtr_id;
	uint16_t port_id = res->port_id;

	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	/* Enable Meter */
	ret = rte_mtr_meter_enable(port_id, mtr_id, &error);
	if (ret != 0) {
		print_err_msg(&error);
		return;
	}
}

cmdline_parse_inst_t cmd_enable_port_meter = {
	.f = cmd_enable_port_meter_parsed,
	.data = NULL,
	.help_str = "Enable port meter",
	.tokens = {
		(void *)&cmd_enable_port_meter_enable,
		(void *)&cmd_enable_port_meter_port,
		(void *)&cmd_enable_port_meter_meter,
		(void *)&cmd_enable_port_meter_port_id,
		(void *)&cmd_enable_port_meter_mtr_id,
		NULL,
	},
};

/* *** Disable Meter of MTR Object  *** */
struct cmd_disable_port_meter_result {
	cmdline_fixed_string_t disable;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t meter;
	uint16_t port_id;
	uint32_t mtr_id;
};

cmdline_parse_token_string_t cmd_disable_port_meter_disable =
	TOKEN_STRING_INITIALIZER(
		struct cmd_disable_port_meter_result, disable, "disable");
cmdline_parse_token_string_t cmd_disable_port_meter_port =
	TOKEN_STRING_INITIALIZER(
		struct cmd_disable_port_meter_result, port, "port");
cmdline_parse_token_string_t cmd_disable_port_meter_meter =
	TOKEN_STRING_INITIALIZER(
		struct cmd_disable_port_meter_result, meter, "meter");
cmdline_parse_token_num_t cmd_disable_port_meter_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_disable_port_meter_result, port_id, UINT16);
cmdline_parse_token_num_t cmd_disable_port_meter_mtr_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_disable_port_meter_result, mtr_id, UINT32);

static void cmd_disable_port_meter_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_disable_port_meter_result *res = parsed_result;
	struct rte_mtr_error error;
	uint32_t mtr_id = res->mtr_id;
	uint16_t port_id = res->port_id;

	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	/* Disable Meter */
	ret = rte_mtr_meter_disable(port_id, mtr_id, &error);
	if (ret != 0) {
		print_err_msg(&error);
		return;
	}
}

cmdline_parse_inst_t cmd_disable_port_meter = {
	.f = cmd_disable_port_meter_parsed,
	.data = NULL,
	.help_str = "Disable port meter",
	.tokens = {
		(void *)&cmd_disable_port_meter_disable,
		(void *)&cmd_disable_port_meter_port,
		(void *)&cmd_disable_port_meter_meter,
		(void *)&cmd_disable_port_meter_port_id,
		(void *)&cmd_disable_port_meter_mtr_id,
		NULL,
	},
};

/* *** Delete Port Meter Object *** */
struct cmd_del_port_meter_result {
	cmdline_fixed_string_t del;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t meter;
	uint16_t port_id;
	uint32_t mtr_id;
};

cmdline_parse_token_string_t cmd_del_port_meter_del =
	TOKEN_STRING_INITIALIZER(
		struct cmd_del_port_meter_result, del, "del");
cmdline_parse_token_string_t cmd_del_port_meter_port =
	TOKEN_STRING_INITIALIZER(
		struct cmd_del_port_meter_result, port, "port");
cmdline_parse_token_string_t cmd_del_port_meter_meter =
	TOKEN_STRING_INITIALIZER(
		struct cmd_del_port_meter_result, meter, "meter");
cmdline_parse_token_num_t cmd_del_port_meter_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_del_port_meter_result, port_id, UINT16);
cmdline_parse_token_num_t cmd_del_port_meter_mtr_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_del_port_meter_result, mtr_id, UINT32);

static void cmd_del_port_meter_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_del_port_meter_result *res = parsed_result;
	struct rte_mtr_error error;
	uint32_t mtr_id = res->mtr_id;
	uint16_t port_id = res->port_id;

	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	/* Destroy Meter */
	ret = rte_mtr_destroy(port_id, mtr_id, &error);
	if (ret != 0) {
		print_err_msg(&error);
		return;
	}
}

cmdline_parse_inst_t cmd_del_port_meter = {
	.f = cmd_del_port_meter_parsed,
	.data = NULL,
	.help_str = "Delete port meter",
	.tokens = {
		(void *)&cmd_del_port_meter_del,
		(void *)&cmd_del_port_meter_port,
		(void *)&cmd_del_port_meter_meter,
		(void *)&cmd_del_port_meter_port_id,
		(void *)&cmd_del_port_meter_mtr_id,
		NULL,
	},
};

/* *** Set Port Meter Profile *** */
struct cmd_set_port_meter_profile_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t meter;
	cmdline_fixed_string_t profile;
	uint16_t port_id;
	uint32_t mtr_id;
	uint32_t profile_id;
};

cmdline_parse_token_string_t cmd_set_port_meter_profile_set =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_meter_profile_result, set, "set");
cmdline_parse_token_string_t cmd_set_port_meter_profile_port =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_meter_profile_result, port, "port");
cmdline_parse_token_string_t cmd_set_port_meter_profile_meter =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_meter_profile_result, meter, "meter");
cmdline_parse_token_string_t cmd_set_port_meter_profile_profile =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_meter_profile_result, profile, "profile");
cmdline_parse_token_num_t cmd_set_port_meter_profile_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_set_port_meter_profile_result, port_id, UINT16);
cmdline_parse_token_num_t cmd_set_port_meter_profile_mtr_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_set_port_meter_profile_result, mtr_id, UINT32);
cmdline_parse_token_num_t cmd_set_port_meter_profile_profile_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_set_port_meter_profile_result, profile_id, UINT32);

static void cmd_set_port_meter_profile_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_set_port_meter_profile_result *res = parsed_result;
	struct rte_mtr_error error;
	uint32_t mtr_id = res->mtr_id;
	uint32_t profile_id = res->profile_id;
	uint16_t port_id = res->port_id;

	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	/* Set meter profile */
	ret = rte_mtr_meter_profile_update(port_id, mtr_id,
		profile_id, &error);
	if (ret != 0) {
		print_err_msg(&error);
		return;
	}
}

cmdline_parse_inst_t cmd_set_port_meter_profile = {
	.f = cmd_set_port_meter_profile_parsed,
	.data = NULL,
	.help_str = "Set port meter profile",
	.tokens = {
		(void *)&cmd_set_port_meter_profile_set,
		(void *)&cmd_set_port_meter_profile_port,
		(void *)&cmd_set_port_meter_profile_meter,
		(void *)&cmd_set_port_meter_profile_profile,
		(void *)&cmd_set_port_meter_profile_port_id,
		(void *)&cmd_set_port_meter_profile_mtr_id,
		(void *)&cmd_set_port_meter_profile_profile_id,
		NULL,
	},
};

/* *** Set Port Meter DSCP Table *** */
struct cmd_set_port_meter_dscp_table_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t meter;
	cmdline_fixed_string_t dscp_table;
	cmdline_multi_string_t token_string;
};

cmdline_parse_token_string_t cmd_set_port_meter_dscp_table_set =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_meter_dscp_table_result, set, "set");
cmdline_parse_token_string_t cmd_set_port_meter_dscp_table_port =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_meter_dscp_table_result, port, "port");
cmdline_parse_token_string_t cmd_set_port_meter_dscp_table_meter =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_meter_dscp_table_result, meter, "meter");
cmdline_parse_token_string_t cmd_set_port_meter_dscp_table_dscp_table =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_meter_dscp_table_result,
		dscp_table, "dscp table");
cmdline_parse_token_string_t cmd_set_port_meter_dscp_table_token_string =
	TOKEN_STRING_INITIALIZER(struct cmd_set_port_meter_dscp_table_result,
		token_string, TOKEN_STRING_MULTI);

static void cmd_set_port_meter_dscp_table_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_set_port_meter_dscp_table_result *res = parsed_result;
	struct rte_mtr_error error;
	enum rte_mtr_color *dscp_table = NULL;
	char *t_str = res->token_string;
	uint32_t mtr_id = 0;
	uint16_t port_id;
	int ret;

	/* Parse string */
	ret = parse_multi_token_string(t_str, &port_id, &mtr_id, &dscp_table);
	if (ret) {
		printf(" Multi token string parse error\n");
		return;
	}

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		goto free_table;

	/* Update Meter DSCP Table*/
	ret = rte_mtr_meter_dscp_table_update(port_id, mtr_id,
		dscp_table, &error);
	if (ret != 0)
		print_err_msg(&error);

free_table:
	free(dscp_table);
}

cmdline_parse_inst_t cmd_set_port_meter_dscp_table = {
	.f = cmd_set_port_meter_dscp_table_parsed,
	.data = NULL,
	.help_str = "Update port meter dscp table",
	.tokens = {
		(void *)&cmd_set_port_meter_dscp_table_set,
		(void *)&cmd_set_port_meter_dscp_table_port,
		(void *)&cmd_set_port_meter_dscp_table_meter,
		(void *)&cmd_set_port_meter_dscp_table_dscp_table,
		(void *)&cmd_set_port_meter_dscp_table_token_string,
		NULL,
	},
};

/* *** Set Port Meter Policer Action *** */
struct cmd_set_port_meter_policer_action_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t meter;
	cmdline_fixed_string_t policer;
	cmdline_fixed_string_t action;
	uint16_t port_id;
	uint32_t mtr_id;
	uint32_t action_mask;
	cmdline_multi_string_t policer_action;
};

cmdline_parse_token_string_t cmd_set_port_meter_policer_action_set =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_meter_policer_action_result, set, "set");
cmdline_parse_token_string_t cmd_set_port_meter_policer_action_port =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_meter_policer_action_result, port, "port");
cmdline_parse_token_string_t cmd_set_port_meter_policer_action_meter =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_meter_policer_action_result, meter,
		"meter");
cmdline_parse_token_string_t cmd_set_port_meter_policer_action_policer =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_meter_policer_action_result, policer,
		"policer");
cmdline_parse_token_string_t cmd_set_port_meter_policer_action_action =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_meter_policer_action_result, action,
		"action");
cmdline_parse_token_num_t cmd_set_port_meter_policer_action_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_set_port_meter_policer_action_result, port_id,
		UINT16);
cmdline_parse_token_num_t cmd_set_port_meter_policer_action_mtr_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_set_port_meter_policer_action_result, mtr_id,
		UINT32);
cmdline_parse_token_num_t cmd_set_port_meter_policer_action_action_mask =
	TOKEN_NUM_INITIALIZER(
		struct cmd_set_port_meter_policer_action_result, action_mask,
		UINT32);
cmdline_parse_token_string_t cmd_set_port_meter_policer_action_policer_action =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_meter_policer_action_result,
		policer_action, TOKEN_STRING_MULTI);

static void cmd_set_port_meter_policer_action_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_set_port_meter_policer_action_result *res = parsed_result;
	enum rte_mtr_policer_action *actions;
	struct rte_mtr_error error;
	uint32_t mtr_id = res->mtr_id;
	uint32_t action_mask = res->action_mask;
	uint16_t port_id = res->port_id;
	char *p_str = res->policer_action;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	/* Check: action mask */
	if (action_mask == 0 || (action_mask & (~0x7UL))) {
		printf(" Policer action mask not correct (error)\n");
		return;
	}

	/* Allocate memory for policer actions */
	actions = (enum rte_mtr_policer_action *)malloc(RTE_MTR_COLORS *
		sizeof(enum rte_mtr_policer_action));
	if (actions == NULL) {
		printf("Memory for policer actions not allocated (error)\n");
		return;
	}
	/* Parse policer action string */
	ret = parse_policer_action_string(p_str, action_mask, actions);
	if (ret) {
		printf(" Policer action string parse error\n");
		free(actions);
		return;
	}

	ret = rte_mtr_policer_actions_update(port_id, mtr_id,
		action_mask, actions, &error);
	if (ret != 0) {
		print_err_msg(&error);
		return;
	}

	free(actions);
}

cmdline_parse_inst_t cmd_set_port_meter_policer_action = {
	.f = cmd_set_port_meter_policer_action_parsed,
	.data = NULL,
	.help_str = "Set port meter policer action",
	.tokens = {
		(void *)&cmd_set_port_meter_policer_action_set,
		(void *)&cmd_set_port_meter_policer_action_port,
		(void *)&cmd_set_port_meter_policer_action_meter,
		(void *)&cmd_set_port_meter_policer_action_policer,
		(void *)&cmd_set_port_meter_policer_action_action,
		(void *)&cmd_set_port_meter_policer_action_port_id,
		(void *)&cmd_set_port_meter_policer_action_mtr_id,
		(void *)&cmd_set_port_meter_policer_action_action_mask,
		(void *)&cmd_set_port_meter_policer_action_policer_action,
		NULL,
	},
};

/* *** Set Port Meter Stats Mask *** */
struct cmd_set_port_meter_stats_mask_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t meter;
	cmdline_fixed_string_t stats;
	cmdline_fixed_string_t mask;
	uint16_t port_id;
	uint32_t mtr_id;
	uint64_t stats_mask;
};

cmdline_parse_token_string_t cmd_set_port_meter_stats_mask_set =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_meter_stats_mask_result, set, "set");
cmdline_parse_token_string_t cmd_set_port_meter_stats_mask_port =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_meter_stats_mask_result, port, "port");
cmdline_parse_token_string_t cmd_set_port_meter_stats_mask_meter =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_meter_stats_mask_result, meter, "meter");
cmdline_parse_token_string_t cmd_set_port_meter_stats_mask_stats =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_meter_stats_mask_result, stats, "stats");
cmdline_parse_token_string_t cmd_set_port_meter_stats_mask_mask =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_meter_stats_mask_result, mask, "mask");
cmdline_parse_token_num_t cmd_set_port_meter_stats_mask_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_set_port_meter_stats_mask_result, port_id, UINT16);
cmdline_parse_token_num_t cmd_set_port_meter_stats_mask_mtr_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_set_port_meter_stats_mask_result, mtr_id, UINT32);
cmdline_parse_token_num_t cmd_set_port_meter_stats_mask_stats_mask =
	TOKEN_NUM_INITIALIZER(
		struct cmd_set_port_meter_stats_mask_result, stats_mask,
		UINT64);

static void cmd_set_port_meter_stats_mask_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_set_port_meter_stats_mask_result *res = parsed_result;
	struct rte_mtr_error error;
	uint64_t stats_mask = res->stats_mask;
	uint32_t mtr_id = res->mtr_id;
	uint16_t port_id = res->port_id;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	ret = rte_mtr_stats_update(port_id, mtr_id, stats_mask, &error);
	if (ret != 0) {
		print_err_msg(&error);
		return;
	}
}

cmdline_parse_inst_t cmd_set_port_meter_stats_mask = {
	.f = cmd_set_port_meter_stats_mask_parsed,
	.data = NULL,
	.help_str = "Set port meter stats mask",
	.tokens = {
		(void *)&cmd_set_port_meter_stats_mask_set,
		(void *)&cmd_set_port_meter_stats_mask_port,
		(void *)&cmd_set_port_meter_stats_mask_meter,
		(void *)&cmd_set_port_meter_stats_mask_stats,
		(void *)&cmd_set_port_meter_stats_mask_mask,
		(void *)&cmd_set_port_meter_stats_mask_port_id,
		(void *)&cmd_set_port_meter_stats_mask_mtr_id,
		(void *)&cmd_set_port_meter_stats_mask_stats_mask,
		NULL,
	},
};

/* *** Show Port Meter Stats *** */
struct cmd_show_port_meter_stats_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t meter;
	cmdline_fixed_string_t stats;
	uint16_t port_id;
	uint32_t mtr_id;
	cmdline_fixed_string_t clear;
};

cmdline_parse_token_string_t cmd_show_port_meter_stats_show =
	TOKEN_STRING_INITIALIZER(
		struct cmd_show_port_meter_stats_result, show, "show");
cmdline_parse_token_string_t cmd_show_port_meter_stats_port =
	TOKEN_STRING_INITIALIZER(
		struct cmd_show_port_meter_stats_result, port, "port");
cmdline_parse_token_string_t cmd_show_port_meter_stats_meter =
	TOKEN_STRING_INITIALIZER(
		struct cmd_show_port_meter_stats_result, meter, "meter");
cmdline_parse_token_string_t cmd_show_port_meter_stats_stats =
	TOKEN_STRING_INITIALIZER(
		struct cmd_show_port_meter_stats_result, stats, "stats");
cmdline_parse_token_num_t cmd_show_port_meter_stats_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_show_port_meter_stats_result, port_id, UINT16);
cmdline_parse_token_num_t cmd_show_port_meter_stats_mtr_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_show_port_meter_stats_result, mtr_id, UINT32);
cmdline_parse_token_string_t cmd_show_port_meter_stats_clear =
	TOKEN_STRING_INITIALIZER(
		struct cmd_show_port_meter_stats_result, clear, "yes#no");

static void cmd_show_port_meter_stats_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_show_port_meter_stats_result *res = parsed_result;
	struct rte_mtr_stats stats;
	uint64_t stats_mask = 0;
	struct rte_mtr_error error;
	uint32_t mtr_id = res->mtr_id;
	uint32_t clear = 0;
	uint16_t port_id = res->port_id;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	if (strcmp(res->clear, "yes") == 0)
		clear = 1;

	memset(&stats, 0, sizeof(struct rte_mtr_stats));
	ret = rte_mtr_stats_read(port_id, mtr_id, &stats,
		&stats_mask, clear, &error);
	if (ret != 0) {
		print_err_msg(&error);
		return;
	}

	/* Display stats */
	if (stats_mask & RTE_MTR_STATS_N_PKTS_GREEN)
		printf("\tPkts G: %" PRIu64 "\n",
			stats.n_pkts[RTE_MTR_GREEN]);
	if (stats_mask & RTE_MTR_STATS_N_BYTES_GREEN)
		printf("\tBytes G: %" PRIu64 "\n",
			stats.n_bytes[RTE_MTR_GREEN]);
	if (stats_mask & RTE_MTR_STATS_N_PKTS_YELLOW)
		printf("\tPkts Y: %" PRIu64 "\n",
			stats.n_pkts[RTE_MTR_YELLOW]);
	if (stats_mask & RTE_MTR_STATS_N_BYTES_YELLOW)
		printf("\tBytes Y: %" PRIu64 "\n",
			stats.n_bytes[RTE_MTR_YELLOW]);
	if (stats_mask & RTE_MTR_STATS_N_PKTS_RED)
		printf("\tPkts R: %" PRIu64 "\n",
			stats.n_pkts[RTE_MTR_RED]);
	if (stats_mask & RTE_MTR_STATS_N_BYTES_RED)
		printf("\tBytes R: %" PRIu64 "\n",
			stats.n_bytes[RTE_MTR_RED]);
	if (stats_mask & RTE_MTR_STATS_N_PKTS_DROPPED)
		printf("\tPkts DROPPED: %" PRIu64 "\n",
			stats.n_pkts_dropped);
	if (stats_mask & RTE_MTR_STATS_N_BYTES_DROPPED)
		printf("\tBytes DROPPED: %" PRIu64 "\n",
			stats.n_bytes_dropped);
}

cmdline_parse_inst_t cmd_show_port_meter_stats = {
	.f = cmd_show_port_meter_stats_parsed,
	.data = NULL,
	.help_str = "Show port meter stats",
	.tokens = {
		(void *)&cmd_show_port_meter_stats_show,
		(void *)&cmd_show_port_meter_stats_port,
		(void *)&cmd_show_port_meter_stats_meter,
		(void *)&cmd_show_port_meter_stats_stats,
		(void *)&cmd_show_port_meter_stats_port_id,
		(void *)&cmd_show_port_meter_stats_mtr_id,
		(void *)&cmd_show_port_meter_stats_clear,
		NULL,
	},
};
