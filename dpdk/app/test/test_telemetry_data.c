/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Intel Corporation
 */

#include <string.h>
#include <sys/socket.h>
#ifndef RTE_EXEC_ENV_WINDOWS
#include <sys/un.h>
#endif
#include <unistd.h>
#include <limits.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_telemetry.h>
#include <rte_string_fns.h>

#include "test.h"
#include "telemetry_data.h"

#define TELEMETRY_VERSION "v2"
#define REQUEST_CMD "/test"
#define BUF_SIZE 1024
#define CHECK_OUTPUT(exp) check_output(__func__, "{\"" REQUEST_CMD "\":" exp "}")

/*
 * Runs a series of test cases, checking the output of telemetry for various different types of
 * responses. On init, a single connection to DPDK telemetry is made, and a single telemetry
 * callback "/test" is registered. That callback always returns the value of the static global
 * variable "response_data", so each test case builds up that structure, and then calls the
 * "check_output" function to ensure the response received over the socket for "/test" matches
 * that expected for the response_data value populated.
 *
 * NOTE:
 * - each test case function in this file should be added to the "test_cases" array in
 *   test_telemetry_data function at the bottom of the file.
 * - each test case function should populate the "response_data" global variable (below)
 *   with the appropriate values which would be returned from a simulated telemetry function.
 *   Then the test case function should have "return CHECK_OUTPUT(<expected_data>);" as it's
 *   last line. The test infrastructure will then validate that the output when returning
 *   "response_data" structure matches that in "<expected_data>".
 * - the response_data structure will be zeroed on entry to each test function, so each function
 *   can begin with a call to "rte_tel_data_string/start_array/start_dict" as so desired.
 * - the expected_output for each function can be just the actual json data from the
 *   "response_data" value. The CHECK_OUTPUT macro will include the appropriate "{\"/test\": ... }"
 *   structure around the json output.
 *
 *  See test_simple_string(), or test_case_array_int() for a basic examples of test cases.
 */


static struct rte_tel_data response_data;
static int sock;


/*
 * This function is the callback registered with Telemetry to be used when
 * the /test command is requested. This callback returns the global data built
 * up by the individual test cases.
 */
static int
telemetry_test_cb(const char *cmd __rte_unused, const char *params __rte_unused,
		struct rte_tel_data *d)
{
	*d = response_data;
	return 0;
}

/*
 * This function is called by each test case function. It communicates with
 * the telemetry socket by requesting the /test command, and reading the
 * response. The expected response is passed in by the test case function,
 * and is compared to the actual response received from Telemetry.
 */
static int
check_output(const char *func_name, const char *expected)
{
	int bytes;
	char buf[BUF_SIZE * 16];
	if (write(sock, REQUEST_CMD, strlen(REQUEST_CMD)) < 0) {
		printf("%s: Error with socket write - %s\n", __func__,
				strerror(errno));
		return -1;
	}
	bytes = read(sock, buf, sizeof(buf) - 1);
	if (bytes < 0) {
		printf("%s: Error with socket read - %s\n", __func__,
				strerror(errno));
		return -1;
	}
	buf[bytes] = '\0';
	printf("%s: buf = '%s', expected = '%s'\n", func_name, buf, expected);
	return strncmp(expected, buf, sizeof(buf));
}

static int
test_null_return(void)
{
	return CHECK_OUTPUT("null");
}

static int
test_simple_string(void)
{
	rte_tel_data_string(&response_data, "Simple string");

	return CHECK_OUTPUT("\"Simple string\"");
}

static int
test_dict_with_array_int_values(void)
{
	int i;

	struct rte_tel_data *child_data = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data, RTE_TEL_INT_VAL);

	struct rte_tel_data *child_data2 = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data2, RTE_TEL_INT_VAL);

	rte_tel_data_start_dict(&response_data);

	for (i = 0; i < 5; i++) {
		rte_tel_data_add_array_int(child_data, i);
		rte_tel_data_add_array_int(child_data2, i);
	}

	rte_tel_data_add_dict_container(&response_data, "dict_0",
	 child_data, 0);
	rte_tel_data_add_dict_container(&response_data, "dict_1",
	 child_data2, 0);

	return CHECK_OUTPUT("{\"dict_0\":[0,1,2,3,4],\"dict_1\":[0,1,2,3,4]}");
}

static int
test_array_with_array_int_values(void)
{
	int i;

	struct rte_tel_data *child_data = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data, RTE_TEL_INT_VAL);

	struct rte_tel_data *child_data2 = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data2, RTE_TEL_INT_VAL);

	rte_tel_data_start_array(&response_data, RTE_TEL_CONTAINER);

	for (i = 0; i < 5; i++) {
		rte_tel_data_add_array_int(child_data, i);
		rte_tel_data_add_array_int(child_data2, i);
	}
	rte_tel_data_add_array_container(&response_data, child_data, 0);
	rte_tel_data_add_array_container(&response_data, child_data2, 0);

	return CHECK_OUTPUT("[[0,1,2,3,4],[0,1,2,3,4]]");
}

static int
test_case_array_int(void)
{
	int i;

	rte_tel_data_start_array(&response_data, RTE_TEL_INT_VAL);
	for (i = 0; i < 5; i++)
		rte_tel_data_add_array_int(&response_data, i);
	return CHECK_OUTPUT("[0,1,2,3,4]");
}

static int
test_case_add_dict_int(void)
{
	int i = 0;
	char name_of_value[8];

	rte_tel_data_start_dict(&response_data);

	for (i = 0; i < 5; i++) {
		sprintf(name_of_value, "dict_%d", i);
		rte_tel_data_add_dict_int(&response_data, name_of_value, i);
	}

	return CHECK_OUTPUT("{\"dict_0\":0,\"dict_1\":1,\"dict_2\":2,\"dict_3\":3,\"dict_4\":4}");
}

static int
test_case_array_string(void)
{
	rte_tel_data_start_array(&response_data, RTE_TEL_STRING_VAL);
	rte_tel_data_add_array_string(&response_data, "aaaa");
	rte_tel_data_add_array_string(&response_data, "bbbb");
	rte_tel_data_add_array_string(&response_data, "cccc");
	rte_tel_data_add_array_string(&response_data, "dddd");
	rte_tel_data_add_array_string(&response_data, "eeee");

	return CHECK_OUTPUT("[\"aaaa\",\"bbbb\",\"cccc\",\"dddd\",\"eeee\"]");
}

static int
test_case_add_dict_string(void)
{
	rte_tel_data_start_dict(&response_data);

	rte_tel_data_add_dict_string(&response_data, "dict_0", "aaaa");
	rte_tel_data_add_dict_string(&response_data, "dict_1", "bbbb");
	rte_tel_data_add_dict_string(&response_data, "dict_2", "cccc");
	rte_tel_data_add_dict_string(&response_data, "dict_3", "dddd");

	return CHECK_OUTPUT("{\"dict_0\":\"aaaa\",\"dict_1\":\"bbbb\",\"dict_2\":\"cccc\",\"dict_3\":\"dddd\"}");
}


static int
test_dict_with_array_string_values(void)
{
	struct rte_tel_data *child_data = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data, RTE_TEL_STRING_VAL);

	struct rte_tel_data *child_data2 = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data2, RTE_TEL_STRING_VAL);

	rte_tel_data_start_dict(&response_data);

	rte_tel_data_add_array_string(child_data, "aaaa");
	rte_tel_data_add_array_string(child_data2, "bbbb");

	rte_tel_data_add_dict_container(&response_data, "dict_0",
	 child_data, 0);
	rte_tel_data_add_dict_container(&response_data, "dict_1",
	 child_data2, 0);

	return CHECK_OUTPUT("{\"dict_0\":[\"aaaa\"],\"dict_1\":[\"bbbb\"]}");
}

static int
test_dict_with_dict_values(void)
{
	struct rte_tel_data *dict_of_dicts = rte_tel_data_alloc();
	rte_tel_data_start_dict(dict_of_dicts);

	struct rte_tel_data *child_data = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data, RTE_TEL_STRING_VAL);

	struct rte_tel_data *child_data2 = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data2, RTE_TEL_STRING_VAL);

	rte_tel_data_start_dict(&response_data);

	rte_tel_data_add_array_string(child_data, "aaaa");
	rte_tel_data_add_array_string(child_data2, "bbbb");
	rte_tel_data_add_dict_container(dict_of_dicts, "dict_0",
			child_data, 0);
	rte_tel_data_add_dict_container(dict_of_dicts, "dict_1",
			child_data2, 0);
	rte_tel_data_add_dict_container(&response_data, "dict_of_dicts",
			dict_of_dicts, 0);

	return CHECK_OUTPUT("{\"dict_of_dicts\":{\"dict_0\":[\"aaaa\"],\"dict_1\":[\"bbbb\"]}}");
}

static int
test_array_with_array_string_values(void)
{
	struct rte_tel_data *child_data = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data, RTE_TEL_STRING_VAL);

	struct rte_tel_data *child_data2 = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data2, RTE_TEL_STRING_VAL);

	rte_tel_data_start_array(&response_data, RTE_TEL_CONTAINER);

	rte_tel_data_add_array_string(child_data, "aaaa");
	rte_tel_data_add_array_string(child_data2, "bbbb");

	rte_tel_data_add_array_container(&response_data, child_data, 0);
	rte_tel_data_add_array_container(&response_data, child_data2, 0);

	return CHECK_OUTPUT("[[\"aaaa\"],[\"bbbb\"]]");
}

static int
test_case_array_u64(void)
{
	int i;

	rte_tel_data_start_array(&response_data, RTE_TEL_U64_VAL);
	for (i = 0; i < 5; i++)
		rte_tel_data_add_array_u64(&response_data, i);
	return CHECK_OUTPUT("[0,1,2,3,4]");
}

static int
test_case_add_dict_u64(void)
{
	int i = 0;
	char name_of_value[8];

	rte_tel_data_start_dict(&response_data);

	for (i = 0; i < 5; i++) {
		sprintf(name_of_value, "dict_%d", i);
		rte_tel_data_add_dict_u64(&response_data, name_of_value, i);
	}
	return CHECK_OUTPUT("{\"dict_0\":0,\"dict_1\":1,\"dict_2\":2,\"dict_3\":3,\"dict_4\":4}");
}

static int
test_dict_with_array_u64_values(void)
{
	int i;

	struct rte_tel_data *child_data = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data, RTE_TEL_U64_VAL);

	struct rte_tel_data *child_data2 = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data2, RTE_TEL_U64_VAL);

	rte_tel_data_start_dict(&response_data);

	for (i = 0; i < 10; i++) {
		rte_tel_data_add_array_u64(child_data, i);
		rte_tel_data_add_array_u64(child_data2, i);
	}

	rte_tel_data_add_dict_container(&response_data, "dict_0",
	 child_data, 0);
	rte_tel_data_add_dict_container(&response_data, "dict_1",
	 child_data2, 0);

	return CHECK_OUTPUT("{\"dict_0\":[0,1,2,3,4,5,6,7,8,9],\"dict_1\":[0,1,2,3,4,5,6,7,8,9]}");
}

static int
test_array_with_array_u64_values(void)
{
	int i;

	struct rte_tel_data *child_data = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data, RTE_TEL_U64_VAL);

	struct rte_tel_data *child_data2 = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data2, RTE_TEL_U64_VAL);

	rte_tel_data_start_array(&response_data, RTE_TEL_CONTAINER);

	for (i = 0; i < 5; i++) {
		rte_tel_data_add_array_u64(child_data, i);
		rte_tel_data_add_array_u64(child_data2, i);
	}
	rte_tel_data_add_array_container(&response_data, child_data, 0);
	rte_tel_data_add_array_container(&response_data, child_data2, 0);

	return CHECK_OUTPUT("[[0,1,2,3,4],[0,1,2,3,4]]");
}

static int
test_string_char_escaping(void)
{
	rte_tel_data_string(&response_data, "hello,\nworld\n");
	return CHECK_OUTPUT("\"hello,\\nworld\\n\"");
}

static int
test_array_char_escaping(void)
{
	rte_tel_data_start_array(&response_data, RTE_TEL_STRING_VAL);
	rte_tel_data_add_array_string(&response_data, "\\escape\r");
	rte_tel_data_add_array_string(&response_data, "characters\n");
	return CHECK_OUTPUT("[\"\\\\escape\\r\",\"characters\\n\"]");
}

static int
test_dict_char_escaping(void)
{
	rte_tel_data_start_dict(&response_data);
	rte_tel_data_add_dict_string(&response_data, "name", "escaped\n\tvalue");
	return CHECK_OUTPUT("{\"name\":\"escaped\\n\\tvalue\"}");
}

static int
connect_to_socket(void)
{
	char buf[BUF_SIZE];
	int sock, bytes;
	struct sockaddr_un telem_addr;

	sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sock < 0) {
		printf("\n%s: Error creating socket: %s\n", __func__,
				strerror(errno));
		return -1;
	}
	telem_addr.sun_family = AF_UNIX;
	snprintf(telem_addr.sun_path, sizeof(telem_addr.sun_path),
			"%s/dpdk_telemetry.%s",	rte_eal_get_runtime_dir(),
			TELEMETRY_VERSION);
	if (connect(sock, (struct sockaddr *) &telem_addr,
			sizeof(telem_addr)) < 0) {
		printf("\n%s: Error connecting to socket: %s\n", __func__,
				strerror(errno));
		close(sock);
		return -1;
	}

	bytes = read(sock, buf, sizeof(buf) - 1);
	if (bytes < 0) {
		printf("%s: Error with socket read - %s\n", __func__,
				strerror(errno));
		close(sock);
		return -1;
	}
	buf[bytes] = '\0';
	printf("\n%s: %s\n", __func__, buf);
	return sock;
}

static int
telemetry_data_autotest(void)
{
	typedef int (*test_case)(void);
	unsigned int i = 0;

	sock = connect_to_socket();
	if (sock <= 0)
		return -1;

	test_case test_cases[] = {
			test_null_return,
			test_simple_string,
			test_case_array_string,
			test_case_array_int, test_case_array_u64,
			test_case_add_dict_int, test_case_add_dict_u64,
			test_case_add_dict_string,
			test_dict_with_array_int_values,
			test_dict_with_array_u64_values,
			test_dict_with_array_string_values,
			test_dict_with_dict_values,
			test_array_with_array_int_values,
			test_array_with_array_u64_values,
			test_array_with_array_string_values,
			test_string_char_escaping,
			test_array_char_escaping,
			test_dict_char_escaping,
	};

	rte_telemetry_register_cmd(REQUEST_CMD, telemetry_test_cb, "Test");
	for (i = 0; i < RTE_DIM(test_cases); i++) {
		memset(&response_data, 0, sizeof(response_data));
		if (test_cases[i]() != 0) {
			close(sock);
			return -1;
		}
	}
	close(sock);
	return 0;
}

REGISTER_TEST_COMMAND(telemetry_data_autotest, telemetry_data_autotest);
