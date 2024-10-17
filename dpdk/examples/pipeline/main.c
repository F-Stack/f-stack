/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>

#include <rte_launch.h>
#include <rte_eal.h>

#include "cli.h"
#include "conn.h"
#include "obj.h"
#include "thread.h"

static const char usage[] =
	"%s EAL_ARGS -- [-h HOST] [-p PORT] [-s SCRIPT]\n";

static struct app_params {
	struct conn_params conn;
	char *script_name;
} app = {
	.conn = {
		.welcome = "\nWelcome!\n\n",
		.prompt = "pipeline> ",
		.addr = "0.0.0.0",
		.port = 8086,
		.buf_size = 1024 * 1024,
		.msg_in_len_max = 1024,
		.msg_out_len_max = 1024 * 1024,
		.msg_handle = cli_process,
		.msg_handle_arg = NULL, /* set later. */
	},
	.script_name = NULL,
};

static int
parse_args(int argc, char **argv)
{
	char *app_name = argv[0];
	struct option lgopts[] = {
		{ NULL,  0, 0, 0 }
	};
	int opt, option_index;
	int h_present, p_present, s_present, n_args, i;

	/* Skip EAL input args */
	n_args = argc;
	for (i = 0; i < n_args; i++)
		if (strcmp(argv[i], "--") == 0) {
			argc -= i;
			argv += i;
			break;
		}

	if (i == n_args)
		return 0;

	/* Parse args */
	h_present = 0;
	p_present = 0;
	s_present = 0;

	while ((opt = getopt_long(argc, argv, "h:p:s:", lgopts, &option_index))
			!= EOF)
		switch (opt) {
		case 'h':
			if (h_present) {
				printf("Error: Multiple -h arguments\n");
				return -1;
			}
			h_present = 1;

			if (!strlen(optarg)) {
				printf("Error: Argument for -h not provided\n");
				return -1;
			}

			app.conn.addr = strdup(optarg);
			if (app.conn.addr == NULL) {
				printf("Error: Not enough memory\n");
				return -1;
			}
			break;

		case 'p':
			if (p_present) {
				printf("Error: Multiple -p arguments\n");
				return -1;
			}
			p_present = 1;

			if (!strlen(optarg)) {
				printf("Error: Argument for -p not provided\n");
				return -1;
			}

			app.conn.port = (uint16_t) atoi(optarg);
			break;

		case 's':
			if (s_present) {
				printf("Error: Multiple -s arguments\n");
				return -1;
			}
			s_present = 1;

			if (!strlen(optarg)) {
				printf("Error: Argument for -s not provided\n");
				return -1;
			}

			app.script_name = strdup(optarg);
			if (app.script_name == NULL) {
				printf("Error: Not enough memory\n");
				return -1;
			}
			break;

		default:
			printf(usage, app_name);
			return -1;
		}

	optind = 1; /* reset getopt lib */

	return 0;
}

int
main(int argc, char **argv)
{
	struct conn *conn;
	struct obj *obj;
	int status;

	/* Parse application arguments */
	status = parse_args(argc, argv);
	if (status < 0)
		return status;

	/* EAL */
	status = rte_eal_init(argc, argv);
	if (status < 0) {
		printf("Error: EAL initialization failed (%d)\n", status);
		return status;
	};

	/* Obj */
	obj = obj_init();
	if (!obj) {
		printf("Error: Obj initialization failed (%d)\n", status);
		return status;
	}

	/* Thread */
	status = thread_init();
	if (status) {
		printf("Error: Thread initialization failed (%d)\n", status);
		return status;
	}

	rte_eal_mp_remote_launch(
		thread_main,
		NULL,
		SKIP_MAIN);

	/* Script */
	if (app.script_name)
		cli_script_process(app.script_name,
			app.conn.msg_in_len_max,
			app.conn.msg_out_len_max,
			obj);

	/* Connectivity */
	app.conn.msg_handle_arg = obj;
	conn = conn_init(&app.conn);
	if (!conn) {
		printf("Error: Connectivity initialization failed (%d)\n",
			status);
		return status;
	};

	/* Dispatch loop */
	for ( ; ; ) {
		conn_poll_for_conn(conn);

		conn_poll_for_msg(conn);
	}

	/* clean up the EAL */
	rte_eal_cleanup();
}
