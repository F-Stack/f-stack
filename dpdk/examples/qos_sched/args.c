/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <locale.h>
#include <unistd.h>
#include <limits.h>
#include <getopt.h>

#include <rte_log.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_string_fns.h>

#include "main.h"

#define APP_NAME "qos_sched"
#define MAX_OPT_VALUES 8
#define SYS_CPU_DIR "/sys/devices/system/cpu/cpu%u/topology/"

static uint32_t app_master_core = 1;
static uint32_t app_numa_mask;
static uint64_t app_used_core_mask = 0;
static uint64_t app_used_port_mask = 0;
static uint64_t app_used_rx_port_mask = 0;
static uint64_t app_used_tx_port_mask = 0;


static const char usage[] =
	"                                                                               \n"
	"    %s <APP PARAMS>                                                            \n"
	"                                                                               \n"
	"Application mandatory parameters:                                              \n"
	"    --pfc \"RX PORT, TX PORT, RX LCORE, WT LCORE\" : Packet flow configuration \n"
	"           multiple pfc can be configured in command line                      \n"
	"                                                                               \n"
	"Application optional parameters:                                               \n"
        "    --i     : run in interactive mode (default value is %u)                    \n"
	"    --mst I : master core index (default value is %u)                          \n"
	"    --rsz \"A, B, C\" :   Ring sizes                                           \n"
	"           A = Size (in number of buffer descriptors) of each of the NIC RX    \n"
	"               rings read by the I/O RX lcores (default value is %u)           \n"
	"           B = Size (in number of elements) of each of the SW rings used by the\n"
	"               I/O RX lcores to send packets to worker lcores (default value is\n"
	"               %u)                                                             \n"
	"           C = Size (in number of buffer descriptors) of each of the NIC TX    \n"
	"               rings written by worker lcores (default value is %u)            \n"
	"    --bsz \"A, B, C, D\": Burst sizes                                          \n"
	"           A = I/O RX lcore read burst size from NIC RX (default value is %u)  \n"
	"           B = I/O RX lcore write burst size to output SW rings,               \n"
	"               Worker lcore read burst size from input SW rings,               \n"
	"               QoS enqueue size (default value is %u)                          \n"
	"           C = QoS dequeue size (default value is %u)                          \n"
	"           D = Worker lcore write burst size to NIC TX (default value is %u)   \n"
	"    --msz M : Mempool size (in number of mbufs) for each pfc (default %u)      \n"
	"    --rth \"A, B, C\" :   RX queue threshold parameters                        \n"
	"           A = RX prefetch threshold (default value is %u)                     \n"
	"           B = RX host threshold (default value is %u)                         \n"
	"           C = RX write-back threshold (default value is %u)                   \n"
	"    --tth \"A, B, C\" :   TX queue threshold parameters                        \n"
	"           A = TX prefetch threshold (default value is %u)                     \n"
	"           B = TX host threshold (default value is %u)                         \n"
	"           C = TX write-back threshold (default value is %u)                   \n"
	"    --cfg FILE : profile configuration to load                                 \n"
;

/* display usage */
static void
app_usage(const char *prgname)
{
	printf(usage, prgname, APP_INTERACTIVE_DEFAULT, app_master_core,
		APP_RX_DESC_DEFAULT, APP_RING_SIZE, APP_TX_DESC_DEFAULT,
		MAX_PKT_RX_BURST, PKT_ENQUEUE, PKT_DEQUEUE,
		MAX_PKT_TX_BURST, NB_MBUF,
		RX_PTHRESH, RX_HTHRESH, RX_WTHRESH,
		TX_PTHRESH, TX_HTHRESH, TX_WTHRESH
		);
}

static inline int str_is(const char *str, const char *is)
{
	return strcmp(str, is) == 0;
}

/* returns core mask used by DPDK */
static uint64_t
app_eal_core_mask(void)
{
	uint32_t i;
	uint64_t cm = 0;
	struct rte_config *cfg = rte_eal_get_configuration();

	for (i = 0; i < APP_MAX_LCORE; i++) {
		if (cfg->lcore_role[i] == ROLE_RTE)
			cm |= (1ULL << i);
	}

	cm |= (1ULL << cfg->master_lcore);

	return cm;
}


/* returns total number of cores presented in a system */
static uint32_t
app_cpu_core_count(void)
{
	int i, len;
	char path[PATH_MAX];
	uint32_t ncores = 0;

	for (i = 0; i < APP_MAX_LCORE; i++) {
		len = snprintf(path, sizeof(path), SYS_CPU_DIR, i);
		if (len <= 0 || (unsigned)len >= sizeof(path))
			continue;

		if (access(path, F_OK) == 0)
			ncores++;
	}

	return ncores;
}

/* returns:
	 number of values parsed
	-1 in case of error
*/
static int
app_parse_opt_vals(const char *conf_str, char separator, uint32_t n_vals, uint32_t *opt_vals)
{
	char *string;
	int i, n_tokens;
	char *tokens[MAX_OPT_VALUES];

	if (conf_str == NULL || opt_vals == NULL || n_vals == 0 || n_vals > MAX_OPT_VALUES)
		return -1;

	/* duplicate configuration string before splitting it to tokens */
	string = strdup(conf_str);
	if (string == NULL)
		return -1;

	n_tokens = rte_strsplit(string, strnlen(string, 32), tokens, n_vals, separator);

	if (n_tokens > MAX_OPT_VALUES)
		return -1;

	for (i = 0; i < n_tokens; i++)
		opt_vals[i] = (uint32_t)atol(tokens[i]);

	free(string);

	return n_tokens;
}

static int
app_parse_ring_conf(const char *conf_str)
{
	int ret;
	uint32_t vals[3];

	ret = app_parse_opt_vals(conf_str, ',', 3, vals);
	if (ret != 3)
		return ret;

	ring_conf.rx_size = vals[0];
	ring_conf.ring_size = vals[1];
	ring_conf.tx_size = vals[2];

	return 0;
}

static int
app_parse_rth_conf(const char *conf_str)
{
	int ret;
	uint32_t vals[3];

	ret = app_parse_opt_vals(conf_str, ',', 3, vals);
	if (ret != 3)
		return ret;

	rx_thresh.pthresh = (uint8_t)vals[0];
	rx_thresh.hthresh = (uint8_t)vals[1];
	rx_thresh.wthresh = (uint8_t)vals[2];

	return 0;
}

static int
app_parse_tth_conf(const char *conf_str)
{
	int ret;
	uint32_t vals[3];

	ret = app_parse_opt_vals(conf_str, ',', 3, vals);
	if (ret != 3)
		return ret;

	tx_thresh.pthresh = (uint8_t)vals[0];
	tx_thresh.hthresh = (uint8_t)vals[1];
	tx_thresh.wthresh = (uint8_t)vals[2];

	return 0;
}

static int
app_parse_flow_conf(const char *conf_str)
{
	int ret;
	uint32_t vals[5];
	struct flow_conf *pconf;
	uint64_t mask;

	memset(vals, 0, sizeof(vals));
	ret = app_parse_opt_vals(conf_str, ',', 6, vals);
	if (ret < 4 || ret > 5)
		return ret;

	pconf = &qos_conf[nb_pfc];

	pconf->rx_port = vals[0];
	pconf->tx_port = vals[1];
	pconf->rx_core = (uint8_t)vals[2];
	pconf->wt_core = (uint8_t)vals[3];
	if (ret == 5)
		pconf->tx_core = (uint8_t)vals[4];
	else
		pconf->tx_core = pconf->wt_core;

	if (pconf->rx_core == pconf->wt_core) {
		RTE_LOG(ERR, APP, "pfc %u: rx thread and worker thread cannot share same core\n", nb_pfc);
		return -1;
	}

	if (pconf->rx_port >= RTE_MAX_ETHPORTS) {
		RTE_LOG(ERR, APP, "pfc %u: invalid rx port %"PRIu16" index\n",
				nb_pfc, pconf->rx_port);
		return -1;
	}
	if (pconf->tx_port >= RTE_MAX_ETHPORTS) {
		RTE_LOG(ERR, APP, "pfc %u: invalid tx port %"PRIu16" index\n",
				nb_pfc, pconf->tx_port);
		return -1;
	}

	mask = 1lu << pconf->rx_port;
	if (app_used_rx_port_mask & mask) {
		RTE_LOG(ERR, APP, "pfc %u: rx port %"PRIu16" is used already\n",
				nb_pfc, pconf->rx_port);
		return -1;
	}
	app_used_rx_port_mask |= mask;
	app_used_port_mask |= mask;

	mask = 1lu << pconf->tx_port;
	if (app_used_tx_port_mask & mask) {
		RTE_LOG(ERR, APP, "pfc %u: port %"PRIu16" is used already\n",
				nb_pfc, pconf->tx_port);
		return -1;
	}
	app_used_tx_port_mask |= mask;
	app_used_port_mask |= mask;

	mask = 1lu << pconf->rx_core;
	app_used_core_mask |= mask;

	mask = 1lu << pconf->wt_core;
	app_used_core_mask |= mask;

	mask = 1lu << pconf->tx_core;
	app_used_core_mask |= mask;

	nb_pfc++;

	return 0;
}

static int
app_parse_burst_conf(const char *conf_str)
{
	int ret;
	uint32_t vals[4];

	ret = app_parse_opt_vals(conf_str, ',', 4, vals);
	if (ret != 4)
		return ret;

	burst_conf.rx_burst    = (uint16_t)vals[0];
	burst_conf.ring_burst  = (uint16_t)vals[1];
	burst_conf.qos_dequeue = (uint16_t)vals[2];
	burst_conf.tx_burst    = (uint16_t)vals[3];

	return 0;
}

/*
 * Parses the argument given in the command line of the application,
 * calculates mask for used cores and initializes EAL with calculated core mask
 */
int
app_parse_args(int argc, char **argv)
{
	int opt, ret;
	int option_index;
	const char *optname;
	char *prgname = argv[0];
	uint32_t i, nb_lcores;

	static struct option lgopts[] = {
		{ "pfc", 1, 0, 0 },
		{ "mst", 1, 0, 0 },
		{ "rsz", 1, 0, 0 },
		{ "bsz", 1, 0, 0 },
		{ "msz", 1, 0, 0 },
		{ "rth", 1, 0, 0 },
		{ "tth", 1, 0, 0 },
		{ "cfg", 1, 0, 0 },
		{ NULL,  0, 0, 0 }
	};

	/* initialize EAL first */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		return -1;

	argc -= ret;
	argv += ret;

	/* set en_US locale to print big numbers with ',' */
	setlocale(LC_NUMERIC, "en_US.utf-8");

	while ((opt = getopt_long(argc, argv, "i",
		lgopts, &option_index)) != EOF) {

			switch (opt) {
			case 'i':
				printf("Interactive-mode selected\n");
				interactive = 1;
				break;
			/* long options */
			case 0:
				optname = lgopts[option_index].name;
				if (str_is(optname, "pfc")) {
					ret = app_parse_flow_conf(optarg);
					if (ret) {
						RTE_LOG(ERR, APP, "Invalid pipe configuration %s\n", optarg);
						return -1;
					}
					break;
				}
				if (str_is(optname, "mst")) {
					app_master_core = (uint32_t)atoi(optarg);
					break;
				}
				if (str_is(optname, "rsz")) {
					ret = app_parse_ring_conf(optarg);
					if (ret) {
						RTE_LOG(ERR, APP, "Invalid ring configuration %s\n", optarg);
						return -1;
					}
					break;
				}
				if (str_is(optname, "bsz")) {
					ret = app_parse_burst_conf(optarg);
					if (ret) {
						RTE_LOG(ERR, APP, "Invalid burst configuration %s\n", optarg);
						return -1;
					}
					break;
				}
				if (str_is(optname, "msz")) {
					mp_size = atoi(optarg);
					if (mp_size <= 0) {
						RTE_LOG(ERR, APP, "Invalid mempool size %s\n", optarg);
						return -1;
					}
					break;
				}
				if (str_is(optname, "rth")) {
					ret = app_parse_rth_conf(optarg);
					if (ret) {
						RTE_LOG(ERR, APP, "Invalid RX threshold configuration %s\n", optarg);
						return -1;
					}
					break;
				}
				if (str_is(optname, "tth")) {
					ret = app_parse_tth_conf(optarg);
					if (ret) {
						RTE_LOG(ERR, APP, "Invalid TX threshold configuration %s\n", optarg);
						return -1;
					}
					break;
				}
				if (str_is(optname, "cfg")) {
					cfg_profile = optarg;
					break;
				}
				break;

			default:
				app_usage(prgname);
				return -1;
			}
	}

	/* check master core index validity */
	for(i = 0; i <= app_master_core; i++) {
		if (app_used_core_mask & (1u << app_master_core)) {
			RTE_LOG(ERR, APP, "Master core index is not configured properly\n");
			app_usage(prgname);
			return -1;
		}
	}
	app_used_core_mask |= 1u << app_master_core;

	if ((app_used_core_mask != app_eal_core_mask()) ||
			(app_master_core != rte_get_master_lcore())) {
		RTE_LOG(ERR, APP, "EAL core mask not configured properly, must be %" PRIx64
				" instead of %" PRIx64 "\n" , app_used_core_mask, app_eal_core_mask());
		return -1;
	}

	if (nb_pfc == 0) {
		RTE_LOG(ERR, APP, "Packet flow not configured!\n");
		app_usage(prgname);
		return -1;
	}

	/* sanity check for cores assignment */
	nb_lcores = app_cpu_core_count();

	for(i = 0; i < nb_pfc; i++) {
		if (qos_conf[i].rx_core >= nb_lcores) {
			RTE_LOG(ERR, APP, "pfc %u: invalid RX lcore index %u\n", i + 1,
					qos_conf[i].rx_core);
			return -1;
		}
		if (qos_conf[i].wt_core >= nb_lcores) {
			RTE_LOG(ERR, APP, "pfc %u: invalid WT lcore index %u\n", i + 1,
					qos_conf[i].wt_core);
			return -1;
		}
		uint32_t rx_sock = rte_lcore_to_socket_id(qos_conf[i].rx_core);
		uint32_t wt_sock = rte_lcore_to_socket_id(qos_conf[i].wt_core);
		if (rx_sock != wt_sock) {
			RTE_LOG(ERR, APP, "pfc %u: RX and WT must be on the same socket\n", i + 1);
			return -1;
		}
		app_numa_mask |= 1 << rte_lcore_to_socket_id(qos_conf[i].rx_core);
	}

	return 0;
}
