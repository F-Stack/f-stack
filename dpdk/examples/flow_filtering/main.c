/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017 Mellanox Technologies, Ltd
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_flow.h>
#include <rte_cycles.h>

static volatile bool force_quit;

static uint16_t port_id;
static uint16_t nr_queues = 5;
static uint8_t selected_queue = 1;
struct rte_mempool *mbuf_pool;
struct rte_flow *flow;

#define SRC_IP ((0<<24) + (0<<16) + (0<<8) + 0) /* src ip = 0.0.0.0 */
#define DEST_IP ((192<<24) + (168<<16) + (1<<8) + 1) /* dest ip = 192.168.1.1 */
#define FULL_MASK 0xffffffff /* full mask */
#define EMPTY_MASK 0x0 /* empty mask */

#include "flow_blocks.c"

static inline void
print_ether_addr(const char *what, struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", what, buf);
}

/* Main_loop for flow filtering. 8< */
static int
main_loop(void)
{
	struct rte_mbuf *mbufs[32];
	struct rte_ether_hdr *eth_hdr;
	struct rte_flow_error error;
	uint16_t nb_rx;
	uint16_t i;
	uint16_t j;
	int ret;

	/* Reading the packets from all queues. 8< */
	while (!force_quit) {
		for (i = 0; i < nr_queues; i++) {
			nb_rx = rte_eth_rx_burst(port_id,
						i, mbufs, 32);
			if (nb_rx) {
				for (j = 0; j < nb_rx; j++) {
					struct rte_mbuf *m = mbufs[j];

					eth_hdr = rte_pktmbuf_mtod(m,
							struct rte_ether_hdr *);
					print_ether_addr("src=",
							&eth_hdr->src_addr);
					print_ether_addr(" - dst=",
							&eth_hdr->dst_addr);
					printf(" - queue=0x%x",
							(unsigned int)i);
					printf("\n");

					rte_pktmbuf_free(m);
				}
			}
		}
	}
	/* >8 End of reading the packets from all queues. */

	/* closing and releasing resources */
	rte_flow_flush(port_id, &error);
	ret = rte_eth_dev_stop(port_id);
	if (ret < 0)
		printf("Failed to stop port %u: %s",
		       port_id, rte_strerror(-ret));
	rte_eth_dev_close(port_id);
	return ret;
}
/* >8 End of main_loop for flow filtering. */

#define CHECK_INTERVAL 1000  /* 100ms */
#define MAX_REPEAT_TIMES 90  /* 9s (90 * 100ms) in total */

static void
assert_link_status(void)
{
	struct rte_eth_link link;
	uint8_t rep_cnt = MAX_REPEAT_TIMES;
	int link_get_err = -EINVAL;

	memset(&link, 0, sizeof(link));
	do {
		link_get_err = rte_eth_link_get(port_id, &link);
		if (link_get_err == 0 && link.link_status == RTE_ETH_LINK_UP)
			break;
		rte_delay_ms(CHECK_INTERVAL);
	} while (--rep_cnt);

	if (link_get_err < 0)
		rte_exit(EXIT_FAILURE, ":: error: link get is failing: %s\n",
			 rte_strerror(-link_get_err));
	if (link.link_status == RTE_ETH_LINK_DOWN)
		rte_exit(EXIT_FAILURE, ":: error: link is still down\n");
}

/* Port initialization used in flow filtering. 8< */
static void
init_port(void)
{
	int ret;
	uint16_t i;
	/* Ethernet port configured with default settings. 8< */
	struct rte_eth_conf port_conf = {
		.txmode = {
			.offloads =
				RTE_ETH_TX_OFFLOAD_VLAN_INSERT |
				RTE_ETH_TX_OFFLOAD_IPV4_CKSUM  |
				RTE_ETH_TX_OFFLOAD_UDP_CKSUM   |
				RTE_ETH_TX_OFFLOAD_TCP_CKSUM   |
				RTE_ETH_TX_OFFLOAD_SCTP_CKSUM  |
				RTE_ETH_TX_OFFLOAD_TCP_TSO,
		},
	};
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_dev_info dev_info;

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
			"Error during getting device (port %u) info: %s\n",
			port_id, strerror(-ret));

	port_conf.txmode.offloads &= dev_info.tx_offload_capa;
	printf(":: initializing port: %d\n", port_id);
	ret = rte_eth_dev_configure(port_id,
				nr_queues, nr_queues, &port_conf);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			":: cannot configure device: err=%d, port=%u\n",
			ret, port_id);
	}

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;
	/* >8 End of ethernet port configured with default settings. */

	/* Configuring number of RX and TX queues connected to single port. 8< */
	for (i = 0; i < nr_queues; i++) {
		ret = rte_eth_rx_queue_setup(port_id, i, 512,
				     rte_eth_dev_socket_id(port_id),
				     &rxq_conf,
				     mbuf_pool);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				":: Rx queue setup failed: err=%d, port=%u\n",
				ret, port_id);
		}
	}

	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.txmode.offloads;

	for (i = 0; i < nr_queues; i++) {
		ret = rte_eth_tx_queue_setup(port_id, i, 512,
				rte_eth_dev_socket_id(port_id),
				&txq_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				":: Tx queue setup failed: err=%d, port=%u\n",
				ret, port_id);
		}
	}
	/* >8 End of Configuring RX and TX queues connected to single port. */

	/* Setting the RX port to promiscuous mode. 8< */
	ret = rte_eth_promiscuous_enable(port_id);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
			":: promiscuous mode enable failed: err=%s, port=%u\n",
			rte_strerror(-ret), port_id);
	/* >8 End of setting the RX port to promiscuous mode. */

	/* Starting the port. 8< */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			"rte_eth_dev_start:err=%d, port=%u\n",
			ret, port_id);
	}
	/* >8 End of starting the port. */

	assert_link_status();

	printf(":: initializing port: %d done\n", port_id);
}
/* >8 End of Port initialization used in flow filtering. */

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

int
main(int argc, char **argv)
{
	int ret;
	uint16_t nr_ports;
	struct rte_flow_error error;

	/* Initialize EAL. 8< */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, ":: invalid EAL arguments\n");
	/* >8 End of Initialization of EAL. */

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	nr_ports = rte_eth_dev_count_avail();
	if (nr_ports == 0)
		rte_exit(EXIT_FAILURE, ":: no Ethernet ports found\n");
	port_id = 0;
	if (nr_ports != 1) {
		printf(":: warn: %d ports detected, but we use only one: port %u\n",
			nr_ports, port_id);
	}
	/* Allocates a mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", 4096, 128, 0,
					    RTE_MBUF_DEFAULT_BUF_SIZE,
					    rte_socket_id());
	/* >8 End of allocating a mempool to hold the mbufs. */
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	/* Initializes all the ports using the user defined init_port(). 8< */
	init_port();
	/* >8 End of Initializing the ports using user defined init_port(). */

	/* Create flow for send packet with. 8< */
	flow = generate_ipv4_flow(port_id, selected_queue,
				SRC_IP, EMPTY_MASK,
				DEST_IP, FULL_MASK, &error);
	/* >8 End of create flow and the flow rule. */
	if (!flow) {
		printf("Flow can't be created %d message: %s\n",
			error.type,
			error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "error in creating flow");
	}
	/* >8 End of creating flow for send packet with. */

	/* Launching main_loop(). 8< */
	ret = main_loop();
	/* >8 End of launching main_loop(). */

	/* clean up the EAL */
	rte_eal_cleanup();

	return ret;
}
