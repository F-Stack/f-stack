#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <stdio.h>
#include "dpdk_init.h"

#define NUM_PORTS 1
#define RX_QUEUE_SIZE 1024

void init_dpdk() {
    int ret = rte_eal_init(0, NULL);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "DPDK initialization failed\n");
    }

    uint16_t port_id = 0;
    if (!rte_eth_dev_is_valid_port(port_id)) {
        rte_exit(EXIT_FAILURE, "Invalid port id\n");
    }

    struct rte_eth_conf port_conf = {0};
    ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Failed to configure the port\n");
    }

    ret = rte_eth_rx_queue_setup(port_id, 0, RX_QUEUE_SIZE, rte_eth_dev_socket_id(port_id), NULL, NULL);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Failed to setup RX queue\n");
    }

    ret = rte_eth_tx_queue_setup(port_id, 0, RX_QUEUE_SIZE, rte_eth_dev_socket_id(port_id), NULL);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Failed to setup TX queue\n");
    }

    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Failed to start the port\n");
    }

    rte_eth_promiscuous_enable(port_id);
}

void receive_packets() {
    struct rte_mbuf *pkts_burst[32];
    uint16_t port_id = 0;
    int ret = rte_eth_rx_burst(port_id, 0, pkts_burst, 32);
    if (ret > 0) {
        for (int i = 0; i < ret; i++) {
            process_packet(pkts_burst[i]);
            rte_pktmbuf_free(pkts_burst[i]);
        }
    }
}