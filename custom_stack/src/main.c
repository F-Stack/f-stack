#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include "dpdk_init.h"
#include "packet_parser.h"

int main() {
    init_dpdk();

    while (1) {
        receive_packets();
    }

    return 0;
}