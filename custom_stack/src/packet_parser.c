#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <stdio.h>
#include "packet_parser.h"

#define PACKET_START_MAGIC 0x12345678
#define PACKET_END_MAGIC 0x87654321

void process_packet(struct rte_mbuf *mbuf) {
    struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);

    if (eth_hdr->ether_type == rte_be_to_cpu_16(ETHERTYPE_IP)) {
        printf("Received IP packet, Src IP: %d.%d.%d.%d, Dst IP: %d.%d.%d.%d\n",
               (ip_hdr->src_addr >> 24) & 0xFF, (ip_hdr->src_addr >> 16) & 0xFF,
               (ip_hdr->src_addr >> 8) & 0xFF, ip_hdr->src_addr & 0xFF,
               (ip_hdr->dst_addr >> 24) & 0xFF, (ip_hdr->dst_addr >> 16) & 0xFF,
               (ip_hdr->dst_addr >> 8) & 0xFF, ip_hdr->dst_addr & 0xFF);
    }
}

void process_packet_with_boundaries(struct rte_mbuf *mbuf) {
    struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);

    if (ip_hdr->src_addr == PACKET_START_MAGIC) {
        printf("Packet Start Detected\n");
    }
    if (ip_hdr->dst_addr == PACKET_END_MAGIC) {
        printf("Packet End Detected\n");
    }
}

void save_packet_to_file(struct rte_mbuf *mbuf) {
    FILE *file = fopen("received_packets.bin", "ab");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    fwrite(rte_pktmbuf_mtod(mbuf, void *), rte_pktmbuf_data_len(mbuf), 1, file);
    fclose(file);
}