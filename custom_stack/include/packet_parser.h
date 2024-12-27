#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

void process_packet(struct rte_mbuf *mbuf);
void process_packet_with_boundaries(struct rte_mbuf *mbuf);
void save_packet_to_file(struct rte_mbuf *mbuf);

#endif // PACKET_PARSER_H