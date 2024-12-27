#include<rte_eal.h>
#include<rte_ethdev.h>
#include<rte_mbuf.h>

#include<stdio.h>
#include<arpa/inet.h>


#define ENABLE_SEND 1
#define ENABLE_ARP 1

#define NUM_MBUFS (4096 - 1)

#define BURST_SIZE 32

int gDpdkPortId = 0; //网络适配器 网卡

#if ENABLE_SEND

// IP地址转换
#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

static uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 156, 127);

// IP
static uint32_t gSrcIp;
static uint32_t gDstIp;

// ETH
static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];

// TCP/UDP
static uint16_t gSrcPort;
static uint16_t gDstPort;

#endif

// DPDK中用于保存以太网端口配置参数的结构体类型
static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

// 初始化以太网端口
static void z_init_port(struct rte_mempool *mbuf_pool) {
    // 获取当前可用的以太网设备数量
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if(nb_sys_ports == 0) {
        rte_exit(EXIT_FAILURE, "No Support eth found\n");
    }

    //获取网卡信息
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(gDpdkPortId, &dev_info);

    const int num_rx_queues = 1; //接收
#if ENABLE_SEND
    const int num_tx_queues = 1; //发送
#else
    const int num_tx_queues = 0;
#endif 

    struct rte_eth_conf port_conf = port_conf_default;

    rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);
    //启动一个读rx队列
    if(rte_eth_rx_queue_setup(gDpdkPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkPortId),
                            NULL, mbuf_pool) < 0 ){
        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
    }

#if ENABLE_SEND
    //启动一个写tx队列
    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.rxmode.offloads;
    if(rte_eth_tx_queue_setup(gDpdkPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkPortId),
                            &txq_conf) < 0 ){
        rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
    }

#endif 

    //启动网卡
    if(rte_eth_dev_start(gDpdkPortId) < 0 ){
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }

    // 以太网端口的混杂模式,以便该端口可以接收到其它所有设备发送的数据帧，
    // 而不仅仅是目的地址是该端口的 MAC 地址的数据帧.
    rte_eth_promiscuous_enable(gDpdkPortId);
}

#if ENABLE_SEND

static int z_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t length) {

    //1 ether
    struct rte_ether_hdr *eth = (struct rte_ether_hdr*)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
    
    //2 iphdr
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr*)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(length - sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64; //TTL
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = gSrcIp;
    ip->dst_addr = gDstIp;

    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);
    
    //3 udp
    struct rte_udp_hdr *udp = (struct rte_udp_hdr*)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udp->src_port = gSrcPort;
    udp->dst_port = gDstPort;
    uint16_t udplen = length - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    udp->dgram_len = htons(udplen);

    rte_memcpy((uint8_t*)(udp + 1), data, udplen);

    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

    return 0;
}

static struct rte_mbuf * z_send_udp(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length ) {
    //从内存池中申请内存
    const unsigned total_len = length + 42;
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if(!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc failed\n");
    }
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

    z_encode_udp_pkt(pktdata, data, total_len);

    return mbuf;
}
#endif

#if ENABLE_ARP

// arp数据包组包
static int z_encode_arp_pkt(uint8_t *msg, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {

    //1 ether
    struct rte_ether_hdr *eth = (struct rte_ether_hdr*)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    //2 arp
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
    arp->arp_hardware = htons(1);
    arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = sizeof(uint32_t);
    arp->arp_opcode = htons(2);

    rte_memcpy(arp->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

    arp->arp_data.arp_sip = sip;
    arp->arp_data.arp_tip = dip;

    return 0;
}

// 发送arp数据包
static struct rte_mbuf * z_send_arp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac, uint32_t sip, uint32_t dip ){

    const unsigned total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if(!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc failed\n");
    }
    mbuf->data_len = total_len;
    mbuf->pkt_len = total_len;

    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    z_encode_arp_pkt(pkt_data,dst_mac,sip,dip);

    return mbuf;
}

#endif


int main(int argc, char *argv[]) {

    //初始化,检测DPDK的环境是否正确
    if(rte_eal_init(argc,argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    } 

    //创建内存池
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS, 
            0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if(mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }

    //初始化以太网端口
    z_init_port(mbuf_pool);

#if ENABLE_SEND
    // 获取端口的Mac地址
    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac);
#endif

    while(1) {
        struct rte_mbuf *mbufs[BURST_SIZE];// 内存池

        unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
        if(num_recvd > BURST_SIZE) {
            rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
        }
        unsigned i = 0;
        for(;i < num_recvd; i++) {
            // 解析获取以太网头
            struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i],struct rte_ether_hdr*);
#if ENABLE_ARP
            //判断类型是否为Arp
            if(ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
                // 解析获取arp头
                struct rte_arp_hdr *ahdr = rte_pktmbuf_mtod_offset(mbufs[i],struct rte_arp_hdr *,
                     sizeof(struct rte_ether_hdr));

                if(ahdr->arp_data.arp_tip == gLocalIp) {
                    struct rte_mbuf *arpbuf = z_send_arp(mbuf_pool,ahdr->arp_data.arp_sha.addr_bytes,
                        ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);

                    struct in_addr addr;
                    addr.s_addr = ahdr->arp_data.arp_sip;
                    printf("arp---> src: %s ",inet_ntoa(addr));

                    addr.s_addr = gLocalIp;
                    printf("local: %s\n",inet_ntoa(addr));

                    rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
                    rte_pktmbuf_free(arpbuf);
                }

                continue;
            }

#endif
            //判断类型是否为IPV4
            if(ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                continue;
            }

            struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
                sizeof(struct rte_ether_hdr));
            //判断协议是否为UDP
            if(iphdr->next_proto_id == IPPROTO_UDP){
                struct rte_udp_hdr *udphdr = 
                    (struct rte_udp_hdr *)(iphdr + 1);
                
#if ENABLE_SEND
                rte_memcpy(gDstMac, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

                rte_memcpy(&gSrcIp, &iphdr->dst_addr, sizeof(uint32_t));
                rte_memcpy(&gDstIp, &iphdr->src_addr, sizeof(uint32_t));

                rte_memcpy(&gSrcPort, &udphdr->dst_port, sizeof(uint16_t));
                rte_memcpy(&gDstPort, &udphdr->src_port, sizeof(uint16_t));
#endif 

                if(ntohs(udphdr->src_port) == 9000) { //端口过滤 网络攻击
                    uint16_t length = ntohs(udphdr->dgram_len);
                    *((char*)udphdr + length) = '\0';

                    struct in_addr addr;
                    addr.s_addr = iphdr->src_addr;
                    printf("src: %s:%d, ",inet_ntoa(addr), ntohs(udphdr->src_port));

                    addr.s_addr = iphdr->dst_addr;
                    printf("dst: %s:%d,length:%d---> %s\n",inet_ntoa(addr), ntohs(udphdr->dst_port),
                        length, (char*)(udphdr + 1));
#if ENABLE_SEND
   
                    struct rte_mbuf *txbuf = z_send_udp(mbuf_pool, (uint8_t *)(udphdr + 1), length);
                    rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
                    rte_pktmbuf_free(txbuf);
#endif
                }
                
                rte_pktmbuf_free(mbufs[i]);
            }
        }
    }
}