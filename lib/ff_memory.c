/*
 * Copyright (C) 2017-2021 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
     
#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_config.h>
#include <rte_eal.h>
#include <rte_pci.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_launch.h>
#include <rte_ethdev.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_thash.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "ff_dpdk_if.h"
#include "ff_dpdk_pcap.h"
#include "ff_dpdk_kni.h"
#include "ff_config.h"
#include "ff_veth.h"
#include "ff_host_interface.h"
#include "ff_msg.h"
#include "ff_api.h"
#include "ff_memory.h"

#define PAGE_SIZE            4096
#define    PAGE_SHIFT            12
#define    PAGE_MASK            (PAGE_SIZE - 1)
#define    trunc_page(x)        ((x) & ~PAGE_MASK)
#define    round_page(x)        (((x) + PAGE_MASK) & ~PAGE_MASK)

extern struct rte_mempool *pktmbuf_pool[NB_SOCKETS];
extern struct lcore_conf lcore_conf;

//struct ff_tx_offload;

// ff_ref_pool allocate rte_mbuf without data space, which data point to bsd mbuf's data address.
static struct rte_mempool *ff_ref_pool[NB_SOCKETS];

#define    Head_INC(h)    {\
    if ( ++h >= TX_QUEUE_SIZE ) \
        h = 0;\
    };

#define    Head_DEC(h)    do{\
    if ( --h < 0 ) \
        h = TX_QUEUE_SIZE-1;\
    }while(0);

// bsd mbuf was moved into nic_tx_ring from tmp_tables, after rte_eth_tx_burst() succeed.
static struct mbuf_txring nic_tx_ring[RTE_MAX_ETHPORTS];
static inline int ff_txring_enqueue(struct mbuf_txring* q, void *p, int seg_num);
static inline void ff_txring_init(struct mbuf_txring* r, uint32_t len);

typedef struct _list_manager_s
{
    uint64_t    *ele;        
    int        size;        
    //int        FreeNum;    
    int     top;
}StackList_t;

static StackList_t         ff_mpage_ctl = {0};
static uint64_t             ff_page_start = (uint64_t)NULL, ff_page_end = (uint64_t)NULL;
static phys_addr_t        *ff_mpage_phy = NULL;

static inline void        *stklist_pop(StackList_t *p);
static inline int         stklist_push(StackList_t * p, uint64_t val);

static int                 stklist_init(StackList_t*p, int size)
{
    
    int i = 0;
    
    if (p==NULL || size<=0){
        return -1;
    }
    p->size = size;
    p->top = 0;
    if ( posix_memalign((void**)&p->ele, sizeof(uint64_t), sizeof(uint64_t)*size) != 0)
        return -2;
    
    return 0;
}

static inline void *stklist_pop(StackList_t *p)
{
    int head = 0;
    
    if (p==NULL)
        return NULL;

    if (p->top > 0 ){
        return (void*)p->ele[--p->top];
    }
    else
        return NULL;
}

//id: the id of element to be freed.
//return code: -1: faile;  >=0:OK.
static inline int stklist_push(StackList_t *p,  const uint64_t val){
    int tail = 0;
    
    if (p==NULL)
        return -1;
    if (p->top < p->size){
        p->ele[p->top++] = val;
        return 0;
    }
    else
        return -1;
}

static inline int stklist_size(StackList_t * p)
{
    return p->size;
}

// set (void*) to rte_mbuf's priv_data.
static inline int ff_mbuf_set_uint64(struct rte_mbuf* p, uint64_t data)
{
    if (rte_pktmbuf_priv_size(p->pool) >= sizeof(uint64_t))
        *((uint64_t*)(p+1)) = data;
    return 0;
}

/*************************
* if mbuf has num segment in all, Dev's sw_ring will use num descriptions. ff_txring also use num segments as below:
* <---     num-1          ---->|ptr| head |
* ----------------------------------------------
* | 0 | 0 | ..............| 0  | p | XXX  |         
*-----------------------------------------------
*************************/
static inline int ff_txring_enqueue(struct mbuf_txring* q, void *p, int seg_num)
{
    int i = 0;
    for ( i=0; i<seg_num-1; i++){
        if ( q->m_table[q->head] ){
            ff_mbuf_free(q->m_table[q->head]);
            q->m_table[q->head] = NULL;
        }
        Head_INC(q->head);
    }
    if ( q->m_table[q->head] )
        ff_mbuf_free(q->m_table[q->head]);
    q->m_table[q->head] = p;
    Head_INC(q->head);
    
    return 0;
}

// pop out from head-1 .
static inline int ff_txring_pop(struct mbuf_txring* q, int num)
{
    int i = 0;

    for (i=0; i<num; i++){
        Head_DEC(q->head);
        if ( (i==0 && q->m_table[q->head]==NULL) || (i>0 && q->m_table[q->head]!=NULL) ){
            rte_panic("ff_txring_pop fatal error!");
        }
        if ( q->m_table[q->head] != NULL ){
            ff_mbuf_free(q->m_table[q->head]);
            q->m_table[q->head] = NULL;
        }
    }    
}

static inline void ff_txring_init(struct mbuf_txring* q, uint32_t num)
{
    memset(q, 0, sizeof(struct mbuf_txring)*num);
}

void ff_init_ref_pool(int nb_mbuf, int socketid)
{
    char s[64] = {0};
    
    if (ff_ref_pool[socketid] != NULL) {
            return;
    }
    snprintf(s, sizeof(s), "ff_ref_pool_%d", socketid);
    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        ff_ref_pool[socketid] = rte_pktmbuf_pool_create(s, nb_mbuf, MEMPOOL_CACHE_SIZE, 0, 0, socketid);
    } else {
        ff_ref_pool[socketid] = rte_mempool_lookup(s);
    }
}

int ff_mmap_init()
{
    int err = 0;
    int i = 0;
    uint64_t    virt_addr = (uint64_t)NULL;
    phys_addr_t    phys_addr = 0;
    uint64_t    bsd_memsz = (ff_global_cfg.freebsd.mem_size << 20);
    unsigned int bsd_pagesz = 0;
    
    ff_page_start = (uint64_t)mmap( NULL, bsd_memsz, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
    if (ff_page_start == (uint64_t)-1){
        rte_panic("ff_mmap_init get ff_page_start failed, err=%d.\n", errno);
        return -1;
    }
    
    if ( mlock((void*)ff_page_start, bsd_memsz)<0 )    {
        rte_panic("mlock failed, err=%d.\n", errno);
        return -1;
    }
    ff_page_end = ff_page_start + bsd_memsz;
    bsd_pagesz = (bsd_memsz>>12);
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1, "ff_mmap_init mmap %d pages, %d MB.\n", bsd_pagesz, ff_global_cfg.freebsd.mem_size);
    printf("ff_mmap_init mem[0x%lx:0x%lx]\n", ff_page_start, ff_page_end);

    if (posix_memalign((void**)&ff_mpage_phy, sizeof(phys_addr_t), bsd_pagesz*sizeof(phys_addr_t))!=0){
        rte_panic("posix_memalign get ff_mpage_phy failed, err=%d.\n", errno);
        return -1;
    }
    
    stklist_init(&ff_mpage_ctl, bsd_pagesz);
    
    for (i=0; i<bsd_pagesz; i++ ){
        virt_addr = ff_page_start + PAGE_SIZE*i;
        memset((void*)virt_addr, 0, PAGE_SIZE);
        
        stklist_push( &ff_mpage_ctl, virt_addr);
        ff_mpage_phy[i] = rte_mem_virt2phy((const void*)virt_addr);
        if ( ff_mpage_phy[i] == RTE_BAD_IOVA ){
            rte_panic("rte_mem_virt2phy return invalid address.");
            return -1;
        }
    }

    ff_txring_init(&nic_tx_ring[0], RTE_MAX_ETHPORTS);
    
    return 0;
}

// 1: vma in fstack page table;  0: vma not in fstack pages, in DPDK pool.
static inline int ff_chk_vma(const uint64_t virtaddr)
{
    return  !!( virtaddr > ff_page_start && virtaddr < ff_page_end );
}

/*
 * Get physical address of any mapped virtual address in the current process.
 */
static inline uint64_t ff_mem_virt2phy(const void* virtaddr)
{
    uint64_t    addr = 0;
    uint32_t    pages = 0;

    pages = (((uint64_t)virtaddr - (uint64_t)ff_page_start)>>PAGE_SHIFT);
    if (pages >= stklist_size(&ff_mpage_ctl)){
        rte_panic("ff_mbuf_virt2phy get invalid pages %d.", pages);
        return -1;
    }
    
    addr = ff_mpage_phy[pages] + ((const uint64_t)virtaddr & PAGE_MASK);
    return addr;
}

void *ff_mem_get_page()
{
    return (void*)stklist_pop(&ff_mpage_ctl);
}

int    ff_mem_free_addr(void *p)
{
    stklist_push(&ff_mpage_ctl, (const uint64_t)p);
    return 0;
}

static inline void ff_offload_set(struct ff_dpdk_if_context *ctx, void *m, struct rte_mbuf *head)
{
    void                    *data = NULL;
    struct ff_tx_offload     offload = {0};
    
    ff_mbuf_tx_offload(m, &offload);
    data = rte_pktmbuf_mtod(head, void*);

    if (offload.ip_csum) {
        /* ipv6 not supported yet */
        struct rte_ipv4_hdr *iph;
        int iph_len;
        iph = (struct rte_ipv4_hdr *)(data + RTE_ETHER_HDR_LEN);
        iph_len = (iph->version_ihl & 0x0f) << 2;

        head->ol_flags |= PKT_TX_IP_CKSUM | PKT_TX_IPV4;
        head->l2_len = RTE_ETHER_HDR_LEN;
        head->l3_len = iph_len;
    }

    if (ctx->hw_features.tx_csum_l4) {
        struct rte_ipv4_hdr *iph;
        int iph_len;
        iph = (struct rte_ipv4_hdr *)(data + RTE_ETHER_HDR_LEN);
        iph_len = (iph->version_ihl & 0x0f) << 2;

        if (offload.tcp_csum) {
            head->ol_flags |= PKT_TX_TCP_CKSUM;
            head->l2_len = RTE_ETHER_HDR_LEN;
            head->l3_len = iph_len;
        }

       /*
         *  TCP segmentation offload.
         *
         *  - set the PKT_TX_TCP_SEG flag in mbuf->ol_flags (this flag
         *    implies PKT_TX_TCP_CKSUM)
         *  - set the flag PKT_TX_IPV4 or PKT_TX_IPV6
         *  - if it's IPv4, set the PKT_TX_IP_CKSUM flag and
         *    write the IP checksum to 0 in the packet
         *  - fill the mbuf offload information: l2_len,
         *    l3_len, l4_len, tso_segsz
         *  - calculate the pseudo header checksum without taking ip_len
         *    in account, and set it in the TCP header. Refer to
         *    rte_ipv4_phdr_cksum() and rte_ipv6_phdr_cksum() that can be
         *    used as helpers.
         */
        if (offload.tso_seg_size) {
            struct rte_tcp_hdr *tcph;
            int tcph_len;
            tcph = (struct rte_tcp_hdr *)((char *)iph + iph_len);
            tcph_len = (tcph->data_off & 0xf0) >> 2;
            tcph->cksum = rte_ipv4_phdr_cksum(iph, PKT_TX_TCP_SEG);

            head->ol_flags |= PKT_TX_TCP_SEG;
            head->l4_len = tcph_len;
            head->tso_segsz = offload.tso_seg_size;
        }

        if (offload.udp_csum) {
            head->ol_flags |= PKT_TX_UDP_CKSUM;
            head->l2_len = RTE_ETHER_HDR_LEN;
            head->l3_len = iph_len;
        }
    }
}

// create rte_buf refer to data which is transmit from bsd stack by EXT_CLUSTER.
static inline struct rte_mbuf*     ff_extcl_to_rte(void *m )
{
    struct rte_mempool *mbuf_pool = pktmbuf_pool[lcore_conf.socket_id];
    struct rte_mbuf *src_mbuf = NULL;
    struct rte_mbuf *p_head = NULL;

    src_mbuf = (struct rte_mbuf*)ff_rte_frm_extcl(m);
    if ( NULL==src_mbuf ){
        return NULL;
    }
    p_head = rte_pktmbuf_clone(src_mbuf, mbuf_pool);
    if (p_head == NULL){
        return NULL;
    }
    
    return p_head;
}

//  create rte_mbuf refer to data in bsd mbuf.
static inline struct rte_mbuf*     ff_bsd_to_rte(void *m, int total)
{
    struct rte_mempool *mbuf_pool = ff_ref_pool[lcore_conf.socket_id];
    struct rte_mbuf *p_head = NULL;
    struct rte_mbuf *cur = NULL, *prev = NULL, *tmp=NULL;
    void    *data = NULL;
    void    *p_bsdbuf = NULL;
    unsigned len = 0;
    
    p_head = rte_pktmbuf_alloc(mbuf_pool);
    if (p_head == NULL){
        return NULL;
    }
    p_head->pkt_len = total;
    p_head->nb_segs = 0;
    cur = p_head;
    p_bsdbuf = m;
    while ( p_bsdbuf ){
        if (cur == NULL) {
            cur = rte_pktmbuf_alloc(mbuf_pool);
            if (cur == NULL) {
                rte_pktmbuf_free(p_head);
                return NULL;
            }
        }
        ff_next_mbuf(&p_bsdbuf, &data, &len);        // p_bsdbuf move to next mbuf.
        cur->buf_addr = data;
        cur->buf_iova = ff_mem_virt2phy((const void*)(cur->buf_addr));
        cur->data_off = 0;
        cur->data_len = len;        

        p_head->nb_segs++;
        if (prev != NULL) {
            prev->next = cur;
        }
        prev = cur;
        cur = NULL;
    }
    
    return p_head;
}

int ff_if_send_onepkt(struct ff_dpdk_if_context *ctx, void *m, int total)
{
    struct rte_mbuf *head = NULL;
    void            *src_buf = NULL;
    void            *p_data = NULL;
    struct lcore_conf *qconf = NULL;
    unsigned        len = 0;

    if ( !m ){
        rte_log(RTE_LOG_CRIT, RTE_LOGTYPE_USER1, "ff_dpdk_if_send_ex input invalid NULL address.");
        return 0;
    }
    p_data = ff_mbuf_mtod(m);
    if ( ff_chk_vma((uint64_t)p_data)){
        head = ff_bsd_to_rte(m, total);
    }
    else if ( (head = ff_extcl_to_rte(m)) == NULL ){
           rte_panic("data address 0x%lx is out of page bound or not malloced by DPDK recver.", (uint64_t)p_data);
        return 0;
    }
    
    if (head == NULL){
        rte_log(RTE_LOG_CRIT, RTE_LOGTYPE_USER1, "ff_if_send_onepkt call ff_bsd_to_rte failed.");
        ff_mbuf_free(m);
        return 0;
    }
    
    ff_offload_set(ctx, m, head);
    qconf = &lcore_conf;
    len = qconf->tx_mbufs[ctx->port_id].len;
    qconf->tx_mbufs[ctx->port_id].m_table[len] = head;
    qconf->tx_mbufs[ctx->port_id].bsd_m_table[len] = m;
    len++;

    return len;
}

int ff_enq_tx_bsdmbuf(uint8_t portid, void *p_mbuf, int nb_segs)
{
    return ff_txring_enqueue(&nic_tx_ring[portid], p_mbuf, nb_segs);
}

