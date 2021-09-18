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

#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

#include "ff_dpdk_pcap.h"
#define FILE_PATH_LEN 64
#define PCAP_FILE_NUM 10

struct pcap_file_header {
    uint32_t magic;
    u_short version_major;
    u_short version_minor;
    int32_t thiszone;        /* gmt to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length saved portion of each pkt */
    uint32_t linktype;       /* data link type (LINKTYPE_*) */
};

struct pcap_pkthdr {
    uint32_t sec;            /* time stamp */
    uint32_t usec;           /* struct timeval time_t, in linux64: 8*2=16, in cap: 4 */
    uint32_t caplen;         /* length of portion present */
    uint32_t len;            /* length this packet (off wire) */
};

static __thread FILE* g_pcap_fp = NULL;
static __thread uint32_t seq = 0;
static __thread uint32_t g_flen = 0;

int ff_enable_pcap(const char* dump_path, uint16_t snap_len)
{
    char pcap_f_path[FILE_PATH_LEN] = {0};

    snprintf(pcap_f_path, FILE_PATH_LEN,  "%s/cpu%d_%d.pcap", dump_path==NULL?".":dump_path, rte_lcore_id(), seq);
    g_pcap_fp = fopen(pcap_f_path, "w+");
    if (g_pcap_fp == NULL) { 
        rte_exit(EXIT_FAILURE, "Cannot open pcap dump path: %s, errno %d.\n", pcap_f_path, errno);
        return -1;
    }
    g_flen = 0;

    struct pcap_file_header pcap_file_hdr;
    void* file_hdr = &pcap_file_hdr;

    pcap_file_hdr.magic = 0xA1B2C3D4;
    pcap_file_hdr.version_major = 0x0002;
    pcap_file_hdr.version_minor = 0x0004;
    pcap_file_hdr.thiszone = 0x00000000;
    pcap_file_hdr.sigfigs = 0x00000000;
    pcap_file_hdr.snaplen = snap_len;   //0x0000FFFF;  //65535
    pcap_file_hdr.linktype = 0x00000001; //DLT_EN10MB, Ethernet (10Mb)

    fwrite(file_hdr, sizeof(struct pcap_file_header), 1, g_pcap_fp);
    g_flen += sizeof(struct pcap_file_header);

    return 0;
}

int
ff_dump_packets(const char* dump_path, struct rte_mbuf* pkt, uint16_t snap_len, uint32_t f_maxlen)
{
    unsigned int out_len = 0, wr_len = 0;
    struct pcap_pkthdr pcap_hdr;
    void* hdr = &pcap_hdr;
    struct timeval ts;
    char pcap_f_path[FILE_PATH_LEN] = {0};

    if (g_pcap_fp == NULL) {
        return -1;
    }
    snap_len = pkt->pkt_len < snap_len ? pkt->pkt_len : snap_len;
    gettimeofday(&ts, NULL);
    pcap_hdr.sec = ts.tv_sec;
    pcap_hdr.usec = ts.tv_usec;
    pcap_hdr.caplen = snap_len;
    pcap_hdr.len = pkt->pkt_len;
    fwrite(hdr, sizeof(struct pcap_pkthdr), 1, g_pcap_fp);
    g_flen += sizeof(struct pcap_pkthdr);

    while(pkt != NULL && out_len <= snap_len) {
        wr_len = snap_len - out_len;
        wr_len = wr_len > pkt->data_len ? pkt->data_len : wr_len ;
        fwrite(rte_pktmbuf_mtod(pkt, char*), wr_len, 1, g_pcap_fp);
        out_len += wr_len;
        pkt = pkt->next;
    }
    g_flen += out_len;

    if ( g_flen >= f_maxlen ){
        fclose(g_pcap_fp);
        if ( ++seq >= PCAP_FILE_NUM )
            seq = 0;
        
        ff_enable_pcap(dump_path, snap_len);
    }

    return 0;
}

