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

#ifndef _FSTACK_DPDK_IF_H
#define _FSTACK_DPDK_IF_H

#include "ff_api.h"

#define ff_IF_NAME "f-stack-%d"

struct loop_routine {
    loop_func_t loop;
    void *arg;
};

int ff_dpdk_init(int argc, char **argv);
int ff_dpdk_if_up(void);
void ff_dpdk_run(loop_func_t loop, void *arg);

struct ff_dpdk_if_context;
struct ff_port_cfg;

struct ff_tx_offload {
    uint8_t ip_csum;
    uint8_t tcp_csum;
    uint8_t udp_csum;
    uint8_t sctp_csum;
    uint16_t tso_seg_size;
};

struct ff_dpdk_if_context *ff_dpdk_register_if(void *sc, void *ifp,
    struct ff_port_cfg *cfg);
void ff_dpdk_deregister_if(struct ff_dpdk_if_context *ctx);

void ff_dpdk_set_if(struct ff_dpdk_if_context *ctx, void *sc, void *ifp);

int ff_dpdk_if_send(struct ff_dpdk_if_context* ctx, void *buf, int total);

void ff_dpdk_pktmbuf_free(void *m);


#endif /* ifndef _FSTACK_DPDK_IF_H */
