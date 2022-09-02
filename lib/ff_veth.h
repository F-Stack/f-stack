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

#ifndef _FSTACK_VETH_H
#define _FSTACK_VETH_H

struct ff_port_cfg;
void *ff_veth_attach(struct ff_port_cfg *cfg);
int ff_veth_detach(void *arg);

void *ff_mbuf_gethdr(void *pkt, uint16_t total, void *data,
    uint16_t len, uint8_t rx_csum);
void *ff_mbuf_get(void *p, void *m, void *data, uint16_t len);
void ff_mbuf_free(void *m);

int ff_mbuf_copydata(void *m, void *data, int off, int len);
int ff_next_mbuf(void **mbuf_bsd, void **data, unsigned *len);
void* ff_mbuf_mtod(void* bsd_mbuf);
void* ff_rte_frm_extcl(void* mbuf);

struct ff_tx_offload;
void ff_mbuf_tx_offload(void *m, struct ff_tx_offload *offload);

void ff_veth_process_packet(void *arg, void *m);

void *ff_veth_softc_to_hostc(void *softc);

void ff_mbuf_set_vlan_info(void *hdr, uint16_t vlan_tci);

#endif /* ifndef _FSTACK_VETH_H */
