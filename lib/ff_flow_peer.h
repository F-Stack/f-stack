/*
 * Copyright (C) 2017-2021 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the copyright notice,
 *    this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _FF_FLOW_PEER_H_
#define _FF_FLOW_PEER_H_

/* Graceful reload, UDP: every generation records the UDP flows it serves
 * into its table in shared memory (entries age out by idle time); while it
 * drains the table is published and the new generation forwards the packets
 * of the live flows to it. Zero-include like ff_flow_map.h: freebsd/
 * includes it too, the includer provides the fixed-width types. */

struct ff_flow_key;

#define FF_FLOW_PEER_CAP    16384u  /* power of two */
#define FF_FLOW_PEER_PROBE  32u

struct ff_flow_peer_ent {
    uint64_t fp;        /* key fingerprint, 0 = never used */
    uint32_t last_ms;
    uint32_t pad;
};

#define FF_FLOW_PEER_MAGIC      0x46504552u
#define FF_FLOW_PEER_NONE       0u
#define FF_FLOW_PEER_PUBLISHING 1u
#define FF_FLOW_PEER_HANDED     2u
#define FF_FLOW_PEER_MODE_HUP   1u
#define FF_FLOW_PEER_MODE_USR2  2u

struct ff_flow_peer_hdr {
    uint32_t magic;
    uint32_t state;
    uint64_t wid;       /* window identity, see ff_flow_peer.c */
    uint32_t mode;
    int32_t  pid;
    uint32_t idle_ms;
    uint32_t cap;
    uint64_t noted;
    uint64_t full;
    uint8_t  pad[16];
};

struct ff_flow_peer_tab {
    struct ff_flow_peer_hdr  h;
    struct ff_flow_peer_ent  e[FF_FLOW_PEER_CAP];
};

/* stack side (writer) */
int  ff_flow_peer_recording(void);
void ff_flow_peer_note(const struct ff_flow_key *key);
void ff_udp_flow_peer_snapshot(void);   /* freebsd/netinet/udp_usrreq.c */

/* lib side */
void ff_flow_peer_attach(void);
void ff_flow_peer_tick(void);

/* table primitives, pure (unit tested); results of tab_find */
#define FF_FLOW_PEER_TAB_MISS   0
#define FF_FLOW_PEER_TAB_LIVE   1
#define FF_FLOW_PEER_TAB_AGED   2
uint64_t ff_flow_peer_fp(const struct ff_flow_key *key);
/* 0 added, 1 refreshed, -1 no slot within the probe window */
int ff_flow_peer_tab_note(struct ff_flow_peer_ent *t, uint32_t cap,
    uint64_t fp, uint32_t now, uint32_t idle);
int ff_flow_peer_tab_find(const struct ff_flow_peer_ent *t, uint32_t cap,
    uint64_t fp, uint32_t now, uint32_t idle);
uint32_t ff_flow_peer_tab_active(const struct ff_flow_peer_ent *t,
    uint32_t cap, uint32_t now, uint32_t idle);

#endif /* _FF_FLOW_PEER_H_ */
