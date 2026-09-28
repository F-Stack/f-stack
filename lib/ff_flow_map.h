/*-
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

#ifndef _FF_FLOW_MAP_H_
#define _FF_FLOW_MAP_H_

/* C-NR-301: software flow table shared between the FreeBSD stack (producer,
 * at syncache-insert time) and the packet dispatcher callback (consumer).
 *
 * This header deliberately includes nothing: freebsd/ translation units must
 * NOT pull in ff_api.h, and the fixed-width types below are available both
 * in the kernel namespace (via <sys/types.h>) and on the host (stdint.h).
 * Every includer is responsible for having those types in scope. */

/* Installed public header (lib/Makefile install), so it must be usable from
 * C++ on its own too — ff_api.h already sits inside an extern "C" block, but
 * including this header directly would otherwise fail to link. */
#ifdef __cplusplus
extern "C" {
#endif

/* Address family tag; internal encoding, NOT a socket AF_* value. */
#define FF_FLOW_MAP_V4  0
#define FF_FLOW_MAP_V6  1

/* 40 bytes, no padding: the compare walks the raw bytes, while the hash mixes
 * only the bytes that carry identity (af, the addresses this af uses, ports).
 * Addresses and ports are kept in network byte order — the table only ever
 * compares for equality, so no byte-swapping is needed (and swapping on the
 * syncache hook would cost a division-free but still useless ntohl per SYN). */
struct ff_flow_key {
    uint8_t  af;        /* FF_FLOW_MAP_V4 / FF_FLOW_MAP_V6 */
    uint8_t  reserved;  /* keep zero: covered by the 40-byte compare */
    uint16_t pad;       /* keep zero: covered by the 40-byte compare */
    uint32_t src[4];    /* foreign address; V4 uses src[0] only */
    uint32_t dst[4];    /* local address;   V4 uses dst[0] only */
    uint16_t sport;     /* foreign port */
    uint16_t dport;     /* local port */
};

/* Cheap gate for the call site in the stack: 0 means "do not even build a
 * key". Called once per accepted SYN, so it must stay a load + compare. */
int ff_flow_map_active(void);

/* The admission rule for a SYN: 1 = go on and answer it, 0 = refuse it
 * (free the entry, drop the segment) because the flow cannot be recorded
 * and would otherwise be answered with a SYN-ACK that the draining
 * generation can only RST. Returns 1 unconditionally while no window is
 * open — an untracked window is not a reason to refuse a connection. */
int ff_flow_map_admit(const struct ff_flow_key *key);

/* P3 (C-P3-1): record a flow as "this generation" BEFORE its SYN-ACK is
 * sent, so the third handshake ACK is classified by the dispatcher instead
 * of being forwarded to the draining generation. Idempotent: a repeated key
 * returns 1 instead of taking a second entry. Never blocks, never sleeps and
 * never takes any stack lock (it runs under NET_EPOCH with the inp/syncache
 * locks already dropped).
 * Returns 0 recorded, 1 already present, <0 on error / table full.
 * The entry is visible to ff_flow_map_lookup() right away: a SYN-ACK that
 * fails to go out therefore leaves a record for a connection that was never
 * established, which is the accepted trade-off of the single-phase form. */
int ff_flow_map_insert(const struct ff_flow_key *key);

/* Counters for ff_top / drain observability; any output pointer may be NULL. */
void ff_flow_map_stats(uint64_t *inserted, uint64_t *dup, uint64_t *full);

/* P3 (C-P3-3/4): extended counters plus the live capacity. 'grown' counts the
 * bounded expansions of the current window, 'grow_fail' an abandoned
 * migration, 'alloc_fail' a failed allocation. Any output pointer may be
 * NULL. */
void ff_flow_map_stats2(uint64_t *inserted, uint64_t *dup, uint64_t *full,
    uint64_t *grown, uint64_t *grow_fail, uint64_t *alloc_fail,
    uint32_t *cap);

/* P3 (C-P3-3): capacity knob for tests and control-plane callers — a power of
 * two within [FF_FLOW_MAP_CAP_MIN, FF_FLOW_MAP_CAP_MAX]. Takes effect at the
 * next open(); it also releases the current table at once (single-thread
 * contract: nothing can be looking up while this runs). The capacity survives
 * close(), so it still describes the table the next open() rebuilds. Not a
 * config directive: the default is unchanged. */
#define FF_FLOW_MAP_CAP_MIN  64u
#define FF_FLOW_MAP_CAP_MAX  (1u << 20)
void ff_flow_map_cap_set(uint32_t cap);

#ifdef __cplusplus
}
#endif

#endif /* _FF_FLOW_MAP_H_ */
