# 07 - mbuf Water Level Backpressure Implementation Report

> f-stack issue #1076: Solution B (mbuf water level backpressure) code implementation
> Implementation date: 2026-08-10
> Prerequisite documents: Reports 00-06

---

## 1. Implementation Overview

Added mbuf pool water level check at `process_packets()` receive entry: when available mbufs fall below configured threshold `mbuf_low_watermark`, drop TCP SYN packets (no SYN-ACK reply), preventing new connections from continuing to consume mbufs and causing entire stack unresponsive. Established connections' data packets are not affected.

**Design Principles**:
- Disabled by default (`mbuf_low_watermark=0`), zero regression
- Only drops SYN (new connection initiation), does not affect existing connections
- Only applies to RX burst packets, skips dispatch ring packets
- Per-packet check, `rte_mempool_avail_count` overhead negligible

---

## 2. Code Changes

### 2.1 Modified Files

| File | Change Type | Description |
|------|------------|-------------|
| `lib/ff_dpdk_if.c` | New function + modify | `is_tcp_syn()` helper + `process_packets()` water level check |
| `lib/ff_config.h` | New field | `struct ff_config.dpdk` add `mbuf_low_watermark` |
| `lib/ff_config.c` | New parsing + default | `MATCH("dpdk","mbuf_low_watermark")` + default 0 |
| `config.ini` | New comment | `# mbuf_low_watermark=0` (not committed) |

### 2.2 is_tcp_syn() Function

Location: `lib/ff_dpdk_if.c`, before `process_packets()`

Function: Parse Ethernet/VLAN/IPv4/IPv6/TCP headers, determine if pure SYN packet (SYN=1, ACK=0).

Parsing flow:
1. Check minimum length (Ethernet header)
2. Parse Ethernet header, skip VLAN tag (same pattern as `protocol_filter`)
3. IPv4: Check `next_proto_id == IPPROTO_TCP`, locate TCP header by IHL offset
4. IPv6: Check `proto == IPPROTO_TCP`, locate TCP header at fixed 40-byte offset
5. Check TCP flags: `(SYN_FLAG | ACK_FLAG) == SYN_FLAG` (pure SYN, not SYN-ACK)

Safety checks:
- Verify remaining length before each layer parse, prevent out-of-bounds read
- IPv4 IHL minimum check (`>= sizeof(struct rte_ipv4_hdr)`)
- IPv6 does not handle extension headers (simplified design; SYN with extension headers yields false negative = backpressure not triggered, safe failure mode; see `08-is_tcp_syn-ipv6-ext-hdr-analysis.md`)

### 2.3 process_packets() Water Level Check

Location: `lib/ff_dpdk_if.c`, inside `process_packets()` for loop, after `data`/`len` extraction, before traffic stats

```c
if (!pkts_from_ring && ff_global_cfg.dpdk.mbuf_low_watermark > 0 &&
    rte_mempool_avail_count(pktmbuf_pool[qconf->socket_id]) <
        ff_global_cfg.dpdk.mbuf_low_watermark &&
    is_tcp_syn(data, len)) {
    ff_traffic.rx_dropped += rtem->nb_segs;
    rte_pktmbuf_free(rtem);
    continue;
}
```

Conditions:
- `!pkts_from_ring`: Skip dispatch ring packets (already processed by previous lcore)
- `mbuf_low_watermark > 0`: Only when user explicitly configures
- `rte_mempool_avail_count(...) < watermark`: Available mbufs below threshold
- `is_tcp_syn(data, len)`: Packet is TCP SYN (new connection initiation)

On hit: increment `rx_dropped`, free mbuf, skip protocol stack processing.

### 2.4 Configuration Item

| Config Item | Location | Type | Default | Description |
|-------------|----------|------|---------|-------------|
| `mbuf_low_watermark` | `[dpdk]` section | unsigned | 0 | 0=disabled; >0 triggers SYN drop below this available mbuf count |

---

## 3. Compilation and Testing

### 3.1 Compilation Verification

- **make clean**: Cleaned 258 intermediate products via `rm_tmp_file.sh` + machine_include directory
- **make**: Full compilation passed, exit code 0, no warnings/errors
- **helloworld linking**: Successfully generated helloworld binary

### 3.2 Startup Test

- helloworld primary process started successfully
- FreeBSD stack initialization complete (79 lines log, including all sysctl settings)
- No error/fail/panic/segfault messages
- `mbuf_low_watermark=0` (default disabled), new code path not executed, zero regression

### 3.3 Uncompleted Tests

| Item | Reason |
|------|--------|
| High CPS mbuf exhaustion reproduction | DPDK NIC L2 network unreachable (same as report 04) |
| Water level backpressure trigger verification | Needs high CPS stress test env |
| `mbuf_low_watermark` threshold quantification | Needs hands-on testing |

---

## 4. Usage Guide

### 4.1 Enabling

Add to `config.ini` `[dpdk]` section:
```ini
[dpdk]
mbuf_low_watermark=3276
```

Recommended initial value: 10% of mbuf pool total capacity. Adjust based on stress testing.

### 4.2 Combining with Other Mechanisms

This is the 4th defense line of Solution C. Recommend also enabling:
1. **maxsockets** (`[freebsd.boot]`): Global socket hard limit
2. **ipfw limit**: per-source concurrent connection limit
3. **somaxconn / syncache**: half-open and accept queue limits
4. **mbuf_low_watermark** (this implementation): mbuf pool water level backpressure

---

## 5. Code Diff Summary

```
lib/ff_config.h:  +1 line  (mbuf_low_watermark field)
lib/ff_config.c:  +3 lines (MATCH branch + default value)
lib/ff_dpdk_if.c: +57 lines (is_tcp_syn function 48 lines + water level check 9 lines)
config.ini:       +2 lines (comment, not committed)
```

Total: ~61 lines added, 0 lines deleted, zero format jitter.
