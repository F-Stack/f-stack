# 08 - is_tcp_syn() IPv6 Extension Header Analysis

> f-stack issue #1076: Accuracy analysis of IPv6 header skip in `is_tcp_syn()` function
> Analysis date: 2026-08-11
> Prerequisite documents: Reports 00-07
> Related commit: `7112dc2bcf` (feat: add mbuf water-level backpressure for issue #1076)

---

## 1. Problem Description

commit `7112dc2bcf`'s new `is_tcp_syn()` function (`lib/ff_dpdk_if.c:2023-2070`) handles IPv6 as:

```c
} else if (ether_type == RTE_ETHER_TYPE_IPV6) {
    if (len < sizeof(struct rte_ipv6_hdr) + sizeof(struct rte_tcp_hdr))
        return 0;
    const struct rte_ipv6_hdr *iph = (const struct rte_ipv6_hdr *)data;
    if (iph->proto != IPPROTO_TCP)
        return 0;
    tcph = (const struct rte_tcp_hdr *)
        ((const char *)data + sizeof(struct rte_ipv6_hdr));
}
```

Report `07` notes "IPv6 does not handle extension headers (simplified design, SYN packets usually have no extension headers)". This analysis verifies whether this judgment is accurate.

---

## 2. IPv6 Extension Header Mechanism

### 2.1 IPv6 Header Structure

IPv6 fixed header is 40 bytes, with `next_header` field (corresponding to DPDK `rte_ipv6_hdr.proto`) specifying the following protocol type. Without extension headers, `next_header == IPPROTO_TCP(6)`, TCP header follows the 40-byte fixed header.

With extension headers, `next_header` points to the first extension header type; each extension header's own `next_header` field chains to the next, until the final upper-layer protocol (TCP).

### 2.2 Extension Header Types (RFC 8200)

| Protocol Number | Type | Likelihood of Appearing in SYN |
|----------------|------|-------------------------------|
| 0 | Hop-by-Hop Options | Low (TFO Cookie in TCP options, not IPv6 Hop-by-Hop; Jumbograms extremely rare) |
| 43 | Routing Header | Low (Mobile IPv6 / SRV6, normal clients don't use) |
| 44 | Fragment Header | Very low (SYN packets typically 60-80 bytes, far below MTU 1280) |
| 51 | Authentication Header (AH) | Low (IPsec VPN scenario, SYN may carry AH) |
| 50 | Encapsulating Security Payload (ESP) | Low (ESP encrypts, cannot parse TCP header) |
| 60 | Destination Options | Very low (rarely used for SYN) |
| 135 | Mobility Header | Very low (Mobile IPv6 scenario) |

### 2.3 External Resource Cross-Validation

- RFC 8200 §4.1: Hop-by-Hop Options if present must be the first extension header
- Linux kernel `net/ipv6/ip6_input.c` `ip6_input_finish()` calls `ipv6_skip_exthdr()` to traverse extension header chain
- DPDK `rte_net_get_ptype()` internally has equivalent `ipv6_skip_exthdr` logic

Conclusion: IPv6 extension headers are a standard protocol mechanism; Linux kernel and DPDK both handle them in normal receive paths. But TCP SYN packets with extension headers are **rare** in production traffic.

---

## 3. F-stack Existing Extension Header Traversal Function

`lib/ff_dpdk_kni.c:281-315` already has `get_ipv6_hdr_len()` function that correctly handles extension header chains:

```c
static int
get_ipv6_hdr_len(uint8_t *proto, void *data, uint16_t len)
{
    int ext_hdr_len = 0;

    switch (*proto) {
        case IPPROTO_HOPOPTS:   case IPPROTO_ROUTING:   case IPPROTO_DSTOPTS:
        case IPPROTO_MH:        case IPPROTO_HIP:       case IPPROTO_SHIM6:
            ext_hdr_len = *((uint8_t *)data + 1) + 1;  // 8-byte units
            break;
        case IPPROTO_FRAGMENT:
            ext_hdr_len = 8;                            // fixed 8 bytes
            break;
        case IPPROTO_AH:
            ext_hdr_len = (*((uint8_t *)data + 1) + 2) * 4;  // 4-byte units
            break;
        case IPPROTO_NONE:
        default:
            return ext_hdr_len;                          // non-extension header, terminate
    }

    if (ext_hdr_len >= len) return len;

    *proto = *((uint8_t *)data);                         // read next_header
    ext_hdr_len += get_ipv6_hdr_len(proto, data + ext_hdr_len, len - ext_hdr_len);

    return ext_hdr_len;
}
```

This function is correctly used by `protocol_filter_ip()` (`:356-358`).

`is_tcp_syn()` **does not use** `get_ipv6_hdr_len()`, but directly checks `iph->proto != IPPROTO_TCP`.

---

## 4. Current Code Behavior Analysis

### 4.1 Without Extension Headers (Common Case, >99%)

- `iph->proto == IPPROTO_TCP` → check passes
- `tcph = data + 40` → offset correct
- TCP flags check correct

**Conclusion: Correct.**

### 4.2 With Extension Headers (Rare Case, <1%)

- `iph->proto` is an extension header type (e.g., 0/43/44/51/60), not equal to `IPPROTO_TCP(6)`
- Function returns 0 (not SYN)
- SYN packet **not dropped**, continues into protocol stack

**Conclusion: False negative.** SYN packet not detected, backpressure not triggered.

### 4.3 Failure Mode Safety Analysis

| Failure Type | Consequence | Safe? |
|-------------|-------------|-------|
| False negative (SYN not detected) | SYN enters protocol stack, backpressure not triggered | **Safe** — same behavior as backpressure disabled |
| False positive (non-SYN misidentified as SYN) | Non-SYN packet dropped | **Unsafe** — affects existing connections |

Current implementation only produces false negatives, not false positives. For backpressure mechanism, false negative is an **acceptable failure mode**.

---

## 5. Potential Improvement

### 5.1 Reuse get_ipv6_hdr_len()

Move `get_ipv6_hdr_len()` from `ff_dpdk_kni.c` to shared header, have `is_tcp_syn()` call it to traverse extension header chain.

Improved IPv6 branch:
```c
} else if (ether_type == RTE_ETHER_TYPE_IPV6) {
    if (len < sizeof(struct rte_ipv6_hdr))
        return 0;
    const struct rte_ipv6_hdr *iph = (const struct rte_ipv6_hdr *)data;
    uint8_t proto = iph->proto;
    uint16_t hdr_len = sizeof(struct rte_ipv6_hdr);
    hdr_len += get_ipv6_hdr_len(&proto, (char *)data + hdr_len, len - hdr_len);
    if (proto != IPPROTO_TCP)
        return 0;
    if (len < hdr_len + sizeof(struct rte_tcp_hdr))
        return 0;
    tcph = (const struct rte_tcp_hdr *)((const char *)data + hdr_len);
}
```

### 5.2 Improvement Cost

- Need to change `get_ipv6_hdr_len()` from static to non-static (or move to shared header)
- ~5 additional lines
- `get_ipv6_hdr_len()` is recursive but extension header chains typically 0-2 levels, negligible overhead

### 5.3 Whether Necessary

Considering:
1. IPv6 TCP SYN with extension headers is rare in production traffic
2. False negative is safe failure mode
3. Current implementation correct for common case
4. Backpressure is best-effort protection, not strict enforcement

**Improvement not necessary, but recommended.** If more precise SYN detection needed in future (e.g., for ACL or rate limiting), should improve.

---

## 6. Other Boundary Issues

### 6.1 QinQ (Double VLAN)

Currently only handles single VLAN. QinQ's second VLAN tag treated as ethertype, doesn't match IPv4/IPv6, returns 0. False negative, safe.

### 6.2 IPv4/IPv6 Unequal Length Check

IPv4 branch checks `len < ihl + sizeof(struct rte_tcp_hdr)` where `ihl` is variable. IPv6 branch checks `len < sizeof(struct rte_ipv6_hdr) + sizeof(struct rte_tcp_hdr)` which is fixed 40+20=60. Both correct.

### 6.3 TCP Minimum Header Length

`sizeof(struct rte_tcp_hdr)` in DPDK is 20 bytes (minimum TCP header). SYN packets typically have 20-60 byte TCP header (with options). Checking `>= 20` is correct minimum check.

---

## 7. Conclusion

| Question | Conclusion |
|----------|------------|
| Accurate without extension headers? | **Accurate** |
| Accurate with extension headers? | **Not accurate** (false negative, SYN not detected) |
| Is false negative safe? | **Safe** — same behavior as backpressure disabled |
| Need immediate fix? | **No** — backpressure is best-effort, false negative acceptable |
| Recommend improvement? | **Recommended** — reuse existing `get_ipv6_hdr_len()` |

Report `07`'s note "IPv6 does not handle extension headers (simplified design, SYN packets usually have no extension headers)" is **directionally correct** (SYN packets usually don't have extension headers), but "usually" ≠ "always". For best-effort backpressure, current implementation is acceptable; for stricter scenarios (ACL/rate limiting), should reuse `get_ipv6_hdr_len()` for improvement.
