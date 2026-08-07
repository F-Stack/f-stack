# 11 IPv6 Reverse Proxy VIP On-link Misjudgment Fix

> Role: spec-writer (documentation sync after coding completion). This report records the **root-cause identification and fix landing** for the problem "when f-stack-based nginx acts as an IPv6 reverse proxy, actively connecting to the upstream backend fails (504)".
> All line numbers are confirmed by reading the code (based on actual code); runtime diagnostics are based on the pcap hard evidence cross-verified by the leader/multi-agent team; see §7 for real-machine end-to-end verification status.
> Files involved: `lib/ff_veth.c` (the only file changed). Reference code: `freebsd/netinet6/in6.c` (unchanged).

---

## 1. Problem symptom

f-stack-based nginx (`nginx_fstack`) configured as an IPv6 reverse proxy:

- The reverse-proxy server `listen [::]:80`: clients can normally access the reverse proxy and receive complete requests;
- But when the reverse proxy actively `connect`s to the upstream backend, **the backend never receives any v6 reverse-proxy requests**, and nginx reports `504 Gateway Timeout`.

Reproduction environment: reproducible on **both** a CVM (virtio NIC) and an mlx5 100G physical machine (no security group), independent of NIC model.

---

## 2. Runtime diagnostics (pcap hard evidence)

Capture file: `/data/workspace/ipv6_proxy.pcap` (captured on-site on the mlx5 physical machine).

| Role | Address |
|------|------|
| Reverse-proxy server VIP | `<VIP_IPV6>` |
| Upstream backend | `<BACKEND_IPV6>` |
| Client | `<CLIENT_IPV6>` |

Key `f-stack.conf` settings:

| Item | Value | Subnet |
|----|----|------|
| `addr6` (primary address) | `<DPDK_NIC_IPV6>` | primary subnet `2e80:1030` |
| `prefix_len` | `64` | — |
| `gateway6` | `<GATEWAY_IPV6>` | primary subnet `2e80:1030` |
| `vip_addr6` | `<VIP_IPV6>` | VIP subnet `1840` (**different subnet** from the primary address) |
| `vip_prefix_len` | `64` | — |

Key pcap observations:

1. **Inbound is entirely normal**: the client connects to VIP `1840::17`, SYN / SYN-ACK / GET / `504` all present, indicating no issue with listening or inbound send/receive.
2. **Outbound is abnormal**: f-stack sends only **1 direct NS** (`who has 1840::18`, solicited-node multicast) for the backend `1840::18`, with **no NA response whatsoever**; after that, **zero TCP SYN** packets are sent to the backend → connect times out → `504`.
3. **Comparison**: in the same pcap, an NS query for the gateway `2e80:1030::1` does receive an NA (normal).

**Conclusion**: f-stack mistakenly judges "traffic destined for the backend `1840::18`" as **directly connected (on-link)**, so it sends a direct NS for the destination address itself to perform address resolution; but the backend is actually behind the gateway, not on the local L2 → no NA is received → the neighbor entry stays `INCOMPLETE` → the SYN queues up and never gets sent.

---

## 3. Root cause analysis

### 3.1 Call chain

1. `lib/ff_veth.c` → `ff_veth_setvaddr6()` uses `sc->prefix_length` (**the primary prefix = 64**) as `ifra_prefixmask` when adding the VIP address;
2. → `freebsd/netinet6/in6.c` → `in6_addifaddr()` handles `SIOCAIFADDR_IN6`;
3. → since the prefix length is not 128, it enters the prefix-route installation branch, `ndpr_raf_onlink = 1`, installing an `1840::/64` **on-link prefix route** for the VIP's subnet;
4. → thereafter, traffic to the backend `1840::18` in the same subnet, via longest-prefix match, hits the `1840::/64` on-link prefix → is judged as directly connected → a direct NS is sent → no NA → the connection fails.

### 3.2 Key in6.c line numbers (unchanged, only referenced for confirmation)

`freebsd/netinet6/in6.c` `in6_addifaddr()` (starting at L1230):

| Landing point | Line number | Description |
|------|------|------|
| `pr0.ndpr_plen = in6_mask2len(&ifra->ifra_prefixmask...)` | L1298-1299 | Converts the prefix length from the passed-in prefixmask |
| `if (pr0.ndpr_plen == 128) { goto aifaddr_out; }` | **L1300-1303** | **Only skips prefix-route installation when it's /128** ("we don't need to install a host route") |
| `pr0.ndpr_raf_onlink = 1;` | **L1316** | Non-/128 branch: marks this prefix as on-link |
| `pfxlist_onlink_check();` | L1361 | The prefix's on-link status takes effect |
| `aifaddr_out:` | L1363 | /128 jumps here directly, **does not install an on-link prefix route** |

That is: only `/128` skips on-link prefix-route installation; a VIP with `/64` will inevitably get an `1840::/64` on-link prefix route installed.

### 3.3 Pre-fix code (incorrect)

Before the fix, `ff_veth_setvaddr6()` used the primary prefix `sc->prefix_length` to construct the prefixmask (the same pattern as the 13.0-baseline):

```
ifr6.ifra_prefixmask.sin6_len = sizeof ifr6.ifra_prefixmask;
memset(&ifr6.ifra_prefixmask.sin6_addr, 0xff, sc->prefix_length / 8);
uint8_t mask_size_mod = sc->prefix_length % 8;
if (mask_size_mod) {
    ifr6.ifra_prefixmask.sin6_addr.__u6_addr.__u6_addr8[sc->prefix_length / 8] =
        ((1 << mask_size_mod) - 1) << (8 - mask_size_mod);
}
```

Two defects:

1. **Main defect**: the VIP is added as `/64` → an `1840::/64` on-link prefix route is installed → backends in the same subnet are misjudged as directly connected;
2. **Secondary defect**: even if a configured prefix were intended to be used, this code mistakenly uses the primary address prefix `sc->prefix_length` instead of `sc->vip_prefix_length`, which is already reserved in the struct for the VIP (see `ff_veth.c` L88 field definition, L145/L201 assignment).

---

## 4. Fix plan

Fix the VIP to always be added as a **/128 host address**: the prefixmask is fixed to all-1s (`memset 0xff, 16`), removing the `mask_size_mod` modulo branch.

`lib/ff_veth.c` `ff_veth_setvaddr6()` (L860-898) after the fix:

```
/* VIP as /128 host addr: avoid installing an on-link prefix route,
 * so traffic to other addrs in the VIP subnet goes via the gateway. */
ifr6.ifra_prefixmask.sin6_len = sizeof ifr6.ifra_prefixmask;
memset(&ifr6.ifra_prefixmask.sin6_addr, 0xff, 16);   /* L879-880 */
```

Effect:

- The VIP is added as `/128` → hits `in6.c` L1300-1303's `/128` special case → **no on-link prefix route is installed**;
- Traffic to other addresses in the VIP's subnet (including the backend `1840::18`) has **no matching on-link prefix** in the Prefix List → goes via the **default gateway** → neighbor discovery is performed for the gateway (which is on the local L2 and can respond with an NA) → the SYN is sent out normally.

This approach is consistent with the native FreeBSD convention of `ifconfig <if> inet6 <addr> prefixlen 128 alias`: attaching a host address to an interface without introducing on-link semantics for that subnet.

---

## 5. diff summary (`lib/ff_veth.c` `ff_veth_setvaddr6`)

```diff
-    ifr6.ifra_prefixmask.sin6_len = sizeof ifr6.ifra_prefixmask;
-    memset(&ifr6.ifra_prefixmask.sin6_addr, 0xff, sc->prefix_length / 8);
-    uint8_t mask_size_mod = sc->prefix_length % 8;
-    if (mask_size_mod)
-    {
-        ifr6.ifra_prefixmask.sin6_addr.__u6_addr.__u6_addr8[sc->prefix_length / 8] = \
-            ((1 << mask_size_mod) - 1) << (8 - mask_size_mod);
-    }
+    /* VIP as /128 host addr: avoid installing an on-link prefix route,
+     * so traffic to other addrs in the VIP subnet goes via the gateway. */
+    ifr6.ifra_prefixmask.sin6_len = sizeof ifr6.ifra_prefixmask;
+    memset(&ifr6.ifra_prefixmask.sin6_addr, 0xff, 16);
```

Scope of change: only the prefixmask construction section within `ff_veth_setvaddr6()`; `ff_veth_setaddr6()` for the primary address is untouched (its behavior is unchanged, the primary address is still added with its configured prefix, as expected).

---

## 6. 13.0 comparison (not a 13→15 regression)

`f-stack-13.0-baseline/lib/ff_veth.c`'s `ff_veth_setvaddr6()` (around L789-796) likewise uses `sc->prefix_length` + `mask_size_mod` to construct the VIP's prefixmask, **identical to the pre-fix 15.0 code**.

Therefore this problem **is not a regression introduced by the 13.0→15.0 upgrade**, but a **long-standing design defect in f-stack**, which only manifests in the specific topology where "the VIP is in a different subnet from the primary address" (when they're in the same subnet, the backend is already on-link, so the misjudgment coincidentally produces no incorrect outcome, which is why it went undiscovered for so long).

---

## 7. Analysis of no impact on inbound traffic

One might worry that changing the VIP to `/128` would affect inbound traffic (client → VIP). Analysis confirms **no impact**:

- Inbound relies on the VIP address itself being reachable locally (a loopback host route), which `in6.c`'s `in6_notify_ifa()` **unconditionally** installs as a `/128` loopback route when the address takes effect, **independent of prefixlen**;
- Both `/128` and `/64` addition methods generate this loopback host route, so the VIP still normally receives packets destined for itself;
- In the pcap, inbound SYN/SYN-ACK/GET/504 are all normal throughout, which also confirms in practice that inbound is unaffected.

The only thing that changes is the "is the VIP's subnet on-link" outbound semantics — which is exactly the point this fix addresses.

---

## 8. Verification status

| Aspect | Result |
|------|------|
| Compile `libfstack.a` | OK |
| `make install` | OK |
| nginx relink | OK (binary md5 changed, confirming the fix is included) |
| Code correctness | Independent gatekeeper gate + fix-verifier cross-check + leader independently read `in6.c` and confirmed (all 6 checks passed) |
| Local CVM real-machine end-to-end | **Blocked**: (1) the CVM's security group drops active outbound connections (requires user's own investigation); (2) during the restart process the virtio NIC fell back to the kernel driver, so this environment cannot cleanly reproduce the VIP6 scenario |
| mlx5 physical machine real-machine end-to-end | **Pending user execution** (no security group, can cleanly reproduce) |

Suggested real-machine verification steps (mlx5 physical machine):

1. Deploy `nginx_fstack` with the fix, using the same configuration as §2;
2. Have a client access the reverse-proxy VIP and observe whether nginx correctly returns the upstream response (no longer 504);
3. Capture packets and confirm: for outbound traffic to the backend `1840::18`, **no direct NS is sent anymore**; instead, neighbor discovery is performed for the **gateway** `2e80:1030::1` and the SYN is sent out;
4. Use `netstat -rn -f inet6` to confirm that the `1840::/64` on-link prefix route **no longer exists** (only the VIP's `/128` host route + the default route).

---

## 9. External corroboration

Real, verifiable sources, each corroborating that "a /128 host address does not create an on-link prefix route, IPv6 determines the next hop using the on-link prefix list rather than pure prefix comparison, and traffic with no matching on-link prefix goes via the default gateway":

| # | Source | URL | Conclusion and relation to this fix |
|---|------|-----|------|
| 1 | FreeBSD `ifconfig(8)` man page | https://man.freebsd.org/cgi/man.cgi?query=ifconfig | inet6 supports the `::1/128` slash notation/`prefixlen` to specify the prefix length; `/128` is the standard native way to attach a single host address to an interface, corroborating that using `/128 alias` in this fix follows the official convention. |
| 2 | Packet Pushers, "On Link in IPv6" (based on RFC 5942) | https://packetpushers.net/blog/on-link-in-ipv6/ | IPv6 does not determine "same link" by "prefix + matching prefix length", but rather maintains an on-link prefix list; **a /128 address/host route by itself does not automatically create an on-link prefix**; when no on-link prefix matches, traffic goes to the default gateway. Directly supports "after changing the VIP to /128, the backend in the same subnet goes via the gateway". |
| 3 | RFC 4861 §5.2 / §2.1 (IPv6 Neighbor Discovery) | https://www.rfc-editor.org/rfc/rfc4861 | The sender performs a **longest-prefix match** against the Prefix List to determine on/off-link: on a match → next hop = the destination address itself (send NS to resolve it); on no match → next hop = the default router (send NS to the gateway). Corroborates the mechanism by which, before the fix, matching the `1840::/64` on-link prefix caused a direct NS to be mistakenly sent for the backend. |

---

## 10. Conclusion

- **Root cause**: `ff_veth_setvaddr6()` added the VIP with the primary `/64` prefix, causing `in6_addifaddr()` to install an `1840::/64` on-link prefix route, which made a cross-subnet backend be misjudged as directly connected, so a direct NS was sent with no NA received and the SYN was never sent.
- **Fix**: fix the VIP to always be added as a `/128` host address, avoiding the on-link prefix route, so cross-subnet traffic goes via the default gateway, consistent with FreeBSD's native `prefixlen 128 alias` convention.
- **Impact scope**: only affects the on-link semantics of the VIP's subnet for outbound traffic; inbound relies on the loopback `/128` host route and is unaffected.
- **Nature**: a long-standing design defect shared by 13.0/15.0, not an upgrade regression.
- **Status**: code fix landed, compilation/gate/cross-verification passed; end-to-end real-machine verification on an mlx5 physical machine pending user execution.
