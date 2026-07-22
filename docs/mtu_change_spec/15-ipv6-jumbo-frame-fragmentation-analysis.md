# 15 — IPv6 Jumbo Frame Fragmentation Anomaly Analysis

> This document analyzes the root cause of f-stack `mtu_enable=1` with MTU=9000 where **without KNI (user-space FreeBSD protocol stack replies), IPv6 echo reply is fragmented into 1448-byte segments**.
> All conclusions are based on actual code file:line (FreeBSD 15.0 user-space protocol stack + f-stack lib layer), cross-validated with external sources.
> This round is pure investigation analysis; no code changes, no commits.

---

## I. Phenomenon

| Test Item | Result |
|--------|------|
| IPv4 bidirectional 8500 ping | Normal (no fragmentation) |
| IPv6 receive 8500 ping (KNI on, kernel stack) | Normal |
| IPv6 receive 8500 ping (**KNI off**, user-space FreeBSD protocol stack reply) | **Reply split into 6 × 1448-byte fragments** |

Physical machine `ff_ifconfig`:
```
f-stack-0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 9000
    inet6 2402:4e00:2e80:1030::b prefixlen 64 autoconf
    nd6 options=123<PERFORMNUD,ACCEPT_RTADV,AUTO_LINKLOCAL,NO_DAD>
```

Client `ping6 -M do -s 8500 2402:4e00:2e80:1030::b` capture:
```
IP6 ::c > ::b: ICMP6, echo request, seq 1, length 8508
IP6 ::b > ::c: frag (0|1448)  ICMP6, echo reply, seq 1, length 1448
IP6 ::b > ::c: frag (1448|1448)
IP6 ::b > ::c: frag (2896|1448)
IP6 ::b > ::c: frag (4344|1448)
IP6 ::b > ::c: frag (5792|1448)
IP6 ::b > ::c: frag (7240|1268)
```
6 fragments: `1448×5 + 1268 = 8508` (8500 payload + 8 ICMP6 header).

## II. Capture Number Reverse Derivation

Fragment size calculation at `freebsd/netinet6/ip6_output.c:1204`:
```c
len = (mtu - unfragpartlen - sizeof(struct ip6_frag)) & ~7;
```
- `unfragpartlen` = 40 (IPv6 header, no extension headers)
- `sizeof(struct ip6_frag)` = 8 (fragment header)
- `& ~7` = 8-byte alignment

Reverse-derive `mtu`:
- If `mtu=1500`: `len = (1500-40-8)&~7 = 1452&~7 = 1448` (1452=0b10110101100, `&~7`=0b10110101000=1448) ✓
- If `mtu=9000`: `len = (9000-48)&~7 = 8952`, only 1 fragment needed (8508<8952), no fragmentation

**The captured 1448 corresponds to `mtu=1500`, not ifnet's 9000.** Core question: why is the `mtu` variable used for IPv6 fragmentation 1500.

## III. Root Cause Code Chain (12 file:line, code prevails)

### 3.1 Init Phase: ndi->maxmtu Set to 1500

| Step | file:line | Code |
|------|-----------|------|
| ① ether_ifattach sets if_mtu=1500 | `freebsd/net/if_ethersubr.c:985` | `ifp->if_mtu = ETHERMTU;` (ETHERMTU=1500) |
| ② ether_ifattach calls if_attach | `freebsd/net/if_ethersubr.c:986` | `if_attach(ifp);` → triggers domain `.dom_ifattach` |
| ③ in6 domain registers dom_ifattach | `freebsd/netinet6/in6_proto.c:115` | `.dom_ifattach = in6_domifattach,` |
| ④ in6_domifattach calls nd6_ifattach | `freebsd/netinet6/in6.c:2607` | `ext->nd_ifinfo = nd6_ifattach(ifp);` |
| ⑤ nd6_ifattach calls nd6_setmtu0 | `freebsd/netinet6/nd6.c:324-325` | `/* XXX: we cannot call nd6_setmtu since ifp is not fully initialized */ nd6_setmtu0(ifp, nd);` |
| ⑥ nd6_setmtu0 sets maxmtu=if_mtu | `freebsd/netinet6/nd6.c:369` | `ndi->maxmtu = ifp->if_mtu;` → **maxmtu=1500** |

f-stack ff_veth init calls ether_ifattach (`lib/ff_veth.c:937`); at this point if_mtu=1500, ndi->maxmtu is initialized to 1500.

### 3.2 ff_veth MTU Change Bypasses Standard Sync Path

| Step | file:line | Code |
|------|-----------|------|
| ⑦ ff_veth if_setmtu(9000) | `lib/ff_veth.c:967` | `if_setmtu(sc->ifp, init_mtu);` (init_mtu=9000) |
| ⑧ if_setmtu only sets if_mtu | `freebsd/net/if.c:4431-4434` | `ifp->if_mtu = mtu; return (0);` — **no nd6_setmtu** |
| ⑨ Standard if_notifymtu includes nd6_setmtu | `freebsd/net/if.c:4440-4443` | `#ifdef INET6 nd6_setmtu(ifp); #endif rt_updatemtu(ifp);` — **not called** |
| ⑩ ff_veth runtime SIOCSIFMTU also bypasses | `lib/ff_veth.c:248-253` | `if_setmtu(ifp, new_mtu);` called directly, not via ifhwioctl/if_notifymtu |

**Full-text search of f-stack lib layer for `nd6_setmtu` = 0 matches**: confirms lib layer never calls nd6_setmtu/if_notifymtu/rt_updatemtu.

Standard FreeBSD kernel path (bypassed by f-stack): `ifhwioctl SIOCSIFMTU` (`if.c:2754`) → `if_notifymtu` (`if.c:4440`) → `nd6_setmtu` (`nd6.c:354`) → `nd6_setmtu0` (`nd6.c:364`) → `ndi->maxmtu = ifp->if_mtu`.

### 3.3 IN6_LINKMTU Returns 1500 → Fragment 1448

| Step | file:line | Code |
|------|-----------|------|
| ⑪ IN6_LINKMTU macro | `freebsd/netinet6/nd6.h:102-106` | `(ndi->linkmtu && ndi->linkmtu < if_mtu) ? linkmtu : ((ndi->maxmtu && ndi->maxmtu < if_mtu) ? maxmtu : if_mtu)` → maxmtu(1500)<if_mtu(9000) → **returns 1500** |
| ⑫ Route nh_mtu=IN6_LINKMTU | `freebsd/netinet6/in6_rmx.c:117-120` | `nh->nh_mtu = IN6_LINKMTU(nh->nh_ifp);` = 1500 |
| ⑬ ip6_getpmtu takes nh_mtu | `freebsd/netinet6/ip6_output.c:1519-1521` | `nh = fib6_lookup(...); mtu = nh->nh_mtu;` = 1500 |
| ⑭ ip6_calcmtu queries hostcache for ICMP6 | `freebsd/netinet6/ip6_output.c:1540-1567` | proto=ICMP6≠TCP/SCTP → `mtu = tcp_hc_getmtu(&inc);`; `if(mtu) mtu=min(mtu,rt_mtu); else mtu=rt_mtu;` → regardless of hostcache, gets 1500 (rt_mtu=1500 is the upper bound) |
| ⑮ Fragment size calculation | `freebsd/netinet6/ip6_output.c:1204` | `len = (1500-40-8)&~7 = 1448` → 6 fragments 1448×5+1268=8508 ✓ |

### 3.4 Root Cause Summary

```
ether_ifattach(if_mtu=1500) → nd6_ifattach → nd6_setmtu0(ndi->maxmtu=1500)
        ↓
ff_veth if_setmtu(9000) → if_mtu=9000, but [nd6_setmtu not called] → ndi->maxmtu stays 1500
        ↓
IN6_LINKMTU = maxmtu(1500) < if_mtu(9000) → returns 1500
        ↓
Route nh_mtu = 1500 → ip6_getpmtu mtu=1500 → ip6_calcmtu mtu=1500
        ↓
ip6_output fragment len=(1500-48)&~7=1448 → 6 fragments
```

## IV. Why IPv4 Normal / Why KNI On Normal

- **IPv4 normal**: IPv4 output path (`ip_output.c`) uses `ifp->if_mtu=9000` for fragmentation decisions, not `IN6_LINKMTU`. if_mtu is correctly set to 9000 by ff_veth, so 8500 packets are not fragmented.
- **KNI on normal**: KNI goes through the Linux kernel stack for replies; the kernel veth interface's `nd_ifinfo` is correctly synced by Linux kernel `ifioctl`/`if_notifymtu` equivalent path, MTU=9000 takes effect. The problem is only in f-stack's user-space FreeBSD protocol stack `nd_ifinfo` not being synced.

## V. Secondary Cause (May Coexist, Pending Runtime Validation)

User `ff_ifconfig` shows `ACCEPT_RTADV` enabled. If the router advertises MTU=1500, `nd6_rtr.c:540-561` sets `ndi->linkmtu=1500`:

```c
// nd6_rtr.c:544
mtu = (u_long)ntohl(ndopts.nd_opts_mtu->nd_opt_mtu_mtu);
// nd6_rtr.c:557-559
if (mtu <= maxmtu) {
    if (ndi->linkmtu != mtu) {
        ndi->linkmtu = mtu;
```

`IN6_LINKMTU` priority: `linkmtu` > `maxmtu` > `if_mtu`. Even if the primary cause is fixed (maxmtu synced to 9000), if `linkmtu=1500` it still suppresses `IN6_LINKMTU` to return 1500.

**Runtime validation method** (pending subsequent execution):
- `ndp -i f-stack-0` to view `linkmtu` / `maxmtu` actual values
- If `linkmtu=0`: primary cause (maxmtu not synced) is the sole root cause; fixing maxmtu suffices
- If `linkmtu=1500`: need additional RA handling (sysctl `net.inet6.ip6.accept_rtadv=0` or ignore RA MTU option)

## VI. Fix Direction (Option A Implemented)

| Option | Change | Pros/Cons |
|------|------|--------|
| **A (implemented)** | After `if_setmtu` at `ff_veth.c:968` and `:253`, add `if_notifymtu(ifp)` | Includes nd6_setmtu + rt_updatemtu, one-shot sync; consistent with standard kernel semantics |
| B | `ff_veth.c` add `nd6_setmtu(ifp)` + `rt_updatemtu(ifp)` separately | Equivalent to A, but needs two lines |
| C | Use standard `ifhwioctl(SIOCSIFMTU)` path instead of direct `if_setmtu` | Larger change, may introduce side effects |

Secondary cause handling to evaluate:
- If runtime confirms `linkmtu=1500` (RA advertisement), need additional: sysctl disable `accept_rtadv`, or `ndp -i f-stack-0` manually set linkmtu, or ignore RA MTU option on f-stack side
- If `linkmtu=0`, Option A fully fixes it

## VII. External References

FreeBSD standard interface MTU change sync path (cross-validated, consistent with code):
```
SIOCSIFMTU (ioctl)
  → ifhwioctl (if.c:2729)
    → if_setmtu (if.c:4431, only sets if_mtu)
    → if_notifymtu (if.c:4440)
      → nd6_setmtu (nd6.c:354, IPv6 sync ndi->maxmtu)
      → rt_updatemtu (update route MTU)
```
- FreeBSD source `github.com/freebsd/freebsd-src` `sys/netinet6/nd6.c`: `nd6_setmtu0` is the sole assignment point for `ndi->maxmtu` (`nd6.c:369`), called by `nd6_ifattach` (init) and `nd6_setmtu` (runtime change).
- f-stack `github.com/F-Stack/f-stack` `freebsd/netinet6/nd6_rtr.c`: RA MTU option handling consistent with upstream.

## VIII. Honest Boundary

- The primary cause (`ndi->maxmtu` not synced) has been fixed by adding `if_notifymtu` and passed physical machine runtime validation (commit `0f25ac495`): after `ifconfig f-stack-0 mtu 9000`, `ping6 -M do -s 8500` reply no longer fragments; IPv6 jumbo send/receive normal.
- Runtime validation confirmed that after the primary cause fix, `IN6_LINKMTU` returns `if_mtu=9000`, i.e., `linkmtu=0` (not suppressed by RA); no additional RA handling needed.
