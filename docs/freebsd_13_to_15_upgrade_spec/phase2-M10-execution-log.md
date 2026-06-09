# Phase-2 M10 Execution Log — FF_FLOW_IPIP (P1d)

> Chinese version: ./zh_cn/phase2-M10-execution-log.md (authoritative)

> Status: ✅ PASS (IPIP tunnel interop both ways; 1 bounce to soft-fallback)
> Date: 2026-06-08
> Upstream basis: M9 commit `2f4748638`

---

## 1. Summary

Enable `FF_FLOW_IPIP=1` (M7+M8 PA/ZC temporarily commented out for isolated GIF/IPIP validation). Involved:

1. `lib/Makefile` enables FF_FLOW_IPIP.
2. `lib/ff_dpdk_if.c` softens `create_ipip_flow` failure from `rte_exit` to a warning (virtio NIC has no rte_flow IPIP offload, but GIF rides the FreeBSD kernel software path which doesn't need hardware flow).
3. `example/Makefile` automatically skips the ZC-dependent helloworld_zc target (M10 testing requires ZC off for isolation).
4. Server-side: `tools/sbin/ifconfig gif0 create / tunnel / inet` 3-step GIF tunnel setup.
5. Client-side Linux: `ip tunnel add gif0 mode ipip` + `ip addr add` + `ip link set up`.
6. ping verification: 3/3 ICMP echo reply ✓.

**Final**: client Linux IPIP ↔ server F-Stack GIF cross-implementation interop, RTT < 1 ms.

---

## 2. Change List

| File | Change | Lines |
|---|---|---|
| `lib/Makefile` | enable `FF_FLOW_IPIP=1` + temporarily comment out PA/ZC | +3 / -3 |
| `lib/ff_dpdk_if.c` | `create_ipip_flow` fail: `rte_exit` → `printf` warning + explanatory comment | +13 / -3 |
| `example/Makefile` | use `nm` to detect whether libfstack.a contains `ff_zc_send`; if not, skip the helloworld_zc target | +9 / -1 |

**Total: 3 files +25/-7**

---

## 3. RCA — Bounce #1

### 3.1 Symptom

With FF_FLOW_IPIP=1 the build PASSed, but helloworld primary, after `Port 0 Link Up`, immediately reported:

```
Flow rule validation failed: Function not implemented
EAL: Error - exiting with code: 1
  Cause: create_ipip_flow failed
```

and `rte_exit(EXIT_FAILURE)` exited; G2 failed.

### 3.2 Root cause

`ff_dpdk_if.c:1442` calls `create_ipip_flow(0)` to install an IPIP-decap flow rule via `rte_flow_create`. The **virtio_net driver** (the measured NIC `0000:00:09.0 1af4:1000 Virtio network device`) does not implement `rte_flow` → ENOTSUP.

But the GIF tunnel actually rides the **FreeBSD kernel software path** (`if_gif.c` / `in_gif.c` are compiled into lib), **orthogonal** to NIC hardware flow offload. The 13.0-baseline `rte_exit` is over-aggressive failure handling here.

### 3.3 Fix

Change `rte_exit(EXIT_FAILURE, ...)` to `printf("M10 [WARN] ...")` soft warning. Comment makes it clear: rte_flow IPIP is a perf optimization (hardware encap/decap offload); when missing, the software path still works.

---

## 4. Gate Results (measured)

### G1 — build

| Item | Result |
|---|---|
| `lib/ make clean && make` | exit=0 / 0 errors / 57 warnings |
| `libfstack.a` | 6.53 MB |
| `example/ make` | helloworld + helloworld_epoll produced; helloworld_zc auto-skipped (lib has no ff_zc_send symbol) |

### G2 — primary smoke

| Item | v1 (rte_exit) | v2 (warning fallback) |
|---|---|---|
| primary stack-up | ✗ (rte_exit) | ✓ ALIVE |
| Flow rule warn | – | `Flow rule validation failed: Function not implemented` (warning) |
| ipfw2 / dpdk if | – | ✓ ✓ |

### G3 — IPIP tunnel functional

| Item | Command | Result |
|---|---|---|
| G3.1 | `tools/sbin/ifconfig gif0 create` | exit=0 ✓ |
| G3.2 | `tools/sbin/ifconfig gif0` | `gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280 / groups: gif` ✓ |
| G3.3 | `tools/sbin/ifconfig` (list all) | `lo0` + `f-stack-0` + `gif0` all visible ✓ |
| G3.4 | `ifconfig gif0 tunnel 9.134.214.176 9.134.211.87` + `ifconfig gif0 inet 10.10.10.1 10.10.10.2 netmask 0xffffffff` | `tunnel inet 9.134.214.176 --> 9.134.211.87 / inet 10.10.10.1 --> 10.10.10.2` flags=`UP,POINTOPOINT,RUNNING,MULTICAST` ✓ |
| G3.5 | client: `ip tunnel add gif0 mode ipip remote 9.134.214.176 local 9.134.211.87` + addr + link up | `gif0@NONE: link/ipip 9.134.211.87 peer 9.134.214.176 inet 10.10.10.2 peer 10.10.10.1/32` ✓ |
| **G3.6** | **`ping -c 3 -W 2 10.10.10.1`** | **3/3 received, 0% loss, RTT 0.288/0.436/0.649 ms ✓** |

### G4 — perf (observation only, OQ-2 default-allowed downgrade)

iperf heavy-traffic not run (client tooling + time budget); functional PASS counts as P1d done.

### G5 — docs

`phase2-M10-spec.md` + `phase2-M10-execution-log.md`; docs anchor + Summary scope follow the M6/M7/M8/M9 pattern.

### G6 — lint: 0 errors.

### G7 — commit: local English commit, no push.

---

## 5. Bounce Count

| # | Stage | Trigger | Fix |
|---|---|---|---|
| 1 | gate→code | rte_exit because virtio has no rte_flow IPIP offload | rte_exit → printf warning (soft fallback) |

**1/3 bounces**, no escalation.

---

## 6. Known Leftovers / Follow-up

| ID | Description | Plan |
|---|---|---|
| F1 | virtio NIC has no rte_flow IPIP hardware offload → CPU software GIF path may underperform a hardware-supported NIC | Won't fix (hardware capability; not a code bug) |
| F2 | iperf heavy-traffic tunnel throughput baseline not done | Deferred to the Phase-5b high-concurrency perf stage |
| F3 | The example Makefile's ZC-symbol probe requires lib to be built first — this ordering dependency could be made explicit | doc + tests pass for now |

---

## 7. Phase Progress

| Phase | Status |
|---|---|
| A. Spec | ✅ |
| B. Research | ✅ |
| C. Code v1 (Makefile only) | ✅ → bounce |
| C. Code v2 (rte_exit fallback + ex Makefile guard) | ✅ |
| D. Review | ✅ 0 lint |
| E. Gate | ✅ G1-G3.6 + G6/G7 PASS; G4 observation only |

**M10 overall: ✅ PASS**
