# 01 — Requirements Spec

> Document version: v0.1 (2026-06-09)
> Parent plan: `plan.md`
> Upstream document: `00-overview-and-glossary.md`

---

## 1. Project Goal (What)

Upgrade the **DPDK 23.11.5 LTS** currently embedded in F-Stack to **DPDK 24.11.6 LTS**, so that F-Stack's main features (helloworld primary, nginx single/multi-process) work on the new DPDK with **functional equivalence + no performance regression**, while preserving the 3 DPDK local patches F-Stack has accumulated.

---

## 2. Functional Requirements (FR)

| ID | Description | Acceptance |
|---|---|---|
| **FR-D-1** | After the full-tree replacement 23.11.5 → 24.11.6, `dpdk/build/` compiles with `meson setup build && ninja -C build` with 0 errors (warnings within ±10% of the 23.11.5 baseline) | TC-G1 (see 06-test §G1) |
| **FR-D-2** | After re-applying the 3 F-Stack historical patches (`5f3768c63` + `62f1c34df` + `92718178b`), `dpdk/build/` still has 0 errors; patch equivalence self-check (diff vs original commits differs only in context lines) | TC-G1.5 |
| **FR-D-3** | F-Stack's `lib/libfstack.a` and `example/{helloworld, helloworld_zc, helloworld_epoll}` all compile (0 errors, warnings not exceeding the freebsd-15 baseline 57 + 5 = 62) | TC-G2 |
| **FR-D-4** | `helloworld` primary brings up the stack on 24.11.6 (including key init logs such as `f-stack-0: Successed to register dpdk interface`), surviving ≥ 12 seconds without crash | TC-A.G2 |
| **FR-D-5** | A single client → server (`<DPDK_NIC_IP>`) curl returns HTTP 200 + real HTML body | TC-A.G3.1 |
| **FR-D-6** | 100 short connections from client → server: 100/100 PASS | TC-A.G3.2 |
| **FR-D-7** | nginx (`app/nginx-1.28.0/`) single-process mode brings up the stack + curl static page HTTP 200 + 100 short connections 100/100 | TC-C.G3 |
| **FR-D-8** | nginx multi-process mode (`worker_processes 4`) brings up the stack: 1 master + 4 workers all alive; client curl + wrk complete at least 1 successful HTTP 200 response | TC-E.G3 |
| **FR-D-9** | F-Stack patch `92718178b` is effective on the 24.11.6 tree: when a secondary process exits (e.g., SIGTERM an nginx worker), the primary (nginx master) does not crash | TC-E.G3.exit |
| **FR-D-10** | F-Stack patch `62f1c34df` is effective on the 24.11.6 tree: secondary process restart (e.g., nginx -s reload) does not enter the timer infinite loop | TC-E.G3.reload |
| **FR-D-11** | F-Stack's historical capabilities (IPFW, NETGRAPH, IPIP tunnel, VLAN+vip+ipfw_pr, and other phase-2 + vlan-test enablement flags) pass single-pass smoke on 24.11.6 (no full 5×3 matrix) | TC-F.G3 |

---

## 3. Non-Functional Requirements (NFR)

| ID | Description | Threshold | Source |
|---|---|---|---|
| **NFR-D-1** | helloworld single-process performance trade-off vs 23.11.5 baseline | short-connection (100×) / long-connection (1000×) median time ≤ +5% | phase-5b methodology |
| **NFR-D-2** | nginx single-process performance trade-off vs 23.11.5 baseline | same as above | same as above |
| **NFR-D-3** | No build-time regression | 24.11.6 full-tree build time ≤ 23.11.5 full-tree build time × 1.3 (+30% allowed, due to 2 new libs + eal/ethdev +2 KLoC each) | measured |
| **NFR-D-4** | `libfstack.a` size does not explode | ≤ 23.11.5 baseline × 1.10 (+10% allowed, due to ethdev/hash increases) | measured |
| **NFR-D-5** | No steady-state memory increase | helloworld primary RSS within ±5% of the 23.11.5 baseline | measured via ps after sleep 60s |
| **NFR-D-6** | No new SIGSEGV/panic/abort/SIGBUS keywords during testing | grep stdout/stderr = 0 hits | each G2/G3 |

> When performance trade-off > 5%, follow the phase-5b rule: downgrade to an observation label + user decision (does not block spec completion; see 06-test §G4 decision matrix for details).

---

## 4. Boundary Conditions

### 4.1 In-scope Tests (defined in this spec phase)

| Test | Requirement |
|---|---|
| TC-A | helloworld single-process function + performance |
| TC-B | helloworld single-process performance (curl-bench 100/1000) |
| TC-C | nginx single-process function (HTTP 200 + 100 short connections) |
| TC-D | nginx single-process performance (wrk if available, else curl loop) |
| TC-E | nginx multi-process function (curl) + FR-D-9/10 verification |
| TC-F | nginx multi-process wrk functional (functionality only, no horizontal-scaling evaluation) |
| TC-G | F-Stack phase-2 + vlan-test historical capability single-pass smoke |

### 4.2 Out-of-scope Tests

| Item | Reason |
|---|---|
| nginx multi-process horizontal-scaling performance (rps scaling linearly with worker count) | Completed by the user later in a physical-machine environment; CVM ssh round-trip ~6 ms determines the single-process throughput ceiling |
| iperf high-throughput test | same as above |
| F-A1 / F-A3 / F-A4 and other phase-5b historical followups | decoupled from this DPDK upgrade |
| Full phase-2 five-config × 3-trial matrix | single-pass smoke only during the upgrade; a full matrix, if needed, is left for a later independent phase-5c |
| KNI subsystem re-enablement | decoupled from this upgrade (see §6 risk register R-D2) |

---

## 5. Acceptance Gates (Gate Matrix)

| Gate | Content | Failure Handling |
|---|---|---|
| **G1 build** | dpdk/build + lib/libfstack.a + example/* — all three layers 0 errors | Phase 2 bounce → coder |
| **G2 startup** | helloworld primary alive ≥ 12 s | Phase 2 bounce → coder (rare, spec) |
| **G3 functional** | TC-A ~ TC-G all PASS | bounce → coder (spec if spec is insufficient) |
| **G4 perf** | NFR-D-1 / NFR-D-2 within ±5% | observation label or spec threshold revision |
| **G5 doc** | this spec + top-level architecture doc DPDK version anchor sync | doc-updater |
| **G6 lint** | `read_lints` 0 errors | doc-updater |
| **G7 commit** | 2 independent commits (`replace:` + `port:`, see plan.md §4.4) | leader |

---

## 6. Risk Register (each entry has detection + mitigation)

| ID | Risk | Detection | Mitigation | Owner |
|---|---|---|---|---|
| **R-D1** | rte_eth_dev_info_get / rte_flow_create / rte_eth_rx_queue_setup and other 24.11 ABI breaks | compile-time unresolved reference / signature mismatch | diff-comparator measured: all rte_* APIs called by F-Stack still exist at the same locations in 24.11.6 (**0 renames / 0 deprecations**), only line-level signature changes fixed in Phase 2 | coder |
| **R-D2** | ~~KNI subsystem completely removed in 24.11 (deprecated since DPDK 22.11+)~~ → **N/A** (closed after user feedback 2026-06-09 14:50) | F-Stack's FF_KNI is a ring + virtio_user self-implementation (lib/Makefile:34 comment + ff_dpdk_kni.c with 0 rte_kni references), unrelated to DPDK librte_kni; the lib/kni of upstream 23.11.5 / 24.11.6 / F-Stack's current dpdk/ all do not exist | **Risk eliminated** — `FF_KNI=1` retained; dpdk/ contains only the single igb_uio kernel module (see 02 §3.6) | leader |
| **R-D3** | igb_uio removed in 24.11 upstream | measured `ls dpdk-stable-24.11.6/kernel/linux/igb_uio/` | Does not affect the upgrade — F-Stack ships its own igb_uio (Copyright 2010-2017 Intel); after the full-tree replacement the `dpdk/kernel/linux/` subtree is restored by re-applying 5f3768c63 | patch-scout confirmed |
| **R-D4** | secondary process eal_bus_cleanup behavior change | whether `eal_bus_cleanup()` inside `rte_eal_cleanup` of 24.11.6 `lib/eal/linux/eal.c` is still called unconditionally | dpdk-24-analyzer measured: **still unconditional**; stable does not include the real 25.07 fix → patch `92718178b` **must be rebased and re-applied** | coder |
| **R-D5** | priv_timer.is_running has zero upstream change in lib/timer 24.11, but the cache_align macro migration may affect ABI offsets | diff-comparator measured: lib/timer file sizes fully identical (27.46/27.61 KB); only the `__rte_cache_aligned` macro position changed (`struct __rte_cache_aligned priv_timer { ... }` replacing `struct priv_timer { ... } __rte_cache_aligned;`); ABI offsets **unchanged** | Phase 2 compile verification suffices (no source change needed) | coder |
| **R-D6** | meson 24 / gcc version requirement changes | 02 §3.8 measured the top-level meson.build of dpdk-stable-24.11.6 + sys_reqs.rst | current CVM gcc 11+ + meson 1.x satisfies the requirement; if insufficient, note the upgrade path in the spec phase | dpdk-24-analyzer |
| **R-D7** | performance trade-off > 5% (24.11 internal optimizations may introduce overhead) | TC-B / TC-D measurement | observation label + user decision (same as phase-5b OQ-2) | gate-keeper |
| **R-D8** | coexistence regression with the 7 FF_* flags enabled in phase-2 | TC-G single-pass smoke | single-pass failure → split into an independent phase; does not block the main upgrade | coder |
| **R-D9** | compatibility with the freebsd 15.0 port + 41 netgraph + 14 ipfw and other subsystems | helloworld startup log (including `ipfw2 (+ipv6) initialized` + `tcp_bbr is now available`) | TC-A.G2 covers this | gate-keeper |
| **R-D10** | DPDK internal ABI_VERSION 24.0 → 25.0 affects the binary compatibility of externally linked libfstack.a | F-Stack links static libs by default, no direct ABI break; but if a user deployment uses dynamic libdpdk, recompilation is needed | documented (chapter 98), non-blocking | leader |
| **R-D11** | `rte_ip.h` emptied in 24.11 (21.6 KB → 210 B), content split into `rte_ip4.h` / `rte_ip6.h` | whether F-Stack `lib/ff_dpdk_if.c` `#include <rte_ip.h>` depends on specific IPv4/IPv6 structs | Phase 2 grep `struct rte_ipv4_hdr / struct rte_ipv6_hdr` in `f-stack/lib/ff_dpdk_*.c`; add `#include <rte_ip4.h>` or `<rte_ip6.h>` if needed | coder |
| **R-D12** | EAL state-sharing regression when nginx multi-worker forks multiple secondaries | TC-E `nginx -s reload` test | coupled with R-D4 / FR-D-9 / FR-D-10 | coder |

---

## 7. Key Decision Points (DP)

### 7.1 Decided

| DP | Decision | Basis |
|---|---|---|
| DP-A1 ~ A8 | see `plan.md` §7.1 | user q1~q4 + addition at 2026-06-09 14:36 |

### 7.2 Closed after spec-phase research (DP-Bx)

| DP | Decision Content | Measured Conclusion | Closure Basis |
|---|---|---|---|
| **DP-B1** | whether patch `92718178b` has been merged upstream in 24.11.6 | **Not merged** — `eal_bus_cleanup()` in 24.11.6 stable is still an unconditional call; the real upstream fix is DPDK 25.07 commit `4bc53f8f0d64` | dpdk-24-analyzer Q3.b |
| **DP-B2** | 24.11.6 KNI subsystem status | **N/A** — KNI truth: F-Stack proactively deleted KNI from dpdk/ back in `29c7d5835`; F-Stack's ff_dpdk_kni.c is a ring + virtio_user self-implementation independent of librte_kni; 24.11.6 upstream has no KNI lib/kernel module at all; FF_KNI=1 retained | user feedback 2026-06-09 14:50 + 02 §3.6 measurement |
| **DP-B3** | igb_uio status in 24.11.6 upstream | upstream no longer has igb_uio (removed in 21.05); F-Stack's own version restored by re-applying `5f3768c63` | patch-scout Q4.1 + dpdk-24-analyzer Q7 |
| **DP-B4** | whether argparse / ptr_compress need enablement | **Not enabled** — 0 references in F-Stack | diff-comparator Q5 |
| **DP-B5** | meson / gcc minimum versions | filled by 02 §3.8 measurement | dpdk-24-analyzer Q8 |
| **DP-B6** | number of rte_flow / rte_ethdev API ABI breaks | **0 renames / 0 deprecations** — all public APIs called by F-Stack are at the same locations in 24.11.6; only line-level signature differences | diff-comparator Q4 |
| **DP-B7** | whether the 5% performance trade-off threshold is reasonable | **keep 5%**, consistent with phase-5b; over-threshold → observation | NFR-D-1 / NFR-D-2 |

### 7.3 Pending for Phase 2 (DP-Cx)

| DP | Decision Content | Decision Timing |
|---|---|---|
| DP-C1 | whether to keep `dpdk.bak-23.11.5/` until all Phase 2 tests PASS | recommend **keeping** until TC-A ~ TC-G all PASS; user decides the cleanup timing |
| DP-C2 | whether the observation label upgrades to blocking when performance trade-off is 5%~10% | after Phase 2 measurement |
| DP-C3 | whether to split an independent phase when TC-G phase-2 historical capability smoke fails | at Phase 2 bounce time |

---

## 8. Implementation Pre-conditions

| # | Condition | Verification |
|---|---|---|
| 1 | F-Stack git working tree clean | `git status -sb` |
| 2 | current 23.11.5 baseline compiles successfully | measured: `f-stack/dpdk/build/` already exists + `compile_commands.json` readable |
| 3 | 23.11.5 baseline performance data obtainable | run the phase-5b matrix on 23.11.5 to capture the baseline before Phase 2 starts |
| 4 | upstream 24.11.6 source in place | `ls /data/workspace/dpdk-stable-24.11.6/lib/argparse/` should exist |
| 5 | 3 historical commits readable (`5f3768c63 + 62f1c34df + 92718178b`) | `git --no-pager show <hash>` verification |
| 6 | rm/kill/chmod wrapper scripts available | `ls -l /data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh` |
| 7 | f-stack-client (<CLIENT_IP>) ssh-accessible | verified during testing |

---

## 9. Document Meta-Information

- **Status**: v0.1 DRAFT — pending gate-keeper review
- **Next**: read `02-current-and-target.md` for details of F-Stack's current patches and 24.11.6 key changes
