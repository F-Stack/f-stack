# 00 — Project Overview & Glossary

> Document language: English (translated from the Chinese first edition)
> Spec series root directory: `/data/workspace/f-stack/docs/dpdk_23_24_upgrade_spec/`
> Document version: v0.1 (2026-06-09)
> Parent plan: `plan.md`

---

## 1. One-Sentence Project Definition

Upgrade the **DPDK 23.11.5 LTS** currently embedded in **F-Stack** to **DPDK 24.11.6 LTS**, and produce a Chinese Spec document set that engineering teams and downstream AI agents can directly execute.

> This Spec phase only produces documents; no code changes. The actual full-tree replacement, re-application of 3 patches, and testing are executed by Phase 2 as defined in `04-port-and-impl.md`.

---

## 2. Project Background

### 2.1 F-Stack's Dependency on DPDK

F-Stack is a project that strips the FreeBSD kernel protocol stack out of the kernel and runs it in DPDK user space: DPDK provides NIC I/O, lcore multithreading, mbuf pools, ring queues, and other infrastructure; F-Stack carries FreeBSD's TCP/IP/IPFW/NETGRAPH on top of it. F-Stack's interface to DPDK is concentrated in four files: `lib/ff_dpdk_if.c` (main glue) + `lib/ff_dpdk_pcap.c` + `lib/ff_dpdk_kni.c` + `lib/ff_memory.c` (page-array).

### 2.2 F-Stack's Embedded DPDK Mode

- The `dpdk/` subdirectory in the F-Stack repo is a full DPDK 23.11.5 mirror (57 libs, including `build/` artifacts; top-level structure identical to upstream 23.11.5, missing only the 4 dotfiles `.ci/.editorconfig/.github/.mailmap`).
- F-Stack's `lib/libfstack.a` links DPDK as a static lib by default, independent of system package management.
- F-Stack has accumulated 3 local patches inside `dpdk/` (see §5.1).

### 2.3 Upgrade Drivers

- **Alignment between 23.11 LTS and 24.11 LTS**: DPDK LTS cycles are about 1 year; 24.11.6 (2026-06) is the latest stable LTS. Staying on 23.11 means drifting away from upstream drivers / PMDs / performance optimizations.
- **Upstream status of patch `92718178b`**: F-Stack's secondary process cleanup fix must wait for the 25.07 upstream fix to be fully eliminated (verified: not merged in 24.11.6 stable). This upgrade only removes the API surface differences between 23 and 24, but `92718178b` still needs a backport (inside 24.11.6, `eal_bus_cleanup()` is still an unconditional call without PRIMARY/SECONDARY distinction).
- **New lib evaluation**: 24.07 introduced `argparse` + `ptr_compress` (HiSilicon / Arm submissions); F-Stack references neither, zero cost.

---

## 3. Scope Boundary

### 3.1 IN-SCOPE (covered by this Spec series)

| Scope | Measured Size |
|---|---|
| `f-stack/dpdk/` (upgrade target, full-tree replacement 23.11.5 → 24.11.6) | Full tree (fully aligned with dpdk-stable-24.11.6 + re-applying 3 F-Stack historical patches) |
| F-Stack's local patches in `dpdk/` (3 commits) | 5f3768c63 + 62f1c34df + 92718178b |
| F-Stack glue files | `lib/ff_dpdk_if.c` + `lib/ff_dpdk_pcap.c` + `lib/ff_dpdk_kni.c` + `lib/ff_memory.c` (line-level ABI compatibility check against 24.11.6) |
| Testing | helloworld single-process function+performance; nginx single-process function+performance; nginx multi-process curl + wrk **functional** |

### 3.2 OUT-OF-SCOPE (NOT covered by this Spec series)

| Scope | Reason for Exclusion |
|---|---|
| Actual full-tree replacement and 3-patch re-application | Spec phase only; Phase 2 executes separately |
| Physical-machine performance baseline re-measurement | CVM ssh round-trip ~6 ms determines the single-process throughput ceiling; multi-process horizontal scaling is completed by the user later in a physical-machine environment |
| 24.11 KNI subsystem re-enablement | Decoupled from this upgrade; if upstream KNI still exists in 24.11.6, FF_KNI=1 stays as-is |
| argparse / ptr_compress enablement | Newly introduced in 24.07, 0 references in F-Stack, zero cost — not enabled |
| Git push | Local commit only; push timing decided by the user |
| English Spec | Deferred until the Chinese version passes manual review (same convention as freebsd_13_to_15_upgrade_spec) |
| Regression matrix with the 7 FF_* flags enabled in phase-2 | Only single-pass smoke verification in 06-test; no full 5×3 matrix |

---

## 4. Three Source Roots (measured)

| Path | Role | Version |
|---|---|---|
| `/data/workspace/dpdk-stable-23.11.5/` | DPDK 23.11.5 upstream pristine | VERSION=23.11.5, ABI_VERSION=24.0 |
| `/data/workspace/dpdk-stable-24.11.6/` | DPDK 24.11.6 upstream pristine (upgrade target) | VERSION=24.11.6, ABI_VERSION=25.0 |
| `/data/workspace/f-stack/dpdk/` | F-Stack embedded current DPDK | VERSION=23.11.5, ABI_VERSION=24.0 (consistent with upstream + 3 local patches) |

---

## 5. F-Stack's Current DPDK Modification List (measured)

### 5.1 Complete coverage of 4 historical patches (**revised 3→4 after user feedback at 2026-06-09 14:50**)

Verified by dpdk-23-patch-scout measurement + user feedback supplementary identification: F-Stack's local modifications inside `dpdk/` = fully covered by 4 commits (patch-scout's first report missed `29c7d5835` because the `diff -rq | head -25` truncation failed to capture the redundant-files deletion list).

| commit | Date | Content Category | Files | Migration Needed on Upgrade? |
|---|---|---|---|---|
| `29c7d5835` | 2025-01-10 | **Remove redundant dpdk files** (supplementary identification after user feedback) | 310 files / -43195 lines (KNI / old igb_uio / liquidio / acc200 / nfp / idpf / flow_classify / Windows EAL log / other redundant cleanup) | **Must re-apply** — in 24.11.6, KNI / old igb_uio are automatically N/A (already absent upstream); other redundant files deleted as needed to keep the lean dpdk/ mirror |
| `5f3768c63` | 2025-10-31 | igb_uio kernel module + FreeBSD 13.1+ adaptation | `dpdk/kernel/linux/{igb_uio/{igb_uio.c, compat.h, Kbuild, Makefile, meson.build}, meson.build}` + `dpdk/lib/eal/freebsd/include/rte_os.h` | **Must re-apply** — 24.11.6 upstream has no igb_uio (removed in DPDK 21.05), and the FreeBSD 13.1+ CPU_AND/CPU_OR adaptation is F-Stack-specific |
| `62f1c34df` | 2026-01-16 | secondary process restart infinite-loop fix | `dpdk/lib/timer/rte_timer.c` + `rte_timer.h` (new `rte_timer_meta_init()`) + `f-stack/lib/ff_dpdk_if.c:910` (call site) | **Must re-apply** — lib/timer has zero line changes in 24.11.6 upstream; F-Stack-specific requirement |
| `92718178b` | 2026-03-18 | secondary process calling eal_bus_cleanup() guard | `dpdk/lib/eal/linux/eal.c` (guard `if (rte_eal_process_type() == RTE_PROC_PRIMARY)` before the `eal_bus_cleanup()` call inside `rte_eal_cleanup`) | **Must re-apply** — 24.11.6 stable has no equivalent fix; the real upstream fix is 25.07 commit `4bc53f8f0d64`, not backported to 24.11.6 |

### 5.2 New libs Not Referenced by F-Stack

`lib/argparse/` + `lib/ptr_compress/` have 0 references in F-Stack (measured grep `rte_argparse|rte_ptr_compress|argparse\.h|ptr_compress\.h` under `f-stack/lib/` and `f-stack/example/` = 0 hits each).

---

## 6. Glossary

| Term | Meaning |
|---|---|
| **DPDK** | Data Plane Development Kit; Intel's open-source user-space network driver framework |
| **DPDK LTS** | Long-Term Support branch; released every 12 months, stable maintenance ~2 years |
| **`f-stack/dpdk/`** | The DPDK mirror embedded in the F-Stack repo (currently 23.11.5) |
| **`dpdk-stable-23.11.5/24.11.6`** | Release tarball / git checkout of the official DPDK stable branches |
| **VERSION / ABI_VERSION** | The two top-level version files of DPDK; the former is the user-visible version, the latter is the SONAME number (24.0 = 23.x compatible family; 25.0 = 24.11+ compatible family) |
| **rte layer** | DPDK public API namespace (lib/<X>/rte_*.h); F-Stack interacts with DPDK through rte_* |
| **Full-tree replacement** | `cp -a /data/workspace/dpdk-stable-24.11.6/* f-stack/dpdk/` replaces the 23.11.5 tree with the 24.11.6 upstream tree in one shot; suitable for LTS-to-LTS upgrades |
| **3-patch re-application** | Re-apply the changes in F-Stack historical commits `5f3768c63 + 62f1c34df + 92718178b` onto the 24.11.6 tree |
| **Primary / Secondary process** | DPDK multi-process mode; the primary holds the NIC, secondaries communicate with it via shared hugepage (F-Stack's nginx multi-worker, `tools/sbin/ipfw`, etc. are all secondaries) |
| **EAL** | Environment Abstraction Layer; DPDK's core subsystem for startup / lcore / hugepage / device scanning |
| **`rte_timer_meta_init()`** | An internal function F-Stack added in lib/timer/ (commit `62f1c34df`); declared "For f-stack internal use only", not exported in the ABI |
| **`eal_bus_cleanup()` PRIMARY guard** | F-Stack commit `92718178b` wraps the `eal_bus_cleanup()` call inside `rte_eal_cleanup()` with `if (rte_eal_process_type() == RTE_PROC_PRIMARY)` to prevent secondary processes from resetting shared devices on exit |
| **`igb_uio`** | Intel 1Gb UIO kernel module; removed from upstream in DPDK 21.05; F-Stack maintains the ≤20.11 version as a vfio-pci alternative |
| **rte_ip.h trap** | 24.11 splits the content of `rte_ip.h` (21.6 KB) into `rte_ip4.h` + `rte_ip6.h`, keeping only a 210B stub include; F-Stack including `<rte_ip.h>` still compiles, but code depending on specific IPv4/IPv6 structs may need additional includes |
| **argparse / ptr_compress** | Two new opt-in libs added in DPDK 24.07 (command-line parsing / 32-to-16-bit pointer compression); 0 references in F-Stack |
| **phase-5b methodology** | F-Stack's existing performance baseline methodology (`tools/sbin/p5b_perf_matrix.sh` + curl-bench + 3 trials + cross-config delta + ssh round-trip ~6 ms ceiling note) |

---

## 7. Four Core Decisions (finalized, confirmed by multi-round Q&A in plan.md)

| # | Decision | Resolution | Source |
|---|---|---|---|
| 1 | Agent team topology | Leader + 5 sub-agents | plan.md §2 |
| 2 | DPDK replacement strategy | Full-tree replacement (backup + cp -a + 3-patch re-application) | plan.md §4, DP-A2 |
| 3 | Test matrix organization | Single spec doc `06-test-and-acceptance-spec.md` | plan.md §0.2, q3=A |
| 4 | Spec document system size | 7 documents streamlined (merged 02+03 + merged 04+05) | plan.md §0.2, q4=B |
| 5 | 3-patch re-application commit form | Merged into one `port:` commit, separate from the `replace:` commit | plan.md §4.4, DP-A8 |

---

## 8. Suggested Reading Order

| Role | Order |
|---|---|
| Project manager / architecture reviewer | 00 → 01 → 06 → 99 |
| Implementation engineer | 00 → 02 → 04 → 06 |
| Downstream AI agents (picking up Phase 2 tasks) | 04 → 02 → 06 |

---

## 9. Document Meta-Information

- **Author**: Leader (executed in the main conversation)
- **Collaborative inputs**: dpdk-23-patch-scout / dpdk-24-analyzer / diff-comparator three-way parallel research (completed)
- **Review**: gate-keeper (will produce `99-review-report.md` in Phase 4)
- **Verification**: all numbers come from measured command output; non-measured inferences are sourced in the glossary and this section
- **Next**: read `01-requirements-spec.md` for the specific problems this upgrade will/won't solve
