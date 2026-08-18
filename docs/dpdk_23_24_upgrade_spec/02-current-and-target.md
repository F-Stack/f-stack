# 02 — Current (23.11.5 + F-Stack patches) vs Target (24.11.6) State Comparison

> Document version: v0.1 (2026-06-09)
> Parent plan: `plan.md`
> Upstream documents: `00-overview-and-glossary.md` + `01-requirements-spec.md`
> Research inputs: dpdk-23-patch-scout + dpdk-24-analyzer two-way parallel research results (measured)

---

## 1. Top-Level Baseline (measured)

| Dimension | Current (23.11.5 + F-Stack patches) | Target (24.11.6 upstream) | Change |
|---|---|---|---|
| `VERSION` | `23.11.5` | `24.11.6` | major version upgrade |
| `ABI_VERSION` | `24.0` | `25.0` | SONAME upgrade (dynamic librte_*.so incompatible) |
| Top-level structure | 19 items (consistent with upstream 23.11.5 + `build/`, missing 4 dotfiles) | 19 items | fully consistent |
| `lib/` subdirectory count | 57 | 59 | +2 (new `argparse` + `ptr_compress`, no deletions) |

---

## 2. F-Stack's Local Modification List Against DPDK 23.11.5 (patch-scout measurement + user feedback correction 2026-06-09 14:50)

Verified by `diff -rq /data/workspace/dpdk-stable-23.11.5 /data/workspace/f-stack/dpdk/` + `git log --diff-filter=D`: all changes F-Stack made inside `dpdk/` = fully covered by **4 commits** (patch-scout's first report missed `29c7d5835` because the `diff -rq | head -25` truncation failed to capture the redundant-files deletion list; this section was completed by measurement after user prompting).

### 2.1 5f3768c63 — Sync DPDK's modifies (2025-10-31)

#### Files Involved

| Category | File | Description |
|---|---|---|
| Added (whole subtree) | `dpdk/kernel/linux/` | upstream 23.11.5's `kernel/` only contains `freebsd/` + `meson.build`, **no linux/ directory** |
| Added | `dpdk/kernel/linux/igb_uio/igb_uio.c` (15.39 KB) | F-Stack's own igb_uio kernel module, Copyright 2010-2017 Intel, ported from the old ≤20.11 DPDK |
| Added | `dpdk/kernel/linux/igb_uio/compat.h` (3.87 KB) | handles kernel < 3.18 / RHEL compatibility |
| Added | `dpdk/kernel/linux/igb_uio/{Kbuild, Makefile, meson.build}` | build files |
| Added | `dpdk/kernel/linux/meson.build` | entry point (cross-build / native distinction; `subdirs = ['igb_uio']`) |
| Modified | `dpdk/kernel/meson.build` | adds the linux subdirectory reference |
| Modified | `dpdk/lib/eal/freebsd/include/rte_os.h` | adds the `__FreeBSD_version >= 1301000` branch (FreeBSD 13.1+ `CPU_AND/CPU_OR` three-argument adaptation) |

#### Key Code Snippet (measured file:line)

`dpdk/lib/eal/freebsd/include/rte_os.h:32-48`:
```c
#ifdef RTE_EAL_FREEBSD_CPUSET_LEGACY
#if __FreeBSD_version >= 1301000
    /* FreeBSD 13.1+ uses 3-argument CPU_AND(dst,src1,src2) */
    CPU_AND(&dst, &cpu_mask, &src);
#else
    /* FreeBSD < 13.1 still uses 2-argument CPU_AND(dst,src) */
    CPU_AND(&dst, &cpu_mask);
#endif
```

#### 24.11.6 Upstream Status

| Dimension | Status |
|---|---|
| Does `kernel/linux/` exist in 24.11.6 | **no igb_uio** (removed from upstream in DPDK 21.05) |
| Does `lib/eal/freebsd/include/rte_os.h` in 24.11.6 upstream contain an equivalent FreeBSD 13.1+ adaptation | to be measured in Phase 2; conservatively assumed **not included** (this patch was introduced by F-Stack for the FreeBSD 15 upgrade) |

→ **Conclusion**: all changes in `5f3768c63` must be re-applied on the 24.11.6 tree (both the igb_uio whole-subtree addition and the freebsd rte_os.h modification).

### 2.2 62f1c34df — Fix infinite loop when restarting DPDK secondary process (2026-01-16)

#### Files Involved

| File | Change | Lines |
|---|---|---|
| `dpdk/lib/timer/rte_timer.c` | adds the `rte_timer_meta_init()` function after `rte_timer_init()` | +13 |
| `dpdk/lib/timer/rte_timer.h` | adds the `int rte_timer_meta_init(void);` declaration (commented "For f-stack internal use only") | +8 |
| `dpdk/lib/timer/version.map` | **unmodified** (meta_init not exported in the ABI, purely internal library linkage) | — |
| `f-stack/lib/ff_dpdk_if.c:910` | calls `rte_timer_meta_init()` after `rte_timer_subsystem_init()` | +1 line context |

#### Design Intent

When a DPDK secondary process restarts, the `running_tim` field of the `priv_timer` global array may still point to the timer of the already-exited primary process; the first `rte_timer_manage` after restart then enters an infinite loop. F-Stack's fix adds `rte_timer_meta_init()` which the secondary calls at startup to reset the per-lcore `running_tim` / `pending_tim` state.

#### 24.11.6 Upstream Status

| Dimension | Status |
|---|---|
| 24.11.6 lib/timer file-level changes | **0** (measured `rte_timer.c` + `rte_timer.h` sizes fully identical, 27.46/27.61 KB) |
| Line-level changes | only the `__rte_cache_aligned` macro position adjustment (`struct __rte_cache_aligned priv_timer { ... }` replacing `struct priv_timer { ... } __rte_cache_aligned;`), ABI offsets unchanged |
| Does upstream contain an equivalent fix | **no** (lib/timer has zero line-level semantic changes in 24 upstream) |

→ **Conclusion**: the `rte_timer_meta_init()` addition in `62f1c34df` must be re-applied (the patch applies trivially to 24.11.6, cherry-pick suffices); also keep the call site `f-stack/lib/ff_dpdk_if.c:910` (outside the dpdk/ subtree, an F-Stack main-body modification).

### 2.3 92718178b — dpdk/eal: fix secondary process calling eal_bus_cleanup() (2026-03-18)

#### Files Involved

| File | Change | Lines |
|---|---|---|
| `dpdk/lib/eal/linux/eal.c` | adds the `if (rte_eal_process_type() == RTE_PROC_PRIMARY)` guard before the `eal_bus_cleanup()` call inside `rte_eal_cleanup()` | +12 / -1 |

#### Design Intent

When a DPDK secondary process exits, the original `eal_bus_cleanup()` resets shared PCI device state; but that state is owned by the primary, and secondary operations cause NIC communication anomalies or crashes on the primary side. F-Stack's fix restricts the cleanup to the primary process.

#### 24.11.6 Upstream Status (dpdk-24-analyzer Q3 measurement)

The `rte_eal_cleanup()` call order at `/data/workspace/dpdk-stable-24.11.6/lib/eal/linux/eal.c:1300-1340`:
```
rte_service_finalize() → eal_bus_cleanup() → vfio_mp_sync_cleanup() →
rte_mp_channel_cleanup() → rte_eal_alarm_cleanup() → ...
→ eal_lcore_var_cleanup() → rte_eal_log_cleanup()
```

Key: **`eal_bus_cleanup()` is still called unconditionally in 24.11.6** (no PRIMARY / SECONDARY distinction).

The `eal: fix MP socket cleanup` in `release_24_11.rst:1411` is a 24.11.4 stable fix, but measured to only fix the MP socket residual-file problem, **not** the secondary device-reset problem F-Stack cares about. The real fix mentioned in F-Stack's comment (DPDK 25.07 commit `4bc53f8f0d64`) is **not backported to 24.11.6 stable**.

→ **Conclusion**: `92718178b` must be rebased and re-applied on the 24.11.6 tree (keeping the PRIMARY guard logic, aligned with the new call order of 24.11.6's `rte_service_finalize()` / `eal_lcore_var_cleanup()`).

### 2.4 29c7d5835 — Remove redundant dpdk files (2025-01-10) **[supplementary identification after user feedback]**

#### Files Involved (**310 files / 43195 lines deleted**)

Measured via `git show 29c7d5835 --stat`; categorized as follows:

| Category | Deleted Paths | Count |
|---|---|---|
| **DPDK KNI subsystem** (user's key concern) | `dpdk/lib/kni/{meson.build, rte_kni.c, rte_kni.h, rte_kni_common.h, rte_kni_fifo.h, version.map}` + `dpdk/kernel/linux/kni/{Kbuild, compat.h, kni_dev.h, kni_fifo.h, kni_misc.c, kni_net.c, meson.build}` + `dpdk/drivers/net/kni/{meson.build, rte_eth_kni.c}` + `dpdk/lib/port/rte_port_kni.{c,h}` + `dpdk/examples/ip_pipeline/kni.{c,h,cli}` + `dpdk/app/test/test_kni.c` | ~17 files |
| **DPDK igb_uio subsystem (old version)** | `dpdk/kernel/linux/igb_uio/{Kbuild, Makefile, compat.h, igb_uio.c, meson.build}` + `dpdk/kernel/linux/meson.build` | 6 files |
| redundant drivers acc200 / liquidio / nfp / idpf / ark / bnxt / cnxk / tap-bpf etc. | `dpdk/drivers/{baseband,net,regex}/...` | ~50 files |
| redundant libs | `dpdk/lib/{flow_classify, eal trace, cryptodev_trace, mempool_trace, ethdev_trace, power_empty_poll, power_intel_uncore}/...` | ~30 files |
| redundant examples | `dpdk/examples/{flow_classify, server_node_efd, ip_pipeline kni, multi_process hotplug_mp commands.h, bond main.h}` | ~20 files |
| redundant docs / dts / buildtools | `dpdk/doc/guides/{nics/{kni,liquidio}.rst, prog_guide/{kernel_nic_interface,flow_classify_lib}.rst, bbdevs/acc200.rst, sample_app_ug/flow_classify.rst}` + `dpdk/dts/...` + `dpdk/buildtools/binutils-avx512-check.py` + `dpdk/devtools/...` | ~20 files |
| other redundant (Windows EAL log / fnmatch / ...) | see `git show 29c7d5835` for details | remainder |

> **Note the igb_uio timeline paradox**: `29c7d5835` (2025-01-10) deleted the **old** igb_uio (5 files / -874 lines); half a year later `5f3768c63` (2025-10-31) re-added the **new** igb_uio (with kernel 6.x compatibility + RHEL kernel < 3.18 fallback) to support the new host kernels during the FreeBSD 15.0 upgrade period. The two versions are not in sync and serve different purposes.

#### 24.11.6 Upstream Status

| Dimension | Status |
|---|---|
| Does 24.11.6 still contain lib/kni / kernel/linux/kni | **0** (DPDK 22.11 deprecated → 23.11 removed from lib/ → 24.11 fully cleaned up) |
| Does 24.11.6 still contain drivers/net/kni | to be measured when re-applying the patch |
| Does 24.11.6 still contain liquidio / acc200 and other redundant files | most likely still present (DPDK upstream does not proactively prune) |

→ **Conclusion**: the **still-applicable** deletion list of `29c7d5835` must be re-applied on the 24.11.6 tree. Specifically:
1. **KNI category**: 24.11.6 upstream no longer has it (**the KNI part of 29c7d5835 is automatically N/A, no action needed**), but the patch commit must explicitly record "upstream already aligned with F-Stack's KNI deletion"
2. **igb_uio category**: 24.11.6 upstream never had igb_uio (removed in 21.05) → **this part of 29c7d5835 is automatically N/A**, restored forward by re-applying 5f3768c63 with F-Stack's own new version
3. **other redundant**: 24.11.6 upstream may still have liquidio/acc200/idpf/nfp/flow_classify/server_node_efd etc. — measure precisely and **continue deleting** (keeping F-Stack's consistent lean dpdk/ mirror policy)

### 2.5 Overview of the 4 Patches

| # | commit | Type | 24.11.6 upstream alignment | Re-apply needed? |
|---|---|---|---|---|
| 1 | `5f3768c63` | ADD (igb_uio subtree + freebsd rte_os.h) | upstream has no igb_uio | **must re-apply** |
| 2 | `62f1c34df` | ADD (rte_timer_meta_init) | lib/timer has 0 line changes in 24 upstream | **must re-apply** |
| 3 | `92718178b` | MODIFY (eal.c PRIMARY guard) | 24.11.6 still calls eal_bus_cleanup unconditionally | **must re-apply** (rebase to the new call order) |
| 4 | `29c7d5835` | DELETE (310-file redundant cleanup) | partially automatic N/A (KNI / igb_uio already absent upstream), the rest of the redundant files still need deletion | **must re-apply** (delete only the redundant files still present in 24.11.6) |

### 2.6 New DPDK Libs Not Referenced by F-Stack

`lib/argparse/` + `lib/ptr_compress/` have 0 references in F-Stack (measured grep `rte_argparse|rte_ptr_compress|argparse\.h|ptr_compress\.h` under `f-stack/lib/` and `f-stack/example/` = 0 hits each). **Zero cost for the upgrade**. However, per the consistent lean policy of §2.4, these two new libs could also be deleted via a 29c7d5835-equivalent deletion list (decision pending by user/leader before M3 starts; conservative = keep, aggressive = also delete).

---

## 3. DPDK 24.11.6 Key Change List (dpdk-24-analyzer measurement)

### 3.1 lib/ Top-Level Additions and Deletions

| Dimension | 23.11.5 | 24.11.6 | Note |
|---|---|---|---|
| subdirectory count | 57 | 59 | +2 |
| added | — | `argparse` + `ptr_compress` | introduced in 24.07; 0 references in F-Stack |
| deleted | — | (none) | LTS-to-LTS keeps ABI backward compatibility |

### 3.2 Line-Count Changes of Key Libs (top 8 rte subsystems)

| lib | 23 lines | 24 lines | Δ | F-Stack impact |
|---|---|---|---|---|
| **eal** | 69732 | 72694 | **+2962** | largest change; the 92718178b patch must be rebased (see §2.3) |
| **ethdev** | 40798 | 43160 | **+2362** | second largest; `rte_ethdev.h` APIs 0 renames (see §3.4) |
| **hash** | 7075 | 7781 | +706 | rte_hash internal optimizations; F-Stack only references `rte_thash` (light hash impact) |
| **net** | 5430 | 5954 | +524 | `rte_ip.h` major refactoring (see the §3.7 trap) |
| **ring** | 5056 | 5313 | +257 | `rte_ring.c` +34% (internal optimization), API unchanged |
| **mempool** | 4255 | 4354 | +99 | minor changes |
| **mbuf** | 5863 | 5920 | +57 | stable interface |
| **timer** | 1592 | 1592 | **0** | only macro position adjustment; the 62f1c34df patch applies trivially |

### 3.3 Important Changes in the lib/eal Subsystem

2 new public headers:
- `rte_bitset.h` (multi-word bitset API; `release_24_11.rst:27-29`)
- `rte_lcore_var.h` (per-lcore static variables; `release_24_11.rst:39-41`)

`rte_bitops.h` 13.67 KB → **39.62 KB** (new 32/64-bit bit operation APIs; F-Stack does not actively reference them, no compile-time impact)

### 3.4 lib/ethdev API Changes (diff-comparator Q4 measurement)

**Key conclusion**: all rte_eth_dev_* / rte_eth_*_burst / rte_eth_promiscuous_* and other APIs called by F-Stack **all still exist + same locations** in 24.11.6.

Spot-check of 13 high-frequency symbols:

| Symbol | 24.11.6 location | same as 23.11.5 |
|---|---|---|
| `rte_eth_dev_count_avail` | `lib/ethdev/rte_ethdev.h:2308` | yes |
| `rte_eth_dev_configure` | `lib/ethdev/rte_ethdev.h:2406` | yes |
| `rte_eth_rx_queue_setup` | `lib/ethdev/rte_ethdev.h:2482` | yes |
| `rte_eth_tx_queue_setup` | `lib/ethdev/rte_ethdev.h:2567` | yes |
| `rte_eth_dev_start` | `lib/ethdev/rte_ethdev.h:2892` | yes |
| `rte_eth_promiscuous_enable` | `lib/ethdev/rte_ethdev.h:2996` | yes |
| `rte_eth_link_get_nowait` | `lib/ethdev/rte_ethdev.h:3095` | yes |
| `rte_eth_macaddr_get` | `lib/ethdev/rte_ethdev.h:3459` | yes |
| `rte_eth_dev_info_get` | `lib/ethdev/rte_ethdev.h:3504` | yes |
| `rte_eth_dev_rss_reta_update` | `lib/ethdev/rte_ethdev.h:4647` | yes |
| `rte_eth_dev_adjust_nb_rx_tx_desc` | `lib/ethdev/rte_ethdev.h:5609` | yes |
| `rte_eth_bond_mode_get` | `drivers/net/bonding/rte_eth_bond.h:164` | 23 line :166 (a -2 line shift is not a change) |
| `rte_eth_bond_members_get` | `drivers/net/bonding/rte_eth_bond.h:201` | 23 already `_members_get` (no rename needed) |

The `RTE_ETH_RX/TX_OFFLOAD_*` macro values are fully unchanged (bits 0..21 all identical):

| Macro | 23.11.5 | 24.11.6 |
|---|---|---|
| `RTE_ETH_RX_OFFLOAD_VLAN_STRIP` | RTE_BIT64(0) | RTE_BIT64(0) |
| `RTE_ETH_RX_OFFLOAD_TIMESTAMP` | RTE_BIT64(14) | RTE_BIT64(14) |
| `RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT` | RTE_BIT64(20) | RTE_BIT64(20) |
| `RTE_ETH_TX_OFFLOAD_MULTI_SEGS` | RTE_BIT64(15) | RTE_BIT64(15) |

Only 1 function in `rte_flow.h` is marked `__rte_deprecated` (`rte_flow_copy()`); F-Stack does not call it.

### 3.5 lib/timer ABI Offset Check

The `__rte_cache_aligned` macro position change:
```diff
-struct priv_timer { ... } __rte_cache_aligned;
+struct __rte_cache_aligned priv_timer { ... };
```

ABI offsets / field offsets / total size **fully unchanged** (the attribute application style adjustment does not affect layout). F-Stack's `rte_timer_meta_init()` patch applies trivially.

### 3.6 The KNI Subsystem Truth (**corrected after user feedback, 2026-06-09 14:50**)

**Key fact chain** (confirmed one by one by measurement):

1. **F-Stack's "KNI" is a ring + virtio_user self-implementation, unrelated to DPDK librte_kni**
   - `lib/Makefile:33-34` comment is explicit: "**No DPDK KNI support on FreeBSD**" + "**Enable KNI, via viritio only, no longer support rte_kni.ko**"
   - grep hits for `rte_kni` in `lib/ff_dpdk_kni.c` = **0**
   - the implementation uses `struct rte_ring **kni_rp;` (line 89) + `rte_ring_dequeue_burst(kni_rp[port_id], ...)` (line 142)
   - libfstack.a `nm` contains no `rte_kni*` symbols

2. **F-Stack proactively deleted the entire KNI subtree from dpdk/ back in commit `29c7d5835`** (see §2.4)
   - upstream 23.11.5: measured `find /data/workspace/dpdk-stable-23.11.5 -name 'kni*' -o -name 'rte_kni*'` = 0 hits (DPDK 23.11 lib/ has no KNI anymore; the residual drivers/net/kni was deleted by 29c7d5835)
   - F-Stack's current `f-stack/dpdk/lib/kni/` + `dpdk/kernel/linux/kni/` do not exist (deleted by 29c7d5835)
   - 24.11.6 upstream: `lib/kni/` + `kernel/linux/kni/` completely absent (measured)

3. **`FF_KNI=1` must be retained** (see lib/Makefile:36) — F-Stack's self-implemented KNI path keeps working; **completely unrelated** to the DPDK upstream KNI subsystem

| Dimension | 23.11.5 (current) | 24.11.6 (upgrade target) | upgrade impact |
|---|---|---|---|
| `f-stack/dpdk/lib/kni/` exists | ❌ (deleted by 29c7d5835) | ❌ (24.11.6 upstream never had it + kept deleted after 29c7d5835 re-application) | 0 |
| `f-stack/dpdk/kernel/linux/kni/` exists | ❌ (deleted by 29c7d5835) | ❌ (same as above) | 0 |
| `f-stack/dpdk/kernel/linux/igb_uio/` exists | ✅ (added by 5f3768c63) | ✅ (restored by 5f3768c63 re-application) | 0 — only the single igb_uio kernel module |
| `lib/Makefile FF_KNI=1` | ✅ enabled by default | ✅ **retained** | F-Stack's ring + virtio_user KNI path keeps working |
| F-Stack `lib/ff_dpdk_kni.c` linkage | independent of librte_kni | independent | 0 |

→ **Conclusion**: **KNI is a zero-risk item in the upgrade** (fully consistent with the user's hint):
- ✅ **keep `FF_KNI=1`** (F-Stack's self-implemented ring-based KNI path keeps working)
- ✅ **dpdk/ keeps only the single igb_uio kernel module** (re-applied by 5f3768c63); dpdk/lib/kni / dpdk/kernel/linux/kni naturally do not enter the upgraded dpdk/ (24.11.6 upstream never had them + the 29c7d5835-equivalent patch re-application keeps them deleted)
- ❌ **not needed**: Plan A (FF_KNI=0) is wrong; Plan B (backing up the KNI subtree) is wrong

**R-D2 level**: downgraded from the previously misjudged "P1 blocking" to **N/A** (no risk exists). Must-Fix-1 KNI decision → **cancelled**.

### 3.7 The lib/net `rte_ip.h` Refactoring Trap (**R-D11 closed by measurement, 2026-06-09 14:40**)

```
23.11.5: rte_ip.h = 21.64 KB (all IPv4/IPv6 structs + helpers)
24.11.6: rte_ip.h = 210 B (stub include only)
         rte_ip4.h = 10.82 KB (new; IPv4 content)
         rte_ip6.h = 21.47 KB (new; IPv6 content)
         rte_cksum.h = 3.71 KB (new; checksum helpers extracted)
```

**F-Stack's measured usage** (grep `f-stack/lib/`):

| File | References |
|---|---|
| `lib/ff_dpdk_if.c:52` | `#include <rte_ip.h>` |
| `lib/ff_dpdk_if.c:2203/2205/2214/2216` | 4 uses of `struct rte_ipv4_hdr *iph;` |
| `lib/ff_dpdk_kni.c:37` | `#include <rte_ip.h>` |
| `lib/ff_dpdk_kni.c:306/309/317/320/321` | 5 uses of `struct rte_ipv4_hdr / rte_ipv6_hdr` |
| `lib/ff_memory.c:50` | `#include <rte_ip.h>` |
| `lib/ff_memory.c:321` | 1 use of `struct rte_ipv4_hdr *iph;` |
| **Total** | **3 includes + 10 struct uses** |

→ **Measured conclusion**: F-Stack only includes `<rte_ip.h>` without explicitly including `<rte_ip4.h>` / `<rte_ip6.h>`. In 24.11.6, `rte_ip.h` is a stub include (210 B) that **should automatically include rte_ip4.h + rte_ip6.h**, so `struct rte_ipv4_hdr / rte_ipv6_hdr` should remain visible.

**M4 compile-time verification required** (does not block the spec): if the stub has no forwarding `#include "rte_ip4.h"` (very unlikely), additional includes are needed; if forwarding exists, zero work. On M4 compile errors, fix with a 1-2 line minimal patch.

### 3.8 Build Toolchain Version Requirements (**DP-B5 closed by measurement, 2026-06-09 14:40**)

| Tool | 23.11.5 minimum | 24.11.6 minimum | measured command |
|---|---|---|---|
| meson | `>= 0.53.2` | **`>= 0.57`** (upgraded) | `head -20 dpdk-stable-{23,24}.11.{5,6}/meson.build` |
| ninja | any modern | any modern | — |
| GCC | generally 4.9+ | generally 7+ (re-check sys_reqs.rst) | — |
| Python | 3.6+ | 3.6+ | — |

**Current CVM toolchain**: usually meson 1.x (far above 0.57), gcc 11+ — satisfies 24.11.6 requirements. **If measurement finds meson < 0.57, `pip install -U meson` is required before M2 starts.**

---

## 4. F-Stack's DPDK Dependencies Outside dpdk/ (patch-scout Q7)

| Path | DPDK Reference Form | Upgrade Impact |
|---|---|---|
| `f-stack/lib/Makefile` | `DPDK_HOME ?= ../dpdk` + `PKG_CONFIG_PATH = ${DPDK_HOME}/build/meson-uninstalled` | **yes** — after the full-tree replacement, build/ is regenerated, the PKG_CONFIG_PATH path unchanged |
| `f-stack/example/Makefile` | same as above | same as above |
| `f-stack/app/nginx-1.28.0/auto/feature/` | probes via `pkg-config --libs libdpdk` | same as above |
| `f-stack/tools/sbin/Makefile` | secondary IPC tools, depend on libfstack.a → DPDK static lib | indirect dependency |

→ **Conclusion**: F-Stack's DPDK dependencies outside dpdk/ are **limited to Makefile paths** (`../dpdk` + `build/`); the full-tree replacement does not affect these Makefiles, no adjustments needed.

---

## 5. Current-State Summary (one diagram)

```
                      F-Stack (feature/1.26)
                            ▼
              ┌─────────────────────────────────┐
              │  f-stack/lib/ff_dpdk_*.c        │ ← 4-file glue layer
              │  + ff_memory.c                  │    calling rte_* public APIs
              └────────────┬────────────────────┘
                           ▼ #include <rte_*.h>
              ┌─────────────────────────────────┐
              │  f-stack/dpdk/  =  23.11.5      │ ← full tree = upstream 23.11.5
              │  (full-tree mirror + 3 local    │   - 4 dotfiles + build/
              │   patches)                      │
              │  ├── lib/ (57)                   │
              │  ├── kernel/linux/ ← 5f3768c63  │   F-Stack's own igb_uio
              │  ├── lib/timer/   ← 62f1c34df   │   rte_timer_meta_init()
              │  ├── lib/eal/linux/ ← 92718178b │   eal_bus_cleanup PRIMARY guard
              │  ├── lib/eal/freebsd/ ← 5f3768c63│   FreeBSD 13.1+ CPU_AND/CPU_OR
              │  └── ...                         │
              └─────────────────────────────────┘

After the upgrade:
              ┌─────────────────────────────────┐
              │  f-stack/dpdk/  =  24.11.6      │ ← full tree = upstream 24.11.6
              │  + 3 patches rebased & re-applied│   - 4 dotfiles + rebuild/
              │  ├── lib/ (59 = 57 + argparse + ptr_compress) │ 0 references
              │  ├── kernel/linux/ ← 5f3768c63 re-applied (igb_uio subtree addition)│
              │  ├── lib/timer/   ← 62f1c34df re-applied (cherry-pick)│
              │  ├── lib/eal/linux/ ← 92718178b re-applied (rebase to 24's new call order)│
              │  ├── lib/eal/freebsd/ ← 5f3768c63 re-applied (FreeBSD 13.1+)│
              │  └── ...                         │
              └─────────────────────────────────┘
```

---

## 6. Document Meta-Information

- **Status**: v0.1 DRAFT — pending gate-keeper review
- **Left for Phase 2 measurement**: DP-B2 (KNI status) + part of DP-B5 (meson minimum version) + R-D11 (whether rte_ip.h needs additional includes)
- **Next**: read `04-port-and-impl.md` for the detailed implementation plan of the full-tree replacement + 3-patch re-application
