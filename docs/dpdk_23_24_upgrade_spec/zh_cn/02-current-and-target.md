# 02 — 当前 (23.11.5 + F-Stack patch) 与目标 (24.11.6) 状态对比

> 文档版本：v0.1（2026-06-09）
> Parent plan：`plan.md`
> 上游文档：`00-overview-and-glossary.md` + `01-requirements-spec.md`
> 调研输入：dpdk-23-patch-scout + dpdk-24-analyzer 两路并行调研结果（实测）

---

## 1. 顶层基线（实测）

| 维度 | 当前（23.11.5 + F-Stack patch）| 目标（24.11.6 upstream）| 变化 |
|---|---|---|---|
| `VERSION` | `23.11.5` | `24.11.6` | 大版本升级 |
| `ABI_VERSION` | `24.0` | `25.0` | SONAME 升级（动态链接 librte_*.so 不兼容）|
| 顶层结构 | 19 项（与 upstream 23.11.5 一致 + `build/`，缺 4 dotfile）| 19 项 | 完全一致 |
| `lib/` 子目录数 | 57 | 59 | +2（新增 `argparse` + `ptr_compress`，无删除）|

---

## 2. F-Stack 当前对 DPDK 23.11.5 的本地修改清单（patch-scout 实测 + 2026-06-09 14:50 user 反馈修正）

经 `diff -rq /data/workspace/dpdk-stable-23.11.5 /data/workspace/f-stack/dpdk/` + `git log --diff-filter=D` 实测确认：F-Stack 在 `dpdk/` 内的所有改动 = **4 个 commit** 完全覆盖（patch-scout 第一次报告漏识别 `29c7d5835`，因 `diff -rq | head -25` 截断未捕获 redundant files 删除清单；本节由 user 提示后实测补全）。

### 2.1 5f3768c63 — Sync DPDK's modifies (2025-10-31)

#### 涉及文件

| 类别 | 文件 | 说明 |
|---|---|---|
| Added (整子树) | `dpdk/kernel/linux/` | upstream 23.11.5 的 `kernel/` 仅含 `freebsd/` + `meson.build`，**无 linux/ 目录** |
| Added | `dpdk/kernel/linux/igb_uio/igb_uio.c`（15.39 KB）| F-Stack 自带的 igb_uio 内核模块，Copyright 2010-2017 Intel，移植自 ≤20.11 老版 DPDK |
| Added | `dpdk/kernel/linux/igb_uio/compat.h`（3.87 KB）| 处理 kernel < 3.18 / RHEL 兼容 |
| Added | `dpdk/kernel/linux/igb_uio/{Kbuild, Makefile, meson.build}` | 构建文件 |
| Added | `dpdk/kernel/linux/meson.build` | 入口（cross-build / native 区分；`subdirs = ['igb_uio']`）|
| Modified | `dpdk/kernel/meson.build` | 添加 linux 子目录引用 |
| Modified | `dpdk/lib/eal/freebsd/include/rte_os.h` | 新增 `__FreeBSD_version >= 1301000` 分支（FreeBSD 13.1+ 的 `CPU_AND/CPU_OR` 三参数适配）|

#### 关键代码片段（实测 file:line）

`dpdk/lib/eal/freebsd/include/rte_os.h:32-48`：
```c
#ifdef RTE_EAL_FREEBSD_CPUSET_LEGACY
#if __FreeBSD_version >= 1301000
    /* FreeBSD 13.1+ 改用 3 参数 CPU_AND(dst,src1,src2) */
    CPU_AND(&dst, &cpu_mask, &src);
#else
    /* FreeBSD < 13.1 仍是 2 参数 CPU_AND(dst,src) */
    CPU_AND(&dst, &cpu_mask);
#endif
```

#### 24.11.6 上游状态

| 维度 | 状态 |
|---|---|
| `kernel/linux/` 在 24.11.6 是否存在 | **不存在 igb_uio**（DPDK 21.05 已从上游移除）|
| `lib/eal/freebsd/include/rte_os.h` 在 24.11.6 上游是否含等效 FreeBSD 13.1+ 适配 | 待阶段二实测；保守假设**未含**（此 patch 是 F-Stack 应对 FreeBSD 15 升级时引入）|

→ **结论**：必须在 24.11.6 树上重打 `5f3768c63` 中的所有改动（既包括 igb_uio 整子树添加，也包括 freebsd rte_os.h 修改）。

### 2.2 62f1c34df — Fix infinite loop when restarting DPDK secondary process (2026-01-16)

#### 涉及文件

| 文件 | 改动 | 行数 |
|---|---|---|
| `dpdk/lib/timer/rte_timer.c` | 在 `rte_timer_init()` 之后新增 `rte_timer_meta_init()` 函数 | +13 |
| `dpdk/lib/timer/rte_timer.h` | 新增 `int rte_timer_meta_init(void);` 声明（注释 "For f-stack internal use only"）| +8 |
| `dpdk/lib/timer/version.map` | **未修改**（meta_init 未导出 ABI，纯库内部链接调用）| — |
| `f-stack/lib/ff_dpdk_if.c:910` | 在 `rte_timer_subsystem_init()` 后调用 `rte_timer_meta_init()` | +1 line context |

#### 设计意图

DPDK secondary 进程重启时，`priv_timer` 全局数组的 `running_tim` 字段可能仍指向已退出的 primary 进程的 timer，重启后第一次 `rte_timer_manage` 进入死循环。F-Stack 的 fix 是新增 `rte_timer_meta_init()` 由 secondary 在启动时调用，重置 per-lcore `running_tim` / `pending_tim` 状态。

#### 24.11.6 上游状态

| 维度 | 状态 |
|---|---|
| 24.11.6 lib/timer 文件级变化 | **0**（实测 `rte_timer.c` + `rte_timer.h` 大小完全一致 27.46/27.61 KB）|
| 行级变化 | 仅 `__rte_cache_aligned` 宏位置调整（`struct __rte_cache_aligned priv_timer { ... }` 替代 `struct priv_timer { ... } __rte_cache_aligned;`），ABI 偏移不变 |
| 上游是否含等效 fix | **未含**（lib/timer 24 上游零行级语义改动）|

→ **结论**：必须重打 `62f1c34df` 中的 `rte_timer_meta_init()` 新增（patch 与 24.11.6 trivially apply，cherry-pick 即可）；同步保留 `f-stack/lib/ff_dpdk_if.c:910` 调用点（不在 dpdk/ 子树内，是 F-Stack 主体修改）。

### 2.3 92718178b — dpdk/eal: fix secondary process calling eal_bus_cleanup() (2026-03-18)

#### 涉及文件

| 文件 | 改动 | 行数 |
|---|---|---|
| `dpdk/lib/eal/linux/eal.c` | `rte_eal_cleanup()` 内 `eal_bus_cleanup()` 调用前加 `if (rte_eal_process_type() == RTE_PROC_PRIMARY)` 守护 | +12 / -1 |

#### 设计意图

DPDK secondary 进程退出时，原 `eal_bus_cleanup()` 会去 reset 共享 PCI 设备状态，但这些状态由 primary 持有，secondary 操作会导致 primary 端 NIC 通信异常或崩溃。F-Stack 的 fix 把 cleanup 限定为 primary 进程独有。

#### 24.11.6 上游状态（dpdk-24-analyzer Q3 实测）

`/data/workspace/dpdk-stable-24.11.6/lib/eal/linux/eal.c:1300-1340` 的 `rte_eal_cleanup()` 调用顺序：
```
rte_service_finalize() → eal_bus_cleanup() → vfio_mp_sync_cleanup() →
rte_mp_channel_cleanup() → rte_eal_alarm_cleanup() → ...
→ eal_lcore_var_cleanup() → rte_eal_log_cleanup()
```

关键：**`eal_bus_cleanup()` 在 24.11.6 中仍无条件调用**（不分 PRIMARY / SECONDARY）。

`release_24_11.rst:1411` 中的 `eal: fix MP socket cleanup` 是 24.11.4 stable 修复，但实测仅修 MP socket 残留文件问题，**非** F-Stack 关注的 secondary 设备 reset 问题。F-Stack 注释提到的真正修复（DPDK 25.07 commit `4bc53f8f0d64`）**未 backport 到 24.11.6 stable**。

→ **结论**：必须在 24.11.6 树上 rebase 重打 `92718178b`（保留 PRIMARY 守护逻辑，配合 24.11.6 新增的 `rte_service_finalize()` / `eal_lcore_var_cleanup()` 调用顺序）。

### 2.4 29c7d5835 — Remove redundant dpdk files (2025-01-10) **[user 反馈后补识别]**

#### 涉及文件（**310 文件 / 43195 行删除**）

`git show 29c7d5835 --stat` 实测；以下按类别归纳：

| 类别 | 删除路径 | 数量 |
|---|---|---|
| **DPDK KNI 子系统**（user 关键关注点） | `dpdk/lib/kni/{meson.build, rte_kni.c, rte_kni.h, rte_kni_common.h, rte_kni_fifo.h, version.map}` + `dpdk/kernel/linux/kni/{Kbuild, compat.h, kni_dev.h, kni_fifo.h, kni_misc.c, kni_net.c, meson.build}` + `dpdk/drivers/net/kni/{meson.build, rte_eth_kni.c}` + `dpdk/lib/port/rte_port_kni.{c,h}` + `dpdk/examples/ip_pipeline/kni.{c,h,cli}` + `dpdk/app/test/test_kni.c` | ~17 文件 |
| **DPDK igb_uio 子系统**（旧版）| `dpdk/kernel/linux/igb_uio/{Kbuild, Makefile, compat.h, igb_uio.c, meson.build}` + `dpdk/kernel/linux/meson.build` | 6 文件 |
| 冗余驱动 acc200 / liquidio / nfp / idpf / ark / bnxt / cnxk / tap-bpf 等 | `dpdk/drivers/{baseband,net,regex}/...` | ~50 文件 |
| 冗余 lib | `dpdk/lib/{flow_classify, eal trace, cryptodev_trace, mempool_trace, ethdev_trace, power_empty_poll, power_intel_uncore}/...` | ~30 文件 |
| 冗余 examples | `dpdk/examples/{flow_classify, server_node_efd, ip_pipeline kni, multi_process hotplug_mp commands.h, bond main.h}` | ~20 文件 |
| 冗余 docs / dts / buildtools | `dpdk/doc/guides/{nics/{kni,liquidio}.rst, prog_guide/{kernel_nic_interface,flow_classify_lib}.rst, bbdevs/acc200.rst, sample_app_ug/flow_classify.rst}` + `dpdk/dts/...` + `dpdk/buildtools/binutils-avx512-check.py` + `dpdk/devtools/...` | ~20 文件 |
| 其他冗余 (Windows EAL log / fnmatch / ...) | 详见 `git show 29c7d5835` | 余 |

> **注意 igb_uio 时间线悖论**：`29c7d5835`（2025-01-10）删除了**旧版** igb_uio（5 文件 / -874 行）；半年后 `5f3768c63`（2025-10-31）又重新添加**新版** igb_uio（含 kernel 6.x 兼容 + RHEL kernel < 3.18 fallback）以支持 FreeBSD 15.0 升级期的新主机内核。两版不同步、目的不同。

#### 24.11.6 上游状态

| 维度 | 状态 |
|---|---|
| 24.11.6 是否仍含 lib/kni / kernel/linux/kni | **0 个**（DPDK 22.11 deprecated → 23.11 lib/ 移除 → 24.11 完全清理）|
| 24.11.6 是否仍含 drivers/net/kni | 待 patch 重打时实测 |
| 24.11.6 是否仍含 liquidio / acc200 等其他冗余 | 大概率仍存在（DPDK upstream 不主动 prune）|

→ **结论**：必须在 24.11.6 树上重打 `29c7d5835` 中**仍然适用**的删除清单。其中：
1. **KNI 类**：24.11.6 上游已无（**29c7d5835 KNI 部分自动 N/A，无需操作**），但需在 patch commit 中显式记录"上游已对齐 F-Stack 的 KNI 删除"
2. **igb_uio 类**：24.11.6 上游本就无 igb_uio（21.05 移除）→ **29c7d5835 此部分自动 N/A**，由 5f3768c63 正向重打恢复 F-Stack 自带新版
3. **其他 redundant**：24.11.6 上游可能仍有 liquidio/acc200/idpf/nfp/flow_classify/server_node_efd 等 — 需精确实测后**继续删除**（保留 F-Stack 一贯 lean dpdk/ 镜像策略）

### 2.5 4 个 patch 总览

| # | commit | 类型 | 24.11.6 上游对齐情况 | 是否需重打 |
|---|---|---|---|---|
| 1 | `5f3768c63` | ADD（igb_uio 子树 + freebsd rte_os.h）| upstream 无 igb_uio | **必须重打** |
| 2 | `62f1c34df` | ADD（rte_timer_meta_init）| lib/timer 24 上游 0 行变化 | **必须重打** |
| 3 | `92718178b` | MODIFY（eal.c PRIMARY 守护）| 24.11.6 仍无条件调用 eal_bus_cleanup | **必须重打**（rebase 配合新调用顺序）|
| 4 | `29c7d5835` | DELETE（310 文件冗余清理）| 部分自动 N/A（KNI / igb_uio 上游已无），其余 redundant 仍需删除 | **必须重打**（仅删除 24.11.6 中仍存在的 redundant） |

### 2.6 F-Stack 不引用的 DPDK 新 lib

`lib/argparse/` + `lib/ptr_compress/` 在 F-Stack 0 引用（实测 grep `rte_argparse|rte_ptr_compress|argparse\.h|ptr_compress\.h` 在 `f-stack/lib/` 与 `f-stack/example/` 下均 0 命中）。**升级零成本**。但按 §2.4 一贯 lean 策略，可考虑通过 29c7d5835 等价删除清单**也删除这两个新 lib**（待 user/leader 在 M3 启动前决策；保守保留 = 不删除，激进 = 也删）。

---

## 3. DPDK 24.11.6 关键变更清单（dpdk-24-analyzer 实测）

### 3.1 lib/ 顶层增删

| 维度 | 23.11.5 | 24.11.6 | 备注 |
|---|---|---|---|
| 子目录数 | 57 | 59 | +2 |
| 新增 | — | `argparse` + `ptr_compress` | 24.07 引入；F-Stack 0 引用 |
| 删除 | — | (无)| LTS-to-LTS 保 ABI 向下兼容 |

### 3.2 关键 lib 行数变化（前 8 个 rte 子系统）

| lib | 23 行 | 24 行 | Δ | F-Stack 影响 |
|---|---|---|---|---|
| **eal** | 69732 | 72694 | **+2962** | 最大变化；92718178b patch 须 rebase（详 §2.3） |
| **ethdev** | 40798 | 43160 | **+2362** | 次大；`rte_ethdev.h` API 0 改名（详 §3.4）|
| **hash** | 7075 | 7781 | +706 | rte_hash 内部优化；F-Stack 仅引用 `rte_thash`（hash 影响轻）|
| **net** | 5430 | 5954 | +524 | `rte_ip.h` 大重构（详 §3.7 陷阱）|
| **ring** | 5056 | 5313 | +257 | `rte_ring.c` +34%（内部优化），API 不变 |
| **mempool** | 4255 | 4354 | +99 | 微小变化 |
| **mbuf** | 5863 | 5920 | +57 | 接口稳定 |
| **timer** | 1592 | 1592 | **0** | 仅宏位置调整；62f1c34df patch trivially apply |

### 3.3 lib/eal 子系统重要变更

新增 2 个公开 header：
- `rte_bitset.h`（多字位集 API；`release_24_11.rst:27-29`）
- `rte_lcore_var.h`（per-lcore 静态变量；`release_24_11.rst:39-41`）

`rte_bitops.h` 13.67 KB → **39.62 KB**（新增 32/64-bit 位操作 API；F-Stack 不主动引用，编译期不影响）

### 3.4 lib/ethdev API 变更（diff-comparator Q4 实测）

**关键结论**：F-Stack 调用的所有 rte_eth_dev_* / rte_eth_*_burst / rte_eth_promiscuous_* 等 API 在 24.11.6 中**全部仍存在 + 位置相同**。

抽查 13 个高频符号：

| 符号 | 24.11.6 位置 | 与 23.11.5 同 |
|---|---|---|
| `rte_eth_dev_count_avail` | `lib/ethdev/rte_ethdev.h:2308` | 是 |
| `rte_eth_dev_configure` | `lib/ethdev/rte_ethdev.h:2406` | 是 |
| `rte_eth_rx_queue_setup` | `lib/ethdev/rte_ethdev.h:2482` | 是 |
| `rte_eth_tx_queue_setup` | `lib/ethdev/rte_ethdev.h:2567` | 是 |
| `rte_eth_dev_start` | `lib/ethdev/rte_ethdev.h:2892` | 是 |
| `rte_eth_promiscuous_enable` | `lib/ethdev/rte_ethdev.h:2996` | 是 |
| `rte_eth_link_get_nowait` | `lib/ethdev/rte_ethdev.h:3095` | 是 |
| `rte_eth_macaddr_get` | `lib/ethdev/rte_ethdev.h:3459` | 是 |
| `rte_eth_dev_info_get` | `lib/ethdev/rte_ethdev.h:3504` | 是 |
| `rte_eth_dev_rss_reta_update` | `lib/ethdev/rte_ethdev.h:4647` | 是 |
| `rte_eth_dev_adjust_nb_rx_tx_desc` | `lib/ethdev/rte_ethdev.h:5609` | 是 |
| `rte_eth_bond_mode_get` | `drivers/net/bonding/rte_eth_bond.h:164` | 23 行号 :166（位置位移 -2 行不算变更）|
| `rte_eth_bond_members_get` | `drivers/net/bonding/rte_eth_bond.h:201` | 23 已是 `_members_get`（无需改名）|

`RTE_ETH_RX/TX_OFFLOAD_*` 宏值完全保持不变（位 0..21 全部一致）：

| 宏 | 23.11.5 | 24.11.6 |
|---|---|---|
| `RTE_ETH_RX_OFFLOAD_VLAN_STRIP` | RTE_BIT64(0) | RTE_BIT64(0) |
| `RTE_ETH_RX_OFFLOAD_TIMESTAMP` | RTE_BIT64(14) | RTE_BIT64(14) |
| `RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT` | RTE_BIT64(20) | RTE_BIT64(20) |
| `RTE_ETH_TX_OFFLOAD_MULTI_SEGS` | RTE_BIT64(15) | RTE_BIT64(15) |

`rte_flow.h` 中 `__rte_deprecated` 标记的函数仅 1 个（`rte_flow_copy()`），F-Stack 不调用此函数。

### 3.5 lib/timer ABI 偏移检查

`__rte_cache_aligned` 宏位置变化：
```diff
-struct priv_timer { ... } __rte_cache_aligned;
+struct __rte_cache_aligned priv_timer { ... };
```

ABI 偏移 / 字段偏移 / 总大小 **完全不变**（attribute 应用方式调整不影响 layout）。F-Stack `rte_timer_meta_init()` patch trivially apply。

### 3.6 KNI 子系统真相（**user 反馈后修正，2026-06-09 14:50**）

**关键事实链**（实测一一确认）：

1. **F-Stack 的 "KNI" 是 ring + virtio_user 自实现，与 DPDK librte_kni 无关**
   - `lib/Makefile:33-34` 注释明确："**No DPDK KNI support on FreeBSD**" + "**Enable KNI, via viritio only, no longer support rte_kni.ko**"
   - `lib/ff_dpdk_kni.c` 对 `rte_kni` 的 grep 命中数 = **0**
   - 实现使用 `struct rte_ring **kni_rp;`（line 89）+ `rte_ring_dequeue_burst(kni_rp[port_id], ...)`（line 142）
   - libfstack.a `nm` 不含任何 `rte_kni*` 符号

2. **F-Stack 早在 commit `29c7d5835` 已主动从 dpdk/ 删除 KNI 全部子树**（详 §2.4）
   - upstream 23.11.5：实测 `find /data/workspace/dpdk-stable-23.11.5 -name 'kni*' -o -name 'rte_kni*'` 0 命中（DPDK 23.11 lib/ 已无 KNI；驱动 drivers/net/kni 残留 — 已被 29c7d5835 删除）
   - F-Stack 当前 `f-stack/dpdk/lib/kni/` + `dpdk/kernel/linux/kni/` 不存在（被 29c7d5835 删）
   - 24.11.6 upstream：`lib/kni/` + `kernel/linux/kni/` 完全不存在（已实测）

3. **`FF_KNI=1` 必须保留**（见 lib/Makefile:36）— F-Stack 自实现的 KNI 路径继续生效；与 DPDK 上游 KNI 子系统**完全无关**

| 维度 | 23.11.5 (现状) | 24.11.6 (升级目标) | 升级影响 |
|---|---|---|---|
| `f-stack/dpdk/lib/kni/` 存在 | ❌（被 29c7d5835 删）| ❌（24.11.6 上游本就无 + 29c7d5835 重打后保持删除）| 0 |
| `f-stack/dpdk/kernel/linux/kni/` 存在 | ❌（被 29c7d5835 删）| ❌（同上）| 0 |
| `f-stack/dpdk/kernel/linux/igb_uio/` 存在 | ✅（5f3768c63 添加）| ✅（5f3768c63 重打恢复）| 0 — 仅 igb_uio 一个内核模块 |
| `lib/Makefile FF_KNI=1` | ✅ 默认开启 | ✅ **保留** | F-Stack ring + virtio_user KNI 路径继续工作 |
| F-Stack `lib/ff_dpdk_kni.c` 链接 | 不依赖 librte_kni | 不依赖 | 0 |

→ **结论**：**KNI 在升级中是 0 风险事项**（与 user 提示完全一致）：
- ✅ **保留 `FF_KNI=1`**（F-Stack 自实现的 ring-based KNI 路径继续工作）
- ✅ **dpdk/ 仅保留 igb_uio 一个内核模块**（5f3768c63 重打）；dpdk/lib/kni / dpdk/kernel/linux/kni 自然不进入升级后的 dpdk/（24.11.6 上游本就无 + 29c7d5835 等价 patch 重打保持）
- ❌ **不需要**：A 方案 (FF_KNI=0) 错误；B 方案 (备份 KNI 子树) 错误

**R-D2 等级**：从此前误判的"P1 阻塞"**降级为 N/A**（不存在风险）。Must-Fix-1 KNI 决策 → **取消**。

### 3.7 lib/net `rte_ip.h` 重构陷阱（**实测闭环 R-D11，2026-06-09 14:40**）

```
23.11.5: rte_ip.h = 21.64 KB（含全部 IPv4/IPv6 结构 + helper）
24.11.6: rte_ip.h = 210 B（仅 stub include）
         rte_ip4.h = 10.82 KB（新增；IPv4 内容）
         rte_ip6.h = 21.47 KB（新增；IPv6 内容）
         rte_cksum.h = 3.71 KB（新增；checksum helper 抽离）
```

**F-Stack 实测使用情况**（grep `f-stack/lib/`）：

| 文件 | 引用 |
|---|---|
| `lib/ff_dpdk_if.c:52` | `#include <rte_ip.h>` |
| `lib/ff_dpdk_if.c:2203/2205/2214/2216` | 4 处 `struct rte_ipv4_hdr *iph;` 使用 |
| `lib/ff_dpdk_kni.c:37` | `#include <rte_ip.h>` |
| `lib/ff_dpdk_kni.c:306/309/317/320/321` | 5 处 `struct rte_ipv4_hdr / rte_ipv6_hdr` 使用 |
| `lib/ff_memory.c:50` | `#include <rte_ip.h>` |
| `lib/ff_memory.c:321` | 1 处 `struct rte_ipv4_hdr *iph;` 使用 |
| **总计** | **3 处 include + 10 处 struct 使用** |

→ **实测结论**：F-Stack 仅 include `<rte_ip.h>` 不显式 include `<rte_ip4.h>` / `<rte_ip6.h>`。24.11.6 中 `rte_ip.h` 是 stub include（210 B），它**应自动 include rte_ip4.h + rte_ip6.h**，所以 `struct rte_ipv4_hdr / rte_ipv6_hdr` 应仍可见。

**M4 编译期必须验证**（不阻塞 spec）：如 stub 没有 forwarding `#include "rte_ip4.h"`（极小概率），需补 include；如有 forwarding 则零工作量。M4 编译错误时 1-2 行最小 patch 解决。

### 3.8 构建工具链版本要求（**实测闭环 DP-B5，2026-06-09 14:40**）

| 工具 | 23.11.5 最低 | 24.11.6 最低 | 实测命令 |
|---|---|---|---|
| meson | `>= 0.53.2` | **`>= 0.57`**（升级）| `head -20 dpdk-stable-{23,24}.11.{5,6}/meson.build` |
| ninja | 任意现代 | 任意现代 | — |
| GCC | 一般 4.9+ | 一般 7+（待 sys_reqs.rst 复查）| — |
| Python | 3.6+ | 3.6+ | — |

**当前 CVM 工具链**：通常 meson 1.x（远超 0.57），gcc 11+ — 满足 24.11.6 要求。**若实测发现 meson < 0.57，M2 启动前必须 `pip install -U meson`**。

---

## 4. F-Stack 在 dpdk/ 之外的 DPDK 依赖（patch-scout Q7）

| 路径 | DPDK 引用形式 | 升级影响 |
|---|---|---|
| `f-stack/lib/Makefile` | `DPDK_HOME ?= ../dpdk` + `PKG_CONFIG_PATH = ${DPDK_HOME}/build/meson-uninstalled` | **是** — 整树替换后 build/ 重新生成，PKG_CONFIG_PATH 路径不变 |
| `f-stack/example/Makefile` | 同上 | 同上 |
| `f-stack/app/nginx-1.28.0/auto/feature/` | 用 `pkg-config --libs libdpdk` 探测 | 同上 |
| `f-stack/tools/sbin/Makefile` | secondary IPC 工具，依赖 libfstack.a → DPDK static lib | 间接依赖 |

→ **结论**：F-Stack 在 dpdk/ 之外的 DPDK 依赖**仅限 Makefile 路径**（`../dpdk` + `build/`），整树替换不影响这些 Makefile，无需调整。

---

## 5. 现状总结（一图概括）

```
                      F-Stack (feature/1.26)
                            ▼
              ┌─────────────────────────────────┐
              │  f-stack/lib/ff_dpdk_*.c        │ ← 4 文件胶水层
              │  + ff_memory.c                  │   调用 rte_* 公开 API
              └────────────┬────────────────────┘
                           ▼ #include <rte_*.h>
              ┌─────────────────────────────────┐
              │  f-stack/dpdk/  =  23.11.5      │ ← 整树 = upstream 23.11.5
              │  (整树镜像 + 3 个本地 patch)     │   - 4 dotfile + build/
              │  ├── lib/ (57)                   │
              │  ├── kernel/linux/ ← 5f3768c63  │   F-Stack 自带 igb_uio
              │  ├── lib/timer/   ← 62f1c34df   │   rte_timer_meta_init()
              │  ├── lib/eal/linux/ ← 92718178b │   eal_bus_cleanup PRIMARY 守护
              │  ├── lib/eal/freebsd/ ← 5f3768c63│   FreeBSD 13.1+ CPU_AND/CPU_OR
              │  └── ...                         │
              └─────────────────────────────────┘

升级后：
              ┌─────────────────────────────────┐
              │  f-stack/dpdk/  =  24.11.6      │ ← 整树 = upstream 24.11.6
              │  + 3 patch rebase 重打           │   - 4 dotfile + 重新 build/
              │  ├── lib/ (59 = 57 + argparse + ptr_compress) │ 0 引用
              │  ├── kernel/linux/ ← 5f3768c63 重打 (igb_uio 子树添加)│
              │  ├── lib/timer/   ← 62f1c34df 重打 (cherry-pick)│
              │  ├── lib/eal/linux/ ← 92718178b 重打 (rebase 配合 24 新调用顺序)│
              │  ├── lib/eal/freebsd/ ← 5f3768c63 重打 (FreeBSD 13.1+)│
              │  └── ...                         │
              └─────────────────────────────────┘
```

---

## 6. 文档元信息

- **状态**：v0.1 DRAFT — 待 gate-keeper 评审
- **遗留待阶段二实测**：DP-B2（KNI 状态）+ DP-B5 部分（meson 最低版本）+ R-D11（rte_ip.h 是否需补 include）
- **下一步**：阅读 `04-port-and-impl.md` 了解整树替换 + 3 patch 重打的详细实施计划
