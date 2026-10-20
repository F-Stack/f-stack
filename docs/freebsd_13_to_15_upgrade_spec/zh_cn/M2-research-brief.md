# M2 启动调研 Brief（M2-research-brief）

> English version: ../M2-research-brief.md

> 系列文档：`/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/`
> 文档版本：v0.1（2026-05-29）
> 适用：M2 里程碑（kern + DP-7/DP-8/DP-9 推迟项重做）开工前内外调研产出
> 工作纪律：所有数字必须基于 `diff -rq` / `cmp` / `grep` / `find` 实测命令产出
> 模板：对标 M1-research-brief.md 10 章节
> 决策点输入：M2 4 决策点（DP-M2-1=D / DP-M2-2=C / DP-M2-3=A / DP-M2-4=B）已用户确认

---

## 1. sys/sys 全 339 DIFFER 风险图谱（DP-9-A 重做范围）

### 1.1 13 → 15 NEW/DEL/DIFFER 全量统计（实测）

| 类型 | 数量 | 说明 |
|---|---|---|
| DEL（13.0-only）| **4** | `_cscan_atomic.h` / `_cscan_bus.h` / `disk/vtoc.h` / `vtoc.h` —— 全部冷僻硬件头，**非 F-Stack 范围**，删除安全 |
| NEW（15.0-only）| **38** | 含关键阻塞头：`kassert.h`（M1 G-M1 编译失败根因）/ `stdarg.h`（14.0 引入）/ `_maxphys.h` / `inotify.h` / `membarrier.h` / `timerfd.h` / `umtxvar.h` / `bitcount.h` / `boottrace.h` / `ctf.h` / `efi_map.h` / `_endian.h` / `_param.h` / `queue_mergesort.h` / `reg.h` / 等 |
| DIFFER | **339** | 含 14 个 F-Stack 改造文件（必须 5 步法）+ 325 个无改造文件（cp -f 即可）|

### 1.2 14 个 sys/sys F-Stack 改造文件（delta-13 / 上游 13→15 实测）

| # | 文件 | delta-13 | 上游 13→15 | spec 是否原列 |
|---|---|---|---|---|
| 1 | `systm.h` | 6 行 | 536 行 | ✅ T-sys-01（M1 已 5 步法） |
| 2 | `refcount.h` | 9 行 | 46 行 | ✅ T-sys-02（M1 已 5 步法） |
| 3 | `callout.h` | 10 行 | 67 行 | ✅ T-sys-03（M1 已 5 步法） |
| 4 | `_callout.h` | 3 行 | 29 行 | ✅ T-sys-03（M1 已 5 步法） |
| 5 | `cdefs.h` | 4 行 | **802 行** | ❌ M1 漏列（M2 新增 T-sys-04） |
| 6 | `counter.h` | 2 行 | 40 行 | ❌ M1 漏列 |
| 7 | `filedesc.h` | 1 行 | 238 行 | ❌ M1 漏列 |
| 8 | `malloc.h` | 2 行 | 113 行 | ❌ M1 漏列 |
| 9 | `namei.h` | 2 行 | 288 行 | ❌ M1 漏列 |
| 10 | `random.h` | 6 行 | 82 行 | ❌ M1 漏列 |
| 11 | `resourcevar.h` | 2 行 | 79 行 | ❌ M1 漏列 |
| 12 | `socketvar.h` | 3 行 | 463 行 | ❌ M1 漏列 |
| 13 | `stdatomic.h` | 7 行 | 50 行 | ❌ M1 漏列 |
| 14 | `user.h` | 2 行 | 308 行 | ❌ M1 漏列 |
| **合计** | | **59 行** | 3137 行 | spec 漏列 10/14 = 71%！|

### 1.3 风险评估

| 风险点 | 等级 | 缓解 |
|---|---|---|
| spec 05 §2.1 漏列 71% sys/sys 改造文件 | 高 | 已在 M1 G-M1 编译时被 G-M1 严格门禁捕获并触发 DP-9 推迟；M2 在 99 §12.13+ 修订 spec |
| 上游 cdefs.h 802 行变化（含 NLEN，C2x 支持等） | 中 | delta-13 仅 4 行，5 步法可行 |
| 14 改造文件都是 .h 头，对依赖链影响广 | 高 | DP-M2-1=D 三细分：先 14 改造 → 38 NEW → 325 DIFFER；细粒度交付便于回滚 |

---

## 2. vm/uma 风险评估（DP-7 重做范围）

### 2.1 vm/ 13 → 15 实测

| 类型 | 数量 | 详情 |
|---|---|---|
| DEL | 2 | `default_pager.c`（14.0 删，pager 子系统重构）/ `vm_swapout_dummy.c`（14.0 删） |
| NEW | 1 | `uma_align_mask.h`（uma 内部抽出新头）|
| DIFFER | 51 | 含 vm_extern.h / vm_page.h（M1 G-M1 编译时引用 sys/kassert.h 缺失）|

### 2.2 F-Stack vm 改造文件（仅 2 个，与 M1 实测一致）

| 文件 | delta-13 | 上游 13→15 | F-Stack 改造内容 |
|---|---|---|---|
| `uma_core.c` | 158 行 | **1868 行**（vm/uma 子系统大改） | 7 处 `#ifndef FSTACK` 包裹（M1 brief §2.5 详列）：noobj_alloc 声明 / startup_alloc 函数体 / pcpu_page_alloc + 同伴 4 函数 + F-Stack stub / pcpu_page_free + F-Stack stub / vm_radix_reserve_kva extern / uma_startup2 if 块 / uma_zone_reserve_kva 函数体 / sysctl pragma |
| `uma_int.h` | （归 8 块统计的第 8 块） | （含上游 13→15 变化）| 1 处 F-Stack 改造（M1 brief §2.5 实测）|

### 2.3 关键利好：F-Stack 改造的 8 个核心符号在 15.0 中**全部存在且数量不变**

实测 `grep -c '\b<sym>\b' 13.0/uma_core.c vs 15.0/uma_core.c`：

| 符号 | 13.0 | 15.0 | 状态 |
|---|---|---|---|
| `noobj_alloc` | 5 | 5 | ✅ 存在 |
| `pcpu_page_alloc` | 4 | 4 | ✅ 存在 |
| `pcpu_page_free` | 3 | 3 | ✅ 存在 |
| `contig_alloc` | 4 | 4 | ✅ 存在 |
| `startup_alloc` | 6 | 6 | ✅ 存在 |
| `vm_radix_reserve_kva` | 2 | 2 | ✅ 存在 |
| `uma_zone_reserve_kva` | 1 | 1 | ✅ 存在 |
| `uma_startup2` | 2 | 2 | ✅ 存在 |

**结论**：尽管 vm/uma 子系统上游变化 1868 行（含 SLAB→FB 优化、batch alloc 重构等），F-Stack 改造的所有锚点符号 100% 保留 → **5 步法迁移可行性高**。

---

## 3. arch（amd64/x86/arm64）风险评估（DP-8 重做范围）

### 3.1 13 → 15 NEW/DEL/DIFFER 实测（修订 M1 估算）

| arch | DEL | NEW | DIFFER | 总变化 | M1 估算 |
|---|---|---|---|---|---|
| amd64 | 17 | 24 | 238 | **279** | M1 估 255 |
| x86 | 9 | 29 | 116 | **154** | M1 估 125 |
| arm64 | 20 | 98 | 248 | **366** | M1 估 286 |
| **合计** | 46 | 151 | 602 | **799** | M1 估 666 |

> spec 偏差：M1 brief §3 实测的 666 文件是 DIFFER+NEW 估算，实际 NEW+DEL+DIFFER = 799。需在 99 §12.15 修订。

### 3.2 5 个 F-Stack arch 改造文件（delta-13 极简）

| # | 文件 | delta-13 | 上游 13→15 |
|---|---|---|---|
| 1 | `amd64/include/atomic.h` | 27 行 | 299 行 |
| 2 | `amd64/include/pcpu_aux.h` | 4 行 | 40 行 |
| 3 | `amd64/include/pcpu.h` | 2 行 | 288 行 |
| 4 | `amd64/include/vmparam.h` | 2 行 | 219 行 |
| 5 | `arm64/include/pcpu.h` | 3 行 | 67 行 |
| **合计** | | **38 行** | 913 行 |

### 3.3 arm64 NEW=98 大量新增子目录扫描

15.0 新增 arm64 文件：`apple/` 子目录（M2 SoC 支持）、`cmn600.c` / `cmn600_acpi.c` / `cmn600_fdt.c`（CoreLink CMN 600 mesh interconnect）、`ptrauth.c` / `hyp_stub.S`（pointer authentication / hypervisor stub）等。**F-Stack 不引入这些新驱动**，cp 到位但不在 lib/Makefile 里编译。

---

## 4. kern/ + ff_kern_* 改造盘点（spec 原 M2 范围）

### 4.1 F-Stack kern 改造文件实测（17 个，spec 列了 15 个 + misc）

| # | 文件 | spec 是否列出 | F-Stack 改造内容 |
|---|---|---|---|
| 1 | `kern_descrip.c` | T-kern-01 P0 | refcount API 适配 |
| 2 | `kern_event.c` | T-kern-02 P0 | kqueue stub |
| 3 | `kern_linker.c` | T-kern-03 P1 | va_size 0 视成功 |
| 4 | **`kern_mbuf.c`** | **T-kern-04 P0** | **m_ext 新字段适配（R-003）** |
| 5 | `kern_sysctl.c` | T-kern-05 P1 | __sysctl 屏蔽 |
| 6 | **`kern_tc.c`** | **❌ M2 漏列（spec 偏差）** | delta-13 仅 7 行 / 上游 659 行 |
| 7 | **`kern_uuid.c`** | **❌ M2 漏列（spec 偏差）** | delta-13 仅 2 行 / 上游 24 行 |
| 8 | `link_elf.c` | T-kern-06 P1 | elf stub |
| 9 | **`subr_epoch.c`** | **T-kern-07 P0** | **epoch → SMR 评估（R-012）** |
| 10 | `subr_param.c` | T-kern-08 P2 | ticks wrap 屏蔽 |
| 11 | `subr_taskqueue.c` | T-kern-09 P1 | taskqueue stub |
| 12 | `sys_generic.c` | T-kern-10 P1 | kern_sigprocmask 屏蔽 |
| 13 | `sys_socket.c` | T-kern-11 P1 | soo_* 屏蔽 |
| 14 | **`uipc_mbuf.c`** | **T-kern-12 P0** | **FSTACK_ZC_SEND + m_ext 新布局** |
| 15 | `uipc_sockbuf.c` | T-kern-13 P1 | sb_aio 屏蔽 |
| 16 | **`uipc_socket.c`** | **T-kern-14 P0** | **pr_usrreqs 合并（R-011）** |
| 17 | `uipc_syscalls.c` | T-kern-15 P1 | sendit/recvit 外部化 |

### 4.2 4 P0 改造文件 delta-13 vs 上游 13→15

| 任务 | 文件 | delta-13 | 上游 13→15 | 5 步法可行性 |
|---|---|---|---|---|
| T-kern-04 | `kern_mbuf.c` | **16 行** | 770 行 | ✅ 改造极简 / 上游中等 |
| T-kern-07 | `subr_epoch.c` | **2 行** | 183 行 | ✅ 改造极简 / 上游小 |
| T-kern-12 | `uipc_mbuf.c` | **29 行** | 821 行 | ⚠️ 改造稍大 / 上游中等 |
| T-kern-14 | `uipc_socket.c` | **2 行** | **3883 行** | ⚠️ 改造极简 / 上游极大（需细致定位锚点）|

### 4.3 lib/Makefile KERN_SRCS 实测（37 个，spec 列了 38）

| 实测 | 与 spec 偏差 |
|---|---|
| 37 个 | spec 05 §2.2 列 "38 KERN_SRCS"，实测漏列 `subr_smr.c` / `subr_filter.c` 已在 13.0 base 中（前者是 SMR 接管前体），新增情况需在 99 §12.16 修订 |

### 4.4 ff_kern_* 文件实测

| 文件 | M2 任务 |
|---|---|
| `ff_subr_epoch.c` | T-ff-04 P0（配合 T-kern-07 SMR）|
| `ff_syscall_wrapper.c` | T-ff-05 P1（配合 T-kern-15）|
| `ff_kern_intr.c` | T-ff-06 P1（ithd 微调）|
| `ff_kern_condvar.c` | T-ff-misc P2 |
| `ff_kern_environment.c` | T-ff-misc P2 |
| `ff_kern_subr.c` | T-ff-misc P2 |
| `ff_kern_synch.c` | T-ff-misc P2 |
| `ff_kern_timeout.c` | T-ff-misc P2 |

8 个 ff_kern_* 全部就位（与 spec 一致）。

---

## 5. netinet/libalias 风险评估（DP-9-B 重做范围）

| 项 | 实测 | 备注 |
|---|---|---|
| 文件数 | 19（13.0）/ 应改为 20（15.0 + alias_db.h NEW）| |
| F-Stack 改造 | 1（`alias_sctp.h`，1 处 `#if INET6 && !FSTACK`） | M1 brief §10 已识别 |
| 上游 14.0+ 引入新依赖 | `__tcp_get_flags / tcp_set_flags / TH_RES1 / sys/stdarg.h` | 当 sys/sys 升级后即可解锁（M1 G-M1 失败的间接根因，DP-9-B 等待 sys/sys 完成）|

---

## 6. 编译依赖图（M2 7 Phase 顺序的依据）

```
[Phase 1] sys/sys (kassert.h / stdarg.h / inotify.h ... ↓ 38 NEW + 325 DIFFER 解锁)
    ↓
[Phase 2] vm/ (vm_extern.h / vm_page.h #include sys/kassert.h ↑ 已就绪)
    ↓
[Phase 3] arch (头文件不直接 include vm/，但部分 amd64/include 引用 vm 类型)
    ↓
[Phase 4] netinet/libalias (alias.c / alias_db.c #include sys/stdarg.h + __tcp_get_flags ↑ 已就绪)
    ↓
[Phase 5] kern/ (kern_mbuf.c / uipc_mbuf.c #include vm/uma.h + sys/sys/* ↑ 已就绪)
    ↓
[Phase 6] ff_kern_*.c + ff_subr_epoch.c (#include kern/* + vm/* + sys/sys/* ↑ 全就绪)
    ↓
[Phase 7] G-M2 编译验收
```

**结论**：DP-M2-1 选项 D 的执行顺序在编译依赖图上完全正确。

---

## 7. f-stack-lib (15.0 baseline) 覆盖性 verify（M2 范围）

实测 `find -type f` 文件数对比（M2 范围 7 子目录）：

| 子目录 | f-stack-lib | 15.0/sys | 状态 |
|---|---|---|---|
| sys | 377 | 377 | ✅ MATCH |
| vm | 52 | 52 | ✅ MATCH |
| amd64 | 263 | 263 | ✅ MATCH |
| x86 | 145 | 145 | ✅ MATCH |
| arm64 | 378 | 378 | ✅ MATCH |
| kern | 249 | 249 | ✅ MATCH |
| netinet | 193 | 193 | ✅ MATCH |
| **合计** | **1657** | **1657** | ✅ 100% MATCH |

> M1 已为整个 M2 范围铺好 15.0 baseline 备份，**M2 verify-only 任务可直接 PASS**，无需补全 INVENTORY.md §8。

---

## 8. F-Stack 社区 / 外部资料调研

### 8.1 web_search 结果（2026-05-29）

| 检索 | 命中 | 价值 |
|---|---|---|
| `FreeBSD 14 epoch SMR replacement inpcb hash lookup migration commit` | `git: de2d47842e88 - main - SMR protection for inpcbs`（2021-12 进入 main，14.0 主线）+ `git: 041e9eb1ae09 - main - inpcb: overhaul in_pcb.h` | 提供 SMR 接管 epoch 的关键 commit 引用，T-kern-07 / T-ff-04 改造手法迁移可借此交叉验证 |
| `FreeBSD 14 m_ext mbuf structure layout changes refcnt ext_type` | mbuf(9) FreeBSD/OpenBSD 手册页 | 手册级别无 m_ext 大改记录；M2 实施时直接以 diff -u 实测为准 |
| `F-Stack FreeBSD 14 upgrade compatibility github issue` | F-Stack 官网（仍标 FreeBSD 11.0 stable）；无 13→14 升级先例 | F-Stack 13→15 是社区"无人区"工作；spec 系列是当前唯一指导 |

### 8.2 RAG_search 与既有文档参考

- 沿用 M1 已建立的 RAG_search 结论（公私统一 KB / 腾讯编程指南 KB 均未发现 F-Stack 项目相关内容）
- 内部 spec：03-freebsd-15-changes.md / 04-diff-and-port-strategy.md / 02-architecture-analysis.md（9 大改造手法）作为本次 M2 5 步法 SOP 的输入

---

## 9. spec 偏差汇总（M2 启动时实测发现，待 99 §12.13+ 修订）

| ID | spec 错处 | 实测真值 | 影响 |
|---|---|---|---|
| §12.13 | spec 05 §2.1 仅列 4 个 sys/sys 改造文件 | 实测 14 个改造（漏列 cdefs.h/counter.h/filedesc.h/malloc.h/namei.h/random.h/resourcevar.h/socketvar.h/stdatomic.h/user.h 共 10 个）| M2 范围必须包含 14 个 5 步法 SOP |
| §12.14 | spec 05 §2.2 M2 范围"38 KERN_SRCS"未含 DP-7/DP-8/DP-9 推迟项 | M2 实质范围扩展约 1500+ 文件 | 需在 99 §12.14 显式声明 M2 范围扩展 |
| §12.15 | spec 05 §2.1 T-arch-02 估"~7 NEW" | 实测 amd64 (17+24+238)=279 + x86 (9+29+116)=154 + arm64 (20+98+248)=366 = **799** | 文件数估算严重偏低 |
| §12.16 | spec 05 §2.2 列 "38 KERN_SRCS" | 实测 lib/Makefile KERN_SRCS+= = **37 个**（含 subr_smr.c 等 13.0→15 新增）| 数字差 1 |
| §12.17 | spec 漏列 kern_tc.c / kern_uuid.c F-Stack 改造 | 实测 17 个 kern 改造（spec 列 15 + misc）| 需补 T-kern-extra-1/2 |

---

## 10. M2 任务建议（基于 DP-M2-1=D 决策）

### 10.1 Phase 1 三细分（DP-M2-1=D）

```
Phase 1A: sys/sys 14 改造 5 步法 SOP（按 delta-13 由小到大顺序）
  filedesc.h(1) → counter.h/malloc.h/namei.h/resourcevar.h/user.h(2) → socketvar.h(3)
  → cdefs.h/_callout.h(3-4) → systm.h/random.h(6) → stdatomic.h/refcount.h(7-9)
  → callout.h(10)
Phase 1B: sys/sys 38 NEW 文件 cp（关键 kassert.h / stdarg.h 等）
Phase 1C: sys/sys 325 DIFFER 文件 cp（仅同步，无改造）+ 4 个 13.0-only 用 rm_tmp_file.sh 删除
  确认每个 13.0-only 不在 F-Stack 引用范围（grep -rln "_cscan_atomic\|_cscan_bus\|vtoc"）
```

### 10.2 Phase 2-6 维持 plan.md 顺序

按 plan.md 已定 7 Phase 拓扑执行，每个 Phase 完成后做 `read_lints + 单文件编译尝试` 局部 Gate。

### 10.3 G-M2 验收（DP-M2-2=C 折中）

按 plan.md 已定流程：先严格 libfstack.a 完整 make → 失败时记录 root cause（必须证明仅来自 net/netinet 未升级）→ 降级 soft gate（kern + ff_kern_* 单文件编译 + diff -rq + read_lints）。

### 10.4 DP-M2-4=B 最小连锁补丁的应用边界

允许的连锁补丁场景：
- ✅ Phase 1 完成后，net/ + netinet/ 中的某个 13.0 文件 #include 引用了 sys/sys 已升级的新接口（如 `__tcp_get_flags`）。**1-2 个文件级**的 cp -f 补丁，必须显式记录到 execution-log §4 打回事件表
- ❌ 重做改造手法 / 大量补丁（>3 个文件）/ 跨子目录连锁补丁——这些必须升级为新决策点交用户确认

---

## 11. 调研结论与 M2 启动确认

| 维度 | 结论 |
|---|---|
| sys/sys 14 改造文件 | 全部锁定，delta-13 极简（59 行总），5 步法可行 ✅ |
| vm/uma 改造 | 8 个核心符号 100% 保留，5 步法可行 ✅ |
| arch 5 改造 | delta-13 极简（38 行总），5 步法可行 ✅ |
| kern 17 改造 | 4 P0 delta-13 都很小，5 步法可行；spec 漏列 2 个待补 ✅ |
| netinet/libalias 1 改造 | 极简，等待 sys/sys 完成解锁依赖 ✅ |
| 15.0 baseline 备份 | M2 范围 100% 覆盖（1657/1657 MATCH），无需补全 ✅ |
| 外部社区 | F-Stack 13→15 无先例，spec 系列是唯一指导 ⚠️ |
| spec 偏差 | 已识别 5 处（§12.13-§12.17 待修订）⚠️ |

**M2 启动建议**：可立即进入 Phase 1A（sys/sys 14 改造 5 步法 SOP）。
