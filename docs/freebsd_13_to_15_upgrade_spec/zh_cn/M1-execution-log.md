# M1 — 执行日志（Execution Log）

> English version: ../M1-execution-log.md

> 系列文档：`/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/`
> 文档版本：v0.1（2026-05-28，M1 启动）
> 维护人：Leader（m1-leader，主对话内）
> 关联：spec `05-implementation-plan.md` §2.1（M1 任务清单）、§4（5 步法 SOP）、§7（Gate 失败处理）；`06-test-and-acceptance-spec.md` §2.2 G-M1；`99-review-report.md` §6（任务追踪表）

---

## 0. 启动元信息

| 项 | 内容 |
|---|---|
| M1 启动时间 | 2026-05-28 |
| 升级范围 | F-Stack `freebsd/` 子树从 FreeBSD-13.0 升级到 FreeBSD-15.0 第一阶段（基础设施 + 头文件 + mips 清理） |
| Spec 基线 | `f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/` v0.3（commit `1aa558c2a`，已 ✅ 评审通过） |
| 工作区 git HEAD（启动时） | `1aa558c2a docs(spec): mark zh_cn/ spec series as APPROVED (v0.3)`，git status clean |
| 整体备份 | `/data/workspace/f-stack-13.0-baseline/`（M1 启动前 cp -a 一次性整体备份；2026-05-28 16:58 完成） |
| 里程碑备份 | `/data/workspace/f-stack-M1-done/`（M1 末结案时 cp -a） |
| 13.0 baseline | `/data/workspace/freebsd-src-releng-13.0/`（社区版只读基线） |
| 15.0 baseline | `/data/workspace/freebsd-src-releng-15.0/`（社区版只读基线） |
| 15.0 f-stack-lib 原始备份 | `/data/workspace/freebsd-src-releng-15.0/f-stack-lib/`（Phase 1.4 + 99 §12.12 已建立；本里程碑做 verify-only） |

### 0.1 启动时实测数据（基线锁定）

| 实测项 | 数值 | 命令 |
|---|---:|---|
| `f-stack/freebsd/` 总文件数 | 18 021 | `find freebsd -type f \| wc -l` |
| `f-stack/freebsd/mips/` 文件数（待删） | 586 | `find freebsd/mips -type f \| wc -l` |
| `f-stack/freebsd/libkern/` | 86 | `find freebsd/libkern -type f \| wc -l` |
| `f-stack/freebsd/opencrypto/` | 36 | 同上 |
| `f-stack/freebsd/crypto/` | 192 | 同上 |
| `f-stack/freebsd/vm/` | 53 | 同上 |
| `f-stack/freebsd/amd64/` | 255 | 同上 |
| `f-stack/freebsd/x86/` | 125 | 同上 |
| `f-stack/freebsd/arm64/` | 286 | 同上 |
| `f-stack/freebsd/netipsec/` | 30 | 同上 |
| `f-stack/freebsd/netgraph/` | 175 | 同上 |
| `f-stack/freebsd/netinet/libalias/` | 19 | 同上 |
| `15.0/f-stack-lib/tools/compat/include/` | 172 | 同上（Phase 1.4 + 99 §12.12） |
| `15.0/f-stack-lib/freebsd/` | 24 593 | 同上（Phase 1.4） |

---

## 1. Agent Team 拓扑（5 角色）

| 角色 | Agent 名 | 实现 | 职责 |
|---|---|---|---|
| Leader | `m1-leader` | 主对话内执行（不 spawn） | 总体统筹；按任务表拾取 T-*；处理打回事件；维护本日志；G-M1 实测决策；与用户同步 |
| Sub-agent A | `m1-analyzer` | `Task` 工具 + `code-explorer` subagent | M1 启动前一次性内外调研：RAG / web_search / 实测 13.0/15.0 baseline；产出 `M1-research-brief.md` |
| Sub-agent B | `m1-coder` | `Task` 工具 + `code-explorer` subagent + `c-precision-surgery` skill（P0/sys 头文件）| 按 spec 05 §4 五步法 SOP 执行 11 个 T-* |
| Sub-agent C | `m1-reviewer` | `Task` 工具 + `code-explorer` subagent + `spec-driven` skill（回写 99 §6）| 按 spec 05 §4 Step 4 + 99 §6 标准审查；不通过即打回 Coder |
| Sub-agent D | `m1-gate` | `Task` 工具 + `code-explorer` subagent | M1 末集中阶段门禁：find / grep / diff -rq / read_lints / 编译尝试 |

**打回链**：`Gate-Keeper 失败 → Reviewer → Coder → 必要时回到 Analyzer 重做调研`。每次打回必须在本日志 §3 事件表追加一行。

---

## 2. 关键决策（已与用户对齐）

| DP | 决策内容 | 决定（用户对齐） |
|---|---|---|
| DP-M1-1 | Team Topology | 标准版 5 角色（与 spec 05 §5 资源表对齐） |
| DP-M1-2 | G-M1 编译门禁严格度 | **先严后宽**：先尝试完整 libff.a 编译（严格 G-M1）；失败时 Leader 在本日志记录 root cause（必须证明仅来自 kern/net/netinet 未升级，而非 M1 改动），降级 soft gate（lint + diff -rq + 单文件编译） |
| DP-M1-3 | 外部调研策略 | M1 启动前由 Analyzer 集中调研一次，产出 `M1-research-brief.md` 后再开工 |
| DP-M1-4 | 备份与回滚粒度 | **两层**：M1 启动前 cp -a 整体备份 → `f-stack-13.0-baseline`；M1 末 cp -a 里程碑 tag → `f-stack-M1-done`；单文件不另备份 |

---

## 3. 任务进度时间线

| T-* ID | 任务 | 优先级 | 状态 | 起 | 止 | Reviewer 通过 | Gate 通过 | 备注 |
|---|---|---|---|---|---|---|---|---|
| T-cleanup-01 | mips 整目录删除 + Makefile/mk 清理 | P0 | ✅ done | 2026-05-28 17:08 | 2026-05-28 17:10 | 2026-05-28 17:30 | 待 M1 末 | 留档至 `/data/workspace/f-stack-mips-removed-2026-05/`（586 文件）；删除 `freebsd/mips/`（17435=18021-586）；lib/Makefile 删 15 行、mk/kern.mk 删 7 行、mk/kern.pre.mk 删 7 行 mips 条件 |
| T-sys-01 | `sys/systm.h` 5 步法 SOP | P0 | ⚠️ DP-9 rollback | 2026-05-28 17:13 | 2026-05-28 17:14 | 2026-05-28 17:30 | 2026-05-28 17:55 | cp 15.0 → fstack；施加 3 处 `#ifndef FSTACK` 改造（kpilite include + critical_enter body + critical_exit body）；与 13.0 改造手法等价。**DP-9 回滚**：因 sys/sys/ 整体范围（339 DIFFER）超出 M1 spec 范畴且引发 G-M1 编译失败（refcount.h kassert.h 依赖），整体回滚到 13.0 F-Stack 版本；M2 阶段统一重做 |
| T-sys-02 | `sys/refcount.h` 5 步法 SOP | P0 | ⚠️ DP-9 rollback | 2026-05-28 17:14 | 2026-05-28 17:15 | 2026-05-28 17:30 | 2026-05-28 17:55 | cp 15.0 → fstack；施加 1 处 `#ifdef FSTACK` 注释块（CAS 自检建议）；与 13.0 改造手法等价（13.0 与 15.0 各 1 处）。**DP-9 回滚根因**：15.0 refcount.h:32 `#include <sys/kassert.h>` 而 kassert.h 是 14.0 才引入的新头文件，f-stack 暂未引入，导致 ff_compat.o 编译失败；整体回滚到 13.0 F-Stack 版本 |
| T-sys-03 | `sys/callout.h` + `sys/_callout.h` | P1 | ⚠️ DP-9 rollback | 2026-05-28 17:18 | 2026-05-28 17:21 | 2026-05-28 17:30 | 2026-05-28 17:55 | cp 15.0 → fstack；callout.h 施加 3 处 F-Stack 改造（callout_reset_tick_on 包装 + callout_process→callout_tick）；_callout.h 施加 2 处（c_time 类型 __sbintime_t→int + 删 c_precision）；与 13.0 改造手法等价。**DP-9 回滚**：与 sys/sys 全子目录推迟一并回滚到 13.0 F-Stack 版本；M2 阶段统一重做 |
| T-libkern-01 | libkern/ 全量基于 15.0 cp -a | P1 | ✅ done | 2026-05-28 17:24 | 2026-05-28 17:26 | 2026-05-28 17:30 | 待 M1 末 | 逐文件同步：删 13.0-only 9 文件（bcmp.c/ffs.c/ffsl.c/ffsll.c/fls.c/flsl.c/flsll.c/mcount.c + arm/ffs.S）；cp 15.0 → fstack 80 文件；gsb_crc32.c 施加 5 步法 SOP 改造（ifunc 块加 `&& !defined(FSTACK)` 内联条件，等价于 13.0 的 `#ifndef FSTACK` 包裹）；最终 81 文件 = 上游 |
| T-opencrypto-01 | opencrypto/ 全量基于 15.0 cp -a | P1 | ✅ done | 2026-05-28 17:26 | 2026-05-28 17:27 | 2026-05-28 17:30 | 待 M1 末 | F-Stack 无改造。逐文件同步：删 13.0-only 3 文件（xform.c/xform_poly1305.h/xform_rijndael.c）；cp 15.0 → fstack 36 文件（含新增 ktls.h/xform_aes_cbc.c/xform_chacha20_poly1305.c）；diff -rq=0 |
| T-vm-01 | vm/ 全量基于 15.0 cp -a | P1 | ⚠️ DP-9 rollback | 2026-05-28 17:27 | 2026-05-28 17:28 | 2026-05-28 17:30 | 2026-05-28 17:56 | 初次执行（已撤销）：DP-7 部分推迟模式同步 50 文件 + 保留 uma_core.c/uma_int.h LEGACY；后因 G-M1 编译时发现 `vm/vm_extern.h:42` 与 `vm_page.h` 引用 `<sys/kassert.h>`（DP-9 副作用）整体回滚到 13.0 F-Stack 版本（53 文件 = baseline，diff=0）；M2 阶段统一重做 |
| T-misc-01 | netipsec/ netgraph/ netinet/libalias/ | P2 | ⚠️ partial（libalias rollback）| 2026-05-28 17:46 | 2026-05-28 17:50 | 2026-05-28 17:51 | 2026-05-28 17:58 | netipsec：✅ cp 32 文件 → diff=0；netgraph：✅ cp 156 文件 + 23 LEGACY-13 + LEGACY.md + ng_socket.c 5 步法；alias_sctp.h 5 步法（已在 libalias 回滚中撤销）。**DP-9 回滚 netinet/libalias**：15.0 alias.c/alias_db.c/alias_proxy.c/alias_sctp.c 引用了 14.0+ 才引入的 `__tcp_get_flags` / `tcp_set_flags` / `TH_RES1` / `<sys/stdarg.h>`（13.0 sys/netinet/tcp.h 未提供），整体回滚到 13.0 F-Stack 版本（19 文件 = baseline，diff=0）；M2 阶段随 sys/sys + sys/netinet/tcp.h 升级一并重做 |
| T-crypto-01 | crypto/ 顶层 cp -a + blowfish 删 | P2 | ✅ done | 2026-05-28 17:35 | 2026-05-28 17:40 | 2026-05-28 17:42 | 待 M1 末 | 逐文件同步：cp 15.0 → fstack 共 300 文件（含新增 chacha20_poly1305.{c,h} / curve25519.{c,h} / openssl/{ossl_*, arm_arch.h 顶层迁移} 等）；F-Stack 唯一改造 skein/amd64/skein_block_asm.s（小写命名，内容与 15.0 上游 .S 字节相同）保留；diff -rq 仅 1 项文件名差（.s vs .S）。spec 偏差：crypto/blowfish 在 13/15 sys/crypto 下都不存在（brief §9-2），spec 描述需在 99 §12.13 修订 |
| T-arch-01 | amd64/x86 头文件跟随 15.0 | P2 | ⚠️ 推迟 M2（DP-8） | 2026-05-28 17:42 | 2026-05-28 17:44 | 2026-05-28 17:44 | 待 M1 末 | **决策 DP-8（M1→M2 推迟）**：amd64 255 + x86 125 = 380 文件大量上游变化（含 cloudabi32/cloudabi64 整子树删除、acpica/exec_machdep.c/asan.h 等大量 NEW/DEL），且 F-Stack 4 个 amd64 改造文件（atomic.h/pcpu_aux.h/pcpu.h/vmparam.h）虽 delta-13 仅 14-37 行但需在 15.0 大幅变化的 baseline 上重定位锚点。M1 全保留 13.0 状态不动，M2 阶段 G-M2 编译失败时按需重做。理由：spec 06 §2.2 G-M1 仅要求 libff.a 默认 KNOB（x86_64）链接通过，arch 子目录字节级对齐不在 M1 范围内 |
| T-arch-02 | arm64 头文件跟随 15.0 | P2 | ⚠️ 推迟 M2（DP-8） | 2026-05-28 17:42 | 2026-05-28 17:44 | 2026-05-28 17:44 | 待 M1 末 | **DP-8 同款**：arm64 286 文件大量上游变化（NEW: apple 子目录 / cmn600.c / ptrauth.c / hyp_stub.S / sdt_machdep.c 等；DEL: bzero.S / in_cksum.c / memmove.S 等），1 个 F-Stack 改造文件（include/pcpu.h delta-13 仅 12 行）需配合 amd64 一同 M2 重做。M1 完全保留 13.0 状态 |
| T-misc-01 | netipsec/ netgraph/ netinet/libalias/ | P2 | ⚠️ partial（libalias rollback）| 2026-05-28 17:46 | 2026-05-28 17:50 | 2026-05-28 17:51 | 2026-05-28 17:58 | netipsec：✅ cp 32 文件 → diff=0；netgraph：✅ cp 156 文件 + 23 LEGACY-13 + LEGACY.md + ng_socket.c 5 步法；alias_sctp.h 5 步法（已在 libalias 回滚中撤销）。**DP-9 回滚 netinet/libalias**：15.0 alias.c/alias_db.c/alias_proxy.c/alias_sctp.c 引用了 14.0+ 才引入的 `__tcp_get_flags` / `tcp_set_flags` / `TH_RES1` / `<sys/stdarg.h>`（13.0 sys/netinet/tcp.h 未提供），整体回滚到 13.0 F-Stack 版本（19 文件 = baseline，diff=0）；M2 阶段随 sys/sys + sys/netinet/tcp.h 升级一并重做 |

---

> 旧表项已被以上覆盖（保留备份说明：M1 期间 4 个 sys 头 + vm/ + netinet/libalias/ 因 DP-9 决策回滚到 13.0；其余子目录保留 15.0 升级状态）

**图例**：⏸ pending / 🔄 in_progress / ✅ done / ❌ blocked / 🔁 sent-back

---

## 4. 打回事件表

> 任一阶段（Coder/Reviewer/Gate-Keeper）发现问题需 send_message 打回上一阶段时，在此追加一行。

| # | 时间 | 触发任务 | 触发角色 | 打回到 | Root cause（实测证据） | 处置 | 闭合时间 |
|---|---|---|---|---|---|---|---|
| 1 | 2026-05-28 17:00 | m1-research | m1-analyzer | Leader | 子代理工具配给不足：仅 4 个只读工具（search_file / search_content / read_file / read_lints），缺 `write_to_file` / bash 执行 / `web_search` / `RAG_search`，无法满足本任务对实测命令产出（diff -rq / grep / cmp）和外部引用（FreeBSD release notes / RAG）的硬约束。子代理按工作纪律"立即返回阶段性结果说明阻塞点"上报，未启动可能产出"猜测内容"的工作。 | Leader 接管：在主对话内同步执行调研（具备完整工具集），按 brief 模板 10 章节产出 `M1-research-brief.md`（v0.1，0 lint）；后续 M1 任务直接由 Leader 主对话内同步执行（不再依赖 spawn 子代理）；spec 风险升级为"团队拓扑实战调整"——5 角色保留为概念分工，物理上由 Leader 一人承担。 | 2026-05-28 17:30 |
| 2 | 2026-05-28 17:24 | T-libkern-01 / T-vm-01 等 P1 批次 | Leader (兼 Reviewer) | Coder (Leader 自身) | 用户在 P1 批次首条批量命令时拒绝执行（理由推断：(a) `rm -rf 整目录` 风险偏激进；(b) "备份改造文件→cp 整目录→恢复"模式跳过了 spec 05 §4 的 5 步法 SOP（Step 2 应该 **算出 delta-13 在 15.0 baseline 上重应用**，而不是把 13.0 上的 F-Stack 文件原样覆盖到 15.0），违反\"严禁猜测、对每个改造文件做 5 步法\"原则）。 | Leader 重新规划为**选项 A 逐文件 5 步法 + 逐文件 cp -f 同步**：(a) 对每个 F-Stack 改造文件单独执行 5 步法（gsb_crc32.c / uma_core.c / uma_int.h 等）；(b) 其他无改造文件用 `cp -f 来源 目标` 而非 `rm -rf 目录 + cp -a`；(c) 13.0-only 文件单独 `rm -f`；(d) 全程依赖 `f-stack-13.0-baseline` 兜底。已就 T-libkern-01 / T-opencrypto-01 / T-vm-01 完成验证。 | 2026-05-28 17:28 |
| 3 | 2026-05-28 17:54 | G-M1 编译验收（Gate-5b 严格模式） | Gate-Keeper（Leader 自身） | Coder→Analyzer 双向 | G-M1 严格 libfstack.a 编译命中 4 个跨范围依赖失败：(1) `sys/refcount.h:32 #include <sys/kassert.h>` —— sys/kassert.h 是 14.0 引入新头，f-stack 未引入；(2) `vm/vm_extern.h:42 #include <sys/kassert.h>` —— 同款依赖；(3) `netinet/libalias/alias.c:1076 __tcp_get_flags` —— 14.0+ 引入的 inline accessor，13.0 sys/netinet/tcp.h 未提供；(4) `netinet/libalias/alias_db.c:37 #include <sys/stdarg.h>` —— 14.0 引入新头。Root cause：spec 05 §2.1 漏列了 sys/sys/ 整子目录范围（NEW 38 / DEL 4 / DIFFER 339），仅声明 4 个改造头文件；M1 实测发现 F-Stack 在 sys/sys/ 共 14 个改造文件（10 个漏列：cdefs.h/counter.h/filedesc.h/malloc.h/namei.h/random.h/resourcevar.h/socketvar.h/stdatomic.h/user.h）。M1 范围内任何升级 sys 头/vm/libalias 的局部动作都会跨子目录引发新依赖断裂。 | 用户决策 DP-9 选项 A：sys/sys/ 全量推迟到 M2；T-sys-01/02/03 共 4 头文件 + T-vm-01 整 vm/ + T-misc-01 中 netinet/libalias/ 全部回滚到 13.0 F-Stack 版本（用 `rm_tmp_file.sh` 留档删除→cp -a baseline 恢复）。回滚后 G-M1 严格编译 ✅ PASS，libfstack.a 4.7M 完整生成。M1 范围实质收窄为：mips 删除 + libkern + opencrypto + crypto + netipsec + netgraph 共 6 个子目录的全量 15.0 同步；sys 头 / vm / libalias / amd64-x86-arm64 全部移到 M2。 | 2026-05-28 18:04 |

---

## 5. Gate 决策记录

> M1 末由 Gate-Keeper 执行 G-M1，所有 5 项硬验收（find mips / grep Makefile mips / diff -rq / read_lints / libff.a 编译）的实测结果与决策（严格通过 / 降级 soft gate）记录于此。

### 5.1 M1 期间产生的额外决策点

| ID | 时间 | 决策 | 触发任务 | 决策内容 | 影响 |
|---|---|---|---|---|---|
| DP-7 | 2026-05-28 17:28 | M1→M2 推迟（uma 部分） | T-vm-01 | uma_core.c (51 行 delta-13 / 1868 行上游 13→15 大改、与 vm 子系统重写紧密耦合) + uma_int.h 暂保留 13.0 F-Stack 版本（标 LEGACY-13.0），M2 阶段 G-M2 编译前再做 5 步法重做 | T-vm-01 当前状态 ⚠️ partial；M2 范围隐式扩展（spec 05 §2.2 M2 本就含 vm/uma 升级，不破坏 spec 边界）；M1 G-M1 编译验收对 uma_*.{c,h} 的检查需调整为"以 13.0 LEGACY 兼容性为准"，不再要求 15.0 baseline 字节一致 |
| DP-8 | 2026-05-28 17:44 | M1→M2 推迟（arch 全量） | T-arch-01 / T-arch-02 | amd64/x86/arm64 三子目录共 666 文件全量保留 13.0 状态不动；5 个 F-Stack 改造文件（amd64/include/atomic.h, pcpu_aux.h, pcpu.h, vmparam.h + arm64/include/pcpu.h）维持 13.0 LEGACY，M2 阶段 G-M2 编译失败时按需重做 | T-arch-01 / T-arch-02 状态 ⚠️ deferred；M1 G-M1 编译验收对 arch 子目录的检查跳过；spec 06 §2.2 G-M1 仅要求 libff.a 默认 KNOB（x86_64）链接，arch 字节对齐不在 M1 范围；M2 范围从"kern/net/netinet 升级"扩展为"kern/net/netinet + arch + vm/uma 升级"（仍不破坏 spec 整体边界） |
| DP-9 | 2026-05-28 17:54 | M1→M2 推迟（sys 头 + vm + libalias 全量） | T-sys-01/02/03 + T-vm-01 + T-misc-01(libalias 部分) | G-M1 严格编译命中 4 个跨范围依赖断裂（sys/kassert.h 缺失 + __tcp_get_flags 未定义 + sys/stdarg.h 缺失等），全部回滚到 13.0 F-Stack 版本。spec 05 §2.1 漏列 sys/sys/ 整子目录范围（339 DIFFER + 14 个 F-Stack 改造文件，spec 仅列 4 个） | M1 范围实质收窄为：mips 删除（T-cleanup-01）+ libkern + opencrypto + crypto + netipsec + netgraph 共 6 个子目录全量 15.0 同步；sys 头 / vm / libalias / amd64-x86-arm64 全部 M2 重做。Gate-5b 编译 ✅ PASS（libfstack.a 4.7M 完整生成）。M2 范围比原 spec 增加：sys/sys/ 全量（含 14 个改造文件 5 步法 + 38 NEW + 339 DIFFER）；spec 99 §12.13 新增条目记录该范围扩展 |
| DP-10 | 2026-05-28 17:50 | 全局新约束：临时文件删除规约 | 全 M1+M2+全部后续阶段 | 用户增设全局规约：所有临时文件/目录删除必须经 `/data/workspace/rm_tmp_file.sh` 脚本执行，严禁直接调用 `rm` shell 命令。脚本提供：高危路径黑名单 + mv 留档至 `/data/workspace/.trash/<UTC时间戳>-<pid>/<原绝对路径>` + 审计追加到 `/data/workspace/.rm_audit.log` | 已实战应用于 DP-9 4 个 sys 头回滚 + vm/ 整目录回滚 + netinet/libalias/ 整目录回滚 + alias*.o 残留清理；trash 目录可随时回查；后续 M1+ 全程沿用此约束 |

### 5.2 G-M1 验收实测（2026-05-28 18:04 完成）

| Gate | 验收项 | 命令 | 结果 |
|---|---|---|---|
| Gate-1 | mips 已删 | `find /data/workspace/f-stack/freebsd/mips -type f \| wc -l` | **0** ✅ PASS |
| Gate-2 | Makefile/mk 中 mips 引用清零 | `grep -rEn '^[^#]*mips' Makefile lib/Makefile mk/ \| wc -l` | **0** ✅ PASS |
| Gate-3a | libkern/ 与 15.0 baseline 对账 | `diff -rq freebsd-src-releng-15.0/sys/libkern f-stack/freebsd/libkern` | 仅 `gsb_crc32.c differ`（F-Stack 改造，5 步法已重做）✅ PASS |
| Gate-3b | opencrypto/ 与 15.0 baseline 对账 | `diff -rq freebsd-src-releng-15.0/sys/opencrypto f-stack/freebsd/opencrypto` | **0 行**（完全一致）✅ PASS |
| Gate-3c | crypto/ 与 15.0 baseline 对账 | `diff -rq freebsd-src-releng-15.0/sys/crypto f-stack/freebsd/crypto` | 仅 `skein/amd64/skein_block_asm.s` vs `.S`（F-Stack 命名习惯，内容字节相同）✅ PASS |
| Gate-3d | netipsec/ 与 15.0 baseline 对账 | `diff -rq freebsd-src-releng-15.0/sys/netipsec f-stack/freebsd/netipsec` | **0 行** ✅ PASS |
| Gate-3e | netgraph/ 与 15.0 baseline 对账 | `diff -rq freebsd-src-releng-15.0/sys/netgraph f-stack/freebsd/netgraph` | 仅 `ng_socket.c differ`（F-Stack 改造）+ 6 个 LEGACY 标记（atm/ + bluetooth/h4/ + ng_h4.h + ng_atmllc.{c,h} + ng_sppp.{c,h} + LEGACY.md）✅ PASS |
| Gate-3f | sys/sys/ 头文件 + vm/ + netinet/libalias/ | DP-9 回滚到 13.0 baseline | M1 不要求字节对齐，M2 范围 ✅ DEFERRED（DP-9） |
| Gate-3g | amd64/x86/arm64/ | DP-8 全量保留 13.0 | M1 不要求字节对齐，M2 范围 ✅ DEFERRED（DP-8） |
| Gate-4 | read_lints 全 freebsd/ | `read_lints /data/workspace/f-stack/freebsd` | **0 diagnostics** ✅ PASS |
| Gate-5b | libfstack.a 严格编译 | `cd /data/workspace/f-stack/lib && make` | DP-9 回滚后 **完整链接成功**：libfstack.a = 4.7M（与 baseline 同尺寸），191 个 .o，含 11 个 top-level + 180 个被合并入 libfstack.ro。**无 mips 相关 .o**。timestamp = 2026-05-28 18:03:37 ✅ PASS |

**G-M1 综合判定**：✅ **PASS**（按用户决策点 build_gate_strictness 的"严格优先"模式实测达成）

**关键证据链**：
- M1 删除 mips：`find f-stack/freebsd/mips -type f` = 0 + 留档至 `/data/workspace/f-stack-mips-removed-2026-05/`（586 文件） + Makefile/mk 中 mips 条件全清
- M1 升级到 15.0：libkern 81 文件 + opencrypto 36 文件 + crypto 300 文件 + netipsec 32 文件 + netgraph 156+23 LEGACY 文件
- DP-9 回滚（M1→M2 推迟）：4 sys 头 + vm 53 文件 + netinet/libalias 19 文件全部恢复到 13.0 baseline 字节
- 编译验收：完整 `make` 链路 ld -r → objcopy localize/globalize → ar 全部通过；libfstack.a 重新生成
- trash 留档：`/data/workspace/.trash/20260528-095512-891005/` (4 sys 头) + `/data/workspace/.trash/20260528-095628-891911/` (vm) + `/data/workspace/.trash/20260528-095814-893986/` (libalias)；可随时回查

### 5.3 全局新约束（DP-10，2026-05-28 17:50 起生效）

> 所有需要删除的临时文件都必须修改并使用 `/data/workspace/rm_tmp_file.sh` 脚本执行，严禁直接调用 `rm` 等 shell 命令直接删除。

脚本能力：
- 高危路径黑名单（拒绝删除 `/`、`/etc`、`/usr`、`/var`、`/home`、`/root`、`/data`、`/data/workspace`、`/data/workspace/{f-stack, freebsd-src-releng-13.0, freebsd-src-releng-15.0, f-stack-13.0-baseline}` 等工程根）
- 留档：`mv` 到 `/data/workspace/.trash/<UTC 时间戳>-<pid>/<原绝对路径>`
- 审计：`/data/workspace/.rm_audit.log` 追加每次操作（BEGIN/OK/SKIP/BLOCK/FAIL/END 状态）
- 拒绝 stdin（防误操作），必须显式传入 path 参数

DP-10 实战应用记录见 §3 任务表 + §5.2 关键证据链。

---

## 7. M1 结案

**结案时间**：2026-05-28 18:10

### 7.1 任务完成情况

11 个 T-* 任务最终状态：

| 任务 ID | M1 状态 | M2 是否需重做 |
|---|---|---|
| T-cleanup-01 | ✅ 完成 | ❌ 无需 |
| T-sys-01 | ⚠️ DP-9 回滚到 13.0 | ✅ M2 需重做 |
| T-sys-02 | ⚠️ DP-9 回滚到 13.0 | ✅ M2 需重做 |
| T-sys-03 | ⚠️ DP-9 回滚到 13.0 | ✅ M2 需重做 |
| T-libkern-01 | ✅ 完成 | ❌ 无需（已升 15.0）|
| T-crypto-01 | ✅ 完成 | ❌ 无需（已升 15.0）|
| T-opencrypto-01 | ✅ 完成 | ❌ 无需（已升 15.0）|
| T-vm-01 | ⚠️ DP-9 整体回滚到 13.0 | ✅ M2 需重做（含 sys/sys 一并）|
| T-arch-01 | ⚠️ DP-8 推迟（保留 13.0）| ✅ M2 需重做 |
| T-arch-02 | ⚠️ DP-8 推迟（保留 13.0）| ✅ M2 需重做 |
| T-misc-01 | ⚠️ partial（netipsec+netgraph ✅；libalias DP-9 回滚 13.0）| ✅ libalias 部分 M2 需重做 |

合计：3 完成 + 1 partial + 7 推迟到 M2。

### 7.2 已交付的 M1 成果

1. **mips 架构整体清退**：删除 `freebsd/mips/` 子目录 586 文件 + 清理 lib/Makefile/mk/kern.mk/mk/kern.pre.mk 中 4 处 mips 构建条件；留档至 `/data/workspace/f-stack-mips-removed-2026-05/`。
2. **6 个子目录全量升级到 FreeBSD 15.0**：
   - `libkern/` 81 文件（删 9 个 13.0-only / cp 80 个 / 5 步法 1 个 gsb_crc32.c）
   - `opencrypto/` 36 文件（删 3 个 13.0-only / cp 36 个 / 0 改造）
   - `crypto/` 300 文件（cp 300 个 / 保留 1 个 .s 大小写改造 skein_block_asm.s）
   - `netipsec/` 32 文件（cp 32 个，含新增 ipsec_offload.{c,h}）
   - `netgraph/` 156 + 23 LEGACY-13 + 1 LEGACY.md = 180 文件（cp 156 个 / 23 个 LEGACY 保留 / 5 步法 1 个 ng_socket.c）
3. **libfstack.a 严格编译通过**：4.7M / 191 .o，与 13.0 baseline 同尺寸；无 mips 残留。
4. **文档资产**：
   - `M1-research-brief.md`（10 章节，含 mips 移除外部 web_fetch 证据 + 13→15 全 diff -rq 实测）
   - `M1-execution-log.md`（本文件，含 7 章节 + 3 个打回事件 + 4 个决策点 DP-7~DP-10）
   - `f-stack/freebsd/netgraph/LEGACY.md`（与 99 §12.12 同质 pattern）
   - `freebsd-src-releng-15.0/f-stack-lib/INVENTORY.md` §7 增订（M1 启动校核 verify-only）
   - `99-review-report.md` §6 任务追踪表 11 条 M1 状态全部回写
5. **基础设施**：
   - `/data/workspace/rm_tmp_file.sh` 全局删除规约脚本（DP-10）
   - `/data/workspace/.trash/` trash 目录（DP-9 三次回滚的留档）
   - `/data/workspace/f-stack-13.0-baseline` 整体备份（M1 启动前）
   - `/data/workspace/f-stack-M1-done` 整体备份（M1 末，29597 文件）

### 7.3 M2 输入清单（M1 → M2 交接）

M2 阶段开工前需阅读：
- 本 execution-log §5.1 决策点 DP-7 / DP-8 / DP-9 / DP-10
- spec 99-review-report.md §6 中标记 ⚠️ 的 7 个 M1 任务
- M1-research-brief.md §10（spec 偏差与 M1 任务建议）

M2 范围实质扩展（spec 05 §2.2 原范围 + 以下 DP 推迟项）：
- sys/sys/ 全量（含 14 个 F-Stack 改造文件 5 步法 + 38 NEW + 339 DIFFER；spec 05 §2.1 原仅声明 4 个改造头文件）
- vm/ 全量（含 uma_core.c/uma_int.h 等 8 个 F-Stack 改造文件 5 步法）
- amd64/x86/arm64 全量（含 5 个 F-Stack 改造文件 5 步法）
- netinet/libalias/ 全量（含 alias_sctp.h F-Stack 改造）

M2 启动建议：
1. 先做"sys/sys/ 全量升级"——这是基础依赖，会影响 vm/ + libalias/ + kern/ + 多数 net*/ 子目录
2. 再做 vm/ 全量（含 uma_*）+ amd64/x86/arm64 全量
3. 最后做 spec 05 §2.2 原范围（kern_*.c / uipc_*.c / subr_epoch.c 等 13 个 P0/P1 任务）

### 7.4 关闭

- M1 plan execution status: **DONE**
- 5 角色 team 物理上由 Leader 一人承担（打回事件 #1 已记录原因）
- 用户决策点全程响应：team_topology / build_gate_strictness / external_research_scope / rollback_granularity / vm_uma_strategy / arch_strategy / sys_sys_strategy（DP-9）+ 全局新约束（DP-10）
- 后续 M2 阶段建议沿用相同 5 角色逻辑分工 + harness+spec 框架

---

## 6. 调研引用

> Analyzer 启动调研产出 `M1-research-brief.md` 后，本节列出关键引用与决策影响。

| 引用源 | 类型 | 用于 | 影响 |
|---|---|---|---|
| `M1-research-brief.md` §1（实测 + UPDATING:751/930-931 引文 + FreeBSD 15.0 release notes web_fetch） | 内部+外部 | T-cleanup-01 mips 移除证据 | T-cleanup-01 直接删除 mips 子目录，无需保留 |
| `M1-research-brief.md` §2-§7（diff -rq 全量实测） | 内部 | T-libkern-01 / T-opencrypto-01 / T-vm-01 / T-arch-01/02 / T-misc-01 | F-Stack 在 7 个子目录的实际改造仅 9 个文件（其中 sys 头 4 个 + 其他 5 个），cp -a 风险极低 |
| `M1-research-brief.md` §9-2（blowfish 实测） | 内部 | T-crypto-01 spec 修订 | spec 05 §2.1 T-crypto-01 描述需在 99 §12.13 修订 |
| `M1-research-brief.md` §9-3（netgraph LEGACY 范围扩展） | 内部 | T-misc-01 spec 修订 | spec 需新增 .c 源文件 LEGACY pattern（99 §12.12 仅含 .h） |
| FreeBSD 15.0 release notes <https://www.freebsd.org/releases/15.0R/relnotes/> | 外部权威 | §1 mips / §4 OpenSSL 3.5.4 / §7.2 IPSEC offload 等多项交叉验证 | spec 03 §2.x mips 时机表述需小幅修订（详见 §9-1） |
| 公私统一 KB / 腾讯编程指南 KB（RAG_search） | 外部 KB | §8 F-Stack 社区资料（结果：未发现 F-Stack 项目本身相关内容） | F-Stack 13→15 是社区"无人区"工作；spec 系列是当前最完备指导 |

---

## 7. 结案小节

（待 M1 全部任务完成 + Gate 通过后填入：任务完成统计 / 打回次数 / Gate 决策 / 备份位置 / 进入 M2 的前置条件）
