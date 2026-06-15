# Spec 审核门禁报告（08-review-gate.md）

> **文档编号**：SPEC-KE-08
> **版本**：v1.0
> **日期**：2026-06-15
> **状态**：**PASS**（已通过门禁）
> **作用域**：对本目录 00~07 文档执行一致性 / 可行性 / 与代码吻合度门禁，记录 bounce

---

## 1. 门禁方法

由 `gatekeeper`（`code-explorer` 只读子 agent）对文档中的关键 `文件:行号` 断言逐条 read/grep 核验（PASS/FAIL），Leader 据结果按 bounce 规约处置。核验维度：
- **与代码吻合度**：断言的行号/标志/字段/逻辑是否与实际代码一致；
- **一致性**：文档之间结论是否自洽（机制 A/B/C 的引用统一）；
- **可行性**：选型（virtio-user 主选、禁用 rte_kni）是否与代码现状及 DPDK 版本自洽。

## 2. 首轮核验结果（19 条）

| 结果 | 条目 |
|---|---|
| PASS（17） | A2,A3,A4,A5,A6,A7,A8,B1,B2,B3,B4,C1,C2,C3,C4,C6,D1 |
| FAIL（2） | A1，C5 |

关键确认（节选，均经实测）：
- A4 `src/event/ngx_event_connect.c:46-50` 选栈逻辑成立；A6 `src/event/ngx_event.h:408-414` 双栈事件分发成立；A8 `ngx_ff_host_event_module.c` 存在。
- B2 `ff_hook_syscall.c:257-258`（`FF_MAX_FREEBSD_FILES=65536`）；B3 `:2336` 实际调用 `ff_linux_epoll_wait`（定义 `ff_linux_syscall.c:247`）→ **印证差异 D2**；B4 `ff_hook_socket/bind/connect` 无 `FF_KERNEL_EVENT` 分支 → "仅镜像 epoll"结论成立。
- C1 `ff_dpdk_kni.c:458-466` virtio_user vdev + 全仓 `lib` 无 `rte_kni_init` 调用 → **印证差异 D1**；C3 `handle_knictl_msg` `ff_dpdk_if.c:1959-1987`；C6 过时 `rte_kni_init` 描述确在 `docs/03-LAYER3-FUNCTIONS.md:421` 与 `docs/zh_cn/03-LAYER3-FUNCTIONS.md:421`。

## 3. FAIL 项与处置（bounce #1）

| 项 | 问题 | 处置 |
|---|---|---|
| **A1** | gatekeeper 断言标志位为 `NGX_HTTP_SRV_CONF\|NGX_CONF_FLAG`；实际为 `NGX_HTTP_MAIN_CONF\|NGX_HTTP_SRV_CONF\|NGX_CONF_FLAG`（`ngx_http_core_module.c:299`）。复核发现 `02-current-state-analysis.md:35` **正文已写全（含 `NGX_HTTP_MAIN_CONF`）**，文档本身无误，FAIL 源于核验时的简写断言。 | 无需改文档；本报告显式记录正确标志位 |
| **C5** | ratelimit 字段在 `01-requirements-spec.md`(NFR-2) 与 `07-test-spec.md`(PERF-4) 使用通配简写 `*_packets_ratelimit`，不够精确。`02`/`05` 已用全称。 | **已修复**：两处改为 `console_packets_ratelimit`/`general_packets_ratelimit`/`kernel_packets_ratelimit`（实际 `config.ini:265-267`） |

## 4. bounce 计数

| 步骤 | bounce 次数 | 上限 | 状态 |
|---|---|---|---|
| spec 文档（M0） | **1** | 3 | 已修复，未超限 |

> 规约：同一步骤打回 ≤3 次，连续 3 次不过转人工。本步骤 1 次即修复通过。

## 5. 复核（bounce #1 后）

- C5 修复已落盘（`01-requirements-spec.md` NFR-2、`07-test-spec.md` PERF-4 均为三个全称字段）。
- A1 经确认文档原文正确。
- 其余 17 条维持 PASS。

## 6. 最终门禁结论

**PASS** ✅ —— 00~07 文档与实际代码交叉验证一致（含已显式记录的两处过时文档差异 D1/D2），选型与 DPDK 23.11.5/24.11.6 现状自洽，外部方案均附可访问 URL。本阶段（中文 spec 文档）可放行；英文版待人工审计后再议。

## 7. 遗留提示（交后续实现阶段）
- 三层架构文档 `03-LAYER3-FUNCTIONS.md:421` 的 `rte_kni_init()` 描述已过时，建议在实现阶段一并订正为 virtio-user。
- `ff_local_*` API 命名与头文件归属、连接级增强是否首期交付，待实现阶段定稿（见 `04`/`05`/`06` 开放项）。
