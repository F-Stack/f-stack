# F-Stack 本地 socket/fd/event 访问能力 —— 项目总览与文档导航（00-overview.md）

> **文档编号**：SPEC-KE-00
> **版本**：v0.1 草稿
> **日期**：2026-06-15
> **状态**：编写中
> **作用域**：`/data/workspace/f-stack/`（本阶段仅产出中文 spec 文档）

---

## 1. 一句话目标

让 DPDK 接管网卡后的 F-Stack 主机，**业务流量走用户态 FreeBSD 协议栈、本机/管理面流量（ping、本地 curl 等）仍可走内核协议栈**，并将该能力以 lib 库形式沉淀。

## 2. 阅读路径

```
plan.md                       ← 总体规划 / 团队拓扑 / 门禁规约（先读）
00-overview.md                ← 本文：导航
01-requirements-spec.md       ← 为什么做、做到什么程度（需求/边界）
02-current-state-analysis.md  ← 现状：F-Stack 已有的两个参考机制（代码级、文件:行号）
03-external-research.md       ← 业界怎么做：KNI/TAP/exception path/virtio-user（附 URL）
04-architecture-design.md     ← 我们怎么做：目标 lib 架构与分流模型
05-interface-design.md        ← 对外 API / 编译宏 / 数据结构
06-milestones.md              ← 分几步落地 + 编码工作清单
07-test-spec.md               ← 怎么验证：单测/集成/性能基线
08-review-gate.md             ← 审核门禁结论 + bounce 记录
```

## 3. 关键术语

| 术语 | 含义 |
|---|---|
| **用户态栈 / F-Stack 栈** | F-Stack 移植的 FreeBSD TCP/IP 协议栈，运行在 DPDK polling 线程内 |
| **内核栈** | Linux 内核原生 TCP/IP 协议栈 |
| **分流（dispatch）** | 按某种判定（fd、地址、配置开关）决定一个 socket/事件走用户态栈还是内核栈 |
| **机制 A** | nginx `kernel_network_stack` per-server 开关（应用配置粒度） |
| **机制 B** | `adapter/syscall` 的 `FF_KERNEL_EVENT` 宏（fd/syscall 粒度，含 `fstack_kernel_fd_map`） |
| **KNI / TAP / exception path / virtio-user** | DPDK 生态中将报文送回内核的几类典型路径（详见 `03-external-research.md`） |

## 4. 现状参考的依据来源（待 02 文档实测精确化）

- `app/nginx-1.28.0/`：`kernel_network_stack` 指令链路（`NGX_HAVE_FSTACK`）。
- `adapter/syscall/`：`FF_KERNEL_EVENT` 宏（`ff_hook_syscall.c`、`Makefile`、`README.md`），含 `helloworld_stack_epoll_kernel` demo。
- `docs/`：三层架构文档（`01/02/03-LAYER*.md`、`F-Stack_Architecture_Layer1/2/3_*.md`）与知识图谱（`KNOWLEDGE_GRAPH_WIKI.md`、`F-Stack_Knowledge_Base_Summary.md`）。

## 5. 文档纪律

- 现状描述一律带 `文件:行号` 实测证据；与文档/README 冲突以**实际代码**为准。
- 外部方案一律附**可访问 URL**。
- 本阶段不改源码、不写实现。
