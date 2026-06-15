# 00 总览：F-Stack 连接级选栈增强（本机直访 F-Stack 服务）

> **文档编号**：SPEC-KE-00
> **版本**：v2（全量重做）
> **日期**：2026-06-15
> **状态**：编写中
> **作用域**：本目录中文 spec 的导航、术语与范围声明

---

## 1. 一句话目标

为 F-Stack 提供一个 lib，使应用进程能在 **F-Stack 用户态栈**与**宿主机 Linux 内核栈**上**同时**创建/监听 socket，并以**统一的 fd / event 抽象**在单事件循环中服务两栈；从而即使 DPDK 接管了网卡，本机的 `ping` / `curl` 等工具也能**直接访问该应用在内核栈侧暴露的服务**。

## 2. 范围声明（重要）

- **本特性 = 连接级选栈增强（Connection-level Stack Selection）**。
- **首要参考**：nginx 的 `kernel_network_stack` 开关（`belong_to_host` 1-bit 选栈 + 双事件后端）。
- **次要参考**：`adapter/syscall` 的 `FF_KERNEL_EVENT` 编译宏（`fstack_kernel_fd_map` + 双栈 epoll 合并）。
- **明确排除（非目标）**：KNI / `rte_kni` / virtio-user / TAP / AF_XDP 等"报文回灌内核"方案——它们解决的是"未被应用接管的报文回到内核"，与本特性"应用主动在内核栈侧暴露服务"是不同问题，仅在方案对比中用于澄清边界。

## 3. 阅读路径

| 顺序 | 文档 | 用途 |
|---|---|---|
| 1 | `plan.md` | 计划、团队、门禁、范围修正 |
| 2 | `01-requirements-spec.md` | 需求与目标/非目标 |
| 3 | `02-current-state-analysis.md` | 机制 A/B 代码级现状（以代码为准） |
| 4 | `03-external-research.md` | 外部方案调研（附 URL） |
| 5 | `04-architecture-design.md` | 双栈选栈架构与事件模型 |
| 6 | `05-interface-design.md` | lib 对外接口契约 |
| 7 | `06-milestones.md` | 里程碑与编码工作清单 |
| 8 | `07-test-spec.md` | 测试与性能基线方案 |
| 9 | `08-review-gate.md` | 审核门禁结论 |

## 4. 术语表

| 术语 | 含义 |
|---|---|
| F-Stack 栈 | DPDK PMD + 用户态 FreeBSD 协议栈（业务高速路径） |
| 内核栈 | 宿主机 Linux 内核网络协议栈（本机/管理/异常路径） |
| 连接级选栈 | 在 socket/listen/connect 粒度上决定该连接走 F-Stack 还是内核栈 |
| `belong_to_host` | nginx 中标记某连接/监听走内核栈的 1-bit 标志 |
| `SOCK_FSTACK` | F-Stack 适配层在 `socket()` type 上附加的标志，表示走 F-Stack |
| `FF_KERNEL_EVENT` | LD_PRELOAD 适配层的编译宏，使事件循环同时处理内核 fd |
| `fstack_kernel_fd_map` | "F-Stack fd → 内核 fd"映射表，用于双栈事件合并 |

## 5. 依据来源

- F-Stack 实际代码（`app/nginx-1.28.0/`、`adapter/syscall/`、`lib/`）——**最高优先级，冲突以代码为准**。
- F-Stack 三层架构文档与知识图谱（`docs/`）。
- 外网公开资料（GitHub issue/wiki、技术博客等），均在 `03` 附可访问 URL。
