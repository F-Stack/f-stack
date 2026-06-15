# 00 总览：F-Stack 连接级选栈增强（单 API + 标记 + config 默认开关）

> **文档编号**：SPEC-KE-00
> **版本**：v3（范式修正重做）
> **日期**：2026-06-15
> **状态**：编写中
> **作用域**：本目录中文 spec 的导航、术语与范围声明

---

## 1. 一句话目标

**标准化 F-Stack 现有的"单 API + `SOCK_KERNEL`/`SOCK_FSTACK` 标记选栈 + 胶水自动适配"能力**，并在 config.ini 增加**一个全局默认栈开关**；使任意 F-Stack 应用**无需改用多套 API**，即可让某些 fd 走宿主机内核栈（本机 `ping`/`curl` 直访其服务，且该应用作客户端也能经内核栈 `connect` 本机/外部内核服务），其余 fd 走 F-Stack 高速路径。

## 2. 范围声明（重要）

- **本特性 = 连接级选栈增强**，选栈方式 = **app 标记（per-fd）+ config.ini 全局默认开关（per-process）**，胶水层自动适配。
- **直接复用基线**：`adapter/syscall` hook 模式的 `SOCK_KERNEL`/`SOCK_FSTACK` 标记选栈（`ff_hook_socket`/`ff_hook_connect`）+ `FF_KERNEL_EVENT` 双栈事件。
- **双向覆盖**：服务端（内核栈监听被本机直访）+ **客户端（经内核栈 `connect` 本机/外部内核服务，新增）**。
- **双模式覆盖**：hook 模式（已支持，直接复用）+ 原生 `ff_api` 模式（补 `ff_socket` 标记识别）。
- **明确排除**：
  - **不**新造 `ff_local_*` 双 API / 类 mTCP 双命名空间（v2 做法作废）。
  - **不**做 gazelle 式线程级选栈（多进程模型靠不同 config 文件）。
  - **不**做 config 端口/地址名单（仅一个全局默认开关）。
  - **不**采用 KNI/`rte_kni`/virtio-user/TAP/AF_XDP 报文回灌（仅边界澄清）。

## 3. 阅读路径

| 顺序 | 文档 | 用途 |
|---|---|---|
| 1 | `plan.md` | 计划、团队、门禁、范式修正 |
| 2 | `01-requirements-spec.md` | 需求与目标/非目标 |
| 3 | `02-current-state-analysis.md` | 单 API+标记/客户端/config/原生模式 代码现状（以代码为准） |
| 4 | `03-external-research.md` | 外部方案调研（附 URL） |
| 5 | `04-architecture-design.md` | 标记+config 选栈架构与双向数据流 |
| 6 | `05-interface-design.md` | 标记/config 契约与双模式适配 |
| 7 | `06-milestones.md` | 里程碑与编码工作清单 |
| 8 | `07-test-spec.md` | 测试与性能基线方案 |
| 9 | `08-review-gate.md` | 审核门禁结论 |

## 4. 术语表

| 术语 | 含义 |
|---|---|
| F-Stack 栈 | DPDK PMD + 用户态 FreeBSD 协议栈（业务高速路径） |
| 内核栈 | 宿主机 Linux 内核网络协议栈（本机/管理/客户端连本机或外部内核服务） |
| 选栈标记 | socket `type` 上的 `SOCK_KERNEL`(0x02000000)/`SOCK_FSTACK`(0x01000000)，per-fd 选栈 |
| 全局默认栈开关 | config.ini 中决定本进程默认栈的开关（`[stack] default_stack`） |
| 胶水自动适配 | 创建时标记/配置定 fd 归属，后续 syscall 经 `is_fstack_fd`/`CHECK_FD_OWNERSHIP` 自动路由 |
| hook 模式 | LD_PRELOAD 接管 POSIX API（`ff_hook_*`），标记选栈已支持 |
| 原生模式 | 应用直接调 `ff_*`（`ff_api.h`），现状 `ff_socket` 不识别标记（需补强） |

## 5. 依据来源

- F-Stack 实际代码（`adapter/syscall/`、`lib/`、`app/nginx-1.28.0/`）——**最高优先级，冲突以代码为准**。
- F-Stack 三层架构文档与知识图谱（`docs/`）。
- 外网公开资料（GitHub/技术博客等），均在 `03` 附可访问 URL。
