# 01 需求规格：F-Stack 连接级选栈增强（单 API + 标记 + config 默认开关）

> **文档编号**：SPEC-KE-01
> **版本**：v3（范式修正重做）
> **日期**：2026-06-15
> **状态**：编写中
> **作用域**：定义本特性的问题域、目标/非目标、功能与非功能需求、成功标准。

---

## 1. 问题域

F-Stack 通过 DPDK 接管网卡后，该网卡流量绕过 Linux 内核协议栈，导致：

1. **服务端方向**：本机工具（`ping`/`curl`/`ssh`）无法访问运行在 F-Stack 用户态栈上的服务。
2. **客户端方向**：F-Stack 应用作客户端时，无法用内核栈去 `connect` 本机服务（`127.0.0.1`/本机内核栈 IP）或外部内核栈服务。

F-Stack 的 `adapter/syscall`（hook/LD_PRELOAD 模式）**已实现"单 POSIX API + `SOCK_KERNEL`/`SOCK_FSTACK` 标记 + 胶水自动适配"**的选栈能力（见 `02`），但：
- 该标记语义**内嵌**在 syscall 适配层，未被标准化为"任意 F-Stack 应用可依赖的选栈约定"；
- **缺少 config.ini 级别的"全局默认栈开关"**（只能靠应用逐 socket 设标记）；
- **客户端连本机/外部内核栈服务**未被系统化文档化；
- **原生 `ff_api` 模式**的 `ff_socket` 现状**不识别**选栈标记（`02 §5`，恒建 F-Stack socket）。

本特性即：**标准化现有"单 API + 标记选栈"约定 + 补齐 config.ini 全局默认开关 + 覆盖客户端方向 + 在原生模式补齐标记识别**，使任意 F-Stack 应用无需改用多套 API 即可按需选栈。

---

## 2. 目标与非目标

### 2.1 目标（In Scope）
- **G1（标记标准化）**：以现有 `SOCK_KERNEL`/`SOCK_FSTACK`（`ff_adapter.h:7-8`）为**唯一选栈标记**，标准化为可被任意 F-Stack 应用使用的约定；**不新造 `ff_local_*` 双 API、不新造 `belong_to_host` 参数**。
- **G2（config.ini 全局默认开关）**：在 config.ini 新增**一个全局默认栈开关**（仿 `[kni]` 范式），决定本进程默认走 F-Stack 还是内核栈；**优先级：app 标记 > config 默认**。
- **G3（服务端选栈）**：应用可让某监听 socket 走内核栈，本机 `ping`/`curl`/`ssh` 直访其服务。
- **G4（客户端选栈，新增）**：应用作客户端可经内核栈 `connect` 访问本机回环/本机内核栈 IP 服务**及外部内核栈服务**（承载点 `ff_hook_connect:858`）。
- **G5（双模式覆盖）**：选栈标记与客户端能力同时覆盖 **hook 模式**（完整复用）与**原生 `ff_api` 模式**（补齐 `ff_socket` 标记识别，`02 §5`）。
- **G6（统一事件）**：单事件循环同时服务内核栈 fd 与 F-Stack fd（复用 `fstack_kernel_fd_map` 双栈合并）。
- **G7（低侵入/默认零开销）**：编译开关默认关闭；不设标记/默认 F-Stack 时行为与原 F-Stack 一致。

### 2.2 非目标（Out of Scope）
- **N1**：**不**新造 `ff_local_*` 双 API / 类 mTCP 双命名空间（v2 做法作废）。
- **N2**：**不**做 gazelle 式**线程级选栈**（F-Stack 多进程模型靠不同 config 文件区分，见 `02 §4`）。
- **N3**：**不**做 config.ini 端口/地址规则名单（仅"一个全局默认开关"）。
- **N4**：**不**采用 KNI/`rte_kni`/virtio-user/TAP/AF_XDP 报文回灌。
- **N5**：本阶段**不写实现代码、不改 f-stack 源码**，仅产出中文 spec；**不生成英文文档**。
- **N6**：不实现内核栈与 F-Stack 间 socket 自动迁移/透明代理（归属在创建时确定）。

---

## 3. 功能需求（FR）

| 编号 | 需求 | 验收要点 | 代码依据 |
|---|---|---|---|
| FR-1 | **标记选栈（服务端）**：带 `SOCK_KERNEL` 的监听 socket 走内核栈，本机 `curl`/`ssh` 可访问 | 本机访问内核栈监听成功 | `ff_hook_socket:387-390` |
| FR-2 | 本机 `ping`（ICMP）对内核栈侧地址可达 | ping 通 | 内核栈原生处理 ICMP |
| FR-3 | **标记选栈（客户端，新增）**：F-Stack 应用经内核栈 `connect` 本机回环/本机 IP 服务 | 本机 server + F-Stack client connect 通 | `ff_hook_connect:858` + `is_fstack_fd:309` |
| FR-4 | **客户端连外部内核栈服务（新增）**：F-Stack 应用作客户端选栈访问外部内核栈服务 | 连外部内核服务成功 | `ff_hook_connect:858` → `ff_linux_connect:144` |
| FR-5 | **config.ini 全局默认开关**：可配置本进程默认栈（F-Stack/内核），app 标记可覆盖 | 默认栈生效、标记覆盖生效 | `ff_config.c:1011`/`ff_config.h:310-319` 范式 |
| FR-6 | **双模式覆盖**：hook 模式直接复用标记；原生 `ff_api` 模式补齐 `ff_socket` 标记识别 | 两模式均可标记选栈 | `02 §2`（hook）/`02 §5`（原生差异） |
| FR-7 | 统一事件循环：单循环同时收 F-Stack 与内核栈事件 | 两栈事件均正确投递 | `ff_hook_syscall.c:2324+` |
| FR-8 | fd 归属判定 + 资源联动：按归属分流，关闭/异常时两栈 fd 一致释放 | 行为正确、无 fd 泄漏 | `is_fstack_fd:309`、close 联动 `:1874-1883` |
| FR-9 | 编译开关：本能力可编译期开/关，默认关闭零开销 | 关闭时与原 F-Stack 行为一致 | `Makefile -DFF_KERNEL_EVENT` 范式 |

---

## 4. 非功能需求（NFR）

| 编号 | 需求 |
|---|---|
| NFR-1 | **默认零开销**：未开启/默认 F-Stack 时不引入额外分支/内存开销 |
| NFR-2 | **业务快路径无回归**：F-Stack 高速路径性能不受影响（基线见 `07`） |
| NFR-3 | **可移植**：兼容本工作区 DPDK 23.11.5 / 24.11.6 与移植后的 FreeBSD 栈 |
| NFR-4 | **可观测**：提供两栈 fd 数、事件数等基本统计 |
| NFR-5 | **接口稳定/低侵入**：复用现有单 API + 标记，不引入多套 API；语义贴合 POSIX/`ff_api.h` |
| NFR-6 | **多进程一致**：每进程经各自 config.ini 独立设默认栈，互不影响（`ff_config.filename:254`） |

---

## 5. 边界与异常场景

- `SOCK_KERNEL` 与 `SOCK_FSTACK` 同时置位时的优先级（实测 `ff_hook_socket:387` 要求 `SOCK_KERNEL && !SOCK_FSTACK` 才走内核，需在接口契约明确）。
- app 标记与 config 默认冲突时：**app 标记优先**。
- 内核栈侧地址/端口与 F-Stack 侧冲突时报错而非静默。
- `maxevents` 过小（机制要求 `>=2`，`:2212-2218`）时的处理。
- 客户端 `connect` 时 fd 归属与目的地址栈不匹配（如内核 fd 连 F-Stack 才可达的地址）时的行为约定。
- 原生模式 `ff_socket` 标记识别补齐前后的兼容性（`02 §5`）。
- 本能力关闭（编译期）时所有路径退化为纯 F-Stack 行为。
- 系统前提缺失（参考 gazelle `rp_filter` 等）时的检测与提示。

---

## 6. 成功标准

1. DPDK 接管网卡后，带 `SOCK_KERNEL` 的内核栈监听：本机 `ping <内核栈IP>` 通、`curl <内核栈服务>` 成功（FR-1/FR-2）。
2. F-Stack 应用作客户端：经内核栈 `connect` 本机服务（127.0.0.1/本机 IP）与外部内核栈服务均成功（FR-3/FR-4）。
3. config.ini 全局默认栈开关生效，且 app 标记可覆盖（FR-5）；多进程用不同 config 文件得到不同默认栈（NFR-6）。
4. hook 与原生两模式均可标记选栈（FR-6）；单事件循环正确服务两栈（FR-7/FR-8）。
5. 本能力关闭/默认 F-Stack 时，业务性能与功能**零回归**（NFR-1/NFR-2）。
6. spec 全集过 `08-review-gate.md` 门禁。
