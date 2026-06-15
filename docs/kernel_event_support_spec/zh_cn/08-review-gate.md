# 08 审核门禁报告

> **文档编号**：SPEC-KE-08
> **版本**：v3（范式修正重做）
> **日期**：2026-06-15
> **状态**：PASS
> **作用域**：对 v3 中文 spec 全集做"与实际代码一致性 / 范式正确性 / 可行性"门禁核验。

---

## 1. 门禁方式

- 团队派出 `gatekeeper`（code-explorer 只读）异步核验；**Leader 同步对全部关键 `文件:行号` 断言逐条实测**（grep/read），两者交叉验证，冲突以**实际代码为准**。
- bounce 规约：任一项 FAIL → 打回上一步修复，同一步骤 ≤3 次，超限转人工。

---

## 2. 核验结果（Leader 实测，全部 PASS）

### 选栈标记（v3 核心）
| 编号 | 断言 | 结果 | 证据 |
|---|---|---|---|
| M1 | 标记定义 | PASS | `adapter/syscall/ff_adapter.h:7-8` `SOCK_FSTACK 0x01000000`、`SOCK_KERNEL 0x02000000` |

### hook 模式单 API + 标记选栈
| 编号 | 断言 | 结果 | 证据 |
|---|---|---|---|
| H1 | 领域判定 | PASS | `ff_hook_syscall.c:360` `fstack_territory`，剥离 4 标志（:363-366）+ AF/类型判定（:368-373） |
| H2 | 选栈核心 | PASS | `:380` `ff_hook_socket`：`territory==0→ff_linux_socket`(:383-385)、`SOCK_KERNEL&&!SOCK_FSTACK→ff_linux_socket`(:387-390)、默认 `type&=~SOCK_FSTACK`(:406)；注释 :376-378 |
| H3 | epoll 同范式 | PASS | `:1981` `ff_hook_epoll_create` 按 `SOCK_KERNEL` 选 `ff_linux_epoll_create`(:1982-1983) |
| H4 | fd 归属宏 | PASS | `:57-61` `CHECK_FD_OWNERSHIP`；`is_fstack_fd` `:309` |

### 客户端 connect（v3 新增）
| 编号 | 断言 | 结果 | 证据 |
|---|---|---|---|
| C1 | connect 按归属路由 | PASS | `ff_hook_syscall.c:847-886` `ff_hook_connect`：`:858 CHECK_FD_OWNERSHIP(connect,...)`、`:881 SYSCALL(FF_SO_CONNECT,args)`；纯按 fd 归属、不看目的地址 |
| C2 | 内核侧封装行号 | PASS | `ff_linux_syscall.c` socket:81/bind:88/listen:96/accept:131/**connect:144**/close:217/epoll_create:233/epoll_ctl:239/epoll_wait:247 |

### config.ini 解析层（全局默认开关落点）
| 编号 | 断言 | 结果 | 证据 |
|---|---|---|---|
| G1 | 解析入口/范式 | PASS | `lib/ff_config.c:956` `ini_parse_handler`；`:963` `MATCH`；`[kni]` 段 `:1011-1026`（`MATCH("kni","enable")` :1011-1012） |
| G2 | 配置结构 | PASS | `lib/ff_config.h:253` `struct ff_config`：dpdk(:255-308)/kni(:310-319)/log(:321-325)/freebsd(:327-334)/pcap(:336-342)；`filename` :254；`extern ff_global_cfg` :345；`ff_load_config` :347 |
| G3 | 默认/校验/释放区 | PASS | 校验 `:1261+`、默认 `:1358+`、字符串释放 `:1647+` |

### 原生 ff_api 模式标记差异（关键，D4）
| 编号 | 断言 | 结果 | 证据 |
|---|---|---|---|
| N1 | 原生 socket 入口 | PASS | `lib/ff_syscall_wrapper.c:912-926` `ff_socket`：`sa.type=linux2freebsd_socket_flags(type)`(:918)→`sys_socket`(:920) 进 FreeBSD 栈 |
| N2 | flags 转换不识别选栈标记 | PASS | `linux2freebsd_socket_flags:668-677` 仅处理 `LINUX_SOCK_NONBLOCK/CLOEXEC`；**不识别 SOCK_KERNEL/SOCK_FSTACK** → "原生 ff_socket 恒建 F-Stack socket"成立 |

### 双栈事件（复用）
| 编号 | 断言 | 结果 | 证据 |
|---|---|---|---|
| E1 | 映射表 | PASS | `:257-258` `fstack_kernel_fd_map[FF_MAX_FREEBSD_FILES=65536]` |
| E2 | 双栈 epoll | PASS | create 镜像 `:1996-1997`、wait 合并 `:2324+`（`:2333-2336` 节流调 `ff_linux_epoll_wait(...,0)`）、`maxevents>=2` `:2213-2216`、close 联动 `:1874-1883` |

### ff_api.h / 范式正确性
| 编号 | 断言 | 结果 | 证据 |
|---|---|---|---|
| A1 | API 行号 | PASS | `ff_api.h` socket:81/listen:89/bind:90/accept:91/connect:93/close:94/kqueue:138/kevent:139 |
| S1 | v3 范式正确性 | PASS | 01/02/04/05/06：(a) 已删 `ff_local_*` 双 API/`belong_to_host` 参数；(b) 统一 `SOCK_KERNEL/SOCK_FSTACK` 标记 + config 全局默认 + 胶水适配；(c) 含客户端 connect 选栈（本机/外部）；(d) 删线程级、无端口名单；(e) 双模式覆盖且如实记录原生模式需补强（D4） |

**通过：19/19。**

---

## 3. README/注释 vs 代码差异（以代码为准）

| 编号 | 描述 | 结论 |
|---|---|---|
| D3 | `ff_hook_syscall.c:2076-2081` 注释"首版不支持 `ff_linux_epoll_wait`" | 与 `:2336` 实际调用冲突：当前**已**调用（`timeout=0`+节流）。以代码为准，已在 `02` 记录 |
| D4 | 直觉"原生 `ff_socket` 也识别 `SOCK_KERNEL`" | `ff_socket:918`+`linux2freebsd_socket_flags:668-677` 证伪：**不识别**，恒建 F-Stack socket。v3 列为原生模式需补强项（`02 §5`/`05 §4`/`06 M4`） |

---

## 4. Bounce 记录

| # | 触发 | 处置 | 复核 |
|---|---|---|---|
| — | 本轮 Leader 实测与文档断言一致，未触发行号类 FAIL | — | — |

- bounce 次数：0（< 3 上限），**无需转人工**。
- 行号类 FAIL：0。

---

## 5. 总体门禁结论

**PASS**。v3 spec 全集与实际代码一致（19/19）。范式已正确收敛为：**复用并标准化 F-Stack 现有"单 API + `SOCK_KERNEL`/`SOCK_FSTACK` 标记选栈 + 胶水自动适配" + config.ini 全局默认开关**，覆盖**服务端 + 客户端（连本机/外部内核服务）双向**与 **hook + 原生双模式**；已彻底移除 `ff_local_*` 双 API 与 gazelle 线程级选栈；KNI 仅作边界澄清。关键事实 D4（原生 `ff_socket` 不识别选栈标记）已如实记录为实现阶段补强项。可进入本地提交。

---

# 实现阶段门禁报告（M1-M6，2026-06-15）

> 对"本地 socket/fd/event 支持"实现做编译/单测/覆盖率/集成 实测门禁。结论来自实际编译与运行，证据可复现。

## I.1 代码改动核验（Leader 实测，全部 PASS）

| 编号 | 断言 | 结果 | 证据 |
|---|---|---|---|
| G1 | 标记对外暴露（M1） | PASS | `lib/ff_api.h` `#ifndef SOCK_FSTACK 0x01000000` / `SOCK_KERNEL 0x02000000`，值与 `adapter/syscall/ff_adapter.h:7-8` 一致 |
| G2 | config 结构（M3） | PASS | `lib/ff_config.h` `struct ff_config` 新增 `struct { int default_to_kernel; } stack;`（kni 段后） |
| G3 | config 解析/默认/访问器（M3） | PASS | `ff_config.c:1027` `MATCH("stack","default_stack")`（`strcasecmp(value,"kernel")?1:0`）；`:1365` 默认 0；`:1382` `ff_default_stack_is_kernel()` |
| G4 | config.ini 段（M3） | PASS | 项目根 `config.ini` 新增 `[stack] default_stack=fstack` + 注释 |
| G5 | 宿主桥声明（M4） | PASS | `lib/ff_host_interface.h` 声明 `ff_host_socket` / `ff_default_stack_is_kernel` |
| G6 | 宿主桥实现（M4） | PASS | `ff_host_interface.c:240` `ff_host_socket` 调宿主 `socket()`；新增 `#include <sys/socket.h>`；`ff_getenv:234` 完整 |
| G7 | ff_socket 选栈分支（M4，零回归） | PASS | `ff_syscall_wrapper.c:928-931` 新分支；原 FreeBSD 路径（`:933` 起）**逐字节未改**（NFR-1） |
| G8 | cmocka 单测（M6） | PASS | `tests/unit/test_ff_config.c` 新增 4 用例并注册；`extern ff_default_stack_is_kernel` |
| G9 | fixtures（M6） | PASS | `valid_stack_kernel.ini`/`valid_stack_garbage.ini`；`valid_all_sections.ini` 含 `[stack] default_stack=fstack` |
| G10 | 范式一致 | PASS | 未新造 `ff_local_*`；单 API + 标记 + config 默认，符合 05/06 |
| G11 | hook 层 config 边界 | PASS | `ff_hook_syscall.c:31` `ff_global_cfg` 注释 "Just for so, no used" → config 默认仅原生模式生效（已据实记录） |

## I.2 编译与单测（硬门禁，PASS）

- **lib 编译**：`cd lib && make` 在 `-Werror` 下成功重链 `libfstack.a`（三处改动文件均通过）。
- **cmocka 单测**：`test_ff_config` **54/54 PASS**（新增 4 个 `[stack]` 用例）；全部可构建 binary 合计 **176 TC，0 失败**。
- **覆盖率（G8）**：`ff_config.c` 行 **89.96%** / 分支 **85.30%**（与基线持平，新增代码已覆盖）。

## I.3 集成实测（核心特性真实跑通，无需 DPDK NIC）

示例 `example/helloworld_stacksel`（`ff_socket(SOCK_KERNEL)`→宿主内核栈，免 EAL）：

| 用例 | 命令 | 结果 |
|---|---|---|
| selftest | `./helloworld_stacksel` | `INTEGRATION PASS: kernel-stack server+client over loopback` |
| FR-1 本机 curl 直访内核栈监听 | `curl 127.0.0.1:18099` | 返回 `hello-stacksel` |
| FR-2 内核 ICMP | `ping -c1 127.0.0.1` | `0% packet loss` |
| FR-3 客户端经内核栈 connect 本机服务 | `helloworld_stacksel client 127.0.0.1 18100` | `connected via kernel stack` + `HTTP/1.1 200 OK` |
| M4 原生 ff_socket(SOCK_KERNEL) | 上述均经 `ff_socket(SOCK_KERNEL)` | 返回真实宿主内核 fd，收发正常 |

## I.4 Skip 项（环境不具备，附实测证据；按 Q1 处置）

| 项 | 原因（实测） | 证据 |
|---|---|---|
| F-Stack 数据面端到端 / hook 模式 / 性能基线 PERF-* | 沙箱**无 DPDK 绑定物理 NIC**（大页存在 `HugePages_Total:4096`，但无可用 NIC/数据面） | — |
| FR-4 连外部内核栈服务 | 机制同 FR-3（仅目的地址不同），FR-3 已实测通；外网出口不保证 | 复用 FR-3 证据 |
| `tests/unit/test_ff_dpdk_if` 与 `tests/integration/*` | **预存基线** 缺失 `ff_tcp_hpts_softclock`（`ff_dpdk_if.c:2459`）；`git stash` 还原本轮改动后**同样失败**，证明非本特性回归 | `git stash` 复现，缺失符号一致 |

> `ff_tcp_hpts_softclock` 缺失影响所有链接 `ff_dpdk_if.o` 的测试 binary，属与本特性无关的预存测试基建问题，建议单独处理；本特性硬门禁不依赖该 binary。

## I.5 Bounce 记录

| # | 触发 | 处置 | 复核 |
|---|---|---|---|
| 自纠 | 编辑 `ff_host_interface.c` 一处 replace 误删 `ff_getenv` 签名 | 同步骤立即恢复 + 加 `ff_host_socket` | 编译通过、`ff_getenv` 完整（G6 PASS） |

- 阶段门禁 bounce：0（无跨步骤打回；上为同步骤即时自纠，< 3 上限）。

## I.6 实现阶段总体结论

**PASS（硬门禁）**：编译 + cmocka 单测全绿（176 TC）+ `ff_config.c` 覆盖率维持；核心"本地 socket/fd/event 访问"特性（标记选栈 M1/M4、config 默认开关 M3、服务端内核栈监听 FR-1/FR-2、客户端内核栈 connect FR-3）已**真实运行验证**。DPDK-NIC 数据面相关（hook 端到端 / 性能基线 / FR-4 外部 / 预存 `ff_tcp_hpts_softclock` 阻塞的测试 binary）因环境无物理 NIC 按 Q1 **skip 并附实测证据**，不影响硬门禁。
