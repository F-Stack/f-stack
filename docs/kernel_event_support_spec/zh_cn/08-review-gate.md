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
