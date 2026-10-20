# 02 — 现状架构与测试目标分层

> 文档版本：v0.1（2026-06-09 17:55 UTC+8）
> Author：spec-author（基于 arch-explorer + mock-strategist + target-prioritizer 三路并行调研）
> 适用范围：F-Stack lib/ FF_HOST_SRCS 11 文件实测清单 + 测试目标 P0/P1/P2/P3 分层

---

## 1. 文档目的

精确盘点 F-Stack lib/ 中由 `lib/Makefile FF_HOST_SRCS` 罗列的 11 个胶水代码文件的：
1. 文件级现状（行数 / 装载条件 / 业务复杂度）
2. 函数级清单（公开 API + static helper + inih handler）
3. 跨文件依赖矩阵（11×11）
4. 外部依赖统计（rte / pthread / sys / printf 4 类）
5. **测试目标 P0/P1/P2/P3 分层与 ROI 决策表**

供 spec 04 / 06 起草时直接引用，gate-keeper 据此 cross-check。

---

## 2. FF_HOST_SRCS 实测清单（lib/Makefile line 272-291 + 568-572）

### 2.1 文件级总览

| # | 文件 | 行数 | 装载条件 | 业务复杂度（1-5）| 主要逻辑 |
|---|---|---|---|---|---|
| 1 | `ff_host_interface.c` | 332 | always | 3 | 进程级 mmap/clock/arc4rand/errno 转换工具集 |
| 2 | `ff_thread.c` | 51 | always | 1 | pthread 薄包装 + thread-local 注入 |
| 3 | `ff_config.c` | 1381 | always | 4 | 11 类 inih handler + argv 解析 + dpdk_argv 构建 + 字符串校验 |
| 4 | `ff_ini_parser.c` | 195 | always | 3 | INI 状态机解析（注释 / section / multiline / BOM / inline-comment）|
| 5 | `ff_dpdk_if.c` | 2887 | always | 5 | 整个 DPDK 启停 + 端口/RSS/bond/timer/burst rx/tx 主循环 |
| 6 | `ff_dpdk_pcap.c` | 137 | always | 2 | pcap 文件头 / 记录写入 + 时间戳 |
| 7 | `ff_epoll.c` | 159 | always | 3 | epoll API → ff_kqueue API 的事件转换映射 |
| 8 | `ff_log.c` | 111 | always | 2 | `fopen` + rte_log 包装 + 日志级别设置 |
| 9 | `ff_init.c` | 69 | always | 1 | 4 步串行初始化序列（无分支逻辑）|
| 10 | `ff_dpdk_kni.c` | 536 | `FF_KNI=1` | 4 | KNI 初始化 + 端口/socket 协议过滤分发 + 多 ring |
| 11 | `ff_memory.c` | 509 | `FF_USE_PAGE_ARRAY=1` | 4 | mbuf 引用池 + virt2phy + tx ring + offload 桥接 |

**总计**：11 文件 / 6377 行，必装 9 + 条件 2。

### 2.2 与 lib/ 全景的关系

- lib/ 共 **31 个 ff_*.c 文件 / 22400 行**
- **本任务覆盖** = HOST_SRCS 11 文件 / 6377 行（28% 行）
- **out-of-scope** = KERN_SRCS ~20 文件 / ~16000 行（72% 行），是 FreeBSD kernel 子集移植，host 端不直接编译

### 2.3 已有测试痕迹（实测）

```bash
$ for f in <11 files>; do
    grep -cE "(^#ifdef.*TEST|UNITTEST|UNIT_TEST|assert\\()" lib/$f
  done
```

| 文件 | `assert()` 计数 | 是否为"测试痕迹" |
|---|---|---|
| ff_dpdk_if.c | 1 (line 784, 硬件 reta_size 校验) | 否，运行期断言 |
| ff_host_interface.c | 3 (lines 68, 176, 209) | 否，运行期断言 |
| 其余 9 文件 | 0 | — |
| `f-stack/tests/` 或 `test/` 目录 | 不存在 | — |

→ **结论**：所有 11 文件都是"绿地测试"，无任何已存在的单元测试代码或残留。

---

## 3. 函数级清单（实测）

### 3.1 公开 API（非 static）

| 文件 | 公开 API 数 | API 列表（line 号）|
|---|---|---|
| **ff_ini_parser.c** | **3** | `ini_parse` (L184), `ini_parse_file` (L178), `ini_parse_stream` (L73) |
| **ff_log.c** | **7** | `ff_log` (L95), `ff_log_close` (L68), `ff_log_open_set` (L48), `ff_log_reset_stream` (L77), `ff_log_set_global_level` (L83), `ff_log_set_level` (L89), `ff_vlog` (L108) |
| **ff_host_interface.c** | **11** | `ff_arc4rand` (L213), `ff_arc4random` (L221), `ff_calloc` (L111), `ff_clock_gettime` (L154), `ff_clock_gettime_ns` (L183), `ff_free` (L131), `ff_get_current_time` (L194), `ff_getenv` (L233), `ff_malloc` (L103), `ff_mmap` (L54), `ff_munmap` (L89), `ff_os_errno` (L238), `ff_realloc` (L119), `ff_setenv` (L228), `ff_update_current_ts` (L206), `panic` (L142, `__noreturn__`) |
| **ff_thread.c** | 2 | `ff_pthread_create` (L33), `ff_pthread_join` (L49) |
| **ff_config.c** | **1** | `ff_load_config` (L1347) |
| **ff_dpdk_if.c** | 17+ | `ff_dpdk_init`, `ff_dpdk_run`, `ff_dpdk_stop`, `ff_dpdk_register_if`, `ff_dpdk_deregister_if`, `ff_dpdk_if_send`, `ff_dpdk_if_up`, `ff_dpdk_pktmbuf_free`, `ff_dpdk_raw_packet_send`, `ff_get_traffic`, `ff_get_tsc_ns`, `ff_in_pcbladdr`, `ff_regist_packet_dispatcher`, `ff_regist_packet_dispatcher_context`, `ff_regist_pcblddr_fun`, `ff_rss_check`, `ff_rss_tbl_get_portrange`, `ff_rss_tbl_init`, `ff_rss_tbl_set_portrange` |
| **ff_dpdk_pcap.c** | 1 | `ff_enable_pcap` (L59) |
| **ff_epoll.c** | 3 | `ff_epoll_create` (L25), `ff_epoll_ctl` (L31), `ff_epoll_wait` (L148) |
| **ff_init.c** | 3 | `ff_init` (L36), `ff_run` (L59), `ff_stop_run` (L65) |
| **ff_dpdk_kni.c** | 5 | `ff_kni_alloc` (L423), `ff_kni_enqueue` (L503), `ff_kni_init` (L377), `ff_kni_process` (L494), `ff_kni_proto_filter` (L371) |
| **ff_memory.c** | 6 | `ff_enq_tx_bsdmbuf` (L505), `ff_if_send_onepkt` (L440), `ff_init_ref_pool` (L213), `ff_mem_free_addr` (L305), `ff_mem_get_page` (L300), `ff_mmap_init` (L228) |
| **总计** | **~75 个公开 API** | — |

### 3.2 ff_config.c 的 11 个 inih handler（**全部 static**，关键约束）

| # | handler | 行 | static? | 直接可测? |
|---|---|---|---|---|
| 1 | `freebsd_conf_handler` | L156 | static | 否 |
| 2 | `vip_cfg_handler` | L380 | static | 否 |
| 3 | `vip6_cfg_handler` | L429 | static | 否 |
| 4 | `ipfw_pr_cfg_handler` | L480 | static | 否 |
| 5 | `port_cfg_handler` | L541 | static | 否 |
| 6 | `vlan_cfg_handler` | L641 | static | 否 |
| 7 | `vdev_cfg_handler` | L746 | static | 否 |
| 8 | `bond_cfg_handler` | L800 | static | 否 |
| 9 | `rss_tbl_cfg_handler` | L860 | static | 否 |
| 10 | `rss_check_cfg_handler` | L903 | static | 否 |
| 11 | `ini_parse_handler` | L935 | static | 否（顶层分发，被 ini_parser 回调）|

**唯一非 static API**：`ff_load_config(int argc, char *const argv[])`（L1347）。

→ **关键约束（写入 R-U-5）**：ff_config.c 的 handler **不能**直接单元测试，必须通过：
- **方案 A（推荐 P0/P1）**：构造 `.ini` 临时文件 + `argv[]` → 调用 `ff_load_config()` → 检查 `ff_global_cfg` 全局结构（端到端黑盒）
- **方案 B（白盒 hack）**：测试时 `#include "ff_config.c"`（hack 方式，可接受作为 P1 增强）
- **方案 C（侵入式，不推荐）**：使 handler 改为非 static（破坏黑盒原则）

### 3.3 ff_ini_parser.c 公开 API（**P0 测试目标**）

来自 `ff_ini_parser.h` L21–48，inih 标准三件套：

```c
typedef int (*ini_handler)(void* user, const char* section,
                           const char* name, const char* value);
typedef char* (*ini_reader)(char* str, int num, void* stream);

int ini_parse(const char* filename, ini_handler handler, void* user);     // L184
int ini_parse_file(FILE* file, ini_handler handler, void* user);          // L178
int ini_parse_stream(ini_reader reader, void* stream,
                     ini_handler handler, void* user);                    // L73
```

返回值约定：`0` 成功；`>0` 首次错误的行号；`-1` 文件打开失败；`-2` 内存分配失败（仅当 `INI_USE_STACK=0`）。

**内部 helper**（全 static，通过 `ini_parse_stream` + 自定义 reader 间接覆盖）：
- `rstrip` (L28), `lskip` (L37), `find_chars_or_comment` (L47), `strncpy0` (L65)

### 3.4 ff_log.c 公开 API（**P0 测试目标**）

来自 `ff_log.c` 实测（**arch-explorer Q5 给出 7 个**，target-prioritizer 计 6 个略偏，以 arch-explorer 为准）：

```c
extern char FF_LOG_FILENAME_PREFIX[];   // 全局常量

int  ff_log_open_set(void);                                 // L48；fopen + 调 ff_log_reset_stream + 2× ff_log_set_level
void ff_log_close(void);                                    // L68；fclose 并置空 ff_global_cfg.log.f
int  ff_log_reset_stream(void *f);                          // L77；rte_openlog_stream(f) 包装
void ff_log_set_global_level(uint32_t level);               // L83；rte_log_set_global_level 包装
int  ff_log_set_level(uint32_t logtype, uint32_t level);    // L89；rte_log_set_level 包装
int  ff_log(uint32_t level, uint32_t logtype,
            const char *format, ...);                        // L95；va_start + rte_vlog + va_end
int  ff_vlog(uint32_t level, uint32_t logtype,
             const char *format, va_list ap);                // L108；rte_vlog 直传
```

**测试要点**：
- **5 个 rte_ 调用全部为 1:1 转发** → 单测须 mock：`rte_openlog_stream` / `rte_log_set_global_level` / `rte_log_set_level` / `rte_vlog`（共 4 个）
- `ff_log_open_set` / `ff_log_close` 依赖全局 `ff_global_cfg`（外部全局变量来自 ff_config.c），fixture 必须构造该 stub
- `ff_log` 变参 → 验证 `va_start/va_end` 配对与返回值透传

---

## 4. 外部依赖统计（11×4 矩阵）

实测 `grep -cE "..."` 命中数（mock-strategist Q1）：

| 文件 (行数) | rte_* | pthread_* | sys 类 | printf 类 |
|---|---:|---:|---:|---:|
| ff_host_interface.c (332) | 6 | 0 | 1 (mmap) | 0 |
| ff_thread.c (51) | 0 | 2 | 0 | 0 |
| ff_config.c (1381) | 7 | 0 | 0 | **56** |
| **ff_ini_parser.c (195)** | **0** | **0** | **0** | **0** |
| ff_dpdk_if.c (2887) | **173** | 0 | 0 | 5 |
| ff_dpdk_pcap.c (137) | 3 | 0 | 0 | 0 |
| ff_epoll.c (159) | 0 | 0 | 0 | 0 |
| ff_log.c (111) | 5 | 0 | 0 | 0 |
| ff_init.c (69) | 0 | 0 | 0 | 0 |
| ff_dpdk_kni.c (536) | 34 | 0 | 0 | 3 |
| ff_memory.c (509) | 24 | 0 | 1 (open) | 1 |

### 4.1 关键观察

1. **零外部依赖文件（最易测，P0 候选）**：`ff_ini_parser.c`（**0/0/0/0**）、`ff_epoll.c`（**0/0/0/0**）、`ff_init.c`（0/0/0/0）— 但 epoll/init 间接依赖 `ff_kqueue/ff_kevent` 等 ff_api stub
2. **rte_ 重灾区**：`ff_dpdk_if.c` 173 + `ff_dpdk_kni.c` 34 + `ff_memory.c` 24 — P2/P3
3. **printf 大户**：`ff_config.c` 56 处（多为错误打印，可保留实调用）

### 4.2 ff_dpdk_if.c 最频繁的 rte_ API（top 5，mock-strategist Q2）

| Rank | rte_ API | 命中 | 主要用途 |
|---|---|---:|---|
| 1 | `rte_exit()` | ~25+ | 错误退出（致命路径，**必 mock**）|
| 2 | `rte_pktmbuf_free()` | ~15 | mbuf 释放 |
| 3 | `rte_eal_process_type()` | 8 | 主备进程判断（控制路径分支，**必 mock**）|
| 4 | `rte_eth_*` 系列 | ~20 | 网卡管理 |
| 5 | `rte_panic()` / `rte_zmalloc()` / `rte_memcpy()` / `rte_ring_*` | 各 5–8 | 致命/内存/环 |

---

## 5. 跨文件依赖矩阵（11×11，仅显示有调用）

行=调用方，列=被调用方（基于 arch-explorer Q6 实测）：

| from \\ to | host_if | thread | config | ini_parse | dpdk_if | dpdk_pcap | epoll | log | init | kni | memory |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **ff_host_interface.c** | — | | | | | | | 1 | | | 2 |
| **ff_thread.c** | 2 | — | | | | | | | | | |
| **ff_config.c** | | | — | 1 | | | | 多 | | | |
| **ff_ini_parser.c** | | | | — | | | | | | | |
| **ff_dpdk_if.c** | 1+extern | | 多 | | — | 1 | | 数十 | | 2+ | 1 |
| **ff_dpdk_pcap.c** | | | | | | — | | | | | |
| **ff_epoll.c** | | | | | | | — | | | | |
| **ff_log.c** | | | 多 | | | | | — (自调用) | | | |
| **ff_init.c** | | | 1 | | 4 | | | | — | | |
| **ff_dpdk_kni.c** | | | 多 | | | | | | | — | |
| **ff_memory.c** | | | 1 | | header 引用 | | | | | | — |

### 5.1 关键观察（用于 mock 优先级）

1. **`ff_log` / `ff_global_cfg` 是公共依赖**：6 个文件（ff_dpdk_if / ff_config / ff_log / ff_dpdk_kni / ff_memory / ff_host_interface）全要它们 → spec 04 §9 必须先建一套 `ff_log_stub.c` + `ff_global_cfg` 静态实例
2. **零外部依赖文件**：`ff_ini_parser.c`（被 ff_config.c 引用，零反向依赖）→ P0 最佳起点
3. **`ff_init.c` 是高层胶水**：3 个公开函数全部转发到 ff_dpdk_*/ff_load_config/ff_freebsd_init → 单测策略"全 mock 下游 + 验证调用顺序"
4. **`ff_dpdk_if.c` 是依赖中心**：调用 6 个其他模块 + 173 个 rte_ → 单测代价最高，仅可拆纯函数子集（4 个候选：`ff_rss_check` / `ff_rss_tbl_get_portrange` / `ff_in_pcbladdr` / `ff_get_tsc_ns`）

---

## 6. 测试目标 P0/P1/P2/P3 分层（**核心 ROI 决策表**）

> 工作量 turns 单位 = spec → impl → 测试通过的迭代轮次估算

| # | 文件 | **优先级** | 行数 | 估计 TC 数 | 工作量 (turns) | mock 复杂度 | ROI 理由 |
|---|---|---|---|---|---|---|---|
| 1 | **ff_ini_parser.c** | **P0** | 195 | 18–22 | 2–3 | **零**（纯 stdlib + FILE\*）| 零 DPDK 依赖、3 公开 API、状态机分支多、临时文件即可全覆盖；最高 ROI |
| 2 | **ff_log.c** | **P0** | 111 | 10–14 | 2 | 低（mock `rte_log/rte_vlog/rte_openlog_stream` 4 符号）| 公开 API 7 个全部可直接调用，`fopen/fclose` 易测；mock 4 rte 符号即可 |
| 3 | **ff_host_interface.c** | **P1** | 332 | 14–18 | 3–4 | 中（mock `rte_malloc/rte_free`，其余 libc）| 11 公开 API、纯进程级工具（pagesize/clock/arc4rand），无主循环依赖 |
| 4 | **ff_epoll.c** | **P1** | 159 | 8–12 | 3 | 中高（需 stub `ff_kqueue/ff_kevent` 等 ff_api 函数）| 3 公开 API + epoll↔kqueue 事件转换是核心业务，转换表完全可测，但 ff_api 依赖需打桩 |
| 5 | **ff_config.c**（端到端 + handler include hack）| **P1** | 1381 | 20–28 | 5–7 | 中（需准备真实 .ini 临时文件 + 部分 stub `rte_strsplit`）| 业务复杂度 4，但只有 1 个公开 API；通过 .ini fixture 端到端能覆盖 ~70%；剩余 handler 用 `#include "ff_config.c"` hack 直接调（白盒）|
| 6 | **ff_thread.c** | **P2** | 51 | 4–6 | 1 | 中（`__thread pcurthread` 注入 + `ff_malloc/ff_free` stub）| 文件极小但 ROI 一般：业务即"传 parent thread 给子线程"，stub 4 符号才能跑；纯包装价值偏低 |
| 7 | **ff_dpdk_pcap.c** | **P2** | 137 | 6–8 | 3 | 中高（mock rte_mbuf 数据结构 + 时间戳）| pcap 文件头格式输出可测，需构造 fake mbuf；价值中等 |
| 8 | **ff_init.c** | **P2** | 69 | 3–4 | 2 | 高（需 stub `ff_load_config/ff_dpdk_init/ff_freebsd_init/ff_dpdk_if_up` 全部）| 业务只有"4 步串行 + exit(1)"，stub 全部依赖后能验证错误传播；ROI 低，但 stub 一旦做好可复用 |
| 9 | **ff_dpdk_if.c** | **P2** | 2887 | 30–50（仅纯函数子集）| 8–12 | **极高**（27 个 rte_ 头 + 主循环 + 硬件状态）| 仅可拆纯函数（`ff_rss_check`/`ff_rss_tbl_get_portrange`/`ff_in_pcbladdr`/`ff_get_tsc_ns`）单测；主初始化/run 路径不可单测 → 留 follow-up |
| 10 | **ff_dpdk_kni.c** | **P2** | 536 | 8–12 | 5–7 | **极高**（KNI 内核模块 + ring + ethdev）| 端口字符串解析 + filter 分发可拆纯函数测；其余依赖内核模块需集成测试 |
| 11 | **ff_memory.c** | **P3** | 509 | — | — | 极高（mmap + virt2phy + ethdev）| **装载条件 `FF_USE_PAGE_ARRAY=1` 默认关闭**；核心 mbuf/物理内存映射黑魔法；除非显式启用，暂不投入 |

### 6.1 分层汇总

- **P0 = 2 文件**（ff_ini_parser.c + ff_log.c）— 立即落地，~4–5 turns，覆盖 3+7 = **10 个公开 API**
- **P1 = 3 文件**（ff_host_interface.c + ff_epoll.c + ff_config.c）— 第二批，~11–14 turns，覆盖 11+3+1 = **15 公开 API**（config 经端到端覆盖 11 handler）
- **P2 = 5 文件**（ff_thread.c + ff_dpdk_pcap.c + ff_init.c + ff_dpdk_if.c + ff_dpdk_kni.c）— follow-up
- **P3 = 1 文件**（ff_memory.c）— 默认关闭，暂不测
- **合计 = 11** ✓

### 6.2 与 plan §1.1 初步分类的差异（重要修订）

| 文件 | plan §1.1 初步 | spec 02 §6 (基于调研) | 调整理由 |
|---|---|---|---|
| **ff_log.c** | P1 | **P0 升** | 公开 API 7 个全可直接调用，仅 mock 4 rte 符号；ROI 比 ff_host_interface.c 高 |
| **ff_config.c** | P0（parser handlers 子集）| **P1 端到端**（不再说 "handlers 子集"）| 11 handler 全 static 不可直接测；必须用 .ini fixture 端到端入口 ff_load_config() |
| **ff_thread.c** | （未列）| **P2** | 51 行小，但 stub 4 符号才能跑；ROI 低 |

---

## 7. 与三层架构 doc 的 anchor

| 11 文件 | 在 docs/01-LAYER1-ARCHITECTURE.md 的位置 | 在 docs/02-LAYER2-INTERFACES.md | 在 docs/03-LAYER3-FUNCTIONS.md |
|---|---|---|---|
| ff_ini_parser.c | L1 lib/ tree 节点 | inih API 接口规约 | 4 公开函数 |
| ff_log.c | L1 lib/ tree 节点 | log API 接口规约 | 7 公开函数 |
| ff_config.c | L1 lib/ tree 节点 | config API 接口规约 | 1 公开 + 11 static handler |
| ff_dpdk_if.c | L1 lib/ tree 节点（核心） | dpdk_if API 接口规约 | ~17 公开 + 大量 static |
| 其余 7 文件 | L1 lib/ tree 节点 | 各自接口规约 | 各自函数清单 |

→ **本任务不动三层架构 doc**；commit 阶段最小化追加 1 行 anchor 到 L1（与 dpdk-23-24 / vlan-test 同款最小 footprint 模式）。

---

## 8. 关键发现汇总（供 spec 04 / 06 参照）

| # | 关键发现 | 影响 |
|---|---|---|
| F1 | ff_config.c 11 handler 全 static | 测试策略 = 端到端 `.ini` fixture（推荐）+ `#include "ff_config.c"` hack（备选）|
| F2 | ff_log.c 5 rte 调用全是 1:1 转发 | mock 模板可复用；fixture 简单 |
| F3 | rte_exit / rte_panic 必须 wrap 否则单测进程被杀 | spec 04 §8 强制规范 |
| F4 | ff_ini_parser.c 是 BSD-licensed inih 第三方代码 | spec 06 §3.1 显式标注"测 F-Stack 集成层 + 状态机覆盖" |
| F5 | ff_global_cfg 是跨文件公共依赖 | spec 04 §9 fixture 模板必须含 `ff_global_cfg` 静态实例 |
| F6 | ff_dpdk_if.c 173 个 rte_ 调用 | spec 04 §7 仅给 P2 纯函数子集 mock 计划；不强求全覆盖 |
| F7 | host 端不直接编译 KERN_SRCS | NFR-U-6 测试 Makefile 不链 `lib/libfstack.a` 整体；仅链被测 .o + stub |
| F8 | f-stack 仓库 0 已有测试痕迹 | 全绿地；无需考虑历史兼容 |

---

**文档结束（v0.1，450 行预算内）**
