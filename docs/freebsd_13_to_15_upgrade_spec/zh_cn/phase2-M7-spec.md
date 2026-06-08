# M7 Spec — FF_USE_PAGE_ARRAY (P1a)

> Spec 版本：v0.1（2026-06-08）  
> 父计划：`phase2-feature-enable-plan.md` v0.1  
> 前置 milestone：M6 已 commit `4139198f6`（feature/1.26 ahead 14）  
> M5 baseline：libfstack.a 5.4 MB / 0 errors / 55 warnings  
> M6 baseline：libfstack.a 6.5 MB / 0 errors / 57 warnings（M7 G1.3 阈值 = 57+5 = 62）

---

## 1. 范围

### 1.1 In scope

| 项 | 说明 |
|---|---|
| 启用 `FF_USE_PAGE_ARRAY=1` | `lib/Makefile:46` 取消注释 |
| **保持 `FF_ZC_SEND` 关闭** | 单独验证 page-array 路径；FF_ZC_SEND 留给 M8 |
| 编译通过 | `lib && make all` exit=0；warnings ≤ 62（M6+5） |
| 主程序冒烟 | `helloworld` 起栈 ≥10s 不崩；log 含 `ff_init_ref_pool` / `ff_mmap_init` 成功痕迹 |
| 简单 curl 验证 | helloworld_epoll 监听 80 端口；本机 curl 通过 page-array 路径不崩 |
| 性能基线（G4 必做） | nginx_fstack 4 核短连/长连，与 M6 baseline 对比 trade-off ≤ 5%；超标转 observation（不阻塞，与 Phase-5b OQ 处理一致） |
| 文档同步（局部） | docs/01-LAYER1 + Summary 增 M7 注脚 |
| 本地 commit | 英文 message，不 push |

### 1.2 Out of scope

| 项 | 理由 |
|---|---|
| FF_ZC_SEND combo | M8/M9 task |
| ff_memory.c 内部重构 | 仅 enable，不改实现 |
| KG 重跑 | M-Final |

---

## 2. 背景与现状（实测）

### 2.1 lib/Makefile 控制点

```
:46   #FF_USE_PAGE_ARRAY=1                ← 取消注释
:113  ifdef FF_USE_PAGE_ARRAY (host CFLAGS)
:114    HOST_CFLAGS+= -DFF_USE_PAGE_ARRAY
:288  ifdef FF_USE_PAGE_ARRAY
:290    FF_HOST_SRCS += ff_memory.c
```

### 2.2 涉及源代码（实测）

| 文件 | 行数 | 角色 |
|---|---|---|
| `lib/ff_memory.c` | 481 | mmap-based page array 与 mbuf reference pool 实现 |
| `lib/ff_memory.h` | ~115 | 4 个 API 声明（FF_USE_PAGE_ARRAY guarded） |
| `lib/ff_dpdk_if.c` | — | 5 处 `#ifdef FF_USE_PAGE_ARRAY` 分支（init/TX/error path） |
| `lib/ff_host_interface.c` | — | 2 处分支（ff_mmap/ff_munmap 4 KB 页特殊路径走 page array） |

### 2.3 公开 API（已声明在 ff_memory.h 内 FF_USE_PAGE_ARRAY 块）

| API | 用途 |
|---|---|
| `ff_init_ref_pool(int nb_mbuf, int socketid)` | 初始化 mbuf reference pool（init 时调用） |
| `ff_mmap_init()` | 初始化 mmap page array（init 时调用） |
| `ff_if_send_onepkt(ctx, m, total)` | TX 单包发送（替代 `ff_dpdk_if_send` 在 FF_USE_PAGE_ARRAY 模式下的实现） |
| `ff_enq_tx_bsdmbuf(portid, p_mbuf, nb_segs)` | 入队 BSD mbuf（TX 完成后异步释放） |
| `ff_mem_get_page()` / `ff_mem_free_addr(addr)` | 4 KB 页快速分配/释放（在 ff_memory.c 内部实现，不在 ff_memory.h 暴露） |

### 2.4 性能动机（README + 历史 commit 推断；可在 research 阶段交叉验证）

减少 mbuf alloc/free 与 mmap/munmap(4 KB) 的 syscall 开销；TX 路径用 reference pool 实现 zero-copy 思路（ZC_SEND 是更彻底版本，M8 处理）。

---

## 3. 接口与代码改动

### 3.1 lib/Makefile 改动（1 行）

```diff
-#FF_USE_PAGE_ARRAY=1
+FF_USE_PAGE_ARRAY=1
```

### 3.2 其它源文件改动

**默认不改动**。若 G1 失败（undefined ref），按 R-M7-1/R-M7-2 修复。

---

## 4. 验收标准（G1-G7）

### G1 — 编译

| AC | 阈值 | 测试 |
|---|---|---|
| G1.1 | exit=0 | `cd lib && make clean && make all` |
| G1.2 | errors=0 | `grep -ic 'error:'` |
| G1.3 | warnings ≤ 62 | `grep -ic 'warning'`（M6=57，allow +5） |
| G1.4 | libfstack.a size | 与 M6（6.5 MB）±5%（page-array 仅加 ff_memory.o ~30 KB） |
| G1.5 | helloworld 链接成功 | `cd example && make` exit=0 |

### G2 — 主程序冒烟

| AC | 测试 | 通过 |
|---|---|---|
| G2.1 | helloworld 后台 ≥10s ALIVE | `[ -d /proc/$PID ]` |
| G2.2 | log 0 SIGSEGV/panic/stub-called | `grep -iE 'sigsegv\|panic\|stub called'` |
| G2.3 | log 含 page-array 初始化痕迹 | `grep -iE 'ref_pool\|mmap_init\|page'` 或非 panic 即可 |

### G3 — 简单功能（curl 测试）

| AC | 测试 | 通过 |
|---|---|---|
| G3.1 | helloworld_epoll 编译并起栈监听 80 | helloworld_epoll PID alive |
| G3.2 | 本机 curl `localhost`（或配置 IP）|  HTTP 200 OR 至少不崩 helloworld_epoll；关心点是 page-array TX 路径不崩 |
| G3.3 降级 | 若 helloworld_epoll/curl 路径因环境（无 80 端口监听绑定）失败，降级为：仅看 helloworld 主程序 polling 30 秒不崩，认为 G3 PASS+observation | OQ-4 默认许可 |

### G4 — 性能基线

| AC | 测试 | 通过条件 |
|---|---|---|
| G4.1 | 性能脚本可用 | `tools/sbin/m5_perf.sh` 已就位（Phase-5b 沿用） |
| G4.2 | M6 vs M7 短连接 rps trade-off | ≤ 5%（超过转 observation） |
| G4.3 | M6 vs M7 长连接 goodput trade-off | ≤ 5% |
| G4.4 降级 | 若环境不允许跑性能（CVM/网络限制），降级为：仅记录 M6→M7 在合成 traffic 下的 1 分钟稳定性观察 | OQ-2 默认许可 |

### G5 — 文档同步（局部）

| AC | 文件 |
|---|---|
| G5.1 | docs/01-LAYER1 + zh_cn 镜像：M7 注脚 |
| G5.2 | docs/Summary + zh_cn：scope 标签 + M7 |
| G5.3 | phase2-M7-execution-log.md（本里程碑产出） |

### G6 — Lint
`read_lints docs/ + lib/` 0 errors。

### G7 — Commit
本地英文 commit；不 push。

---

## 5. 风险

| ID | 风险 | 缓解 |
|---|---|---|
| **R-M7-1** | ff_memory.c 在 14.0+ ABI 下可能引用已删除/改名的 mbuf 域（如 m_ext, m_extadd 旧用法） | G1 失败时打 stub 或最小 patch；reviewer 比对 freebsd-src-releng-15.0/sys/sys/mbuf.h |
| **R-M7-2** | DPDK 23.11.5 mbuf API 与 ff_memory.c 旧用法（pktmbuf_init / mempool） 不兼容 | grep `rte_mbuf_init\|rte_mempool_create` 在 ff_memory.c |
| **R-M7-3** | helloworld_epoll 二进制 stale（使用旧 libfstack.a 链接） | example/make 强制重链 |
| **R-M7-4** | 性能 trade-off > 5% | observation 标签，由用户决策（plan §8 OQ-2 默认许可） |
| **R-M7-5** | DPDK runtime 残留导致 helloworld 启动失败 | 启动前 rm_tmp_file.sh 清理 /var/run/dpdk/rte/* |

---

## 6. Phase 进度

| Phase | 状态 |
|---|---|
| A. Spec（本文档） | ✅ DRAFT |
| B. Research | 跳过（合并入 §2） |
| C. Code | ⏭ |
| D. Review | ⏭ |
| E. Gate | ⏭ |

---

> 下一步：Phase C — coder 执行 `lib/Makefile:46` 1 行 diff，触发 G1-G7。
