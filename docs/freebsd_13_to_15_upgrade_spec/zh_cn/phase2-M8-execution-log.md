# Phase-2 M8 Execution Log — FF_ZC_SEND (P1b)

> 状态：✅ PASS（all gates green，1 bounce 内修复完成）
> 日期：2026-06-08
> 上游基础：M7 commit `cba3d882b` (FF_USE_PAGE_ARRAY)

---

## 1. 摘要

启用 `FF_ZC_SEND=1`（默认 `FF_USE_PAGE_ARRAY=0`，独立验证 ZC 路径）。M8 在 G2/G3 出现一次 bounce，调试发现的根因比初期 spec §5 风险更复杂 —— **不只是用户态/内核态宏对齐问题，而是 13.0 baseline 遗留的 ZC fast-path 设计本身存在 3 个共同失效点**：

1. ZC fast-path 判断条件过宽（`UIO_SYSSPACE && UIO_WRITE` 命中所有 `ff_write` 调用 → 普通 char buffer 被误当 mbuf）
2. 缺少专用 ZC 入口（`ff_write` 不能区分 mbuf 指针 vs char 数组）
3. `dofilewrite` 强行覆盖 `auio->uio_offset = offset` → 即使 caller 设了 sentinel 也会丢失

**修复**：引入 `FSTACK_ZC_MAGIC` sentinel 协议 + 新 `ff_zc_send` 公开 API + `dofilewrite` 保留 ZC sentinel + 普通 `ff_write/ff_writev` 显式 `uio_offset=0` 防误命中。

---

## 2. 改动清单

### 2.1 内核侧（freebsd/）

| 文件 | 改动 | 行数 |
|---|---|---|
| `freebsd/sys/mbuf.h` | 新增 `FSTACK_ZC_MAGIC` 宏（值 `0xF8AC2C00F8AC2C00`） | +13 |
| `freebsd/kern/uipc_mbuf.c` | `m_uiotombuf` ZC fast-path 新增 `uio_offset == FSTACK_ZC_MAGIC` 谓词 | +12 / -2 |
| `freebsd/kern/sys_generic.c` | `dofilewrite` 在 `auio->uio_offset == FSTACK_ZC_MAGIC` 时跳过覆盖 + include `sys/mbuf.h` | +12 / -1 |

### 2.2 lib 侧

| 文件 | 改动 | 行数 |
|---|---|---|
| `lib/Makefile` | `FF_ZC_SEND=1`（取消注释） | +1 / -1 |
| `lib/ff_syscall_wrapper.c` | 新增 `ff_zc_send` API + `ff_write/ff_writev` 显式设 `uio_offset=0` + include `sys/mbuf.h` | +35 / 0 |
| `lib/ff_api.h` | 声明 `ff_zc_send` + 用法说明 | +10 |
| `lib/ff_api.symlist` | 把 `ff_zc_send` 加入导出符号白名单 | +1 |

### 2.3 example 侧

| 文件 | 改动 |
|---|---|
| `example/Makefile` | helloworld_zc target 加 `-DFSTACK_ZC_SEND` |
| `example/main_zc.c` | line 215 `ff_write` → `ff_zc_send` + 顶部 extern 声明 |

**总计 8 文件 +85/-4**

---

## 3. RCA 演进

### Bounce #1 — 起始假设：用户态宏漏传

helloworld_zc 起栈正常但单次 curl 即触发 GPF（IP `0x10facb6` = `m_demote+0x36`）。gdb 抓 coredump 显示 `rbx = 0x312e312f50545448` ASCII = `"HTTP/1.1"` —— `iov_base` 指向 HTML 字符串被 fast-path 当 mbuf 指针。

第一次假设：`example/Makefile` 编译 helloworld_zc 时漏传 `-DFSTACK_ZC_SEND`，使 `main_zc.c:225` 走 `#else` 分支用 `ff_write(html_buf, ...)`。补丁后 build PASS，**但单次 curl 仍崩**（GPF 同地址）。

### Bounce #1 cont. — baseline 也崩

发现关键证据：纯 baseline `helloworld` (用 main.c + 普通 `ff_write(html, len)`) **同样在 100x 短连压测中段 GPF**。说明 lib 内的 ZC fast-path 谓词命中范围太宽 —— `ff_write` 内部设 `auio.uio_segflg = UIO_SYSSPACE` 后 `kern_writev → dofilewrite → fo_write → sosend → m_uiotombuf` 必触发 fast-path，把 char buffer 当 mbuf 解析。

### Bounce #1 cont. — 引入 sentinel

设计 `FSTACK_ZC_MAGIC` (`0xF8AC2C00F8AC2C00`) sentinel 写入 `uio->uio_offset`，fast-path 增 `uio_offset == FSTACK_ZC_MAGIC` 谓词。普通 `ff_write/ff_writev` 显式设 `uio_offset = 0` opt-out。同步新增 `ff_zc_send` 专用入口（main_zc.c:215 改用之），保持 `ff_write` 公共 API 语义不变。

### Bounce #1 cont. — debug 揭示 dofilewrite 丢 sentinel

新版本起栈测试，单次 curl 收到 649 bytes 但**全是 mbuf header 内存**（`m_data` 指针 + 大量 0x00），不是 HTML 字符串。primary 不崩但 payload 错乱。

加 printf debug 在 `ff_zc_send` 与 fast-path 入口：
- `[ZC] ff_zc_send: fd=1027 mb=0x7ffff78e1c00 nbytes=649` — caller mbuf 正确（m_data ASCII = "HTTP/1.1 200 OK..Server: F-Stack" ✓）
- `[ZC-FP]` debug **完全没出现** → fast-path 没触发

读 `freebsd/kern/sys_generic.c:559` —— `dofilewrite` 强行 `auio->uio_offset = offset`，而 `kern_writev` 传入 `offset = (off_t)-1`，**sentinel 在到达 `m_uiotombuf` 前已被覆盖为 -1**。补丁 `sys_generic.c` 在 sentinel 已存在时跳过覆盖，重测：
- `[ZC-FP] enter: m=0x7ffff78e1c00 total=649` ✓ fast-path 命中
- HTTP/1.1 200 OK + Content-Length: 438 + 真实 HTML body ✓ ✓ ✓

### Bounce 计数

| # | 阶段 | 触发原因 | 修复 |
|---|---|---|---|
| 1 | gate→code | helloworld_zc 单次 curl GPF + baseline 100x 也 GPF + payload 错乱 | 3 处源码 + sentinel 协议 + ff_zc_send 新 API（合并为单次 bounce） |

打回计数 **1/3**（plan §6 限额），**未 escalation**。

---

## 4. Gate 实测结果

### G1 — 编译

| 子项 | 结果 |
|---|---|
| `lib/ make clean && make` | exit=0 / 0 errors / 57 warnings (= M6/M7 baseline) |
| `libfstack.a` 大小 | 6.55 MB |
| `example/ make` | exit=0 / 3 binaries (helloworld 29.02 / _epoll 29.02 / _zc 29.03) |
| `nm libfstack.a \| grep ff_zc_send` | `T ff_zc_send`（全局导出） |

### G2 — 主程序冒烟

| 子项 | 结果 |
|---|---|
| primary 起栈 12s ALIVE | ✓ |
| 关键日志 | `ipfw2 (+ipv6) initialized` / `tcp_bbr is now available` / `f-stack-0: Successed to register dpdk interface` |
| SIGSEGV / panic / stub-called | 0 |

### G3 — 功能验收

| 子项 | 结果 |
|---|---|
| G3.2 单次 curl `--http0.9 -sS http://9.134.214.176/` | HTTP 200 / Content-Length 438 / body = 真 HTML |
| body 验证 | hexdump 前 80 字节 = `<!DOCTYPE html>\r\n<html>\r\n<head>\r\n<title>Welcome to F-Stack!</title>\r\n<style>...` ✓ |
| G3.3 100x 短连压测 | ok=100 fail=0 ✓ |
| baseline non-ZC（helloworld）100x 压测 | ok=100 fail=0 ✓（M8 修复同时治好该回归） |
| primary 退出 | 干净 SIGTERM（5s 内退出，无 SIGKILL） |

### G4 — 简易性能 observation（OQ-2 默认许可降级）

| build | 1000 短连耗时 | 推算 conn/s |
|---|---|---|
| helloworld (baseline non-ZC) | 6.884s | ~145 |
| helloworld_zc (FF_ZC_SEND) | 6.768s | ~148 |

差异在测量噪声范围内（client 端 curl 串行 + ssh round-trip 占主导）。完整性能基线推迟到 M9 PA+ZC combo 与 phase-5b 方法学复用时进行。

### G5 — 文档

`phase2-M8-spec.md` + `phase2-M8-execution-log.md` 完整；docs/01-LAYER1-ARCHITECTURE.md + Summary 双语 anchor 同 M6/M7 模式。

### G6 — Lint

0 errors（read_lints 全清）。

### G7 — Commit

本地英文 commit，不 push（per 规约）。

---

## 5. 设计契约（生效到 M9 之后）

```
                   user-space                    libfstack
   ff_zc_mbuf_get -+
                  |--- 构造 mbuf chain (m_getm2, M_WAITOK, MT_DATA, flags=0)
   ff_zc_mbuf_write
                  |--- 填充 mbuf m_dat + 累加 m_len
                  v
   ff_zc_send(fd, mbuf, len)
                  |--- aiov.iov_base = mbuf
                  |--- auio.uio_segflg = UIO_SYSSPACE
                  |--- auio.uio_offset = FSTACK_ZC_MAGIC  <-- 关键 sentinel
                  v
   kern_writev → dofilewrite (kept FSTACK_ZC_MAGIC) → fo_write → sosend
                  → m_uiotombuf (FSTACK_ZC_SEND fast-path 命中)
                  → 直接返回 caller mbuf chain，跳过 copy 循环
                  → tcp_usr_send → sbappendstream → tcp_output → DPDK TX

   普通 ff_write / ff_writev 同样路径，但 uio_offset = 0 不命中 fast-path，
   走 m_getm2 + uiomove copy loop（旧行为）。

   ff_send / ff_sendto / ff_sendmsg 走 sendit → kern_sendit，后者已显式
   设 uio_offset = 0，不会误命中 fast-path。
```

---

## 6. 已知遗留与 follow-up

| 项 | 描述 | 计划 |
|---|---|---|
| **F1**（信息性，非阻塞） | 当前 G4 性能由 ssh round-trip + curl 串行主导，无法体现 ZC vs 非 ZC 真实差异 | M9 复用 phase-5b CVM A/B + 物理机方法学，wrk/iperf 大并发对比 |
| **F2**（已解决） | M7 baseline 测试同样可能因 ZC fast-path 误命中崩溃，但因 M7 时未压测 1000 conn 而未暴露 | M8 修复同时治好（baseline 100x 已验证） |
| **F3** | M9 PA+ZC combo 是否有交叉问题尚需验证 | M9 单独 spec |

---

## 7. Phase 进度

| Phase | 状态 |
|---|---|
| A. Spec | ✅ |
| B. Research | ✅ |
| C. Code v1（仅 Makefile） | ✅ → bounce |
| C. Code v2（sentinel + new API + 6 files） | ✅ |
| D. Review | ✅（self review，0 lint） |
| E. Gate | ✅ G1-G7 全 PASS |

**M8 整体：✅ PASS**
