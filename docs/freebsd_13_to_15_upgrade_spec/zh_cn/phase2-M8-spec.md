# M8 Spec — FF_ZC_SEND (P1b)

> Spec 版本：v0.1（2026-06-08）  
> 父计划：`phase2-feature-enable-plan.md` v0.1  
> 前置 milestone：M7 已 commit `cba3d882b`（feature/1.26 ahead 15）  
> M7 baseline：libfstack.a 6.55 MB / 0 errors / 57 warnings / `ff_mmap_init mmap 65536 pages, 256 MB.`

---

## 1. 范围

### 1.1 In scope

| 项 | 说明 |
|---|---|
| 启用 `FF_ZC_SEND=1` | `lib/Makefile:47` 取消注释（实际宏是 `-DFSTACK_ZC_SEND`） |
| **关闭 `FF_USE_PAGE_ARRAY`** | M8 单独验证 ZC（M9 做 combo） |
| 扩展 `example/Makefile` | 新增 `helloworld_zc` target，编译 main_zc.c |
| 编译通过 | `lib && make all` exit=0；`example && make` 产出 helloworld + helloworld_epoll + **helloworld_zc** |
| 主程序冒烟 | helloworld_zc 起栈 ≥10s 不崩 |
| 客户端联动测试 | 从 `f-stack-client` (9.134.211.87) curl/wrk → server (9.134.214.176:80)，至少完成 1 次完整 HTTP 200 响应 |
| 简单性能观察 | 短连 100 次 + 长连 30s，对比 helloworld vs helloworld_zc（同条件） |
| 文档同步 + commit | 局部 docs；本地 commit；不 push |

### 1.2 Out of scope

- FF_USE_PAGE_ARRAY combo（M9）
- 完整 perf baseline（M9 综合做）
- ZC read 路径（`ff_zc_mbuf_read` 当前注释 `/* DOTO: Support read zero copy */` 即未实现，server 端只测 ZC write/send）

---

## 2. 背景与现状（实测）

### 2.1 控制点

```
lib/Makefile:47   #FF_ZC_SEND=1                ← 取消注释
lib/Makefile:204  ifdef FF_ZC_SEND
lib/Makefile:205  CFLAGS+= -DFSTACK_ZC_SEND     ← 注意宏名 FSTACK_ZC_SEND（非 FF_ZC_SEND）
```

### 2.2 ZC API（`lib/ff_api.h:347-380` + `lib/ff_veth.c:306-360`）

| API | 用途 |
|---|---|
| `struct ff_zc_mbuf { bsd_mbuf, bsd_mbuf_off, off, len }` | ZC mbuf chain handle |
| `int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len)` | 申请 mbuf chain（`m_getm2(NULL, len, M_WAITOK, MT_DATA, 0)`） |
| `int ff_zc_mbuf_write(struct ff_zc_mbuf *zm, const char *data, int len)` | 写入数据（多次调用累计） |
| `int ff_zc_mbuf_read(struct ff_zc_mbuf *m, ...)` | 当前为 `return 0` stub（未实现，**out of scope**） |

ZC 实现**独立于** FF_USE_PAGE_ARRAY，无 ifdef 交叉依赖。

### 2.3 client/server 拓扑（用户已配置）

| 角色 | 主机 | IP | OS |
|---|---|---|---|
| server (本机) | 当前 | 9.134.214.176 | Linux + DPDK + f-stack | 
| client | f-stack-client (ssh hostname) | 9.134.211.87 | Linux 6.6 TencentOS |

### 2.4 example/Makefile 现状

```makefile
TARGET="helloworld"
all:
	cc ${CFLAGS} -DINET6 -o ${TARGET} main.c ${LIBS}
	cc ${CFLAGS} -o ${TARGET}_epoll main_epoll.c ${LIBS}
```

**缺 helloworld_zc target**，需扩展（M8 in-scope）。

---

## 3. 改动

### 3.1 `lib/Makefile`（2 行）

```diff
-FF_USE_PAGE_ARRAY=1                  # M7 enabled, M8 must disable
-#FF_ZC_SEND=1
+#FF_USE_PAGE_ARRAY=1                 # M8: disable for isolated ZC verification (M9 will combo)
+FF_ZC_SEND=1
```

### 3.2 `example/Makefile`（+1 行 target）

```diff
 all:
 	cc ${CFLAGS} -DINET6 -o ${TARGET} main.c ${LIBS}
 	cc ${CFLAGS} -o ${TARGET}_epoll main_epoll.c ${LIBS}
+	cc ${CFLAGS} -DINET6 -o ${TARGET}_zc main_zc.c ${LIBS}
```

### 3.3 其他源代码

**默认不改动**。若 G1 失败，按 R-M8-1/M8-2 修复。

---

## 4. 验收标准（G1-G7）

### G1 — 编译
| AC | 阈值 |
|---|---|
| G1.1 lib `make all` | exit=0 / 0 errors / warnings ≤ 62 |
| G1.2 libfstack.a | 与 M7 6.55 MB ±5% |
| G1.3 example `make` | exit=0；产出 helloworld + helloworld_epoll + **helloworld_zc** 三个二进制 |

### G2 — 主程序冒烟
| AC | 测试 |
|---|---|
| G2.1 | helloworld_zc 起栈 ≥10s ALIVE，0 SIGSEGV/panic |
| G2.2 | log 无 "stub called" / "FATAL" 关键词 |

### G3 — 客户端联动 HTTP 测试（OQ-1 default：用户提供 client）
| AC | 命令（在 server 侧编排） | 通过 |
|---|---|---|
| G3.1 | server 启动 helloworld_zc primary（监听 [port0] addr 9.134.214.176:80） | bind 成功，log 显示 listen |
| G3.2 | `ssh f-stack-client 'curl -sS -o /dev/null -w "%{http_code} %{size_download}\n" --connect-timeout 5 http://9.134.214.176/'` | HTTP 200 + body size > 0 |
| G3.3 | `ssh f-stack-client 'for i in $(seq 1 100); do curl -sS -o /dev/null --connect-timeout 5 http://9.134.214.176/; done; echo done'` 100 次短连 | 100 次成功，无 timeout/connection refused |

### G4 — 简单性能观察（OQ-2 降级许可）
| AC | 方法 |
|---|---|
| G4.1 | 短连：客户端 `time { for i in $(seq 1 1000); do curl ...; done; }`（helloworld vs helloworld_zc）| 记录 wall time，对比 ZC vs 默认 |
| G4.2 | 长连：客户端 `wrk -t1 -c10 -d10s http://9.134.214.176/`（如 wrk 可用），否则 ab，最不济 curl loop | 记录 rps |

### G5 — 文档同步（局部）
- docs/01-LAYER1 + zh_cn 镜像：M8 注脚
- docs/Summary + zh_cn：scope 标签 + M8
- 本里程碑 execution-log

### G6 — Lint：0 errors  
### G7 — Commit：本地英文 commit，不 push

---

## 5. 风险

| ID | 风险 | 缓解 |
|---|---|---|
| **R-M8-1** | `m_getm2` 在 14.0+ 是否签名变更 | grep `freebsd-src-releng-15.0/sys/sys/mbuf.h` 确认；目前 lib 已编译 OK 推断兼容 |
| **R-M8-2** | f-stack-client → server 路由不通（不同 VPC 子网） | 实测 ssh ok 但跨 ARP/路由层不一定通；G3.2 实测 + 必要时调 ARP |
| **R-M8-3** | DPDK runtime 残留（M7 SIGTERM 干净退出但残文件可能） | 启动前 rm_tmp_file.sh 清 /var/run/dpdk/rte/* |
| **R-M8-4** | port[0].addr 配置不匹配 9.134.214.176（用户机器 IP） | 实测 config.ini 已设 9.134.214.176（user runtime） |
| **R-M8-5** | helloworld_zc bind 80 端口需 root + ARP gratuitous | sudo + helloworld_zc 自带 dpdk_if 应自动发 ARP |

---

## 6. Phase 进度

| Phase | 状态 |
|---|---|
| A. Spec（本文档） | ✅ |
| B. Research | 合并入 §2 |
| C. Code | ✅ v1（启用 FF_ZC_SEND） |
| D. Review | ⏭ |
| E. Gate v1 | ⚠ G2 FAIL → bounce(gate→code) #1 |
| C. Code v2（M8 真根因修复，见 §7） | ⏭ |
| E. Gate v2 | ⏭ |

---

## 7. RCA — Bounce #1 根因 & 修复（2026-06-08 15:30）

### 7.1 现象

helloworld_zc 起栈 init 完整（ipfw2/tcp_bbr/dpdk if registered），但**单次 client 端 curl 即触发 GPF 崩溃**：

```
dmesg: traps: helloworld_zc[1623044] general protection fault ip:10facb6 sp:7fffffffdae0
```

idle 状态 42s 不崩，**仅在数据包到达时崩**。

### 7.2 gdb 调用栈（coredump `core.helloworld_zc.1623044.1780903615`）

```
#0  0x10facb6 in m_demote ()         <-- mov 0x1c(%rbx),%ecx；rbx 是无效指针
#1  0x11069f4 in sbappendstream ()
#2  0x124674e in tcp_usr_send ()
#3  0x111175f in sosend_generic ()
#4  0x1111a06 in sousrsend ()
#5  0x10f3b42 in kern_writev ()
#6  0x1061c08 in ff_write ()
#7  0x064aff5 in loop (arg=...) at main_zc.c:225  <-- #else 分支
```

**关键寄存器**：`rbx = 0x312e312f50545448` → ASCII = "HTTP/1.1"（little-endian 字节序：`48 54 54 50 2f 31 2e 31`）。即 `m_demote` 跟随 mbuf 链 `m_next` 时落入 `html_buf` char 数组本身。

### 7.3 根因（file:line 引用）

`freebsd/kern/uipc_mbuf.c:2028-2037` 是 F-Stack **原生** ZC fast path 设计（13.0 baseline 同代码 — 见 `f-stack-13.0-baseline/freebsd/kern/uipc_mbuf.c:1776`，与 13→15 升级**无关**）：

```c
2028: #ifdef FSTACK_ZC_SEND
2029:     if (uio->uio_segflg == UIO_SYSSPACE && uio->uio_rw == UIO_WRITE) {
2030:         m = (struct mbuf *)uio->uio_iov->iov_base;  // ← 直接当 mbuf
2031:         uio->uio_iov->iov_base = (char *)(uio->uio_iov->iov_base) + total;
2032:         ...
2036:     } else {
2037: #endif
```

**契约**：当 lib 编了 `FSTACK_ZC_SEND` 后，**所有** `ff_write` 调用必须传 mbuf 指针（即 caller 必须先 `ff_zc_mbuf_get` + `ff_zc_mbuf_write`）；普通 char buffer 不再被 lib 接受。

**bug 触发链**：
1. `lib/Makefile:204-205` 启用 `-DFSTACK_ZC_SEND` → libfstack.a 内 `m_uiotombuf` 进入上面的 fast path。
2. `example/Makefile:21` 编译 `helloworld_zc` 时 **未传 -DFSTACK_ZC_SEND** → `main_zc.c:183` 的 `#ifdef FSTACK_ZC_SEND` 不成立 → `main_zc.c:225` 走 `#else` 用 `ff_write(clientfd, html_buf, buf_len)`，`html_buf` 是普通 char 数组。
3. lib 内 `m_uiotombuf` 把 `iov_base = html_buf` 当 mbuf 指针 → `m_demote` 解析 `html_buf` 内 ASCII 文本（"HTTP/1.1...") 为 `m_next` → 寻 `0x102cfdf84` 不存在的地址 → GPF。

### 7.4 修复方案（最小 diff）

**仅一处**：`example/Makefile` line 21 加 `-DFSTACK_ZC_SEND`。

```diff
- cc ${CFLAGS} -DINET6 -o ${TARGET}_zc main_zc.c ${LIBS}
+ cc ${CFLAGS} -DINET6 -DFSTACK_ZC_SEND -o ${TARGET}_zc main_zc.c ${LIBS}
```

**无需** lib/ 改动 — 与 M6 user-space ip_fw.h ABI 同步同构（user/kernel 宏一致性）。

### 7.5 与 M9 的耦合性

M9 同时启用 PA + ZC 时**仍需此修复**——`main_zc.c` 与 `m_uiotombuf` 的宏契约独立于 PA。

---

> 下一步：Phase C v2 — coder 在 example/Makefile 加 `-DFSTACK_ZC_SEND`，重编 helloworld_zc，重跑 G1-G7。
