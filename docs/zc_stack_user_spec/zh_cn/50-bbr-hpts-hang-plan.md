# 50. nginx_fstack + BBR 大文件下载偶发 hang —— 排查与修复 plan

> 现象：测试机 f-stack-client 执行 `curl -v http://f-stack2/database.db --output /dev/null`（多次），**偶发 hang 无法下载完成**。
> nginx_fstack 运行于本机（PID 969652/969653，/usr/local/nginx_fstack），开启 BBR。
> 方法：实测优先、代码为准、交叉验证、外网佐证；rm/kill/chmod 一律走 /data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh；commit message 简短英文。

---

## §0 Phase-0 实测侦察结论（已完成，代码/配置/日志为准）

### 0.1 运行环境（实测）
- nginx_fstack 用 `/usr/local/nginx_fstack/conf/f-stack.conf`：`hz=1000000`（✓ 符合 BBR 要求）、`net.inet.tcp.functions_default=bbr`（**这是"开启 BBR"**）、`net.inet.tcp.hpts.skip_swi=1`、`net.inet.tcp.hpts.minsleep=250`、`net.inet.tcp.cc.algorithm=cubic`。
- 下载对象 `/usr/local/nginx_fstack/html/database.db` = **151904256 字节（≈145MB 大文件）**；nginx 监听 `9.134.214.176:80`。
- 本机经 eth1 可达 9.134.214.176（同 helloworld 验证路径）。

### 0.2 根因证据链（实测交叉验证，多源一致）
1. **f-stack swi 全是 no-op 桩**：`lib/ff_kern_intr.c` 的 `swi_add`/`swi_sched`/`swi_remove` 空实现、`intr_event_bind` 返回 EOPNOTSUPP。
2. **15.0 hpts 依赖 swi 唤醒**：`freebsd/netinet/tcp_hpts.c:528/538 swi_sched(hpts->ie_cookie,0)` 唤醒 hpts swi 线程干活 → f-stack 下 swi_sched 空操作 → **hpts swi 线程永不运行**。
3. **15.0 另一驱动 `tcp_hpts_softclock()` 在 f-stack 主循环未被调用**：全 `lib/` 仅 `ff_stub_14_extra.c:627` 定义指针=NULL；真正调用点只在 `freebsd/kern/subr_trap.c:143 userret()`（f-stack run-to-completion **无 userret**）与 `tcp_lro.c:1261`。主循环 `lib/ff_dpdk_if.c` 不驱动 hpts。
4. **13.0 的 skip_swi 直驱机制在 15.0 丢失**：13.0 baseline `tcp_hpts.c` 有 `tcp_hpts_callout_skip_swi`（FSTACK 默认=1）+ sysctl 节点 + L1030/1856/1998 直驱逻辑；当前 15.0 树 **grep skip_swi = 0 命中**（机制未移植）。
5. **启动日志 + runtime-fix 文档佐证**：`net.inet.tcp.hpts.skip_swi=1 error:2`（节点未注册→config 意图被静默忽略）；runtime-fix 文档 L123 当时判定"非致命"，仅验收 ifconfig/netstat/基础 curl，**未测大文件 BBR**。
6. **git 历史直接命中**：`ae7ea12bc` "rack works correctly, but **bbr still has some problems when transferring large files**"；`e592cbbfe` hz 须=1e6（已满足）；`7bc94688f` bbr cwnd 参数序修复（已在 HEAD）。
7. **外网佐证**：F-Stack 1.22 release "RACK/BBR **significantly improves large file transfer (>10x) in high latency/loss**，依赖 HPTS"——BBR 正是大文件场景且依赖 HPTS。

### 0.3 根因结论（高置信度，待复现+修复闭环确认）
13→15 升级时，f-stack 特有的 HPTS 驱动适配（13.0 的 `skip_swi=1` 直驱）**未移植到 15.0**；而 15.0 hpts 的两条驱动路径在 f-stack 下均失效（swi_sched no-op + 主循环未调 `tcp_hpts_softclock`）。BBR 依赖 HPTS 做 µs 级 pacing：cwnd-limited 小响应可由常规 tcp_output 直发（curl 小文件/helloworld 正常），但**大文件进入 BBR pacing 阶段后，待发包被挂到 hpts 等待 pacing 定时，而 hpts 不被驱动 → paced 包不发出 → 连接 stall → curl hang**。偶发性源于是否进入 pacing、ACK 时序与 cwnd 状态。

---

## §1 修复设计（FreeBSD-15 原生 soft-timer 驱动）

15.0 提供 `tcp_hpts_softclock()` 软定时器机制（`sys/systm.h:410` 宏，**null 安全**：`hpts_that_need_softclock>0` 才调用函数指针 `__tcp_run_hpts`）。FreeBSD 在 userret 调用它以高效驱动 hpts。f-stack 无 userret，应**在主循环调用**它——这正是丢失的驱动，且替代 13.0 skip_swi。

### 实现（仿 `ff_hardclock` extern 模式；ff_dpdk_if.c 为 host/DPDK 编译模式，不能直接 include 内核头）
1. **内核态封装**（`lib/ff_kern_timeout.c`，已含 `<sys/systm.h>`，`ff_hardclock` 同文件 `#ifdef FSTACK`）：新增
   ```c
   void ff_tcp_hpts_softclock(void);
   void ff_tcp_hpts_softclock(void) { tcp_hpts_softclock(); }
   ```
   （宏内对函数指针的调用不会递归展开，等价 `if (hpts_that_need_softclock>0) __tcp_run_hpts();`）
2. **主循环调用**（`lib/ff_dpdk_if.c`）：在 `extern void ff_hardclock(void);`(L152) 旁加 `extern void ff_tcp_hpts_softclock(void);`；在主循环每轮 `process_msg_ring(...)`(L2450) 之后调用 `ff_tcp_hpts_softclock();`，使 hpts 在每个 poll pass 被驱动（忙轮询下亚 µs 级；空闲时宏 gate 几乎零开销）。

风险控制：宏 null 安全 + 仅 pacing 有待办时执行；调用上下文与常规 tcp_output 一致（lcore f-stack 线程，无额外持锁）。

---

## §2 执行步骤

| 步 | 内容 | 门禁 |
|---|---|---|
| S1 复现 | 本机 curl 145MB×N 到 9.134.214.176，记录 hang 发生（基线）| 观测到 hang/超时 ≥1 次 |
| S2 改码 | ff_kern_timeout.c 加封装 + ff_dpdk_if.c extern+调用 | 编译通过 |
| S3 建库 | 重建 libfstack.a（FF_ZC 开关保持 nginx 构建一致；走 rm_tmp_file.sh 清理，不用 make clean）| -Werror clean；改动文件零新增告警 |
| S4 建 nginx | 重建 nginx_fstack 链接新 libfstack.a（定位其构建路径）| 链接成功 |
| S5 验证 | kill_process.sh 停旧 nginx → 启新 → curl 145MB×N（更多次）| **N 次全部完整下载、size=151904256、无 hang** |
| S6 提交 | git commit（简短英文）| — |

> 任一门禁失败打回上一步，单步 ≤3 次，超限停人工。

## §3 验收
- AC1：修复前能复现 hang（基线）。
- AC2：修复后连续 ≥10 次 145MB 下载全部成功、字节数正确、无 hang/超时。
- AC3：编译 -Werror clean；非 ZC/常规路径无回归（小文件 curl 仍 200）。

## §4 风险
| 风险 | 缓解 |
|---|---|
| nginx_fstack 重建路径不明/复杂 | 先定位构建脚本；若不可重建，至少以 libfstack 级 + helloworld/已知手段验证，并如实记录 |
| tcp_hpts_softclock 高频开销 | 宏 gate `hpts_that_need_softclock>0`；__tcp_run_hpts 内部按 slot 限频 |
| 调用上下文/锁 | 与 userret 语义一致；主循环 process_packets 后调用，无新持锁 |
| 复现偶发、不稳定 | 多次循环下载 + 加超时；统计 hang 率 |

## §5 规约
删除→rm_tmp_file.sh；停进程→kill_process.sh；改权限→chmod_modify.sh；make/configure 类可执行（非直接 chmod）。

---

## §6 执行结果（实测闭环）

### 6.1 根因修订（bounce[S5]=1）
首版修复在主循环调用 gate 宏 `tcp_hpts_softclock()`，实测仅边际改善（传输量从 ≤700KB 升至偶发 1.8–3.4MB，仍 hang）。深挖发现：`hpts_that_need_softclock` 仅在单 hpts 连接数 `> conn_cnt_thresh` 时自增（tcp_hpts.c:1731-1733），单个下载连接下恒为 0 → gate 宏空转。而 pacing wheel 实际由 swi/callout 服务，二者在 f-stack 均为 no-op。修订为**绕过 gate 直接经 `tcp_hpts_softclock` 函数指针调用 `__tcp_run_hpts`**（ungated），每个 loop pass 驱动 wheel。

### 6.2 实测对照
| 版本 | 145MB×12 结果 |
|---|---|
| 基线（修复前 nginx_fstack）| **OK=0 / HANG=12**（均收 ~16KB–700KB 后 stall，rc=28）|
| 首版（gated 宏）| OK=0 / HANG=12（部分达 1.8–3.4MB，仍 stall）|
| **修订版（ungated 直驱 wheel）** | **OK=12 / HANG=0**（满 151904256 字节，~0.3–0.4s，~400MB/s）|

### 6.3 改动（提交）
- `lib/ff_kern_timeout.c`：新增 `ff_tcp_hpts_softclock()`（`#undef` gate 宏后直调 `__tcp_run_hpts` 指针）。
- `lib/ff_dpdk_if.c`：主循环每轮 `process_msg_ring` 后调用 `ff_tcp_hpts_softclock()`。
- `lib/ff_api.symlist`：导出 `ff_tcp_hpts_softclock`（供 host 态 ff_dpdk_if.o 跨对象引用）。
- 重建 libfstack.a → make install 到 /usr/local/lib → 重链接 + 重装 nginx_fstack → 重启验证。

### 6.4 结论
根因 = FreeBSD 13→15 升级后，f-stack 特有的 HPTS 驱动适配丢失：15.0 下 hpts wheel 仅靠 swi/callout 服务，而 f-stack `swi_sched`/`intr_event` 为 no-op、且无 userret 调 softclock → RACK/BBR paced 包永不发出 → 大文件传输 stall。修复以 FreeBSD-15 原生 `__tcp_run_hpts` 在 run-to-completion 主循环直驱 wheel，闭环验证大文件下载从 100% hang 变为 100% 成功。AC1/AC2/AC3 全部达成。
