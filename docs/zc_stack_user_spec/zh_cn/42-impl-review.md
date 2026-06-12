# 42. 发包零拷贝原生化 —— 实施期 review（M0-M5 执行记录）

> 对应 plan：41-impl-plan.md。所有结论均为**实测**（编译/运行/grep），无臆造。
> 分支 feature/1.26。功能 commit：`b6ce5884c`（M0+M1）。

---

## §1 里程碑结果总表

| 里程碑 | 内容 | 门禁结果 | bounce |
|---|---|---|---|
| M0 内核 | kern_zc_sendit + 删 5 处魔改 + m_uiotombuf ZC 分支移除 | **PASS** | 0 |
| M1 用户态 | ff_zc_send→kern_zc_sendit；M_PKTHDR；pkthdr.len；删 opt-out | **PASS** | 0 |
| M2 单测 | test_ff_zc_send.c 算法一致性 13 用例 | **PASS** | 0 |
| M3 功能 E2E | helloworld_zc 真实 curl http=200 | **PASS** | 0 |
| M4 性能/稳定 | 1000 请求稳定性 PASS；精确 A/B 基线 **deferred** | **PASS（稳定性）** | 0 |
| M5 收尾 | 本文档 + 提交 + gatekeeper | 进行中 | — |

**总 bounce = 0**（无单步 ≥3，无需人工决策）。

---

## §2 M0 内核 patch（实测证据）

| 改动 | 文件:符号 | 验证 |
|---|---|---|
| K1 声明 | `freebsd/sys/syscallsubr.h` `kern_zc_sendit`（gated FSTACK_ZC_SEND）| 编译通过 |
| K2 实现 | `freebsd/kern/uipc_syscalls.c` `kern_zc_sendit`（紧随 kern_zc_recvit）| `nm libfstack.a` 含 `t kern_zc_sendit` |
| D1 删宏 | `freebsd/sys/mbuf.h` FSTACK_ZC_MAGIC | grep=0 |
| D2 m_uiotombuf | `freebsd/kern/uipc_mbuf.c` 删 FSTACK_ZC_SEND 快路径分支 | grep FSTACK_ZC_SEND=0 |
| D3 守护 | `freebsd/kern/sys_generic.c` uio_offset 单行 + 删 mbuf.h include | grep FSTACK_ZC_SEND=0 |

kern_zc_sendit 关键语义（实测对照 33-spec §2.2）：入参校验失败 m_freem(top)+EINVAL；getsock(&cap_send_rights)/MAC 失败 m_freem+return；`sosend(so,NULL,NULL,top,NULL,flags,td)`；**sosend 后绝不二次 m_freem**（INV-3 防双重释放）；EPIPE→SIGPIPE（除非 SO_NOSIGPIPE/MSG_NOSIGNAL）。impl-review 子 agent 复核 27/27 PASS。

### DEV-1（spec 偏差，实测驱动，已记录）
33-spec §3.2 要求"m_uiotombuf 回退到 vanilla FreeBSD 15.0，diff=0"。**实测不可行**：vanilla m_uiotombuf 调用 `m_uiotombuf_nomap`（`freebsd/kern/uipc_mbuf.c:1845 #ifndef FSTACK` 内，FSTACK 构建下**不编译**），全量回退必然链接失败。故采用 plan 预设折中 **R-M0-1**：仅删除 m_uiotombuf 内的 `#ifdef FSTACK_ZC_SEND` 快路径分支，保留既有 13.0-era m_uiotombuf 正常拷贝路径。
- 用户核心目标（消除魔改 magic、降低误触/升级成本）**完全达成**：FSTACK_ZC_MAGIC 与 uio_offset 哨兵已彻底清除，m_uiotombuf 不再有任何 ZC 特判分支。
- AC4「m_uiotombuf diff vs vanilla=0」**降级**为「ZC 魔改分支清零」；其余 AC4 项（mbuf.h MAGIC=0、sys_generic uio_offset 回归 vanilla 单行+删 include）**达成**。

---

## §3 M1 用户态（实测证据）

| 改动 | 文件 | 验证 |
|---|---|---|
| U1 ff_zc_send | `lib/ff_syscall_wrapper.c` | cast top + kern_zc_sendit(curthread,fd,top,0)；`nm` 含 `T ff_zc_send` |
| U2 ff_zc_mbuf_get | `lib/ff_veth.c:316` | `m_getm2(...,MT_DATA,M_PKTHDR)` + len<0 校验 |
| U3 ff_zc_mbuf_write | `lib/ff_veth.c:362` | `head->m_pkthdr.len += progress`（链头累加，O(1)）|
| U4 删 opt-out | `lib/ff_syscall_wrapper.c` | ff_write/ff_writev 无 `auio.uio_offset = 0`（grep=0）|
| U5 ff_api.h | `lib/ff_api.h` | 文档块更新（签名不变）|

**ABI 不变**：ff_zc_send/ff_zc_mbuf_get/ff_zc_mbuf_write 签名 100% 保留；`example/main_zc.c` **零修改**（`git diff --stat` 空）；helloworld_zc 链接通过。

---

## §4 AC1 编译门禁（四组合，全 make_rc=0）

| 组合 | libfstack.a bytes |
|---|---|
| default | 6539824 |
| FF_ZC_RECV=1 | 6541322 |
| FF_ZC_SEND=1 | 6540798 |
| FF_ZC_SEND=1 FF_ZC_RECV=1 | 6542296 |

改动 5 文件单独编译（build 同款 -Werror flags）**零新增告警**（sys_generic.c 仅 L962/964 既有 `-Warray-bounds`，非本次改动且 `-Wno-error`）。

> 构建合规：未用 `make clean`（其内含直接 rm），改用 `/data/workspace/rm_tmp_file.sh` 清理产物；临时文件/进程/权限分别走 rm_tmp_file.sh / kill_process.sh / chmod_modify.sh。

---

## §5 M2 单元测试

`tests/unit/test_ff_zc_send.c`（13 用例，加入 P3_TESTS）：U1-U10 + 多段 + 校验类。
- 运行：13/13 PASS；valgrind memcheck rc=0（无 definite leak）。

### DEV-2（单测范围说明，实测驱动）
实测 `gcc -fsyntax-only ff_veth.c` 失败于 `sys/ctype.h`、`ff_syscall_wrapper.c` 失败于 `sys/limits.h`（FreeBSD 专有头）。现有 host-based cmocka harness **无法编译**这两个 TU，故无法直接链接真实函数做单测。M2 采用**算法一致性测试**：mbuf shim 忠实复刻 ff_zc_mbuf_get/write 的 M_PKTHDR/pkthdr.len 累加与边界逻辑（头部注明与源码同步）。真实二进制由 M3 端到端覆盖。
> spec 37 §8.3 引用的 `tests/integration/test_ff_zc_recv_integration.c`（称 commit 8a06862cd 建立）**实测不存在**（该 commit 仅改 docs+main_zc.c+symlist）；ZC-send 测试以真实存在的 `test_ff_dpdk_kni/pcap` 范式为准。

---

## §6 M3 功能 E2E（真实二进制，最强验证）

环境：本 server VM（DPDK NIC 0000:00:09.0 virtio/igb_uio 已绑定，hugepage 4096×2M，config addr 9.134.214.176 / lcore4）——与 ZC-recv M2 同机。

- helloworld_zc（FF_ZC_SEND）启动：DPDK Port 0 Link Up，f-stack 注册接口 MAC 20:90:6f:7d:5d:08。
- 本机经 eth1 路由可达 data-plane IP，curl×5：**全部 http=200 size=438**，应答内容为 F-Stack 欢迎页，5 次一致。
- 链路证明：`ff_zc_mbuf_get(M_PKTHDR)`→`ff_zc_mbuf_write(pkthdr.len)`→`ff_zc_send`→`kern_zc_sendit`→`sosend(uio=NULL, top)`。**size=438 正确直接证明 pkthdr.len 修复生效**（若 pkthdr.len=0 则 resid=0 应答为空）——这是新原生路径在真实栈上的端到端确证。
- 进程清理走 kill_process.sh。

---

## §7 M4 性能/稳定性

- **稳定性压测**（本机 curl 1000 次顺序请求）：**ok=1000 bad=0**，server 存活，无 panic/segfault/abort（验证 issue #712「大量发包崩溃」关切——新路径稳定）。
- **精确 A/B 性能基线（wrk T1/T2/T3，Δ≤±3%）**：**deferred**。理由（如实）：本机无 wrk；且严谨基线需 M2 同款远程 client VM（9.134.211.87），本机单机 wrk 与 server 抢占同核不可比。**禁止臆造性能数据**；待用户在双机环境按 38-perf-baseline-spec 复测。

---

## §8 验收对照（AC1-AC6）

| AC | 结果 | 证据 |
|---|---|---|
| AC1 编译干净 | ✅ | 四组合 make_rc=0；改动文件零新增告警 |
| AC2 功能 PASS | ✅ | M3 http=200 size=438；example/main_zc.c 零改动；与 FSTACK_ZC_RECV 双开共存编译 OK |
| AC3 性能持平 | ⏳ deferred | 需双机 wrk；单机稳定性 1000/1000 OK |
| AC4 内核 diff 收缩 | ◑ 部分 | MAGIC/sys_generic 回归 vanilla；m_uiotombuf 见 DEV-1（仅去 ZC 分支，未全量回 vanilla，因 nomap/mc_uiotomc 不可用）|
| AC5 内存安全 | ◑ | 单测 valgrind 0 leak；kern_zc_sendit 错误路径单点 m_freem 经 review 确认无双重释放/UAF；DPDK 运行态精确 mempool 计数 deferred（同 21-m2 结论，运行态 valgrind 成本高）|
| AC6 spec 文档完整 | ✅ | 41-plan + 42-review；无直接 rm/kill/chmod |

---

## §9 bounce counter（per memory 86071475）

```
M0=0  M1=0  M2=0  M3=0  M4=0  M5=0
```
全程 0 打回；无步骤触及 3 次上限；无需人工决策。两处 DEV（DEV-1 m_uiotombuf 折中、DEV-2 单测范围）为**实测驱动的设计决策**（plan 已预设 R-M0-1 回退路径），非门禁失败。

---

## §10 提交记录

| commit | 内容 |
|---|---|
| `b6ce5884c` | feat(zc-send): M0 内核 + M1 用户态（功能代码 + 41-plan）|
| （本阶段）| test(zc-send): M2 单测 + 42-review 文档 |

## §11 遗留 / 建议（待人工或后续）
1. 精确 A/B 性能基线（双机 wrk T1/T2/T3 + 大 payload P1-P4）——按 38-spec 在 client VM 复测。
2. DPDK 运行态 mempool 精确计数 / valgrind（AC5 补全）。
3. 真实二进制的多段大包发送路径（>1 mbuf）E2E：helloworld 应答固定 438B 为单段；多段已由 M2 算法单测覆盖，建议后续用大 payload 自定义 client 在真实栈上补测。
4. m_uiotombuf 若未来需 diff-vs-vanilla=0，须同步回退 m_uiotombuf_nomap/mc_uiotomc/M_EXTPG/mchain 全套（大改，本期不做）。
