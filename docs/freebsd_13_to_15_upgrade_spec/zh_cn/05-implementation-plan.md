# 05 — 详细实施计划（Implementation Plan）

> English version: ../05-implementation-plan.md

> 系列文档：`/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/`
> 文档版本：v0.1（2026-05-26）
> 输入：`04-diff-and-port-strategy.md` 的 57 个 T-* 任务清单
> 输出：可被后续 AI 代理直接拾取的里程碑 + 任务 + SOP + 回滚

---

## 1. 总体节奏与决策点

### 1.1 里程碑总览

```
M1 → M2 → M3 → M4 → M5 → GATE-Acceptance
基础  kern  网络  边缘  tools+ff  验收
小    大    大    中    大
```

### 1.2 五个关键决策点（最终落定）

| DP | 决策内容 | 决定 | 影响里程碑 |
|---|---|---|---|
| DP-1 | 是否删除 `f-stack/freebsd/mips/` | **删除** | M1 |
| DP-2 | 是否引入 sys/netlink/ | **不引入** | 全程（C-1）|
| DP-3 | 同步策略 | **渐进式（M1→M5）** | 全程 |
| DP-4 | ff_*.c 升级时机 | **与 freebsd/ 同步**（不在 M5 末单独做）| M2/M3/M4 各阶段同步 |
| DP-5 | tools/ 升级 | **独立里程碑 M5** | M5 |

---

## 2. 里程碑详细定义

### 2.1 M1 — 基础设施 + 头文件 + mips 清理

**目标**：搭好新 15.0 基线 + 处理低耦合子目录 + 清理 mips。

**输入**：
- `freebsd-src-releng-15.0/f-stack-lib/`（Phase 1.4 产物）
- `f-stack/freebsd/sys/` `f-stack/freebsd/libkern/` `f-stack/freebsd/opencrypto/` `f-stack/freebsd/crypto/` 的现状

**任务清单**：

| 任务 ID | 内容 | 文件数 | 优先级 |
|---|---|---|---|
| T-cleanup-01 | 删除 `f-stack/freebsd/mips/`；清理 Makefile / mk 中 mips 条件 | 1 dir | P0 |
| T-sys-01 | `sys/systm.h`：重做 kpilite.h 屏蔽 + critical_enter/exit stub | 1 | P0 |
| T-sys-02 | `sys/refcount.h`：重做 refcount_acquire_if_not_zero CAS 自检 | 1 | P0 |
| T-sys-03 | `sys/callout.h` + `sys/_callout.h`：重做简化 | 2 | P1 |
| T-libkern-01 | libkern/ 全量基于 15.0 上游 cp -a；评估改造是否仍需 | ~70 | P1 |
| T-crypto-01 | crypto/ 顶层 cp -a 15.0；blowfish 删除（已在上游删）；新增 chacha20_poly1305.c/.h 与 curve25519.c/.h 保留不引入 | ~22 | P2 |
| T-opencrypto-01 | opencrypto/ 全量基于 15.0 cp -a；评估 xform_* 调整 | ~23 | P1 |
| T-vm-01 | vm/ 全量基于 15.0 cp -a；评估 uma_core 改动是否触及 F-Stack | ~26 | P1 |
| T-arch-01 | amd64/x86 头文件跟随 15.0；评估是否触及 F-Stack | ~20 | P2 |
| T-arch-02 | arm64 头文件跟随 15.0；处理新增 cmn600/ptrauth 等（F-Stack 不用，stub 化）| ~7 NEW | P2 |
| T-misc-01 | netipsec/ netgraph/ netinet/libalias/ 等子目录 cp -a 跟随升级 | ~40 | P2 |

**M1 退出条件**：
- `find f-stack/freebsd/mips -type f` 为空
- libkern/ opencrypto/ crypto/ vm/ amd64/ x86/ arm64/ 子目录的 `*.c *.h` 全部基于 15.0 上游字节一致（或与 02 改造手法对齐）
- M1 阶段尚未涉及 libff 编译，只更新 sys/ 子树
- 通过 `diff -rq` 验证 M1 范围内文件**或来自 15.0、或可在 02 改造手法中找到对应标签**

**估算**：1-2 周（含 reviewer 1 次 mid-review）

### 2.2 M2 — kern 核心（38 KERN_SRCS）

**目标**：完成 F-Stack 受影响最重的 kern/ 子目录升级 + ff_* 中受 kern 改动影响的胶水文件升级。

**任务清单**：

| 任务 ID | 文件 | 优先级 | 备注 |
|---|---|---|---|
| T-kern-01 | `kern_descrip.c` | P0 | refcount API 适配 |
| T-kern-02 | `kern_event.c` | P0 | kqueue stub 重做 |
| T-kern-03 | `kern_linker.c` | P1 | va_size 0 视成功重做 |
| **T-kern-04** | **`kern_mbuf.c`** | **P0** | **m_ext 新字段适配（R-003）** |
| T-kern-05 | `kern_sysctl.c` | P1 | __sysctl 屏蔽重做 |
| T-kern-06 | `link_elf.c` | P1 | elf stub 重做 |
| **T-kern-07** | **`subr_epoch.c`** | **P0** | **epoch → SMR 评估（R-012）** |
| T-kern-08 | `subr_param.c` | P2 | ticks wrap 屏蔽 |
| T-kern-09 | `subr_taskqueue.c` | P1 | taskqueue stub 重做 |
| T-kern-10 | `sys_generic.c` | P1 | kern_sigprocmask 屏蔽重做；同步 ff_syscall_wrapper.c |
| T-kern-11 | `sys_socket.c` | P1 | soo_* 屏蔽重做；评估 KTLS stub |
| **T-kern-12** | **`uipc_mbuf.c`** | **P0** | **FSTACK_ZC_SEND 适配 + m_ext 新布局** |
| T-kern-13 | `uipc_sockbuf.c` | P1 | sb_aio 屏蔽重做 |
| **T-kern-14** | **`uipc_socket.c`** | **P0** | **pr_usrreqs 合并适配（R-011）** |
| T-kern-15 | `uipc_syscalls.c` | P1 | sendit/recvit 外部化重做 |
| T-kern-misc | 其他 23 个 KERN_SRCS（未改造的）基于 15.0 上游 cp -a | P3 | 直拷 |
| **T-ff-04** | **`ff_subr_epoch.c`** | **P0** | **配合 T-kern-07** |
| T-ff-05 | `ff_syscall_wrapper.c` | P1 | 配合 T-kern-15 |
| T-ff-06 | `ff_kern_intr.c` | P1 | ithd 子系统微调 |
| T-ff-misc | `ff_kern_*` 其余 wrapper（condvar/environment/subr/synch/timeout）| P2 | 接口稳定，小改 |

**M2 退出条件**：
- 38 KERN_SRCS 全部基于 15.0 + F-Stack 改造手法落地
- ff_subr_epoch.c / ff_kern_*.c 全部跟随升级
- `make` 阶段：在 M2 后**首次尝试编译 libff.a**（允许在 M3 完成前因为 net/ netinet/ 未升级而失败，但 kern/ 部分应已编译通过）

**估算**：2-3 周

### 2.3 M3 — 网络栈（net + netinet + netinet6）

**目标**：完成 F-Stack 最核心的网络栈升级；解决 if_t / inpcb SMR / rib-nexthop 三大 P0 KPI 破坏。

**任务清单**：

| 任务 ID | 文件 | 优先级 | 备注 |
|---|---|---|---|
| **T-net-01** | **`net/if.c`** | **P0** | **if_t 不透明化（R-013）** |
| **T-net-02** | **`net/if_var.h`** | **P0** | **配合 T-net-01** |
| T-net-03 | `net/if_ethersubr.c` | P1 | 屏蔽 BPF tap 重做 |
| T-net-04 | `net/netisr.c` | P1 | ff_veth 调度重做 |
| **T-net-05** | **`net/route.c`** | **P0** | **rib/nexthop 适配** |
| T-net-misc | net/ 其余 17 NET_SRCS（未改造的）cp -a | P3 | 直拷 |
| **T-netinet-01** | **`tcp_input.c`** | **P0** | **RSS 重做 + SMR 适配** |
| T-netinet-02 | `tcp_output.c` | P1 | |
| T-netinet-03 | `tcp_subr.c` | P1 | |
| **T-netinet-04** | **`tcp_var.h`** | **P0** | **tcpcb 字段裁剪 + RACK 字段** |
| T-netinet-05 | `tcp_stacks/rack.c` | P1 | module name 改 fstack 重做 |
| T-netinet-06 | `tcp_stacks/bbr.c` | P1 | 同上 |
| **T-netinet-07** | **`in_pcb.c`** | **P0** | **RSS 端口范围 + SMR 适配** |
| T-netinet-08 | `tcp_usrreq.c` | P1 | protosw 合并适配 |
| T-netinet-09 | `udp_usrreq.c` | P1 | 同上 |
| T-netinet-10 | `raw_ip.c` | P1 | 同上 |
| T-netinet-misc | 其余 12 NETINET_SRCS cp -a | P3 | 直拷 |
| T-netinet6-01 | netinet6/ 全量 cp -a + 评估改造 | P2 | 改动稀少 |
| **T-ff-01** | **`ff_glue.c`** | **P0** | **pr_usrreqs → protosw 直接调用** |
| **T-ff-02** | **`ff_veth.c`** | **P0** | **if_t 访问函数 + if_alloc 新签名** |
| **T-ff-03** | **`ff_route.c`** | **P0** | **rib/nexthop API** |

**M3 退出条件**：
- 网络栈全量升级
- `libff.a` 在 M3 末**编译通过**
- 单元启动验证：`fstack` 主程序至少能跑起来到 `mi_startup()` 完成

**估算**：3-4 周（最重的里程碑）

### 2.4 M4 — 边缘子系统（netipsec / netgraph / netpfil / 其余）

**目标**：处理可选子系统的升级，确保整体编译矩阵下全部 0 错误。

**任务清单**：

| 任务 ID | 内容 | 优先级 |
|---|---|---|
| T-netipsec-01 | netipsec/ 全量 cp -a + 评估（新增 ipsec_offload.c）| P1 |
| T-netgraph-01 | netgraph/ 全量 cp -a + 重做 ng_socket H-2 改造 | P1 |
| T-netpfil-01 | netpfil/ipfw/ 全量 cp -a + 评估 ip_fw_compat.c（新增） | P1 |
| T-netpfil-02 | netpfil/pf/（如果 F-Stack 启用）跟随升级 | P2 |
| T-bsm-01 | bsm/ cp -a（极少改） | P3 |
| T-ddb-01 | ddb/ 是否需要（F-Stack 通常不用） | P3 |

**M4 退出条件**：
- 全部可选子系统升级完成
- `libff.a` 在所有支持的 KNOB 组合（IPSEC / IPFW / NETGRAPH）下编译通过
- 编译告警相对 13.0 baseline 无新增（或新增项已在 99 中记录）

**估算**：1-2 周

### 2.5 M5 — tools 12 个 + ff_compat + 验收

**目标**：完成用户态工具升级 + IPC 桥 + 全栈验收测试。

**任务清单**：

| 任务 ID | 内容 | 优先级 | 工作量 |
|---|---|---|---|
| T-tools-arp | arp/ 重做 H-6/H-7（基于 15.0 usr.sbin/arp） | P1 | 中 |
| **T-tools-ifconfig** | **ifconfig/ 重做（受 libifconfig 抽象层变化影响）** | **P0** | **大** |
| T-tools-ipfw | ipfw/ 重做 | P1 | 中 |
| T-tools-libmemstat | libmemstat/ 重做 | P2 | 小 |
| T-tools-libnetgraph | libnetgraph/ 重做 | P1 | 中 |
| T-tools-libutil | libutil/ 评估（极少改）| P3 | 小 |
| T-tools-libxo | libxo/ 评估 | P3 | 小 |
| T-tools-ndp | ndp/ 重做 | P1 | 中 |
| **T-tools-netstat** | **netstat/ 重做（sysctl 接管最多）** | **P0** | **大** |
| T-tools-ngctl | ngctl/ 重做 | P1 | 中 |
| **T-tools-route** | **route/ 重做（RTM_* 通道 + rib/nexthop 用户态 API）** | **P0** | **大** |
| T-tools-sysctl | sysctl/ 重做 | P1 | 中 |
| T-compat-01 | `tools/compat/`（ff_ipc.c/h）跟随 ff_* 升级，确保 IPC 协议兼容 | P1 | 中 |
| T-acceptance | 跑 06 的 9 个验收用例 | — | — |
| T-perf | 跑 06 §5 性能基线 | — | — |

**M5 退出条件**：
- 全 12 个工具二进制可生成
- 06 §3 的 9 个用例全过
- 06 §5 性能不退化 > 5%
- libff ABI 经审视无意外破坏

**估算**：3-4 周

---

## 3. 任务总数与排期

| 里程碑 | T-* 任务数 | 预计周数 | P0 数 |
|---|---|---|---|
| M1 | 11 | 1-2 | 2 |
| M2 | 21 | 2-3 | 4 |
| M3 | 22 | 3-4 | **9** |
| M4 | 6 | 1-2 | 0 |
| M5 | 15 | 3-4 | 3 |
| **合计** | **75 个任务** | **10-15 周** | **18 个 P0** |

> 任务总数 75 比 04 §9 的 57 略多，因 05 在 M1/M2/M3/M4 中加入了"直拷未改造文件"的批量任务（cp -a 类，工作量小但需记录）。**本表 75 任务 / 18 个 P0 是全局唯一台账基准**（响应审计 §6.2-2，2026-05-28 收口）；04 §9 的 57 / 24 是"狭义移植 / 移植决策点"子集；99 §4.2 的 19 是"按风险归属"附属视角；详见 `04-diff-and-port-strategy.md §9.1` 与 `99-review-report.md §12.8`。

---

## 4. 每个 P0 任务的执行 SOP（5 步法 + Gate 校验）

> 该 SOP 可被 `c-precision-surgery` skill 直接消化。

```
[Step 1] 准备 3 路 baseline
  - baseline-15 = freebsd-src-releng-15.0/sys/<subdir>/<file>
  - baseline-13 = freebsd-src-releng-13.0/sys/<subdir>/<file>
  - fstack-13   = f-stack/freebsd/<subdir>/<file>

[Step 2] 计算 F-Stack patch
  - delta-13 = diff baseline-13 vs fstack-13
  - 用 02 的 9 大手法标签给 delta-13 分类

[Step 3] 在 baseline-15 上重新应用 delta-13
  - 重点 Review：
    * delta-13 触及的符号在 15.0 是否还存在
    * 15.0 新增代码段是否需要施加同类改造
    * 接口签名变化（R-011/012/013/003/rib）必须显式适配
  - 产出：fstack-15-draft

[Step 4] 单文件 Gate
  - 编译检查：尝试以单文件方式编译（如果工程允许）
  - lint：read_lints
  - grep 保留扩展：FSTACK_ZC_SEND / ff_ipc 等不能丢

[Step 5] 落盘 + 记录
  - mv fstack-15-draft → f-stack/freebsd/<subdir>/<file>
  - 在 99-review-report.md 任务追踪表中标记 ✓
  - 提交 review（每 5 个 P0 任务为一批）
```

---

## 5. 资源与人员分配

| 角色 | 担当 | 主任务 |
|---|---|---|
| Tech Lead | 1 人 | 总体把关、P0 任务 review、决策点最终判断 |
| Senior Engineer × 2 | 2 人 | M2 / M3 核心 port 任务（kern + net + netinet）|
| Engineer × 1 | 1 人 | M5 tools 工作（最多并行性）|
| Reviewer / QA | 1 人 | 06 验收用例 + 99 审查报告维护 |
| AI Agent（c-precision-surgery） | 全程辅助 | 单文件 5 步法 SOP 执行 |

> AI agent 适合的任务：每个 T-* 单文件改造（5 步法明确、上下文有限）。
> 不适合 AI 的任务：跨模块设计决策（如 SMR 接管面 / 评估 libff ABI 变化）。

---

## 6. 回滚方案（NFR-4）

### 6.1 双工作区双备份

```
/data/workspace/f-stack/                  ← 升级主工作区
/data/workspace/f-stack-13.0-baseline/    ← 升级开始前 cp -a 的备份（用户操作，不在本系列产物内）
```

升级开始前的强制动作：
```bash
cp -a /data/workspace/f-stack /data/workspace/f-stack-13.0-baseline
```

### 6.2 单里程碑回滚

每个里程碑完成时打 tag 备份：
```bash
cp -a /data/workspace/f-stack /data/workspace/f-stack-M<N>-done
```

任意里程碑失败可回到上一个 `f-stack-M<N-1>-done`。

### 6.3 单任务回滚

每个 P0 任务在 Step 5 落盘前先备份单文件：
```bash
cp -a <file> <file>.bak.before-T-<id>
```

> 注：本计划不动 Git。所有备份基于文件系统 cp。

---

## 7. 风险监控与升级路径

### 7.1 Gate 失败处理

| 阶段 | Gate 失败 | 处置 |
|---|---|---|
| M1 末 | 头文件无法对齐 | 单点 review；不阻塞 M2 启动（除非影响 kern 编译） |
| M2 末 | KERN_SRCS 编译有错误 | Tech Lead 介入；考虑是否需要"扩大 stub 范围" |
| M3 末 | libff.a 不能编译 | **最严重**：暂停 M4 启动；3 大 P0 KPI 任务（T-net-01 / T-netinet-01 / T-net-05）逐个回滚 + 重做 |
| M4 末 | 可选子系统未通过 | 关掉对应 KNOB；记入 R-006 类风险 |
| M5 末 | 验收用例失败 | 按用例严重程度回到 M3 或 M5 中段 |

### 7.2 时间盒（time-box）

- 每个 P0 任务时间盒：**2 天**；超过则 Tech Lead 介入
- 每个里程碑硬上限：M2 / M3 各 4 周；M5 4 周；总不超过 16 周

---

## 8. 与 F-Stack 现有 build/CI 的集成

| 集成点 | 操作 |
|---|---|
| `f-stack/Makefile` | 检查 mips 相关条件已删 |
| `f-stack/lib/Makefile` | 跟进 `KERN_SRCS+=` 等列表是否需要因 15.0 文件 NEW/DEL 调整 |
| `f-stack/tools/<tool>/Makefile` | M5 重做 H-7 时同步检查 |
| F-Stack CI（如有） | M5 末跑全套验收用例 |

---

## 9. 不在本计划范围内的事（C-1 重申）

| 项 | 说明 |
|---|---|
| netlink port | C-1 显式排除；如需，开新工作流 |
| 抗量子加密 ML-KEM 引入 | 同上 |
| inotify / timerfd / kqueuex 等新 syscall 暴露给 ff_syscall_wrapper.c | 同上 |
| DPDK 升级 | 同上；如 15.0 需要新 DPDK，开新工作流 |
| Git 提交 | C-4 |
| 性能基准重建 | 仅做"不退化 > 5%"对比；不做新基准 |

---

## 10. 与 06 验收的衔接

| 本节产物 | 06 中应对章节 |
|---|---|
| M2-M5 各退出条件 | `06 §2` 编译矩阵 |
| FR-6 9 个验收用例 | `06 §3` 用例清单 |
| NFR-1 性能不退化 5% | `06 §5` 性能基线 |
| 75 个 T-* 任务追踪 | `99-review-report.md` 实施进度表 |

---

## 11. 实施开工前 Checklist

- [ ] 备份原 f-stack 工作区
- [ ] 确认宿主机 GCC ≥ 10 或 clang ≥ 12
- [ ] 确认 DPDK LTS 版本与 15.0 兼容（A-3 假设）
- [ ] 确认 F-Stack 现有 build 在 13.0 基线上 0 错误（A-2 假设）
- [ ] 06 中 9 个验收用例对应的测试环境就绪
- [ ] Tech Lead 复核 18 个 P0 任务的执行顺序与时间盒
- [ ] reviewer 确认 99 报告框架已建（虽然 99 在 Spec 阶段产出，但实施阶段需要持续填进度）
- [ ] AI Agent 上下文准备：04 + 05 + 02 + 03 是后续 AI 代理拾取任务的标准输入
