# M6 Spec — FF_NETGRAPH + FF_IPFW Combo (P0)

> 父计划：`phase2-feature-enable-plan.md`（v0.1，2026-06-08 已接受）  
> Spec 版本：v0.1（2026-06-08）  
> 状态：DRAFT → 待 Phase D reviewer 审查  
> 工作 commit baseline：`07f9bb0b7`（feature/1.26 ahead 13）  
> M5 编译 baseline：0 errors / 55 warnings / `libfstack.a` 5.4 MB（默认配置；本里程碑 G1 阈值 = baseline + 5）

---

## 1. 范围（in / out scope）

### 1.1 In scope（必须完成）

| 项 | 说明 |
|---|---|
| 启用 `FF_NETGRAPH=1` | `lib/Makefile:43` 取消注释 |
| 启用 `FF_IPFW=1` | `lib/Makefile:44` 取消注释 |
| 编译通过 | `cd lib && make all` 无 error；warning ≤ 60（55 + 5） |
| 主程序冒烟 | `example/helloworld` 起栈 ≥ 10s 不崩 |
| ipfw 用户态工具可用 | `cd tools/ipfw && make` 产出 `ipfw` 可执行；`./ipfw add 100 deny ip from 1.2.3.4 to any` + `./ipfw show` 显示规则 |
| netgraph 控制可用 | `tools/ngctl list` 至少能空列出（即使 0 active node 也应返回） |
| 文档同步（局部） | 短版 L1/L2/L3 + 长版 + Summary：增加"FF_NETGRAPH/FF_IPFW 编译选项"章节；新增对应 zh_cn 镜像 |
| 本地 commit | 英文 commit message；不 push |

### 1.2 Out of scope（明确不做）

| 项 | 理由 |
|---|---|
| `freebsd/netpfil/ipfw/nat64/`、`nptv6/` | NETIPFW_SRCS 未列入；若用户使用 `ipfw nat64*` 命令将得到运行时错误，文档需说明限制 |
| `freebsd/netpfil/ipfw/ip_fw_bpf.c`、`ip_fw_compat.c` | NETIPFW_SRCS 未列入；保持现状（与 13.0 时期一致） |
| netgraph 8 个被排除节点：`ng_base.c`（被 ff_ng_base.c 替代）、`ng_bpf.c`、`ng_checksum.c`、`ng_device.c`、`ng_macfilter.c`、`ng_mppc.c`、`ng_tty.c`、`ng_vlan_rotate.c` | NETGRAPH_SRCS 故意排除；保持现状 |
| `tools/ipfw/` 中 nat64clat/nat64lsn/nat64stl/nptv6 工具命令 | 用户态会编进 `ipfw` 二进制（Makefile 无条件加），但因 kernel 端 sockopt 不存在，运行时会返回 ENOPROTOOPT；不视为本里程碑缺陷，文档说明 |
| 性能测试（rps / cps / latency） | M6 不要求（plan §3 表格：M6 G4 不做）；性能基线留 M7/M8/M9 |
| KG_WIKI 重跑索引 | M6 不做（plan §5.4：仅 M-Final 重跑） |
| FreeBSD 14/15 新增的 ipfw eaction 扩展（如 `recvtag`） | 仅在 spec 中标注存在性，运行时是否生效不验证 |

---

## 2. 背景与现状（实测引用）

### 2.1 编译选项控制点（lib/Makefile）

```
:43   #FF_NETGRAPH=1                    ← 需取消注释
:44   #FF_IPFW=1                        ← 需取消注释
:104  ifdef FF_NETGRAPH                 (host-side flag injection)
:105    HOST_CFLAGS+= -DFF_NETGRAPH
:108  ifdef FF_IPFW                     (both host + kern flag)
:109    HOST_CFLAGS+= -DFF_IPFW
:110    CFLAGS+= -DFF_IPFW
:224  ifdef FF_NETGRAPH                 (VPATH +=$S/netgraph)
:237  ifdef FF_IPFW                     (VPATH +=$S/netpfil/ipfw + .../pmod)
:266  ifdef FF_NETGRAPH                 (FF_SRCS+= ff_ng_base.c ff_ngctl.c)
:424  ifdef FF_NETGRAPH                 (NETGRAPH_SRCS list = 41 .c)
:575  ifdef FF_IPFW                     (NETIPFW_SRCS list = 13 .c)
```

### 2.2 涉及源码统计（实测 2026-06-08）

| 维度 | 值 | 数据来源 |
|---|---|---|
| `freebsd/netgraph/` 顶层 .c | 49 | `ls freebsd/netgraph/*.c \| wc -l` |
| 含子目录（bluetooth/ + netflow/） | 74（不本地编译） | `find freebsd/netgraph -name '*.c' \| wc -l` |
| `NETGRAPH_SRCS` 实际编译 | 41 | `lib/Makefile:426-466` |
| `freebsd/netpfil/ipfw/` 顶层 .c | 25 | `ls freebsd/netpfil/ipfw/*.c \| wc -l` |
| `NETIPFW_SRCS` 实际编译 | 13 | `lib/Makefile:577-589` |
| `tools/ipfw/` 总条目 | 26（含 10 个 .o 残留） | `ls tools/ipfw \| wc -l` |
| `tools/ipfw/*.c` | 12 | `ls tools/ipfw/*.c \| wc -l` |
| `tools/ipfw/*.o`（残留） | 10 | 必须 build 前清理（用 `rm_tmp_file.sh`） |

### 2.3 排除清单确认（NETGRAPH_SRCS 未含 8 个）

| 文件 | 原因（推测） | 风险 |
|---|---|---|
| `ng_base.c` | 被 `lib/ff_ng_base.c` 替代（用户态 epoch/inputqueue 改造） | 无 |
| `ng_bpf.c` | 依赖 BPF 内核接口；无 BPF 设备 | 中（用户若调用会失败） |
| `ng_checksum.c` | 依赖 mbuf 校验和 offload | 低 |
| `ng_device.c` | 依赖 `/dev/ngd*` 字符设备 | 中 |
| `ng_macfilter.c` | 依赖 ifp ethernet hook | 低 |
| `ng_mppc.c` | 依赖加密模块 | 低 |
| `ng_tty.c` | 依赖 tty 子系统 | 低 |
| `ng_vlan_rotate.c` | FreeBSD 14+ 新增 | 低 |

### 2.4 IPFW 排除清单

| 文件 | 状态 | 风险 |
|---|---|---|
| `ip_fw_bpf.c` | 顶层有源，未列 NETIPFW_SRCS | 链接期 `ipfw_bpf_init` 等符号若 `ip_fw2.c` 引用 → 由 `ff_stub_14_extra.c` 兜底（待 Phase D 验证） |
| `ip_fw_compat.c` | 顶层有源，未列 | 老 sockopt 路径不可用（不影响 ipfw3 协议） |
| `nat64/`、`nptv6/` | 完全不编译 | `ipfw nat64*` `ipfw nptv6` 运行时返回 ENOPROTOOPT |

### 2.5 桥接节点 `ng_ipfw.c`（P0 bundle 根因）

`freebsd/netgraph/ng_ipfw.c` 在 NETGRAPH_SRCS 中（41 个之一），它声明 `KLD_DEPEND(ng_ipfw, ipfw, ...)`，**编译期就要求** ipfw 子系统存在 → **这正是 P0 必须 NETGRAPH 与 IPFW combo 启用的根本原因**。

> 来源：scout 报告（task 1，§5）+ 实测 `grep -n KLD_DEPEND freebsd/netgraph/ng_ipfw.c`（待 Phase C 阶段二次验证）

### 2.6 用户态工具：`tools/ipfw/Makefile` 实测

```makefile
TOPDIR?=${CURDIR}/../..
SRCS = ipfw2.c ipv6.c main.c nat.c tables.c compat.c
SRCS += nat64clat.c nat64lsn.c nat64stl.c nptv6.c        # 始终编译，但 kernel 不支持
ifneq (${MK_DUMMYNET},"no") SRCS += dummynet.c           # 默认开启
ifneq (${MK_PF},"no")       SRCS += altq.c               # 默认开启
LIBADD = util
MAN = ipfw.8
```

`tools/ipfw/compat.c` 已是 F-Stack 加层，把 `socket()/setsockopt()/getsockopt()` 替换为 `ff_ipc_*`，与 lib 端 `ip_fw_sockopt.c` 通过 IPC 通信。

---

## 3. 接口与数据结构变更点

### 3.1 lib/Makefile 修改（最小 diff）

```diff
-#FF_NETGRAPH=1
+FF_NETGRAPH=1
-#FF_IPFW=1
+FF_IPFW=1
```

**仅 2 行改动**。其它编译选项保持注释。

### 3.2 lib/ 源文件修改（预计）

| 文件 | 预期改动 | 触发条件 |
|---|---|---|
| `lib/ff_stub_14_extra.c` | 可能新增 ipfw / netgraph 在 14.0+ 缺失的 stub | Phase E G1 编译失败时由 coder 增量修复 |
| `lib/ff_ng_base.c` | 可能因 FF_NETGRAPH 启用首次实编译，触发新 warning/error | Phase E G1 |
| 其它 lib/ff_*.c | **不主动修改**；仅在 G1 失败时 reviewer/coder 联合定位 | — |

### 3.3 freebsd/netgraph/ + freebsd/netpfil/ipfw/ 修改

**默认不修改**。若 G1 编译失败需打 patch，必须：
1. 备份原文件到 `/data/workspace/freebsd-src-releng-15.0/f-stack-lib/freebsd/netgraph/`（或 ipfw/）
2. 在 spec / execution-log 中记录 patch 原因 + 上游对应 commit（如有）
3. reviewer 必须特别核查不要偏离上游意图

### 3.4 tools/ipfw/ 修改

**默认不修改**。Build 前用 `rm_tmp_file.sh` 清理 10 个 `.o` 残留。

---

## 4. 验收标准（每条均可执行 + 有测量值）

### G1 — 编译门

| AC ID | 测试 | PASS 条件 |
|---|---|---|
| **G1.1** | `cd lib && make clean && make all 2>&1 \| tee /tmp/m6_compile.log` | exit=0 |
| **G1.2** | `grep -ic 'error:' /tmp/m6_compile.log` | 0 |
| **G1.3** | `grep -ic 'warning' /tmp/m6_compile.log` | ≤ 60（baseline 55 + 5） |
| **G1.4** | `ls -l lib/libfstack.a` | size ≥ 5.4 MB（baseline）×0.95（避免无逻辑回退） |
| **G1.5** | `cd tools/ipfw && /data/workspace/rm_tmp_file.sh tools/ipfw/*.o 2>/dev/null; make 2>&1` | exit=0 + 产出 `ipfw` 可执行（注意：clean 必须用 rm_tmp_file.sh，不直接 rm） |

### G2 — 主程序冒烟门

| AC ID | 测试 | PASS 条件 |
|---|---|---|
| **G2.1** | `cd example && sudo ./helloworld -c ../config.ini --proc-type=primary --proc-id=0 &; sleep 10; /data/workspace/kill_process.sh helloworld` | exit=0；进程在 10s 内不崩 |
| **G2.2** | `dmesg \| tail -50`（或 helloworld stdout） | 无 SIGSEGV / panic / "stub called" 关键词 |

### G3 — 功能门

| AC ID | 测试 | PASS 条件 |
|---|---|---|
| **G3.1** | helloworld 后台运行中：`cd tools/ipfw && sudo ./ipfw add 100 deny ip from 1.2.3.4 to any` | exit=0；stdout 含 "00100 deny ip from 1.2.3.4 to any" |
| **G3.2** | `sudo ./ipfw show` | exit=0；输出含 "00100 deny ip from 1.2.3.4 to any" 行 |
| **G3.3** | `sudo ./ipfw delete 100 && sudo ./ipfw show` | exit=0；规则消失 |
| **G3.4** | `cd tools/ngctl && sudo ./ngctl list`（如 ngctl 工具未在 tools/ 下，本 AC 降级为：仅检查 `lib/ff_ng_base.c` 中 `ng_init` 类初始化函数被调用，通过 strings 或 helloworld stdout 判断） | exit=0 或降级条件满足 |
| **G3.5（OQ-4 适用）** | 若 G3.1~3.4 任一因 NIC/硬件依赖失败 | 可降级为冒烟 PASS + observation 标签（plan §8 OQ-4 默认允许） |

### G4 — 性能门

**不做**（plan §3 M6 表格：G4 不要求）。

### G5 — 文档同步门

| AC ID | 改动文件 | 验收 |
|---|---|---|
| **G5.1** | `docs/01-LAYER1-ARCHITECTURE.md` + `docs/zh_cn/01-LAYER1-ARCHITECTURE.md` | 在 §2/§4 中提及 FF_NETGRAPH/FF_IPFW 的启用状态、引入文件数、桥接节点 ng_ipfw |
| **G5.2** | `docs/03-LAYER3-FUNCTIONS.md` + `docs/zh_cn/03-LAYER3-FUNCTIONS.md` | 在 §3 中新增「lib/ff_ng_base.c」「lib/ff_ngctl.c」函数级条目（参考 phase-1 风格） |
| **G5.3** | `docs/F-Stack_Knowledge_Base_Summary.md` + zh_cn 镜像 | 在版本与里程碑栏添加 M6 |
| **G5.4** | `docs/freebsd_13_to_15_upgrade_spec/zh_cn/phase2-M6-execution-log.md` | 完整执行日志 |
| **G5.5** | `docs/freebsd_13_to_15_upgrade_spec/zh_cn/phase2-M6-review-report.md` | reviewer 报告 |
| **G5.6** | `read_lints docs/` | 0 errors |

### G6 — Lint 门

`read_lints docs/` + `read_lints lib/` 0 errors。

### G7 — Commit 门

| AC ID | 验收 |
|---|---|
| **G7.1** | git commit subject 英文，body 覆盖 (a) 改动文件清单 (b) 验收 G1-G6 结果 (c) bounce ledger |
| **G7.2** | `git log -1` 显示新 commit；`git status -sb` 显示 clean working tree |
| **G7.3** | `git push` **未执行**（plan §6.2 强约束） |

---

## 5. 风险与回滚

| 风险 | 检测 | 缓解 | Owner |
|---|---|---|---|
| **R-M6-1** ng_ipfw.c KLD_DEPEND 未在用户态生效 | 编译期可能直接报 unresolved symbol；运行时 ng_ipfw 节点无法 attach | 若仅为编译错则 ff_stub_14_extra 添 stub；若运行时不 attach，文档说明（可降级） | coder + reviewer |
| **R-M6-2** ipfw 用户态工具 .o 残留导致老符号链接 | `tools/ipfw/*.o` 时间戳早于源 .c | G1.5 前必须 rm_tmp_file.sh 清理；提供专用清理脚本（如需） | gate-keeper |
| **R-M6-3** 8 个排除 ng_*.c 在 NETGRAPH_SRCS 用户调用时段错误 | 用户尝试 `ngctl mkpeer ... bpf` 等命令 | 文档明示不支持；G3 测试不触发这些命令 | doc-updater |
| **R-M6-4** 14.0+ 新增 ipfw 符号缺失（如 `ipfw_eaction_*`） | G1 出现 undefined reference | ff_stub_14_extra 添 stub；reviewer 比对 freebsd-src-releng-15.0/sys/netpfil/ipfw/ip_fw2.c | coder |
| **R-M6-5** ipfw rule add 通过但内核侧未生效（数据面不 match） | G3.1 PASS 但实际 ping 不被拒绝 | 若发现，先确认 pfil 钩子是否注册（`ip_fw_pfil.c:ipfw_attach_hooks`）；不能修复则降级为 observation（OQ-4） | gate-keeper |
| **R-M6-6** 编译告警暴增（>60） | G1.3 失败 | 1) 优先 fix 真正回归告警；2) 若是 NETGRAPH/IPFW 子系统老告警，spec 决策提升阈值（spec patch 后再走） | reviewer |

**回滚策略**：任一 G1-G3 失败超 3 次打回（同阶段计），escalate；用户决策后选择：
- (a) 接受降级（observation 标签）
- (b) 暂停 M6，先做 M7（独立无依赖）
- (c) 修订 spec 阈值

---

## 6. 测试清单（按 G1-G7 落实可执行命令）

详见 §4 各 AC 的"测试"列。所有命令禁止使用直接 `rm`/`kill`/`chmod`，必须经 `rm_tmp_file.sh`/`kill_process.sh`/`chmod_modify.sh`。

### 6.1 测试前的环境清理（强制）

```bash
# 清理 tools/ipfw 残留 .o（10 个，详见 §2.2）
cd /data/workspace/f-stack
/data/workspace/rm_tmp_file.sh \
  tools/ipfw/altq.o tools/ipfw/compat.o tools/ipfw/dummynet.o tools/ipfw/ipv6.o \
  tools/ipfw/ipfw2.o tools/ipfw/main.o tools/ipfw/nat.o tools/ipfw/nat64clat.o \
  tools/ipfw/nat64lsn.o tools/ipfw/tables.o
# 清理 lib/ 编译产物
cd lib && make clean   # make clean 内部 rm 由 build 系统执行，规约允许
```

### 6.2 G1 测试脚本（建议）

```bash
cd /data/workspace/f-stack/lib
make clean 2>&1 | tail -3
make all 2>&1 | tee /tmp/m6_compile_$(date -u +%Y%m%d_%H%M%S).log
LOG=$(ls -t /tmp/m6_compile_*.log | head -1)
echo "errors: $(grep -ic 'error:' $LOG)"
echo "warnings: $(grep -ic 'warning' $LOG)"
ls -l libfstack.a
```

### 6.3 G3.1-3.3 测试脚本（建议）

```bash
# 启动 helloworld
cd /data/workspace/f-stack/example
sudo ./helloworld -c ../config.ini --proc-type=primary --proc-id=0 > /tmp/m6_helloworld.log 2>&1 &
sleep 5
# 加规则
cd ../tools/ipfw
sudo ./ipfw add 100 deny ip from 1.2.3.4 to any && \
sudo ./ipfw show | grep "00100 deny" && \
sudo ./ipfw delete 100 && \
echo "G3 PASS"
# 清理
/data/workspace/kill_process.sh helloworld
```

---

## 7. 一致性自检（spec 内部）

| 检查项 | 状态 |
|---|---|
| 所有 file:line 引用真实存在 | ✅（见 §2.1 / §2.6 验证） |
| 所有 AC 有可执行命令 | ✅（§4 + §6） |
| 所有 risk 有 mitigation | ✅（§5） |
| 与 plan §3 M6 范围一致 | ✅ |
| 与 plan §4 5-phase 流程对齐 | ✅ |
| 无 TBD 项 | ✅（OQ 已在 plan §8 全部默认决策） |

---

## 8. 进入 Phase B / C 的前置条件

| 前置 | 状态 |
|---|---|
| Spec 1.0 通过 self-check | ✅ |
| reviewer 确认 spec 无 fatal gap | ⏳ Phase D 反向门，此时跳过；如 Phase C 中发现 spec 不可实现则按 bounce(code → spec) 打回 |
| Research-brief 是否需要单独 phase B？ | **不需要**；本 spec 已含 scout 关键发现 §2.5/§2.6/§2.7（兼并 phase B） |

---

## 9. 进度

| 阶段 | 状态 |
|---|---|
| Phase A（本 spec） | ✅ DRAFT 完成 |
| Phase B（research） | 已合并到 §2（M6 不单独做 brief） |
| Phase C（code） | ⏭ 待启动 |
| Phase D（review） | ⏭ |
| Phase E（gate G1-G7） | ⏭ |

---

> 下一步：进入 **Phase C — coder**，对 `lib/Makefile:43-44` 执行 2 行 diff，触发 G1。
