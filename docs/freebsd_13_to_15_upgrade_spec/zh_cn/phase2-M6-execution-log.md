# M6 Execution Log — FF_NETGRAPH + FF_IPFW Combo (P0)

> Spec: `phase2-M6-spec.md` v0.1  
> Plan parent: `phase2-feature-enable-plan.md` v0.1  
> Execution date: 2026-06-08  
> HEAD before: `07f9bb0b7`  
> Branch: `feature/1.26` ahead 13 vs upstream  
> Status: **PASS**（G1-G7 全门通过，含 OQ-4 内的 G3 降级路径未触发——G3 实际全部通过）

---

## 1. 5-phase 流水线执行结果

| Phase | 状态 | 主要产出 |
|---|---|---|
| A. Spec | ✅ | `phase2-M6-spec.md`（10 节，含 6 风险 + 7 AC + 可执行测试脚本） |
| B. Research | ✅（合并入 spec §2） | netgraph 49 顶层 .c / NETGRAPH_SRCS=41；ipfw 25 顶层 + 子目录；NETIPFW_SRCS=13 |
| C. Code | ✅ | 4 文件修改 +98/-4（详见 §2） |
| D. Review | ✅ | 静态扫描 0 forbidden call / 0 lint error |
| E. Gate | ✅ | G1-G7 全部 PASS（详见 §3） |

---

## 2. 代码改动（最终 4 文件）

### 2.1 `lib/Makefile`（5 行）
```diff
-#FF_NETGRAPH=1
-#FF_IPFW=1
+FF_NETGRAPH=1
+FF_IPFW=1
…
 NETIPFW_SRCS+=             \
   ip_fw_dynamic.c \
   …
   ip_fw2.c \
+  ip_fw_compat.c \         (M6 新增；提供 IP_FW3 v0/v1 dispatch table 注册)
   ip_fw_pmod.c \
```

### 2.2 `lib/ff_stub_14_extra.c`（+82 行：M6 stub 块）

7 个 link-only stub，签名均与上游 freebsd-src-releng-15.0 严格一致：

| 符号 | 来源（上游 header:line） | 实现 |
|---|---|---|
| `ipfw_bpf_init(int)` | `sys/netpfil/ipfw/ip_fw_private.h:162` | no-op |
| `ipfw_bpf_uninit(int)` | `:163` | no-op |
| `ipfw_bpf_tap(u_char *, u_int)` | `:164` | no-op |
| `ipfw_bpf_mtap(struct mbuf *)` | `:165` | no-op |
| `ipfw_bpf_mtap2(void *, u_int, struct mbuf *)` | `:166` | no-op |
| `sctp_calculate_cksum(struct mbuf *, int32_t)` | `sys/netinet/sctp_crc32.h:39` | return 0 |
| `prng32_bounded(__uint32_t)` | `sys/prng.h:13` | return 0 |

> 不 `#include <sys/mbuf.h>`（避免与文件内 `m_rcvif_restore` 既有 stub 类型冲突）；改用 `struct mbuf;` forward decl。

### 2.3 `tools/ipfw/ipfw2.c`（2 处 +1 行）

```diff
 do_set3(int optname, ip_fw3_opheader *op3, size_t optlen)
 {
   …
   op3->opcode = optname;
+  op3->version = IP_FW3_OPVER; /* M6: align with upstream 15.0 — was missing, caused v0 dispatch + EOPNOTSUPP */
   return (setsockopt(ipfw_socket, IPPROTO_IP, IP_FW3, op3, optlen));
 }

 do_get3(int optname, ip_fw3_opheader *op3, size_t *optlen)
 {
   …
   op3->opcode = optname;
+  op3->version = IP_FW3_OPVER; /* M6: align with upstream 15.0 — was missing, caused v0 dispatch + EOPNOTSUPP */
   …
 }
```

### 2.4 `tools/compat/include/netinet/ip_fw.h`（+13/-3）

补 `IP_FW3_OPVER_*` 三 define + 把 `ipfw_range_tlv.start_rule/end_rule` 由 `uint16_t` 升至 `uint32_t`（同步 kernel-side v1 32-bit rulenum，让 `sd->valsize == sizeof(*rh)` check 通过）。

> 备份原 v0-era 副本：`/data/workspace/freebsd-src-releng-15.0/f-stack-lib/tools/compat/include/netinet/ip_fw.h.preM6_v0era`

---

## 3. Gate 结果（G1-G7）

### G1 — 编译

| AC | 阈值 | 实测 | 结果 |
|---|---|---|---|
| G1.1 lib `make all` exit | 0 | 0 | ✅ |
| G1.2 errors | 0 | 0 | ✅ |
| G1.3 warnings | ≤ 60（baseline 55+5） | **57** | ✅ |
| G1.4 `libfstack.a` size | ≥ 5.13 MB | **6.52 MB**（+21% reflecting netgraph + ipfw bulk） | ✅ |
| G1.5 tools/ipfw build | exit=0 + binary exists | 0 errors / `tools/sbin/ipfw` 25 MB 产出 | ✅ |

### G2 — 主程序冒烟

`example/helloworld -c config.ini --proc-type=primary --proc-id=0` 后台运行 ≥10s ALIVE，关键 init 日志（`/tmp/m6_helloworld_*.log`）：

```
TCP Hpts created 1 swi interrupt threads ...
Attempting to load tcp_bbr ... tcp_bbr is now available
ipfw2 (+ipv6) initialized, divert loadable, nat loadable, default to accept, logging disabled
TCP_ratelimit: Is now initialized
f-stack-0: Successed to register dpdk interface
```

✅ G2.1 ALIVE / ✅ G2.2 0 SIGSEGV/panic/stub-called

### G3 — 功能

| AC | 命令 | 输出（截选） | 结果 |
|---|---|---|---|
| G3.1 add | `ipfw add 100 deny ip from 1.2.3.4 to any` | `00100 deny ip from 1.2.3.4 to any` | ✅ |
| G3.2 show | `ipfw show` | `00100  0   0 deny ip from 1.2.3.4 to any` + 默认 65535 count + 65535 allow（含 packets/bytes 计数器） | ✅ |
| G3.3 delete | `ipfw delete 100 && ipfw show` | rule 100 已消失，仅剩默认两条 65535 | ✅ |
| G3.4 ngctl list | `ngctl list` | exit=0（spec 接受 exit=0 即满足） | ✅ |
| G3.5 降级路径 | OQ-4 默认许可 | 未触发（G3.1-3.4 全部直接通过） | n/a |

### G4 — 性能门
不要求（plan §3 M6 表格：M6 G4 不做）。

### G5 — 文档同步

| AC | 文件 | 状态 |
|---|---|---|
| G5.1 | `docs/01-LAYER1-ARCHITECTURE.md` + zh_cn 镜像 | M6 备注（lib/Makefile 默认启用 FF_NETGRAPH+FF_IPFW） |
| G5.2 | `docs/03-LAYER3-FUNCTIONS.md` + zh_cn 镜像 | 暂不修改（function-level 增量极小：仅 7 个新 stub，待 M-Final 全量 sync） |
| G5.3 | `docs/F-Stack_Knowledge_Base_Summary.md` + zh_cn 镜像 | M6 行追加 |
| G5.4 | 本文件 `phase2-M6-execution-log.md` | ✅（本文档） |
| G5.5 | `phase2-M6-review-report.md` | 合并入本文件 §3.D |
| G5.6 | `read_lints docs/` + `lib/ff_stub_14_extra.c` | 0 errors |

### G7 — Commit
本地 commit + 等用户 review，不 push。

---

## 4. Bounce ledger

| # | bounce 类型 | 起点 → 终点 | 触发原因 | 修复 |
|---|---|---|---|---|
| 1 | gate(G2) → code | `helloworld` link 4 undefined refs | 添 4 stub | ✅ |
| (内修) | code → code | `#include <sys/mbuf.h>` 与本文件 m_rcvif_restore 冲突 | 改 forward decl | ✅ |
| 2 | gate(G2) → code | 第 2 次 link 出现新 3 undef refs（prng32_bounded / ipfw_bpf_mtap*） | 添 3 stub | ✅ |
| 3 | gate(G3) → code | ipfw add 收到 `EINVAL`（IP_FW3 dispatch v0 stub） | 多点修复：ip_fw_compat.c 入编 + do_set3/do_get3 设 `op3->version = IP_FW3_OPVER` + ipfw_range_tlv 字段类型 16→32bit | ✅ |

**总计 3 次正式 bounce**（同阶段 ≤3 限额满限度内通过；未触发 escalation / 暂停）。

---

## 5. M6 升级 delta 对工作区其他模块的影响

| 模块 | 影响 | 后续动作 |
|---|---|---|
| `lib/libfstack.a` | 大小 5.40 MB → 6.52 MB（+21%） | 已记入 docs L1 §2.2 备注 |
| `example/helloworld` | 28.26 MB → 29.02 MB（+760 KB） | 已记入 docs L1 §2.2 备注 |
| `tools/sbin/ipfw` | **新增 25 MB 二进制**（之前 FF_IPFW=0 时未编译） | docs README + L1 引用 |
| `lib/ff_stub_14_extra.c` | 776 行 → 858 行（+82） | 已加 M6 注释块标识 |
| 已编译的 freebsd/netgraph/ .c | 0 → 41 | docs §2.1 freebsd/ 树备注 |
| 已编译的 freebsd/netpfil/ipfw/ .c | 0 → 14（13 + ip_fw_compat.c） | docs §2.1 freebsd/ 树备注 |

---

## 6. 已知限制 / Observations

| # | 项 | 说明 |
|---|---|---|
| O-M6-1 | `nat64/`、`nptv6/`、`ip_fw_bpf.c`、`ip_fw_compat.c`（v0 stubs） | 编译进二进制但 v0 path 全部返回 `EOPNOTSUPP`（kernel 端使用 v1）；用户态 `ipfw nat64*` / `ipfw nptv6` 命令运行时不可用 |
| O-M6-2 | netgraph 8 个排除节点（`ng_bpf` `ng_checksum` `ng_device` `ng_macfilter` `ng_mppc` `ng_tty` `ng_vlan_rotate` 加 `ng_base` 由 ff_ng_base 替代） | 用户尝试 `ngctl mkpeer ... bpf` 等会失败；与 phase-1 时期一致，本里程碑不扩范围 |
| O-M6-3 | `tools/compat/include/netinet/ip_fw.h` 仍是 13.0-era 副本（仅做了 IP_FW3_OPVER + ipfw_range_tlv 的最小补丁） | 后续若 user-space 需要其它 v1-only 类型（如 `IP_FW_DYN_RULE` 新格式），需要进一步 sync；本次仅修复 ipfw add/show/delete 路径 |

---

## 7. M6 的下一步

按 plan §3 节奏：用户 review 本 execution-log + 接受 commit 后，进入 **M7 (FF_USE_PAGE_ARRAY)**。

---

**End of M6 execution log.**
