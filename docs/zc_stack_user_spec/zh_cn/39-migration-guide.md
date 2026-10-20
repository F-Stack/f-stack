# 39. 已部署项目迁移指南

> 适用对象：已使用 `FF_ZC_SEND=1` 编译并部署 f-stack 的项目
> 目标：从旧魔改方案（FSTACK_ZC_MAGIC + m_uiotombuf）迁移至新原生方案（kern_zc_sendit + sosend(top)），过程透明、ABI 不变

---

## §1 迁移摘要

| 维度 | 影响 |
|---|---|
| 应用层源码 | **零修改**（ff_zc_send / ff_zc_mbuf_get / ff_zc_mbuf_write 签名不变；example/main_zc.c 不需改）|
| 编译开关 | `FF_ZC_SEND=1` 不变（含义切换：从"魔改启用"→"原生路径启用"，对外透明）|
| ABI / 符号 | `ff_zc_send` 单符号不变；`ff_api.symlist` 不增不减 |
| 重新编译 | **必须**（lib + example 全量重编；详见 §3）|
| 内核 patch | 内置在 f-stack 自带 freebsd 树；用户无需自行 patch 上游内核 |
| 行为变化 | 大数据 send 不再 crash/hang（issue #712）；错误码语义对齐 sosend(9)；详见 §4 |

---

## §2 升级步骤

### §2.1 拉取新版本

```
cd <project>/f-stack
git fetch origin
git checkout <new-tag-or-branch>      # 含本 spec 实施期 commit
```

### §2.2 强制全量清理重编（避免 stale .o，M2 教训）

> **关键警告**：M2 阶段曾因增量编译跳过 `uipc_mbuf.o` 重编译导致 ZC-send hook 缺失（详见 21-m2-test-report.md §RCA）。新方案虽不再依赖 m_uiotombuf 魔改，但 `kern_zc_sendit` 是新增源文件，**仍必须 `make clean`** 才能保证旧 `uipc_syscalls.o` 被替换为新版（含 kern_zc_sendit）。

```
cd lib
PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig make clean
PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig FF_ZC_SEND=1 make
```

### §2.3 验证 lib 构建产物含新符号

```
nm libfstack.a | grep -E "T (kern_zc_sendit|ff_zc_send)$"
```

应同时命中（`kern_zc_sendit` 来自 freebsd/kern/uipc_syscalls.o，`ff_zc_send` 来自 lib/ff_syscall_wrapper.o）。

### §2.4 验证旧符号已消失

```
grep -rn "FSTACK_ZC_MAGIC" freebsd/ lib/      # 应 0 命中
nm libfstack.a | grep -i magic                # 应 0 命中
```

### §2.5 重新编译用户 server

```
cd ../example   # 或用户自己的 server
PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig make clean
PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig FF_ZC_SEND=1 make
```

### §2.6 启动并 smoke test

```
# 启动（保持原启动方式）
./helloworld_zc --conf /path/to/config.ini --proc-type=primary

# client smoke
ssh f-stack-client "curl -s -o /dev/null -w 'http=%{http_code}\n' http://<server-ip>/"
# 期望: http=200
```

---

## §3 行为变化（用户感知）

### §3.1 不变项

| 项 | 旧 | 新 |
|---|---|---|
| ff_zc_send 签名 | `ssize_t ff_zc_send(int, const void *, size_t)` | 同 |
| 调用序列（get → write → send） | 同 | 同 |
| 成功返回值 | 字节数 | 字节数 |
| 错误返回 | -1 + errno | -1 + errno |
| `FF_ZC_SEND` 编译开关 | 启用 | 启用（但内部走原生路径）|

### §3.2 变化项

| 项 | 旧（魔改）| 新（原生）|
|---|---|---|
| 大数据（> SO_SNDBUF）发送 | **crash/hang**（issue #712）| 阻塞 sosend / 非阻塞返 EWOULDBLOCK；调用方需自分片 |
| 错误码 EMSGSIZE（UDP > MTU）| 旧路径未覆盖到，行为不定 | 明确返回 EMSGSIZE |
| 错误码 ENOBUFS（atomic 缓冲耗尽）| 旧路径不规范 | 明确返回 ENOBUFS |
| 普通 ff_write/ff_writev 与 ZC 共存 | 需 uio_offset=0 opt-out 防误触；M8 阶段曾 GPF | 无需 opt-out（kern_writev 路径不感知 ZC）|
| make 增量陷阱 | 易触发（5 处魔改文件中任一 stale .o → bad chain）| 大幅减小（仅 kern_zc_sendit 是新文件）；仍建议 make clean |
| FreeBSD 上游升级 | 需重新审计 m_uiotombuf 周边 ~120 行 | 几乎无侵入；仅需检查 kern_zc_sendit 调用的 sosend 签名 |

### §3.3 性能

预期 Δ ≤ ±3%（详见 38-perf-baseline-spec.md PERF-2）。原方案与新方案在 sosend 跳过 m_uiotombuf 这一关键点行为等价；新方案的额外开销在 kern_zc_sendit 入口的 `getsock + MAC` 检查（与 kern_sendit 一致），这部分原方案走 kern_writev 时同样存在。

---

## §4 调用方代码审查清单

虽然 ABI 不变，迁移者**应**复查应用层代码是否触及以下"灰区行为"：

| # | 检查 | 旧行为 | 新行为 | 建议 |
|---|---|---|---|---|
| 1 | 单次 ff_zc_send 数据量 > SO_SNDBUF | crash/hang | EWOULDBLOCK / 阻塞 | 自分片：`for (chunks of MIN(SNDBUF, total))` |
| 2 | UDP 单包 > MTU | 不定行为 | EMSGSIZE | 拆包发送 |
| 3 | TCP socket + MSG_EOR | 旧 API 未暴露 flags | 新 API 暴露后立即 EINVAL（uipc_socket.c:2354）| 不要在 TCP 设 MSG_EOR |
| 4 | ff_zc_send 后再访问 zc_buf.bsd_mbuf | UAF（旧也是）| UAF（新强 spec 35 INV-2 显式禁止）| send 后立即丢弃指针 |
| 5 | 期望 ff_zc_send "send 多少 nbytes 就发多少" | 是 | 实发 = top->m_pkthdr.len（即 ff_zc_mbuf_write 累计写入）| 保证 nbytes >= 累计 write 量 |

---

## §5 回退方案

若新方案在生产环境触发 unexpected 错误：

### §5.1 紧急关闭 ZC（不重编）

不可直接禁用 — `FF_ZC_SEND` 是编译期开关。需重编译。

### §5.2 重编为非 ZC 版本（最快）

```
cd lib
PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig make clean
PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig make            # 不带 FF_ZC_SEND
```

应用代码若仍调用 `ff_zc_send` 会链接报错；建议运行时通过条件编译或动态 dispatch 切换：

```c
#ifdef FSTACK_ZC_SEND
    n = ff_zc_send(fd, zc_buf.bsd_mbuf, len);
#else
    /* fallback to ff_writev with normal char* buffer */
    n = ff_write(fd, char_buf, len);
#endif
```

→ 这要求应用层维护**两套发送路径**；ABI 上 ff_zc_send 在不带 `FSTACK_ZC_SEND` 时不存在。

### §5.3 git revert 到旧魔改版本

```
git revert <new-impl-commit>      # 回退到 commit 之前
make clean && make
```

旧魔改版本仍在历史 commit 中可用，但本期 spec 实施完成后 master 不再保留。

---

## §6 升级前自检清单

| # | 检查项 | 通过标准 |
|---|---|---|
| 1 | 你的应用是否使用 `FF_ZC_SEND`？ | 否 → 无影响；是 → 继续 |
| 2 | 你的应用是否跑过 issue #712 场景（大包 send）？ | 是 → 强烈建议升级（修复 crash）|
| 3 | 你的应用是否调 ff_zc_send 时传入 nbytes < 实际 write 累计量？ | 是 → 升级前修复 |
| 4 | 你的应用是否在 ff_zc_send 后再访问 zc_buf.bsd_mbuf？ | 是 → 升级前修复（INV-2 违反）|
| 5 | 你的部署是否曾遇 stale .o 类问题？ | 是 → 升级时务必 `make clean` |
| 6 | 你是否 fork 了 f-stack 自带 freebsd 树并自行 patch？ | 是 → 升级时合并冲突，对照 31 删除清单 |

---

## §7 临时文件 / 进程清理规约

> 重要：升级与回退过程中产生的临时文件、build 残留、stale 进程，**必须**经规约脚本处理，详见 §2.2 / §5。

| 操作 | 必须用脚本 |
|---|---|
| 清理 stale `.o`、build 中间产物 | `/data/workspace/rm_tmp_file.sh <abs-path>...` |
| 清理 hugepage rtemap | `/data/workspace/rm_tmp_file.sh /dev/hugepages/rtemap_*`（注：实际使用需先 `ls` 拿到具体文件路径列表）|
| 终止 server 进程 | `/data/workspace/kill_process.sh <pid>` 或 `<process_name_pattern>` |
| 给新脚本加 +x | `/data/workspace/chmod_modify.sh +x <abs-path>` |

不允许在升级文档/脚本中出现直接的 `rm`/`kill`/`pkill`/`chmod` 命令字符串。

---

## §8 FAQ

**Q1：升级后 example/main_zc.c 需要改吗？**
不需要。本期 spec 的 ABI 不变性条款（G4）保证 example/main_zc.c L208-245 的 ZC 调用序列零修改通过。

**Q2：升级后旧编译的 server 二进制还能用吗？**
不能直接复用。`kern_zc_sendit` 是新符号，旧二进制链接的旧 lib 不含此符号；需重新编译 server 二进制。

**Q3：性能会下降吗？**
预期 Δ ≤ ±3%（噪声内）。新路径在 sosend(top) 跳过 m_uiotombuf 这一关键点上行为等价；额外的 getsock+MAC 与 kern_sendit 一致，原方案也存在。详见 38-perf-baseline-spec.md。

**Q4：是否还可以与 `FF_USE_PAGE_ARRAY` / `FF_ZC_RECV` 同时启用？**
可以。三者互不依赖；新方案保持开关独立性（`FF_ZC_SEND` / `FF_ZC_RECV` / `FF_USE_PAGE_ARRAY` 任意组合）。

**Q5：FreeBSD 上游再升级时，新方案会不会比旧方案更稳？**
是。新方案只新增 `kern_zc_sendit`（不修改 sosend 内部、不修改 m_uiotombuf），上游升级时只需校验 `sosend(...)` 签名是否变化（极少）即可，迁移成本远低于旧方案的 m_uiotombuf 重审计。

---

## §9 可门禁验证条款（gatekeeper）

| 条款 | 验证方式 | 通过判据 |
|---|---|---|
| M-G1 | spec 列出 ABI 不变项与变化项 | 表格命中 |
| M-G2 | spec 列出 `make clean` 必要性 | §2.2 + §3.2 |
| M-G3 | spec 不出现直接 rm/kill/chmod 命令 | 自动 grep |
| M-G4 | spec 列出回退方案 | §5 |

---

下一篇：**40-acceptance-and-milestones.md**（验收 + M0-M5 里程碑）。
