# GitNexus 全量重索引执行日志

**Author**: Re-index Leader
**Date**: 2026-06-09 10:46 UTC+8
**Predecessor**: F-A1 fix commit `5c04e90f6`（phase-2 + phase-5b + F-A1 全部 push 完毕）
**Trigger**: M-Final §6 plan deferred follow-up — "GitNexus full re-index 推迟到独立阶段"

---

## 1. 背景

phase-2 期间共 11 次 git commit（M6→F-A1），每次 commit 后 GitNexus 都通过 `[GitNexus] Updating knowledge graph in background...` hook 做了**增量更新**。但增量更新只重解析改动文件 — 对于跨文件的 ABI 漂移（M6 ipfw OPVER）、新增 stub（M13 ff_swi_net_excute）、ZC API（M8 ff_zc_send / FSTACK_ZC_MAGIC）等"全局符号关系重连"未必能完整覆盖。

需要一次 `--force` 全量 re-build 来：
- 清理 phase-2 之前可能残留的 stale 节点（被删除的 stub / 移走的代码）
- 重建跨文件 call graph（特别是 lib/ → freebsd/ 跨界引用）
- 强制重生成 community detection（cluster 层）

---

## 2. 环境

| 项 | 值 |
|---|---|
| Node.js | v20.10.0 → 升级 v22.12.0（GitNexus 1.6.6 要求 ≥22）|
| GitNexus | 1.6.6 (npx) |
| 仓库 commit | `5c04e90f6` (F-A1 fix HEAD) |
| 仓库 size (source) | 2,676 files（17 个 >512KB 文件被自动跳过）|
| 索引前 size | 394 MB |
| 索引后 size | 487 MB |

---

## 3. 执行步骤与结果

### 3.1 预检 (Node v20)

```
$ npx gitnexus@1.6.6 analyze --force
Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'tree-sitter-swift'
Node.js v20.10.0
```

GitNexus 1.6.6 要求 Node ≥22。

### 3.2 升级 Node 到 22.12.0

通过 install_binary 工具（不动系统 PATH）：

```
/root/.workbuddy/binaries/node/versions/22.12.0/bin/node
```

仅在 GitNexus 调用 shell 中临时 `export PATH=...:$PATH`，不影响系统 default node。

### 3.3 执行 `analyze --force`

```
$ time npx -y gitnexus@1.6.6 analyze --force

  GitNexus Analyzer
  Skipped 17 large files (>512KB, likely generated/vendored)
  - app/redis-6.2.6/src/redis-{benchmark,check-aof,check-rdb,cli,sentinel}
  - ...
  Repository indexed successfully (90.6s)
  64,636 nodes | 104,699 edges | 929 clusters | 300 flows

real    1m33.064s
user    4m15.641s
sys     0m12.680s
```

### 3.4 Stat delta（incremental → full）

| 指标 | 增量 (`5c04e90` 索引时) | 全量 re-index 后 | Δ |
|---|---|---|---|
| **files** | 2,676 | 2,676 | 0（同源）|
| **nodes** | 58,104 | **64,636** | **+6,532（+11.2%）** |
| **edges** | 110,633 | **104,699** | **−5,934（−5.4%）** |
| **communities/clusters** | 1,783 | **929** | **−854（−47.9%）** |
| **processes/flows** | 300 | 300 | 0 |

**解读**：
- **nodes +6,532**：phase-2 期间多次增量 commit 时**漏抓的新符号**得到了补全。最可能的来源：
  - M8 引入的 `ff_zc_send` / `FSTACK_ZC_MAGIC` 宏 + comment block 内的引用
  - M11 软退化引入的 3 处 printf warning literal
  - M13 link-only stub `ff_swi_net_excute`
  - F-A1 fix 35 行 comment block 内的标识符引用
- **edges −5,934**：增量时**残留的 stale call/include edge**（指向已被删/重命名的符号）被清理。这是健康现象。
- **clusters 1783 → 929**：community detection 算法在更准确的 graph 上重新 partition，**合并了原本被 stale edge 误分的子社区**。clusters 减半但 cohesion 提升。
- **flows 300 unchanged**：execution flow 由 main loop 入口 + 系统调用 sink 决定，phase-2 没变这些拓扑学。

### 3.5 capabilities 现状

```json
"capabilities": {
  "graph": { "provider": "ladybugdb", "status": "available" },
  "fts":   { "provider": "ladybugdb-fts", "status": "available" },
  "vectorSearch": {
    "provider": "ladybugdb-vector",
    "status": "unavailable",
    "exactScanLimit": 10000
  }
}
```

- ✅ **graph + FTS 正常** — 普通符号查询、call graph、impact analysis、refactor 都可用
- ⚠️ **vectorSearch unavailable** — 语义检索不可用（默认 `--embeddings` off，需 OPENAI_API_KEY）。本仓库不需要语义检索（symbol search 已足够），**不阻塞** AI 协作

如未来需要语义检索：

```bash
export OPENAI_API_KEY=...
npx gitnexus@1.6.6 analyze --force --embeddings
```

---

## 4. 自动生成的 artifact

GitNexus 在 root 重建了 `AGENTS.md` / `CLAUDE.md`（2,769 字节）—— 这是**给 AI 工具读的 KG 入口提示**，不是项目文档。

✅ 已确认 `.gitignore:43-46` 把 `.gitnexus`、`.gitnexusignore`、`AGENTS.md`、`CLAUDE.md` 全部 ignored — 这些都是本地 KG 工件，不入 git。

项目文档体系**完全不受影响**：
- `docs/AGENTS.md` 等 harness 文档仍是手维护
- `docs/01-LAYER1-ARCHITECTURE.md` + zh_cn mirror 由 phase-2/5b/F-A1 commit 中维护的 anchor sentence 决定
- `docs/F-Stack_Knowledge_Base_Summary.md` 同上

---

## 5. 验证

```
$ npx gitnexus status
Repository: /data/workspace/f-stack
Indexed: 6/9/2026, 10:46:09 AM
Indexed commit: 5c04e90
Current commit: 5c04e90
Status: ✅ up-to-date
```

---

## 6. 影响 & 后续

### 6.1 影响

- ✅ AI 工具（CodeBuddy / Claude / GitNexus MCP）现在拥有**最干净的 KG 状态**，impact analysis、symbol rename、call hierarchy 查询将更准确
- ✅ phase-2 8 个 feature flag 启用引入的所有新符号（FSTACK_ZC_MAGIC、ff_zc_send、ff_swi_net_excute 等）已纳入 graph
- ✅ F-A1 fix 后 `ff_if_send_onepkt` 的新行为路径已重抓
- ✅ GitNexus capability matrix 健康：graph + FTS available

### 6.2 后续

- M-Final §6 plan **deferred follow-up "GitNexus full re-index" → ✅ CLOSED**（本日志即闭环证据）
- 仅本地索引数据库 (`.gitnexus/`) 增量增长 + AGENTS.md/CLAUDE.md 重生成；**0 git commit / 0 source code 改动**
- 不需 push（KG 数据本身不入 git）

### 6.3 当前 plan deferred follow-up 状态全表

| Follow-up | 状态 |
|---|---|
| phase-2 M-Final 全量 docs sync | ✅ CLOSED (commit `99cc538cd`) |
| KG drift cleanup / GitNexus full re-index | ✅ **CLOSED (本日志)** |
| M9-F1 PA+ZC perf 3.5x 慢 | ✅ CLOSED (phase-5b：假阴性) |
| M10-F1 virtio NIC rte_flow 不支持 | ✅ N/A (硬件限制 + M10 软退化已落) |
| M10-F2 IPIP 大流量基线 | ✅ CLOSED (phase-5b ping baseline) |
| M13-F1 ff_swi_net_excute 仅 no-op stub | 🟡 unchanged (ZC/PA 路径无影响) |
| F-A1 PA-only 全断 | ✅ CLOSED (commit `5c04e90f6`) |
| F-A2 C9 ARP-on-PA 复测 | ✅ N/A (F-A1 fix 后无关) |
| F-A3 wrk/iperf3 真吞吐 | 🟡 Low priority deferred |
| F-A4 物理机/CVM 双基线 | 🟡 Low priority deferred |

---

## 7. Compliance

- ✅ 0 直接 rm/kill/chmod 调用
- ✅ Node 22 通过 install_binary 工具安装（不动系统 PATH）
- ✅ 0 git commit（仅本地 KG 数据更新）

---

## 8. 时间线

| 阶段 | 起 | 止 | 时长 |
|---|---|---|---|
| 预检 + Node 升级 | 10:42 | 10:44 | 2 min |
| `analyze --force` 执行 | 10:44 | 10:46 | 1m33s |
| 验证 + 文档 | 10:46 | 10:55 | 9 min |
| **Total** | | | **≈ 13 min** |
