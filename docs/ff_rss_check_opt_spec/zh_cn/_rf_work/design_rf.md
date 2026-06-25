# R-F 修复方案设计（design_rf）

> 写角色：leader 接管（原 designer 子 agent 为只读 code-explorer，无写文件能力，已完成全部只读核验并交付行号事实，leader 据此接管落盘；后续由独立 reviewer 子 agent 审核，满足写/审分离）。
> 权威根因：以 `_rf_work/arbiter_rootcause.md` 裁决为最终结论 —— **0.2 真因 = key 不一致（非字节序）**。
> 已数学证明 `rte_softrss(be_to_cpu_32(bytes)) ≡ toeplitz_hash(bytes)`，字节序/GFNI 假设已被位级推翻、作废。
> 代码版本：f-stack 当前 `lib/ff_dpdk_if.c`、`lib/ff_config.{c,h}`。所有行号为实际文件行号（leader 已逐一交叉验证）。
> 修复路线：**路线③（用户定夺）= ①根因修复为主 + ②软扫描兜底，新增运行时配置开关切换，真机实测后定最终启用**。

---

## 1. 根因复述（权威，禁止重新引入字节序假设）

- **0.1（secondary 全部 init 失败）**：`ff_rss_thash_ctx_init`（L2972-3043）的 ctx name 仅含 port_id
  （`ff_rss_thash_%u` L2993、`ff_rss_thash6_%u` L3023），而 `rte_thash_init_ctx` 在 EAL 进程间共享
  tailq 上做全局重名检查、命中返 `EEXIST`→NULL。primary 先占名，所有 secondary 同名 init 必败
  （L2995 `ctx==NULL`→continue），secondary 动态路径全退化软扫描。入口调用点（L1476 附近）
  primary/secondary 均执行、无 `process_type` 守卫。
- **0.2（thash 选端口不通）= key 不一致**：`rte_thash_add_helper`→`generate_subkey` 用 LFSR m-序列
  **原地改写 `ctx->hash_key`**；adjust 内部 `rte_thash_get_key(ctx)` 取**改写后** key 反算 sport，
  而 `ff_rss_check`（L2951，用全局 `rsskey`）与 NIC（L742，端口 init 用原始 `rsskey`）用**原始** key；
  `ff_rss_thash_ctx_init` 在 `add_helper` 后**从不** `get_key`/不更新 `rsskey`/不 `rss_hash_update`
  → 三方 key 不同 → 反算端口在原始 key 下落点≈随机（22-27% 巧合）→ 经常不通、recheck 多次仍不通；
  `enable=0` 纯软算全程原始 key 自洽 → 真机正确。

### 1.1 改写字节段（实测宏值，决定 v4/v6 耦合）

| 路径 | sport offset/len（宏） | generate_subkey 改写 bit 范围 = [off, off+len+TOEPLITZ_HASH_LEN-1] | key 字节段 |
|---|---|---|---|
| v4 | `FF_RSS_THASH_V4_SPORT_OFF=64` / `LEN=16` | bit[64, 64+16+32-1]=bit[64,111]（实际写至 110） | **字节 8-13** |
| v6 | `FF_RSS_THASH_V6_SPORT_OFF=256` / `LEN=16` | bit[256, 303]（实际写至 302） | **字节 32-37** |

`TOEPLITZ_HASH_LEN=32`；默认 key 40 字节（320 bit）。v4 段与 v6 段**不重叠**。

### 1.2 hash 对 key 的依赖范围（关键耦合点）

- v4 tuple 12 字节 → Toeplitz 用 key 前 **16 字节**（含字节 8-13，不含 32-37）。
- v6 tuple 36 字节 → Toeplitz 用 key 前 **40 字节**（含字节 8-13 **与** 32-37）。
- ⇒ **v6 hash 依赖 v4 改写的字节 8-13**；而一张 NIC 只能编程**一把** key。
  ⇒ 路线① 要让 v4、v6 的 check/adjust/NIC 三方同时对齐，**v6 ctx 必须基于「v4 已改写字节 8-13 的 key」初始化**（串行构造），不能各自从原始 key 独立 init。

---

## 2. 路线①（根因修复，默认启用）详细设计

### 2.1 key 串行构造（primary 进程，per port）

```
原始 rsskey (40B)
  │
  ├─[v4] init_ctx("ff_rss_thash_%u", rsskey)  + add_helper(v4,off=64,len=16)
  │        → rte_thash_get_key(ctx_v4) = KEY_V4 (字节8-13 = v4 m-序列, 其余原始)
  │
  ├─ 构造 K1 = rsskey 副本; K1[8..13] = KEY_V4[8..13]
  │
  ├─[v6] init_ctx("ff_rss_thash6_%u", K1) + add_helper(v6,off=256,len=16)
  │        → rte_thash_get_key(ctx_v6) = KEY_FINAL (字节8-13 = v4改, 字节32-37 = v6改, 其余原始)
  │
  ├─ 全局 rsskey ← KEY_FINAL（需 malloc 持久 buffer 持有，因 rsskey 为指针；不可指向栈/ctx 内部）
  └─ rte_eth_dev_rss_hash_update(port, {rss_key=rsskey, rss_key_len, rss_hf})
```

正确性校验（位级）：
- NIC = KEY_FINAL。
- v4 check 用 KEY_FINAL 前16字节 = {字节0-7原始, 8-13 v4改, 14-15原始}；adjust 用 ctx_v4 key 前16字节 = 同值（ctx_v4 字节0-7,14-15 原始、8-13 v4改）→ **v4 三方一致** ✓。
- v6 check 用 KEY_FINAL 前40字节；adjust 用 ctx_v6 key（基于 K1 → 字节8-13 v4改、其余原始、再 add_helper 改 32-37）= KEY_FINAL → **v6 三方一致** ✓。

> 若仅启用 v4（v6 init/add_helper 任一失败）：全局 rsskey ← KEY_V4，NIC 上传 KEY_V4；v4 一致，v6 动态路径禁用（走软扫描）。
> v4 失败：本 port 全程软扫描，不上传任何改写 key（rsskey 保持原始，与 NIC 一致）。

### 2.2 primary / secondary 分支

`rte_eal_process_type()`（或 `ff_global_cfg.dpdk.proc_type`）判断：

- **primary**：执行 2.1 全套（init+add_helper+串行构造+get_key+写全局 rsskey+`rss_hash_update`）。
- **secondary**：
  - `rte_thash_find_existing("ff_rss_thash_%u")` / `..._6_%u` 复用 primary 共享 ctx（**不 init、不改 NIC**）。
  - `rte_thash_get_helper(ctx,"sport")` 取 helper（adjust 需要）。
  - 取 key 同步本进程全局 `rsskey`：优先 `rte_thash_get_key(ctx_v6)`（= KEY_FINAL，含 v6 段）；
    若仅 v4 ready 则用 `rte_thash_get_key(ctx_v4)`（= KEY_V4）。secondary 独立地址空间，需把此 key
    复制进本进程 malloc buffer 并令全局 `rsskey` 指向它，使本进程 `ff_rss_check` 与 primary 上传 NIC 的 key 一致。
  - find_existing 失败（ENOENT，正常时不应发生）→ 本进程禁用 thash adjust、走软扫描，**不动** 全局 rsskey（保持原始，但此时 NIC 是 primary 上传的改写 key → check 会不一致）。

  > ⚠ secondary find_existing 失败属异常分支：此时本进程 check 用原始 key 而 NIC 是改写 key，
  > 软扫描也会错。设计上 secondary 必须成功 find_existing 才能保证一致；失败应记 WARNING 并
  > 同样退回路线②语义（让 adjust_sport return -1 走内核软扫描）——但需在 02/07 spec 标注此残余风险，
  > 由真机 SOP 验证 secondary 是否稳定 find_existing 成功。

### 2.3 `rss_hash_update` 失败处理（驱动不支持等）

`rte_eth_dev_rss_hash_update` 返回 `-ENOTSUP/-EINVAL/-ENODEV/-EIO` 任一非 0：
- **回滚**：全局 `rsskey` 恢复为**原始**（free 掉 KEY_FINAL buffer，rsskey 重新指向 `default_rsskey_40bytes`/52）；
- 标记本 port `rss_thash_ready=0`、`rss_thash6_ready=0`（禁用 adjust）；
- 记 WARNING：NIC 不支持改 key，自动切路线②软扫描。
- 此时 NIC = 原始（端口 init 已下发原始），check = 原始，一致 → 软扫描正确。

> 时序要点：端口 init（L742 设 rss_key=rsskey 指针，`rte_eth_dev_configure` 时下发原始 key）
> 在 ctx_init（L1476 附近）**之前**。故 ctx_init 阶段改 key 必须用 `rss_hash_update` 重传，
> 不能仅改全局指针。改 key 须在**无业务流量窗口**（端口已 configure、尚未大量收发时）完成。

### 2.4 adjust_sport（L3052+ / v6 L3391+）

key 对齐后逻辑基本不变（仍 `rte_thash_adjust_tuple` 反算 + 可选 recheck）。仅需：
- 入口增加路线判定：仅当 `cfg.thash_adjust` 生效、对应 `rss_thashX_ready==1`、key 已成功上传 NIC 时才走 adjust；
  否则直接 `return -1`（→ 内核侧软扫描，已验证正确）。v4/v6 对称。

---

## 3. 路线②（软扫描兜底）设计

复用既有兜底链，**最小实现**：当配置开关关闭根因修复、或 ctx 不可用、或 `rss_hash_update` 失败、或 secondary find_existing 失败时：
- `ff_rss_thash_ctx_init` 不改全局 `rsskey`（保持原始，与 NIC 原始 key 一致）；
- `ff_rss_adjust_sport`/`6` 直接 `return -1` → 触发既有内核侧软扫描（用 `ff_rss_check` 原始 key 口径，**真机已证明正确**）。
- 零 NIC 行为变更。

---

## 4. 配置开关设计（ff_config）

仿现有 `enable`/`recheck`（`ff_config.c` `rss_check_cfg_handler` L931-960；结构 `ff_config.h` `struct ff_rss_check_cfg` L241-247）。

- **新增字段**：`int thash_adjust;`（加入 `struct ff_rss_check_cfg`，置于 `recheck` 之后）。
  - 语义：`thash_adjust=1` → 路线①（取回改写 key、同步全局 rsskey、`rss_hash_update` 上传 NIC）。
  - `thash_adjust=0` → 路线②（不改 key、不用 adjust，adjust_sport 直接 return -1 走内核软扫描）。
  - **默认值 = 1（路线③以①为主）。落地写法（采纳审核 R7）**：`rss_check_cfgs` 由 `rss_check_cfg_handler` 首次 `calloc`（ff_config.c L941，默认全 0），故**必须在该首次 calloc 之后立即显式 `rcc->thash_adjust = 1;`**，再由后续 `thash_adjust=` 行覆盖。这样：配了 `[rss_check]` 段未写 thash_adjust → 默认 1 走①；写 `thash_adjust=0` → 切②。
  - 边界：完全不配 `[rss_check]` 段时 `rss_check_cfgs==NULL`，意味 thash 动态路径默认仍按 1 处理（rcc==NULL 视为开），与原默认语义一致。
- **解析**：`rss_check_cfg_handler`（L931-963）内 `else if (strcmp(name,"thash_adjust")==0) cur->thash_adjust = atoi(value);`，并在该函数首次分配 `rcc` 后置 `rcc->thash_adjust = 1;`。
- **门控范围（与 `rss_check.enable` 解耦）**：`ff_rss_thash_build_key` 与 `ff_rss_thash_ctx_init` 的**调用**现由 `thash_adjust` 门控（rcc==NULL 也视为开，保持原默认语义），不再随 `rss_check.enable` 启停；`ff_rss_tbl_init`/`ff_rss_tbl6_init` 仍归 `enable`。`ff_rss_adjust_sport`/`_sport6` 的 route② 守卫同样按 `thash_adjust` 判定。
- config.ini `[rss_check]` 段示例（仅文档，不入仓库本地测试值）：
  ```ini
  [rss_check]
  enable=1
  recheck=1
  thash_adjust=1   ; 1=根因修复(改NIC key) 0=软扫描兜底
  ```

> 真机若 `rss_hash_update` 不可用，用户改 `thash_adjust=0` 即切②，无需改代码重编。

---

## 5. 改动清单（lib，v4/v6 对称，最小 diff）

| 文件 | 函数/位置 | 改动 |
|---|---|---|
| `lib/ff_config.h` | `struct ff_rss_check_cfg` L241 | 新增 `int thash_adjust;` |
| `lib/ff_config.c` | `rss_check_cfg_handler` L951+ | 解析 `thash_adjust`；默认 1 兜底 |
| `lib/ff_dpdk_if.c` | `ff_rss_thash_ctx_init` L2972-3043 | primary/secondary 分支；v4 串行→v6；get_key 串行构造 KEY_FINAL；写全局 rsskey(malloc 持久)；`rss_hash_update`；失败回滚 |
| `lib/ff_dpdk_if.c` | `ff_rss_adjust_sport` L3052+ / `_sport6` L3391+ | thash_adjust/ready/上传成功 才走 adjust，否则 return -1 |
| `lib/ff_dpdk_if.c` | 新增 helper（static） | `ff_rss_thash_sync_key()` 等封装串行构造+上传+回滚（仅必要注释） |

> 不改内核侧；不改 `set_rss_table`（RETA=idx%nb_queues 前提已确认）；保持现有 attempts/-1 回退结构。

---

## 6. 风险与真机验证点（本机 virtio reta=0 无法端到端验证）

1. `rte_eth_dev_rss_hash_update` 驱动支持性（部分网卡 -ENOTSUP / 改 key 重置队列）→ SOP 实测；不支持则 `thash_adjust=0`。
   - **rss_hf 必须回填实际值**（impl-review BLOCK-1）：Intel PMD（i40e/ixgbe/ice）会将 `rss_hf==0` 解读为"关闭 RSS"。实现必须先 `rte_eth_dev_rss_hash_conf_get(port_id, &cur)` 取当前 hf 回填到 update 入参，避免传 0。
2. 改 NIC key 须在无流量窗口（init 早期）→ 已在 ctx_init 阶段（端口刚 configure）。
3. secondary `find_existing` 是否稳定成功（多进程启动时序）→ SOP 实测；失败有残余不一致风险（§2.2 ⚠）。
4. RETA 真为 idx%nb_queues（用户已确认 set_rss_table 写入）→ SOP 可选 `rte_eth_dev_rss_reta_query` 复核。
5. v4/v6 串行构造正确性 → 单测离线对拍（同 KEY_FINAL 下 adjust 选出的 sport 经 ff_rss_check 必落 desired 队列）。
6. **多 port 残余风险（impl-review BLOCK-2，design 自身盲区修订）**：
   - 全局 `rsskey` 是单实例指针（`ff_dpdk_if.c:120-121`），而 `ff_rss_check`/`adjust_sport` 不按 port 区分 key。若按 port 循环各自串行构造 + 写全局 `rsskey`，第 N 轮的 init_ctx 基 key 已被前一轮 KEY_FINAL 污染，且前一轮 `rte_malloc` 的 buffer 悬挂泄漏。
   - **本期最小修法**：仅对**首个有效 port**（`reta_size >= 2`）执行 §2.1 串行构造 + §2.3 NIC 上传；其余 port `rss_thashX_ready=0` 走软扫描兜底。这与 F-Stack 主流单 port 部署假设一致。
   - 多 port 部署需更深改造（per-port `rsskey` 数组 + `ff_rss_check`/`adjust` 按 port 取 key），不在本期范围。
   - 实现细节：循环入口保存 `orig_rsskey`/`orig_len`，每轮 init_ctx 都用 `orig_rsskey` 而非可能已被替换的全局 `rsskey`；旧 `new_rsskey` 覆盖前 `rte_free` 释放（防泄漏）；处理完首个有效 port 后 `break`。

---

## 7. 单测要点（tests/unit/test_ff_dpdk_if.c + test_ff_config.c，cmocka，既有用例零回归）

> **单测 vs SOP 分工说明（gatekeeper N2 采纳）**：本节列出的 T-RF1/2/3/5 中，T-RF2/T-RF3（adjust 选 sport 真落 desired 队列）与 T-RF5（hash_update 失败回滚）依赖完整 EAL/DPDK ctx 与真 PMD 行为，单测层难以构造；本期实际落地为下面两个层级：
> - **单测层（test_ff_dpdk_if.c + test_ff_config.c，4 用例）**：覆盖 T-RF4 的 `thash_adjust` 配置开关解析（默认 1 / 显式 0）+ `adjust_sport*` 与 `ctx_init` 的 route② 守卫返回值。
> - **真机/离线对拍层（realmachine_sop.md §3 P3）**：T-RF2/T-RF3（v4/v6 三方 key 对齐反算等价率）+ §1/§2（路线①/② 切换）+ §4（RETA 假设 query）。
> 这是经过推理的工程取舍，不是单测覆盖疏漏。

- T-RF1：secondary 路径用 `find_existing` 复用同一 ctx（mock 多进程或验证命名不再含 proc_id、find_existing 返回非空）。
- T-RF2：串行构造 KEY_FINAL 后，测试侧独立 toeplitz 复算：对随机元组，adjust 选出的 sport 用**同一 KEY_FINAL** 复算 `ff_rss_check` 必命中 desired 队列（等价率应 ~100%，对照修复前 22-27%）。
- T-RF3：v6 对称（KEY_FINAL 含 v6 段，v6 adjust→check 命中）。
- T-RF4：`thash_adjust=0`（或 ctx 不可用 / hash_update 失败 mock）→ adjust_sport return -1（软扫描兜底）。
- T-RF5：`rss_hash_update` 失败回滚 → 全局 rsskey 恢复原始、ready=0。

---

## 8. 可追溯性

| 需求 | 根因 | 方案 | 用例 | 门禁 |
|---|---|---|---|---|
| 0.1 secondary init | tailq 同名 EEXIST | §2.2 primary建+secondary find_existing 共享单 ctx | T-RF1 | name 不含 proc_id、find_existing 复用 |
| 0.2 选端口不通 | key 不一致 | §2.1 串行构造+§2.3 上传NIC / §3 软扫描兜底 | T-RF2/3/4/5 | 三方 key 一致、兜底 return -1、字节序非根因表述 |
| 路线③开关 | — | §4 thash_adjust | T-RF4 | 默认1、可切0 |
