# 诊断员B — DPDK rte_thash 源码考据（只读，以实际代码为准）

源码：`/data/workspace/dpdk-stable-23.11.5/lib/hash/rte_thash.c` 与 `rte_thash.h`
F-Stack 对照：`/data/workspace/f-stack/lib/ff_dpdk_if.c`
结论原则：仅基于源码事实，不臆测。

---

## 1. rte_thash_init_ctx 的命名对象 / 多进程语义（对应问题 0.1）

### 代码事实
- ctx 用 **TAILQ + rte_zmalloc** 管理，注册的 tailq 名为 `"RTE_THASH"`：
  - `rte_thash.c:22-26` `EAL_REGISTER_TAILQ(rte_thash_tailq)`，name = `"RTE_THASH"`。
- `rte_thash_init_ctx`（`rte_thash.c:234-322`）：
  - `rte_thash.c:250` 取 `rte_mcfg_tailq_write_lock()`（全局 mcfg 锁，primary/secondary 共享）。
  - `rte_thash.c:253-262` 先遍历 tailq，**若已存在同名 ctx → `rte_errno = EEXIST; return NULL`**。
  - `rte_thash.c:265` tailq entry 用 `rte_zmalloc("THASH_TAILQ_ENTRY", ...)`。
  - `rte_thash.c:274` ctx 本体 `rte_zmalloc(NULL, sizeof(ctx)+key_len, 0)`。
- **lookup API 存在**：`rte_thash_find_existing(const char *name)`（`rte_thash.c:324-348`），按 name 遍历 tailq 命中返回 ctx，未命中 `rte_errno = ENOENT`。头文件 `rte_thash.h:294-305` 明确文档化该 API。

### 关键多进程语义结论
**rte_thash ctx 是"由 primary 创建、通过命名 tailq 在 secondary 共享"的对象，secondary 不应再次 init_ctx，应改用 find_existing。**

1. `rte_zmalloc` 分配自 hugepage 共享堆，tailq 元数据存于 mcfg 共享内存，primary 创建后 secondary 进程**理论上可见同名 entry**。
2. 但 **F-Stack 当前所有进程（含 secondary）都各自调用 `ff_rss_thash_ctx_init` → `rte_thash_init_ctx`**（`ff_dpdk_if.c:2994`、`3024`），用的是**相同 name**（`ff_rss_thash_%u` / `ff_rss_thash6_%u`，按 port_id，**不含 lcore/proc 区分**）。
   - primary 先建成功；secondary 后到，命中 `rte_thash.c:253-262` 的同名检查 → 返回 **NULL（EEXIST）**。
   - 这与现象 0.1「主进程成功、所有 secondary 失败」**完全吻合**。
3. **另一隐患（更深层）**：`generate_subkey`（`rte_thash.c:402-435`）会**改写 ctx->hash_key**（写 m-sequence），`rte_thash_add_helper` 内调用之。即 init+add_helper 是**有写副作用**的构造过程；多进程各自 init 会各自改 key，语义上 thash ctx 设计为单写者构造。secondary 重复构造既不必要也被 EEXIST 拒绝。

> 注：rte_thash 头文件未声明任何 "multi-process safe / process-shared" 宏；`rte_thash_add_helper` 文档明确标 *"not multi-thread safe"*（`rte_thash.h:320`）。adjust/get_complement 标 *multi-thread safe*（只读）。即：**构造期（init/add_helper）非并发安全；查询期（adjust/get_complement/get_key）只读安全。**

### 0.1 修复方向（可行性）
- **方案A（推荐，符合 DPDK 习惯）**：仅 primary 执行 init_ctx+add_helper；secondary 调 `rte_thash_find_existing(name)` 拿 ctx，再 `rte_thash_get_helper(ctx,"sport")` 拿 helper。需用 `rte_eal_process_type()==RTE_PROC_SECONDARY` 分支。
  - **风险点**：ctx 中保存的 `matrices` 指针、helper 中 `lfsr` 指针均为 primary 地址；secondary 共享 hugepage 下指针有效（同映射）。但 **adjust 路径在本机非 GFNI（`ctx->matrices==NULL`）时走 `rte_softrss`，不依赖 matrices**，故 find_existing 复用对 v4/v6 adjust 是可行的。
- **方案B（次选）**：每进程用**互异 name**（带 lcore/proc id）各自 init。可绕开 EEXIST，但**每进程重复构造、重复改 key、内存翻倍**，且无意义（key 相同，结果相同），不推荐。
- **结论**：0.1 是「secondary 误调 init_ctx 撞 EEXIST」，正解是 secondary 改走 find_existing/get_helper（方案A）。

---

## 2. rte_thash_adjust_tuple 的 hash 口径 / 字序 / 取位（对应问题 0.2 核心）

`rte_thash_adjust_tuple`：`rte_thash.c:785-852`

### 事实拆解
1. **入参 tuple 当作 uint8 字节流指针**，但内部按 4 字节分组转换：
   - `rte_thash.c:800-802` 强制 `tuple_len % 4 == 0`（4 字节对齐要求，头文件 `rte_thash.h:429` 也写明 "Must be multiple of 4"）。
2. **hash 计算口径（非 GFNI 分支）**：`rte_thash.c:811-817`
   ```c
   for (j = 0; j < (tuple_len / 4); j++)
       tmp_tuple[j] = rte_be_to_cpu_32(*(uint32_t *)&tuple[j*4]);
   hash = rte_softrss(tmp_tuple, tuple_len / 4, hash_key);
   ```
   - 即：**把 tuple 每 4 字节按 big-endian→cpu 转换成 uint32**，再喂 `rte_softrss`。
   - `rte_softrss`（`rte_thash.h:175-190`）内部对 key 做 `rte_cpu_to_be_32`，对 input_tuple 直接按 uint32 字 + bit 扫描。
   - **净效果**：tuple 被当作"网络字节序的 uint32 数组"参与 Toeplitz；即 adjust 期望 **tuple 内存是网络序（be）字节布局**，be_to_cpu 后还原成数值再算。
3. **desired_value 对应 hash 的哪几位**：**LSB（最低 reta_sz_log 位）**。
   - `rte_thash_get_complement`（`rte_thash.c:677-682`）：`compl_table[(hash ^ desired_hash) & h->lsb_msk]`，`lsb_msk = (1<<reta_sz_log)-1`（`rte_thash.c:606`）。即只关心 **hash 的低 reta_sz_log 位**。
   - 头文件 `rte_thash.h:430-431` 明确 "desired_value: Desired value of **least significant bits** of the hash"。
4. **adjust 改写 tuple 的哪个 bit**：`rte_thash.c:820-829`
   ```c
   offset = h->tuple_offset + h->tuple_len - ctx->reta_sz_log; /* 子tuple尾部 reta_sz_log 位 */
   tmp = read_unaligned_bits(tuple, ctx->reta_sz_log, offset);
   tmp ^= adj_bits;
   write_unaligned_bits(tuple, ctx->reta_sz_log, offset, tmp);
   ```
   - 改的是 helper 覆盖子 tuple 的**末尾 reta_sz_log 个 bit**（按 bit 偏移，**MSB-first 位序**——见 `set_bit`/`read_unaligned_byte` `rte_thash.c:384-396,696-731`）。
   - 注释 `rte_thash.c:822-825`："LSB of adj_bits corresponds to offset+len bit of the subtuple"。
   - F-Stack 的 helper：`offset=64`(sport 起始 bit)、`len=16`（`ff_dpdk_if.c:2143,3002-3004`）。改写位 = bit `64+16-reta_log2` 起的 reta_log2 位，落在 **sport 字段的低位区**（sport 占 bit 64..79）。

### 关键对齐细节
- adjust 对 **read/write_unaligned_bits 用的是 bit 流 MSB-first 视角**（`rte_thash.c:696-783`），与 softrss/adjust 内部 be_to_cpu 的"网络序"是自洽的一套。
- 但 **F-Stack 传给 adjust 的 tuple 是 host-order bcopy 字节**（`ff_dpdk_if.c:3092-3096`，直接 `bcopy(&saddr,...)`，**未做 cpu_to_be 转换**），见第4节。

---

## 3. rte_thash_add_helper / rte_thash_get_complement 的 offset/len 语义

- `rte_thash_add_helper(ctx, name, len, offset)`（`rte_thash.c:571-659`）：
  - **offset、len 单位均为 bit**（`rte_thash.h:325-331`："Length in bits"/"Offset in bits"）。
  - `len` 必须 ≥ `reta_sz_log`（`rte_thash.c:579`），且 `offset+len+31 ≤ key_len*8`（`rte_thash.c:580-581`）。
  - 内部记录 `tuple_offset=offset`、`tuple_len=len`（`rte_thash.c:604-605`），供 adjust 用。
- **sport 字段在 tuple 中的位置对应**（F-Stack v4）：
  - tuple 布局 saddr(4)|daddr(4)|sport(2)|dport(2)，sport 起始 byte 8 = **bit 64**（`ff_dpdk_if.c:140-142`），与 helper offset=64 一致。
  - helper len=16 覆盖整个 sport 16 bit；adjust 实际只改其低 reta_log2 位。
- `rte_thash_get_complement`：见第2节，纯查表 `compl_table`，只读、MT-safe。

---

## 4. rte_softrss vs rte_softrss_be 字节序差异；F-Stack toeplitz_hash 等价于哪个；解释 0.2 失败

### DPDK 两实现差异（`rte_thash.h:175-219`）
| | rte_softrss (`:175`) | rte_softrss_be (`:205`) |
|---|---|---|
| 对 rss_key | `rte_cpu_to_be_32(key[j])` 转换后用 | 直接当 host uint32 用（需先 `rte_convert_rss_key` 把 key 转好） |
| 对 input_tuple | 直接当 host uint32（数值）扫描 bit | 同左 |
| 适用 | 原始 key + host-order 数值 tuple | 预转换 key（"be"键），结果与 NIC 一致 |

- `rte_thash_adjust_tuple` 用的是 **rte_softrss**（非 _be），且**先把 tuple 做 be_to_cpu_32**（`rte_thash.c:814`）。
  - 含义：adjust 把 **tuple 内存解释为网络序字节**，转成数值后用 softrss（softrss 内部再把 key cpu_to_be）。

### F-Stack 自实现 toeplitz_hash（`ff_dpdk_if.c:2588-2609`）
- **纯字节流、MSB-first**：外层逐 byte `data[i]`，内层 `bit b: data[i] & (1<<(7-b))`（高位优先），key 也按 `key[0..3]` 大端拼成 v 再逐 bit 移位补 `key[i+4]`。
- 即：**toeplitz_hash 把 data 当成"网络字节序字节流"，把 key 当成"原始字节序字节流（MSB-first）"** —— 这是经典 BSD/网卡口径（与 FreeBSD net/toeplitz.c 同源）。

### 等价性判定（核心）
- F-Stack `ff_rss_check`（`ff_dpdk_if.c:2918-2954`）：
  - 用 `bcopy(&saddr,...)`、`bcopy(&sport,...)` 把 **host-order 的 uint32/uint16 原样字节**塞进 data。
  - **小端机上**：`saddr`(host uint32) 的内存字节 = **小端排列**，但 toeplitz_hash 按 MSB-first 字节流处理 → 实际等价于把"host 小端字节"当网络字节算。
  - 关键：F-Stack 的 saddr/sport **进入 ff_rss_check 前是什么字节序，取决于调用方**（in_pcb 等），且 ff_rss_check 内部**不做任何 ntoh/hton**，直接拿内存字节流喂 toeplitz。
- DPDK adjust 路径：F-Stack 同样用 `bcopy`（host-order 内存字节）填 tuple（`ff_dpdk_if.c:3092-3096`），**但 adjust 内部多做了 `rte_be_to_cpu_32`**（`rte_thash.c:814`）。

**=> 字节序口径不一致的根因：**
- **toeplitz_hash 直接吃字节流（无 be_to_cpu）；adjust 内部对同样的 host-order 字节先做 be_to_cpu_32 再算。**
- 在**小端机**上，`rte_be_to_cpu_32` 会**把 host 小端字节做一次字节翻转**，等于 adjust 实际算的是"翻转后的数值"，而 ff_rss_check 算的是"未翻转的字节流"。
- 两者对 **saddr/daddr（uint32）和 sport/dport（uint16，且 adjust 按 32 位组处理 sport|dport 合并字）** 的解释发生**字节序错位** → **同一组 (saddr,daddr,sport,dport)，adjust 内部算出的 hash ≠ toeplitz_hash 算出的 hash**。
- 因此 adjust 反算/挑选出的 sport，**经 ff_rss_check 用 toeplitz_hash 复核时落到的队列与 desired 不符 → 复核大概率失败**（现象 0.2）。
- 此外 **sport/dport 在 adjust 中合并成一个 4 字节组**做 be_to_cpu（tuple[8..11]），sport(2)+dport(2) 的半字字节序在小端下也会与 ff_rss_check 的逐字段 bcopy 口径错位，进一步放大不一致。

### 等价结论
- **F-Stack toeplitz_hash ≈ DPDK 的「rte_softrss_be 口径（对 tuple 不做 be_to_cpu 的纯字节/数值直算）」更接近**，而 adjust 走的是「rte_softrss + tuple be_to_cpu」口径。**两者在小端机上字节序不等价**，这是 0.2 的根本原因。

### 补充（重要）：rte_thash_adjust_tuple 有「三种口径」，真机走哪条取决于 GFNI
adjust 内部按 `ctx->matrices` 是否为 NULL 分两条路（`rte_thash.c:808-818`）：
1. **GFNI 分支**（`ctx->matrices != NULL`，CPU 支持 GFNI+AVX512）：`rte_thash.c:810`
   `hash = rte_thash_gfni(ctx->matrices, tuple, tuple_len);`
   - `rte_thash_gfni`（`rte_thash_x86_gfni.h:176-185`）**直接把 tuple 当字节流处理，不做任何 be_to_cpu_32 翻转**。
   - 文档明确要求 **"Data must be in network byte order"**（`rte_thash_x86_gfni.h:170`、`rte_thash_gfni.h:30`）。
2. **标量分支**（`ctx->matrices == NULL`，非 GFNI）：`rte_thash.c:811-817`
   先 `rte_be_to_cpu_32(*(uint32_t*)&tuple[j*4])` 再 `rte_softrss`。
3. **F-Stack toeplitz_hash**（`ff_dpdk_if.c:2588-2609`）：纯网络序字节流 MSB-first，**无 be_to_cpu**。

**口径对照（关键）**：
| 路径 | 对 tuple 的处理 | 期望 tuple 内存布局 |
|---|---|---|
| GFNI 分支 | 直接字节流 | **网络序(be)字节** |
| 标量分支 | 先 be_to_cpu_32 再算 | **网络序(be)字节**（转成数值） |
| F-Stack toeplitz_hash | 直接字节流 MSB-first | **网络序(be)字节** |

- **三者都"期望 tuple 是网络序字节"**。但 GFNI 与 F-Stack 是"字节流直算"同口径；标量分支多了一次 be_to_cpu_32（在小端机上等于额外翻转每个 4 字节 word）。
- **=> 关键转折**：若真机走 **GFNI 分支**，adjust 与 F-Stack toeplitz_hash **口径一致**（都字节流直算），0.2 字节序问题**不复现**；若走 **标量分支**，则标量的 be_to_cpu_32 制造不一致 → 0.2 复现。
- **但还有第二层错位（无论走哪条都存在）**：F-Stack 喂给 adjust/check 的 tuple 是 **host-order bcopy**（`ff_dpdk_if.c:3092-3096` 直接 `bcopy(&saddr,...)`，**未 hton**）。小端机上这**不是**网络序字节，而三条 hash 路径都"期望网络序字节"。
  - 对 GFNI/标量/toeplitz 而言，只要**输入字节口径自洽**（adjust 和 check 用同一份 host-order 字节），且**同走一条 hash 实现**，hash 值仍能内部自洽 → 复核可过。
  - 真正出问题的是 **adjust 与 check 走了不同 hash 实现**（adjust=标量 be_to_cpu_32，check=toeplitz 字节流），口径不同 → hash 不等 → 复核失败。
- **所以 0.2 的精确根因 = 「adjust 标量分支的 be_to_cpu_32」与「ff_rss_check toeplitz_hash 字节流」口径不一致**；GFNI 分支反而与 toeplitz 一致。**真机实际走哪条分支必须实测 `rte_thash_gfni_supported()` 返回值**（`rte_thash.c:94-105`：需 RTE_CPUFLAG_GFNI 且 SIMD≥512），这决定 0.2 是否复现及修复策略。

---

## 5. DPDK rte_thash 是否官方支持多进程

- 头文件/源码**无任何 "process shared / multi-process" 专门声明或宏**。
- 唯一相关：ctx 经 **EAL TAILQ + rte_malloc（hugepage 共享）** 管理（`rte_thash.c:22-26,265,274`），并提供 `rte_thash_find_existing`（`rte_thash.c:324`）——这是 DPDK 标准的"primary 建、secondary lookup 共享"模式（与 mempool/ring/hash 一致）。
- 但构造 API 明确**非并发/单写者**：`rte_thash_add_helper` 文档 "This function is **not multi-thread safe**"（`rte_thash.h:320`）。
- **结论**：DPDK rte_thash **支持多进程"共享"语义（primary create + secondary find_existing），但不支持多进程/多线程并发"构造"**。F-Stack 现状是 secondary 也调 init_ctx，违反此模式 → 0.1。

---

## 修复可行性建议汇总（供 leader/diag-code 对接）

- **0.1**：secondary 进程改用 `rte_thash_find_existing` + `rte_thash_get_helper`，不再 init_ctx/add_helper。判断 `rte_eal_process_type()`。非 GFNI 机上 adjust 不依赖 matrices，find_existing 复用安全可行。
- **0.2**：让 adjust 的输入字节序与 ff_rss_check/toeplitz_hash 对齐。两条路任选其一：
  - (a) **改 toeplitz_hash 侧**：不现实（要与 NIC 实际 RSS 口径一致，NIC 是网络序字节流）。
  - (b) **改喂给 adjust 的 tuple 字节序**：在调用 `rte_thash_adjust_tuple` 前，把 saddr/daddr/sport/dport **按网络序（hton）布局**填入 tuple，使 adjust 内部 `be_to_cpu_32` 还原出的数值与 ff_rss_check 的字节流口径一致；并注意 sport|dport 合并字的半字顺序。**这是最小改动方向**，但必须用真机 ff_rss_check 复核验证（代码已有 recheck 兜底 `ff_dpdk_if.c:3102-3108`，但 recheck 大概率失败正是现象，需让 recheck 高概率通过而非靠 fallback）。
  - 强烈建议：在修复后用一组固定 (saddr,daddr,dport) 离线对比 `toeplitz_hash` 与 adjust 内部 `rte_be_to_cpu_32+rte_softrss` 的逐 sport hash 表，确认两者低 reta_log2 位一致后再上线。

> 全部结论均引自上述 文件:行号 代码事实，未做超出源码的推断。
