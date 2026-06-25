# 0.2 根因独立仲裁报告（arbiter / 只读代码考据）

> 角色：独立仲裁员，全新视角，仅凭实际源码 + 严格位级推导裁决，禁止从众/臆测。
> 源码版本：DPDK 23.11.5 / f-stack（/data/workspace）。
> 争议：开启 `rss_check.enable` 后 `rte_thash_adjust_tuple` 反算的源端口经常不落本队列；
> `rss_check.enable=0` 纯软算 `ff_rss_check` 正确。
> H1（两位前序诊断员）：根因=字节序不一致（be_to_cpu_32 翻字节），且 GFNI≠标量。
> H2（leader）：根因=key 不一致（add_helper 用 LFSR 改写了 ctx->hash_key），与字节序无关；GFNI=标量。

---

## 最终裁决（先给结论）

**H2 成立；H1 的"字节序"论断与"GFNI≠标量"论断均错误。**

1. **Q-A 字节序**：在【同 key、同 12 字节 tuple】下，`rte_softrss(be_to_cpu_32(bytes), key)` 与 `toeplitz_hash(key, bytes)` **逐位完全等价**。`be_to_cpu_32` 不是 bug，恰恰是把"小端内存里的 uint32 字"还原成"MSB-first 数值"，从而让 softrss 的按字处理与 toeplitz 的按字节流 MSB-first 处理一一对应。字节序**不是**根因。
2. **Q-B key 改写**：`rte_thash_add_helper → generate_subkey` 确实用 LFSR m-序列**原地改写了 `ctx->hash_key` 的 bit[64,110]**（v4，key 字节 8~13）。`adjust_tuple` 内部 `rte_thash_get_key(ctx)` 取的是**改写后**的 key；而 `ff_rss_check`/NIC 用的是**原始** `default_rsskey_40bytes`。三方 key 不同 → hash 系统性不同 → 反算端口落错队列。这是**真正根因**。
3. **Q-C GFNI vs 标量**：GFNI 矩阵由 `ctx->hash_key` 经 `rte_thash_complete_matrix` 生成，且 `generate_subkey` 改写 key 后会**重建矩阵**（rte_thash.c L430-432）。故 GFNI 分支与标量分支用的是**同一把（改写后的）key**，是同一 Toeplitz 函数的两种实现，对同输入给同结果。H1"二者口径不同/GFNI 与 toeplitz 一致而标量不一致"**自相矛盾、不成立**。

---

## Q-A 【字节序】严格位级推导

### 被比较的两个函数

**A) `toeplitz_hash`**（f-stack `lib/ff_dpdk_if.c` L2588-2609），标准 FreeBSD/Toeplitz：

```c
v = (key[0]<<24)+(key[1]<<16)+(key[2]<<8)+key[3];   // key 流前 32 bit 窗口
for (i=0;i<datalen;i++)
  for (b=0;b<8;b++) {
    if (data[i] & (1<<(7-b))) hash ^= v;            // data 按 MSB-first 取 bit
    v <<= 1;
    if ((i+4)<keylen && (key[i+4] & (1<<(7-b)))) v |= 1; // 从 key 流补下一 bit
  }
```

- data 的全局比特序：字节 `i` 的 bit `(7-b)`（b=0→MSB），全局位置 `g = 8*i + b`。
- 当 `data` 的全局第 g 个比特为 1：`hash ^=` 「key 比特流中从 bit g 开始连续 32 个比特组成的 uint32」（`v` 是滑动窗口，第 g 步时窗口起点恰为 key 流 bit g）。
- 即 toeplitz：`hash = XOR_{g: data_bit[g]==1} KeyWindow32(g)`，其中 `KeyWindow32(g)=key 流 bit[g..g+31]`（MSB-first），key 流 = key 字节数组按 MSB-first 拼接。

**B) `rte_softrss(input, len, key)`**（DPDK `rte_thash.h` L175-190）：

```c
for (j=0;j<input_len;j++)
  for (map=input_tuple[j]; map; map&=(map-1)) {
    i = rte_bsf32(map);                              // i = LSB 计数的置位 bit
    ret ^= rte_cpu_to_be_32(key32[j]) << (31-i)
         | (uint32_t)((uint64_t)rte_cpu_to_be_32(key32[j+1]) >> (i+1));
  }
```

`adjust_tuple`（rte_thash.c L812-817）喂给 softrss 的 input：

```c
for (j=0;j<tuple_len/4;j++)
  tmp_tuple[j] = rte_be_to_cpu_32(*(uint32_t*)&tuple[j*4]);  // 字节流 -> MSB-first 数值
hash = rte_softrss(tmp_tuple, tuple_len/4, hash_key);
```

### 逐位对应（核心）

**第一步：input_tuple[j] 的 bit 与 data 字节流位置的对应。**

`tmp_tuple[j] = be_to_cpu_32(tuple[4j..4j+3])`，无论本机字节序，`be_to_cpu_32` 的语义恒为"把 4 个字节按 MSB-first（tuple[4j] 为最高字节）解释为数值"。
所以 `tmp_tuple[j]` 的（按 LSB 计数的）bit `i`，对应字节流中字节 `4j` 起的 MSB-first 第 `(31-i)` 个比特，即全局位置：

```
g = 8*(4j) + (31 - i) = 32j + 31 - i
```

这与 toeplitz 对 data 的全局比特定义 `g=8*i+b` 完全一致（同一个字节流、同一种 MSB-first 取位）。

**第二步：softrss 对该置位 bit 贡献的 key 窗口起点。**

softrss 贡献 = `be32(key32[j])<<(31-i) | (be32(key32[j+1])>>(i+1))`。
`be32(key32[j])` = key 字节 `4j,4j+1,4j+2,4j+3` 按 MSB-first 的 uint32（与 toeplitz 的 key 流定义一致）。

- `be32(key32[j]) << (31-i)`：取 key 流 bit `[32j .. 32j+i]`（共 i+1 个高位）放到结果高 (i+1) 位。
- `be32(key32[j+1]) >> (i+1)`：取 key 流 bit `[32(j+1) .. 32(j+1)+30-i]`（共 31-i 个）放到结果低 (31-i) 位。
- 拼接得到的 32 位 = key 流 bit `[32j+(31-i) .. 32j+(31-i)+31]` = `[g .. g+31]`（因 g=32j+31-i）。

即 softrss 对该置位比特贡献 `KeyWindow32(g)`，**与 toeplitz 在同一 g 处贡献的 key 窗口逐位相同**。

**第三步：求和集合相同。**

softrss 对 word j 遍历所有置位 bit i（`map&=(map-1)`），等价遍历 data 字节流中字节 `[4j,4j+4)` 区间内所有为 1 的全局比特 g；j 遍历全 word ⇒ 覆盖全部字节流比特。toeplitz 同样遍历全部字节流比特。两者求和集合与每项贡献逐位一致：

```
rte_softrss(be_to_cpu_32(bytes), key) ≡ toeplitz_hash(key, bytes)   （逐位恒等，与本机字节序无关）
```

### Q-A 结论

**等价。** 字节序不是问题。`be_to_cpu_32` 是 softrss（按 uint32 字、要求字内 MSB-first 数值）与字节流 MSB-first Toeplitz 之间的**正确**桥接，不是 H1 所称的"字节翻转 bug"。H1 的字节序论断**错误**。

（注：`rte_softrss_be` L205-219 才是"key 已预转换、直接吃机器序字"的变体；`adjust_tuple` 用的是普通 `rte_softrss` + `be_to_cpu_32`，配对正确。）

---

## Q-B 【key 改写】源码考据

### B1. add_helper 确实改写 ctx->hash_key

调用链：`rte_thash_add_helper`（rte_thash.c L571）→ 无重叠时走 L640-641 `generate_subkey(ctx, lfsr, start, end-1)` → `generate_subkey`（L402-435）内 `set_bit(ctx->hash_key, get_bit_lfsr(lfsr), i)`（L421-422）**原地写 ctx->hash_key**。`set_bit`（L384-396）按 MSB-first 写第 pos 位。

### B2. 改写的确切 bit 范围（代入 v4）

f-stack 调用：`rte_thash_add_helper(ctx, "sport", len=FF_RSS_THASH_SPORT_HELPER_LEN=16, offset=FF_RSS_THASH_V4_SPORT_OFF=64)`（L2143-2144、L3002-3004）。
`TOEPLITZ_HASH_LEN = 32`（rte_thash.c L17）。ctx flags=0（无 MINIMAL_SEQ）。

```
end   = offset + len + TOEPLITZ_HASH_LEN - 1 = 64 + 16 + 32 - 1 = 111      (L590)
start = offset = 64                                                        (L591-593, 无 MINIMAL_SEQ)
generate_subkey(ctx, lfsr, start=64, end-1=110)  -> 改写 bit[64, 110]      (L641)
```

**改写 bit[64,110]**：bit64 = key 字节 8 的 MSB，bit110 = key 字节 13 的 bit6（110/8=13 余 6）。即 **key 字节 8~13 被 LFSR m-序列覆盖**。这正是源端口（tuple offset 64，即第 9~10 字节 sport）参与 hash 的窗口区，目的是构造互补表使端口可反算 —— 但代价是 key 被改了。

### B3. ff_rss_thash_ctx_init 之后没有任何 key 回写/上传

`ff_rss_thash_ctx_init`（L2972-3043）：
- L2994 `rte_thash_init_ctx(name, rsskey_len, reta_log2, rsskey, 0)`：把**原始 rsskey** memcpy 进 ctx->hash_key（rte_thash.c L288-289）。
- L3002 `rte_thash_add_helper(...)`：**改写 ctx->hash_key bit[64,110]**。
- 之后仅 `rte_thash_get_helper` 取 helper 指针，**没有 `rte_thash_get_key`、没有更新全局 `rsskey`、没有 `rte_eth_dev_rss_hash_update`**。

全工程检索确证：`grep rte_eth_dev_rss_hash_update | rte_thash_get_key | rte_thash_gfni` 在 `f-stack/lib/ff_dpdk_if.c` **0 命中**。NIC 的 RSS key（`port_conf.rx_adv_conf.rss_conf.rss_key = rsskey`，L742-743）始终是**原始 key**，从未被改写后的 key 替换。

### B4. 三方实际用的 key

| 使用方 | key | 出处 |
|---|---|---|
| **NIC 硬件 RSS** | 原始 `default_rsskey_40bytes` | L742-743 / L1042 / L1208，且无 hash_update 覆盖 |
| **`ff_rss_check`（软算校验）** | 原始 `rsskey`（=default_rsskey_40bytes） | `toeplitz_hash(rsskey_len, rsskey, ...)` L2951 |
| **`rte_thash_adjust_tuple`（反算）** | **改写后** `ctx->hash_key`（bit[64,110] 被 LFSR 覆盖） | L804 `hash_key = rte_thash_get_key(ctx)` = `ctx->hash_key` (rte_thash.c L684-688) |

### Q-B 结论

**adjust_tuple 用改写后 key，ff_rss_check 与 NIC 用原始 key，三方 key 不同。** 这是 0.2 的根本原因。
反算时 adjust_tuple 在"改写 key 的 hash 空间"里求出落本队列的端口；但该端口拿回去给 **原始 key 的 NIC/ff_rss_check** 算，落点系统性偏移 → 经常不在本队列。recheck 用 ff_rss_check（原始 key）当然多次仍可能不通。

---

## Q-C 【GFNI vs 标量】

### C1. 两分支同一把 key

`rte_thash_adjust_tuple`（rte_thash.c L808-818）：
- `ctx->matrices != NULL`（GFNI 支持）→ `rte_thash_gfni(ctx->matrices, tuple, tuple_len)`。
- 否则 → `be_to_cpu_32 + rte_softrss(tmp_tuple, ..., hash_key=ctx->hash_key)`。

矩阵来源：`rte_thash_init_ctx` L304-305 由 `ctx->hash_key` 经 `rte_thash_complete_matrix` 生成；而 `generate_subkey` 改写 key 后 L430-432 **重新调用 `rte_thash_complete_matrix(ctx->matrices, ctx->hash_key, key_len)` 重建矩阵**。所以 GFNI 矩阵反映的也是**改写后**的 ctx->hash_key。

⇒ GFNI 分支与标量分支 = **同一把改写后的 key、同一个 Toeplitz 函数的两种实现**，对同 tuple 必给**相同** hash。

### C2. H1"GFNI≠标量"为何不成立

H1 称"GFNI 字节流直算与 toeplitz 一致、标量 be_to_cpu_32 分支与 toeplitz 不一致"。但：
- 由 Q-A，标量分支（be_to_cpu_32+softrss）在**同 key** 下与 toeplitz **逐位等价**；
- 由 C1，GFNI 与标量**同 key 同函数**，结果相同；
- 故"GFNI 对、标量错"在数学上不可能成立——两者要么都对、要么都错，差别只在 key，不在实现口径。

H1 把"复现条件=真机无 GFNI"误解读成"实现口径差异"。真正的复现差异其实来自 **key 改写在 hash 空间的偏移**，与是否走 GFNI 无关；只要 adjust_tuple 用改写 key 而 NIC/check 用原始 key，无论 GFNI 还是标量都会错。（若某些场景"看起来"在支持 GFNI 的机器上不复现，那是 reta/队列分布的偶发掩盖，非口径差异。）

### Q-C 结论

**GFNI 与标量是同一函数同一 key 的两种实现，对同输入同结果。H1 的"二者口径不同"自相矛盾、不成立。**

---

## 0.2 根因表述的修正

**错误表述（H1，应废弃）**：
> "be_to_cpu_32 造成字节翻转，标量分支与 toeplitz 字节序不一致；GFNI 分支与 toeplitz 一致故仅真机复现。"

**正确表述（H2，应采纳）**：
> `rte_thash_add_helper` 为构造端口互补表，用 LFSR m-序列**原地改写了 `ctx->hash_key` 的 bit[64,110]（key 字节 8~13）**。`rte_thash_adjust_tuple` 据此**改写后的 key** 反算源端口，而 `ff_rss_check` 与 NIC 硬件仍用**原始 rsskey**。三方 key 不一致，导致反算端口在原始 key 的 hash 空间里系统性落错队列，recheck 多次仍不通。字节序（be_to_cpu_32）与 GFNI/标量分支差异均**非**根因。

---

## 修复方向（key 对齐）

核心：让"反算所用 key"与"校验/NIC 实际生效 key"三方一致。两条互斥路线：

**路线①（推荐：把改写后的 key 同步到 check + NIC）**
1. `ff_rss_thash_ctx_init` 中 `rte_thash_add_helper` 之后，调 `rte_thash_get_key(ctx)` 取回改写后的 key。
2. 用该 key 覆盖供 `ff_rss_check` 用的 key（即让 toeplitz_hash 也用改写后 key），并调 `rte_eth_dev_rss_hash_update(port_id, &rss_conf{key=改写后key})` 把改写 key 重新上传 NIC，使 NIC 实际 RSS 与之一致。
3. 风险：`rss_hash_update` 部分网卡/驱动不支持或需重置队列；多端口需逐端口对齐；运行时改 NIC key 影响在途流量分布。需在初始化早期、流量前完成。

**路线②（不改 NIC：放弃 adjust_tuple，回退/坚持纯软扫描）**
- 若不能改 NIC key，则 adjust_tuple 路线无法与原始 key 的 NIC 自洽，应直接走 `ff_rss_check` 软扫描端口（即 `rss_check.enable=0` 的正确路径），不启用 thash 反算。

> 倾向路线①（保留反算的性能收益），但必须验证目标真机 `rte_eth_dev_rss_hash_update` 可用且能在无流量窗口完成；否则退路线②。

---

## 与 0.1（多进程）修复方案的耦合 —— 关键约束

0.2 的修复（key 对齐）与 0.1（多进程共享）**强耦合**，必须一并设计，否则按下葫芦起瓢：

- 若每进程各自 `rte_thash_init_ctx` + `add_helper`，而 `add_helper` 内部 LFSR（`alloc_lfsr`/`get_bit_lfsr`）在无固定种子时**各进程产生不同 m-序列** → 各进程改写出的 ctx->hash_key **互不相同**。
- 但**一张 NIC 只能有一把 RSS key**。N 个进程 N 把不同改写 key，**无法同时与单一 NIC key 一致** → 路线①在"每进程独立 ctx"下从原理上无法成立。

**结论性建议**：0.1 应采用 **primary 进程创建、secondary 进程 `rte_thash_find_existing` 共享同一个 ctx**（DPDK 多进程标准用法，rte_thash 的 ctx 存于共享 tailq，见 rte_thash.c `rte_thash_find_existing` L324-348）。这样：
1. 全进程共用同一把"改写后 key"；
2. 该唯一 key 上传 NIC 一次，三方（NIC / 所有进程的 check / 所有进程的 adjust_tuple）一致；
3. 0.2 路线① 才有可落地前提。

即：**0.1 必须 primary-create + secondary-find_existing 共享单一 ctx；0.2 的 key 对齐必须基于这把共享 key 上传 NIC。两者不可分开实现。**

---

## 证据行号索引

- DPDK `rte_thash.c`：init_ctx 拷 key L288-289、GFNI 矩阵生成 L304-305；set_bit L384-396；generate_subkey 改写 hash_key L402-435（写 L421-422，重建矩阵 L430-432）；add_helper start/end 计算 L590-593、generate_subkey 调用 L641；find_existing L324-348；rte_thash_get_key=return ctx->hash_key L684-688；adjust_tuple hash_key=get_key L804、GFNI/标量分支 L808-818。
- DPDK `rte_thash.h`：rte_softrss L175-190；rte_softrss_be L205-219；TOEPLITZ_HASH_LEN=32 (rte_thash.c L17)。
- f-stack `ff_dpdk_if.c`：default_rsskey_40bytes L92、rsskey 全局 L120-121；常量 V4_SPORT_OFF=64/HELPER_LEN=16/TUPLE_LEN=12 L141-144；NIC key 设置 L742-743/L1042/L1208；toeplitz_hash L2588-2609；ff_rss_check 用 rsskey L2918-2954（hash L2951）；ff_rss_thash_ctx_init L2972-3043（init_ctx L2994、add_helper L3002，无 get_key/hash_update）；ff_rss_adjust_sport L3052-3115。
- 反证：`rte_eth_dev_rss_hash_update` / `rte_thash_get_key` / `rte_thash_gfni` 在 ff_dpdk_if.c **0 命中**。

---

*裁决人：arbiter（独立只读考据）。结论仅依据上述实际源码与位级推导得出。*
