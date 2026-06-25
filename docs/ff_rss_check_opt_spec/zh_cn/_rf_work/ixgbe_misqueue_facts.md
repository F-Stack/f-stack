# ixgbe X550 misqueue 根因诊断 — 已确认事实清单（团队输入，权威）

> 本文件汇总用户在物理机（Intel X550T 10G, ixgbe PMD, 多进程 1 primary + N secondary, symmetric_rss=0, key 40 字节）上反复实测得到的**铁证事实**。所有诊断 agent 必须以此为唯一事实基准，禁止与之矛盾的假设，禁止重新引入已排除项。

## 1. 已确认为「正确、无问题」的部分（禁止再怀疑）

- **F1**：`ff_rss_check` 纯软算法正确。`enable=0` 纯软算校验，用 `default_rsskey_40bytes` → 完全正常（NIC 按 default key 分流，软算用 default key，一致）。
- **F2**：KEY_FINAL 这个 key 值本身正确。把 KEY_FINAL **硬编码进 `default_rsskey_40bytes` 静态数组**、短路掉 `ff_rss_thash_build_key`（函数不执行）、`enable=0` 纯软算 → **完全正常**。
- **F3**：RETA 表 = `idx % nb_queues`，NIC reta_query 实测 `mismatch_vs_idx%nbq=0`，假设成立。
- **F4**：v4 反算 ctx key 与全局 rsskey 前 16 字节逐字节相同（v4 hash 只用前 16 字节），v4 key 段一致。
- **F5**：DPDK softrss(be_to_cpu_32(bytes)) ≡ toeplitz_hash(bytes) 已数学证明；字节序、取位口径均非根因。

## 2. 决定性对照实验（root cause 必落在此差异上）

| 实验 | KEY_FINAL 来源 | build_key | enable | 结果 |
|---|---|---|---|---|
| **B2** | 硬编码进 `default_rsskey_40bytes`【**静态数组/BSS**】 | 不执行(短路) | 0 纯软算 | ✅ **正常** |
| **B3** | `ff_rss_thash_build_key` 内 `rte_malloc("ff_rsskey_synced")`【**rte_malloc 共享大页堆**】 | 正常执行 | 0 纯软算 | ❌ **坏(很多不通)** |

**B2 与 B3 的唯一差异 = 全局 `rsskey` 指向的 key buffer 的内存类型：**
- B2：`rsskey` 指向**静态 BSS 数组** `default_rsskey_40bytes`（内容 = KEY_FINAL）。
- B3：`rsskey` 指向 **`rte_malloc` 分配的共享大页 buffer** `new_rsskey`（内容 = 同样的 KEY_FINAL）。

KEY_FINAL 内容完全相同。两条路最终都执行 `port_conf.rx_adv_conf.rss_conf.rss_key = rsskey;` → `rte_eth_dev_configure(port_conf)` → dev_start → `ixgbe_rss_configure` 用 `dev->data->dev_conf.rx_adv_conf.rss_conf.rss_key`（浅拷贝的指针）写 RSSRK 寄存器。

→ **root cause 必然与「rss_key 指向 rte_malloc 内存 vs 静态内存」在 ixgbe dev_configure/dev_start 多进程下下发 NIC 的差异有关。**

## 3. 关键代码事实（lib/ff_dpdk_if.c，以代码为准）

- 全局 `static uint8_t *rsskey = default_rsskey_40bytes;`（L121），`static int rsskey_len`（L120）。
- `default_rsskey_40bytes` 是文件作用域 static 数组（BSS/data 段，每进程私有同地址）。
- `ff_rss_thash_build_key`：`new_rsskey = rte_malloc("ff_rsskey_synced", orig_rsskey_len, 0)`，`memcpy(new_rsskey, KEY_FINAL内容)`，`rsskey = new_rsskey`。在 init_port_start 的 L747（dev_configure 之前）调用。
- `port_conf.rx_adv_conf.rss_conf.rss_key = rsskey`（L748）。
- DPDK `rte_eth_dev_configure`（lib/ethdev/rte_ethdev.c L1333-1335）：`memcpy(&dev->data->dev_conf, dev_conf, sizeof(...))` **浅拷贝**，rss_key 只拷指针。
- `ixgbe_rss_configure`（drivers/net/ixgbe/ixgbe_rxtx.c L3739）：`rss_conf = dev->data->dev_conf.rx_adv_conf.rss_conf;` 用该指针 → `ixgbe_hw_rss_hash_set` 写 RSSRK 寄存器（L3569 循环 10 个 32-bit = 40 字节）。

## 4. 待诊断 agent 验证的核心假设（候选方向，非结论）

- **H1（最强嫌疑）**：多进程下，`dev_configure` 浅拷贝的 `rss_key` 指针指向 primary 的 rte_malloc 地址。secondary 进程不 dev_configure（L838 continue），但 **primary 的 dev_start 时刻**，`dev->data` 是共享的吗？`dev->data->dev_conf.rss_conf.rss_key` 指针在共享 `dev->data` 里，指向 primary rte_malloc 的虚拟地址 —— 若该地址在写 RSSRK 寄存器的时刻内容/可达性异常，会写错 key。但 B3 在 enable=0、纯 primary 软算也坏，secondary 可能不是关键。
- **H2**：`new_rsskey = rte_malloc(len=40)` 的 buffer **只有 40 字节**。ixgbe `ixgbe_hw_rss_hash_set` 读 `hash_key[0..39]`（L3569 `i<10`, `hash_key[i*4+3]` 最大下标 39）正好 40 字节，不越界。但若 rte_malloc 对齐/cacheline 导致实际可读区域问题？需核 rte_malloc 返回 buffer 是否足 40 字节连续。
- **H3**：`dev_configure` 是否在 build_key 之后、但 `rsskey`/`new_rsskey` 在 dev_start 写寄存器前被覆盖或释放？（new_rsskey 未 free，应活着，但需确认 init_port_start 多 port 循环里 new_rsskey 是否被下一轮覆盖——ff_rss_key_built 防多次，但需核）
- **H4**：B2 静态数组 vs B3 rte_malloc，ixgbe/dev_configure 是否对 rss_key 指针的内存属性（是否在 DPDK hugepage/IOVA 范围）有隐含要求？某些 PMD 对 rss_key 内存有 DMA/物理地址假设？（需查 ixgbe 是否 DMA rss_key — 通常 RSSRK 是 MMIO 寄存器，PIO 写，不该要求 hugepage，但需核）
- **H5**：`new_rsskey` 内容在 memcpy 后、dev_start 前，是否真的是 KEY_FINAL？（B3 的 NIC-readback 显示 KEY_FINAL，但 readback 在 dev_start 后，可能是寄存器自洽假象 —— 需在 dev_configure 前后、dev_start 前后多点 dump new_rsskey 内容 + 寄存器）

## 5. 诊断纪律

- 以 §1 事实为绝对基准，禁止重新引入「字节序/取位/RETA/key值本身/软算法」为根因（均已排除）。
- root cause 必须能解释「静态数组正常、rte_malloc 坏」这个唯一差异。
- 禁止臆测，所有结论需代码行号或可复现实验支撑。
- 删文件用 rm_tmp_file.sh，禁直接 rm。
