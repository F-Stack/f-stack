# ff_rss_check thash 优化运行时缺陷 — 代码考据诊断（诊断员A，只读）

> 范围：仅基于 `/data/workspace/f-stack/lib/ff_dpdk_if.c` 及配套 DPDK 源码 `/data/workspace/f-stack/dpdk/lib/hash/rte_thash.c` 的**实际代码**。所有行号均为真实文件行号。结论分"代码已确证"与"需真机/DPDK侧进一步佐证"两档。

---

## 0. 关键宏与全局状态（事实基线）

`lib/ff_dpdk_if.c`：

```
120: static int rsskey_len = sizeof(default_rsskey_40bytes);
121: static uint8_t *rsskey = default_rsskey_40bytes;
133: static uint16_t rss_reta_size[RTE_MAX_ETHPORTS];
137: static struct rte_thash_ctx *rss_thash_ctx[RTE_MAX_ETHPORTS];       // 进程私有 static
138: static struct rte_thash_subtuple_helper *rss_thash_sport_h[...];
139: static int rss_thash_ready[RTE_MAX_ETHPORTS];
141: #define FF_RSS_THASH_V4_TUPLE_LEN   12   // saddr4|daddr4|sport2|dport2
142: #define FF_RSS_THASH_V4_SPORT_OFF   64   // bit 64 = byte 8 = sport 起始
143: #define FF_RSS_THASH_SPORT_HELPER_LEN   16  // 覆盖 sport(16bit)
144: #define FF_RSS_THASH_ADJUST_ATTEMPTS    16
148: static struct rte_thash_ctx *rss_thash6_ctx[RTE_MAX_ETHPORTS];
151: #define FF_RSS_THASH_V6_TUPLE_LEN   36   // saddr16|daddr16|sport2|dport2
152: #define FF_RSS_THASH_V6_SPORT_OFF   256  // bit 256 = byte 32 = sport 起始
```

- `rss_thash_ctx[]` 等是 **static 数组**，每个进程（primary/secondary）各有一份私有副本；但其指向的对象由 `rte_thash_init_ctx` 在 **EAL 共享 tailq** 中登记（见 §1.2），这是 0.1 的核心矛盾。

---

## 1. 0.1 根因：secondary 进程 thash ctx 初始化全部失败

### 1.1 ff_rss_thash_ctx_init 名字拼装（lib/ff_dpdk_if.c L2972–3043）

```
2980:  for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
2982:      uint16_t reta_size = rss_reta_size[port_id];
2986:      rss_thash_ready[port_id] = 0;
2988:      if (reta_size < 2)            // 降级条件：reta_size < 2 跳过该 port
2989:          continue;
2991:      reta_log2 = ff_rss_reta_log2(reta_size);
2993:      snprintf(name, sizeof(name), "ff_rss_thash_%u", port_id);   // ★ 只含 port_id，不含 proc_id
2994:      ctx = rte_thash_init_ctx(name, rsskey_len, reta_log2, rsskey, 0);
2995:      if (ctx == NULL) { ... continue; }    // 失败 → 该 port 关闭动态路径
...
3002:      rte_thash_add_helper(ctx, "sport", FF_RSS_THASH_SPORT_HELPER_LEN, FF_RSS_THASH_V4_SPORT_OFF)
3017:      rss_thash_ctx[port_id] = ctx;
3018:      rss_thash_ready[port_id] = 1;
...
3023:      snprintf(name, sizeof(name), "ff_rss_thash6_%u", port_id);  // ★ v6 同样只含 port_id
3024:      ctx = rte_thash_init_ctx(name, rsskey_len, reta_log2, rsskey, 0);
```

**事实**：
- name 拼法为 `ff_rss_thash_%u` / `ff_rss_thash6_%u`，**仅含 `port_id`，完全不含 `proc_id`**。
- v4、v6 两套独立 ctx，各调一次 `rte_thash_init_ctx`，各加一个名为 `"sport"` 的 helper（v4 offset=64，v6 offset=256，len 均=16）。
- 降级条件：`reta_size < 2` 跳过。
- 入口：L1476，在 `init_port_start()` 之后、`rss_check_cfgs->enable` 为真时，**primary 与 secondary 都会进入**（L1467–1477 这段没有 `RTE_PROC_PRIMARY` 守卫）。

### 1.2 DPDK rte_thash_init_ctx 的共享语义（dpdk/lib/hash/rte_thash.c L207–294）

```
220:  thash_list = RTE_TAILQ_CAST(rte_thash_tailq.head, rte_thash_list);  // ★ 进程间共享 tailq
222:  rte_mcfg_tailq_write_lock();
225:  TAILQ_FOREACH(te, thash_list, next) {        // ★ 遍历共享列表查重名
226:      ctx = (struct rte_thash_ctx *)te->data;
227:      if (strncmp(name, ctx->name, sizeof(ctx->name)) == 0)
228:          break;
231:  if (te != NULL) {
232:      rte_errno = EEXIST;                       // ★ 重名直接返回 NULL
233:      goto exit;
```

`rte_thash_tailq` 是通过 `RTE_TAILQ_CAST(...head...)` 访问的 **EAL 共享内存 tailq**，多进程共享。primary 先建好 `ff_rss_thash_0`、`ff_rss_thash6_0` 并 `TAILQ_INSERT_TAIL`（L281）。secondary 启动后用**完全相同的 name** 调用，在 L225–228 命中重名 → L232 `EEXIST` → 返回 NULL → f-stack L2995 `ctx==NULL` → `continue`，`rss_thash_ready[port_id]` 保持 0。

### 1.3 0.1 结论（代码已确证）

**根因成立**：`ff_rss_thash_ctx_init` 用的 ctx name 只带 `port_id`、不带 `proc_id`，而 `rte_thash_init_ctx` 在 EAL 共享 tailq 上做全局重名检查并对重名返回 `EEXIST`。多进程场景下：
- primary 先创建成功并登记到共享 tailq；
- 每个 secondary 用同名再次创建，必然命中 `EEXIST` 返回 NULL，v4/v6 两套 ctx 全部失败 → secondary 的 `rss_thash_ready/rss_thash6_ready` 全为 0 → 动态路径在所有 secondary 退化为软扫描。

这与"只有主进程初始化成功，所有 secondary 子进程失败"的现象**完全吻合**。

补充确认（排除"secondary rsskey 为空导致提前 return"的干扰假设）：secondary 在 `init_port_start` 中于 L832 `continue` 之前已执行 L713–743（`if(pconf)` 内）对 `rsskey/rsskey_len` 赋值，因此 secondary 进入 `ff_rss_thash_ctx_init` 时 L2977 `rsskey==NULL||rsskey_len==0` 不成立，会真正走到 L2994 的创建并因 EEXIST 失败——即失败发生在 `rte_thash_init_ctx` 而非提前返回。

### 1.4 修复方向建议（0.1）
- **方案A（每进程独立 ctx）**：name 拼入 `proc_id`，如 `snprintf(name, ..., "ff_rss_thash_%u_%u", port_id, ff_global_cfg.dpdk.proc_id)`（v4/v6 同改）。每个进程拥有各自独立 ctx，互不重名，自洽性强、无跨进程只读指针依赖。**已知代价（diag-dpdk 与本员一致认可需记录）**：N 个进程 × N 个 port 的 ctx entry 全挂在同一共享 `RTE_THASH` tailq 上，`rte_zmalloc` 走共享 hugepage 堆，**内存随进程数线性增长**（单个 ctx = sizeof(ctx)+key_len，量级小，但需在文档作为已知代价记入）。
- **方案B（secondary 复用 primary ctx）**：仅 primary `init_ctx`+`add_helper`；secondary 改为 `rte_thash_find_existing(name)`（DPDK L296+）+ `rte_thash_get_helper`。diag-dpdk 从源码确认：ctx/helper/lfsr/compl_table 均在共享 hugepage、跨进程指针有效；secondary 只做只读 `adjust`（`get_complement` 标 MT-safe）安全；非 GFNI 时不依赖 matrices。需 `rte_eal_process_type()==RTE_PROC_SECONDARY` 分支。diag-dpdk 额外指出 `init/add_helper` 有写副作用（改 hash_key）且非并发安全，语义上倾向单写者(primary)构造——此点支持方案B。
- **两员当前共识**：A、B 源码层面均可行。本员与 diag-dpdk 都略倾向方案A（自洽、无跨进程只读依赖），代价是内存线性增长；方案B 更省内存、更贴 DPDK "primary create + secondary find_existing" 标准模式。**最终由 leader 裁决**。

---

## 2. 0.2 根因：动态反算 sport 经常"不通"

### 2.1 ff_rss_adjust_sport（lib/ff_dpdk_if.c L3052–3115）

```
3083: desired = queueid + (ff_arc4random() % ((reta_size+nb_queues-1)/nb_queues)) * nb_queues;
3088: for (tries=0; tries<(int)((reta_size+nb_queues-1)/nb_queues); tries++) {
3092:     memset(tuple, 0, sizeof(tuple));
3093:     bcopy(&saddr, &tuple[0], sizeof(saddr));   // ★ 主机字节序整数直接拷字节
3094:     bcopy(&daddr, &tuple[4], sizeof(daddr));
3095:     bcopy(&sport, &tuple[8], sizeof(sport));
3096:     bcopy(&dport, &tuple[10], sizeof(dport));
3098:     if (rte_thash_adjust_tuple(rss_thash_ctx[port_id], rss_thash_sport_h[port_id],
3099:             tuple, sizeof(tuple), desired & (reta_size-1),
3100:             FF_RSS_THASH_ADJUST_ATTEMPTS, NULL, NULL) == 0) {
3102:         int recheck = (... rss_check_cfgs->recheck);
3104:         bcopy(&tuple[8], &sport, sizeof(sport));     // 取回被改写的 sport
3105:         if (!recheck || ff_rss_check(softc, saddr, daddr, sport, dport)) {
3106:             *out_sport = sport; return 0;
3110:     desired += nb_queues;
3114: return -1;   // 全部 tries 失败 → 调用方回退软扫描
```

- desired 取值域：`D(q)={ v∈[0,reta_size) | v%nb_queues==queueid }`，循环次数 = `ceil(reta_size/nb_queues)`，每轮 `desired += nb_queues`，越界回绕到 queueid。逻辑上覆盖整个 D(q) 集合。
- tuple 填充：**`bcopy` 把主机字节序的 saddr/daddr/sport/dport 原样拷入字节缓冲**（与 `ff_rss_check`/`toeplitz_hash` 的喂入方式一致，L2938–2948）。
- tuple 长度 12（v4）/36（v6），均为 4 字节倍数，满足 `rte_thash_adjust_tuple` 的 `tuple_len%4==0`（DPDK L773）。

### 2.2 ff_rss_check / toeplitz_hash（lib/ff_dpdk_if.c L2588–2609, L2918–2954）

```
2588: toeplitz_hash(keylen,key,datalen,data):
2597:   v = (key[0]<<24)+(key[1]<<16)+(key[2]<<8)+key[3];   // 大端读 key 前4字节
2598:   for (i=0;i<datalen;i++) for(b=0;b<8;b++):
2600:     if (data[i] & (1<<(7-b))) hash ^= v;              // ★ 逐字节、MSB-first 扫描 data
2602:     v<<=1; if((i+4)<keylen && (key[i+4]&(1<<(7-b)))) v|=1;
...
2938: bcopy(&saddr,&data[..],4); bcopy(&daddr,...); bcopy(&sport,2); bcopy(&dport,2);  // 主机序字节流
2951: hash = toeplitz_hash(rsskey_len, rsskey, datalen, data);
2953: return ((hash & (reta_size-1)) % nb_queues) == queueid;   // ★ 先 &(reta-1) 再 %nb_queues
```

- `toeplitz_hash` 把 `data[]` 当**纯字节流**、按 byte 内 MSB-first 处理（标准 Microsoft Toeplitz）。它**不关心** data 里整数是大端还是小端，只认"喂进来的字节序列"。
- 取位口径：`(hash & (reta_size-1)) % nb_queues`。
- RETA 表 `set_rss_table`（L613–635）：`reta_conf[i].reta[j] = hash++ % nb_queues`，即 `reta[idx]=idx%nb_queues`，与 check 的 `%nb_queues` 一致。
- **入参字节序来源**：`ff_rss_check` 的 saddr/daddr/sport/dport 来自内核 in_pcb（v4 地址在 BSD in_pcb 内为**网络序**存放，端口 inp_lport/inp_fport 亦为**网络序**）。这里是**待真机/调用链佐证项**（见 §6），但**关键在于：纯软算路径（rss_check.enable=0）真机完全正确**，说明"软算这条链自洽"——即 `toeplitz_hash` 接收的字节流字节序与真机 NIC 硬件 RSS 计算所用字节序**一致**。这构成下面对比的"黄金基准"。

### 2.3 rte_thash_adjust_tuple 内部 hash 口径（dpdk/lib/hash/rte_thash.c L757–824）

```
780: for (i=0;i<attempts;i++) {
781:   if (ctx->matrices != NULL)
782:       hash = rte_thash_gfni(ctx->matrices, tuple, tuple_len);     // GFNI 分支
783:   else {
784:       for (j=0;j<(tuple_len/4);j++)
785:           tmp_tuple[j] = rte_be_to_cpu_32(*(uint32_t*)&tuple[j*4]); // ★ 按 4 字节大端→主机
789:       hash = rte_softrss(tmp_tuple, tuple_len/4, hash_key);         // 标量分支
792:   adj_bits = rte_thash_get_complement(h, hash, desired_value);
798:   offset = h->tuple_offset + h->tuple_len - ctx->reta_sz_log;
799:   tmp = read_unaligned_bits(tuple, ctx->reta_sz_log, offset);
800:   tmp ^= adj_bits;
801:   write_unaligned_bits(tuple, ctx->reta_sz_log, offset, tmp);       // ★ 改写 tuple 中 reta_sz_log 位
```

**关键差异点**：
1. **标量分支（L784–789）**：DPDK 假定 `tuple[]` 是**网络字节序**，对每个 4 字节 word 做 `rte_be_to_cpu_32` 转成主机序的 32-bit word 数组，再交给 `rte_softrss`（按 32-bit word 做 Toeplitz）。
2. **GFNI 分支（L782）**：`rte_thash_gfni` 直接对字节流 tuple 运算，口径又与标量分支不同（GFNI 处理的是字节序列）。运行时走哪条取决于 `ctx->matrices != NULL`，即 `rte_thash_gfni_supported()`（CPU 是否支持 GFNI 指令，DPDK L74–）。

### 2.4 0.2 核心不一致（代码已确证为"高度可疑根因"）

把三方口径并排：

| 维度 | toeplitz_hash / ff_rss_check（软算，真机正确） | rte_thash_adjust_tuple 标量分支 | rte_thash_adjust_tuple GFNI 分支 |
|---|---|---|---|
| tuple 喂入 | f-stack 用 bcopy 主机序整数 → 字节流 | 同样字节流，但内部 `rte_be_to_cpu_32` 当作大端读 | 直接吃字节流 |
| 算法粒度 | 逐 **字节** MSB-first | 逐 **32-bit word**（已 be→cpu） | 字节流（GFNI 矩阵） |
| sport 位置语义 | 字节流中 sport 在 byte 8（v4）原样 | be→cpu 后 word 内字节被翻转 | helper offset 按字节流 bit 64 |

**矛盾本质**：f-stack 写 tuple 的方式（`bcopy` 主机序整数，L3093–3096）与 `ff_rss_check`/`toeplitz_hash` 的喂入方式**完全相同**——这本意是想让 adjust 和 check 用"同一份字节流口径"。但 `rte_thash_adjust_tuple` 标量分支在内部**额外做了 `rte_be_to_cpu_32`**（L784–787），把这份字节流当成"网络序"重新解释；GFNI 分支则不做该转换。于是：

- 在**小端**机器上（x86 真机绝大多数），f-stack 用 `bcopy(&saddr,...)` 写入的是 saddr 的**小端字节序列**；`toeplitz_hash` 按这串小端字节算 → 与真机 NIC 一致（已被 enable=0 正确性反证）。
- 而 `rte_thash_adjust_tuple` 标量分支对同一串小端字节做 `rte_be_to_cpu_32`（在小端机即字节翻转），相当于把 saddr 又翻回大端 word 再算 hash → **算出来的 hash 与 toeplitz_hash 不是同一个口径**。
- 更关键的是 adjust 改写的是 sport 那 `reta_sz_log` 位（L798–801），它是基于"DPDK 自己那套（翻转后）hash 口径"反算的 complement。把这个 sport 取回（f-stack L3104 `bcopy(&tuple[8],&sport,...)`）后，**真机 NIC 用的是 toeplitz（未翻转）口径**，两者口径不同 → 反算出的 sport 落到 NIC 实际计算的错误队列 → "经常不通"。

这解释了现象的两个层次：
1. **enable=1 主进程经常不通**：adjust 口径 ≠ NIC/toeplitz 口径。
2. **recheck=1 仍可能多次重试且最终仍不通**：`ff_rss_check`（L3105）用的是 toeplitz 口径，能正确判出 adjust 给的 sport 是错的 → 进入下一轮 `desired += nb_queues`；但每一轮 adjust 仍用错口径，所产 sport 在 toeplitz 口径下落点**基本随机**，`ceil(reta_size/nb_queues)` 次有限尝试内不一定能撞中正确队列 → 最终 `return -1` 回退软扫描；即使偶尔撞中也表现为"多次重试"。
3. **enable=0 软算完全正确**：纯 `ff_rss_check`/软扫描全程只用 toeplitz 口径，与 NIC 自洽，故正确。

> **GFNI 分支重要转折（diag-dpdk 已从 DPDK 源码确证，dpdk/lib/hash/rte_thash_x86_gfni.h L170/L176-185）**：`rte_thash_gfni` 直接把 tuple 当**字节流**运算、**不做 `rte_be_to_cpu_32` 翻转**，且文档明确要求 "Data must be in network byte order"。结论：
> - **GFNI 分支（字节流直算） == f-stack toeplitz_hash（字节流 MSB-first） 口径一致** → 走 GFNI 时 **0.2 不复现**。
> - **标量分支（be_to_cpu_32 + softrss） ≠ toeplitz** → 走标量时 **0.2 复现**。
> - 走哪条取决于 `rte_thash_gfni_supported()`（dpdk/lib/hash/rte_thash.c，需 CPU 有 GFNI 指令且 SIMD≥512）。
>
> **因此 0.2 的复现是"条件性"的：真机 CPU 不支持 GFNI（→ 标量分支）才会复现。这与现象"经常不通/多次重试"一致——强烈提示真机走的是标量分支。但必须在真机实测 `rte_thash_gfni_supported()` 返回值/`ctx->matrices` 是否为空，以最终锁定，禁止臆测。** 无论结果如何，f-stack 侧"adjust 用 bcopy 主机序字节、期望与 toeplitz 同口径"的假设在标量分支下不成立。

### 2.5 修复方向建议（0.2）
核心：**统一 adjust 与 NIC/toeplitz 的 hash 字节序口径**。可选：
- **方案A（对齐 DPDK 标量口径）**：填 tuple 时改用网络序写入（`rte_cpu_to_be_32(saddr)` 等、sport/dport 用 `rte_cpu_to_be_16`），使 `rte_thash_adjust_tuple` 内部 `rte_be_to_cpu_32` 还原出正确 word；**同时** `ff_rss_check`/`toeplitz_hash` 的喂入也必须改成与 NIC 实际口径严格一致的字节序，并在改后重新验证 enable=0 软算仍正确。**风险**：会动到当前已正确的软算链，需谨慎。
- **方案B（不走 DPDK adjust 的内部 hash，仅借其 complement 数学）**：评估是否可直接复用 `rte_thash_get_complement` + 自己用 `toeplitz_hash` 算 hash，绕开 `rte_be_to_cpu_32`/GFNI 的口径分歧（需 DPDK helper 内部 `tuple_len`/bit 布局适配，见 §6）。
- **方案C（保留软算为准）**：既然 enable=0 软算真机完全正确且开销可接受，评估动态 adjust 是否仅作"加速首选项"，强制 recheck=1 且失败必回退软扫描——但当前 recheck 已是这样仍多次重试，说明 adjust 命中率太低，性价比存疑。

**强烈建议**：在定方案前，先在真机用同一组 (saddr,daddr,sport,dport) 分别打印 `toeplitz_hash` 结果、`rte_thash_adjust_tuple` 内部 hash（或 `rte_softrss`/`rte_thash_gfni` 单独调用）结果、以及 NIC 实际入队 queueid，三者对齐即可一锤定音字节序/字序具体差在哪一步。

---

## 3. v6 路径对照（lib/ff_dpdk_if.c L3142–3172, L3391–3449）

- `ff_rss_check6`（L3142）：`bcopy(saddr6,16); bcopy(daddr6,16); bcopy(&sport,2); bcopy(&dport,2)` → `toeplitz_hash` → `(hash&(reta-1))%nb_queues==queueid`，结构与 v4 完全对称。v6 地址来自内核为 16 字节网络序，`bcopy` 原样拷入，与 v4 同样的"字节流口径"。
- `ff_rss_adjust_sport6`（L3391）：tuple 布局 saddr6[0..16]|daddr6[16..32]|sport[32..34]|dport[34..36]，tuple_len=36（4 的倍数 ✔），其余逻辑（desired/循环/recheck/回退）与 v4 一致。
- 因此 **0.1、0.2 两个缺陷在 v6 路径同样存在**，根因与修复方向同 v4（name 不含 proc_id；adjust 内部 `rte_be_to_cpu_32` 口径分歧对 36 字节按 9 个 word 处理）。

---

## 4. 多进程模型（事实）

- `ff_global_cfg.dpdk.proc_id`、`nb_procs`、`proc_lcore[]` 为配置项；`lcore_conf.proc_id = ff_global_cfg.dpdk.proc_id`（L319）。
- 参数校验：L1399–1406（nb_procs 范围、proc_id<nb_procs）。
- `rte_eal_process_type()` 守卫的关键点：
  - L832：`init_port_start` 中，非 primary 在配置 port 前 `continue`（secondary 不做 dev_configure/queue_setup/dev_start/set_rss_table）。
  - L939：仅 primary 做 `check_all_ports_link_status`。
  - L413/452/530：msg ring、mempool 等按 primary/secondary 分支。
- **`set_rss_table`（L923）只在 primary、且 `nb_queues>1` 时调用**：RETA 表是 NIC 级共享硬件状态，primary 配置一次即对所有进程/队列生效，secondary 不需也不应重配——这部分设计正确。
- **`ff_rss_thash_ctx_init`（L1476）primary/secondary 均执行**，无 process_type 守卫——这正是 0.1 暴露的位置（secondary 也跑，但因共享 tailq 重名而全败）。

---

## 5. 0.1 / 0.2 根因小结

| 缺陷 | 根因（代码已确证） | 触发位置 | 修复方向 |
|---|---|---|---|
| 0.1 secondary 全部 init 失败 | thash ctx name 仅含 port_id（L2993/3023），而 `rte_thash_init_ctx` 在 EAL 共享 tailq 上做全局重名检查并对重名返回 EEXIST（DPDK L225–234）。primary 先占名，secondary 同名必败 | L2994/3024 | name 拼入 proc_id（首选）或 secondary 改用 rte_thash_find_existing |
| 0.2 反算 sport 经常不通 | f-stack 用 bcopy 主机序写 tuple（L3093–3096），期望与 toeplitz_hash 同字节流口径；但 `rte_thash_adjust_tuple` 标量分支内部对 tuple 做 `rte_be_to_cpu_32`（DPDK L784–787），GFNI 分支又是另一口径——均与真机 NIC/toeplitz 口径不一致，导致反算 sport 落错队列；recheck 用正确口径能识别错误但有限重试内难撞中 | L3098 / DPDK L784 | 统一 adjust 与 NIC/toeplitz 字节序口径（首选改 tuple 为网络序并复核软算），或绕开内部 hash 仅借 complement |

---

## 6. 需 DPDK 源码侧 / 真机侧进一步佐证的点

1. **★决定性：真机走 GFNI 还是标量分支**：取决于 `rte_thash_gfni_supported()`（DPDK rte_thash.c，需 CPU 有 GFNI 指令且 SIMD≥512）。diag-dpdk 已从源码确证两分支口径不同：**GFNI 分支字节流直算、不做 be 翻转，与 toeplitz_hash 口径一致 → 走 GFNI 则 0.2 不复现**；**标量分支 be_to_cpu_32+softrss、与 toeplitz 不一致 → 走标量则 0.2 复现**。故 0.2 复现是条件性的：**真机 CPU 不支持 GFNI 才复现**。现象"经常不通"强烈提示真机走标量分支，但必须在真机实测 `rte_thash_gfni_supported()` 返回值 / `ctx->matrices` 是否为空一锤定音——此结果直接决定 0.2 复现条件与修复必要性，禁止臆测。
2. **rte_thash_add_helper 的 tuple_len/bit 布局**：helper 的 `tuple_len`、`tuple_offset` 与 adjust 中 `offset = tuple_offset + tuple_len - reta_sz_log` 的实际取值（DPDK rte_thash.c L544+ 未细读），决定改写的是 sport 哪几位，影响方案B 可行性——建议补读 `rte_thash_add_helper` 与 `rte_thash_get_complement`（DPDK L381）全文。
3. **内核 in_pcb 传入 ff_rss_check 的地址/端口确切字节序**：v4 saddr/daddr、sport/dport 进入 `ff_rss_check` 时是否均为网络序，需顺调用链（注册 dispatcher / pcblddr 路径）佐证。虽不影响"软算自洽"结论，但定方案A时必须精确。
4. **方案B（secondary 共享 primary ctx）可行性**：thash ctx 由 `rte_zmalloc` 分配（DPDK L246），其在 secondary 进程地址空间的可访问性、helper/matrices 指针跨进程有效性需 DPDK 多进程文档/实测确认。倾向于不采用，优先方案A（每进程独立 ctx）。
5. **真机三方 hash 对齐实验**：建议打印同一元组的 toeplitz_hash、rte_softrss/rte_thash_gfni、NIC 实际入队 queueid 三者，直接定位 0.2 字节序差异的精确环节。

---

诊断员A（只读代码考据）· 仅以实际代码为准
