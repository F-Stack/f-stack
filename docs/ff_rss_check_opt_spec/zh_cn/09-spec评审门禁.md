# 09 spec 评审门禁 —— ff_rss_check 三项优化

> 角色：gatekeeper（M5 spec 门禁）。对 plan.md + 01~08 全部中文 spec 逐条断言审核。
> **强制原则（禁止臆测）**：本门禁每条断言均**回到实际代码/头文件核实**（给 `文件:行号` 证据），不仅信 spec 自述；spec 与代码不一致以**代码为准**，标 FAIL 并指明应打回的里程碑（M1/M2/M3/M4）。
> 审核基线 commit：`2422d12eb`（feature/1.26）。
> 核实涉及文件：`f-stack/lib/ff_dpdk_if.c`、`f-stack/lib/ff_config.c`、`f-stack/freebsd/netinet/in_pcb.{c,h}`、`f-stack/freebsd/netinet6/in6_pcb.c`、`f-stack-13.0-baseline/freebsd/netinet/{in_pcb.c}`、`f-stack-13.0-baseline/freebsd/netinet6/in6_pcb.c`、`dpdk-stable-24.11.6/lib/hash/rte_thash.h`、`f-stack/tests/unit/test_ff_dpdk_if.c`、`f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/M3-research-brief.md`、`f-stack/docs/03-LAYER3-FUNCTIONS.md`。

---

## 0. 行号核实方法学说明（避免误判 FAIL）

DPDK/FreeBSD 与 lib 代码中，多函数采用「返回类型独占一行 + 函数名在下一行」的内核风格，例如：

```2850:2852:f-stack/lib/ff_dpdk_if.c
int
ff_rss_check(void *softc, uint32_t saddr, uint32_t daddr,
    uint16_t sport, uint16_t dport)
```

故 spec 中标注的函数行号若与本门禁实测相差 **±1**，且属「返回类型行 vs 函数名行」差异，**判一致（PASS）**，不判 FAIL。同理 spec 标注「调用点行号」与「函数定义行号」不同属正常（如 `in_pcbladdr` 调用点 L1129 vs 定义 L1192），以语义为准。本门禁所有 PASS 均已确认无**实质**行号/语义错误。

---

## A. 与代码一致性断言

### A1. 用户态 RSS 现状（02 描述 vs 代码）

| 断言点 | spec 描述 | 实测证据（文件:行号） | 结论 |
|--------|-----------|----------------------|------|
| `ff_rss_check` IPv4-only + 入参 | 02§1.1/§1.4 `uint32_t saddr/daddr`，IPv4-only | `ff_dpdk_if.c:2851-2852` `ff_rss_check(void *softc, uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport)` | **PASS** |
| hash 输入布局 | 02§1.4 `saddr(4)+daddr(4)+sport(2)+dport(2)=12B` | `ff_dpdk_if.c:2865-2880` bcopy 顺序 saddr→daddr→sport→dport | **PASS** |
| 落队列判定式 L2885 | 02§1.4 `((hash&(reta-1))%nb_queues)==queueid` | `ff_dpdk_if.c:2885` `return ((hash & (reta_size - 1)) % nb_queues) == queueid;` | **PASS** |
| `nb_queues<=1` 返回 1 | 02§1.4/04§1.4 L2858 | `ff_dpdk_if.c:2858-2860` `if (nb_queues <= 1) return 1;` | **PASS** |
| `ff_rss_tbl_*` 行号 | init L2598 / set L2737 / get L2796 | `ff_dpdk_if.c:2598`(init)、get 内 `-ENOENT` 返回见 `:2844/2847` | **PASS** |
| `ff_rss_tbl[]` static 全局 | 02§1.2 L172 static | `ff_dpdk_if.c:172` `static struct ff_rss_tbl_type ff_rss_tbl[FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES];` | **PASS** |
| 结构体 IPv4-only | 02§1.3 L155-172 `uint32_t saddr/daddr` | `ff_dpdk_if.c:155-172` `ff_rss_tbl_dip_type.daddr`(L156)/`ff_rss_tbl_type.saddr`(L167) 均 `uint32_t` | **PASS** |
| `toeplitz_hash` 行号 | 02§1.1 L2547 / 07§0.2 L2548 | `ff_dpdk_if.c:2547`(返回类型)/`:2548`(函数名 `toeplitz_hash`) | **PASS**（±1 风格差异） |
| `ff_in_pcbladdr` 支持 v4/v6 | 02§3.1 L2571，支持 AF_INET/AF_INET6_FREEBSD | `ff_dpdk_if.c:2571`(def)、`:2579-2584` AF_INET / AF_INET6_FREEBSD 分支 | **PASS** |

**A1 结论：PASS**（用户态 RSS 现状 02 描述与代码完全一致）。

### A2. 内核侧 13.0↔15.0 差异属实

| 断言点 | spec 描述 | 实测证据 | 结论 |
|--------|-----------|----------|------|
| 13.0 baseline `in_pcb.c` 有 RSS 钩子 | 02§2.1 lport_dest L689、flag 解析 L707、清除 L712、get_portrange L805-806、ff_rss_check L904-905 | `f-stack-13.0-baseline/.../in_pcb.c:689`(lport_dest)、`:707`(rss_check_flag)、`:712`(清除)、`:805`(ff_rss_tbl_get_portrange)、`:904`(ff_rss_check) | **PASS** |
| 13.0 `in_pcbconnect_setup` + ff_in_pcbladdr/flag | 02§2.0/§2.1 `_setup` L1458、ff_in_pcbladdr L1526-1530、flag L1583-1589 | 13.0 `in_pcbconnect_setup`:1458、`ff_in_pcbladdr(AF_INET,...)`:1528、`INPLOOKUP_WILDCARD\|INPLOOKUP_LPORT_RSS_CHECK`:1588、`in_pcbconnect`:1228 | **PASS** |
| 15.0 `in_pcbconnect`(L1083) 缺失 ff_in_pcbladdr | 02§2.1(B)：15.0 仅原生 `in_pcbladdr`(L1129)、仅传 `INPLOOKUP_WILDCARD` | `f-stack/.../in_pcb.c:1083`(in_pcbconnect)、`:1128`(in_nullhost 分支)、`:1129`(in_pcbladdr 调用)、`:1145-1147`(in_pcb_lport_dest 传 INPLOOKUP_WILDCARD) | **PASS** |
| 15.0 `in_pcb_lport_dest`(L756) 缺失 RSS 钩子 | 02§2.1(A)：15.0 全缺；02§2.0 同名 +const | `f-stack/.../in_pcb.c:756-758` `in_pcb_lport_dest(const struct inpcb *inp, ...)`；**FSTACK/ff_rss/INPLOOKUP_LPORT_RSS_CHECK grep=0** | **PASS** |
| 15.0 lookup 新增 RT_ALL_FIBS | 02§2.0：`in_pcblookup_local(..., RT_ALL_FIBS, lookupflags, cred)` | `f-stack/.../in_pcb.c:877-878` `in_pcblookup_local(pcbinfo, laddr, lport, RT_ALL_FIBS, lookupflags, cred)` | **PASS** |
| 15.0 in_pcb_lport_dest 含 INET6 分支 | 02§2.0/04§2.3 v4/v6 统一 | `f-stack/.../in_pcb.c:860-871` INET6 分支 `in6_pcblookup_local(...)` | **PASS** |
| `INPLOOKUP_LPORT_RSS_CHECK` 在 enum 外、不在 MASK | 02§2.2：enum L616-621、宏 L623-625、MASK L627 不含 | `f-stack/.../in_pcb.h:616-621`(enum)、`:623-625`(`#ifdef FSTACK #define ... 0x80000000`)、`:627-628`(INPLOOKUP_MASK 仅 4 个 enum 位，**不含** RSS_CHECK) | **PASS** |

**A2 结论：PASS**（13.0↔15.0 差异、grep=0、enum/MASK 现状全部属实）。

### A3. rte_thash API 存在性与约束（DPDK 24.11.6）

| 断言点 | spec 描述 | 实测证据（`dpdk-stable-24.11.6/lib/hash/rte_thash.h`） | 结论 |
|--------|-----------|--------------------------------------------------------|------|
| `rte_thash_init_ctx` 存在/签名 | 02§4.1 L303 `(name, key_len, reta_sz, key, flags)` | `:304` `rte_thash_init_ctx(const char *name, uint32_t key_len, uint32_t reta_sz, uint8_t *key, uint32_t flags)` | **PASS** |
| `rte_thash_complete_matrix` | 02§4.1 L256 | `:257` `rte_thash_complete_matrix(uint64_t *matrixes, const uint8_t *rss_key, int size)` | **PASS** |
| `rte_thash_get_complement` | 02§4.1 L380 | `:381` `rte_thash_get_complement(struct rte_thash_subtuple_helper *h, uint32_t hash, uint32_t desired_hash)` | **PASS** |
| `rte_thash_adjust_tuple` | 02§4.1 L456 / 04§3.3 引用 | `:457` `rte_thash_adjust_tuple(ctx, h, tuple, tuple_len, desired_value, attempts, fn, userdata)` | **PASS** |
| `rte_thash_add_helper` | 03§3.2 L348 | `:349` `rte_thash_add_helper(ctx, name, len, offset)` | **PASS** |
| reta_sz 为对数 | 02§4.1/03§3.2/04§3.2 | `:288-291` "Logarithm of the NIC's Redirection Table (ReTa) size" | **PASS** |
| tuple_len 4 倍数 | 02§4.1/03§3.2/04§3.3 | `:441-442` "Length of the tuple. Must be multiple of 4." | **PASS** |
| desired_value=hash 低位 | 04§3.3 | `:443-444` "Desired value of least significant bits of the hash" | **PASS** |
| adjust_tuple 多线程安全 | 02§4.1/04§3.2 | `:433` "This function is multi-thread safe." | **PASS** |
| add_helper len≥reta_sz / 非线程安全 | 03§3.2 | `:341` "Must be no shorter than reta_sz"；helper 建议初始化期建好 | **PASS** |
| RETA_SZ_MIN/MAX | 03§3.2 L261-263 | `:261` `RTE_THASH_RETA_SZ_MIN 2U`、`:263` `RTE_THASH_RETA_SZ_MAX 16U` | **PASS** |

**A3 结论：PASS**（四个核心 API 实际存在，签名与 04/05 引用一致；约束全部属实）。

### A4. symmetric_rsskey / symmetric_rss 开关 / rss_hf（04§2.4/§3.4 vs 代码）

| 断言点 | spec 描述 | 实测证据（`ff_dpdk_if.c`） | 结论 |
|--------|-----------|---------------------------|------|
| `symmetric_rsskey[52]` | 04§3.4/03§3.4 L110 | `:110` `static uint8_t symmetric_rsskey[52]` | **PASS** |
| `symmetric_rss` 开关 | 04§2.4/§3.4 L699 | `:699` `if (ff_global_cfg.dpdk.symmetric_rss && dev_info.hash_key_size != 0)`；`:701` `rsskey = symmetric_rsskey;` | **PASS** |
| `rss_hf=RTE_ETH_RSS_PROTO_MASK` | 04§2.4 `default_rss_hf=RTE_ETH_RSS_PROTO_MASK`(L681-683) | `:681` `uint64_t default_rss_hf = RTE_ETH_RSS_PROTO_MASK;`、`:683` `rss_conf.rss_hf = default_rss_hf;` | **PASS**（任务简写「rss_hf=...(L681)」属近似，spec 写法 L681-683 更精确） |
| `&= flow_type_rss_offloads` 收窄 | 04§2.4 L705 | `:705` `rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;` | **PASS** |
| `default_rsskey_40bytes[40]` 非对称 | 03§3.4/04§3.4 L92 | `:92` `static uint8_t default_rsskey_40bytes[40]`；运行期 `rsskey`(L121)/`rsskey_len`(L120) | **PASS** |

**A4 结论：PASS**。
**附注（非 FAIL，编码期提示）**：`hash_key_size==52` 分支用的是 `default_rsskey_52bytes`（L690），而非 `symmetric_rsskey`；`symmetric_rsskey` 仅在 `symmetric_rss` 开关开启时启用（L699-701）。此细节不影响任何 spec 断言成立性，仅供 0.3 编码期注意「运行期 `rsskey` 实际取值取决于 hash_key_size 与 symmetric_rss 开关」——04§3.4「ctx key 必须=运行期 rsskey」的结论依然正确。

**A 类总结：A1/A2/A3/A4 全部 PASS。**

---

## B. 三项需求闭环断言

### B1. 0.1 回迁方案覆盖度与 15.0 适配

| 断言点 | 核查 | 结论 |
|--------|------|------|
| 覆盖 `in_pcb_lport_dest` 选端口逻辑 | 04§1.1(A)/§1.2、05§2.1、06 R-A.1(A1)：body 内回迁 rss_* 变量、flag 解析+清除、get_portrange、命中轮转/未命中软算、LOOPBACK | **PASS** |
| 覆盖 `in_pcbconnect` ff_in_pcbladdr 对接 | 04§1.1(B)/05§2.2 改动点 1：L1128 分支内、L1129 前插 `ff_in_pcbladdr(AF_INET,...)` | **PASS**（插入点已核实 L1128/1129 真实存在） |
| 覆盖 INPLOOKUP 处理（flag 传入+清除） | 04§1.1(C)/§1.3、05§2.2 改动点 2/§2.3：L1145-1147 加 flag；入口清除（沿用 13.0 L712） | **PASS** |
| 覆盖 ff_in_pcbladdr | 接口 L2571 不变、已支持 v4，05§1.1 | **PASS** |
| 适配 const inpcb | 04§1.2.2：lookupflags 值参可改、不改 inp | **PASS**（L756 const 已核实） |
| 适配 protosw 合并 | 02§2.3/04§5.3 标待确认（编码期核 connect 调用方） | **PASS**（标待确认合理，不影响方案成立） |
| 适配 lookup 新增 RT_ALL_FIBS | 04§1.2.4/05§2.1：复用 15.0 现有 lookup 调用形态（L877-878） | **PASS** |

**B1 结论：PASS**。0.1 回迁四个落点（lport_dest 逻辑 + in_pcbconnect 地址对接 + flag 传入 + 宏处理）全覆盖，15.0 适配点（const、_setup 合并、RT_ALL_FIBS、enum 化）全部对应真实代码。

### B2. 0.2 IPv6 方案

| 断言点 | 核查 | 结论 |
|--------|------|------|
| v6 独立表/函数（方案 A）保证 IPv4 零回归 | 04§2.2 决策 A：不动 `ff_rss_tbl_type`/`ff_rss_check` v4 签名与布局；05§1.2 全为新增符号 `ff_rss_check6`/`ff_rss_tbl6_*`；兼容矩阵 05§4 v4 行「否/无」 | **PASS** |
| 不改 v4 接口签名 | 05§1.1 v4 接口「不变」；方案 B（改签名）被明确否决（04§2.2/§4） | **PASS** |
| 内核 in6 对接点已定/标待确认 | 04§2.3：倾向复用统一 `in_pcb_lport_dest`（已核实含 INET6 分支 L860-871），实际调用链标待确认（in6_pcbconnect 是否复用），05§2.4 给两条路径 | **PASS**（对接点候选有据：统一函数 INET6 分支真实存在；待确认为编码期核实项，不阻塞方案） |
| config v6 解析 | 04§2.5/05§3.2：含 `:` 走 `inet_pton(AF_INET6)`，v4 分支不变（现状 `inet_pton(AF_INET)` L913-914 已核实） | **PASS** |
| 36B 布局满足 tuple_len 4 倍数 | 04§2.1：16+16+2+2=36，36/4=9 | **PASS** |

**B2 结论：PASS**。IPv6 为「全新增」（13.0/15.0 内核侧均 grep=0，已核实），方案 A 通过「纯新增符号 + 不动 v4 结构/签名」保证 IPv4 零回归，逻辑自洽。

### B3. 0.3 落队列映射推导正确性

核心断言：`desired_value ∈ D(q)={ v∈[0,R) | v%Q==q }`，使反算端口满足 `ff_rss_check` 落队列式 `((hash&(R-1))%Q==q)`。

**门禁独立推导复核**：
- 代码事实：`ff_rss_check` 判定 `((hash & (reta_size-1)) % nb_queues) == queueid`（`ff_dpdk_if.c:2885`，已核实）。记 `R=reta_size`、`Q=nb_queues`、`q=queueid`。
- `rte_thash_adjust_tuple` 令 `hash & (R-1) == desired_value`（`rte_thash.h:443-444` "least significant bits"，helper len 覆盖 reta_sz_log2，已核实）。
- 代入：`(hash & (R-1)) % Q == desired_value % Q`。要使其 `== q`，**充要条件 = `desired_value % Q == q`**，即 `desired_value ∈ {v∈[0,R) | v%Q==q}`。
- **推导与 04§3.3 一致 → 数学正确**。

| 断言点 | 核查 | 结论 |
|--------|------|------|
| desired_value 映射推导 | 与门禁独立推导一致 | **PASS** |
| 强制软算复核兜底 | 04§3.3 算法 5 / 05§1.3 步骤 4：反算端口必经 `ff_rss_check` 复核==1 才返回，否则丢弃回退 | **PASS**（正确性零容忍由软算复核守护） |
| attempts 用尽回退 | 04§3.6/05§1.3 步骤 5/06 R-B.3 | **PASS** |
| init 失败降级 | 04§3.6：ctx init 失败 → 降级纯软算（等价 0.1） | **PASS** |
| 与落队列式精确对齐（含 %Q） | 04§3.3 显式处理 `% nb_queues`，特例 R%Q==0 / R%Q!=0 / Q==1 均覆盖 | **PASS** |

**B3 结论：PASS**。0.3 落队列映射推导经门禁独立复算正确；`% nb_queues` 被显式处理（这是 03§3.4 风险点 1 的命门，spec 已正确解决）；强制软算复核 + attempts 回退 + init 降级构成三重兜底，与 `ff_rss_check` 落队列式精确对齐。

### B4. 0.5 bind-then-connect 落点实证与 R-E 范围

> 核心断言：bind(addr,0) 后 connect 绕过 RSS 的丢失点（v4 hunk1/hunk2、v6 in6_pcbbind）属实；15.0 connect 期 RSS 路径已具备（hunk3 等价），R-E 只需补 bind 门控；v4 必做 + v6 建议同步。

| 断言点 | 实测证据（文件:行号） | 结论 |
|--------|----------------------|------|
| v4 hunk1 丢失点：`in_pcbbind` 入 hash 块无 FSTACK 守卫 | `f-stack/.../in_pcb.c:739-748` `if (__predict_false((error = in_pcbinshash(inp)) != 0)) { MPASS(SO_REUSEPORT_LB); ... }` 无 `#ifdef FSTACK if(inp_lport!=0)` | **PASS** |
| v4 hunk2 丢失点：`in_pcbbind_setup` lport==0 分配端口无 #ifndef FSTACK | `f-stack/.../in_pcb.c:1273-1279` `if (*lportp!=0) lport=*lportp; if (lport==0) { in_pcb_lport(... lookupflags); }` 无 `#ifndef FSTACK` | **PASS** |
| v4 hunk3 已等价具备（无需改） | `f-stack/.../in_pcb.c:1313` `anonport=(inp->inp_lport==0)`；`:1363-1366` `in_pcb_lport_dest(... INPLOOKUP_WILDCARD\|INPLOOKUP_LPORT_RSS_CHECK)`（FSTACK 守卫 L1365-1366） | **PASS** |
| v4 故障链成立 | bind 占端口 → inp_lport≠0 → connect L1313 anonport=false → L1377 else 绕过 RSS（L1363-1366） | **PASS**（逻辑链经代码核实） |
| v6 in6_pcbbind 提前分配端口 | `f-stack/.../in6_pcb.c:354` `if (lport==0) { in6_pcbsetport(...); }`；`:361-369` else 入 `in_pcbinshash` | **PASS** |
| v6 connect RSS 分支已具备但条件被 bind 破坏 | `f-stack/.../in6_pcb.c:515-516` `if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)) { if (inp->inp_lport==0) {`；`:521` `INPLOOKUP_WILDCARD\|INPLOOKUP_LPORT_RSS_CHECK` | **PASS** |
| v6 故障链成立 | bind(v6,0) → in6p_laddr 非 unspec + inp_lport≠0 → connect L515 两条件均破 → 绕过 RSS | **PASS** |
| v6 13.0 baseline 无 FSTACK（v6 为全新增） | 02 §3.2 已实证 13.0/15.0 `in6_pcb.c` grep FSTACK/ff_rss=0（v6 RSS 13.0 本就无） | **PASS** |
| 不破坏 R-A~R-D | 0.5 复用 R-A connect 期 RSS 路径（不改 connect）、不改用户态接口、门控仅 lport==0 分支（05 §2.5） | **PASS** |
| bind 指定端口零回归 | 门控仅 `lport==0`（hunk1 `if(inp_lport!=0)` / hunk2 `if(lport==0)`），bind(addr,N) 不受影响（04 §3-ter.6 / AC-05-4） | **PASS** |
| v6 connect L515 条件联动标待确认（不阻塞） | 04 §3-ter.4 给路径 A/B/C 三方案，倾向路径 B（放宽 L515 为 inp_lport==0），标编码期实证（不影响 v4 方案成立，v6 为建议同步） | **PASS**（待确认合理，不阻塞） |

**B4 结论：PASS**。0.5 v4 丢失点（hunk1 L739-748 / hunk2 L1275-1279）与 hunk3 已等价具备（L1313/L1363-1366）、v6 未闭合点（in6_pcbbind L354/L361-369 + connect L515-516）均经代码实证；R-E 范围（v4 必做 hunk1+hunk2 + v6 建议同步 in6_pcbbind 门控 + L515 条件联动待确认）落点真实、故障链成立、bind 指定端口零回归、不破坏 R-A~R-D。v6 的 connect L515 条件联动为编码期实证项，不影响 v4 方案成立性。

**B 类总结：B1/B2/B3/B4 全部 PASS，五项需求（0.1~0.5）闭环成立。**

---

## C. 测试闭环断言

| 断言点 | 核查 | 结论 |
|--------|------|------|
| 07 用例数量 | 单元 14（01-01~06 含保留 6 + 02-01~05 + 03-01~05 = 3+6+5+5，去重计 §1.4 表 14 行）+ 集成 5（IT-RSS-01~05）+ 真机 4（RT-RSS-01~04）+ 零回归 9（RG-1~9） | **PASS** |
| 覆盖三项每个被测点 | 验收矩阵 07§5：0.1→01-01~06/IT-01,02,05/RT-01,02/RG-1~5；0.2→02-01~05/IT-04/RT-04/RG-6,7；0.3→03-01~05/IT-03/RT-03/RG-9 | **PASS** |
| mock 策略对 `ff_veth_softc_to_hostc`/static 可行 | 07§0.2：stub L101 当前返回 NULL（已核实）→ 用例改 stub 返回受控 ctx；static `rss_reta_size`(L133)/`rsskey`(L121)/`toeplitz_hash`(L2548) 不可直接访问，给出「测试侧独立复算 Toeplitz + 自洽性降级」策略（§0.3/§0.4） | **PASS**（mock 策略基于真实符号可见性，含 static 不可写的降级方案，务实可行） |
| 08 性能口径可执行 | 08§2 微基准（rte_rdtsc 打点 M-1~M-5）+ §2.2 端到端（E-1~E-3）+ §3 同口径固定项 + §4 真机步骤（B0/B1/B2 对照） | **PASS** |
| 硬门槛=不选错队列 0 容忍 + IPv4 不回归 | 08§5 P-3（D3 软算复核 0 失败，零容忍）+ P-1（IPv4 不回归）标为**硬门槛**；性能收益项 P-2/P-4/P-5 不阻断功能验收 | **PASS** |

**C 类总结：PASS**。
- 用例对实际函数/落点（含 static 符号可见性 L101/L121/L133/L2548）取证，mock 策略务实（关键：承认 static `rss_reta_size` 不可直接注入，给出「测试侧独立复算期望 + 自洽性断言降级到集成/真机」的备选，避免臆造能改 static 的假设）。
- 08 性能硬门槛抓住了正确性零容忍（P-3）与 IPv4 不回归（P-1），性能收益项合理归为非阻断，符合「0.1 回迁/0.2 新增非性能主目标」定位。

---

## D. 文档自洽断言

| 断言点 | 核查 | 结论 |
|--------|------|------|
| 00 总览/索引 | `zh_cn/` 下**无 00-总览/索引**，仅 plan.md + 01~09 | **PASS（建议补，非阻塞）** |
| 01-08 交叉引用一致 | 04 引 01/02/03；05 引 04；06 引 04/05；07 引 01/02/04/05/06；08 引 01/04/06/07 — 引用链闭合、章节号对应 | **PASS** |
| 行号/术语统一 | 关键行号（L2851/2885/2796/172/756/1083/1129/1145、in_pcb.h 623-625、rte_thash 四 API）在 01~08 间标注一致，且经本门禁核实与代码相符 | **PASS** |
| 无遗漏需求 | 三项 0.1/0.2/0.3 在 01（需求）→02（现状）→03（外网）→04（方案）→05（接口）→06（里程碑 R-A/B/C）→07（测试）→08（性能）逐层贯穿，无断链 | **PASS** |

**D 类结论：PASS**。
**建议（非阻塞）**：补一份 `00-总览索引.md`（列 plan + 01~09 章节地图 + 三项需求↔里程碑↔用例的导航表），提升 spec 可导航性。当前缺 00 不影响 spec 完整性与成立性，记为优化建议。

---

## E. 与既有文档不冲突断言（抽查）

| 抽查对象 | 核查 | 结论 |
|----------|------|------|
| `freebsd_13_to_15_upgrade_spec` M3-brief | `M3-research-brief.md:139-145`：13→15 升级时 `INPLOOKUP_LPORT_RSS_CHECK` 仅「保留 #define 紧跟 enum 后」，评级 EASY，**未提移植消费逻辑**——与本 spec（01§1.1/02§1.2「M3-brief 当时只评估保留 #define，未移植消费逻辑」）**完全一致** | **PASS（不冲突）** |
| 三层架构 Layer3 | `03-LAYER3-FUNCTIONS.md:207-218`：`struct ff_rss_tbl_type { uint32_t saddr; ... }` IPv4-only、`ff_rss_tbl_init`(L221) 内部表——与本 spec 02§1.3 结构描述一致 | **PASS（不冲突）** |
| KNOWLEDGE_GRAPH_WIKI / Layer1/2 | 抽查无与 RSS/in_pcb 三项优化矛盾的描述（本 spec 的「15.0 内核钩子缺失」是升级遗留事实，与三层架构静态结构描述正交） | **PASS（不冲突）** |

**E 类结论：PASS**。本 spec 与既有 13→15 升级 spec、三层架构/知识图谱**不矛盾**；尤其「内核 RSS 钩子在 15.0 缺失」恰好补全了 M3-brief 当时「只保留 #define、未移植消费逻辑」的遗留缺口，二者互为印证。

---

## F. 待确认项总表（01-08 去重汇总）

> 原则：待确认项属**编码期核实项**，不阻塞 spec 定稿（除非影响方案成立性）。下表去重后逐项标明应在哪个编码里程碑（R-A/R-B/R-C）起步核实。经评估，**无任何一项影响方案成立性**（均为落点精确化/调优参数/硬件能力确认）。

| # | 待确认项 | 来源（spec） | 应核实里程碑 | 是否影响方案成立 |
|---|----------|-------------|--------------|------------------|
| F1 | 15.0 `in_pcbconnect` 中 `ff_in_pcbladdr` 精确插入点（`in_nullhost(inp_laddr)` 分支内、`in_pcbladdr` L1129 之前） | 01§5、02§7.1、04§5.1、05§2.2 | **R-A** | 否（落点精确化，分支已核实存在） |
| F2 | connect 调用链是否经 protosw 合并影响 `lookupflags` 透传 | 02§2.3/§7.3、04§5.3 | **R-A** | 否（核实项，按需调整） |
| F3 | `ff_rss_tbl_get_portrange`(L2796) 现有精确返回语义（命中 0 / 未命中 -ENOENT / 错误码） | 05§1.1、07§1.1/§6.2 | **R-A**（断言以现有实现为准） | 否（已见 L2844/2847 返回 -ENOENT；编码期对齐调用形态） |
| F4 | `ff_rss_tbl_get_portrange` 端口轮转是函数内自增 `dport[0]` 还是调用方推进 | 07§1.1(TC-01-02)/§6.3 | **R-A** | 否（测试断言细化） |
| F5 | IPv6 connect 选端口实际走统一 `in_pcb_lport_dest`(L756) 还是 `in6_pcb` 独立路径 → 决定 0.2 内核对接点 | 01§5、02§3.2/§7.2、04§2.3/§5.2、05§2.4、07§2.4/§6.8 | **R-C** | 否（两条路径均有方案，05§2.4 给二选一，统一函数 INET6 分支已核实存在） |
| F6 | IPv6 RSS hash 网卡/DPDK 侧 RSS offload field（`flow_type_rss_offloads` 含 v6） | 01§5、02§7.4、04§2.4/§5.4、07§3.4/§6.9、08§6.4 | **R-C**（真机确认） | 否（默认 PROTO_MASK 已含 v6，仅确认硬件能力；不支持则 v6 落单队列，属硬件限制非 bug） |
| F7 | rte_flow 路径（`ff_dpdk_if.c:1001/1167` 硬编码 IPV4_TCP）是否在 0.2 范围 | 04§2.4 | **R-C** | 否（倾向不在 0.2 范围，标注即可） |
| F8 | v6 静态表容量宏（`FF_RSS_TBL6_MAX_*`）取值与内存预算 | 04§2.2/§5.6、05§1.4、06 R-C.3 | **R-C** | 否（倾向沿用 v4 宏，按内存预算复核） |
| F9 | 0.3 非对称 `default_rsskey_40bytes`(L92) 下 `adjust_tuple` 收敛率与合理 `attempts`（倾向初值 16） | 01§5、02§7.5、03§5.2、04§3.4/§5.5、06 R-B、08§6.2 | **R-B**（单测/真机调优） | 否（性能项，正确性由软算复核兜底；属调优参数） |
| F10 | thash helper（offset/len）添加方式（v4 offset=64bit / v6 offset=256bit、len≥reta_sz_log2 倾向 16） | 02§4.1、04§3.2、05§1.3 | **R-B**（v4）/**R-C**（v6） | 否（设计已给倾向值，编码期落实） |
| F11 | static `rss_reta_size`(L133) 在单测中的注入方式（倾向新增 test-only accessor，或断言改为测试侧独立复算） | 07§0.3/§6.1 | **R-A/R-B**（测试构建期） | 否（测试工程项，已给降级方案） |
| F12 | `rss_tbl_cfg_handler`(`ff_config.c:881`) 链接属性（是否 static），决定 v6 解析单测入口 | 07§1.2(TC-02-04)/§6.5 | **R-C** | 否（实测：函数无 static 前缀，为文件级函数；测试入口编码期定） |
| F13 | `ff_rss_check6`/`ff_rss_tbl6_*`/`ff_rss_adjust_sport[6]`/`ff_rss_thash_ctx_init` 新增函数落点行号 | 05§1.2/§1.3、07§1.2/§1.3/§6.4 | **R-B/R-C**（新增后回填） | 否（新增项，编码后回填行号） |
| F14 | desired_value 选取能否在 `ff_rss_adjust_sport` 内独立观测断言 | 07§1.3(TC-03-01)/§6.6 | **R-B** | 否（测试可观测性，否则经 03-02 端到端覆盖） |
| F15 | 集成/真机主动 connect 客户端载体（helloworld 是否含 connect / echo client / 自备最小程序） | 07§2.1/§6.7、08§6.5 | **R-A**（集成起步） | 否（测试载体选择） |
| F16 | 性能打点宏（`FF_RSS_PERF_PROBE`）命名与落位（仅 perf 构建启用） | 08§2.1/§6.1 | **R-B**（性能基线期） | 否（工程项） |
| F17 | wiki 量级值（软算 300+/连接、静态表 100~250、多进程 35%+）以本机真机实测校准 | 03§5.1、08§0/§6.3 | **R-B**（真机基线） | 否（预期参照，非硬门槛） |
| F18 | reta_size 与 nb_queues 真机实际取值（决定 D(q) 候选数与反算难度） | 08§3/§6.6 | **R-B**（真机记录） | 否（环境记录项） |
| F19 | 0.5 v4 hunk1 在 15.0 `in_pcbbind` L739-748（含 in_pcbinshash 失败回滚）的精确门控适配（lport==0 整块跳过、lport≠0 维持回滚） | 01§3-ter.8、02§6-ter.2、04§3-ter.6、06 R-E | **R-E** | 否（落点精确化，丢失点已核实存在） |
| F20 | 0.5 hunk2 后 `in_pcbbind_setup` 回写 lport=0 对 `in_pcbbind` L746-747 INP_ANONPORT 与 bind 返回语义影响 | 01§3-ter.8、04§3-ter.6 | **R-E** | 否（编码期复核） |
| F21 | 0.5 v6 connect `in6_pcbconnect` L515 进入 RSS 分支条件是否需放宽（in6p_laddr unspec && inp_lport==0 → inp_lport==0），路径 B | 01§3-ter.8、02§6-ter.3、04§3-ter.4、06 R-E.1(E5) | **R-E** | 否（v6 建议同步，v4 必做不依赖；路径 A/B/C 已给方案） |
| F22 | 0.5 REUSEPORT_LB（L740 MPASS）场景 bind(addr,0) 延迟分配行为 | 01§3-ter.7 AC-05-6、04§3-ter.6、07 RG-12 | **R-E** | 否（兼容性核实） |
| F23 | 0.5 是否需 per-socket `IP_BIND_ADDRESS_NO_PORT` setsockopt vs 隐式生效 | 01§3-ter.8、03§5.4/§6.5 | **R-E**（产品/编码决策） | 否（倾向沿用上游隐式语义） |
| F24 | 0.5 上游 commit `cb9b4d462` 是否已合入本仓库 13.0 baseline（决定 v4 是漏移植回迁 or 相对 baseline 新增） | 02§6-ter.4、03§6.4、06 R-E.1(E6) | **R-E**（起步 grep） | 否（不影响 15.0 落点，仅定性描述） |
| F25 | 0.5 R-E 内核 in_pcb/in6_pcb 单测载体（FreeBSD 内核单测框架/自备桩）；现有 lib cmocka 不覆盖内核 in_pcb | 07§1.5-ter/§6.10 | **R-E** | 否（测试工程项，已给集成/真机降级） |
| F26 | 0.5 最小 bind-then-connect 客户端载体 + 移植前后对照基线构造 | 07§2.6/§6.11、08§5-ter/§6.7 | **R-E** | 否（测试载体选择） |

**待确认总表条数：26 条（去重后；本轮 R-E 新增 F19~F26 共 8 条）。** 全部为编码期核实/调优/硬件确认/测试工程项，**无一项影响 spec 阶段方案成立性**。

---

## 总门禁结论

### 断言统计

| 类别 | 子断言 | PASS | FAIL |
|------|--------|------|------|
| A 与代码一致性 | A1/A2/A3/A4（A2 增 0.5 bind/connect 落点核实，见 B4 表） | 4 | 0 |
| B 需求闭环 | B1/B2/B3/B4（B4 = 0.5 bind-then-connect） | 4 | 0 |
| C 测试闭环 | C（5 子项） | 5 | 0 |
| D 文档自洽 | D（4 子项，含 00 缺失=建议补） | 4 | 0 |
| E 既有文档不冲突 | E（3 抽查） | 3 | 0 |
| **合计** | **20 个主断言/子项** | **20** | **0** |

> 说明：本轮 R-E（需求 0.5）增补新增 B4（0.5 闭环断言，11 个落点行号全部经代码实证 PASS），合计主断言由 19 增至 20，FAIL 仍为 0。0.5 的 v4 丢失点 / hunk3 已具备 / v6 未闭合点全部回代码核实（`in_pcb.c:739-748/1273-1279/1313/1363-1366`、`in6_pcb.c:354/361-369/515-521`），无 FAIL。

- **FAIL 项：0**。无任一断言因 spec 与代码不一致而判 FAIL，无需打回任何里程碑。
- **编码期待确认项：26 条**（全部记入 F 表，无一影响方案成立性；本轮 R-E 新增 F19~F26）。
- **建议（非阻塞）**：补 `00-总览索引.md`（D 类，已在本轮随 R-E 增补一并补齐 0.5/R-E 导航行）。

### 结论

**spec 阶段门禁：有条件 PASS（CONDITIONAL PASS）。**

- 「有条件」仅指存在 26 条**编码期**待确认项（属正常的实现期核实/调优项，按 F 表在 R-A/R-B/R-C/R-D/R-E 起步时先 grep/读码核实再动手，结论回写 spec，不臆测），**不存在任何阻断 spec 定稿的 FAIL**。
- 全部代码一致性断言（A）、需求闭环（B，含 0.3 落队列映射经门禁独立推导复核正确、0.5 bind-then-connect 落点经代码实证）、测试闭环（C）、文档自洽（D）、既有文档不冲突（E）均 PASS。
- spec 五项方案（0.1 回迁 / 0.2 IPv6 新增 / 0.3 thash 动态优化 / 0.4 recheck 运行时开关 / 0.5 IP_BIND_ADDRESS_NO_PORT bind-then-connect RSS 移植）落点真实、推导正确、IPv4 零回归约束闭合、正确性零容忍由软算复核守护——**方案成立，spec 可定稿，准予进入后续编码阶段（R-A→R-B→R-C→R-D→R-E）**。
- 0.5（R-E）增补要点：v4 必做 hunk1（`in_pcb.c:739-748` 入 hash 门控）+ hunk2（L1275-1279 端口分配门控），connect 期 hunk3 已等价具备（L1313/L1363-1366）无需改；v6 建议同步（`in6_pcbbind` L354/L361-369 门控 + connect L515 条件联动待编码实证）。全部丢失点/已具备点经代码实证 PASS。

### bounce 记录

- 本次门禁审核 bounce 计数：**0**（一次性通过，无需打回重审）。
