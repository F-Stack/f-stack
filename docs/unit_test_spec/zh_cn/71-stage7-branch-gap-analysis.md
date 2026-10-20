# Stage-7 Branch Gap Analysis — Per-File

| Field | Value |
|---|---|
| Spec ID | 71-stage7-branch-gap-analysis |
| Version | v1.0 (Phase 2 完成 — async team 4 analysts 汇总) |
| Status | READY-FOR-IMPLEMENTATION |
| Reference | 70-stage7-branch-boost-plan.md |

---

## §0 Baseline (Phase 0 实测)

```
=== merged unit + integration ===
Project   line=60.4% (1486/2461)  branch=57.2% (899/1573)  func=74.1% (103/139)

=== per headroom file ===
ff_config.c           branch= 75.18% ( 512/ 681)   missing: 169
ff_dpdk_kni.c         branch= 40.91% (  36/  88)   missing:  52
ff_ini_parser.c       branch= 83.82% (  57/  68)   missing:  11
ff_host_interface.c   branch= 92.45% (  98/ 106)   missing:   8
ff_epoll.c            branch= 89.13% (  41/  46)   missing:   5
ff_dpdk_pcap.c        branch= 88.89% (  16/  18)   missing:   2

=== capped (out-of-scope this stage) ===
ff_log.c / ff_thread.c / ff_init.c    branch=100% capped
ff_dpdk_if.c                          branch=22.64% (受 unit mock 限制)
```

LCOV 注：本仓库导出的 BRDA 用 `taken=0` 而非 `taken="-"` 标识"未取该 leg"，两者语义相同。

---

## §A ff_config.c (priority P0, gap=169)

来自 `analyst-config` async 子代理的 12 聚类报告。建议落地的核心聚类：

### G-CFG-01: `parse_lcore_mask` 大写/越界路径（+8 br, 4 TC）

- **Missing**: L98 br=2 (大写 `'X'`), L99 br=0/1, L131 br=0 (高位非零), L132 br=0/1, L135 br=0 (proc_id ≥ count)
- **Why**: 现有 fixtures 全用小写 `0xF`，从未喂 `0X3` / proc_id 越界 / 高位非零的"剥离 0x 后仍含非 0 字符"路径
- **TC**:
  1. `test_parse_lcore_mask_uppercase_0X_prefix_succeeds`
  2. `test_parse_lcore_mask_trailing_nonzero_high_bit_returns_zero`
  3. `test_parse_lcore_mask_proc_id_exceeds_lcore_count_returns_zero`
  4. `test_parse_lcore_mask_blanks_around_mask`
- **Patch**: 无（仅 fixture/TC 即可）

### G-CFG-02: `vlan_cfg_handler` 重绑定 + 字段重复写 [NEW-BUG]（+14 br, 5 TC, ~16 行 patch）

- **Missing**: L647/652/662/673/690/692/708/710 多处 false 分支 + sscanf fail / portid 越界 / vip_addr 触发 vip_cfg_handler
- **[NEW-BUG]**：vlan_cfg_handler 内 `addr/netmask/broadcast/gateway/vip_addr_str` 等多处 `cur->X = strdup(value)` 在**重复 key** 场景下不 free 旧值（同 Stage-6 修过 log.dir/filename/proc_type 的同款 bug，**剩 vlan/port/vdev/bond 4 个 handler 内 6×4=24 处未修**）
- **TC**:
  1. `test_vlan_cfg_handler_vlanid_not_in_filter_returns_one`
  2. `test_vlan_cfg_handler_bad_section_name_returns_zero`
  3. `test_vlan_cfg_handler_portid_over_max_returns_one`
  4. `test_vlan_cfg_handler_vip_addr_triggers_vip_cfg_handler`
  5. `test_vlan_cfg_handler_repeated_key_no_leak` (valgrind 验证 bug 已修)
- **Patch**: 在 vlan_cfg_handler 所有字段 strdup 前加 `if (cur->X) free(cur->X);` (~16 行)

### G-CFG-03..G-CFG-12（缩略）：

| ID | 主题 | TC 数 | Δ br | Patch |
|---|---|---|---|---|
| G-CFG-03 | vdev_cfg_handler 字段重复写 + sscanf fail | 4 | +12 | ~12 行 |
| G-CFG-04 | bond_cfg_handler 同上 | 4 | +14 | ~14 行 |
| G-CFG-05 | port_cfg_handler 字段重复写 + INET6 + vip 数组 | 5 | +18 | ~20 行 |
| G-CFG-06 | freebsd boot/sysctl 链表多 entry / 非数值 | 3 | +6 | 无 |
| G-CFG-07 | INET6 路径（addr6/gateway6/vip_addr6_array）| 4 | +10 | 无 |
| G-CFG-08 | rss_check_cfgs / rss_tbl_str 边界 | 2 | +6 | 无 |
| G-CFG-09 | dpdk_args_setup 各 lcore_mask/proc_lcore 组合 | 3 | +8 | 无 |
| G-CFG-10 | OOM (calloc/strdup 返 NULL) [需 wrap] | 2 | +4 | 1 行 NULL guard 补 |
| G-CFG-11 | 错误 INI（缺 section / 类型错误）| 2 | +4 | 无 |
| G-CFG-12 | -t/-c/-p 命令行覆盖默认值 | 3 | +6 | 无 |

**§A 总计**：~40 TC，+110 branches，patch ~64 行（分 ≤30 行/commit 拆 3 个 patch commit）

---

## §B ff_dpdk_pcap.c (priority P2, gap=2)

来自 `analyst-pcap-epoll`：

### G-PCAP-01: `ff_dump_packets` while-loop snap_len 截断（不可达）

- **Missing**: L118 br=3
- **结论**：这是**死代码分支** — `out_len += min(remaining, data_len)` 上限就是 `snap_len`，`out_len > snap_len` 严格不可达。不补丁。
- **TC**: 无（不可达分支）
- **Patch**: 无（建议不动；88.9% 即 G-PCAP-01 不可达后的天花板）

### G-PCAP-02: `g_flen < f_maxlen` 不轮转分支（+1 br, 1 TC）

- **Missing**: L127 br=1
- **Why**: 现有 TC 用 `f_maxlen=1` 全轮转或永不调 dump，从未让"写包但 g_flen 还未到 maxlen"路径走过
- **TC**:
  1. `test_ff_dump_packets_no_rotate_when_under_max` — 设 `f_maxlen=10MB`，写一小包，验证不轮转
- **Patch**: 无

**§B 总计**：1 TC，+1 br（达成 ≥95% 目标 = 17/18 = 94.4%；接近但严格未到 95% — 实际 G-PCAP-01 不可达使 100% 实质不可达，G-CB-7-2 此文件目标降为 ≥94.4% 或保留 88.9% 不动）

**决策**：考虑到 G-PCAP-01 不可达，**目标调整为 88.9%→94.4%**（+1 TC 即可）

---

## §C ff_epoll.c (priority P1, gap=5)

来自 `analyst-pcap-epoll`：

| Cluster | Missing | TC | Δ br |
|---|---|---|---|
| G-EPOLL-01 | L89 br=1: events 不含 EPOLLIN | `test_ff_epoll_ctl_add_writeonly_only_epollout` | +1 |
| G-EPOLL-02 | L113 br=2: EVFILT_READ + data=0 + 无 EV_EOF | `test_ff_epoll_wait_evfilt_read_data_zero_no_eof` | +1 |
| G-EPOLL-03 | L116 br=1: filter 既非 READ 也非 WRITE | `test_ff_epoll_wait_unknown_filter_skipped` | +1 |
| G-EPOLL-04 | L133 br=1: EV_EOF + filter 非 READ/WRITE | `test_ff_epoll_wait_eof_unknown_filter` | +1 |
| G-EPOLL-05 | L152 br=2: events 非空 + maxevents=0 | `test_ff_epoll_wait_zero_maxevents_returns_zero` | +1 |

**§C 总计**：5 TC，+5 br → 100%（46/46）

---

## §D ff_ini_parser.c (priority P1, gap=11)

来自 `analyst-iniparser-kni`：

### G-INI-01: 多行 value continuation 路径（+4 br, 2 TC）

- **Missing**: L121 br=0..3 全部 untaken（INI_ALLOW_MULTILINE 启用但无续行 fixture）
- **TC**:
  1. `test_ff_ini_parse_multiline_value_continuation` — 喂 `key=line1\n line2\n line3\n` 续行 INI
  2. `test_ff_ini_parse_multiline_value_with_blank_line` — 续行后接空白 + 后续段名

### G-INI-02: BOM / 段不闭合 / = vs : / 错误恢复（+5 br partial, 3 TC）

- **Missing**: L106 br=1 (BOM 第二字节非 0xBB), L107 br=1 (BOM 第三字节非 0xBF), L133 br=1 (no-`]` not-error path), L141 br=2 (`:` 分隔符), L155 br=3 (handler 返 0 inside-section), L158 br=1 (no-eq-and-error-already-set)
- **TC**:
  1. `test_ff_ini_parse_partial_bom_byte2_not_bb` — `0xEF 0xBB 0x?? key=value` (实际不太可能 — 把 BOM 部分变第二字节为 0xC0 类似)
  2. `test_ff_ini_parse_section_no_close_bracket` — `[section_no_close\nkey=val`
  3. `test_ff_ini_parse_colon_separator` — `key:value`
- **Patch**: 无

**§D 总计**：5 TC，+9 br → 97% (66/68，G-INI-02 部分分支可达性受限)

---

## §E ff_dpdk_kni.c (priority P0, gap=52)

来自 `analyst-iniparser-kni`：52 missing 拆 7 个 cluster：

| Cluster | Missing | TC 数 | Δ br | Patch |
|---|---|---|---|---|
| G-KNI-01: kni_process_tx ring 处理 + ratelimit | L142×5,L148×2,L149×2,L161×2,L163×2 = 13 | 3 | +13 | 无（需 mock ring）|
| G-KNI-02: kni_process_rx 路径 | L181×2,L183×2,L185×2 = 6 | 2 | +6 | 无 |
| G-KNI-03: protocol_filter_l4 TCP/UDP 长度边界 | L199×2,L209×2,L221×2 = 6 | 4 | +6 | 无 |
| G-KNI-04: ff_kni_alloc OOM 路径 + 各 ring 创建 | L426×2,L435×2,L466×2,L476×2,L480×2,L486×2 = 12 | 4 | +12 | 1 行 NULL guard |
| G-KNI-05: proto_filter NULL / 无效 port_id | L114 br=0, L121 br=4, L334 br=3 (IPv6) | 3 | +3 | 5 行 NULL/range guard |
| G-KNI-06: ratelimit 三档（console/general/kernel）边界 | L383/394/402/410/513 br=0 等 = 5 | 3 | +5 | 无 |
| G-KNI-07: enqueue 错误路径 | L521×4, L522×0, L529×1 = 6 | 2 | +6 | 无 |

**§E 总计**：21 TC，+51 br → ~93% (~82/88)，远超 ≥55% 目标，等价完成 aspirational 65% 目标

---

## §F ff_host_interface.c (priority P2, gap=8)

来自 `analyst-host-iface`：

### G-HIF-01: `ff_mmap` prot/flags 位标志 false 分支（+4 br, 4 TC）

- **Missing**: L70/71/75/76 br=1（PROT_READ / PROT_WRITE / MAP_PRIVATE / MAP_ANON 各 false 分支）
- **TC**:
  1. `test_ff_mmap_prot_writeonly` (PROT_WRITE only)
  2. `test_ff_mmap_prot_readonly` (PROT_READ only)
  3. `test_ff_mmap_map_shared_anon` (MAP_SHARED|MAP_ANON)
  4. `test_ff_mmap_file_backed_no_anon` (mkstemp + ftruncate + MAP_PRIVATE no anon)

### G-HIF-02: `ff_get_current_time` NULL guard 分支（+2 br, 2 TC）

- **Missing**: L196 br=1 (sec=NULL), L200 br=1 (nsec=NULL)
- **TC**:
  1. `test_ff_get_current_time_null_sec`
  2. `test_ff_get_current_time_null_nsec`

### G-HIF-03: `clock_gettime` assert-fail（不可达 / wrap-only，**Stage-7 不做**）

- **Missing**: L176/209 br=0
- **决策**：需 `-Wl,--wrap=clock_gettime` 注入失败，工作量与价值不对等。**Stage-7 不做**，留 `[FU-S7-HIF-CLOCK-WRAP]` future。

**§F 总计**：6 TC，+6 br → 98.1% (104/106) ≥ 95% ✓

---

## §Z 整体规模汇总

| File | New TC | Δ branches | Branch%（before → after） | Patch lines |
|---|---|---|---|---|
| ff_config.c | ~40 | +110 | 75.2% → ~91% | ~64（分 3 commit）|
| ff_dpdk_kni.c | 21 | +51 | 40.9% → ~93% | ~6 |
| ff_ini_parser.c | 5 | +9 | 83.8% → ~97% | 0 |
| ff_host_interface.c | 6 | +6 | 92.5% → 98.1% | 0 |
| ff_epoll.c | 5 | +5 | 89.1% → 100% | 0 |
| ff_dpdk_pcap.c | 1 | +1 | 88.9% → 94.4% (G-PCAP-01 不可达)| 0 |
| **Σ** | **~78** | **+182** | – | **~70** |

**项目整体 branch 预测**：57.2% + 182/1573 × 100% = 57.2% + 11.6pp = **68.8%**（远超 G-CB-7-1 ≥65% 目标）

按 Q4 扩展授权 ≤30 行/commit，patch 拆为 5~6 个 commit，混在 TC commit 中提交。

---

## §Y 外网资料启发（Phase 2 收集）

未做深度外网搜索 — 4 analyst 直接基于代码 + lcov 实测确定 gap 已足够（247 missing 全部 mapped）。如未来 Stage-8 介入未覆盖文件需要外网启发再补充。

EOF
