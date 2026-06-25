# R-F 真机验证 SOP（路线③：①根因修复为主 + ②软扫描兜底）

> 单测/本机 virtio reta=0 无法端到端验证「key 三方对齐 → adjust 选 sport 真落本队列」。本 SOP 给出可在真 RSS 网卡（Intel i40e/ixgbe/ice、Mellanox mlx5、virtio with reta>0 等）上**逐项执行**的最小验证步骤。
> 验证目标：(P1) 路线①是否在真机可用；(P2) 路线②兜底是否随时可切换；(P3) 三方 key 真的对齐了（不是巧合命中）；(P4) RETA 假设成立。

---

## 0. 验证前置

- 已 `make install` 含 R-F 修复的 `lib/libfstack.a`、`lib/ff_config.h`。
- 测试机至少 ≥2 个 RX 队列（多队列 RSS 才有意义）。
- 业务跑在端口 0；`config.ini` 含 `[rss_check]` 段（参考下面）。
- 准备一个轻量发包源（如 `f-stack/tools/ff_rss_self_queue_info` / `pktgen` / 任意可发 TCP/UDP 真流量的客户端）。
- 控制端能 `ssh`/`tmux` 进入测试机看 `ff_log` + 内核 `dmesg`。

config.ini 关键段示例：

```ini
[rss_check]
enable=1
recheck=1
thash_adjust=1   ; 路线① 默认；切 0 即路线② 软扫描
rss_tbl=0 <local_ip4> <peer_ip4> <peer_port>
```

---

## 1. P1 — 路线① 启动可用性验证（thash_adjust=1）

**步骤 1.1**：`thash_adjust=1` 启动 f-stack 实例（primary 进程）。

**步骤 1.2**：检查启动日志，要求看到 **以下其中之一**：

- 成功：`ff_rss_thash_ctx_init: port N key sync ok (v6_ready=X), remaining ports use soft scan` —— **P1 PASS**，说明 v4 ctx 建好、v6 ctx 建好（v6_ready=1）或仅 v4（v6_ready=0）、且 `rte_eth_dev_rss_hash_update` 在该网卡上**真的工作**。继续 §2。
- 路线② 自动降级：`rte_eth_dev_rss_hash_update(port N) failed (-XX), route② fallback` 或 `rte_eth_dev_rss_hash_conf_get(port N) failed (-XX), route② fallback` 或 `rte_thash_init_ctx(v4) failed for port N` —— **P1 在该网卡上不可用**，但路线② 已自动接管（adjust_sport 守卫已让所有调用走软扫描，零业务影响）。**结论**：把 `thash_adjust=0` 写死，跳到 §3 验证路线② 全程正确。
- 严重：`rss_thash_init` 全部 port 都失败 + 业务出错（不应发生，路线② 兜底应保护到位）→ 转人工排查。

**步骤 1.3**（路线① 成功路径补强）：用 `dpdk-procinfo` 或 `rte_eth_dev_rss_hash_conf_get` 实测确认 NIC RSS key 已被替换。简易 dump（在 f-stack 进程内任一调试点）：

```c
struct rte_eth_rss_conf c;
uint8_t k[64];
c.rss_key = k; c.rss_key_len = sizeof(k);
rte_eth_dev_rss_hash_conf_get(0, &c);
/* hex-dump k[0..40] 与 default_rsskey_40bytes 比较：bytes 8-13、32-37 应不同 */
```

期望：字节 8-13 与 32-37 均**不等于** `default_rsskey_40bytes` 对应位置（被 LFSR 改写）。

---

## 2. P2 — 路线①/② 切换实测

**步骤 2.1**：启动时 `thash_adjust=1`，验证 §1 通过；`f-stack` 跑业务，记录 5 分钟 RSS-relevant 指标基线（每 RX 队列 pps、misqueue 计数、`ff_rss_check` 命中率等）。

**步骤 2.2**：停 f-stack，把 `config.ini` 改 `thash_adjust=0`，重启。**期望**：

- 启动日志见 `ff_rss_thash_ctx_init: thash_adjust=0, route② soft scan only`。
- 所有 `ff_rss_adjust_sport*` 调用返回 -1（→ 内核走软扫描）。
- NIC RSS key 仍为**原始 default_rsskey_40bytes**（用 §1.3 的 dump 验证 bytes 8-13、32-37 是原始 0x6d/0x5a/...）。
- 业务功能正常（misqueue=0、`ff_rss_check` 命中率 100%）。

**步骤 2.3**：性能对比（可选）：路线① vs 路线② 在同样负载下 connect()/bind() 路径的 sport 选择延迟。预期路线② 软扫描略慢于路线① O(1) 反算，但**业务正确性必须等价**。

---

## 3. P3 — 三方 key 对齐离线对拍（不依赖真机即可测）

> 此步在任何机器（含本机）都能跑，用于验证 R-F 修复**逻辑层面**的位级正确性，与 §1/§2 互补。

**步骤 3.1**：写一个 micro-bench（不入仓，仅本地一次性脚本）：
- 取 `default_rsskey_40bytes` 复制为 K0；
- 用 R-F 的串行构造算法（v4 add_helper offset=64 len=16；v6 add_helper offset=256 len=16，基于 v4-rewritten K1）算出 KEY_FINAL；
- 对随机 1000 组 (saddr, daddr, dport)，用 `rte_thash_adjust_tuple(ctx_v4, helper, ...)` 反算 sport（ctx_v4 用 K0 init + add_helper），记录 sport_v4；
- 用同一组元组 + sport_v4 + KEY_FINAL，跑 `toeplitz_hash`，验证 `(hash & (reta_size-1)) % nb_queues == desired_qid`。
- v6 同。

**期望**：等价率 ≥ 99.5%（理论 100%；少量残差因 adjust 的 attempts 上限导致——我们已让 adjust 失败时 return -1 走软扫描兜底，无业务影响）。

> 此步是 design §7 T-RF2/3 的对拍版，单测里因构造完整 ctx 复杂未直接覆盖；真机上线前建议手工跑一次。

---

## 4. P4 — RETA 假设确认（reta[idx]=idx%nb_queues）

**步骤 4.1**：在 f-stack 进程内任一调试点调用：

```c
struct rte_eth_rss_reta_entry64 reta[ (rss_reta_size+RTE_ETH_RETA_GROUP_SIZE-1) / RTE_ETH_RETA_GROUP_SIZE ];
memset(reta, 0xFF, sizeof(reta));  /* mask=all */
rte_eth_dev_rss_reta_query(0, reta, rss_reta_size);
/* 遍历 reta[g].reta[i]，验证 == (g*RTE_ETH_RETA_GROUP_SIZE + i) % nb_queues */
```

**期望**：完全匹配 `idx%nb_queues`（用户已确认 `set_rss_table`(L613) 写入此模式）。若不匹配，路线①/② 都需要在 design §6.4 标注为前提失败。

---

## 5. P5 — secondary 进程 find_existing 验证（多进程部署）

> 仅当用户实际跑 multi-process EAL（rare），否则跳过。

**步骤 5.1**：primary 启动后看到 §1 成功日志。

**步骤 5.2**：启动 secondary（`--proc-type=secondary`），检查日志：

- 成功：无 `rte_thash_find_existing(v4) failed for port N (secondary)` 报错。
- 失败：见到该 WARNING → 该 secondary 进程 `rss_thashX_ready=0`、走软扫描兜底（功能不破，但损失 thash O(1) 反算）。

---

## 6. 异常预案（按 bounce 规约）

| 现象 | 分类 | 处置 |
|---|---|---|
| `rte_thash_init_ctx` 一直返 NULL（primary） | 路线① 不可用 | 改 `key_sync=0`，跑路线② |
| `rte_eth_dev_rss_hash_update` 一直 -ENOTSUP | 路线① 不可用（驱动） | 改 `key_sync=0`，跑路线② |
| `rss_hash_update` 成功但 NIC 仅写部分队列（i40e 老固件） | 路线① 半坏 | 改 `key_sync=0`，路线② 兜底；issue NIC 厂商 |
| 路线② 也 misqueue >0 | RETA 假设破裂或软扫描 bug | 转人工，先关 enable=0 全软算 |

---

## 7. 真机 OK 后的提交流程

1. 跑 §1 + §2 + §4，记录控制台日志/dump 截图到 `_rf_work/realmachine_log_<date>.txt`。
2. 改 `_rf_work/team_runtime_postmortem.md` 增补一节"§7 真机 SOP 实测结果"。
3. 用户确认 OK 后，**手动通知 leader 提交**（本任务约定不主动 git）；提交时 config.ini **不入本地测试值**（按 AI memory 44404940 规约）。
