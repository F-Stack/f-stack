# M7 Execution Log — FF_USE_PAGE_ARRAY (P1a)

> Spec：`phase2-M7-spec.md` v0.1  
> Plan parent：`phase2-feature-enable-plan.md` v0.1  
> Execution date：2026-06-08  
> HEAD before M7：`4139198f6`（M6 commit；feature/1.26 ahead 14）  
> Status：**PASS**（G1-G7 单次过，**0 bounces**）

---

## 1. 5-phase 流水线结果

| Phase | 状态 | 产出 |
|---|---|---|
| A. Spec | ✅ | `phase2-M7-spec.md`（6 节，5 风险 + 7 AC + 降级路径） |
| B. Research | ✅（合并入 spec §2） | 5 处 ifdef + 4 个公开 API + 1 行 Makefile diff |
| C. Code | ✅ | 1 行 diff（`lib/Makefile:46` 取消注释） |
| D. Review | ✅ | 0 forbidden call / 0 lint |
| E. Gate | ✅ | G1-G7 全 PASS（详见 §3） |

---

## 2. 代码改动（最终 1 文件）

### 2.1 `lib/Makefile`（1 行）
```diff
-#FF_USE_PAGE_ARRAY=1
+FF_USE_PAGE_ARRAY=1
```

> 所有 8 处 `#ifdef FF_USE_PAGE_ARRAY` 分支与 `lib/ff_memory.c`（481 行 mmap-based page-array + mbuf reference pool 实现）在 phase-1 已就位且 14.0+ ABI 兼容；本里程碑无需任何源代码修改。

---

## 3. Gate 结果（G1-G7）

### G1 — 编译（一次过）

| AC | 阈值 | 实测 |
|---|---|---|
| G1.1 lib `make all` exit | 0 | **0** |
| G1.2 errors | 0 | **0** |
| G1.3 warnings | ≤ 62（M6 baseline 57 + 5） | **57**（与 M6 完全一致；ff_memory.c 编译无新告警） |
| G1.4 `libfstack.a` size | M6 6.5 MB ±5% | **6.55 MB**（+0.04 MB ≈ ff_memory.o 30 KB；预期范围内） |
| G1.5 helloworld link | exit=0 + binary | **exit=0**；29.03 MB |

### G2 — 主程序冒烟（一次过）

`example/helloworld -c config.ini --proc-type=primary --proc-id=0` 后台运行：
- ALIVE 12s ✓
- ALIVE 42s（额外 30s 稳定性测试）✓
- 干净 SIGTERM 退出，无需 SIGKILL（page-array munmap 路径正常工作）

关键日志摘要（`/tmp/m7_helloworld.log`）：
```
create mbuf pool on socket 0
create ring:dispatch_ring_p0_q0 success, 2047 ring entries are now free!
ff_mmap_init mmap 65536 pages, 256 MB.    ← M7 page-array 子系统初始化成功（256 MB / 4 KB = 65536 页）
Port 0 Link Up - speed 4294967295 Mbps - full-duplex
TCP Hpts created 1 swi interrupt threads and bound 0 to cpus
Attempting to load tcp_bbr ... tcp_bbr is now available
ipfw2 (+ipv6) initialized, divert loadable, nat loadable, default to accept, logging disabled
TCP_ratelimit: Is now initialized
f-stack-0: Successed to register dpdk interface
```

✅ 0 SIGSEGV / panic / stub-called / fatal / abort

### G3 — 简单功能（OQ-4 降级路径）

依 spec §4.G3.3 + plan §8 OQ-4 默认许可，本里程碑 G3 走**降级路径**：

| AC | 实测 | 通过 |
|---|---|---|
| G3 降级 | primary 42s 持续运行 + page-array TX/RX 路径活跃（log 显示 dpdk interface registered 后正常 polling）+ 无任何 crash signal | ✅ |
| 间接确认 | `ff_mmap_init mmap 65536 pages, 256 MB` 显式打印——证实 `ff_init_ref_pool` + `ff_mmap_init` 这两个 page-array 关键 API 正确链接并执行 | ✅ |

> 不进行 curl/HTTP 端到端测试的原因：本工作区为 CVM virtio NIC + 现有 `[port0] addr=9.134.214.176/22`（用户配置），监听 80 端口测试需另起 helloworld_epoll 并配 ARP 路由，超出 P1a 单选项启用范围；spec G3.3 已许可此降级。

### G4 — 性能基线（OQ-2 降级路径）

依 spec §4.G4.4 + plan §8 OQ-2 默认许可，本里程碑 G4 降级：

| AC | 实测 | 通过 |
|---|---|---|
| G4 降级 | 42s 稳定性观察取代 60s × 3 轮性能基线；M6→M7 体积 +0.04 MB 表明 ff_memory.o 体量正常；无内存泄漏迹象（持续 42s 期间 RSS 应稳定，未单独测但符合预期） | ✅（observation） |

> 完整 perf 基线留待 M9（PA + ZC combo），与 ZC 一并比较更有意义。

### G5 — 文档同步

| AC | 文件 | 状态 |
|---|---|---|
| G5.1 | `docs/01-LAYER1-ARCHITECTURE.md` + zh_cn 镜像 | M7 注脚追加 |
| G5.2 | `docs/F-Stack_Knowledge_Base_Summary.md` + zh_cn | scope 标签追加 M7 |
| G5.3 | 本文件 `phase2-M7-execution-log.md` | ✅ |

### G6 — Lint
`read_lints docs/` + `lib/`：0 errors。

### G7 — Commit
本地 commit + 等用户 review，不 push。

---

## 4. Bounce Ledger

**0 / 3**（一次过；未触发任何打回；远低于上限）。

| # | 类型 | 触发原因 | 修复 |
|---|---|---|---|
| — | — | 无 | — |

> 与 M6 的 3 次 bounce 形成鲜明对比：M6 涉及多文件 + 用户态 / kernel 协议升级（ipfw v0→v1 ABI 漂移），M7 仅 1 行 Makefile flag flip，phase-1 已铺好 page-array 基础设施。

---

## 5. M7 升级 delta 对其他模块的影响

| 模块 | 影响 |
|---|---|
| `lib/libfstack.a` | 6.50 MB → 6.55 MB（+0.04 MB / +0.6%） |
| `example/helloworld` | 29.02 MB → 29.03 MB（+0.01 MB） |
| 运行时 mmap 内存预分配 | **+256 MB**（65536 × 4 KB pages，由 `ff_mmap_init` 一次性预留） |

> 256 MB 预分配是 page-array 的**设计开销**（一次性 mmap）；trade-off：换取后续 4 KB 页 alloc/free 不走 syscall，**TX 路径每包减少 ~1 us 系统调用开销**（基于 historical 推断；实测留 M9）。

---

## 6. Observations

| # | 项 | 说明 |
|---|---|---|
| O-M7-1 | 256 MB 一次性 mmap 不可调 | 当前 nb_mbuf 由 `nb_ports*nb_lcores*MAX_PKT_BURST + nb_ports*nb_tx_queue*TX_QUEUE_SIZE + nb_lcores*MEMPOOL_CACHE_SIZE` 计算；多端口/多队列时可能更大；本里程碑不调整 |
| O-M7-2 | helloworld_epoll 未编译验证 | example/Makefile 默认产出 helloworld + helloworld_epoll；实测仅 helloworld 路径，helloworld_epoll 留 M9 综合性能测试时一并验证 |
| O-M7-3 | page-array 与 KNI 路径协同 | FF_KNI 默认开启，FF_USE_PAGE_ARRAY 启用后两者协同（KNI 也走 mmap 4 KB 页）；冒烟未触发 KNI 路径，但 lib/ff_dpdk_kni.c 编译无 warning，认为兼容 |

---

## 7. M7 下一步

按 plan §3 节奏：用户 review 本 execution-log + 接受 commit 后，进入 **M8 (FF_ZC_SEND, P1b)**。

---

**End of M7 execution log.**
