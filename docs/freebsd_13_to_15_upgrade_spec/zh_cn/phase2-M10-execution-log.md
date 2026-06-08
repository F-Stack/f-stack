# Phase-2 M10 Execution Log — FF_FLOW_IPIP (P1d)

> 状态：✅ PASS（IPIP 隧道双端互通；1 bounce 修软退化）
> 日期：2026-06-08
> 上游基础：M9 commit `2f4748638`

---

## 1. 摘要

启用 `FF_FLOW_IPIP=1`（M7+M8 PA/ZC 暂回退到注释，独立验证 GIF/IPIP 路径）。涉及：

1. lib/Makefile 启用 FF_FLOW_IPIP
2. lib/ff_dpdk_if.c 把 `create_ipip_flow` 失败 `rte_exit` 改为软警告（virtio NIC 无 rte_flow IPIP 卸载，但 GIF 走 FreeBSD 内核软件路径不依赖硬件 flow）
3. example/Makefile 自动跳过依赖 ZC 的 helloworld_zc target（因 M10 测试需 disable ZC 隔离）
4. 服务端 `tools/sbin/ifconfig gif0 create / tunnel / inet` 三步配 GIF 隧道
5. 客户端 Linux `ip tunnel add gif0 mode ipip` + `ip addr add` + `ip link set up`
6. ping 验证：3/3 ICMP echo reply ✓

**最终结果**：客户端 Linux IPIP ↔ 服务端 F-Stack GIF 跨实现互通，RTT < 1ms。

---

## 2. 改动清单

| 文件 | 改动 | 行数 |
|---|---|---|
| `lib/Makefile` | 启用 `FF_FLOW_IPIP=1` + 把 PA/ZC 临时回退到注释 | +3 / -3 |
| `lib/ff_dpdk_if.c` | `create_ipip_flow` fail 由 `rte_exit` 改为 `printf` 软警告 + 注释解释 | +13 / -3 |
| `example/Makefile` | 用 `nm` 探测 libfstack.a 是否含 `ff_zc_send`，缺则跳过 helloworld_zc target | +9 / -1 |

**总计 3 文件 +25/-7**

---

## 3. RCA — Bounce #1

### 3.1 现象

启用 FF_FLOW_IPIP=1 编译 PASS，但 helloworld primary 起栈到 `Port 0 Link Up` 后立即报：

```
Flow rule validation failed: Function not implemented
EAL: Error - exiting with code: 1
  Cause: create_ipip_flow failed
```

并 `rte_exit(EXIT_FAILURE)` 退出，G2 失败。

### 3.2 根因

`ff_dpdk_if.c:1442` 调用 `create_ipip_flow(0)` 通过 `rte_flow_create` API 在 NIC 上创建 IPIP 解封装 flow rule。**virtio_net 驱动**（实测网卡 `0000:00:09.0 1af4:1000 Virtio network device`）不实现 `rte_flow` API → ENOTSUP。

但 GIF 隧道实际走 **FreeBSD 内核软件路径**（`if_gif.c` / `in_gif.c` 在 lib 内已编入），与 NIC 硬件 flow 卸载**正交**。13.0 baseline 该 rte_exit 是过激的失败处理。

### 3.3 修复

把 `rte_exit(EXIT_FAILURE, ...)` 改为 `printf("M10 [WARN] ...")` 软警告。注释清楚说明：rte_flow IPIP 是性能优化（硬件卸载封装/解封装），缺失时软件路径仍可工作。

---

## 4. Gate 实测结果

### G1 — 编译

| 子项 | 结果 |
|---|---|
| `lib/ make clean && make` | exit=0 / 0 errors / 57 warnings |
| `libfstack.a` | 6.53 MB |
| `example/ make` | helloworld + helloworld_epoll 产出，helloworld_zc 自动跳过（lib 无 ff_zc_send 符号） |

### G2 — 主程序冒烟

| 子项 | v1（rte_exit）| v2（warning fallback） |
|---|---|---|
| primary 起栈 | ✗ (rte_exit) | ✓ ALIVE |
| Flow rule warn | – | `Flow rule validation failed: Function not implemented`（warning） |
| ipfw2 / dpdk if | – | ✓ ✓ |

### G3 — IPIP 隧道功能验收

| 子项 | 命令 | 结果 |
|---|---|---|
| G3.1 | `tools/sbin/ifconfig gif0 create` | exit=0 ✓ |
| G3.2 | `tools/sbin/ifconfig gif0` | `gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280 / groups: gif` ✓ |
| G3.3 | `tools/sbin/ifconfig` (list all) | `lo0` + `f-stack-0` + `gif0` 三接口可见 ✓ |
| G3.4 | `ifconfig gif0 tunnel 9.134.214.176 9.134.211.87` + `ifconfig gif0 inet 10.10.10.1 10.10.10.2 netmask 0xffffffff` | `tunnel inet 9.134.214.176 --> 9.134.211.87 / inet 10.10.10.1 --> 10.10.10.2` flags=`UP,POINTOPOINT,RUNNING,MULTICAST` ✓ |
| G3.5 | client: `ip tunnel add gif0 mode ipip remote 9.134.214.176 local 9.134.211.87` + addr + link up | `gif0@NONE: link/ipip 9.134.211.87 peer 9.134.214.176 inet 10.10.10.2 peer 10.10.10.1/32` ✓ |
| **G3.6** | **`ping -c 3 -W 2 10.10.10.1`** | **3/3 received, 0% loss, RTT 0.288/0.436/0.649 ms ✓** |

### G4 — 性能（observation only，OQ-2 默认许可降级）

iperf 大流量未跑（client 端工具 + 时间预算限制）；功能 PASS 即认为 P1d 完结。

### G5 — 文档

`phase2-M10-spec.md` + `phase2-M10-execution-log.md`；docs anchor + Summary scope 同 M6/M7/M8/M9 模式。

### G6 — Lint：0 errors。

### G7 — Commit：本地英文 commit，不 push。

---

## 5. Bounce 计数

| # | 阶段 | 触发 | 修复 |
|---|---|---|---|
| 1 | gate→code | rte_exit 因 virtio 无 rte_flow IPIP 卸载 | rte_exit → printf warning（软退化） |

**1/3 bounces**，未 escalation。

---

## 6. 已知遗留 / Follow-up

| ID | 描述 | 计划 |
|---|---|---|
| F1 | virtio NIC 无 rte_flow IPIP 硬件卸载 → CPU 软件 GIF 路径性能可能低于硬件支持的 NIC | 不修（硬件能力限制；非代码 bug） |
| F2 | iperf 大流量隧道吞吐基线未做 | 推迟到 phase-5b 大并发性能阶段 |
| F3 | M10 例 Makefile 探测 ZC 符号需要先编 lib —— 此 ordering 依赖未来可加 explicit dependency | 文档 + 测试通过即可 |

---

## 7. Phase 进度

| Phase | 状态 |
|---|---|
| A. Spec | ✅ |
| B. Research | ✅ |
| C. Code v1（Makefile only） | ✅ → bounce |
| C. Code v2（rte_exit fallback + ex Makefile guard） | ✅ |
| D. Review | ✅ 0 lint |
| E. Gate | ✅ G1-G3.6 + G6/G7 PASS；G4 observation only |

**M10 整体：✅ PASS**
