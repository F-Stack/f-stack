# Phase-2 M11/M12/M13 Joint Spec — P2 Smoke Trio

> 状态：DRAFT → ready
> 上游基础：M10 commit `90c730496`
> 复杂度：S（合并三个 P2 单选项 smoke 验证；rte_flow fallback 与 M10 同模式）

---

## 1. 目标

按 plan 优先级 **P2 = 编译 + 主程序起栈 + 文档** 即可（不要求功能/硬件依赖）：

- **M11 — FF_FLOW_ISOLATE**（独立启用）
- **M12 — FF_FDIR**（独立启用）
- **M13 — FF_LOOPBACK_SUPPORT**（独立启用）

合并到一份 spec + 顺序执行 + 单 commit per milestone。

---

## 2. 设计

### 2.1 已知 rte_flow 依赖（M10 模式延续）

| 选项 | 涉及 rte_flow 调用 | 行号 | 当前失败行为 |
|---|---|---|---|
| FF_FLOW_ISOLATE | `port_flow_isolate(0,1)` | ff_dpdk_if.c:1407-1408 | rte_exit |
| FF_FLOW_ISOLATE | `init_flow(0, 80)` | ff_dpdk_if.c:1432-1435 | rte_exit |
| FF_FDIR | `fdir_add_tcp_flow(0, 0, FF_FLOW_INGRESS, 0, 80)` | ff_dpdk_if.c:1463-1465 | rte_exit |
| FF_LOOPBACK_SUPPORT | （仅在 ff_dpdk_if.c:2423 mbuf 软件回环路径，不依赖 rte_flow） | – | – |

### 2.2 修复策略

与 M10 `create_ipip_flow` 同模式：把 4 处 rte_exit 改为 printf 警告，让 primary 在缺 rte_flow 硬件支持的 NIC 上仍可起栈。

---

## 3. Acceptance Criteria

| ID | 验收 |
|---|---|
| AC-M11-1..3 | FF_FLOW_ISOLATE=1 单独启用，lib build 通过，helloworld primary 起栈 ≥12s 无 panic |
| AC-M12-1..3 | FF_FDIR=1 单独启用，同上 |
| AC-M13-1..3 | FF_LOOPBACK_SUPPORT=1 单独启用，同上 |
| AC-Mxx-doc | 各 milestone 独立 anchor 句 + 单 commit |

---

## 4. 风险

| ID | 风险 | 缓解 |
|---|---|---|
| R-Mxx-1 | rte_flow fallback 链路修改可能影响后续启用其他 flow 选项的硬件部署 | 注释清晰说明：fallback 仅在硬件不支持时生效；硬件支持时 ret=0 路径不变 |
| R-Mxx-2 | LOOPBACK 路径的 mbuf 软件回环可能与 PA/ZC 交互 | M13 测试时 disable PA/ZC（同 M10 模式） |

---

## 5. 工作流（每 milestone 同样的 5 步）

1. 启用相应 Makefile 行（M10 风格 PA/ZC 注释）
2. 一次性把 4 处 rte_exit 改为 printf warning（合并到 M11 第一次 commit；M12/M13 复用）
3. lib + example 重编 → G1 PASS
4. 起栈 12s alive → G2 PASS
5. 文档 anchor + commit

---

> 下一步：开始 M11。
