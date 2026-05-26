# 06 — 测试与验收 Spec（Test & Acceptance Spec）

> 系列文档：`/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/`
> 文档版本：v0.1（2026-05-26）
> 输入：`01-requirements-spec.md` FR-5 / FR-6 / NFR-1
> 受众：实施工程师 + Reviewer + QA

---

## 1. 测试总览

```
编译测试（FR-5）  →  单元/接口测试  →  功能用例（FR-6）  →  性能基线（NFR-1）  →  回归测试
```

每个里程碑结束都跑对应阶段的测试，作为退出 Gate。

---

## 2. 编译矩阵（FR-5）

### 2.1 矩阵维度

| 维度 | 值 |
|---|---|
| 编译器 | clang 12 / clang 16 / GCC 10 / GCC 12 |
| 架构 | x86_64（必选）、arm64（建议） |
| DPDK 版本 | LTS 当前版本（保持不变，约束 C-3） |
| `WITH_IPSEC` KNOB | OFF / ON |
| `WITH_NETGRAPH` KNOB | OFF / ON |
| `WITH_IPFW` KNOB | OFF / ON |

### 2.2 编译验收标准（每个矩阵格子）

| 检查项 | 标准 |
|---|---|
| `libff.a` 生成 | 必须成功 |
| 12 个 tools 二进制生成（ff_arp, ff_ifconfig, ff_ipfw, ff_libmemstat, ff_ndp, ff_netstat, ff_ngctl, ff_route, ff_sysctl + 3 个自带 knictl/traffic/top）| 必须全部生成 |
| 错误数 | 0 |
| 新增 warning 数 | 0（相对 13.0 baseline）。新增项必须在 `99-review-report.md` 中显式记录并标 P2/P3 |
| 编译时间 | 不退化 > 30%（信息项，不强制）|

### 2.3 编译矩阵跑法

```bash
# 在升级开始前打 baseline
cd /data/workspace/f-stack
make clean && make 2>&1 | tee build-13.0-baseline.log

# 每个里程碑末重复
make clean && make 2>&1 | tee build-M<N>.log
diff build-13.0-baseline.log build-M<N>.log
```

---

## 3. 功能性验收用例（FR-6 → 9 个用例）

### 3.1 用例清单

| 用例 ID | 名称 | 类型 | 优先级 |
|---|---|---|---|
| TC-01 | 单 lcore 启动 + DPDK 网卡绑定 + IP 配置 | 启动 | P0 |
| TC-02 | TCP echo 服务（IPv4）收发 | 数据面 | P0 |
| TC-03 | UDP echo 服务（IPv4）收发 | 数据面 | P0 |
| TC-04 | TCP echo 服务（IPv6）收发 | 数据面 | P1 |
| TC-05 | `ff_ifconfig` 接口配置 + 查询 | 控制面 | P0 |
| TC-06 | `ff_netstat -an` 套接字状态查询 | 控制面 | P0 |
| TC-07 | `ff_ipfw add allow tcp from ...` 规则下发 + 查询 | 控制面 | P1 |
| TC-08 | `ff_route add` 路由下发 + `ff_route get` 查询 | 控制面 | P0（受 rib/nexthop 重写影响最大）|
| TC-09 | `ff_ngctl` netgraph 节点创建 + 连接 | 控制面 | P2 |

### 3.2 单个用例的标准格式

每个用例须在测试报告中具备：

```
TC-XX：用例名
  前置条件：
    - 配置文件 config.ini 内容（最小化）
    - 网卡数量与绑定状态
  执行步骤：
    1. ./fstack --config config.ini &
    2. <验证操作>
  期望结果：
    - 退出码 0
    - stdout 含关键字 "..."
    - <数据面用例> 包丢失率 = 0
  实际结果：
    - <填写>
  通过/失败：
    - <PASS / FAIL>
```

### 3.3 各里程碑应跑的用例子集

| 里程碑 | 必跑用例 |
|---|---|
| M2 末 | （仅编译，不跑功能）|
| M3 末 | TC-01 / TC-02（极简启动 + TCP echo）|
| M4 末 | TC-01 / TC-02 / TC-03 / TC-05 |
| **M5 末** | **全部 9 个用例**（FR-6 验收） |

---

## 4. 单元/接口测试（针对 P0 任务）

### 4.1 ff_glue.c（T-ff-01）单元

| 测试点 | 期望 |
|---|---|
| `protosw` 中 `pru_*` 字段直接调用（不再经 `pr_usrreqs`） | 编译通过；socket 创建路径走通 |

### 4.2 ff_veth.c（T-ff-02）单元

| 测试点 | 期望 |
|---|---|
| `if_alloc(IFT_ETHER)` 返回 `if_t`（非 `struct ifnet *`） | 类型匹配；F-Stack 自家 ifp 操作走访问函数 |
| `if_setflags / if_getflags / if_setname` 等访问函数 | 行为与 13.0 直接字段访问等价 |

### 4.3 ff_route.c（T-ff-03）单元

| 测试点 | 期望 |
|---|---|
| `rtinit` 接受 `rib` + `nexthop` 新 API | 路由表条目可添加 |
| `ff_route` 用户态工具与内核 rib 表交互 | TC-08 通过 |

### 4.4 ff_subr_epoch.c（T-ff-04）单元

| 测试点 | 期望 |
|---|---|
| SMR 路径下 inpcb hash lookup 不 panic | TC-02 / TC-04 不卡死 |

### 4.5 uipc_mbuf.c FSTACK_ZC_SEND（T-kern-12）单元

| 测试点 | 期望 |
|---|---|
| `m_uiotombuf` 走 ZC 路径（iov_base 直挂 m_ext）| 大包发送性能不退化 |
| 新 `m_ext` 字段（refcnt/ext_type 重组）| 不出现 use-after-free / double-free |

---

## 5. 性能基线（NFR-1）

### 5.1 基线指标

| 指标 | 工具 | 期望 |
|---|---|---|
| 单流 TCP 吞吐（loopback） | iperf3 / pktgen | 不退化 > 5% |
| 单流 UDP PPS | dpdk-pktgen | 不退化 > 5% |
| 短连接 QPS（HTTP echo） | wrk2 | 不退化 > 5% |
| 连接建立延迟 P99 | wrk2 | 不退化 > 10% |
| 单核 lcore CPU 利用率（满载下） | perf top | 不退化（绝对值仅信息项）|

### 5.2 基线采集时机

```
升级开始前：在 13.0 baseline 上采集，存 baseline-perf-13.0.json
M5 末：在 15.0 升级后采集，存 perf-15.0.json
对比：diff 两份，写入 99-review-report.md
```

### 5.3 RACK 默认化的"性能提升"如何记录

15.0 默认 TCP 栈含 RACK 改进，可能带来吞吐提升。这种**提升**作为额外收益记录，不抵消任何不退化要求；如某些场景出现退化，须按 NFR-1 标准追责。

---

## 6. 回归测试

### 6.1 与既有 F-Stack 用例集衔接

如 F-Stack 仓内已有 example/ helloworld example、nginx_fstack 配合测试，M5 末跑一遍作为回归。

### 6.2 抓包验证

| 用例 | 验证点 |
|---|---|
| TC-02 抓包 | TCP three-way handshake 字段（SEQ/ACK/Flags）与 13.0 baseline 一致 |
| TC-03 抓包 | UDP 校验和正确 |
| TC-04 抓包 | IPv6 包头长度 / 扩展头一致 |

---

## 7. 验收用 Gate 总表

| Gate | 阶段 | 通过条件 |
|---|---|---|
| **G-M1** | M1 末 | mips 已删；libkern/ 等 cp -a 完成；编译矩阵 1 格通过（默认编译器 + x86_64 + 默认 KNOB） |
| **G-M2** | M2 末 | KERN_SRCS 编译通过；ff_subr_epoch.c 编译通过 |
| **G-M3** | M3 末 | libff.a 完整编译通过；TC-01 / TC-02 通过 |
| **G-M4** | M4 末 | 编译矩阵全格通过；TC-01 / TC-02 / TC-03 / TC-05 通过 |
| **G-M5** | M5 末 | 9 个 TC 全过；性能基线达标；libff ABI 审视无意外破坏；reviewer 出具 99 报告 |
| **G-Acceptance** | 项目结束 | 全部 Gate 通过；reviewer 签字 |

---

## 8. 测试环境要求

| 项 | 要求 |
|---|---|
| 硬件 | x86_64 服务器；至少 2 个 NIC（一个绑 DPDK，一个走 host）|
| OS | Linux（F-Stack 实际跑在 Linux）|
| 编译器 | GCC 10+ 或 clang 12+ |
| DPDK | LTS 当前版本（与现有 F-Stack 兼容版本一致）|
| 测试工具 | iperf3 / wrk2 / tcpdump / dpdk-pktgen / perf |

---

## 9. 测试报告模板（M5 末交付）

```markdown
# F-Stack 13→15 升级测试报告

## 1. 编译矩阵结果
| 编译器 × 架构 × KNOB | libff.a | tools 二进制 | 错误 | 新增 warning |
|---|---|---|---|---|
| ... | ✓ | 12/12 | 0 | 0 |

## 2. 功能用例结果
| TC-ID | 通过/失败 | 备注 |
|---|---|---|
| TC-01 | PASS | |
| TC-02 | PASS | |
| ... |

## 3. 性能基线对比
| 指标 | 13.0 | 15.0 | Δ | 通过 |
|---|---|---|---|---|
| TCP 吞吐 | X Gbps | Y Gbps | +Z% | ✓ |
| ... |

## 4. 已知缺陷与待办
- [ ] ...

## 5. 签字
- 实施工程师：____
- Reviewer：____
- Tech Lead：____
```

---

## 10. 与其他文档的衔接

| 本节产物 | 衔接对象 |
|---|---|
| 编译矩阵 | `05-implementation-plan.md` §2 各里程碑退出条件 |
| TC-01..09 | `01-requirements-spec.md` FR-6 验收 |
| 性能基线 | `01-requirements-spec.md` NFR-1 验收 |
| Gate G-M1..G-M5 | `05-implementation-plan.md` §1.1 节奏 |
| 测试报告模板 | `99-review-report.md` 引用为附件 |

---

## 11. 不在本测试范围内的事

| 项 | 说明 |
|---|---|
| netlink 兼容性测试 | DP-2 不引入 netlink |
| 抗量子 TLS 测试 | C-1 不引入 |
| pkgbase 安装测试 | F-Stack 不依赖 base |
| Fuzz 测试 / 大规模长稳测试 | Spec 阶段不安排；后续质量保障阶段单独立项 |
| 跨 IPv4-IPv6 双栈复杂场景 | 在基础 TC-02/04 通过后，由 QA 团队补充用例 |
