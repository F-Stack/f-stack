# 06 — 测试与验收 Spec（Test & Acceptance Spec）

> English version: ../06-test-and-acceptance-spec.md

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
| `tools/` 编译目标全部生成（按 `f-stack/tools/` 子目录 Makefile target 实测，2026-05-28 订正）| 共 17 个子目录：**11 个 PROG（用户态命令）** = 9 freebsd 原生（`arp` / `ifconfig` / `ipfw` / `ndp` / `netstat` / `ngctl` / `route` / `sysctl` / `knictl`）+ 2 F-Stack 自带（`top` / `traffic`）；**4 个 LIB（库目标）** = `libmemstat`→LIB=memstat / `libnetgraph`→LIB=netgraph / `libutil`→LIB=util / `libxo`→LIB=xo；**2 个辅助子目录**：`compat/`（占位，无 Makefile target）/ `sbin/`（无 Makefile）。F-Stack 实际 ff_* 包装名：`ff_arp` / `ff_ifconfig` / `ff_ipfw` / `ff_ndp` / `ff_netstat` / `ff_ngctl` / `ff_route` / `ff_sysctl` / `ff_top` / `ff_traffic`（`knictl` 通常不加 `ff_` 前缀；`libmemstat` 等是库不是命令，无 `ff_` 前缀）。**全部 11 个 PROG 二进制 + 4 个 LIB 静态/动态库目标必须成功生成；详见 `99-review-report.md` §12.9** |
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

### 3.3 TC-01..TC-09 最小可执行映射（2026-05-28 增补；响应审计 §6.2-4）

> 本节响应独立审计 P2-007："TC-01..TC-09 只有名称与模板，未指定实际 F-Stack 示例程序、配置文件、网卡绑定命令、预期 stdout 关键字"。
> 数据来源（实测 2026-05-28）：`/data/workspace/f-stack/example/Makefile`（产物 `helloworld` / `helloworld_epoll`，源 `main.c` / `main_epoll.c`，含 `#ifdef INET6` 双栈分支）；`/data/workspace/f-stack/config.ini`（标准入口配置，含 `[dpdk] lcore_mask / port_list / numa_on` 等字段）；`/data/workspace/f-stack/tools/{arp,ifconfig,ipfw,ndp,netstat,ngctl,route,sysctl,knictl,top,traffic}/` 命令工具集（详见 §2.2）。
> 当前 F-Stack 仓内**无独立 UDP / IPFW / NETGRAPH example**；TC-03 / TC-07 / TC-09 标"待 M1 准备阶段补"，**不凭猜测填路径**。

| TC | example 程序 | 最小 config 字段 | 网卡/前置命令 | stdout 预期关键字（PASS 标志）| 实测前置条件 |
|---|---|---|---|---|---|
| **TC-01** | `example/helloworld` | `[dpdk] lcore_mask=1, channel=4, promiscuous=1, numa_on=1, allow=<PCI>, port_list=0; [port0] addr=192.168.1.2/24, gateway=192.168.1.1` | `dpdk-devbind.py --bind=vfio-pci <PCI>` 后 `./helloworld --conf config.ini` | DPDK 启动横幅（`EAL: Detected ...`）+ 监听端口（`f-stack helloworld start, port=80`，详见 main.c 行 124-217 含 `ff_init` / `ff_run`）；无 panic / 0 exit | 至少 1 块 DPDK 兼容 NIC；2MB×1024 hugepage |
| **TC-02** | 同 TC-01 | 同 TC-01；`port_list=0` | TC-01 启动后，外部主机 `curl http://192.168.1.2/` | 外部主机收到 `<html>...</html>` 静态页（main.c 顶部硬编码字符串）；helloworld stdout 出现 accept/read/write 日志 | TC-01 已 PASS |
| **TC-03** | （待 M1 准备阶段补；F-Stack 仓内无独立 UDP example，建议参考 main.c socket 类型改为 `SOCK_DGRAM` 或新增 `main_udp.c`） | UDP 监听端口字段（待补） | 待补 | 待补 | 待 M1 实测后填 |
| **TC-04** | `example/helloworld`（编译时定义 `INET6`，main.c 行 165-169 已含 `sockfd6` 双栈分支） | TC-01 + `[port0] addr6=2001:db8::2/64` | `./helloworld --conf config.ini`；外部主机 `curl -6 'http://[2001:db8::2]/'` | 同 TC-02 但走 IPv6；helloworld stdout 同 TC-02 路径 | TC-01 + IPv6 上联 |
| **TC-05** | F-Stack tools/ifconfig（产物 `ff_ifconfig`） | 复用 TC-01 config | `./ff_ifconfig f-stack-0 inet 192.168.1.2/24 alias`；查询 `./ff_ifconfig -a` | 输出含 `f-stack-0: ... inet 192.168.1.2 netmask 0xffffff00`（freebsd ifconfig 标准格式） | helloworld 已运行（提供 ff_ipc 通道） |
| **TC-06** | F-Stack tools/netstat（产物 `ff_netstat`，源同 freebsd `tools/netstat/main.c`） | 复用 TC-01 config | `./ff_netstat -an` | 输出 `Active Internet connections (including servers)` 表头 + 至少 1 行 `tcp4 ... LISTEN`（即 helloworld 监听 port 80） | TC-01 已 PASS |
| **TC-07** | F-Stack tools/ipfw（产物 `ff_ipfw`） | 复用 TC-01 config；`f-stack.conf` 启用 `FF_IPFW=1`（详见 04 §2.13 NETIPFW_SRCS） | `./ff_ipfw add 100 allow tcp from any to me 80` 后 `./ff_ipfw list` | 输出 `00100 allow tcp from any to me dst-port 80`（freebsd ipfw 标准格式） | 编译时 `FF_IPFW=1`；helloworld 已运行 |
| **TC-08** | F-Stack tools/route（产物 `ff_route`） | 复用 TC-01 config | `./ff_route add -net 10.0.0.0/8 192.168.1.1` 后 `./ff_route get 10.1.2.3` | 输出 `route to: 10.1.2.3` + `gateway: 192.168.1.1`（rib/nexthop 重写后必须仍能产生该输出，是 R-014 验收点） | helloworld 已运行；R-014 ff_route.c 已重写为 rib/nexthop API（M3 末验收点） |
| **TC-09** | （待 M1 准备阶段补；F-Stack 仓内无独立 NETGRAPH example）；产物 `ff_ngctl` 存在但需 `FF_NETGRAPH=1` 编译 | 复用 TC-01 config + 启用 `FF_NETGRAPH=1`（详见 04 §2.9） | 待补；建议参考 freebsd `ngctl mkpeer` / `ngctl list` 用法 | 待补；至少 `ff_ngctl list` 应输出 `There are X total nodes:` 表头 | 编译时 `FF_NETGRAPH=1`；helloworld 已运行；待 M1 实测 |

> 实施约束：以上 9 行除 TC-03 / TC-09 标"待 M1 准备阶段补"外，其余 7 行的 example 程序、config 字段、tool 命令均与 F-Stack 仓内实际产物一一对应。**TC-03 / TC-09 在 M1 实施阶段必须先实测对应 example 是否需要新增（如 `main_udp.c` / `main_ng.c`），再回填本表对应行**。
> 若 example 缺失导致 TC 无法跑通，应在 99 §6 实施进度跟踪表中记录"TC-XX BLOCKED, missing example"并补开 T-example-XX 任务。

### 3.4 各里程碑应跑的用例子集

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
| `if_alloc(IFT_ETHER)` 返回 `if_t`（typedef 为 `struct ifnet *`，13.0 中该 API 直接返回 `struct ifnet *`） | 类型匹配；F-Stack 自家 ifp 操作统一通过 `if_get*/if_set*` 访问函数，不直接依赖字段布局 |
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

### 5.4 物理机基线落档（外部团队执行；2026-06-05 接收）

**数据来源**：iWiki 4021545579（外部 OSPF/CMC 项目组在 Intel Xeon 8255C @ 2.5GHz + Mellanox CX-5 100G + TencentOS 4.4 + Linux 6.6.98 物理机平台执行 13.0 vs 15.0 并测对照）。

**与本项目 CVM 同时序 A/B 的关系**：物理机为**外部基线**，本项目 CVM 为**内部 A/B**；两者构成跨虚拟化层的双重基线，详细差异分析见 `physical-machine-bench-report.md` §5。

#### 5.4.1 helloworld 单核长连接（NFR-1 单流 TCP 吞吐）

| 指标 | 13.0 | 15.0 | Δ | NFR-1 阈值 | 通过 |
|---|---:|---:|---:|---|:---:|
| Req/sec | 958,109 | 1,056,178 | **+10.24%** | 不退化 > 5% | ✓（净收益） |
| p50 | 121 us | 107 us | -11.57% | — | — |
| p99 | 204 us | 197 us | -3.43% | 不退化 > 10% | ✓ |

#### 5.4.2 nginx_fstack 长连接（NFR-1 长连接 QPS 参考项）

| lcores | 13.0 (Req/s) | 15.0 (Req/s) | Δ | 通过 |
|---:|---:|---:|---:|:---:|
| 1 | 314,889 | 330,837 | **+5.06%** | ✓ |
| 2 | 623,962 | 653,648 | **+4.76%** | ✓ |
| 4 | 1,230,502 | 1,289,872 | **+4.83%** | ✓ |

#### 5.4.3 nginx_fstack 短连接（NFR-1 短连接 QPS）

| lcores | 13.0 (Req/s) | 15.0 (Req/s) | Δ | NFR-1 阈值 | 通过 |
|---:|---:|---:|---:|---|:---:|
| 1 | 127,592 | 124,727 | -2.25% | 不退化 > 5% | ✓ |
| 2 | 256,208 | 246,873 | -3.65% | 不退化 > 5% | ✓ |
| 4 | 406,380 | 381,614 | **-6.10%** | 不退化 > 5% | ⚠ **越线 1.10pp** |

#### 5.4.4 关键判定

1. **总体 PASS**：物理机 helloworld + nginx 长连接均显著 +5%~+10% 净收益；短连接 1/2 核在 NFR-1 阈值内通过。
2. **观察项**：nginx 短连接 4 核 -6.10% **超过 5% 阈值 1.10pp**，按 NFR-1 应触发评议；处置策略详见 `physical-machine-bench-report.md` §6.2（首选：备案为 trade-off，理由是 5 个 P0 SIGSEGV 修复价值远大于多核短连接 -6%；可选：物理机 perf 双版叠图定位 sonewconn/accept/kern_descrip 路径）。
3. **跨平台反差**：物理机 helloworld +10% 与 CVM 同时序 helloworld -7%~-9% 方向相反，已由 `13.0-baseline-cvm-bench-report.md` §11.5 perf flamegraph 归因为虚拟化层 virtio 路径开销在窄通道下放大；该反差**不否定**升级，反而印证 vendor 演进收益（RACK / CUBIC / sb_locking）在无 virtio 干扰的物理机上完全释放。

**详细对比、原始 wrk 输出、跨平台交叉对照、NFR-1 验收矩阵**：参见 `physical-machine-bench-report.md`。

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
| §5.4 物理机基线 | `physical-machine-bench-report.md`（iWiki 4021545579 外部团队数据二次整理） |
| §5 CVM 同时序 A/B | `13.0-baseline-cvm-bench-report.md`（本项目内 helloworld 单核 + perf 根因） |
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
