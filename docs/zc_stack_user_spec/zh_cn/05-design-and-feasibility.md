# 05 · 方案设计与可行性结论（FSTACK_ZC_RECV）

> 依据 01-04 实测 + 交叉验证综合。结论可溯源到代码；设计级未验证项显式标注「待实现验证」。

## 0. 可行性结论（先给结论）
**结论：可行（高置信度）。** 核心依据：
1. 内核零拷贝引擎**已原生就绪** —— `soreceive_generic_locked` 的 `mp0!=NULL` 分支（uipc_socket.c:3061-3066）以 mbuf 链返回、避免拷贝，且经 FreeBSD 官方手册确认（04 §1）。
2. RX 侧**数据已零拷贝** —— DPDK mbuf 经 m_extadd(EXT_DISPOSABLE) 挂为 BSD ext-mbuf（03 §1），唯一残余拷贝点是 soreceive→uiomove（02 §2）。
3. 所有权移交**有现成 refcount 支撑** —— BSD mbuf 未释放则 DPDK seg 不回收（03 §2/§4）。
**唯一缺口**：用户态到 soreceive 的 mp0 贯通通道 + APP 端 release 契约。**属可控工程量，非架构性障碍。**

## 1. 内核机制选型对比

| 维度 | 方案A：复用 soreceive mp0（推荐）| 方案B：仿 send 的 FSTACK_ZC_RECV 哨兵 hook |
|---|---|---|
| 原理 | kern_recvit 把 soreceive 第4参由 NULL 改为透传 mp 出参 | 在 soreceive/uiomove 处加 magic 判定，特殊路径返回 mbuf |
| 内核改动面 | 极小：仅 kern_recvit(uipc_syscalls.c:948) + 一个新入口 | 大：需改 soreceive 拷贝循环逻辑，侵入核心路径 |
| 与上游一致性 | 高（mp0 是 FreeBSD 原生官方能力）| 低（自造 hack，升级 FreeBSD 易冲突）|
| 风险 | 低（复用成熟分支 + 现有记账/锁，02 §4 自洽）| 高（改 soreceive 易引入回归）|
| 协议层改动 | 无（TCP 默认 soreceive_generic 已支持；UDP dgram mp0!=NULL 回退 generic L3508）| 可能需多协议适配 |
| 对称性 | 与 send 不对称但更干净 | 表面与 send 对称，实则方向相反强行对称 |

**推荐方案A**。理由：mp0 是 FreeBSD 官方零拷贝 API（04 §1 手册佐证），改动最小、风险最低、升级友好；send 的 magic 机制因方向相反（用户→内核 vs 内核→用户）不宜强行镜像（01 §5）。

## 2. API 设计（建议）
对称于 send 的 get/write/send，read 侧需 recv→consume→release 三段：

```c
/* 1) 从 socket 零拷贝收取 mbuf 链；成功时 zm->bsd_mbuf 指向内核交出的链，返回字节数 */
ssize_t ff_zc_recv(int fd, struct ff_zc_mbuf *zm, size_t nbytes);

/* 2) 顺序读出/遍历 mbuf 链数据（重设计现有空 stub ff_zc_mbuf_read）
 *    现签名 const char*data 与读出语义矛盾，应改为 out 形参或返回段指针/长度 */
int ff_zc_mbuf_read(struct ff_zc_mbuf *zm, char *out, int len);   /* data 去 const，作 OUT */
/* 或零拷贝遍历： */
int ff_zc_mbuf_segment(struct ff_zc_mbuf *zm, void **seg_data, int *seg_len);

/* 3) APP 读完后归还整链（触发逐段 ff_mbuf_ext_free → rte_pktmbuf_free_seg）*/
void ff_zc_recv_free(struct ff_zc_mbuf *zm);   /* 内部 m_freem(zm->bsd_mbuf) */
```
- `struct ff_zc_mbuf` 可复用（01 §1.1）：bsd_mbuf=链首、bsd_mbuf_off=遍历游标、off=已读偏移、len=总长。
- 内核侧：新增 `ff_zc_recv` → 新 kern_recvit 变体（透传 `struct mbuf **mp`）→ soreceive(..., mp, ...)。

## 3. mbuf 生命周期 / 所有权方案（闭环论证）
- 取走：mp0!=NULL 分支 `sbfree`(L3060)+`*mp=m`(L3063)，内核 **不 m_free**（L3068 仅 mp==NULL 走），sb_mb 前移(L3065) → 内核侧不再持有，无双重 free（03 §6 已验证）。
- 持有：BSD ext-mbuf 在 APP 手中，m_ext refcnt>0 → DPDK seg 不回收（03 §2 归还链由 BSD free 驱动）→ **无 use-after-free**。
- 归还：`ff_zc_recv_free`→`m_freem(链)`→ 每段 refcnt 归零 → ff_mbuf_ext_free → ff_rte_frm_extcl(取 ext_arg1) → rte_pktmbuf_free_seg → DPDK seg 归还。
- **强制契约**：APP 必须 release，否则 mempool 泄漏（03 §6）。建议文档 + 调试期 mbuf 计数告警。

## 4. 边界处理矩阵
| 场景 | 设计处理 | 依据 |
|---|---|---|
| 整 mbuf（len==m_len-moff）| 零拷贝直交 | uipc_socket.c:3061-3066 |
| 部分 mbuf（split）| 回退 m_copym（非零拷贝，但正确）| L3081/3098 |
| MSG_PEEK | 不支持 ZC，回退拷贝 | 不摘链 L3055/3076 |
| MSG_WAITALL | 逐段零拷贝多轮交付 | L3129-3165 |
| 非阻塞 DONTWAIT | 部分 mbuf m_copym(M_NOWAIT)；官方手册警示 ZC+DONTWAIT 限制 | L3081 + 04 §1 BUGS |
| MSG_OOB | 不支持 ZC（独立 uiomove）| L2682 |
| 控制消息 SCM | 走 controlp 独立通道（已 mbuf 直交）| L2888-2955 |
| KERN_TLS | 回退 soreceive_generic | L3456/3470 |
| UDP | soreceive_dgram mp0!=NULL 回退 generic，天然可用 | L3508 |

## 5. 风险与工作量评估
| 风险 | 等级 | 缓解 |
|---|---|---|
| mempool 泄漏（APP 不 release）| 中 | 强制 release API + 调试计数告警 |
| split/PEEK/OOB 非零拷贝边界 | 低 | 明确回退拷贝，文档标注 ZC 仅大块整 mbuf 生效 |
| page-array 时序（FF_USE_PAGE_ARRAY）| 中 | 实现期专项验证（03 §5）|
| kern_recvit 变体与现有 recv 共存 | 低 | 仿 ff_zc_send 隔离（01 §2 防误触经验）|

**工作量估算（实现期，非本期）**：
- 内核：kern_recvit 变体 + soreceive mp 透传（~50-100 行）；
- 用户态：ff_zc_recv + ff_zc_mbuf_read 重写 + ff_zc_recv_free（~100-150 行）；
- 编译开关 FSTACK_ZC_RECV（lib/Makefile，仿 L212）；
- 示例 + 测试 + 性能基线。
- 粗估 **8-15 人天**（不含大规模性能调优）。

## 6. 实现里程碑建议
- **M0** 内核 mp 贯通：kern_recvit 变体 + soreceive mp 透传，单元验证 mbuf 正确交出
- **M1** 用户态 API：ff_zc_recv / ff_zc_mbuf_read 重写 / ff_zc_recv_free
- **M2** 生命周期闭环：refcnt + release 契约 + 泄漏检测；valgrind/mempool 计数
- **M3** 边界完备：split/PEEK/WAITALL/DONTWAIT/UDP 回退正确性测试
- **M4** 示例 + 性能基线（对比拷贝路径，大包收取/代理转发场景）
- **M5** FF_USE_PAGE_ARRAY 兼容性验证

## 7. 适用 / 不适用场景
- **适用**：大块数据收取、代理/转发（收到即转发，免拷贝）、零拷贝 splice 类。
- **不适用/收益低**：小包、MSG_PEEK、OOB、TLS、需要立即处理数据内容（仍要访问即触发 cache miss）的场景。

## 8. 结论复述
**ZC-read 可行**：内核引擎（mp0）+ RX 零拷贝（ext-mbuf）+ 所有权（refcnt）三大基础**均已存在并实测确认**，外网官方资料全面佐证（04）。剩余为"用户态↔soreceive 的 mp 贯通通道 + release 契约"工程实现，推荐**方案A（复用 soreceive mp0）**，风险可控，估 8-15 人天。
