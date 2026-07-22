# 11 IPv6 反向代理 VIP on-link 误判修复

> 角色：spec-writer（编码完成后的文档同步）。本报告记录「f-stack 版 nginx 做 IPv6 反向代理时，主动 connect 上游后端连不通（504）」问题的**根因定位与修复落地**。
> 所有行号经读码核实（以代码为准）；运行时诊断以 leader/多 agent 交叉验证的 pcap 铁证为准；真机端到端验证情况见 §7。
> 涉及文件：`lib/ff_veth.c`（唯一改动文件）。参考代码：`freebsd/netinet6/in6.c`（未改）。

---

## 1. 问题现象

f-stack 版 nginx（`nginx_fstack`）配置为 IPv6 反向代理：

- 反代服务端 `listen [::]:80`：客户端能正常访问反代、能收到完整请求；
- 但反代主动 `connect` 上游后端时，**后端抓不到任何 v6 反代请求**，nginx 报 `504 Gateway Timeout`。

复现环境：CVM（virtio 网卡）与 mlx5 100G 物理机（无安全组）**均可复现**，与网卡型号无关。

---

## 2. 运行时诊断（pcap 铁证）

抓包文件：`/data/workspace/ipv6_proxy.pcap`（mlx5 物理机现场）。

| 角色 | 地址 |
|------|------|
| 反代服务端 VIP | `2402:4e00:1840::17` |
| 上游后端 | `2402:4e00:1840::18` |
| 客户端 | `2402:4e00:1701:c000::1` |

`f-stack.conf` 关键配置：

| 项 | 值 | 网段 |
|----|----|------|
| `addr6`（主地址） | `2402:4e00:2e80:1030::b` | 主网段 `2e80:1030` |
| `prefix_len` | `64` | — |
| `gateway6` | `2402:4e00:2e80:1030::1` | 主网段 `2e80:1030` |
| `vip_addr6` | `2402:4e00:1840::17` | VIP 网段 `1840`（与主地址**不同网段**） |
| `vip_prefix_len` | `64` | — |

pcap 关键观测：

1. **入向完整正常**：客户端连 VIP `1840::17`，SYN / SYN-ACK / GET / `504` 一应俱全，说明监听与入向收发无问题。
2. **出向异常**：f-stack 对后端 `1840::18` 只发了 **1 个直连 NS**（`who has 1840::18`，solicited-node 组播），**无任何 NA 响应**；此后**零 TCP SYN** 发往后端 → connect 超时 → `504`。
3. **对照**：同一 pcap 中，NS 询问网关 `2e80:1030::1` 能得到 NA（正常）。

**结论**：f-stack 把「去往后端 `1840::18`」误判为**直连（on-link）**，于是对目的地址本身发直连 NS 做地址解析；而后端实际在网关后面、不在本地 L2 → 收不到 NA → 邻居表项停在 `INCOMPLETE` → SYN 排队发不出。

---

## 3. 根因分析

### 3.1 调用链

1. `lib/ff_veth.c` → `ff_veth_setvaddr6()` 给 VIP 添加地址时，`ifra_prefixmask` 使用了 `sc->prefix_length`（**主前缀 = 64**）；
2. → `freebsd/netinet6/in6.c` → `in6_addifaddr()` 处理 `SIOCAIFADDR_IN6`；
3. → 由于前缀长度非 128，走入前缀路由安装分支，`ndpr_raf_onlink = 1`，为 VIP 网段安装 `1840::/64` **on-link 前缀路由**；
4. → 此后去往同网段的后端 `1840::18`，最长前缀匹配命中 `1840::/64` on-link 前缀 → 被判为直连 → 发直连 NS → 无 NA → 连不通。

### 3.2 in6.c 关键行号（未改，仅引用核实）

`freebsd/netinet6/in6.c` `in6_addifaddr()`（L1230 起）：

| 落点 | 行号 | 说明 |
|------|------|------|
| `pr0.ndpr_plen = in6_mask2len(&ifra->ifra_prefixmask...)` | L1298-1299 | 由传入的 prefixmask 换算前缀长度 |
| `if (pr0.ndpr_plen == 128) { goto aifaddr_out; }` | **L1300-1303** | **仅当 /128 时跳过前缀路由安装**（"we don't need to install a host route"） |
| `pr0.ndpr_raf_onlink = 1;` | **L1316** | 非 /128 分支：把该前缀标记为 on-link |
| `pfxlist_onlink_check();` | L1361 | 前缀 on-link 生效 |
| `aifaddr_out:` | L1363 | /128 直接跳到此，**不安装 on-link 前缀路由** |

即：只有 `/128` 才会跳过 on-link 前缀路由安装；`/64` 的 VIP 必然装上 `1840::/64` on-link 前缀路由。

### 3.3 修复前的代码（错误）

修复前 `ff_veth_setvaddr6()` 用主前缀 `sc->prefix_length` 构造 prefixmask（与 13.0-baseline 同款逻辑）：

```
ifr6.ifra_prefixmask.sin6_len = sizeof ifr6.ifra_prefixmask;
memset(&ifr6.ifra_prefixmask.sin6_addr, 0xff, sc->prefix_length / 8);
uint8_t mask_size_mod = sc->prefix_length % 8;
if (mask_size_mod) {
    ifr6.ifra_prefixmask.sin6_addr.__u6_addr.__u6_addr8[sc->prefix_length / 8] =
        ((1 << mask_size_mod) - 1) << (8 - mask_size_mod);
}
```

两处缺陷：

1. **主缺陷**：VIP 以 `/64` 加入 → 装 `1840::/64` on-link 前缀路由 → 同网段后端被误判直连；
2. **次缺陷**：即便要用配置前缀，这里也误用了主地址前缀 `sc->prefix_length`，而非结构体中本就为 VIP 预留的 `sc->vip_prefix_length`（见 `ff_veth.c` L88 字段定义、L145/L201 赋值）。

---

## 4. 修复方案

将 VIP 固定以 **/128 host 地址**方式添加：prefixmask 固定全 1（`memset 0xff, 16`），删除 `mask_size_mod` 取模分支。

`lib/ff_veth.c` `ff_veth_setvaddr6()`（L860-898）修复后：

```
/* VIP as /128 host addr: avoid installing an on-link prefix route,
 * so traffic to other addrs in the VIP subnet goes via the gateway. */
ifr6.ifra_prefixmask.sin6_len = sizeof ifr6.ifra_prefixmask;
memset(&ifr6.ifra_prefixmask.sin6_addr, 0xff, 16);   /* L879-880 */
```

效果：

- VIP 以 `/128` 加入 → 命中 `in6.c` L1300-1303 `/128` 特判 → **不安装 on-link 前缀路由**；
- 去往 VIP 同网段的其它地址（含后端 `1840::18`）在 Prefix List 上**无匹配 on-link 前缀** → 走**默认网关** → 对网关做邻居发现（网关在本地 L2、能应答 NA）→ SYN 正常送出。

此做法与 FreeBSD 原生 `ifconfig <if> inet6 <addr> prefixlen 128 alias` 惯例一致：给接口挂一个 host 地址而不引入该网段的 on-link 语义。

---

## 5. diff 摘要（`lib/ff_veth.c` `ff_veth_setvaddr6`）

```diff
-    ifr6.ifra_prefixmask.sin6_len = sizeof ifr6.ifra_prefixmask;
-    memset(&ifr6.ifra_prefixmask.sin6_addr, 0xff, sc->prefix_length / 8);
-    uint8_t mask_size_mod = sc->prefix_length % 8;
-    if (mask_size_mod)
-    {
-        ifr6.ifra_prefixmask.sin6_addr.__u6_addr.__u6_addr8[sc->prefix_length / 8] = \
-            ((1 << mask_size_mod) - 1) << (8 - mask_size_mod);
-    }
+    /* VIP as /128 host addr: avoid installing an on-link prefix route,
+     * so traffic to other addrs in the VIP subnet goes via the gateway. */
+    ifr6.ifra_prefixmask.sin6_len = sizeof ifr6.ifra_prefixmask;
+    memset(&ifr6.ifra_prefixmask.sin6_addr, 0xff, 16);
```

改动范围：仅 `ff_veth_setvaddr6()` 内 prefixmask 构造段；未触碰主地址 `ff_veth_setaddr6()`（其行为不变，主地址仍按配置前缀加，属预期）。

---

## 6. 13.0 对照（非 13→15 回归）

`f-stack-13.0-baseline/lib/ff_veth.c` 的 `ff_veth_setvaddr6()`（对应 L789-796 附近）同样使用 `sc->prefix_length` + `mask_size_mod` 构造 VIP 的 prefixmask，**与 15.0 修复前完全一致**。

因此该问题**不是 13.0→15.0 升级引入的回归**，而是 f-stack **长期存在的设计缺陷**：仅在「VIP 与主地址不同网段」这一特定拓扑下才会暴露（同网段时后端本就 on-link，误判恰好不产生错误后果，故长期未被发现）。

---

## 7. 入向不受影响分析

有人可能担心 VIP 改 `/128` 后入向（客户端 → VIP）受影响。分析确认**不受影响**：

- 入向依赖的是 VIP 地址本身在本机可达（loopback host route），该 host route 由 `in6.c` 的 `in6_notify_ifa()` 在地址生效时**无条件**为该地址安装 `/128` loopback 路由，**不依赖 prefixlen**；
- `/128` 与 `/64` 两种加法都会生成该 loopback host route，故 VIP 仍正常接收发往自己的报文；
- pcap 中入向 SYN/SYN-ACK/GET/504 全程正常，运行时亦印证入向不受影响。

唯一改变的是「VIP 网段是否 on-link」这一出向语义，正是本次要修的点。

---

## 8. 验证情况

| 环节 | 结果 |
|------|------|
| 编译 `libfstack.a` | OK |
| `make install` | OK |
| nginx 重链 | OK（二进制 md5 变化，确认含本修复） |
| 代码正确性 | 独立 gatekeeper 门禁 + fix-verifier 交叉核实 + leader 独立读 `in6.c` 坐实（6 条核查全过） |
| 本机 CVM 真机端到端 | **受阻**：(1) CVM 有安全组丢主动外连（需用户自查）；(2) 重启过程中 virtio 网卡退回内核驱动，本环境无法干净复现 VIP6 场景 |
| mlx5 物理机真机端到端 | **待用户执行**（无安全组、可干净复现） |

真机验证建议步骤（mlx5 物理机）：

1. 部署含修复的 `nginx_fstack`，配置同 §2；
2. 客户端访问反代 VIP，观察 nginx 是否正常回上游响应（不再 504）；
3. 抓包确认：出向对后端 `1840::18` **不再发直连 NS**，而是对**网关** `2e80:1030::1` 做邻居发现并将 SYN 送出；
4. `netstat -rn -f inet6` 确认**不再存在** `1840::/64` 的 on-link 前缀路由（仅 VIP `/128` host 路由 + 默认路由）。

---

## 9. 外网印证

真实可查来源，逐条印证「/128 host 地址不建 on-link 前缀路由、IPv6 用 on-link 前缀列表而非纯前缀比较判定下一跳、无匹配 on-link 前缀时走默认网关」：

| # | 来源 | URL | 结论与本修复的关系 |
|---|------|-----|------|
| 1 | FreeBSD `ifconfig(8)` man page | https://man.freebsd.org/cgi/man.cgi?query=ifconfig | inet6 支持 `::1/128` 斜杠记法/`prefixlen` 指定前缀长度；`/128` 是原生用来给接口挂单个 host 地址的标准写法，印证本修复用 `/128 alias` 属官方惯例。 |
| 2 | Packet Pushers《On Link in IPv6》（据 RFC 5942） | https://packetpushers.net/blog/on-link-in-ipv6/ | IPv6 不靠「前缀+前缀长度相同就算同链路」判定，而是维护 on-link 前缀列表；**一个 /128 地址/主机路由本身不会自动创建 on-link 前缀**，无匹配 on-link 前缀时流量发往默认网关。直接支持「VIP 改 /128 后同网段后端走网关」。 |
| 3 | RFC 4861 §5.2 / §2.1（IPv6 邻居发现） | https://www.rfc-editor.org/rfc/rfc4861 | 发送方对 Prefix List 做**最长前缀匹配**判定 on/off-link：命中前缀→下一跳=目的地址本身（对目的发 NS 解析）；未命中→下一跳=默认路由器（对网关发 NS）。印证修复前因 `1840::/64` on-link 前缀命中而误对后端发直连 NS 的机理。 |

---

## 10. 结论

- **根因**：`ff_veth_setvaddr6()` 用主前缀 `/64` 加 VIP，导致 `in6_addifaddr()` 安装 `1840::/64` on-link 前缀路由，使跨网段后端被误判直连、发直连 NS 无 NA、SYN 发不出。
- **修复**：VIP 固定 `/128` host 加入，避免 on-link 前缀路由，跨网段流量走默认网关，与 FreeBSD 原生 `prefixlen 128 alias` 惯例一致。
- **影响面**：仅出向 VIP 网段的 on-link 语义；入向依赖 loopback `/128` host route 不受影响。
- **性质**：13.0/15.0 同款长期设计缺陷，非升级回归。
- **状态**：代码修复已落地、编译/门禁/交叉核实通过；mlx5 物理机真机端到端验证待用户执行。
