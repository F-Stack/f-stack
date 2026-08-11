# 08 - is_tcp_syn() IPv6 扩展头分析

> f-stack issue #1076: `is_tcp_syn()` 函数中 IPv6 头跳过判断的准确性分析
> 分析时间：2026-08-11
> 前置文档：00-07 号文档
> 关联提交：`7112dc2bcf`（feat: add mbuf water-level backpressure for issue #1076）

---

## 1. 问题描述

commit `7112dc2bcf` 新增的 `is_tcp_syn()` 函数（`lib/ff_dpdk_if.c:2023-2070`）中，IPv6 分支的处理为：

```c
} else if (ether_type == RTE_ETHER_TYPE_IPV6) {
    if (len < sizeof(struct rte_ipv6_hdr) + sizeof(struct rte_tcp_hdr))
        return 0;
    const struct rte_ipv6_hdr *iph = (const struct rte_ipv6_hdr *)data;
    if (iph->proto != IPPROTO_TCP)
        return 0;
    tcph = (const struct rte_tcp_hdr *)
        ((const char *)data + sizeof(struct rte_ipv6_hdr));
}
```

文档 `07` 注释"IPv6 不处理扩展头（简化设计，SYN 包通常无扩展头）"。本分析验证此判断是否准确。

---

## 2. IPv6 扩展头机制

### 2.1 IPv6 报头结构

IPv6 固定报头 40 字节，其中 `next_header` 字段（对应 DPDK `rte_ipv6_hdr.proto`）指定紧跟的协议类型。若无扩展头，`next_header == IPPROTO_TCP(6)`，TCP 报头紧跟在 40 字节固定头之后。

若有扩展头，`next_header` 指向第一个扩展头类型，扩展头内部再通过各自的 `next_header` 字段链式指向下一个，直到最终上层协议（TCP）。

### 2.2 扩展头类型（RFC 8200）

| 协议号 | 类型 | 出现在 SYN 的可能性 |
|--------|------|---------------------|
| 0 | Hop-by-Hop Options | 低（TFO Cookie 在 TCP 选项中，不在 IPv6 Hop-by-Hop；Jumbograms 极罕见） |
| 43 | Routing Header | 低（Mobile IPv6 / SRV6，普通客户端不用） |
| 44 | Fragment Header | 极低（SYN 包通常 60-80 字节，远小于 MTU 1280） |
| 51 | Authentication Header (AH) | 低（IPsec VPN 场景，SYN 可携带 AH） |
| 50 | Encapsulating Security Payload (ESP) | 低（ESP 加密后无法解析 TCP 头） |
| 60 | Destination Options | 极低（很少用于 SYN） |
| 135 | Mobility Header | 极低（Mobile IPv6 场景） |

### 2.3 外网资料交叉验证

- RFC 8200 §4.1：Hop-by-Hop Options 若存在必须是第一个扩展头
- Linux 内核 `net/ipv6/ip6_input.c` 的 `ip6_input_finish()` 调用 `ipv6_skip_exthdr()` 遍历扩展头链
- DPDK `rte_net_get_ptype()` 内部也有 `ipv6_skip_exthdr` 等价逻辑

结论：IPv6 扩展头是标准协议机制，Linux 内核和 DPDK 均在正常收包路径中处理。但带扩展头的 TCP SYN 包在生产流量中**罕见**。

---

## 3. f-stack 已有扩展头遍历函数

`lib/ff_dpdk_kni.c:281-315` 已有 `get_ipv6_hdr_len()` 函数，正确处理扩展头链：

```c
static int
get_ipv6_hdr_len(uint8_t *proto, void *data, uint16_t len)
{
    int ext_hdr_len = 0;

    switch (*proto) {
        case IPPROTO_HOPOPTS:   case IPPROTO_ROUTING:   case IPPROTO_DSTOPTS:
        case IPPROTO_MH:        case IPPROTO_HIP:       case IPPROTO_SHIM6:
            ext_hdr_len = *((uint8_t *)data + 1) + 1;  // 8 字节为单位
            break;
        case IPPROTO_FRAGMENT:
            ext_hdr_len = 8;                            // 固定 8 字节
            break;
        case IPPROTO_AH:
            ext_hdr_len = (*((uint8_t *)data + 1) + 2) * 4;  // 4 字节为单位
            break;
        case IPPROTO_NONE:
        default:
            return ext_hdr_len;                          // 非扩展头，终止
    }

    if (ext_hdr_len >= len) return len;

    *proto = *((uint8_t *)data);                         // 读 next_header
    ext_hdr_len += get_ipv6_hdr_len(proto, data + ext_hdr_len, len - ext_hdr_len);

    return ext_hdr_len;
}
```

该函数被 `protocol_filter_ip()`（`:356-358`）正确使用：

```c
hdr_len = sizeof(struct rte_ipv6_hdr);
proto = ((struct rte_ipv6_hdr *)data)->proto;
hdr_len += get_ipv6_hdr_len(&proto, (void *)data + hdr_len, len - hdr_len);
```

`is_tcp_syn()` **未使用** `get_ipv6_hdr_len()`，而是直接检查 `iph->proto != IPPROTO_TCP`。

---

## 4. 当前代码的行为分析

### 4.1 无扩展头（常见情况，>99%）

- `iph->proto == IPPROTO_TCP` → 检查通过
- `tcph = data + 40` → 偏移正确
- TCP flags 检查正确

**结论：正确**。

### 4.2 有扩展头（罕见情况，<1%）

- `iph->proto` 是扩展头类型（如 0/43/44/51/60），不等于 `IPPROTO_TCP(6)`
- 函数返回 0（不是 SYN）
- SYN 包**未被丢弃**，继续进入协议栈

**结论：假阴性（false negative）**。SYN 包未被检测到，背压机制未触发。

### 4.3 失败模式安全分析

| 失败类型 | 后果 | 是否安全 |
|---------|------|---------|
| 假阴性（SYN 未被检测） | SYN 进入协议栈，不触发背压 | **安全** — 与不启用背压时行为相同 |
| 假阳性（非 SYN 被误判为 SYN） | 非 SYN 包被丢弃 | **不安全** — 影响已有连接 |

当前实现只会产生假阴性，不会产生假阳性。对于背压机制，假阴性是**可接受的失败模式**。

---

## 5. 潜在改进

### 5.1 复用 get_ipv6_hdr_len()

将 `get_ipv6_hdr_len()` 从 `ff_dpdk_kni.c` 移到共享头文件（如 `ff_dpdk_if.h` 或新建 `ff_proto_parse.h`），`is_tcp_syn()` 调用它遍历扩展头链。

改进后的 IPv6 分支：

```c
} else if (ether_type == RTE_ETHER_TYPE_IPV6) {
    if (len < sizeof(struct rte_ipv6_hdr))
        return 0;
    const struct rte_ipv6_hdr *iph = (const struct rte_ipv6_hdr *)data;
    uint8_t proto = iph->proto;
    uint16_t hdr_len = sizeof(struct rte_ipv6_hdr);
    hdr_len += get_ipv6_hdr_len(&proto, (char *)data + hdr_len, len - hdr_len);
    if (proto != IPPROTO_TCP)
        return 0;
    if (len < hdr_len + sizeof(struct rte_tcp_hdr))
        return 0;
    tcph = (const struct rte_tcp_hdr *)((const char *)data + hdr_len);
}
```

### 5.2 改进代价

- 需要将 `get_ipv6_hdr_len()` 从 static 改为非 static（或移到共享头）
- 增加少量代码行（约 5 行）
- `get_ipv6_hdr_len()` 是递归调用，但扩展头链通常 0-2 层，开销可忽略

### 5.3 是否必要

考虑到：
1. 带扩展头的 IPv6 TCP SYN 包在生产流量中罕见
2. 假阴性是安全失败模式
3. 当前实现对常见情况正确
4. 背压机制是 best-effort 保护，非严格 enforcement

**改进非必要，但推荐**。若未来需要更精确的 SYN 检测（例如用于 ACL 或限速场景），则应改进。

---

## 6. 其他边界问题

### 6.1 QinQ（双层 VLAN）

当前只处理单层 VLAN。QinQ 包的第二个 VLAN tag 会被当作 ethertype，不匹配 IPv4/IPv6，返回 0。假阴性，安全。

### 6.2 IPv4 IPv6 不等长检查

IPv4 分支检查 `len < ihl + sizeof(struct rte_tcp_hdr)`，其中 `ihl` 是可变的。IPv6 分支检查 `len < sizeof(struct rte_ipv6_hdr) + sizeof(struct rte_tcp_hdr)`，这是固定 40+20=60。两者均正确。

### 6.3 TCP 最小头部长度

`sizeof(struct rte_tcp_hdr)` 在 DPDK 中是 20 字节（最小 TCP 头）。SYN 包通常 TCP 头 20-60 字节（含选项）。检查 `>= 20` 是正确的最小检查。

---

## 7. 结论

| 问题 | 结论 |
|------|------|
| IPv6 无扩展头时判断准确吗？ | **准确** |
| IPv6 有扩展头时判断准确吗？ | **不准确**（假阴性，SYN 未被检测） |
| 假阴性安全吗？ | **安全** — 与不启用背压时行为相同 |
| 需要立即修复吗？ | **否** — 背压是 best-effort 机制，假阴性可接受 |
| 建议改进吗？ | **推荐改进** — 复用已有的 `get_ipv6_hdr_len()` |

文档 `07` 注释"IPv6 不处理扩展头（简化设计，SYN 包通常无扩展头）"的判断**方向正确**（SYN 包通常无扩展头），但"通常"不等于"总是"。对于 best-effort 背压机制，当前实现可接受；若用于更严格的场景（ACL/限速），应复用 `get_ipv6_hdr_len()` 改进。
