# Phase-2 M10 Spec — FF_FLOW_IPIP (P1d)

> 状态：DRAFT → ready
> 上游基础：M9 commit `2f4748638`
> 复杂度：M（涉及双端隧道配置 + 路由）

---

## 1. 目标 / 范围

### in-scope

- `lib/Makefile` 启用 `FF_FLOW_IPIP=1`（单独，不与其他 P1 同启）
- 复用 lib/ff_dpdk_if.c 现有 4 处 ifdef 与已编入的 in_gif.c / if_gif.c / ng_gif.c
- G1-G3：编译 + 起栈 + 通过 `tools/sbin/ifconfig gif0 create` 在服务端创建 GIF 隧道、客户端用 `ip tunnel` 配置对端隧道、配置路由后做基础 ping 验证
- 文档同步

### out-of-scope

- ZC / PA combo（M10 单独 build；为避免变量交叉，暂 disable M7/M8）
- IPv6 over IPv4 / IPv4 over IPv6 复杂矩阵
- iperf 大流量性能（OQ-2 默认许可降级）

---

## 2. Acceptance Criteria

| ID | 验收 |
|---|---|
| AC-M10-1 | `lib/Makefile`：`FF_FLOW_IPIP=1` + 暂时回退 PA/ZC 到注释（独立验证） |
| AC-M10-2 | `lib/ make`：exit=0 / 0 errors / warnings ≤ 60 |
| AC-M10-3 | helloworld primary 起栈 ≥ 12s ALIVE，无 panic |
| AC-M10-4 | `tools/sbin/ifconfig gif0 create` 成功（exit=0） |
| AC-M10-5 | `ifconfig gif0 inet ...` 配置 GIF 隧道 + 路由后，从 client 端 `ping` server 端 GIF 内 IP 至少 1 个 ICMP echo reply ✓（OQ-4 降级许可：若客户端 GIF 反向不通可作 G3.5 observation） |
| AC-M10-6 | 文档 anchor + execution log |

---

## 3. 风险

| ID | 风险 | 缓解 |
|---|---|---|
| R-M10-1 | f-stack-client（Linux）gif 隧道用 `ip tunnel mode ipip` vs FreeBSD GIF 兼容性 | RFC 2003 IPIP 标准协议，应可互通；如不通降级为 observation |
| R-M10-2 | tools/sbin/ifconfig 缺少 GIF clone 支持 | 实测 `ifconfig gif0 create` 看是否报错；如缺 fallback 至 ngctl mkpeer |

---

## 4. 验收命令

```sh
# G1
cd /data/workspace/f-stack/lib && make clean && make
cd /data/workspace/f-stack/example && /data/workspace/rm_tmp_file.sh ./helloworld* && make

# G2
/data/workspace/rm_tmp_file.sh /var/run/dpdk/rte/{config,fbarray_*,hugepage_info}
sudo ./helloworld -c ../config.ini --proc-type=primary --proc-id=0 &
sleep 12 && [ -d /proc/$PID ] && echo ALIVE

# G3 server side
sudo /data/workspace/f-stack/tools/sbin/ifconfig gif0 create
sudo /data/workspace/f-stack/tools/sbin/ifconfig gif0 tunnel <server_outer> <client_outer>
sudo /data/workspace/f-stack/tools/sbin/ifconfig gif0 inet <server_inner>/30 <client_inner>

# G3 client side (via ssh)
ssh f-stack-client "sudo ip tunnel add gif0 mode ipip remote <server_outer> local <client_outer>"
ssh f-stack-client "sudo ip addr add <client_inner>/30 dev gif0"
ssh f-stack-client "sudo ip link set gif0 up"
ssh f-stack-client "ping -c 3 -W 2 <server_inner>"

/data/workspace/kill_process.sh $PID
```

---

> 下一步：Phase C — 启用 Makefile + 编译 + 实测。
