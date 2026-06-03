# Rib/rtentry IP Configuration Fix Plan（runtime-fix Phase 2）

> 目标：让 `ff_ifconfig` 显示 `f-stack-0` 的 `inet 192.168.1.1`，`ff_netstat -a` 继续显示 `tcp4/tcp6 *.80 LISTEN`。

> 文档目的：在已有 runtime-fix 5 commit（UMA / atomic / rtbridge / docs ×2）的基础上，攻克"最后一公里"IP 配置失败问题。

---

## 1. 用户原始需求（2026-06-01 20:41）

继续 runtime-fix。已修 3 个根本问题（UMA 死循环 + smr_create %gs + rt_ifmsg NULL deref），helloworld init success ✅，ff_netstat -a tcp4/tcp6 *.80 LISTEN ✅。**剩 1 项严格验收**：`ff_ifconfig` 显示 `inet 192.168.1.1`。

用户原话："验收标准为执行 ff_ifconfig 和 ff_netstat -a 可以获取到相关网卡和监听 80 端口信息，暂不需要实际 curl 测试"。

启动命令：`cd /data/workspace/f-stack; bash ./start.sh ./example/helloworld`。

## 2. 调研实测发现（Phase 0 静态调研已完成）

### 2.1 关键纠错（!!!）

之前 runtime-fix-execution-log.md §10.3 记录的"errno 55 EOPNOTSUPP"是**误判**：
- **FreeBSD errno 55 = ENOBUFS**（No buffer space available），见 `freebsd/sys/errno.h:118`
- FreeBSD EOPNOTSUPP = 45
- Linux EOPNOTSUPP = 95（值不同 — 之前在 helloworld 日志看到 55 直接 mapping 到 Linux 的 EOPNOTSUPP 是错误的）

### 2.2 真实根因调用链（4 方交叉验证）

```
ff_veth_setaddr → socreate(AF_INET) → ifioctl(SIOCAIFADDR)
  → in_control_ioctl → in_aifaddr_ioctl → ifa_maintain_loopback_route
    → rib_action(RTM_ADD) → rib_add_route → add_route_byinfo
      → rt_alloc(rnh, dst, netmask) → NULL → return ENOBUFS (55)
```

### 2.3 关键代码定位（实测取证）

| 项 | 位置 | 状态 |
|---|---|---|
| 真实 `rt_alloc` | `f-stack/freebsd/net/route/route_rtentry.c:82`（8375 字节 / 6 个 14.0+ rib 核心函数） | ✅ 文件已存在但未编译 |
| 真实签名 | `rt_alloc(rnh, dst, struct sockaddr *netmask)` | ✅ |
| `lib/Makefile` SRCS | 含 route_ctl.c / route_tables.c / route_helpers.c / route_ifaddrs.c / route_temporal.c / nhop_utils.c / nhop.c / nhop_ctl.c / rtsock.c / slcompress.c —— **不含 route_rtentry.c** | ❌ 漏 |
| `ff_stub_14_extra.c` 错误 stub | 6 个：rt_alloc / rt_free / rt_free_immediate / rt_get_family / rt_get_raw_nhop / rt_is_host —— 全返 NULL / 签名错（rt_alloc 第 3 参 `route_nhop_data *` vs 真实 `sockaddr *`） | ❌ 截胡链接 |

### 2.4 4 方交叉验证一致性表

| 数据源 | rt_alloc 签名 |
|---|---|
| 15.0 baseline `/data/workspace/freebsd-src-releng-15.0/sys/net/route/route_rtentry.c:82` | `(rnh, dst, struct sockaddr *netmask)` ✅ |
| fstack `f-stack/freebsd/net/route/route_rtentry.c:82` | `(rnh, dst, struct sockaddr *netmask)` ✅ |
| 调用方 `f-stack/freebsd/net/route/route_ctl.c:762` | `rt_alloc(rnh, dst, netmask)` ✅ |
| fstack stub `f-stack/lib/ff_stub_14_extra.c:534` | `(rnh, dst, struct route_nhop_data *rnd)` ❌ |

**结论**：lib stub 签名错误 + 总返 NULL → 永远走 `add_route_byinfo` 的 `return (ENOBUFS)` 兜底 → ff_veth_setaddr 失败 → ifa_maintain_loopback_route 失败 → IP 配不上。

## 3. 决策点（DP-RT-FIX-1~3）

| DP | 选项 | 推荐 |
|---|---|---|
| **DP-RT-FIX-1** 修复策略 | **A: 把 route_rtentry.c 加到 lib/Makefile SRCS + 删 ff_stub_14_extra.c 中 6 个错 stub**（根本修复） / B: 仅修 stub 签名 + 返伪 rtentry（不可行：rt_alloc 内部 uma_zalloc + RTF_HOST 逻辑需真实运行） | **A** |
| **DP-RT-FIX-2** 验证范围 | A: 严格 - ff_ifconfig 显示 inet + ff_netstat -a 显示 :80 LISTEN（与用户原话 100% 对齐） / **B: 严格 A + helloworld init success 不退化** / C: 严格 B + 6 工具 EAL stage 不退化 | **B** |
| **DP-RT-FIX-3** commit 节奏 | **A: 一根因一 commit**（同 runtime-fix #1-3 风格） / B: 单 commit 合并 | **A** |

未答按 **A/B/A** 默认。

## 4. 6 阶段流水线

| Phase | 任务 | 关键产物 |
|---|---|---|
| Phase 0 | Kickoff：cp -a rib-fix-start 备份 + 更新 execution log §6 嫌疑点 8/9 | rib-fix-start 33,122 文件 |
| Phase 1 | 静态调研（已完成 - 上面 §2 调研） | 见上 |
| Phase 2 | 修复实施：lib/Makefile +1 SRCS（route_rtentry.c）+ ff_stub_14_extra.c 删 6 个错 stub | 2 文件修改 |
| Phase 3 | 强制重编（make clean → make）+ example 重 link | libfstack.a 5.2M+ / 251 .o（+1） / helloworld 27M+ |
| Phase 4 | 重启 helloworld + 实测 ff_ifconfig / ff_netstat 严格 2 项验收 | runtime 输出验证 |
| Phase 5 | 项目结案：cp -a rib-fix-done + 更新 99 §12.20 + runtime-fix-execution-log §11 + 2 commits | git log + 备份 |

## 5. 强制规约（继承全部 3 项 + commit message 英文）

| 规约 | AI memory ID | 内容 |
|---|---|---|
| rm_tmp_file.sh | 81725399 | 所有删除走 `/data/workspace/rm_tmp_file.sh` |
| kill_process.sh | 90098233 | 所有进程终止走 `/data/workspace/kill_process.sh` |
| chmod_modify.sh | 21626578 | 所有权限修改走 `/data/workspace/chmod_modify.sh` |
| commit message 英文 | 73362122 | 所有 git commit message 英文 |
| 实测优先 | - | 4 方交叉验证；不一致以代码为准 |
| 强制重编 | - | 修头文件后必 `make clean`（M3 末 .o 缓存教训） |

## 6. 风险评估

| 风险 | 缓解 |
|---|---|
| route_rtentry.c 编译可能引入额外 link 错误 | 真实文件已存在 15.0 vendor；只 8375 字节；相邻 route_*.c 都已编译 OK → 风险低 |
| 删 6 个 stub 后是否触发其他 undef 引用 | rt_alloc 真实在 route_rtentry.o 提供；其他 5 个也是；删 stub 后由真实 .o 解析 → 无 undef |
| 是否影响其他 5 个 commit 已修问题 | 修改范围仅 2 文件（Makefile + ff_stub_14_extra.c），不动 amd64/atomic.h、amd64/vmparam.h、arm64/vmparam.h |
| 验收时 helloworld 是否需要 restart | 是 — 旧 helloworld 113746 跑了 18+ 分钟，新 binary link 后必须新进程才能生效 |

## 7. 待用户确认

请回复 **"接受计划并立即开始"** 或 **"调整 DP-RT-FIX-X"**。如直接说 **"继续执行"**，按 A/B/A 默认开干。
