# F-Stack LD_PRELOAD 无锁环形队列改造 — 测试规格文档

> **文档编号**: SPEC-004  
> **版本**: v1.0 Draft  
> **日期**: 2026-03-27  
> **状态**: 待审核  
> **前置文档**: SPEC-001 需求规格文档, SPEC-002 架构设计文档, SPEC-003 接口规格文档

---

## 1. 概述

本文档定义从信号量同步机制迁移至 DPDK `rte_ring` 无锁环形队列方案的完整测试策略，涵盖：

- 功能测试：验证 ring 模式下所有 socket 操作的正确性
- 性能基准测试：量化 ring 模式相比 sem 模式的性能改进
- 回归测试：确保 5 个 helloworld 示例程序全部通过
- 压力测试：高并发、长时间运行稳定性验证
- Nginx 集成验证：真实应用场景验证

---

## 2. 测试环境要求

### 2.1 硬件要求

| 项目 | 最低配置 | 推荐配置 |
|------|---------|---------|
| CPU | 4 核 x86_64 | 8 核+ x86_64（支持 SSE4.2） |
| 内存 | 4GB + 2GB Hugepage | 16GB + 4GB Hugepage |
| NIC | 支持 DPDK 的网卡（Intel 82599/X520/X710） | 双端口 10GbE |
| 客户端 | 独立物理机/VM | 独立物理机 + wrk/ab 工具 |

### 2.2 软件要求

| 项目 | 版本 |
|------|------|
| OS | Linux 4.15+ (Ubuntu 18.04/20.04/22.04, CentOS 7/8) |
| GCC | 7.0+ |
| DPDK | 与 F-Stack 匹配版本（通过 pkg-config 检测） |
| F-Stack | 当前开发分支 |
| wrk | 4.1.0+ |
| ab (Apache Bench) | 2.3+ |
| perf | Linux perf tools |
| Nginx | 1.25+ (with F-Stack 适配补丁) |

### 2.3 编译配置矩阵

所有测试必须在以下编译配置组合下执行：

| 配置编号 | `FF_USE_RING_IPC` | `FF_PRELOAD_POLLING_MODE` | `FF_THREAD_SOCKET` | `FF_KERNEL_EVENT` | `FF_MULTI_SC` |
|---------|-------------------|--------------------------|--------------------|--------------------|---------------|
| C1 | ✅ | ❌ | ❌ | ❌ | ❌ |
| C2 | ✅ | ❌ | ❌ | ❌ | ✅ |
| C3 | ✅ | ❌ | ✅ | ❌ | ❌ |
| C4 | ✅ | ❌ | ❌ | ✅ | ❌ |
| C5 (对照) | ❌ | ❌ | ❌ | ❌ | ❌ |
| C6 (对照) | ❌ | ✅ | ❌ | ❌ | ❌ |
| C7 (互斥) | ✅ | ✅ | — | — | — |

**C7** 配置预期编译失败（互斥检查生效）。

---

## 3. 功能测试

### 3.1 基础 Socket 操作测试

| 测试编号 | 测试名称 | 操作序列 | 预期结果 | 优先级 |
|---------|---------|---------|---------|--------|
| FT-001 | socket 创建 | `socket(AF_INET, SOCK_STREAM, 0)` | 返回 fd > 0 | P0 |
| FT-002 | socket 创建 (UDP) | `socket(AF_INET, SOCK_DGRAM, 0)` | 返回 fd > 0 | P0 |
| FT-003 | bind | `bind(fd, addr, len)` | 返回 0 | P0 |
| FT-004 | listen | `listen(fd, backlog)` | 返回 0 | P0 |
| FT-005 | connect | `connect(fd, addr, len)` | 返回 0 | P0 |
| FT-006 | accept | `accept(listen_fd, ...)` | 返回 client_fd > 0 | P0 |
| FT-007 | accept4 | `accept4(listen_fd, ..., SOCK_NONBLOCK)` | 返回 client_fd > 0 | P1 |
| FT-008 | read/write | `write(fd, buf, len)` + `read(fd, buf, len)` | 数据一致 | P0 |
| FT-009 | send/recv | `send(fd, buf, len, 0)` + `recv(fd, buf, len, 0)` | 数据一致 | P0 |
| FT-010 | sendto/recvfrom | UDP sendto + recvfrom | 数据一致 | P1 |
| FT-011 | sendmsg/recvmsg | `sendmsg` + `recvmsg` (scatter-gather) | 数据一致 | P1 |
| FT-012 | writev/readv | `writev` + `readv` (多 iov) | 数据一致 | P1 |
| FT-013 | close | `close(fd)` | 返回 0 | P0 |
| FT-014 | shutdown | `shutdown(fd, SHUT_WR)` | 返回 0 | P1 |
| FT-015 | getsockopt/setsockopt | SO_REUSEADDR, SO_REUSEPORT | 设置/获取一致 | P1 |
| FT-016 | getsockname/getpeername | 绑定后获取 | 地址信息正确 | P1 |
| FT-017 | ioctl (FIONBIO) | 设置非阻塞 | 返回 0 | P1 |
| FT-018 | fcntl (F_GETFL/F_SETFL) | 获取/设置标志 | 返回正确标志 | P1 |

### 3.2 Epoll 操作测试

| 测试编号 | 测试名称 | 测试场景 | 预期结果 | 优先级 |
|---------|---------|---------|---------|--------|
| FT-020 | epoll_create | `epoll_create(size)` | 返回 epfd > 0 | P0 |
| FT-021 | epoll_ctl ADD | `EPOLL_CTL_ADD(epfd, fd, EPOLLIN)` | 返回 0 | P0 |
| FT-022 | epoll_ctl MOD | `EPOLL_CTL_MOD(epfd, fd, EPOLLOUT)` | 返回 0 | P1 |
| FT-023 | epoll_ctl DEL | `EPOLL_CTL_DEL(epfd, fd)` | 返回 0 | P1 |
| FT-024 | epoll_wait timeout=0 | 无就绪事件，timeout=0 | 立即返回 0 | P0 |
| FT-025 | epoll_wait timeout>0 | 无就绪事件，timeout=1000 | ~1s 后返回 0 | P0 |
| FT-026 | epoll_wait timeout=-1 | 有就绪事件，timeout=-1 | 事件到达时返回 | P0 |
| FT-027 | epoll_wait 事件触发 | 对端发送数据 | 返回 EPOLLIN 事件 | P0 |
| FT-028 | epoll_wait 多事件 | 多个 fd 同时就绪 | 返回所有就绪事件 | P1 |
| FT-029 | epoll_wait 超时精度 | timeout=10ms | 实际返回时间 10±5ms | P1 |

### 3.3 Kevent 操作测试

| 测试编号 | 测试名称 | 测试场景 | 预期结果 | 优先级 |
|---------|---------|---------|---------|--------|
| FT-030 | kqueue 创建 | `kqueue()` | 返回 kq > 0 | P0 |
| FT-031 | kevent 注册 | `EV_SET + kevent(kq, &kev, 1, NULL, 0, NULL)` | 返回 0 | P0 |
| FT-032 | kevent timeout=NULL | 有事件到达 | 事件到达时返回 | P0 |
| FT-033 | kevent timeout 指定 | `timeout={0, 100000}` | ~100us 后返回 | P0 |
| FT-034 | kevent EVFILT_READ | 对端发送数据 | 返回读事件 | P0 |
| FT-035 | kevent EV_EOF | 对端关闭连接 | 返回 EV_EOF 标志 | P1 |

### 3.4 特殊场景测试

| 测试编号 | 测试名称 | 测试场景 | 预期结果 | 优先级 |
|---------|---------|---------|---------|--------|
| FT-040 | alarm_event_sem 替代 | 信号处理中调用 alarm_event_sem | APP 正常唤醒并退出 | P0 |
| FT-041 | fork 场景 | `FF_USE_THREAD_STRUCT_HANDLE` + fork | 父子进程独立运行 | P1 |
| FT-042 | 多线程 attach | `FF_THREAD_SOCKET` + 多线程 | 每个线程独立 sc + ring | P1 |
| FT-043 | select 操作 | `FF_PRELOAD_SUPPORT_SELECT` + select | 正确返回就绪 fd | P2 |
| FT-044 | 内核事件混合 | `FF_KERNEL_EVENT` + ring 模式 | fstack + 内核事件均正常 | P1 |
| FT-045 | 大缓冲区传输 | `write(fd, 1MB_buf, 1MB)` | 数据完整接收 | P1 |
| FT-046 | 零字节操作 | `read(fd, buf, 0)` | 返回 -1, errno=EINVAL | P2 |
| FT-047 | 无效 fd 操作 | `read(invalid_fd, ...)` | 返回 -1, errno=EBADF | P2 |
| FT-048 | Ring 满场景 | 连续发起超过 ring_size 个请求 | 入队阻塞/spin 重试，不丢失 | P0 |

### 3.5 等待策略测试

| 测试编号 | 测试名称 | 等待模式 | 预期结果 | 优先级 |
|---------|---------|---------|---------|--------|
| FT-050 | busy-poll 模式 | `wait_mode=0` | 极低延迟，CPU 100% | P0 |
| FT-051 | yield-poll 模式 | `wait_mode=1` | 较低延迟，CPU < 100% | P0 |
| FT-052 | eventfd 模式 | `wait_mode=2` | 中等延迟，CPU 低 | P1 |
| FT-053 | 模式切换 | 运行时切换 wait_mode | 请求不丢失 | P2 |

---

## 4. 性能基准测试

### 4.1 测试指标

| 指标 | 定义 | 目标（ring vs sem） |
|------|------|-------------------|
| **单次 syscall RTT** | 从 APP 发送请求到收到响应的时间 | ring ≤ 1μs，sem 2-5μs（2-5x 改进） |
| **吞吐量 (RPS)** | 每秒处理的请求数 | ring ≥ 1.5x sem |
| **epoll_wait 延迟** | 事件到达到 epoll_wait 返回的时间 | ring ≤ 2μs |
| **CPU 占用率** | fstack + APP 的 CPU 使用率 | busy-poll: ≈200%, yield-poll: < 150% |
| **P99 延迟** | 第 99 百分位延迟 | ring P99 < sem P50 |
| **上下文切换率** | 每秒上下文切换次数 | ring ≈ 0 (无 futex), sem > 0 |

### 4.2 微基准测试

#### PB-001: 空操作 RTT 测试

```
测试方法:
  1. APP 发起一个最简单的 syscall (如 getsockname)
  2. 测量从 SYSCALL 宏开始到返回的 TSC 周期
  3. 重复 1,000,000 次，计算平均值/P50/P99/P99.9

测量工具: rte_rdtsc() 内嵌

预期结果:
  - ring busy-poll: avg < 500ns, P99 < 1μs
  - ring yield-poll: avg < 1μs, P99 < 2μs
  - sem (对照): avg 2-5μs, P99 > 5μs
```

#### PB-002: epoll_wait 超时精度测试

```
测试方法:
  1. 调用 epoll_wait(epfd, events, maxevents, timeout)
  2. timeout 取值: 1ms, 10ms, 100ms, 1000ms
  3. 测量实际返回时间与期望超时的偏差
  4. 每个 timeout 值重复 1000 次

预期结果:
  - ring: 偏差 < 1ms (对于 timeout >= 10ms)
  - sem: 偏差 1-10ms (CLOCK_REALTIME 精度限制)
```

#### PB-003: O(n) vs O(1) 分发效率

```
测试方法:
  1. 设置不同数量的 active sc: 1, 4, 8, 16, 32
  2. 只有 1 个 sc 有请求，其余 idle
  3. 测量 ff_handle_each_context 处理该请求的耗时

预期结果:
  - ring: 耗时不随 sc 数量变化 (O(1))
  - sem: 耗时随 sc 数量线性增长 (O(n))
```

### 4.3 HTTP 吞吐量基准测试

#### PB-010: 短连接 HTTP 1.0 (close)

```
测试方法:
  - 服务端: fstack + main_stack_epoll 示例 (返回固定 HTML)
  - 客户端: wrk -t4 -c100 -d30s http://server:80/
  - 连接模式: 短连接 (Connection: close)

采集指标:
  - RPS (Requests/sec)
  - avg/P50/P99 延迟
  - 传输速率 (Transfer/sec)

对照组: sem 模式 + POLLING 模式
```

#### PB-011: 长连接 HTTP 1.1 (keep-alive)

```
测试方法:
  - 服务端: 同上
  - 客户端: wrk -t4 -c100 -d30s -H "Connection: keep-alive" http://server:80/
  - 连接模式: 长连接

采集指标: 同 PB-010
```

#### PB-012: 高并发连接

```
测试方法:
  - 服务端: fstack + 示例程序
  - 客户端: wrk -t8 -c1000 -d60s http://server:80/
  - 并发连接数: 100, 500, 1000, 5000, 10000

采集指标: RPS, 延迟分布, 错误率
```

### 4.4 CPU 占用率对比

```
测试方法:
  1. 运行 helloworld 示例，无客户端连接（空闲状态）
  2. top -p <pid> 采集 5 分钟 CPU 使用率
  3. 对比三种模式:
     a. ring busy-poll
     b. ring yield-poll
     c. ring eventfd
     d. sem 模式 (对照)
     e. POLLING_MODE (对照)

预期结果:
  | 模式 | 空闲 CPU | 满载 CPU |
  |------|---------|---------|
  | busy-poll | ~100% | ~100% |
  | yield-poll | < 50% | ~100% |
  | eventfd | < 5% | ~80% |
  | sem (对照) | < 5% | ~80% |
  | POLLING (对照) | ~100% | ~100% |
```

---

## 5. 回归测试

### 5.1 示例程序回归矩阵

所有 5 个 helloworld 示例必须在 Ring 模式下通过：

| 示例程序 | 文件 | 事件模型 | 测试步骤 | Pass 标准 |
|---------|------|---------|---------|----------|
| helloworld_stack | `main_stack.c` | kevent | 启动 → wrk 测试 30s → 信号退出 | RPS > 0, 无 crash, 正常退出 |
| helloworld_stack_epoll | `main_stack_epoll.c` | epoll | 启动 → wrk 测试 30s → 信号退出 | 同上 |
| helloworld_stack_epoll_kernel | `main_stack_epoll_kernel.c` | epoll + kernel | 启动 → wrk 测试 30s → 信号退出 | 同上 |
| helloworld_stack_epoll_thread_socket | `main_stack_epoll_thread_socket.c` | epoll + 多线程 | 启动(2 workers) → wrk 测试 30s → 退出 | 同上 |
| helloworld_stack_thread_socket | `main_stack_thread_socket.c` | kevent + 多线程 | 启动(2 workers) → wrk 测试 30s → 退出 | 同上 |

### 5.2 回归测试流程

```bash
#!/bin/bash
# regression_test.sh

# 编译配置 C1: FF_USE_RING_IPC=1
make clean
make FF_USE_RING_IPC=1

# 1. 启动 fstack 实例
./fstack -c /etc/f-stack.conf &
FSTACK_PID=$!
sleep 2

# 2. 逐个测试示例程序
for prog in helloworld_stack helloworld_stack_epoll \
            helloworld_stack_epoll_kernel \
            helloworld_stack_epoll_thread_socket \
            helloworld_stack_thread_socket; do

    echo "Testing $prog..."
    LD_PRELOAD=./libff_syscall.so ./$prog &
    APP_PID=$!
    sleep 2

    # HTTP 请求测试
    wrk -t2 -c50 -d10s http://<server_ip>:80/ > ${prog}_result.txt 2>&1

    # 检查结果
    if grep -q "Requests/sec" ${prog}_result.txt; then
        RPS=$(grep "Requests/sec" ${prog}_result.txt | awk '{print $2}')
        echo "  PASS: $prog - RPS=$RPS"
    else
        echo "  FAIL: $prog - no response"
    fi

    # 优雅退出
    kill -SIGTERM $APP_PID
    wait $APP_PID 2>/dev/null
done

# 3. 清理
kill $FSTACK_PID
```

### 5.3 sem 模式不退化验证

确保 **不启用** `FF_USE_RING_IPC` 时，原有 sem 模式完全不受影响：

```bash
# 编译配置 C5: 无 FF_USE_RING_IPC
make clean
make

# 运行相同回归测试流程
# 结果必须与改造前一致
```

---

## 6. 压力测试

### 6.1 长时间运行稳定性

| 测试编号 | 测试名称 | 持续时间 | 负载描述 | Pass 标准 |
|---------|---------|---------|---------|----------|
| ST-001 | 72 小时稳定性 | 72h | wrk -t4 -c200 持续 | 无 crash, 无内存泄漏, RPS 波动 < 10%（注：SPEC-001 AC-003 验收门槛为 24h，72h 为加强测试） |
| ST-002 | 连接风暴 | 1h | 每秒新建 1000 连接 | 无 fd 泄漏, 无 ring 溢出 |
| ST-003 | 大量并发 | 4h | wrk -t8 -c10000 | 无 hang, 错误率 < 0.1% |
| ST-004 | 空闲稳定性 | 24h | 无客户端连接 | CPU 使用率稳定, 无内存增长 |

### 6.2 内存泄漏检测

```
检测方法:
  1. 记录启动时的 rte_malloc 统计:
     rte_malloc_dump_stats(stdout, NULL)

  2. 运行压力测试 1 小时

  3. 再次记录 rte_malloc 统计

  4. 对比:
     - alloc_count 与 free_count 差值应恒定
     - heap_totalsz_bytes 不应持续增长

  5. Ring 本身无动态内存分配（创建时一次性分配）

关注点:
  - ff_so_context 的生命周期（attach/detach 平衡）
  - share_mem_alloc / share_mem_free 平衡
  - ring zone 创建后不销毁（设计如此）
```

### 6.3 Ring 满/空边界测试

| 测试编号 | 测试名称 | 场景 | 预期行为 |
|---------|---------|------|---------|
| ST-010 | Ring 满压力 | fstack 故意延迟处理 | APP 入队 spin 等待，不丢失请求 |
| ST-011 | Ring 空频繁 | 极低频率请求 | fstack 正常轮询，无 CPU 浪费（yield 模式） |
| ST-012 | Ring 单元素 | ring_size=2 (最小) | 功能正确但性能下降 |
| ST-013 | Ring 大容量 | ring_size=4096 | 功能正确，内存占用合理 |

---

## 7. Nginx 集成验证

### 7.1 Nginx 配置

```nginx
# nginx.conf (LD_PRELOAD 模式)
worker_processes 1;

events {
    worker_connections 1024;
    use epoll;
}

http {
    server {
        listen 80;
        server_name localhost;

        location / {
            return 200 "Hello from F-Stack + Ring IPC\n";
        }
    }
}
```

### 7.2 Nginx 测试场景

| 测试编号 | 测试名称 | 负载 | Pass 标准 |
|---------|---------|------|----------|
| NG-001 | 短连接基准 | `wrk -t4 -c100 -d30s` | RPS >= sem 模式的 1.2x |
| NG-002 | 长连接基准 | `wrk -t4 -c100 -d30s --latency` | 延迟 P99 <= sem 模式的 0.8x |
| NG-003 | 高并发 | `wrk -t8 -c5000 -d60s` | 错误率 < 0.01% |
| NG-004 | 静态文件 | 1KB/10KB/100KB 文件 | 传输速率 >= sem 模式 |
| NG-005 | Graceful reload | `nginx -s reload` 期间持续请求 | 无请求丢失 |
| NG-006 | Worker 进程退出 | `kill -QUIT worker_pid` | 主进程重新 fork worker |

### 7.3 Nginx 多 Worker 测试（FF_MULTI_SC）

```
测试配置:
  - worker_processes 4
  - FF_MULTI_SC=1 + FF_USE_RING_IPC=1
  - 每个 worker 独立 sc 和 ring zone

测试步骤:
  1. 启动 4 个 fstack 实例
  2. 启动 Nginx (worker_processes 4)
  3. wrk -t8 -c1000 -d60s
  4. 验证负载在 4 个 worker 间均衡
  5. kill 一个 worker，验证其余 worker 继续服务
```

---

## 8. 编译测试

### 8.1 编译正确性

| 测试编号 | 编译配置 | 预期结果 |
|---------|---------|---------|
| CT-001 | `FF_USE_RING_IPC=1` | 编译成功，无 warning |
| CT-002 | 无额外宏（默认 sem 模式） | 编译成功，无 warning |
| CT-003 | `FF_USE_RING_IPC=1 FF_PRELOAD_POLLING_MODE=1` | 编译失败（互斥检查） |
| CT-004 | `FF_USE_RING_IPC=1 FF_THREAD_SOCKET=1` | 编译成功 |
| CT-005 | `FF_USE_RING_IPC=1 FF_KERNEL_EVENT=1` | 编译成功 |
| CT-006 | `FF_USE_RING_IPC=1 FF_MULTI_SC=1` | 编译成功 |
| CT-007 | `FF_USE_RING_IPC=1 FF_USE_THREAD_STRUCT_HANDLE=1` | 编译成功 |
| CT-008 | `FF_USE_RING_IPC=1 FF_PRELOAD_SUPPORT_SELECT=1` | 编译成功 |
| CT-009 | 所有目标：fstack, libff_syscall.so, example | 均编译成功 |

### 8.2 链接测试

```bash
# 验证 libff_syscall.so 导出符号完整
nm -D libff_syscall.so | grep -E "(socket|bind|listen|connect|accept|read|write|close|epoll|kevent|select|fork)" | sort

# 验证无未定义符号引用 rte_ring
nm -D libff_syscall.so | grep "rte_ring" | head -20

# 验证 fstack 二进制链接正确
ldd fstack | grep -E "(dpdk|fstack)"
```

---

## 9. 测试数据采集与报告

### 9.1 性能数据采集脚本

```bash
#!/bin/bash
# perf_benchmark.sh

MODES=("ring_busy" "ring_yield" "ring_eventfd" "sem" "polling")
RESULTS_DIR="perf_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p $RESULTS_DIR

for mode in "${MODES[@]}"; do
    echo "=== Testing mode: $mode ==="
    
    # 编译对应模式
    make clean
    case $mode in
        ring_busy)    make FF_USE_RING_IPC=1 ;;
        ring_yield)   make FF_USE_RING_IPC=1 ;;
        ring_eventfd) make FF_USE_RING_IPC=1 ;;
        sem)          make ;;
        polling)      make FF_PRELOAD_POLLING_MODE=1 ;;
    esac
    
    # 启动服务
    ./fstack -c /etc/f-stack.conf &
    sleep 2
    LD_PRELOAD=./libff_syscall.so ./helloworld_stack_epoll &
    sleep 2
    
    # 运行 wrk
    for conn in 10 50 100 500 1000; do
        wrk -t4 -c${conn} -d30s --latency http://<server_ip>:80/ \
            > $RESULTS_DIR/${mode}_c${conn}.txt 2>&1
    done
    
    # 采集 CPU 使用率
    top -b -n5 -p $(pgrep -f "helloworld|fstack") \
        > $RESULTS_DIR/${mode}_cpu.txt 2>&1
    
    # 清理
    killall helloworld_stack_epoll fstack 2>/dev/null
    sleep 2
done
```

### 9.2 测试报告模板

```
=== F-Stack Ring IPC 性能基准测试报告 ===
日期: YYYY-MM-DD
硬件: CPU型号, 内存, NIC型号
软件: OS版本, GCC版本, DPDK版本, F-Stack版本

1. 编译测试结果
   CT-001 ~ CT-009: PASS/FAIL

2. 功能测试结果
   FT-001 ~ FT-053: PASS/FAIL 汇总

3. 回归测试结果
   5 个 helloworld 程序: PASS/FAIL

4. 性能对比
   | 模式 | 连接数 | RPS | Avg延迟 | P99延迟 | CPU% |
   |------|-------|-----|---------|---------|------|
   | ring (busy) | 100 | ... | ... | ... | ... |
   | ring (yield) | 100 | ... | ... | ... | ... |
   | sem | 100 | ... | ... | ... | ... |
   | polling | 100 | ... | ... | ... | ... |

5. 压力测试结果
   ST-001 ~ ST-013: PASS/FAIL

6. Nginx 集成结果
   NG-001 ~ NG-006: PASS/FAIL

7. 结论与建议
```

---

## 10. 测试优先级与执行计划

### 10.1 Phase 1 — 冒烟测试（Day 1-2）

- [ ] CT-001 ~ CT-009 编译测试
- [ ] FT-001 ~ FT-018 基础 Socket 操作
- [ ] FT-020 ~ FT-027 Epoll 基本操作
- [ ] 5 个 helloworld 回归测试

### 10.2 Phase 2 — 功能完整性（Day 3-5）

- [ ] FT-028 ~ FT-053 完整功能测试
- [ ] FT-040 alarm_event_sem 替代验证
- [ ] FT-048 Ring 满场景
- [ ] FT-050 ~ FT-052 三种等待策略验证

### 10.3 Phase 3 — 性能基准（Day 6-8）

- [ ] PB-001 ~ PB-003 微基准测试
- [ ] PB-010 ~ PB-012 HTTP 吞吐量测试
- [ ] CPU 占用率对比

### 10.4 Phase 4 — 稳定性与集成（Day 9-14）

- [ ] ST-001 72 小时稳定性测试
- [ ] ST-002 ~ ST-003 压力测试
- [ ] NG-001 ~ NG-006 Nginx 集成验证
- [ ] 内存泄漏检测

### 10.5 Phase 5 — 报告（Day 15）

- [ ] 汇总所有测试数据
- [ ] 生成性能对比图表
- [ ] 编写测试报告
- [ ] 提出优化建议

---

## 附录 A: 故障排查指南

### A.1 Ring 相关问题排查

| 症状 | 可能原因 | 排查方法 |
|------|---------|---------|
| APP hang (不返回) | ring 满，fstack 未消费 | `rte_ring_dump()` 检查 ring 状态 |
| fstack 无法收到请求 | ring zone 未正确创建/附加 | 检查 `rte_memzone_lookup` 返回值 |
| 响应数据错误 | sc 指针被覆写 | 检查 `sc->completion` 原子操作正确性 |
| 性能不如预期 | false sharing | `perf c2c` 检查 cache line 竞争 |
| 超时不准确 | TSC 频率获取错误 | `rte_get_tsc_hz()` 值是否合理 |
| 编译错误 | DPDK 版本不兼容 | 检查 `rte_ring_create` 参数签名 |

### A.2 调试日志

Ring 模式下的调试日志通过 `DEBUG_LOG` 宏输出（需要编译时不定义 `NDEBUG`）：

```c
#ifdef FF_USE_RING_IPC
DEBUG_LOG("ring enqueue: sc=%p, ops=%d, req_ring count=%u\n",
          sc, sc->ops, rte_ring_count(ring_zone->req_ring));
DEBUG_LOG("ring dequeue: sc=%p, result=%d, rsp_ring count=%u\n",
          sc, sc->result, rte_ring_count(ring_zone->rsp_ring));
#endif
```
