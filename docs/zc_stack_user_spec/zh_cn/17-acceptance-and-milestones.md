# 17 · 验收标准与里程碑

## 1. 验收标准（DoD）
### 功能
- [ ] AC-F1：ff_zc_recv 在 TCP 上零拷贝收取整 mbuf 段，数据与发送端一致。
- [ ] AC-F2：ff_zc_mbuf_segment/read 正确遍历/读出多段链。
- [ ] AC-F3：ff_zc_recv_free 正确归还整链（含混合 ext/copym 段）。
- [ ] AC-F4：普通 ff_read/ff_recv/ff_recvfrom/ff_recvmsg 行为零回归。

### 内存安全
- [ ] AC-M1：recv+free 循环后 rte_mempool_in_use_count 回基线（无泄漏）。
- [ ] AC-M2：valgrind 0 definite leak（unit + integration make check）。
- [ ] AC-M3：free 后访问防护（segment 返回 -1，无 use-after-free）。

### 边界
- [ ] AC-B1：split/PEEK/OOB/TLS/UDP 回退路径数据正确。
- [ ] AC-B2：非阻塞 EAGAIN / 连接关闭 0 / 半包 语义正确。

### 兼容/工程
- [ ] AC-C1：FSTACK_ZC_RECV 未定义时全部改动不参与编译，现有构建零影响。
- [ ] AC-C2：编译开关 FF_ZC_RECV→FSTACK_ZC_RECV 与 SEND 范式一致。
- [ ] AC-C3：示例 example/main_zc.c（或新增）演示 recv 序列。

### 性能（基线对比）
- [ ] AC-P1：大包收取场景，ZC 路径相对拷贝路径 CPU/吞吐有可测收益（M4 基线报告）。

## 2. 里程碑（实现期，本规格之后）
| 里程碑 | 内容 | 退出条件 |
|---|---|---|
| **M0** 内核 mp 贯通 | kern_zc_recvit + soreceive(&mp) 透传（FSTACK_ZC_RECV 门控）| 内核编译通过；mbuf 链能交出 |
| **M1** 用户态 API | ff_zc_recv + ff_zc_mbuf_read 重写 + ff_zc_recv_free | API 单元测试通过（16 §3）|
| **M2** 生命周期闭环 | refcnt + release 契约 + 泄漏检测 | AC-M1/M2/M3 通过 |
| **M3** 边界完备 | split/PEEK/WAITALL/DONTWAIT/UDP 回退 | AC-B1/B2 通过 |
| **M4** 示例+性能基线 | recv 示例 + ZC vs copy 基线 | AC-P1 报告产出 |
| **M5** page-array 兼容 | FF_USE_PAGE_ARRAY=1 下验证 | 该模式下 AC-F/M 全通过 |

## 3. 风险与回滚
- 任一 AC-M（内存安全）不过 → 回滚到 M2 重做生命周期。
- read() 路径 ZC（K2）作为可选项，若 M0-M3 工期紧可延后，不阻塞 recv 系主功能。

## 4. 工作量复述（来自 05 §5）
内核 ~50-100 行 + 用户态 ~100-150 行 + 测试 + 示例，粗估 8-15 人天（不含大规模性能调优）。
