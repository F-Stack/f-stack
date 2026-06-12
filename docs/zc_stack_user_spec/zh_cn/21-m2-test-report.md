# 21 · M2 测试执行报告（ZC-RECV）

> 执行：2026-06-11。双机：server=本机（VM-213-67，data-plane DPDK NIC 9.134.214.176 / MAC 20:90:6f:7d:5d:08，云 metadata 实测确认）；client=f-stack-client（VM-211-87，9.134.211.87，wrk 4.2.0 @ /tmp/wrk/wrk）。
> 铁律：仅记录实际执行结果，不臆造数据。

## 1. 根因与修复（关键）
首轮 curl 全部 http=000，曾误判为"环境问题"。经用户纠正（普通 helloworld 在 client 测试 http=200 正常）后实际调试，定位**真实根因**：

- **增量编译陷阱**：先做了无 flag 的 baseline build（所有 .o 不含 FSTACK_ZC_SEND），随后 `FF_ZC_SEND=1 make` 因 `uipc_mbuf.c` 未改动、其 .o（06-09 15:48）比 .c 新而**被 make 跳过未重编译** → `m_uiotombuf` 的 FSTACK_ZC_SEND 内核 hook **缺失**（objdump 验证 magic `0xf8ac2c00` 不在 uipc_mbuf.o）。
- 后果：`ff_zc_send`（应答路径，A/B 两版都用）设了 magic 但内核 hook 不识别 → 把 mbuf 链指针当 char buffer → 应答崩坏，连接不可用 → http=000。
- **这也解释了为何 A(baseline) 与 B(ZC-recv) 都失败**（两者应答都走 ff_zc_send）。
- **修复**：删除 stale 的 `uipc_mbuf.o` / `sys_generic.o`（经 rm_tmp_file.sh），带 `FF_ZC_SEND=1 FF_ZC_RECV=1` 重编译；objdump 验证 uipc_mbuf.o 现含 `movabs $0xf8ac2c00f8ac2c00`。重链 libfstack.a + 重建 server。
- **构建规约（记入）**：变更 FF_ZC_* 等编译开关后**必须 `make clean` 或删除受影响 .o 后重编译**，不能依赖增量编译（make 基于时间戳，不感知 CFLAGS 变化）。

## 2. 功能验证（PASS，修复后）
| 项 | 结果 |
|---|---|
| lib（clean+FF_ZC_SEND=1 FF_ZC_RECV=1）| ✅ -Werror 零错误；uipc_mbuf.o 含 ZC-send hook |
| 符号导出 | ✅ ff_zc_recv / ff_zc_mbuf_segment / ff_zc_recv_free |
| server B（ZC-recv）启动 | ✅ DPDK 注册 OK |
| **client curl ×5** | ✅ **http=200 size=438**（ff_zc_recv→segment→free 全链路 + ff_zc_send 应答均正常）|

## 3. 单核性能基线 A/B（lcore_mask=10 → lcore4，wrk，按 freebsd-13-to-15 方法论 T1/T2/T3）
A=baseline（ff_read 接收）；B=ZC-recv（ff_zc_recv 接收）；二者应答均 ff_zc_send，隔离接收路径差异。

| 档位 | wrk 参数 | A baseline req/s | B ZC-recv req/s | Δ |
|---|---|---|---|---|
| T1 | -t2 -c10 -d5s | 22,363 | 22,115 | −1.1%（噪声）|
| **T2** | -t4 -c100 -d30s | 31,056 / 32,136 / 30,066（avg **31.1k**）| 39,046(离群) / 32,219 / 31,987（avg **32.1k**，去离群）| **持平（≤+3%，噪声内）**|
| T3 | -t8 -c500 -d30s | 28,615 | 28,317 | −1.0%（饱和）|

> 注：B 首次 T2=39,046 经复测确认为 warmup/噪声离群值；3 次复测后 A≈B。

延迟（T2）：A avg 3.71ms / B avg 4.12ms；T3：A 17.87ms / B 18.06ms —— 同量级。
server 单核 CPU（T2）：72–84%，**未饱和** → 该负载瓶颈在 client/网络，非 server 接收拷贝。

## 4. 性能结论（诚实）
- **此小包 echo 负载（256B 请求 / 438B 应答）下，ZC-recv 与 ff_read 吞吐/延迟持平（噪声内）**。
- 原因：小请求的 `soreceive→uiomove` 拷贝开销相对 TCP 处理 + syscall + 调度可忽略；且 f-stack 用 UIO_SYSSPACE，uiomove 本就是同地址空间 memcpy（已很廉价）。
- ZC-recv 的收益预期在 **大块数据收取 / 代理转发（收到即转发免拷贝）** 场景（spec 15/17 §适用场景），需用大 payload 工作负载（如大文件下载、大 body POST）专门测量；本轮 echo 负载无法体现。
- **历史极限参考**（同机同 config 单核 lcore4，helloworld kqueue，docs/freebsd_13_to_15 13.0-baseline）：T2 220,691 / T3 239,555 req/s。本轮 main_zc（echo + 模拟 1 万次空循环 + ff_zc_send）req/s 远低于该 kqueue helloworld，因应用模型与负载不同（main_zc 每请求含人为 busy-loop 与 ZC 应答构造），不可直接横比。

## 5. M2 验收对照（spec 17）
| AC | 状态 | 说明 |
|---|---|---|
| 构建/启动 | ✅ | clean 重编译后 -Werror 通过；DPDK 注册 |
| AC-F1 ff_zc_recv 全链路功能 | ✅ | curl http=200 size=438（5/5）|
| AC-F4 普通 recv 零回归 | ✅ | A(ff_read) 同样 http=200 正常 |
| AC-P1 单核性能 A/B | ✅（已采集）| 小包 echo 下持平；大 payload 收益待专测 |
| AC-M1/M2 内存安全 | ⏳ | T1/T2/T3 共 ~400 万请求无崩溃；valgrind/mempool 精确计数待补（DPDK 运行态 valgrind 成本高）|

## 6. 合规
- ✅ 停进程走 kill_process.sh；清 rtemap/stale .o 走 rm_tmp_file.sh；**修复了此前一次误用 `rm -rf` 的违规**（已改用脚本）。
- ✅ 未臆造数据；http=000→根因→修复→http=200 全程实测；性能离群值如实标注并复测校正。
- ✅ client wrk 命令经 ssh 下发（复用已有 /tmp/wrk/wrk，未重复安装）。

## 7. 后续
- AC-M（内存安全精确化）：大 payload 长跑 + rte_mempool_in_use_count 前后对比。
- 大 payload 性能专测以体现 ZC-recv 设计收益。
