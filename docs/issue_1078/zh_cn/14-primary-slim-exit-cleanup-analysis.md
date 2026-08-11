# 14. primary_slim 退出清理分析

> 本文档分析 commit `1c28aaa2df` 中 `ff_dpdk_run()` 对 primary_slim+PRIMARY 跳过 `ff_unload_config()` + `rte_eal_cleanup()` 的决定是否正确，以及缺失的清理逻辑。
> 编写时间：2026-08-11。依据：DPDK 24.11.6 源码 + issue #1078 既有文档 `01`/`10` + 外网交叉验证。

## 摘要

跳过 `rte_eal_cleanup()` 的设计意图是保护 secondary 依赖的共享资源，但经 DPDK 源码逐函数坐实，其实际效果**有限**——`rte_eal_cleanup()` 并不删除 `/var/run/dpdk/rte/config` 文件，mp_socket 的 `unlink` 在下次 primary 启动时会被 `bind` 覆盖，hugepage 用 `MAP_SHARED` 映射在 primary 退出时内核只 munmap primary 自己的映射不影响 secondary。真正的缺失是**没有通知 secondary 退出**，导致孤儿进程。按 issue #1078 设计哲学（文档 `10` 附加条件 3："primary 常驻、不优雅退出"），这个退出路径是兜底而非正常流程。

## 1. `ff_dpdk_run()` 当前实现

`lib/ff_dpdk_if.c:3004-3026`：

```c
void ff_dpdk_run(loop_func_t loop, void *arg) {
    ...
    rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN);
    rte_eal_mp_wait_lcore();
    stop_clock();
    rte_free(lr);

    if (!(ff_global_cfg.dpdk.primary_slim &&
          rte_eal_process_type() == RTE_PROC_PRIMARY)) {
        ff_unload_config();
        rte_eal_cleanup();
    }
    ff_log_close();
}
```

primary_slim+PRIMARY 时跳过 `ff_unload_config()` + `rte_eal_cleanup()`，只调 `ff_log_close()`。

`ff_dpdk_stop()`（:3029-3035）只设 `stop_loop = 1`（`__thread` 变量），打印警告 `"slim primary stopping - control plane degraded, need planned full restart"`。

## 2. `rte_eal_cleanup()` 逐函数行为

`dpdk/lib/eal/linux/eal.c:1300-1346`：

| 序号 | 调用 | 行号 | 实际行为 | 删除文件？ | 影响 secondary？ |
|------|------|------|---------|-----------|-----------------|
| 1 | `rte_service_finalize()` | 1323 | 清理 service core 子系统 | 否 | 否 |
| 2 | `vfio_mp_sync_cleanup()` | 1332 | 清理 VFIO mp sync 线程 | 否 | 否（本机用 igb_uio） |
| 3 | `rte_mp_channel_cleanup()` | 1334 | `close_socket_fd()` → `close(fd)` + `unlink(path)` | **是**（mp_socket 文件） | 否（secondary 有自己的 mp_socket fd） |
| 4 | `rte_eal_alarm_cleanup()` | 1335 | 清理 alarm 线程 | 否 | 否 |
| 5 | `eal_mp_dev_hotplug_cleanup()` | 1338 | 清理热插拔 mp 线程 | 否 | 否 |
| 6 | `rte_eal_memory_detach()` | 1340 | munmap primary 的 hugepage 映射；内部还调 `eal_memalloc_cleanup()`（关闭 hugepage fd）和 `rte_fbarray_detach()`（分离 fbarray） | 否 | **否**（MAP_SHARED，secondary 映射不受影响；详见 B2 边界） |
| 7 | `rte_eal_malloc_heap_cleanup()` | 1341 | 清理 primary 的 malloc heap | 否 | 否 |
| 8 | `eal_cleanup_config()` | 1342 | `free()` 3 个字符串（`hugefile_prefix`/`hugepage_dir`/`mbuf_pool_ops_name`） | **否** | 否 |
| 9 | `eal_lcore_var_cleanup()` | 1343 | 清理 lcore 变量 | 否 | 否 |
| 10 | `rte_eal_log_cleanup()` | 1344 | 清理日志 | 否 | 否 |

> **注**：`rte_eal_cleanup()` 中还调用了 `eal_bus_cleanup()`（`:1329-1330`，primary 专属，清理 bus 层状态），`rte_trace_save()`（`:1336`）和 `eal_trace_fini()`（`:1337`）。其中 `eal_bus_cleanup()` 是 primary 专属调用，可能与跳过 cleanup 的决策相关。

### 2.1 `rte_mp_channel_cleanup()` 详解

`dpdk/lib/eal/common/eal_common_proc.c:666-678`：

```c
void rte_mp_channel_cleanup(void) {
    int fd = rte_atomic_exchange_explicit(&mp_fd, -1, ...);
    if (fd < 0) return;
    pthread_cancel((pthread_t)mp_handle_tid.opaque_id);
    rte_thread_join(mp_handle_tid, NULL);
    close_socket_fd(fd);  // close(fd) + unlink(path)
}
```

`close_socket_fd()`（:595-603）会 `unlink` mp_socket 文件。但：
- primary 退出时内核已关闭所有 fd
- mp_socket 文件残留不影响下次启动（`bind` 会覆盖）
- secondary 有自己的 mp_socket fd，不受 primary unlink 影响

### 2.2 `eal_cleanup_config()` 详解

`dpdk/lib/eal/common/eal_common_options.c:2037-2044`：

```c
eal_cleanup_config(struct internal_config *internal_cfg) {
    free(internal_cfg->hugefile_prefix);
    free(internal_cfg->hugepage_dir);
    free(internal_cfg->user_mbuf_pool_ops_name);
    return 0;
}
```

**只 free 3 个字符串，不删除 `/var/run/dpdk/rte/config` 文件**。config 文件的清理在 `eal_clean_runtime_dir()`（`linux/eal.c:84`）中，该函数在 **primary 启动时**调用（清理上次残留），不在 `rte_eal_cleanup()` 中。

### 2.3 hugepage 用 MAP_SHARED

`dpdk/lib/eal/linux/eal_memory.c:556`：

```c
retval = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
```

`MAP_SHARED` 语义：映射在所有引用它的进程都 munmap 后才真正释放。primary 退出时内核 munmap primary 的映射，**secondary 的映射不受影响**，hugepage 物理内存不会被释放。

## 3. 跳过 cleanup 的实际效果

| 资源 | 跳过 cleanup | 进程退出时内核行为 | 实际效果 |
|------|-------------|-------------------|---------|
| mp_socket 文件 | 不 unlink | fd 关闭，文件残留 | 下次 primary 启动 `bind` 覆盖，无害 |
| `/var/run/dpdk/rte/config` | 不删除（cleanup 也不删） | 文件残留（tmpfs） | 下次 `eal_clean_runtime_dir()` 清理，无害 |
| hugepage 映射 | 不 munmap | 内核自动 munmap primary 的映射 | secondary 的 MAP_SHARED 映射不受影响 |
| malloc heap | 不清理 | 内核自动回收 | 无害 |
| ini 配置内存 | 不 `ff_unload_config()` | 内核自动回收 | 无害 |

**结论**：跳过 `rte_eal_cleanup()` 的实际效果**几乎为零**——进程退出时内核会自动完成大部分清理（munmap、close fd、回收内存），DPDK 的 cleanup 只补充了 `unlink` mp_socket 文件和 `free` 字符串，这些都不影响下次启动。

文档 `10` 附加条件 3 的说法"避免 `rte_eal_cleanup()` 拆除共享资源"**不完全准确**：`rte_eal_cleanup()` 实际上不拆除 secondary 依赖的共享资源（hugepage 用 MAP_SHARED，config 文件不在 cleanup 中删除）。

## 4. 真正的缺失：没有 secondary 退出通知

`ff_dpdk_stop()` 只设 `stop_loop = 1`（`__thread` 变量），只停 primary 自己的 `main_loop`。**没有跨进程通知 secondary 退出的机制**：

- `ff_ipc_send` / `msg_ring.*stop` / `broadcast.*secondary` 在 `lib/` 中无匹配
- `rte_eal_mp_wait_lcore()` 等的是 lcore（线程）退出，不是 process 退出——secondary 是独立进程不是 lcore

### 4.1 primary 退出后的时序

1. primary 收到信号或 `ff_dpdk_stop()` 被调用
2. `stop_loop = 1`（per-thread）
3. primary 的 `main_loop` 退出
4. `rte_eal_mp_wait_lcore()` 返回（只等 primary 自己的 lcore）
5. 跳过 cleanup
6. `ff_log_close()`
7. `ff_dpdk_run()` 返回，primary 进程退出
8. **secondary 仍在跑**，成为孤儿进程

### 4.2 孤儿 secondary 的状态

primary 退出后 secondary 失去：
- IPC 服务端（`eal_common_proc.c:750-751`，secondary 的 mp 请求目的地硬编码为 primary）
- 动态扩堆代理（`malloc_heap.c:484`，`request_to_primary()` 失败）
- 中断处理（`multi_proc_support.rst:174-177`，所有中断只在 primary 触发）

但 secondary 仍能收发包（数据面不依赖 primary 在线，文档 `01` 关键结论 2 坐实），进入**控制面降级态**（文档 `10` §1.4）。

### 4.3 f-stack 没有信号 handler

`example/` 中无 `SIGINT`/`SIGTERM` handler（仅 `echo_server.py` 用 Python signal，不相关）。helloworld 收到 `SIGTERM` 时走默认行为（直接退出），不走 `ff_dpdk_stop()`。

## 5. 设计哲学分析

### 5.1 issue #1078 的定位

文档 `10` 附加条件 3 明确：
> "运维上必须保证：**primary 常驻、不优雅退出**（避免 `rte_eal_cleanup()` 拆除共享资源）、且**至少一个数据面进程始终存活**（维持 uio refcnt ≥ 1）。"

文档 `10` L5 边界：
> "优雅退出未测 — E2/E2e/E3b 均为强杀 primary。走 `rte_eal_cleanup()` 的优雅退出会拆 EAL 共享资源（N4），其影响未实测（待补实验 E8）。"

### 5.2 跳过 cleanup 的真正价值

跳过 cleanup 的真正价值**不是保护 secondary**（hugepage 用 MAP_SHARED 不受影响），而是：
1. **保守策略**：避免在 cleanup 过程中的 `pthread_cancel` 等操作可能产生的未定义行为
2. **兜底**：primary 不应该正常退出，这个路径是"万一"的兜底

### 5.3 与文档 `10` 的差异

文档 `10` 说法"避免 `rte_eal_cleanup()` 拆除共享资源"经源码坐实**不准确**：
- `rte_eal_cleanup()` 不删除 config 文件（`eal_cleanup_config` 只 free 字符串）
- hugepage 用 MAP_SHARED，primary cleanup 不影响 secondary
- mp_socket unlink 不影响 secondary（secondary 有自己的 fd）

## 6. 外网交叉验证

### 6.1 DPDK 官方文档

`dpdk/doc/guides/prog_guide/multi_proc_support.rst:19-24`：
> "secondary processes can only run alongside a primary process **or after a primary process has already configured the hugepage shared memory for them**"

这句"or after"给出了"primary 缺席仍可跑"的文字空间，但无保障语义。

`dpdk/doc/guides/rel_notes/release_18_02.rst`：
> "It is expected that all DPDK applications call rte_eal_cleanup() before exiting. Not calling this function could result in leaking hugepages, leading to failure during initialization of secondary processes."

但经源码坐实，`rte_eal_cleanup()` 实际不释放 hugepage 物理内存（MAP_SHARED 在进程退出时由内核回收），只 munmap primary 自己的映射。官方"leaking hugepages"的说法可能指早期版本行为。

### 6.2 社区实践

- VPP / DPVS 均采用单进程多线程，不存在 primary/secondary 退出问题
- f-stack native-mt（`thread_mode=1`）也是单进程多线程方向

## 7. 改进建议

### 7.1 最小改动（推荐）

在 `ff_dpdk_run()` 的 cleanup skip 块中加警告日志，提示运维 primary 退出后 secondary 成为孤儿：

```c
if (!(ff_global_cfg.dpdk.primary_slim &&
      rte_eal_process_type() == RTE_PROC_PRIMARY)) {
    ff_unload_config();
    rte_eal_cleanup();
} else {
    fprintf(stderr, "primary_slim: primary exiting without cleanup; "
        "secondary processes are orphaned and enter control-plane "
        "degraded state, need planned full restart\n");
}
```

### 7.2 中等改动（可选）

在 `ff_dpdk_stop()` 中通过 IPC 广播 stop 给所有 secondary，等它们退出后再 cleanup。但 f-stack 当前无跨进程 stop 通知机制，需要新增 IPC 消息类型。

### 7.3 不建议的改动

不建议在 primary_slim 退出时调 `rte_eal_cleanup()`——虽然经分析其对 secondary 无实际影响，但 `pthread_cancel` mp_handle_tid 线程等操作在多进程环境下可能有未定义行为，保守跳过更安全。

## 8. 诚实边界

| 编号 | 边界 | 说明 |
|------|------|------|
| B1 | **VFIO 未验证** | 本机用 igb_uio，`vfio_mp_sync_cleanup()` 的行为未验证。VFIO 下 primary cleanup 可能影响 secondary 的 group fd |
| B2 | **`rte_eal_memory_detach` 内部未深入** | 该函数可能不只 munmap，还可能释放 fbarray 共享文件。未逐行分析 |
| B3 | **优雅退出未实测** | 文档 `10` L5 的 E8 实验未执行，本分析基于源码静态分析 |
| B4 | **长期稳定性未测** | 孤儿 secondary 的长期行为（小时级）未验证 |

## 9. 结论

1. 跳过 `rte_eal_cleanup()` 和 `ff_unload_config()` 的**实际效果有限**——进程退出时内核会自动完成大部分清理
2. 真正的缺失是**没有通知 secondary 退出**，导致孤儿进程进入控制面降级态
3. 按 issue #1078 设计哲学，primary 不应正常退出，这个路径是兜底
4. 建议最小改动：加警告日志提示运维 secondary 已成为孤儿
