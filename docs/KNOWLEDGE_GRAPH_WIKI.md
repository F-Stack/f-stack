# F-Stack 知识图谱 Wiki

> 本文档由 GitNexus 知识图谱自动提取 + AI 生成。索引时间：2026-04-09，commit: a695757。

---

## 1. 项目概览

| 指标 | 数据 |
|------|------|
| 索引文件数 | 25,723 |
| 符号节点 | 710,596 |
| 关系边 | 1,270,994 |
| 功能聚类 | 11,375 (communities) |
| 执行流 | 300 (processes) |
| 排除目录 | `freebsd/`, `dpdk/`（仅排除索引，引用关系保留） |

### 节点类型分布

| 类型 | 数量 | 说明 |
|------|------|------|
| Macro | 311,802 | C 预处理宏定义 |
| Function | 159,305 | 函数定义 |
| Property | 103,447 | 结构体字段/属性 |
| Struct | 74,359 | 结构体定义 |
| File | 25,723 | 源文件 |
| Community | 11,375 | 功能聚类 |
| Typedef | 10,634 | 类型别名 |
| Enum | 5,759 | 枚举类型 |
| Union | 3,458 | 联合体 |
| Folder | 1,880 | 目录 |
| Method | 1,268 | 方法（C++ / ObjC） |
| Section | 1,010 | 文档分节 |
| Process | 300 | 执行流 |
| Class | 255 | 类（C++ 部分） |
| Namespace | 19 | 命名空间 |

---

## 2. 核心功能聚类（Top Communities）

聚类由 GitNexus 社区检测算法自动识别，`cohesion` 越高表示聚类内部关联越紧密。

### 2.1 网络协议栈核心

| 聚类 | 符号数 | 内聚度 | 说明 |
|------|--------|--------|------|
| **Net** | 823 | 0.921 | 网络子系统核心（TCP/IP 协议栈） |
| **Netinet** | 245 | 0.900 | Internet 协议族（IPv4/IPv6/TCP/UDP） |
| **Tcp_stacks** | 91 | 0.771 | TCP 协议栈实现 |
| **Netstat** | 158 | 0.947 | 网络状态统计工具 |

### 2.2 内核基础设施

| 聚类 | 符号数 | 内聚度 | 说明 |
|------|--------|--------|------|
| **Sys** | 932 | 0.903 | 系统调用和内核基础接口 |
| **Kern** (comm_307) | 212 | 0.926 | 内核核心功能 |
| **Kern** (comm_89) | 213 | 0.256 | 内核扩展（低内聚，跨模块依赖多） |
| **Kern** (comm_294) | 137 | 0.692 | 内核辅助模块 |
| **Vm** | 101 | 0.679 | 虚拟内存管理 |
| **Amd64** | 188 | 0.490 | x86-64 架构相关代码 |
| **Arm** | 149 | 0.973 | ARM 架构支持 |

### 2.3 DPDK 相关

| 聚类 | 符号数 | 内聚度 | 说明 |
|------|--------|--------|------|
| **Ethdev** | 148 | 0.759 | DPDK 以太网设备抽象层 |
| **Kvargs** | 115 | 0.813 | DPDK Key-Value 参数解析 |
| **Cnxk** | 686 | 0.721 | Marvell CNXK 网卡驱动 |
| **Mlx5** (comm_5663) | 146 | 0.689 | Mellanox ConnectX-5 驱动 |
| **Mlx5** (comm_6413) | 110 | 0.443 | Mlx5 扩展功能 |
| **Sfc** | 224 | 0.836 | Solarflare 网卡驱动 |
| **I40e** | 108 | 0.556 | Intel XL710 网卡驱动 |
| **Bnx2x** | 148 | 0.947 | Broadcom NetXtreme II 驱动 |
| **Qede** | 86 | 0.889 | QLogic 网卡驱动 |
| **Nvidia** | 128 | 0.613 | NVIDIA 网卡支持 |

### 2.4 文件系统

| 聚类 | 符号数 | 内聚度 | 说明 |
|------|--------|--------|------|
| **Zfs** (comm_9633) | 1,015 | 0.812 | ZFS 文件系统核心 |
| **Zfs** (comm_9624) | 819 | 0.762 | ZFS 数据管理层 |
| **Libzfs** | 256 | 0.728 | ZFS 用户态库 |
| **Libzfs_input_check** | 142 | 0.673 | ZFS 输入校验 |

### 2.5 应用与工具

| 聚类 | 符号数 | 内聚度 | 说明 |
|------|--------|--------|------|
| **Test** (多个) | 282–84 | 0.38–0.90 | 各模块的测试代码 |
| **Vhost** | 275 | 0.805 | Virtio/Vhost 用户态网络设备 |
| **Hiredis** | 85 | 0.726 | Redis C 客户端库 |
| **Lua** | 125 | 0.787 | Lua 脚本引擎集成 |
| **Debugger** | 194 | 0.686 | 内核调试器 (DDB) |
| **Modules** | 131 | 0.926 | 内核可加载模块框架 |

---

## 3. 高频函数（调用热点）

以下是被调用次数最多的 Top 50 函数，反映了代码库中的核心依赖关系：

### 3.1 内存管理（最高频）

| 函数 | 入度 | 来源 |
|------|------|------|
| `rte_free()` | 1,166 | DPDK 内存释放 |
| `rte_zmalloc()` | 477 | DPDK 零初始化内存分配 |
| `rte_zmalloc_socket()` | 286 | DPDK NUMA-aware 内存分配 |
| `rte_malloc()` | 180 | DPDK 通用内存分配 |
| `mlx5_free()` | 171 | Mlx5 驱动内存释放 |
| `rte_pktmbuf_free()` | 459 | DPDK 数据包 mbuf 释放 |
| `rte_pktmbuf_alloc()` | 152 | DPDK mbuf 分配 |
| `rte_pktmbuf_free_seg()` | 149 | DPDK mbuf 段释放 |
| `rte_mempool_put()` | 152 | DPDK 内存池归还 |
| `m_freem()` | 517 | FreeBSD mbuf 链释放 |
| `m_pullup()` | 157 | FreeBSD mbuf 数据对齐 |
| `m_adj()` | 142 | FreeBSD mbuf 长度调整 |

### 3.2 设备与驱动

| 函数 | 入度 | 来源 |
|------|------|------|
| `device_get_softc()` | 1,809 | FreeBSD 驱动获取私有数据（**全局第一**） |
| `device_printf()` | 1,122 | 设备日志打印 |
| `device_set_desc()` | 412 | 设备描述设置 |
| `device_get_nameunit()` | 153 | 获取设备名 |
| `device_get_parent()` | 148 | 获取父设备 |
| `bus_alloc_resource_any()` | 181 | 总线资源分配 |
| `bus_release_resource()` | 179 | 总线资源释放 |
| `bus_setup_intr()` | 145 | 中断注册 |

### 3.3 同步原语

| 函数 | 入度 | 来源 |
|------|------|------|
| `mutex_enter()` / `mutex_exit()` | 585 / 589 | ZFS 互斥锁 |
| `pthread_mutex_lock()` / `unlock()` | 257 / 256 | POSIX 互斥锁 |
| `rte_spinlock_lock()` / `unlock()` | 190 / 198 | DPDK 自旋锁 |

### 3.4 错误处理与日志

| 函数 | 入度 | 来源 |
|------|------|------|
| `panic()` | 1,071 | 内核 panic |
| `rte_exit()` | 236 | DPDK 致命退出 |
| `AcpiOsPrintf()` | 312 | ACPI 日志 |
| `db_printf()` | 271 | 内核调试器输出 |
| `rte_flow_error_set()` | 345 | DPDK 流规则错误设置 |
| `ngx_conf_log_error()` | 201 | Nginx 配置错误日志 |

### 3.5 网络数据操作

| 函数 | 入度 | 来源 |
|------|------|------|
| `rte_ether_addr_copy()` | 167 | MAC 地址复制 |
| `mc_send_command()` | 213 | FSLMC 总线命令发送 |
| `mc_encode_cmd_header()` | 213 | FSLMC 命令头编码 |
| `mbox_get()` / `mbox_put()` | 210 / 210 | CNXK 邮箱通信 |
| `roc_nix_to_nix_priv()` | 228 | CNXK NIX 私有数据转换 |
| `cnxk_eth_pmd_priv()` | 187 | CNXK 以太网 PMD 私有数据 |

---

## 4. 关键执行流（Processes）

执行流由 GitNexus 自动检测的跨函数调用链。`cross_community` 表示跨聚类调用，`intra_community` 表示聚类内部调用。

### 4.1 数据面关键路径

| 执行流 | 步数 | 类型 | 说明 |
|--------|------|------|------|
| Main → Rte_vlog | 5-6 | cross | 应用主循环 → DPDK 日志输出 |
| Cmd_send_parsed → Rte_mempool_get_ops | 9 | cross | **最长执行流**：命令解析 → 内存池操作获取 |
| Cmd_send_parsed → Rte_mempool_default_cache | 6 | cross | 命令解析 → 内存池缓存 |
| T4_eth_xmit → RTE_MBUF_DIRECT | 5 | cross | Chelsio T4 网卡发送 → mbuf 检查 |
| T4_sge_alloc_rxq → RTE_MEMPOOL_HEADER_SIZE | 5 | cross | T4 接收队列分配 → 内存池头大小计算 |
| Run_regex → RTE_MBUF_* | 5-6 | cross | 正则匹配引擎 → mbuf 操作族 |
| Ice_init_hw → Ice_msec_delay | 5 | cross | Intel ICE 网卡初始化 → 延时等待 |

### 4.2 存储路径

| 执行流 | 步数 | 类型 | 说明 |
|--------|------|------|------|
| Dsl_dataset_promote_sync → 多个目标 | 5-6 | mixed | ZFS 数据集提升（快照→克隆） |
| Dsl_scan_sync → Kmem_free | 5 | cross | ZFS 扫描同步 → 内存释放 |
| Zfs_create → KUID_TO_SUID | 5 | cross | ZFS 创建 → UID 转换 |
| Zfs_acl_ids_create → Zfs_acl_valid_ace_type | 5 | cross | ZFS ACL 创建 → ACE 类型验证 |

### 4.3 架构特殊路径

| 执行流 | 步数 | 类型 | 说明 |
|--------|------|------|------|
| Pmap_enter → Pt2tab_index | 7 | cross | ARM 页表映射（第二长执行流） |
| X86emu_exec_one_byte → Longjmp | 6 | cross | x86 模拟器 → 长跳转 |
| Cvmx_helper_shutdown → CVMX_ADD_IO_SEG | 6 | cross | MIPS Cavium 网络关闭 → IO 段操作 |

### 4.4 应用层路径

| 执行流 | 步数 | 类型 | 说明 |
|--------|------|------|------|
| ClientCommand → ClientInstallWriteHandler | 5 | cross | Redis 客户端命令 → 写处理器 |
| ClientCommand → ServerAssert | 5 | cross | Redis 命令 → 服务端断言 |
| ZiplistTest → ZIPLIST_BYTES | 5 | intra | Redis ziplist 测试 → 字节操作 |

---

## 5. 目录结构

```
f-stack/
├── lib/            # F-Stack 核心库（ff_api, ff_dpdk_if, ff_config 等）
├── adapter/        # LD_PRELOAD 适配层（syscall hook, socket ops）
├── app/            # 应用程序（Nginx, Redis 等 F-Stack 改造版）
├── example/        # 示例程序（helloworld, kqueue 用法等）
├── tools/          # 工具（ifconfig, netstat, arp, route 等用户态移植）
├── mk/             # 构建系统（Makefile include 文件）
├── doc/            # 原始文档
├── docs/           # 架构文档和 Specs 文档
├── dpdk/           # DPDK 23.11.5 子模块（已从索引排除）
└── freebsd/        # FreeBSD 13.1 内核源码（已从索引排除）
```

### 5.1 核心库文件 (`lib/`)

| 文件 | 职责 |
|------|------|
| `ff_api.h` / `ff_api.c` | F-Stack 公开 API（Socket, KQueue, 路由, 日志等） |
| `ff_dpdk_if.h` / `ff_dpdk_if.c` | DPDK 接口层（收发包、main_loop、设备初始化） |
| `ff_config.h` / `ff_config.c` | 配置解析（ini 格式） |
| `ff_host_interface.h` / `ff_host_interface.c` | 主机接口抽象 |
| `ff_veth.h` / `ff_veth.c` | 虚拟以太网设备 |
| `ff_msg.h` / `ff_msg.c` | F-Stack 进程间消息 |
| `ff_log.h` | 日志 API（ff_log, ff_vlog, ff_log_reset_stream） |
| `ff_epoll.h` / `ff_epoll.c` | Epoll 兼容层 |
| `ff_errno.h` | 错误码映射 |

### 5.2 适配器层 (`adapter/`)

| 文件 | 职责 |
|------|------|
| `syscall/ff_hook_syscall.c` | LD_PRELOAD 系统调用劫持（3254 行） |
| `syscall/ff_socket_ops.h` / `.c` | Socket 操作上下文和处理 |
| `syscall/ff_so_zone.c` | 共享内存区域管理 |
| `syscall/ff_epoll.c` | Epoll 适配 |

---

## 6. 依赖关系概览

```
                    ┌──────────────┐
                    │  Applications │
                    │ (Nginx/Redis) │
                    └──────┬───────┘
                           │ ff_* API
                    ┌──────▼───────┐
                    │   lib/       │
                    │  F-Stack Core │
                    └──┬───────┬───┘
                       │       │
              ┌────────▼──┐ ┌──▼────────┐
              │  FreeBSD   │ │   DPDK     │
              │  TCP/IP    │ │  23.11.5   │
              │  Stack     │ │ (PMD/EAL)  │
              └────────────┘ └────────────┘

  adapter/                    tools/
  LD_PRELOAD Hook ──────►  ifconfig/netstat
  (syscall redirect)       (用户态网络工具)
```

### 关系类型

知识图谱中所有关系均为 `CodeRelation` 类型（1,270,994 条），涵盖：
- 函数调用（CALL）
- 类型引用（USES_TYPE）
- 宏展开（EXPANDS）
- 文件包含（INCLUDES）
- 结构体成员访问（HAS_MEMBER）
- 社区归属（BELONGS_TO）

---

## 7. 知识图谱使用指南

### 查询工具

| 工具 | 用途 | 示例 |
|------|------|------|
| `gitnexus_query` | 按概念搜索执行流 | "packet receive" |
| `gitnexus_context` | 查看符号的 360° 关系 | "ff_init" 的所有调用者/被调用者 |
| `gitnexus_impact` | 修改前影响分析 | 改 ff_dpdk_if.c 的影响半径 |
| `gitnexus_detect_changes` | 提交前变更范围检查 | 确认 staged 文件的影响 |
| `gitnexus_rename` | 安全重命名 | 多文件批量重命名 |
| `gitnexus_cypher` | 自定义图查询 | 高级分析 |

### 更新索引

```bash
# 环境变量（TencentOS 4.4 需要）
export LD_LIBRARY_PATH="/opt/OpenCloudOS/gcc-toolset-14/root/usr/lib64:$LD_LIBRARY_PATH"
export PATH="/root/.workbuddy/binaries/node/versions/20.18.0/bin:$PATH"

# 检查状态
cd /data/workspace/f-stack && npx gitnexus@1.5.3 status

# 重新索引
npx gitnexus@1.5.3 analyze

# 强制完全重建
npx gitnexus@1.5.3 analyze --force
```

> **自动更新**：已配置 Git `post-commit` hook，每次 commit 后自动在后台重新索引。

---

*Generated from GitNexus knowledge graph (710,596 nodes, 1,270,994 edges) — 2026-04-09*
