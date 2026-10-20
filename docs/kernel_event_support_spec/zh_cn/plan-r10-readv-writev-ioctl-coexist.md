# R10 计划：补齐 FF_KERNEL_COEXIST 残余入口（readv/writev/ioctl + dup/dup2/select/poll 评估）

> 里程碑编号：R10（接续 R9 kqueue 共存 + IPv6 V6ONLY）。基线 commit `03f244ac1`。
> 方法：harness 工程 + spec 驱动 + agent team（leader + impl/spec-writer/tester/reviewer 子 agent）。
> 强制规约：rm/kill/chmod 一律走 `/data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh`；lib 注释精简；commit 英文简短；config.ini 本地测试改动不提交；门禁失败打回上一步（单步 bounce≤3，超则停转人工）；子 agent 全部完成前 leader 严禁退出，主动轮询等待。

---

## 1. 背景与需求

用户需求：双栈共存功能完善，当前 `ff_readv`/`ff_writev`/`ff_ioctl` 未实现内核 fd 对应路由，需实现+测试（含中英文档、三层架构+知识图谱更新）；并检查是否还有其他 `ff_*` 接口未支持双栈共存，一并实现和测试。

## 2. 实证现状（已交叉核实，以代码为准）

`lib/ff_syscall_wrapper.c` 全部 42 个 `ff_*` 入口，按 coexist 路由分类：

### 2.1 已支持 coexist（R1-R9 落地）
socket / getsockopt / setsockopt / close / read / write / sendto / send(委托) / sendmsg / recvfrom / recv(委托) / recvmsg / fcntl / accept / accept4 / listen / bind / connect / getpeername / getsockname / shutdown / kqueue / kevent。

### 2.2 未支持 coexist —— 本轮目标
| 入口 | 行号 | 现状 | 处置 |
|------|------|------|------|
| `ff_readv` | L1179 | 仅 `kern_readv`，无内核 fd 路由 | **实现**（仿 `ff_read`） |
| `ff_writev` | L1236 | 仅 `kern_writev`，无内核 fd 路由 | **实现**（仿 `ff_write`） |
| `ff_ioctl` | L1067 | `linux2freebsd_ioctl`→`kern_ioctl`，无内核 fd 路由 | **实现**（内核 fd 用原始 Linux request 直传 host；双栈 fd 评估 host 同驱动如 FIONBIO） |
| `ff_dup` | L2099 | `sys_dup`，无内核 fd 路由 | **实现**（内核 fd→host dup，返回新 encode fd） |
| `ff_dup2` | L2117 | `sys_dup2`，无内核 fd 路由 | **评估并实现**（两端均内核 fd→host dup2；混栈不可行则明确拒绝+文档） |
| `ff_select` | L1859 | `kern_select`，无内核 fd 路由 | **评估**：encode 内核 fd（≥0x40000000）远超 `FD_SETSIZE`，无法装入 `fd_set` → 预判为**硬限制**，文档明示（实测确认） |
| `ff_poll` | L1878 | `kern_poll`，无内核 fd 路由 | **评估**：`pollfd.fd` 为 int 可容纳 encode fd；评估纯内核 fd 经 host poll 的可行性，低风险则实现，否则文档明示限制 |

### 2.3 N/A（非 fd 或 F-Stack 专属语义，不纳入）
`ff_zc_send`/`ff_zc_recv`（`FSTACK_ZC_*` 零拷贝 mbuf，无内核语义）、`ff_sysctl`、`ff_gettimeofday`、`ff_route_ctl`。

### 2.4 缺失 host 桥（需新增，仿 `ff_host_read/write`）
- `ssize_t ff_host_readv(int fd, const void *iov, int iovcnt)` → libc `readv`
- `ssize_t ff_host_writev(int fd, const void *iov, int iovcnt)` → libc `writev`
- `int ff_host_ioctl(int fd, unsigned long request, void *argp)` → libc `ioctl`（host 命名空间，用原始 Linux request）
- （若 dup 实现）`int ff_host_dup(int fd)` / 必要时 `int ff_host_dup2(int oldfd, int newfd)`

> `struct iovec` 在 FreeBSD/host 同 ABI 布局一致（`void* + size_t`），按既有 `sendmsg/recvmsg` 经验以 `void*` 透传到 host TU 再 cast，规避命名空间冲突。

## 3. 方案设计

### 3.1 readv / writev（主，低风险）
逐字节仿 `ff_read`/`ff_write`：
```c
#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(fd))
        return ff_host_readv(ff_kernel_fd_real(fd), iov, iovcnt);
#endif
```
- 仅 encode 内核 fd 路由 host；双栈 fd（F-Stack fd 值）照走 F-Stack（与 read/write 一致，应用面 fd 即 F-Stack fd）。
- 宏关 / coexist=0：函数体逐字节不变。

### 3.2 ioctl（主，中风险）
- 在 `linux2freebsd_ioctl` 翻译**之前**插入内核 fd 分支：`if (ff_is_kernel_fd(fd)) return ff_host_ioctl(real, request, argp);`（原始 Linux request，不翻译）。
- 双栈 fd：评估常用控制类 ioctl（如 `FIONBIO`/`FIONREAD`）是否需同驱动 host 侧（仿 `ff_fcntl` 双驱动）；以实测与最小必要为准，避免过度。
- va_arg 取 `argp` 的方式保持与现有一致。

### 3.3 dup / dup2（额外发现）
- `ff_dup`：`if (ff_is_kernel_fd(oldfd)) { int n = ff_host_dup(real); return n<0?-1:ff_kernel_fd_encode(n); }`
- `ff_dup2`：两端均内核 fd→host dup2 后返回 encode；一端内核一端 F-Stack 的混栈 dup2 语义不成立 → 明确拒绝（errno=EINVAL/EBADF）+ 文档限制。以实测为准。

### 3.4 select / poll（额外发现，评估为主）
- `ff_select`：encode 内核 fd ≥ `0x40000000` ≫ `FD_SETSIZE`(1024) → 无法置入 `fd_set`，**硬限制**。实测确认后写入文档（已知限制），不强行实现。
- `ff_poll`：`pollfd.fd` 可容纳 encode fd。评估"纯内核 fd 子集经 host poll、F-Stack fd 经 kern_poll、合并 revents"的复杂度与风险。低风险且不破坏现有则实现；否则文档明示限制（推荐内核 fd 用 epoll/kqueue 多路复用）。

> 全部改动 `#ifdef FF_KERNEL_COEXIST` 门控；宏关产物逐字节零回归（git stash 取基线 + nm/size diff 校验）。

## 4. 里程碑与门禁

| 里程碑 | 内容 | 门禁标准 |
|--------|------|----------|
| **M0** 调研冻结 | 本计划（gap 已实证） | gap 清单与代码一致；外网交叉验证 readv/writev/ioctl 双栈惯例 |
| **M1** spec 修订 | `kernel_event_support_spec/`(中英) 补 R10：现状缺口 D12-D15、方案、里程碑、测试点、review-gate | 中英对齐、lint 0 错、标注"R10 待实现"不当既成 |
| **M2** 实现 | lib：新增 host 桥 + readv/writev/ioctl 路由 + dup/dup2 + select/poll 处置 | 全程宏门控、注释精简 |
| **M3** 双编译零回归 | 宏开（新符号齐全、0 error）+ 宏关（无新符号、size=R9 基线、逐字节） | nm/size diff = 基线一致 |
| **M4** 单测 | cmocka：readv/writev/ioctl/dup（及 poll 若实现）host 桥与路由用例；双态 test_p1 | 宏开全 PASS（含新例）、宏关零回归（新例被门控排除） |
| **M5** 真机验证 | INET6-off helloworld + 内核侧 lo 测试；对内核 fd 实测 readv/writev/ioctl；F-Stack 侧不回归 | 内核侧功能正常、F-Stack 侧 200 不回归 |
| **M6** 三层架构+知识图谱（中英） | `docs/` 与 `docs/zh_cn/`：补 R10 入口、刷新行数/桥数、已知限制更新（readv/writev/ioctl 由限制改为已支持；select/poll 限制澄清） | 行数 wc -l 实测、桥数 grep 核对、中英对齐、无残留旧值 |
| **M7** 门禁汇总+提交 | leader 独立交叉复核全部门禁；英文简短 commit（lib+tests+spec+三层文档；排除 config.ini/Makefile 本地改动） | 全门禁 PASS、提交集精确 |

打回规则：任一门禁失败打回上一步重修，单步 bounce≤3，超则停转人工。

## 5. 测试点（实证，禁臆测）

- **UT**（cmocka，真实 socket/pipe/epoll）：
  - `ff_host_readv`/`ff_host_writev`：真实 socketpair/pipe 读写 iov，校验字节数与内容。
  - `ff_host_ioctl`：真实 socket `FIONBIO`/`FIONREAD` 生效。
  - `ff_host_dup`：dup host fd 后两 fd 同源可读写。
  - 路由层：encode 内核 fd 经 `ff_readv/writev/ioctl/dup` 命中 host 桥（可经真实 host fd 验证）。
- **IT/真机**：内核侧（127.0.0.1）对受管内核 fd 做 readv/writev/ioctl 行为正确；helloworld 不回归（内核侧 200、F-Stack 侧 200）。
- **零回归**：宏关 test_p1 全 PASS 且 R10 新例被宏门控排除；lib 宏关产物 size/nm = R9 基线。

## 6. 外网调研项（M0/M1）

- readv/writev 在用户态栈/内核栈共存的透传惯例（github f-stack issues、libuinet）。
- ioctl request 在 Linux vs FreeBSD 的差异，确认内核 host fd 必须用原始 Linux request。
- select/poll 对大 fd 值（>FD_SETSIZE）的限制，佐证 select 硬限制结论。

## 7. 风险

- R-1 ioctl 双栈 fd 同驱动范围过宽引入回归 → 仅对明确必要的控制 ioctl 同驱动，其余仅 encode 内核 fd 路由；以实测为准。
- R-2 dup2 混栈语义 → 明确拒绝并文档化，不臆造语义。
- R-3 poll 实现复杂度超预算 → 评估后若高风险则降级为文档限制，不强行实现（避免 bounce 超限）。
- R-4 iovec 跨命名空间 → 沿用 sendmsg/recvmsg 的 void* 透传经验。

## 8. 交付物

lib（ff_host_interface.c/.h、ff_syscall_wrapper.c）+ tests/unit + spec（中英）+ 三层架构/知识图谱（中英）+ 本 plan。English commit，排除 config.ini/Makefile 本地改动。
