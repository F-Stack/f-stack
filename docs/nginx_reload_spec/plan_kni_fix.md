# plan：graceful_reload 下开启 KNI 后 worker 无法启动（RX-35）

> 2026-10-10，第 4 版（计划门禁 PR-K4 已通过）。执行结果：代码审核 CR-K～CR-K5（CR-K4 打回 1 次），测试证据审计 TA→TA2（打回 1 次），文档审核 GD-K（FAIL）→ GD-K2（FAIL）→ GD-K3。**实现与本计划不一致的地方以代码为准，差异汇总见 §10**。台账在 `docs/nginx_reload_spec/work/kni-fix-20261010/`（仅本地，已被 gitignore 排除）。文中地址一律使用占位符。

## 1. 现象与证据（已实测）

| 场景 | 结果 | 证据 |
|---|---|---|
| 用户现场：18:44 以 kni=0 启动，常驻 primary 随之拉起；之后改为 `[kni] enable=1` 并重启 master | worker 打印 `vdev_scan(): Received 0 vdevs`，随后 `EAL: PANIC in ff_kni_alloc(): create kni ring failed!` | `evidence/02-user-run-*` |
| 干净环境下直接用 KNI 配置启动 | `veth0` 出现，worker 正常，HUP 完成 6 次转移 | `evidence/01-start-*` |
| 定向复现：kni=0 启动 → 只停 master → 改为 kni=1 → 再启动 master | 打印 `resident slim primary found, reusing`，所有 worker panic，可稳定复现 | `evidence/03-repro-*` |

## 2. 根因（调研员 A/B 与 leader 三方核对，以代码为准）

- `ngx_process_cycle.c: ngx_ff_slim_primary_ensure()` 只要 primary 存活就复用。存活判定只检查 pidfile、`kill(pid,0)` 和 comm 三项，**不比较 primary 启动时所用的 f-stack 配置**；primary 只在 spawn 时读一次配置。
- 设备侧共享资源都由 primary 按**它自己的**配置创建，包括端口/队列、mbuf 池、ring，以及 KNI 的 virtio_user 与 `kni_ring_<port>`/`kni_inject_<port>`。secondary 则按**它自己的**配置去 lookup，查不到 KNI ring 时 `rte_panic`（`ff_dpdk_kni.c: ff_kni_alloc()`）。
- 与 35bf93dc1 无关（经 `git show --stat` 核实，该提交未改动这两个文件）。这是 M1 常驻 primary（13d1b4ec7）遗留的缺口；RT-12 只覆盖了「全新启动 + KNI」的场景。
- 手册「Resident primary failure」中写的 "stop, then start" 在 primary 存活时无效；文档也没有说明修改配置后如何生效。

## 3. 修复设计（只作用于 graceful_reload=1 分支）

### 3.1 primary 侧配置指纹 `ff_primary_conf_digest(conf, &digest, &kni_enable)`（lib/ff_config.c，单测）

- 解析：调用 lib 的 `ini_parse()`，handler 独立实现：不打印、不修改 `ff_global_cfg`，每行都返回 1，不中止解析。`ini_parse` 返回非 0（文件打不开或有语法错误）时，本函数返回 -1，调用方按「无法核实」处理。这样空白裁剪、`;` 行内注释、section/name 匹配都与 `ff_load_config()` 使用同一个解析器；`kni_enable` 与 lib 一样用 `atoi`（M6）。
- 摘要：按出现顺序，对 `section\0name\0value\0` 累积计算 FNV-1a 64。
  - `[dpdk]`：全部纳入，只排除 6 个本进程键：`log_level`、`fstack_log_level`、`fstack_log_file_prefix`、`idle_sleep`、`pkt_tx_delay`、`reload_heartbeat_timeout_ms`（PR-K2 已抽查核实）。`file_prefix`、`extra_eal_args`、`allow`、`nb_vdev` 都纳入，所以 EAL 运行目录一旦变化，摘要一定变化。
  - `[kni]`：纳入 `enable`、`owner_proc_id`、`kernel_packets_ratelimit`（最后一项由 primary 的 `kni_process_tx` 读取）。`method`、`tcp_port`、`udp_port`、`console_*`、`general_*`、`kni_action` 都在 worker 侧使用，不纳入。
  - `[portN]`/`[vdevN]`/`[bondN]`/`[vlanN]`：全部纳入，只排除地址类与 FreeBSD 本进程键：`addr`、`netmask`、`broadcast`、`gateway`、`addr6`、`prefix_len`、`gateway6`、`vip_*`、`if_name`、`ipfw_pr`。
  - `[freebsd.*]`/`[pcap]`/`[stack]`/`[rss_check]` 不纳入。其中 `[stack] kernel_coexist` 只在本进程生效，实现阶段用 grep 核实。

### 3.2 统计 primary 的存活使用者 `ff_primary_users(runtime_dir)`（lib/ff_config.c，单测）

- 枚举 `runtime_dir/mp_socket_*`，跳过不带后缀的 `mp_socket`。
- 对每一项用 `AF_UNIX/SOCK_DGRAM` 尝试 `connect()`：只有返回 `ECONNREFUSED` 或 `ENOENT` 才算失效，其余结果都计为使用者（fail-safe）。目录无法读取时返回 -1。
- 已知盲区：secondary 在 fork 之后、EAL 建 socket 之前的这段时间无法被统计到。对策是发信号前再扫描一次，并把这一残余写进文档。

### 3.3 sidecar `/var/run/ff_slim_primary.conf`

- 写入时机：primary 子进程在 `ff_init()` 成功后、写 pidfile 之前写入。
- 内容：`pid`、`start_time`（取自 `/proc/self/stat` 第 22 字段）、`digest`、`kni`、`runtime_dir`。**`runtime_dir` 取 EAL 实际使用的值**，由 lib 新增的 `ff_eal_runtime_dir()`（ff_init.c，返回 `rte_eal_get_runtime_dir()`）提供，不再根据配置推算。
- 写法：临时文件以 `O_CREAT|O_EXCL|O_NOFOLLOW` 打开，写完后 `rename`；读取时同样带 `O_NOFOLLOW`。写入失败则 `_exit(2)`，不 post 信号量。
- 有效性：只有 `pid` 等于 pidfile 中的 pid，且 `start_time` 与 `/proc/<pid>/stat` 一致时才视为有效，否则视为缺失。

### 3.4 每代固定使用启动时的 f-stack 配置快照（MUST-1）

- master 用全局变量 `ngx_ff_conf_snapshot` 记录当前快照路径：`/var/run/ff_nginx_fstack.<master_pid>.<seq>.conf`。快照是用户 `fstack_conf` 的只读副本（0600，先写临时文件再 rename）。
- 常驻 primary 的 spawn 和 graceful 模式下 worker 的 `ff_mod_init` 都改为使用快照路径。指纹基于快照计算，因此 sidecar 中的摘要与 primary 实际读到的内容完全一致，消除了 TOCTOU。
- 全局路径只在**所有校验通过之后**才切换：首次启动在 ensure 判定为复用或重建之后；HUP 在预检通过且 `ngx_init_cycle` 成功之后。若新的 nginx.conf 改了 `fstack_conf` 路径，则对新路径另做快照并再比较一次，不一致就按现有语义 abort，全局路径保持不变。切换成功后删除上一份快照。
- 效果：HUP 被拒绝或中止时，G_old 中崩溃后被重拉的 worker 仍读旧快照，不会进入 panic 循环；只改了 ini、没有发 HUP 而 worker 崩溃时也一样。
- master 退出时（`ngx_master_process_exit`）删除当前快照。graceful_reload=0 时不做快照，路径保持不变。
- 【v4】快照在启动入口（`ngx_process_cycle.c` 中 graceful 检测之前）就生成。此后的 detect、nb_procs、指纹计算全部基于快照，以消除启动阶段的 TOCTOU（PR-K3 SHOULD-1）。
- 【v4】临时文件用 `O_CREAT|O_EXCL|O_NOFOLLOW` 打开，文件名带 pid 和计数，保证唯一。以下所有退出或中止路径都要先删除当前快照和待定快照，再退出：ensure 拒绝或超时、拓扑校验的 `exit(2)`、启动时 attach 失败、HUP 时 `ngx_init_cycle` 失败、路径变更后比对不一致导致的 abort。另外，master 启动时会清理 `/var/run/ff_nginx_fstack.<pid>.*` 中 pid 已不存在、或进程 comm 不是 nginx 的残留文件（PR-K3 SHOULD-2、6）。
- 【v4】快照路径放在静态缓冲区里，不从 cycle pool 分配，删除前判空。权限 0600 依赖 worker 以 root 运行（f-stack 本身就要求如此），手册中写明（NIT-1、2）。

### 3.5 首次启动、USR2 新 master 的 ensure，以及 spawn 超时后的复用分支

先生成快照并计算指纹。若 primary 存活，读取 sidecar，再用纯函数 `ff_primary_reuse_check(sidecar_ok, same_digest, users, inherited)`（lib/ff_config.c，单测）决定处理方式：

| sidecar 有效 | 摘要相同 | 使用者 | 继承启动（USR2） | 判定 |
|---|---|---|---|---|
| 是 | 是 | 任意 | 任意 | 复用 |
| 否 | — | — | — | 拒绝 |
| 是 | 否 | ≠0 或 -1 | 任意 | 拒绝 |
| 是 | 否 | 0 | 是 | 拒绝 |
| 是 | 否 | 0 | 否 | 重建 |

- **拒绝**：打印 EMERG，内容包括 pid、两边的 kni、使用者数和处理指引，然后 `exit(2)`，不发送任何信号。USR2 场景下老 master 会打印 `ff usr2: new binary exited before taking over` 并复位（PR-K2 已核实）。
- **重建**：
  1. 打印 NOTICE `graceful_reload: restarting the resident slim primary (pid N): its fstack config differs`；
  2. 用 sidecar 中的 `runtime_dir` 再扫描一次使用者，并核对 comm 和 start_time，确认后发 SIGTERM；
  3. 最多等待 `NGX_FF_SLIM_PRIMARY_STOP_SEC`（10 s），直到 `/proc/<pid>` 消失，或者状态为 `Z` 且 `/proc/<pid>/task` 只剩线程组 leader（多线程进程的 leader 先变成 Z 时，fd 可能还没释放，PR-K3 SHOULD-3）。超时则 EMERG 并 `exit(2)`，不升级为 SIGKILL。
  4. 删除 pidfile 和 sidecar，按原流程 spawn。
- spawn 超时后的 `reusing externally-started slim primary` 分支同样要读取并比较 sidecar，不一致则 EMERG 并 `exit(2)`。
- 安全依据：
  - igb_uio 在最后一个 fd 关闭时调用 `pci_clear_master()`（`dpdk/kernel/linux/igb_uio/igb_uio.c: igbuio_pci_release()`）。已确认没有使用者，所以 primary 退出即满足这个条件。
  - 新 primary 启动时执行 `clear_hugedir()`；mp_socket 在 bind 前会先 unlink；tap 设备随 fd 关闭而注销。重新 spawn 前 `veth0` 是否已消失，需要实测确认。
  - vfio-pci 只做文档论证（release 时会关闭设备），本机未测试。
  - `!ngx_inherited` 不作为安全屏障，安全性由使用者统计保证。

### 3.6 HUP 预检（`ngx_ff_reload_hup()`）

- 位置：放在 USR2 回滚分支、in-flight 拒绝、binary-upgrade 拒绝、`ngx_ff_reload_shm == NULL` 拒绝**之后**，`ngx_ff_reload_set_log()` 与 T0→T1 的 FSM 事件**之前**。
- 行为：从当前 `fstack_conf` 生成待定快照并计算指纹，与 sidecar 比较。sidecar 缺失或摘要不同时：
  - 打印 `graceful reload rejected: fstack config differs from the resident slim primary (kni %d -> %d); restart nginx and the slim primary to apply it`；
  - 删除待定快照；
  - 调用 `ngx_ff_reload_note_hup_rejected()`，与其他拒绝路径保持一致；
  - 返回 `NGX_DECLINED`。
  rt27 中「FSM 计数不变」的判据是：本次 HUP 之后，`graceful reload fsm: ... -> ...` 转移行的数量不增加（PR-K3 NIT-3）。
  此时 FSM 不发生转移，rt23 依赖的拒绝文案也不受影响。
- 预检通过时，待定快照在 init_cycle 成功后切换为当前快照（见 §3.4）。

### 3.7 lib 侧兜底提示（ff_dpdk_kni.c）

secondary 侧 lookup 返回 NULL 时，panic 文本改为：`kni ring %s not found: the primary did not create it (is [kni] enable=1 in the primary's config?)`。仍然调用 `rte_panic`：lib 不应假设上层是 nginx，而 nginx 侧已由预检和快照覆盖。

### 3.8 不变的部分

- graceful_reload=0 不进入上述任何路径，也不做快照。
- 摘要相同时，复用、HUP、USR2 的行为都不变。
- 新增的 lib 函数在 `ff_api.h` 中声明，附简短接口注释。它们属于 HOST 目标文件，本身就是全局符号，不需要修改 symlist。

## 4. 测试与回归矩阵

- **单测**（tests/unit/test_ff_config.c）
  - `ff_primary_conf_digest`：
    - 等价写法（空白、行内注释）的摘要相同；
    - 以下任一项变化都会改变摘要：kni 0/1、owner_proc_id、lcore_mask、file_prefix、port lcore_list；
    - 排除键（idle_sleep、addr、ipfw_pr）变化不改变摘要；
    - `enable = 1` 能正确解析为 kni_enable=1；
    - 文件不存在时返回 -1。
  - `ff_primary_users`（在临时目录中构造）：
    - 已 bind 的存活 DGRAM socket 计 1；
    - bind 后关闭的 socket（ECONNREFUSED）计 0；
    - 不带后缀的 `mp_socket` 不计；
    - 目录不存在时返回 -1。
  - `ff_primary_reuse_check`：覆盖判定表的全部分支。
  - 全量回归：`make -C tests/unit test`、`test_reload_harness`、`make -C tests/integration test`、`check_ring_name_mirror.sh`。
- **harness 扩展**
  - `reload_supervisor.py` 新增 `launch`：只能在 phase=running 时调用；必须是同一个 stack；重新校验 sha256；环境变量的构造方式与 start 一致，并显式剔除 `NGINX`；不改写 `self.launcher`。
  - `reload_runtime.sh` 新增 `relaunch_master`，以「出现新的 master pid 和 start_time，并且日志中有预期文案」作为判据。
  - `test_reload_harness.py` 补充 launch 的用例：阶段约束和 sha 校验。
- **新用例 rt27**：没有 `/dev/vhost-net` 时，与 rt12 一样记为 SKIP，并标注 LIMITED；断言用的文案在实现阶段逐字固定。步骤如下：
  1. 以 kni=0 启动，得到 primary P1，HTTP 200。
  2. 把 ini 改为 kni=1 后发 HUP：出现 `graceful reload rejected: fstack config differs`，FSM 计数不变，worker pid 不变，HTTP 200。再 TERM 一个 G_old worker：被重拉的 worker 正常（读的是旧快照），HTTP 200。
  3. ini 保持 kni=1，发 USR2：新 master 报 EMERG 后退出，老 master 打印 `new binary exited before taking over`。然后把 ini 改回 kni=0 并发 HUP：6 次转移完成，且**不出现** `HUP during a binary upgrade, rolling back`。
  4. 有使用者时拒绝：stack 保持运行，ini 改为 kni=1，用另一份 nginx conf（独立的 pid 和 error_log）launch 第二个 master：出现 EMERG `still used by`，第二个 master 退出，原 stack 不受影响，HTTP 200。
  5. sidecar 缺失时拒绝：用 `mv` 把 sidecar 移走，只停 master，然后 relaunch：出现 EMERG，primary 没有被触碰（P1 的 pid 与 start_time 都不变）。之后把 sidecar 移回原处。被拒绝的 master 判为「新 pid 出现过并且已经退出，日志中有对应文案」（SHOULD-7）。
  6. 重建（RX-35 主场景，kni 0→1）：ini 保持 kni=1，relaunch，出现 `restarting the resident slim primary`，新 primary P2 与 P1 不同，P1 已退出，`veth0` 出现，有 2 个 worker，HTTP 200。
  7. 配置不变时发 HUP：6 次转移，`veth0` 仍在。
  8. 反向重建：只停 master，ini 改为 kni=0，relaunch：出现 `restarting`，primary P3 与 P2 不同，`veth0` 消失，HTTP 200。
  9. 停止超时（对 P3 操作，最后执行）：只停 master，ini 改为 kni=1，用 supervisor 的 `STOP` 暂停 P3，然后 relaunch。约 10 s 后出现 EMERG `did not exit`，没有发送 KILL，被拒绝的 master 已退出。接着发 `CONT`：P3 因挂起的 TERM 退出，属于预期结果，不计为失败。
  10. stop_stack（确认没有残留的快照文件）。
- **实机回归**（构建 K，生产形态，客户端为 f-stack-client）
  - IPv4：precheck、baseline、rt01、rt02、gr0、rt23、rt25、rt12、rt27、rt30、rt31；
  - IPv4 rv9 30 轮；
  - IPv6：precheck、rt01、rt02、rv9 20 轮。
- **用户现场**：在 `nginx-gr-live` 上复现「kni=0 时 primary 已常驻 → 改为 kni=1 → 重启 master」，要求自动重建并成功启动；HUP 期间短连接 0 失败，50 MB 文件 md5 一致；之后保持运行。现场证据交 TA 审计。前提：kni=0 的那个常驻 primary 必须由构建 K 拉起，因为旧构建拉起的 primary 没有 sidecar，按判定表会被拒绝（PR-K3 SHOULD-4）。
- **升级影响**（写入手册）：从旧构建升级到构建 K 时，必须整体停机后重启，常驻 primary 也要先停掉。旧构建的 primary 没有 sidecar，所以 USR2 热升级会被拒绝，升级过程中会有一次服务中断（PR-K3 SHOULD-5）。

## 5. 团队编排、超时与打回

| 阶段 | 执行者 | 独立审核 |
|---|---|---|
| 计划 | leader | PR-K（FAIL）→ PR-K2（FAIL）→ PR-K3（FAIL）→ PR-K4（PASS） |
| 代码、单测、harness/supervisor | leader | CR-K（PASS）、CR-K2、CR-K3（增量 PASS）、CR-K4（FAIL）→ CR-K5（PASS） |
| 构建与单测 | leader 兼任 | 失败则打回编码阶段 |
| 实机回归与用户现场 | leader 执行 | TA（FAIL）→ TA2（PASS） |
| 文档 | leader | GD-K（FAIL）→ GD-K2（FAIL）→ GD-K3 |
| 终门禁 | — | G-K |

- 子 agent 一律使用同步 `task`（code-explorer，只读），每次都设置 `max_turns`；不使用异步成员。子 agent 出现异常时，另起新实例重做，并遵守写审分离。
- 任一门禁失败都打回上一步。同一步骤最多打回 3 次，超过就停止，交人工决策。打回计数记在 `state.json`。
- harness 运行期间严禁修改源文件。

## 6. 规约

- 文件删除、进程停止、权限修改只能通过规约脚本完成（`rm_tmp_file.sh`、`kill_process.sh`、`chmod_modify.sh`）。lib 和 nginx 的注释保持简短英文，新增行不超过 80 列。
- 提交分两次：代码+测试一次，文档一次。commit message 用 1~3 句英文；不提交 config.ini，不 push。
- 文档同步：06 §10 新增 RX-35 及其残余；08 §2.3.3 补 K 行和 rt27；09 新增 §30；00 的 I 行；英文镜像；用户手册「Resident primary failure」与「KNI notes」（说明配置变更如何生效、从旧构建升级的操作步骤、vfio-pci 限定，并订正 "stop, then start"）；Layer3 与知识图谱中的新 API。
- 提交前做真实地址扫描：IPv4 用 `\b(\d{1,3}\.){3}\d{1,3}\b`，IPv6 用 `2402:[0-9a-f:]+`；只放行 `127.0.0.1`、`192.168.*` 示例和 `fe80::`。

## 7. 第 1 轮审核（PR-K）处置

| 编号 | 处置 |
|---|---|
| M1 | HUP 预检提前到 T1 之前（§3.6），并通过快照（§3.4）覆盖 G_old 重拉 |
| M2 | sidecar 记录 primary 的实际 runtime_dir；sidecar 缺失或不一致时一律不发信号（§3.3、§3.5） |
| M3 | 改为 connect 探测并按 fail-safe 计数，发信号前复扫（§3.2） |
| M4 | supervisor 增加 `launch`，并纳入 CR（§4） |
| M5 | 摘要覆盖所有设备侧项，只排除经核实的本进程键；不一致即视为致命（§3.1） |
| M6 | 使用 lib 的 `ini_parse` 加独立 handler，配等价性单测（§3.1、§4） |
| S1~S7 | 分别见 §3.5、§3.5、§3.3/§3.4、§3.8、§3.7、§4、§5/§6 |

## 8. 第 2 轮审核（PR-K2）处置

| 编号 | 处置 |
|---|---|
| MUST-1 | 新增 §3.4 配置快照：每一代固定使用自己启动时的配置，G_old 重拉不会再 panic 循环；改 fstack_conf 路径的残余也随之消除 |
| MUST-2 | runtime_dir 改取 primary 的 EAL 实际值（`ff_eal_runtime_dir()`）；摘要覆盖 file_prefix、extra_eal_args、allow、nb_vdev；删除按配置推算的逻辑 |
| MUST-3 | rt27 第 3 步改为先改回 kni=0 再发 HUP，并断言不出现 rollback 文案 |
| SHOULD-1、2 | 纳入 `kernel_packets_ratelimit`；`[vlanN]` 已归类（§3.1） |
| SHOULD-3 | 预检位置已固定（§3.6） |
| SHOULD-4 | 超时复用分支也做比较（§3.5） |
| SHOULD-5 | 见 §4 的 launch 设计 |
| SHOULD-6 | 判定函数改为纯函数并配单测；rt27 第 4~6 步覆盖三条安全路径；手册补充升级步骤 |
| SHOULD-7 | vfio-pci 只做论证，限定写入文档 |
| NIT | 独立 handler 与解析错误、ff_api.h 声明、O_EXCL/O_NOFOLLOW、kernel_coexist 核实、ipfw_pr 排除、rt27 SKIP 语义，均已处理 |

## 9. 第 3 轮审核意见（PR-K3）处置（第 4 版，计划阶段已打回 3 次，达到上限；再不通过即停止）

| 编号 | 处置 |
|---|---|
| MUST-1 | rt27 调整顺序：主场景重建（0→1）放到第 6 步，停止超时改为第 9 步对 P3 执行，删去会引起歧义的括注；CONT 后 P3 退出属于预期 |
| SHOULD-1 | 快照提前到 graceful 检测之前生成，所有扫描都基于快照（§3.4） |
| SHOULD-2、6 | 所有退出和中止路径都删除快照；启动时清理残留快照；临时文件使用 O_EXCL 并保证文件名唯一（§3.4） |
| SHOULD-3 | 等待条件改为「/proc 消失」，或「Z 状态且只剩 leader」（§3.5） |
| SHOULD-4、5 | 写明用户现场的前提和升级影响（§4，并同步到手册） |
| SHOULD-7 | 被拒 master 的判据改为「新 pid 出现过并已退出，且有对应日志文案」（rt27 第 5 步） |
| NIT-1~5 | 静态缓冲区与判空、0600 写入手册、note_hup_rejected 与 FSM 计数判据（§3.6）。台账目录真实存在于 `docs/nginx_reload_spec/work/kni-fix-20261010/`，因被 gitignore 排除，搜索工具可能看不到，可直接 read_file 读取 |

## 10. 实现与本计划的差异（以代码为准）

| 计划位置 | 计划写法 | 实现 |
|---|---|---|
| §3.4 快照命名、变量 | `ff_nginx_fstack.<master_pid>.<seq>.conf`，`ngx_ff_conf_snapshot` | `ff_nginx_fstack.<pid>.<start_time>.<seq>.conf`；变量为 `ngx_ff_conf_snap`（当前）和 `ngx_ff_conf_snap_next`（HUP 待定） |
| §3.4 首次启动的切换 | ensure 判定之后切换 | 启动时直接写入 `ngx_ff_conf_snap`，后面的检测都基于它；切换只发生在 HUP 中 |
| §3.4 快照生成时机 | 在 graceful 检测之前生成 | 先用原文件做 graceful 检测，为 1 时才生成快照，再用快照复检（graceful=0 不生成快照） |
| §3.4 残留清理条件 | pid 不存在或 comm 不是 nginx | 按文件名中的 pid 和起始时间判断：进程不在了，或起始时间不符，或 pid 与自己相同；不看二进制名 |
| §3.5 发信号 | 核对 comm/start_time 后发 SIGTERM | `pidfd_open` → 核对 → `pidfd_send_signal(SIGTERM)`；pidfd 不可用时拒绝，日志注明 `pidfd unsupported` |
| §3.5 等待判据 | /proc 消失，或 Z 且只剩 leader | 也接受起始时间变化、X 状态；leader 判定用 `ngx_ff_proc_threads() <= 1` |
| §3.5 拒绝范围 | 判定表 | 另外包括 spawn 超时后 externally-started 分支（`no_restart=1`）；超时拒绝时 SIGTERM 已发出，处于挂起状态 |
| §3.6 记录缺失时的 HUP 文案 | 与摘要不同时同一条 differs 文案 | 单独一条：`graceful reload rejected: the resident slim primary (pid N) has no valid record; restart nginx and the slim primary` |
| §4 `relaunch_master` | 放在 reload_runtime.sh，以新 pid/start_time 判定 | 放在 test_graceful_reload.sh，只调用 supervisor launch；被拒的判定由 `expect_refused` 完成：日志有对应文案、pid 文件中有 pid、15 s 内退出 |
| §4 rt27 第 6 步「2 个 worker」 | 字面 2 | 断言为 `$WORKERS` |
| §4 rt27 第 9 步 | 约 10 s 后 EMERG，没有 KILL | 40 s 内出现 `did not exit within`；P3 仍存活；只统计 STOP 前所取 evmark 之后的 `signal_requested` KILL，结果为 0；CONT 后 15 s 内退出。10 s 本身没有测量（日志用的是缓存时间） |
| §4 回归矩阵 | rv9 IPv4 30 轮、IPv6 20 轮 | 先按计划跑完，又补跑 IPv4、IPv6 各 100 轮；rt12、rt27 在 9 项批量之外单独运行 |
| §4 rt27 证据 | — | 每步输出 `rt27 N:` 证据行，第 10 步输出 stop_stack 前后的快照目录 |

