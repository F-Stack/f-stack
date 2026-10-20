# 04 F-Stack Current State Analysis: nginx Adaptation Layer and Library Facts, and the List of Obstacles to Lossless Reload (English)

> **English translation** of `docs/nginx_reload_spec/zh_cn/04-fstack-current-analysis.md` (v1.5). The Chinese text is
> authoritative; where the two differ, the Chinese original governs.
> Translated 2026-09-30.

| Item | Value |
| --- | --- |
| Document ID | 04 |
| Title | Code probing of the current F-Stack nginx adaptation layer and library (precondition facts for lossless reload + 8 code-level obstacles) |
| Version | v1.5 (on v1.4: **final gate G-D rework F-01 cross-document sweep** — the R-01 code fix (`lib/ff_dpdk_if.c:669-673`, per-generation pool `cache_size=0`) has landed; this document was swept end to end and **no "per-generation pool not zeroed / still 256" wording needs rewriting** (the §5-2 F2 "dirty EAL" disproved entry is unrelated to R-01 and is left as is), so only the version header is synced. v1.3 = **corrected per the `plan_cross_audit` G-A verdict R-25** — the last item of §3.5, "the dispatch callback is not used by nginx", is outdated: it was unused in the M0 period, but **from M3 nginx registers a flow_map dispatcher** (`ngx_ff_module.c:492`)) |
| Date | 2026-08-18 (v1.1~v1.3 additions: 2026-09-17) |
| Status | pending human audit |
| Source artefact | `work/probe-fstack-current.md` (prober `probe-fstack`, filed 2026-08-18; read-only probing, no code changed). This document is the formalised rewrite: all factual evidence kept (file:line) together with the unconfirmed markings; the "probing method and list of files read" is kept as §1 so the evidence stays traceable |
| Line-number check | The line-number anchors in this document were re-checked and corrected against HEAD `28e751259` on 2026-09-17 |
| Revision notes | v1.1 (2026-09-17): corrected by this round's spec×code cross-audit (`plan_audit`) — the nginx adaptation layer and library line-number anchors rewritten after re-checking against HEAD `28e751259` (the M1~M6 implementation shifted `lib/ff_dpdk_if.c`/`lib/ff_api.h`/`lib/ff_config.c`/`ngx_ff_module.c`/`ngx_process_cycle.c` systematically), correcting 2 fact descriptions that the implementation has since overturned (the worker QUIT branch's `ngx_set_shutdown_timer` was restored by M4; the worker-0 hardcoded primary was removed by M1 under `graceful_reload=1`), and marking the F2 "dirty EAL" mechanism as disproved. **v1.2 (2026-09-17): corrected per the audit-anchor independent re-check (`work/audit-G1-fix-review-anchor.md`, bounce-1)** — the §3.2 multi-process path anchors of the send/receive model changed to `ff_dpdk_if.c:562-601` (taking the lcore at `:572`, lcore_list index → queue id at `:584-596`, §4 obstacle 7 synced); the §3.1 `ff_stop_run` anchor for setting stop_loop changed to `:3830`; the §5-6 KNI anchor changed to `:3658-3676` with the configuration key corrected to `[kni] enable`; the §2.1 `ngx_ff_graceful_reload` anchor changed to `:49`; §3.3 message types extended with `FF_RELOAD` (10 types in total); a "M0 baseline" note added to the §1 file list. **v1.3 (2026-09-17): corrected per the `plan_cross_audit` G-A verdict R-25** — ① the last §3.5 item "dispatch callback ... not used by nginx" annotated in place: that statement holds only for M0~M2; from M3 nginx registers a flow_map dispatcher (`app/nginx-1.28.0/src/event/modules/ngx_ff_module.c:492`); ② after re-checking, the three §3.2 anchors (including taking the lcore at `:572`) need no correction; ③ the document header declaration converged with R-11 to a per-item verifiable wording (this document has no blanket fallback declaration, so nothing needs rewriting). **v1.4 (2026-09-18): final gate G-D rework F-01 cross-document sweep** — the R-01 code fix has landed; the sweep found no R-01 wording here, so only the version header is synced. **v1.5 (2026-09-18): R-01 mechanism error wrap-up (G-D "must be completed before commit")** — the sweep found no landing point for that mechanism error here (the §5-2 F2 "dirty EAL" disproved entry is unrelated to R-01 and is left as is), so only the version header is synced |

Probing scope: `/data/workspace/f-stack` (DPDK 24.11.6 + FreeBSD 15.0), nginx adaptation `app/nginx-1.28.0/`, core library `lib/`.

Related: [00 Overview](overview.md) | [03 Legacy Scheme Verification](legacy-solution.md) | [05 ld_preload Alternative Route](ld-preload-alternative.md) | [06 Solution Design](solution-design.md)

---

## 1. Probing method

Files actually read (in full or in key sections):

- `app/nginx-1.28.0/src/event/modules/ngx_ff_module.c` (full, the syscall interception layer)
- `app/nginx-1.28.0/src/event/modules/ngx_ff_host_event_module.c` (full, the host epoll module)
- `app/nginx-1.28.0/src/os/unix/ngx_process_cycle.c` (M0 baseline read L28-520, L755-1278; the line numbers in this document have been corrected against HEAD per §2.2/§2.3/§2.5)
- `app/nginx-1.28.0/src/event/ngx_event.c` (L655-774), `src/event/ngx_event.h` (L395-454)
- `app/nginx-1.28.0/src/core/ngx_connection.c` (L14-73, L460-570)
- `app/nginx-1.28.0/src/os/unix/ngx_channel.c` (L195-255)
- `app/nginx-1.28.0/src/http/ngx_http_core_module.c`, `src/http/ngx_http.c` (located by search)
- `lib/ff_api.h` (full), `lib/ff_init.c` (full), `lib/ff_msg.h` (full)
- `lib/ff_dpdk_if.c` (HEAD key sections L500-960, L1480-1600, L2000-2200, L2470-2720, L2900-3200, L3400-3820)
- `lib/ff_syscall_wrapper.c` (L900-960 `ff_socket`)
- `lib/ff_freebsd_init.c` (L260-370 `ff_freebsd_init`)
- `lib/ff_kern_timeout.c` (L1245-1315, the `ff_hardclock` family)
- `lib/ff_config.c` (L1022-1130 `[dpdk]`/`[kni]` configuration parsing; L1182-1339 `dpdk_args_setup`; L1340-1375 `proc_type` parsing)
- `tools/compat/ff_ipc.c`, `tools/compat/ff_ipc.h` (full)

Keywords searched (grep evidence): `ff_mod_init|ff_run`, `NGX_HAVE_FSTACK|ngx_ff`, `fstack_conf|belong_to_host|SOCK_FSTACK`, `rte_eal_init|RTE_PROC_PRIMARY|proc_type`, `reuseport`, `dispatch_ring|ff_inpkt`, `ff_hardclock|rte_timer_manage`, `ff_socket|ff_getmaxfd`, `kernel_network_stack`, `ff_freebsd_init`.

Everything was read-only; no write operation was run and no git write command was executed.

## 2. nginx adaptation layer fact list

### 2.1 The adaptation changes F-Stack made to nginx (file list)

New files (F-Stack specific):

- `src/event/modules/ngx_ff_module.c`: the libc symbol interception layer plus `ff_mod_init`.
- `src/event/modules/ngx_ff_host_event_module.c`: the host-side (Linux kernel epoll) event module.

Modified files (relative to official nginx 1.28.0, inserted through `#if (NGX_HAVE_FSTACK)` / `NGX_HAVE_KQUEUE || NGX_HAVE_FSTACK`):

- `src/os/unix/ngx_process_cycle.c` (the core change of the process model / reload path, see §2.2/§2.5)
- `src/os/unix/ngx_process_cycle.h:40-50` (the `NGX_FF_PROCESS_NONE/PRIMARY/SECONDARY` enum plus the `ngx_ff_process` global; M1 added `NGX_FF_PROCESS_SLIM_PRIMARY :45` and `ngx_ff_graceful_reload :49`)
- `src/os/unix/ngx_channel.c:216-218, 230-234` (channel events with `belong_to_host=1`)
- `src/event/ngx_event.c:673-677, 742-747` (extra initialisation of the host event module)
- `src/event/ngx_event.h:140, 406-446` (the `belong_to_host` bit plus dual-track `ngx_add_event`/`ngx_del_event` inline dispatch and `ngx_ff_process_host_events`)
- `src/core/ngx_connection.c:14-52` (`ngx_ff_skip_listening_socket()`), `src/core/ngx_connection.c:1310` (new connections decide `belong_to_host` by `is_fstack_fd(s)`)
- `src/core/ngx_connection.h:93` (`belong_to_host:1`)
- `src/core/nginx.c:35, 161-165, 1715` plus `src/core/ngx_cycle.h:124` (the `fstack_conf` directive, storing the f-stack config.ini path)
- `src/http/ngx_http_core_module.c:298-302` plus `ngx_http_core_module.h:206` plus `src/http/ngx_http.c:1890` (the `kernel_network_stack` directive: choose the kernel stack or the F-Stack stack per server)
- `src/event/ngx_event_connect.c:46-47` (upstream connections decide by `pc->belong_to_host` whether to create with `SOCK_FSTACK`)
- `src/stream/*`, `src/mail/*` have the same `kernel_network_stack` (`ngx_stream.c:1049`, `ngx_mail.c:351`, etc.)
- `src/os/unix/ngx_recv.c/ngx_send.c/ngx_readv_chain.c/ngx_writev_chain.c` etc.: `#if (NGX_HAVE_KQUEUE) || (NGX_HAVE_FSTACK)` (reusing the kqueue branch's ready semantics)
- Build system: `auto/options:182,219,457` (`--with-ff_module`), `auto/modules:58-61` (defining `NGX_HAVE_FSTACK`, `SOCK_FSTACK=0x1000`), `auto/sources:112-113` (KQUEUE_MODULE/SRCS extended with the two ff files), `auto/make:22-43` (linking `$FF_PATH/lib/libfstack` whole-archive)

### 2.2 Process model (master / worker / when ff_init runs)

- The master process does **not** do ff_init / DPDK initialisation: `ngx_master_process_cycle` contains no `ff_mod_init` call; the main loop is purely signal-driven `sigsuspend` (`src/os/unix/ngx_process_cycle.c:155-299`, `sigsuspend` at `:299`). The master's `ngx_ff_process == NGX_FF_PROCESS_NONE` (default 0).
- The master skips creating every F-Stack-domain listening socket: `ngx_ff_skip_listening_socket()` returns 1 directly in the master (`NGX_FF_PROCESS_NONE`) branch, skipping AF_INET/INET6+STREAM/DGRAM sockets (`src/core/ngx_connection.c:23-41`; call sites `ngx_connection.c:481`, `:788`).
- Workers are created by a standard fork: `ngx_start_worker_processes` → `ngx_spawn_process(cycle, ngx_worker_process_cycle, i, ...)` (`ngx_process_cycle.c:2047`); the fork happens before the worker does ff_init.
- **[After the fork each worker runs ff_init independently]**: `ngx_worker_process_init` calls `ff_mod_init(fstack_conf, worker, worker==0)` (`ngx_process_cycle.c:2936`). With `graceful_reload=0` (the default), worker 0 → `--proc-type=primary`, worker i>0 → `--proc-type=secondary` (`ngx_process_cycle.c:2931/2933`; `ngx_ff_module.c:496-515` `ff_mod_init` assembles the arguments).
  > **Note (corrected 2026-09-17)**: after M1, with `graceful_reload=1` all workers are secondaries plus a resident slim primary (`ngx_ff_module.c:496-527`, `ngx_process_cycle.c:2929/2933`); the `graceful_reload=0` branch keeps the original description above verbatim.
- The master synchronises worker 0's initialisation with POSIX shm plus an unnamed semaphore: `mmap + sem_init(pshared=1)`, the master's `sem_timedwait` waits at most 15 s, and on timeout the master exits with code 2 (`ngx_process_cycle.c:2024-2099`); worker 0 calls `sem_post` after `ff_mod_init` succeeds (`:2952-2953`).
- Listening sockets are created inside each worker: after `ff_mod_init` succeeds the worker calls `ngx_open_listening_sockets(cycle)` (`ngx_process_cycle.c:3147`; 2026-09-22 sync: the original `:2956` was a line-number drift, the real call site has been corrected). At this point `ngx_socket(...)` goes through the libc-intercepted `socket()` → `ff_socket()` (see §2.4 on the fd mechanism).
- The nginx worker count corresponds one-to-one with `nb_procs` in config.ini (worker i ↔ `--proc-id=i`); traffic is split by the NIC RSS queue ↔ proc mapping (see §3.2/§3.5).
- Worker exit order protection: the primary worker (worker 0) calls `ngx_msleep(500)` before exiting so that secondaries exit first (`ngx_process_cycle.c:3082-3084`).

### 2.3 Event loop (how epoll/kqueue is replaced)

- The main event module is `ngx_kqueue_module`: F-Stack adds the two ff files to KQUEUE_MODULE/KQUEUE_SRCS (`auto/sources:112-113`). When nginx calls `kqueue()`/`kevent()`, the same-named libc symbols in `ngx_ff_module.c` hijack them to `ff_kqueue()`/`ff_kevent()` (`ngx_ff_module.c:862-891`; inside kevent the ident for EVFILT_READ/WRITE/VNODE is restored with `restore_fstack_fd`).
- The auxiliary host event module `ngx_ff_host_event_module` uses the real Linux kernel `epoll_create/epoll_ctl/epoll_wait` (`ngx_ff_host_event_module.c:102-127, 340`) and handles kernel fds only (the master-worker channel, etc.).
- Dual-track dispatch: `ev->belong_to_host==1` → `ngx_ff_host_event_actions.*`, otherwise → `ngx_event_actions.*` (= the kqueue module actions → the ff stack) (`src/event/ngx_event.h:406-424`). Channel events always have `belong_to_host=1` (`ngx_channel.c:216-218`).
- Each event module's init runs in `ngx_event_process_init`: first the main module (kqueue→ff), then `ngx_ff_host_event_actions.init` (`ngx_event.c:723-747`).
- Worker event loop: `ff_run(ngx_worker_process_cycle_loop, cycle)` (`ngx_process_cycle.c:2732`) → `ff_dpdk_run` → `rte_eal_mp_remote_launch(main_loop, ..., CALL_MAIN)` (`lib/ff_dpdk_if.c:3797`). Each main_loop round: `rte_timer_manage` driving (`:3497-3499`) → receive/send/IPC msg → call `lr->loop()`, i.e. `ngx_worker_process_cycle_loop` → `ngx_process_events_and_timers(cycle)` (`ngx_process_cycle.c:2626`).
- The master has no event loop; it waits purely in `sigsuspend` (`ngx_process_cycle.c:299`).
- Single-process mode is supported too: `ngx_single_process_cycle` runs `ff_mod_init(0, primary)` + `ff_run(ngx_single_process_cycle_loop)` (`ngx_process_cycle.c:1908`).

### 2.4 fd lifetime (is an fd an in-process index or a cross-process entity)

- An ff socket fd is **an fd inside this process's FreeBSD user-space stack**, not a Linux kernel fd: `ff_socket()` calls `sys_socket(curthread, ...)` directly and returns `curthread->td_retval[0]` (`lib/ff_syscall_wrapper.c:917-961`); the fd belongs to this process's FreeBSD `kern_descrip` fd table (`ff_fdused_range(fd_reserve)` inside `ff_freebsd_init`, `lib/ff_freebsd_init.c:355`). It is meaningless across processes.
- On the nginx side the fd namespaces are separated: the libc interception layer adds an offset to ff fds, `convert_fstack_fd = sockfd + ngx_max_sockets` (`ngx_ff_module.c:155-156`); `is_fstack_fd` tests `sockfd >= ngx_max_sockets` (`:169-174`); restoring subtracts it back (`:160-165`). At init it validates `ngx_max_sockets + ff_getmaxfd() <= INT_MAX` (`:322`).
- When the master forks a worker: the master has not run ff_init (its `socket()` goes to the real SYSCALL because `inited==0`, `ngx_ff_module.c:573-580`), so the fork inherits only kernel fds (channel pipes, etc.). A worker's ff fds are all created by itself after the fork; **there is no master→worker ff listening fd passing**.
- `close` is intercepted too: `close()` checks `is_fstack_fd` and then goes to `ff_close` (`ngx_ff_module.c:785-789`).

### 2.5 The reload (HUP) path: what happens in the F-Stack version

Signal chain: SIGCHLD→`ngx_reap`, SIGHUP (HUP = `NGX_RECONFIGURE_SIGNAL`)→`ngx_reconfigure`, QUIT→`ngx_quit` (`ngx_process_cycle.c:98-108` plus the signal handling in `src/os/unix/ngx_process.c`, unchanged).

F-Stack changed the `ngx_reconfigure` branch of `ngx_master_process_cycle` into a **two-stage serial reload** (`ngx_process_cycle.c:373-438`, the `graceful_reload=0` branch; `graceful_reload=1` takes the native sequential reload at `:375-390`):

1. On the first HUP (`ngx_reconfigure=1` and `!sig_worker_quit`): set `sig_worker_quit=1`, send QUIT to all children (`ngx_signal_worker_processes(NGX_SHUTDOWN_SIGNAL)`), continue (`:393-397`).
2. In later loop iterations, if workers are still alive (`live=1`) it continues and waits (`:400-402`).
3. Once all workers have exited (`live=0`, confirmed through `ngx_reap_children`): reset `sig_worker_quit`, run `ngx_init_cycle` (rebuild the configuration, re-parse nginx.conf) → `ngx_start_worker_processes(NGX_PROCESS_JUST_RESPAWN)` → `ngx_start_cache_manager_processes` → sleep 100 ms → send QUIT to the old workers again (there are none left at this point) (`:406-437`).

That is: only after **all** old workers (including the ff primary = worker 0) have exited do the new workers fork and each run ff_init (the new worker 0 re-runs `rte_eal_init` as the DPDK primary and takes over the NIC). During that time the data plane is completely empty.

Supporting changes:

- When a worker receives QUIT it does a graceful shutdown — `ngx_close_listening_sockets(cycle)` (ff fds are closed inside this process's stack) plus `ngx_close_idle_connections`, waits for `ngx_event_no_timers_left()`, then `ngx_worker_process_exit` (`ngx_process_cycle.c:2676-2704`, `:2631-2636`).
  > **Note (corrected 2026-09-17)**: the original statement that "the F-Stack worker branch has **no** `ngx_set_shutdown_timer` (`:894-898` vs native `:951-957`)" is an M0-period fact; M4 (C-NR-401) has restored that call (HEAD `ngx_process_cycle.c:2656/2761`); its definition and declaration already existed (`ngx_cycle.c:1429`/`ngx_cycle.h:143`).
- Automatic respawn is forbidden during reload: the respawn condition in `ngx_reap_children` gained `&& !ngx_reconfigure` (`ngx_process_cycle.c:2357`).
- The master's `ngx_quit` branch: only non-F-Stack calls `ngx_close_listening_sockets`; the F-Stack version skips it (the master never had ff listening fds) (`:367-369`).
- Unchanged: `ngx_signal_worker_processes`, the body of `ngx_init_cycle`, and the channel message (`NGX_CMD_*`) logic match native (apart from `belong_to_host`).

## 3. Library fact list

### 3.1 The `ff_api.h` interface surface / `ff_init` parameters

- `ff_init(int argc, char * const argv[])` (`lib/ff_api.h:61`; implemented in `lib/ff_init.c:36-56`): the order is `ff_load_config` → `ff_dpdk_init(dpdk_argc, dpdk_argv)` → `ff_freebsd_init()` → `ff_dpdk_if_up()`. argv holds f-stack's own parameters (--conf/--proc-id/--proc-type, etc.); after `ff_load_config` parses them it reassembles `dpdk_argv` for the EAL (defined in `lib/ff_config.c:1182` `dpdk_args_setup`).
- `ff_run(loop_func_t loop, void *arg)` (`ff_api.h:63`; `ff_init.c:59-62`) → `ff_dpdk_run`; `ff_stop_run()` (`ff_api.h:65`) sets `stop_loop=1` (`ff_dpdk_if.c:3830`, inside `ff_dpdk_stop()`).
- Socket family: `ff_socket/setsockopt/getsockopt/listen/bind/accept/accept4/connect/close/shutdown/getpeername/getsockname/read/readv/write/writev/send/sendto/sendmsg/recv/recvfrom/recvmsg/select/poll` (`ff_api.h:107-186`); `ff_kqueue/ff_kevent/ff_kevent_do_each` (`:172-176`); `ff_gettimeofday` (`:180-182`); `ff_dup/ff_dup2` (`:185-186`).
- Auxiliary: `ff_fdisused/ff_getmaxfd` (`:206/208`), `ff_regist_packet_dispatcher(_context)` (`:316/319`), `ff_dpdk_raw_packet_send` (`:341`), the `ff_zc_*` zero-copy family (`:485-587`).
- EAL parameter pass-through: from config.ini `[dpdk]`, `no_huge`/`proc_mask(-c)`/`nb_channel(-n)`/`memory`/`log_level`/`proc_type`/`base_virtaddr`/`file_prefix`/`allow(--allow PCI)`/`vdev` are all assembled into `dpdk_argv` (`ff_config.c:1188-1261`); `--proc-type` comes from `cfg->dpdk.proc_type` (`:1207-1210`; default "auto", `:1365-1366`; only primary/secondary/auto allowed, `:1369-1372`). In the nginx scenario `ff_mod_init` overrides proc_type to primary/secondary (`ngx_ff_module.c:496-515`; with `graceful_reload=1`, M1 changes it to all secondary, see the note in §2.2).

### 3.2 `ff_dpdk_if.c`: EAL initialisation, PCI takeover, primary/secondary

- `rte_eal_init` is called inside `ff_dpdk_init()` (`lib/ff_dpdk_if.c:2000`): `ff_dpdk_if.c:2012`. Pre-checks `nb_procs ∈ [1, RTE_MAX_LCORE]`, `proc_id ∈ [0, nb_procs)` (`:2002-2009`). Then `init_lcore_conf` (`:2027`) → `init_mem_pool` (`:2034`) → `init_dispatch_ring` (`:2050`) → `init_msg_ring` (`:2062`) → `init_port_start` (called at `:2128`, defined at `:1113`; internally dev_configure / rx / tx queue setup / start).
- NIC PCI takeover: EAL `--allow=<PCI>` (or `-c` plus default probe); the primary runs `rte_eth_dev_configure`/queue setup/start; secondaries operate the same NIC's RX/TX queues directly through DPDK multi-process shared hugepage device state.
- Resources that the primary exclusively creates and secondaries only look up (code-level evidence, `RTE_PROC_PRIMARY` checks):
  - mempool: primary `rte_pktmbuf_pool_create`, secondary `rte_mempool_lookup` (application-side pool `ff_dpdk_if.c:666-671`; shared RX pool `:792-805`)
  - rte_ring (dispatch/msg ring): primary `rte_ring_create`, secondary `rte_ring_lookup` (`:830 create_ring`; primary create `:838-839`, secondary lookup `:845`/`:852`)
  - link state check, flow isolate, rte_flow rules, FDIR (`:459`, `:2118`, `:2156`, `:2190`; KNI ownership in `ff_dpdk_kni.c:103` `ff_kni_is_runtime_owner`)
- **[Two processes cannot both initialise as primary]**: under the same file_prefix DPDK EAL allows only one primary (secondaries attach to the primary's hugepage configuration). With `graceful_reload=0` nginx hard-codes the identity by worker number (worker0 = primary), and the master uses a semaphore so that later secondaries are forked only after worker0 is ready (`ngx_process_cycle.c:2024-2099`).
  > **Note (corrected 2026-09-17)**: after M1, with `graceful_reload=1` all workers are secondaries plus a resident slim primary (`ngx_process_cycle.c:2929/2933`, `ngx_ff_module.c:496-527`); the `=0` branch keeps the original description above verbatim.
- Send/receive model: in multi-process mode (`thread_mode=0`) each process binds one lcore (`proc_lcore[proc_id]`, `ff_dpdk_if.c:562-601`, taking the lcore at `:572`; note that `:529-558` is the `thread_mode=1` branch); that lcore's index in the NIC `lcore_list` is its RX queue id (`:584-596`); in `main_loop` each process calls `rte_eth_rx_burst` on its own queue (`:3596`). Cross-process packet forwarding goes through the dispatch_ring (any process enqueues at `:2601-2602`; the target process dequeues at `:2718` `process_dispatch_ring`).
- The current state of the timer is in §3.4; the timer library's shared memzone structure and the background of the local patch are in [03 Legacy Scheme Verification](legacy-solution.md) §5.

### 3.3 ff_ipc / ff_msg: existing IPC capability

- The library itself has **no** `ff_ipc.c`; the IPC implementation lives in `tools/compat/ff_ipc.c` (the tool-side client) plus `ff_dpdk_if.c` (the data-plane server).
- Communication model: a tool process (ff_top/ff_sysctl/ff_route/ff_ipc_msg, etc.) runs `rte_eal_init` as `--proc-type=secondary` and attaches (`tools/compat/ff_ipc.c:65-75`), takes a message from the shared mempool `ff_msg_pool` (`:77-80, 94-111`), enqueues it to the target ff process's `ff_msg_ring_in_<proc_id>` (`:133-159`), and blocks waiting on `ff_msg_ring_out_<proc_id>_<msg_type>` (`:161-192`, polling with `usleep` at most 1000 ms × 1000 times).
- Data-plane server: each ff process's `main_loop` runs `process_msg_ring(proc_id, ...)` (`ff_dpdk_if.c:3640`; implementation `:3002`) → `handle_msg()` (`:2925`) dispatching by msg_type to the sysctl/ioctl/route/top/ngctl/ipfw/traffic/knictl handlers.
- Full set of message types (`lib/ff_msg.h:37-59`, 10 in total): FF_SYSCTL, FF_IOCTL, FF_IOCTL6, FF_ROUTE, FF_TOP, FF_NGCTL, FF_IPFW_CTL, FF_TRAFFIC, FF_KNICTL, plus **FF_RELOAD** added by M2 (ff_msg.h:54 — the graceful reload control family; the sub-command is in `ff_reload_args.cmd`, and the reply carries the answering process's generation/heartbeat/active-generation view, transported over the (proc_id, generation) msg_ring set).
- **[Conclusion: the existing IPC covers only control-plane tool messages; there is no mechanism or message type for passing fd/socket/listening/TCP session state across processes]** (the structures in `ff_msg.h:134-155` have no corresponding fields either).

### 3.4 Current state of timers

- Initialisation: `init_clock()` (`ff_dpdk_if.c:1508-1576`, called at the end of `ff_dpdk_init` at `:2148`) = `rte_timer_subsystem_init` + `rte_timer_meta_init` + creating the periodic rte_timer `freebsd_clock` (period = 1/config freebsd.hz, PERIODICAL, bound to the current lcore, callback `ff_hardclock_job`).
- Callback implementation: `ff_hardclock_job → ff_hardclock()` (`ff_dpdk_if.c:305-310`; `lib/ff_kern_timeout.c:1250-1261`): `ticks++`, `callout_tick()`, `tc_ticktock()`, `cpu_tick_calibration()`. With `thread_mode=1` workers use `ff_hardclock_worker()` (only `callout_tick()`, `ff_kern_timeout.c:1269-1273`; registered in `init_clock_worker`, `ff_dpdk_if.c:1549-1568`).
- Driver point: each `main_loop` round takes `cur_tsc = rte_rdtsc()`, and if `freebsd_clock.expire < cur_tsc` it calls `rte_timer_manage()` (`ff_dpdk_if.c:3497-3499`).
- Other clock points: each round `ff_tcp_hpts_softclock()` drives the HPTS pacing wheel (`:3687`; implementation `ff_kern_timeout.c:1299-1303`); `ff_get_tsc_ns()` (defined at `ff_dpdk_if.c:5040`) is the timecounter source (`ff_kern_timeout.c:1305-1311` `ff_tc_get_timecount`).
- **[No kernel signal / independent timer thread]**: everything is driven by the run-to-completion main loop of `ff_run` (the comment at `ff_kern_timeout.c:1263-1294` states explicitly that the swi/userret paths are no-ops in f-stack).

### 3.5 Current state of multi-process / reuseport support

- SO_REUSEPORT: only a Linux→FreeBSD constant pass-through in setsockopt (`lib/ff_syscall_wrapper.c:82, 561-562`). F-Stack nginx's multiple workers are **not** kernel reuseport semantics but "**one completely isolated FreeBSD stack instance per worker, each socket/bind/listen on the same IP:port without conflict (stack isolation), traffic split by a static NIC RSS queue↔proc mapping, and each TCP connection living inside exactly one process's stack**".
- One independent stack instance per process: `ff_freebsd_init()` (`lib/ff_freebsd_init.c:269-370`) runs a complete FreeBSD kernel initialisation in each process (kern_setenv, mp_ncpus, UMA, mi_startup, fd_reserve); with `thread_mode=0`, `nb_cpus=1` (`:298-301`).
- `thread_mode=1` (in-process multi-threaded native-mt) and `proc_type=secondary` are explicitly mutually exclusive (`lib/ff_config.c:1601-1608` reports an error; `:1610-1611` forces primary). nginx's multi-process mode uses `thread_mode=0`.
- Dispatch callback: `ff_regist_packet_dispatcher(_context)` lets an application redirect packets to a given queue/process (`ff_api.h:247` / `:316-319`; `ff_dpdk_if.c:2589-2604`). ~~nginx does not use it~~ **[2026-09-17 correction, R-25] that statement is outdated**: **it was unused in the M0 period; from M3 nginx registers a flow_map dispatcher** (`app/nginx-1.28.0/src/event/modules/ngx_ff_module.c:492` `ff_regist_packet_dispatcher_context(ngx_ff_flow_map_dispatcher)`); this item only holds for the M0~M2 point in time.

## 4. Code-level obstacle list for lossless reload

Organised around "why the current architecture cannot do nginx's native lossless reload (old and new workers coexisting, listening fd inheritance, the old worker finishing existing connections before exiting)"; each item carries its evidence location. This list feeds the candidate evaluation in [06 Solution Design](solution-design.md) and the obstacle-resolution mapping in [07 Milestones](milestones.md).

- **Obstacle 1 [reload was changed into two serial stages: all old workers exit → only then do new workers start, leaving a service gap]**
  Evidence: `app/nginx-1.28.0/src/os/unix/ngx_process_cycle.c:373-438` (the `graceful_reload=0` branch: `sig_worker_quit` sends QUIT first and only continues to init_cycle/start workers when `live==0`; the `=1` branch takes the native sequential reload instead).
  Reason: the new worker 0 must run `rte_eal_init` as the DPDK primary, while the old worker 0 is still the primary (owning NIC/mempool/ring), and the two cannot coexist (see obstacle 4).

- **Obstacle 2 [listening socket fds cannot be inherited/passed across processes]**
  Evidence: ff fds are process-private FreeBSD stack fds (`lib/ff_syscall_wrapper.c:917-961` returns `td_retval[0]`; `lib/ff_freebsd_init.c:355` gives each process its own fd table); the master creates no ff listening sockets (`ngx_connection.c:23-41`); after the fork each worker does its own ff_socket/bind/listen (`ngx_process_cycle.c:2956` plus `ngx_connection.c:543-547`); the IPC has no fd-passing message type (none in the `lib/ff_msg.h:37-59` enum).
  Reason: a new worker cannot "take over" the old worker's listening socket; it must rebuild everything, and during the transition the port is briefly unlistened in the new stack (SYNs arrive on the RSS queue with nobody accepting).

- **Obstacle 3 [TCP connection state (PCB/sockbuf) lives in the worker's private stack with no migration mechanism]**
  Evidence: one independent `ff_freebsd_init` instance per process (`lib/ff_freebsd_init.c:269-370`); processes share only data-plane resources such as mempool/ring/dispatch ring (`ff_dpdk_if.c:684`, `:863`), with no TCP state export/import interface anywhere in `ff_api.h`.
  Reason: an old worker exiting destroys all TCP connections on it; a lossless reload needs connection migration or the old worker to keep serving existing connections until they end naturally, whereas the current reload QUITs all old workers (including the serving primary), and after QUIT the worker exits fairly quickly because of `ngx_close_listening_sockets` + `no_timers_left` (long connections are drained as fast as logic outside `ngx_event_no_timers_left` allows, but the ff stack dies with the process).

- **Obstacle 4 [the DPDK primary is a single point: worker0 is hard-coded primary, old and new primaries cannot coexist]**
  Evidence: `ngx_process_cycle.c:2930-2933` (`graceful_reload=0` and worker==0 → `NGX_FF_PROCESS_PRIMARY`; otherwise `SECONDARY`); `ngx_ff_module.c:496-515` (proc_type==1 → `--proc-type=primary`); the primary exclusively creates mempool/ring/port (`ff_dpdk_if.c:666-671`, `:838-839`, `:1113`); the master uses a semaphore so secondaries are forked only after worker0 is ready (`ngx_process_cycle.c:2024-2099`).
  Reason: nginx's native reload order (start the new workers first, then exit the old ones) requires the new primary to finish `rte_eal_init` while the old primary is alive — impossible under the same DPDK file_prefix; this is the fundamental constraint that made F-Stack's reload serial.
  > **Note (corrected 2026-09-17)**: this obstacle was removed by M1 — with `graceful_reload=1` all workers are secondaries plus a resident slim primary (`ngx_ff_module.c:496-527`, `ngx_process_cycle.c:2929/2933`), so a new primary no longer has to coexist with an old one; the `=0` branch keeps the original description above verbatim.

- **Obstacle 5 [a worker dying during reload is not respawned, plus the fragile timing of sleeping 500 ms before the primary exits]**
  Evidence: `ngx_process_cycle.c:2357` (the respawn condition adds `!ngx_reconfigure`); `ngx_process_cycle.c:3082-3084` (the primary sleeps 500 ms before exiting, waiting for secondaries).
  Reason: poor fault tolerance in the transition; 500 ms is an empirical value rather than a synchronisation primitive, and on a slow machine a secondary may lose the primary's shared resources before the primary has fully exited (not measured, see the unconfirmed list).

- **Obstacle 6 [the master is not on the data plane and cannot act as "configuration-switch coordinator + listening holder"]**
  Evidence: the master does not run ff_init (no ff calls in `ngx_process_cycle.c:155-299`); the master's `socket()` is not intercepted (`ngx_ff_module.c:573-580`, `inited==0` goes to the kernel).
  Reason: any scheme of "the master holding ff listening centrally and distributing to workers" has no infrastructure in the current state (fds have no cross-process semantics and the IPC has no passing channel).

- **Obstacle 7 [traffic distribution is a static NIC RSS queue↔proc mapping, and during the transition nobody consumes the queue]**
  Evidence: `init_lcore_conf` binds one lcore = one RX queue per process (multi-process path `ff_dpdk_if.c:562-601`, taking the lcore at `:572`, lcore_list index → queue id at `:584-596`); each `main_loop` does its own `rx_burst` (`:3596`); cross-process only via dispatch ring (`:2601-2602`, `:2718`).
  Reason: after an old worker stops its loop, packets on its queue back up until the ring/descriptors fill and packets are dropped; before a new worker comes up, no process receives on its behalf (unless RSS is redirected, which does not exist dynamically today). This obstacle is the "queue with no owner" root cause confirmed by issue #1036 (see [01](vpp-vcl-research.md) §6.2 and [03](legacy-solution.md) §7).

- **Obstacle 8 [timers/clocks die with the process]**
  Evidence: `freebsd_clock` is an in-process rte_timer driven by that process's `rte_timer_manage` in main_loop (`ff_dpdk_if.c:1508-1576`, `:3497-3499`); `ff_hardclock` advances ticks/callout/timecounter (`ff_kern_timeout.c:1250-1261`).
  Reason: while an old worker exits, all TCP timers in its stack (RTO/keepalive/delayed ACK) stop and the congestion-control state of existing connections freezes; a scheme of "the old worker drags on until connections end" would require the old process to stay alive running ff_run, which conflicts with the current all-exit reload semantics (the current implementation does allow a worker to drag on to `no_timers_left`, but then the master keeps waiting with `live=1` and the new configuration does not take effect — a semantic mismatch with the lossless goal).

- **Supplementary fact (not an obstacle but it affects the design)**: F-Stack's worker QUIT branch originally had no `ngx_set_shutdown_timer` (M0-period comparison with native `ngx_process_cycle.c:951-957`), so existing long connections could hold a worker from exiting and the master would wait forever with `live=1`, hanging the reload (only a TERM/INT could force it).
  > **Note (corrected 2026-09-17)**: M4 (C-NR-401) restored the `ngx_set_shutdown_timer` call (HEAD `ngx_process_cycle.c:2656/2761`); "does not call it" above is an M0-period fact.

## 5. Unconfirmed list

The following cannot be settled by reading code statically; they need runtime experiments or deeper tracing:

1. How a secondary process behaves after the primary exits on DPDK 24.11: mempool/ring are created by the primary in shared hugepage; whether a secondary keeps sending/receiving stably after the primary dies, and how long until something breaks — not measured. (The 500 ms sleep at `ngx_process_cycle.c:3082-3084` hints that upstream already knows this window is sensitive.)
2. **Disproved (corrected 2026-09-17)**: the original item "a worker's exit does not go through the `ff_dpdk_run` finishing path; whether `rte_eal_cleanup` (the `stop_clock()` section at `ff_dpdk_if.c:3805`) not being called leaves dirty state" was disproved by M6 on-site forensics — the F2 root cause is a lifetime mismatch of nginx's `ngx_ff_worker_sem` semaphore (`ngx_start_worker_processes` destroys it without setting NULL, and worker 0's `sem_post` has no null check, so a respawn error hits a dangling pointer → glibc futex fatal → SIGABRT storm), **not** "a worker exiting without `rte_eal_cleanup` leaves a dirty EAL"; see `work/impl/m6-f2-forensics.md` and 07 §2.7(3), fix commit `c5b93f862`. Static fact still held: a worker actually ends with `ngx_worker_process_exit → exit(0)` (`ngx_process_cycle.c:1258`), and hugepage resources are released only when the process dies.
3. The measured length of the reload gap: the 15 s semaphore wait ceiling (`ngx_process_cycle.c:2064`), the master's `ngx_msleep(100)` (`:433`) and the primary's 500 ms before exit (`:3084`) are all static values; the real gap = old worker exit time + new worker EAL+stack initialisation time, not measured (corresponds to the E-NR-04 baseline collection in [08 Test Plan](testing-plan.md)).
4. Whether SO_REUSEPORT inside the ff stack (`ff_syscall_wrapper.c:561-562` pass-through) is actually set by F-Stack nginx in the scenario where several processes each listen on the same port (the path seen at `ngx_connection.c:556-566` sets SO_REUSEADDR; whether REUSEPORT is additionally set under the SOCK_FSTACK branch was not traced line by line).
5. The fd allocation conflict behaviour when the `kernel_network_stack` directive (`ngx_http_core_module.c:298`) and listening ownership (`ngx_http.c:1890`) are used so that some servers on the same port use the kernel stack and others the F-Stack stack — not dug into (small impact on this spec's main line).
6. With KNI enabled (configuration key `[kni] enable=1`, consistent with 07 §2.7 C-NR-602), the impact on the control plane of the KNI virtio_user vdev belonging to the primary during the reload gap (the criterion inside main_loop is at `ff_dpdk_if.c:3658-3676`, comment at `:3660`) — not expanded.
