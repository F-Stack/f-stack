# 05 Alternative Route Analysis: the adapter/syscall (LD_PRELOAD) Architecture and the Feasibility of Lossless nginx Reload (English)

> **English translation** of `docs/nginx_reload_spec/zh_cn/05-ld-preload-alternative.md` (v1.3). The Chinese text is
> authoritative; where the two differ, the Chinese original governs.
> Translated 2026-09-30.

| Item | Value |
| --- | --- |
| Document ID | 05 |
| Title | Probing the F-Stack adapter/syscall (LD_PRELOAD ring IPC) architecture + the feasibility and gap list of lossless nginx reload |
| Version | v1.3 (on v1.2: **final gate G-D rework F-01 cross-document sweep** — the R-01 code fix (`lib/ff_dpdk_if.c:669-673`, per-generation pool `cache_size=0`) has landed; this document was swept end to end and **no "per-generation pool not zeroed / still 256" wording needs rewriting** (every `256` hit in this document is the `FF_KERNEL_EVENT` "poll kernel fds once every 256 iterations", unrelated to the mempool cache), so only the version header is synced. v1.1 = **corrected per the `plan_cross_audit` G-A verdicts R-27/R-28** — the §1 line counts of six files corrected against `wc -l` (163/752/371/36/267/437; previously 164/753/372/37/268/439); the §2.3 rsp_ring legacy fallback anchor corrected from `ff_ring_ipc.c:49-75` + `ff_hook_syscall.c:3411-3440` to `ff_ring_ipc.c:141-155` (enqueue at `:154`); §6 items 3/4/7 split into "part confirmed" and "part not confirmed", with `ff_hook_syscall.c:255-258`/`:3248`, `ff_compat.c:97`, `ff_init_main.c:541` coordinates added) |
| Date | 2026-08-18 (v1.1 addition: 2026-09-17) |
| Status | pending human audit |
| Revision notes | v1.1 (2026-09-17): corrected per the `plan_cross_audit` G-A verdicts R-27/R-28 — the §1 line counts, the §2.3 rsp_ring anchor, and §6 unconfirmed items 3/4/7 split and rewritten, see the Version row. v1.2 (2026-09-18): final gate G-D rework F-01 cross-document sweep — the R-01 code fix has landed; the sweep found no R-01 wording here, so only the version header is synced. **v1.3 (2026-09-18): R-01 mechanism error wrap-up (G-D "must be completed before commit")** — the sweep found no landing point for that mechanism error here (every `256` hit is the `FF_KERNEL_EVENT` every-256 poll, unrelated to the mempool cache), so only the version header is synced |
| Source artefact | `work/probe-ld-preload.md` (prober `probe-ldpreload`, filed 2026-08-18; read-only probing, no code changed, no git write operation). This document is the formalised rewrite: all factual evidence kept (file:line), deviations from existing specs marked, unconfirmed list kept; the "probing method" is kept as §1 so the evidence stays traceable |

Probing scope: `/data/workspace/f-stack/adapter/syscall/` plus `docs/ld_preload_ring_spec/zh_cn/` 01 and 02. All line numbers follow the code in the current workspace (probing point in time 2026-08-18).

Related: [00 Overview](overview.md) | [04 Current Analysis](current-analysis.md) | [06 Solution Design](solution-design.md)

---

## 1. Probing method

- Read `docs/ld_preload_ring_spec/zh_cn/01-requirements-spec.md` and `02-architecture-design-spec.md` in full (about 300/640 lines) and extracted the functional positioning.
- Read the code line by line (full text, not sampled):
  - `adapter/syscall/ff_hook_syscall.c` (3445 lines, read in 4 segments)
  - `adapter/syscall/ff_ring_ipc.c` (**163** lines), `ff_socket_ops.c` (**752** lines), `ff_so_zone.c` (**371** lines), `fstack.c` (**36** lines) — **[2026-09-17 correction, R-27] the previous 164/753/372/37 differ from `wc -l` by 1** (`wc -l` counts newlines and does not count a final line without one; `wc -l` measurements are authoritative here)
  - `ff_declare_syscalls.h`, `ff_hook_syscall.h`, `ff_socket_ops.h`, `ff_adapter.h`, `ff_linux_syscall.c` (**267** lines, corrected as above), `Makefile`
  - `adapter/syscall/README.md` (**437** lines, English, corrected as above)
- Analysis method: cross-check code facts along four dimensions — the hook surface (syscall coverage), the IPC surface (ring/sem dual path), the lifetime surface (attach/detach/fork/exit), and the nginx mapping surface (master/worker, HUP/USR2, connection ownership).
- Not done: compiling, running, git log archaeology (within this time box the current code is authoritative).

## 2. Key points extracted from the existing spec documents

### 2.1 Functional positioning (01-requirements-spec.md)

- The goal of the change is to replace the IPC between the LD_PRELOAD module (`libff_syscall.so`) and the fstack instance process from "three-layer synchronisation" (state machine IDLE/REQ/REP + spinlock + POSIX cross-process semaphore; 01 §1.1, citing `ff_socket_ops.h:73-75/103/111`) with DPDK `rte_ring` SPSC dual rings (FR-001/FR-002, §2).
- The motivation is purely performance: sem/futex kernel-mode cost of 100-200 ns (§1.2.1), `sem_timedwait`'s millisecond-level timeout precision (§1.2.2), an O(n) walk over 32 sc on the fstack side (§1.2.3), fragile `alarm_event_sem` compensation (§1.2.4), and a compile-time split between polling and semaphore modes (§1.2.5).
- Five operating modes are kept compatible (C-001 table): PIPELINE (default), RTC/FF_THREAD_SOCKET, FF_KERNEL_EVENT, FF_MULTI_SC, FF_PRELOAD_POLLING_MODE (unified to a busy-poll strategy under ring).
- Note: 01/02 are the spec of the "ring IPC change", not the spec of the LD_PRELOAD feature itself. The LD_PRELOAD feature is positioned in README.md: let existing applications (nginx being typical) attach to F-Stack without code changes (README L7-L16).

### 2.2 Architecture design (02-architecture-design-spec.md)

- Dual SPSC ring model: a request ring APP→fstack and a response ring fstack→APP, both in hugepage (§2.1/2.2).
- The new state machine drops IDLE/REQ/REP; an sc's lifetime is managed implicitly by ring enqueue/dequeue (§2.3). **Note its implicit assumption: one sc belongs to only one initiator at a time** (§2.3 note: "in req_ring = the request has been submitted").
- Three waiting strategies — busy/yield/eventfd — configurable at run time (§6.2 promises the environment variable `FF_RING_WAIT_MODE`, default yield-poll).
- Industry comparison: VPP memif / svm_msg_q (§4); `rte_ring` was chosen because F-Stack already uses it heavily (dispatch_ring/msg_ring).
- Error handling (§8): spin-retry when the ring is full; C-005 requires "residual sc pointers in the ring must be cleaned up on detach when a process exits abnormally".

### 2.3 Deviations between the spec and the code (important)

- **`wait_mode` is not configurable at run time**: spec 02 §6.2 promises an `FF_RING_WAIT_MODE` environment variable; the code never reads that variable with `getenv`, and `ff_create_so_memzone` calls `ff_create_sc_ring_zone(proc_id, FF_RING_SIZE, FF_RING_DEFAULT_WAIT_MODE)` (`ff_so_zone.c:124-125`), where `FF_RING_DEFAULT_WAIT_MODE` is a compile-time constant (`ff_socket_ops.h:155-157`).
- **The response path has diverged from spec v1.0**: the spec has responses go over the rsp_ring; the implementation evolved into the v3.3 D2 fix — the fstack side no longer enqueues to the rsp_ring but sets `sc->completion=1` directly (same cache line as the result), and the rsp_ring is enqueued only as a legacy fallback inside `ff_ring_alarm_wakeup`. **[2026-09-17 correction, R-27] the anchor was misplaced**: `ff_ring_ipc.c:49-75` is the **completion path** (the response wait on the `ff_ring_submit_and_wait` side); **the real landing point of the legacy fallback enqueue is `ff_ring_ipc.c:141-155`** (`ff_ring_alarm_wakeup()`, with the enqueue statement at **`:154`** (`rte_ring_sp_enqueue(ring_zone->rsp_ring, sc)`); the comment at `:148-150` says "kept as a no-op fallback for any legacy path"); `ff_hook_syscall.c:3411-3440` is unrelated, the previous reference was wrong.
- **Cleaning the ring on detach is not implemented**: spec C-005 requires draining residual ring entries on detach; `ff_detach_so_context` (`ff_so_zone.c:229-264`) performs no ring operation at all.
- 03/04 (interface/test) plus `ld_preload_ring_support.md` and `ring_ipc_perf_offline_analysis.md` were not read this round (the task only required 01/02); they may contain additional constraints (see §6-6).

## 3. Code fact list

### 3.1 The hooked system calls (complete list)

Declaration surface (`ff_declare_syscalls.h:1-31` plus `ff_hook_syscall.h:6-14`); LD_PRELOAD hijacking is realised by aliasing `ff_hook_##fn` to the `fn` symbol through strong_alias (`ff_hook_syscall.c:43-52`):

| Category | Interfaces | Evidence |
| --- | --- | --- |
| socket creation | socket / bind / listen / connect / shutdown | `ff_declare_syscalls.h:1-11` |
| accepting | accept / accept4 | `ff_declare_syscalls.h:9-10` |
| send/receive | recv / recvfrom / recvmsg / read / readv / send / sendto / sendmsg / write / writev | `ff_declare_syscalls.h:12-23` |
| metadata | getsockname / getpeername / getsockopt / setsockopt | `ff_declare_syscalls.h:5-8` |
| control | close / fcntl / ioctl (variable arguments implemented separately) / select | `ff_declare_syscalls.h:24-30`; the variable-argument ioctl at `ff_hook_syscall.c:1939-1950` |
| events | epoll_create / epoll_ctl / epoll_wait; kqueue / kevent exported directly | `ff_declare_syscalls.h:26-28`; `ff_hook_syscall.h:12-14` |
| process | **fork** (hooked); **the exec family is not hooked at all** | `ff_declare_syscalls.h:29`; no exec symbol anywhere in the directory |
| glibc hardening | `__recv_chk` / `__read_chk` / `__recvfrom_chk` | `ff_hook_syscall.h:6-9` |

Routing rule: `is_fstack_fd(fd)` (fd >= `ff_kernel_max_fd`, i.e. RLIMIT_NOFILE, `ff_hook_syscall.c:309-316`, `:3192-3202`) — if true go to fstack (the `CHECK_FD_OWNERSHIP` macro at L57-63), otherwise go to the real system call via dlsym'ed libc (`ff_linux_syscall.c:80-267`). An fstack fd = the real fd + `ff_kernel_max_fd` (`convert_fstack_fd` L296-298, inverse L301-307).

### 3.2 The hook semantics of fork (`ff_hook_syscall.c:2426-2496`)

- The real fork goes through `ff_linux_fork` → dlsym'ed libc fork (`ff_linux_syscall.c:254-259`).
- FF_MULTI_SC: before the fork, switch `sc = scs[current_worker_id].sc; ff_so_zone = ff_so_zones[current_worker_id]` (L2434-2435) so the child inherits that worker's sc and zone; the parent does `current_worker_id++` (L2451).
- The whole fork window holds `sc->lock` (L2438-2440); the parent does `sc->refcount++` (L2447).
- FF_USE_THREAD_STRUCT_HANDLE: the parent sets `sc->forking=1` and spins until the child finishes (L2455-2457); the child first calls `ff_adapter_child_process_init()` to attach a new sc (L2470, implementation at L3335-3347, internally `ff_attach_so_context(0)` always attaching zone 0), then sends an `FF_SO_FORK` request; on the stack side `ff_sys_fork` calls `ff_adapt_user_thread_add(parent)` to copy the thread and fd table inside the FreeBSD stack (`ff_socket_ops.c:381-395`), and the child gets a new thread handle (L2482).
- The supported topology is limited, as the comments state: master→child→workers flat or one level of nesting; worker→worker→worker chains are not supported (L244-247).
- **exec is not hooked**: after a USR2 binary upgrade the so is loaded again and in-process `sc`/`scs`/`current_worker_id`/`inited`/`fstack_kernel_fd_map` are all zeroed and reset.

### 3.3 The ring IPC mechanism (`ff_ring_ipc.c` + `ff_socket_ops.c` + `ff_so_zone.c`)

- Naming: `ff_sc_req_ring_%d` / `ff_sc_rsp_ring_%d` / `ff_sc_ring_zone_%d` (`ff_so_zone.c:18-20`), distinguished by proc_id (the fstack instance number).
- Creation (primary = the fstack process): `ff_create_sc_ring_zone` (`ff_so_zone.c:273-337`), SPSC flags `RING_F_SP_ENQ|RING_F_SC_DEQ` (L280), ring_size default 64 (`ff_socket_ops.h:147-149`); the eventfd is created only when `wait_mode==2` (L321-330). On the APP side `ff_attach_sc_ring_zone` looks the zone up by name (L344-370).
- **The message format is the sc pointer itself** (a `void*` is enqueued, no message header). On the APP side, `ff_ring_submit_and_wait` (`ff_hook_syscall.c:3384-3443`): first set `completion=0` (v3.3 H23 fix so a completion is not cleared after it happens; comment at L3395-3398) → `rte_ring_sp_enqueue`, spinning while full → then, per wait_mode, spin waiting for `sc->completion==1` (acquire semantics at L3419). The timeout is based on `rte_rdtsc` (L3414-3421).
- Consumption on the fstack side: the ring branch of `ff_handle_each_context` (`ff_socket_ops.c:621-668`): a fast empty check with `rte_ring_empty` (D5, L653) + inline dequeue burst (D6, L654-660) + `ff_handle_socket_ops_ring` (L524-549) running `ff_so_handler` without locks → `ff_ring_send_response` sets `completion=1` (release semantics, `ff_ring_ipc.c:61`). The main loop takes no zone-level lock.
- Stack process and client pairing: the fstack process creates a zone+ring per proc_id according to `nb_procs` (`ff_so_zone.c:74-139`); the APP is a DPDK secondary process (`--proc-type=secondary`, `ff_hook_syscall.c:3267-3272`) and binds to an instance through `ff_attach_so_context(worker_id % nb_procs)` (L3297).
- Multiple clients: each zone has `SOCKET_OPS_CONTEXT_MAX_NUM=32` sc slots (`ff_socket_ops.h:45`); attach sets `inuse=1`, `refcount=1` (`ff_so_zone.c:200-212`); the same sc can be shared by forked processes (refcount mechanism). Under FF_MULTI_SC the APP keeps an `scs[32]` array occupied in order (`ff_hook_syscall.c:234-251`, `:3305-3310`).

### 3.4 The stack process side (`fstack.c` + `ff_socket_ops.c`)

- The `fstack` binary is a standard F-Stack application (`fstack.c:15-36`): `ff_init` → `ff_set_max_so_context(32)` → `ff_create_so_memzone` → `ff_run(loop)`, and the loop only calls `ff_handle_each_context` (L7-12).
- Multi-process: standard F-Stack config.ini multi-process instances (README L263-273 starts multiple instances with `start.sh -b adapter/syscall/fstack` plus lcore_mask); one zone/ring per instance, 32 sc per zone.
- All real socket actions (`ff_socket/ff_bind/ff_accept/ff_read...`) execute inside the stack process (the `ff_sys_*` wrappers at `ff_socket_ops.c:124-267`) — **connection state, the fd table (FreeBSD) and the protocol stack all live in the stack process**.
- Resident state: `ff_bound_fds[8]` (static, in stack process memory, L42) records bound address→fd; binding the same address again triggers `ff_dup2(bound_fd, fd)` to reuse the old listening socket (`ff_sys_bind` L131-147).

### 3.5 Resource reclaim when a client exits or crashes

- Normal exit: the so destructor `ff_adapter_exit` (`ff_hook_syscall.c:3131-3160`): under FF_MULTI_SC, if this is the master (`current_worker_id == worker_id`), it loops over every `scs[i]` running `ff_application_exit` (FF_SO_EXIT_APPLICATION → stack side `ff_adapt_user_thread_exit`, `ff_socket_ops.c:410-419`) plus `ff_detach_so_context`; otherwise it detaches the single sc. Detach semantics: refcount>1 decrements; only refcount==1 frees the inuse slot (`ff_so_zone.c:241-263`).
- Thread exit: the pthread_key destructor (L3045-3052) detaches the sc only under FF_THREAD_SOCKET.
- **Abnormal exit (kill -9 / crash)**: the destructor does not run → the sc inuse slot is occupied forever → once the zone's 32 slots fill, new APP attaches fail (`ff_so_zone.c:194-198`). **There is no heartbeat, no process monitoring and no orphan reclaim on the stack side.** Residual entries in the req_ring are still processed by the stack (the result is simply never read, harmless); `completion` is never cleared (a later submit on that sc would clear it, but that sc has leaked and is not reused).
- **A client exit does not close the socket fd on the stack side**: detach only frees the sc slot, and `ff_sys_close` runs only when the APP explicitly calls close (L269-275). Process death destroys the Linux fd table, but the stack process's FreeBSD fd table is unaffected → the connection fd leaks. README L22 states explicitly that there is "still a potential memory leak and deadlock risk when a process ends".

### 3.6 fd passing / socket sharing after fork

- The Linux fd table is naturally copied by fork (fd numbers unchanged); on the APP side an "fd" is only `number + ff_kernel_max_fd offset`, and the socket itself lives in the stack process.
- On the stack side the FreeBSD fd table is copied only on the FF_SO_FORK path when FF_USE_THREAD_STRUCT_HANDLE is enabled (`ff_adapt_user_thread_add`, `ff_socket_ops.c:390-392`); when that macro is off, `ff_sys_fork` returns 0 directly without any stack-side action (L383-394).
- **fd and sc are not strongly bound**: every `ff_sys_*` handler takes `args->fd` and executes directly, with no check of which sc/thread the fd belongs to (e.g. `ff_sys_read` L224-229). Any sc in the same zone can operate on any fd number (the base assumption of PIPELINE mode).
- FF_KERNEL_EVENT's fstack↔kernel epoll fd mapping table `fstack_kernel_fd_map[65536]` (`ff_hook_syscall.c:255-259`) is an in-process array: inherited by fork; lost after exec.

### 3.7 epoll_wait semantics (a critical nginx path)

- Ring mode (L2267-2299): `ff_ring_submit_and_wait(timeout_us)`; timeout<0 blocks forever and a timeout maps to 0 events (L2291-2292); when `timeout<=0 && ret==0` it goes to RETRY and spins (L2406-2410).
- FF_KERNEL_EVENT: it also calls the kernel epoll, but **polls kernel fds only once every 256 iterations** (`if ((count & 0xff) == 0)`, L2333-2345) — control-plane events (nginx channel/timer fds) can be delayed by hundreds of loop iterations. `maxevents` must be >=2 (L2213-2217).
- The fstack epoll is a kqueue wrapper whose triggering differs from standard epoll for multiple accepts, so nginx needs `multi_accept on` (README L232, L138).

## 4. Feasibility analysis of combining with nginx (code level)

Prerequisite configuration (README L203-288): compile with `FF_KERNEL_EVENT=1 + FF_MULTI_SC=1`; nginx uses `listen ... reuseport` + `worker_processes=N` + `FF_NB_FSTACK_INSTANCE=N`; fstack instances start first.

### 4.1 Basic viability of master + worker all under LD_PRELOAD

- The master starts with LD_PRELOAD; signal / pid file / open / write / kill and other **non-socket system calls are not hooked** and go to the kernel, so the pid file and signal semantics are unchanged (hook list in §3.1).
- reuseport mode: the master calls socket/bind/listen for each worker — each socket call triggers `ff_adapter_init`, attaching sc in order and recording it in `scs[]` (`ff_hook_syscall.c:392-404`, `:3297-3310`); at fork the sc/zone is switched to the child according to `current_worker_id` (L2434-2435). This flow is the nginx working path documented explicitly in the README (L188-201).
- Socket fd inheritance when a worker forks: Linux fd numbers are inherited naturally; the connection body on the stack side does not move. **Viable.**
- The master's epoll: the nginx master mainly uses signals plus the channel (kernel fds) and takes the FF_KERNEL_EVENT kernel path; a worker's epoll mixes control fds (channel/timer) with data fds, which is exactly the FF_KERNEL_EVENT scenario (README L180-186). **Viable, but affected by the 1/256 polling delay in §3.7.**

### 4.2 HUP reload (the master does not exit; workers are replaced)

- The master survives → the listening fd is held continuously and the stack-side listening socket is stable. **Lossless listening holds in the "first fork / single round" scenario** [2026-09-22 sync, A01-7: the index and generation lifetimes under multiple rounds of reload are not proven; multiple rounds are not proven].
- New workers fork through the already-verified fork hook path, so workers can be generated again (each HUP makes the master fork another batch of workers; FF_MULTI_SC's `scs[]`/`current_worker_id` keep increasing, and 32 sc per zone is the capacity ceiling — during the transition of multiple reload rounds, "old workers not yet exited + new workers already started" occupy sc simultaneously, so repeated reloads risk exhaustion and need load testing).
- Old workers exiting: nginx's graceful logic closes connections explicitly (close hook → FF_SO_CLOSE → the stack closes the socket) — **the connection handling semantics are the same as kernel nginx: graceful retirement, not lossless.** If a worker dies abnormally (without close), the stack-side fd leaks (§3.5). The sc slot is reclaimed through refcount/detach (present on the normal exit path; absent on abnormal exit).
- Conclusion: under this architecture HUP behaves like kernel nginx (listening is lossless, existing connections close gracefully), with no natural gain and no extra loss (apart from sc capacity and leak risks).

### 4.3 USR2 binary upgrade (the new master execs a new file)

- **exec not being hooked is a hard gap** (§3.2/§4.3): in the new master the so is loaded again, so `sc / scs[] / current_worker_id / worker_id / inited / fstack_kernel_fd_map` are all zeroed. The old listening fd number survives the exec (Linux semantics), and the new process's first socket call re-runs `ff_adapter_init` (if RLIMIT is the same the fd decision is the same), but FF_MULTI_SC's worker→sc mapping system is completely lost, and the new master's fork flow restarts from `current_worker_id=0`.
- Favourable fact: the stack process does not move at all and `ff_bound_fds` stays resident (stack process memory, `ff_socket_ops.c:42`); when the new master binds the same address, `sockaddr_is_bound` hits → `ff_dup2(old_listening_fd, new_fd)` (L131-147) — **the listening socket can be reused by the new generation on the stack side**, provided the old master does not close the old listening fd when it exits (nginx's USR2 keeps the old master's listening until QUIT; when the old master QUITs it closes → `ff_sys_close` calls `sockaddr_unbind` and clears the table, L273 — so the new generation must really bind again; if the new master has already completed the dup in time, there is no problem).
- Established connections: the connection fd body lives in the stack process's global FreeBSD fd table; fd numbers are valid across processes with no sc ownership check (§3.6). **In theory** a new worker only needs the fd number to keep reading and writing that connection through its own sc — a "connection migration potential" unique to this architecture. But: nginx itself has no connection hand-off mechanism (native USR2 does not migrate connections either, it only shares listening); the nginx run-time state for fd→connection (read buffer, state machine) lives in the old worker process and cannot be rebuilt across an exec. So "connection-level lossless reload" exceeds nginx's native capability and would need nginx changes (for example reconstructing connections from the fd table) — a major change.
- Conclusion: the USR2 route has code-level support for "lossless listening" in this architecture (reuse through `ff_dup2`), but the loss of exec state means the FF_MULTI_SC/FF_KERNEL_EVENT mapping reconstruction path is not covered by existing code; recovery logic after exec must be added (or avoided on the nginx side by having the old master pass an explicit fd list before USR2).

### 4.4 Performance / maturity limits (README + code)

- Roughly twice the CPU (each instance group occupies two cores; README L15-16, L307); beyond 8 cores short-connection performance is lower than standard F-Stack (L319).
- With multiple fstack instances it cannot act as a client — the nginx reverse proxy/proxy scenario is unusable (L25-29, including 铁皮大爷's RSS change proposal).
- ring vs sem: a 2-4% performance difference; the official recommendation is still sem for production, with ring kept as a reserve for future multi-thread sc sharing / cross-process sc sharing (L37-39, L379).
- `pkt_tx_delay` is reused as the sc processing window, a coarse parameter (L88-92).
- `epoll_wait` with `timeout<=0 && ret==0` spins on RETRY (L2406-2410) plus the default yield-poll strategy: idle CPU is high (acknowledged by the goal of NFR-003 in spec 01).
- **In ring mode there is no serialisation for concurrent use of the same sc**: sem mode's `ACQUIRE_ZONE_LOCK(FF_SC_IDLE)` spin naturally serialises one sc; in ring mode clearing `completion=0` before submit is lock-free (L3398), so two threads sharing one sc trample each other's completion — consistent with spec 02 §2.3's single-holder assumption of "sc lifetime managed implicitly by the ring", but it means that in the default PIPELINE mode (sc is process-global, not thread-local, `ff_hook_syscall.c:227` plus `ff_socket_ops.h:27-31`) a multi-threaded APP has a data-race risk in ring mode (an nginx worker is a process and is not affected; an APP with a thread pool is at risk).

## 5. Advantage / gap list

### 5.1 The "natural advantages" of the ld_preload route for lossless nginx reload

1. **Connection and listening socket ownership lives in the stack process**: every `ff_socket/ff_accept/ff_close` runs in the stack process (`ff_socket_ops.c:124-275`), so an nginx (client) restart does not touch network stack state — the client lifetime is decoupled from the connection lifetime, the core structural advantage of this route (isomorphic with baseline 2 in [01](vpp-vcl-research.md) §6.2: "queue/receive ownership decoupled from the business process").
2. **fds have no process ownership**: fd numbers are globally valid inside a stack instance's FreeBSD fd table, and `ff_sys_*` executes directly with `args->fd` without any sc ownership check (§3.6) — migrating a connection across processes only needs the fd number, with no SCM_RIGHTS-style kernel fd passing.
3. **The stack process is completely unaware of an nginx restart**: fstack is an independent process and all IPC state (zone/sc/ring) lives in hugepage shared memory (`ff_so_zone.c:66-157`), so restarting nginx as a whole does not affect the stack-side data structures.
4. **Reusing listening sockets across generations already has a mechanism**: `ff_bound_fds` plus `ff_dup2` on the stack side (`ff_socket_ops.c:131-147`); a new master binding the same address can attach back to the old listening socket.
5. **fork is supported and verified on the "first fork + single nginx round" path** [2026-09-22 sync, A01-7: "fully supported" is too strong; the index/generation lifetimes under multiple reload rounds and the 32-sc capacity ceiling of point 3 above are not proven and need load-test corroboration]: the fork path under FF_MULTI_SC + FF_USE_THREAD_STRUCT_HANDLE (`ff_hook_syscall.c:2426-2496`) is designed for the nginx reuseport workflow (README L188-201).
6. **The control plane falls back to the kernel automatically**: FF_KERNEL_EVENT keeps nginx channel/timer and other control fds on kernel semantics (L2324-2345), so reload control behaviour matches kernel nginx with no adaptation.
7. **The sc refcount supports parent/child sharing** (L2447 plus `ff_so_zone.c:244-256`): the master forking a worker does not consume a new sc (shared count), so the capacity pressure during the transition is smaller than one sc per worker.

### 5.2 The "gap list"

1. **exec is not hooked** (§3.2/§4.3): after a USR2 upgrade all so state is lost, and FF_MULTI_SC's `scs[]`/`current_worker_id` and FF_KERNEL_EVENT's fd mapping table cannot be rebuilt — the biggest hard gap for a lossless binary upgrade.
2. **No reclaim when a client exits abnormally** (§3.5): after kill -9 the sc slot leaks permanently (32 ceiling) and the stack-side connection fd is never closed; there is no heartbeat, monitoring or orphan reclaim.
3. **A client exit ≠ closing the connection**: detach only returns the sc slot (`ff_so_zone.c:229-264`); existing connections require the APP to close explicitly before exiting, otherwise they leak — "keep a connection alive until a new worker takes over" has no code path today, only theoretical potential (the reverse of advantage 2).
4. **ring wait_mode is not configurable at run time** (§2.3 deviation one): the promised `FF_RING_WAIT_MODE` is not implemented, so the low-CPU eventfd mode cannot be enabled online.
5. **In ring mode, multi-thread contention on the same sc** (last item of §4.4): in the default PIPELINE mode the sc is shared at process level and the ring path has no serialisation, so multi-threaded APPs face correctness risks (nginx's multi-process model is not affected).
6. **FF_KERNEL_EVENT polls kernel epoll 1/256** (L2333-2345): control-plane event latency is amplified, and channel events during reload (such as worker-exit notifications) respond more slowly — needs runtime quantification.
7. **sc capacity of 32 per instance** (`ff_socket_ops.h:45`): two generations of workers coexisting during reload plus FF_MULTI_SC occupying `scs[]` in order — the risk of sc exhaustion under frequent reloads is unassessed.
8. **Multiple instances cannot act as a client** (README L25-29): if nginx does proxying (including health-check active connections to upstreams) it is unusable in a multi-instance deployment.
9. **Maturity**: the memory-leak/deadlock risk on process exit is on record officially (README L22); the sendmsg/readv families are not heavily verified (L23); the ring route is still officially positioned as a "reserve" rather than a recommended production configuration (L379).
10. **spec C-005's ring residue cleanup is not implemented** (§2.3 deviation three): after v3.3 D2 the practical impact is small, but it is inconsistent with the design document.

## 6. Unconfirmed list (static analysis cannot settle these; runtime verification or further reading is needed)

1. **`ff_adapter_child_process_init` always attaches zone 0** (`ff_hook_syscall.c:3338`: `ff_attach_so_context(0)`, and that function under FF_MULTI_SC sets `ff_so_zone = ff_so_zones[0]`, `ff_so_zone.c:165-167`) and how that interacts with FF_MULTI_SC switching to the `current_worker_id` zone before fork (L2434-2435): after the child's sc variable is overwritten by the zone-0 new sc, whether the inherited value of `scs[current_worker_id].sc` matches the value actually used is doubtful from reading the code; it needs runtime logging (it directly affects the correctness of the nginx fork flow).
2. In the USR2 scenario, when the new master re-binds the same address, whether the old master has already closed the old listening fd (which decides whether `ff_bound_fds`/`ff_dup2` reuse holds) — it depends on the nginx USR2 timing and the stack-side unbind timing, and needs measurement.
3. How the fd mapping table behaves after fork inheritance under FF_KERNEL_EVENT (the master's map is inherited by all workers; whether the per-process map cleanup at L1875-1883 tramples across processes). **[2026-09-17 split, R-28] part confirmed**: `fstack_kernel_fd_map[]` (`ff_hook_syscall.c:255-258`) is an **in-process** static array (gated by `#ifdef FF_KERNEL_EVENT`, `FF_MAX_FREEBSD_FILES = 65536`) ⇒ **inherited by fork with copy-on-write (each process has an independent copy), lost after exec, and never trampled across processes** — this can be confirmed statically. **Still unconfirmed**: the **complete semantics of the fd table copy** (each worker inherits a snapshot from the fork instant and is independent afterwards; the interaction with `ff_adapt_user_proc_add`/`thread_add` is item 7).
4. How the `FF_PROC_ID` environment variable is actually used in the nginx scenario (README L421-429 mentions it, but the nginx deployment section only uses FF_NB_FSTACK_INSTANCE, L280-282); whether that variable survives exec. **[2026-09-17 split, R-28] part confirmed**: the read point is `ff_hook_syscall.c:3248` (`getenv(FF_PROC_ID_STR)`; the comment at `:3246` says "to set worker_id", i.e. the **worker_id / CPU affinity base**). **Still unconfirmed (explicitly marked)**: **whether `FF_PROC_ID` is preserved after exec — not measured** (Linux exec preserving environ is the expected behaviour, but this tree has not measured it, so no claim is made).
5. The measured occupancy curve of `scs[]`/zone under multiple HUP reload rounds (quantification of gap 7).
6. `03-interface-spec.md` / `04-test-spec.md` / `ld_preload_ring_support.md` / `ring_ipc_perf_offline_analysis.md` were not read; they may contain additional constraints on sc sharing and capacity design.
7. The complete semantics of the fd table copy in `ff_adapt_user_thread_add/exit` (library side) — this round only looked at the adapter-layer call sites, not the implementations of `ff_adapt_user_proc/thread`. **[2026-09-17 note, R-28] entry coordinates located**: `ff_adapt_user_thread_add()` is in **`lib/ff_compat.c:97`**, `ff_adapt_user_proc_add()` is in **`lib/ff_init_main.c:541`**; **the complete fd-table-copy semantics still need careful reading and remain unconfirmed**.
8. Edge behaviour of the kevent wrapper behind epoll_wait under multiple accepts / `multi_accept` (README L138 mentions differences; the `ff_epoll` implementation was not verified item by item).
