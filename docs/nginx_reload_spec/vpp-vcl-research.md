# 01 VPP/VCL Research: How VCL Supports Lossless nginx Reload (English)

> **English translation** of `docs/nginx_reload_spec/zh_cn/01-vpp-vcl-research.md` (v1.4). The Chinese text is
> authoritative; where the two differ, the Chinese original governs.
> Translated 2026-09-30.

| Item | Value |
| --- | --- |
| Document ID | 01 |
| Title | How VPP VCL supports lossless nginx reload: mechanisms, engineering problems and lessons |
| Version | v1.4 (on v1.3: **final gate G-D rework F-01 cross-document sweep** — the R-01 code fix (`lib/ff_dpdk_if.c:669-673`, per-generation pool `cache_size=0`) has landed; this document was swept end to end and **no "per-generation pool not zeroed / still 256" wording needs rewriting** (this document does not discuss per-generation mempools), so only the version header is synced. v1.2 = **corrected per the `plan_cross_audit` G-A verdict R-11** — two stale anchors in the §6.1 comparison table: `ff_init`/`ff_run` `ngx_process_cycle.c L397/L924` changed to `ngx_ff_module.c:317` and `ngx_process_cycle.c:681/1962/2732` (noting that the symbol is authoritative); `ngx_ff_worker_sem` `L459-L509` changed to `:2024-2037` creation / `:2063-2064` 15 s `sem_timedwait` / `:2090-2099` destroy + set NULL / `:2952-2953` worker0 `sem_post`, plus a note on the F2 root cause and fix confirmed in M6) |
| Date | 2026-08-18 (v1.1–v1.2 additions: 2026-09-17) |
| Status | pending human audit |
| Source artefact | `work/research-vpp-vcl.md` (researcher `researcher-vpp-vcl`, filed 2026-08-18). This document is the formalised rewrite: process narrative removed, all factual evidence kept (file:line, URL, commit hash, issue number), together with the unconfirmed markings and the single-source declarations; the "list of operations actually executed" is kept as §1 so the evidence stays traceable |
| Revision notes | v1.1 (2026-09-17): corrected by this round's spec×code cross-audit (`plan_audit`) — the §6.4 statement about the age of VPP issue #3547 changed from "crash chain unfixed for three years" to the fact per `gh` metadata (created 2025-02-02, closed without a fix, nearly two years ago). **v1.2 (2026-09-17): corrected per the `plan_cross_audit` G-A verdict R-11** — two stale anchors in §6.1 fixed (`ff_init`/`ff_run` and `ngx_ff_worker_sem`), see the Version row. **v1.3 (2026-09-18): final gate G-D rework F-01 cross-document sweep** — the R-01 code fix has landed; the sweep found no R-01 wording here, so only the version header is synced. **v1.4 (2026-09-18): R-01 mechanism error wrap-up (G-D "must be completed before commit")** — the sweep found no landing point for that mechanism error here (this document does not discuss per-generation mempools), so only the version header is synced |

Related: [00 Overview](overview.md) | [02 Other Project Research](other-projects-research.md) | [06 Solution Design](solution-design.md)

---

## 1. Research method and the operations actually executed

### 1.1 Searches and fetches actually performed

| # | Operation | Keywords / URL | Result |
| --- | --- | --- | --- |
| 1 | web_search | "VPP VCL Communication Library architecture LDP LD_PRELOAD docs.fd.io" | hit docs.fd.io 18.01 vcl_ldpreload doc, FDio/vpp wiki, DeepWiki |
| 2 | web_search | "vppcom_fork VCL fork child process handling session ownership" | hit DeepWiki VCL chapter, Envoy VCL socket doc |
| 3 | web_search | "FDio vpp nginx VCL graceful reload zero downtime issue" | hit FDio/vpp wiki VPP-HostStack-LDP-nginx, the VSAP project (gitee mirror) |
| 4 | web_search | "VPP session layer app namespace app worker svm_fifo message queue architecture" | hit DeepWiki session layer, FDio/vpp wiki SessionLayerArchitecture |
| 5 | web_fetch | https://github.com/FDio/vpp/wiki/VPP-HostStack-LDP-nginx | full text extracted |
| 6 | web_fetch | https://deepwiki.com/FDio/vpp/2.2-vpp-communication-library-(vcl) | full text extracted (indexed 2026-08-17, commit ebad6e) |
| 7 | web_fetch | https://deepwiki.com/FDio/vpp/2.1-session-layer-architecture | full text extracted |
| 8 | web_fetch | https://docs.fd.io/vpp/18.01/vcl_ldpreload_doc.html | full text extracted (old documentation) |
| 9 | web_fetch | https://github.com/FDio/vpp/wiki/VPP-HostStack-VCL | full text extracted |
| 10 | web_fetch | https://gitee.com/mirrors_gerrit_fd_io/r_vsap (and the vpp_patches, ldp, common subdirectories) | README and directory structure extracted |
| 11 | web_fetch | https://docs.fd.io/csit/master/report/introduction/methodology_hoststack_testing/methodology_vsap_ab_with_nginx.html | full text extracted (CSIT-2302.11) |
| 12 | gh CLI | `gh search issues 'nginx' / 'reload' / 'SIGUSR2' / 'VCL fork' -R FDio/vpp` | hit #3547 / #3645 / #3490 / #3463 / #3189 and others |
| 13 | gh CLI | `gh issue view 3547 / 3645` (with all comments) | details and maintainer replies extracted |
| 14 | gh CLI | `gh api search/commits q=repo:FDio/vpp+fork+vcl` plus per-sha `gh api repos/FDio/vpp/commits/<sha>` | date / message / file list of 7 key commits |
| 15 | curl raw.githubusercontent.com | `src/vcl/{vppcom.c,ldp.c,vcl_locked.c,vcl_private.c,vcl_private.h,vppcom.h}` and `src/vnet/session/{application.c,application.h,application_worker.c}` on FDio/vpp master/v21.06/v20.09/v19.08/v19.04/v18.07, read by grep/sed section extraction | fork handling, worker cleanup and listener-owner migration code all read in the original |
| 16 | curl gitee raw | r_vsap `vpp_patches/common/0001-session-pinning.patch`, `vpp_patches/ldp/master/0001-LDP-remove-lock.patch` | patch text read |
| 17 | local search | `/data/workspace/f-stack` `adapter/syscall/README.md`, `app/nginx-1.28.0/src` (`ngx_ff_module.c`, `ngx_process_cycle.c`), git log | F-Stack current-state comparison material |

### 1.2 Cross-validation

- VCL three-layer architecture (LDP/VLS/VCL): three-way agreement between the FDio/vpp wiki (VPP-HostStack-VCL), DeepWiki 2.2 and the source (the file header comment of `vcl_locked.c`).
- The fork three-phase mechanism: three-way agreement between the source (master `vcl_locked.c` L2005-L2060, L2280), the DeepWiki description, and the commit history (053a0e44ed / 47c40e2d94).
- The nginx reload problem: issue #3547 (symptom plus reporter analysis) and issue #3645 (reproducing versions plus maintainer analysis) corroborate each other; the VPP source comment (the reason for deferred SIGCHLD cleanup) and the #3547 deadlock analysis corroborate each other.
- The VSAP project: three-way agreement between the gitee mirror README, the official CSIT documentation and the patch text.

## 2. VCL architecture facts (with sources)

### 2.1 Layering: LDP → VLS → VCL (vppcom) → VPP session layer

Source: https://github.com/FDio/vpp/wiki/VPP-HostStack-VCL (maintained by Dave Wallace, edited 2026-04-21); consistent with the layout of `src/vcl/`.

- **VCL (vppcom)**: a POSIX-like but not POSIX-compatible integer-handle API that manages the interaction with the session layer and supports multi-worker applications. Source `src/vcl/vppcom.c`, `vcl_private.c/h`.
- **VLS (VCL Locked Sessions, `src/vcl/vcl_locked.c`)**: a locking shim above VCL. Intended for applications that cannot avoid sharing sessions across workers or cannot register workers explicitly. Three operating modes (summarised from the original file-header comment of `vcl_locked.c` L56-L73):
  1. per-process workers: intercept `fork` and treat every child as a new worker that must register with VCL; VLS sessions are cloned and then **explicitly shared** between workers, only the shared session is locked, and only one process may operate on it at a time;
  2. per-thread workers: each new pthread registers as a worker (enabled by configuration); when a thread accesses a session it does not own, the clone is shared implicitly through a VCL+VPP RPC request;
  3. single-worker multi-thread: no assumption is made, locking is aggressive.
- **LDP (`src/vcl/ldp.c`, `libvcl_ldpreload.so`)**: an LD_PRELOAD shim that intercepts socket/bind/connect/epoll* and redirects them to VLS/VCL. The wiki says verbatim that "LDP is not guaranteed to always work"; statically linked applications are not supported; the combination of "syscall + options + thread and fork behaviour" is only partially supported.

### 2.2 The application attach model: application / app namespace / app worker

Source: DeepWiki 2.1 (https://deepwiki.com/FDio/vpp/2.1-session-layer-architecture) plus `src/vnet/session/application.h`.

- **application_t (app)**: one VCL attach corresponds to one app; attaching binds an app namespace (isolated routing/address space, namespace-id + secret, binary API only).
- **app_worker_t (app_wrk)**: the working entity of an app, one per process/thread. Key structure fields (checked against `application.h` L32-L81):
  - `event_queue`: that worker's **svm message queue** (the VPP→app event channel);
  - `listeners_table`: the table of listening handles managed by that worker;
  - `half_open_table`: the half-open connection pool ("Tracked in case worker detaches" — a field designed for worker detach);
  - `connects_seg_manager`: the shared-memory segment manager dedicated to outbound connections;
  - `api_client_index`: commented explicitly as "Needed for multi-process apps".
- **The session_t ownership triple**: `thread_index` (VPP thread) + `session_index` + `app_wrk_index` (owning app worker); `session_handle_t` is a 64-bit handle encoding (thread_index, session_index).
- **app_listener_t (the app-level shared structure of a listen)**: a `workers` bitmap (which app workers are accepting) + `accept_rotor` (rotating cursor) + `cl_listeners` (the vector of fifo-backed cl sessions, one per app worker). **There is only one listen socket on the VPP side; it belongs to the app, and several app workers share it through the bitmap** — this is the structural basis of lossless reload.

### 2.3 Data and event channels: svm fifo + svm_msg_q

Source: DeepWiki 2.1/2.2 plus `src/vcl/vppcom.c` (the control message family at L43-L224).

- **Data plane**: one pair of shared-memory fifos per session (rx/tx, `svm_fifo_t`), allocated in shared-memory segments divided per app/worker (segment manager).
- **Control plane (app→VPP, ctrl_mq)**: SESSION_CTRL_EVT_LISTEN / CONNECT / CONNECT_STREAM / UNLISTEN / SHUTDOWN / DISCONNECT / TERMINATE / APP_DETACH (`vppcom.c` L43-L224).
- **Event plane (VPP→app, app_event_queue)**: SESSION_IO_EVT_RX/TX, SESSION_CTRL_EVT_CLOSE/HALF_CLOSE/RESET, etc.; on the VPP side the vlib node `session_queue_node` handles app requests.
- **Attach channel, one of two**: the app socket API (`app-socket-api`, default `/var/run/vpp/app_ns_sockets/default`) or the legacy binary API (`api-socket-name`); once the session layer enables the socket API, all applications must use it uniformly (wiki VPP-HostStack-VCL, "additional mode limitations" section).
- **Notification**: with `use-mq-eventfd` enabled the message queue notifies through an eventfd, and the eventfd can be added to VCL's internal epoll (`vcl_mq_epoll_add_evfd`).

### 2.4 vcl_worker_t and the fd table

Source: DeepWiki 2.2 plus `vcl_private.h` L153-L190, L304-L307.

- Each vcl worker holds: the session pool, `ctrl_mq`, `app_event_queue`, `mqs_epfd` (the mq event epoll fd) and `forked_child` (the parent worker records the index of the child worker it forked).
- The fd table is **per-process local**: LDP separates native fds from VCL handles by handle shifting (`vlsh_bit_val`, tunable through the environment variable `LDP_ENV_SID_BIT`); there is no global cross-process fd table.
- A thread-local `__thread uword __vcl_worker_index` locates the current worker quickly (`vppcom.c` L11).

## 3. fork / session ownership mechanisms

### 3.1 The fork three-phase handling (master branch, `src/vcl/vcl_locked.c`)

Registration: `pthread_atfork(vls_app_pre_fork, vls_app_fork_parent_handler, vls_app_fork_child_handler)` (L2280-L2281).

1. **prepare (L2005-L2009)**: intercept SIGCHLD (`vls_incercept_sigchld`, saving the old handler) and call `vcl_flush_mq_events()` to drain the parent worker's mq events, so that mq consumption state is not inconsistent after the fork.
2. **parent (L2057-L2061)**: `vcm->forking = 1; while (vcm->forking);` — **the parent spins and waits** until the child handler finishes initialisation and clears it. That is, by the time `fork()` returns to the parent, the child's worker registration has necessarily completed.
3. **child (L2012-L2054)**:
   - `vcl_set_worker_index(~0)` clears the inherited old worker index from the memory image;
   - `vppcom_worker_register()` **registers a new app worker with VPP** (VPP allocates a new event_queue/segment);
   - `vls_worker_alloc()` creates a new VLS worker;
   - `vls_worker_copy_on_fork(parent_wrk)` (L1100-L1139): `pool_dup` copies the parent worker's whole session pool, `hash_dup` copies the vpp_handle→session_index hash, vep (VCL epoll) handles are rebuilt (`vls_validate_veps`) and all vls entries are re-attached from the parent vcl worker to the child;
   - `vls_share_sessions(parent, child)` establishes **explicit sharing** (shared_data: owner_wrk_index + workers_subscribed + a spin lock);
   - `parent_wrk->forked_child = the new worker index`.

### 3.2 Child exit reclaim: SIGCHLD interception plus deferred cleanup

Source: `vcl_locked.c` L1924-L1995 (master original).

- `vls_intercept_sigchld_handler`: on SIGCHLD it does **not clean up in signal context** (original comment: the parent may enter the handler holding locks such as localtime/mspace_free, and cleanup would take those locks again and deadlock — which corroborates the deadlock the #3547 reporter observed); it only appends the child worker index to `pending_vcl_wrk_cleanup` and chains back to the application's old handler.
- The real cleanup happens at the process's next `vls_epoll_wait/vls_select`: `vls_handle_pending_wrk_cleanup` → `vls_cleanup_forked_child` (wait for grandchildren to disappear, clean up recursively, `vls_cleanup_vcl_worker`: unshare sessions + `vcl_worker_cleanup(wrk, notify_vpp)`).
- **In app socket API mode `notify_vpp=0`** (original comment at L1871-L1877: "Since child may have exited and therefore fd of vpp_app_socket_api may have been closed, so DONOT notify VPP") — a child exit does not ask VPP to delete the app worker.
- `vcl_worker_cleanup` (`vcl_private.c` L118-L137): on notify it calls `vcl_api_app_worker_del`, then closes `mqs_epfd` and frees the session pool / hash / bitmap.
- **Known structural limitation**: inside `vls_intercept_sigchld_handler` the original comment reads `/* TODO we need to support multiple children */` — each worker records only one `forked_child`, so **multiple simultaneously live children are not supported** (the nginx pattern of forking workers serially, where the old worker exits before the next fork, works only by luck; concurrent multi-child respawn is risky).

### 3.3 Session ownership and the migration API

- Ownership: on the VPP side a session belongs to (VPP thread, app_wrk); on the VCL side session objects are pooled per worker and are **copied** on fork (copy plus explicit sharing), not referenced as the same object.
- **Migration API (commit 30e79c2e38, 2019-01-03, Florin Coras)**. Original commit message: "In case of multi process apps, after forking, the parent may decide to close part or all of the sessions it shares with the child. Because the sessions have fifos allocated in the parent's segment manager, they must be moved to the child's segment manager."
  - Message structure (18-byte limit, u16 worker index): `session_worker_update_msg_t{client_index, wrk_index, req_wrk_index, handle}`, and the reply carries the new rx/tx fifo addresses and the segment_handle.
  - Current master state: the VCL-side `vcl_send_session_worker_update` (`vppcom.c` L272) still exists and is called by `vcl_locked.c` L982 in the session-sharing flow (it asks VPP to move the fifo into the new worker's segment). The VPP-side migration entry point for ordinary sessions was not located in `application.c` (see the unconfirmed list in §7).
- **listen owner migration**: `application_change_listener_owner` (`src/vnet/session/application.c` L1539-L1557, master original): the new app_wrk calls `app_worker_start_listen`, the old app_wrk calls `app_worker_stop_listen`, and `s->app_wrk_index` is changed. Listen ownership can change hands between app workers seamlessly.
- **The cross-process relation between epoll fds and sessions**: the fd table is per-process local (inherited naturally when fork copies the memory image); a VCL epoll (vep) is a worker-private object, so vep handles must be remapped when sessions are copied on fork (commit 5788a34be6 "vcl: validate vep handle when copying sessions on fork", 2021-06-22); `vcl_locked_session_t` additionally has a `libc_epfd` field for mixed use with libc epoll.

### 3.4 Is the mq shared

No. Each vcl worker is given its own ctrl_mq and app_event_queue by VPP at registration; at fork the pre-fork only flushes the parent worker's own events, and after registration the child uses its own new queue. Concurrent parent/child access to the same session is serialised by the VLS explicit sharing lock.

### 3.5 Fork support evolution timeline (all commit hashes verified through the gh api)

| Date | Commit | Note |
| --- | --- | --- |
| 2017-11-07 | 2e005bbbdf | "VCL: handle process fork." (vppcom.c, the earliest fork handling, Dave Wallace) |
| 2018-11-13 | 053a0e44ed | "vcl/session: apps with process workers": on fork the child is registered with VPP as a new worker (the per-process worker model is established) |
| 2018-11-27 | 47c40e2d94 | "vcl: basic support for apps that fork": intercept fork + register a new worker + parent/child session sharing |
| 2019-01-03 | 30e79c2e38 | "vcl/session: add api for changing session app worker": session ownership migration (moving the fifo segment) |
| 2019-01-15 | f9240dc920 | "vcl: move forking logic to vls" (fork logic moves from vppcom to `vcl_locked.c`; after this there is no fork logic in vppcom.c — which is why grepping `vppcom.c` in v19.04~master finds no `vppcom_fork`) |
| 2021-06-22 | 5788a34be6 | validate the vep handle when copying sessions on fork (fixes EPOLL_CTL_DEL during child cleanup) |
| 2025-01-06 | 4d9df5cb3d | "vcl: fix vls wrk index on fork" (Type: fix) — the most recent fork-related fix |

[Note] `vppcom_fork()`, the function name mentioned in the task description, does not appear anywhere in the FDio/vpp mainline source (vppcom.c from v18.07 to master); since 2019 fork handling lives in `src/vcl/vcl_locked.c` (the VLS layer) under the atfork three-phase handler names above. "vppcom_fork" is more likely an old document's generic name for "VCL handles fork".

## 4. VPP + nginx integration and reload behaviour

### 4.1 Official integration methods

**(a) The LDP method (no nginx code change)** — source: https://github.com/FDio/vpp/wiki/VPP-HostStack-LDP-nginx (full text fetched):

- VPP `startup.conf` needs `session { use-app-socket-api }`;
- start: `sudo LD_PRELOAD=$LDP_PATH VCL_CONFIG=$VCL_CFG nginx -c nginx.conf`;
- minimal `vcl.conf`: `heapsize/segment-size/add-segment-size/rx-fifo-size/tx-fifo-size/app-socket-api /var/run/vpp/app_ns_sockets/default`;
- nginx.conf configuration verified to work: `worker_processes 4; daemon off; master_process on;` (events block uses epoll);
- performance advice: use taskset to bind nginx to the same NUMA cores as the VPP workers and the NIC.

**(b) The VCL code integration method (nginx source modified)** — source: the VSAP project (gerrit.fd.io/r/vsap, gitee mirror https://gitee.com/mirrors_gerrit_fd_io/r_vsap):

- based on nginx 1.14.2, `./configure --with-vcl --vpp-lib-path=... --vpp-src-path=...`;
- the repository provides `nginx_patches/0001-ngxvcl.patch` plus `vpp_patches/vcl/0001-ngxvcl-api.patch` (the VPP-side API patch);
- VSAP (VPP Stack Acceleration Project, an official FDio project, see https://github.com/FDio and the CSIT documentation) patches to VPP:
  - `vpp_patches/common/0001-session-pinning.patch` (2019-10-17, Intel, Sun Guoao): adds a per-VPP-thread app worker rotation table (`vpp_app_worker_map_t`) to app_listener, so accept distribution changes from global rotation to rotation over a worker subset fixed per VPP thread — a performance optimisation, not a reload feature;
  - `vpp_patches/ldp/{2001,2005,master}/0001-LDP-remove-lock.patch` (2020-06-03, zsj): **removes `vcl_locked.c` (the whole VLS lock layer) directly from CMakeLists**, so `ldp.c` talks to vppcom directly; the README claims it "saves about 100% of single-core CPU cycles" for CPU-bound applications. The price is giving up VLS's multi-thread/multi-process lock protection (it then depends on the application's own worker-partitioning discipline).
- The VSAP repository has no LICENSE file; the README says nothing about nginx reload support (confirmed — not "not found").

**(c) Test baseline**: CSIT officially measures VSAP nginx CPS/RPS with `ab` on a 100G NIC (https://docs.fd.io/csit/master/report/introduction/methodology_hoststack_testing/methodology_vsap_ab_with_nginx.html, CSIT-2302.11); the document states explicitly that the LD_PRELOAD approach "naturally has more overhead and other limitations".

### 4.2 The mechanism of nginx HUP reload in VCL mode (code-derived chain)

The behaviour corresponding to the standard HUP sequence of the nginx master under VCL (derived from the source facts in §3; each step marked with its basis):

1. The master forks a new worker → the **atfork child handler** registers a new app worker for each new worker and copies the parent session pool (including the listen session handle), sharing it explicitly with the master (§3.1).
2. The new worker's listen takes effect: the app_listener's workers bitmap on the VPP side gains the new app worker (`app_worker_start_listen`, logic near `application.c` L1314), and accept events begin to be distributed to the new worker in rotation (`app_listener_select_worker`, L173).
3. The old worker exits after finishing its existing keepalive requests → the master receives SIGCHLD → VLS intercepts it and **defers cleanup of the old child's vcl worker to epoll_wait** (§3.2); in app socket API mode no app worker del is sent to VPP.
4. **listen is not interrupted**: the listen session belongs to the app on the VPP side (app_listener); as long as some worker is in the bitmap it is not unlistened; `application_change_listener_owner` additionally supports an explicit owner change (§3.3).
5. Established connections are not migrated across processes: the old worker's connections close when the old worker exits (this matches native nginx semantics — on reload the old worker finishes the current request and then closes keepalive connections, which is a graceful exit, not packet loss).

**What is supported natively**: the process-independence of listen (held at a single point on the VPP side), copying the session table and registering the worker at fork, the parent/child sharing lock, deferred cleanup, and the session ownership migration API.

**Conclusion: the "losslessness" of HUP reload is supported mechanically by the VCL architecture (listen is not switched, old and new workers coexist, the old worker exits gracefully), but the implementation path has unfixed bugs (see §4.3).**

### 4.3 Known issue evidence (verified with the gh CLI)

**Issue #3547 [VPP-2086] "VCL and VPP(V2306) will crash when reloading nginx using jemter test" (CLOSED, closed without an actual fix; the title is quoted verbatim from the reporter, "jemter" is their original spelling and has not been corrected)**
https://github.com/FDio/vpp/issues/3547

- Scenario: JMeter with 100 threads plus a nginx reload every 2 seconds (worker auto=8) → nginx or vpp crashes quickly.
- Reporter's root-cause analysis (summary of the original): vcl and vls share `__vcl_worker_index` (TLS); when the old nginx exit interleaves with the new fork, the indices of the two worker pools (vcl/vls) do not match; a chain then follows: VPP loops forever in `session_wrk_handle_evts_main_rpc`, nginx crashes in `vcl_send_session_accepted_reply` (`session->vpp_evt_q = 0`, reached through the `vppcom_session_unbind` path), VPP crashes in `app_worker_get`. The reporter wrote three patches, still could not finish, gave up and filed the bug.
- Maintainer florincoras closed it with: "We're lacking context/email for this one. Please reopen if this issue was not solved" — **no fix given**. The 2025-01 commit 4d9df5cb3d "fix vls wrk index on fork" is suspected to target that worker-index mismatch (the timing matches, but there is no issue link; this is only an inference, not confirmed).

**Issue #3645 "VPP main thread stuck at session_wrk_handle_evts_main_rpc() when working with nginx through VCL" (OPEN, reported 2025-11-18, still open as of 2026-08)**
https://github.com/FDio/vpp/issues/3645

- Scenario: `kill -HUP` to reload nginx while `wrk` is load-testing forwarding → the **VPP main thread hangs forever** in `session_wrk_handle_evts_main_rpc()`, vppctl becomes unreachable, the http client cannot connect; nginx workers recover after a while but VPP does not.
- Reproducing versions: reproduced on 22.10 / 23.10 / 25.10; reload with no traffic is fine; increasing event-queue-length only delays it (8192 hangs at the first reload; 100000 survives the first one).
- Maintainer florincoras' analysis (original comment): suspects "a bug in the code that tries to synchronize events when one of them needs to be handled on main thread (typically a listen)", or a side effect of a connect flood under high load forcing control events onto the main thread.
- The reporter confirmed that the `show app mq` queue was not full, ruling out simple congestion; the symptom looks more like an event-synchronisation deadlock/livelock.
- **This is the most direct current evidence about "nginx reload in VCL mode": as of VPP 25.10, reloading under traffic still hangs VPP, unresolved by the community.**

**Others related (titles only, not expanded individually)**:

- #3490 [VPP-2028] "The number of nginx startup threads is incorrect" (closed)
- #3463 [VPP-2001] "VCL crash when test nginx via ldp" (closed)
- #3189 [VPP-1726] "VPP + VCL fail / crash on small load" (closed)

**SIGUSR2 / binary upgrade (exec a new binary)**: `gh search issues 'SIGUSR2' -R FDio/vpp` returns nothing relevant (only one unrelated python API issue); the wiki and documentation also say nothing about preserving VCL state across exec. **No** support or discussion of VCL for nginx binary hot upgrade (SIGUSR2 + exec) was found. By mechanism, exec would discard all VCL user-space state (worker registration, handle table, shared-memory mappings) and the new process must attach again completely — marked as inference, not confirmed.

## 5. Known limitations summary

| Limitation | Source |
| --- | --- |
| LDP is not guaranteed to work; statically linked applications unsupported; syscall/thread/fork combination support incomplete | wiki VPP-HostStack-VCL, original text |
| The VCL API is not thread-safe; sessions must not be shared across workers (VLS locking required) | same |
| binary API and app socket API are mutually exclusive | same |
| The VLS fork model supports only a single live child (TODO comment) | original comment near `vcl_locked.c` master L1957 |
| In app socket API mode a child worker exit does not notify VPP (app worker state may be left behind) | original comment `vcl_locked.c` L1871-L1877 |
| Reloading nginx under traffic → VPP main hangs (22.10~25.10), open and unfixed | issue #3645 |
| High-frequency reload → vcl/vls worker pool index misalignment, crash chain (V2306, closed without fix) | issue #3547 |
| Inherent overhead and other limitations of the LD_PRELOAD approach | official CSIT documentation |
| After VSAP's lock-free LDP removes the VLS lock layer, sharing sessions across processes/threads loses lock protection | r_vsap `vpp_patches/ldp` patch text (deletes `vcl_locked.c` from CMakeLists) |

## 6. Lessons for F-Stack

### 6.1 Structural comparison (verified against the local code)

| Dimension | VPP + VCL | F-Stack app/nginx (source integration) | F-Stack adapter/syscall (LD_PRELOAD) |
| --- | --- | --- | --- |
| Stack location | separate VPP process, centralised single instance | one FreeBSD stack instance embedded per worker process (`ff_init` + `ff_run`). **[2026-09-17 correction, R-11] the original reference `ngx_process_cycle.c L397/L924` is stale**: the only call site of `ff_init()` is **`app/nginx-1.28.0/src/event/modules/ngx_ff_module.c:317`**; `ff_run` is at **`ngx_process_cycle.c:681`/`:1962`/`:2732`** (the M1~M6 implementation shifted line numbers systematically). **Prefer symbol names over line numbers** | separate fstack instance process (`ff_handle_each_context` loop); the app process attaches through libff_syscall.so with an sc context |
| listen ownership | held at a single point by the VPP-side app_listener, shared by app workers through a bitmap | each worker's stack instance binds/listens on its own (reuseport-like semantics) | held by the fstack instance; fds mapped through hooks (FF_MULTI_SC: the master pre-creates an fd and binds an sc per worker, verified in the README) |
| app↔stack channel | shared-memory svm fifo (data) + svm_msg_q (events/control), an independent mq per worker | in-process direct calls to ff_api (no IPC) | hugepage shared-memory sc context plus sem or a DPDK SPSC rte_ring IPC (FF_USE_RING_IPC, ld_preload_ring_spec) |
| fork semantics | pthread_atfork three phases: register a new app worker + copy the session pool + explicit sharing; deferred SIGCHLD cleanup | after the master forks a worker, startup is synchronised with a POSIX shm semaphore (`ngx_ff_worker_sem`, 15 s timeout). **[2026-09-17 correction, R-11] the original reference `ngx_process_cycle.c L459-L509` is stale**: the measured landing points are **creation `:2024-2037`** / **15 s `sem_timedwait` `:2063-2064`** / **destroy + set NULL `:2090-2099`** / **worker0 `sem_post` (with a null check) `:2952-2953`**. Also note that M6 confirmed this semaphore's lifetime mismatch as the root cause of F2 (respawn storm); the fix is set-NULL after destroy plus a null check before post (see [07](milestones.md) §2.7(3)); the new worker gets a brand-new stack instance | fork supported since 2023 (PR #887: each forked process has its own FreeBSD `struct thread`); FF_MULTI_SC uses a static scs array, selecting the sc by `current_worker_id` |
| listen continuity at reload | guaranteed mechanically (listen decoupled from processes + worker register/unregister) | no guarantee: the new worker's new instance re-establishes listen, leaving a window → packet loss / broken connections (a known team problem; this document gives the state comparison) | structurally closer to VPP (the stack process is centralised), but the sc→instance mapping is statically pre-allocated, so changing the worker set at reload requires reconfiguration |

### 6.2 Separating the two levels: NIC queue ownership vs listening fd ownership (against the #1036 root cause)

The root cause of F-Stack HUP packet loss is already confirmed by the local archive #1036 (`docs/f-stack-issue-ana.md`, duplicate of #547): in the multi-process model each worker exclusively owns a NIC hardware queue (RSS); at reload the old worker exits while the new worker has not finished DPDK/F-Stack stack initialisation, leaving a "queue with no owner" window that loses packets — **the problem is in the data plane (NIC queue ownership), not in the listening fd itself.** The VPP/VCL structure happens to decouple both levels:

- **Data plane (NIC queue ownership)**: the DPDK NIC is taken over by the independent VPP process (vfio-pci); nginx is only a client attaching through shared memory. A reload only replaces app workers; the VPP process and queue ownership do not move at all — **the receive queue always has an owner**, so a "no-owner window" does not exist structurally. Within the reload window, SYNs and data packets keep being taken by VPP (held in the listener's accept queue and in per-session fifos) and are distributed once the new app worker is registered into the bitmap. Issue #3645 confirms this from the opposite direction: when reloading under traffic goes wrong, what hangs is VPP-side event synchronisation (which shows packets keep entering VPP), not a queue losing its owner.
- **Control plane (listen ownership)**: listen is a single app-level object on the VPP side (app_listener); an app worker is merely an accept tenant in the bitmap, so adding or removing workers does not touch listen itself, and there is no listening gap.

Inference for F-Stack: for the app/nginx route (a stack instance per worker, directly owning queues) to eliminate the no-owner window, it must detach "receive/queue ownership" from the worker lifetime — exactly the direction already verified by #1078 primary_slim (the primary owns no queue and does not exit; when secondaries are replaced, queue ownership does not change; the PoC measured 12/12 connections with zero interruption after killing the primary, see `docs/issue_1078/zh_cn/`), and isomorphic with the adapter/syscall route (the fstack instance process is centralised and does not exit with an app reload). Three independent sources (the VPP architecture, the #1078 PoC, the adapter/syscall design) point at the same conclusion: **centralised queue/receive ownership, decoupled from the business process lifetime, is the structural precondition for a lossless reload on a user-space stack**; listening fd ownership is a second-order control-plane problem.

[Note] Cross-corroboration with [02 Other Project Research](other-projects-research.md): its statement that "**no precedent for migrating established TCP connections was found in this search range**" (Envoy's original words: existing connections are not transferred; Envoy's sentence describes only Envoy's own behaviour and is not an industry-wide survey conclusion) corroborates §4.2 point 5 here (in VCL mode the old worker's connections close on drain rather than migrating); its Facebook LPC 2021 pattern of "traffic keeps going to the old instance until the new one is ready" is isomorphic with the app_listener workers bitmap mechanism here (accept is not distributed to a new worker until it is registered in the bitmap, and VPP keeps receiving packets without loss) — "do not cut traffic over before ready" is free in the VPP structure, while in the F-Stack structure it first requires a queue that always has an owner.

### 6.3 Concrete mechanisms worth borrowing (ordered by relevance to the F-Stack nginx reload problem)

1. **Centralised receive ownership (NIC queues decoupled from business processes)**: see §6.2 — this is the most direct counterpart in the VPP model to F-Stack's #1036 root cause (the RSS queue with no owner), and it outranks every control-plane mechanism.
2. **listen ownership decoupled from the process lifetime**: VPP puts listen in a stack-side app-level object (app_listener) and a worker is just an accept tenant in the bitmap; adding or removing workers does not touch listen. For F-Stack not to lose SYNs at reload, the core direction is to promote listen (or its equivalent) from "some worker's stack instance" to centralised state across workers — cheaper on the adapter/syscall route (the fstack instance is already central) than on the app/nginx one-stack-per-process route.
3. **Worker registration plus fork-copied session tables**: the atfork three phases (flush mq → parent spins until the child has registered → child copies the session pool and rebuilds epoll handles) is a mature template for "hot-joining a process"; F-Stack's FF_MULTI_SC static scs array could evolve towards dynamic worker register/unregister.
4. **Session/listen ownership migration APIs**: `session_worker_update` (moving the fifo segment) and `application_change_listener_owner` (changing the listen owner) are the direct mechanisms for an old master exiting and a new one taking over (the commit message of 30e79c2e38 was written exactly for multi-process app parent/child handover).
5. **Deferred SIGCHLD cleanup**: do not do complex cleanup in signal context (the VPP comment names the localtime/mspace_free lock deadlock risk); park it as pending and handle it in the event loop — a general engineering practice that F-Stack should follow on either route.
6. **An independent mq per worker plus a pre-fork flush**: avoids contention over consumption state when parent and child share a queue.
7. **Test method**: the VPP community's verification pattern is JMeter/wrk continuous traffic plus a reload every 2 seconds (both #3547 and #3645 reproduce that way). The F-Stack reload acceptance spec should gate on "thousands of reloads under traffic + no deadlock or crash on the VPP/fstack side + zero connection errors".

### 6.4 VCL's lessons (negative)

- VCL's reload path (fork registration + two generations of workers coexisting + detach cleanup + event synchronisation) is one of the most bug-dense areas of the whole chain: #3547's crash chain (gh metadata: created 2025-02-02, closed unfixed nearly two years later) and #3645's hang, still open. This shows that even where the architecture "mechanically supports" lossless reload, keeping cross-process state consistent (TLS worker index, per-worker pools, VPP-side event synchronisation) is extremely hard to get right. F-Stack should make reload an explicit, observable state machine (each stage instrumentable and revertible) rather than implicit logic scattered across fork/signal hooks.
- VCL trades correctness for a locking shim (VLS) plus explicit sharing, and then trades performance for removing the lock layer (VSAP) — the dilemma itself shows that lock granularity for "several processes sharing one stack" is the core difficulty. F-Stack's per-worker independent instance route naturally avoids shared locks, but its price is listen continuity; that is a route trade-off, not an implementation defect.

## 7. Unconfirmed list

1. **The body of the VPP-HostStack-nginx wiki page** (the VCL code-integration nginx document): the page exists (edited 2026-04-21), but GitHub wiki pages render dynamically and both web_fetch and curl only got the navigation frame; the body was **not obtained**.
2. **The content of VSAP `nginx_patches/0001-ngxvcl.patch` and `vpp_patches/vcl/0001-ngxvcl-api.patch`**: only their existence and the README description (the `--with-vcl` integration, TLS environment variables) are confirmed; the patch bodies were not read.
3. **SIGUSR2 / exec binary hot upgrade**: no issue, document or commit evidence in FDio/vpp; "no support found" for VCL; "exec discards all VCL state and must attach again" is a mechanical inference, not measured.
4. **The correspondence between commit 4d9df5cb3d (fix vls wrk index on fork) and issue #3547**: timing and symptom match, but neither the commit nor the issue references the other — not confirmed.
5. **The VPP-side worker_update migration entry point for ordinary sessions**: the VCL-side send function (`vppcom.c` L272) and the message structure are confirmed present on master, but the corresponding handler in VPP's `application.c`/`session.c` was not located (possibly renamed or moved) — not confirmed; the listen migration entry point `application_change_listener_owner` has been verified.
6. **Details of #3490 / #3463 / #3189**: only titles and states verified; the bodies were not read individually.
7. **Whether #3645 is fixed after VPP 25.10 (e.g. 26.01/26.04)**: the issue is still open with no linked PR; 2026 commits were not checked one by one.
8. **The AsterNOS-VPP article** (2026-05, Baijiahao/Zhihu/bilibili): marketing content from a domestic vendor claiming to run native nginx on LDP; the technical details were not re-confirmed and are not used as mechanism evidence.
9. The relation between the VSAP session-pinning patch and the latest VPP (25.x): the patch is based on 2019 code (the old `application.c` structure) and that file has been refactored on master; whether the patch still applies was not verified.

## Appendix: source index for this document

- FDio/vpp wiki:
  - https://github.com/FDio/vpp/wiki/VPP-HostStack-VCL
  - https://github.com/FDio/vpp/wiki/VPP-HostStack-LDP-nginx
  - https://github.com/FDio/vpp/wiki/VPP-HostStack-nginx (body not obtained)
- DeepWiki (auto-generated FDio/vpp documentation, indexed 2026-08-17, commit ebad6e):
  - https://deepwiki.com/FDio/vpp/2.1-session-layer-architecture
  - https://deepwiki.com/FDio/vpp/2.2-vpp-communication-library-(vcl)
- VPP source (raw.githubusercontent.com, master and historical tags): `src/vcl/{vcl_locked.c, vcl_private.c/h, vppcom.c/h, ldp.c}`, `src/vnet/session/{application.c/h, application_worker.c}`
- FDio/vpp commits: 2e005bbbdf / 053a0e44ed / 47c40e2d94 / 30e79c2e38 / f9240dc920 / 5788a34be6 / 4d9df5cb3d
- FDio/vpp issues: #3547 / #3645 (open) / #3490 / #3463 / #3189
- VSAP: https://gerrit.fd.io/r/vsap (gitee mirror https://gitee.com/mirrors_gerrit_fd_io/r_vsap ; the patch text was read through gitee raw)
- CSIT: https://docs.fd.io/csit/master/report/introduction/methodology_hoststack_testing/methodology_vsap_ab_with_nginx.html
- docs.fd.io: https://docs.fd.io/vpp/18.01/vcl_ldpreload_doc.html
- F-Stack local: `/data/workspace/f-stack/adapter/syscall/README.md`, `app/nginx-1.28.0/src/event/modules/ngx_ff_module.c`, `app/nginx-1.28.0/src/os/unix/ngx_process_cycle.c`, git log
- F-Stack local archives: `docs/f-stack-issue-ana.md` (#1036/#528/#547: the root cause of F-Stack reload packet loss = the RSS queue with no owner, duplicate chain); `docs/issue_1078/zh_cn/` (primary_slim: a PoC decoupling queue ownership from the primary's lifetime)
