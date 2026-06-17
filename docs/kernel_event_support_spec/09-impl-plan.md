# 09 Implementation Plan: F-Stack + Kernel Stack Automatic Dual-Stack Coexistence (R0-R7)

> **Document ID**: SPEC-KE-09 (implementation-phase plan)
> **Version**: v6 (native automatic dual-stack coexistence paradigm)
> **Date**: 2026-06-17
> **Status**: R0-R7 all done and gate PASS (**R7 v6 auto dual-stack measured, commit 13b418191**; real-machine single listen(80) dual-stack 9.134.214.176 + 127.0.0.1 each HTTP 200)
> **Basis**: the v6 spec in this directory (00-08); line numbers are subject to the actual code, gatekeeper re-verified. v6 changes are landed; §3 below is implemented code.
> **Authoritative full text**: `zh_cn/09-impl-plan.md`.

---

## 0. Scope and Gate

- **R0-R6 done**: revert → spec → hook solidification → native per-fd coexistence → tests/perf → gate/commit → compile-macro gating (ba148589d).
- **R7 done (commit 13b418191)**: native automatic dual-stack (default dual-build/dual-drive + `ff_native_fd_map` + dual-stack events + accept ownership + dual-fire connect) landed and gate PASS.
- **Hard gate (met)**: dual-mode compilation passes + cmocka dual-mode all green + **macro-off `nm` coexist symbols=0 (size 6539682, byte-for-byte identical to baseline, zero regression)** + **F-Stack business fast path + single-stack connection hot path zero regression (NFR-1/NFR-2)**.
- **Coexistence iron rule (NFR-3)**: the F-Stack fd is always built and always carries the business; satisfied.
- **connect contract**: implemented per the user-confirmed Q2=B (dual-fire connect, F-Stack as the return/data primary path) in `05 §6`.

---

## 1. Agent Team Topology

| Agent | Role | Responsibility |
|---|---|---|
| Leader | orchestration+authoring+arbitration | orchestration, coding, gate arbitration, commit, bounce counting |
| arch-probe | architecture probe (read-only) | measure v5 current state + hook isomorphism/divergence |
| spec-writer | spec upgrade | v6 Chinese & English docs (this round's output) |
| build | compilation (actual build) | lib dual-build / tests |
| unit-test | unit tests | cmocka v6 dual-mode cases |
| review | review (read-only) | minimal diff/zero regression/coexistence iron rule/conventions |
| test | integration/performance | one-listen-many-uses real-machine dual-stack + fast-path no regression |
| gatekeeper | gate (read-only) | per-assertion + gate items |

**Gate rollback**: any phase failing bounces back to the previous step; ≤3 bounces for the same step, escalate to manual when exceeded; bounces recorded in `08`.

---

## 2. R0-R6 Change Points (done, measured anchors)

| Milestone | File | Change |
|---|---|---|
| R0 | `ff_syscall_wrapper.c`, `ff_host_interface.{c,h}` | revert the ff_host_socket side path (0748eff94) |
| R2 | `adapter/syscall/`, demo | hook solidification + same-process dual-stack demo |
| R3 | `ff_config.{c,h}` | `stack.kernel_coexist` (`:1027-1031`/`:1363`/`:321-323`) |
| R3 | `ff_host_interface.{c,h}` | 18 `ff_host_*` bridges + `FF_KERNEL_FD_BASE` |
| R3 | `ff_syscall_wrapper.c` | `ff_socket` per-fd either/or + 13-entry `ff_is_kernel_fd` routing |
| R3 | `ff_epoll.c` | `ff_epoll_pairs` merge |
| R6 | `lib/Makefile` + 7 files | `FF_KERNEL_COEXIST` gating (`:174-177` dual CFLAGS) |

---

## 3. R7 native automatic dual-stack per-file rework (v6 core, implemented commit 13b418191)

> All new code goes inside `#ifdef FF_KERNEL_COEXIST`; runtime `kernel_coexist=0` short-circuits; `SOCK_FSTACK`/macro-off is byte-for-byte zero regression.

### 3.1 `lib/ff_host_interface.h` (HOST_CFLAGS header)
- Inside the `#ifdef FF_KERNEL_COEXIST` block (currently `:94-160`) add accessor declarations:
  ```c
  int  ff_native_map_get(int fstack_fd);
  void ff_native_map_set(int fstack_fd, int host_fd);
  void ff_native_map_clear(int fstack_fd);
  ```
- **Do not touch the struct header** (avoid ABI skew, `10 §7`).

### 3.2 `lib/ff_host_interface.c` (HOST_CFLAGS)
- In the existing 18-bridge block (inside `#ifdef FF_KERNEL_COEXIST`) add:
  ```c
  static int ff_native_fd_map[FF_MAX_FREEBSD_FILES];   /* =65536, mimics ff_hook_syscall.c:258, lock-free */
  int  ff_native_map_get(int fd){ return (fd>=0 && fd<FF_MAX_FREEBSD_FILES) ? ff_native_fd_map[fd] : 0; }
  void ff_native_map_set(int fd,int h){ if(fd>=0 && fd<FF_MAX_FREEBSD_FILES) ff_native_fd_map[fd]=h; }
  void ff_native_map_clear(int fd){ if(fd>=0 && fd<FF_MAX_FREEBSD_FILES) ff_native_fd_map[fd]=0; }
  ```
- `#define FF_MAX_FREEBSD_FILES` here if lib does not already define it (mimics adapter).

### 3.3 `lib/ff_syscall_wrapper.c` (CFLAGS)
- `ff_socket`(`:915-947`): refactor inside the `#ifdef FF_KERNEL_COEXIST` block —
  - `SOCK_KERNEL && !SOCK_FSTACK && coexist`: keep v5 (kernel only + encode).
  - **new default dual-stack**: `!SOCK_FSTACK && coexist` (no marker) → first `sys_socket` builds F-Stack fd `s`, then `ff_host_socket(...)` builds host `h`, `ff_native_map_set(s,h)`, return `s`; `ff_host_socket` failure per the `05 §7` contract.
  - `SOCK_FSTACK` / coexist-off: original `sys_socket` path (`:937-943` unchanged).
- `ff_bind`(`:1607-1627`): keep the existing `#ifdef` `ff_is_kernel_fd` block; after `kern_bindat` succeeds (`:1620-1623`) add a `#ifdef` block: `int h=ff_native_map_get(s); if(h>0) ff_host_bind(h, addr, addrlen);` (use the **raw linux addr**, not bsdaddr).
- `ff_listen`(`:1584-1605`): after `sys_listen` succeeds add `int h=ff_native_map_get(s); if(h>0) ff_host_listen(h, backlog);`.
- `ff_close`(`:1095-1112`): after `kern_close` succeeds add `int h=ff_native_map_get(fd); if(h>0){ ff_host_close(h); ff_native_map_clear(fd); }`; and clear `ff_epoll_pairs` for a kqueue fd (cooperating with `ff_epoll.c`, see 3.4).
- `ff_accept`/`ff_accept4`(`:1514-1582`): for a dual-stack listen fd (`ff_native_map_get(s)>0`) follow `05 §5` single-stack ownership (kern_accept→EAGAIN→ff_host_accept+encode).
- `ff_setsockopt`(`:999`)/`ff_fcntl`(`:1495`): for a dual-stack fd, after the F-Stack path sync `ff_host_setsockopt/fcntl` to `map[s]`.
- `ff_connect`(`:1629-1649`): implemented per Q2=B — `kern_connectat` primary, best-effort `ff_host_connect(map[s])` dual-fire (`05 §6`).
- **Hot path unchanged**: recv/send/read/write/recvfrom/sendto keep the v5 single `ff_is_kernel_fd` check and do **not** add `ff_native_map_get` (NFR-2).

### 3.4 `lib/ff_epoll.c` (HOST_CFLAGS)
- `ff_epoll_ctl`(`:99-115`): keep the existing `ff_is_kernel_fd(fd)` branch (kernel-only fd); **add**: for a dual-stack listen fd with `ff_native_map_get(fd)>0` — register on the kqueue (original path, `:120+`) **and** `ff_host_epoll_ctl(ff_epoll_host_ep(epfd,1), op, ff_native_map_get(fd), event)` (pass `event.data`).
- `ff_epoll_wait`(`:214-252`): the existing merge skeleton already supports it (host `timeout=0` first, then kqueue), no major change; confirm both stacks' listen events enter the merge.
- `ff_close` cooperation: when a kqueue fd is closed, clear the `ff_epoll_pairs` pairing + `ff_host_close(host_ep)` (new helper, e.g. `ff_epoll_close_pair(kq)`).

### 3.5 `lib/Makefile`
- Already in place (`:174-177` dual CFLAGS); no change (`ff_native_fd_map` lives in HOST_CFLAGS `ff_host_interface.c`, the dual-drive branches in CFLAGS `ff_syscall_wrapper.c`, all covered).

### 3.6 demo
- Rework `example/helloworld_stacksel` or add a new one: a plain `ff_socket`+`bind(80)`+`listen` (no marker) + `ff_epoll` loop accepting/handling both stacks' connections; return a preset HTTP body. Used for IT-1/2/3 real-machine dual-stack.

---

## 4. Key Design Decisions
- **Reuse first**: `FF_KERNEL_FD_BASE`/`ff_host_*`/`ff_epoll_pairs` are reused from v5; v6 only layers on `ff_native_fd_map` + default dual-build/dual-drive.
- **Lock-free map**: single-threaded polling model, mimics the hook `fstack_kernel_fd_map` (NFR-5).
- **Zero hot-path overhead**: a connection fd is single-stack; recv/send do not consult the map (NFR-2).
- **connect ambiguity**: the draft is pending user confirmation; a pure-kernel client uses `SOCK_KERNEL` to avoid the ambiguity.
- **Reachability layering**: map/dual-build/dual-drive/accept-ownership/event-merge go through cmocka (host compilation + mocked `ff_host_*`); one-listen-many-uses goes through real-machine DPDK dual-stack integration.

---

## 5. Execution Steps (done)
1. R0-R6 done (see §2).
2. R7 spec upgraded to v6 (Chinese & English synced).
3. **R7 implementation done** (connect contract Q2=B confirmed): 3.1→3.2 (map)→3.3 (socket dual-build + bind/listen/close/accept dual-drive + setsockopt/fcntl)→3.4 (epoll dual-register + close clears the pairing)→3.6 (demo).
4. R7 tests done: cmocka dual-mode (macro-off P1 50/50; macro-on P1 incl. `test_ff_native_fd_map`/`test_ff_kernel_fd_encode_roundtrip`) + real-machine dual-stack (single listen(80): kernel `curl 127.0.0.1:80=200`, F-Stack `ssh f-stack-client→9.134.214.176:80=200`) + perf A/B (v6 default dual-build vs pure F-Stack, T1/T2/T3 x3 trials, Δ −1.73%/+1.68%/+5.87%, all within noise, no regression, see `10 §10`).
5. R7 gate PASS: `08 §4` V1-V12 measured; dual-build `nm` zero regression (macro-off coexist symbols=0, size 6539682 identical to baseline; macro-on incl. `ff_native_fd_map`); Chinese & English spec synced; English short commit `13b418191`; config local values not committed. bounce=1 (test_ff_epoll stub, fixed).

## 6. Workspace Script Conventions
Delete files via `/data/workspace/rm_tmp_file.sh`; stop processes via `/data/workspace/kill_process.sh`; change permissions via `/data/workspace/chmod_modify.sh`; after a header change, `clean` full lib rebuild (`10 §7`).
