F-Stack dual-stack coexistence: one listen serving both the DPDK NIC and local loopback

1. What problem this solves

Getting straight to the point: the kernel-stack coexistence capability introduced in F-Stack v2.0 (expected official release 2026.10) solves one of F-Stack's most classic pain points — after DPDK takes over the NIC, curling a locally listened service from the same machine fails with Connection refused from the kernel.

First some background. Once F-Stack binds a NIC to DPDK, all traffic on that NIC completely bypasses the Linux kernel protocol stack and goes straight into F-Stack's user-space FreeBSD stack. The consequence: if you listen on port 80 in F-Stack, curling your NIC IP from another machine on the same network works, but curling 127.0.0.1 or the local IP on the same machine gets Connection refused — because local requests go through the Linux kernel stack, which knows nothing about F-Stack's port 80.

This keeps coming up in issues, and the official answer has always been "test from another machine" or "use KNI packet injection". Issues #511/#585/#741/#849 are all the same thing.

This feature turns that "manual workaround" into "default behavior": the same socket, the same listen(80), runs on both the F-Stack user-space stack (DPDK NIC, business fast path) and the Linux kernel stack (local loopback/management plane) at the same time. A remote curl to the NIC IP goes through F-Stack, a local curl to 127.0.0.1 goes through the kernel, both paths work simultaneously, and events from both stacks are handled in the same epoll/kqueue event loop.

The core value in one sentence:

【Note 1】The F-Stack user-space stack is always in place and always carries the business fast path; the kernel stack is only a "parallel attachment", the second stack used to serve local/management/client access. It never bypasses or replaces F-Stack.

It must be made clear what this is NOT, to avoid misunderstanding:

- It does not bypass sockets to the kernel (an early erroneous implementation did exactly that, detailed in 4.1, already reverted)
- It is not "whole process defaults to kernel stack" (that is anti-F-Stack and explicitly out of scope)
- It is not KNI packet injection (that is a separate independent mechanism, unrelated to this feature)
- It is not connection migration/transparent proxying (a TCP connection physically exists only on the stack that received the SYN; it cannot be "dual-stacked")

2. Main use cases

2.1 Locally accessing your own listening service

The most direct scenario. During development and operations you always want to curl the service you just started from the same machine to confirm it's alive, instead of spinning up another machine every time. With dual-stack enabled, a local curl 127.0.0.1:80 just works.

2.2 Server-side bidirectional reachability

The same listen(80): remote access via the DPDK NIC at `<DPDK_NIC_IP>:80` goes through the F-Stack fast path, local access via 127.0.0.1:80 goes through the kernel stack. One socket serves both purposes — no need to open an extra SOCK_KERNEL socket for the kernel side, no marker needed.

2.3 Client connecting to kernel services

As a client needing to connect to local or external kernel services (e.g. a local daemon or a management-plane API), both dual-stack connect and pure-kernel SOCK_KERNEL work without detours.

2.4 Monitoring scenarios needing kernel visibility

F-Stack listening ports are invisible in Linux's ss/netstat (that's a user-space stack). With dual-stack enabled, ss can see the kernel-side port 80 listener, making monitoring and health checks much easier. In issues #593/#594 the official answer also used kernel_coexist as the "make the port kernel-visible" solution.

2.5 Cases where it does not fit

- Needing a single connection truly duplexed across both stacks (data on one fd either goes through F-Stack or the kernel, it cannot send/receive on both stacks at once) — default dual-stack connect is only "one connection per stack, F-Stack primary"; for a pure-kernel client use SOCK_KERNEL
- Using select/poll for multiplexing (detailed in 4.6; kernel fds don't fit into fd_set, not supported)
- Wanting to drop F-Stack and keep only the kernel (this feature provides no "whole process defaults to kernel", that would be a bypass)

3. Architectural characteristics

3.1 One listen serving both stacks

```
                    ┌──────────────────────────────────────────┐
                    │     Same app process, single ff_api       │
                    │                                          │
  default socket/listen(80) ──► auto dual-create                │
                    │                                          │
        ┌───────────┴───────────┐                              │
        ▼                       ▼                              │
┌───────────────┐      ┌────────────────┐                      │
│ F-Stack user  │      │  Linux kernel  │                      │
│ stack         │      │  stack (parallel│                      │
│ (DPDK+FreeBSD)│      │  attachment)    │                      │
│ business fast │      │  local/mgmt     │                      │
│ path          │      │                 │                      │
└───────┬───────┘      └───────┬────────┘                      │
        │                      │                               │
        │ remote curl          │ local curl                    │
        │ <DPDK_NIC_IP>:80    │ 127.0.0.1:80                  │
        ▼                      ▼                               │
  F-Stack side 200     kernel side 200                          │
                    │                                          │
            ff_native_fd_map[fstack_fd]=host_fd                │
            one event loop for both stacks                      │
                    └──────────────────────────────────────────┘
```

3.2 fd three-state routing

This is the core model of the whole feature. An incoming fd is classified into three forms by its value range and the mapping table:

```
ff_* entry(fd)
  ├─ ff_is_kernel_fd(fd)? (fd >= 0x40000000)
  │     yes ─►【single-stack: kernel only】go ff_host_*(real fd)
  │     no  ─► go F-Stack original path
  │              └─ ff_native_map_get(fd) > 0 ?
  │                   yes ─►【dual-stack】F-Stack path + drive map[fd]=host_fd too
  │                   no  ─►【single-stack: F-Stack only】(default-off/SOCK_FSTACK/conn fd)
```

The three fd spaces do not collide: F-Stack fd < 65536, kernel encode fd >= 0x40000000, host fd bounded by RLIMIT_NOFILE.

【Note 2】The key design is "hot path never queries the map". An accepted connection fd is always single-stack — an F-Stack-side connection returns the raw fd, a kernel-side connection returns the encode fd. After that, recv/send routes with a single ff_is_kernel_fd check, never touching the mapping table, zero extra overhead on the data hot path. Dual-create/dual-drive only happens on one-time operations like socket/bind/listen/close.

3.3 Two-layer gating guarantees zero regression

```
Compile-time gate: FF_KERNEL_COEXIST (commented off by default in lib/Makefile)
  ├─ undefined ──► all coexistence code excluded via #ifdef, not compiled
  │                 SOCK_FSTACK/SOCK_KERNEL macros invisible, ff_native_fd_map absent
  │                 ► libfstack.a byte-identical to original F-Stack
  └─ defined ──► coexistence compiled in
        └─ Runtime gate: config [stack] kernel_coexist
              ├─ =0 (default) ──► dual-create/dual-drive short-circuited, F-Stack only (zero regression)
              └─ =1 ──► auto dual-stack: default dual-create/dual-drive + marker single-stack override
```

Triple zero-regression guarantee: compile macro off, runtime switch off, or SOCK_FSTACK marker — any one of the three degrades to pure F-Stack.

4. Refactoring work and problems encountered

The following is rather dry; readers who don't need to dig into the implementation can skip this section and jump straight to section 5.

4.1 The detour taken: v3 pure-kernel bypass (reverted)

This feature did not land in one shot; a major directional mistake was made along the way.

The earliest version (v3, commit 0748eff94) wired `ff_socket(SOCK_KERNEL)` directly to a pure host socket(), completely bypassing F-Stack. It appeared to solve "local machine can connect", but it was a fundamental error — it bypassed F-Stack, violating the iron rule "F-Stack always in place". The perf baseline report confirmed the problem: both A/B versions tested in v3 were pure kernel; "coexistence" was never actually tested.

After the revert, the correct paradigm was redone: the app runs on F-Stack, per-fd SOCK_KERNEL attaches through the kernel stack additionally, both coexisting in the same process.

【Note 3】This detour is worth remembering: coexistence is not an "either F-Stack or kernel" choice, but "F-Stack primary, kernel attached in parallel". Once it becomes a bypass, both the performance baseline and the stability assessment become distorted.

4.2 v5: compile-macro gating + per-fd either-or

The first correct implementation after the revert was v5 (commit ba148589d), which did two things:

- Wrapped all coexistence code in the compile macro FF_KERNEL_COEXIST, off by default in lib/Makefile, guaranteeing that with the macro off, libfstack.a is byte-identical to original F-Stack (nm comparison shows 0 coexistence symbols)
- per-fd either-or semantics: with SOCK_KERNEL, create a kernel fd (encoded as a high-bit fd >= 0x40000000); otherwise go the F-Stack original path

This version was tested and usable, but the semantics were "each fd chooses one stack by itself". To also be reachable locally you had to write an extra SOCK_KERNEL socket — a hassle.

4.3 v6: default upgraded to auto dual-stack

v6 (commit 13b418191) upgraded the default semantics from "either-or" to "auto dual-stack":

- A default (no marker) ff_socket creates both the F-Stack fd and the kernel host fd, registers ff_native_fd_map[fstack_fd]=host_fd, and returns the raw F-Stack fd
- ff_bind/ff_listen/ff_close drive both stacks for that dual-stack fd
- markers become "single-stack override": SOCK_KERNEL kernel only, SOCK_FSTACK F-Stack only

The core addition is the 65536-entry lock-free mapping table ff_native_fd_map (modeled on the adapter's fstack_kernel_fd_map), plus the "single-stack ownership" of accept — accepting from a dual-stack listen fd returns a single-stack connection fd, F-Stack side returns raw fd, kernel side returns encode fd.

4.4 Pitfall: header change without clean rebuild caused ABI skew

During the perf baseline run we hit a build-hygiene pitfall: adding int kernel_coexist to the stack sub-structure of struct ff_config shifted the offset of the log sub-structure after it (containing log.f). The lib Makefile does not track header dependencies, so the incremental build left .o files mixing old and new ff_config.h layouts — ff_log.o read log.f with the old offset, picking up some other non-zero field in the new layout, and fclose segfaulted immediately.

The fix was simple: remove all .o files and libfstack.a, full rebuild. But it exposed a rule — for changes to structure headers like ff_config.h, lib must be clean-rebuilt; incremental builds can mask ABI skew.

4.5 Pitfall: kqueue-model apps cannot see kernel-side events

After R7 landed, auto dual-stack was complete for ff_epoll_*, but apps using ff_kqueue/ff_kevent directly (e.g. example/main.c uses the kqueue model) could not see kernel-side connections. Measured: the kernel TCP completed the handshake, the GET entered the kernel buffer and was ACKed (packet capture shows ack 73 matching), but the app was never woken up to accept the kernel listen fd — local curl 127.0.0.1:80 returned http_code 000 (6s timeout).

Root cause: ff_kqueue/ff_kevent had no FF_KERNEL_COEXIST routing at all; only the F-Stack listen fd was registered into the F-Stack kqueue, and the dual-stack listen's kernel-side host fd never entered any event backend.

Fix (R9, commit 03f244ac1): symmetric kqueue coexistence modeled on ff_epoll — in ff_kevent's changelist, EV_ADD/EV_DELETE whose ident is a kernel fd or dual-stack fd map to host epoll_ctl (EVFILT_READ↔EPOLLIN, EVFILT_WRITE↔EPOLLOUT); the eventlist first collects kernel readiness then merges F-Stack readiness.

4.6 Pitfall: IPv6 dual-create port conflict

Also found in R9. With -DINET6 enabled, a default ff_socket(AF_INET6) dual-creates, and when the host-side IPv6 socket binds [::]:80, because the machine has net.ipv6.bindv6only=0, [::] also occupies IPv4, conflicting with the same process's host-side 0.0.0.0:80 — measured errno=98 EADDRINUSE, the process could not start at all.

Fix: set IPV6_V6ONLY=1 on the host-side IPv6 socket so it handles only IPv6 and coexists with host IPv4 on the same port.

4.7 Wrap-up: kernel routing for remaining interfaces

R8 (commit 55a84f313) completed kernel-fd routing for sendmsg/recvmsg/getpeername/getsockname/shutdown; R10 (commit c6f5918b8 + 2422d12eb) added readv/writev/ioctl/dup/dup2. A few points worth noting:

- ioctl request encoding differs between Linux and FreeBSD; the kernel host fd must use the raw Linux request passed straight to host libc, must not go through linux2freebsd_ioctl translation
- dup2 with one kernel fd and one F-Stack fd ("mixed-stack") has no valid semantics; explicitly rejected with errno=EINVAL, no invented semantics
- select is not supported: the encode kernel fd (>= 0x40000000) far exceeds fd_set's FD_SETSIZE(1024), cannot fit — hard limit
- poll is also not supported: merging is complex and risky; conservatively downgraded to a documented limitation

For multiplexing kernel fds, use ff_epoll_* or ff_kqueue.

4.8 No performance regression

The most important point. Measured data (v6 dual-stack scope, real-machine wrk):

| Tier | Coexist off A0 | Dual-stack on A1 | Δ |
|------|----------:|----------:|------:|
| T1 (-t2 -c10) | 28,216 | 27,729 | −1.73% |
| T2 (-t4 -c100) | 202,805 | 206,219 | +1.68% |
| T3 (-t8 -c500) | 120,702 | 127,784 | +5.87% |

Throughput differences all fall within trial noise, p99 basically equal. It also makes logical sense — the dual-create cost is paid once at listen socket creation; keep-alive connections have a single-stack data hot path that never queries the map, so the F-Stack business fast path has no measurable regression.

5. Usage, configuration and results

5.1 Compilation

The default build contains no coexistence code. To enable it, compile with the macro:

```bash
cd f-stack/lib && make clean && make FF_KERNEL_COEXIST=1 -j$(nproc)
```

On the app side, if you want to use markers (SOCK_KERNEL/SOCK_FSTACK), compile the app with -DFF_KERNEL_COEXIST too (otherwise the two macros are invisible). Using only the default dual-stack does not need it.

5.2 Configuration

Add kernel_coexist to the [stack] section of config.ini:

```ini
[stack]
# 0=disabled (pure F-Stack), 1=enabled (default socket auto dual-stack)
kernel_coexist = 1
```

Note: this runtime switch only takes effect when the compile macro FF_KERNEL_COEXIST is on. Macro off, or set to 0 here, is pure F-Stack, zero regression.

5.3 Usage

Default dual-stack (nothing to add):

```c
int s = ff_socket(AF_INET, SOCK_STREAM, 0);   /* dual-stack: F-Stack fd + kernel host fd */
ff_bind(s, &addr80, sizeof(addr80));           /* dual-drive: both stacks bind 80 */
ff_listen(s, backlog);                          /* dual-drive: both stacks listen */
ff_epoll_ctl(ep, EPOLL_CTL_ADD, s, &ev);        /* dual-register: kqueue + kernel epoll */

/* remote curl <DPDK_NIC_IP>:80 via F-Stack, local curl 127.0.0.1:80 via kernel, both reachable */
```

For single-stack, override with markers:

```c
int konly = ff_socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0);  /* kernel only */
int fonly = ff_socket(AF_INET, SOCK_STREAM | SOCK_FSTACK, 0);  /* F-Stack only */
```

5.4 Results

Functional correctness (real machine, commit 13b418191):

- Single listen(80): local curl 127.0.0.1:80 = 200 (kernel side), remote ssh → `<DPDK_NIC_IP>:80` = 200 (F-Stack side)
- ss shows the kernel-side port 80 listener, ff_netstat shows the F-Stack-side port 80 listener

Zero regression (triple guarantee):

- Compile macro off: libfstack.a has 0 coexistence symbols, byte-identical to original F-Stack
- kernel_coexist=0: dual-create/dual-drive short-circuited at runtime
- SOCK_FSTACK marker: F-Stack only

Performance (section 4.8): T1/T2/T3 throughput differences all within noise, hot path never queries the map.

5.5 Known limitations

- select does not support kernel fds (encode fd cannot fit into fd_set), poll is also not supported — use epoll/kqueue for kernel fds
- A single connection cannot be truly duplexed across both stacks — default dual-stack connect is "F-Stack primary + kernel concurrent connect as backup"; for a pure-kernel client use SOCK_KERNEL
- Observability stats (ff_stack_get_stats) are not implemented yet; fd counts/event counts for both stacks are not visible
- IPv6 depends on host-side V6ONLY; bindv6only-related behavior was handled in R9

Related reading:

- Full spec: docs/kernel_event_support_spec/zh_cn/ (00-10 + plan-r9/plan-r10)
- Three-layer architecture: docs/zh_cn/F-Stack_Architecture_Layer1_System_Overview.md
- Knowledge graph: docs/zh_cn/KNOWLEDGE_GRAPH_WIKI.md (section 2A, FF_KERNEL_COEXIST delta)
- Related issues: #511/#585/#741/#849 (local curl connection-refused scenario)
