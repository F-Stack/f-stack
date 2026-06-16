# 08 Review Gate Report

> **Document ID**: SPEC-KE-08
> **Version**: v3 (paradigm-correction rework)
> **Date**: 2026-06-15
> **Status**: PASS
> **Scope**: Perform a "consistency with the actual code / paradigm correctness / feasibility" gate verification on the full v3 Chinese spec.

---

## 1. Gate Method

- The team dispatched a `gatekeeper` (code-explorer, read-only) for asynchronous verification; **the Leader synchronously measured each key `file:line` assertion one by one** (grep/read), with the two cross-validated; on conflict, **the actual code is authoritative**.
- bounce convention: any item FAIL → bounce back to the previous step for repair, ≤3 times for the same step, escalate to manual when exceeded.

---

## 2. Verification Results (Leader-measured, all PASS)

### Stack-Selection Markers (v3 core)
| ID | Assertion | Result | Evidence |
|---|---|---|---|
| M1 | Marker definitions | PASS | `adapter/syscall/ff_adapter.h:7-8` `SOCK_FSTACK 0x01000000`, `SOCK_KERNEL 0x02000000` |

### Hook Mode Single API + Marker-Based Selection
| ID | Assertion | Result | Evidence |
|---|---|---|---|
| H1 | Domain determination | PASS | `ff_hook_syscall.c:360` `fstack_territory`, strips 4 flags (:363-366) + AF/type determination (:368-373) |
| H2 | Selection core | PASS | `:380` `ff_hook_socket`: `territory==0→ff_linux_socket` (:383-385), `SOCK_KERNEL&&!SOCK_FSTACK→ff_linux_socket` (:387-390), default `type&=~SOCK_FSTACK` (:406); comment :376-378 |
| H3 | epoll same paradigm | PASS | `:1981` `ff_hook_epoll_create` selects `ff_linux_epoll_create` by `SOCK_KERNEL` (:1982-1983) |
| H4 | fd ownership macro | PASS | `:57-61` `CHECK_FD_OWNERSHIP`; `is_fstack_fd` `:309` |

### Client connect (v3 newly added)
| ID | Assertion | Result | Evidence |
|---|---|---|---|
| C1 | connect routes by ownership | PASS | `ff_hook_syscall.c:847-886` `ff_hook_connect`: `:858 CHECK_FD_OWNERSHIP(connect,...)`, `:881 SYSCALL(FF_SO_CONNECT,args)`; routed purely by fd ownership, not by destination address |
| C2 | Kernel-side wrapper line numbers | PASS | `ff_linux_syscall.c` socket:81/bind:88/listen:96/accept:131/**connect:144**/close:217/epoll_create:233/epoll_ctl:239/epoll_wait:247 |

### config.ini Parsing Layer (the global default switch landing point)
| ID | Assertion | Result | Evidence |
|---|---|---|---|
| G1 | Parsing entry/paradigm | PASS | `lib/ff_config.c:956` `ini_parse_handler`; `:963` `MATCH`; `[kni]` section `:1011-1026` (`MATCH("kni","enable")` :1011-1012) |
| G2 | Config struct | PASS | `lib/ff_config.h:253` `struct ff_config`: dpdk(:255-308)/kni(:310-319)/log(:321-325)/freebsd(:327-334)/pcap(:336-342); `filename` :254; `extern ff_global_cfg` :345; `ff_load_config` :347 |
| G3 | Default/validation/free regions | PASS | validation `:1261+`, default `:1358+`, string freeing `:1647+` |

### Native ff_api Mode Marker Difference (key, D4)
| ID | Assertion | Result | Evidence |
|---|---|---|---|
| N1 | Native socket entry | PASS | `lib/ff_syscall_wrapper.c:912-926` `ff_socket`: `sa.type=linux2freebsd_socket_flags(type)`(:918)→`sys_socket`(:920) enters the FreeBSD stack |
| N2 | flags conversion does not recognize selection markers | PASS | `linux2freebsd_socket_flags:668-677` only handles `LINUX_SOCK_NONBLOCK/CLOEXEC`; **does not recognize SOCK_KERNEL/SOCK_FSTACK** → "native ff_socket always creates an F-Stack socket" holds |

### Dual-Stack Events (reused)
| ID | Assertion | Result | Evidence |
|---|---|---|---|
| E1 | Mapping table | PASS | `:257-258` `fstack_kernel_fd_map[FF_MAX_FREEBSD_FILES=65536]` |
| E2 | Dual-stack epoll | PASS | create mirror `:1996-1997`, wait merge `:2324+` (`:2333-2336` throttled call `ff_linux_epoll_wait(...,0)`), `maxevents>=2` `:2213-2216`, close linkage `:1874-1883` |

### ff_api.h / Paradigm Correctness
| ID | Assertion | Result | Evidence |
|---|---|---|---|
| A1 | API line numbers | PASS | `ff_api.h` socket:81/listen:89/bind:90/accept:91/connect:93/close:94/kqueue:138/kevent:139 |
| S1 | v3 paradigm correctness | PASS | 01/02/04/05/06: (a) the `ff_local_*` dual API/`belong_to_host` parameter has been removed; (b) unified `SOCK_KERNEL/SOCK_FSTACK` markers + config global default + glue adaptation; (c) includes client connect selection (local/external); (d) thread-level removed, no port lists; (e) dual-mode coverage and faithful recording that native mode needs enhancement (D4) |

**Passed: 19/19.**

---

## 3. README/Comments vs Code Differences (code is authoritative)

| ID | Description | Conclusion |
|---|---|---|
| D3 | The comment at `ff_hook_syscall.c:2076-2081` "the first version does not support `ff_linux_epoll_wait`" | Conflicts with the actual call at `:2336`: currently it **does** call it (`timeout=0`+throttle). Code is authoritative, already recorded in `02` |
| D4 | The intuition "native `ff_socket` also recognizes `SOCK_KERNEL`" | `ff_socket:918`+`linux2freebsd_socket_flags:668-677` falsify it: **does not recognize**, always creates an F-Stack socket. v3 lists it as a native-mode enhancement item (`02 §5`/`05 §4`/`06 M4`) |

---

## 4. Bounce Record

| # | Trigger | Handling | Re-verification |
|---|---|---|---|
| — | This round's Leader measurements were consistent with the doc assertions; no line-number FAIL triggered | — | — |

- bounce count: 0 (< 3 limit), **no manual escalation needed**.
- line-number-class FAIL: 0.

---

## 5. Overall Gate Conclusion

**PASS**. The full v3 spec is consistent with the actual code (19/19). The paradigm has correctly converged to: **reusing and standardizing F-Stack's existing "single API + `SOCK_KERNEL`/`SOCK_FSTACK` marker-based selection + glue auto-adaptation" + the config.ini global default switch**, covering **both server and client (connecting to local/external kernel services) directions** and **both hook and native modes**; the `ff_local_*` dual API and gazelle thread-level selection have been completely removed; KNI is boundary clarification only. The key fact D4 (native `ff_socket` does not recognize selection markers) has been faithfully recorded as an implementation-phase enhancement item. May proceed to a local commit.

---

# Implementation-Phase Gate Report (M1-M6, 2026-06-15)

> Perform a compile/unit-test/coverage/integration measured gate on the "local socket/fd/event support" implementation. Conclusions come from actual compilation and execution; the evidence is reproducible.

## I.1 Code-Change Verification (Leader-measured, all PASS)

| ID | Assertion | Result | Evidence |
|---|---|---|---|
| G1 | Marker external exposure (M1) | PASS | `lib/ff_api.h` `#ifndef SOCK_FSTACK 0x01000000` / `SOCK_KERNEL 0x02000000`, values consistent with `adapter/syscall/ff_adapter.h:7-8` |
| G2 | config struct (M3) | PASS | `lib/ff_config.h` `struct ff_config` adds `struct { int default_to_kernel; } stack;` (after the kni section) |
| G3 | config parse/default/accessor (M3) | PASS | `ff_config.c:1027` `MATCH("stack","default_stack")` (`strcasecmp(value,"kernel")?1:0`); `:1365` default 0; `:1382` `ff_default_stack_is_kernel()` |
| G4 | config.ini section (M3) | PASS | Project-root `config.ini` adds `[stack] default_stack=fstack` + comments |
| G5 | host-bridge declaration (M4) | PASS | `lib/ff_host_interface.h` declares `ff_host_socket` / `ff_default_stack_is_kernel` |
| G6 | host-bridge implementation (M4) | PASS | `ff_host_interface.c:240` `ff_host_socket` calls the host `socket()`; adds `#include <sys/socket.h>`; `ff_getenv:234` intact |
| G7 | ff_socket selection branch (M4, zero regression) | PASS | `ff_syscall_wrapper.c:928-931` new branch; the original FreeBSD path (from `:933`) is **byte-for-byte unchanged** (NFR-1) |
| G8 | cmocka unit tests (M6) | PASS | `tests/unit/test_ff_config.c` adds 4 cases and registers them; `extern ff_default_stack_is_kernel` |
| G9 | fixtures (M6) | PASS | `valid_stack_kernel.ini`/`valid_stack_garbage.ini`; `valid_all_sections.ini` contains `[stack] default_stack=fstack` |
| G10 | paradigm consistency | PASS | No new `ff_local_*`; single API + markers + config default, consistent with 05/06 |
| G11 | hook-layer config boundary | PASS | `ff_hook_syscall.c:31` `ff_global_cfg` comment "Just for so, no used" → the config default takes effect in native mode only (faithfully recorded) |

## I.2 Compilation and Unit Tests (hard gate, PASS)

- **lib compilation**: `cd lib && make` successfully re-links `libfstack.a` under `-Werror` (all three changed files pass).
- **cmocka unit tests**: `test_ff_config` **54/54 PASS** (4 new `[stack]` cases); all buildable binaries total **176 TC, 0 failures**.
- **Coverage (G8)**: `ff_config.c` line **89.96%** / branch **85.30%** (on par with baseline, the new code is covered).

## I.3 Integration Measurement (the core feature actually runs through, without a DPDK NIC)

Example `example/helloworld_stacksel` (`ff_socket(SOCK_KERNEL)`→host kernel stack, EAL-free):

| Case | Command | Result |
|---|---|---|
| selftest | `./helloworld_stacksel` | `INTEGRATION PASS: kernel-stack server+client over loopback` |
| FR-1 local curl direct access to the kernel-stack listen | `curl 127.0.0.1:18099` | Returns `hello-stacksel` |
| FR-2 kernel ICMP | `ping -c1 127.0.0.1` | `0% packet loss` |
| FR-3 client connects to a local service via the kernel stack | `helloworld_stacksel client 127.0.0.1 18100` | `connected via kernel stack` + `HTTP/1.1 200 OK` |
| M4 native ff_socket(SOCK_KERNEL) | All the above go through `ff_socket(SOCK_KERNEL)` | Returns a real host kernel fd, send/recv normal |

## I.4 Skipped Items (environment not available, with measured evidence; handled per Q1)

| Item | Reason (measured) | Evidence |
|---|---|---|
| F-Stack data-plane end-to-end / hook mode / performance baseline PERF-* | The sandbox has **no DPDK-bound physical NIC** (hugepages exist `HugePages_Total:4096`, but no usable NIC/data plane) | — |
| FR-4 connecting to an external kernel-stack service | The mechanism is the same as FR-3 (only the destination address differs), FR-3 has been measured through; external egress not guaranteed | Reuse the FR-3 evidence |
| `tests/unit/test_ff_dpdk_if` and `tests/integration/*` | **Pre-existing baseline** missing `ff_tcp_hpts_softclock` (`ff_dpdk_if.c:2459`); after `git stash` reverting this round's changes it **still fails**, proving it is not a regression of this feature | `git stash` reproduction, identical missing symbol |

> The missing `ff_tcp_hpts_softclock` affects all test binaries linking `ff_dpdk_if.o`; it is a pre-existing test-infrastructure problem unrelated to this feature and is recommended to be handled separately; this feature's hard gate does not depend on that binary.

## I.5 Bounce Record

| # | Trigger | Handling | Re-verification |
|---|---|---|---|
| self-fix | Editing `ff_host_interface.c`, one replace mistakenly deleted the `ff_getenv` signature | Same-step immediate restore + add `ff_host_socket` | Compilation passes, `ff_getenv` intact (G6 PASS) |

- Phase gate bounce: 0 (no cross-step bounce; the above is a same-step immediate self-fix, < 3 limit).

## I.6 Implementation-Phase Overall Conclusion

**PASS (hard gate)**: compilation + cmocka unit tests all green (176 TC) + `ff_config.c` coverage maintained; the core "local socket/fd/event access" feature (marker selection M1/M4, config default switch M3, server-side kernel-stack listen FR-1/FR-2, client kernel-stack connect FR-3) has been **actually run and verified**. The DPDK-NIC data-plane-related items (hook end-to-end / performance baseline / FR-4 external / test binaries blocked by the pre-existing `ff_tcp_hpts_softclock`) are, due to the absence of a physical NIC in the environment, **skipped with measured evidence** per Q1, without affecting the hard gate.
