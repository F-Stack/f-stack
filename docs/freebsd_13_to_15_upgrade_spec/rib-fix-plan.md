# Rib/rtentry IP Configuration Fix Plan (runtime-fix Phase 2)

> Chinese version: `./zh_cn/rib-fix-plan.md`
>
> **Goal**: make `ff_ifconfig` show `inet 192.168.1.1` on `f-stack-0` and keep `ff_netstat -a` showing `tcp4/tcp6 *.80 LISTEN`.
>
> **Document purpose**: on top of the existing 5 runtime-fix commits (UMA / atomic / rtbridge / docs ×2), close the "last mile" IP-config failure.

---

## 1. Original user request (2026-06-01 20:41)

Continue runtime-fix. Three root causes already fixed (UMA infinite-loop allocator + `smr_create` `%gs` panic + `rt_ifmsg` NULL deref); `helloworld init success.` ✅; `ff_netstat -a` shows `tcp4/tcp6 *.80 LISTEN` ✅. **One strict acceptance item remains**: `ff_ifconfig` must display `inet 192.168.1.1`.

User verbatim: "the acceptance criterion is that running `ff_ifconfig` and `ff_netstat -a` returns the right NIC and 80-port listen info; no actual `curl` test required for now".

Launch command: `cd /data/workspace/f-stack; bash ./start.sh ./example/helloworld`.

## 2. Investigation findings (Phase 0 static research, complete)

### 2.1 Critical correction (!!!)

The "errno 55 = EOPNOTSUPP" recorded in `runtime-fix-execution-log.md` §10.3 is a **misjudgement**:

- **FreeBSD `errno` 55 = `ENOBUFS`** (No buffer space available); see `freebsd/sys/errno.h:118`.
- FreeBSD `EOPNOTSUPP` = 45.
- Linux `EOPNOTSUPP` = 95 (different value — the earlier mapping of "55" in the helloworld log to Linux's `EOPNOTSUPP` was incorrect).

### 2.2 True root-cause call chain (4-way cross-verified)

```
ff_veth_setaddr → socreate(AF_INET) → ifioctl(SIOCAIFADDR)
  → in_control_ioctl → in_aifaddr_ioctl → ifa_maintain_loopback_route
    → rib_action(RTM_ADD) → rib_add_route → add_route_byinfo
      → rt_alloc(rnh, dst, netmask) → NULL → return ENOBUFS (55)
```

### 2.3 Code-location evidence (measured)

| Item | Location | State |
|---|---|---|
| Real `rt_alloc` | `f-stack/freebsd/net/route/route_rtentry.c:82` (8375 bytes / 6 14.0+ rib core funcs) | ✅ file exists but NOT compiled |
| Real signature | `rt_alloc(rnh, dst, struct sockaddr *netmask)` | ✅ |
| `lib/Makefile` SRCS | contains route_ctl.c / route_tables.c / route_helpers.c / route_ifaddrs.c / route_temporal.c / nhop_utils.c / nhop.c / nhop_ctl.c / rtsock.c / slcompress.c — **does NOT contain route_rtentry.c** | ❌ missing |
| `ff_stub_14_extra.c` wrong stubs | 6 entries: rt_alloc / rt_free / rt_free_immediate / rt_get_family / rt_get_raw_nhop / rt_is_host — all return NULL / wrong signature (`rt_alloc` 3rd arg `struct route_nhop_data *` vs real `struct sockaddr *`) | ❌ short-circuits the link |

### 2.4 4-way cross-verification of the signature

| Source | `rt_alloc` signature |
|---|---|
| 15.0 baseline `/data/workspace/freebsd-src-releng-15.0/sys/net/route/route_rtentry.c:82` | `(rnh, dst, struct sockaddr *netmask)` ✅ |
| fstack `f-stack/freebsd/net/route/route_rtentry.c:82` | `(rnh, dst, struct sockaddr *netmask)` ✅ |
| Caller `f-stack/freebsd/net/route/route_ctl.c:762` | `rt_alloc(rnh, dst, netmask)` ✅ |
| fstack stub `f-stack/lib/ff_stub_14_extra.c:534` | `(rnh, dst, struct route_nhop_data *rnd)` ❌ |

**Conclusion**: the lib stub has the wrong signature and always returns NULL → execution always falls through to the `return (ENOBUFS)` fallback in `add_route_byinfo` → `ff_veth_setaddr` fails → `ifa_maintain_loopback_route` fails → IP cannot be configured.

## 3. Decision points (DP-RT-FIX-1~3)

| DP | Options | Recommended |
|---|---|---|
| **DP-RT-FIX-1** Fix strategy | **A: add `route_rtentry.c` to `lib/Makefile` SRCS + drop the 6 wrong stubs in `ff_stub_14_extra.c`** (root fix) / B: only fix the stub signatures + return a forged rtentry (NOT viable: `rt_alloc` internally calls `uma_zalloc` and the `RTF_HOST` logic must run for real) | **A** |
| **DP-RT-FIX-2** Verification scope | A: strict — `ff_ifconfig` shows `inet` + `ff_netstat -a` shows `:80 LISTEN` (100% aligned with user verbatim) / **B: strict A + `helloworld init success.` does not regress** / C: strict B + 6 tools' EAL stage does not regress | **B** |
| **DP-RT-FIX-3** Commit cadence | **A: one root cause = one commit** (same style as runtime-fix #1-#3) / B: a single combined commit | **A** |

If unanswered, proceed under default **A/B/A**.

## 4. 6-phase pipeline

| Phase | Task | Key artifact |
|---|---|---|
| Phase 0 | Kickoff: `cp -a` rib-fix-start backup + update execution log §6 suspects 8/9 | rib-fix-start 33,122 files |
| Phase 1 | Static research (done — §2 above) | as above |
| Phase 2 | Implement fix: `lib/Makefile` += `route_rtentry.c` + `ff_stub_14_extra.c` drops 6 wrong stubs | 2 files modified |
| Phase 3 | Force rebuild (`make clean && make`) + relink example | libfstack.a 5.2M+ / 251 .o (+1) / helloworld 27M+ |
| Phase 4 | Restart helloworld + run the 2 strict acceptance items (`ff_ifconfig` / `ff_netstat`) | runtime output verification |
| Phase 5 | Closure: `cp -a` rib-fix-done + update 99 §12.20 + runtime-fix-execution-log §11 + 2 commits | git log + backups |

## 5. Mandatory conventions (inherits all 3 + English commit messages)

| Convention | AI memory ID | Content |
|---|---|---|
| rm_tmp_file.sh | 81725399 | All deletions go through `/data/workspace/rm_tmp_file.sh` |
| kill_process.sh | 90098233 | All process termination go through `/data/workspace/kill_process.sh` |
| chmod_modify.sh | 21626578 | All permission changes go through `/data/workspace/chmod_modify.sh` |
| English commit messages | 73362122 | All git commit messages in English |
| Measure-first | — | 4-way cross-verification; if inconsistent, source code wins |
| Force rebuild | — | After header changes, mandatory `make clean` (M3-end .o-cache lesson) |

## 6. Risk assessment

| Risk | Mitigation |
|---|---|
| Compiling `route_rtentry.c` may introduce extra link errors | The file already exists in the 15.0 vendor; only 8375 bytes; sibling `route_*.c` already build OK → low risk |
| Removing the 6 stubs may trigger other undefined references | Real `rt_alloc` is provided by `route_rtentry.o`; the other 5 are also there; after removing the stubs, real `.o` resolves them → no undef |
| Could it affect the previously fixed 5 commits? | The change set is only 2 files (Makefile + ff_stub_14_extra.c); does not touch amd64/atomic.h, amd64/vmparam.h, arm64/vmparam.h |
| Does helloworld need restart for verification? | Yes — the old helloworld pid 113746 has been running 18+ min; a relinked binary needs a new process to take effect |

## 7. Awaiting user confirmation

Reply **"accept the plan and start now"** or **"adjust DP-RT-FIX-X"**. If the user says **"continue"**, proceed under default A/B/A.
