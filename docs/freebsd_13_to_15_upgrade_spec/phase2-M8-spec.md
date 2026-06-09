# M8 Spec — FF_ZC_SEND (P1b)

> Chinese version: ./zh_cn/phase2-M8-spec.md (authoritative)

> Spec version: v0.1 (2026-06-08)
> Parent plan: `phase2-feature-enable-plan.md` v0.1
> Predecessor milestone: M7 committed at `cba3d882b` (feature/1.26 ahead 15)
> M7 baseline: libfstack.a 6.55 MB / 0 errors / 57 warnings / `ff_mmap_init mmap 65536 pages, 256 MB.`

---

## 1. Scope

### 1.1 In scope

| Item | Note |
|---|---|
| Enable `FF_ZC_SEND=1` | uncomment `lib/Makefile:47` (the actual macro is `-DFSTACK_ZC_SEND`) |
| **Disable `FF_USE_PAGE_ARRAY`** | M8 validates ZC alone (combo is M9) |
| Extend `example/Makefile` | add a `helloworld_zc` target that compiles main_zc.c |
| Build clean | `lib && make all` exit=0; `example && make` produces helloworld + helloworld_epoll + **helloworld_zc** |
| Primary smoke | helloworld_zc alive ≥10 s without crash |
| Client-side test | from `f-stack-client` (9.134.211.87) curl/wrk → server (9.134.214.176:80), at least one full HTTP 200 response |
| Simple perf observation | 100× short conn + 30 s long conn, helloworld vs helloworld_zc under the same conditions |
| Doc sync + commit | partial docs; local commit; no push |

### 1.2 Out of scope

- FF_USE_PAGE_ARRAY combo (M9)
- Full perf baseline (M9 will do it together with PA+ZC)
- ZC read path (`ff_zc_mbuf_read` is currently a `/* DOTO: Support read zero copy */` no-op; server-side only tests ZC write/send)

---

## 2. Background and State (measured)

### 2.1 Control points

```
lib/Makefile:47   #FF_ZC_SEND=1                ← uncomment
lib/Makefile:204  ifdef FF_ZC_SEND
lib/Makefile:205  CFLAGS+= -DFSTACK_ZC_SEND     ← note: macro is FSTACK_ZC_SEND (not FF_ZC_SEND)
```

### 2.2 ZC API (`lib/ff_api.h:347-380` + `lib/ff_veth.c:306-360`)

| API | Purpose |
|---|---|
| `struct ff_zc_mbuf { bsd_mbuf, bsd_mbuf_off, off, len }` | ZC mbuf-chain handle |
| `int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len)` | request the mbuf chain (`m_getm2(NULL, len, M_WAITOK, MT_DATA, 0)`) |
| `int ff_zc_mbuf_write(struct ff_zc_mbuf *zm, const char *data, int len)` | write data (cumulative across calls) |
| `int ff_zc_mbuf_read(struct ff_zc_mbuf *m, ...)` | currently a `return 0` stub (not implemented; **out of scope**) |

ZC implementation is **independent** of FF_USE_PAGE_ARRAY; no ifdef cross-dependency.

### 2.3 client/server topology (already configured by the user)

| Role | Host | IP | OS |
|---|---|---|---|
| server (this box) | current | 9.134.214.176 | Linux + DPDK + f-stack |
| client | f-stack-client (ssh hostname) | 9.134.211.87 | Linux 6.6 TencentOS |

### 2.4 example/Makefile current state

```makefile
TARGET="helloworld"
all:
	cc ${CFLAGS} -DINET6 -o ${TARGET} main.c ${LIBS}
	cc ${CFLAGS} -o ${TARGET}_epoll main_epoll.c ${LIBS}
```

**Missing helloworld_zc target**, must be added (M8 in-scope).

---

## 3. Changes

### 3.1 `lib/Makefile` (2 lines)

```diff
-FF_USE_PAGE_ARRAY=1                  # M7 enabled, M8 must disable
-#FF_ZC_SEND=1
+#FF_USE_PAGE_ARRAY=1                 # M8: disable for isolated ZC verification (M9 will combo)
+FF_ZC_SEND=1
```

### 3.2 `example/Makefile` (+1 target line)

```diff
 all:
 	cc ${CFLAGS} -DINET6 -o ${TARGET} main.c ${LIBS}
 	cc ${CFLAGS} -o ${TARGET}_epoll main_epoll.c ${LIBS}
+	cc ${CFLAGS} -DINET6 -o ${TARGET}_zc main_zc.c ${LIBS}
```

### 3.3 Other source

**Default: no change**. If G1 fails, fix per R-M8-1 / R-M8-2.

---

## 4. Acceptance Criteria (G1-G7)

### G1 — build
| AC | Threshold |
|---|---|
| G1.1 lib `make all` | exit=0 / 0 errors / warnings ≤ 62 |
| G1.2 libfstack.a | within ±5% of M7's 6.55 MB |
| G1.3 example `make` | exit=0; produces helloworld + helloworld_epoll + **helloworld_zc** (3 binaries) |

### G2 — primary smoke
| AC | Test |
|---|---|
| G2.1 | helloworld_zc alive ≥10 s, 0 SIGSEGV/panic |
| G2.2 | log free of "stub called" / "FATAL" keywords |

### G3 — client-side HTTP test (OQ-1 default: client provided by user)
| AC | Command (server-side orchestrated) | Pass |
|---|---|---|
| G3.1 | server starts helloworld_zc primary (listens on [port0] addr 9.134.214.176:80) | bind succeeds, log shows listen |
| G3.2 | `ssh f-stack-client 'curl -sS -o /dev/null -w "%{http_code} %{size_download}\n" --connect-timeout 5 http://9.134.214.176/'` | HTTP 200 + body size > 0 |
| G3.3 | `ssh f-stack-client 'for i in $(seq 1 100); do curl -sS -o /dev/null --connect-timeout 5 http://9.134.214.176/; done; echo done'` 100× short conn | 100× success, no timeout / connection refused |

### G4 — simple perf observation (OQ-2 downgrade-allowed)
| AC | Method |
|---|---|
| G4.1 | short conn: client `time { for i in $(seq 1 1000); do curl ...; done; }` (helloworld vs helloworld_zc) | record wall time, compare ZC vs default |
| G4.2 | long conn: client `wrk -t1 -c10 -d10s http://9.134.214.176/` (if wrk available); else ab; else curl loop | record rps |

### G5 — doc sync (partial)
- docs/01-LAYER1 + zh_cn mirror: M8 footnote
- docs/Summary + zh_cn: scope tag + M8
- this milestone's execution log

### G6 — lint: 0 errors
### G7 — commit: local English commit, no push

---

## 5. Risks

| ID | Risk | Mitigation |
|---|---|---|
| **R-M8-1** | `m_getm2` signature changed in 14.0+ | grep `freebsd-src-releng-15.0/sys/sys/mbuf.h`; current lib already builds OK suggests compat |
| **R-M8-2** | f-stack-client → server routing fails (different VPC subnet) | ssh works empirically but cross-ARP/route is uncertain; G3.2 measures it, fix ARP if needed |
| **R-M8-3** | DPDK runtime residue (M7 SIGTERM was clean but stale files possible) | pre-launch `rm_tmp_file.sh` cleans `/var/run/dpdk/rte/*` |
| **R-M8-4** | port[0].addr config doesn't match 9.134.214.176 (user box IP) | measured: config.ini set to 9.134.214.176 (user runtime) |
| **R-M8-5** | helloworld_zc binding port 80 needs root + gratuitous ARP | sudo + helloworld_zc's own dpdk_if should auto-emit ARP |

---

## 6. Phase Progress

| Phase | Status |
|---|---|
| A. Spec (this doc) | ✅ |
| B. Research | folded into §2 |
| C. Code | ✅ v1 (FF_ZC_SEND on) |
| D. Review | ⏭ |
| E. Gate v1 | ⚠ G2 FAIL → bounce(gate→code) #1 |
| C. Code v2 (real M8 root cause fix, see §7) | ⏭ |
| E. Gate v2 | ⏭ |

---

## 7. RCA — Bounce #1 Root Cause & Fix (2026-06-08 15:30)

### 7.1 Symptom

helloworld_zc init clean (ipfw2/tcp_bbr/dpdk if registered) but **a single client-side curl triggers a GPF crash**:

```
dmesg: traps: helloworld_zc[1623044] general protection fault ip:10facb6 sp:7fffffffdae0
```

Idle 42 s no crash; **only crashes on packet arrival**.

### 7.2 gdb call stack (coredump `core.helloworld_zc.1623044.1780903615`)

```
#0  0x10facb6 in m_demote ()         <-- mov 0x1c(%rbx),%ecx; rbx is an invalid pointer
#1  0x11069f4 in sbappendstream ()
#2  0x124674e in tcp_usr_send ()
#3  0x111175f in sosend_generic ()
#4  0x1111a06 in sousrsend ()
#5  0x10f3b42 in kern_writev ()
#6  0x1061c08 in ff_write ()
#7  0x064aff5 in loop (arg=...) at main_zc.c:225  <-- #else branch
```

**Key register**: `rbx = 0x312e312f50545448` → ASCII = "HTTP/1.1" (little-endian: `48 54 54 50 2f 31 2e 31`). I.e., `m_demote` followed `m_next` into the `html_buf` char array.

### 7.3 Root cause (file:line refs)

`freebsd/kern/uipc_mbuf.c:2028-2037` is F-Stack's **native** ZC fast path (the same code as the 13.0 baseline — see `f-stack-13.0-baseline/freebsd/kern/uipc_mbuf.c:1776`; **unrelated to the 13→15 upgrade**):

```c
2028: #ifdef FSTACK_ZC_SEND
2029:     if (uio->uio_segflg == UIO_SYSSPACE && uio->uio_rw == UIO_WRITE) {
2030:         m = (struct mbuf *)uio->uio_iov->iov_base;  // ← treated as mbuf directly
2031:         uio->uio_iov->iov_base = (char *)(uio->uio_iov->iov_base) + total;
2032:         ...
2036:     } else {
2037: #endif
```

**Contract**: once lib is built with `FSTACK_ZC_SEND`, **every** `ff_write` call must be passed an mbuf pointer (caller must `ff_zc_mbuf_get` + `ff_zc_mbuf_write` first); a plain char buffer is no longer accepted by lib.

**Bug chain**:
1. `lib/Makefile:204-205` enables `-DFSTACK_ZC_SEND` → libfstack.a's `m_uiotombuf` enters the fast path above.
2. `example/Makefile:21` builds helloworld_zc **without `-DFSTACK_ZC_SEND`** → `main_zc.c:183` `#ifdef FSTACK_ZC_SEND` fails → `main_zc.c:225` runs the `#else` branch using `ff_write(clientfd, html_buf, buf_len)`; `html_buf` is a plain char array.
3. Inside lib, `m_uiotombuf` treats `iov_base = html_buf` as an mbuf pointer → `m_demote` parses ASCII text inside `html_buf` ("HTTP/1.1...") as `m_next` → reaches `0x102cfdf84` (a non-existent address) → GPF.

### 7.4 Fix (minimal diff)

**One site only**: add `-DFSTACK_ZC_SEND` to `example/Makefile` line 21.

```diff
- cc ${CFLAGS} -DINET6 -o ${TARGET}_zc main_zc.c ${LIBS}
+ cc ${CFLAGS} -DINET6 -DFSTACK_ZC_SEND -o ${TARGET}_zc main_zc.c ${LIBS}
```

**No** lib/ change needed — same as M6's user-space ip_fw.h ABI sync (user/kernel macro consistency).

### 7.5 Coupling with M9

M9 enabling PA + ZC together **still needs this fix** — `main_zc.c`'s macro contract with `m_uiotombuf` is independent of PA.

---

> Next: Phase C v2 — coder adds `-DFSTACK_ZC_SEND` to example/Makefile, rebuilds helloworld_zc, re-runs G1-G7.
