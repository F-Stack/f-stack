# Phase-2 M8 Execution Log — FF_ZC_SEND (P1b)

> Chinese version: ./zh_cn/phase2-M8-execution-log.md (authoritative)

> Status: ✅ PASS (all gates green; fixed within 1 bounce)
> Date: 2026-06-08
> Upstream basis: M7 commit `cba3d882b` (FF_USE_PAGE_ARRAY)

---

## 1. Summary

Enable `FF_ZC_SEND=1` (default `FF_USE_PAGE_ARRAY=0`, isolated ZC validation). M8 took one bounce at G2/G3; once we dug in, the root cause was deeper than the spec §5 risks suggested — **not just user/kernel macro alignment, but three co-failing design points in the 13.0-baseline ZC fast-path itself**:

1. The ZC fast-path predicate is too loose (`UIO_SYSSPACE && UIO_WRITE` matches every `ff_write` → plain char buffers get mistaken for mbufs).
2. There is no dedicated ZC entry point (`ff_write` cannot tell mbuf pointer from char array).
3. `dofilewrite` unconditionally overwrites `auio->uio_offset = offset` → even if the caller writes a sentinel, it gets lost.

**Fix**: introduce a `FSTACK_ZC_MAGIC` sentinel protocol + a new `ff_zc_send` public API + `dofilewrite` preserves the ZC sentinel + plain `ff_write/ff_writev` explicitly set `uio_offset=0` to guarantee no false hit.

---

## 2. Change List

### 2.1 Kernel side (freebsd/)

| File | Change | Lines |
|---|---|---|
| `freebsd/sys/mbuf.h` | new `FSTACK_ZC_MAGIC` macro (value `0xF8AC2C00F8AC2C00`) | +13 |
| `freebsd/kern/uipc_mbuf.c` | `m_uiotombuf` ZC fast path now also checks `uio_offset == FSTACK_ZC_MAGIC` | +12 / -2 |
| `freebsd/kern/sys_generic.c` | `dofilewrite` skips overwriting when `auio->uio_offset == FSTACK_ZC_MAGIC` + include `sys/mbuf.h` | +12 / -1 |

### 2.2 lib side

| File | Change | Lines |
|---|---|---|
| `lib/Makefile` | `FF_ZC_SEND=1` (uncomment) | +1 / -1 |
| `lib/ff_syscall_wrapper.c` | new `ff_zc_send` API + `ff_write/ff_writev` set `uio_offset=0` explicitly + include `sys/mbuf.h` | +35 / 0 |
| `lib/ff_api.h` | declare `ff_zc_send` + usage notes | +10 |
| `lib/ff_api.symlist` | add `ff_zc_send` to the export whitelist | +1 |

### 2.3 example side

| File | Change |
|---|---|
| `example/Makefile` | helloworld_zc target now passes `-DFSTACK_ZC_SEND` |
| `example/main_zc.c` | line 215 `ff_write` → `ff_zc_send` + extern declaration at the top |

**Total: 8 files +85/-4**

---

## 3. RCA Trajectory

### Bounce #1 — initial hypothesis: user-space macro missing

helloworld_zc init OK but a single curl GPF (IP `0x10facb6` = `m_demote+0x36`). Coredump in gdb: `rbx = 0x312e312f50545448` ASCII = `"HTTP/1.1"` — `iov_base` pointing at the HTML string was treated as an mbuf pointer by the fast path.

First hypothesis: `example/Makefile` missed `-DFSTACK_ZC_SEND` when building helloworld_zc, so `main_zc.c:225` ran the `#else` branch using `ff_write(html_buf, ...)`. After the patch the build PASSed, but **a single curl still crashed** (same GPF address).

### Bounce #1 cont. — even baseline crashes

Key new evidence: pure baseline `helloworld` (using main.c + plain `ff_write(html, len)`) **also GPF'd mid-way through a 100× short-conn test**. This proved lib's ZC fast-path predicate is too loose — `ff_write` internally sets `auio.uio_segflg = UIO_SYSSPACE`, then `kern_writev → dofilewrite → fo_write → sosend → m_uiotombuf` always trips the fast path, parsing the char buffer as an mbuf.

### Bounce #1 cont. — sentinel introduced

Designed the `FSTACK_ZC_MAGIC` sentinel (`0xF8AC2C00F8AC2C00`) written into `uio->uio_offset`, and the fast-path now also checks `uio_offset == FSTACK_ZC_MAGIC`. Plain `ff_write/ff_writev` explicitly set `uio_offset = 0` to opt out. Added a dedicated `ff_zc_send` entry point (main_zc.c:215 switched to use it), keeping `ff_write`'s public API semantics unchanged.

### Bounce #1 cont. — debug shows `dofilewrite` drops the sentinel

After the new build started, a single curl returned 649 bytes, but **all of it was mbuf-header memory** (`m_data` pointer + lots of 0x00s), not the HTML string. Primary stayed alive, payload was scrambled.

Added printf debug on `ff_zc_send` and at the fast-path entry:
- `[ZC] ff_zc_send: fd=1027 mb=0x7ffff78e1c00 nbytes=649` — caller mbuf is correct (m_data ASCII = "HTTP/1.1 200 OK..Server: F-Stack" ✓)
- `[ZC-FP]` debug **never appears** → fast path did not trigger.

Reading `freebsd/kern/sys_generic.c:559` — `dofilewrite` unconditionally `auio->uio_offset = offset`, while `kern_writev` passes `offset = (off_t)-1`; **the sentinel got overwritten with -1 before reaching `m_uiotombuf`**. Patched `sys_generic.c` to skip the overwrite when the sentinel is already present, retested:
- `[ZC-FP] enter: m=0x7ffff78e1c00 total=649` ✓ fast path hit
- HTTP/1.1 200 OK + Content-Length: 438 + the real HTML body ✓ ✓ ✓

### Bounce ledger

| # | Stage | Trigger | Fix |
|---|---|---|---|
| 1 | gate→code | helloworld_zc single-curl GPF + baseline 100× also GPF + payload scrambled | 3 source edits + sentinel protocol + new ff_zc_send API (rolled into one bounce) |

Bounce count **1/3** (plan §6 budget); **no escalation**.

---

## 4. Gate Results (measured)

### G1 — build

| Item | Result |
|---|---|
| `lib/ make clean && make` | exit=0 / 0 errors / 57 warnings (= M6/M7 baseline) |
| `libfstack.a` size | 6.55 MB |
| `example/ make` | exit=0 / 3 binaries (helloworld 29.02 / _epoll 29.02 / _zc 29.03) |
| `nm libfstack.a \| grep ff_zc_send` | `T ff_zc_send` (globally exported) |

### G2 — primary smoke

| Item | Result |
|---|---|
| primary alive ≥12 s | ✓ |
| Key log | `ipfw2 (+ipv6) initialized` / `tcp_bbr is now available` / `f-stack-0: Successed to register dpdk interface` |
| SIGSEGV / panic / stub-called | 0 |

### G3 — functional

| Item | Result |
|---|---|
| G3.2 single curl `--http0.9 -sS http://9.134.214.176/` | HTTP 200 / Content-Length 438 / body = real HTML |
| body verification | hexdump first 80 bytes = `<!DOCTYPE html>\r\n<html>\r\n<head>\r\n<title>Welcome to F-Stack!</title>\r\n<style>...` ✓ |
| G3.3 100× short-conn | ok=100 fail=0 ✓ |
| baseline non-ZC (helloworld) 100× short-conn | ok=100 fail=0 ✓ (M8 fix incidentally cured this regression) |
| primary exit | clean SIGTERM (within 5 s; no SIGKILL needed) |

### G4 — simple perf observation (OQ-2 default-allowed downgrade)

| build | 1000 short-conn time | Implied conn/s |
|---|---|---|
| helloworld (baseline non-ZC) | 6.884s | ~145 |
| helloworld_zc (FF_ZC_SEND) | 6.768s | ~148 |

Difference is in measurement noise (client-side curl serialization + ssh round-trip dominates). The full perf baseline is deferred to M9 (PA+ZC combo) using the Phase-5b methodology.

### G5 — docs

`phase2-M8-spec.md` + `phase2-M8-execution-log.md` complete; docs/01-LAYER1-ARCHITECTURE.md + Summary bilingual anchors follow the M6/M7 pattern.

### G6 — lint

0 errors (read_lints clean).

### G7 — commit

Local English commit, no push (per mandate).

---

## 5. Design Contract (in effect from M9 onwards)

```
                   user space                    libfstack
   ff_zc_mbuf_get -+
                  |--- build mbuf chain (m_getm2, M_WAITOK, MT_DATA, flags=0)
   ff_zc_mbuf_write
                  |--- fill m_dat + accumulate m_len
                  v
   ff_zc_send(fd, mbuf, len)
                  |--- aiov.iov_base = mbuf
                  |--- auio.uio_segflg = UIO_SYSSPACE
                  |--- auio.uio_offset = FSTACK_ZC_MAGIC  <-- key sentinel
                  v
   kern_writev → dofilewrite (kept FSTACK_ZC_MAGIC) → fo_write → sosend
                  → m_uiotombuf (FSTACK_ZC_SEND fast-path hit)
                  → return the caller's mbuf chain directly, skip the copy loop
                  → tcp_usr_send → sbappendstream → tcp_output → DPDK TX

   plain ff_write / ff_writev: same path, but uio_offset = 0 → fast path miss,
   take m_getm2 + uiomove copy loop (legacy behavior).

   ff_send / ff_sendto / ff_sendmsg → sendit → kern_sendit, which already
   sets uio_offset = 0; cannot trip the fast path by accident.
```

---

## 6. Known Leftovers and Follow-ups

| ID | Description | Plan |
|---|---|---|
| **F1** (informational, non-blocking) | The current G4 perf is dominated by ssh round-trip + curl serialization; cannot reflect ZC vs non-ZC delta accurately | M9 reuses the Phase-5b CVM A/B + physical-machine methodology with wrk/iperf at high concurrency |
| **F2** (already resolved) | The M7 baseline test could also crash from the same ZC fast-path mis-hit, but it never went past 1000 conn so it didn't surface | fixed alongside M8 (baseline 100× verified) |
| **F3** | M9 PA+ZC combo cross-impact still needs validation | own spec for M9 |

---

## 7. Phase Progress

| Phase | Status |
|---|---|
| A. Spec | ✅ |
| B. Research | ✅ |
| C. Code v1 (Makefile only) | ✅ → bounce |
| C. Code v2 (sentinel + new API + 6 files) | ✅ |
| D. Review | ✅ (self review, 0 lint) |
| E. Gate | ✅ G1-G7 all PASS |

**M8 overall: ✅ PASS**
