# Issue #331 Investigation Overview: kqueue EVFILT_TIMER Precision

## 1. Issue Summary

- **#331** (reported 2019-02-12, OPEN): kqueue `EVFILT_TIMER` precision is very poor. User sets a 10-second timer, but it actually fires after 30-100 seconds, with deviation worsening over runtime.
- **#701** (2022-10-13, CLOSED): User self-diagnosed the root cause — F-Stack modified BSD callout to accept ticks parameter, kern_event.c uses a value relative to sbinuptime causing deviation; hacking to absolute value initially resolved it. Maintainer said they would check; no official fix.
- **#702** (2022-10-14, CLOSED): rack/bbr PCB memory leak, hpts skip_swi compile-time default fix.
- Maintainer commented in #331 that "#701/#702 should be fixed but commits are missing."

## 2. Investigation Conclusions

### 2.1 Commit History Review

| Commit | Description | Fixes #331? |
|--------|-------------|-------------|
| `e592cbbfe` (2023-02-14, Ref #701 #702) | Only changes config.ini (bbr recommended hz 100000→1000000) | **No** (config workaround, no code change) |
| `a816e8963` (2023-01-06, Fix #702) | Changes tcp_hpts.c skip_swi compile-time default | **No** (fixes PCB leak, not timer precision) |

Both commits exist in current HEAD (feature/1.26, 48fb0cdf1). The maintainer said "commits are missing" — they actually exist but neither is a code fix for timer precision. **The code bug in #331 remains unfixed to this day.**

### 2.2 Root Cause (Dual Bug)

**Bug 1: Callout scheduling double-counting (precision issue, direct root cause of #331/#701)**

- `freebsd/kern/kern_event.c:949-959` `filt_timerstart`: `kc->next = to + sbinuptime()` (manually computes absolute sbintime, based on TSC).
- `freebsd/kern/kern_event.c:787-792` `kqtimer_sched_callout`: `callout_reset_sbt_on(&kc->c, kc->next, ..., C_ABSOLUTE)` passes absolute sbt.
- `freebsd/sys/callout.h:96-97` F-Stack macro: `callout_reset_sbt_on(c, sbt, ...) = callout_reset_tick_on((c), (sbt)/tick_sbt, ...)` — **ignores C_ABSOLUTE**, converts absolute sbt to absolute ticks.
- `lib/ff_kern_timeout.c:391` `callout_cc_add`: `c->c_time = ticks + to_ticks` — when `to_ticks` is absolute ticks, **double-counting** occurs (`ticks` is the count since F-Stack start, `to_ticks` is TSC-scale absolute ticks; different scales).

**Bug 2: Regular callout wheel never driven (callouts never fire, discovered during investigation)**

- `lib/ff_kern_timeout.c:355-357` `callout_tick`: the `softclock(cc)` call is inside `#ifndef FSTACK` — when F-Stack compiles with `-DFSTACK`, this call is dead code; `softclock()` is never called.
- F-Stack only drives the HPTS wheel via `ff_tcp_hpts_softclock()` (main loop `ff_dpdk_if.c:2811`); the regular callout wheel (EVFILT_TIMER, sleepq, etc.) **is never processed**.
- Therefore, even if Bug 1 is fixed (to_ticks correct), callouts still never fire.

### 2.3 Why TCP Timers Are Unaffected

- `lib/ff_stub_14_extra.c:149-153`: `callout_when` is an empty function stub.
- `tcp_timer.c:920-923` calls `callout_when` then sbt remains relative → macro converts to relative ticks → `c->c_time=ticks+relative` is correct (accidentally).
- TCP timers are actually driven by the HPTS wheel (`ff_tcp_hpts_softclock`), not the regular callout wheel.
- The bug only affects kern_event.c EVFILT_TIMER (manually computes absolute + depends on regular callout wheel).

## 3. Fix Plan (Two Parts)

### 3.1 Bug 1 Fix: kern_event.c kqtimer_sched_callout

Convert absolute sbintime to relative ticks using sbinuptime() (same scale), pass directly to `callout_reset_tick_on`, bypassing the macro that ignores C_ABSOLUTE:

```c
static void
kqtimer_sched_callout(struct kq_timer_cb_data *kc)
{
    sbintime_t now = sbinuptime();
    int to_ticks = kc->next > now ? (kc->next - now) / tick_sbt + 1 : 0;
    callout_reset_tick_on(&kc->c, to_ticks, filt_timerexpire, kc->kn,
        kc->cpuid, 0);
}
```

### 3.2 Bug 2 Fix: ff_kern_timeout.c callout_tick

Remove the `#ifndef FSTACK` guard so that `softclock(cc)` is called under F-Stack, driving the regular callout wheel. Also add a forward declaration for `softclock`.

## 4. Modified Files

| File | Change |
|------|--------|
| `freebsd/kern/kern_event.c:787-797` | kqtimer_sched_callout changed to pass relative ticks |
| `lib/ff_kern_timeout.c:199` | Add softclock forward declaration |
| `lib/ff_kern_timeout.c:355-357` | Remove #ifndef FSTACK guard, call softclock(cc) |
| `example/evfilt_timer_test.c` | New test program |

## 5. Test Results

| Test | Config | Result |
|------|--------|-------|
| Reproduce (bug state) | 1s timer, run 90s | **Zero triggers** (sbinuptime based on TSC, system uptime 35 days → timer fires ~35 days later) |
| T1 Precision (after fix) | 1s timer, 30 triggers | **PASS**, interval exactly 1.000s |
| T2 Periodic rearm | rearm every 10 triggers | **PASS**, interval still ~1s after rearm (20ms drift self-corrects) |
| T3 TCP regression | csum_test_server echo | **PASS**, TCP echo normal |
| T4 Default config | No extra config | **PASS** (T3 covers) |

## 6. hz Granularity Note

hz=100 → tick=10ms → EVFILT_TIMER precision upper bound is 10ms. Users can increase hz to improve (e.g., hz=1000→1ms). This is a design limitation, not a bug.
