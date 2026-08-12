# Issue #331 Root Cause Analysis and Fix Plan

## 1. Root Cause Analysis

### 1.1 Bug 1: Callout Scheduling Double-Counting (Precision Issue)

**Call chain**:
```
filt_timerstart (kern_event.c:949-959)
  kc->next = to + sbinuptime()          // absolute sbintime (TSC scale)
  → kqtimer_sched_callout (kern_event.c:787-792)
    callout_reset_sbt_on(&kc->c, kc->next, ..., C_ABSOLUTE)
    → macro callout_reset_sbt_on (callout.h:96-97)
      callout_reset_tick_on((c), (kc->next)/tick_sbt, ...)   // ignores C_ABSOLUTE, absolute sbt → absolute ticks
      → callout_cc_add (ff_kern_timeout.c:391)
        c->c_time = ticks + to_ticks   // ticks(since F-Stack start) + absolute_ticks(TSC scale) = double-counting
```

**Mathematical Verification** (system uptime 35 days, hz=100):
- `sbinuptime()` ≈ 35 days of sbintime (TSC-based, since CPU power-on).
- `kc->next` = SBT_1S + SBT_35days ≈ SBT_35days.
- `to_ticks` = kc->next / tick_sbt ≈ 35days/10ms ≈ 3.024e8 (absolute ticks, TSC scale).
- `ticks` (count since F-Stack start) ≈ 0.
- `c->c_time` = 0 + 3.024e8 → timer fires after 3.024e8 ticks (≈35 days).

**Scale Mismatch**: `sbinuptime()`/`kc->next` is TSC-based (since CPU power-on); `ticks` is F-Stack start count. Scale difference = system uptime. This is the root cause of #331 (10s→30-100s) and #701 (since_last 6.2s/68.4s growing over time).

### 1.2 Bug 2: Regular Callout Wheel Never Driven

**Code** (`lib/ff_kern_timeout.c:329-358`):
```c
callout_tick(void)
{
    ...
    cc = CC_SELF();
    ...
    for (; (cc->cc_softticks - ticks) < 0; cc->cc_softticks++) {
        bucket = cc->cc_softticks & callwheelmask;
        if (!LIST_EMPTY(&cc->cc_callwheel[bucket])) {
            need_softclock = 1;
            break;
        }
    }
    mtx_unlock(&cc->cc_lock);
#ifndef FSTACK
    if (need_softclock)
        softclock(cc);    // ← Dead code when F-Stack compiles with -DFSTACK!
#endif
}
```

- `callout_tick` is called by `ff_hardclock` (rte_timer callback, every 10ms).
- `softclock(cc)` processes the regular callout wheel (executing expired callout handlers).
- `#ifndef FSTACK` makes this call never execute under F-Stack → callouts on the regular callout wheel (EVFILT_TIMER, sleepq, etc.) **never fire**.
- F-Stack only drives the HPTS wheel via `ff_tcp_hpts_softclock()` (`ff_dpdk_if.c:2811` main loop); TCP timers via HPTS path are unaffected.

**Debug Verification**: After Bug 1 fix (to_ticks=100 correct), added debug printf confirming kqtimer_sched_callout was called with correct to_ticks, but filt_timerexpire was never called (no DBG expire) → confirms callout never fires.

### 1.3 Why TCP Timers Are Unaffected

- `lib/ff_stub_14_extra.c:149-153`: `callout_when` is an empty function stub.
- `tcp_timer.c:920-923` calls `callout_when` then `tp->t_timers[which]` remains relative sbt (stub is no-op).
- Macro converts to relative ticks → `c->c_time = ticks + relative` = correct (accidentally).
- TCP timers are actually driven by HPTS wheel (`ff_tcp_hpts_softclock`), not the regular callout wheel.
- Bug only affects kern_event.c EVFILT_TIMER (manually computes absolute + depends on regular callout wheel).

### 1.4 Upstream Comparison

Upstream FreeBSD 15.0 `kern_timeout.c:880-920` `callout_when`: with C_ABSOLUTE, preserves absolute sbt; otherwise converts to absolute. Upstream `callout_reset_sbt_on` (:939) is a real function using sbt-based callout wheel (`c->c_time = to_sbt` absolute). F-Stack uses old tick-based wheel (ff_kern_timeout.c) + empty stub callout_when + macro-ized callout_reset_sbt_on; the three are mismatched.

## 2. Fix Plan

### 2.1 Bug 1 Fix: kern_event.c kqtimer_sched_callout

`freebsd/kern/kern_event.c:787-797`:

```c
static void
kqtimer_sched_callout(struct kq_timer_cb_data *kc)
{
    /* F-Stack callout is tick-based; the sbt macro ignores C_ABSOLUTE,
     * so convert the absolute fire time to relative ticks here. */
    sbintime_t now = sbinuptime();
    int to_ticks = kc->next > now ? (kc->next - now) / tick_sbt + 1 : 0;

    callout_reset_tick_on(&kc->c, to_ticks, filt_timerexpire, kc->kn,
        kc->cpuid, 0);
}
```

**Principle**: Uses sbinuptime() (same scale as kc->next) to compute relative time `(kc->next - now)`, converts to relative ticks. Scale cancels out; result is uptime-independent. `+1` rounds up to avoid early firing (filt_timerexpire_l checks `now >= kc->next`). When `kc->next <= now` (already expired), to_ticks=0 → fires on next tick.

**Compatibility**: Compatible with NOTE_ABSTIME (kc->next=to absolute boot time) and normal periodic (kc->next=to+sbinuptime).

### 2.2 Bug 2 Fix: ff_kern_timeout.c callout_tick

`lib/ff_kern_timeout.c:355-357`: Remove `#ifndef FSTACK` guard:
```c
    if (need_softclock)
        softclock(cc);
```

`lib/ff_kern_timeout.c:199`: Add forward declaration:
```c
static void softclock(void *arg);
```

**Principle**: softclock() only does cc_lock + iterate callout wheel + call handler; no SWI/scheduler dependency; safe to call in F-Stack userspace (ff_hardclock/rte_timer context).

### 2.3 Excluded Alternatives

| Alternative | Exclusion Reason |
|-------------|-----------------|
| Pass kc->to relative + remove C_ABSOLUTE | Incompatible with NOTE_ABSTIME (kc->to=0 fires immediately) |
| Fix macro + implement callout_when | Large scope, affects TCP path, high risk |
| `(kc->next/tick_sbt) - ticks` (Option E original) | sbinuptime (TSC scale) vs ticks (F-Stack start scale) mismatch → huge to_ticks |

## 3. Performance Considerations

- Bug 1 fix only changes callout scheduling parameter computation; no runtime overhead.
- Bug 2 fix makes softclock check the callout wheel every 10ms (O(1) fast return when need_softclock is false); overhead is negligible.
- EVFILT_TIMER precision upper bound is tick granularity (1/hz=10ms@hz=100); design limitation, not a bug.

## 4. native-mt Notes

In native-mt (multi-threaded), each worker has an independent callout_cpu (CC_SELF returns per-thread cc); ff_hardclock_worker calls callout_tick → softclock to process that worker's callout wheel. Single-threaded test verified; multi-threaded high-concurrency scenario recommended for future stress testing.
