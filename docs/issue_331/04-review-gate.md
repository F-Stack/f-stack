# Issue #331 Review Gate

## 1. Code Change Review

### 1.1 kern_event.c kqtimer_sched_callout

- [x] `freebsd/kern/kern_event.c:787-797`: Changed to pass relative ticks (sbinuptime same-scale computation)
- [x] `ticks` visible (sys/kernel.h:76 extern, kern_event.c:42 includes it) ✓ M1 sub-agent confirmed
- [x] `tick_sbt` visible (sys/time.h:507, via sys/param.h:144 indirect include) ✓ M1 sub-agent confirmed
- [x] `callout_reset_tick_on` signature matches (ff_kern_timeout.c:720) ✓ M1 sub-agent confirmed
- [x] `filt_timerexpire` forward declaration at L172 (before L787) ✓ M1 sub-agent confirmed
- [x] Compatible with NOTE_ABSTIME (kc->next=to absolute; if expired, to_ticks=0)
- [x] filt_timerexpire_l periodic reschedule path correct (kc->next advanced at L843/L845 before L872 reschedule)
- [x] No lint errors
- [x] No debug printf residue

### 1.2 ff_kern_timeout.c callout_tick

- [x] `lib/ff_kern_timeout.c:355-357`: Removed #ifndef FSTACK guard, calls softclock(cc)
- [x] `lib/ff_kern_timeout.c:199`: Added `static void softclock(void *arg);` forward declaration
- [x] softclock() has no SWI/scheduler dependency, safe in userspace ✓
- [x] No lint errors

### 1.3 Blast Radius

- [x] Only kern_event.c EVFILT_TIMER manually computes absolute sbt (broken); other C_ABSOLUTE callers (tcp_timer/subr_sleepqueue/tcp_hpts/iflib) go through callout_when stub keeping relative → safe ✓ M1 sub-agent confirmed
- [x] softclock change is additive (regular callout wheel enabled); does not affect HPTS path (TCP still driven by HPTS)

## 2. Test Review

- [x] Reproduction test: bug state 90s zero triggers (delay ≈ uptime 35 days) ✓
- [x] T1 Precision: after fix 30 triggers, interval 1.000s ✓
- [x] T2 Periodic rearm: ~1s after rearm (20ms drift self-corrects) ✓
- [x] T3 TCP regression: echo normal ✓
- [x] T4 Default config: T3 covers ✓

## 3. Documentation Review

- [x] plan.md: complete plan ✓
- [x] 00-Investigation Overview: root cause + fix + test results ✓
- [x] 01-Test Plan and Environment: environment + matrix ✓
- [x] 02-Test Results and Data Analysis: reproduction + T1-T4 data ✓
- [x] 03-Root Cause Analysis and Fix Plan: dual bug + plan + exclusions ✓
- [x] 04-Review Gate: this document ✓
- [x] issue-ana.md Chinese and English #331/#701/#702 entries updated ✓

## 4. Constraint Compliance

- [x] rm→rm_tmp_file.sh, kill→kill_process.sh, chmod→chmod_modify.sh
- [x] lib minimal comments (kqtimer_sched_callout has 2 lines of necessary comments explaining why macro is bypassed)
- [x] commit message English 1-3 sentences
- [x] config.ini local test values not committed
- [x] make clean before compilation (always clean build)
- [x] Code/doc writing and review by different agents (main agent writes docs, sub-agent #2 reviews)

## 5. Potential Risks

- **native-mt multi-threaded**: softclock runs in each worker's ff_hardclock_worker context, processing that worker's callout wheel. Single-threaded verified; multi-threaded stress testing recommended for future.
- **softclock performance**: checks callout wheel every 10ms; O(1) when need_softclock=false. With many callouts, softclock iterates buckets, but F-Stack scenarios have limited callout count.
- **NOTE_ABSTIME**: fix is compatible (expired fires immediately, future scheduled by relative ticks), but precision is limited by tick granularity.
