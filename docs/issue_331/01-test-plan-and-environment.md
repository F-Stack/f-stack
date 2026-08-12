# Issue #331 Test Plan and Environment

## 1. Test Environment

| Item | Config |
|------|--------|
| Machine | Dual NIC, DPDK exclusive NIC IP <DPDK_NIC_IP> |
| System uptime | 35 days (critical: sbinuptime is TSC-based, bug-state timer delay ≈ uptime) |
| F-Stack | feature/1.26 branch, FreeBSD 15.0 + DPDK 24.11.6 LTS |
| config.ini | hz=100, lcore_mask=1 (single thread), TCP functions_default=freebsd |
| Kernel stack test | 127.0.0.1 lo |
| DPDK NIC test | ssh f-stack-client → <DPDK_NIC_IP> |

## 2. Test Program

`example/evfilt_timer_test.c` (adapted from #701 reproducer):
- ff_kqueue + EVFILT_TIMER(NOTE_SECONDS, 1), 1-second periodic timer.
- Loop uses ff_kevent to fetch events, measures since_last interval with clock_gettime(CLOCK_MONOTONIC).
- Rearm timer every 10 triggers (EV_ADD) to test reschedule path.
- Exit after 30 triggers.

## 3. Test Matrix

| Test | Purpose | Config | Expected |
|------|---------|--------|----------|
| Reproduce | Confirm bug exists | bug-state lib (git stash revert fix) | Zero triggers within 90s (timer delay ≈ uptime 35 days) |
| T1 | Verify precision fix | fixed lib, 1s timer | 30 triggers, interval 1.000s ± 10ms |
| T2 | Verify periodic rearm | same as T1, rearm every 10 triggers | Interval still ~1s after rearm |
| T3 | TCP regression | csum_test_server + f-stack-client echo | TCP echo normal |
| T4 | Default config regression | No extra config | F-Stack starts normally + TCP echo (T3 covers) |

## 4. Reproduction Method

1. `git stash push -- freebsd/kern/kern_event.c` (revert Bug 1 fix, back to bug state).
2. `make clean && make` (lib) + compile evfilt_timer_test.
3. Run `./evfilt_timer_test --conf=config.ini --proc-type=primary --proc-id=0`, 90s timeout.
4. Observe: only "START" output, no "TRIGGER" (zero triggers).
5. `git stash pop` to restore fix.

## 5. Verification Method

1. After fix: `make clean && make` + compile test.
2. Run evfilt_timer_test, observe since_last values in TRIGGER lines.
3. Run csum_test_server + f-stack-client python client to verify TCP echo.

## 6. Key Observation Points

- **EAL argv**: `f-stack -c1 -n4 --proc-type=primary` (no extra_eal_args).
- **DBG sched** (during debug): `next`/`now` are sbintime (TSC scale), `to_ticks` should be ~100 (1s/10ms).
- **TRIGGER since_last**: After fix, should be stable at 1.000, not growing with uptime.
