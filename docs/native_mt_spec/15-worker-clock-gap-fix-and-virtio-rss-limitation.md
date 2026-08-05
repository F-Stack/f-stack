# 15 Worker Clock Gap Fix and virtio RSS Limitation

> **Doc ID**: SPEC-NMT-15
> **Version**: v1
> **Date**: 2026-08-03
> **Status**: H1 (worker clock gap) located and fixed, verified in measurement.
> **⚠️ Conclusion superseded (2026-08-03)**: this document's Section 5 "the final bottleneck of 2-thread throughput being virtio PMD lacking RSS/RETA support (environment limitation, not a code defect)" **has been disproven by measurement**; refer to `16-multiqueue-comparison-experiment-and-root-cause-correction.md`.
> **Evidence rule**: all counts, req/s, and backtraces in this document come from actual run output; fabrication forbidden.

---

## 0. Superseding Statement (added 2026-08-03)

The conclusions in Sections 5 and 9 of this document about "virtio lacking RSS causing multi-queue failure" **do not hold**, because the comparison experiment missed the key configuration: **`thread_mode=0` + 2 processes with 2 queues**.

Doc 16 re-ran that experiment and measured:

| Configuration | Queue count | req/s |
|---|---|---|
| `thread_mode=0`, 1 process | 1 | 206,963 |
| **`thread_mode=0`, 2 processes** | **2** | **231,570** (normal) |
| `thread_mode=1`, 2 threads | 2 | 0 (not working) |

That is, virtio dual queues work normally and achieve higher throughput on the **exact same "no RSS" code path**. This document wrongly attributed the "1 queue vs 2 queue" difference to "process mode vs thread mode".

The true root cause is two code defects (details in doc 16):
1. **R1**: worker cred is attached to the global `prison0`, while a socket's vnet is taken from `CRED_TO_VNET(cred)` rather than `curvnet` (`freebsd/kern/uipc_socket.c:948`) → all worker sockets / `ifioctl` are silently redirected to vnet0.
2. **R2**: worker `pcpu_init()` passes `rte_lcore_id()` as cpuid, but this build is non-SMP (`MAXCPU==1`) → `zpcpu_get()` out of bounds.

After the fix, `thread_mode=1` dual threads reached ~233k req/s (on par with 2 processes' ~234k), and a 60-second 400-connection soak reached 497k req/s.

**Therefore the statement in this document's Section 9 "this is an environment constraint; nothing left to fix code-side" is also wrong.**

---

## 1. This Round's Starting Point

Doc 14's conclusion: per-vnet isolation (each worker independently `vnet_alloc()`s + independent ifp) eliminated the `in_pcblookup_mbuf` crash, but 2-thread throughput collapsed to 91.39 req/s while 1 thread was 209,388 req/s. This round locates the root cause of that throughput collapse.

---

## 2. Root Cause H1: Workers' FreeBSD Clock Was Never Driven

### 2.1 Code Evidence Chain

| Link | Location | Fact |
|---|---|---|
| Timer is thread-private | `lib/ff_dpdk_if.c:92` | `static __thread struct rte_timer freebsd_clock;` |
| Registration function | `lib/ff_dpdk_if.c:1181-1196` | `rte_timer_init(&freebsd_clock)` + `rte_timer_reset(..., rte_lcore_id(), &ff_hardclock_job, NULL)` inside `init_clock()` |
| Only registration call site | `lib/ff_dpdk_if.c:1722` | `init_clock()` is called only once in `ff_dpdk_init()` (main thread) |
| Worker init path | `lib/ff_freebsd_init.c:110-149` | `ff_stack_thread_init()` only does pcpu/thread/callwheel/vnet, **no `rte_timer_*` registration** |
| Data-plane determination | `lib/ff_dpdk_if.c:2679-2680` | `if (freebsd_clock.expire < cur_tsc) rte_timer_manage();` |
| Callwheel is thread-private | `lib/ff_kern_timeout.c:183-185` | `__thread struct callout_cpu cc_cpu;`, `CC_SELF()` returns this thread's instance |
| Tick advancement | `lib/ff_kern_timeout.c:339-349` | `callout_tick()` uses `cc = CC_SELF()` to advance this thread's `cc_softticks` |

DPDK-side key semantics: `rte_timer_manage()` only handles timers **registered on the current lcore** (`dpdk/lib/timer/rte_timer.c:674-686`; returns directly when the per-lcore `pending_head` is empty).

**Corollary**: a worker's `freebsd_clock` is a zero-initialized TLS (`expire == 0`); `0 < cur_tsc` is always true so `rte_timer_manage()` is called every round, but no timer is registered on that lcore → `ff_hardclock_job` never fires → the worker's `cc_cpu` callwheel never advances → syncache timeout, TCP retransmission, delayed ACK, keepalive, and TIME_WAIT recycling on vnet_i are all paralyzed.

### 2.2 Measured Validation (before fix)

Probe counts `ff_hardclock_job` firings per lcore, printed every 5 seconds:

```
DBG CLK lcore=1 hardclock=501  expire=7142589130052176
DBG CLK lcore=2 hardclock=0    expire=0
DBG CLK lcore=1 hardclock=1001 expire=7142602110052176
DBG CLK lcore=2 hardclock=0    expire=0
DBG CLK lcore=1 hardclock=1501 expire=7142615090052176
DBG CLK lcore=2 hardclock=0    expire=0
DBG CLK lcore=1 hardclock=2001 expire=7142628070052176
DBG CLK lcore=2 hardclock=0    expire=0
```

- lcore=1 (DPDK master lcore, main thread, vnet0): +500 per 5 seconds, i.e. 100Hz, normal
- lcore=2 (worker, vnet_2): **hardclock always 0, expire always 0**

H1 verified by measurement.

---

## 3. Fix Solution (Zero Data-Plane Locks)

### 3.1 Core Constraint

The fix must: let the worker advance its own callwheel, but **must not touch the globally shared time base**, otherwise N threads advancing it simultaneously would make time run N times faster.

Global state needing protection:

| Global state | Location | Consequence if ticked by multiple threads |
|---|---|---|
| `volatile int ticks` | `lib/ff_glue.c:132` | `atomic_add_int(&ticks,1)` executed by N threads → ticks advances N times faster → all ticks-based timeouts fire N times earlier |
| `static long count` + `tc_windup()` | `freebsd/kern/kern_tc.c:1923-1935` | timecounter advances at multiple speed; system time distorted |
| `static struct timespec current_ts` | `lib/ff_host_interface.c:64` | concurrent writes to the same timespec by multiple threads |

### 3.2 Implementation

**`lib/ff_kern_timeout.c`** — add a worker-specific clock entry:

```c
/*
 * Worker-thread clock: only advances this thread's own callwheel (cc_cpu is
 * __thread). Global `ticks` and the timecounter stay owned by the main thread,
 * otherwise N threads ticking them would make the shared time base run N times
 * too fast and break every ticks-based timeout.
 */
void
ff_hardclock_worker(void)
{
    callout_tick();
}
```

Compare the main-thread version `ff_hardclock()` (unchanged; the trailing un-enabled `#ifdef DEVICE_POLLING` block omitted):

```c
void
ff_hardclock(void)
{
    atomic_add_int(&ticks, 1);
    callout_tick();
    tc_ticktock((hz + 999)/1000);
    cpu_tick_calibration();
}
```

**`lib/ff_dpdk_if.c`** — add the worker timer callback and registration function:

```c
static void
ff_hardclock_worker_job(__rte_unused struct rte_timer *timer,
    __rte_unused void *arg) {
    ff_hardclock_worker();
}

/* Register this worker's own freebsd_clock (a __thread rte_timer) on its own
 * lcore, so main_loop's rte_timer_manage() can drive its per-thread callwheel.
 * The DPDK timer subsystem is already initialized by the main thread. */
static void
init_clock_worker(void)
{
    uint64_t hz = rte_get_timer_hz();
    uint64_t intrs = US_PER_S / ff_global_cfg.freebsd.hz;
    uint64_t tsc = (hz + US_PER_S - 1) / US_PER_S * intrs;

    rte_timer_init(&freebsd_clock);
    rte_timer_reset(&freebsd_clock, tsc, PERIODICAL,
        rte_lcore_id(), &ff_hardclock_worker_job, NULL);
}
```

The call site in `main_loop()` (after `ff_stack_thread_init()`, before `while(1)`):

```c
    if (ff_global_cfg.dpdk.thread_mode) {
        unsigned lcore = rte_lcore_id();
        if (freebsd_clock.expire == 0)
            init_clock_worker();
        ...
    }
```

`freebsd_clock.expire == 0` precisely distinguishes the main thread from workers: the main thread was already reset in `init_clock()` (expire non-zero) so it skips; workers' TLS is zero so they register.

**`lib/ff_api.symlist`** — add `ff_hardclock_worker` to avoid link failure from objcopy localization.

### 3.3 Zero Data-Plane Lock Argument

- The `while(1)` loop body is at `lib/ff_dpdk_if.c:2672-2826`; the whole file has only 3 lock operations (`:191` def, `:2657` lock, `:2659` unlock), **all outside the loop body**.
- `init_clock_worker()` call site is at `:2651-2652`, in the init path.
- `freebsd_clock` is `__thread`, bound to this lcore; `rte_timer_reset` has no cross-thread contention; no lock needed.
- `mtx_lock(&cc->cc_lock)` inside `callout_tick()` is a no-op in f-stack (`lib/include/sys/mutex.h:57-67` all `DO_NOTHING`), and `cc_cpu` is thread-private.
- `callout_tick()` is a safe pattern of "read-only global `ticks` + write-only thread-private `cc_softticks`" (`lib/ff_kern_timeout.c:342`).

### 3.4 Measured Validation (after fix)

```
DBG CLK lcore=1 hardclock=1001 expire=7143639270566176
DBG CLK lcore=2 hardclock=999  expire=7143639298714294
DBG CLK lcore=1 hardclock=1501 expire=7143652250566176
DBG CLK lcore=2 hardclock=1499 expire=7143652278714294
DBG CLK lcore=1 hardclock=2001 expire=7143665230566176
DBG CLK lcore=2 hardclock=1999 expire=7143665258714294
```

The worker (lcore=2) hardclock changed from **0 to advancing in sync with the main thread** (1999 vs 2001); `expire` is now registered non-zero. Fix effective.

---

## 4. Exclusion Conclusions for Other Hypotheses

| Hypothesis | Conclusion | Measured basis |
|---|---|---|
| H2: per-vnet ARP-table isolation prevents gateway MAC resolution | **Excluded** | after the client cleared its ARP cache, probes show `arp=1` received on **both lcores**; the ARP/NDP cross-queue cloning mechanism at `lib/ff_dpdk_if.c:2031-2061` works normally |
| H3: `ff_veth_set_gateway` fails in the worker vnet | **Excluded** | probe `setaddr_count=2` (both vnets configured with IPs), `ifaddr[0]=0x21f4c4a0` (vnet0), `ifaddr[1]=0x7fe2204836f0` (vnet_2) both non-NULL, no `setaddr failed`/`set_gateway failed` in logs |
| H4: worker time base stalled | **Same source as H1**, fixed with H1 | see 3.4 |

---

## 5. ~~Final Bottleneck: virtio PMD Lacks RSS/RETA (Environment Limitation)~~【This section's conclusion overturned; see Section 0 and doc 16】

### 5.1 Symptom

After the clock fix, 2-thread throughput improved from 91.39 req/s to 557.34 req/s (6x), but still far below 1 thread's ~209k req/s.

### 5.2 Measured Localization

Client-side tcpdump (during wrk):

```
13:42:15.912247 IP 9.134.211.87.33858 > 9.134.214.176.80: Flags [S], seq 3566723268, ...
13:42:16.929338 IP 9.134.211.87.33858 > 9.134.214.176.80: Flags [S], seq 3566723268, ...
13:42:17.953339 IP 9.134.211.87.33858 > 9.134.214.176.80: Flags [S], seq 3566723268, ...
13:42:18.977337 IP 9.134.211.87.33858 > 9.134.214.176.80: Flags [S], seq 3566723268, ...
13:42:20.001348 IP 9.134.211.87.33858 > 9.134.214.176.80: Flags [S], seq 3566723268, ...
13:42:21.025330 IP 9.134.211.87.33858 > 9.134.214.176.80: Flags [S], seq 3566723268, ...
6 packets captured
```

The client repeatedly retransmits the same SYN; f-stack never replies with SYN-ACK.

RX-layer probes (distinguishing "arrived at NIC" vs "entered the stack"):

```
=== before wrk ===
DBG CLK lcore=1 hardclock=2001 arp=0 rxburst=3  vethin=3
DBG CLK lcore=2 hardclock=1999 arp=0 rxburst=12 vethin=12
=== after wrk (t1 -c4 -d5s) ===
DBG CLK lcore=1 hardclock=3500 arp=0 rxburst=9  vethin=9
DBG CLK lcore=2 hardclock=3498 arp=0 rxburst=23 vethin=23
```

During wrk, `rxburst` only increased by 6+11=17 packets, and `rxburst == vethin` (all arrived packets entered the stack; the stack dropped nothing). **The SYN never reached the DPDK NIC.**

### 5.3 Root Cause

The NIC is virtio:

```
0000:00:09.0 'Virtio network device 1000' drv=igb_uio unused=
```

`lib/ff_dpdk_if.c:1009-1016` only prints `port[%d]: rss table size: %d` and records `rss_reta_size[port_id]` when `dev_info.reta_size` is non-zero. The measured ff_log has **no such output at all**, so `dev_info.reta_size == 0`, i.e. **virtio PMD provides no RSS/RETA capability**.

Under multi-queue config (2 queues, `dispatch_ring_p0_q0` / `dispatch_ring_p0_q1` both created successfully), virtio cannot distribute packets to the correct queue by flow hash, so TCP connections cannot be established. Single queue (1 thread) is unaffected.

**This is a virtual-NIC environment limitation, not an f-stack code defect.** ICMP single packets occasionally pass (ping 0% loss) but TCP connection establishment requires stable bidirectional queue consistency, hence wrk fails.

---

## 6. Performance Baseline Measured Data

Load command: `ssh f-stack-client "/data/wrk/wrk -t5 -c100 -d10s http://9.134.214.176:80/"`, 30-second trial interval.

### 6.1 thread_mode=1 (native-mt)

| Threads | lcore_mask | Trial 1 | Trial 2 | Trial 3 | Mean | Latency avg | Note |
|---|---|---|---|---|---|---|---|
| 1 | 2 | 208,092 | 212,124 | 209,155 | **209,790** | 451-461us | single queue, normal |
| 2 | 6 | 557 | 0 | — | — | 519us | virtio no RSS, multi-queue broken |

1-thread 3 trials fluctuate <2%; data stable.

### 6.2 thread_mode=0 (multi-process) Zero-Regression Comparison

| Config | req/s | Latency avg | Conclusion |
|---|---|---|---|
| thread_mode=0, lcore_mask=2 | **216,812** | 442.56us | consistent with historical baseline; this round's fix did not break multi-process mode |

---

## 7. This Round's Change List

| File | Change | Nature |
|---|---|---|
| `lib/ff_kern_timeout.c` | add `ff_hardclock_worker()` (advances only this thread's callwheel) | H1 fix |
| `lib/ff_dpdk_if.c` | add `ff_hardclock_worker_job()` / `init_clock_worker()`; worker clock registration in `main_loop` | H1 fix |
| `lib/ff_api.symlist` | add `ff_hardclock_worker` symbol export | H1 fix (link requirement) |
| `lib/ff_freebsd_init.c` | clean up last round's debug printf | cleanup |
| `lib/ff_veth.c` | clean up last round's debug probes | cleanup |
| `example/main.c` | clean up debug fprintf | cleanup |

All debug probes completely removed (grep `DBG `/`dbg_*` zero hits); after cleanup, 1-thread independently re-measured at 208,092 req/s, same order as before cleanup (208,514 req/s), confirming cleanup introduced no regression. That re-measure is 1-thread Trial 1 in the 6.1 table.

---

## 8. Independent Review Conclusion

Reviewed by an independent reviewer (writer/reviewer separation), all PASS:

| Audit item | Conclusion | Key evidence |
|---|---|---|
| A. Core data-plane zero locks | PASS | `while(1)` at `:2672-2826`; 3 lock operations (`:191`/`:2657`/`:2659`) all outside the loop; mutex.h all `DO_NOTHING` |
| B. Global time base not broken | PASS | `ff_hardclock_worker()` has no `atomic_add_int(&ticks)`/`tc_ticktock`/`cpu_tick_calibration`; `ff_hardclock()` untouched this round (`git diff` of `ff_kern_timeout.c` only adds the worker function) |
| C. thread_mode=0 zero regression | PASS | `init_clock_worker()` strictly inside the `thread_mode` branch; `init_clock()` main-thread path unchanged |
| D. Timer registration correctness | PASS | tsc algorithm character-identical to `init_clock()`; no repeated `rte_timer_subsystem_init`/`rte_timer_meta_init` |
| E. Debug code cleanup thorough | PASS | all `dbg_*`/`DBG ` patterns zero hits |
| F. vnet isolation completeness | PASS | `vnet_alloc` + `td_vnet` + `lo_set_defaultaddr` complete; `veth_ctx[lcore][port]` 2D access complete |

---

## 9. Remaining Items and Follow-up Directions

1. **virtio RSS limitation**: this machine's virtio NIC has no RSS capability; true 2/4-thread scalability cannot be validated in this environment. Need to re-measure 2/4-thread baselines on an RSS-capable physical NIC (ixgbe/i40e/mlx5 etc.). This is an environment constraint; nothing left to fix code-side.
2. **Software distribution fallback (optional enhancement)**: to support multi-threading on virtual NICs without RSS, consider single-queue RX + software hash distribution by five-tuple into each worker's `dispatch_ring` (`lib/ff_dpdk_if.c:2100-2114` already has a consumer-side mechanism), but this introduces cross-thread mbuf passing and requires evaluating the impact on "zero data-plane locks"; not implemented this round.
3. **per-vnet clock semantics self-consistent**: the division of labor of independent worker callwheels + main-thread-exclusive global ticks is correct in the current architecture. If the main thread also becomes a pure worker in the future (no special master-lcore role), the ownership of global ticks needs redesign.
