F-Stack 2.0 Preview 6: LD_PRELOAD Lock-Free Ring IPC — Three Years of Evolution from Three-Layer Semaphore Synchronization to SPSC Dual Rings

1. What this feature does and its key characteristics

Let's get straight to the point: F-Stack's LD_PRELOAD module (libff_syscall.so) has evolved for three years since its initial commit in May 2023. This article covers the lock-free ring queue rework done for it in the first half of 2026 (FF_USE_RING_IPC), along with every optimization and change from the initial version to now.

Some background first. F-Stack's standard integration path requires code changes: the application calls the ff_*-prefixed APIs plus the ff_run() main loop, which is highly invasive. To lower the migration barrier for existing applications, the community submitted the adapter/syscall directory to the dev branch in 2023 (commit 8f5f1dfbb, 2023-05-03), providing the libff_syscall.so dynamic library that hijacks Linux socket syscalls via LD_PRELOAD and forwards them to an fstack instance process for handling — applications can integrate with zero code changes. The official positioning at the initial release was deliberately restrained: "the functionality is still incomplete and for testing only".

Three years later, this module supports fork, accept4, _FORTIFY_SOURCE wrapper functions, and the epoll polling mode, and has evolved the IPC between APP and fstack from three-layer semaphore synchronization to DPDK lock-free rte_ring dual-ring SPSC. The three keywords of this article:

- **Zero-code integration**: socket/bind/connect/read/write/epoll/kevent/select are all hijacked; existing applications (Nginx, netperf, etc.) run on F-Stack with zero code changes
- **Dual-ring SPSC**: FF_USE_RING_IPC replaces sem_wait/sem_post with rte_ring single-producer-single-consumer mode, eliminating the global lock and O(n) traversal
- **Honest convergence**: the ring rework went through seven rounds of measured iteration (v1~v3.7), and the final conclusion was not "ring wins across the board" but "ring has no performance advantage under LD_PRELOAD + FF_MULTI_SC; sem is recommended for production" — the core message of this article: optimization requires baselines, falsification, and the courage to overturn your own conclusions

Scale numbers: the adapter/syscall directory has accumulated 40+ commits since the initial version; the ring project produced 4 spec documents (docs/ld_preload_ring_spec/) and 1 v3.7 final performance analysis (ring_ipc_perf_offline_analysis.md); during the performance campaign, QPS went from 91k to 102.2k (+12.3%).

2. Main applicable scenarios

2.1 Zero-code integration of existing applications with F-Stack

This is the fundamental positioning of the LD_PRELOAD module. In the historical issue archive, when the maintainers answered "how to port existing multi-threaded / multi-process / Go / netperf-style applications", it was almost always their first recommendation: no source changes needed — start the fstack instance process first, then launch the application with LD_PRELOAD. The adapted interface surface covers the socket family, the epoll family, kqueue/kevent, select, fork, and the __recv_chk/__read_chk/__recvfrom_chk wrapper functions for glibc _FORTIFY_SOURCE builds.

2.2 Zero-code Nginx integration

F-Stack ships with Nginx 1.16.1 by default, which integrates via LD_PRELOAD without any code changes. Two compile switches must be enabled together — FF_KERNEL_EVENT + FF_MULTI_SC — with multi_accept on and listen reuseport in the configuration. The unsupported scenario is explicit: multiple instances acting as a client (reverse proxy) is not yet supported; it requires adding RSS symmetric-hash instance selection in the hook layer, as community member @铁皮大爷 did.

2.3 fork-based multi-process applications

After the fork support landed in 2025-05 (commit 4891fabf5, PR #887), every forked process owns an independent FreeBSD struct thread, with behavior aligned to Linux kernel fork. Combined with FF_MULTI_SC, the classic Nginx master-fork-worker model runs fine.

2.4 Scenarios that are not a good fit

- Chasing peak performance: each application instance group needs 2 CPU cores (1 fstack + 1 APP), nearly doubling CPU usage — "not cost-effective" in the maintainers' own words. For peak performance, change code and use standard F-Stack.
- Short-connection scenarios beyond 8 cores: LD_PRELOAD performs below standard F-Stack, limited by the matching degree between the APP and the fstack instance.

3. Architectural characteristics

3.1 Overall topology

```
┌───────────────────────────────────────────────────┐
│         User application (Nginx / netperf / ...)   │
│  socket()/bind()/listen()/connect()/accept()/      │
│  read()/write()/epoll_wait()/kevent()/fork()       │
└──────────────────────┬────────────────────────────┘
                       │ LD_PRELOAD hijacking
                       ▼
┌───────────────────────────────────────────────────┐
│  libff_syscall.so (APP-side hook layer)            │
│  ff_hook_syscall.c:                                │
│  route by fd: F-Stack or kernel;                   │
│  fill sc->ops/sc->args for the fstack instance     │
└──────────────────────┬────────────────────────────┘
                       │ Hugepage shared memory (rte_malloc)
                       │   ff_so_context (sc, one per context)
                       ▼
┌───────────────────────────────────────────────────┐
│  fstack instance process (1 instance = 1 full      │
│    F-Stack stack)                                  │
│  ff_handle_each_context() main loop:               │
│  handle sc requests → ff_so_handler → F-Stack API  │
│  time window reuses config.ini's pkt_tx_delay      │
└───────────────────────────────────────────────────┘
```

The core communication carrier is the ff_so_context (sc for short) on DPDK hugepage shared memory. The APP fills the socket operation to execute into the sc; the fstack instance's main loop handles it and writes the result back. The fstack instance and the APP are recommended to run on different physical cores of the same NUMA node.

3.2 Initial synchronization mechanism: three-layer semaphore sync

The initial version (2023-05 ~ 2026-04 default path) synchronized sc through three layers:

| Layer | Mechanism | Location |
|---|---|---|
| State machine | FF_SC_IDLE → FF_SC_REQ → FF_SC_REP → FF_SC_IDLE | ff_socket_ops.h |
| Mutex | rte_spinlock_t lock (sc-level + zone-level global lock) | ff_socket_ops.h |
| Semaphore | sem_t wait_sem (POSIX cross-process semaphore, futex-based) | ff_socket_ops.h |

One round trip of a socket call:

```
APP side                          fstack side
────────                          ──────────
FF_SC_IDLE ──fill ops/args──► FF_SC_REQ
                                    │ main loop O(n) scans all sc,
                                    │ dirty-reads status==REQ
                                    ▼
                              trylock → ff_so_handler(sc)
                                → F-Stack API handling
                                    │
                                    ▼
                            write back sc->result + sem_post wakeup
                                    │
FF_SC_REP ◄─────────────────────────┘
  │ read result/error
  ▼
FF_SC_IDLE
```

3.3 New synchronization mechanism: dual-ring SPSC

Commit d2b71ac89 on 2026-04-09 introduced FF_USE_RING_IPC: DPDK rte_ring (SPSC mode) replaces sem. The request ring is produced by APP and consumed by fstack; the response ring is produced by fstack and consumed by APP:

```
APP side                          fstack side
────────                          ──────────
① fill sc->ops/sc->args
② rte_ring_sp_enqueue(req_ring, sc)
        ┌─────────────┐
        │ Request ring │────► ③ rte_ring_sc_dequeue_burst()
        │  (SPSC)      │       batch dequeue, O(1) replaces O(n)
        └─────────────┘       ④ ff_handle_socket_ops_ring(sc)
                                  → sc->result = ...; sc->error = errno
        ┌─────────────┐       ⑤ rte_ring_sp_enqueue(rsp_ring, sc)
        │ Response ring│◄───（after the D2 optimization: write
        │  (SPSC)      │      sc->completion directly）
        └─────────────┘
⑥ rte_ring_sc_dequeue(rsp_ring) → read result/error
```

Equivalent migration of state semantics: sc in req_ring = old FF_SC_REQ; in rsp_ring = old FF_SC_REP; in neither ring = idle. The spinlock and state-machine transitions no longer participate in synchronization logic.

3.4 Why rte_ring was chosen

The spec document (SPEC-002) gives four reasons: F-Stack itself already uses rte_ring heavily (dispatch_ring, msg_ring) — zero learning cost; DPDK-native SPSC needs no self-built lock-free algorithm; Hugepage + rte_memzone has proven cross-process visibility; simpler than VPP's svm_msg_q. The 1:1 binding between APP and fstack instance naturally satisfies the SPSC constraint.

4. What was reworked and what problems were hit

The rest is a bit dry; skip this section if you don't need the implementation details and jump straight to Section 5.

4.1 Initial-version issue list (the motivation for the ring rework)

The spec document (SPEC-001) lists 5 performance bottlenecks of the initial semaphore mechanism:

1. **Kernel-mode transitions**: sem_wait/sem_post go through the futex syscall, 100-200ns each, amplified by short epoll_wait timeouts
2. **Poor timeout precision**: sem_timedwait uses CLOCK_REALTIME, affected by NTP adjustments, with wakeup granularity limited by the scheduler tick (1-4ms); plus a race: fstack may sem_post after the timeout returned, causing the next sem_timedwait to return immediately with a stale result
3. **O(n) traversal**: ff_handle_each_context scans the status field of all 32 sc every round, dirty-reading even the vast majority that are IDLE
4. **Fragile alarm_event_sem compensation**: only 1 of the 5 example programs actually calls it; the rest have it commented out
5. **Mode split**: the semaphore mode (low CPU, high latency) and the polling mode FF_PRELOAD_POLLING_MODE (low latency, 100% CPU) are mutually exclusive compile-time macros with no runtime switching

4.2 Three years of intermediate evolution (2023-08 ~ 2026-03, the groundwork before ring)

The ring did not come out of nowhere; the community fixed quite a few pitfalls during those three years, in chronological order:

| Date | commit | Content |
|---|---|---|
| 2023-08 | 0ee517ed0 | Fixed Ubuntu 22.04 / kernel 5.19 / gcc 11.4 build errors (#777), pre-C99 declaration issue |
| 2025-03 | 5de6ec6d2 | Added epoll polling mode, improving latency for RTT-sensitive scenarios |
| 2025-03 | 3c21f2253 | Fixed uninitialized sh_fromlen in ff_hook_recvfrom causing a -1 return (PR #872) |
| 2025-03 | e3766b423 | accept4 support + LINUX_SOCK_CLOEXEC/NONBLOCK support for ff_socket |
| 2025-05 | 111816e29 | Hooked __recv_chk/__read_chk/__recvfrom_chk; applications built with _FORTIFY_SOURCE now work |
| 2025-05 | 4891fabf5 | Full fork support (PR #887), each process gets an independent FreeBSD struct thread |
| 2026-03 | b36ce995d | Fixed the ioctl variadic-signature conflict compile error (#942, PR #1048) |

The ioctl pitfall deserves one more sentence: in glibc, ioctl(2) has a variadic signature int ioctl(int, unsigned long, ...), but ff_declare_syscalls.h registered it with fixed parameters — new toolchains blow up immediately. This kind of "glibc signature vs hook declaration" mismatch is a born minefield for LD_PRELOAD-style approaches, and can only be fixed pitfall by pitfall through community contributions.

4.3 The ring initial version landed (2026-04)

On 2026-03-27 four spec documents (requirements/architecture/interface/test) were produced first; after passing review, d2b71ac89 landed in one shot on 2026-04-09: dual rte_ring SPSC, the FF_USE_RING_IPC compile switch, three wait strategies (busy-poll/yield-poll/eventfd, default yield-poll), rte_rdtsc replacing sem_timedwait for microsecond-level timeouts, and alarm_event_sem reworked as a sentinel enqueue. The design strictly followed "compile-macro switch + old path untouched", allowing gradual migration.

4.4 The ring performance campaign (2026-05, the full collection of lessons from seven rounds)

The initial ring failed its first real measurement: short-connection QPS of 91k, 12.4% below the sem baseline of 105k. Thus began the seven-round iteration from v1 to v3.7 — the most valuable part of this article is not "how it was fixed" but "how wrong hypotheses were falsified one by one".

**Round 1 hypotheses (H10/H11, v1)**: after reading only the ring branch of ff_socket_ops.c, concluded "the sem mode has no 30us drain forced idle spinning". Falsified — checking the else branch showed sem has the same if (diff_tsc >= drain_tsc) break loop. Lesson: one-sided code analysis; never conclude without comparing against the other branch.

**Round 2 hypothesis (H15, v2)**: based on "sem has the nb_handled bypass and ring doesn't", assumed the ring's dequeue burst cross-core read of prod.tail caused an LLC miss explosion. Falsified by perf stat: the ring's LLC misses were actually 23% fewer than sem's (6.8K/s magnitude, not a bottleneck). Lesson: don't write hypotheses into documents before validating a falsifiable physical quantity.

**Round 3 (v3.1)**: turned "one sched_yield every 256 PAUSEs" into a secondary cause (H18) by pure arithmetic; measured three configurations (yield threshold 0xFF / 0x1FFF / busy-poll) — QPS all 92k, voluntary_ctxt_switches growth ≈ 0 — spin_count is a local variable and a single wait in short-connection scenarios never reaches 256. Lesson: sample frequency-class estimates in 10 seconds before taking a 30-minute detour.

**Round 4 (v3.2)**: perf top callgraph pinned the real causes — ff_ring_process_requests Self 15.44% (every main-loop spin went through the full dequeue burst function call stack even when nb=0) + ff_ring_send_response Self 3.33% (every response wrote rsp_ring->prod.tail, triggering cache invalidation on the APP core). The same round falsified two of our own hypotheses: H21 treated the wrk latency delta of +190us as single-syscall overhead (off by 3 orders of magnitude; the real cause was CPU-occupancy squeeze); H24, after perf had already given clear evidence, still floated a "cross-NUMA" environment hypothesis (the only variable in a same-environment controlled experiment is the IPC implementation itself).

**The failure of Plan C (v3.3, H25)**: tried to replicate sem's nb_handled fast skip with an atomic pending_count bypass — QPS regressed 4% instead (91k → 87k). Root cause: the APP wrote the atomic 2-4 extra times per syscall; the cross-core cache ping-pong cost more than the dequeue path it saved. The plan was implemented and reverted the same day, and the code was later deleted entirely (f344d945f). The lesson was written into the document as the "symmetric evaluation table" methodology: any optimization must list both the "physical quantities eliminated" and the "physical quantities introduced", and the latter must be clearly smaller in magnitude before implementation is allowed.

**The success of D2 (v3.4, +9.7%)**: abandoned the response ring; fstack writes sc->completion directly after handling (a field pre-reserved on sc cache line 0), and the APP side spins on the completion flag. Write frequency identical to the sem baseline, zero new cross-core fields. QPS 91k → 100k; ff_ring_send_response disappeared from perf top.

**D5 (+1.3%)**: ff_ring_process_requests now does an inline rte_ring_empty() fast-empty check first, not expanding the function call stack when empty. Self 18.98% → 4.53%, but QPS only rose 1.3% — the saved CPU was immediately filled by main-loop spinning. This is the starting point of the key insight: with fstack lcore at 100% CPU and the 30us drain design, IPC CPU savings do not translate 1:1 into QPS.

**D6 (+0.9%)**: ff_handle_socket_ops_ring marked static inline, called by name in the main loop (removing the function pointer), aligning with sem's ff_handle_socket_ops. 101.3k → 102.2k.

Final convergence: ring single-worker QPS 102.2k, still 2.7% short of sem's 105k. perf top shows the main-loop CPU share on both sides is now identical (50.13% vs 50.41%); the remaining gap comes from the acquire fence and ring metadata maintenance in rte_ring_sc_dequeue_burst — sem's dirty read is a plain load with no fence. **This is the physical cost of the SPSC architecture, irreducible in the single-worker single-lcore scenario.**

4.5 Unexpected bonus: the sem-path startup starvation fix

An old problem was fixed along the way during the ring campaign (8125beece, 2026-05-25). Symptom: with sem mode + FF_MULTI_SC + idle_sleep=0 in config.ini, on multi-worker startup with no traffic yet, nginx's second worker hangs in rte_spinlock_lock inside ff_attach_so_context — the gdb stack looks exactly like a deadlock.

But it is starvation, not deadlock: the fstack secondary lcore spins tightly on a dedicated core, releasing the lock every 50-100us but with a release window << 1us (idle_sleep=0 does not yield the CPU); the nginx worker is an ordinary scheduled process whose cmpxchg is always one beat late, making the probability of hitting the window approach zero. The fix changed only 13+/5- lines: snapshot tmp (the in-use sc count) before entering the while loop, and on unlikely(!tmp) do unlock → pause → lock to yield a window, with zero impact under load. The optimal patch is "conditional yielding", not "unconditional yielding".

[Note 1] This starvation phenomenon also shows: in cross-process spinlock contention, a dedicated-core DPDK lcore always beats an ordinary scheduled process — that is physics, not a code bug. A symptom that can be eliminated by configuration (idle_sleep = 1) is 99% a timing-window / scheduling-class problem.

4.6 Multi-core long-connection measurements: finally falsifying the ring's design goal (v3.5~v3.7)

After single-worker convergence, the comparison moved to multi-core. The results were harsher than expected:

| Scenario | Conclusion |
|---|---|
| Multi-core short connections (1/2/4 cores) | ring ≡ sem (gaps -1.9%/0%/-0.3%, within noise) |
| Multi-core long connections (1/2/4 cores) | ring **consistently worse than** sem by 2.4%~4.5%, directionally stable and beyond noise |

Long connections amplify rather than offset the ring's disadvantage: under FF_MULTI_SC each fstack lcore and nginx worker share a 1:1 zone, and sem's zone lock is exclusively held by the fstack lcore (cache line stays exclusive, nearly free), while the ring pays an acquire fence on every dequeue to synchronize with the memory system — linearly amplified at high QPS. The earlier prediction that "under long connections sem's lock-holding pressure would rise and the ring's lock-free advantage would emerge" was completely falsified.

The v3.7 final conclusions (2026-05-25 evening):

1. **Performance**: the ring has no net win in any measured scenario; sem remains the optimal configuration for LD_PRELOAD + FF_MULTI_SC
2. **Robustness**: the ring main loop's theoretical lock-free value (startup starvation immunity) was already fixed at the source in sem by 8125beece
3. **Architecture**: the ring code is kept (FF_USE_RING_IPC with D2/D5/D6 as default behavior, c62d56a3b) as reserved capability for future "multi-threaded sc sharing within one process" and "cross-process sc sharing (worker count > fstack instance count)" scenarios; the current fork multi-process scenario does not enable it by default

[Note 2] This convergence conclusion is worth rereading: a well-designed plan, backed by a complete spec and seven rounds of optimization, was ultimately judged "worse than the old approach" by controlled experiments. Without a baseline alongside the implementation, this conclusion would never have appeared. In performance work, "baseline before optimization" is worth more than "data before theory".

4.7 Still moving after the ring (2026-05 ~ 08)

The module did not stop after convergence: the README was fully refreshed (bc7c380b2, 2026-05-26); ff_hook_bind gained an addrlen bounds check (8762e05c1, 2026-06-08, #1068); a UDP echo server example was added (2215dc4f2, 2026-08-07, #1063).

5. How to use it, how to configure it, and the results

5.1 Compilation

```bash
export FF_PATH=/data/f-stack
export PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig

cd /data/f-stack/adapter/syscall
# Seamless Nginx integration: enable FF_KERNEL_EVENT + FF_MULTI_SC together
export FF_KERNEL_EVENT=1
export FF_MULTI_SC=1
# Optional: enable the lock-free ring IPC (off by default, see 5.4 recommended config)
#export FF_USE_RING_IPC=1
make clean; make all
```

Build artifacts: fstack (the instance program), libff_syscall.so (the hijacking library), 5 helloworld examples plus the main_stack_udp example. FF_USE_RING_IPC and FF_PRELOAD_POLLING_MODE are mutually exclusive — the Makefile has a compile-time check and errors out if both are defined.

5.2 Running

```bash
# 1. Start the fstack instance first (lcore_mask etc. same as standard F-Stack)
bash ./start.sh -b adapter/syscall/fstack

# 2. Then launch the application with LD_PRELOAD
export LD_PRELOAD=/data/f-stack/adapter/syscall/libff_syscall.so
export FF_NB_FSTACK_INSTANCE=4        # 1:1 with the nginx worker count
/usr/local/nginx/sbin/nginx
```

Runtime environment variables: FF_NB_FSTACK_INSTANCE (instance count, default 1), FF_INITIAL_LCORE_ID (starting core, default 0x4), FF_PROC_ID (process id, used with CPU binding). Applications that can bind cores themselves (e.g. nginx worker_cpu_affinity) should bind their own.

5.3 Nginx configuration essentials (no code changes, but configuration tuning is required)

```nginx
worker_processes  4;
worker_cpu_affinity 10000 100000 1000000 10000000;

events {
    worker_connections  1024;
    multi_accept on;      # F-Stack epoll wraps kqueue; must be on
    use epoll;
}

http {
    access_log  off;
    sendfile    off;      # must be off with F-Stack
    keepalive_timeout  0;

    server {
        listen       80 reuseport;   # each fd pairs with a different fstack instance's sc
        location / {
            return 200 "0123456789abcdefghijklmnopqrstuvwxyz";
        }
    }
}
```

Note that kern.maxfiles should not exceed 65536 (to guarantee correct mapping from epoll fds to kernel fds).

5.4 Results and recommended configuration

Performance data (dual E5-2670 v3 / 10G X540, measured in the v3.7 final version):

| Scenario | Sem | Ring | Gap |
|---|---|---|---|
| Multi-core short connections 1/2/4 cores (10k QPS) | 10.4 / 20.8 / 35.9 | 10.2 / 20.8 / 35.8 | ≤2% (noise) |
| Multi-core long connections 1/2/4 cores (10k QPS) | 33.3 / 65.9 / 130.5 | 31.8 / 64.3 / 127.0 | -2.4%~-4.5% |
| Single-worker optimization trajectory | — | 91k → 102.2k (+12.3%) | 2.7% short of sem's 105k |

Recommended production configuration (2026-05-25 final):

```bash
# LD_PRELOAD + nginx multi-worker recommended (default, ring off)
make FF_KERNEL_EVENT=1 FF_MULTI_SC=1
# config.ini: idle_sleep = 0 (safe after 8125beece), pkt_tx_delay = 50 (short) / 100 (long connections)
```

Enable the ring path only in any of these cases: multiple threads within one process need to share sc; multiple processes need to share sc (worker count > fstack instance count); or accepting a -2.4%~-4.5% performance loss in exchange for a lock-free main loop design.

Overall advice for F-Stack users: LD_PRELOAD is a "fewer code changes" trade-off, not a "best performance" path. For peak performance, integrate standard F-Stack with code changes; for quickly migrating existing applications, LD_PRELOAD + the default sem configuration suffices — enable ring when the future many-to-many sharing scenarios arrive.

Further reading:

- Ring requirements/architecture/interface/test specs: docs/ld_preload_ring_spec/01~04
- v3.7 final performance analysis (full recap of the seven rounds): docs/ld_preload_ring_spec/ring_ipc_perf_offline_analysis.md
- Official module docs (all feature updates 2023-05 ~ 2026-05): adapter/syscall/README.md
- Initial WeChat article (2023-05): https://mp.weixin.qq.com/s/hmxCEu0kOzp5X5TEB7r3OQ
- Three-layer architecture docs: docs/01-LAYER1-ARCHITECTURE.md
- Knowledge graph: docs/KNOWLEDGE_GRAPH_WIKI.md
- Historical issue archive: docs/f-stack-issue-ana.md
