# 16 Multi-Queue Comparison Experiment and Root-Cause Correction: native-mt Multi-Thread Throughput Fix

> **Doc ID**: SPEC-NMT-16
> **Version**: v1
> **Date**: 2026-08-03
> **Status**: completed (code fixed and measured-verified)
> **Nature**: **correction of doc 15's conclusion + true root-cause location and fix**
> **Companion docs**: `plan-16-multiqueue-comparison-and-correction.md` (plan), `_m1_A_codepath.md` (code-path verification), `_m1_B_external.md` (external research), `_m4_D_review.md` (independent review)

---

## 1. Conclusion Summary

### 1.1 Doc 15's Conclusion Disproven by Measurement

Doc 15 Section 5 had determined:

> "The final bottleneck of 2-thread throughput was located as virtio PMD lacking RSS/RETA support (environment limitation, not a code defect)"

**That conclusion is wrong.** This round re-ran the key comparison experiment missing from doc 15 (`thread_mode=0` + 2 processes with 2 queues), proving that virtio dual queues work normally and achieve higher throughput on the **exact same "no RSS" code path**. The original experiment wrongly attributed the "1 queue vs 2 queue" difference to "process mode vs thread mode".

### 1.2 True Root Causes (two independent defects, both code-verified and fixed)

| # | Defect | Symptom | Fix location |
|---|---|---|---|
| **R1** | worker cred attached to the global `prison0`, while a socket's vnet is taken from the cred's prison (`CRED_TO_VNET`) rather than `curvnet` → all worker sockets / `ifioctl` silently redirected to vnet0 | worker vnet has no interface address, no default route (`ENETUNREACH`); app listen PCBs all built in vnet0 while the data plane looks up PCBs in the worker vnet → SYN received but no SYN-ACK returned | `lib/ff_freebsd_init.c` adds `ff_worker_prison_init()` |
| **R2** | worker `pcpu_init()` passes `rte_lcore_id()` (=2) as cpuid, but this build is non-SMP (`MAXCPU==1`), `mp_maxid==0`; UMA/SMR per-cpu arrays allocated for only 1 CPU → `zpcpu_get()` out of bounds | after R1 fixed, the worker vnet's PCB table is genuinely used; `in_pcblookup_mbuf` SIGSEGVs under load | `lib/ff_freebsd_init.c` `ff_pcpu_thread_init()` changed to pass 0 |

Bonus fix R3: `init_mem_pool()` loop upper bound `nb_procs` → thread_mode-aware (a conditional defect triggered only across NUMA).

### 1.3 Fix Effect

`thread_mode=1` dual threads recovered from **completely unusable** (0 req/s, client repeatedly retransmitting SYN) to **~233k req/s**, on par with 2-process mode (~234k); a 60-second 400-connection soak reached **497k req/s**, 29.83M requests with zero errors.

---

## 2. Decisive Comparison Experiments (All Actually Executed)

Unified load command: `ssh f-stack-client "/data/wrk/wrk -t5 -c100 -d10s http://9.134.214.176:80/"`

### 2.1 Before Fix: Exposing Doc 15's Experiment-Design Defect

| Experiment | Config | Process/Thread | Queues | Measured req/s |
|---|---|---|---|---|
| E1 | `thread_mode=0`, `lcore_mask=2` | 1 process | 1 | 206,963 |
| **E2** | `thread_mode=0`, `lcore_mask=6` | **2 processes** (primary + secondary) | **2** | **231,570** ✅ |
| E3 | `thread_mode=1`, `lcore_mask=6` | 1 process 2 threads | 2 | **connection timeout** (0) ❌ |

E2's dual-queue evidence:
- `example/f-stack-0.log`: `lcore: 1, port: 0, queue: 0`
- `example/f-stack-1.log`: `lcore: 2, port: 0, queue: 1`
- `dispatch_ring_p0_q0` / `dispatch_ring_p0_q1` both created successfully

**E2 is the experiment doc 15 never ran, and it is exactly what overturned the original conclusion.**

### 2.2 NIC-Side Config Byte-Identical Across the Two Modes (probe-verified)

Adding a temporary probe after `rte_eth_dev_configure`, the two modes output **identically**:

```
DBGCFG port=0 nb_queues=2 mq_mode=0 rss_hf=0x0 reta=0 max_rxq=4
```

That is, `mq_mode = RTE_ETH_MQ_RX_NONE`, `rss_hf = 0`, `reta_size = 0` (no RSS) is **the same configuration** under 2 processes and 2 threads. Since 2 processes can run at 231k, "no RSS" naturally cannot explain 2 threads' 0 req/s.

### 2.3 Queue-Level Traffic Evidence (before fix)

| Config | q0 received | q1 received | req/s |
|---|---|---|---|
| 2 processes 2 queues | 998,397 | 1,060,665 | 231,373 ✅ |
| 2 threads 2 queues | 11 | 11 | 0 ❌ |

Both queues work at full load under 2 processes, proving the host side indeed distributed traffic to both queues.

### 2.4 After Fix (final validation, clean build, zero debug residue)

| Experiment | Config | trial 1 | trial 2 | trial 3 |
|---|---|---|---|---|
| **E4** | `thread_mode=1`, 2 threads 2 queues | **233,380** | **234,084** | **230,510** |
| E5-a | `thread_mode=1`, 1 thread 1 queue | 209,483 | 209,739 | — |
| E5-b | `thread_mode=0`, 1 process 1 queue | 209,946 | 209,367 | — |
| E5-c | `thread_mode=0`, 2 processes 2 queues | 234,613 | 233,982 | — |

- E4 latency: `Latency 410.91us~ 418.93us`, `Socket errors` all 0
- Single-thread baseline 209,483/209,739 consistent with doc 15's recorded 209,790 → **no regression**
- Both `thread_mode=0` configs consistent with before-fix → **zero regression**

### 2.5 Long Soak (stress validation for the residual SMR risk)

```
ssh f-stack-client "/data/wrk/wrk -t8 -c400 -d60s http://9.134.214.176:80/"
  29834366 requests in 1.00m, 18.03GB read
  Requests/sec: 497043.57
```
60 seconds, 400 concurrent connections, 29.83M requests: zero socket errors, zero Non-2xx, process alive.

---

## 3. Root Cause R1: Worker Sockets Silently Redirected to vnet0

### 3.1 Runtime Hard Evidence (temporary probes, removed)

```
Main thread (f-stack-0.log):
DBGSOCK cret=0 so=0x7f9526f94400 so_vnet=0x37754ef0 curvnet=0x37754ef0 ioctl_ret=0
DBGVNET curvnet=0x37754ef0 ifp_vnet=0x37754ef0 ifp_fib=0 gw_ifa=0x37d1f240 self_ifa=0x37d1f240 unit_eq=1 flags=0x8803

Worker (helloworld.log):
DBGSOCK cret=0 so=0x7f9526f95c00 so_vnet=0x37754ef0 curvnet=0x7f952000eb10 ioctl_ret=0
DBGVNET curvnet=0x7f952000eb10 ifp_vnet=0x7f952000eb10 ifp_fib=0 gw_ifa=0 self_ifa=0 unit_eq=1 flags=0x8802
f-stack-0: ff_veth_set_gateway failed DBGERR=51
```

Interpretation:

| Observation | Meaning |
|---|---|
| worker `so_vnet=0x37754ef0` **equals main thread's vnet0**, while `curvnet=0x7f952000eb10` | the socket's vnet and the worker's own vnet **mismatch** |
| `ioctl_ret=0` but `self_ifa=0`, `gw_ifa=0` | `SIOCAIFADDR` "succeeded", but the address is not in the worker vnet |
| `unit_eq=1` | `ifunit_ref(if_name)` equals `sc->ifp` → the interface itself is on the worker vnet's `V_ifnet`; not an interface misplacement |
| `flags`: main thread `0x8803` includes `IFF_UP`(0x1); worker `0x8802` lacks it | a side effect of the address not being attached |
| `DBGERR=51` = **ENETUNREACH** | `freebsd-src-releng-15.0/sys/sys/errno.h:114`; comes from `net/route.c:507` `rt_getifa_fib()` where `info->rti_ifa == NULL` |

### 3.2 Code Chain (verified item by item)

| Step | Location | Fact |
|---|---|---|
| 1 | `freebsd/net/vnet.c:336` | `curvnet = prison0.pr_vnet = vnet0 = vnet_alloc();` — prison0 permanently bound to vnet0 |
| 2 | `lib/ff_init_main.c:586-590` | worker cred: `p->p_ucred = crget(); ... cr_prison = &prison0;` |
| 3 | `freebsd/net/vnet.h:247` | `#define CRED_TO_VNET(cr) (cr)->cr_prison->pr_vnet` → **vnet0** |
| 4 | `freebsd/kern/uipc_socket.c:948` | `so = soalloc(CRED_TO_VNET(cred));` → all worker sockets' `so_vnet` = vnet0 |
| 5 | `freebsd/kern/uipc_socket.c:829-833` | `so->so_vnet = vnet;` (from the soalloc argument) |
| 6 | `freebsd/net/if.c:2908` | `ifioctl()` starts with `CURVNET_SET(so->so_vnet);` → **switches to vnet0** |
| 7 | `lib/ff_veth.c:599-601` | `ff_veth_setaddr` uses `socreate()` + `ifioctl(so, SIOCAIFADDR, ...)` |
| 8 | consequence | the worker's IP is added to **vnet0**'s `f-stack-0` (hence `ioctl_ret=0`); the worker's own vnet's ifp never gets an address |
| 9 | `lib/ff_veth.c:1028` → `lib/ff_veth.c:638` (`rib_action`) → `freebsd/net/route/route_ctl.c:756-757` → `freebsd/net/route.c:497,507` | `ff_veth_set_gateway`'s `rib_action(RTM_ADD)` uses `curvnet` directly (not via socket) → `ifa_ifwithroute` cannot find the on-link ifa → `ENETUNREACH` |

### 3.3 Impact Scope (not just routing)

All worker operations that "enter the stack via sockets" are silently redirected to vnet0:
- `ff_veth_setaddr` / `ff_veth_setaddr6` / `ff_veth_setvaddr` (`ifioctl` path)
- `lo_set_defaultaddr()` (defined `lib/ff_freebsd_init.c:219-263`; its `socreate` at `:255`, `ifioctl` at `:259`; worker call site `:215`, main-thread call site `:342`)
- **app-side `ff_socket`/`ff_bind`/`ff_listen`**: worker listen PCBs all built in vnet0's PCB hash table, while the data plane's `ff_veth_input` uses `ifp->if_vnet`(=worker vnet) as curvnet to look up PCBs → listen socket never found → no SYN-ACK

This exactly matches the measured "listen succeeds, client repeatedly retransmits SYN with no response".

### 3.4 Why thread_mode=0 Has No Such Problem

Multi-process mode: each process has an independent address space, each with its own `prison0`, and each `prison0.pr_vnet = its own vnet0`, so `CRED_TO_VNET(cred) == curvnet` always holds. **Single-process multi-thread shares the unique `prison0` (`lib/ff_init_main.c:97`), which is what exposes the mismatch.**

### 3.5 Fix

`lib/ff_freebsd_init.c` adds `ff_worker_prison_init()`: allocates an independent prison for each worker, `pr_vnet` pointing to that worker's vnet, and rewrites the worker cred's `cr_prison`. Key points:
- Copy scalar and string fields from `prison0`; `LIST_INIT` the three list heads; `mtx_init` initializes `pr_mtx`.
- **Deliberately not linked into** `allprison` / prison0's children list, avoiding global-list concurrency and jail-iteration side effects.
- The call site must be after `vnet_alloc()` and before `lo_set_defaultaddr()` (the latter calls `socreate`).

After the fix, the worker's `ff_veth_set_gateway failed` disappeared, and probes confirm each thread's listen socket lands in its own vnet:

```
DBGAPP lcore=1 kq=1024 sockfd=1025 vnet=0x8c2fef0
DBGAPP lcore=2 kq=1024 sockfd=1025 vnet=0x7fef0000eb10
```

---

## 4. Root Cause R2: Per-CPU Out-of-Bounds SIGSEGV Under Non-SMP View

After fixing R1, the worker vnet's PCB table was genuinely used for the first time, and the crash was immediately exposed under load:

```
Thread 4 "dpdk-worker2" received signal SIGSEGV, Segmentation fault.
#0  in_pcblookup_mbuf ()
#1  tcp_input ()
#2  ip_input ()
#3  netisr_dispatch ()
#4  ether_nh_input ()
#5  netisr_dispatch ()
#6  ether_input ()
#7  process_packets ()
#8  main_loop ()
```

### 4.1 Code Chain

| Step | Location | Fact |
|---|---|---|
| 1 | `freebsd/amd64/include/param.h:60-66` | `SMP` undefined → **`MAXCPU == 1`** (`lib/opt/opt_global.h` and `lib/Makefile` whole tree have no `-DSMP`) |
| 2 | `lib/ff_glue.c:140,145` | `mp_ncpus = 1`, `mp_maxid = 0` |
| 3 | `freebsd/vm/uma_core.c:2546-2548` | `#ifndef SMP` strips the `UMA_ZONE_PCPU` flag → per-cpu allocation has only 1 slot |
| 4 | `freebsd/kern/subr_smr.c:597-605` | SMR initializes only `0..mp_maxid` (i.e. only CPU 0) |
| 5 | `freebsd/kern/subr_pcpu.c:96` | `pcpu_init()` sets `pc_zpcpu_offset = zpcpu_offset_cpu(cpuid)` |
| 6 | `freebsd/sys/pcpu.h:234-236,249-252` | `zpcpu_offset_cpu(cpu) = UMA_PCPU_ALLOC_SIZE * cpu` (PAGE_SIZE); `zpcpu_get(base) = base + zpcpu_offset()` |
| 7 | `freebsd/kern/subr_pcpu.c:88` | `KASSERT(cpuid < MAXCPU)` is **compiled out** because `INVARIANTS` is undefined, so cpuid=2 silently passes |
| 8 | `freebsd/netinet/in_pcb.c:583,615-617` | PCB zone created with `UMA_ZONE_SMR`, `ipi_smr = uma_zone_get_smr(...)`; `in_pcblookup_mbuf` goes through `smr_enter/smr_exit` |
| 9 | consequence | worker originally passed `rte_lcore_id()`=2 → offset=8192 → `zpcpu_get()` in `smr_enter` reads out-of-bounds memory → SIGSEGV |

### 4.2 Additional Verified Collateral Defects (same root cause)

- `freebsd/netinet/ip_id.c:270` `zpcpu_get(V_ip_id)` executes on the `ip_output` → `ip_fillid()` (`freebsd/netinet/ip_output.c:371`) path → before the fix, every time that branch was reached it was an out-of-bounds read.
  (Precise boundary: the line is in the `else` branch; when `:250`'s `if (V_ip_rfc6864 && (ip->ip_off & htons(IP_DF)) == htons(IP_DF)) ip->ip_id = 0;` hits, this line is not reached, so it is not "reached on every packet".)
- `lib/ff_kern_timeout.c:254,730-734`: `timeout_cpu = PCPU_GET(cpuid)`, and `if (cpu >= MAXCPU) panic("Invalid CPU in callout %d")`. Before the fix, worker `c_cpu = 2 >= MAXCPU(1)`.

### 4.3 Fix

`ff_pcpu_thread_init()` changed to `pcpu_init(pcpup, 0, sizeof(struct pcpu))`.

Correctness basis:
- `pcpup` is `__thread` (`lib/ff_freebsd_init.c:85`); `lib/include/amd64/include/pcpu.h:33-53` redefines all `PCPU_GET/PCPU_SET/get_pcpu` to access via `pcpup`, **unrelated to `cpuid_to_pcpu[]`** → each thread still has an independent pcpu; isolation unchanged.
- The main-thread path already passes 0 (`lib/ff_freebsd_init.c:293` `ff_pcpu_thread_init(0)`) → **no-op** for `thread_mode=0`.
- Review suggestion adopted: `ff_pcpu_thread_init()` call site moved into the `init_lock` critical section, because `pcpu_init()` writes the globals `cpuid_to_pcpu[0]` and `cpuhead` (`freebsd/kern/subr_pcpu.c:91-92`). Init path only; zero data-plane impact.

---

## 5. Bonus Fix R3: mempool Loop Upper Bound

`lib/ff_dpdk_if.c:547-551`:

```c
uint16_t nb_pools = ff_global_cfg.dpdk.thread_mode
    ? ff_global_cfg.dpdk.nb_threads : ff_global_cfg.dpdk.nb_procs;
for (i = 0; i < nb_pools; i++) {
    lcore_id = ff_global_cfg.dpdk.proc_lcore[i];
```

The original upper bound was `nb_procs`, but with `thread_mode=1`, `lib/ff_config.c:1465-1484` stuffs `nb_procs` to 1 with the real thread count in `nb_threads`. Consequence: a mempool is only built for the NUMA socket of `proc_lcore[0]`; if a worker is on another socket, `init_port_start` (`lib/ff_dpdk_if.c:1062-1086`) fetches the pool by the queue lcore's socket and gets NULL.
`nb_mbuf` scale calculation already correctly used `nb_threads` (`:526-527`); this change makes the loop consistent with it.

**This machine's lcores 1/2 are on the same socket, so this defect was not triggered** (ff_log only shows `create mbuf pool on socket 0`); it is a preventive fix.

---

## 6. Disproven Hypotheses (avoid future dead ends)

| Hypothesis | Verdict | Basis |
|---|---|---|
| virtio lacking RSS causes multi-queue failure | **Disproven** | E2 measured 2 processes 2 queues at 231,570 req/s; both modes' `DBGCFG` config byte-identical |
| `dispatch_ring`/`msg_ring` allocated by `nb_procs` causing worker NULL access | Disproven | `init_dispatch_ring` uses `pconf->nb_lcores`(=2) (`lib/ff_dpdk_if.c:643-660`); `init_msg_ring` explicitly picks `nb_threads` by thread_mode (`:692-694`) |
| `veth_ctx` main-thread/worker entry misplacement | Disproven | 2D `[lcore][port]` isolation; probe `unit_eq=1` |
| KNI ownership swallowing port-80 SYN | Disproven | this machine's config.ini has the `[kni]` section entirely commented (`config.ini:298` is `#[kni]`, KNI not enabled); and even if enabled, `method=reject` sends port-80 traffic through `ff_veth_input` (`lib/ff_dpdk_if.c:2081-2089`) |
| worker vnet has no listen socket | Disproven | `example/main.c:22-28` `__thread` fds + `:62-140` per-thread `SO_REUSEPORT`+`bind`+`listen`; probe `DBGAPP` shows both lcores have sockfds |
| worker/socket vnet-context misalignment at the `ifp` layer | Disproven | probe `curvnet == ifp_vnet`; the misalignment is on the **cred→prison→vnet** chain (i.e. R1) |

---

## 7. External-Research Cross-Validation (`_m1_B_external.md`, 24 verifiable sources)

Key conclusions (cross-checked against code; code wins on conflict):

1. **Without `VIRTIO_NET_F_RSS`, the guest cannot control inbound distribution; the queue is decided unilaterally by the host.**
   - vhost-net + tap backends use the Linux kernel tun's automatic flow steering: **learn on egress, look up on ingress**; on a table miss, hash by `txq = ((u64)__skb_get_hash_symmetric(skb) * numqueues) >> 32` (**not fixed to queue 0**); table entries age out with `TUN_FLOW_EXPIRE = 3*HZ`.
   - vhost-user / OVS-DPDK backends instead do "queue bound to a PMD thread" (OVS official doc: single PMD → all traffic into the same vhost queue).
   - Note: the KVM wiki "Multiqueue" claim of "no hash → fixed to the first queue" is a 2012 design draft; **the kernel code wins**.
2. **DPDK takeover does not affect host-side steering** (steering is in the host kernel, unaware of the guest driver). `VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET` is issued automatically by DPDK at `dev_start` (`dpdk-stable-24.11.6/drivers/net/virtio/virtio_ethdev.c:2383-2387` → `virtio_set_multiple_queues_auto()`); no app intervention needed.
   **Strong corollary**: `virtio_cvq.c:197-200` has `virtio_send_command()` return -1 when `!cvq` → `dev_start` fails. Since f-stack's 2-queue **starts successfully**, the cvq exists, `VQ_PAIRS_SET` was successfully issued, QEMU-side `curr_queue_pairs=2`, and `peer_attach()` was done for queue 1 → **"host only enabled 1 queue" is excluded**.
3. **This round's E2 result positively corroborates the above mechanism**: two processes each send from their own queue; the host tun learns the "flow→queue" mapping, inbound aligns accordingly, and both queues run at full load (998k / 1060k).
4. **No public record found of f-stack successfully running multi-queue on virtio** (4 public cases all stop at "virtio lacks RSS → error → degrade to single queue / patch source"). This document's E2/E4 results can serve as the first reproducible evidence for this scenario.
5. **Items with no reliable source found** (honestly marked, not fabricated): a direct DPDK bug report of "only queue 0 receiving packets"; "whether KNI must be disabled" has no source and no conclusion was drawn.

---

## 8. Residual Risks (explicitly recorded, not introduced this round)

### 8.1 SMR / UMA per-CPU Slots Shared Among Multiple Workers

After the R2 fix, all workers' `pc_zpcpu_offset` is 0, so multiple workers **share the same** SMR per-CPU slot. Theoretical window: thread A's `smr_exit` setting `SMR_SEQ_INVALID` could clear thread B's read-section marker → `smr_poll` wrongly concludes no readers → PCB recycled early (UAF). Relevant code: `freebsd/sys/smr.h:106-160`, `freebsd/netinet/in_pcb.c:1820-1888`.

Must be clear:
1. **This risk was not introduced by this round's changes.** Before the fix, non-zero offset → **guaranteed out-of-bounds** (measured SIGSEGV); after the fix it is "legal but shared", a strict improvement.
2. Full elimination requires making the f-stack kernel view SMP-aware (`mp_maxid > 0` + truly allocating per-cpu arrays by thread count), far beyond this round's scope; **recommended as a separate project**.
3. Stress validation: the 60s / 400-connection / 29.83M-request soak observed no UAF symptoms (zero socket errors, zero Non-2xx, process alive), but the static risk window objectively exists.

### 8.2 `cpuid_to_pcpu[0]` and `cpuhead` Overwritten/Chained by Multiple Workers

`pcpu_init()` writes the globals `cpuid_to_pcpu[0]` (array of 1 element) and the `cpuhead` list. Exhaustive verification confirmed **no readers in this build** (all call sites of `pcpu_find()` / `cpuhead` traversal / direct `cpuid_to_pcpu[]` reads are in files not in `lib/Makefile`'s SRCS, or closed by `#ifndef FSTACK`), so there is no actual error. Per the review suggestion, the call was moved into the `init_lock` critical section to eliminate concurrent writes.

### 8.3 `jailed()` Becomes True Under Workers (scope bounded; no TCP/UDP change)

`jailed()` is a macro, not a stubbable function: `freebsd/sys/jail.h:449` `#define jailed(cred) (cred->cr_prison != &prison0)` (the same-named stub in `lib/ff_glue.c:346-352` is entirely inside `#if 0`, not compiled). Therefore per-worker prisons make `jailed()` **true** for worker creds.

The impact scope has been bounded item by item:
- **PCB insert/lookup ordering unaffected**: `in_pcbjailed()` (`freebsd/netinet/in_pcb.c:2743-2746`) goes through `prison_flag()`, and f-stack's stub (`lib/ff_glue.c:286-290`) **ignores cred**, only returning `(flag & PR_HOST) != 0`; call sites pass `PR_IP4`/`PR_IP6`, so it is always false.
- **The only `jailed()` reader in the compiled set is `freebsd/netinet/raw_ip.c:500`** (`in_jail.c` / `in6_jail.c` / `kern_jail.c` / `kern_cpuset.c` are not in `lib/Makefile` SRCS), affecting only raw IP + `IP_HDRINCL` paths, and its `prison_local_ip4` is a stub returning 0 (`lib/ff_glue.c:299-302`).

Conclusion: **no behavioral change to TCP/UDP data plane or PCB hash ordering**. If raw IP functionality is enabled in the future, this path needs re-checking.

### 8.4 CM5-B Existing Concurrency Risk List

Global operations related to worker creds in `ff_init_main.c` such as `uifind(0)`/`crget()` still depend on init-phase serialization; see R1-R5 recorded in docs 13/14. This round did not change their nature.

---

## 9. Change List

| File | Change | Note |
|---|---|---|
| `lib/ff_freebsd_init.c` | add `#include <sys/jail.h>` | `struct prison` definition |
| `lib/ff_freebsd_init.c` | `ff_pcpu_thread_init()`: `pcpu_init(pcpup, cpuid, ...)` → `pcpu_init(pcpup, 0, ...)` | fix R2; no-op for `thread_mode=0` |
| `lib/ff_freebsd_init.c` | add `ff_worker_prison_init()` | fix R1 |
| `lib/ff_freebsd_init.c` | `ff_stack_thread_init()`: `ff_pcpu_thread_init()` moved into `init_lock` critical section; call `ff_worker_prison_init()` after `vnet_alloc()` | ordering constraint + review NIT |
| `lib/ff_dpdk_if.c` | `init_mem_pool()` loop upper bound thread_mode-aware | fix R3 |

**Unchanged**: `lib/ff_veth.c`, `example/main.c`, `lib/ff_api.symlist` byte-identical to HEAD (all temporary probes from the locating phase removed; `grep -rn "DBG\|dbg_" lib/ example/` zero hits).

**Compile**: `lib/` and `example/` both `make clean` then full rebuild, zero errors.

**Review**: independent agent 7 items all PASS, overall verdict **APPROVE_WITH_NITS** (see `_m4_D_review.md`).

---

## 10. Reproduction Steps

```bash
# 2 threads (fix validation)
# config.ini: thread_mode=1, lcore_mask=6
cd /data/workspace/f-stack/lib && make clean && make -j8
cd ../example && make clean && make -j8
setsid nohup ./helloworld --conf ../config.ini > /tmp/run.log 2>&1 < /dev/null &
# warm up with one curl first (refresh client-side ARP), then load test
ssh f-stack-client "curl -s -o /dev/null http://9.134.214.176/"
ssh f-stack-client "/data/wrk/wrk -t5 -c100 -d10s http://9.134.214.176:80/"

# 2-process comparison (E2/E5-c)
# config.ini: thread_mode=0, lcore_mask=6
setsid nohup /data/workspace/f-stack/example/helloworld --conf /tmp/a.ini --proc-type=primary   --proc-id=0 > /tmp/a.log 2>&1 < /dev/null &
setsid nohup /data/workspace/f-stack/example/helloworld --conf /tmp/b.ini --proc-type=secondary --proc-id=1 > /tmp/b.log 2>&1 < /dev/null &
```

Notes:
- Before startup, confirm no residual processes (`pgrep helloworld`; clean via `/data/workspace/kill_process.sh`)
- Must use `setsid` to fully detach from the terminal, otherwise the parent shell exiting takes the process with it
- The client-side ARP cache may point to an old MAC; warm up with one `curl` before load testing
