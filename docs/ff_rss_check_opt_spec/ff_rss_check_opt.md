F-Stack ff_rss_check Optimization in Practice: Three-Layer Acceleration for Client Source-Port Selection, from Static Port Tables to rte_thash Reverse Calculation

1. Purpose and Key Features

Straight to the point: in a multi-queue / multi-process (share-nothing) F-Stack deployment, when a process acts as a client and initiates TCP/UDP connections, it must pick a "smart" local source port — one that makes the connection's return packets (SYN-ACKs, response data) land back in the receive queue of the very process that initiated the connection after NIC RSS hashing. Picking the wrong queue means connections fail to establish or packets "leak" into another process, which is fatal in a multi-process architecture. `ff_rss_check` (`lib/ff_dpdk_if.c`) is the function that does this port selection.

Selecting a port has two constraints: the return packets must land in the local queue (RSS affinity), and the port must be free (4-tuple uniqueness). The original implementation scanned ports one by one with software Toeplitz hash computation, costing hundreds of tsc per connect on average, and with high process counts it could retry dozens of times, becoming the connection-establishment bottleneck for short-connection workloads.

This feature adds three layers of optimization on this port-selection path:

- **Static table fast path** (already upstream in F-Stack, commit e54aa4317; was lost during the 13.0->15.0 upgrade and then ported back): precompute "which local ports land in the local queue for a given remote 4-tuple" and rotate ports by direct table lookup at connect time, eliminating per-port software hashing
- **rte_thash reverse-calculation path** (new in this repo, beyond upstream): when the static table misses, use DPDK's `rte_thash_adjust_tuple()` to reverse-calculate a source port that satisfies the queue constraint directly from the target queue, replacing the per-port software scan

【Note】The thash reverse calculation has a limited candidate port range (only some bits are adjusted), so think twice when the number of concurrent connections and required ports is very large.

- **Full IPv6 chain** (not in upstream either, brand new): extend both paths above to IPv6 (36-byte tuple of 16+16+2+2)

There are also two supporting changes: the post-reverse-calc software recheck was made a runtime switch (off by default, performance first), and deferred port allocation for `bind(addr,0)`-then-connect (aligning with Linux's `IP_BIND_ADDRESS_NO_PORT` semantics + RSS affinity).

One-sentence summary: **layered hot-path degradation, each layer independently usable, zero tolerance for wrong queues**. A static-table hit takes the fastest path; a miss goes through thash reverse calculation; reverse-calculation failure falls back to the software scan. Every layer guarantees the finally selected port is confirmed by independent software computation to land in the local queue (or explicitly accepts slight distribution unevenness per the switch).

2. Main Applicable Scenarios

2.1 Client short connections under multi-process / multi-queue deployment

This is the most typical scenario. The classic F-Stack deployment is 1 primary + N secondaries sharing NIC queues, where each process only receives packets of its own queue. When a process acts as a client (e.g. nginx reverse-proxying to upstreams, gateway active probing) and its chosen source port hashes to a different queue, the return packets land in the wrong process. The shorter the connections and the more frequent the connects, the larger the port-selection overhead share, and the more this feature pays off.

2.2 High-frequency connection establishment in reverse proxies / gateways

nginx_fstack reverse-proxy scenario: clients come in over keep-alive connections, and nginx acts as a client opening short connections to upstreams. Every upstream connection goes through port selection once; the static table hits extremely well for such "relatively fixed remote addresses" (just configure the common upstreams in the rules).

2.3 Multi-queue applications that need precise control of return-packet core affinity

Any application that cares about "return packets landing on the local core" benefits — this is not just about performance; in a multi-process architecture, wrong-queue return packets mean the feature simply does not work.

2.4 Less suitable scenarios

- Pure server-side listen + accept applications (port selection only happens on active connect; pure listening never triggers it)
- Remote addresses that are completely random with no way to preconfigure a static table, plus a very high connection concurrency (static table misses, degrading to thash reverse calculation — whose candidate port range is severely limited, so use with care — or to the software scan; correct but with diminished gains)
- Single-queue deployments (only one queue, so any port "lands in the local queue"; it takes the zero-overhead short-circuit path)

3. Architectural Characteristics

3.1 Three-layer port-selection decision path

On a connect, the kernel-side `in_pcb_lport_dest` (`freebsd/netinet/in_pcb.c`) selects the source port in this order:

```
connect → in_pcb_lport_dest(INPLOOKUP_LPORT_RSS_CHECK)
  │
  ├─ Static table ff_rss_tbl hit?
  │     Yes ─►【Fast path】rotate a port (O(1), no hash computation)
  │             └─ Port occupied → rotate to the next candidate
  │     No  ─►【Dynamic path】
  │             ├─ thash_adjust=1 and ctx ready?
  │             │     Yes ─► rte_thash_adjust_tuple reverse-calculates the source port
  │             │             ├─ recheck=1 → software recomputation confirms the queue → return on pass
  │             │             └─ attempts exhausted / failed → degrade to software scan
  │             └─ No  ─►【Fallback path】per-port software ff_rss_check scan
  │
  └─ Final port → return packets land in the local process queue via NIC RSS
```

The three layers degrade one by one and are independent: the static table is pure lookup (fastest), thash reverse calculation is mathematical inversion (second fastest, hundreds of ns per candidate), and the software scan is full Toeplitz computation (slowest but always correct). A failure in any layer does not affect correctness; it only gets slower.

3.2 Core of reverse calculation: locating the source port by the "return-packet field order"

There is a highly counterintuitive design point here, and it is the cornerstone of thash reverse-calculation correctness.

Toeplitz hashing is asymmetric: `hash(src, dst, sport, dport) != hash(dst, src, dport, sport)`. Outbound packets (local→remote) and return packets (remote→local) land in **different** queues after NIC RSS. Our reverse calculation targets **return packets** landing in the local queue, so the tuple must be constructed in the **return-packet field order**:

```
Outbound: srcIP=local  dstIP=remote  srcPort=local  dstPort=80
Return:   srcIP=remote dstIP=local   srcPort=80     dstPort=local  ← the local port is in the dstPort field!
```

Therefore the reverse-calculation helper must be added at the dstPort field position of the return-packet tuple: for the IPv4 12-byte tuple, the local port is at byte10 = bit80 (not the outbound sport field byte8 = bit64); for the IPv6 36-byte tuple, it is at byte34 = bit272 (not bit256). The code has `FF_RSS_THASH_V4_SPORT_OFF=80` and `FF_RSS_THASH_V6_SPORT_OFF=272` (`lib/ff_dpdk_if.c:176/187`), with comments explicitly explaining this "return-packet dstPort field" rationale.

【Note 1】This design was not right from the start. The earliest implementation reverse-calculated at the outbound sport field (v4 offset=64), which resulted in listen succeeding but connections not working — outbound packets landed correctly but return packets landed in the wrong queue. It only worked end to end after correcting to the dstPort field. See 4.5.

3.3 Three-party key alignment architecture

For thash reverse calculation to work there is a precondition: **the RSS key used for reverse calculation, the key used for software recomputation, and the key actually used by the NIC must be exactly identical**. The architecture guarantees this with two measures:

- `ff_rss_thash_build_key(port_id, reta_size)` (`lib/ff_dpdk_if.c:3459`) serially builds the v4→v6 thash contexts **before** `dev_configure`, publishes the unified key produced (KEY_FINAL) to the global rsskey, which the caller programs into the NIC at dev_configure time — all three parties henceforth share the same key
- secondary processes reuse the same-named ctx created by the primary via `rte_thash_find_existing`, instead of initializing independently (this also fixes the EEXIST error from duplicate ctx initialization in multi-process setups)

4. What Was Changed and What Problems Were Hit

The following gets dry; skip this section if you don't need the implementation details and go straight to section 5 for usage.

4.1 Starting point: the upstream static-table optimization (e54aa4317)

The origin of this mechanism is an official F-Stack optimization (commit e54aa4317, covered in the official wiki and in the WeChat article https://mp.weixin.qq.com/s/x5wWecqEKWGdcVbhne78tw). The core idea is trading space for time: at startup, per configured `(local address, remote address, remote port)` rules, precompute "which local ports hash to the local queue" into `ff_rss_tbl`, then rotate ports by table lookup at connect time, turning "dynamic computation" into "static lookup". Official measurements: ~2-6% QPS improvement in normal scenarios, and up to 36.94% / 38.79% in special scenarios (8/16 processes) — under some process-count configurations the original implementation's random port selection retried far beyond the mathematical expectation (measured 46~60 tries at 8 processes vs a theoretical expectation of 8~12), and table lookup eliminated that overhead entirely.

4.2 Problem 1: the 13.0→15.0 upgrade lost the kernel-side hooks (R-A port-back)

During the FreeBSD 13.0 → 15.0 upgrade, the user-space interfaces (`ff_rss_check`, `ff_rss_tbl_init/set/get_portrange`, etc.) were all kept intact, but **the kernel-side `#ifdef FSTACK` hooks consuming them were not ported** — in 15.0's `in_pcb.c` the `INPLOOKUP_LPORT_RSS_CHECK` macro was reduced to an unused `#define`, the whole RSS port-selection mechanism was effectively dead kernel-side, and it fell back to native random port selection.

Fix (commit 22462f58d): re-port following the 15.0 code structure. 15.0 differs from 13.0 in three adaptation points: `in_pcb_lport_dest`'s parameter became `const struct inpcb *` (the RSS logic only touches local variables); `in_pcbconnect_setup` was merged into `in_pcbconnect` (the `ff_in_pcbladdr` hook point moved accordingly); the lookup series of calls gained the `RT_ALL_FIBS` argument. After porting back, real-machine tests showed: primary/secondary each connected 200 times, 200/200 landing in the local queue.

4.3 Change 2: thash reverse calculation replacing the per-port scan (R-B)

A static-table hit is the fast path, but on a **miss** the per-port software computation still ran. Using DPDK 24.11.6's `rte_thash_adjust_tuple()` reverse calculation turns this O(port-count) scan into direct inversion. The key is translating "lands in the local queue" precisely into the reverse-calculation `desired_value`: this repo's queue-landing check is `((hash & (R-1)) % Q) == queueid`, so `desired = queueid + (rand % ceil(R/Q)) * Q`, making the low bits of the reverse-calculated hash land precisely in the target queue's set. After a successful reverse calculation, **a mandatory software `ff_rss_check` recomputation** verifies the result — zero tolerance for wrong queues; if attempts run out it returns -1 to fall back to the software scan.

4.4 Change 3: the full IPv6 chain (R-C)

The upstream static table is IPv4-only. Following scheme A, brand-new v6-dedicated symbols were added (`ff_rss_check6`, `ff_rss_tbl6_*`, `ff_rss_adjust_sport6`) without touching any v4 structure or signature. Kernel-side, an `AF_INET6` parallel branch was added in the unified `in_pcb_lport_dest` and `in6_pcbladdr` was wired up. The evidence of zero IPv4 regression is rock-solid: in the git diff of R-C vs R-B, `in_pcb.c` is +86/-0 — pure additions, not a single v4 line removed.

4.5 Problem 2: Toeplitz asymmetry — reverse calculation must follow the return-packet field order (c42340d5 / R-G)

After thash reverse calculation landed, a strange symptom appeared on physical machines: listen succeeded but connections failed, with IPv4 normal and IPv6 broken (later confirmed both versions had this trap; v4 was fixed first, then v6 symmetrically). The root cause is the Toeplitz asymmetry from 3.2: the initial implementation reverse-calculated at the **outbound packet's** sport field position (v4 offset=64, v6 offset=256), so outbound packets landed in the right queue but **return SYN-ACKs landed in the wrong queue**, and the handshake of course never completed.

Fix (IPv4 commit c42340d5, IPv6 symmetric port R-G): move the helper offset to the **return-packet dstPort field position** — v4 64→80, v6 256→272, fill the tuple in return-packet field order, and call `ff_rss_check` for verification in return-packet field order as well. After the fix, physical-machine end-to-end verification showed: v6 multi-queue active connects had 100% of return packets landing in the local process queue with 0 misqueues, and IPv4 had zero regression.

4.6 Problem 3: add_helper rewriting the key causing three-party key mismatch (R-F)

After fixing the offset, unit tests revealed a subtler problem: the "per-candidate equivalence rate" of thash reverse calculation was only ~22-27% (meaning reverse-calculated ports mostly failed the software recomputation and needed 3~6 retries). Tracing it down, the root cause turned out to be `rte_thash_add_helper` using an LFSR to **rewrite ctx->hash_key in place** — so `rte_thash_adjust_tuple` reverse-calculated with the rewritten key while `ff_rss_check` software computation and the NIC hardware used the original key; the three parties had different keys and that 22-27% was pure coincidence.

Fix: `ff_rss_thash_build_key` serially builds the contexts before dev_configure, publishes the unified KEY_FINAL to the global rsskey and programs it into the NIC; with the three parties aligned the equivalence rate should reach ~100%.

4.7 Change 4: recheck recomputation off by default (R-D)

Once the three-party keys were aligned, confidence in the reverse-calculated results went up, and the "mandatory software recomputation after successful reverse calculation" safety net became pure overhead — microbench measured a single `ff_rss_check` recomputation at about 99.4 ns/call, while the recheck=0 hot path needs only ~0.31 ns/call, a difference of about 300x; converted to per-connection (average 3.9 adjust calls) it saves about 390 ns, and the v6 reta=512 long-tail scenario saves about 2 us per connection.

So the recomputation was made a runtime switch `recheck` (`config.ini` `[rss_check]` section), **0 by default (performance first)**, with 1 available for debug/ops to keep the zero-tolerance hard gate. The failure fallback chain (attempts exhausted → software scan) is unaffected.

4.8 Change 5: deferred port allocation for bind-then-connect (R-E)

There was one more path left uncovered: applications that first `bind(local_addr, 0)` and then `connect(remote)`. Native FreeBSD allocates an anonymous port at bind time; at connect time it finds "a port already exists" and bypasses the RSS port-selection logic, so the selected port does not land in the local queue. This aligns exactly with Linux's `IP_BIND_ADDRESS_NO_PORT` semantics — defer port allocation to connect time based on the full 4-tuple.

Fix (commit ff9e3c449, +16/-1, fully macro-gated): v4's `in_pcbbind` hash-insertion block got an `lport != 0` gate, and `in_pcbbind_setup`'s port allocation got an `#ifndef FSTACK` gate; v6 was changed symmetrically. Not fixing the port at bind time → connect naturally enters the RSS port-selection branch. There is also an interesting trap: nginx first calls `setsockopt(IP_BIND_ADDRESS_NO_PORT)`, and this option's Linux value 24 happens to collide with FreeBSD's `IP_BINDANY`=24 — v4 was silently misconfigured into transparent proxy mode and v6 got EINVAL outright. Intercepting it at the syscall translation layer (commit a2537e143) fully resolved it.

4.9 Test and verification status

- Unit tests: 39 run / 36 PASSED / 3 SKIPPED (the 3 SKIPPED are the existing degradation where DPDK EAL cannot init in the unit-test environment); the v4/v6 full-loop 100% queue-landing hard assertions all pass
- Real machine (R-A software-scan path): primary/secondary each 200 connects, 200/200 landing in the local queue
- Physical machine (v6 reverse path): end-to-end pass on a NIC with real v6 RSS capability, 0 misqueues
- Local virtio `reta_size=0`: the thash ctx cannot initialize, so on the real machine it takes the software-scan degradation path (which conveniently validates the degradation chain); the thash path's correctness is fully covered by the unit-test reta=128/512 suites

5. How to Use, Configure, and What Results to Expect

5.1 Configuration

The `[rss_check]` section of config.ini (example):

```ini
[rss_check]
# Master switch: 1=enable static RSS table port selection, 0=off (default)
enable=1
# Debug switch: 1=mandatory software recomputation after successful thash reverse calculation (default 0, performance first)
recheck=0
# thash reverse-calculation switch (decoupled from the static RSS table enable): 1=enable reverse calculation in multi-queue (default), 0=software scan only
thash_adjust=1
# Static table rules: <NIC port ID> <local address> <remote address> <remote port>, multiple rules separated by semicolons
rss_tbl=0 192.168.1.1 192.168.2.1 80;0 192.168.1.1 192.168.2.1 443
```

It is recommended to configure the common upstreams (remote address + port) in the static table rules — the higher the hit rate, the larger the gains. The same saddr/sport pair supports at most 16 entries and at most 4 daddrs per group; configurations beyond that are ignored.

5.2 Results

Static-table path (official measurements, from the e54aa4317 era):

| lcores | Original dynamic QPS | Static-table QPS | Improvement |
|--------|-------------:|-----------:|------:|
| 1 | 38,093 | 38,456 | +0.95% |
| 2 | 73,566 | 75,009 | +1.96% |
| 4 | 139,205 | 142,325 | +2.24% |
| 6 | 196,471 | 202,068 | +2.85% |
| 8 | 201,823 | 276,368 | +36.94% |
| 12 | 371,362 | 394,151 | +6.14% |
| 16 | 398,376 | 552,894 | +38.79% |

2~6% in normal scenarios, and 35%+ in the 8/16-process scenarios where the original implementation's random retries exploded.

thash reverse-calculation path (measured in this repo):

- recheck=0 hot path ~0.31 ns/call vs ~99.5 ns/call with recheck=1 (microbench, about 300x difference)
- Saves about 390 ns per connection (v4), and about 2 us per connection in the v6 reta=512 long tail
- 100% full-loop queue landing (unit-test hard assertions); zero tolerance for wrong queues is guarded by the software recomputation under recheck=1

5.3 Notes

- The static table and thash reverse calculation are "acceleration layers"; final correctness is guaranteed by the software-scan fallback chain. A failure in any layer degrades automatically — no manual intervention needed.
- ~~With recheck=0 (default), RSS distribution may be slightly uneven (some connections' return packets may land outside the local queue), but TCP/UDP connection correctness is unaffected (ports remain unique, 4-tuples remain valid, and the kernel locates the PCB by 4-tuple); enable recheck=1 for scenarios requiring zero tolerance for wrong queues.~~
- In environments without RSS support (e.g. the local virtio NIC), reta_size=0 and the thash reverse calculation automatically degrades to the software scan on the real machine — this is by design, not a bug.

Further reading:

- Spec: docs/ff_rss_check_opt_spec/zh_cn/ (00-10 + plan, full design and verification of the five requirements 0.1~0.5)
- Official initial blog article: https://mp.weixin.qq.com/s/x5wWecqEKWGdcVbhne78tw
- Official wiki: ff_rss_check() Optimization (corresponding commit e54aa4317)
- DPDK Toeplitz Hash Library: https://doc.dpdk.org/guides/prog_guide/toeplitz_hash_lib.html
- Three-layer architecture docs: docs/zh_cn/01-LAYER1-ARCHITECTURE.md (the ff_dpdk_if.c section)
