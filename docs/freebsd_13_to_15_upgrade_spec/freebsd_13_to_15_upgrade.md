F-Stack 2.0 Preview: Upgrading the FreeBSD Protocol Stack from 13.0 to 15.0 — Trimming and Redoing Across 6 Releases

1. What this project does and its key characteristics

Let's get straight to the point: F-Stack strips the FreeBSD kernel protocol stack out of the kernel and runs it in DPDK user space. The protocol stack is not written from scratch — it is a trimmed subset of the upstream FreeBSD source. F-Stack v1.25 is aligned with FreeBSD 13.0-RELEASE-p2, while FreeBSD 15.0-RELEASE was officially released in 2025. In between lie 6 releases (14.0/14.1/14.2/14.3/14.4, roughly 4 years of evolution). What F-Stack 2.0 sets out to do is to lift this "trimmed subset" from the 13.0 baseline onto the 15.0 baseline.

Why the upgrade is a must, in one sentence: staying on 13.0 means missing upstream security fixes, performance improvements (TCP stack evolution), and new driver support — and drifting further away from the community. The hard part of this upgrade: between 13 and 15 the networking core went through multiple P0-level KBI/KPI breaking changes. **This cannot be fixed by applying patches — the F-Stack trim + adapt approach must be redone from scratch on the 15.0 source.**

Key characteristics (the three keywords of this upgrade):

- **Trim and redo**: the `freebsd/` subtree of F-Stack is a curated subset of upstream `sys/` (25 top-level directories, 18000+ files). Upgrading means redoing the "trim + FSTACK adaptation" work on the 15.0 source, not porting diffs.
- **Layered milestones**: M1 infrastructure → M2 kern → M3 network stack → M4 glue-layer ABI → M5 full acceptance. Each milestone ends with a build gate and a bounce-back chain, advancing like a snowball.
- **Functional parity alignment**: this upgrade is "alignment only, no feature expansion" — new 15.0 capabilities (netlink, ML-KEM post-quantum crypto, etc.) are explicitly out of scope, so that post-upgrade behavior stays equivalent and comparable to the 13.0 baseline.

Some measured numbers to size up the effort: 102 file diffs in the `freebsd/` subtree (~50 files with substantial rework), 163 in `tools/`, 44 `ff_*.c/.h` glue files in `lib/`. The whole project ran from 2026-05-26 to 06-09: 26 commits, 47 spec documents, a 5-cell build matrix all green, and all 9 functional acceptance tests passed.

2. Main applicable scenarios

2.1 Production deployments that need upstream security fixes and ongoing evolution

This is the primary scenario. FreeBSD 13.0 has a limited security support window; security fixes and performance patches for the protocol stack keep landing in 14.x/15.0. Long-term production maintenance requires keeping up. After the upgrade, F-Stack 2.0 is aligned with 15.0-RELEASE-p9, with `__FreeBSD_version` moving from 1300139 to 1500068.

2.2 Environments that need new hardware / new driver support

The 15.0 driver stack and DPDK compatibility surface are much broader than in the 13.0 era. Although F-Stack's DPDK-side drivers come from DPDK itself, the protocol stack's support for NIC offload, TSO/LRO, RACK and other capabilities has evolved in 15.0.

2.3 Multi-process / multi-queue production deployments (the key validation surface after the upgrade)

The upgrade project ran full acceptance on the classic 1 primary + N secondary deployment: a build matrix (default/FF_IPFW/FF_NETGRAPH/FF_USE_PAGE_ARRAY/FF_KNI), 9 runtime functional acceptance tests, and 13.0 vs 15.0 dual-baseline performance comparison — all backed by data.

2.4 Scenarios that are not a good fit

- Just wanting to try 15.0 new features (netlink, post-quantum crypto, etc.) — this upgrade is explicitly "alignment only, no expansion"; those capabilities are out of scope.
- Scenarios depending on the mips architecture — mips was removed entirely in FreeBSD 14.0, and the upgrade must accept that.
- Expecting a big performance boost after the upgrade — the measured 13.0 vs 15.0 result is flat-to-slightly-down (see 4.6/5.2). The payoff of the upgrade is security and evolutionary sustainability, not performance.

3. Architectural characteristics

3.1 F-Stack's "trim + adapt" model

To understand this upgrade, start with how F-Stack organizes its source. F-Stack does not move the whole of FreeBSD into user space; instead:

```
FreeBSD sys/ full source (13.0: includes mips; 15.0: includes netlink)
   │
   │  trim: keep only the protocol-stack-related subset
   │    kern / net / netinet / netinet6 / netipsec / netgraph / vm /
   │    libkern / opencrypto / amd64 / x86 / arm64 / ...
   ▼
f-stack/freebsd/ (25 top-level directories, 18000+ files)
   │
   │  FSTACK adaptation (9 techniques)
   │    FSTACK-stub: short-circuit host-coupled functions with #ifndef FSTACK
   │    FSTACK-altimpl: alternative implementations under #ifdef FSTACK
   │    IPC-replace: ff_ipc_* replacing raw socket/sysctl
   │    Glue files: ff_*.c/.h (44 files) replacing VFS/process/signal etc.
   ▼
libfstack.a (user-space protocol stack library) + DPDK NIC I/O
```

The essence of the upgrade: this layer of "trim + adapt" done on the 13.0 baseline must be **redone** on the 15.0 baseline — because the networking core KBI/KPI is no longer compatible in many places between 13 and 15. Applying 13.0 patches directly onto 15.0 is simply impossible.

3.2 The 13→15 core KBI/KPI breaking-change checklist

This is the "minefield map" of the upgrade, the backbone of the project-wide risk list:

| Change | 13.0 | 15.0 | Impact on F-Stack |
|------|------|------|-------------------|
| pr_usrreqs merge | standalone `struct pr_usrreqs` vector table | merged into `struct protosw` | P0: all protocol registration code rewritten |
| inpcb concurrency protection | epoch | SMR | P0: inpcb lifecycle rework |
| if_t opaqueness | kernel API exposes `struct ifnet *` | `if_t` + `if_get*/if_set*` accessors | P0: all direct field accesses must change |
| mbuf layout | old m_pkthdr/m_ext layout | field adjustments | P0: all offset dependencies broken |
| routing subsystem | traditional route | fib_algo/rib rewrite + netlink added | P0: rib/nexthop rewrite is the single biggest risk |
| mips architecture | present (586 files) | removed entirely in 14.0 | P0 task: subtree and Makefile branch cleanup |
| TCP stack | single tcp_output | stacks framework vtable + RACK/BBR selectable stacks (15.0 default stack is still freebsd default; RACK is more mature but not enabled by default) | P0: TCP path adaptation |
| toolchain | clang/llvm 11 | clang/llvm 19 (requires GCC ≥ 9) | P1: C11 _Atomic dependency |
| syscall table | SYS_MAXSYSCALL=580 | 599 (+22/-3) | P3: compat shim handling |

3.3 Layered milestone model

The upgrade was not done all at once. It was split into 5 milestones by dependency, each ending with a build gate that bounces failures back:

```
M1 infrastructure: mips cleanup + header baseline + cp -a for libkern/opencrypto etc.
   │  G-M1: build matrix default cell passes
   ▼
M2 kern: 10 kern files applied with the 5-step method (subr_*.c, kern_*.c)
   │  G-M2: KERN_SRCS builds
   ▼
M3 network stack: netinet/netinet6 on 4 parallel tracks
   │  G-M3: libff.a full build + TCP/UDP echo up
   ▼
M4 glue layer: lib/ff_*.c adapted to the 15.0 ABI (R-013/R-004)
   │  G-M4: full build matrix + 4 TCs
   ▼
M5 full acceptance: 9 TC functional tests + performance baseline + reviewer sign-off
   │  G-M5/G-Acceptance
   ▼
Phase-2 capability enablement (M6-M13): FF_NETGRAPH/FF_IPFW/PA/ZC and other config switches
```

4. What was reworked and what problems were hit

The rest is a bit dry; skip this section if you don't need the implementation details and jump straight to Section 5.

4.1 Starting point: dual-version source baselines and a diff plan

The first step of the upgrade was not writing code — it was laying out three source roots (measured versions: 13.0 = RELEASE-p2, 15.0 = RELEASE-p9): the community 13.0 full source, the community 15.0 full source, and the F-Stack tree (adapted from 13.0). Then an untouched 15.0 f-stack-lib baseline was created, and file-by-file diffs produced the map of "what FSTACK customization done on 13.0 must be redone at the corresponding spot on the 15.0 baseline". This diff plan directly determined the project's scale estimate: 102 + 163 + 44 files to rework.

4.2 M1~M3: the trim-and-redo snowball

M1 took care of the fundamentals: cleaning up the 586-file mips subtree (15.0 has already removed that architecture — without cleanup the build chain breaks outright), cp -a for libkern/opencrypto/vm and other subdirectories on the 15.0 baseline, and header baseline alignment.

M2 used a "5-step method" to apply 10 kern files one by one onto the 15.0 baseline: read the FSTACK adaptation on 13.0 → redo it on the corresponding 15.0 file → build verification → bounce-back fixes → gate. M3 was the heavy part: netinet/netinet6 advanced on 4 parallel tracks (SMR-ification of in_pcb/in_pcbgroup, the pr_usrreqs→protosw merge, the tcp stacks framework, and the routing subsystem rib/nexthop rewrite).

[Note 1] The fib_algo/rib rewrite of the routing subsystem was the single biggest risk of the entire upgrade — FreeBSD 14/15 replaced the traditional routing table implementation outright. In M5 acceptance, TC-08 (ff_route add + ff_route get) specifically targeted this area, and it only passed once the fib4_lookup symbol was confirmed to be properly defined in libfstack.a.

4.3 Problem 1: helloworld startup hang (runtime-fix phase)

After M5 acceptance passed, bringing up helloworld on a physical machine hung right after "Port 0 Link Up", with 4 threads spinning in R+ state. gdb attach produced the full stack: an infinite loop in `uma_small_alloc → zone_import → zone_alloc_item → zone_ctor → uma_startup1`.

The root cause turned out to be a classic "rename not followed through" pitfall: FreeBSD 14.0 renamed the UMA_MD_SMALL_ALLOC macro to UMA_USE_DMAP. On the 13.0 baseline F-Stack had this macro wrapped in `#ifndef FSTACK` (user space does not use DMAP direct mapping), but the wrapper was lost during the upgrade. The consequence: the uma keg took the uma_small_alloc path → vm_page_alloc_noobj_domain is a stub returning NULL → keg_fetch_slab spins forever on M_WAITOK waiting for memory that never comes.

The same phase also unearthed two sibling problems from the same root: smr_create's atomic barrier took the kernel %gs path and SEGV'd in user space, and rtbridge's rtsock/netlink callback stub was NULL and got dereferenced by rt_ifmsg. The fix principle was "one root cause, one commit": 3 root causes, 3 commits, plus one panic defensive hardening.

[Note 2] This pitfall deserves a special record: it shows that "macro renames" — seemingly harmless upstream evolution — are fatal to trim-based derived projects. Every #ifdef wrapper that derived code places around an upstream symbol must be checked one by one during an upgrade.

4.4 Problem 2: ABI skew from a header change without a clean rebuild

This was a build-hygiene pitfall hit in the M3 phase, sharing the same origin as the kernel_coexist field of the kernel-stack coexistence feature (FF_KERNEL_COEXIST): adding a field to a struct changed the offsets of the following members, but the Makefile did not track header dependencies, so incremental builds mixed .o files with old and new layouts — and at runtime fclose segfaulted outright. The lesson was written into the mandatory rules: any struct header change must be followed by a full `make clean` rebuild. From late M3 onwards, the upgrade project turned "make clean && make on every fix" into a hard pipeline rule.

4.5 Problem 3: attributing the 9% performance gap (13.0 vs 15.0 dual baselines)

The performance baseline comparison produced a number that had to be accounted for: in the helloworld scenario, 15.0 throughput was 7.59% (T2 t4c100) to 9.37% (T3 t8c500) lower than 13.0, and p99 tail latency degraded by 27.8% (T3). This could not be hand-waved away, so the project did a root-cause analysis:

| Culprit (13→15 vendor evolution) | Share |
|--------------------------|------|
| TCP stacks framework vtable dispatch (tcp_output → tcp_default_output) | main factor ~+1% |
| TCP CUBIC congestion-control state machine extension | ~+0.6% |
| socket buffer locking rework | ~+1.5% |

Conclusion: the 9% gap is not a regression introduced by the upgrade rework — it is the evolution cost of FreeBSD 15.0 upstream itself (in exchange for capabilities such as the RACK/BBR stack framework). Under real workloads like nginx/redis, the gap narrows to roughly flat.

4.6 Phase-2: re-enabling 15.0 capabilities

After the main upgrade, Phase-2 re-validated and re-enabled F-Stack's compile-time config switches on the 15.0 baseline: FF_NETGRAPH (41 netgraph nodes) + FF_IPFW (14 kernel objects, a 25MB ipfw user-space binary), FF_USE_PAGE_ARRAY (one-shot 256MB mmap), FF_ZC_SEND (zero-copy send), the PA+ZC combination, FF_FLOW_IPIP (GIF tunnel graceful degradation), and the FF_FLOW_ISOLATE/FF_FDIR/FF_LOOPBACK_SUPPORT smoke-test trio. Each switch got its own milestone with one build + runtime verification.

FF_USE_PAGE_ARRAY alone even triggered a panic (F-A1); after the fix changed it to a soft drop, all four production configs C0/C7/C8/C9 became production-ready.

4.7 Leftover follow-ups

At project closure, 13 follow-up items were archived, none of which block delivery: 5 vlan test items (vlan_filter_id hardware offload etc.), physical-machine verification of the FDIR capacity limit, English translation of the spec series, etc. The English spec translation is, per plan, "deferred until after manual review".

5. How to use it, how to configure it, and the results

5.1 Usage (for F-Stack users)

The upgrade replaces the "protocol stack foundation", but **usage is completely unchanged**: still `cd f-stack/lib && make clean && make` to build libfstack.a, config.ini unchanged, ff_* APIs unchanged. That is the delivery promise of "functional parity alignment" — transparent to upper-layer applications.

The compile-time config switch validation matrix on the 15.0 baseline (5 cells all PASS):

| Config | Description | libfstack.a |
|------|------|-------------|
| default | x86_64 default KNOB | 5.2M / 193 .o |
| FF_IPFW=1 | ipfw firewall | 5.5M / 206 .o |
| FF_NETGRAPH=1 | netgraph framework | 5.9M / 250 .o |
| FF_USE_PAGE_ARRAY=1 | page array memory | 5.2M / 207 .o |
| FF_KNI=1 | KNI interface | 5.2M / 207 .o |

5.2 Results

Functional acceptance (9 TCs all PASS): TCP/UDP echo (v4/v6), ff_ifconfig, ff_netstat, ff_ipfw, ff_route add/get (rib rewrite regression), ff_ngctl — all built and brought up successfully. Physical-machine dual baselines (same hardware, same-minute A/B comparison):

| Scenario | 13.0 req/s | 15.0 req/s | Δ throughput | Δ p99 |
|------|-----------:|-----------:|-------:|------:|
| T1 t2c10 | 24,414 | 23,757 | −2.69% | +39.7% |
| T2 t4c100 | 220,691 | 203,933 | −7.59% | +2.0% |
| T3 t8c500 | 239,555 | 217,100 | −9.37% | +27.8% |

Under the helloworld micro-benchmark, 15.0 has a 7~9% throughput gap (root cause in 4.5 — upstream evolution cost, not a regression); under real nginx/redis workloads it is roughly flat. Phase-5b matrix conclusion: all four production configs C0/C7/C8/C9 are production-ready, with C8 (ZC-only) recommended as the production default.

5.3 Value for upgraders / secondary developers

If you plan a similar major-version jump, the parts of this spec worth reading: the milestone layering + build gate + bounce-back chain organization (cumulative bounces 0~3, never triggering a pause), the "trim + adapt" technique catalog (FSTACK-stub/altimpl/IPC-replace and 6 others, 9 in total), the P0 risk list with the two-dimension priority convention (risk level and task priority tracked separately), and the three real-world pitfalls (macro rename losing a wrapper, struct-header ABI skew, performance gap attribution).

Further reading:

- Project closure overview: docs/freebsd_13_to_15_upgrade_spec/00-project-closure.md
- Change list: docs/freebsd_13_to_15_upgrade_spec/03-freebsd-15-changes.md
- Startup hang debugging: docs/freebsd_13_to_15_upgrade_spec/runtime-fix-execution-log.md
- Dual-baseline performance: docs/freebsd_13_to_15_upgrade_spec/13.0-baseline-cvm-bench-report.md
- Three-layer architecture docs: docs/01-LAYER1-ARCHITECTURE.md
- Knowledge graph: docs/KNOWLEDGE_GRAPH_WIKI.md
