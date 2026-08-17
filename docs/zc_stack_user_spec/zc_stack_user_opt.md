F-Stack 2.0 Preview 8: The User-Space Zero-Copy Stack — From the MAGIC Sentinel Hack to FreeBSD's Native Symmetric sosend Architecture

1. What this feature does and its key characteristics

Let's get straight to the point: F-Stack has long had a "last mile" memory-copy problem between user space and the protocol stack. This article walks through the evolution of zero-copy from 2018 to 2026 — in the early days only the receive direction was naturally zero-copy, a hacked send-side scheme arrived in 2022, and in June 2026 everything finally converged into a complete, fully symmetric, purely native user-space zero-copy stack.

First, where the copies happen. Packet processing on a server has two directions:

- **Receive direction**: NIC → DPDK hugepage is DMA, naturally zero-copy; but the application's `ff_read()` copies data from the protocol-stack mbuf into the user buffer (confirmed by the maintainers in issue #407 — by design).
- **Send direction**: two copies — data is copied from the application layer into the FreeBSD protocol stack when the application calls the socket send API (app → stack), and the protocol stack copies data into the DPDK rte_mbuf (stack → NIC).

Before June 2026, F-Stack's zero-copy landscape looked like this: the receive-direction zero-copy (FF_ZC_RECV) existed only as empty interfaces with no actual implementation — the real receive-side zero-copy was implemented via FreeBSD's native interface on 2026-06-11 (commit b87f5f0d2); the send-direction zero-copy (FF_ZC_SEND) used the FSTACK_ZC_MAGIC sentinel + m_uiotombuf kernel-hack workaround — it worked, but carried GPF risk, crashes on large payloads, and high maintenance cost on FreeBSD upgrades. The native rewrite on 2026-06-12 (commit b6ce5884c) moved the send direction onto FreeBSD 15.0's native `sosend(top)` path, completing a fully symmetric bidirectional zero-copy stack. The three keywords of this article:

- **Bidirectional symmetry**: ZC-send (`kern_zc_sendit` + sosend top) and ZC-recv (`kern_zc_recvit` + soreceive mp0) mirror each other across five dimensions — kernel entry, user-space API, lifecycle, error paths, and ABI delta.
- **Purely native**: directly reuses FreeBSD 15.0 upstream capability — the `sosend(9)` man page literally says "Data may be sent as an mbuf chain via top, avoiding a data copy"; F-Stack only added one entry point to pass top through to sosend.
- **Hack removal**: all 17 touchpoints of the FSTACK_ZC_MAGIC sentinel + m_uiotombuf hack were removed, m_uiotombuf reverted to the vanilla 15.0 version, and the kernel patch went from "5 hacked sites" to "1 new function only".

Scale numbers: 30+ spec documents (numbered 00-50, spanning three batches: feasibility research, the first ZC-recv spec, and the native ZC-send spec); ZC-recv landed with 4 changes, the ZC-send native rewrite with 10 changes (2 NEW + 3 MODIFY + 5 DELETE); single-core A/B measurements across three wrk tiers were all flat within noise.

2. Main applicable scenarios

2.1 Large-block data send/receive

This is where zero-copy pays off most concretely. The M2 measurements already proved: under small-packet echo (256B request / 438B reply), ZC is flat against ordinary read/write — the `uiomove` copy cost of a small request is negligible relative to TCP processing + syscall + scheduling, and since f-stack uses UIO_SYSSPACE, uiomove is already a same-address-space memcpy, i.e. cheap. The real payoff is at 4KB/64KB/1MB payload sizes: large file downloads, large body POSTs, block-storage workloads.

2.2 Proxy forwarding (receive-then-forward)

Forwarding applications (proxies, gateways) receive data and send it out as-is. The traditional path copies into the user buffer on recv and copies back into the protocol stack on send — two copies; on the ZC path, recv hands over the mbuf chain and send delivers the mbuf chain directly — zero copies end to end. This is explicitly flagged in the spec as the priority payoff scenario.

2.3 Relationship with FF_USE_PAGE_ARRAY (needs clarifying)

FF_USE_PAGE_ARRAY is the "protocol stack → DPDK" direction zero-copy contributed by PR #364 in 2020 (mmap + mlock + virt2phy lookup) — a different copy segment from the application-layer zero-copy in this article. It remains experimental to this day: the issue archive confirms it silently drops packets under i40e and the maintainers do not recommend enabling it; Phase-2 measurements even hit a panic (F-A1, since fixed as a soft drop). The three switches are fully independent and combinable.

2.4 Scenarios that are not a good fit

- Small-packet echo workloads: measured zero gain; enabling it only adds API complexity.
- Fast-iteration environments relying on incremental builds: switching FF_ZC_* switches requires make clean, otherwise you hit the M2 http=000 pitfall (see 4.3).
- Expecting doubled performance: the official WeChat article in 2022 already said the improvement "may not be obvious — around 2-3%". Zero-copy saves the memcpy, not the protocol-stack overhead itself.

3. Architectural characteristics

3.1 Three send paths compared (core diagram)

```
【Traditional copy path】
APP buffer ──ff_write──► uiomove copy ──► m_getm2 allocates mbuf ──► stack
(one allocation + one copy)

【Old MAGIC hack path (2026-06-08 ~ 06-12)】
APP: ff_zc_mbuf_get/write build the mbuf chain
        │  ff_zc_send disguises the mbuf chain as char* (iov_base)
        │  and injects uio_offset = FSTACK_ZC_MAGIC (0xF8AC2C00F8AC2C00)
        ▼
kern_writev → dofilewrite (guard: overwrite offset only when not MAGIC)
        ▼
m_uiotombuf (consumer: detects MAGIC → reinterprets iov_base as an mbuf chain, skips copy)
        ↓ 5 kernel hack sites; ordinary ff_write must explicitly opt out

【New native path (2026-06-12 onward)】
APP: ff_zc_mbuf_get(M_PKTHDR) → ff_zc_mbuf_write(maintains pkthdr.len)
        │  ff_zc_send(fd, top, n) —— top is the mbuf chain
        ▼
kern_zc_sendit (new, the only kernel change)
        │  sosend(so, NULL, NULL, top, NULL, flags, td)
        ▼
sosend_generic: the uio==NULL branch
        │  resid = top->m_pkthdr.len
        │  delivers top directly, skipping m_uiotombuf entirely
```

The new scheme has no magic, no uio_offset pass-through, and no opt-out needed for ff_write/ff_writev. The entire sosend region was verified by measurement to contain zero FSTACK_* macros — this is native FreeBSD upstream capability.

3.2 The receive-direction symmetric structure

```
Traditional receive: soreceive → uiomove copy into user buffer
ZC receive: kern_zc_recvit (new entry, passes through soreceive's mp0 out-param)
        → ff_zc_recv(fd, &zm, nbytes)
        → ff_zc_mbuf_segment reads segment by segment
        → ff_zc_recv_free must free after use
```

3.3 Bidirectional symmetry table (five-dimension mirror)

| Dimension | ZC-recv (landed) | ZC-send (after the native rewrite) |
|---|---|---|
| Kernel entry | `kern_zc_recvit` → `soreceive(mp0)` | `kern_zc_sendit` → `sosend(top)` |
| Native mechanism | soreceive's `mp0!=NULL` branch | sosend's `uio==NULL && top!=NULL` branch |
| Length source | `uio->uio_resid` | `top->m_pkthdr.len` |
| Bypassed point | uiomove copy | m_uiotombuf allocation + copy |
| User-space API | `ff_zc_recv` / `ff_zc_mbuf_segment` / `ff_zc_recv_free` | `ff_zc_send` / `ff_zc_mbuf_get` / `ff_zc_mbuf_write` |
| ABI delta | +3 symbols | 0 symbols (implementation only) |

Both sides share the same `struct ff_zc_mbuf` (four fields: bsd_mbuf/bsd_mbuf_off/off/len), with field semantics reused symmetrically.

4. What was reworked and what problems were hit

The rest is a bit dry; skip this section if you don't need the implementation details and jump straight to Section 5.

4.1 Early schemes reviewed (2018~2022, the differences from the earliest docs to today)

The 2018 baseline (issue #407): the receive direction was zero-copy from NIC to hugepage, but `ff_read()` had a copy; the send direction "was a copy".

PR #364 in 2020 (@jinhao2) added the first segment: FF_USE_PAGE_ARRAY, zero-copy in the protocol-stack → DPDK direction. The idea: mmap 256MB at init (memsz_MB configurable) + mlock the physical memory, maintain a virtual→physical page table, and when a stack mbuf data address falls inside the pool, fill the physical address directly into rte_mbuf's buf_addr/buf_physaddr — no copy; a circular queue with length equal to the NIC's tx_queue_length guarantees safe release. The scheme is transparent to applications, but works for ixgbe while silently dropping packets under i40e — to this day the official position is "an experimental feature never formally enabled".

2022-04-15 (commit e12886c/021aaded) added the second segment: FF_ZC_SEND, zero-copy in the app → stack direction. `ff_zc_mbuf_get()` allocates an mbuf chain via m_getm2 as the application buffer, `ff_zc_mbuf_write()` writes directly into the mbuf, and `ff_write(fd, zc_buf.bsd_mbuf, len)` adopts the passed-in mbuf chain inside m_uiotombuf, skipping the copy. The companion WeChat article "F-Stack send zero-copy introduction" stated honestly: the expected performance gain is about 2-3%, "to be verified against real scenarios".

4.2 M8 re-enablement: the FSTACK_ZC_MAGIC sentinel scheme (2026-06-08)

Phase-2 of the FreeBSD 13→15 upgrade re-enabled FF_ZC_SEND on the 15.0 baseline (commit add33a04a). The 13.0-era direct pass-through changed shape under 15.0 and landed as the sentinel scheme: `ff_zc_send` disguises the mbuf chain as char* inside iov_base while injecting the magic number `0xF8AC2C00F8AC2C00` into `uio->uio_offset`; a guard is added in dofilewrite (overwrite the offset only when it is not magic); a consumer point is added in m_uiotombuf (on detecting magic, reinterpret iov_base as an mbuf chain). Five kernel hack sites in total, and ordinary ff_write/ff_writev must explicitly opt out with `uio_offset=0` to avoid colliding with the magic.

The scheme carried three burdens from day one: the M8 phase once GPF'd outright due to a missing opt-out (RCA at ff_syscall_wrapper.c:1146); issue #712 (open since 2022-11-01) has no solution for crash/hang on large-payload sends; and every FreeBSD upgrade requires re-auditing the ~120 lines around m_uiotombuf.

4.3 Problem 1: the incremental-build trap, http=000 (the M2 lesson)

During the M2 measurement for ZC-recv on 2026-06-11, the first round of curl returned http=000 across the board — initially misdiagnosed as an environment problem. Real debugging pinned the culprit: a flag-less baseline build was done first, then `FF_ZC_SEND=1 make`; uipc_mbuf.c was unchanged and its .o was newer than the .c, so make skipped recompiling it by timestamp — the MAGIC consumer hook in m_uiotombuf was missing (objdump verified the magic was absent from uipc_mbuf.o). Consequence: ff_zc_send set the magic but the kernel hook did not recognize it; the mbuf chain pointer was treated as a char buffer and the reply was corrupted. After deleting the stale .o and rebuilding, http=200 passed across the board.

[Note 1] This pitfall has since become a mandatory rule: after switching FF_ZC_* and similar compile flags you must make clean or delete the affected .o files — make is timestamp-based and does not perceive CFLAGS changes. This is also the inherent fragility of the sentinel scheme — the more hack sites there are, the larger the stale-.o combination explosion surface.

4.4 ZC-recv lands and the research pivot (2026-06-11)

ZC-recv landed the same day (commit b87f5f0d2, M0+M1): the new `kern_zc_recvit` passes through soreceive's native `mp0` out-param, with three new user-space APIs: ff_zc_recv/ff_zc_mbuf_segment/ff_zc_recv_free. It only adds, never hacks — soreceive's core is untouched. M2 measurements (single-core A/B, three wrk tiers): T1 −1.1%, T2 ≈ +3%, T3 −1.0% — flat against ff_read under small-packet echo (within noise). The honest conclusion: the payoff lies in large-payload scenarios; an echo workload cannot show it.

More importantly, while doing ZC-recv, the send side was investigated along the way: FreeBSD 15.0's `sosend()` signature has always carried a `top` (mbuf chain) parameter, and when `uio==NULL && top!=NULL` it delivers the mbuf chain directly, skipping m_uiotombuf. The research verified by measurement that the entire sosend region contains no FSTACK_* macros (git blame shows f-stack's deltas are not there) — **the upstream native capability was there all along; f-stack's MAGIC scheme disguises an mbuf as a uio to route around it, a "needless reinvention"**. What was missing was only an entry point to pass top from user space through to sosend (fully isomorphic to the receive side's mp0 being hardcoded NULL — kern_zc_recvit already demonstrated how to do it).

4.5 The native rewrite: kern_zc_sendit (2026-06-12)

The plan landed in one day (commit b6ce5884c): the new `kern_zc_sendit(td, s, top, flags)` calls `sosend(so, NULL, NULL, top, NULL, flags, td)` directly, and the hack was dismantled at the same time — of the 17 touchpoints, the MAGIC macro in mbuf.h, the ZC branch in m_uiotombuf, the guard in dofilewrite, and the opt-outs in ff_write/ff_writev were 5 DELETEs, reverting m_uiotombuf to the vanilla 15.0 version; ff_zc_send was rewritten to call kern_zc_sendit; ff_zc_mbuf_get/write got the M_PKTHDR gap fixed.

The M_PKTHDR gap is the technical prerequisite of this scheme and deserves a closer look: sosend's uio==NULL branch uses `top->m_pkthdr.len` as resid (the data length), but the old ff_zc_mbuf_get allocated the chain head with `m_getm2(..., flags=0)` — **without M_PKTHDR** — and the code maintaining pkthdr.len inside ff_zc_mbuf_write was commented out. Going straight to the native path would yield resid=0 and nothing would be sent. The fix is two lines: add M_PKTHDR at allocation and accumulate pkthdr.len on write — but those two lines are the watershed between "the native capability works" and "silently sends nothing".

[Note 2] ABI stability was the contract of this rewrite: the ff_zc_send/ff_zc_mbuf_get/ff_zc_mbuf_write signatures unchanged, the example/main_zc.c call sequence unchanged (the G4 acceptance clause literally diffs it for 0 line changes), the FF_ZC_SEND switch name kept but its meaning switched from "hack enabled" to "native path enabled", and exported symbols neither added nor removed. The only requirement for deployed projects is to rebuild after make clean.

4.6 Behavior changes (user-perceivable)

| Item | Old (hack) | New (native) |
|---|---|---|
| Large sends (>SO_SNDBUF) | crash/hang (issue #712) | blocks, or returns EWOULDBLOCK when non-blocking; caller fragments itself |
| UDP single packet > MTU | undefined behavior | explicit EMSGSIZE |
| Ordinary ff_write coexisting with ZC | opt-out needed to avoid collision; once GPF'd | no opt-out needed |
| FreeBSD upgrade maintenance | re-audit ~120 lines around m_uiotombuf | only verify whether the sosend signature changed |

4.7 The honest performance boundary

- 2022 official article: send zero-copy expected to gain about 2-3%, to be measured against real scenarios.
- 2026-06 ZC-recv single-core measurement: flat against ordinary read across three wrk tiers under small-packet echo (within noise); the payoff is expected in large-block data / proxy-forwarding scenarios.
- ZC-send native-rewrite performance target (spec 38): vs baseline and vs the old hack, Δ ≤ ±3% across the three wrk tiers (within noise) — the rewrite is an "equivalent replacement", not a "performance optimization"; the payoff is clearing the architectural debt.
- Large-payload (4KB/64KB/1MB) dedicated measurement is follow-up work (the spec already lists P2-P4 scenarios; the old scheme has crash risk at P3/P4, the new scheme must deliver intact data).

5. How to use it, how to configure it, and the results

5.1 Compile switches (three, fully independent and combinable)

```makefile
# lib/Makefile
#FF_ZC_SEND=1      # send zero-copy (native kern_zc_sendit path)
#FF_ZC_RECV=1      # receive zero-copy (kern_zc_recvit path)
#FF_USE_PAGE_ARRAY=1  # stack→DPDK zero-copy (experimental, not recommended for production)
```

After switching flags, **make clean is mandatory** (the 4.3 pitfall).

5.2 Send zero-copy API usage

```c
struct ff_zc_mbuf zc_buf;

ff_zc_mbuf_get(&zc_buf, buf_len);          // allocate the mbuf chain buffer (with M_PKTHDR)
ff_zc_mbuf_write(&zc_buf, data, len);      // write directly into the mbuf chain; callable multiple times
ff_zc_send(fd, zc_buf.bsd_mbuf, buf_len);  // deliver the mbuf chain, skipping the copy

// after a successful send, bsd_mbuf is owned by the protocol stack — do not access it;
// to reuse zc_buf, ff_zc_mbuf_get must be called again
```

Caller code-review essentials (spec 39 migration guide): don't send more than SO_SNDBUF in one call (otherwise EWOULDBLOCK, fragment yourself); keep a UDP packet under MTU (otherwise EMSGSIZE); drop the bsd_mbuf pointer immediately after send (otherwise UAF); the nbytes argument must be ≥ the actual accumulated write amount (actual sent length = pkthdr.len).

5.3 Receive zero-copy API usage

```c
struct ff_zc_mbuf zm;
ssize_t n = ff_zc_recv(fd, &zm, nbytes);
// read segment by segment: ff_zc_mbuf_segment(&zm, &seg, &len)
ff_zc_recv_free(&zm);   // must free after use, otherwise mbuf leak
```

5.4 Results

Measured data (2026-06-11, single-core lcore4, three wrk tiers, A = ordinary read / B = ZC-recv):

| Tier | A req/s | B req/s | Δ |
|---|---|---|---|
| T1 (-t2 -c10) | 22,363 | 22,115 | −1.1% |
| T2 (-t4 -c100) | ~31.1k | ~32.1k | flat (within noise) |
| T3 (-t8 -c500) | 28,615 | 28,317 | −1.0% |

Zero-copy shows no measurable gain under small-packet echo — this is by design, not a failure. The payoff scenarios are large payloads and forwarding.

5.5 Advice for users

- Large-block data / forwarding workloads: enable FF_ZC_SEND + FF_ZC_RECV and rework the send/receive paths with the ZC APIs.
- Small-packet RPC/echo workloads: don't bother; ordinary ff_read/ff_write is fine — measurements show no difference.
- FF_USE_PAGE_ARRAY: officially positioned as experimental, packet drops under i40e, and Phase-2 measurement once triggered a panic (fixed as a soft drop).
- Upgrading to a new version: rebuild after make clean; example/main_zc.c needs no changes.

Further reading:

- User-space zero-copy stack spec overview: docs/zc_stack_user_spec/30-spec-overview.md
- Current-state survey and removal list (17 touchpoints): docs/zc_stack_user_spec/31-current-state-and-removal.md
- Symmetric architecture design (kern_zc_sendit ↔ kern_zc_recvit): docs/zc_stack_user_spec/32-native-arch-design.md
- Native sosend(top) research: docs/zc_stack_user_spec/22-native-zc-send-research.md
- Migration guide for deployed projects: docs/zc_stack_user_spec/39-migration-guide.md
- ZC-recv M2 measurement report: docs/zc_stack_user_spec/21-m2-test-report.md
- Initial send zero-copy introduction (2022): https://mp.weixin.qq.com/s/j_b7pVOoFa6sqaWQD6eBpw
- Related issues: #364 (PR, stack→DPDK zero-copy), #407 (receive-side zero-copy confirmation), #712 (large-packet send crash), #467 (zero-copy API discussion)
- Three-layer architecture docs: docs/01-LAYER1-ARCHITECTURE.md
- Knowledge graph: docs/KNOWLEDGE_GRAPH_WIKI.md
