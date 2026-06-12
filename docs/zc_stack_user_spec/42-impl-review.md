# 42. Native-izing Send Zero-Copy —— Implementation-Phase review (M0-M5 execution record)

> Corresponding plan: 41-impl-plan.md. All conclusions are **measured** (compile/run/grep), no fabrication.
> Branch feature/1.26. Feature commit: `b6ce5884c` (M0+M1).

---

## §1 Milestone Results Summary Table

| Milestone | Content | Gate result | bounce |
|---|---|---|---|
| M0 kernel | kern_zc_sendit + delete 5 hacks + m_uiotombuf ZC branch removal | **PASS** | 0 |
| M1 userspace | ff_zc_send→kern_zc_sendit; M_PKTHDR; pkthdr.len; delete opt-out | **PASS** | 0 |
| M2 unit test | test_ff_zc_send.c algorithm-consistency 13 cases | **PASS** | 0 |
| M3 functional E2E | helloworld_zc real curl http=200 | **PASS** | 0 |
| M4 performance/stability | 1000-request stability PASS; precise A/B baseline **deferred** | **PASS (stability)** | 0 |
| M5 wrap-up | this document + commit + gatekeeper | in progress | — |

**Total bounce = 0** (no single step ≥3, no human decision needed).

---

## §2 M0 Kernel patch (measured evidence)

| Change | File:symbol | Verification |
|---|---|---|
| K1 declaration | `freebsd/sys/syscallsubr.h` `kern_zc_sendit` (gated FSTACK_ZC_SEND) | compiles |
| K2 implementation | `freebsd/kern/uipc_syscalls.c` `kern_zc_sendit` (immediately following kern_zc_recvit) | `nm libfstack.a` contains `t kern_zc_sendit` |
| D1 delete macro | `freebsd/sys/mbuf.h` FSTACK_ZC_MAGIC | grep=0 |
| D2 m_uiotombuf | `freebsd/kern/uipc_mbuf.c` delete FSTACK_ZC_SEND fast-path branch | grep FSTACK_ZC_SEND=0 |
| D3 guard | `freebsd/kern/sys_generic.c` uio_offset single line + delete mbuf.h include | grep FSTACK_ZC_SEND=0 |

kern_zc_sendit key semantics (measured against 33-spec §2.2): input validation failure m_freem(top)+EINVAL; getsock(&cap_send_rights)/MAC failure m_freem+return; `sosend(so,NULL,NULL,top,NULL,flags,td)`; **never a second m_freem after sosend** (INV-3 prevents double free); EPIPE→SIGPIPE (unless SO_NOSIGPIPE/MSG_NOSIGNAL). impl-review sub-agent re-checked 27/27 PASS.

### DEV-1 (spec deviation, measurement-driven, recorded)
33-spec §3.2 requires "m_uiotombuf reverts to vanilla FreeBSD 15.0, diff=0". **Measurement shows this is infeasible**: vanilla m_uiotombuf calls `m_uiotombuf_nomap` (inside `freebsd/kern/uipc_mbuf.c:1845 #ifndef FSTACK`, **not compiled** under the FSTACK build), so a full revert would inevitably fail to link. Therefore the plan's preset compromise **R-M0-1** is adopted: only delete the `#ifdef FSTACK_ZC_SEND` fast-path branch inside m_uiotombuf, retaining the existing 13.0-era m_uiotombuf normal copy path.
- The user's core goal (eliminate the hack magic, reduce accidental-trigger/upgrade cost) is **fully achieved**: FSTACK_ZC_MAGIC and the uio_offset sentinel are thoroughly removed, and m_uiotombuf no longer has any ZC special-case branch.
- AC4 "m_uiotombuf diff vs vanilla=0" is **downgraded** to "ZC hack branch zeroed"; the remaining AC4 items (mbuf.h MAGIC=0, sys_generic uio_offset returned to the vanilla single line + delete include) are **achieved**.

---

## §3 M1 Userspace (measured evidence)

| Change | File | Verification |
|---|---|---|
| U1 ff_zc_send | `lib/ff_syscall_wrapper.c` | cast top + kern_zc_sendit(curthread,fd,top,0); `nm` contains `T ff_zc_send` |
| U2 ff_zc_mbuf_get | `lib/ff_veth.c:316` | `m_getm2(...,MT_DATA,M_PKTHDR)` + len<0 validation |
| U3 ff_zc_mbuf_write | `lib/ff_veth.c:362` | `head->m_pkthdr.len += progress` (chain-head accumulation, O(1)) |
| U4 delete opt-out | `lib/ff_syscall_wrapper.c` | ff_write/ff_writev have no `auio.uio_offset = 0` (grep=0) |
| U5 ff_api.h | `lib/ff_api.h` | doc block updated (signature unchanged) |

**ABI unchanged**: ff_zc_send/ff_zc_mbuf_get/ff_zc_mbuf_write signatures 100% preserved; `example/main_zc.c` **zero modification** (`git diff --stat` empty); helloworld_zc links.

---

## §4 AC1 Compile Gate (four combinations, all make_rc=0)

| Combination | libfstack.a bytes |
|---|---|
| default | 6539824 |
| FF_ZC_RECV=1 | 6541322 |
| FF_ZC_SEND=1 | 6540798 |
| FF_ZC_SEND=1 FF_ZC_RECV=1 | 6542296 |

The 5 changed files compiled individually (with the same build -Werror flags) had **zero new warnings** (sys_generic.c only has the pre-existing `-Warray-bounds` at L962/964, not from this change and `-Wno-error`).

> Build compliance: `make clean` was not used (it contains a direct rm internally); cleanup of artifacts uses `/data/workspace/rm_tmp_file.sh` instead; temporary files/processes/permissions go through rm_tmp_file.sh / kill_process.sh / chmod_modify.sh respectively.

---

## §5 M2 Unit Testing

`tests/unit/test_ff_zc_send.c` (13 cases, added to P3_TESTS): U1-U10 + multi-segment + validation class.
- Run: 13/13 PASS; valgrind memcheck rc=0 (no definite leak).

### DEV-2 (unit-test scope note, measurement-driven)
Measurement shows `gcc -fsyntax-only ff_veth.c` fails on `sys/ctype.h`, and `ff_syscall_wrapper.c` fails on `sys/limits.h` (FreeBSD-proprietary headers). The existing host-based cmocka harness **cannot compile** these two TUs, so it cannot directly link the real functions for unit testing. M2 adopts an **algorithm-consistency test**: the mbuf shim faithfully replicates the M_PKTHDR/pkthdr.len accumulation and boundary logic of ff_zc_mbuf_get/write (the header notes it is synchronized with the source). The real binary is covered end-to-end by M3.
> The `tests/integration/test_ff_zc_recv_integration.c` referenced by spec 37 §8.3 (claimed established in commit 8a06862cd) **does not exist by measurement** (that commit only changed docs+main_zc.c+symlist); the ZC-send test follows the actually existing `test_ff_dpdk_kni/pcap` paradigm.

---

## §6 M3 Functional E2E (real binary, strongest verification)

Environment: this server VM (DPDK NIC 0000:00:09.0 virtio/igb_uio already bound, hugepage 4096×2M, config addr 9.134.214.176 / lcore4) —— same machine as ZC-recv M2.

- helloworld_zc (FF_ZC_SEND) startup: DPDK Port 0 Link Up, f-stack registered the interface MAC 20:90:6f:7d:5d:08.
- The local machine can reach the data-plane IP via eth1 routing, curl×5: **all http=200 size=438**, the response content is the F-Stack welcome page, consistent across 5 times.
- Path proof: `ff_zc_mbuf_get(M_PKTHDR)`→`ff_zc_mbuf_write(pkthdr.len)`→`ff_zc_send`→`kern_zc_sendit`→`sosend(uio=NULL, top)`. **size=438 being correct directly proves the pkthdr.len fix is effective** (if pkthdr.len=0 then resid=0 and the response would be empty) —— this is the end-to-end confirmation of the new native path on the real stack.
- Process cleanup goes through kill_process.sh.

---

## §7 M4 Performance/Stability

- **Stability stress test** (1000 sequential requests via local curl): **ok=1000 bad=0**, the server survived, no panic/segfault/abort (verifies the issue #712 "crash on heavy sending" concern —— the new path is stable).
- **Precise A/B performance baseline (wrk T1/T2/T3, Δ≤±3%)**: **deferred**. Reason (faithful): this machine has no wrk; and a rigorous baseline needs the same remote client VM as M2 (9.134.211.87), as single-machine wrk on this host contends for the same core with the server and is not comparable. **No fabricating performance data**; awaiting the user's re-measurement in a dual-machine environment per 38-perf-baseline-spec.

---

## §8 Acceptance Comparison (AC1-AC6)

| AC | Result | Evidence |
|---|---|---|
| AC1 clean compilation | ✅ | four combinations make_rc=0; zero new warnings in changed files |
| AC2 functional PASS | ✅ | M3 http=200 size=438; example/main_zc.c zero change; compiles OK with FSTACK_ZC_RECV both-on coexistence |
| AC3 performance on par | ⏳ deferred | needs dual-machine wrk; single-machine stability 1000/1000 OK |
| AC4 kernel diff shrinkage | ◑ partial | MAGIC/sys_generic returned to vanilla; m_uiotombuf see DEV-1 (only removed the ZC branch, not fully reverted to vanilla, because nomap/mc_uiotomc unavailable) |
| AC5 memory safety | ◑ | unit-test valgrind 0 leak; kern_zc_sendit error-path single-point m_freem confirmed by review to have no double-free/UAF; precise mempool count under DPDK runtime deferred (same as 21-m2 conclusion, runtime valgrind cost is high) |
| AC6 spec documentation complete | ✅ | 41-plan + 42-review; no direct rm/kill/chmod |

---

## §9 bounce counter (per memory 86071475)

```
M0=0  M1=0  M2=0  M3=0  M4=0  M5=0
```
0 bounces throughout; no step reached the limit of 3 times; no human decision needed. The two DEVs (DEV-1 m_uiotombuf compromise, DEV-2 unit-test scope) are **measurement-driven design decisions** (the plan already preset the R-M0-1 rollback path), not gate failures.

---

## §10 Commit Record

| commit | Content |
|---|---|
| `b6ce5884c` | feat(zc-send): M0 kernel + M1 userspace (feature code + 41-plan) |
| (this phase) | test(zc-send): M2 unit test + 42-review document |

## §11 Remaining / Recommendations (pending human or follow-up)
1. Precise A/B performance baseline (dual-machine wrk T1/T2/T3 + large payload P1-P4) —— re-measure on the client VM per 38-spec.
2. Precise mempool count / valgrind under DPDK runtime (AC5 completion).
3. Multi-segment large-packet send path (>1 mbuf) E2E on the real binary: the helloworld fixed 438B response is single-segment; multi-segment is already covered by the M2 algorithm unit test, recommend a follow-up using a large-payload custom client to supplement the test on the real stack.
4. If m_uiotombuf needs diff-vs-vanilla=0 in the future, the full set of m_uiotombuf_nomap/mc_uiotomc/M_EXTPG/mchain must be reverted in sync (a large change, not done this phase).
