# 41. Native-izing Send Zero-Copy (userspace → protocol stack) —— Implementation-Phase plan

> Phase: implementation phase (spec 30-40 ready and passed by the gatekeeper)
> Mode: harness engineering + spec-driven + agent team (leader + sub-agents)
> Goal: switch `FSTACK_ZC_SEND` from the `FSTACK_ZC_MAGIC + m_uiotombuf` hack to
>       the FreeBSD-native `sosend(uio=NULL, top=chain)` path (adding a symmetric `kern_zc_sendit`),
>       eliminating the m_uiotombuf kernel patch and reducing accidental-trigger and upgrade-maintenance cost.
> Mandatory regulation: DP-10 (rm/kill/chmod must all go through `/data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh`);
>           measurement-first, no speculation; gatekeeper failure bounces back to the previous step, single-step bounce ≤ 3 times, stop and escalate to human decision when exceeded.

---

## §0 Phase-0 Reconnaissance Conclusions (completed, all file:line measured, code is authoritative)

### 0.1 The 5 existing hack touchpoints (confirmed consistent with 31-spec)

| # | File | Measured line | Current state | Disposition |
|---|---|---|---|---|
| 1 | `freebsd/sys/mbuf.h` | 1856-1869 | `#ifdef FSTACK_ZC_SEND` + `#define FSTACK_ZC_MAGIC ((off_t)0xF8AC2C00F8AC2C00LL)` | DELETE |
| 2 | `freebsd/kern/uipc_mbuf.c` | 1955-2077 | `#ifndef FSTACK`(vanilla 15.0) / `#else`(13.0 simplified + ZC branch) / `#endif` wrapping m_uiotombuf | RESTORE→vanilla |
| 3 | `freebsd/kern/uipc_mbuf.c` | 2028-2049,2070-2072 | `#ifdef FSTACK_ZC_SEND` fast path inside m_uiotombuf | DELETE (with #2) |
| 4 | `freebsd/kern/sys_generic.c` | 57 | `#include <sys/mbuf.h> /* M8 */` | delete depending on dependencies |
| 5 | `freebsd/kern/sys_generic.c` | 560-573 | dofilewrite `#ifdef FSTACK_ZC_SEND` uio_offset guard | DELETE→single line |
| 6 | `lib/ff_syscall_wrapper.c` | 1146-1151 | ff_write `auio.uio_offset = 0;` opt-out + comment | DELETE |
| 7 | `lib/ff_syscall_wrapper.c` | 1175 | ff_writev `auio.uio_offset = 0;` | DELETE |
| 8 | `lib/ff_syscall_wrapper.c` | 1186-1226 | old ff_zc_send (constructs uio + MAGIC + kern_writev) | REWRITE |
| 9 | `lib/ff_veth.c` | 306-323 | ff_zc_mbuf_get `m_getm2(...,MT_DATA,0)` without M_PKTHDR | REWRITE +M_PKTHDR |
| 10 | `lib/ff_veth.c` | 325-356 | ff_zc_mbuf_write commented out the pkthdr.len accumulation (L349-350) | REWRITE to maintain pkthdr.len |

### 0.2 Native sosend(top) entry (confirmed)
- `kern_zc_recvit` measured at `uipc_syscalls.c:1064-1108`, immediately following `#endif /* FSTACK_ZC_RECV */`(L1109) —— the symmetric insertion point for `kern_zc_sendit`.
- `syscallsubr.h:304-310` is the `kern_zc_recvit` declaration; the new declaration is inserted right after it (after L310).
- `kern_sendit` pattern measured: `getsock(td, s, &cap_send_rights, &fp)`(L745/750) + `mac_socket_check_send`(L770) —— reused by `kern_zc_sendit`.

### 0.3 m_uiotombuf revert feasibility (critical compile risk, pre-verified)
- In the f-stack tree, `m_uiotombuf_nomap`(L1865), `mc_split`/`mc_first`(L1122/1127), and `struct mchain` all exist;
- vanilla `freebsd-src-releng-15.0/sys/kern/uipc_mbuf.c`'s `m_uiotombuf` is at L1950, aligned with the f-stack `#ifndef FSTACK` branch (L1956-1992);
- revert = delete the `#else` 13.0 branch + remove the `#ifndef FSTACK/#else/#endif` wrapping, retaining the vanilla branch as unconditional code;
- ⚠ M0 must verify with **actual compilation** that the vanilla branch links (whether mc_uiotomc is fully defined); on failure, bounce.

### 0.4 Build environment (confirmed ready)
- DPDK 23.11.5 pkgconfig @ `/usr/local/lib64/pkgconfig`; cmocka 1.1.7;
- `uipc_mbuf.c` compiled into lib (lib/Makefile:361); `lib/libfstack.a` from the last M2 build exists.

### 0.5 ⚠ Critical cross-validation gaps (spec doc vs code measurement, code is authoritative)
1. **`tests/integration/test_ff_zc_recv_integration.c` referenced by spec 37 §8.3 (claimed established in commit 8a06862cd) does not exist**: measurement shows 8a06862cd only changed docs + example/main_zc.c + ff_api.symlist, with no zc test files at all. Neither `tests/unit` nor `tests/integration` currently has zc tests. → ZC-send tests must follow the **actually existing** paradigms (`test_ff_dpdk_kni.c`'s EAL+cmocka, `test_ff_dpdk_pcap.c`'s mbuf construction, `test_ff_dpdk_if_integration.c`'s real EAL).
2. **`ff_veth.c` / `ff_syscall_wrapper.c` deeply depend on FreeBSD kernel headers** (`sys/socketvar.h`, `net/if_var.h`, `netinet/in.h`…); the existing host-based unit harness (which compiles `lib/*.c` into `lib_objs` using host headers) **cannot host-compile** these two files. → spec 37's U1-U12 pure-logic unit-test assumption does not directly hold; M2 must adjust pragmatically (see §3 M2).

---

## §1 Agent Team Topology (team: zc-send-impl)

| Role | Implementation | Responsibility |
|---|---|---|
| **Leader** (this conversation) | main agent | milestone scheduling, actual code editing/compiling/test execution, gatekeeper adjudication, bounce counter, commit |
| **impl-review** | `Task(code-explorer)` read-only | reviews after each milestone's code changes: consistency with spec/measurement, diff minimization, regulation compliance |
| **gatekeeper** | `Task(code-explorer)` read-only | milestone gate final review: grep/build artifacts/symbols/diff-vs-vanilla sampling, PASS/FAIL |

> Editing actions are executed by the Leader using the `c-precision-surgery` (kernel precision patch) + `c-unittest-expert` (unit test) skills;
> sub-agents are read-only analysis (the efficient mode consistent with the spec phase).

### Gatekeeper bounce regulation (per memory 86071475)
- Any milestone gate FAIL → bounce that milestone for repair;
- **single-milestone bounce ≤ 3 times**; on the 4th still FAIL → **stop the task, escalate to human decision**;
- maintain a `bounce[Mx]` count per milestone, recorded in the 49/4x review.

---

## §2 Milestone Overview and Gates

| Milestone | Content | Gate |
|---|---|---|
| **M0 kernel** | K1 kern_zc_sendit declaration + K2 implementation; D1 delete MAGIC macro; D2 revert m_uiotombuf→vanilla; D3 delete sys_generic guard | compile 4 combinations `-Werror` clean; `nm` contains `kern_zc_sendit`; grep C2/K-G3/4/5=0; diff m_uiotombuf vs vanilla=0 |
| **M1 userspace** | U1 rewrite ff_zc_send→kern_zc_sendit; U2 ff_zc_mbuf_get +M_PKTHDR; U3 ff_zc_mbuf_write maintain pkthdr.len; U4 delete ff_write/writev opt-out; U5 ff_api.h comments | compile clean; `nm` contains `ff_zc_send`; `example/main_zc.c` diff=0; U-G1/3/4/5 grep; helloworld_zc links |
| **M2 unit test** | per §0.5 pragmatic plan: host-compilable pure-logic cases + non-compilable parts covered at compile-time/integration-time | test compile+run PASS; valgrind 0 definite leak; no new regulation violation |
| **M3 functional/integration** | replicate the E2E path of 21-m2-report (helloworld_zc + HTTP, send path); run for real if the environment permits | http=200 (send zero-copy path); or faithfully record environment limitations + degrade to libfstack link-level verification |
| **M4 performance baseline** | wrk T1/T2/T3 + large packets; compared against baseline | best-effort; if the environment is insufficient, **faithfully mark as deferred, no fabricating data** |
| **M5 wrap-up** | implementation review doc (42-impl-review.md) + bounce summary + batch commit (concise English msg) | gatekeeper final review PASS |

> M3/M4 are constrained by the DPDK runtime (hugepage/NIC/vdev); for anything that cannot be run for real, **faithfully record** it, do not fabricate results (regulation #4).
> Scope supplement: if **receive-layer (ZC-recv) problems** are discovered during implementation, fix them together (user authorized).

---

## §3 Milestone Detailed Specs

### M0 — Kernel patch (c-precision-surgery)
- **K1** insert `#ifdef FSTACK_ZC_SEND ... int kern_zc_sendit(...); #endif` after `freebsd/sys/syscallsubr.h` L310 (symmetric to kern_zc_recvit).
- **K2** insert the `kern_zc_sendit` implementation after `freebsd/kern/uipc_syscalls.c` L1109 (the 33 §2.2 version: input validation m_freem→getsock→MAC→sosend(so,NULL,NULL,top,NULL,flags,td)→on success td_retval=len/on failure SIGPIPE→fdrop).
- **D1** delete the entire 1856-1869 block in `freebsd/sys/mbuf.h`.
- **D2** in `freebsd/kern/uipc_mbuf.c` delete the `#else`(13.0+ZC) branch + remove the `#ifndef FSTACK/#else/#endif` wrapping, retaining the vanilla branch.
- **D3** `freebsd/kern/sys_generic.c` 560-573→single line `auio->uio_offset = offset;`; grep-verify whether the L57 include can be deleted.
- **Gate M0**:
  1. `cd lib && PKG_CONFIG_PATH=... make clean && FF_ZC_SEND=1 make` (then test default / FF_ZC_RECV=1 / both-on) four combinations `-Werror` clean;
  2. `nm libfstack.a | grep kern_zc_sendit` = 1 T symbol;
  3. `grep FSTACK_ZC_SEND freebsd/kern/uipc_mbuf.c freebsd/kern/sys_generic.c freebsd/sys/mbuf.h` = 0;
  4. `grep FSTACK_ZC_MAGIC freebsd/ lib/` source 0;
  5. diff m_uiotombuf region vs `freebsd-src-releng-15.0/sys/kern/uipc_mbuf.c` = 0.
  - FAIL → bounce[M0]++ (≤3).

### M1 — Userspace API (c-precision-surgery)
- **U1** `lib/ff_syscall_wrapper.c:1186-1226` rewrite ff_zc_send (the 34 §3.3 version: cast top + kern_zc_sendit(curthread,fd,top,0)).
- **U2** `lib/ff_veth.c:306-323` ff_zc_mbuf_get: `m_getm2(...,MT_DATA,0)`→`M_PKTHDR`, add `len<0` validation.
- **U3** `lib/ff_veth.c:325-356` ff_zc_mbuf_write: chain head `head->m_pkthdr.len += progress` (O(1)), add data!=NULL/len<0/len==0 handling, delete unused ret.
- **U4** delete `lib/ff_syscall_wrapper.c:1146-1151` (ff_write opt-out) + `:1175` (ff_writev opt-out).
- **U5** `lib/ff_api.h:437-446` update the doc block (signature unchanged).
- **Gate M1**: compile clean; `nm libfstack.a | grep ff_zc_send`=1; `grep -n "auio.uio_offset = 0" lib/ff_syscall_wrapper.c`=0; ff_zc_mbuf_get contains M_PKTHDR, ff_zc_mbuf_write contains uncommented m_pkthdr.len; `git diff --stat example/main_zc.c`=empty; `cd example && FF_PATH=... make` helloworld_zc links.
  - FAIL → bounce[M1]++ (≤3).

### M2 — Unit testing (pragmatic, c-unittest-expert)
- Constrained by §0.5(2), `ff_veth.c`/`ff_syscall_wrapper.c` cannot be host-compiled. Pragmatic strategy:
  - **Plan A (preferred)**: create `tests/unit/test_ff_zc_send_logic.c`, **extract the pure logic of the functions under test** (the pkthdr.len accumulation/boundary of ff_zc_mbuf_write + the input validation of ff_zc_send) and cover U5/U6/U7/U8/U9/U10/U11/U12-class assertions via a local mbuf shim + `--wrap`; the Makefile mimics `test_ff_dpdk_pcap` adding per-target `-DFSTACK_ZC_SEND`.
  - **If Plan A is infeasible due to BSD header coupling → bounce once**, switch to **Plan B**: M_PKTHDR/pkthdr.len correctness covered by **M0/M1 compile-time assertions + M3 integration functionality**, the unit test only keeps the independently-compilable ff_zc_send input-validation stub; and faithfully record the harness limitation in 42-impl-review.
- **Gate M2**: test binary compile + run PASS; `make check`(valgrind) 0 definite leak.
  - FAIL → bounce[M2]++ (≤3).

### M3 — Functional/integration
- Replicate the E2E of `21-m2-test-report.md`: after `FF_PATH`/`FF_DPDK` are configured, start the service with `example/helloworld_zc` (FF_ZC_SEND=1) + HTTP GET to verify the send zero-copy path http=200; process cleanup goes through `/data/workspace/kill_process.sh`, temporary files go through `rm_tmp_file.sh`.
- Insufficient environment (no hugepage/NIC/vdev) → degrade to: libfstack.a + helloworld_zc link-level + symbol verification, and **faithfully record**.
- **Gate M3**: http=200 (ideal) or link-level PASS + limitation record. FAIL → bounce[M3]++ (≤3).

### M4 — Performance (best-effort)
- If the environment permits: wrk T1/T2/T3 + large packets vs baseline, Δ≤±3%; otherwise **faithfully mark deferred**, no fabricating.

### M5 — Wrap-up
- Write `docs/zc_stack_user_spec/zh_cn/42-impl-review.md` (per-milestone results + bounce counter + gate sampling + spec-deviation notes).
- Batch `git commit` (concise English msg, per regulation #5 + memory 73362122): M0 kernel / M1 userspace / M2 unit test / (M3 if there are artifacts) / M5 review.
- gatekeeper final review.

---

## §4 Risks and Rollback

| Risk | Trigger | Disposition |
|---|---|---|
| R-M0-1 | link failure after reverting vanilla m_uiotombuf (mc_uiotomc undefined) | bounce M0; switch to the "only delete the ZC branch, retain the 13.0 simplified version" compromise (achieving the core goal of eliminating the hack, AC4 diff item downgraded with annotation) |
| R-M0-2 | kern_zc_sendit unreferenced causing `-Werror=unused` | M1's ff_zc_send is the referencer; when M0 is compiled alone the function is gated but referenced by symlist/caller, merge M0+M1 compile verification if necessary |
| R-M2-1 | ff_veth.c cannot be host-compiled | Plan A→B degradation (§3 M2) |
| R-M3-1 | DPDK runtime unavailable | degrade to link-level + faithful record, do not fabricate http=200 |
| General | single-step bounce ≥3 | **stop the task, escalate to human decision** (memory 86071475) |

---

## §5 bounce counter (maintained during execution)

```
M0=0  M1=0  M2=0  M3=0  M4=0  M5=0
```

(updated in real time during execution; any =3 triggers human intervention.)
