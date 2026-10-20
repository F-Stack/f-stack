# M6 Spec — FF_NETGRAPH + FF_IPFW Combo (P0)

> Chinese version: ./zh_cn/phase2-M6-spec.md (authoritative)

> Parent plan: `phase2-feature-enable-plan.md` (v0.1, accepted 2026-06-08)
> Spec version: v0.1 (2026-06-08)
> Status: DRAFT → pending Phase D reviewer
> Working commit baseline: `07f9bb0b7` (feature/1.26 ahead 13)
> M5 build baseline: 0 errors / 55 warnings / `libfstack.a` 5.4 MB (default config; this milestone's G1 threshold = baseline + 5)

---

## 1. Scope (in / out)

### 1.1 In scope (must do)

| Item | Note |
|---|---|
| Enable `FF_NETGRAPH=1` | uncomment `lib/Makefile:43` |
| Enable `FF_IPFW=1` | uncomment `lib/Makefile:44` |
| Build clean | `cd lib && make all` no error; warnings ≤ 60 (55 + 5) |
| Primary smoke | `example/helloworld` stays alive ≥ 10 s without crashing |
| ipfw user-space tool works | `cd tools/ipfw && make` produces an `ipfw` binary; `./ipfw add 100 deny ip from 1.2.3.4 to any` + `./ipfw show` lists the rule |
| netgraph control works | `tools/ngctl list` returns at least an empty list (0 active node OK as long as it returns) |
| Doc sync (partial) | short L1/L2/L3 + long + Summary: add a "FF_NETGRAPH/FF_IPFW build options" section; add zh_cn mirrors |
| Local commit | English commit message; no push |

### 1.2 Out of scope (explicitly not done)

| Item | Reason |
|---|---|
| `freebsd/netpfil/ipfw/nat64/`, `nptv6/` | not in `NETIPFW_SRCS`; if a user runs `ipfw nat64*`, runtime returns an error; doc must call out the limit |
| `freebsd/netpfil/ipfw/ip_fw_bpf.c`, `ip_fw_compat.c` | not in `NETIPFW_SRCS`; left as-is (matches the 13.0 era) |
| 8 excluded netgraph nodes: `ng_base.c` (replaced by ff_ng_base.c), `ng_bpf.c`, `ng_checksum.c`, `ng_device.c`, `ng_macfilter.c`, `ng_mppc.c`, `ng_tty.c`, `ng_vlan_rotate.c` | intentionally excluded from `NETGRAPH_SRCS`; left as-is |
| nat64clat/nat64lsn/nat64stl/nptv6 commands inside `tools/ipfw/` | the user-space binary will compile them in (Makefile is unconditional), but kernel-side sockopts don't exist → runtime returns `ENOPROTOOPT`; not a milestone defect, doc explains |
| Perf testing (rps / cps / latency) | M6 doesn't require it (plan §3 M6 row: G4 not done); perf baseline lives in M7/M8/M9 |
| KG_WIKI re-index | M6 doesn't do it (plan §5.4: only M-Final re-runs) |
| FreeBSD 14/15 new ipfw eaction extensions (e.g. `recvtag`) | spec only notes their existence; runtime correctness not validated |

---

## 2. Background and State (measured)

### 2.1 Build option control points (lib/Makefile)

```
:43   #FF_NETGRAPH=1                    ← uncomment
:44   #FF_IPFW=1                        ← uncomment
:104  ifdef FF_NETGRAPH                 (host-side flag injection)
:105    HOST_CFLAGS+= -DFF_NETGRAPH
:108  ifdef FF_IPFW                     (both host + kern flag)
:109    HOST_CFLAGS+= -DFF_IPFW
:110    CFLAGS+= -DFF_IPFW
:224  ifdef FF_NETGRAPH                 (VPATH +=$S/netgraph)
:237  ifdef FF_IPFW                     (VPATH +=$S/netpfil/ipfw + .../pmod)
:266  ifdef FF_NETGRAPH                 (FF_SRCS+= ff_ng_base.c ff_ngctl.c)
:424  ifdef FF_NETGRAPH                 (NETGRAPH_SRCS list = 41 .c)
:575  ifdef FF_IPFW                     (NETIPFW_SRCS list = 13 .c)
```

### 2.2 Source statistics (measured 2026-06-08)

| Dimension | Value | Source |
|---|---|---|
| `freebsd/netgraph/` top-level .c | 49 | `ls freebsd/netgraph/*.c \| wc -l` |
| Including subdirs (bluetooth/ + netflow/) | 74 (not built locally) | `find freebsd/netgraph -name '*.c' \| wc -l` |
| `NETGRAPH_SRCS` actually built | 41 | `lib/Makefile:426-466` |
| `freebsd/netpfil/ipfw/` top-level .c | 25 | `ls freebsd/netpfil/ipfw/*.c \| wc -l` |
| `NETIPFW_SRCS` actually built | 13 | `lib/Makefile:577-589` |
| `tools/ipfw/` total entries | 26 (incl. 10 stale .o) | `ls tools/ipfw \| wc -l` |
| `tools/ipfw/*.c` | 12 | `ls tools/ipfw/*.c \| wc -l` |
| `tools/ipfw/*.o` (stale) | 10 | must clean before build (use `rm_tmp_file.sh`) |

### 2.3 Exclusion confirm (8 not in NETGRAPH_SRCS)

| File | Reason (inferred) | Risk |
|---|---|---|
| `ng_base.c` | replaced by `lib/ff_ng_base.c` (user-space epoch/inputqueue) | none |
| `ng_bpf.c` | depends on the BPF kernel interface; no BPF device | medium (user calls fail) |
| `ng_checksum.c` | depends on mbuf checksum offload | low |
| `ng_device.c` | depends on `/dev/ngd*` char device | medium |
| `ng_macfilter.c` | depends on the ifp ethernet hook | low |
| `ng_mppc.c` | depends on the crypto module | low |
| `ng_tty.c` | depends on the tty subsystem | low |
| `ng_vlan_rotate.c` | introduced in FreeBSD 14+ | low |

### 2.4 IPFW exclusion list

| File | State | Risk |
|---|---|---|
| `ip_fw_bpf.c` | source present, not in NETIPFW_SRCS | link-time symbols like `ipfw_bpf_init` referenced by `ip_fw2.c` → covered by `ff_stub_14_extra.c` (Phase D verifies) |
| `ip_fw_compat.c` | source present, not listed | the old sockopt path is unavailable (does not affect ipfw3 protocol) |
| `nat64/`, `nptv6/` | not built at all | `ipfw nat64*` / `ipfw nptv6` returns `ENOPROTOOPT` at runtime |

### 2.5 The bridge node `ng_ipfw.c` (root cause of the P0 bundle)

`freebsd/netgraph/ng_ipfw.c` is in `NETGRAPH_SRCS` (one of the 41); it declares `KLD_DEPEND(ng_ipfw, ipfw, ...)`, **requiring the ipfw subsystem at build time** → **this is precisely why P0 must enable NETGRAPH and IPFW as a combo**.

> Source: scout report (task 1, §5) + measurement of `grep -n KLD_DEPEND freebsd/netgraph/ng_ipfw.c` (re-verified during Phase C).

### 2.6 User-space tool: `tools/ipfw/Makefile` measured

```makefile
TOPDIR?=${CURDIR}/../..
SRCS = ipfw2.c ipv6.c main.c nat.c tables.c compat.c
SRCS += nat64clat.c nat64lsn.c nat64stl.c nptv6.c        # always built; kernel doesn't support
ifneq (${MK_DUMMYNET},"no") SRCS += dummynet.c           # default on
ifneq (${MK_PF},"no")       SRCS += altq.c               # default on
LIBADD = util
MAN = ipfw.8
```

`tools/ipfw/compat.c` is already F-Stack's shim, replacing `socket()/setsockopt()/getsockopt()` with `ff_ipc_*`, talking to the lib-side `ip_fw_sockopt.c` over IPC.

---

## 3. Interface and Data-structure Changes

### 3.1 lib/Makefile change (minimal diff)

```diff
-#FF_NETGRAPH=1
+FF_NETGRAPH=1
-#FF_IPFW=1
+FF_IPFW=1
```

**Two lines only**. Other build options remain commented.

### 3.2 lib/ source-file changes (anticipated)

| File | Expected change | Trigger |
|---|---|---|
| `lib/ff_stub_14_extra.c` | possibly add ipfw / netgraph stubs missing in 14.0+ | Phase E G1 build failure → coder incrementally fixes |
| `lib/ff_ng_base.c` | likely first-time real compile after FF_NETGRAPH on; new warnings/errors possible | Phase E G1 |
| Other lib/ff_*.c | **not actively modified**; only located by reviewer/coder if G1 fails | — |

### 3.3 freebsd/netgraph/ + freebsd/netpfil/ipfw/ changes

**Default: no change**. If G1 needs a patch, must:
1. Backup the original to `/data/workspace/freebsd-src-releng-15.0/f-stack-lib/freebsd/netgraph/` (or `ipfw/`).
2. Document the patch reason + matching upstream commit (if any) in spec / execution-log.
3. Reviewer must verify the patch doesn't drift from upstream intent.

### 3.4 tools/ipfw/ changes

**Default: no change**. Pre-build, use `rm_tmp_file.sh` to clean the 10 stale `.o`s.

---

## 4. Acceptance Criteria (each executable + measurable)

### G1 — Build gate

| AC ID | Test | PASS criterion |
|---|---|---|
| **G1.1** | `cd lib && make clean && make all 2>&1 \| tee /tmp/m6_compile.log` | exit=0 |
| **G1.2** | `grep -ic 'error:' /tmp/m6_compile.log` | 0 |
| **G1.3** | `grep -ic 'warning' /tmp/m6_compile.log` | ≤ 60 (baseline 55 + 5) |
| **G1.4** | `ls -l lib/libfstack.a` | size ≥ 5.4 MB (baseline) × 0.95 (no illogical regression) |
| **G1.5** | `cd tools/ipfw && /data/workspace/rm_tmp_file.sh tools/ipfw/*.o 2>/dev/null; make 2>&1` | exit=0 + `ipfw` binary produced (note: clean MUST go through rm_tmp_file.sh, not raw rm) |

### G2 — Primary smoke gate

| AC ID | Test | PASS criterion |
|---|---|---|
| **G2.1** | `cd example && sudo ./helloworld -c ../config.ini --proc-type=primary --proc-id=0 &; sleep 10; /data/workspace/kill_process.sh helloworld` | exit=0; primary alive within 10 s |
| **G2.2** | `dmesg \| tail -50` (or helloworld stdout) | no SIGSEGV / panic / "stub called" keyword |

### G3 — Functional gate

| AC ID | Test | PASS criterion |
|---|---|---|
| **G3.1** | with helloworld in background: `cd tools/ipfw && sudo ./ipfw add 100 deny ip from 1.2.3.4 to any` | exit=0; stdout contains `00100 deny ip from 1.2.3.4 to any` |
| **G3.2** | `sudo ./ipfw show` | exit=0; output contains the `00100 deny ip from 1.2.3.4 to any` line |
| **G3.3** | `sudo ./ipfw delete 100 && sudo ./ipfw show` | exit=0; the rule is gone |
| **G3.4** | `cd tools/ngctl && sudo ./ngctl list` (if ngctl is not under tools/, downgrade this AC to checking that init functions like `ng_init` in `lib/ff_ng_base.c` are reached, judged from strings or helloworld stdout) | exit=0 or downgrade satisfied |
| **G3.5 (OQ-4 applicable)** | If any of G3.1~3.4 fails due to NIC/hardware dependency | may downgrade to smoke PASS + observation tag (plan §8 OQ-4 default permits) |

### G4 — Perf gate

**Not required** (plan §3 M6 row: G4 not done).

### G5 — Doc-sync gate

| AC ID | File | Acceptance |
|---|---|---|
| **G5.1** | `docs/01-LAYER1-ARCHITECTURE.md` + `docs/zh_cn/01-LAYER1-ARCHITECTURE.md` | mention FF_NETGRAPH/FF_IPFW enable status, file count, bridge node ng_ipfw in §2/§4 |
| **G5.2** | `docs/03-LAYER3-FUNCTIONS.md` + `docs/zh_cn/03-LAYER3-FUNCTIONS.md` | add function-level entries for `lib/ff_ng_base.c` / `lib/ff_ngctl.c` in §3 (phase-1 style) |
| **G5.3** | `docs/F-Stack_Knowledge_Base_Summary.md` + zh_cn mirror | add an M6 row to the version-and-milestone table |
| **G5.4** | `docs/freebsd_13_to_15_upgrade_spec/zh_cn/phase2-M6-execution-log.md` | full execution log |
| **G5.5** | `docs/freebsd_13_to_15_upgrade_spec/zh_cn/phase2-M6-review-report.md` | reviewer report |
| **G5.6** | `read_lints docs/` | 0 errors |

### G6 — Lint gate

`read_lints docs/` + `read_lints lib/` 0 errors.

### G7 — Commit gate

| AC ID | Acceptance |
|---|---|
| **G7.1** | git commit subject in English; body covers (a) modified file list (b) G1-G6 results (c) bounce ledger |
| **G7.2** | `git log -1` shows the new commit; `git status -sb` clean |
| **G7.3** | `git push` **not executed** (plan §6.2 hard constraint) |

---

## 5. Risks and Rollback

| Risk | Detection | Mitigation | Owner |
|---|---|---|---|
| **R-M6-1** ng_ipfw.c KLD_DEPEND ineffective in user space | possible build-time unresolved symbol; runtime ng_ipfw node fails to attach | if build-only error, add stub in ff_stub_14_extra; if runtime can't attach, doc explains (downgrade allowed) | coder + reviewer |
| **R-M6-2** stale `.o` in tools/ipfw causes old-symbol linkage | `tools/ipfw/*.o` mtime older than the `.c` | before G1.5, `rm_tmp_file.sh` cleans; provide a dedicated cleaning script if needed | gate-keeper |
| **R-M6-3** Calls to the 8 excluded ng_*.c segfault | user tries `ngctl mkpeer ... bpf` etc. | doc states unsupported; G3 doesn't trigger such commands | doc-updater |
| **R-M6-4** New 14.0+ ipfw symbols missing (e.g. `ipfw_eaction_*`) | G1 unresolved reference | add stub in ff_stub_14_extra; reviewer cross-checks `freebsd-src-releng-15.0/sys/netpfil/ipfw/ip_fw2.c` | coder |
| **R-M6-5** ipfw rule add succeeds but kernel-side has no effect | G3.1 PASS but ping not actually denied | first confirm pfil hook registration (`ip_fw_pfil.c:ipfw_attach_hooks`); if unfixable, downgrade to observation (OQ-4) | gate-keeper |
| **R-M6-6** Warnings explode (>60) | G1.3 fail | (1) prefer to fix real-regression warnings; (2) if old NETGRAPH/IPFW subsystem warnings, spec patches the threshold then proceeds | reviewer |

**Rollback strategy**: if any G1-G3 is bounced more than 3 times in the same stage, escalate; user picks:
- (a) accept downgrade (observation tag)
- (b) pause M6, do M7 first (independent)
- (c) revise spec thresholds

---

## 6. Test List (G1-G7 executable commands)

See the "test" column in §4 for each AC. **No raw `rm`/`kill`/`chmod`** — must use `rm_tmp_file.sh`/`kill_process.sh`/`chmod_modify.sh`.

### 6.1 Pre-test environment cleanup (mandatory)

```bash
# Clean the 10 stale .o under tools/ipfw (see §2.2)
cd /data/workspace/f-stack
/data/workspace/rm_tmp_file.sh \
  tools/ipfw/altq.o tools/ipfw/compat.o tools/ipfw/dummynet.o tools/ipfw/ipv6.o \
  tools/ipfw/ipfw2.o tools/ipfw/main.o tools/ipfw/nat.o tools/ipfw/nat64clat.o \
  tools/ipfw/nat64lsn.o tools/ipfw/tables.o
# Clean lib/ build artifacts
cd lib && make clean   # `make clean`'s internal rm is run by the build system; allowed by the mandate
```

### 6.2 G1 test script (suggested)

```bash
cd /data/workspace/f-stack/lib
make clean 2>&1 | tail -3
make all 2>&1 | tee /tmp/m6_compile_$(date -u +%Y%m%d_%H%M%S).log
LOG=$(ls -t /tmp/m6_compile_*.log | head -1)
echo "errors: $(grep -ic 'error:' $LOG)"
echo "warnings: $(grep -ic 'warning' $LOG)"
ls -l libfstack.a
```

### 6.3 G3.1-3.3 test script (suggested)

```bash
# Start helloworld
cd /data/workspace/f-stack/example
sudo ./helloworld -c ../config.ini --proc-type=primary --proc-id=0 > /tmp/m6_helloworld.log 2>&1 &
sleep 5
# Add rule
cd ../tools/ipfw
sudo ./ipfw add 100 deny ip from 1.2.3.4 to any && \
sudo ./ipfw show | grep "00100 deny" && \
sudo ./ipfw delete 100 && \
echo "G3 PASS"
# Cleanup
/data/workspace/kill_process.sh helloworld
```

---

## 7. Self-consistency Check (within this spec)

| Check | Status |
|---|---|
| Every file:line reference resolves | ✅ (see §2.1 / §2.6 verification) |
| Every AC has executable commands | ✅ (§4 + §6) |
| Every risk has a mitigation | ✅ (§5) |
| Aligns with plan §3 M6 scope | ✅ |
| Aligns with plan §4 5-phase pipeline | ✅ |
| No TBD items | ✅ (all OQs were defaulted in plan §8) |

---

## 8. Pre-conditions for Phase B / C

| Pre-condition | Status |
|---|---|
| Spec 1.0 self-check passes | ✅ |
| Reviewer confirms no fatal gap | ⏳ Phase D inverse gate; skipped here; if Phase C uncovers an unbuildable spec, bounce(code → spec) applies |
| Standalone Phase B research-brief? | **No**; this spec already incorporates the scout findings (§2.5/§2.6/§2.7), Phase B merged in |

---

## 9. Progress

| Phase | Status |
|---|---|
| Phase A (this spec) | ✅ DRAFT done |
| Phase B (research) | merged into §2 (M6 has no standalone brief) |
| Phase C (code) | ⏭ pending |
| Phase D (review) | ⏭ |
| Phase E (gate G1-G7) | ⏭ |

---

> Next: enter **Phase C — coder**, apply the 2-line diff at `lib/Makefile:43-44`, kick off G1.
