# 39. Migration Guide for Already-Deployed Projects

> Applicable to: projects that have compiled and deployed f-stack with `FF_ZC_SEND=1`
> Goal: migrate from the old hacked approach (FSTACK_ZC_MAGIC + m_uiotombuf) to the new native approach (kern_zc_sendit + sosend(top)), with a transparent process and unchanged ABI

---

## §1 Migration Summary

| Dimension | Impact |
|---|---|
| Application-layer source | **Zero modification** (ff_zc_send / ff_zc_mbuf_get / ff_zc_mbuf_write signatures unchanged; example/main_zc.c needs no change) |
| Compile switch | `FF_ZC_SEND=1` unchanged (meaning shifts: from "enable hack" → "enable native path", transparent to the outside) |
| ABI / symbols | `ff_zc_send` single symbol unchanged; `ff_api.symlist` neither added to nor removed from |
| Recompile | **Required** (full rebuild of lib + example; see §3) |
| Kernel patch | Built into f-stack's bundled freebsd tree; users need not patch the upstream kernel themselves |
| Behavior change | Large-data send no longer crashes/hangs (issue #712); error-code semantics aligned with sosend(9); see §4 |

---

## §2 Upgrade Steps

### §2.1 Pull the new version

```
cd <project>/f-stack
git fetch origin
git checkout <new-tag-or-branch>      # includes this spec's implementation-phase commit
```

### §2.2 Force a full clean rebuild (avoid stale .o, the M2 lesson)

> **Critical warning**: During the M2 phase, incremental compilation skipped recompiling `uipc_mbuf.o`, which caused the ZC-send hook to be missing (see 21-m2-test-report.md §RCA). Although the new approach no longer depends on the m_uiotombuf hack, `kern_zc_sendit` is a newly added source file, so you **still MUST `make clean`** to ensure the old `uipc_syscalls.o` is replaced with the new one (containing kern_zc_sendit).

```
cd lib
PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig make clean
PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig FF_ZC_SEND=1 make
```

### §2.3 Verify the lib build artifact contains the new symbol

```
nm libfstack.a | grep -E "T (kern_zc_sendit|ff_zc_send)$"
```

Both should be hit (`kern_zc_sendit` from freebsd/kern/uipc_syscalls.o, `ff_zc_send` from lib/ff_syscall_wrapper.o).

### §2.4 Verify the old symbols are gone

```
grep -rn "FSTACK_ZC_MAGIC" freebsd/ lib/      # should be 0 hits
nm libfstack.a | grep -i magic                # should be 0 hits
```

### §2.5 Recompile the user server

```
cd ../example   # or the user's own server
PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig make clean
PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig FF_ZC_SEND=1 make
```

### §2.6 Start and smoke test

```
# start (keep the original startup method)
./helloworld_zc --conf /path/to/config.ini --proc-type=primary

# client smoke
ssh f-stack-client "curl -s -o /dev/null -w 'http=%{http_code}\n' http://<server-ip>/"
# expected: http=200
```

---

## §3 Behavior Changes (User-Perceived)

### §3.1 Unchanged Items

| Item | Old | New |
|---|---|---|
| ff_zc_send signature | `ssize_t ff_zc_send(int, const void *, size_t)` | Same |
| Call sequence (get → write → send) | Same | Same |
| Success return value | Byte count | Byte count |
| Error return | -1 + errno | -1 + errno |
| `FF_ZC_SEND` compile switch | Enable | Enable (but internally takes the native path) |

### §3.2 Changed Items

| Item | Old (hack) | New (native) |
|---|---|---|
| Large-data (> SO_SNDBUF) send | **crash/hang** (issue #712) | blocking sosend / non-blocking returns EWOULDBLOCK; caller must self-fragment |
| Error code EMSGSIZE (UDP > MTU) | Not covered by the old path, undefined behavior | Explicitly returns EMSGSIZE |
| Error code ENOBUFS (atomic buffer exhausted) | Old path non-standard | Explicitly returns ENOBUFS |
| Coexistence of plain ff_write/ff_writev with ZC | Required uio_offset=0 opt-out to prevent accidental triggering; GPF occurred during the M8 phase | No opt-out needed (the kern_writev path is unaware of ZC) |
| make incremental trap | Easily triggered (any stale .o among the 5 hacked files → bad chain) | Greatly reduced (only kern_zc_sendit is a new file); make clean still recommended |
| FreeBSD upstream upgrade | Re-audit of the ~120 lines around m_uiotombuf required | Almost non-intrusive; only need to check the sosend signature called by kern_zc_sendit |

### §3.3 Performance

Expected Δ ≤ ±3% (see 38-perf-baseline-spec.md PERF-2). The old approach and the new approach are behaviorally equivalent at the critical point of sosend skipping m_uiotombuf; the new approach's extra overhead is the `getsock + MAC` check at the kern_zc_sendit entry (consistent with kern_sendit), which also exists in the old approach when it takes the kern_writev path.

---

## §4 Caller Code Review Checklist

Although the ABI is unchanged, migrators **should** re-review whether the application-layer code touches the following "gray-area behaviors":

| # | Check | Old behavior | New behavior | Recommendation |
|---|---|---|---|---|
| 1 | Single ff_zc_send data size > SO_SNDBUF | crash/hang | EWOULDBLOCK / blocking | Self-fragment: `for (chunks of MIN(SNDBUF, total))` |
| 2 | UDP single packet > MTU | undefined behavior | EMSGSIZE | Split into multiple packets |
| 3 | TCP socket + MSG_EOR | old API did not expose flags | new API exposes it, returns EINVAL immediately (uipc_socket.c:2354) | Do not set MSG_EOR on TCP |
| 4 | Accessing zc_buf.bsd_mbuf again after ff_zc_send | UAF (old also) | UAF (new strong spec 35 INV-2 explicitly forbids) | Discard the pointer immediately after send |
| 5 | Expecting ff_zc_send to "send exactly however many nbytes you pass" | yes | actually sent = top->m_pkthdr.len (i.e., cumulative ff_zc_mbuf_write writes) | Ensure nbytes >= cumulative write amount |

---

## §5 Rollback Plan

If the new approach triggers an unexpected error in production:

### §5.1 Emergency shutdown of ZC (no recompile)

Cannot be disabled directly — `FF_ZC_SEND` is a compile-time switch. A recompile is required.

### §5.2 Recompile as a non-ZC version (fastest)

```
cd lib
PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig make clean
PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig make            # without FF_ZC_SEND
```

If the application code still calls `ff_zc_send`, it will produce a link error; runtime switching via conditional compilation or dynamic dispatch is recommended:

```c
#ifdef FSTACK_ZC_SEND
    n = ff_zc_send(fd, zc_buf.bsd_mbuf, len);
#else
    /* fallback to ff_writev with normal char* buffer */
    n = ff_write(fd, char_buf, len);
#endif
```

→ This requires the application layer to maintain **two send paths**; at the ABI level, ff_zc_send does not exist without `FSTACK_ZC_SEND`.

### §5.3 git revert to the old hacked version

```
git revert <new-impl-commit>      # roll back to before the commit
make clean && make
```

The old hacked version is still available in historical commits, but it will no longer be retained on master after this spec implementation is complete.

---

## §6 Pre-Upgrade Self-Check Checklist

| # | Check item | Pass criterion |
|---|---|---|
| 1 | Does your application use `FF_ZC_SEND`? | No → no impact; Yes → continue |
| 2 | Has your application run the issue #712 scenario (large-packet send)? | Yes → upgrade strongly recommended (fixes the crash) |
| 3 | Does your application pass nbytes < the actual cumulative write amount when calling ff_zc_send? | Yes → fix before upgrading |
| 4 | Does your application access zc_buf.bsd_mbuf again after ff_zc_send? | Yes → fix before upgrading (INV-2 violation) |
| 5 | Has your deployment ever encountered stale-.o-type problems? | Yes → be sure to `make clean` during the upgrade |
| 6 | Did you fork f-stack's bundled freebsd tree and patch it yourself? | Yes → merge conflicts during the upgrade; refer to the 31 deletion list |

---

## §7 Temporary-File / Process Cleanup Regulation

> Important: temporary files, build residue, and stale processes produced during the upgrade and rollback process **must** be handled via the regulation scripts; see §2.2 / §5.

| Operation | Script that must be used |
|---|---|
| Clean up stale `.o`, build intermediate artifacts | `/data/workspace/rm_tmp_file.sh <abs-path>...` |
| Clean up hugepage rtemap | `/data/workspace/rm_tmp_file.sh /dev/hugepages/rtemap_*` (note: actual use requires first running `ls` to obtain the concrete file path list) |
| Terminate the server process | `/data/workspace/kill_process.sh <pid>` or `<process_name_pattern>` |
| Add +x to a new script | `/data/workspace/chmod_modify.sh +x <abs-path>` |

Direct `rm`/`kill`/`pkill`/`chmod` command strings are not allowed to appear in upgrade docs/scripts.

---

## §8 FAQ

**Q1: Does example/main_zc.c need to change after the upgrade?**
No. This spec's ABI-invariance clause (G4) guarantees that the ZC call sequence at example/main_zc.c L208-245 passes with zero modification.

**Q2: Can the old compiled server binary still be used after the upgrade?**
It cannot be reused directly. `kern_zc_sendit` is a new symbol; the old lib that the old binary linked against does not contain this symbol; the server binary needs to be recompiled.

**Q3: Will performance degrade?**
Expected Δ ≤ ±3% (within noise). The new path is behaviorally equivalent at the critical point of sosend(top) skipping m_uiotombuf; the extra getsock+MAC is consistent with kern_sendit and also exists in the old approach. See 38-perf-baseline-spec.md.

**Q4: Can it still be enabled simultaneously with `FF_USE_PAGE_ARRAY` / `FF_ZC_RECV`?**
Yes. The three are mutually independent; the new approach keeps the switches independent (any combination of `FF_ZC_SEND` / `FF_ZC_RECV` / `FF_USE_PAGE_ARRAY`).

**Q5: When FreeBSD upstream is upgraded again, will the new approach be more stable than the old one?**
Yes. The new approach only adds `kern_zc_sendit` (does not modify sosend internals, does not modify m_uiotombuf); on an upstream upgrade you only need to verify whether the `sosend(...)` signature has changed (rare), making the migration cost far lower than the m_uiotombuf re-audit of the old approach.

---

## §9 Gatekeeper-Verifiable Clauses (gatekeeper)

| Clause | Verification method | Pass criterion |
|---|---|---|
| M-G1 | spec lists ABI unchanged items and changed items | Tables hit |
| M-G2 | spec lists the necessity of `make clean` | §2.2 + §3.2 |
| M-G3 | spec does not contain direct rm/kill/chmod commands | Automated grep |
| M-G4 | spec lists a rollback plan | §5 |

---

Next: **40-acceptance-and-milestones.md** (acceptance + M0-M5 milestones).
