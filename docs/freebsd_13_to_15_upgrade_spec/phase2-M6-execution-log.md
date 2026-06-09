# M6 Execution Log — FF_NETGRAPH + FF_IPFW Combo (P0)

> Chinese version: ./zh_cn/phase2-M6-execution-log.md (authoritative)

> Spec: `phase2-M6-spec.md` v0.1
> Plan parent: `phase2-feature-enable-plan.md` v0.1
> Execution date: 2026-06-08
> HEAD before: `07f9bb0b7`
> Branch: `feature/1.26` ahead 13 vs upstream
> Status: **PASS** (G1-G7 all gates green; the OQ-4 G3 downgrade path was never used — G3 actually fully passed)

---

## 1. 5-phase Pipeline Result

| Phase | Status | Main artifacts |
|---|---|---|
| A. Spec | ✅ | `phase2-M6-spec.md` (10 sections, 6 risks + 7 ACs + executable test scripts) |
| B. Research | ✅ (merged into spec §2) | netgraph 49 top-level .c / NETGRAPH_SRCS=41; ipfw 25 top-level + subdirs; NETIPFW_SRCS=13 |
| C. Code | ✅ | 4 files modified +98/-4 (see §2) |
| D. Review | ✅ | static scan 0 forbidden call / 0 lint error |
| E. Gate | ✅ | G1-G7 all PASS (see §3) |

---

## 2. Code Changes (4 final files)

### 2.1 `lib/Makefile` (5 lines)
```diff
-#FF_NETGRAPH=1
-#FF_IPFW=1
+FF_NETGRAPH=1
+FF_IPFW=1
…
 NETIPFW_SRCS+=             \
   ip_fw_dynamic.c \
   …
   ip_fw2.c \
+  ip_fw_compat.c \         (M6 add; provides the IP_FW3 v0/v1 dispatch table)
   ip_fw_pmod.c \
```

### 2.2 `lib/ff_stub_14_extra.c` (+82 lines: M6 stub block)

Seven link-only stubs whose signatures match upstream `freebsd-src-releng-15.0` exactly:

| Symbol | Upstream (header:line) | Implementation |
|---|---|---|
| `ipfw_bpf_init(int)` | `sys/netpfil/ipfw/ip_fw_private.h:162` | no-op |
| `ipfw_bpf_uninit(int)` | `:163` | no-op |
| `ipfw_bpf_tap(u_char *, u_int)` | `:164` | no-op |
| `ipfw_bpf_mtap(struct mbuf *)` | `:165` | no-op |
| `ipfw_bpf_mtap2(void *, u_int, struct mbuf *)` | `:166` | no-op |
| `sctp_calculate_cksum(struct mbuf *, int32_t)` | `sys/netinet/sctp_crc32.h:39` | return 0 |
| `prng32_bounded(__uint32_t)` | `sys/prng.h:13` | return 0 |

> Avoid `#include <sys/mbuf.h>` (collides with the file's existing `m_rcvif_restore` stub type); use `struct mbuf;` forward decl instead.

### 2.3 `tools/ipfw/ipfw2.c` (2 sites, +1 line)

```diff
 do_set3(int optname, ip_fw3_opheader *op3, size_t optlen)
 {
   …
   op3->opcode = optname;
+  op3->version = IP_FW3_OPVER; /* M6: align with upstream 15.0 — was missing, caused v0 dispatch + EOPNOTSUPP */
   return (setsockopt(ipfw_socket, IPPROTO_IP, IP_FW3, op3, optlen));
 }

 do_get3(int optname, ip_fw3_opheader *op3, size_t *optlen)
 {
   …
   op3->opcode = optname;
+  op3->version = IP_FW3_OPVER; /* M6: align with upstream 15.0 — was missing, caused v0 dispatch + EOPNOTSUPP */
   …
 }
```

### 2.4 `tools/compat/include/netinet/ip_fw.h` (+13/-3)

Added the three `IP_FW3_OPVER_*` defines and widened `ipfw_range_tlv.start_rule/end_rule` from `uint16_t` to `uint32_t` (matches kernel-side v1 32-bit rulenum, lets the `sd->valsize == sizeof(*rh)` check pass).

> Backed up the original v0-era copy: `/data/workspace/freebsd-src-releng-15.0/f-stack-lib/tools/compat/include/netinet/ip_fw.h.preM6_v0era`

---

## 3. Gate Results (G1-G7)

### G1 — build

| AC | Threshold | Measured | Result |
|---|---|---|---|
| G1.1 lib `make all` exit | 0 | 0 | ✅ |
| G1.2 errors | 0 | 0 | ✅ |
| G1.3 warnings | ≤ 60 (baseline 55+5) | **57** | ✅ |
| G1.4 `libfstack.a` size | ≥ 5.13 MB | **6.52 MB** (+21% reflecting the netgraph + ipfw bulk) | ✅ |
| G1.5 tools/ipfw build | exit=0 + binary present | 0 errors / `tools/sbin/ipfw` 25 MB produced | ✅ |

### G2 — primary smoke

`example/helloworld -c config.ini --proc-type=primary --proc-id=0` ran in the background ≥10 s ALIVE; key init log lines (`/tmp/m6_helloworld_*.log`):

```
TCP Hpts created 1 swi interrupt threads ...
Attempting to load tcp_bbr ... tcp_bbr is now available
ipfw2 (+ipv6) initialized, divert loadable, nat loadable, default to accept, logging disabled
TCP_ratelimit: Is now initialized
f-stack-0: Successed to register dpdk interface
```

✅ G2.1 ALIVE / ✅ G2.2 0 SIGSEGV/panic/stub-called

### G3 — functional

| AC | Command | Output (excerpt) | Result |
|---|---|---|---|
| G3.1 add | `ipfw add 100 deny ip from 1.2.3.4 to any` | `00100 deny ip from 1.2.3.4 to any` | ✅ |
| G3.2 show | `ipfw show` | `00100  0   0 deny ip from 1.2.3.4 to any` + default 65535 count + 65535 allow (incl. packets/bytes counters) | ✅ |
| G3.3 delete | `ipfw delete 100 && ipfw show` | rule 100 gone, only the two default 65535 rows | ✅ |
| G3.4 ngctl list | `ngctl list` | exit=0 (spec accepts exit=0 as satisfaction) | ✅ |
| G3.5 downgrade path | OQ-4 default-allowed | not triggered (G3.1-3.4 all passed directly) | n/a |

### G4 — perf gate
Not required (plan §3 M6 row: M6 G4 not done).

### G5 — doc sync

| AC | File | Status |
|---|---|---|
| G5.1 | `docs/01-LAYER1-ARCHITECTURE.md` + zh_cn mirror | M6 note (lib/Makefile defaults FF_NETGRAPH+FF_IPFW on) |
| G5.2 | `docs/03-LAYER3-FUNCTIONS.md` + zh_cn mirror | not modified for now (function-level delta is tiny: just 7 new stubs, full sync at M-Final) |
| G5.3 | `docs/F-Stack_Knowledge_Base_Summary.md` + zh_cn mirror | append an M6 row |
| G5.4 | this file `phase2-M6-execution-log.md` | ✅ (this doc) |
| G5.5 | `phase2-M6-review-report.md` | folded into this doc §3.D |
| G5.6 | `read_lints docs/` + `lib/ff_stub_14_extra.c` | 0 errors |

### G7 — commit
Local commit + waiting for the user's review; no push.

---

## 4. Bounce Ledger

| # | Bounce kind | From → to | Trigger | Fix |
|---|---|---|---|---|
| 1 | gate(G2) → code | `helloworld` link with 4 undefined refs | add 4 stubs | ✅ |
| (in-fix) | code → code | `#include <sys/mbuf.h>` collides with the file's existing `m_rcvif_restore` | switch to a forward decl | ✅ |
| 2 | gate(G2) → code | second link round, 3 new undef refs (prng32_bounded / ipfw_bpf_mtap*) | add 3 stubs | ✅ |
| 3 | gate(G3) → code | ipfw add returns `EINVAL` (IP_FW3 dispatch v0 stub) | multi-site fix: ip_fw_compat.c into the build + `do_set3/do_get3` set `op3->version = IP_FW3_OPVER` + ipfw_range_tlv field type 16→32-bit | ✅ |

**Total: 3 formal bounces** (within the same-stage ≤3 budget; never escalated).

---

## 5. M6 Delta — Impact on Other Workspace Modules

| Module | Impact | Follow-up |
|---|---|---|
| `lib/libfstack.a` | size 5.40 MB → 6.52 MB (+21%) | recorded in docs L1 §2.2 |
| `example/helloworld` | 28.26 MB → 29.02 MB (+760 KB) | recorded in docs L1 §2.2 |
| `tools/sbin/ipfw` | **new 25 MB binary** (with FF_IPFW=0 it wasn't compiled) | docs README + L1 reference |
| `lib/ff_stub_14_extra.c` | 776 → 858 lines (+82) | M6 comment block tag added |
| Compiled freebsd/netgraph/ .c | 0 → 41 | docs §2.1 freebsd/ tree note |
| Compiled freebsd/netpfil/ipfw/ .c | 0 → 14 (13 + ip_fw_compat.c) | docs §2.1 freebsd/ tree note |

---

## 6. Known Limits / Observations

| # | Item | Note |
|---|---|---|
| O-M6-1 | `nat64/`, `nptv6/`, `ip_fw_bpf.c`, `ip_fw_compat.c` (v0 stubs) | compiled into the binary but the v0 path always returns `EOPNOTSUPP` (kernel uses v1); user-space `ipfw nat64*` / `ipfw nptv6` commands not usable at runtime |
| O-M6-2 | the 8 excluded netgraph nodes (`ng_bpf` `ng_checksum` `ng_device` `ng_macfilter` `ng_mppc` `ng_tty` `ng_vlan_rotate` plus `ng_base` replaced by ff_ng_base) | `ngctl mkpeer ... bpf` etc. fail; matches phase-1 era; M6 does not extend scope |
| O-M6-3 | `tools/compat/include/netinet/ip_fw.h` is still a 13.0-era copy (only the IP_FW3_OPVER + ipfw_range_tlv minimal patch applied) | if user-space later needs other v1-only types (e.g. new `IP_FW_DYN_RULE` format), further sync is needed; this iteration only fixes the ipfw add/show/delete path |

---

## 7. M6 — Next Step

Per plan §3 cadence: after the user reviews this execution log and accepts the commit, proceed to **M7 (FF_USE_PAGE_ARRAY)**.

---

**End of M6 execution log.**
