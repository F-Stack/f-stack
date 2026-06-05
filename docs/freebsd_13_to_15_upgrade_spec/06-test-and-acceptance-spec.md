# 06 — Test & Acceptance Spec

> Chinese version: ./zh_cn/06-test-and-acceptance-spec.md
>
> Series root: `/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/`
> Document version: v0.1 (2026-05-26)
> Input: FR-5 / FR-6 / NFR-1 from `01-requirements-spec.md`
> Audience: Implementation engineers + Reviewer + QA

---

## 1. Test Overview

```
Build test (FR-5)  →  Unit/Interface test  →  Functional cases (FR-6)  →  Performance baseline (NFR-1)  →  Regression
```

The corresponding stage runs at the end of each milestone, serving as the exit gate.

---

## 2. Compile Matrix (FR-5)

### 2.1 Matrix dimensions

| Dimension | Values |
|---|---|
| Compiler | clang 12 / clang 16 / GCC 10 / GCC 12 |
| Architecture | x86_64 (mandatory), arm64 (recommended) |
| DPDK version | the current LTS (kept unchanged, constraint C-3) |
| `WITH_IPSEC` KNOB | OFF / ON |
| `WITH_NETGRAPH` KNOB | OFF / ON |
| `WITH_IPFW` KNOB | OFF / ON |

### 2.2 Build acceptance criteria (per matrix cell)

| Check | Criterion |
|---|---|
| `libff.a` produced | must succeed |
| All `tools/` build targets produced (measured against per-subdir Makefile targets, corrected 2026-05-28) | 17 subdirs total: **11 PROG (user-space commands)** = 9 freebsd-native (`arp` / `ifconfig` / `ipfw` / `ndp` / `netstat` / `ngctl` / `route` / `sysctl` / `knictl`) + 2 F-Stack-shipped (`top` / `traffic`); **4 LIB targets** = `libmemstat`→LIB=memstat / `libnetgraph`→LIB=netgraph / `libutil`→LIB=util / `libxo`→LIB=xo; **2 helper subdirs**: `compat/` (placeholder, no Makefile target) / `sbin/` (no Makefile). The actual F-Stack ff_* wrapper names: `ff_arp` / `ff_ifconfig` / `ff_ipfw` / `ff_ndp` / `ff_netstat` / `ff_ngctl` / `ff_route` / `ff_sysctl` / `ff_top` / `ff_traffic` (`knictl` typically does not get the `ff_` prefix; `libmemstat` etc. are libraries, no `ff_` prefix). **All 11 PROG binaries + 4 LIB static/shared library targets must build successfully; see `99-review-report.md` §12.9** |
| Errors | 0 |
| New warnings | 0 (vs 13.0 baseline). New warnings must be explicitly recorded in `99-review-report.md` and tagged P2/P3 |
| Build time | regression ≤ 30% (informational, not enforced) |

### 2.3 Compile-matrix run

```bash
# Take baseline before upgrade starts
cd /data/workspace/f-stack
make clean && make 2>&1 | tee build-13.0-baseline.log

# Repeat at end of each milestone
make clean && make 2>&1 | tee build-M<N>.log
diff build-13.0-baseline.log build-M<N>.log
```

---

## 3. Functional Acceptance Cases (FR-6 → 9 cases)

### 3.1 Case list

| Case ID | Name | Type | Priority |
|---|---|---|---|
| TC-01 | Single-lcore startup + DPDK NIC binding + IP configuration | startup | P0 |
| TC-02 | TCP echo service (IPv4) round-trip | data plane | P0 |
| TC-03 | UDP echo service (IPv4) round-trip | data plane | P0 |
| TC-04 | TCP echo service (IPv6) round-trip | data plane | P1 |
| TC-05 | `ff_ifconfig` interface configuration + query | control plane | P0 |
| TC-06 | `ff_netstat -an` socket-state query | control plane | P0 |
| TC-07 | `ff_ipfw add allow tcp from ...` rule install + query | control plane | P1 |
| TC-08 | `ff_route add` route install + `ff_route get` query | control plane | P0 (most affected by rib/nexthop rewrite) |
| TC-09 | `ff_ngctl` netgraph node creation + connection | control plane | P2 |

### 3.2 Per-case standard format

Every case in the test report must contain:

```
TC-XX: case name
  Preconditions:
    - config.ini content (minimal)
    - NIC count and binding state
  Steps:
    1. ./fstack --config config.ini &
    2. <verification operation>
  Expected:
    - exit code 0
    - stdout contains keyword "..."
    - <data-plane case> packet loss = 0
  Actual:
    - <fill in>
  Pass/Fail:
    - <PASS / FAIL>
```

### 3.3 TC-01..TC-09 minimal-executable mapping (added 2026-05-28; addresses audit §6.2-4)

> This section addresses independent audit P2-007: "TC-01..TC-09 only have names and templates; the actual F-Stack example program, config file, NIC binding command, expected stdout keyword have not been specified".
> Data source (measured 2026-05-28): `/data/workspace/f-stack/example/Makefile` (artifacts `helloworld` / `helloworld_epoll`, sources `main.c` / `main_epoll.c`, with `#ifdef INET6` dual-stack branch); `/data/workspace/f-stack/config.ini` (standard entry config with `[dpdk] lcore_mask / port_list / numa_on` etc.); `/data/workspace/f-stack/tools/{arp,ifconfig,ipfw,ndp,netstat,ngctl,route,sysctl,knictl,top,traffic}/` command tool set (see §2.2).
> The current F-Stack repo has **no standalone UDP / IPFW / NETGRAPH example**; TC-03 / TC-07 / TC-09 are marked "to be filled at the M1 prep stage". **Do not fill paths by guessing**.

| TC | example program | minimal config fields | NIC / pre-command | stdout expected keyword (PASS marker) | measured precondition |
|---|---|---|---|---|---|
| **TC-01** | `example/helloworld` | `[dpdk] lcore_mask=1, channel=4, promiscuous=1, numa_on=1, allow=<PCI>, port_list=0; [port0] addr=192.168.1.2/24, gateway=192.168.1.1` | `dpdk-devbind.py --bind=vfio-pci <PCI>` then `./helloworld --conf config.ini` | DPDK boot banner (`EAL: Detected ...`) + listening port (`f-stack helloworld start, port=80`, see main.c lines 124-217 with `ff_init` / `ff_run`); no panic / 0 exit | at least 1 DPDK-compatible NIC; 2MB×1024 hugepages |
| **TC-02** | same as TC-01 | same as TC-01; `port_list=0` | After TC-01 boots, on the external host `curl http://192.168.1.2/` | external host receives the `<html>...</html>` static page (string hardcoded at top of main.c); helloworld stdout shows accept/read/write log | TC-01 PASS |
| **TC-03** | (to be filled at M1 prep stage; the F-Stack repo has no standalone UDP example; suggest changing main.c socket type to `SOCK_DGRAM` or adding `main_udp.c`) | UDP listening-port fields (TBF) | TBF | TBF | to be filled after M1 measurement |
| **TC-04** | `example/helloworld` (compile-time `INET6` defined; main.c lines 165-169 already have `sockfd6` dual-stack branch) | TC-01 + `[port0] addr6=2001:db8::2/64` | `./helloworld --conf config.ini`; on the external host `curl -6 'http://[2001:db8::2]/'` | same as TC-02 but over IPv6; helloworld stdout same as TC-02 path | TC-01 + IPv6 uplink |
| **TC-05** | F-Stack tools/ifconfig (artifact `ff_ifconfig`) | reuse TC-01 config | `./ff_ifconfig f-stack-0 inet 192.168.1.2/24 alias`; query `./ff_ifconfig -a` | output contains `f-stack-0: ... inet 192.168.1.2 netmask 0xffffff00` (freebsd ifconfig standard format) | helloworld already running (provides ff_ipc channel) |
| **TC-06** | F-Stack tools/netstat (artifact `ff_netstat`; same source as freebsd `tools/netstat/main.c`) | reuse TC-01 config | `./ff_netstat -an` | output `Active Internet connections (including servers)` header + at least one `tcp4 ... LISTEN` row (i.e. helloworld listening on port 80) | TC-01 PASS |
| **TC-07** | F-Stack tools/ipfw (artifact `ff_ipfw`) | reuse TC-01 config; `f-stack.conf` enables `FF_IPFW=1` (see 04 §2.13 NETIPFW_SRCS) | `./ff_ipfw add 100 allow tcp from any to me 80` then `./ff_ipfw list` | output `00100 allow tcp from any to me dst-port 80` (freebsd ipfw standard format) | compiled with `FF_IPFW=1`; helloworld already running |
| **TC-08** | F-Stack tools/route (artifact `ff_route`) | reuse TC-01 config | `./ff_route add -net 10.0.0.0/8 192.168.1.1` then `./ff_route get 10.1.2.3` | output `route to: 10.1.2.3` + `gateway: 192.168.1.1` (after the rib/nexthop rewrite this output must still be produced; this is an R-014 acceptance point) | helloworld already running; R-014 ff_route.c rewritten to rib/nexthop API (M3-end acceptance) |
| **TC-09** | (to be filled at M1 prep stage; the F-Stack repo has no standalone NETGRAPH example); the `ff_ngctl` artifact exists but needs `FF_NETGRAPH=1` build | reuse TC-01 config + enable `FF_NETGRAPH=1` (see 04 §2.9) | TBF; suggest referencing freebsd `ngctl mkpeer` / `ngctl list` usage | TBF; at minimum `ff_ngctl list` should output `There are X total nodes:` header | compiled with `FF_NETGRAPH=1`; helloworld already running; pending M1 measurement |

> Implementation constraint: of the 9 rows above, except TC-03 / TC-09 marked "to be filled at the M1 prep stage", the other 7 rows have example programs, config fields, and tool commands corresponding 1:1 to actual F-Stack repo artifacts. **TC-03 / TC-09 must, at the M1 implementation phase, first measure whether the corresponding example needs to be added (e.g. `main_udp.c` / `main_ng.c`) before back-filling the corresponding row in this table**.
> If example absence blocks a TC, record "TC-XX BLOCKED, missing example" in 99 §6 implementation-progress tracking, and open a T-example-XX task.

### 3.4 Subset of cases per milestone

| Milestone | Cases to run |
|---|---|
| End of M2 | (build only, no functional run) |
| End of M3 | TC-01 / TC-02 (minimal startup + TCP echo) |
| End of M4 | TC-01 / TC-02 / TC-03 / TC-05 |
| **End of M5** | **All 9 cases** (FR-6 acceptance) |

---

## 4. Unit / Interface Tests (for P0 tasks)

### 4.1 ff_glue.c (T-ff-01) unit

| Test point | Expectation |
|---|---|
| `pru_*` fields invoked directly on `protosw` (no longer via `pr_usrreqs`) | builds; the socket-create path works |

### 4.2 ff_veth.c (T-ff-02) unit

| Test point | Expectation |
|---|---|
| `if_alloc(IFT_ETHER)` returns `if_t` (typedef of `struct ifnet *`; in 13.0 the API directly returned `struct ifnet *`) | type-compatible; F-Stack's own ifp manipulation uniformly goes through `if_get*/if_set*` accessors and does not directly depend on field layout |
| `if_setflags / if_getflags / if_setname` accessors | semantics equivalent to direct field access in 13.0 |

### 4.3 ff_route.c (T-ff-03) unit

| Test point | Expectation |
|---|---|
| `rtinit` accepts the new `rib` + `nexthop` API | route-table entries can be added |
| `ff_route` user-space tool interacts with the kernel rib table | TC-08 PASS |

### 4.4 ff_subr_epoch.c (T-ff-04) unit

| Test point | Expectation |
|---|---|
| inpcb hash lookup on the SMR path does not panic | TC-02 / TC-04 do not hang |

### 4.5 uipc_mbuf.c FSTACK_ZC_SEND (T-kern-12) unit

| Test point | Expectation |
|---|---|
| `m_uiotombuf` takes the ZC path (iov_base hung directly on m_ext) | large-packet send performance does not regress |
| New `m_ext` fields (refcnt/ext_type rearrangement) | no use-after-free / double-free |

---

## 5. Performance Baseline (NFR-1)

### 5.1 Baseline metrics

| Metric | Tool | Expectation |
|---|---|---|
| Single-flow TCP throughput (loopback) | iperf3 / pktgen | regression ≤ 5% |
| Single-flow UDP PPS | dpdk-pktgen | regression ≤ 5% |
| Short-connection QPS (HTTP echo) | wrk2 | regression ≤ 5% |
| Connection-establishment latency P99 | wrk2 | regression ≤ 10% |
| Single-core lcore CPU utilization (under saturation) | perf top | no regression (absolute value informational only) |

### 5.2 Baseline collection timing

```
Before upgrade starts: collect on the 13.0 baseline → baseline-perf-13.0.json
End of M5: collect on the 15.0 upgrade → perf-15.0.json
Compare: diff the two; record into 99-review-report.md
```

### 5.3 How "performance gain" from RACK-as-default is recorded

The 15.0 default TCP stack contains RACK improvements that may yield throughput gains. Such **gains** are recorded as bonus benefits and do not offset any non-regression requirement; if a regression appears in some scenario, it must still be tracked under NFR-1.

### 5.4 Bare-metal baseline filed (run by external team; received 2026-06-05)

**Data source**: iWiki 4021545579 (the external OSPF/CMC project team ran a 13.0 vs 15.0 paired test on a Intel Xeon 8255C @ 2.5 GHz + Mellanox CX-5 100 G + TencentOS 4.4 + Linux 6.6.98 bare-metal rig).

**Relation to this project's CVM same-timeline A/B**: the bare-metal data is an **external baseline**; the CVM data is this project's **internal A/B**. Together they form a dual baseline crossing the virtualization layer; detailed delta analysis is in `physical-machine-bench-report.md` §5.

#### 5.4.1 helloworld single-core long-conn (NFR-1 single-flow TCP throughput)

| Metric | 13.0 | 15.0 | Δ | NFR-1 threshold | Pass |
|---|---:|---:|---:|---|:---:|
| Req/sec | 958,109 | 1,056,178 | **+10.24%** | regression ≤ 5% | ✓ (net gain) |
| p50 | 121 us | 107 us | -11.57% | — | — |
| p99 | 204 us | 197 us | -3.43% | regression ≤ 10% | ✓ |

#### 5.4.2 nginx_fstack long-conn (NFR-1 long-conn QPS, informational)

| lcores | 13.0 (Req/s) | 15.0 (Req/s) | Δ | Pass |
|---:|---:|---:|---:|:---:|
| 1 | 314,889 | 330,837 | **+5.06%** | ✓ |
| 2 | 623,962 | 653,648 | **+4.76%** | ✓ |
| 4 | 1,230,502 | 1,289,872 | **+4.83%** | ✓ |

#### 5.4.3 nginx_fstack short-conn (NFR-1 short-conn QPS)

| lcores | 13.0 (Req/s) | 15.0 (Req/s) | Δ | NFR-1 threshold | Pass |
|---:|---:|---:|---:|---|:---:|
| 1 | 127,592 | 124,727 | -2.25% | regression ≤ 5% | ✓ |
| 2 | 256,208 | 246,873 | -3.65% | regression ≤ 5% | ✓ |
| 4 | 406,380 | 381,614 | **-6.10%** | regression ≤ 5% | ⚠ **over threshold by 1.10 pp** |

#### 5.4.4 Key verdicts

1. **Overall PASS**: bare-metal helloworld + nginx long-conn show a clear +5%~+10% net gain; short-conn 1/2 cores stay within NFR-1 threshold.
2. **Observation item**: nginx short-conn 4 cores at -6.10% **exceeds the 5% threshold by 1.10 pp**. Per NFR-1 this triggers a review; disposition options are recorded in `physical-machine-bench-report.md` §6.2 (preferred: file as a trade-off — the 5 P0 SIGSEGV fixes are strictly more valuable than a -6% on multi-core short-conn; optional: do a bare-metal perf bi-version flame-graph overlay to localize sonewconn / accept / kern_descrip paths).
3. **Cross-platform reversal**: the bare-metal helloworld +10% and the CVM same-timeline helloworld -7%~-9% point in opposite directions. `13.0-baseline-cvm-bench-report.md` §11.5 perf flame-graph attributes this to the virtio path overhead being amplified in narrow channels; **the reversal does not refute the upgrade** — instead it confirms that the vendor evolution gains (RACK / CUBIC / sb_locking) are fully released on bare metal that has no virtio interference.

**Detailed comparison, raw wrk output, cross-platform reading, and NFR-1 acceptance matrix**: see `physical-machine-bench-report.md`.

---

## 6. Regression Tests

### 6.1 Hand-off with existing F-Stack case set

If the F-Stack repo already has example/ helloworld example or nginx_fstack-paired tests, run them once at end of M5 as regression.

### 6.2 Packet-capture verification

| Case | Verification point |
|---|---|
| TC-02 capture | TCP three-way-handshake fields (SEQ/ACK/Flags) match the 13.0 baseline |
| TC-03 capture | UDP checksum correct |
| TC-04 capture | IPv6 header length / extension-header consistent |

---

## 7. Acceptance Gate Summary

| Gate | Phase | Pass condition |
|---|---|---|
| **G-M1** | End of M1 | mips deleted; libkern/ etc. cp -a done; one matrix cell builds (default compiler + x86_64 + default KNOB) |
| **G-M2** | End of M2 | KERN_SRCS builds; ff_subr_epoch.c builds |
| **G-M3** | End of M3 | libff.a builds completely; TC-01 / TC-02 PASS |
| **G-M4** | End of M4 | The full compile matrix passes; TC-01 / TC-02 / TC-03 / TC-05 PASS |
| **G-M5** | End of M5 | All 9 TCs PASS; performance baseline meets target; libff ABI review shows no surprises; reviewer issues 99 report |
| **G-Acceptance** | Project end | All gates pass; reviewer signs off |

---

## 8. Test Environment Requirements

| Item | Requirement |
|---|---|
| Hardware | x86_64 server; ≥ 2 NICs (one bound to DPDK, one for the host) |
| OS | Linux (F-Stack actually runs on Linux) |
| Compiler | GCC 10+ or clang 12+ |
| DPDK | Current LTS (compatible with the existing F-Stack version) |
| Test tools | iperf3 / wrk2 / tcpdump / dpdk-pktgen / perf |

---

## 9. Test Report Template (deliverable at end of M5)

```markdown
# F-Stack 13→15 Upgrade Test Report

## 1. Compile-matrix results
| Compiler × Arch × KNOB | libff.a | tools binaries | errors | new warnings |
|---|---|---|---|---|
| ... | ✓ | 12/12 | 0 | 0 |

## 2. Functional case results
| TC-ID | Pass/Fail | Note |
|---|---|---|
| TC-01 | PASS | |
| TC-02 | PASS | |
| ... |

## 3. Performance baseline comparison
| Metric | 13.0 | 15.0 | Δ | Pass |
|---|---|---|---|---|
| TCP throughput | X Gbps | Y Gbps | +Z% | ✓ |
| ... |

## 4. Known defects and TODOs
- [ ] ...

## 5. Sign-off
- Implementation engineer: ____
- Reviewer: ____
- Tech Lead: ____
```

---

## 10. Hand-off to Other Documents

| Artifact from this section | Hand-off target |
|---|---|
| Compile matrix | per-milestone exit criteria in `05-implementation-plan.md` §2 |
| TC-01..09 | FR-6 acceptance in `01-requirements-spec.md` |
| Performance baseline | NFR-1 acceptance in `01-requirements-spec.md` |
| §5.4 bare-metal baseline | `physical-machine-bench-report.md` (iWiki 4021545579 external-team data, post-processed in-project) |
| §5 CVM same-timeline A/B | `13.0-baseline-cvm-bench-report.md` (this project's helloworld single-core + perf root cause) |
| Gate G-M1..G-M5 | cadence in `05-implementation-plan.md` §1.1 |
| Test report template | referenced as appendix from `99-review-report.md` |

---

## 11. Things Out of Scope of This Test

| Item | Note |
|---|---|
| netlink compatibility test | DP-2 does not introduce netlink |
| Post-quantum TLS test | C-1 does not introduce |
| pkgbase install test | F-Stack does not depend on base |
| Fuzz tests / large-scale soak tests | Not scheduled for the Spec phase; tracked separately under follow-up QA |
| Cross IPv4-IPv6 dual-stack complex scenarios | After basic TC-02/04 pass, additional cases supplemented by QA team |
