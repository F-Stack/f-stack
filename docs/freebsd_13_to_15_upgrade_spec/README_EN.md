# F-Stack FreeBSD 13.0 → 15.0 Upgrade Project — English Brief

> **Note**: The detailed spec markdown collection (47 documents) is maintained in Chinese under `zh_cn/`, by project design — see `zh_cn/plan.md:4` ("English version deferred until after human audit"). The top-tier 3-layer architecture documentation under `docs/01-LAYER1-ARCHITECTURE.md`, `docs/02-LAYER2-INTERFACES.md`, and `docs/03-LAYER3-FUNCTIONS.md` is **fully bilingual** and already contains anchors to every phase below.
>
> **Authoritative project-level closure (Chinese)**: `zh_cn/00-project-closure.md`

## Status

✅ **CLOSED — temporarily wrapped up on 2026-06-09**

## Scope

Port F-Stack from FreeBSD 13.0-RELEASE to FreeBSD 15.0-RELEASE, retaining the full TCP/IP stack with all DPDK / netinet / netinet6 / net/route + FIB rework / netgraph / ipfw / vlan / KTLS-stub coverage, on the v1.26 branch.

## Phases delivered (26 ahead commits, 47 spec markdowns)

| Phase | Outcome |
|---|---|
| **M0–M1** spec writing | 9-document spec set + reviewer audit (`99-review-report.md`) |
| **M2** kern subsystem application | 10 kern files via 5-step procedure (DP-M2-5 option-B remainder closed in Phase-5b) |
| **M3** netinet/netinet6 application | 4-gradient parallel agent execution; 4×3 build matrix all green |
| **M4** lib/ff_*.c R-013/R-004 ABI adaptation | Edge subsystem upgrade (spec 05 §2.4); ABI compat audited |
| **M5** build + runtime + perf baseline | 9 testcases runtime PASS; 6-cell build matrix all green |
| **runtime-fix** | helloworld primary startup hang root-caused and fixed |
| **rib-fix** | Phase-5b prerequisite fib_algo regression patched |
| **independent audit + dual baselines** | CVM + physical-machine 13.0 baselines for cross-validation |
| **Phase-2 M6** | `FF_NETGRAPH=1` + `FF_IPFW=1` enabled by default; 41 netgraph nodes + 14 ipfw kernel objects in `libfstack.a` (5.4→6.5 MB); 25 MB `tools/sbin/ipfw` user-space binary first produced |
| **Phase-2 M7** | `FF_USE_PAGE_ARRAY=1`; 481-line `lib/ff_memory.c`; 256 MB one-shot mmap at startup |
| **Phase-2 M8** | `FF_ZC_SEND=1` with `FSTACK_ZC_MAGIC` sentinel protocol + new `ff_zc_send` API; also fixes a pre-existing 13.0-baseline ZC fast-path mis-predicate bug |
| **Phase-2 M9** | PA + ZC combo (1-line Makefile change); HTTP 200 + 100/100 short-conn PASS |
| **Phase-2 M10** | `FF_FLOW_IPIP=1` with software GIF tunnel fallback; ping 3/3 0% loss end-to-end |
| **Phase-2 M11/M12/M13** | P2 smoke trio: `FF_FLOW_ISOLATE` / `FF_FDIR` / `FF_LOOPBACK_SUPPORT` each enabled with clean lib build + primary alive |
| **Phase-2 M-Final** | docs sync + KG full re-index (58 171 nodes / 110 704 edges) |
| **Phase-5b** | 5-config × 2-3 testcase × 3-trial perf baseline matrix; closes M9-F1 + M10-F2; finds F-A1 (HIGH) |
| **F-A1 fix** | `lib/ff_memory.c:ff_if_send_onepkt` `rte_panic` demoted to non-fatal soft drop; PA-only 1000/1000 curl PASS; **all four configs (C0/C7/C8/C9) production-ready** |
| **VLAN + vip_addr + ipfw_pr config-layer test (2026-06-09)** | Dual-vlan multi-tenant config-layer acceptance via 4-sub-agent harness; G1/G2/G3/G4 all PASS, BOUNCE 0/3, hard evidence `00010 setfib 0 ip from 192.169.0.0/24 out` + `00020 setfib 1 ip from 192.169.1.0/24 out` from `tools/sbin/ipfw show` matches `ff_veth.c:949 fib_num = vlan_cfg->vlan_idx` exactly |

## Build / runtime / perf acceptance summary

- **Build**: 6 configs all green (C0/C7/C8/C9 + 13.0-baseline + Phase-2 M11/M12/M13 smokes)
- **Runtime**: helloworld primary stack-up + HTTP 200 + 100/100 short-conn PASS on every config; ipfw / ngctl / GIF tunnel / VLAN+vip+ipfw_pr all functional
- **Performance**: cross-config baseline matrix in Phase-5b shows 13.0-baseline parity or slight gain; ssh round-trip caps absolute throughput at ~137 conn/s (relative cross-config delta is the meaningful signal)

## Outstanding follow-ups (13 items, none blocking)

- **vlan-test (P3)**: F-V1 loopback ping vip / F-V2 client 802.1Q e2e / F-V3 ifname buffer bug / F-V4 vlan_filter HW filter pushdown / F-V5 G1 reproducibility CI
- **Phase-2 (P3)**: M11-followup-A multi-queue NIC isolate fallback / M12-followup-B FDIR rule capacity / M13-followup-C FF_LOOPBACK + vlan compat
- **Audit (P3)**: 4 medium + 12 low severity comments backfill
- **ABI (P3)**: forward-compat doc for v1.27 sticking
- **EN-trans (P4)**: zh_cn → en spec full translation, deferred to post-audit per project design

## Compliance

- **Workspace mandates** (DP-10 `rm_tmp_file.sh` / `kill_process.sh` / `chmod_modify.sh`): **0 violations across the entire project lifecycle**
- **Commit policy**: all 26 ahead commits are local-only; user decides push timing
- **Cross-source verification**: code ↔ KG ↔ spec ↔ runtime, no inconsistency left unresolved

## Knowledge graph

- `.gitnexus/lbug` synced to HEAD `ba477ac38a3b19d739a18bc8cf98e1c436e13ab4` at 2026-06-09T03:51:35Z
- 58 171 nodes / 110 704 edges / 1 778 communities / 300 processes
- Sub-agents may query KG directly to retrieve any phase's code/doc anchors

## Re-entry guide

For anyone (human or AI) picking the project up later:

1. **Top-level overview** — read `docs/freebsd_13_to_15_upgrade_spec/zh_cn/00-project-closure.md` (Chinese, definitive)
2. **English brief** — this file
3. **Detailed phase logs** — `zh_cn/<phase>-execution-log.md` for any phase listed above
4. **Code structure** — `docs/01-LAYER1-ARCHITECTURE.md` (English) / `docs/zh_cn/01-LAYER1-ARCHITECTURE.md` (Chinese), both already updated through vlan-test
5. **Code-level queries** — query the knowledge graph (`.gitnexus/lbug`) directly
6. **Commit range** — `cb1fe9950..ba477ac38` covers the entirety of Phase-2 M-Final → vlan-test
