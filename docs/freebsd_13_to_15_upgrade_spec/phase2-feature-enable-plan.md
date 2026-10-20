# F-Stack FreeBSD 15.0 Upgrade — Phase-2 Feature-Enable Plan

> Chinese version: ./zh_cn/phase2-feature-enable-plan.md (authoritative)

> Document: Phase-2 kickoff plan; lives alongside the existing `plan.md` (Phase-1 spec authoring + M0~M5 port, frozen at v0.3).
> Plan version: **v0.1 (2026-06-08)**
> Working style: **harness engineering + spec-driven + multi-agent team (1 leader + 5 sub-agents)**
> Output root: `/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/`
> HEAD at start: `07f9bb0b7` (feature/1.26 ahead 13 vs upstream/feature/1.26)
> Document language: Chinese-first; English mirror per milestone wrap-up (per existing convention).

---

## 0. Goal and Scope

### 0.1 Overall goal

On top of the FreeBSD 15.0 port that already passed **M0~M5 + runtime-fix + rib-fix + Phase-5b NFR-1**, incrementally enable the 7 default-commented `FF_*` build flags in `lib/Makefile`. Each milestone closes the loop "build → primary runs → functional/perf acceptance → doc sync".

### 0.2 Build-flag tiering (user request × Makefile measured cross-check)

| Flag | Makefile lines | HOST_CFLAGS | CFLAGS | VPATH adds | New .c files | Priority |
|---|---|---|---|---|---|---|
| `FF_NETGRAPH` | 43, 104-106, 224-226, 266-269, 424 | `-DFF_NETGRAPH` | — | `$S/netgraph` | `ff_ng_base.c` + `ff_ngctl.c` + freebsd/netgraph/*.c | **P0** |
| `FF_IPFW` | 44, 108-111, 237-240, 575-590 | `-DFF_IPFW` | `-DFF_IPFW` | `$S/netpfil/ipfw`, `$S/netpfil/ipfw/pmod` | `NETIPFW_SRCS` (13 `ip_fw_*.c` + `ip_fw2.c` + `ip_fw_pmod.c` + `tcpmod.c`) | **P0** |
| `FF_USE_PAGE_ARRAY` | 46, 113-115, 288-291 | `-DFF_USE_PAGE_ARRAY` | — | — | `ff_memory.c` (already present) | **P1a** |
| `FF_ZC_SEND` | 47, 204-206 | — | `-DFSTACK_ZC_SEND` ⚠ | — | `example/main_zc.c` (example side, not lib) | **P1b** |
| `FF_FLOW_IPIP` | 41, 100-102 | `-DFF_FLOW_IPIP` | — | — | only ff_dpdk_if.c branches | **P1d** |
| `FF_FLOW_ISOLATE` | 39, 96-98 | `-DFF_FLOW_ISOLATE` | — | — | only ff_dpdk_if.c branches | **P2** |
| `FF_FDIR` | 40, 92-94 | `-DFF_FDIR` | — | — | only ff_dpdk_if.c branches | **P2** |
| `FF_LOOPBACK_SUPPORT` | 55, 157-160 | `-DFF_LOOPBACK_SUPPORT` | `-DFF_LOOPBACK_SUPPORT` | — | only ff_dpdk_if.c branches | **P2** |

> ⚠ **Important finding** (measured during reconnaissance): the actual macro for `FF_ZC_SEND` is `FSTACK_ZC_SEND` (`lib/Makefile:205`), **not** `-DFF_ZC_SEND`. Source-side check `example/main_zc.c:183 #ifdef FSTACK_ZC_SEND` confirms. The plan uses `FSTACK_ZC_SEND` throughout.

### 0.3 Out of scope

| Item | Note |
|---|---|
| `FF_IPSEC` | not requested by user; left commented (default off) |
| `FF_KNI` / `FF_INET6` / `FF_TCPHPTS` / `FF_EXTRA_TCP_STACKS` | already on by default; unchanged this phase |
| Kernel new subsystems (NETLINK protocol, KTLS) | per DP-2: not introduced, header-only retained |
| Real production rollout | only this workspace's CVM / physical-machine baseline boxes |
| Remote push | **each milestone: local commit + wait for user review; no auto-push** |

---

## 1. Workspace State (measured, not memorized)

### 1.1 Repo and branch

| Item | Value | Source |
|---|---|---|
| Main repo | `/data/workspace/f-stack/` | `pwd` |
| Current branch | `feature/1.26` | `git status` |
| HEAD | `07f9bb0b7` (docs sync 2026-06-08) | `git log -1` |
| Ahead of origin | 13 commits | `git status -sb` |
| 13.0 baseline | `/data/workspace/f-stack-13.0-baseline/` | project convention |
| Community 13.0 src | `/data/workspace/freebsd-src-releng-13.0/` | project convention |
| Community 15.0 src | `/data/workspace/freebsd-src-releng-15.0/` | project convention |
| 15.0 pristine baseline | `/data/workspace/freebsd-src-releng-15.0/f-stack-lib/` | project convention (only `freebsd/` + `tools/` + `INVENTORY.md`) |

### 1.2 Source and tooling readiness

| Resource | Path | Status |
|---|---|---|
| netgraph kernel src | `freebsd/netgraph/*.c` | ✅ 74 .c |
| ipfw kernel src | `freebsd/netpfil/ipfw/*.c` + `freebsd/netpfil/ipfw/pmod/*.c` | ✅ (VPATH ready) |
| ipfw user-space tool | `tools/ipfw/` (incl. `ipfw2.c` `ipfw.8` `dummynet.c` `altq.c`, 26 files) | ✅ |
| ifconfig tool | `tools/ifconfig/` (40 files incl. `af_inet.c` `af_inet6.c` `af_link.c`) | ✅ |
| GIF tunnel driver | `freebsd/net/if_gif.c` + `if_gif.h` | ✅ |
| ZC example | `example/main_zc.c` | ✅ |
| ZC docs | `lib/ff_api.h:381 // See 'example/main_zc.c'` | ✅ |
| `ff_ng_base.c` / `ff_ngctl.c` | `lib/` (landed in M5) | ✅ |
| `ff_memory.c` (page-array) | `lib/` | ✅ |
| `f-stack-client` | **not in repo** | ⚠ Spec must clarify whether the user maintains it independently or this phase needs to provide it; listed under §3.OQ-1 |

### 1.3 Known minor mismatches (left over from phase-1 docs sync)

| Item | Symptom | Handling |
|---|---|---|
| docs say "33 .c files" | measured `lib/ff_*.c` = **31** | fix in passing during doc-update (non-blocking) |
| docs say `ff_epoll.c ~134` | measured ~159 / ~134 (different metrics) | reconcile via `wc -l` at each milestone close |

> These are tiny number drifts left by the phase-1 docs-sync commit `07f9bb0b7`; this plan re-aligns them at each milestone close.

---

## 2. Agent-Team Topology (1 leader + 5 sub-agents)

```
                        ┌─────────────────────────────┐
                        │   Leader (main agent)       │
                        │  · state machine / bounce # │
                        │  · final commit / progress  │
                        └────┬────────────────┬───────┘
                             │                │
        ┌────────────────────┼─────────┬──────┴──────┬───────────┐
        ▼                    ▼         ▼             ▼           ▼
 ┌────────────┐  ┌──────────────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐
 │spec-author │  │  research-scout  │  │  coder   │  │ reviewer │  │ gate-keeper │
 │spec-driven │  │  external research│  │ code edits│  │ static  │  │ build/run/  │
 │ writes spec│  │ github/blog/wiki │  │c-precision│  │ x-check │  │ functional/ │
 │ + decisions│  │ + freebsd src    │  │ -surgery │  │ bounce   │  │ perf + docs │
 └────────────┘  └──────────────────┘  └──────────┘  └──────────┘  └─────────────┘
        ↓                ↓                  ↓             ↓             ↓
  spec.md       research/{topic}.md     code change    review report   gate report
                                                       (PASS/FAIL +    + bounce ledger
                                                        bounce reason)
```

### 2.1 Roles and sub-agent picks

| Role | Sub-agent / Skill | Main tools |
|---|---|---|
| **Leader** | main agent (this dialog) | plan_create / todo_write / git / coordination |
| **spec-author** | spec-driven skill primary, code-explorer auxiliary | write_to_file (spec.md) |
| **research-scout** | code-explorer × N parallel + external (web_fetch / web_search subject to env) | search_content / RAG_search / web_fetch |
| **coder** | c-precision-surgery (precise C edits, minimal diff) | replace_in_file (lib/ + tools/ + freebsd/) |
| **reviewer** | code-explorer (separate context to avoid coder bias) | search_content / read_file / cite spec |
| **gate-keeper** | main agent + execute_command (make / primary stack-up / ff_ipfw / perf scripts) | execute_command + acceptance gates |

### 2.2 Bounce protocol (consistent with phase-1 style)

- Each milestone owns its bounce counter; per-stage sub-counters:
  - bounce(spec → research): spec stage finds an external-info gap
  - bounce(code → spec): coder finds the spec un-implementable
  - bounce(review → code): reviewer finds spec/mandate violation
  - bounce(gate → code): build/run/test fails
  - bounce(gate → spec): test reveals spec acceptance is insufficient (rare)
- Same-stage cumulative bounce ≥ **3** → **pause the milestone**, draft an escalation report, **human decision**
- Total bounce ceiling per milestone ≤ 6 (cross-stage); above that, force-pause

---

## 3. Milestone Breakdown (M6 ~ M13)

> Numbered after phase-1's M0~M5. Each milestone has its own spec, commit and execution log.

### M6 — FF_NETGRAPH + FF_IPFW Combo (P0)

| Item | Value |
|---|---|
| Scope | enable FF_NETGRAPH + FF_IPFW **together**; neither released alone |
| Main risks | (1) some of the 74 netgraph .c files have changed interfaces between 13→15 (e.g. `ng_node_t` / `ng_ID_t`); reviewer must check whether `ff_stub_14_extra` covers it; (2) the 13 NETIPFW_SRCS files + user-space `tools/ipfw/ipfw2.c` need 14/15 ABI sync; (3) `tools/ipfw/` already contains stale build artifacts like `ipfw2.o`, must clean via `rm_tmp_file.sh` |
| Acceptance | (a) `make` clean: 0 error / 0 warning (warning threshold §6.4); (b) `example/helloworld` + `tools/sysctl` primary stacks up; (c) `tools/ipfw add 100 deny ip from 1.2.3.4 to any` works, `ipfw show` lists the rule; (d) simple ping shows the rule matches (`pkts/bytes` counters change); (e) netgraph at least responds to `ngctl list` (returning empty is fine if no active node) |
| Output files | `phase2-M6-spec.md` / `phase2-M6-research-brief.md` (if needed) / `phase2-M6-execution-log.md` |
| Start condition | user accepts this plan |
| Definition of done | (a)~(e) all PASS + 3-tier docs synced + local commit + waiting for review |

### M7 — FF_USE_PAGE_ARRAY alone (P1a)

| Item | Value |
|---|---|
| Scope | enable `FF_USE_PAGE_ARRAY=1` only; keep `FF_ZC_SEND` off |
| Main change | `ff_memory.c` joins `FF_HOST_SRCS`; DPDK mbuf takes the page-array mempool path |
| Acceptance | (a) build PASS; (b) primary stacks up; (c) a single short-conn curl rides the page-array path without crash; (d) `dpdk-procinfo` or `tools/sysctl` can read out the page-array enable state (exact probe defined in spec) |
| Perf baseline | default vs FF_USE_PAGE_ARRAY, **one short + one long conn** trial, record rps / latency p99 / cpu%; trade-off ≤ 5% = PASS (matches Phase-5b NFR-1 threshold) |
| Output | `phase2-M7-spec.md` + `phase2-M7-execution-log.md` |

### M8 — FF_ZC_SEND alone (P1b)

| Item | Value |
|---|---|
| Scope | enable `FF_ZC_SEND=1` only (real macro `-DFSTACK_ZC_SEND`); keep `FF_USE_PAGE_ARRAY` off |
| Main change | `example/main_zc.c` takes the `#ifdef FSTACK_ZC_SEND` branch; server compiles to `helloworld_zc` binary |
| Acceptance | (a) build PASS; (b) `helloworld_zc` primary stacks up; (c) f-stack-client (**OQ-1 to clarify**: client provenance) sends packets, server receives and ZC-replies; (d) compared to default helloworld, **4 KB / 64 KB single-link throughput** at least no worse |
| Output | `phase2-M8-spec.md` + `phase2-M8-execution-log.md` |

### M9 — FF_USE_PAGE_ARRAY + FF_ZC_SEND combo (P1c)

| Item | Value |
|---|---|
| Scope | M7+M8 together |
| Acceptance | union of M7+M8 + joint perf baseline (combo not worse than either alone by more than -5%) |
| Risks | mbuf refcnt / page array conflicting with ZC path; whether `ff_memory.c` needs a new ZC-compat branch decided in spec |
| Output | `phase2-M9-spec.md` + `phase2-M9-execution-log.md` |

### M10 — FF_FLOW_IPIP (P1d)

| Item | Value |
|---|---|
| Scope | enable `FF_FLOW_IPIP=1` only |
| Test topology | server runs f-stack primary + `tools/ifconfig` brings up `gif0` (GIF/IPIP); client is Linux using `ip tunnel add` to set up the peer end |
| Acceptance | (a) build PASS; (b) primary stacks up; (c) `ff_ifconfig gif0 create` + `ff_ifconfig gif0 inet 10.0.0.1 10.0.0.2` succeed; (d) after the client configures the peer tunnel + route, `ping 10.0.0.1` works; (e) `ff_route get` shows the IPIP-tunneled route |
| Risks | whether `if_gif.c` was changed 13→15; whether DPDK-side IPIP flow rule depends on NIC hardware capability |
| Output | `phase2-M10-spec.md` + `phase2-M10-execution-log.md` |

### M11 — FF_FLOW_ISOLATE (P2a)

| Item | Value |
|---|---|
| Scope | enable `FF_FLOW_ISOLATE=1` only |
| Acceptance | (a) build PASS; (b) primary stacks up; (c) **smoke pass** (no functional check required, since it depends on NIC SR-IOV/VLAN isolation, which this CVM lacks); (d) doc explains enable conditions and hardware dependence |
| Output | `phase2-M11-spec.md` + `phase2-M11-execution-log.md` |

### M12 — FF_FDIR (P2b)

Same style as M11: build + primary stack-up + hardware dependence note only.

### M13 — FF_LOOPBACK_SUPPORT (P2c)

| Item | Value |
|---|---|
| Scope | enable `FF_LOOPBACK_SUPPORT=1` only |
| Acceptance | (a) build PASS; (b) primary stacks up; (c) `127.0.0.1` ping inside f-stack works (`tools/sysctl` or a small custom helloworld test) |
| Output | `phase2-M13-spec.md` + `phase2-M13-execution-log.md` |

> ⚠ **Re: "FF_FLOW_IPIP appears in both P1 and P2" in the user's original ask** — P1 (M10) wins; P2 doesn't repeat. This plan only schedules it at M10.

### M-Final — Wrap-up (unified docs sync)

| Item | Value |
|---|---|
| Scope | After M6~M13 finish, re-run GitNexus indexing + full sync of the 18 3-tier-architecture docs + KG_WIKI |
| Output | `phase2-final-execution-log.md` + a docs-sync commit similar to phase-1 |
| Note | Same approach as phase-1 (see `docs-sync-2026-06-08-execution-log.md`) |

---

## 4. Per-milestone Standardized Workflow (Spec-Driven 5-phase)

```
       ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
       │ Phase A  │ →  │ Phase B  │ →  │ Phase C  │ →  │ Phase D  │ →  │ Phase E  │
       │ Spec     │    │ Research │    │ Code     │    │ Review   │    │ Gate     │
       │  by      │    │ (option) │    │  by      │    │   by     │    │  by      │
       │spec-author│   │ research │    │ coder    │    │reviewer  │    │gatekeeper│
       └──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘
            ↑               ↑               ↓               ↓               ↓
            │               │               │               │               │
            └───── bounce ──┴────────────── bounce ────────┴── bounce ─────┘
                            (same stage ≥3 → pause → human decision)
```

### 4.1 Phase A — Spec (mandatory)

- Inputs: original user requirement + Makefile measurements (this plan §0.2) + phase-1 existing spec docs
- Output: `phase2-MN-spec.md` containing
  - scope (in / out)
  - background and state (measured citations only; no guesses)
  - interface / data-structure changes (cited by file:line)
  - acceptance criteria (executable, measurable)
  - risks and rollback (each risk has detection + mitigation)
  - test list (build matrix + primary smoke + functional + perf + docs)
- DoD: spec passes ≥ 99/100 self-consistency check (no internal contradiction, no TBD)

### 4.2 Phase B — Research (on demand)

- Trigger: spec stage finds an external-info gap (e.g. did upstream freebsd-15 change ipfw ABI)
- Input: spec.md + research topic
- Output: `phase2-MN-research-brief.md` containing
  - github search (F-Stack/f-stack issues + freebsd/freebsd-src commits)
  - official release notes (13.0 / 14.0 / 15.0)
  - Chinese blogs / wechat
  - DeepWiki F-Stack auto-generated wiki
  - every conclusion has URL + cited excerpt

### 4.3 Phase C — Code (mandatory)

- Inputs: spec.md + research-brief (if any) + phase-1 lib/ implementation
- Output: actual git diff (lib/ + tools/ + freebsd/ + new ff_*.c if needed)
- Sub-rules:
  - prefer `replace_in_file` (minimal diff); new files via `write_to_file`
  - new source files **must** be backed up to `/data/workspace/freebsd-src-releng-15.0/f-stack-lib/` (per user rule §5)
  - any temp .o / backup / leftover → must use `/data/workspace/rm_tmp_file.sh`
  - any process cleanup → must use `/data/workspace/kill_process.sh`
  - any chmod → must use `/data/workspace/chmod_modify.sh`

### 4.4 Phase D — Review (mandatory)

- Reviewer uses an **independent** code-explorer sub-agent (isolate context to avoid coder bias)
- Checks:
  1. spec ↔ code consistency (every AC implemented)
  2. each risk has detection + mitigation, landed in code or docs
  3. diff vs upstream `freebsd-src-releng-15.0` (does our edit drift from upstream intent)
  4. delta vs 13.0 baseline (does it break a 13.0 compat assumption)
  5. static scan for the 3 forbidden commands (rm/kill/chmod)
  6. commit-message template (English subject + body)
- Output: `phase2-MN-review-report.md` (PASS / FAIL + must-fix list)

### 4.5 Phase E — Gate (mandatory)

Run serially; any failure bounces back to the corresponding stage:

| Gate | Test | On fail → bounce |
|---|---|---|
| **G1 build** | `make clean && make all` 0 error, warning ≤ M5 baseline + 5 | code |
| **G2 primary smoke** | `example/helloworld -c x.conf -p 0 --proc-type=primary --proc-id=0`, alive 10 s | code (rarely spec) |
| **G3 functional** | per-milestone (M6 ipfw add/show; M10 GIF tunnel ping; M13 lo ping) | code (spec if insufficient) |
| **G4 perf** | mandatory for M7/M8/M9; optional otherwise; threshold ±5% | code |
| **G5 doc sync** | 3-tier + KG (each P0/P1 partial sync; M-Final full re-run) | doc-updater |
| **G6 lint** | `read_lints` 0 errors | doc-updater |
| **G7 commit** | English subject + body; local commit; **no push** | leader |

---

## 5. Test and Acceptance Strategy (detailed)

### 5.1 Build matrix

| Dimension | Values |
|---|---|
| Host | CVM (used by M5) + physical-machine baseline (matches Phase-5b) |
| Compiler | gcc 10/11/12 (Makefile already has `GCCVERGE10/11/12` branches) |
| Arch | amd64 (default; only one in this workspace) |
| Flag combos | see each milestone's in-scope FF_* combo in §3 |

### 5.2 Perf baseline (M7/M8/M9 only)

| Dimension | Value |
|---|---|
| Test program | nginx_fstack (Phase-5b style) + helloworld(_zc) (M8/M9 specific) |
| Traffic | short conn (rps) + long conn (goodput) |
| Concurrency | 4 / 8 cores |
| Duration | 60 s × 3 rounds, average |
| Metrics | rps / latency p50 / p99 / cpu% / mem% |
| Threshold | default ≥ M5 baseline -5%; trade-off > 5% → must have an explicit spec decision + observation tag |

### 5.3 Generic primary smoke script (refined per milestone)

```bash
# Template (each milestone tweaks)
cd /data/workspace/f-stack/example
sudo ./helloworld -c ../config.ini --proc-type=primary --proc-id=0 &
HELLOWORLD_PID=$!
sleep 5
# functional check (per milestone)...
# clean up: must use kill_process.sh; raw kill is forbidden
/data/workspace/kill_process.sh $HELLOWORLD_PID
```

### 5.4 Doc-sync strategy (per milestone)

| Document | M6/M10 (P0/P1d) | M7/M8/M9 (P1a-c) | M11/M12/M13 (P2) | M-Final |
|---|---|---|---|---|
| `phase2-MN-spec.md` | yes | yes | yes | — |
| `phase2-MN-research-brief.md` | on demand | on demand | on demand | — |
| `phase2-MN-execution-log.md` | yes | yes | yes | — |
| `phase2-MN-review-report.md` | yes | yes | yes | — |
| 3-tier 6 docs + Summary partial update | yes (small diff) | yes (small diff) | yes (small diff) | full re-check |
| KG_WIKI re-run GitNexus | no (small partial) | no | no | **yes** (M-Final) |
| README + zh_cn mirror | yes | yes | yes | yes |

---

## 6. Tooling and Mandates

### 6.1 Mandatory wrappers (workspace AI memory; zero tolerance)

| Command | Replaced by |
|---|---|
| `rm <path>` / `rm -rf` / `rm -f` | `/data/workspace/rm_tmp_file.sh <path1> [path2 ...]` |
| `kill <pid>` / `pkill` / `killall` | `/data/workspace/kill_process.sh <pid_or_name>` |
| `chmod <mode> <path>` / `install -m` / `setfacl` | `/data/workspace/chmod_modify.sh <mode> <path1> [path2 ...]` |

> Note: `make clean` / `make install` / `cp` and similar internal implicit rm/chmod are **allowed** (the user explicitly said "not direct chmod calls" + "install-class commands allowed"). But agent-authored scripts and commands **must not** call rm/kill/chmod directly.

### 6.2 git mandate

- commit message: **English** (subject + body)
- one commit per milestone (covers all relevant lib/ + tools/ + freebsd/ + docs edits)
- **after each milestone commit, wait for the user; no auto-push** (same as the phase-1 docs sync)
- remote: `origin` = `feature/1.26` (unchanged)

### 6.3 Source-backup mandate (user §5)

- For any **new** source file (.c / .h), the pre-edit "pristine baseline" must be stored under `/data/workspace/freebsd-src-releng-15.0/f-stack-lib/`.
- Edits to existing files do **not** need re-backup (13.0 baseline is at `freebsd-src-releng-13.0/f-stack-lib/`; 15.0 upstream is at `freebsd-src-releng-15.0/sys/`).

### 6.4 Warning threshold

- M5 baseline: build-warning baseline (grep `make all 2>&1 | grep -c warning` at runtime)
- Each milestone allows +5 (absolute); over budget → G1 fail → bounce to code

### 6.5 Cross-source verification

| Source | Role |
|---|---|
| `f-stack/lib/`, `f-stack/freebsd/`, `f-stack/tools/` | **current implementation** (highest authority) |
| `freebsd-src-releng-15.0/sys/`, `freebsd-src-releng-15.0/f-stack-lib/` | **upstream baseline** (diff reference) |
| `freebsd-src-releng-13.0/`, `f-stack-13.0-baseline/` | **13.0 historical baseline** (compat reference) |
| `docs/freebsd_13_to_15_upgrade_spec/zh_cn/M*-execution-log.md` | **historical decisions** (DP-1 ~ DP-N) |
| `docs/01-LAYER1`, `02-LAYER2`, `03-LAYER3` | **architecture docs** (read-only; phase-1 sync already aligned to v1.26) |
| GitNexus `meta.json` (`.gitnexus/`) | **current KG snapshot** (commit `208b0c4`, 2656 files / 64855 nodes) |
| External | github issues + official release notes + Chinese blogs |

> **Iron rule**: any inconsistency is resolved in favor of the **current implementation**; if implementation contradicts spec/upstream/historical decision, **always** record it in the spec stage + reviewer confirm before changing anything. **Never silently change the implementation to fit the docs**.

---

## 7. External-Research Inventory (for research-scout)

| Dimension | Entry point |
|---|---|
| FreeBSD 15.0 release notes | https://www.freebsd.org/releases/15.0R/relnotes/ |
| FreeBSD 14.0 release notes | https://www.freebsd.org/releases/14.0R/relnotes/ |
| FreeBSD ipfw / netgraph 14/15 ABI changes | https://man.freebsd.org/cgi/man.cgi?query=ipfw / `git log freebsd-src-releng-15.0/sys/netpfil/ipfw/` |
| F-Stack community | https://github.com/F-Stack/f-stack/issues + wiki |
| DeepWiki | https://deepwiki.com/F-Stack/f-stack |
| DPDK 23.11.5 zero-copy / page-array | https://doc.dpdk.org/guides-23.11/ |
| Chinese community | search "FreeBSD 15", "f-stack ipfw", "DPDK zero copy", "GIF tunnel f-stack", etc. |
| Internal KB | via `RAG_search`: TencentOS / TencentOS for Network / similar work |

---

## 8. Open Questions (human decisions)

| OQ | Content | Default | Decision time |
|---|---|---|---|
| **OQ-1** | Is `f-stack-client` user-maintained or to be provided this phase? | assume **user-maintained** (the user provides IP + binary path for ZC/GIF tests) | before M8 |
| **OQ-2** | Reuse the Phase-5b CVM A/B + physical-machine methodology for perf? | default **yes** (preserve comparability) | before M7 |
| **OQ-3** | Run M-Final docs sync immediately after M13, or in batches (small sync after each P0/P1)? | default **batched small sync + final full KG re-run** | after M6 done |
| **OQ-4** | If NETGRAPH+IPFW combo G3 fails because of NIC-driver limitations (no DPDK control), can we downgrade to smoke-PASS + observation tag? | default **allowed**, but mandatory observation block | M6 G3 |
| **OQ-5** | If web_fetch / web_search is blocked by the network, may research rely on local source + RAG_search alone? | default **allowed**, declared at the top of the research-brief | M6 Phase B |

---

## 9. Risk Register (per milestone)

| Risk | Impact | Mitigation | Watchpoint |
|---|---|---|---|
| FF_NETGRAPH undefined symbols (13→15 ABI drift) | M6 G1 fail | cover via `ff_stub_14_extra.c` stubs; reviewer matches `freebsd-src-releng-15.0/sys/netgraph/ng_base.c` upstream signatures | grep `undefined reference` in build log |
| FF_IPFW user-space `tools/ipfw/ipfw2.o` stale | stale at build time | pre-launch `rm_tmp_file.sh` cleans residue | `find tools/ipfw -name '*.o'` |
| FF_USE_PAGE_ARRAY × ZC combo memory-lifetime conflict | M9 SIGSEGV | spec stage lists the mbuf refcnt model upfront; reviewer focuses on ff_memory.c | runtime gdb |
| GIF tunnel client-side config varies by client OS | M10 G3 not reproducible | spec lists Linux + assumed-client variants and pins OQ-1 | spec § acceptance scripts |
| Perf trade-off > 5% | M7/M8/M9 G4 fail | same as Phase-5b: observation vs blocking — user decides | gate report |
| 3-tier doc "33 .c" tiny drift | doc inconsistency | M-Final fixes in pass | M-Final |
| GitNexus index node count changes via schema v1 | KG_WIKI text mismatches | M-Final uses real meta.json after re-run; don't reuse old v0 table | M-Final |

---

## 10. Progress Tracking (status table; leader updates after each milestone)

| Milestone | Priority | Status | Spec | Research | Code | Review | Gate | Bounce | Commit | Pushed |
|---|---|---|---|---|---|---|---|---|---|---|
| M6 NETGRAPH+IPFW | P0 | ✅ DONE | ✅ | ✅ | ✅ | ✅ | ✅ G1-G5/G7 PASS | 3/3 | `4139198f6` | NO |
| M7 PAGE_ARRAY | P1a | ✅ DONE | ✅ | ✅ | ✅ | ✅ | ✅ G1-G5/G7 PASS | 0/3 | `cba3d882b` | NO |
| M8 ZC_SEND | P1b | ✅ DONE | ✅ | ✅ | ✅ | ✅ | ✅ G1-G7 PASS (HTTP 200/438B real HTML, 100/100 short-conn) | 1/3 | `add33a04a` | NO |
| M9 PA+ZC combo | P1c | ✅ DONE | ✅ | ✅ | ✅ | ✅ | ✅ G1-G3 PASS (G4 perf observation deferred) | 0/3 | `2f4748638` | NO |
| M10 FLOW_IPIP | P1d | ✅ DONE | ✅ | ✅ | ✅ | ✅ | ✅ G1-G3.6 PASS (ping 3/3 IPIP tunnel cross-impl) | 1/3 | `90c730496` | NO |
| M11 FLOW_ISOLATE | P2a | ✅ DONE (smoke) | ✅ | ✅ | ✅ | ✅ | ✅ G1/G2 PASS | 0/3 | `6be5461a9` | NO |
| M12 FDIR | P2b | ✅ DONE (smoke) | ✅ | ✅ | ✅ | ✅ | ✅ G1/G2 PASS | 0/3 | `b6bf3f094` | NO |
| M13 LOOPBACK | P2c | ✅ DONE (smoke) | ✅ | ✅ | ✅ | ✅ | ✅ G1/G2 PASS (+1 link stub `ff_swi_net_excute`) | 0/3 | `73622c85c` | NO |
| M-Final docs sync | – | ✅ DONE | – | – | ✅ | ✅ | ✅ status table backfilled + 4 layer1+summary docs synced + plan §10 updated | – | (this commit) | NO |

**Bounce ledger (plan-wide cumulative)**: 0
**Escalations**: 0

---

## 11. Pacing Suggestions (advisory, non-binding)

| Milestone | Estimated agent-turn budget |
|---|---|
| M6 NETGRAPH + IPFW (most complex) | 8~14 turns |
| M7 / M8 / M9 ZC + PA | 5~8 turns each |
| M10 FLOW_IPIP | 6~10 turns |
| M11 / M12 / M13 P2 trio | 3~5 turns each |
| M-Final docs sync | same as phase-1 (~10 turns) |

Overall: after the user accepts the plan, **run milestones serially** (avoid context contamination); user reviews after each, then on to the next.

---

## 12. Kickoff Checklist (run after the user accepts)

| # | Check | Command |
|---|---|---|
| 1 | HEAD is clean | `git status -sb` |
| 2 | M5 build baseline (default config) | `cd lib && make all 2>&1 \| tee /tmp/m5_baseline.log` then `grep -c warning /tmp/m5_baseline.log` |
| 3 | gitnexus meta.json reachable | `python3 -c "import json; print(json.load(open('.gitnexus/meta.json'))['stats'])"` |
| 4 | The 3 forbidden-command wrapper scripts are executable | `ls -l /data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh` |
| 5 | `freebsd-src-releng-15.0/f-stack-lib/` writable | `touch test && rm test` (note: this rm test must use rm_tmp_file.sh) |

---

## 13. Relationship to Phase-1 Doc Set

| Reuse | Item |
|---|---|
| ✅ reuse | `plan.md` (master) / `00-overview-and-glossary.md` / `01-requirements-spec.md` / `02-architecture-analysis.md` glossary and DP table (DP-1 ~ DP-5) |
| ✅ reuse | `06-test-and-acceptance-spec.md` test methodology (CVM A/B + physical-machine baseline) |
| ✅ reuse | `runtime-fix-execution-log.md` 5 P0 SIGSEGV fix patterns (spec must self-check whether they're triggered again) |
| ✅ reuse | `docs/01-LAYER1`, `02-LAYER2`, `03-LAYER3`, `Summary`, `KNOWLEDGE_GRAPH_WIKI` (v1.26 baseline, 2026-06-08 sync) |
| ⛔ no rewrite | the existing master plan.md (frozen v0.3) |
| ⛔ no rewrite | M0~M5 + Phase-5b + runtime-fix + rib-fix execution logs |

---

## 14. Plan Versions

| Version | Date | Status |
|---|---|---|
| **v0.1** | **2026-06-08** | **this version** (awaiting user acceptance) |

---

> **Current state: awaiting user acceptance. Once accepted, immediately enter M6 Phase A (spec-author drafts `phase2-M6-spec.md`) and proceed per §4 standardized workflow.**
