# F-Stack Native "Single-Process + Multi-Thread + Multi-Stack-Instance" Support Research & Chinese Spec — Master Plan

> This document is the master plan (plan.md) for this research round. It fixes the research direction, goal boundaries, agent-team division of labor, milestones, and mandatory conventions.

## 0. Positioning of This Round: Redo from Scratch

### 0.1 Background
The previous spec (committed as `497e53e11`, under `docs/multi_thread_spec/zh_cn/`) eventually **recommended the "multi-process + LD_PRELOAD adapter multi-worker (FF_THREAD_SOCKET / FF_MULTI_SC / SO_REUSEPORT)" route** and downgraded "native single-process multi-thread multi-stack-instance" to a high-risk long-term alternative.

**The user explicitly rejected that recommendation**, pointing out: (1) the AI reached a recommendation conclusion without asking the user first; (2) the target direction should be **native (in-library `lib/` layer) support for single-process + multi-thread + multi-stack-instance, not an adapter**.

### 0.2 Old Conclusion Invalidated
- The old spec's "recommend adapter multi-worker" conclusion **is invalidated this round**; the old directory is kept only as an audit trail.
- This round's spec is output to the **new directory** `docs/native_mt_spec/zh_cn/`, without polluting the old spec.
- The new spec overview (`00`) explicitly states "the old adapter recommendation is invalidated and superseded by this native approach".

### 0.3 The Only Goal Direction of This Round
Demonstrate and design f-stack's **in-library native support for "single-process + multi-thread + multi-stack-instance"**:

> One process starts N pthreads (each thread pinned to one lcore); each thread runs its own `ff_init` / `ff_run` to produce **an independent FreeBSD stack instance**, by making FreeBSD global state **per-thread** to achieve share-nothing (lock-free).

**Hard boundaries (must not be violated):**
1. **adapter / LD_PRELOAD / multi-worker is not the target approach** — it is recorded objectively only in the "current state and existing capability" section, **must not be the recommendation or steal the spotlight**.
2. The spec does **not present "which of A/B/C options is better" for the user to choose** — the direction is already decided by the user; the spec answers **"how to implement the native multi-stack-instance approach"** (change list, initialization mechanism, configuration, milestones, risks, tests).
3. "Shared single stack + fine-grained locking" is only a **rejected alternative** for comparison, **must not reverse-recommend the adapter**.
4. Keep **zero regression** for the multi-process mode (primary/secondary behavior unchanged; thread mode is an opt-in behind a switch).

## 1. Research Goal Checklist

| # | Goal | Mandatory |
|---|------|-----------|
| 1 | Full chain of the existing multi-process model (proc_type/proc_id/proc_lcore/RSS/IPC Ring/KNI primary-only/mempool sharing) as the modification baseline | Yes |
| 2 | Complete inventory of FreeBSD stack global state + per-thread approach (`__thread` / `RTE_PER_LCORE` / lcore_id-indexed arrays) | Yes |
| 3 | Per-thread independent FreeBSD stack-instance initialization mechanism (`ff_freebsd_init`/`mi_startup`/`thread0`/`pcpup` run N times, or VNET virtualization needed) | Yes |
| 4 | DPDK native multi-thread integration (single-process `rte_eal_mp_remote_launch` on multiple lcores, per-thread RX/TX queues + independent rings keeping SC/SP, MT-safe mempool, `RTE_PER_LCORE`) | Yes |
| 5 | Configuration extension (new thread run-mode switch, lcore_mask semantics under single-process multi-thread) without breaking multi-process zero regression | Yes |
| 6 | KNI/IPC/toolchain ownership design under native multi-thread | Yes |
| 7 | Alignment with FreeBSD native SMP/per-CPU/VNET and DPDK per-lcore mechanisms (source + external cross-validation) | Yes |
| 8 | Compatibility red lines (multi-process zero regression, API compatibility), failure-isolation risk (thread crash kills whole process) documented with mitigation | Yes |
| 9 | **issue #430** recorded as "first-hand evidence of application-side multi-threading demand" (socket flag bits already ready), **not as a conclusion anchor** | Yes |
| 10 | Test strategy, performance baseline (native multi-thread vs multi-process), honest-boundary layering (items that static analysis cannot conclude and require runtime validation) | Yes |

## 2. Agent Team Division of Labor (1 leader + code-explorer subagents, writer/reviewer separation)

| Role | Phase | Responsibility |
|------|-------|----------------|
| leader (main agent) | whole | Orchestration, polling/waiting, out-of-band probing, timeout/exception fallback, SM2 external research, SM3 solution design, SM4 document writing, SM6 commit (pure-summary single-role tasks may be handled directly) |
| code-explorer A | SM1 | FreeBSD global-state inventory + stack-instance initialization feasibility (read-only) |
| code-explorer B | SM1 | DPDK native multi-thread capabilities / independent queue rings / mempool (read-only) |
| code-explorer C | SM1 | Lifecycle + config + KNI/IPC ownership + issue #430 evidence verification (read-only) |
| code-explorer (gatekeeper) | SM5 | Independent review gate (≠leader≠writer, writer/reviewer separation) |

## 3. Milestones

- **SM0** Create directory + write plan.md (this step)
- **SM1** 3 code-explorer subagents explore in parallel, produce file:line-verified material
- **SM2** External + source cross-research (FreeBSD per-CPU/VNET/SMP, DPDK per-lcore, mTCP/Seastar thread-per-core)
- **SM3** Native multi-stack-instance implementation design (no adapter recommendation)
- **SM4** Write 14 Chinese specs (plan + 00-12)
- **SM5** Independent gate review (bounce≤3, bounced back to the original writer for fix and re-review)
- **SM6** After gate PASS, commit locally (docs only, English commit; config.ini local values not committed)

## 4. Document Structure (`docs/native_mt_spec/zh_cn/`)

| File | Content |
|------|---------|
| `plan.md` | This file |
| `00-调研结论总览.md` | Conclusion-first, native direction confirmed, old adapter recommendation invalidated, section index |
| `01-需求规格.md` | Goals/scope boundaries/acceptance criteria/terminology (application-side vs stack-side multi-threading) |
| `02-现状与差距分析.md` | Multi-process model layer by layer (file:line) + existing thread infrastructure + adapter as current-state record only |
| `03-FreeBSD栈全局状态清单.md` | Global-state item-by-item table: file:line + type + already per-thread? + isolation method + change cost + risk |
| `04-栈实例初始化机制设计.md` | Whether `ff_freebsd_init`/`mi_startup`/`thread0`/`pcpu` can run N times / VNET virtualization, per-instance init flow |
| `05-方案与架构设计.md` | Native multi-stack-instance overall architecture/data flow/per-thread strategy; shared single stack + locks as rejected comparison |
| `06-DPDK多线程对接方案.md` | mp_remote_launch on multiple lcores / per-thread independent queues + independent rings (SC/SP) / MT-safe mempool / RTE_PER_LCORE |
| `07-接口与配置设计.md` | thread run-mode switch / lcore_mask semantics / ff_config changes / API compatibility / opt-in zero regression |
| `08-KNI-IPC-工具链归属.md` | KNI single-thread ownership / simplified inter-thread shared-memory IPC / tools ownership |
| `09-外网与源码交叉调研.md` | FreeBSD per-CPU/VNET/SMP, DPDK per-lcore, mTCP/Seastar thread-per-core, issue #430 evidence |
| `10-里程碑与工作清单.md` | Coding milestones CM0-CMn (ordered by risk) / WBS / rollback points / gates |
| `11-测试性能与风险兼容.md` | Unit/integration/perf baseline (multi-thread vs multi-process) / zero-regression red line / failure-isolation risk / honest boundary layering |
| `12-spec评审门禁.md` | Item-by-item assertion checklist (code consistency/native direction self-consistency/no adapter recommendation residue/honest boundaries) |

## 5. Mandatory Conventions (all carried over, zero tolerance)

- **Execution based on facts, not speculation; code is the source of truth**; cross-validation conflicts are resolved in favor of code; all code references carry file:line.
- Deletion goes through `/data/workspace/rm_tmp_file.sh`; kill goes through `/data/workspace/kill_process.sh`; chmod goes through `/data/workspace/chmod_modify.sh`.
- lib minimal comments; commit message in English 1-3 sentences; config.ini local test values not committed; run `make clean` before compiling after code changes (not applicable to this pure research round).
- This machine has dual NICs: DPDK-exclusive NIC IP `<DPDK_NIC_IP>` requires `ssh f-stack-client` to test; kernel stack is tested against `127.0.0.1` lo.
- **Writer/reviewer separation**: writer ≠ reviewer ≠ leader (leader only writes pure-summary content, reviewed by an independent gatekeeper).
- Leader polls and waits + out-of-band probing first + timeout detection + exception fallback; leader must not exit early before all subagents finish.
- Gate failure bounces back to the previous step for rework; bounce≤3 per step, otherwise escalate to human decision.

## 6. References

- Old material (referable but must be re-organized around the native goal and re-verified against code; copying the old adapter recommendation verbatim is forbidden): `docs/multi_thread_spec/zh_cn/_material_code.md`, `_material_web.md`.
- f-stack three-layer architecture docs and knowledge graph: `docs/`.
- FreeBSD 15.0 source: `/data/workspace/freebsd-src-releng-15.0/` (VNET/pcpu/curthread/UMA per-CPU).
- DPDK source: `/data/workspace/dpdk-stable-24.11.6/` (`rte_eal_remote_launch`/lcore/`RTE_PER_LCORE`/mempool MT-safe).
