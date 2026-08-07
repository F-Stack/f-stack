# plan-16 Multi-Queue Comparison and Correction: Overturning "virtio Lacks RSS Causing native-mt Multi-Thread Failure"

> **Doc ID**: PLAN-NMT-16
> **Version**: v1
> **Date**: 2026-08-03
> **Nature**: this round's master plan (plan first, then execute)
> **Evidence rule**: all conclusions must come from actual runs/actual code; speculation forbidden; when code conflicts with docs/external material, **code wins**.

---

## 0. Positioning of This Round: Correct Doc 15's Conclusion

### 0.1 User Challenge (valid)

Doc 15 (`15-worker-clock-gap-fix-and-virtio-rss-limitation.md` Section 5) concluded:

> "The final bottleneck of 2-thread throughput was located as virtio PMD lacking RSS/RETA support (environment limitation, not a code defect)"

The user pointed out this conclusion does not hold, for these reasons:
1. Although virtio does not support standard RSS (RETA redirection table), it **has its own receive-side load balancing** (`VIRTIO_NET_F_MQ` + vhost/tun-side flow steering);
2. If **`thread_mode=0` with 2 workers (2 processes / 2 queues)** is used as a comparison test, performance should be normal — then the original conclusion is overturned.

### 0.2 Verified Evidence: The Original Comparison Experiment Design Indeed Had a Flaw

Doc 15 Section 6's comparison table:

| Tested config | Queue count | Result |
|---|---|---|
| `thread_mode=1` + `lcore_mask=2` | **1** | 209,790 req/s |
| `thread_mode=1` + `lcore_mask=6` | **2** | 557 / 0 req/s |
| `thread_mode=0` + `lcore_mask=2` | **1** | 216,812 req/s |

**Missing item**: `thread_mode=0` + **2 processes with 2 queues**.

Therefore the original experiment wrongly attributed the "1 queue vs 2 queue" difference to the "process mode vs thread mode" difference. To prove "multi-queue unusable in this virtio environment", one must prove `thread_mode=0` dual queues are **also** unusable; that experiment was never run.

### 0.3 Verified Code Facts (not speculation)

| Fact | Location | Content |
|---|---|---|
| virtio `reta_size` depends on `VIRTIO_NET_F_RSS` | `dpdk-stable-24.11.6/drivers/net/virtio/virtio_ethdev.c:2660-2669` | host advertises `VIRTIO_NET_F_RSS` → `reta_size = VIRTIO_NET_RSS_RETA_SIZE`; otherwise `reta_size = 0`, `flow_type_rss_offloads = 0`, `hash_key_size = 0` |
| Multi-queue capability is an **independent** feature | `dpdk-stable-24.11.6/drivers/net/virtio/virtio_ethdev.c:1840-1852` | `max_virtqueue_pairs` is read if **either** `VIRTIO_NET_F_MQ` **or** `VIRTIO_NET_F_RSS` is advertised; `max_queue_pairs` forced to 1 only when neither is present |
| f-stack-side RSS config skipped | `f-stack/lib/ff_dpdk_if.c:885-926` | the whole RSS config block (`mq_mode = RTE_ETH_MQ_RX_RSS`, `rss_hf`, `rss_key`, `ff_rss_thash_build_key`) is wrapped in `if (dev_info.flow_type_rss_offloads)`; virtio has no RSS → **the whole block does not execute** |
| `rss_reta_size` stays 0 | `f-stack/lib/ff_dpdk_if.c:1009-1016` | assigned and prints `rss table size` only when `dev_info.reta_size` is non-zero |

**Key corollary (this round's core to be validated)**: the above "no RSS" code path is **fully shared** between `thread_mode=0` and `thread_mode=1` (`init_port_start` does not distinguish thread_mode). Therefore:

- If `thread_mode=0` dual queues are **normal** → "no RSS causes multi-queue failure" is **overturned**; the `thread_mode=1` problem must be in thread_mode-specific code paths;
- If `thread_mode=0` dual queues **also fail** → the original conclusion's direction holds, but one still must supply evidence on whether virtio MQ negotiated successfully (cannot conclude merely from the absence of an "rss table size" log line).

### 0.4 This Round's Only Goal

Use **measurement** to decide the above dichotomy, and when judged "code defect", locate and fix so that `thread_mode=1` multi-threading reaches usable throughput (must not be shelved as a "remaining item" unless confirmed unimplementable after 3 bounces).

**Hard boundaries (carried over, must not be violated)**:
1. **Never add locks to the core data-plane path, and must not attempt a lock-based solution**; locks allowed only in non-data-plane paths such as init.
2. `thread_mode=0` (multi-process) **zero regression**.
3. The per-vnet protocol-stack isolation design must not regress into "shared single stack + global lock".

---

## 1. Hypothesis List (Each to Be Judged by Measurement This Round)

| ID | Hypothesis | Judgment method | Expected evidence |
|---|---|---|---|
| **H0** | `thread_mode=0` dual-process dual-queue **works normally** in this virtio environment | E2 experiment | wrk req/s at a normal scale (≥100k) |
| H5 | virtio MQ (`VIRTIO_NET_F_MQ`) negotiated successfully, dual queues genuinely effective | read ff_log/DPDK PMD logs + actual `rte_eth_dev_info` values | `max_rx_queues > 1`; dual-queue rx_queue_setup success |
| H6 | under `thread_mode=1`, the `dispatch_ring` / `msg_ring` arrays are allocated by `nb_procs`(=1) instead of `nb_threads`, and worker `proc_id=1` accesses uninitialized elements out of bounds | code walk `ff_dpdk_if.c:548 / 690-692 / 2106 / 2335-2348` + probes | ring pointer NULL or not created |
| H7 | under `thread_mode=1`, the main-thread ifp (`veth_ctx` index) and the worker ifp ownership misalign (`veth_ctx[lcore][port]` main-thread entry written with a different lcore index during the `ff_freebsd_init` phase) | code walk `ff_dpdk_if.c:2649-2664` + `ff_veth.c` | main-thread lcore's `veth_ctx` entry NULL or pointing to someone else's |
| H8 | KNI ownership (`ff_kni_is_owner_thread`) swallows packets that should enter the stack under thread_mode=1 dual queues | disable `kni.enable` and re-test + probes | throughput recovers after disabling KNI |
| H9 | without RSS, f-stack does not configure `mq_mode`; the NIC distributes by virtio's default policy; packets landing on a non-owner queue are **not software-redistributed** because `packet_dispatcher` is not registered, entering the wrong vnet directly | code walk `ff_dpdk_if.c:1983-2029` + per-queue receive probes | SYN lands on queue A but the socket is in vnet B |

> H9 and H0 are complementary: even if `thread_mode=0` dual queues go through the same dispatch logic, **each multi-process has an independent vnet and all listen on the same port**, so any queue receiving a SYN can complete the handshake locally; whereas under `thread_mode=1`, if the listen socket is only built in some vnets (depending on app behavior), a SYN landing on the wrong queue gets no response. **This is the current strongest candidate**; must be verified by measurement, writing conclusions first is forbidden.

---

## 2. Experiment Matrix (All Must Be Actually Executed)

Unified load command (user-specified, must not change):

```
ssh f-stack-client "/data/wrk/wrk -t5 -c100 -d10s http://<DPDK_NIC_IP>:80/"
```

Unified prerequisite: before each startup, `pgrep` to confirm no residual helloworld processes; if present, clean via `/data/workspace/kill_process.sh` (**`kill`/`pkill`/`killall` strictly forbidden**).

| Experiment | thread_mode | lcore_mask | Processes | Queues | Purpose |
|---|---|---|---|---|---|
| **E1** | 0 | 2 | 1 | 1 | single-queue baseline reproduction (anchor) |
| **E2** | 0 | 6 | **2** (primary `--proc-id=0` + secondary `--proc-id=1`) | **2** | **This round's key**: judge H0 |
| **E3** | 1 | 6 | 1 (2 threads) | 2 | reproduce doc 15's failure |
| E4 | 1 | 6 | 1 (2 threads) | 2 | post-fix re-test |
| E5 | 0 | 2 / 6 | 1 / 2 | 1 / 2 | post-fix zero-regression re-test |

E2 execution points (must verify first, no fabricated command lines):
- `config.ini` `[port0] lcore_list` must explicitly cover both lcores;
- the two processes each have their own `--proc-id`, DPDK primary/secondary;
- KNI handled only by primary (the existing `ff_config.c` validation requires the primary lcore to be in the lcore_list).

**config.ini local test values (`lcore_mask`/`thread_mode`/local IP/`idle_sleep` etc.) are never committed.**

---

## 3. Agent Team Division of Labor (1 leader + subagents, writer/reviewer separation)

Team name: `nmt-mq-parity`

| Role | Agent | Phase | Responsibility | Allowed to write? |
|---|---|---|---|---|
| leader | main agent | whole | orchestration, polling/waiting, out-of-band probing, timeout/exception fallback, experiment execution and data aggregation (pure execution/aggregation single-role tasks may be handled directly) | plan/aggregation only |
| A. Code probing | subagent (read-only) | M1 | **all code-path differences** between thread_mode=0 vs 1 (ring allocation, veth_ctx, KNI ownership, queue mapping, vnet/listen-socket ownership), verify H6/H7/H8/H9 | No (read-only) |
| B. External research | subagent (read-only) | M1 | virtio MQ/RSS, vhost flow steering, f-stack github issue/wiki/blog "virtio multi-queue + f-stack multi-process" evidence, cross-validate; code wins on conflict | No (read-only) |
| C. Fix implementation | subagent | M3 | implement code fix per verdict (zero data-plane locks), `make clean` then full build | Yes (code) |
| D. Independent review | subagent (≠C) | M4 | review C's changes: zero-lock constraint, thread_mode=0 zero regression, per-vnet isolation completeness, no debug residue | No (review only) |
| E. Doc writing | subagent | M5 | write doc 16 spec (conclusion + measured data + correction note) and revise doc 15's conclusion | Yes (docs) |
| F. Gate | subagent (≠E) | M6 | verify each `file:line` reference and each data point in the docs matches reality; wording does not overstep the evidence boundary | No (review only) |

**Role-separation iron rule**: writers (C/E) and reviewers (D/F) must be different agents; if the leader takes over any "write" task, the subsequent review must spawn a new subagent, never self-write-self-review.

**Timeout and fallback mechanism (leader must execute)**:
- each subagent gets an **8-minute** soft timeout;
- polling period **90 seconds**: `send_message` inquiry + **out-of-band probing first** (directly read files the subagent should have produced / `git status` / log artifacts);
- message unanswered but out-of-band probing shows output → keep waiting;
- timeout with no output → fallback: ① leader takes over (subsequent review must spawn a new review agent); ② spawn a new same-role subagent to re-run; ③ escalate per bounce≤3 to human.
- **Before all subagents finish, the leader must not exit early / aggregate early / `team_delete`.**

---

## 4. Milestones and Gates

| Milestone | Content | Gate (on failure, bounce back to previous step) |
|---|---|---|
| **M0** | plan written (this doc) | plan covers hypotheses/experiment matrix/division/gates/conventions |
| **M1** | code-path-difference probing (A) + external cross-research (B) **in parallel** | every H6-H9 has `file:line`-level evidence or an explicit "no evidence" conclusion; no "speculation" wording |
| **M2** | execute E1/E2/E3, produce measured data | E2 must actually run with raw wrk output; process/queue counts must have evidence (logs or `ps`) |
| **M3** | verdict + fix implementation (C) | `make clean` then full build passes (**incremental build forbidden**); zero data-plane locks |
| **M4** | independent review (D) | all 6 audit items PASS |
| **M5** | E4/E5 re-tests + doc writing (E) | post-fix thread_mode=1 dual-thread throughput usable; thread_mode=0 zero regression |
| **M6** | gate verification (F) + commit | all doc references/data points verified consistent; commit message English 1-3 sentences; `config.ini` local values not committed |

**bounce counter**: counted independently per step; same step bounces **≤3 times**; if the 3rd bounce still fails → **stop the task, escalate to human decision**; no pass-with-disease, no shelving as "remaining items".

---

## 5. Mandatory Conventions (zero tolerance, apply throughout)

1. **Actual execution**: all conclusions must have actual run output or `file:line` code evidence; giving results without execution is strictly forbidden.
2. **Cross-validation**: code / docs / external three-way cross-check; on conflict **actual code wins**.
3. **Deletion**: always `/data/workspace/rm_tmp_file.sh <path...>`; **`rm` strictly forbidden** (including in comments and inside remote ssh command strings).
4. **Killing processes**: always `/data/workspace/kill_process.sh <pid|name>`; **`kill`/`pkill`/`killall` strictly forbidden**.
5. **Changing permissions**: always `/data/workspace/chmod_modify.sh <mode> <path...>`; **`chmod` strictly forbidden**; `make install`-type allowed.
6. **Compiling**: after every code change, **`make clean` then full rebuild**; incremental-build success is not "compiled successfully".
7. **Comments**: `lib/` only very necessary comments; no long essays; no comments on self-explanatory code.
8. **Commits**: commit message English, 1-3 sentences; `config.ini` local test changes not committed (must review `git diff` before `git add`).
9. **Zero data-plane locks**: never add locks to the core data-plane path, nor attempt lock-based solutions.

---

## 6. Deliverables

| Deliverable | Path |
|---|---|
| This plan | `docs/native_mt_spec/zh_cn/plan-16-多队列对照纠偏.md` |
| This round's conclusion doc | `docs/native_mt_spec/zh_cn/16-多队列对照实验与根因纠偏.md` |
| Doc 15 conclusion revision | `docs/native_mt_spec/zh_cn/15-worker时钟缺口修复与virtio-RSS限制.md` (add correction pointers in Sections 5/9) |
| Code fix | `lib/` (depending on verdict) |
| Local commit | English message 1-3 sentences |
