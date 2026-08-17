F-Stack Development Workflow with CodeBuddy: Three Self-Built Skills + the Harness Multi-Agent Gate System — How 13 Major Features Were Completed with AI Assistance in 2026

1. What this workflow does and its key characteristics

Let's get straight to the point: F-Stack has been using CodeBuddy for AI-assisted development since early 2026, and by now "how to make AI work reliably in this large C codebase" has been distilled into a reusable workflow — three self-built skills (f-stack-dev-rule / f-stack-info-search / f-stack-issue-process) + the harness engineering multi-agent process + an end-to-end gate system. This article explains the workflow: what it consists of, what problem each part solves, and how it performed in real-world use during 2026.

The conclusion first. From the start of 2026 to now (mid-August), the list of major features completed by F-Stack with AI assistance through this workflow (data from the project's iWiki work list):

| Feature | Completed | Duration |
|---|---|---|
| LD_PRELOAD semaphore → lock-free ring IPC | 2026.05.25 | 10 days |
| FreeBSD 13.0 → 15.0 protocol stack upgrade | 2026.06.09 | 10 days |
| DPDK upgrade to 24.11 (dev branch) | 2026.06.10 | 1 day |
| Unit test framework (Unity/CMocka) | 2026.06.11 | 2 days |
| Receive zero-copy ff_zc_mbuf_read | 2026.06.11 | 1 day |
| Send zero-copy native rewrite (dropping the MAGIC hack) | 2026.06.12 | 1 day |
| lib local socket access | 2026.06.18 | 4 days |
| io_uring benchmark research | 2026.06.18 | 1 day |
| ff_rss_check optimization (IPv6 + rte_thash) | 2026.07.16 | 15 days |
| MTU change support (jumbo frame) | 2026.07.22 | 3 days |
| LRO support + TSO improvements | 2026.07.23 | 1 day |
| Multi-process vnet bonding / single-process multi-threaded multi-stack (native-mt) | 2026.08.05 | 5 days |
| Bulk issue handling 320 → 0 | 2026.08.10 | ongoing |

The unified division of labor across all these features: **all code is written by AI; humans only handle prompts, spec documents, plans, direction correction, result review, and test acceptance**. The three keywords of this article:

- **Rules first**: the first thing AI does in F-Stack is not writing code, but loading f-stack-dev-rule — 13 sections of mandatory rules with zero tolerance, front-loading every point where AI tends to fail (rm/kill/chmod, incremental builds, config.ini pollution, real IP leakage, comment style) into rules.
- **Layered skills**: three skills each cover one segment — dev-rule covers "how to change", info-search covers "how to search", issue-process covers "how to handle issues"; a batch of general-purpose skills (spec-driven, harness engineering, C development, unit testing, etc.) can be installed to match — outside the scope of this article.
- **Harness multi-agent gates**: major tasks must follow the full chain of "research → Chinese spec → human review → multi-agent implementation → gate review → milestone commits", with write-review separation and a per-step bounce limit of 3.

2. Main applicable scenarios

2.1 Major feature development (research + spec + implementation + acceptance)

Any task at the "new feature / major upgrade" level in F-Stack goes through the harness process: first a multi-agent research phase produces Chinese spec documents (under docs/<FEATURE>_spec/zh_cn/), after human review passes, a separate multi-agent effort does implementation and acceptance, with multiple milestone commits, and only after acceptance is the English spec translated. The 2026 freebsd 13→15 upgrade (47 spec documents), native-mt, and LRO/TSO were all done this way.

2.2 Issue analysis and bulk handling

The f-stack-issue-process skill defines a three-step SOP for issues (read the full text → search for information → comprehensive judgment), paired with five conclusion templates. In 2026 the project cleaned issues down from 320 to 0, semi-automated throughout: AI analyzes and archives per the SOP, humans confirm or fix and then reply to close.

2.3 Performance optimization campaigns (those needing controlled experiments)

For "optimization" tasks like ring IPC performance and RSS check optimization, AI's value lies not in writing code but in executing controlled-experiment discipline: baseline before optimization, data before theory, every hypothesis paired with a falsifiable physical quantity. The ring IPC v1~v3.7 seven-round iteration is a complete case of AI self-falsifying under rule constraints.

2.4 Scenarios that are not a good fit

- One-sentence small changes: just state the need directly; don't wrap it in the harness process (small tasks execute directly per the task-sizing rules).
- Cases requiring physical-environment validation when the environment is unavailable: the rules require "never guess without executing"; when the environment is missing, AI can only honestly mark "unverified", and forcing a conclusion is harmful.
- Token-quota-tight periods: a task like native-mt that is "tantamount to rebuilding a small f-stack" consumes enormously (iWiki's own words) and is better done after quota resets.

3. Architectural characteristics

3.1 Overall workflow diagram

```
User requirement
   │
   ▼
┌─────────────────────────────────────────────┐
│ Task sizing (f-stack-dev-rule section 12)    │
│   small task → direct analysis & execution   │
│   major task → harness process (below)       │
└────────────────────┬────────────────────────┘
                     ▼
┌─────────────────────────────────────────────┐
│ Major-task harness process                   │
│ 12.1 research: multi-agent produces Chinese  │
│      spec + gate review                      │
│      (leader + search/arch-probe/design/     │
│         writing/review sub-agents)           │
│   ↓ human spec review                        │
│ 12.2 implementation & acceptance:            │
│      multi-agent coding + CR + testing       │
│ 12.3 generate plan.md first for human        │
│      review before each phase executes       │
│ 12.4 multiple git commits by milestone       │
│ 12.5 translate the English spec after        │
│      acceptance                              │
└────────────────────┬────────────────────────┘
                     ▼
┌─────────────────────────────────────────────┐
│ Execution-time support from the three skills │
│ ┌──────────────┐ ┌──────────────┐ ┌────────────────┐ │
│ │dev-rule      │ │info-search   │ │issue-process   │ │
│ │13 mandatory  │ │5-part search │ │3-step SOP +    │ │
│ │rule sections │ │process       │ │5 conclusion    │ │
│ └──────────────┘ └──────────────┘ └────────────────┘ │
└────────────────────┬────────────────────────┘
                     ▼
        Gate system (write-review separation +
        bounce ≤ 3 + test gates)
```

3.2 The division of labor among the three self-built skills

**f-stack-dev-rule (how to change)**: the mandatory rule collection for every task in the F-Stack workspace — 13 sections, zero tolerance. The core items: shell operations must go through the three scripts rm_tmp_file.sh/kill_process.sh/chmod_modify.sh (direct rm/kill/chmod strictly forbidden); make clean before full rebuild after code changes (incremental builds do not count as verification); config.ini local test values must not be committed; documents must never contain real IPs — use placeholders; commit messages in English, 1-3 sentences; minimal comments in lib; multi-agent write-review separation / bounce ≤ 3 / leader must keep polling without early exit; all research-type tasks must use info-search; task sizing and the harness process; code changes must pass unit tests and runtime regression tests.

**f-stack-info-search (how to search)**: the information-search SOP for all question/analysis/research tasks, in five parts: consult the three-layer architecture docs and knowledge graph (LAYER1/2/3 + KNOWLEDGE_GRAPH_WIKI under docs/) → check code commit history (local git log + DPDK upstream) → check related issues/PRs (local issue archive first, then gh search) → check public sources (DPDK Bugzilla/Patchwork/mailing lists) → internal and external technical material (blogs/WeChat articles/iWiki, with bilingual Chinese-English keywords). The core discipline is three-way evidence convergence: internal docs + external material + actual code, with the actual code prevailing on any conflict.

**f-stack-issue-process (how to handle issues)**: a three-step SOP — read the full issue text (including all comments, never the title alone) → invoke info-search → comprehensive judgment. Five conclusion templates (fixed / upstream patch unmerged / unfixed / workaround available / not a bug), with the key constraint of **never auto-operating on issues**: after analysis, human confirmation is required before commenting or closing; replies are in English and state only the core conclusion. **After each handling, the Chinese and English issue analysis archives (f-stack-issue-ana.md) are updated in sync — new knowledge points can be added continuously for later issue analysis and problem research.**

3.3 The gate system (the brakes on AI work)

```
Write code/docs ──► independent agent review ──► PASS ──► next milestone
                        │ FAIL
                        ▼
                   bounce back for fixes (bounce counter)
                        │
                   bounce > 3 → stop the task, hand to a human
```

- **Write-review separation (iron rule)**: writing code/docs and reviewing must be different agents; the leader must never write and review its own work; pure research/probing/summary single-role work can be done by the leader.
- **Leader polling**: the leader must not exit early before every sub-agent reports its final result; indefinite dead-waiting is forbidden — side-channel probing (reading landed files, git status) takes priority over message probing. Otherwise agents like CodeBuddy frequently hit cases where a subprocess exits abnormally for various reasons, interrupting the whole task and requiring a human to continue it.
- **Abnormal fallback**: when a sub-agent times out or stalls, the leader takes over or spawns a new agent to redo the work, without violating write-review separation.
- **Test gates**: code changes must complete unit tests and runtime regression tests, subject to the same gate rules.

4. What was built, what problems were hit, and how they were solved

The rest is a bit dry; skip this section if you don't need the implementation details and jump straight to Section 5.

4.1 How the skill system grew (from scattered rules to three skills)

This system was not designed in one shot — it was forced out by real-world problems. It started completely bare, gradually hit pitfalls and refined itself during AI development, and was later consolidated into the single f-stack-dev-rule skill for unified loading (13 sections), replacing more than ten scattered individual rules. info-search and issue-process were distilled from issue-handling practice: issues must be researched before concluding, searching has a fixed five-part process, conclusions have five templates, archives must be kept in sync in Chinese and English — these "how to do it right" lessons were solidified into skills.

The skills land in a "library + source" dual form: installed under ~/.codebuddy/skills/ for CodeBuddy to load, with a source copy kept under docs/zh_cn/skills/; the rules explicitly state "if use_skill is unavailable before installation, read the full SKILL.md under docs/zh_cn/skills/ directly and follow it as the rules". Any zero-tolerance violation bounces the task immediately.

[Note 1] One rule deserves a standalone mention: the three scripts rm_tmp_file.sh/kill_process.sh/chmod_modify.sh are not formalism — a misuse of rm -rf happened once during the ZC-recv measurements in June 2026 (recorded and fixed in the M2 report). The rules constrain the most common dangerous actions of AI; the scripts carry audit logs (chmod snapshots to /tmp/.trash/, audits to /tmp/.chmod_audit.log), so problems can be traced back.

4.2 Real problem 1: AI can "look right but be entirely wrong"

The local socket access feature (2026.06.18, 4 days) is a typical counter-example — iWiki's own words: "AI performed poorly on this feature; it was bounced back and reworked many times before final completion". This shows the two most valuable links in the process are "human review" and "bounce-back", not AI's ability to get it right in one pass. In the rules this corresponds to the bounce ≤ 3 chain: a gate failure must bounce back to the previous step for fixes; more than 3 bounces on one step stops the task for human decision — no passing with defects.

4.3 Real problem 2: AI guesses; the "seeking-truth" rules keep it in check

Rule sections 9 (seek truth from facts) and 10 (information search) exist precisely for this: every action must be actually executed — never produce results from guessing without execution; cross-verify code/docs/external sources, with actual code prevailing on conflicts; items that cannot be statically confirmed or lack the environment must be honestly marked "unverified / not executed". The ring IPC performance analysis v1~v3.7 seven-round iteration is the best footnote to these rules: v1's one-sided code-analysis error, v2's unverified hypothesis, v3.3's Plan C measured 4% regression and same-day rollback — every wrong step was falsified by measured data, finally converging on the counter-intuitive but correct conclusion "ring has no net win; sem is recommended for production".

4.4 Real problem 3: build hygiene and the incremental trap

The most common pitfall when AI writes C code is incremental builds: after switching FF_ZC_* flags, make skips .o recompilation by timestamp, leaving the kernel hook missing and producing the bizarre http=000 symptom (the ZC M2 report). The rules hard-code "make clean before code changes, verification counts only with a clean build, incremental builds do not count", and even include workarounds for two known local pitfalls (the IDE safe-delete hook intercepting make clean is avoided with a PATH prefix; the make -j16 race is avoided by running make machine_includes first). The "macro rename losing a wrapper" pitfall from the freebsd 13→15 upgrade (UMA_MD_SMALL_ALLOC → UMA_USE_DMAP) and the "header struct change without clean rebuild causes ABI skew" pitfall were also distilled into rule clauses.

4.5 Real problem 4: token consumption and task splitting

The iWiki note for native-mt (2026.08.05, 5 days) is honest: "this feature is extremely complex, tantamount to rebuilding a small f-stack, and consumes a lot of tokens" — the residual risks were recorded truthfully and work paused, to resume after token quota resets. This shows the harness process has one more real-world constraint: tasks must be split into milestones by token budget, and when something cannot be finished it is better to leave honest archives (residual risk lists) than to paper over the ending. Bulk issue handling 320→0 was practice in the other direction — semi-automated per the SOP using imate (the intranet OpenClaw) during token-tight periods (GLM-5.2 does not count against the quota).

[Note] As of now (2026.08.17), for the initial research, architecture documentation, and task breakdown of major tasks, high-cost models such as OPUS-5/Codex are still recommended (**quota consumption is very, very large — special attention needed**); after the breakdown, the actual coding and other small/concrete tasks can be handed to models like GLM-5.2/DSV4. Side note: Deepseek-V4.0-pro-0813 currently still performs terribly on research analysis and architecture design in large repositories and major tasks; GLM-5.3's performance has not been measured yet.

4.6 The documentation assets accumulated across the 2026 features

Every major feature left complete documentation through the harness process: freebsd_13_to_15_upgrade_spec (47 documents), zc_stack_user_spec (37 documents), ld_preload_ring_spec, mtu_change_spec, lro_tso_spec, native_mt_spec, the RSS check optimization spec, and more, plus the three-layer architecture docs (LAYER1/2/3) and the knowledge graph (KNOWLEDGE_GRAPH_WIKI). These documents in turn became the search sources for info-search — documents → code → decisions form a closed loop.

[Note] After a new feature lands, the architecture docs and the knowledge graph should be updated accordingly; otherwise info-search's search sources go stale and later research gets outdated conclusions. The updates can be enforced by process (including doc-update items in each milestone) or automated — e.g., git operations automatically triggering a knowledge-graph rebuild (the GitNexus background updates after every commit are exactly this kind of mechanism).

5. How to use it, how to configure it, and the results

5.1 Skill installation and loading

All three skills are installed under ~/.codebuddy/skills/ (f-stack-dev-rule / f-stack-info-search / f-stack-issue-process) and loaded on demand with use_skill in CodeBuddy sessions. Any task in the F-Stack workspace loads f-stack-dev-rule first; question/analysis/research tasks must load f-stack-info-search; issue analysis and handling loads f-stack-issue-process (whose search phase internally invokes info-search).

5.2 Companion general-purpose skills (install to match, not expanded here)

General-purpose skills such as spec-driven development (spec-driven), harness engineering (harness-engineering), C development/unit testing (c-pro, c-unittest-expert, etc.), and C precision-surgery modifications (c-precision-surgery) combine with F-Stack's three self-built skills — the self-built skills enforce "F-Stack-specific constraints", while the general-purpose skills enforce "general engineering methods".

5.3 Results (2026 measured data)

| Dimension | Data |
|---|---|
| Major features completed with AI assistance | 13 (about 54 working days cumulative; calendar time far shorter thanks to AI parallelism) |
| Largest single task | FreeBSD 13→15 upgrade (10 days, 47 specs, 26 commits, 5-cell build matrix all green) |
| Issue cleanup | 320 → 0 (cleared 2026.08.10) |
| Build baseline | lib error 0 / warning 51 (existing baseline, zero new warnings from changes) |
| Documentation assets | 7 feature spec directories + three-layer architecture docs + knowledge graph + bilingual issue archive |
| Blog articles | 8 in the F-Stack 2.0 Preview series (Chinese + English), to be published progressively |

5.4 Advice for users

- Read the rules before letting AI touch anything: each of dev-rule's 13 sections was bought with real-world experience; any violation bounces the task back from human review.
- Don't skip the spec phase for major tasks: the Chinese spec + human review is the cheapest direction-correction point; the local socket rework proves that "skipping research and coding directly" is more expensive.
- Trust the gates, not single outputs: anything AI writes must pass an independent agent review; bounces are normal process, not failure.
- Let AI honestly say "I don't know": when the environment is missing, mark "unverified" — that is worth far more than forcing a conclusion.

Further reading:

- Mandatory development rules: docs/zh_cn/skills/f-stack-dev-rule/SKILL.md
- Information search skill: docs/zh_cn/skills/f-stack-info-search/SKILL.md
- Issue handling SOP: docs/zh_cn/skills/f-stack-issue-process/SKILL.md
- Three-layer architecture docs: docs/01-LAYER1-ARCHITECTURE.md
- Knowledge graph: docs/KNOWLEDGE_GRAPH_WIKI.md
- Historical issue archive: docs/f-stack-issue-ana.md
- 2026 feature specs: docs/<FEATURE>_spec/ (freebsd_13_to_15_upgrade_spec, zc_stack_user_spec, ld_preload_ring_spec, mtu_change_spec, lro_tso_spec, native_mt_spec, etc.)
