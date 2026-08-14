---
name: f-stack-dev-rule
description: Mandatory development rules for the F-Stack project (zero tolerance). Covers: shell operations must go through rm_tmp_file.sh / kill_process.sh / chmod_modify.sh scripts, make clean before full rebuild after code changes, local config.ini test values must not be committed, no real IPs in docs (use placeholders), English commit messages (1-3 sentences), English-only short comments in F-Stack code, minimal comments in lib/, multi-agent collaboration rules (write/review separation, bounce<=3, leader polling without early exit), no speculation without actual execution (code is authoritative), all question/analysis/research tasks must use the f-stack-info-search skill, task sizing and harness workflow (large tasks: multi-agent research producing a Chinese spec for human review -> human-triggered implementation and acceptance -> plan.md review first -> multiple milestone commits -> translate the spec to English after acceptance), and code changes must complete unit tests plus runtime regression tests subject to gate rules. Use this skill for any development, debugging, testing, or commit task in the /data/workspace/f-stack workspace.
---

# F-Stack Mandatory Development Rules

This skill is a collection of mandatory rules for all development tasks in the /data/workspace/f-stack workspace. Violating any of them causes the task to be bounced back for correction. Zero tolerance.

## 1. Shell Operation Script Rules

Direct invocation of rm / kill / chmod command families is forbidden. Always use the following scripts:

### 1.1 Delete files -> /data/workspace/rm_tmp_file.sh

- Single file: `/data/workspace/rm_tmp_file.sh /full/path/to/file`
- Multiple files: `/data/workspace/rm_tmp_file.sh /path/a /path/b`
- Directory: `/data/workspace/rm_tmp_file.sh /full/path/to/dir`
- Trash location: `/tmp/.trash` (keeps the path prefix for traceability)
- Permanent purge: `/data/workspace/rm_tmp_file.sh --purge <trash_path> [--older-than Nd] [--dry-run]` (purge whitelist is only /tmp/.trash, /data/.Trash-0/files, /data/.Trash-0/info)
- Forbidden: direct `rm`, `rm -rf`, `find -delete`, or embedding rm inside bash snippets
- Bulk deletion of *.o etc.: first collect absolute paths with `ls`/`find`, then pass them all to the script at once

### 1.2 Stop processes -> /data/workspace/kill_process.sh

- Single PID: `/data/workspace/kill_process.sh <pid>`
- Multiple PIDs: `/data/workspace/kill_process.sh <pid1> <pid2>`
- Forbidden: `kill`, `pkill`, `killall`, `kill -9`, `pgrep | xargs kill`, kill embedded in trap/cleanup, or any other form

### 1.3 Change permissions -> /data/workspace/chmod_modify.sh

- Usage: `/data/workspace/chmod_modify.sh <mode> <path1> <path2> ...` (mode is compatible with chmod(1), octal or symbolic)
- Forbidden: direct `chmod`, `chmod -R`, `install -m`, `setfacl`, or any other form
- Note: the script snapshots pre-change permissions to /tmp/.trash/, audits to /data/workspace/.chmod_audit.log, refuses high-risk paths, and warns on setuid/setgid bits

### 1.4 General rules

- make clean / make install and other build-system targets are build tool operations and may run directly
- If a script lacks a needed feature (e.g. --reference=), extend the script first, then use it; no temporary bypasses allowed

## 2. Build Rules

- After modifying any .c/.h file, run `make clean` (or an equivalent full-clean target) before a full rebuild; incremental builds are forbidden
- Header changes affect every translation unit that includes them; clean is required even for a single-file change
- Build verification is only valid with a clean build; a passing incremental build is not evidence
- After modifying a common header, verify every file that includes it still compiles; a full make with no errors is required before a PR
- Two known local build pitfalls and their workarounds:
  - The IDE-injected safe-delete hook blocks the rm inside make clean: use `PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin" make clean`
  - `make -j16` races with machine_includes: run `make machine_includes` first, then `make -j16`
- Baseline reference: lib builds with error 0 / warning 51 (existing baseline; new changes must not add warnings)

## 3. config.ini Rules

- For config.ini and similar committed config files, only changes directly related to the current feature may be committed
- Never commit local test/debug environment tweaks: lcore_mask, vlan_filter, idle_sleep, real local IPs in [portN], temporary perf-tuning values, etc.
- Always review `git diff` item by item before `git add config.ini`
- Never restore local test values with `git checkout config.ini` (local config is required for local runs and must be kept)
- Correct approach: do not select config.ini in git add; leave local test values in the unstaged area

## 4. No Real IPs in Docs

- Never record real IPs of the local runtime environment in any document (docs, README, spec, test reports, execution logs, commit messages, PR comments, etc.)
- Use descriptive placeholders: `<DPDK_NIC_IP>`, `<DPDK_NIC_IPV6>`, `<KERNEL_NIC_IP>`, `<CLIENT_IP>`, `<CLIENT_IPV6>`, `<GATEWAY_IP>`, `<GATEWAY_IPV6>`, `<BROADCAST_IP>`, `<NETWORK_PREFIX>`, `<VIP_IPV6>`, `<BACKEND_IPV6>`, etc.
- Generic forms (e.g. 9.134.x) are allowed; complete real addresses are forbidden
- `127.0.0.1` and `fe80::` link-local addresses may be written

## 5. Commit Rules

- Commit messages are always in English, 1-3 short sentences, no long essays
- Local config.ini test values must not be committed (see section 3)
- Fixing an accidental commit uses forward-fix (a new commit to roll back), never rewriting history

## 6. Code Comment Language Rules

- F-Stack project (/data/workspace/f-stack, including all code files under lib/, freebsd/, example/, tests/, etc.): comments and git commit messages must use short English; Chinese is forbidden
- Documentation files (docs/*.md, Chinese spec docs) are exempt and follow the required document language

## 7. Minimal Comments in lib/

- Only add comments where truly necessary: public interface contracts (e.g. ff_api.h), config item meanings (e.g. config.ini), and genuinely complex/non-obvious algorithms or edge handling
- Never comment self-evident code (simple assignments, obvious branches, self-explanatory calls)
- Even for complex logic, keep comments concise; prefer clear naming and structure for self-explanatory code

## 8. Multi-Agent Collaboration Rules

Applies to harness-engineering + multi-agent (agent team / spec-driven) tasks:

- **Leader must not exit early**: the leader must not end the task before every sub-agent reports its final result; actively poll and wait
- **Sub-agent timeout detection**: no unbounded waiting; side-channel probing (reading written files, git status, artifacts) takes priority over message probing
- **Write/review separation**: writing code/docs and reviewing must be done by different agents; the leader must never write and review its own work; pure research/probing/summarizing single-role tasks may be done by the leader
- **bounce<=3**: any stage-gate failure must bounce back to the previous step for a fix, never ship with known failures; after 3 bounces on one step, stop immediately and escalate to a human decision
- **Failure fallback**: on sub-agent timeout/stall/verdict conflict, the leader may take over or spawn a new agent to redo it, without violating write/review separation

## 9. No Speculation Rules

- All actions must actually be executed; never give results based on guesswork without execution
- Cross-verify code/docs/external data sources; where they conflict, the actual code is authoritative
- Items that cannot be statically verified or where the environment is insufficient must be honestly marked "unverified/not executed"; never assert PASS by assumption

## 10. Information Search Rules

- All question/analysis/research tasks must use the **f-stack-info-search** skill to search for information
- Coverage: issue analysis, bug location, feature research, information gathering before design, technical Q&A, and any other scenario requiring research
- Follow the five parts of f-stack-info-search: architecture docs and knowledge graph -> commit history -> related issues/PRs -> public resources -> internal/external websites, blogs, WeChat articles, etc.
- Cross-validation: converge evidence from internal docs + external resources + actual code/testing; where they conflict, the actual code is authoritative
- Never answer or conclude based on guesswork without searching

## 11. Runtime Test Environment

- This machine has two NICs: the DPDK-exclusive NIC and eth1 are different cards
- Testing DPDK NIC programs: access the DPDK-managed NIC on this machine from the peer via `ssh f-stack-client` (use the `<DPDK_NIC_IP>` placeholder)
- Testing the kernel stack on this machine: use 127.0.0.1 on lo
- Stop processes via kill_process.sh, clean temp files via rm_tmp_file.sh, restore config.ini temp test values after testing, and never commit them

## 12. Task Sizing and Harness Workflow Rules

- Judge the task size automatically from the prompt or by the model: small tasks may be analyzed and executed directly; large tasks must follow these steps:
- 12.1 Feature research: first complete feature research using the multi-agent harness approach, producing a Chinese spec document (other spec-related skills may be installed and used) plus gate review; Chinese docs go under `docs/<FEATURE_NAME>_spec/zh_cn/`; **do not produce the English spec yet** (translate it only after feature acceptance); submit for human review
- 12.2 Implementation and acceptance: after the human review of the spec passes, a human prompt triggers the actual implementation and acceptance phase (multi-agent harness approach, following all multi-agent rules), completing code writing, CR, testing (unit tests and runtime tests), doc updates, and gate reviews at each milestone
- 12.3 Both spec generation and actual implementation must first produce a plan.md for human review before execution
- 12.4 Make multiple git commits by milestone
- 12.5 After test acceptance completes, translate the Chinese spec docs under `docs/<FEATURE_NAME>_spec/zh_cn/` into English (both file names and contents must be translated) and place them under `docs/<FEATURE_NAME>_spec/`

## 13. Test Gate Rules

- Any change involving code must complete unit tests and runtime regression tests
- Unit tests and runtime regression tests are subject to the same gate rules (bounce<=3, write/review separation, etc.; see section 8)
