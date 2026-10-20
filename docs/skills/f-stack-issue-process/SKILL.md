---
name: f-stack-issue-process
description: Standard operating procedure (SOP) for analyzing and processing F-Stack/f-stack GitHub issues. Use when analyzing, judging the status of, replying to, closing, or batch-processing issues of the F-Stack/f-stack repository. Includes a three-step flow (read the full issue -> search for information (invoke the f-stack-info-search skill) -> comprehensive judgment), five conclusion templates, rules for syncing the local issue analysis archives (docs/f-stack-issue-ana.md and docs/zh_cn/f-stack-issue-ana.md), the safety constraint of never operating issues automatically, DPDK version tracking, and issue ownership classification. Trigger words: analyze issue, issue processing, issue #N, batch analyze issues, reply to issue, close issue.
---

# F-Stack Issue Analysis and Processing SOP

Scope: analyze issues of the F-Stack GitHub repository (F-Stack/f-stack), judge their status, and give processing suggestions.

## Environment Preparation

- GitHub Token configured (GH_TOKEN environment variable)
- Official F-Stack repository cloned to /data/workspace/f-stack
- gh CLI installed

## Step 1: Read the Full Issue

The full issue text and all discussions must be obtained; never judge from the title alone.

```bash
export GH_TOKEN='<token>'

# Get the issue body
gh issue view <NUMBER> -R F-Stack/f-stack

# Get all comments (API, no truncation)
gh api repos/F-Stack/f-stack/issues/<NUMBER>/comments --jq '.[] | {user: .user.login, created_at: .created_at, body: .body}'
```

Record the following:

- Reporter (author)
- F-Stack / DPDK version
- Error symptoms (crash, performance, build failure, functional anomaly, etc.)
- Reproduction steps or environment description
- Existing discussion conclusions (whether maintainers replied, whether a solution exists)

## Step 2: Search for Information

Invoke the **f-stack-info-search** skill to search for information, which has five parts:

- Check architecture docs and knowledge graph: three-layer architecture docs under docs/ (LAYER1/2/3) + KNOWLEDGE_GRAPH_WIKI
- Check commit history: local git log search for fixing commits + DPDK upstream
- Check related Issues and PRs: first check the local issue analysis archives (docs/zh_cn/f-stack-issue-ana.md, docs/f-stack-issue-ana.md), then gh search issues/prs + DPDK Patchwork
- Check public resources: DPDK Bugzilla / Patchwork / inbox.dpdk.org / web search
- Internal/external information search for general analysis/research tasks: tech blogs / WeChat articles / tech communities / internal knowledge bases / iWiki, bilingual keyword construction and three-way evidence convergence

After the search, return to this skill and continue with Step 3 comprehensive judgment.

## Step 3: Comprehensive Judgment

Give a clear conclusion in Chinese (or English for the reply), using the following format:

### Conclusion Templates

```
## Issue #<NUMBER> Analysis Conclusion

**Title:** <issue title>
**Status:** <one of the following>

### Case 1: Already fixed
- Conclusion: fixed
- Fix commit: <hash> (<commit message>)
- Fixed in: F-Stack v<x.y> / DPDK <version>
- Backported: yes/no
- Suggested action: closable; reply telling the user to upgrade to v<x.y>

### Case 2: Upstream patch exists but not merged
- Conclusion: upstream patch not merged
- Patch link: <URL>
- Patch status: Accepted / Under Review / Superseded
- Affected versions: fix status across DPDK 22.11 / 23.11 / 24.11 LTS
- Suggested action: wait for merge / cherry-pick manually

### Case 3: Not fixed
- Conclusion: not fixed
- Root cause: <detailed description>
- Scope: <which versions/scenarios are affected>
- Fix plan: <suggested approach>
- Suggested action: development work needed

### Case 4: Workaround exists
- Conclusion: workaround exists
- Workaround steps: <concrete operations>
- Root fix needed: yes/no
- Suggested action: reply with the workaround, keep the issue open pending a root fix

### Case 5: Not a bug (usage question / outdated / cannot reproduce)
- Conclusion: not a bug / outdated / cannot reproduce
- Reason: <detailed explanation>
- Suggested action: closable; reply explaining the reason
```

## Key Notes

1. **Never operate issues automatically**
   - After analysis, human confirmation is required before commenting on or closing an issue
   - Give suggested actions but do not execute them directly
   - Wait for explicit user instructions before acting (comment, close, label, etc.)
   - Issue reply comments must be in English, do not @ anyone, no long-winded analysis, do not repeat what existing replies already contain, and state only the core conclusion and key steps

2. **Classify issue ownership**
   - F-Stack itself: code under lib/, the FreeBSD porting layer, ff_* APIs
   - DPDK upstream: code under dpdk/, drivers, EAL layer
   - User configuration: config.ini, hugepages, NIC offload, ASLR, etc.
   - Application integration: Nginx/Redis integration, multi-process architecture

3. **DPDK version tracking**

   - F-Stack v2.0 -> DPDK 24.11.6
   - F-Stack v1.25 -> DPDK 23.11.5
   - F-Stack v1.24 -> DPDK 22.11.6
   - F-Stack v1.22.1 -> DPDK 20.11.9
   - F-Stack v1.21.x -> DPDK 19.11.14
   - When DPDK versions are involved, clearly state the fix status across 22.11 / 23.11 / 24.11 LTS

4. **Sync the issue analysis archives**
   - After every reply or issue modification, the local issue analysis archives must be updated:
     - Chinese: docs/zh_cn/f-stack-issue-ana.md
     - English: docs/f-stack-issue-ana.md
   - The two archives stay consistent (bilingual), recording: issue number, title, analysis conclusion, and actions taken (reply/close/fix commit)

5. **Build fix rules**
   - After fixing a file, ensure all other files depending on it still compile
   - After modifying a common header, verify every file that includes it one by one
   - A full make with no errors is required before a PR
   - Build verification commands:

     ```bash
     # F-Stack lib build verification
     cd /data/workspace/f-stack/lib && make clean && make

     # ftdns-dev src build verification
     cd /data/workspace/ftdns-dev/src && make clean && make
     ```

## Batch Analysis Flow

When batch-analyzing multiple issues:

```bash
# 1. Get all open issues in the given range
gh issue list -R F-Stack/f-stack --state open --limit 500 \
  --json number,title,labels,createdAt,author \
  --jq '[.[] | select(.number >= <START> and .number <= <END>)] | sort_by(.number)'

# 2. Run the three-step analysis flow for each one

# 3. Produce a categorized summary report including:
#    - Total count
#    - Classification by type (Bug / feature request / usage question / build issue)
#    - Classification by status (fixed / not fixed / workaround exists / outdated)
#    - Suggested action list (which to close, which need fixes, which need replies)
```

## Relationship with Development Rules

If the issue processing involves code changes, all mandatory rules of the f-stack-dev-rule skill must also be followed (rm/kill/chmod scripts, make clean builds, config.ini not committed, no real IPs in docs, English code comments, minimal lib comments, etc.).
