---
name: f-stack-info-search
description: F-Stack information search skill. Use when gathering evidence for issue analysis, bug location, or feature research in the F-Stack/f-stack repository. Contains five parts: check project architecture docs and knowledge graph (three-layer architecture docs LAYER1/2/3 and KNOWLEDGE_GRAPH_WIKI under docs/), check commit history (local git log search for fixing commits + DPDK upstream), check related Issues and PRs (first check the local issue analysis archives docs/f-stack-issue-ana.md and docs/zh_cn/f-stack-issue-ana.md, then gh search issues/prs + DPDK Patchwork), check public resources (DPDK Bugzilla/Patchwork/inbox.dpdk.org/web search), and internal/external information search for general analysis and research tasks (tech blogs/WeChat articles/tech communities/internal knowledge bases/iWiki, bilingual keyword construction and three-way evidence convergence). Invoked by the search step of the f-stack-issue-process skill; can also be used standalone. Trigger words: check commit history, search for information, check related issues, check public resources, git log search, gh search, architecture docs, knowledge graph, research information.
---

# F-Stack Information Search Skill

Gather evidence for F-Stack issue analysis, bug location, and feature research. Invoked by the search step of the f-stack-issue-process skill; can also be used standalone.

## Environment Preparation

- GitHub Token configured (GH_TOKEN environment variable)
- Official F-Stack repository cloned to /data/workspace/f-stack
- gh CLI installed

## Part 1: Check Architecture Docs and Knowledge Graph

Before searching code, first consult f-stack's existing three-layer architecture docs and knowledge graph (`/data/workspace/f-stack/docs/`) to quickly locate the layers, modules, interfaces, and functions involved, narrowing the later search scope.

Three-layer architecture docs (bilingual, identical content):

- Layer1 system overview: `01-LAYER1-ARCHITECTURE.md` (Chinese) / `F-Stack_Architecture_Layer1_System_Overview.md` (English)
- Layer2 interface specification: `02-LAYER2-INTERFACES.md` (Chinese) / `F-Stack_Architecture_Layer2_Interface_Specification.md` (English)
- Layer3 function index: `03-LAYER3-FUNCTIONS.md` (Chinese) / `F-Stack_Architecture_Layer3_Function_Index.md` (English)

Knowledge graph:

- `KNOWLEDGE_GRAPH_WIKI.md`: knowledge graph wiki
- `F-Stack_Knowledge_Base_Summary.md`: knowledge base overview

Usage:

- Locate the involved layers and components (e.g. protocol stack layer, DPDK abstraction layer, interface layer) by keyword/module name in the architecture docs
- Use the knowledge graph to locate related code paths and functions, then narrow the git log / gh search scope accordingly
- The Chinese and English content is identical; consult either language

## Part 2: Check Commit History

Search for related fixes in the local F-Stack repository.

```bash
cd /data/workspace/f-stack

# Search commit messages by keyword
git log --all --oneline --grep='<keyword>'

# Search change history by file path
git log --all --oneline -- <file path>

# Search for fixing commits
git log --all --oneline --grep='fix' --grep='<keyword>' --all-match

# View the details of a commit
git show <commit-hash>
```

Also check f-stack's own modifications to DPDK (the local dpdk/ directory is a plain directory inside the f-stack repository with **no DPDK upstream commit history**; git log can only find f-stack's own few modifications):

```bash
# f-stack's own modifications to dpdk/ (not upstream commits)
git log --all --oneline -- dpdk/
git show <commit-hash>
```

Checking DPDK upstream fixes must go through external channels (no upstream history locally):

```bash
# Search fixing commits in the official DPDK repository
gh search commits '<keyword>' -R DPDK/dpdk --limit 20
```

Or use the DPDK Patchwork API (see Part 3), DPDK Bugzilla/mailing lists (see Part 4).

Points of interest:

- Whether DPDK upstream has fixing commits (Fixes/fix/patch) after the version mentioned in the issue
- Whether the fix has been backported to the version in use (F-Stack currently uses DPDK 24.11.6)
- Whether f-stack's dpdk/ has a corresponding local patch or a missed port

## Part 3: Check Related Issues and PRs

First check the local issue analysis archives (highest priority, avoid re-analyzing):

- Chinese: docs/zh_cn/f-stack-issue-ana.md
- English: docs/f-stack-issue-ana.md

When looking for similar issues, first search these two archives for existing analysis records (issue number, keyword, error symptom). If found, cite the existing conclusion directly; if not, analyze and supplement. The Chinese and English archives stay in sync.

```bash
export GH_TOKEN='<token>'

# Search related issues (open + closed)
gh search issues '<keyword>' -R F-Stack/f-stack --limit 20

# Search related PRs (especially merged ones)
gh search prs '<keyword>' -R F-Stack/f-stack --limit 20

# View a specific PR
gh pr view <NUMBER> -R F-Stack/f-stack

# View a PR's diff
gh pr diff <NUMBER> -R F-Stack/f-stack
```

DPDK upstream Patchwork (when tracking upstream patches):

- API: `https://patches.dpdk.org/api/patches/?q=<keyword>`
- Fetch with the WebFetch tool

## Part 4: Check Public Resources

Search the following sources by priority:

1. DPDK Bugzilla: https://bugs.dpdk.org
2. DPDK Patchwork: https://patches.dpdk.org
3. DPDK mailing list archive: https://inbox.dpdk.org (prefer the API to avoid the Anubis bot)
4. Web search: Stack Overflow, CSDN, GitHub global search

Note: sites like lore.kernel.org may be blocked by the Anubis bot; prefer API endpoints or inbox.dpdk.org.

## Part 5: Internal/External Information Search for General Analysis and Research Tasks

For general tasks such as issue analysis, bug location, and feature research, after completing the previous four parts, further search internal and external resources such as tech websites, blogs, and WeChat articles for cross-validation and background.

### 5.1 Search goals

- Existing analysis and solutions for similar problems (pitfalls others hit, fix ideas)
- Explanations and implementation details of related features (to understand the design intent)
- Upstream/community discussion and handling of the problem
- Industry best practices and performance data (for design reference)

### 5.2 Search channels (by priority)

1. External technical resources (web_search / web_fetch):
   - GitHub issues / wiki / discussions (F-Stack, DPDK, FreeBSD upstream repositories)
   - Tech blogs and personal sites (e.g. medium, dev.to, personal tech blogs)
   - Tech communities (Stack Overflow, Server Fault, Unix & Linux SE, CSDN, Zhihu, Juejin, SegmentFault)
   - WeChat official account articles (search on weixin.sogou.com, then web_fetch the article body)
2. Internal knowledge bases (RAG_search, if enterprise knowledge bases are connected): search internal best practices, historical handling records, and internal component docs
3. Tencent internal iWiki (if iWiki documents are involved, use the iwiki-doc skill to search docs, spaces, and directory trees on iwiki.woa.com)

### 5.3 Keyword construction

- Search in both Chinese and English, one round each; construct Chinese and English keywords separately
- Combinations: `<tech term> + <version>` (e.g. "DPDK 24.11 RSS hash"), `<exact error message>` (pasting the original log/error text gives the highest hit rate), `<function name> + <symptom>` (e.g. "rte_thash_adjust_tuple misqueue"), `<issue title keyword> + fix/regression`
- Add qualifiers: `site:github.com`, `site:stackoverflow.com`, `inurl:blog`, etc.
- Mind version timeliness: prefer resources close in time to the version in use (F-Stack v2.0 / DPDK 24.11.6 / FreeBSD 15.0) to avoid outdated conclusions

### 5.4 Cross-validation and evidence convergence

- Three-way evidence convergence: internal docs + external resources + actual code/testing, mutually confirming
- External conclusions must be checked against the local actual code; **where they conflict, the actual code is authoritative**
- Mark external resources with source and publication time; conclusions from a single source are marked "only this source, not double-verified"
- Honestly mark what cannot be verified as "unverified/not executed"; never speculate

## Search Output Requirements

- For each source, give the query terms and a summary of hits, with concrete links or commit hashes
- Cross-validation: converge evidence from code/docs/external data sources; where they conflict, the actual code is authoritative
- Honestly mark items that cannot be verified or where the environment is insufficient as "unverified/not executed"; never speculate
- Never include real IPs in the output (use placeholders like `<DPDK_NIC_IP>`)
