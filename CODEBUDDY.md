# CODEBUDDY.md

This file provides guidance to CodeBuddy Code when working with the F-Stack open source project.

## Project Overview

F-Stack is an open source high-performance network framework based on DPDK, porting the FreeBSD TCP/IP stack to user space. It achieves 10 million concurrent connections, 5 million RPS, 1 million CPS.

- **Primary Language:** C
- **F-Stack Version:** 2.0
- **DPDK Version:** 24.11.6
- **Repository:** https://github.com/F-Stack/f-stack
- **Local Clone:** `/data/workspace/f-stack`

## Build Commands

```bash
# 1. Build DPDK
cd /data/workspace/f-stack/dpdk
meson setup -Denable_kmods=true build
ninja -C build
ninja -C build install

# 2. Build F-Stack
export FF_PATH=/data/workspace/f-stack
export PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig
cd /data/workspace/f-stack/lib
make          # build
make install  # install (libfstack.a -> /usr/local/lib, ff_*.h -> /usr/local/include)

# 3. Clean rebuild
cd /data/workspace/f-stack/lib && make clean && make
```

## F-Stack Skills

All F-Stack work must be driven by the following three skills. Use the `use_skill` tool to load them; if unavailable, read the corresponding `SKILL.md` from `docs/zh_cn/skills/` (Chinese) or `docs/skills/` (English) instead.

| Skill | When to use |
|-------|-------------|
| `f-stack-dev-rule` | **Every** development, debugging, testing, or commit task in `/data/workspace/f-stack`. Mandatory rules: rm/kill/chmod scripts, make clean builds, config.ini not committed, no real IPs in docs, English code comments, minimal lib comments, multi-agent collaboration, no speculation. Zero tolerance. |
| `f-stack-issue-process` | Analyzing, judging, replying to, closing, or batch-processing F-Stack GitHub issues. Three-step SOP: read the full issue -> search information -> comprehensive judgment. |
| `f-stack-info-search` | Searching for evidence for issue analysis, bug location, or feature research. Five parts: architecture docs/knowledge graph, commit history, related issues/PRs, public resources, internal/external websites and blogs. Invoked by `f-stack-issue-process`; also usable standalone. |

### Installation

- Installed locally at `~/.codebuddy/skills/{f-stack-dev-rule,f-stack-issue-process,f-stack-info-search}/SKILL.md`
- Source files kept in-repo at `docs/zh_cn/skills/` (Chinese) and `docs/skills/` (English)
- To (re)install: copy the `SKILL.md` files from either source directory into `~/.codebuddy/skills/<skill-name>/`

### Notes

- Question/analysis/research tasks must use `f-stack-info-search` to search before answering; never guess without searching.
- Issue replies must be in English, short, no @-mentions, and must not repeat existing replies; after replying to or modifying an issue, update the bilingual issue analysis archives (`docs/f-stack-issue-ana.md`, `docs/zh_cn/f-stack-issue-ana.md`).
