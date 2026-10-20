# 03 Verification of the Legacy Community nginx Reload Scheme and the Evolution of the DPDK Timer (English)

> **English translation** of `docs/nginx_reload_spec/zh_cn/03-fstack-legacy-solution.md` (v1.1). The Chinese text is
> authoritative; where the two differ, the Chinese original governs.
> Translated 2026-09-30.

| Item | Value |
| --- | --- |
| Document ID | 03 |
| Title | Full-chain verification of issue #547 / #12, analysis of the legacy iWiki 4015929276 scheme, PR#559, the git evidence chain for the DPDK 18.11→19.11→24.11.6 timer evolution, and the conclusion that the legacy scheme no longer works |
| Version | v1.1 |
| Date | 2026-08-18 |
| Status | pending human audit |
| Source artefact | `work/evidence-legacy.md` (verifier `evidence-hunter`, filed 2026-08-18). This document is the formalised rewrite: all factual evidence kept (original issue comments, commit hashes, line numbers, iWiki metadata) together with the unconfirmed markings; real test addresses appearing in the original document have been replaced by placeholders (`<DPDK_NIC_IP>`) per the workspace rules and noted in place; the "list of operations actually executed" is kept as §0 so the evidence stays traceable |
| Revision notes | v1.1 (2026-09-17): corrected by this round's spec×code cross-audit (`plan_audit`) — the number of `rte_timer`-related commits changed from "only 3 in the whole tree" to **4** (adding M2 Batch A `982a5793a`, the self-driven hardclock); the HEAD-column line numbers of the §5.5 table relocated against HEAD `28e751259` (the v1.20 column annotated "M0-period snapshot, not re-verified this round"); the §8 U1 (and §6.2) `ff_syscall_wrapper.c` line numbers updated to `:100/982/1044-1049` |

Related: [00 Overview](overview.md) | [04 Current Analysis](current-analysis.md) | [06 Solution Design](solution-design.md)

---

## 0. Operations and commands actually executed

All of it was read-only verification (read-only gh CLI + read-only git log/show/diff/blame + iwiki-cli get/download + read_file). No git write operations were performed, and no direct rm/kill/chmod (temporary screenshots were cleaned up through the `rm_tmp_file.sh` that ships with `f-stack-dev-rule`).

```bash
# === gh CLI verification ===
gh api repos/F-Stack/f-stack/issues/547              # #547 title/author/time/body
gh api repos/F-Stack/f-stack/issues/547/comments --paginate  # all #547 comments
gh api repos/F-Stack/f-stack/issues/547/timeline     # #547 close/reference/label events
gh api repos/F-Stack/f-stack/issues/12               # #12 title/author/time/body
gh api repos/F-Stack/f-stack/issues/12/comments --paginate   # all #12 comments
gh api repos/F-Stack/f-stack/issues/12/timeline      # #12 close/reference events
gh search issues "reload" --repo F-Stack/f-stack --limit 30
gh search prs    "reload" --repo F-Stack/f-stack --limit 20
gh api repos/F-Stack/f-stack/pulls/559               # multi-process file-prefix support PR

# === read-only git verification (f-stack repository) ===
git log --all --oneline -- lib/ff_dpdk_if.c | head -50
git log --all --oneline -i --grep=timer  | head
git log --all --oneline -i --grep=reload | head
git log --all --oneline --grep='19.11'   | head
git log --all --oneline -i --grep=upgrade| head
git log --all --oneline -i --grep=nginx  | head
git log --all --oneline -S 'rte_timer'        -- lib/ff_dpdk_if.c
git log --all --oneline -S 'rte_timer_meta_init'
git log -1 --format='%h %ad %s' a9643ea85 v1.20 v1.21
git show 406002113 --stat                          # the commit that closed #12
git show 62f1c34df --stat                          # introduction of rte_timer_meta_init
git show 62f1c34df -- lib/ff_dpdk_if.c
git show 14355bf7b --stat                          # re-apply of 4 local patches
git show 9817534a2 --stat                          # PR#559 merge commit
git show v1.20:lib/ff_dpdk_if.c     | grep -n 'timer\|hardclock'
git show v1.20:dpdk/lib/librte_timer/rte_timer.c  | grep -n 'static.*priv_timer\|subsystem_init'

# === iWiki fetching (iwiki-doc skill) ===
iwiki-cli metadata 4015929276
iwiki-cli get      4015929276
iwiki-cli download 34479037 34479039 34479050 34479057 34479068 34479073 34479081
# the 7 screenshots were parsed and then read as images through read_file

# === current code (HEAD) checks ===
read_file lib/ff_dpdk_if.c            240-280, 1235-1280, 2785-2815
read_file dpdk/lib/timer/rte_timer.c  120-220
search_content lib/ff_dpdk_if.c "rte_timer|ff_timer|freebsd_clock"
```

## 1. Issue #547 "Is F-stack support reload without any packet dropped?"

### 1.1 Metadata

| Field | Value |
| --- | --- |
| Number | #547 |
| Title | Is F-stack support reload without any packet dropped? |
| Author | orange30 |
| State | closed (closed by orange30 himself on 2021-09-22) |
| Created | 2020-09-18 08:05:02Z |
| Closed | 2021-09-22 14:14:17Z |
| Labels | enhancement (added later by jfb8856606 on 2022-10-18) |
| Later cross-references | #1036 (2026-03-18), #528 (2026-03-18), #673 (2026-03-20) |

### 1.2 Body (original)

> https://github.com/F-Stack/f-stack/issues/12
> The url said the reload has been supported, but it drop a lot packets when reload!
> In production, the packet drop is not vary good.
> Is there a method which support reload without any packet dropped?
> @whl739

### 1.3 All comments (in time order, original text kept)

#### C1 — jfb8856606 — 2020-10-27T13:47:52Z

> There is currently no good way to achieve it.
>
> Unless you use soft distribution, all secondary worker don't bind the queue of NIC.

#### C2 — orange30 — 2020-11-02T04:16:01Z

> I am writing one version to support nginx reload.
> 1, It can work well on f-stack-1.20, and we can assign which cores is used to be rcv cores in f-stack.conf and nginx.conf.
> 2, When two processs is attached to the same core, it can renice the priority dynamically according the numbers of connections.
> 3, Because of the timer lib is changed in dpdk 19, my version cann't be work in new f-stack version. In dpdk 19, timer lib uses rte_memzone_reserve to apply global memory; in 18, it just be a static global variable in process.
> 4, There is also some other problems to solve and to discuss, for example wrk has a little read errors. If anyone has interest, we can discuss the problems together.
> 5, By the way, is there a WeChat Group to discuss problems of f-stack? @jfb8856606
>
> There is some photos to show the version：
>
> Configure：4 cores as rcv core, 26 cores as nginx core.
> ![image](https://user-images.githubusercontent.com/44566632/97828245-7d57a200-1d01-11eb-8ad0-df80cdbd4c0f.png)
> ![image](https://user-images.githubusercontent.com/44566632/97828270-8f394500-1d01-11eb-a5e5-6fbff2abb869.png)
>
> Before reload:
> ![image](https://user-images.githubusercontent.com/44566632/97828340-d0c9f000-1d01-11eb-8519-6998825abe19.png)
>
> Make some HTTP persistent connections.
>
> After reload:
> ![image](https://user-images.githubusercontent.com/44566632/97828375-e808dd80-1d01-11eb-95f2-129b322b8d7c.png)
>
> The wrk's read error problem when reload:
> ![image](https://user-images.githubusercontent.com/44566632/97828728-eab80280-1d02-11eb-98f2-319d96111e3d.png)

#### C3 — jfb8856606 — 2020-11-02T05:27:58Z

> @orange30 Good job. You can search 'johnjfb' in WeChat, and I will add you to F-Stack's WeChat Group.

#### C4 — orange30 — 2021-09-22T14:14:17Z (**close event**)

> After solve some bugs，the changed version has support nginx reload without any packet dropped.

#### C5 — ygm521 — 2022-02-27T11:00:14Z

> @orange30 hello， f-stack reload，some questions asked,thanks! WeChat ygmdream

#### C6 — RockGo — 2022-03-25T06:29:38Z

> @orange30 can you share the idea, WeChat RockGo56

#### C7 — orange30 — 2022-09-28T11:42:25Z

> @ygm521 @RockGo for reference only.
>
> `<img width="1497" alt="1" ...>` (7 images, 1.png~7.png; the content is the same as the 7 screenshots in iWiki document 4015929276 — see §3.2)

### 1.4 Key facts extracted

- **The author orange30 names the failure root cause on 2020-11-02 (C2)**: DPDK 19's timer library switched to `rte_memzone_reserve` for its global memory, whereas DPDK 18 only had a process-static global variable. His modified version, based on F-Stack 1.20 (DPDK 18.11), does not work on 19.11+.
- **On 2021-09-22 (C4) the author closed it himself**, only stating that "after fixing some bugs it supports reload without packet loss"; **no code/PR was published**, and the scheme was not merged into F-Stack mainline.
- **This issue has no code merge, no PR link and no commit reference** (no commit_id in the timeline).
- **The `enhancement` label was only added later, on 2022-10-18, by jfb8856606.**

## 2. Issue #12 "support nginx reload."

### 2.1 Metadata

| Field | Value |
| --- | --- |
| Number | #12 |
| Title | support nginx reload. |
| Author | beacer |
| State | closed |
| Created | 2017-05-23 06:33:25Z |
| Closed | 2017-08-23 09:01:33Z |
| Closed by | commit `406002113b143fda1fa444f0af42b97b41951882` ("Support nginx reload. close #12.") by logwang, with whl739 triggering the close event |

### 2.2 Body (original)

> Nginx reload function doesn't work.
>
> Environment
> ----------------
>
> 1. F-stack version: master:afba4e3b
> 2. CPU: Intel(R) Xeon(R) CPU E5-2650 v4 @ 2.20GHz
> 3. OS: CentOS Linux release 7.2.1511 (Core)
> 4. Kernel: 3.10.0-327.el7.x86_64
>
> Steps
> -------
>
> 1. setup f-stack and nginx app, make sure curl works
> 2. change the nginx configure file `/usr/local/nginx_fstack/conf/nginx.conf`
>     e.g., add new server (listen port), or add a proxy server(upstream)
> 3. try reload with 'killall -SIGHUP nginx'
>
> > consider `fstack-nginx` is working in "single-process" mode, no master process. So use `killall` to send signal to all processes.
>
> Expect that new configure applied, actually it does not. Even the curl fails after "reload".
>
> Reproducible
> -----------------
>
> Being able to reproduce.

### 2.3 All comments (in time order, original text kept)

#### C1 — whl739 — 2017-05-23T06:49:49Z (**main F-Stack maintainer**)

> Nginx reload is not supported for now. Because we didn't implement/hook the `fork` function, all processes are working in `NGX_PROCESS_SINGLE` mode.
> This will be fixed after we implement/hook `fork`.

#### C2 — beacer — 2017-06-13T09:53:50Z

> @whl739 just wondering if `fork` be implemented on the next release (July) or not ? Thanks!

#### C3 — whl739 — 2017-06-13T09:57:58Z

> `fork` will be implemented on the next release (July).

#### C4 — friendwu — 2017-06-15T02:38:42Z

> @whl739 sorry, I don't quite understand, and would you please teach me, why should f-stack implement fork hook?
>
> I'm now porting my project(DNS Authoritative Server) to f-stack, using the master-worker pattern, and... it seems to work well:
>
> After master start running, it calls the "ff_mod_init" and then forks the worker, worker finally calls the "ff_init" and "ff_run", are there any problems which I haven't found?

#### C5 — whl739 — 2017-06-15T02:46:45Z

> @friendwu
> All I really want to do is what you say, i just want to wrap them in fork. Thus user's code can be changed as little as possible.

#### C6 — hhkbble — 2017-07-21T17:43:52Z

> @whl739 how does this going？thx.

#### C7 — whl739 — 2017-07-22T07:23:02Z

> Sorry, recently, i was busy with other works.
> This may be delayed for few weeks.

#### C8 — hhkbble — 2017-07-23T05:58:38Z

> @whl739 I attended a sharing of Intel yesterday, and Intel recommend f-stack for us, we want to try it on our lb on mesos cluster. So, really looking forward to this feature and thanks for your quick response.

#### C9 — hhkbble — 2017-08-11T05:09:55Z

> @whl739 how does this going? ＾ᗜ＾

#### C10 — whl739 — 2017-08-14T03:23:24Z

> Working now. May be done this week.

### 2.4 The closing commit (406002113b143fda1fa444f0af42b97b41951882)

- Author: logwang <logwang@tencent.com>, time 2017-08-23 16:54:32 +0800
- Title: "Support nginx reload. close #12."
- Key changes (`git show 406002113 --stat`):

```
app/nginx-1.11.10/src/event/modules/ngx_ff_channel.c             | 793 ++++++  # the middle-layer channel (core implementation)
app/nginx-1.11.10/src/core/nginx.c                                |  55 +-
app/nginx-1.11.10/src/core/ngx_cycle.c                            |   2 +
app/nginx-1.11.10/src/core/ngx_cycle.h                            |   4 +
app/nginx-1.11.10/src/os/unix/ngx_process_cycle.c                 | 306 ++++++  # fork flow rework
app/nginx-1.11.10/src/event/modules/ngx_ff_module.c               |  55 +-
doc/F-Stack_Nginx_APP_Guide.md                                    | 187 ++---
README.md                                                         |   4 +-
... (other nginx config/auto tool tweaks)
freebsd/kern/kern_descrip.c                                       |  20 +-   # kernel descriptor fork adaptation
```

**Key fact**: this commit does **not** introduce a zero-loss reload scheme of "old and new processes coexisting + a middle-layer dispatch"; it implements **the native nginx master-worker reload based on the fork protocol** — that is, "killall -SIGHUP nginx" makes the workers re-read the configuration and keep serving, but **connections are lost during the restart** (which is the root cause behind issue #547's title "drop a lot packets when reload").

### 2.5 Key facts extracted

- #12 only solves "the reload process can start and re-read the configuration"; it does **not** solve "zero packet loss during reload".
- After being closed it was repeatedly cross-referenced by many issues: #38, #70, #84, #235, #286 and others; eventually #547's "drop a lot packets when reload" describes the real behaviour of the version implemented by this commit.

## 3. iWiki 4015929276 "F-Stack Nginx reload scheme"

### 3.1 Metadata

| Field | Value |
| --- | --- |
| Document ID | 4015929276 |
| Title | F-Stack Nginx reload scheme |
| Space | 915964362 (~fengbojiang, personal space) |
| Author | 姜凤波 (fengbojiang, i.e. jfb8856606 / johnjiang, an F-Stack maintainer) |
| Created | 2025-08-25 20:47:51 |
| Last modified | 2025-12-12 12:41:51 |
| Related issue | https://github.com/F-Stack/f-stack/issues/547 |
| Parent directory | 4015138227 |

### 3.2 Body (original)

> This scheme applies only to F-Stack-1.20 (DPDK-18.11); it does not apply from 1.21 (DPDK-19.11) onwards
>
> Original link: https://github.com/F-Stack/f-stack/issues/547
>
> ![企业微信截图_17561254269161.png](https://iwiki.woa.com/tencent/api/attachments/s3/url?attachmentid=34479037)
> ![企业微信截图_17561254357073.png](https://iwiki.woa.com/tencent/api/attachments/s3/url?attachmentid=34479039)
> ![企业微信截图_17561255698874.png](https://iwiki.woa.com/tencent/api/attachments/s3/url?attachmentid=34479050)
> ![企业微信截图_17561257178764.png](https://iwiki.woa.com/tencent/api/attachments/s3/url?attachmentid=34479057)
> ![企业微信截图_17561258148977.png](https://iwiki.woa.com/tencent/api/attachments/s3/url?attachmentid=34479068)
> ![企业微信截图_17561258436279.png](https://iwiki.woa.com/tencent/api/attachments/s3/url?attachmentid=34479073)
> ![企业微信截图_17561259335258.png](https://iwiki.woa.com/tencent/api/attachments/s3/url?attachmentid=34479081)

### 3.3 Analysis of the 7 screenshots (in order)

> Downloaded to `/tmp/iwiki_547/` with `iwiki-cli download` and recognised by read_file as images; after downloading, cleaned up with `rm_tmp_file.sh` (compliant).

#### Figure 1 (problem analysis)

- **Native nginx reload analysis**:
  1. Start new worker processes to load the new configuration file
  2. The kernel stack maintains the global socket connections
  3. During reload the stack decides, per connection, whether it goes to the new or the old process
- **DPDK nginx comparison**:
  1. DPDK bypasses the kernel stack; **the user-space stack lives inside the process**
     - **Problem to solve**: while old and new processes coexist, something must maintain the global connections to decide whether a connection goes to the new or the old process
  2. A DPDK process is usually used with **each process occupying 100% of one CPU**
     - **Problem to solve**: the feasibility of "two DPDK processes running on the same core" coexisting
- Figure: native nginx master/worker stack architecture vs the DPDK nginx stack+queue architecture

#### Figure 2 (scheme analysis-1)

- **The global connections problem**
  - Response: introduce a middle logic layer that maintains the global connections, etc.
- **"Two DPDK processes on the same core": coexistence feasibility**
  1. The DPDK Technical Lead points out that with "two DPDK processes on the same core" the mempool module is unsafe; analysing the relevant source confirms that "a buffer obtained from the same mempool being freed by both processes after use" causes a crash
  2. **Response**: **allocate different mempools to the old and new processes**
  - Special case: "the mempool used by the NIC driver"; **disable the cache + shrink the conflict domain**, with a very small measured performance loss
  - (1) the conflict domain is refined from numa-id granularity to workerid granularity
  - (2) the bottom layer uses CAS atomic instructions to resolve conflicts
- **"Two DPDK processes on the same core": process scheduling weight redistribution**
  - Under CFS scheduling: an ordinary process has nice 0 and a baseline weight of 1024
  - Response: adjust through the process nice value
  - Relation between nice value and scheduling weight: `1024 / (1.25 ^ nice_value)`
- Figure: the reworked processing framework (master + middle layer + old/new worker queues)

#### Figure 3 (scheme analysis-2)

- **The "identify whether a server reply packet enters the old or the new process" problem**
  1. The five-tuple decides which worker process a packet enters
  2. During reload a server reply packet cannot be identified as belonging to the new or the old process
  - Response: **configure two internal IPs on the NIC that talks to the backend server**; **the old and new processes use different IPs to talk to the backend server** (internal IPs are plentiful)
- **New problems**
  1. Under reverse proxying, f-stack **adds local-port selection logic in the connect phase** of the socket to guarantee that the reply packet enters the same process
  2. That scheme needs to call bind in the socket establishment phase, but the FreeBSD stack **does not support the `IP_BIND_ADDRESS_NO_PORT` option**
  - Response: **develop `IP_BIND_ADDRESS_NO_PORT` support in the FreeBSD network stack**
- Figure: the five-tuple `hash % N = workerid` routing logic

#### Figure 4 (project development)

- **Introduce a dispatch process as the middle logic layer**
  1. Maintain the global connection table
  2. Connect to worker processes through lock-free ring queues
  3. Extend the original inter-process communication channel; the dispatch process always holds the full picture
  4. **The DPDK primary changes from the first worker process to the first dispatch process**
- **Development related to "two DPDK processes on the same core"**
  - Coexistence feasibility: allocate different mempools to old and new processes; modify the NIC driver's use of the mempool
  - Dynamically adjust the CPU occupancy of old and new processes:
    - Load: the middle layer maintains the packet processing rate of old and new workers as the basis for dynamic adjustment
    - Adjustment: (1) build a mapping table between load ratio and nice value; (2) during coexistence the middle layer adjusts dynamically
- **The "identify whether a server reply packet enters the old or the new process" problem**
  1. Modify nginx to bind different source IPs according to whether a process is old or new
  2. Develop `IP_BIND_ADDRESS_NO_PORT` support for the stack
- **Adjusting the old worker's exit condition**
  - Problem: nginx's native exit condition only cares whether the stack has sockets belonging to that worker; **it must also consider connections that reached the middle layer but have not entered the user-space stack yet**
  - Change: the exit condition becomes "the global connections contain no connection belonging to this process"

#### Figure 5 (description and analysis of the small number of timeouts)

- **Symptom**: during self-testing, **wrk shows a small number of timeouts under repeated reloads**
- **Analysis**
  1. Presumably because at certain instants the CPU processing capacity is insufficient
  2. Many potential causes: new process start events? Old process exit events? Traffic switch events? Bugs elsewhere? etc.
- **Breakthrough**
  1. Read part of the wrk source and work out the timeout handling logic
  2. Use eBPF tools to pinpoint that the timeouts concentrate **at the instant of the old/new traffic switch**
- Figure: measured data for `wrk -c50 -t10 --latency http://<DPDK_NIC_IP>/2 -d600000s` (the original screenshot command contains a real test address, replaced here by the `<DPDK_NIC_IP>` placeholder per the documentation rules): **wrk ran 10 hours with 200 reloads; result: Socket errors: connect 0, read 0, write 0, timeout 112**

#### Figure 6 (cause of and solution to the small number of timeouts)

- **Cause analysis**
  1. The nice value of a newly started worker was initially set to 19, giving it 1.7% of the CPU
  2. At the traffic-switch instant, how much processing capacity should be pre-allocated to the new worker?
     - (1) too large and the old worker's performance is cut too much
     - (2) too small and the new worker's performance may not be enough
- **Innovative solution**
  1. Native nginx switches traffic for all workers at once; **change this to each worker switching traffic in turn**
  2. When reloading to a given worker, **bind the new worker process to a reserved CPU core** (for example the last core) and set its nice value back to normal. The traffic switch also triggers the middle layer's dynamic CPU allocation adjustment between old and new processes
  3. **After 1 second, bind the new worker back to its original CPU core**

#### Figure 7 (acceptance and summary)

- **Stability**: under long and frequent reloads during the load test, no timeouts or other errors appeared
- **Performance**: **QPS reaches 580k, more than twice native nginx**
  - Test comparison environment: the same environment, the same configuration: long connections, small packets, logging enabled, etc., see the attachment
- **Compatibility**: existing nginx modules can be used directly without modification
- Figure: a bar chart of native nginx (~225k QPS) vs the reload-capable DPDK nginx (~580k QPS)

### 3.4 Key facts extracted

- **This scheme is orange30's personal modification on F-Stack 1.20 (DPDK 18.11); the original code was not obtained within this search range (not seen as open source / not merged; search cut-off 2026-09; only the issue #547 screenshots and WeChat contact leads exist)**. Issue #547 only has screenshot discussion and WeChat contacts.
- The maintainer fengbojiang archived the scheme in his personal iWiki space and marked explicitly that it "**does not apply from 1.21 (DPDK-19.11) onwards**" — exactly matching orange30's own statement in #547 comment C2 that "my version cann't be work in new f-stack version".
- The four core modifications of the scheme:
  1. A **dispatch process middle layer** maintaining the global connection table plus lock-free ring queues (same idea as the `ngx_ff_channel.c` middle-layer channel in the #12 commit 406002113 but more radical — the former adapts the fork protocol, the latter shares state through DPDK multi-process).
  2. **Different mempools for old and new processes** (solving the mempool unsafety of "two DPDK processes on the same core") plus disabling the cache for the NIC driver's mempool.
  3. **Dynamic nice-value adjustment with the CFS weight formula `1024 / (1.25^nice)`**.
  4. **Two internal NIC IPs + `IP_BIND_ADDRESS_NO_PORT`** (requiring new support in the FreeBSD stack) so server replies can be identified as old or new process.

## 4. Related PR / commit evidence

### 4.1 gh search "reload" -R F-Stack/f-stack

Issue overview (7 items):

| # | Number | State | Title |
| --- | --- | --- | --- |
| 1 | #1036 | closed | 如何实现nginx 优雅的reload |
| 2 | #528 | closed | /usr/local/nginx_fstack/sbin/nginx -e reload Startup failed |
| 3 | #673 | closed | exec() support in F-stack |
| 4 | #547 | closed | Is F-stack support reload without any packet dropped? |
| 5 | #12 | closed | support nginx reload. |
| 6 | #382 | closed | fstack nginx fail to start by systemd |
| 7 | #398 | closed | Nginx built with f-stack is the same performance as nginx without |

Only 1 PR: **PR#559** (merged).

### 4.2 PR#559 — Config: Support parse "--file-prefix" & "--pci-whitelist" for multi-processes

- Number: #559
- Author: hawkxiang
- State: closed (merged)
- Merged: 2020-11-19 14:43:26 +0800
- Local merge commit: `9817534a213ffa9f3c68eb721683a807d20387fd` (9817534a2)
- Changes: `lib/ff_config.c` 18 lines, `lib/ff_config.h` 6 lines
- **Key statements in the PR body**:

> Modified the f-stack configuration file recognition to support parsing the file-prefix and pci-whitelist configuration items, solving the **memory anomaly when multiple processes bind the same CPU core**:
> a. Several containers on the same physical machine each deploy DPDK programs and share the physical machine's hugepages;
> b. **Similar to nginx's reload process, multiple processes bind the same CPU core and share hugepages**

- **Significance**: this is the **only** merged PR in the F-Stack mainline directly related to "multi-process coexistence during reload", but it only supports `--file-prefix` at the configuration-parsing level so that several groups of DPDK processes use different shared-memory prefixes; it does **not** touch timer / mempool / process scheduling or other core changes.

### 4.3 Other grep hits (documentation/historical commits only, no code changes)

- `git log -i --grep=nginx`: mainly nginx 1.11.10 → 1.25.2 → 1.28.0 upgrades, IP_TRANSPARENT support, IPV6_PKTINFO translation, etc.; **[as of the 2026-08-18 baseline] no reload core commit**. **[2026-09-22 sync, A01-4]** Afterwards M2/M5 landed reload- and USR2-related changes; this sentence only describes the repository state at that baseline point in time.
- `git log -i --grep=reload`: hits `docs: ...`-type blog/benchmark commits, no reload code changes (the latest native-mt / 23→24 upgrades are not reload topics either).
- `git log -S 'rte_timer' -- lib/ff_dpdk_if.c`: **3** commits as of this document's writing baseline (2026-08-18), plus 1 added later by M2 Batch A, so **4 in total**:
  - `a9643ea85` (2017-04-21 init, F-Stack repository initialisation)
  - `62f1c34df` (2026-01-16, jinliu777 "Fix infinite loop when restarting DPDK secondary process", introducing `rte_timer_meta_init`)
  - `82b409faf` (2026 native-mt callwheel per-thread)
  - `982a5793a` (2026-09-02, M2 Batch A self-driven hardclock — the commit message states that the self-driven hardclock **replaces rte_timer** on the graceful path)

## 5. Git evidence chain for the timer evolution

### 5.1 Timeline overview

| Time | Event | Commit | Key change |
| --- | --- | --- | --- |
| 2017-04-21 | repository init | a9643ea85 | DPDK timer lib (17.11 era): `static struct priv_timer priv_timer[RTE_MAX_LCORE]`, a process-static array; `rte_timer_subsystem_init` only spinlock-inits the static array |
| 2019-11-23 | tag **v1.20** | 4b05018ff "DPDK: update to 18.11.5." | DPDK 18.11.5 LTS; the timer lib is still process-static (see §5.2) |
| **2020-06-18** | **DPDK 19.11.2 upgrade** | **37a7c72f0 / 4418919fe** | **the timer lib switches to a global memzone through `rte_memzone_reserve`** (the failure watershed named by orange30) |
| 2020-11-19 | PR#559 merged | 9817534a2 | multi-process file-prefix/pci-whitelist parsing (the basis of memory isolation during reload) |
| 2021-01-29 | tag v1.21 | 2df8fe233 | "Update release note for 1.21."; DPDK 19.11.x |
| 2026-01-16 | local patch introducing `rte_timer_meta_init` | **62f1c34df** | F-Stack's own DPDK timer patch: fixes "rte_timer_manage infinite loop when restarting a DPDK secondary process" |
| 2026-06-09 | 4 local DPDK patches re-applied to 24.11.6 | **14355bf7b** | one of the four patches is `rte_timer_meta_init`; the same commit also copies `dpdk/lib/timer/` from 23.11.5 into the 24.11.6 tree |

### 5.2 The process-static timer lib implementation of v1.20 (DPDK 18.11.5)

> `git show v1.20:dpdk/lib/librte_timer/rte_timer.c`

```c
// L52 - process-static array (one independent copy per DPDK process)
static struct priv_timer priv_timer[RTE_MAX_LCORE];

// L67-78 - subsystem_init only spinlock-inits the static array
int
rte_timer_subsystem_init(void)
{
    unsigned lcore_id;
    /* since priv_timer is static, it's zeroed by default, so only init some
     * fields.
     */
    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id ++) {
        rte_spinlock_init(&priv_timer[lcore_id].list_lock);
        priv_timer[lcore_id].prev_lcore = lcore_id;
    }
}
```

### 5.3 The shared-memzone timer lib implementation at current HEAD (DPDK 24.11.6 + F-Stack local patches)

> `dpdk/lib/timer/rte_timer.c` (the local copy maintained by F-Stack, see the note in patch 14355bf7b)

```c
// L122-185 - subsystem_init changed to shared memory via rte_memzone_lookup/reserve_aligned
int
rte_timer_subsystem_init(void)
{
    const struct rte_memzone *mz;
    struct rte_timer_data *data;
    int i, lcore_id;
    static const char *mz_name = "rte_timer_mz";
    const size_t data_arr_size =
            RTE_MAX_DATA_ELS * sizeof(*rte_timer_data_arr);
    const size_t mem_size = data_arr_size + sizeof(*rte_timer_mz_refcnt);
    bool do_full_init = true;

    rte_mcfg_timer_lock();

    if (rte_timer_subsystem_initialized) {
        rte_mcfg_timer_unlock();
        return -EALREADY;
    }

    mz = rte_memzone_lookup(mz_name);
    if (mz == NULL) {
        mz = rte_memzone_reserve_aligned(mz_name, mem_size,
                SOCKET_ID_ANY, 0, RTE_CACHE_LINE_SIZE);
        ...
    }
    rte_timer_data_mz = mz;
    rte_timer_data_arr = mz->addr;        // the array points into the shared memzone
    rte_timer_mz_refcnt = (void *)((char *)mz->addr + data_arr_size);
    ...
    (*rte_timer_mz_refcnt)++;
    rte_timer_subsystem_initialized = 1;
    rte_mcfg_timer_unlock();
    return 0;
}

// L216-228 - [F-Stack local patch] rte_timer_meta_init
int
rte_timer_meta_init(void)
{
    struct rte_timer_data *timer_data;
    struct priv_timer *pt;
    unsigned lcore_id = rte_lcore_id();
    TIMER_DATA_VALID_GET_OR_ERR_RET(default_data_id, timer_data, -EINVAL);
    pt = &timer_data->priv_timer[lcore_id];
    memset(pt, 0, sizeof(*pt));           // explicitly initialise this lcore slot
    pt->prev_lcore = lcore_id;
    return 0;
}
```

### 5.4 Commit 62f1c34df, which introduced `rte_timer_meta_init` (key evidence)

- Date: 2026-01-16 17:41:18 +0800
- Author: jinliu777
- Title: "Fix infinite loop when restarting DPDK secondary process"
- stat:

```
dpdk/lib/timer/rte_timer.c | 14 ++++++++++++++   # adds rte_timer_meta_init + header
dpdk/lib/timer/rte_timer.h |  9 +++++++++    # exported symbol
lib/ff_dpdk_if.c           |  8 ++++++++   # called once from init_clock, synchronised from stop_clock
```

Excerpt of the `lib/ff_dpdk_if.c` diff:

```c
@@ init_clock(void) @@
    rte_timer_subsystem_init();
+   rte_timer_meta_init();      // <-- new: fixes the rte_timer_manage infinite loop when a secondary process restarts
    uint64_t hz = rte_get_timer_hz();
    ...

+static int
+stop_clock(void) {
+    rte_timer_stop_sync(&freebsd_clock);
+    return 0;
+}

@@ ff_dpdk_run() @@
    rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN);
    rte_eal_mp_wait_lcore();
+   stop_clock();
```

**Significance**:

1. **F-Stack still needed a local patch to DPDK's shared memzone timer in 2026** — direct proof that "shared timer state breaks when primary/secondary processes coexist".
2. **The commit message "restarting DPDK secondary process"** — "secondary restart" corresponds exactly to the core scenario of nginx reload: "a new worker (secondary) starts while the old worker exits".

### 5.5 F-Stack's own timer usage layer in `ff_dpdk_if.c` (before the change vs now)

| Item | v1.20 (init a9643ea85 + the v1.20 tag) (*) | current HEAD (DPDK 24.11.6) |
| --- | --- | --- |
| `freebsd_clock` storage | `static struct rte_timer freebsd_clock;` (L80, global) | `static __thread struct rte_timer freebsd_clock;` (L147, one per thread, native-mt rework) |
| hardclock callback | `freebsd_hardclock_job` (L131) | `ff_hardclock_job` (L306, main thread) + `ff_hardclock_worker_job` (L313, worker thread) |
| subsystem_init call | `rte_timer_subsystem_init()` (L794) | `rte_timer_subsystem_init()` + `rte_timer_meta_init()` (L1534-1535) |
| main_loop driver | `rte_timer_manage()` (L1533) | `rte_timer_manage()` (L3499); the scheduling point `if (unlikely(freebsd_clock.expire < cur_tsc))` is the same |

(*) The v1.20 column is an M0-period snapshot and was not re-verified this round (2026-09-17).

**Key finding**: F-Stack's own timer usage code in `ff_dpdk_if.c` (the subsystem_init + reset + manage call skeleton) **barely changed** between the 2017 init and 2026 (apart from native-mt turning it into `__thread`). **Everything that changed is inside the DPDK timer lib itself (18.11 static → 19.11+ shared memzone) plus F-Stack's local patches to that library.** Also note (corrected 2026-09-17): M2 Batch A (`982a5793a`) **replaces** the `rte_timer` call with a self-driven hardclock on the graceful path (C-NR-307), see §4.3.

## 6. Key points of the legacy scheme and the conclusion that it no longer works (code as authority)

### 6.1 Technical points of the legacy scheme

Source: the full text of iWiki 4015929276 + the analysis of the 7 screenshots + issue #547 comments C2 (C3).

| Dimension | What the legacy scheme did | Necessary condition |
| --- | --- | --- |
| **Architecture** | introduce a **dispatch process** as the middle logic layer maintaining a global connection table; workers talk to dispatch through lock-free ring queues | DPDK processes can stably "coexist as multiple processes on the same core" |
| **mempool isolation** | the old and new workers each allocate a **different mempool**; the NIC driver's mempool has its cache disabled and its conflict domain narrowed (numa id → workerid granularity) | solves "a buffer from the same mempool freed concurrently by two processes causing a crash" |
| **Process scheduling** | dynamic adjustment through the `nice` value: `nice=19` gives the new worker only 1.7% of a CPU, and after 1 second it is bound back to its original CPU core; CFS weight formula `1024 / (1.25 ^ nice_value)` | Linux CFS scheduling + multiple processes coexisting on the same core |
| **Connection routing** | the NIC is given two internal IPs and the old and new workers use different ones; f-stack adds local-port selection in the socket connect phase so replies enter the same process | the FreeBSD stack supports the **`IP_BIND_ADDRESS_NO_PORT`** option (the old F-Stack 1.20's FreeBSD 11/13 does not; it had to be developed) |
| **Exit condition** | the worker exit condition changes to "the global connections contain no connection of this process" (instead of "no socket of this process") | the dispatch middle layer has a complete connection view |
| **DPDK timer assumption** | F-Stack 1.20 (on DPDK 18.11): **the timer lib is independent static data per process** — `static struct priv_timer priv_timer[RTE_MAX_LCORE]` | the "process-static" implementation of the old DPDK timer library |

### 6.2 Where the legacy scheme breaks on DPDK 19.11+ (code as authority)

| Legacy-scheme dependency | Reality on DPDK 19.11+ | Failure effect |
| --- | --- | --- |
| "the timer lib is independent static data per process" → the `priv_timer` arrays of the dispatch process and the workers are physically isolated | **from 19.11 the `priv_timer` array moved into a shared memzone** ("rte_timer_mz"), and all DPDK processes share one `rte_timer_data` | every process's reset `freebsd_clock` goes into the same `priv_timer[lcore_id]` slot; several processes driving the same slot → contention, duplicate firing, and `rte_timer_manage` firing another process's timer by mistake |
| multiple processes coexisting on the same core | **[2026-09-22 sync, A01-3]** "mempool isolation + nice adjustment **can solve it**" is too strong: the DPDK prohibition says *among other issues*, mempool is only one example; this spec's scheme (S3) **isolates only the two identified paths, mempool and timer; the risk of other per-`lcore_id` shared slots is not enumerated**, so the wording becomes "**the identified paths are isolated, the rest is not enumerated**". **The original acceptance bar is not relaxed by this item** (RV1/RV6/RV15 + PT-NR-08/09 + IT-NR-A13 measured corroboration is still required), and the existing same-`lcore_id` decision is unchanged. But once the timer is shared, `rte_timer_manage` of the dispatch process and of the workers runs on the same lcore (at different times), and the `prev_lcore` relation becomes disordered | the worker's `ff_hardclock` cadence is disturbed; connection timeouts/RTO retransmission timing becomes inaccurate, indirectly causing connection anomalies during reload |
| `rte_timer_subsystem_init` is called only once | **the current version additionally needs `rte_timer_meta_init`** to explicitly initialise this process's lcore slot (patch 62f1c34df, 2026-01-16); otherwise restarting a secondary process leads to an "infinite loop" | F-Stack still carries a local patch for this defect in 2026; the "DPDK 19 timer library change" orange30 described in 2020-11 has still not been closed by an upstream fix |
| `--file-prefix` supporting memory isolation for several groups of DPDK processes during reload | PR#559 (merged 2020-11) added configuration-file parsing | this layer is fine, but it is only infrastructure, not a cure for the shared timer/connection state problem |
| the FreeBSD stack's `IP_BIND_ADDRESS_NO_PORT` | the current FreeBSD 15.0 tree **already supports it** (**confirmed 2026-08-18**, see §8 U1): the stack behaviour layer comes from cb9b4d462 (2025-07-25, bind does not allocate a port, source port chosen for RSS consistency at connect time) ported to the 15.0 tree by ff9e3c449 (2026-06-22) (`freebsd/netinet/in_pcb.c`, `#ifdef FSTACK` block); the setsockopt interface layer comes from a2537e143 (2026-07-16), intercepting `LINUX_IP_BIND_ADDRESS_NO_PORT(24)` as a successful no-op at `lib/ff_syscall_wrapper.c:100/982/1044-1049` (handling the numeric conflict with FreeBSD's `IP_BINDANY(24)`). Note: this is an F-Stack local extension — upstream FreeBSD 15.0 has no such option (the Linux compatibility layer explicitly reports it as unsupported) | the stack precondition for the "two NIC IPs + old/new worker each using one" scheme **is in place**; this risk is removed in the S1 evaluation (see [06](solution-design.md) §3.1/S1) |

### 6.3 The failure watershed and how to characterise the current state

- **Watershed commit**: `37a7c72f0 / 4418919fe` (2020-06-18, "DPDK: upgrade to DPDK 19.11.2(LTS)."). Before it, v1.20 (DPDK 18.11.5) had a process-static timer lib; after it, v1.21+ uses a shared memzone.
- **The person who confirmed the legacy scheme's failure**: orange30 himself (issue #547 comment C2, 2020-11-02).
- **The maintainer's archival confirmation**: fengbojiang (jfb8856606) put the scheme into his personal iWiki space 4015929276 marked "not applicable from 1.21+", indirectly acknowledging the failure officially.
- **The F-Stack mainline has made no fix for shared timer state across processes during reload** — `git log -S 'rte_timer' -- lib/ff_dpdk_if.c` returns 3 commits as of this document's writing baseline (2026-08-18) (init 2017 / 2026-01-16 patch / 2026 native-mt callwheel), **with a 4th added later by M2 Batch A, `982a5793a` (2026-09-02 self-driven hardclock, see §4.3)**; none of these four targets reload.

## 7. Related local archives (confirmed entries)

Local archives in `docs/zh_cn/f-stack-issue-ana.md` directly related to this verification:

| Lines | Issue | State | Recorded conclusion (excerpt) |
| --- | --- | --- | --- |
| L2074-2076 | **#547** | ⚪closed | Final reply 2021-09-22: orange30 confirms that after fixing bugs his version supports zero-loss reload; the scheme is based on DPDK 18.11 + F-Stack 1.20 with a dedicated receive core + dynamic renice; not merged into the official tree; DPDK19+ is incompatible because the timer lib changed (`rte_memzone_reserve`) and needs adaptation. Related: #12, #1036, #528 |
| L2175-2177 | **#12** | ⚪closed | As of closing (2017-08) the official plan was to support reload-like capability by implementing/hooking fork; the **feature was still in progress**, not verified as complete |
| L557-559 | #528 | ⚪closed | The official final confirmation: `-s reload` triggers nginx's graceful reload signal, but F-Stack nginx does not support graceful reload, so any invocation of the reload flow causes a brief service interruption. Zero-downtime reload needs DPDK 18.11 plus orange30's community patch (the #547 dedicated receive core scheme); DPDK19+ needs adaptation to the timer lib change |

**Related issues** (gh search "reload" -R F-Stack/f-stack): #1036, #528, #673, #547, #12, #382, #398. Of these, #528, #1036 and #673 serve as corroboration here (cross-referenced sources); their comments were not fetched in depth.

## 8. Unconfirmed list / follow-up verification to-do

| ID | Unconfirmed item | Reason | Suggested next step |
| --- | --- | --- | --- |
| U1 | ~~whether the current FreeBSD 15.0 tree supports `IP_BIND_ADDRESS_NO_PORT`~~ **→ confirmed (2026-08-18): it does** | Original reason for being unconfirmed: the first verification did not grep the identifier in the `freebsd/` tree (the implementation is a `#ifdef FSTACK` behaviour change plus an interception in `lib/ff_syscall_wrapper.c`, so no bare option name matches), and `git log --grep=IP_BIND_ADDRESS_NO_PORT` was not run. Confirmation chain (all confirmed IN-HEAD with `git merge-base --is-ancestor`): cb9b4d462 (2025-07-25 original implementation) → ff9e3c449 (2026-06-22 port to the 15.0 tree, `freebsd/netinet/in_pcb.c` bind-then-connect + RSS-consistent source port selection) → a2537e143 (2026-07-16 `lib/ff_syscall_wrapper.c:100/982/1044-1049` setsockopt/getsockopt wiring, handling the numeric conflict with `IP_BINDANY(24)`); plus 35aa95846/23e545932/458e91288/699c763b4, 8 related commits in total | ~~resolved~~ Note: this support is an **F-Stack local extension**; upstream FreeBSD 15.0 (freebsd-src-releng-15.0) has no such option (the Linux compatibility layer `linux_socket.c` explicitly reports unsupported), so these patches must be preserved when upgrading the FreeBSD tree |
| U2 | Whether the `ff_dpdk_if.c` timer usage layer was adjusted during the 1.20 → 1.21 upgrade | `git log -S 'rte_timer' -- lib/ff_dpdk_if.c` returns only 3 commits, and the v1.20→v1.21 diff shows no output for the keyword 'timer' (the skeleton did not change) | But a complete comparison of identifiers such as `freebsd_clock` and the job function names was not done; 100% confirmation would need the full v1.20 vs v1.21 diff |
| U3 | The raw data of the bar chart in iWiki screenshot 7 (acceptance) | The bar chart has no specific test commands/environment parameters; the screenshot says "see the attachment" but the iWiki document has no attachment link | Re-test on site: find a comparison machine with 4 rcv cores + 26 nginx cores and measure QPS following orange30's modification |
| U4 | The reproducibility of "wrk 10h, 200 reloads, 112 timeouts" as a 0.000006% probability | The screenshot data is credible but needs independent measurement | Reproduce: capture the traffic-switch instant with wireshark/ebpf and verify where the timeouts concentrate |
| U5 | orange30's original modified code | Only screenshots and a WeChat contact exist; **not obtained within this search range (not seen as open source; search cut-off 2026-09)** | **Within this search range** it is unrecoverable; if needed one can only ask jfb8856606 for an introduction through the WeChat group (issue #547 comment C3) |
| U6 | The measured behaviour of "multiple worker processes during reload" on current 24.11.6 + native-mt | This verification is static analysis only; runtime data is missing | Run one zero-loss reload reproduction on the local DPDK NIC with a 4-core/26-core ratio: see whether packets are lost and how many, look at the `rte_timer_manage` error counters, look for memzone refcnt anomalies |
| U7 | Whether issues #528, #1036, #673 added new scheme details in their comments | Per the task, only #547 and #12 were fetched in depth; the others are only cross-referenced | Open a separate verification if a complete picture is needed |

## 9. Inputs for the later spec documents (already merged into [06 Solution Design](solution-design.md) and [07 Milestones](milestones.md))

1. **Do not treat "orange30's screenshot scheme" as the F-Stack mainline reload design** — it is confirmed to be a personal community version, applicable only to DPDK 18.11 / F-Stack 1.20.
2. **A new scheme after DPDK 19.11+ must solve 3 independent problems at once**: (a) state isolation of the shared memzone timer under multi-process coexistence; (b) stack support for `IP_BIND_ADDRESS_NO_PORT` (**confirmed by U1: the F-Stack 15.0 stack supports it**, see §6.2/§8, as a local extension); (c) a standardised implementation of the dispatch middle layer's connection table and ring queues.
3. **Existing mainline PR worth borrowing**: only PR#559 (multi-process file-prefix parsing) — currently the only usable multi-process memory isolation infrastructure for reload.
4. **Local DPDK patch worth borrowing**: `rte_timer_meta_init` (62f1c34df) — but its goal is "a secondary process restart does not loop forever", and it does **not** directly solve "isolating old and new timer state during reload".

---

**Evidence strength statement**: this document is entirely based on the gh CLI / git log/show / iwiki-cli / direct reads of the current code, with no speculation; the unconfirmed items are concentrated in §8 (originally 7 items; U1 was confirmed as "supported" on 2026-08-18, leaving 6), and the main gap is runtime data.
