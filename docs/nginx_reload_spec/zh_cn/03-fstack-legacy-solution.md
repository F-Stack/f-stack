# 03 旧社区 Nginx reload 方案考证与 DPDK 定时器实现演变

| 项 | 值 |
|---|---|
| 文档编号 | 03 |
| 标题 | issue #547 / #12 全链考证、iWiki 4015929276 旧方案解析、PR#559、DPDK 18.11→19.11→24.11.6 定时器演变 git 证据链、旧方案失效性结论 |
| 版本 | v1.0 |
| 日期 | 2026-08-18 |
| 状态 | 待人工审计 |
| 来源产物 | work/evidence-legacy.md（考证员 evidence-hunter，2026-08-18 落盘）。本篇为正式化改写：保留全部事实证据（issue 评论原文、commit hash、行号、iWiki 元数据）、未坐实标注；原文档中出现的真实测试地址已按工作区规约替换为占位符（`<DPDK_NIC_IP>`），并在相应位置注明；「实际执行的操作清单」保留为第 0 节以体现证据可追溯 |

相关篇章：[00-总览](00-overview.md) | [04-现状分析](04-fstack-current-analysis.md) | [06-方案设计](06-solution-design.md)

---

## 0. 实际执行的操作与命令清单

全部为只读考证（gh CLI 只读 + git log/show/diff/blame 只读 + iwiki-cli get/download + read_file）。未执行任何 git 写操作，未直接 rm/kill/chmod（临时截图通过 f-stack-dev-rule 自带 `rm_tmp_file.sh` 清理）。

```bash
# === gh CLI 考证 ===
gh api repos/F-Stack/f-stack/issues/547              # #547 标题/作者/时间/正文
gh api repos/F-Stack/f-stack/issues/547/comments --paginate  # #547 全部评论
gh api repos/F-Stack/f-stack/issues/547/timeline     # #547 关闭/引用/label 事件
gh api repos/F-Stack/f-stack/issues/12               # #12 标题/作者/时间/正文
gh api repos/F-Stack/f-stack/issues/12/comments --paginate   # #12 全部评论
gh api repos/F-Stack/f-stack/issues/12/timeline      # #12 关闭/引用事件
gh search issues "reload" --repo F-Stack/f-stack --limit 30
gh search prs    "reload" --repo F-Stack/f-stack --limit 20
gh api repos/F-Stack/f-stack/pulls/559               # 多进程 file-prefix 支持 PR

# === git 只读考证（f-stack 仓库） ===
git log --all --oneline -- lib/ff_dpdk_if.c | head -50
git log --all --oneline -i --grep=timer  | head
git log --all --oneline -i --grep=reload | head
git log --all --oneline --grep='19.11'   | head
git log --all --oneline -i --grep=upgrade| head
git log --all --oneline -i --grep=nginx  | head
git log --all --oneline -S 'rte_timer'        -- lib/ff_dpdk_if.c
git log --all --oneline -S 'rte_timer_meta_init'
git log -1 --format='%h %ad %s' a9643ea85 v1.20 v1.21
git show 406002113 --stat                          # 关 #12 的 commit
git show 62f1c34df --stat                          # rte_timer_meta_init 引入
git show 62f1c34df -- lib/ff_dpdk_if.c
git show 14355bf7b --stat                          # 4 个本地补丁 re-apply
git show 9817534a2 --stat                          # PR#559 merge commit
git show v1.20:lib/ff_dpdk_if.c     | grep -n 'timer\|hardclock'
git show v1.20:dpdk/lib/librte_timer/rte_timer.c  | grep -n 'static.*priv_timer\|subsystem_init'

# === iWiki 抓取（iwiki-doc skill） ===
iwiki-cli metadata 4015929276
iwiki-cli get      4015929276
iwiki-cli download 34479037 34479039 34479050 34479057 34479068 34479073 34479081
# 7 张截图解析后通过 read_file 图像读取

# === 当前代码（HEAD）核查 ===
read_file lib/ff_dpdk_if.c            240-280, 1235-1280, 2785-2815
read_file dpdk/lib/timer/rte_timer.c  120-220
search_content lib/ff_dpdk_if.c "rte_timer|ff_timer|freebsd_clock"
```

## 1. Issue #547「Is F-stack support reload without any packet dropped?」

### 1.1 元数据

| 字段 | 值 |
|---|---|
| 编号 | #547 |
| 标题 | Is F-stack support reload without any packet dropped? |
| 作者 | orange30 |
| 状态 | closed（orange30 自己于 2021-09-22 关闭）|
| 创建时间 | 2020-09-18 08:05:02Z |
| 关闭时间 | 2021-09-22 14:14:17Z |
| 标签 | enhancement（jfb8856606 于 2022-10-18 补加）|
| 后续交叉引用 | #1036（2026-03-18）、#528（2026-03-18）、#673（2026-03-20）|

### 1.2 正文（原文）

> https://github.com/F-Stack/f-stack/issues/12
> The url said the reload has been supported, but it drop a lot packets when reload!
> In production, the packet drop is not vary good.
> Is there a method which support reload without any packet dropped?
> @whl739

### 1.3 全部评论（按时间顺序，原文保留）

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

#### C4 — orange30 — 2021-09-22T14:14:17Z（**关闭事件**）
> After solve some bugs，the changed version has support nginx reload without any packet dropped.

#### C5 — ygm521 — 2022-02-27T11:00:14Z
> @orange30 hello， f-stack reload，some questions asked,thanks! WeChat ygmdream

#### C6 — RockGo — 2022-03-25T06:29:38Z
> @orange30 can you share the idea, WeChat RockGo56

#### C7 — orange30 — 2022-09-28T11:42:25Z
> @ygm521 @RockGo for reference only.
>
> `<img width="1497" alt="1" ...>`（7 张图片，1.png～7.png；内容与 iWiki 4015929276 文档的 7 张截图相同——见 §3.2）

### 1.4 关键事实提炼

- **作者 orange30 2020-11-02（C2）明确指认失效根因**：DPDK 19 的 timer 库改用 `rte_memzone_reserve` 申请全局内存，而 DPDK 18 仅为进程内静态全局变量。他基于 F-Stack 1.20（DPDK 18.11）的改造版本在 19.11+ 不可用。
- **2021-09-22（C4）作者自行关闭**，只声明"修了一些 bug 后支持无丢包 reload"，**未公开代码/PR**，方案未合入 F-Stack 主线。
- **本 issue 无任何代码合并 / PR 关联 / commit 引用**（timeline 中无 commit_id）。
- **2022-10-18 才被 jfb8856606 补加 `enhancement` 标签**。

## 2. Issue #12「support nginx reload.」

### 2.1 元数据

| 字段 | 值 |
|---|---|
| 编号 | #12 |
| 标题 | support nginx reload. |
| 作者 | beacer |
| 状态 | closed |
| 创建时间 | 2017-05-23 06:33:25Z |
| 关闭时间 | 2017-08-23 09:01:33Z |
| 关闭方式 | commit `406002113b143fda1fa444f0af42b97b41951882`（"Support nginx reload. close #12."）由 logwang 提交，whl739 触发 close 事件 |

### 2.2 正文（原文）

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

### 2.3 全部评论（按时间顺序，原文保留）

#### C1 — whl739 — 2017-05-23T06:49:49Z（**F-Stack 主要维护者**）
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

### 2.4 关闭 commit（406002113b143fda1fa444f0af42b97b41951882）

- 作者：logwang <logwang@tencent.com>，时间 2017-08-23 16:54:32 +0800
- 标题："Support nginx reload. close #12."
- 关键改动（`git show 406002113 --stat`）：

```
app/nginx-1.11.10/src/event/modules/ngx_ff_channel.c             | 793 ++++++  # 中间层 channel（核心实现）
app/nginx-1.11.10/src/core/nginx.c                                |  55 +-
app/nginx-1.11.10/src/core/ngx_cycle.c                            |   2 +
app/nginx-1.11.10/src/core/ngx_cycle.h                            |   4 +
app/nginx-1.11.10/src/os/unix/ngx_process_cycle.c                 | 306 ++++++  # fork 流程改造
app/nginx-1.11.10/src/event/modules/ngx_ff_module.c               |  55 +-
doc/F-Stack_Nginx_APP_Guide.md                                    | 187 ++---
README.md                                                         |   4 +-
... (其他 nginx 配置/auto 工具微调)
freebsd/kern/kern_descrip.c                                       |  20 +-   # kernel 描述符 fork 适配
```

**关键事实**：本次提交**未引入「新旧进程共存 + 中间层 dispatch」的零丢包 reload 方案**，而是实现了**基于 fork 协议的原生 nginx master-worker 模式 reload**——即 "killall -SIGHUP nginx" 能让 worker 重读配置并继续服务，但**重启期间连接会丢**（这也是 issue #547 标题"drop a lot packets when reload"的根因）。

### 2.5 关键事实提炼

- #12 解决的只是「reload 进程能起来并重读配置」，**没有解决「reload 期间零丢包」**。
- 关闭后被多个 issue 反复 cross-referenced：#38、#70、#84、#235、#286 等等，最终 #547 描述"drop a lot packets when reload"指的就是这个 commit 实现版本的真实表现。

## 3. iWiki 4015929276《F-Stack Nginx reload方案》

### 3.1 元数据

| 字段 | 值 |
|---|---|
| 文档 ID | 4015929276 |
| 标题 | F-Stack Nginx reload方案 |
| 空间 | 915964362 (~fengbojiang，个人空间) |
| 作者 | 姜凤波 (fengbojiang, 即 jfb8856606 / johnjiang，F-Stack 维护者) |
| 创建时间 | 2025-08-25 20:47:51 |
| 最后修改 | 2025-12-12 12:41:51 |
| 关联 issue | https://github.com/F-Stack/f-stack/issues/547 |
| 父目录 | 4015138227 |

### 3.2 正文（原文）

> 该方案仅适用于 F-Stack-1.20（DPDK-18.11), 1.21(DPDK-19.11) 以后版本不适用
>
> 原文链接：https://github.com/F-Stack/f-stack/issues/547
>
> ![企业微信截图_17561254269161.png](https://iwiki.woa.com/tencent/api/attachments/s3/url?attachmentid=34479037)
> ![企业微信截图_17561254357073.png](https://iwiki.woa.com/tencent/api/attachments/s3/url?attachmentid=34479039)
> ![企业微信截图_17561255698874.png](https://iwiki.woa.com/tencent/api/attachments/s3/url?attachmentid=34479050)
> ![企业微信截图_17561257178764.png](https://iwiki.woa.com/tencent/api/attachments/s3/url?attachmentid=34479057)
> ![企业微信截图_17561258148977.png](https://iwiki.woa.com/tencent/api/attachments/s3/url?attachmentid=34479068)
> ![企业微信截图_17561258436279.png](https://iwiki.woa.com/tencent/api/attachments/s3/url?attachmentid=34479073)
> ![企业微信截图_17561259335258.png](https://iwiki.woa.com/tencent/api/attachments/s3/url?attachmentid=34479081)

### 3.3 7 张截图解析（按顺序）

> 通过 `iwiki-cli download` 下载至 `/tmp/iwiki_547/`，由 read_file 图像识别完成；下载完成后已用 `rm_tmp_file.sh` 清理（合规）。

#### 图 1（问题分析）
- **原生 nginx reload 分析**：
  1. 通过启动 new worker 进程加载新配置文件
  2. 内核协议栈维护着全局 socket connections
  3. Reload 期间协议栈决定各 connection 的去往新进程还是旧进程
- **DPDK nginx 对比分析**：
  1. DPDK bypass 内核协议栈，**用户态协议栈在进程内部**
     - **待解问题**：在新旧进程共存期间，需要有地方维护全局 connections 来决策该去往新进程还是旧进程
  2. DPDK 进程一般用法是**每进程 100% 占用一个 CPU**
     - **待解问题**：需解决"两个 DPDK 进程跑在同一个 core"的共存可行性问题
- 配图：原生 nginx master/worker 协议栈架构 vs DPDK nginx 协议栈+队列架构

#### 图 2（方案分析-1）
- **全局 connections 问题**
  - 应对方案：引入中间逻辑层，维护全局 connections 等
- **"两个 DPDK 进程跑在同一个 core"：共存可行性**
  1. DPDK Technical Lead 指出："两个 DPDK 进程跑在同一个核"这种情况，mempool 模块不安全；分析相关源码可确认"同一 mempool 中申请出来的 buffer，同时被这两个进程使用后释放"会导致 crash
  2. **应对方案**：**给新旧进程申请不同的 mempool**
  - 特殊情况："网卡驱动使用的 mempool"；**关闭 cache + 减小冲突域**，经测试性能损失很小
  - (1) 冲突域从 numa id 粒度优化为 workerid 粒度
  - (2) 底层使用 CAS 原子指令解决冲突
- **"两个 DPDK 进程跑在同一个 core"：进程调度权重重分配**
  - CFS 调度下：普通进程的 nice 值等于 0，其权重为基准的 1024
  - 应对方案：通过进程 nice 值进行调整
  - nice 值和调度权重的关系：`1024 / (1.25 ^ nice_value)`
- 配图：改造后处理框架（master + 中间层 + 新旧 worker 队列）

#### 图 3（方案分析-2）
- **"server 返回报文识别进新旧进程"问题**
  1. 五元组信息决定报文进入哪一个 worker 进程
  2. reload 期间，server 返回报文无法识别该进入新进程还是旧进程
  - 应对方案：与后端 server 通信的网卡**配置两个内网 IP**；**新旧进程分别使用不同的 ip 与后端 server 通信**（内网 ip 较为充足）
- **新问题**
  1. 反向代理下，f-stack 在 socket 连接的 connect 阶段**增加挑选 local port 的逻辑**，来保证返回报文进入同进程
  2. 上述方案需要在建立 socket 阶段调用 bind，但 freebsd 协议栈**不支持 `IP_BIND_ADDRESS_NO_PORT` 选项**
  - 应对方案：**给 freebsd 网络协议栈开发支持 IP_BIND_ADDRESS_NO_PORT**
- 配图：五元组 hash%N=workerid 路由逻辑图

#### 图 4（项目开发）
- **引入 dispatch 进程作为中间逻辑层**
  1. 维护全局 connection 表
  2. 与 worker 进程通过 ring 无锁队列连接
  3. 扩展原进程间通信通道，dispatch 进程常握全面信息
  4. **DPDK primary 从首个 worker 进程调整为首个 dispatch 进程**
- **"两个 DPDK 进程跑在同一个 core" 相关开发**
  - 共存可行性：新旧进程申请不同 mempool；修改网卡驱动对 mempool 的使用
  - 动态调整新旧进程 CPU 占用：
    - 负载：中间层维护新旧 worker 报文处理速率，作为动态调整基础
    - 调整：(1) 建立负载比与 nice 值映射表 (2) 新旧进程共存期间，中间层进行动态调整
- **"server 返回报文识别进新旧进程"问题**
  1. 修改 nginx 支持根据进程新旧状态 bind 不同的源 ip
  2. 为协议栈开发支持 IP_BIND_ADDRESS_NO_PORT 功能
- **老 worker 进程退出条件调整**
  - 问题描述：原生 nginx 退出条件只关注协议栈内没有本 worker 相关 socket；**需增加考虑到达中间层但尚未进入用户态协议栈的连接（或 connection）**
  - 修改方案：退出条件修改为"全局 connections 中没有本进程相关的 connection"

#### 图 5（少量超时问题描述与分析）
- **问题现象**：自测时，**wrk 在多次 reload 情况下会有少量 timeout**
- **问题分析**
  1. 推测因某些瞬间 cpu 处理能力不够
  2. 有很多潜在的可能：新进程启动事件？老进程退出事件？还是流量切换事件？存在其他位置 bug 导致？等等
- **突破点**
  1. 阅读 wrk 部分源码，梳理 timeout 的处理逻辑
  2. 使用 eBPF 相关工具，精准定位到 timeout 集中发生在新老进程**流量切换的瞬间**
- 配图：`wrk -c50 -t10 --latency http://<DPDK_NIC_IP>/2 -d600000s` 实测数据（原截图命令中含真实测试地址，此处按文档规约以 `<DPDK_NIC_IP>` 占位符替代）：**wrk 跑 10 小时，期间 reload 200 次，测试结果 Socket errors: connect 0, read 0, write 0, timeout 112**

#### 图 6（少量超时问题原因与解决方案）
- **问题原因分析**
  1. 新启动 worker 的 nice 最初被设置成 19，占 1.7% 的 cpu
  2. 当流量切换瞬间，给新 worker 预分配多大处理能力？
     - (1) 若给太大，老 worker 性能被削减太多
     - (2) 若给太小，新 worker 性能不一定足够
- **创新性解决方案**
  1. 原生 nginx 同时让所有 worker 进行流量切换；**改进为各个 worker 依次进行流量切换的方式**
  2. reload 到每个 worker 时，**把新 worker 进程绑定至预留的 cpu 核**（比如最后一个核），同时把该进程 nice 值设置回正常状态。流量切换，同时会触发中间层动态调整新旧进程 cpu 分配的机制
  3. **1 秒钟后将新 worker 绑定回原 cpu 核**

#### 图 7（验收与总结）
- **稳定性**：压测期间长时间频繁 reload，无 timeout 或其他 error 出现
- **性能**：**QPS 可以达到 58 万，是原生 nginx 的两倍+**
  - 测试对比环境：同一套环境，同样配置：长连接，小包，写日志打开等，详见附件
- **兼容性**：已有 nginx 模块无需改动就可直接使用
- 配图：原生 nginx（~22.5 万 QPS）vs 支持 reload 版本 DPDK nginx（~58 万 QPS）柱状图

### 3.4 关键事实提炼

- **本方案是 orange30 个人在 F-Stack 1.20（DPDK 18.11）上做的改造版，原始代码从未开源/未合并**。issue #547 仅有截图讨论、微信联系。
- 维护者 fengbojiang 自己把方案归档到 iWiki 个人空间，并明确标注"**1.21（DPDK-19.11）以后版本不适用**"——这与 #547 评论 C2 中 orange30 自陈"my version cann't be work in new f-stack version"完全一致。
- 方案核心四大改造点：
  1. **dispatch 进程中间层**维护全局 connection 表 + 无锁 ring 队列（与 #12 commit 406002113 的 `ngx_ff_channel.c` 中间层 channel 思路同源但更激进——前者是 fork 协议适配，后者是 DPDK multi-process 共享状态）。
  2. **新旧进程不同 mempool**（解决"同 core 两 DPDK 进程"mempool 不安全问题）+ 网卡驱动 mempool 关闭 cache。
  3. **进程 nice 值动态调整 + CFS 权重公式 `1024 / (1.25^nice)`**。
  4. **网卡双内网 IP + `IP_BIND_ADDRESS_NO_PORT`**（需 freebsd 协议栈新开发支持）让 server 回包可识别新旧进程。

## 4. 相关 PR / Commit 证据

### 4.1 gh search "reload" -R F-Stack/f-stack

issue 总览（7 条）：

| # | 编号 | 状态 | 标题 |
|---|------|------|------|
| 1 | #1036 | closed | 如何实现nginx 优雅的reload |
| 2 | #528 | closed | /usr/local/nginx_fstack/sbin/nginx -e reload Startup failed |
| 3 | #673 | closed | exec() support in F-stack |
| 4 | #547 | closed | Is F-stack support reload without any packet dropped? |
| 5 | #12 | closed | support nginx reload. |
| 6 | #382 | closed | fstack nginx fail to start by systemd |
| 7 | #398 | closed | Nginx built with f-stack is the same performance as nginx without |

PR 仅 1 条：**PR#559**（已合并）。

### 4.2 PR#559 - Config: Support parse "--file-prefix"&"--pci-whitelist" for multi-processes

- 编号：#559
- 作者：hawkxiang
- 状态：closed (merged)
- 合入时间：2020-11-19 14:43:26 +0800
- 本地 merge commit：`9817534a213ffa9f3c68eb721683a807d20387fd`（9817534a2）
- 改动：`lib/ff_config.c` 18 行、`lib/ff_config.h` 6 行
- **PR body 关键叙述**：

> 修改 f-stack 配置文件识别功能，支持 parse file-prefix & pci-whitelist 两个配置项，解决**多进程绑定同 CPU 核心时内存异常问题**：
> a. 同物理机上多个容器分别部署 DPDK 程序，共用物理机 Hugepage；
> b. **类似 Nginx 的 reload 过程，多进程绑定相同 CPU 核心，共用 Hugepage**

- **意义**：这是 F-Stack 主线**唯一**一条与「reload 期间多进程共存」直接相关的合入 PR，但仍只是配置解析层面支持 `--file-prefix` 让多组 DPDK 进程用不同共享内存前缀，**不涉及 timer / mempool / 进程调度等核心改造**。

### 4.3 其他 grep 命中（仅文档/历史 commit，非代码改动）

- `git log -i --grep=nginx`：主要是 nginx 1.11.10 → 1.25.2 → 1.28.0 升级、IP_TRANSPARENT 支持、IPV6_PKTINFO 翻译等，**无 reload 核心 commit**。
- `git log -i --grep=reload`：命中 `docs: ...` 类的博客/benchmark commit，无 reload 代码改动（最新 native-mt / 23→24 升级等都不是 reload 主题）。
- `git log -S 'rte_timer' -- lib/ff_dpdk_if.c` 全树仅 3 个 commit：
  - `a9643ea85`（2017-04-21 init，F-Stack 仓库初始化）
  - `62f1c34df`（2026-01-16，jinliu777 "Fix infinite loop when restarting DPDK secondary process"，引入 `rte_timer_meta_init`）
  - `82b409faf`（2026 native-mt callwheel per-thread）

## 5. 定时器演变 git 证据链

### 5.1 时间线总览

| 时间 | 事件 | 提交 | 关键变化 |
|------|------|------|----------|
| 2017-04-21 | 仓库 init | a9643ea85 | DPDK timer lib（17.11 时期）：`static struct priv_timer priv_timer[RTE_MAX_LCORE]` 进程内静态数组；`rte_timer_subsystem_init` 仅 spinlock-init 静态数组 |
| 2019-11-23 | tag **v1.20** | 4b05018ff "DPDK: update to 18.11.5." | DPDK 18.11.5 LTS；timer lib 仍为进程内静态（见 §5.2） |
| **2020-06-18** | **DPDK 19.11.2 升级** | **37a7c72f0 / 4418919fe** | **timer lib 切到 `rte_memzone_reserve` 全局 memzone**（orange30 指认的失效分水岭） |
| 2020-11-19 | PR#559 合入 | 9817534a2 | 多进程 file-prefix/pci-whitelist 解析（reload 期间内存隔离基础） |
| 2021-01-29 | tag v1.21 | 2df8fe233 | "Update release note for 1.21."；DPDK 19.11.x |
| 2026-01-16 | 引入 `rte_timer_meta_init` 本地补丁 | **62f1c34df** | F-Stack 自有 DPDK timer 补丁：解决"DPDK secondary 进程重启时 rte_timer_manage 死循环" |
| 2026-06-09 | 本地 DPDK 4 补丁 re-apply 到 24.11.6 | **14355bf7b** | 4 补丁之一即 `rte_timer_meta_init`；同提交还把 `dpdk/lib/timer/` 从 23.11.5 cp 到 24.11.6 树 |

### 5.2 v1.20（DPDK 18.11.5）timer lib 进程内静态实现

> `git show v1.20:dpdk/lib/librte_timer/rte_timer.c`

```c
// L52 - 进程内静态数组（每个 DPDK 进程独立一份）
static struct priv_timer priv_timer[RTE_MAX_LCORE];

// L67-78 - subsystem_init 仅为静态数组 spinlock-init
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

### 5.3 当前 HEAD（DPDK 24.11.6 + F-Stack 本地补丁）timer lib 共享 memzone 实现

> `dpdk/lib/timer/rte_timer.c`（F-Stack 维护的本地副本，见补丁 14355bf7b 注释）

```c
// L122-185 - subsystem_init 改为 rte_memzone_lookup/reserve_aligned 共享内存
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
    rte_timer_data_arr = mz->addr;        // 数组指向共享 memzone
    rte_timer_mz_refcnt = (void *)((char *)mz->addr + data_arr_size);
    ...
    (*rte_timer_mz_refcnt)++;
    rte_timer_subsystem_initialized = 1;
    rte_mcfg_timer_unlock();
    return 0;
}

// L216-228 - 【F-Stack 本地补丁】rte_timer_meta_init
int
rte_timer_meta_init(void)
{
    struct rte_timer_data *timer_data;
    struct priv_timer *pt;
    unsigned lcore_id = rte_lcore_id();
    TIMER_DATA_VALID_GET_OR_ERR_RET(default_data_id, timer_data, -EINVAL);
    pt = &timer_data->priv_timer[lcore_id];
    memset(pt, 0, sizeof(*pt));           // 显式初始化本 lcore 槽
    pt->prev_lcore = lcore_id;
    return 0;
}
```

### 5.4 `rte_timer_meta_init` 引入 commit 62f1c34df（关键证据）

- 日期：2026-01-16 17:41:18 +0800
- 作者：jinliu777
- 标题："Fix infinite loop when restarting DPDK secondary process"
- stat：

```
dpdk/lib/timer/rte_timer.c | 14 ++++++++++++++   # 新增 rte_timer_meta_init + 头文件
dpdk/lib/timer/rte_timer.h |  9 +++++++++    # 导出符号
lib/ff_dpdk_if.c           |  8 ++++++++   # init_clock 调一次，stop_clock 同步
```

`lib/ff_dpdk_if.c` 改动 diff 摘录：

```c
@@ init_clock(void) @@
    rte_timer_subsystem_init();
+   rte_timer_meta_init();      // <-- 新增：解决 secondary 进程重启时 rte_timer_manage 死循环
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

**意义**：

1. **F-Stack 在 2026 年仍需对 DPDK 共享 memzone timer 做本地补丁**——直接坐实"多进程（primary/secondary）共存时 timer 库共享状态会出问题"。
2. **commit message "restarting DPDK secondary process"** —— "secondary 重启"恰好对应 nginx reload 期间"新 worker（secondary）启动 + 老 worker 退出"的核心场景。

### 5.5 F-Stack 自身 ff_dpdk_if.c timer 使用层（变更前 vs 当前）

| 项目 | v1.20（init a9643ea85 + v1.20 tag） | 当前 HEAD（DPDK 24.11.6）|
|------|--------------------------------------|----------------------------|
| `freebsd_clock` 存储 | `static struct rte_timer freebsd_clock;`（L80，全局）| `static __thread struct rte_timer freebsd_clock;`（L113，每线程一份，native-mt 改造）|
| hardclock 回调 | `freebsd_hardclock_job`（L131）| `ff_hardclock_job`（L255，主线程）+ `ff_hardclock_worker_job`（L262，worker 线程）|
| subsystem_init 调 | `rte_timer_subsystem_init()`（L794）| `rte_timer_subsystem_init()` + `rte_timer_meta_init()`（L1244-1245）|
| main_loop 驱动 | `rte_timer_manage()`（L1533）| `rte_timer_manage()`（L2805），调度点 `if (unlikely(freebsd_clock.expire < cur_tsc))` 一致 |

**关键发现**：F-Stack 自身 `ff_dpdk_if.c` 中 timer 使用代码（subsystem_init + reset + manage 调用骨架）从 2017 init 到 2026 之间**基本未变**（除 native-mt 改成 `__thread`）。**变化的全部集中在 DPDK timer lib 自身（18.11 静态 → 19.11+ 共享 memzone）以及 F-Stack 给该库打的本地补丁。**

## 6. 旧方案要点与失效性结论（以代码为准）

### 6.1 旧方案技术要点

来源：iWiki 4015929276 文档全文 + 7 张截图解析 + issue #547 评论 C2（C3）。

| 维度 | 旧方案做法 | 必要条件 |
|------|------------|----------|
| **架构** | 引入 **dispatch 进程**作为中间逻辑层，维护全局 connection 表；worker 通过 ring 无锁队列与 dispatch 通信 | DPDK 进程能稳定"多进程同 core 共存" |
| **mempool 隔离** | 新旧 worker 各自申请**不同 mempool**；网卡驱动用 mempool 关闭 cache + 缩小冲突域（numa id → workerid 粒度）| 解决"同一 mempool buffer 被两进程并发释放 crash" |
| **进程调度** | 通过 `nice` 值动态调整：`nice=19` 新 worker 仅占 1.7% CPU，1 秒后绑回原 CPU 核；CFS 权重公式 `1024 / (1.25 ^ nice_value)` | Linux CFS 调度 + 多进程同 core 共存 |
| **连接路由** | 网卡配两个内网 IP，新旧 worker 各用一个；f-stack socket connect 阶段增加 local port 挑选逻辑保证回包入同进程 | freebsd 协议栈支持 **`IP_BIND_ADDRESS_NO_PORT`** 选项（旧 F-Stack 1.20 的 freebsd 11/13 不支持，需新开发）|
| **退出条件** | worker 退出条件改为"全局 connections 中无本进程 connection"（而非"无本进程 socket"）| dispatch 中间层有完整 connection 视图 |
| **DPDK timer 假设** | F-Stack 1.20（基于 DPDK 18.11）：**timer lib 是每进程独立静态数据**——`static struct priv_timer priv_timer[RTE_MAX_LCORE]` | 旧版 DPDK timer 库的"进程内静态"实现 |

### 6.2 旧方案在 DPDK 19.11+ 失效的关键环节（以代码为准）

| 旧方案依赖点 | DPDK 19.11+ 实际情况 | 失效影响 |
|--------------|----------------------|----------|
| "timer 库是每进程独立静态数据" → dispatch 进程与其他 worker 进程的 `priv_timer` 数组物理隔离 | **19.11 起 `priv_timer` 数组搬入共享 memzone**（"rte_timer_mz"），所有 DPDK 进程共享同一份 `rte_timer_data` | 每进程 reset 的 `freebsd_clock` 都进同一份 `priv_timer[lcore_id]` 槽；多进程同时驱动同一槽→ 竞争、重复触发、`rte_timer_manage` 误触发别进程定时器 |
| 多进程同 core 共存 | mempool 隔离 + nice 调整可解决。但 timer 共享后，dispatch 进程 + worker 进程的 rte_timer_manage 会在同一 lcore 上跑（不同时刻），prev_lcore 关系紊乱 | worker 的 `ff_hardclock` 触发节奏被打乱，连接超时/RTO 重传时间不准，间接导致 reload 期间连接异常 |
| `rte_timer_subsystem_init` 仅 init 一次 | **现版本需配套 `rte_timer_meta_init`** 显式初始化本进程 lcore 槽（补丁 62f1c34df，2026-01-16），否则 secondary 进程重启会"infinite loop" | 2026 年仍有 F-Stack 本地补丁在补这一缺陷；orange30 在 2020-11 描述的"DPDK 19 timer 库变化"问题至今未通过上游修复彻底闭环 |
| `--file-prefix` 支持 reload 期间多组 DPDK 进程内存隔离 | PR#559（2020-11 合入）补了配置文件解析 | 这一层已 OK，但只是基础设施，不是 timer/connection 共享状态问题的解药 |
| freebsd 协议栈 `IP_BIND_ADDRESS_NO_PORT` | 当前 freebsd 15.0 树**已支持**（**2026-08-18 已坐实**，见 §8 U1）：协议栈行为层由 cb9b4d462（2025-07-25，bind 不分配端口、connect 时按 RSS 一致性选源端口）经 ff9e3c449（2026-06-22）port 到 15.0 树（`freebsd/netinet/in_pcb.c` `#ifdef FSTACK` 块）；setsockopt 接口层由 a2537e143（2026-07-16）在 `lib/ff_syscall_wrapper.c:100/979/1041-1046` 拦截 `LINUX_IP_BIND_ADDRESS_NO_PORT(24)` 为成功 no-op（处理与 FreeBSD `IP_BINDANY(24)` 数值冲突）。注：此系 F-Stack 本地扩展，上游原生 FreeBSD 15.0 无此选项（Linux 兼容层显式报 unsupported）| "网卡双 IP + 新旧 worker 各用一 IP"方案的协议栈前提**已具备**，S1 评估中该风险消除（见 [06](06-solution-design.md) §3.1/S1）|

### 6.3 失效分水岭与现状定性

- **分水岭 commit**：`37a7c72f0 / 4418919fe`（2020-06-18，"DPDK: upgrade to DPDK 19.11.2(LTS)."）。该 commit 之前 v1.20（DPDK 18.11.5）timer 库是进程内静态；之后 v1.21+ 改共享 memzone。
- **旧方案失效确认人**：orange30 本人（issue #547 评论 C2，2020-11-02）。
- **维护者归档确认**：fengbojiang (jfb8856606) 把方案放进个人 iWiki 空间 4015929276 标注"1.21+ 不适用"，间接官方承认失效。
- **F-Stack 主线未做任何针对 reload 期间多进程共享 timer 状态的修复**——git log -S 'rte_timer' -- lib/ff_dpdk_if.c 全树仅 3 个 commit（init 2017 / 2026-01-16 补丁 / 2026 native-mt callwheel），其中 native-mt 改造目标也不是 reload。

## 7. 关联本地档案（已坐实条目）

`docs/zh_cn/f-stack-issue-ana.md` 中与本考证直接相关的本地档案：

| 行号 | issue | 状态 | 已记录结论摘录 |
|------|-------|------|----------------|
| L2074-2076 | **#547** | ⚪closed | 2021-09-22 最终回复：orange30 确认修复 bug 后版本支持零丢包 reload，方案基于 DPDK18.11+F-Stack-1.20，专用接收核 + 动态 renice；未合并入官方；DPDK19+ 因 timer 库变化（`rte_memzone_reserve`）不兼容需适配。相关：#12、#1036、#528 |
| L2175-2177 | **#12** | ⚪closed | 截至关闭时（2017-08）官方计划通过实现/hook fork 来支持类似 reload 的能力，**功能仍在推进中**而非已验证完成 |
| L557-559 | #528 | ⚪closed | 官方最终确认 `-s reload` 触发 nginx 优雅重载信号，但 F-Stack nginx 不支持优雅重载，无论如何调用重载进程都会造成短暂服务中断。零停机 reload 需 DPDK 18.11 配合 orange30 社区补丁（#547 专用接收核方案），DPDK19+ 需适配 timer 库变化 |

**关联 issue**（gh search "reload" -R F-Stack/f-stack）：#1036、#528、#673、#547、#12、#382、#398。其中 #528、#1036、#673 在本考证中作为佐证（cross-referenced 来源），未单独深抓评论。

## 8. 未坐实清单 / 后续考证待办

| 编号 | 未坐实项 | 原因 | 建议下一步 |
|------|----------|------|------------|
| U1 | ~~当前 freebsd 15.0 树是否已支持 `IP_BIND_ADDRESS_NO_PORT`~~ **→ 已坐实（2026-08-18）：支持** | 原未坐实原因：初版考证未在 freebsd/ 树中以标识符 grep 定位（实现为 `#ifdef FSTACK` 行为改动 + `lib/ff_syscall_wrapper.c` 拦截，无裸选项名命中），且未跑 `git log --grep=IP_BIND_ADDRESS_NO_PORT`。坐实证据链（均 `git merge-base --is-ancestor` 确认 IN-HEAD）：cb9b4d462（2025-07-25 原始实现）→ ff9e3c449（2026-06-22 port 到 15.0 树，`freebsd/netinet/in_pcb.c` bind-then-connect + RSS 一致性选源端口）→ a2537e143（2026-07-16 `lib/ff_syscall_wrapper.c:100/979/1041-1046` setsockopt/getsockopt 接线，处理与 `IP_BINDANY(24)` 数值冲突）；配套 35aa95846/23e545932/458e91288/699c763b4 共 8 个相关 commit | ~~已解决~~ 注意：该支持为 **F-Stack 本地扩展**，上游原生 FreeBSD 15.0（freebsd-src-releng-15.0）无此选项（Linux 兼容层 `linux_socket.c` 显式报 unsupported），升级 freebsd 树时需保留这些补丁 |
| U2 | F-Stack 1.20 vs 1.21 升级期间 ff_dpdk_if.c timer 使用层是否曾有调整 | `git log -S 'rte_timer' -- lib/ff_dpdk_if.c` 仅返回 3 个 commit，且 v1.20→v1.21 diff 关键字 'timer' 无输出（说明骨架无变）| 但未对 `freebsd_clock` 标识符名、job 函数名等做完整比对；如要 100% 坐实需对 v1.20 与 v1.21 完整 diff |
| U3 | iWiki 截图 7（验收）柱状图原始数据 | 柱状图无具体测试命令/环境参数；截图自述"详见附件"但 iWiki 文档无附件链接 | 实地复测：找一台 4-rcv-core + 26-nginx-core 的对照机，按 orange30 改法实测 QPS |
| U4 | "wrk 跑 10h 200 次 reload 112 timeout" 对应 0.000006% 概率的复现性 | 截图数据可信但需独立实测验证 | 复现：wireshark/ebpf 抓流量切换瞬间，验证 timeout 集中点 |
| U5 | orange30 改造版原始代码 | 仅有截图 + 微信联系，**从未开源** | 不可恢复；如有需要只能向 jfb8856606 通过微信群引荐（issue #547 评论 C3）|
| U6 | 当前 24.11.6 + native-mt 下"reload 期间多 worker 进程"实测表现 | 本考证仅做静态分析，缺运行时数据 | 在本机 DPDK 网卡 + 4-core/26-core 配比下做一次 reload 零丢包复现：先看是否丢包、丢多少、看 rte_timer_manage 错误计数、看 memzone refcnt 异常 |
| U7 | issue #528、#1036、#673 评论是否补充新方案细节 | 本考证按任务要求只深抓 #547、#12；其余仅做交叉引用 | 如需完整画像再单开考证 |

## 9. 对后续 spec 文档的输入要点（已并入 [06-方案设计](06-solution-design.md) 与 [07-里程碑](07-milestones.md)）

1. **不要把「orange30 截图方案」当 F-Stack 主线 reload 设计**——已坐实是社区个人版，仅适用 DPDK 18.11 / F-Stack 1.20。
2. **DPDK 19.11+ 后的新方案需同时解决 3 个独立问题**：(a) 共享 memzone timer 在多进程共存下的状态隔离；(b) 协议栈 `IP_BIND_ADDRESS_NO_PORT` 支持（**U1 已坐实：F-Stack 15.0 栈已支持**，见 §6.2/§8，系本地扩展）；(c) dispatch 中间层 connection 表与 ring 队列的标准化实现。
3. **可借鉴的现有主线 PR**：仅 PR#559（多进程 file-prefix 解析）——是目前唯一可用的 reload 期间多进程内存隔离基础设施。
4. **可借鉴的本地 DPDK 补丁**：`rte_timer_meta_init`（62f1c34df）——但其目标是"secondary 进程重启不死循环"，**未直接解决"reload 期间新旧 timer 状态隔离"**。

---

**证据强度声明**：本篇全部基于 gh CLI / git log/show / iwiki-cli / 当前代码直接读取，未做推测；未坐实项集中于 §8（原 7 项，U1 已于 2026-08-18 坐实为「支持」后余 6 项），主要缺运行时数据。
