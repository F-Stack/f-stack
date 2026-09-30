# 02 Other Project Research: Kernel Baseline and Other User-Space Stacks on Lossless nginx Reload (English)

> **English translation** of `docs/nginx_reload_spec/zh_cn/02-other-projects-research.md` (v1.3). The Chinese text is
> authoritative; where the two differ, the Chinese original governs.
> Translated 2026-09-30.

| Item | Value |
| --- | --- |
| Document ID | 02 |
| Title | Three kernel-baseline mechanisms / the eBPF line / other user-space stacks / general patterns and a first applicability judgement |
| Version | v1.3 (on v1.2: **final gate G-D rework F-01 cross-document sweep** — the R-01 code fix (`lib/ff_dpdk_if.c:669-673`, per-generation pool `cache_size=0`) has landed; this document was swept end to end and **no "per-generation pool not zeroed / still 256" wording needs rewriting** (this document does not discuss per-generation mempools), so only the version header is synced. v1.1 = **corrected per the `plan_cross_audit` G-A verdict R-07 same-source item** — §5.1-1 item 1, "USR2-style binary upgrade is impossible on the current F-Stack architecture", annotated in place: that conclusion applies only to the mainline architecture before M5; M5 implements USR2 through "resident slim primary + generation-directory arbitration" (`ngx_process_cycle.c:495` `ngx_exec_new_binary`, C-NR-501~504, [08](testing-plan.md) RT-04 / RT-04b pass on a real machine); the historical conclusion is **kept, not deleted**, to preserve audit traceability) |
| Date | 2026-08-18 (v1.1 addition: 2026-09-17) |
| Status | pending human audit |
| Revision notes | v1.1 (2026-09-17): corrected per the `plan_cross_audit` G-A verdict R-07 same-source item — §5.1-1 item 1 annotated in place with the fact that M5 has implemented it; the historical conclusion is kept. v1.2 (2026-09-18): final gate G-D rework F-01 cross-document sweep — the R-01 code fix has landed; the sweep found no R-01 wording here, so only the version header is synced. **v1.3 (2026-09-18): R-01 mechanism error wrap-up (G-D "must be completed before commit")** — the sweep found no landing point for that mechanism error here (this document does not discuss per-generation mempools), so only the version header is synced |
| Source artefact | `work/research-other-projects.md` (researcher `researcher-others`, filed 2026-08-18). This document is the formalised rewrite: process narrative removed, all factual evidence kept (URL, original sentences, issue/PR numbers), together with the unconfirmed markings and the single-source declarations; the "list of operations actually executed" is kept as §1 so the evidence stays traceable |

Related: [00 Overview](overview.md) | [01 VPP/VCL Research](vpp-vcl-research.md) | [06 Solution Design](solution-design.md)

---

## 1. Research method and the operations actually executed

Method: `web_search` to find leads → `web_fetch` to obtain first-hand sources (official documentation / official blogs / GitHub repositories / kernel documentation) for cross-validation; the local F-Stack repository archive (`docs/f-stack-issue-ana.md`) is used for the applicability analysis. Asserting from memory is forbidden; every point whose original text was not obtained goes into the §6 list.

Operations actually performed (grouped by topic):

| # | Operation | Result |
| --- | --- | --- |
| 1 | web_fetch the official nginx control documentation | success (HUP/USR2/WINCH/QUIT in full) |
| 2 | web_fetch the official nginx `ngx_http_core_module` (listen/reuseport) | success |
| 3 | web_fetch the F5/NGINX official Socket Sharding blog (1.9.1) | success (the old nginx.com link 301-redirects to f5.com; body and performance data obtained) |
| 4 | web_archive fetch of the original nginx.com blog page | failed (HTTP 429 rate limiting, twice) |
| 5 | web_fetch nginx trac ticket #237 (systemd socket activation) | success (including Maxim Dounin's official reply, verbatim) |
| 6 | web_fetch the Envoy official hot restart architecture documentation | success |
| 7 | web_fetch the HAProxy 3.0 official Management Guide | success (seamless reload / -x / SIGTTOU etc. in full) |
| 8 | web_search + web_fetch the Cloudflare tubular blog | success (the correct slug is tubular-fixing-the-socket-api-with-ebpf/) |
| 9 | web_fetch the Linux kernel `prog_sk_lookup` documentation | only search-snippet-level original sentences obtained (the kernel.org page was not fetched in full) |
| 10 | web_fetch the Chinese translation of Facebook LPC 2021 "From XDP to Socket" (Tencent Cloud community edition) | success (including socket takeover and `bpf_sk_reuseport` details; the original LPC slides were not obtained directly) |
| 11 | web_fetch the Cilium official documentation intro page | success (the socket-level LB original sentence); the cilium.io 1.6 blog body was drowned in page framework, so only its title and the intro documentation were used |
| 12 | web_fetch the mTCP GitHub README + `api.h` header + `src` directory structure | success (the `api.c` original text was partly truncated; the `mtcp_init.c` path returns 404 and does not exist) |
| 13 | web_fetch the Seastar GitHub README + `doc/tutorial.md` | success |
| 14 | web_fetch the 6WIND Virtual Accelerator official documentation introduction page | success (the product home page www.6wind.com returns 403) |
| 15 | web_fetch the OpenOnload GitHub README | success |
| 16 | web_fetch the ansyun/dpdk-nginx README | success |
| 17 | web_search lwIP/PicoTCP + nginx | no nginx port found (not exhaustive) |
| 18 | web_search 6WIND + nginx combined directly | no first-hand material (see §6) |
| 19 | local search of the f-stack repository for nginx reload archives | success (`docs/f-stack-issue-ana.md` #12 / #528 / #547 / #1036) |

## 2. Kernel baseline: three mechanisms (the comparison baseline)

### 2.1 nginx binary online upgrade (SIGUSR2, two masters coexisting)

Source: the official nginx documentation https://nginx.org/en/docs/control.html (referred to below as [NGINX-CTL])

Flow (key original sentences):

1. Prerequisite: the new binary replaces the old file first;
2. The old master renames the pid file to `nginx.pid.oldbin`, then `exec`s the new executable, and the new master starts new workers;
3. "After that all worker processes (old and new ones) continue to accept requests." — old and new workers accept requests in parallel. The documentation does not say directly that the listening fd is inherited, but the fact that old and new workers accept at the same time lets one infer that the new master inherited the listening sockets through fork+exec; and an nginx core developer states the internal mechanism explicitly in trac #237: "nginx is capable of using inherited file descriptors for listening sockets, via NGINX environment variable with a list of file descriptors to use" (https://trac.nginx.org/nginx/ticket/237, Maxim Dounin's reply);
4. Key difference: on HUP the old workers close the listening sockets; on USR2 "the old master process does not close its listen sockets, and it can be managed to start its worker processes again if needed" — listening is kept for rollback;
5. Two rollback paths: send HUP to the old master (restart the old workers without re-reading the configuration, then QUIT the new master); or TERM the new master (the old master restarts its workers automatically);
6. Finishing a successful upgrade: QUIT the old master.

Why connections are not lost (based on the [NGINX-CTL] mechanism):

- The listening fd is inherited across fork+exec (kernel fd semantics plus an explicit list passed through the NGINX environment variable), so the new master can accept new connections from the moment its initialisation completes — there is no listening gap;
- All established connections live inside the old workers' own processes (accepted sockets); the old workers drain the existing connections before exiting;
- The old master keeps the listening fd, so rollback has no listening gap either.

### 2.2 HUP reload (re-reading the configuration with the same binary)

Source: [NGINX-CTL]. Original text: "The master process first checks the syntax validity, then tries to apply new configuration... If this fails, it rolls back changes and continues to work with old configuration. If this succeeds, it starts new worker processes, and sends messages to old worker processes requesting them to shut down gracefully. Old worker processes close listen sockets and continue to service old clients. After all clients are serviced, old worker processes are shut down."

Key points: a configuration failure can be rolled back; the new workers start first, the old workers close listening but keep serving existing connections until drained. Difference from USR2: HUP changes the configuration but not the binary, and the old workers close the listening socket (nothing is kept for rollback); USR2 changes the binary, and the old master does not close listening so that rollback is possible. **[2026-09-22 sync, A01-5]** The above is the **general HUP/USR2 semantics**, which must be stated separately according to whether the listening configuration changes: when the listen directive does not change, the new workers reuse/inherit the same listening fd (the listening reuse at `ngx_cycle.c:533-540`) and only then do the old workers close their own reference; when the listen directive changes (ports/addresses added or removed), the new cycle creates new listening sockets through `ngx_open_listening_sockets(cycle)` (`ngx_cycle.c:624`; the same function on the worker side is at `ngx_process_cycle.c:2111`/`:3147`), and the old listening sockets close when the old workers exit. It must **not** be written generically as "the new workers always create new listening sockets and the old workers keep theirs until they exit".

Known boundary (the HAProxy documentation's statement about the same class of mechanism, usable as corroboration): when the old process closes the listening port, "the kernel may not always redistribute any pending connection that was remaining in the socket's backlog. Under high loads, a SYN packet may happen just before the socket is closed, and will lead to an RST packet being sent to the client." (https://docs.haproxy.org/3.0/management.html) That is, connections in the backlog that have not been accepted may still be lost at the boundary; "lossless" is approximately lossless in the engineering sense.

### 2.3 Reload under SO_REUSEPORT (socket sharding)

Sources:

- The official nginx listen documentation: https://nginx.org/en/docs/http/ngx_http_core_module.html — "reuseport this parameter (1.9.1) instructs to create an individual listening socket for each worker process (using the SO_REUSEPORT socket option on Linux 3.9+ and DragonFly BSD, or SO_REUSEPORT_LB on FreeBSD 12+), allowing a kernel to distribute incoming connections between worker processes."
- The official NGINX blog (F5 archive): https://www.f5.com/company/blog/nginx/socket-sharding-nginx-release-1-9-1 (Andrew Hutchings, 2015-05-26): "there are multiple socket listeners for each IP address and port combination, one for each worker process", "The kernel determines which available socket listener (and by implication, which worker) gets the connection."; performance: 36 cores, 4 workers, wrk load test — "reuseport increases requests per second by 2 to 3 times, and reduces both latency and the standard deviation for latency"; caveats: a blocked single worker also affects the pending connections the kernel has already assigned to it; the mail module is not supported.

Reload behaviour: the official documentation has **no specific description of HUP/USR2 behaviour in reuseport mode [no official original text found]**. Mechanically one may infer (inference, not confirmed in the official documentation): at reload each new worker creates its own listening socket and joins the kernel reuseport group, the old workers keep their own sockets and keep serving existing connections until they exit; new connections are distributed by the kernel by hash over "all sockets in the group at that moment", so old and new workers accept new connections in parallel. Corroboration: Envoy enables `reuse_port` by default and on hot restart "Envoy passes each socket to the new process by worker index. Thus, no connections are dropped in the accept queues of the draining process." (https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/hot_restart) — an official behaviour description for the same reuseport + hot restart combination. **[2026-09-22 sync, A01-5]** Envoy is the official behaviour of **another proxy** and **cannot serve as evidence of nginx's HUP/USR2 behaviour under reuseport**; it is registered here only as corroboration of "the same mechanism combination". The nginx-side conclusion still follows the nginx source and official documentation, and the paragraph above keeps its "no official original text found" marking.

Known shortcomings:

- The kernel distributes by connection four-tuple hash, with no load awareness; "uneven distribution" (for example a few high-traffic long connections concentrating on one worker) is not acknowledged in nginx's official material (the official blog instead says "the load was spread evenly across the worker processes", under short-connection load-test conditions), and no first-hand quantitative source for the nginx scenario was found in this research [not confirmed]. For UDP there is first-hand Facebook material on the distribution problem (see §2.4).
- The Envoy documentation notes the boundary of the reuseport + hot restart combination: when the number of concurrent connections decreases, "some connections may be dropped in the accept queues of the old process workers" (same Envoy URL).
- Security note: the official nginx documentation states "Inappropriate use of this option may have its security implications."

### 2.4 eBPF-guided / redirected sockets (the sk_lookup and sk_reuseport lines)

Correction of the task premise (important): among public first-hand material, the complete practice of using eBPF for "zero-downtime restart" is **Facebook (Meta)**'s LPC 2021 talk (using BPF_PROG_TYPE_SK_REUSEPORT + REUSEPORT_SOCKARRAY, plus the earlier pure SCM_RIGHTS fd-passing socket takeover); **Cloudflare** contributed and runs in production the **sk_lookup hook** (the tubular tool), whose purpose is "breaking the bind/listen API limits + dynamically steering new connections", and it is not a dedicated restart mechanism; **Cilium**'s socket-level LB is east-west service load balancing (rewriting at `connect()`), unrelated to process restart. Detailed below.

**(a) Facebook, "From XDP to Socket: Routing of Packets beyond XDP with BPF" (LPC 2021)**

Source (Chinese translation; the original LPC page was not obtained directly): https://cloud.tencent.com/developer/article/1917092 (translation; the original talk is in the LPC 2021 programme, and the original link arthurchiao.art/blog/facebook-from-xdp-to-socket-zh/ is the translator's note) [translation source; the first-hand slides were not obtained, not re-confirmed]

- The early socket takeover scheme (which they call zero downtime restart): do not wait for the old process to drain; start the new process directly and transfer the old process's TCP listening socket and UDP VIP socket (fd, via SCM_RIGHTS) to the new process over a local socket; the old process keeps serving accepted connections (1~N), the new process takes new connections (N+1~∞), and the old process drains in the background. Advantages: a release loses no capacity and the probability of resetting old connections drops sharply. Defect: UDP (especially QUIC) connection state lives at the application layer, so migrating the kernel socket cannot guarantee consistent routing for existing UDP flows; packets scatter randomly over the old and new processes, forcing a user-space patch that parses QUIC ConnectionIDs and forwards — complex and fragile.
- The new scheme: BPF_PROG_TYPE_SK_REUSEPORT + BPF_MAP_TYPE_REUSEPORT_SOCKARRAY (key = VIP:Port, value = the business process's socket fd). After the new process binds but before it is ready, BPF keeps sending all traffic to the old process; once the application has finished initialisation/health checks it updates the map to trigger the switch; for existing UDP flows a flow→socket mapping keeps routing consistent. Effect: packet loss during a release does not rise noticeably; compared with socket takeover, which loses packets at 3x traffic, the `bpf_sk_reuseport` group loses almost nothing even at 30x traffic with the CPU saturated.
- Kernel pitfalls exposed when landing it: binding the same port with and without SO_REUSEPORT from old and new processes both succeed, triggering long-chain traversal of the kernel bind hash bucket (near linux v5.10 `net/ipv4/inet_connection_sock.c`, fixed after a kernel mailing-list discussion in 2020-06), causing CPU spikes and even host locking at high connection rates.

**(b) Cloudflare sk_lookup + tubular**

Sources: the official blog "Production ready eBPF, or how we fixed the BSD socket API" (Lorenz Bauer, 2022-02-17) https://blog.cloudflare.com/tubular-fixing-the-socket-api-with-ebpf/ ; open source https://github.com/cloudflare/tubular ; kernel documentation https://www.kernel.org/doc/html/latest/bpf/prog_sk_lookup.html

- Motivation: "We've outgrown the BSD sockets API." — services spread over a huge number of IPs, several services share one port (the public recursive resolver and the authoritative DNS both listen on 53), Spectrum must listen on all 2^16 ports, and traditional bind is infeasible.
- Mechanism: the sk_lookup hook is a Cloudflare contribution to the Linux kernel (kernel documentation: "BPF sk_lookup program type was introduced to address setup scenarios where binding sockets to an address with bind() socket call is impractical"); tubular = a BPF program attached to sk_lookup plus user-space Go management code; bindings (match rules, supporting CIDR/port wildcards, LPM trie longest-prefix-first) and sockets are associated by label, deciding which socket each new connection/packet goes to.
- Relation to restart/release: listening addresses can be added and removed online ("you can change the addresses of a service on the fly... it's just an HTTP POST away"); three ways to obtain a business socket: passing the fd via SCM_RIGHTS (needs a process change, abandoned), systemd socket activation, or `pidfd_getfd` to borrow an fd from an external process ("We can use it to iterate all file descriptors of a foreign process, and pick the socket we are interested in."; the example `tubectl register-pid` borrows an fd from the httpd process). tubular's own BPF program can be upgraded atomically through `bpf_link`, "otherwise we may drop connections".
- Production scale: "tubular is in production at Cloudflare today", "tubular runs on thousands of machines".
- Boundary: sk_lookup only takes effect at the socket lookup stage of new connections/packets; already established TCP connections are outside its scope (the original text does not systematically discuss migrating established TCP connections; this is a mechanism inference) [inference, not confirmed in the original text]. The kernel version is not stated in the original text (inferred to be about 5.9+: sk_lookup needs 5.9, bpf_link needs 5.7, pidfd_getfd needs 5.6) [inference].

**(c) Cilium socket-level LB (clarification: not a restart mechanism)**

Source: https://docs.cilium.io/en/latest/overview/intro/ — "East-west load balancing rewrites service connections at the socket level (connect()), avoiding the overhead of per-packet NAT and fully replacing kube-proxy."; the feature first appeared in the Cilium 1.6 release blog (2020/2019-08-20) https://cilium.io/blog/2019/08/20/cilium-16/ . Its BPF programs are attached to hooks such as cgroup connect4/connect6 and rewrite service addresses (east-west load balancing); the public documentation does not describe it as a zero-downtime restart method [the task premise does not match reality; recorded truthfully].

## 3. Conclusions per user-space stack project

### 3.1 Seastar (the ScyllaDB base, share-nothing DPDK mode)

Sources: GitHub README https://github.com/scylladb/seastar ; official tutorial https://raw.githubusercontent.com/scylladb/seastar/master/doc/tutorial.md

- Architecture (original sentences from the tutorial): "Seastar programs use the share-nothing programming model, i.e., the available memory is divided between the cores, each core works on data in its own part of memory, and communication between cores happens via explicit message passing"; "Seastar-based programs run a single thread on each CPU. Each of these threads runs its own event loop, known as the engine"; network stack: "Seastar can use the host operating system's TCP stack, it also provides its own high-performance TCP/IP stack built on top of the task scheduler and the share-nothing architecture"; DPDK: "Seastar comes with its own userspace TCP/IP stack for better performance", "works with a customized version of DPDK" (README).
- nginx or an equivalent HTTP server: no nginx port. It ships an httpd demo component (the README performance section mentions WRK vs httpd) and there are third-party web frameworks (cpv-framework).
- reload/connection migration mechanism: the README and the tutorial contain nothing at all about restart / connection migration / zero downtime [checked as "none", based on a non-exhaustive search of those two official documents]. That is, Seastar provides no framework-level ability to keep connections across a process restart; ScyllaDB's availability comes from the cluster layer (replicas + client driver reconnect + rolling restart), and no first-hand documentation of ScyllaDB rolling restart was obtained in this research [not confirmed; inference only].

### 3.2 mTCP (KAIST, an epoll-compatible user-space stack)

Source: GitHub https://github.com/mtcp-stack/mtcp (README and source tree); header https://raw.githubusercontent.com/mtcp-stack/mtcp/master/mtcp/src/include/mtcp_api.h

- Form: multiple I/O engines — DPDK/netmap/psio/onvm; "mTCP expects a one-to-one RSS queue to CPU binding" (README). The programming model is visible from the header signatures: `mtcp_core_affinitize(int cpu)` plus `mtcp_create_context(int cpu)` returning a per-core mctx, and almost every socket API takes mctx as its first parameter — each thread is bound to a core and holds one stack context (the header has no comments; this is inferred from the signatures).
- Multi-process/fork: the README, Notes, FAQ and api.h contain no statement at all about fork/multi-process support or limits [not found in the official documentation]. Combined with DPDK EAL global initialisation and the global `g_mtcp[]` array (the structure of api.c), it is a reasonable inference that sharing a stack instance across processes after fork is not supported [inference, not confirmed].
- nginx or equivalent: no nginx port; the official ports are lighttpd-1.4.32 (`apps/lighttpd-1.4.32`) and the ab load-test client.
- reload/upgrade mechanism: the README says nothing about reload/graceful; it only has "^C for graceful exit, press twice for forced exit". Conclusion: no such mechanism (at the documentation level) [based only on the README, not re-confirmed].

### 3.3 6WIND Virtual Accelerator (commercial)

Source: official documentation https://doc.6wind.com/new/virtual-accelerator-3/3.4/virtual-accelerator/getting-started/introduction.html (the product page www.6wind.com/virtual-accelerator/ returns 403; the datasheet PDF was not fetched)

- Architecture: the fast path (6WINDGate technology) runs on dedicated cores inside the KVM hypervisor, bypassing and offloading the Linux network stack; "a continuous and transparent synchronization mechanism, so that all Linux configuration is synchronized into the fast path"; the acceleration targets are virtual switching (OVS/Linux Bridge offload), VM traffic (Virtio backend PMD), forwarding/tunnels/IPsec/NAT/QoS, etc.; transparent to applications: "existing Linux applications do not need to be modified to benefit from packet processing acceleration", with standard Linux APIs/tools preserved (iproute2/iptables/ovs-vsctl, etc.).
- nginx: the documentation does not mention nginx; this introduction page does not expand the traffic path details of local host applications such as a web server ("processes all incoming packets from NICs or vNICs"; it does not state how packets are handed back to the kernel stack). The inference is that the model is "local application sockets still belong to the Linux kernel stack, the fast path only accelerates forwarding/VM traffic", so nginx's reload/USR2 semantics are preserved naturally [inference: based on the architecture description of "no application change needed + Linux API preserved"; the local application path details were not re-confirmed]. No first-hand material for a direct "fast path nginx" combination was found (the search came up empty) [not found].

### 3.4 ansyun/dpdk-nginx (an nginx branch on the DPDK user-space stack ANS)

Source: https://github.com/ansyun/dpdk-nginx (README)

- Form: forked from nginx (the README body says 1.9.5 and ABOUT says 1.12.2, the load-test output shows 1.12.2; the body is a historical leftover); links DPDK directly (dpdk-16.07) and the companion user-space stack ANS (the dpdk-ans repository).
- Key capability: "ANS tcp stack support reuseport, so can enable nginx reuseport feature, multi nginx can listen on same port." — the user-space stack implements an SO_REUSEPORT equivalent, scaling horizontally with several independent nginx processes listening on the same port (the performance test runs 4/8/10 nginx instances side by side).
- reload/smooth upgrade: the README does not mention nginx -s reload / signals / hot upgrade at all [checked as none]. There is no evidence that it has a lossless reload.
- Significance: it proves that "a user-space stack implementing a reuseport equivalent + several processes side by side" is feasible on a DPDK stack — the closest precedent of the same kind for F-Stack (only at the connection-distribution level; it contains no drain semantics description).

### 3.5 OpenOnload (AMD/Xilinx Solarflare; a comparison sample: kernel bypass that keeps socket semantics)

Source: https://github.com/Xilinx-CNS/onload (README)

- Positioning: "a high performance user-level network stack, which accelerates TCP and UDP network I/O for applications using the BSD sockets on Linux"; "comprises a user-level shared library that intercepts network-related system calls and implements the protocol stack, and supporting kernel modules"; "Binary compatible with existing applications."
- The sentence most critical for this topic (original README text): "It is compatible with the full system call API, including those aspects that are usually problematic for user-level networking, such as fork(), exec(), passing sockets through Unix domain sockets, and advancing the protocol when the application is not scheduled."
- That is: Onload treats fork/exec/UDS socket passing — the semantics hardest to keep compatible in user-space networking — as compatibility targets, so nginx's master-worker fork model and the fd inheritance semantics of HUP/USR2 are not broken under its model (the README does not discuss nginx reload behaviour directly [not confirmed], but keeping the existing process model compatible is the architectural goal). It is a different species from independent user-space stacks such as F-Stack/Seastar where "the stack is the process", and it represents the "bypass-accelerate but keep kernel socket semantics" route.
- The README has no dedicated section on process restart/hot upgrade [checked as none].

### 3.6 lwIP / PicoTCP

- lwIP: positioned for embedded use (can run bare metal); in web scenarios it ships its own httpd or a CGI demo; no nginx port was found [not seen in the search, not exhaustive]. Source (background): https://gitee.com/alios-things/lwip and others. PicoTCP: likewise nothing nginx-related found [not found]. Both are single-process library forms with no reload mechanism to speak of [common-knowledge level; no first-hand reload documentation to cite].

### 3.7 Current state of F-Stack's official nginx (local archive, for reference by §5)

Source: the local repository `/data/workspace/f-stack/docs/f-stack-issue-ana.md` (issue analysis archive, entries #12 / #528 / #547 / #1036)

- Official conclusion: F-Stack nginx does not support graceful reload out of the box (stated explicitly in `doc/F-Stack_Nginx_APP_Guide.md`); root cause: "under F-Stack's multi-process model, each worker exclusively binds a NIC hardware queue (via RSS); during reload, when the old worker exits before the new worker has finished initializing DPDK/the F-Stack stack, there is a window where no process holds that queue, causing packets to be dropped—unlike native nginx workers, which share..." (#1036 conclusion).
- Multi-process constraint: "exec() is not supported; DPDK resources cannot survive an exec() call. Multi-process operation uses fork() followed by separate ff_init() calls per process." (#12-related conclusion in the archive) → **as of this research baseline (2026-08-18)** the nginx USR2 route was judged dead on this basis (USR2 depends on exec'ing the new binary). **[2026-09-22 sync, A01-4]** That conclusion carries a historical limit: **M5 has landed a self-developed USR2 form** ([00] §3.3 "cross-master generation isolation"; the USR2 branches of `ngx_ff_reload_fsm.h` and `ngx_process_cycle.c` on the nginx side), so "judged dead" applies only to the **original baseline form** and must not be quoted as a conclusion about the current scheme.
- Community precedent: #547 (orange30, confirmed 2021-09-22) "DPDK 18.11 + f-stack-1.20, separating a dedicated receive core (rcv core) from the nginx cores plus dynamic renice priority, achieving zero packet loss on nginx reload", not merged into the official mainline, and incompatible with DPDK 19+ because the timer library changed.
- Also: the LD_PRELOAD mode (libff_syscall.so hooking system calls) is another attach path (`docs/zh_cn/F-Stack_Architecture_Layer1_System_Overview.md`, method 2), detailed in [05 ld_preload alternative route](ld-preload-alternative.md).

## 4. General patterns: the classes of lossless reload in user space and the kernel

Combining the sources above, industry practice falls into six classes (each with a representative and a source):

**P1. Passing the listening fd across processes (fd inheritance / SCM_RIGHTS / retrieval over a domain socket)**

- nginx USR2: inheritance through fork+exec plus an explicit fd list in the NGINX environment variable ([NGINX-CTL]; the official reply in trac #237, verbatim).
- Envoy hot restart: the new process retrieves a copy of the listen sockets from the old process by worker index over a unix domain socket RPC, "no connections are dropped in the accept queues of the draining process" (https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/hot_restart).
- HAProxy: `-x <unix_socket>` "connect to the specified socket and try to retrieve any listening sockets from the old process"; in master-worker mode it uses sockpair@ automatically and needs no `expose-fd listeners` (https://docs.haproxy.org/3.0/management.html).
- Facebook socket takeover: SCM_RIGHTS over a local socket to move the listening fd from the old process to the new one (LPC 2021 translation, see §2.4(a)).
- systemd socket activation: the init system holds the listening fd and passes it to the service process via SCM_RIGHTS (`sd_listen_fds`); nginx does not support this feature officially and considers its internal NGINX environment variable mechanism sufficient (https://trac.nginx.org/nginx/ticket/237, status REOPENED for 14 years).
- Constraint common to all of them: fd passing only solves "no listening gap"; established connections are not migrated — Envoy's original sentence: "existing connections are not transferred to the new Envoy process: they must complete during the drain process or be terminated."; nginx/HAProxy/FB are isomorphic (the old process drains).

**P2. SO_REUSEPORT group (a kernel/user-space-stack equivalent) + old process drain**

- nginx reuseport (see §2.3); HAProxy: "HAProxy works around this on systems that support the SO_REUSEPORT socket options, as it allows the new process to bind without first asking the old one to unbind." (docs.haproxy.org, same as above); Envoy enables `reuse_port` by default.
- User-space-stack equivalent precedent: the ANS stack implements reuseport so that several dpdk-nginx instances share a port (§3.4). Facebook's new scheme is essentially the programmable version of a reuseport group (an `sk_reuseport` program takes over distribution inside the group).
- Shortcomings: hash distribution is not load-aware; backlog connections can be lost at the boundary (acknowledged in the official HAProxy documentation); consistent routing for UDP/QUIC is hard (Facebook's first-hand experience).

**P3. Programmable socket lookup / steering (eBPF: sk_lookup, sk_reuseport)**

- Cloudflare tubular/sk_lookup: new connections are steered dynamically to any socket and listen rules can be changed online (§2.4(b)).
- Facebook sk_reuseport + map: before the new process is ready, BPF keeps sending traffic to the old one, and the application layer triggers the switch explicitly; existing UDP flows use a flow→socket map for consistency (§2.4(a)).
- Essence: the decision "which process takes a new connection" moves from a fixed kernel hash to a user-space programmable map, so releases/restarts can control where new connections go precisely.
- Applies only to the kernel stack (the hooks are on the kernel lookup path); a user-space stack must build an equivalent in its own packet-distribution layer.

**P4. Two-process/two-instance hot standby + traffic switch (no connection migration)**

- Old and new instances run in parallel, new connections switch to the new instance, the old instance drains: Facebook's scheme, HAProxy SIGTTOU pause/resume ("the old process continues to process existing connections"), and HAProxy master-worker reload (SIGUSR2 re-execs itself and `-sf` passes the old worker pids) are all instance-level hot standby.
- Worth noting: within the searched range, **no project was found doing "state migration of established TCP connections / takeover after flow-table synchronisation"** (connection migration only appears for UDP/QUIC as a flow map that "keeps routing to the old process", not as moving state into the new process). So-called zero downtime everywhere = seamless new connections + old connections draining [generalisation over all sources in this report].

**P5. Bypass acceleration that keeps kernel socket semantics (an architectural avoidance)**

- OpenOnload: compatible with the whole set of system-call semantics including fork/exec/UDS fd passing (§3.5), so nginx's existing reload/upgrade mechanism is not broken. 6WIND Virtual Accelerator is the same idea (local applications still use the Linux stack; the fast path only accelerates forwarding/VM traffic, §3.3 [partly inference]).
- This route trades performance ceiling for "zero application change + preserved semantics" (limited by NIC/vendor binding or the acceleration scope).

**P6. Cluster-level fault tolerance (giving up single-machine losslessness)**

- Seastar/ScyllaDB: the framework provides no process-level connection retention; it relies on replicas + client reconnect + rolling restart (§3.1 [no first-hand rolling-restart documentation obtained]). For short-connection businesses such as HTTP this is equivalent to "acceptable"; it does not suit long-connection businesses.

## 5. First applicability judgement for F-Stack

Combining the local archive (§3.7) with the patterns above:

1. A USR2-style binary upgrade (the exec variant of P1) is impossible on the current F-Stack architecture: DPDK resources cannot survive an exec (archive #12 conclusion), and both the old master and the exec'd new master must re-run `ff_init` to bind queues — unless the "stack instance" is decoupled from the "nginx process" (see §4). **[2026-09-17 annotation in place, R-07 same source]** This conclusion targets the mainline architecture **before M5** (no resident primary). **M5 implements a USR2 binary upgrade through "resident slim primary + generation-directory arbitration"** (`ngx_process_cycle.c:495` `ngx_exec_new_binary`, C-NR-501~504, [08](testing-plan.md) RT-04 / RT-04b pass on a real machine): the exec still happens, but DPDK resources belong to the resident primary and do not disappear with the master's exec. **This historical conclusion is kept to preserve audit traceability — do not delete it** (keeping it is exactly what lets a reader see how a later milestone overturned the conclusion).
2. The root cause of packet loss on a HUP-style reload is not the listening fd (in a user-space stack an fd is only a handle) but the window during which the RSS hardware queue has no owner (archive #1036 root cause). Therefore copying P1 (fd passing / SCM_RIGHTS) does not solve the problem, and copying P2 brings limited benefit either — every F-Stack worker is already an independently listening stack instance, so a "reuseport equivalent" exists naturally (new connections enter the queues by RSS hash); what is really missing is "somebody always receiving from the queue during the switch".
   [2026-08-18 addition: convergence with the VPP/VCL line] This judgement independently reaches the same structural conclusion as [01 VPP/VCL Research](vpp-vcl-research.md) §6.2: **decoupling NIC queue / receive ownership from the business process lifetime is the structural precondition for a lossless reload on a user-space stack; the listening fd is a second-order problem.** The VPP/VCL model decouples both levels naturally (data plane: queues belong to the independent VPP process, so the no-owner window does not exist structurally, and #3645 confirms from the opposite direction that packets keep entering VPP and only event synchronisation hangs; control plane: listen belongs to a single app-level object on the VPP side). Corroboration (as relayed by the researcher-vpp-vcl report; not independently verified here): the #1078 primary_slim PoC — 12/12 existing connections with zero interruption after killing the primary — and the centralised design of adapter/syscall. This structural precondition is what directions A/B/C below have in common; direction C and VCL's atfork + app_listener workers bitmap (accept events are not distributed to a new worker until it is registered in the bitmap, isomorphic with Facebook's "do not cut traffic over before ready") belong to the same family of designs.
3. Directions judged most feasible first (argument material for the spec stage, not a conclusion; the final grading is in [06 Solution Design](solution-design.md) §4):
   - **Direction A (P2/P4, the mainstream industry form)**: the old workers keep the queues and existing connections and keep draining; the new workers take over the queues and accept new connections only after finishing initialisation — the difficulty is that under DPDK's exclusive queue model only one process can hold a queue at a time, which is exactly what community scheme #547 (a dedicated receive core + dynamic priority) tried to solve; but that scheme is based on DPDK 18.11, was never merged, and is incompatible with 19+. The current mainline repository uses DPDK 24.11.6, so it must be redesigned (for example an independent dispatcher/receive process holding all queues and distributing to nginx processes by a flow table — formally close to Facebook's "dedicated receive path + flow→process map" (§2.4(a)) and to VPP's worker distribution model).
   - **Direction B (P3)**: introduce a "programmable socket lookup" equivalent into F-Stack's RSS/distribution layer (a map inside the dispatcher process: VIP:Port → nginx instance); before a new instance is ready, traffic keeps going to the old instance, and an explicit action triggers the switch — a user-space port of Facebook's `sk_reuseport` model. UDP/multi-tenant scenarios need a flow consistency table (Facebook's experience).
   - **Direction C (P5, architectural)**: under the LD_PRELOAD adapter mode, if "stack state" and fd semantics can be made further kernel-like/daemon-like (the stack independent of the application process), the reload problem turns into "the daemon does not move, only the application process is replaced" — close to the OpenOnload/VCL (LDP) form; this line crosses with researcher A's VPP/VCL conclusion and is evaluated together at the spec stage.
   - Connection migration (moving TCP state): **no precedent was found within this search range** (P4 conclusion; search cut-off 2026-09; no claim that none exists objectively); it is not recommended as an F-Stack goal. The goal should be defined as "zero loss for new connections + existing connections drain to completion or are served by the old instance until they end naturally".
4. Explicitly not applicable: systemd socket activation (nginx does not support it officially, trac #237); Cilium SocketLB (unrelated to restart, §2.4(c)); pure kernel eBPF hooks (F-Stack's receive path does not go through the kernel).

## 6. Not confirmed / not found list

1. nginx's official description of reload behaviour in reuseport mode — the official documentation has none; archive.org fetches of the original nginx.com blog failed twice with 429; the f5.com archive page now cited has no reload section. The §2.3 reload behaviour is a mechanism inference plus Envoy corroboration.
2. A first-hand quantitative source for nginx reuseport's "uneven distribution of new connections" — not found (the official blog's test says it is even, under short-connection load-test conditions). Only the Envoy documentation confirms "connections may be dropped from accept queues when concurrency decreases", and Facebook confirms the UDP distribution problem.
3. The original Facebook LPC 2021 slides/video — not obtained directly; what is cited is the Tencent Cloud community Chinese translation (with the details cross-read from figures inside the translation), marked "this source only, not re-confirmed".
4. The minimum kernel version 5.9+ for sk_lookup — not stated in Cloudflare's original text; it is a feature inference (bpf_link 5.7, pidfd_getfd 5.6, sk_lookup 5.9).
5. Whether Cloudflare's tubular is actually used for zero-downtime "restart" of nginx-like business processes — the original text only confirms "dynamic management of listening addresses + atomic upgrade of tubular itself + production use for Spectrum/authoritative DNS"; it does not say it is used to restart business processes.
6. 6WIND: the traffic path details for local host applications (the introduction page does not expand them); first-hand material on "running nginx on the fast path" — not found.
7. mTCP: an official statement about fork/multi-process support — none in the README/FAQ/api.h; "single-process multi-thread model" is inferred from the API signatures and the RSS binding description.
8. First-hand documentation that Seastar/ScyllaDB rolling restart depends on client driver reconnect — not obtained (the Seastar README/tutorial do confirm the reverse conclusion that "the framework has no connection migration mechanism").
9. lwIP/PicoTCP having no nginx port — based on nothing found in the search (not exhaustive).
10. The Cilium cilium.io 1.6 blog body was fetched incompletely (the page is a JS framework); the socket LB details follow the original sentence on the docs.cilium.io intro page.
11. The TencentOS user-space stack — not researched separately (F-Stack itself is Tencent's open-source user-space stack and is treated as the same object; TencentOS Server kernel-side optimisations are unrelated to this topic).
