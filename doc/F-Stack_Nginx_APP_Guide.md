# F-Stack Nginx APP Guide

F-Stack is an open source network framework based on DPDK. F-Stack supports standard Nginx as HTTP framework which means all web application based on HTTP can easily use F-Stack.

## How does Nginx use F-Stack?

  Nginx APP is in `app/nginx-1.28.0` directory.

```

                                                        +--------+
                         +------------------------+     |
                            channel: socketpair         |
                         +------------------------+     |  signal(reload, quit..)
                                                        |
                                                        |
                                              +---------v--------+
                                              |                  |
                             +----------------+  master process  +---------------+
                             |                |                  |               |
                             |  channel       +----------+-------+               |
                             |                           |              channel  |
                             |                  channel  |                       |
                             |                           |                       |
                   +---------+----------+     +----------+--------+    +---------+--------+
first one to start |                    |     |                   |    |                  |
 last one to exit<-+   primary worker   |     |  secondary worker |    | secondary worker |
                   |                    |     |                   |    |                  |
                   +--------------------+     +-------------------+    +------------------+
                   +--------------------+     +-------------------+  
                   |                    |     |                   |
                   |   fstack,kernel    |     |   fstack,kernel   |
                   |     and channel    |     |     and channel   |
                   |     loop thread    |     |     loop thread   |
                   |                    |     |			  |
                   +--------------------+     +-------------------+
                    woker process cycle        woker process cycle

```

- spawn primary worker firstly, and then wait for primary startup, continue to spawn secondary workers.

- a major addition to the worker process is fstack-handling：ff_init();ff_run(worker_process_cycle); worker_process_cycle(handle channel/host/fstack event).

- with `graceful_reload=1` the topology changes: a resident slim primary (a DPDK primary with no rx/tx queue) is spawned at startup and survives reloads/upgrades, and every nginx worker attaches as a DPDK secondary. See "Graceful reload" below.

## What's Different?
### New directives:
All the directives below are available only when ```NGX_HAVE_FSTACK``` is defined.
```
    Syntax: kernel_network_stack on | off;
    Default: kernel_network_stack off;
    Context: http, server, stream, mail

    Determines whether the listening socket of this server should run on the
    kernel network stack or on fstack. The listening socket is opened by the
    master with a plain socket() and inherited by every worker generation;
    the connection is then driven by nginx's internal host epoll.
```

```
    Syntax: proxy_kernel_network_stack on | off;
    Default: proxy_kernel_network_stack off;
    Context: http, server, location (http proxy); stream, server (stream proxy)

    Determines whether the proxied (upstream) connection should go through
    kernel network stack or fstack. It affects the upstream connection only,
    not the listener. This directive is not available in the mail module.
```

```
    Syntax: schedule_timeout time;
    Default: schedule_timeout 30ms;
    Context: main

    Sets a time interval for polling kernel_network_stack. The default value is 30 msec.
```

Note on scope: these two directives are implemented by nginx itself (an internal host epoll plus a `socket()` override that adds `SOCK_FSTACK` for F-Stack sockets). They are **not** the library's stack-coexist mechanism (`[stack] kernel_coexist` in the F-Stack config file plus the `FF_KERNEL_COEXIST` build flag, which serves native `ff_api` applications). The nginx directives work with a default build and are not affected by that flag or config key. See "Mixed mode" below for the operational limits of running part of the traffic on the kernel stack.

### Command-line `reload`
With the default `graceful_reload=0`, the `reload` is not graceful: service will still be unavailable (about one second) during the process of reloading.

With `graceful_reload=1`, the `reload` is lossless: the new generation of workers spawns and reaches READY while the old generation keeps serving, rx ownership then flips to the new generation, and the old generation drains its established connections to natural completion. See "Graceful reload" below.

### Necessary modifies in nginx.conf:
```
    user  root; # root account is necessary.
    fstack_conf f-stack.conf;  # path of f-stack configuration file, default: $NGX_PREFIX/conf/f-stack.conf.
    worker_processes  1; # graceful_reload=0: equal to the lcore count of `dpdk.lcore_mask` in f-stack.conf;
                         # graceful_reload=1: one less than the lcore count (the resident slim primary owns one lcore,
                         #                     and worker_processes = nb_procs - 1).

    events {
        worker_connections  102400; # increase
        use kqueue; # use kqueue
    }

    sendfile off; # sendfile off
```

Optional: `worker_shutdown_timeout` (e.g. `worker_shutdown_timeout 30s;`) bounds the drain window of old workers during a graceful reload; when unset, internal 30s caps apply (see "Forced-exit cap" below).

## Graceful reload (`graceful_reload`)

### Overview and deployment form

The nginx APP supports lossless reload and binary upgrade via `graceful_reload` in the `[dpdk]` section of the F-Stack config file (`fstack_conf`).

- `graceful_reload=0` (default): behavior identical to previous releases. Worker 0 is the DPDK primary; `reload` follows the legacy two-phase serial order (old workers exit before new workers start) with about one second of service unavailability.
- `graceful_reload=1`: lossless reload and lossless binary upgrade. Requires `primary_slim=1`, `nb_procs >= 2` (set nginx `worker_processes = nb_procs - 1`) and `thread_mode=0`.

With `graceful_reload=1`:

- The nginx master spawns a **resident slim primary** at startup: a DPDK primary with no rx/tx queue (`--proc-type=primary --proc-id=0` + `primary_slim=1`) that runs the control plane only (device init, IPC server, KNI init). It is double-forked and detached from the master lifecycle: `reload`/`upgrade` never signal it, and it survives master exit. It is detected via `/var/run/ff_slim_primary.pid` (diagnostics go to `/var/run/ff_slim_primary.log`); run the master as root or make `/var/run` writable.
- All nginx workers attach as DPDK **secondaries**: worker `i` runs F-Stack `proc_id = i + 1` because the slim primary owns `proc_id 0`. Accordingly set `dpdk.lcore_mask` to `worker_processes + 1` bits and exclude the primary lcore from every `[portN] lcore_list`. The master validates the topology before spawning workers: the `dpdk.lcore_mask` bit count must equal `worker_processes + 1` exactly (too many lcores leave queues with no consumer — a silent RSS black hole; too few make worker attach fail with proc_id out of range).
- The master waits up to 60s for the slim primary to become ready (the primary_slim baseline reports measured ~25s for EAL + port init) and up to 60s for worker 0 to confirm its secondary attach; the legacy 15s primary-worker gate stays unchanged when `graceful_reload=0`.
- The queue/lcore mapping is **generation-agnostic**: during a reload the new worker of a slot uses the same lcore and rx queue as the old one, so no lcore or queue configuration changes across generations. RX queue ownership flips from the old generation to the new one at handover.
- **Generational mempools** (`mbuf_pool_<n>_gen0/gen1`) are pre-built at init and ping-pong reused, so the two generations coexisting on the same lcore never share packet buffers.
- On `reload` (HUP): the new generation of workers is spawned and reaches READY **while the old generation keeps serving**; rx ownership then flips to the new generation (handover) and the old generation drains its established connections before exiting. Established connections run to natural completion — packets arriving on a queue already owned by the new generation are forwarded between the generations over per-generation drain rings. A HUP issued while a round is in flight is rejected (`graceful reload rejected: previous reload still in progress`).
- On `upgrade` (USR2): traffic switches on WINCH, and USR2 itself moves no hardware ownership, so a failed new binary costs nothing. See "Binary upgrade (USR2/WINCH)" below.

### Reload observability (log lines)

Each reload round is driven by an explicit T0-T5 state machine; every transition is logged at NOTICE level in the nginx error log:

- `graceful reload: spawning new generation <N> (epoch <E>)` — round starts (T0 -> T1).
- `graceful reload: new generation ready (<N> workers), old generation draining` — all new workers READY (T1 -> T2).
- `graceful reload fsm: <S1> -> <S2> (transition <n>, elapsed <M> ms)` — one line per FSM transition; a normal round shows six (T0_IDLE -> T1_GNEW_SPAWN -> T2_HANDOVER -> T3_DRAIN -> T4_DRAIN_DONE -> T5_GOLD_QUIT -> T0_IDLE).
- `graceful reload: old generation drained, quitting` — drain complete (T3 -> T4); ` (deadline forced)` is appended when the `worker_shutdown_timeout` deadline forced completion.
- `graceful reload complete: generation <N> now active (took <M> ms: handover <M> ms, drain <M> ms, drain forwarded <N> / relayed <N> pkts, ring peak rx <N> / tx <N>)` — round complete (T5 -> T0). Fields: total wall time, handover phase, drain phase, packets forwarded to / relayed from the old generation over the drain rings, and the drain ring peak occupancy (see below).
- After each round the workers log the steady state in the F-Stack log: `reload data plane retired (steady state, generation <N>)`.

Failure paths — the old generation is never touched by an abort:

- `graceful reload rejected: previous reload still in progress (state <S>)` / `graceful reload rejected: binary upgrade in progress` — re-entry protection.
- `graceful reload aborted: <reason> (old generation untouched)` — e.g. `READY wait timed out`, `worker 0 failed to attach to the resident primary`, `G_old park confirmation timed out`, `rx ownership flip failed`; the FSM goes T_ERROR and back to T0_IDLE.
- If the old generation hangs in drain: `graceful reload: G_old drain exceeds <M> ms, QUIT re-delivered by signal (channel suspected lost)`, then `graceful reload: G_old drain exceeds <M> ms, SIGTERM escalation (open connections will be reset)`.

### drain_ring watermark and full-ring alerts

While the old generation drains, packets of its connections are forwarded between the two generations over per-generation drain rings:

- `drain_ring_size` (default 2048; must be a power of two; values below 1024 draw a warning) sets the capacity of one generation's drain ring pair. Raising it reserves `nb_rx_queue * 2 (generations) * 2 (directions) * drain_ring_size` additional mbufs in each of the two mbuf pool budgets — check memory headroom before increasing.
- A full drain ring drops the packet and logs a rate-limited WARNING (at most one line per second and per direction):
  `graceful reload drain: drain_tx full (<n>/<cap> entries, <drops> dropped): packet dropped, TCP retransmits recover`
  (and the `drain_rx` counterpart). A drop here is recovered end-to-end by TCP retransmission — the alert indicates latency/retransmission pressure during the drain, not permanent data loss for TCP traffic.
- The peak occupancy is reported in the `ring peak rx <N> / tx <M>` field of the `graceful reload complete` line; full-ring events always show up there. If the peak is persistently close to the capacity, increase `drain_ring_size` for the site. With the default 2048 the measured peak stayed below 1.2% of capacity in testing (12 active streams, ~66k relayed packets per reload).

### Resident primary failure (degradation and recovery)

The resident slim primary holds no rx/tx queue, so its death does **not** interrupt the data plane: the workers (DPDK secondaries) keep serving (verified with active streams, zero failures). Notes:

- The slim primary is not respawned automatically.
- A reload issued while the primary is dead may still complete if the DPDK runtime files under `/var/run/dpdk/rte/` are intact (new workers attach to the leftover mappings). If they are gone, new workers fail to attach and the master aborts the round after the 60s attach gate — the old generation keeps serving (fail-safe).
- Recovery: fully restart nginx (stop, then start). The master spawns a fresh slim primary when `/var/run/ff_slim_primary.pid` no longer points to a live process.

### New generation crash after handover (heartbeat takeover)

After the handover the old generation has already detached from the hardware. If the new generation stalls or crashes:

- The rx-owner generation advances a shared-memory heartbeat counter once per loop pass; the old generation samples it. A stall longer than `reload_heartbeat_timeout_ms` (default 1000 ms; `0` falls back to the default) makes the old generation autonomously reclaim rx and keep serving. The takeover is logged in the F-Stack log: `reload rx owner stalled >%ums: generation %d taking rx back` (ALERT); a deferred variant (`reload heartbeat stalled >%ums, generation %d (rx return deferred: park order pending or not detached from hardware)`, WARNING) covers stalls where the old generation cannot yet return to the hardware.
- Tuning: the default 1s balances failover speed against false positives; a smaller value fails over faster but may trigger on transient stalls.
- Residual case: if **both** generations are gone, only the resident primary remains and nothing polls the NIC — a full outage requiring an external restart of nginx.

### Forced-exit cap (`worker_shutdown_timeout`)

`worker_shutdown_timeout` bounds how long an old worker may drain: when set, drain completion is forced at the deadline (`old generation drained (deadline forced)`). Independently, two internal safety caps (the `snd_pending` wait and the delayed listening-socket close) apply at `max(30s, worker_shutdown_timeout)`; hitting one logs e.g. `ff drain: listen close capped at <N> ms (quit+<M> ms, syncache=<n>, snd_pending=<n>)` or `ff drain: snd_pending wait capped at <N> ms (...)`. With `worker_shutdown_timeout` unset or <= 30s the caps are 30s (the previous fixed behavior).

### Binary upgrade (USR2/WINCH)

Standard procedure (all signals go to the old master's pid):

1. Build the new binary against the same `libfstack` as the running one (rebuild both binaries together; mixing binaries from different lib builds is not supported).
2. `kill -USR2 <old master>`: the new master starts, reuses the resident slim primary and forks all-secondary workers. The old generation keeps serving; USR2 moves no hardware ownership.
3. Confirm the new generation is up: the new master's worker processes exist, and the F-Stack log of the new workers shows `generation directory attached: epoch <N> slot <S> pid <PID>` with an epoch different from the old generation's (slot in 1..3). Note this line appears at the very beginning of the worker init and is **not** a readiness marker — confirm the workers finished initialization (steady-state log lines / listening sockets up) and keep a safety margin before the next step.
4. `kill -WINCH <old master>`: rx is handed to the new binary — `ff usr2: handed rx to the new binary (epoch <N> gen <G>), old generation draining` — and the old workers drain their established connections (same drain machinery as a HUP reload).
5. `kill -QUIT <old master>` after the drain to finish the upgrade.

Behavior notes:

- WINCH issued before the new generation registered is deferred (`ff usr2: WINCH before the new generation registered, deferring (old workers keep serving)`); a new binary that never registers times out after 120s.
- A new binary that dies before taking over is free of impact: `ff usr2: new binary exited before taking over, old generation keeps serving`.
- Rollback: `kill -HUP <old master>` during an upgrade is interpreted as a rollback (`ff usr2: HUP during a binary upgrade, rolling back`); if the new master dies after the handover, the old generation reclaims rx automatically (`ff usr2: new binary (epoch <N>) is gone, taking rx back`, `ff usr2: rx owner reset to generation <G>, old generation serving again`).
- There is no automatic traffic switch on USR2: the switch happens on WINCH, issued by the operator or automation once the new generation is confirmed ready.

### Mixed mode: some servers on the kernel stack

With `kernel_network_stack on` (listener side) and/or `proxy_kernel_network_stack on` (upstream side), one nginx instance serves part of its traffic from the Linux kernel stack while the rest runs on F-Stack. Operational notes measured on a `graceful_reload=1` deployment:

- **Idle kernel-stack connections are dropped when the old generation exits.** The drain completion test is F-Stack specific (`ff_socket_snd_pending()` / `ff_syncache_count()` plus `worker_shutdown_timeout`); kernel-stack connections are not counted in it. An old generation that only holds **idle** keepalive connections on a `kernel_network_stack on` server therefore finishes draining immediately (drain ~1s) and `ngx_close_idle_connections()` closes them, at the same moment the old generation logs `exiting`. **Active** connections are not affected: in measurements, streams in flight (including proxied upstream connections that live on the kernel stack) ran to natural completion with zero errors, and the old generation stayed until they ended. Long-lived **idle** connections on a mixed-mode server are consequently not protected by the drain window — expect reconnects at reload time, or keep that traffic on F-Stack listeners.
- **Kernel-stack listeners themselves survive the reload.** The listening socket is opened by the master and inherited by every generation, so its socket inode does not change across a reload and new connections are accepted throughout.
- Polling granularity for the mixed event loop is `schedule_timeout` (main context, default 30ms). Lowering it reduces the response latency of kernel-stack connections at the cost of more loop passes.

### KNI notes (graceful_reload + `[kni]` enable=1)

- The kernel-side exception interface is a virtio_user paired port named `veth<port_id>` (rte_kni.ko is no longer supported). It survives reloads, and KNI ownership follows the generation directory across generations and masters. Set `owner_proc_id` to a secondary proc_id whose lcore is in the port's `lcore_list`.
- **Addressing warning**: the kernel-side `veth<port_id>` address must be a `/32` (or live in a dedicated subnet). Configuring it with the same subnet mask as another interface of the host (e.g. the management NIC) adds a second connected route and hijacks the host's return traffic (observed: ssh sessions broken).
- Known limitation: on clouds whose fabric only delivers platform-assigned IPs, management-plane reachability of a self-chosen KNI address from external clients cannot be validated (proxy ARP answers, but the packets never reach the NIC). The KNI data plane itself (divert-to-kernel and inject-from-kernel) is verified bidirectionally across reloads on such environments.
- **Do not use ICMP as the control probe when testing KNI reachability, and do not ping from the server itself.** With `method=reject`, ICMP is not in the `tcp_port`/`udp_port` whitelist, so it is diverted to the kernel — which does not own the F-Stack IP and silently drops it. A perfectly healthy stack is then reported as unreachable. Use an HTTP/TCP probe against a whitelisted port instead (e.g. `curl -o /dev/null -w '%{http_code}' http://<DPDK_NIC_IP>/` == 200).
- Likewise, a management-plane ping must be issued **from a remote client**, not from the server: the server-local ping to its own `veth<port_id>` address is answered by the host route and never leaves the host or traverses KNI, so it is always "ok" and says nothing about KNI. Judge the result in three states: `ok` (client ping answered), `LIMITED` (KNI address unreachable while the control address answers — the environment cannot deliver the address, the criterion is not judged rather than failed), `DOWN` (neither answers — a real failure).

### Tools: addressing a generation (`-p` / `-g`)

The `ff_*` tools (`ff_netstat`, `ff_sysctl`, `ff_traffic`, ...) accept:

- `-p <proc_id>[:<gen>[:<epoch>]]`
- `-g <gen>[:<epoch>]`

The recommended path is to omit both: the tool auto-probes the resident primary for the currently active `(epoch, gen)` and addresses the serving generation — this works through reloads and through the dual-master USR2 window. Explicit coordinates are only needed to address a non-active generation (e.g. the draining old one); take the epoch from the `generation directory attached: epoch <N> slot <S>` line of the target's F-Stack log. There is no silent fallback: if the probe fails or a coordinate is malformed, the tool refuses with an explicit error.

## Nginx compiling
	./configure --prefix=/usr/local/nginx_fstack --with-ff_module
	make
	make install

Optional modules used by the F-Stack test setup: `--with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_v2_module`. For binary upgrades (USR2) both the old and the new binary must be built against the same libfstack.

