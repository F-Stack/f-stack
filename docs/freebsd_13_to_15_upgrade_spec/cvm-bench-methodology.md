# F-Stack CVM Two-Machine Benchmark Methodology

> Chinese version: `./zh_cn/cvm-bench-methodology.md`
>
> Source: abstracted and unified from five cross-application measurements — §12.10 (helloworld) / §12.12 (helloworld_epoll) / §12.13 (nginx) / §12.14 (redis) / §12.15 (nginx multi-process).
>
> Companion diagram: `cvm-bench-methodology.svg` (physical topology + operational swimlane timeline).

---

## 0. One-line summary

**Two CVMs; the server side runs DPDK + F-Stack** — the server-side F-Stack app pins lcores and owns the data-plane NIC. **The client-side stack is selectable**: kernel TCP/IP or F-Stack adapter, depending on test purpose. Within the same time window, the server is launched with the 13.0 baseline binary first and then the 15.0 runtime-fix binary, for an A/B compare. All client-side commands are dispatched **by the AI AGENT (co-located on the server)** over ssh; stdout flows back through the ssh tunnel to the AI AGENT and is IP-masked by a `sed` pipe before landing on disk.

---

## 1. Physical topology

| Role | Real IP (D-segment kept only) | Masked in docs | Hardware / software stack |
|---|---|---|---|
| server data-plane | `x.x.x.176` | `192.168.1.1` | Server CVM 16 vCPU AMD EPYC 7K62 elastic NIC, taken over by DPDK PMD → F-Stack stack |
| server control-plane | `x.x.x.87` | `192.168.1.3` | Server's second NIC (NOT taken over by DPDK; remains on kernel); the AI AGENT uses this IP to ssh to the client |
| client | `x.x.x.67` | `192.168.1.2` | CVM, virtio_net, runs sshd + wrk / curl / redis-benchmark |

**Control-plane vs data-plane separation** (dual-NIC, single-card architecture):

- Control plane (out-of-band): AI AGENT (local) ── ssh ──> server control NIC (`x.x.x.87`) ──> client (`x.x.x.67`) sshd
- Data plane (in-band): client injection tool ──> server data NIC (`x.x.x.176`, DPDK PMD) ──> F-Stack stack

The server data NIC must be owned by the DPDK PMD (kernel no longer holds the IPv4 path); the server control NIC must remain with the kernel, otherwise the AI AGENT cannot ssh to the client.

**Client stack — pick one of two**:

| Option | Path | Use case | Deployment cost |
|---|---|---|---|
| A | Linux kernel TCP/IP (default) | Press server only; do not care about client bypass | Lowest, client NIC stays with kernel |
| B | F-Stack adapter (`fstack-client`) | Both ends bypassed; mirror production; eliminate kernel-network jitter | Requires client NIC also taken over by DPDK |

The stack choice does not affect the relative A/B delta but the absolute throughput differs.

**The two planes do not interfere**: ssh always goes through the kernel path (server side via the control NIC `x.x.x.87`; client side, regardless of whether F-Stack bypass is enabled, ssh stays on the kernel); the benchmark data plane uses the chosen stack and is physically isolated from ssh on a different NIC channel.

---

## 2. Dual-tree A/B switch convention

| Tree | Path | Purpose |
|---|---|---|
| 15.0 rfix | `/data/workspace/f-stack/` | Main dev tree (runtime-fix) |
| 13.0 baseline | `/data/workspace/f-stack-13.0-baseline/` | Historical baseline |

Each tree builds its own `lib/libfstack.a` and app binaries (`helloworld` / `nginx_fstack_{15rfix,13baseline}` / `redis_fstack_{15rfix,13baseline}` etc.); switching the link target via the `FF_PATH` env var avoids cross-overwrite.

---

## 3. Standard procedure (10 steps)

### ① Build both trees

```
make -C /data/workspace/f-stack/lib
make -C /data/workspace/f-stack-13.0-baseline/lib
```

Two independent `libfstack.a` produced.

### ② Build app twice

For each app under test (helloworld / nginx / redis), build with each tree's `FF_PATH` and install to a separate prefix:

```
/usr/local/nginx_fstack_15rfix/    /usr/local/nginx_fstack_13baseline/
/usr/local/redis_fstack_15rfix/    /usr/local/redis_fstack_13baseline/
```

For nginx and redis (constrained by the chmod convention), **do NOT run `make install`** (it internally uses `install -m`); instead, do `mkdir -p + cp -p` manually.

### ③ Server start (one of the two trees)

```bash
cd /data/workspace/f-stack/example   # or /usr/local/<app>/sbin/
nohup ./<app> --conf <config.ini> --proc-type=primary >/tmp/<app>.log 2>&1 &
disown
```

- `nohup` + `disown`: detach from terminal; defend against SIGHUP.
- `--proc-type=primary`: primary identity; DPDK requests hugepages and initializes `rtemap_*`.
- Multi-process mode: in `config.ini` set `lcore_mask` to multi-bit (`0x30` = 2 workers, `0xf0` = 4 workers); `worker_processes` in `nginx.conf` must equal `popcount(lcore_mask)`; F-Stack auto-derives `nb_procs / proc_id / proc_mask`.

### ④ Smoke probe (AI AGENT dispatches via ssh; client executes)

All client-side commands are triggered by the server-co-located AI AGENT through the ssh channel; stdout flows back through the ssh tunnel and is written to server-local `/tmp/<app>-bench/`:

| App | AI-AGENT command |
|---|---|
| helloworld | `ssh client "wrk -t2 -c10 -d5s http://192.168.1.1/" \| sed ...` |
| nginx_fstack | `ssh client 'for i in {1..10}; do curl -o /dev/null -s -w "%{http_code}\n" http://192.168.1.1/; done' \| sed ...` (expect 10× 200) |
| redis_fstack | `ssh client "redis-cli -h 192.168.1.1 PING; redis-cli -h 192.168.1.1 SET smoke ..." \| sed ...` ⇒ `PONG` / `OK` |

Smoke must succeed before formal benchmark — to rule out server start failure / unready listener / stack abnormality.

### ⑤ Benchmark T1 / T2 / T3 (AI AGENT via ssh)

| Tier | wrk parameters | redis-benchmark equivalent | Purpose |
|---|---|---|---|
| T1 | `-t2 -c10 -d5s` | `-c 10 -n 50000 --threads 2 -t ping,set,get` | Light load + cold-start filtering |
| T2 | `-t4 -c100 -d30s` | `-c 50 -n 500000 --threads 4 -t ping,set,get` | Main regression verdict |
| T3 | `-t8 -c500 -d30s` | `-c 200 -n 1000000 --threads 8 -P 16 -t set,get` | Tail-latency-sensitive |

Dispatch template:

```bash
ssh client "wrk -t4 -c100 -d30s http://192.168.1.1/" \
  | sed -e ...IP mask... \
  > /tmp/<app>-bench/wrk.txt
```

The multi-process functional verification (§12.15) only runs T2 because the goal is "feature OK" rather than scaling.

### ⑥ Source-side IP masking (sed before AI-AGENT writes to disk)

The stdout returned over ssh is masked by an AI-AGENT sed pipe before being written to artifacts (**real IPs only appear inside the ssh tunnel; never landed on disk**):

```
| sed -e 's/x\.x\.x\.176/192.168.1.1/g' \
      -e 's/x\.x\.x\.67/192.168.1.2/g' \
      -e 's/x\.x\.x\.87/192.168.1.3/g' \
      -e 's/:<actual ssh port>/:22/g'
```

> The `x.x.x.176` notation here means the real A/B/C segments are masked while the D segment is retained; in the actual command this needs to be substituted with the real regex.
> `perf.data` binaries are not modified (low information density, not human-readable; minimal external-leak risk).

### ⑦ Terminate the server master

```
/data/workspace/kill_process.sh <master_pid>
```

**Never** call `kill` / `pkill` / `killall` directly. In multi-process mode only kill the master; secondary workers exit on their own once they receive the master-exit signal. Verify with `pgrep -af 'nginx: worker'` or `pstree -p <master_pid>`.

### ⑧ Clear leftover rtemap

```
ls /dev/hugepages/rtemap_* | xargs /data/workspace/rm_tmp_file.sh
```

After the DPDK primary exits, hugepages are not auto-released — they must be trashed. Skipping this causes "Cannot get hugepage information" on the next start.

### ⑨ Switch to the other tree

Return to ③, restart the server with the other binary, and repeat ④⑤⑥⑦⑧. Complete both A/B rounds **within the same time window**, to maximally suppress baseline drift from CPU neighbours / network jitter / clock skew.

### ⑩ Document landing + config restore

- Paste the masked wrk / curl / redis-benchmark output into the matching §12.x of `runtime-fix-execution-log.md`: tabular comparison + timeline + key findings + artifact list + compliance audit.
- Any `*.conf` modified by a temporary sed must be restored from `*.bak_1proc` (especially important in multi-process tests; otherwise the next server start would use the wrong `lcore_mask`).
- `git commit` uses an English message; **do NOT push** (per the project's long-term convention).

---

## 4. Artifact convention

| Path | Content | Retention |
|---|---|---|
| `/tmp/<app>-bench/curl_x10.txt` | 10 curl HTTP codes | per-test |
| `/tmp/<app>-bench/wrk.txt` | 30s wrk output (already IP-masked) | per-test |
| `/tmp/<app>-bench/T{1,2,3}.txt` | redis-benchmark three-tier output | per-test |
| `/tmp/<app>-bench/<app>_stdout.log` | Server stdout (DPDK init / abnormality) | per-test |
| `/usr/local/<app>_fstack_*/` | Two-version app install dirs | persistent |
| `*.bak_1proc` | Config restore backup | persistent |
| `runtime-fix-execution-log.md §12.x` | Experiment record (canonical) | persistent (git) |

---

## 5. Cross-application result overview (13 → 15, same env, same `lcore=4`)

| App | Model | T2 Δ% | T3 Δ% | Note |
|---|---|---|---|---|
| helloworld | kqueue blocking | -7.59% | -9.37% | **Significant regression** |
| helloworld_epoll | epoll(LT) event loop | (smoke OK) | (single tier) | Functional verification only |
| nginx_fstack | epoll event loop | -1.05% | -0.55% | Flat |
| redis_fstack | ae (custom) + pipeline | +0.10% ~ +5.37% | ≈0% | **No regression, even slight gain** |

Conclusion: the negative side of the 13→15 vendor evolution path (`tcp_default_output` vtable wrapper / CUBIC upgrade / socket-buffer locking refactor / `ether_nh_input` pipeline) is effectively absorbed by event-driven app models; redis's ae + pipeline further amortizes the overhead into batches and shows the strongest immunity to regression.

---

## 6. Pre-execution checklist

- [ ] Are both trees' lib up to date (`ls -la lib/libfstack.a` mtime compare)?
- [ ] Did the app produce two binaries (different sizes ⇒ different lib linked)?
- [ ] Is `/dev/hugepages/` clean before start?
- [ ] Does `config.ini` `lcore_mask` match the multi-process scenario?
- [ ] Does AI AGENT have key-less ssh to client (`ssh client true` returns within 1 s)?
- [ ] Confirmed client-side stack option (kernel default / F-Stack adapter requires `fstack-client` pre-installed)?
- [ ] Is the sed IP-mask pipe wired into every ssh-stdout landing path (zero risk of real IP leaking into artifacts)?
- [ ] After killing the master, have all workers exited (`pgrep`)?
- [ ] Has rtemap been cleaned (`ls /dev/hugepages/`)?
- [ ] Has the temp-sed-modified `.conf` been restored from `.bak`?
- [ ] Is the commit message English-only and unpushed?
