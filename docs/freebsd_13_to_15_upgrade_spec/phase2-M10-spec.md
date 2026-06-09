# Phase-2 M10 Spec — FF_FLOW_IPIP (P1d)

> Chinese version: ./zh_cn/phase2-M10-spec.md (authoritative)

> Status: DRAFT → ready
> Upstream basis: M9 commit `2f4748638`
> Complexity: M (involves dual-side tunnel config + routing)

---

## 1. Goal / Scope

### in-scope

- `lib/Makefile` enables `FF_FLOW_IPIP=1` (alone, not combined with other P1)
- Reuses lib/ff_dpdk_if.c's existing 4 ifdef sites and the already-built in_gif.c / if_gif.c / ng_gif.c
- G1-G3: build + stack-up + create a server-side GIF tunnel via `tools/sbin/ifconfig gif0 create`, configure the peer end with `ip tunnel` on the client, set up routes and run a basic ping test
- Doc sync

### out-of-scope

- ZC / PA combo (M10 builds alone; to avoid cross-variable interference, M7/M8 are temporarily disabled)
- IPv6-over-IPv4 / IPv4-over-IPv6 complex matrix
- iperf heavy-traffic perf (OQ-2 default-allowed downgrade)

---

## 2. Acceptance Criteria

| ID | Criterion |
|---|---|
| AC-M10-1 | `lib/Makefile`: `FF_FLOW_IPIP=1` + temporarily comment out PA/ZC (isolated validation) |
| AC-M10-2 | `lib/ make`: exit=0 / 0 errors / warnings ≤ 60 |
| AC-M10-3 | helloworld primary alive ≥ 12 s, no panic |
| AC-M10-4 | `tools/sbin/ifconfig gif0 create` succeeds (exit=0) |
| AC-M10-5 | After `ifconfig gif0 inet ...` configures the GIF tunnel + route, the client can `ping` the server's GIF inner IP and receive at least 1 ICMP echo reply ✓ (OQ-4 downgrade allowed: if the client's reverse GIF doesn't work, accept G3.5 observation) |
| AC-M10-6 | Doc anchor + execution log |

---

## 3. Risks

| ID | Risk | Mitigation |
|---|---|---|
| R-M10-1 | f-stack-client (Linux) `ip tunnel mode ipip` vs FreeBSD GIF compat | RFC 2003 IPIP is a standard protocol; should interop; if not, downgrade to observation |
| R-M10-2 | tools/sbin/ifconfig may lack GIF clone support | empirically `ifconfig gif0 create` to check; if missing, fall back to `ngctl mkpeer` |

---

## 4. Acceptance Commands

```sh
# G1
cd /data/workspace/f-stack/lib && make clean && make
cd /data/workspace/f-stack/example && /data/workspace/rm_tmp_file.sh ./helloworld* && make

# G2
/data/workspace/rm_tmp_file.sh /var/run/dpdk/rte/{config,fbarray_*,hugepage_info}
sudo ./helloworld -c ../config.ini --proc-type=primary --proc-id=0 &
sleep 12 && [ -d /proc/$PID ] && echo ALIVE

# G3 server side
sudo /data/workspace/f-stack/tools/sbin/ifconfig gif0 create
sudo /data/workspace/f-stack/tools/sbin/ifconfig gif0 tunnel <server_outer> <client_outer>
sudo /data/workspace/f-stack/tools/sbin/ifconfig gif0 inet <server_inner>/30 <client_inner>

# G3 client side (via ssh)
ssh f-stack-client "sudo ip tunnel add gif0 mode ipip remote <server_outer> local <client_outer>"
ssh f-stack-client "sudo ip addr add <client_inner>/30 dev gif0"
ssh f-stack-client "sudo ip link set gif0 up"
ssh f-stack-client "ping -c 3 -W 2 <server_inner>"

/data/workspace/kill_process.sh $PID
```

---

> Next: Phase C — flip the Makefile + build + measure.
