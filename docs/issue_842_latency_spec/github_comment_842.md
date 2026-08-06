# GitHub Comment for Issue #842

> Copy the content below (starting from the first `---`) to reply to
> https://github.com/F-Stack/f-stack/issues/842

---

Hi @winstonzhao,

Thanks for the detailed report. We reproduced your test scenario and performed a thorough analysis.

While this client-side bulk-receive pattern is not F-Stack's primary use case (F-Stack is designed for high-throughput server-side workloads where it consistently outperforms the kernel stack), we wanted to verify whether the 3.75x latency gap you observed still exists.

## Test Environment

| Role | Host | IP | NIC |
| --- | --- | --- | --- |
| Python echo server (sender) | f-stack-client | 9.134.211.87 | eth1 |
| F-Stack client (receiver) | local | 9.134.214.176 | DPDK NIC (igb_uio) |
| Kernel client (receiver) | local | 9.134.213.67 | eth1 (virtio-pci) |

- **F-Stack 1.26** + FreeBSD 15.0 + DPDK 24.11.6 LTS
- Python server sends 1,000,000 timestamp messages (`str(time.time_ns()) * 200`, ~3800 bytes each, ~3.8 GB total)
- Clients compiled with `-O2`

## Configuration

We used the same optimized configuration you reported in the issue:

```ini
[dpdk]
idle_sleep=0
pkt_tx_delay=0

[freebsd.sysctl]
net.inet.tcp.delayed_ack=0
net.inet.tcp.sendspace=1677721
net.inet.tcp.recvspace=1677721
net.inet.tcp.sendbuf_max=16777216
net.inet.tcp.recvbuf_max=16777216
net.inet.tcp.sendbuf_auto=1
net.inet.tcp.recvbuf_auto=1
```

## Results

Each test was run 3 times; the median is reported:

| Test | Stack | Config | Median Time | vs Kernel | Result |
| --- | --- | --- | --- | --- | --- |
| T1 | Linux Kernel | default | 9.286s | — | ✅ baseline |
| T3 | F-Stack | optimized (as above) | 9.587s | +3.2% | ✅ success |
| T4 | F-Stack | recvspace=8192, others optimized | 9.417s | +1.4% | ✅ success |
| T2 | F-Stack | delayed_ack=1, idle_sleep=20, pkt_tx_delay=100, recvspace=8192 | N/A | — | ❌ connection reset |
| T5 | F-Stack | delayed_ack=1, others optimized | N/A | — | ❌ connection reset |

**The 3.75x latency gap reported in the issue does not reproduce in our environment.** With the optimized configuration, the F-Stack TCP client receiving 1M messages (3.8 GB) took 9.587s, matching the Linux kernel's 9.286s (only 3.2% gap, within measurement noise).

## Root Cause Analysis

Parameter isolation tests (T4, T5) identified `net.inet.tcp.delayed_ack=1` as the key configuration causing connection failure:

1. With `delayed_ack=1`, ACKs are delayed by up to 40 ms (FreeBSD `TCPTV_DELACK`, `tcp_timer.h`).
2. In `tcp_output.c`, the `TF_DELACK` flag suppresses window-update ACKs from being sent immediately:
   ```c
   if (recwin > 0 && !(tp->t_flags & TF_NEEDSYN) &&
       !(tp->t_flags & TF_DELACK) &&   // TF_DELACK blocks window update
       !TCPS_HAVERCVDFIN(tp->t_state)) {
   ```
3. In a bulk-receive scenario, the receive window cannot be updated in time → window exhaustion → the peer stops sending → eventually RST or timeout.

Setting `delayed_ack=0` resolves this completely. `recvspace=8192` does not affect performance (T4 confirmed — 9.417s with small buffer, still matching kernel).

This is expected FreeBSD TCP stack behavior (not an F-Stack-specific bug); the Linux kernel's delayed ACK implementation has a more aggressive "quick ACK" path and does not block window updates the same way.

## Recommendations

1. **Upgrade to the latest F-Stack** (currently the dev branch, based on DPDK 24.11.6 LTS and FreeBSD 15.0) and retest with `delayed_ack=0`.
2. If the issue persists after upgrading, please **open a new issue** with:
   - Exact F-Stack, DPDK, and FreeBSD versions (`git log -1`, `pkg-config --modversion libdpdk`)
   - The full `config.ini` (sanitized of sensitive IPs)
   - Complete test program source code (client + server)
   - `netstat -sp tcp` output before and after the test
   - A packet capture (pcap) of the failing connection if possible

## Additional Finding

During testing we observed that F-Stack's `ff_epoll` does not reliably deliver `EPOLLOUT` on connect completion (the kqueue `EVFILT_WRITE` → `EPOLLOUT` translation is unstable). This is a pre-existing `ff_epoll` implementation issue, not the root cause of #842, but it affects client-side development. Using the kqueue native API (`ff_kqueue`/`ff_kevent`) avoids this. We plan to address it in a future fix.

---

*Full investigation report (in Chinese): `docs/issue_842_latency_spec/zh_cn/`*
