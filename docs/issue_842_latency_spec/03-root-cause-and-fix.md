# 03 - Root Cause Analysis and Fix Plan

## 1. Root Cause Analysis of delayed_ack=1 Causing Connection Failure

### 1.1 Root Cause Mechanism

With `delayed_ack=1`, FreeBSD TCP stack delays ACK by 40ms (`TCPTV_DELACK = MSEC_2_TICKS(40)`, `tcp_timer.h:119`). In large data receive scenarios, this causes TCP receive window exhaustion:

```
Server sends data → Client receives → sets TF_DELACK (delayed ACK 40ms)
→ Client recv() frees buffer → recwin increases
→ tcp_output checks window update, but TF_DELACK is set → window update blocked
→ Within 40ms, receive buffer fills up → recwin=0 → sends zero window ACK
→ Server receives zero window → stops sending → continues window probes
→ Eventually connection timeout or RST
```

### 1.2 Code Evidence

**ACK delay condition** (`freebsd/netinet/tcp_input.c:511-515`):
```c
#define DELAY_ACK(tp, tlen) \
    ((!tcp_timer_active(tp, TT_DELACK) && \
      (tp->t_flags & TF_RXWIN0SENT) == 0) && \
     (tlen <= tp->t_maxseg) && \
     (V_tcp_delack_enabled || (tp->t_flags & TF_NEEDSYN)))
```

**Window update blocked** (`freebsd/netinet/tcp_output.c:655-657`):
```c
if (recwin > 0 && !(tp->t_flags & TF_NEEDSYN) &&
    !(tp->t_flags & TF_DELACK) &&  // ← TF_DELACK blocks window update
    !TCPS_HAVERCVDFIN(tp->t_state)) {
```

**40ms timer** (`freebsd/netinet/tcp_timer.h:119`):
```c
#define TCPTV_DELACK MSEC_2_TICKS(40) // 40ms timeout
```

### 1.3 Why Kernel Is Not Affected

Linux kernel's delayed_ack implementation has these differences:
- Linux delayed_ack delays up to 200ms but has a **quick ACK** mechanism (immediate ACK after receiving first data segment)
- Linux window updates are not blocked by delayed_ack
- Linux has more aggressive window update strategy

## 2. ff_epoll EPOLLOUT Conversion Analysis

### 2.1 Initial Observation

During early investigation, observed ff_epoll sometimes returning EPOLLIN instead of EPOLLOUT after connect completion.

### 2.2 In-depth Testing Conclusion: ff_epoll Conversion Logic Is Correct

After multiple rounds of parameter isolation testing and code tracing, confirmed ff_epoll's EPOLLOUT conversion logic is correct:

- `ff_event_to_epoll()` (`lib/ff_epoll.c:209-248`): EVFILT_WRITE → EPOLLOUT conversion correct
- `ff_epoll_ctl(ADD, EPOLLOUT|EPOLLET)`: correctly enables EVFILT_WRITE, disables EVFILT_READ
- `ff_epoll_ctl(MOD, EPOLLIN|EPOLLET)`: correctly enables EVFILT_READ, disables EVFILT_WRITE

Verification results (consistent across all config combinations):
- EPOLLOUT correctly returned on connect completion (3/3 tests passed)
- EPOLL_CTL_MOD switching from EPOLLOUT to EPOLLIN works correctly
- Full 1 million message test passed (ff_epoll version 9.312s, on par with kernel 9.286s)

The initially observed EPOLLIN issue originated from the test program registering both ff_epoll and kqueue on the same socket (dual registration caused kqueue knote mechanism interference), not a defect in ff_epoll itself. In normal usage (using only ff_epoll or only kqueue), this problem does not occur.

### 2.3 Known Behavior Differences (Not Defects)

kqueue's EV_CLEAR and epoll's EPOLLET are fundamentally different:
- kqueue EV_CLEAR: rechecks condition on each `kern_kevent` call, re-triggers if still satisfied
- epoll EPOLLET: only triggers on state transition (e.g., send buffer from full to non-full)

This does not affect actual usage because users typically switch event masks via `EPOLL_CTL_MOD` after receiving events.

## 3. TX Drain Mechanism Analysis

### 3.1 Mechanism

`lib/ff_dpdk_if.c:2643-2645`:
```c
if (pkt_tx_delay) {
    drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * pkt_tx_delay;
}
```

`lib/ff_dpdk_if.c:2728-2743`:
```c
if (unlikely(diff_tsc >= drain_tsc)) {
    // flush TX batch
    send_burst(qconf, qconf->tx_mbufs[port_id].len, port_id);
    qconf->tx_mbufs[port_id].len = 0;
}
```

With pkt_tx_delay=100, TX data is buffered for up to 100us. A 62-byte GET request waits 100us in the TX buffer before being flushed.

### 3.2 Impact

In the delayed_ack=1 scenario, the TX drain's 100us delay exacerbates the problem: GET request is delayed, server waits longer before starting to send data. But TX drain itself is not the root cause (with pkt_tx_delay=0 but delayed_ack=1, T5 still fails).

## 4. Fix Plan

### 4.1 Configuration Fix (Verified Effective)

Set in `config.ini`'s `[freebsd.sysctl]` section:
```ini
net.inet.tcp.delayed_ack=0
```

Also recommended:
```ini
[dpdk]
idle_sleep=0
pkt_tx_delay=0
```

### 4.2 Code Fix Suggestions (Not in This Round's Scope)

1. **ff_epoll EPOLLOUT fix**: Investigate instability of kqueue notification in F-Stack FreeBSD TCP stack's `soisconnected` call path
2. **delayed_ack default value**: Consider changing F-Stack's `tcp_delack_enabled` default to 0 (F-Stack is a userspace stack; ACK delay is harmful to throughput)
3. **Documentation update**: Clearly document the risk of delayed_ack=1 in large data receive scenarios in config.ini comments

### 4.3 No Code Fix Needed

The core conclusion is **Issue #842 does not reproduce in this environment** (F-Stack matches kernel with optimized config). No lib code modifications needed. The delayed_ack=1 issue is FreeBSD TCP stack's pre-existing behavior (not a bug introduced by F-Stack), solvable through configuration.
