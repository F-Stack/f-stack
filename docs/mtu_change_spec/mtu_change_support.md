F-Stack 2.0 Preview 7: MTU Change Support — Breaking the 1500 Hard Limit for 9000 Jumbo Frames, and the Two Pitfalls Along the Way

1. What this feature does and its key characteristics

F-Stack's DPDK-controlled NIC was previously locked at MTU 1500. This project turned the status quo — "decreasing MTU works, increasing MTU (jumbo frames) is completely unsupported" — into full support: set any MTU between 1500 and 9000 at startup via configuration, change it at runtime through the standard SIOCSIFMTU ioctl, with the protocol stack and DPDK hardware kept in sync.

The pre-change baseline looked like this. A conclusive research was done in mid-July 2026 (see `docs/mtu_change_spec/zh_cn/00~15`); the three-way cross-verified conclusion was "partial support":

- Decreasing MTU (≤1500): works out of the box. `ff_ioctl(SIOCSIFMTU)` goes through FreeBSD `ether_ioctl`, which writes values ≤ ETHERMTU directly into `if_mtu`.
- Increasing MTU (>1500, jumbo): double-blocked. At the protocol-stack layer, `ether_ioctl` hardcodes `EINVAL` for `ifr_mtu > ETHERMTU(1500)`; at the DPDK hardware layer there is no MTU wiring at all — no `rte_eth_dev_set_mtu` call, the mbuf pool is fixed at `RTE_MBUF_DEFAULT_BUF_SIZE` (2048 usable dataroom), and `rxmode` has no jumbo/scatter configuration.

This conclusion matched F-Stack official issues #239/#490/#720 exactly: the jumbo support issue had been OPEN for a long time, and the maintainers explicitly replied "mtu cannot exceed 1500". So this project was not about applying patches — it was about connecting three broken layers: the protocol stack, the DPDK hardware layer, and the configuration system. A few key points:

- **Software-hardware linkage**: one MTU with three views — the protocol-stack `if_mtu`, the DPDK port MTU, and the mbuf pool capacity. All three must agree; startup fails if any mismatches.
- **Multi-process division of labor**: the DPDK physical port is shared state; the primary alone owns the hardware (sets both soft and hard), while secondaries set only their own process's software MTU — zero IPC between processes.
- **Zero-regression commitment**: the new `mtu_enable` master switch; when disabled, legacy configs keep the exact MTU 1500, 2176B mbufs, and ioctl behavior.

2. Main applicable scenarios

2.1 Large-packet throughput optimization

This is the most direct motivation. The historical conclusion of issue #1033 already noted that the performance drop in large-packet scenarios is partly caused by IP fragmentation forced by MTU 1500. With jumbo frames enabled, an 8500-byte packet is no longer split into 6 fragments, and fragmentation/reassembly overhead drops to zero. Suitable for internal high-speed networks, large data-block transfers, and storage networks where the link MTU can be unified.

2.2 Tunnel/overlay scenarios that need to flexibly reduce MTU

Reducing MTU always worked, but after this rework all runtime changes go through the standard SIOCSIFMTU semantics — a single `ff_ifconfig f-stack-0 mtu <N>` changes both the protocol stack and the hardware. VXLAN/GRE/tunnel overlay scenarios often need MTU pushed down to the 1400 range to leave room for tunnel headers.

2.3 Unified jumbo frames in multi-process production deployments

Under the classic 1 primary + N secondary deployment, each process sets MTU once to stay consistent (primary manages hardware, secondaries manage their own software views) — no cross-process coordination mechanism needed.

2.4 Scenarios that are not a good fit

- The link peer does not support jumbo: PMDs like virtio have limited jumbo capability, and the underlying NIC/vSwitch/peer must all support it; otherwise large frames get dropped or fragmented mid-path — code support is useless if the link doesn't follow.
- Deep MTU linkage between KNI and the kernel stack: KNI veth interface MTU linkage is out of scope for this phase (only verified that both work independently after the mutual exclusion was lifted).
- Transaction-level cross-process MTU consistency: this phase explicitly skips IPC coordination; a process that never sets MTU keeps its old software value — a known usage constraint.

3. Architectural characteristics

3.1 The three broken layers before the rework

The root-cause diagram drawn during the research phase — the starting point for understanding every change:

```
┌────────────────────────────────────────────────┐
│ Application: ff_ifconfig f-stack-0 mtu 9000    │
│   ff_ioctl(SIOCSIFMTU)                          │
└───────────────────┬────────────────────────────┘
                    ▼
┌────────────────────────────────────────────────┐
│ Protocol stack (ff_veth.c + trimmed FreeBSD)    │
│   ff_veth_ioctl → ether_ioctl                   │
│   if (ifr_mtu > ETHERMTU) → EINVAL ← hardcoded 1500│
│   if_mtu written only to ifnet, no HW linkage   │
└───────────────────┬────────────────────────────┘
                    ▼（gap: even success is not pushed to HW）
┌────────────────────────────────────────────────┐
│ DPDK hardware layer (ff_dpdk_if.c)              │
│   No rte_eth_dev_set_mtu call                   │
│   rxmode has no mtu/max_rx_pkt_len/jumbo config │
│   mbuf pool fixed 2048 dataroom ← can't fit big frames│
└────────────────────────────────────────────────┘
```

3.2 The SIOCSIFMTU path after the rework (split by process role)

```
                ff_ifconfig mtu <N>
                       │
              ff_veth_ioctl(SIOCSIFMTU)   ← intercepted, no longer delegates to ether_ioctl
                       │
         rte_eal_process_type() role check
            ┌──────────┴──────────┐
            ▼                     ▼
       primary                secondary
   ff_dpdk_if_set_mtu()     if_setmtu() software-only
   ① -EBUSY → stop port        │（never touches DPDK port control APIs）
   ② rte_eth_dev_set_mtu       │
   ③ rte_eth_dev_get_mtu readback│
   ④ rollback on failure:      │
      restore old MTU          │
      + restart port           │
   ⑤ on success → if_setmtu(ifp)│
   ⑥ if_notifymtu(ifp)         │
      ├ nd6_setmtu (IPv6 sync) │
      └ rt_updatemtu (route sync)│
```

Key design constraint: `ff_veth.c` does not include `rte_ethdev.h`; all hardware operations go through the opaque interfaces `ff_dpdk_if_get_mtu/set_mtu/get_mtu_capability` in `ff_dpdk_if.h`, and DPDK negative errno values are converted to BSD positive errno via `ff_dpdk_errno_to_bsd()`.

3.3 The two mbuf carrying modes

```
large mode                          scatter mode
┌──────────────────────────┐        ┌──────────┐┌──────────┐
│ single mbuf, data_room    │        │ standard ││ standard │→ ...
│ sized by HEADROOM+        │        │ mbuf     ││ mbuf     │
│ max_mtu+L2_overhead       │        │ 2048B    ││ 2048B    │
└──────────────────────────┘        └────┬─────┘└────┬─────┘
     more memory, simpler path          │  RX_OFFLOAD_SCATTER
                                        │  multi-seg chaining
                                        ▼
                                   less memory, but requires PMD
                                   scatter + multi_segs support,
                                   and the multi-seg mbuf
                                   conversion path must be verified
```

In large mode `data_room_size = align(HEADROOM + max_mtu + L2_overhead)`; exceeding UINT16_MAX must fail deterministically, so `max_mtu=65535` is unavailable in large mode. Scatter mode keeps standard mbufs, configurable up to 65535 but subject to PMD capability.

4. What was reworked and what problems were hit

The rest is a bit dry; skip this section if you don't need the implementation details and jump straight to Section 5.

4.1 Research conclusions turned directly into requirement decisions (D-MTU-01~06)

The research wrapped up with 6 decisions, all carried through the implementation:

| ID | Decision |
|---|---|
| D-MTU-01 | Implement both large and scatter mbuf modes, selected by configuration |
| D-MTU-02 | `max_mtu` is configurable; defaults to 9000 when the feature is enabled |
| D-MTU-05 | **Do not modify the freebsd/ tree**; intercept SIOCSIFMTU in lib/ff_veth.c to bypass ether_ioctl's 1500 hard check |
| D-MTU-06 | With `mtu_enable=0`, behavior stays identical to the old version (MTU 1500, 2176B mbufs, ioctl unchanged) |

D-MTU-05 deserves one more sentence: the ETHERMTU hard check in `ether_ioctl` is a general FreeBSD semantic. F-Stack's choice was not to change it inside the trimmed stack, but to intercept SIOCSIFMTU in the ff_veth driver layer and handle it there. This keeps the freebsd/ subtree untouched — no new patch maintenance burden when the FreeBSD baseline is upgraded.

4.2 Code implementation (M1~M5, 2026-07-21)

| Milestone | commit | Content |
|---|---|---|
| M1 | 97452db34 | Config parsing & validation: enum ff_mbuf_mode, ff_port_cfg.mtu, dpdk.{mtu_enable,max_mtu,mbuf_mode}; strict strtoul parsing; cross-field validation; 8 unit tests + 7 fixtures |
| M2 | eec178902 | DPDK layer: ff_mtu_data_room_size() alignment, large-mode data_room sizing, rxmode.mtu + PMD capability check + scatter offload, set/get_mtu readback |
| M3 | 0849f9f3a | ff_veth integration: opaque MTU API, DPDK errno→BSD errno conversion, SIOCSIFMTU interception (primary soft+hard / secondary soft only), initial if_mtu read from hardware at startup |
| M4 | ef20b1abf | EBUSY state machine: -EBUSY → stop/set_mtu/get_mtu/start; rollback restore old MTU + restart port on failure |
| M5 | 314df8a0a | Integration tests + architecture doc updates |
| Wrap-up | 0f8f6991e / 332abf997 / 4c30d118f | magic numbers → named macros, SIOCSIFMTU handler fall-through dedup, bool→uint8_t clean-build fix |

One iron rule for config parsing: no `atoi()`. The new `ff_parse_u16/ff_parse_mbuf_mode` do strict parsing (strtoul + errno/endptr/range checks); any illegal configuration fails loudly at startup instead of silently falling back to 1500. `mtu_enable=0` combined with `mtu>1500` fails parsing outright with a hint to enable the feature first.

4.3 Problem 1: IPv6 jumbo replies fragmented at 1448 bytes (the biggest pitfall)

During physical-machine validation after the feature went live, a bizarre symptom appeared: **IPv4 jumbo worked bidirectionally, but IPv6 received an 8500-byte ping fine while the reply was split into 6 fragments of 1448 bytes**.

Back-calculation from the capture: 6 fragments = 1448×5 + 1268 = 8508, matching the fragmentation formula `len = (mtu - 40 - 8) & ~7`, which solves to mtu=1500 — the stack had if_mtu set to 9000, yet IPv6 fragmentation still used MTU 1500.

The root-cause chain spans 12 file:line references (full analysis in `15-ipv6-jumbo-frame-fragmentation-analysis.md`); it boils down to one sentence:

```
ether_ifattach(if_mtu=1500) → nd6_ifattach → nd6_setmtu0(ndi->maxmtu=1500)
        ↓
ff_veth if_setmtu(9000) → if_mtu=9000, but [nd6_setmtu not called] → ndi->maxmtu stuck at 1500
        ↓
IN6_LINKMTU = min semantics → maxmtu(1500) < if_mtu(9000) → returns 1500
        ↓
route nh_mtu=1500 → ip6_getpmtu → ip6_calcmtu → fragment len=(1500-48)&~7=1448
```

The real pitfall: `if_setmtu()` only writes `ifp->if_mtu` — **it does not notify protocol families**. The standard FreeBSD kernel path `ifhwioctl → if_setmtu → if_notifymtu → nd6_setmtu + rt_updatemtu` synchronizes IPv6's `ndi->maxmtu` and the route MTU, but F-Stack took the "call if_setmtu directly" shortcut to bypass ether_ioctl's 1500 hard check and dropped the `if_notifymtu` step. The IPv4 output path judges fragmentation with `ifp->if_mtu` directly, so it was unaffected; IPv6 goes through IN6_LINKMTU and got hit.

The fix (commit 0f25ac495, +163/-1): both paths in `ff_veth.c` — startup initialization and runtime SIOCSIFMTU — now call `if_notifymtu(ifp)` after `if_setmtu`, aligning with standard kernel semantics. Physical-machine retest: `ping6 -M do -s 8500` replies are no longer fragmented; IPv6 jumbo works bidirectionally.

[Note 1] This pitfall has general value: in FreeBSD, "changing if_mtu" and "notifying protocol families" are two separate things. Any code that bypasses the standard ifhwioctl path and calls if_setmtu directly (driver init, ioctl interception) must add if_notifymtu itself; otherwise IPv6's nd_ifinfo and route nh_mtu stay at the old values forever. Incidentally, the secondary cause — a router advertisement lowering linkmtu — was also investigated; runtime verification confirmed linkmtu=0 (not affected by RA), so the primary-cause fix closed the loop.

4.4 Problem 2: the KNI/MTU mutual exclusion — banned first, lifted later

The initial requirement R-MTU-009 agreed: when `mtu_enable=1` and KNI/kernel coexistence are both enabled, reject at configuration time with EOPNOTSUPP — the rationale being the risk of dual-stack MTU inconsistency.

Physical-machine testing overturned this conservative decision (commit 989f1d2da, +1/-6): `mtu_enable=1` coexisting with `kni.enable=1` works perfectly — with veth0 MTU=1500 the kernel stack sends and receives normally with defragmentation, and with `ifconfig veth0 mtu 9000` the KNI path handles jumbo frames fine too. The exclusion was an unnecessary restriction; after lifting it, KNI users can also use jumbo frames.

[Note 2] This back-and-forth shows that conservative spec-stage constraints deserve re-examination after real measurements: an EOPNOTSUPP rejection is the safest wording, but if measurements show coexistence is fine, lifting the exclusion is friendlier to users than maintaining a "paper risk".

4.5 Other engineering details

- **EBUSY state machine**: `rte_eth_dev_set_mtu` may return -EBUSY for a running port; M4 implements stop/set_mtu/get_mtu/start within the primary process, with rollback restoring the old MTU and restarting the port on failure; secondaries simply return 0 without touching hardware.
- **Multi-process consistency by usage convention**: zero IPC, zero transactions, zero message rings between processes; each process triggers SIOCSIFMTU once. A process that never sets MTU keeps its old software value (a known constraint, explicitly stated in the spec).
- **Gates**: -Werror build, git-diff-verified zero changes to the freebsd/ tree, no rte_eth* references in ff_veth.c, no atoi, no IPC residue, zero regression across all paths with mtu_enable=0 — all six PASS.

5. How to use it, how to configure it, and the results

5.1 Configuration

```ini
[dpdk]
mtu_enable=1          # feature master switch, default 0 (behavior identical to the old version when off)
max_mtu=9000          # runtime MTU upper bound + large-mode pool pre-allocation basis, default 9000
mbuf_mode=large       # large: one mbuf carries jumbo; scatter: standard mbuf multi-seg chain

[port0]
mtu=9000              # protocol-stack + hardware MTU at port startup, default 1500
```

Constraint quick reference:

- `mtu_enable=0` combined with `mtu>1500`: parsing fails, with a hint to enable the MTU feature first
- In large mode `max_mtu` is bounded by `data_room_size <= UINT16_MAX` (65535 unavailable); scatter mode can go to 65535 but is subject to PMD capability
- Illegal configurations fail at startup; there is no silent fallback

5.2 Runtime changes

```bash
# primary process: changes soft + hardware together (including EBUSY → stop/set/start)
ff_ifconfig -p 0 f-stack-0 mtu 9000

# query
ff_ifconfig -p 0 f-stack-0
f-stack-0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 9000
```

Multi-process convention: a change on the primary updates both soft and hardware; each secondary must trigger its own change (updating only its own software view). This is a usage convention, not a bug; cross-process IPC coordination is a future milestone outside this scope.

5.3 Results (physical-machine measurements)

| Test item | Result |
|---|---|
| IPv4 jumbo | `ping -M do -s 8972` bidirectional 8500-byte traffic fine, MTU=9000 without fragmentation ✅ |
| IPv6 jumbo | `ping6 -M do -s 8500` fine (before the fix, replies were split into 6 fragments of 1448; after adding if_notifymtu, no fragmentation) ✅ |
| KNI/MTU coexistence | `mtu_enable=1` + `kni.enable=1` coexist fine; veth0 MTU 1500/9000 both send and receive correctly ✅ |
| Unit tests | 59 passed (including 8 new MTU tests), all 12 test binaries PASS ✅ |
| Gates | -Werror / freebsd tree untouched / no rte_eth leakage / no atoi / no IPC residue / zero regression — all PASS ✅ |

Unit test coverage: 8 new config-parsing cases (UT-CFG-01..08) + 7 fixtures, focusing on config-validation boundaries (defaults, cross-field conflicts, illegal strings, overflow).

5.4 Advice for users

- Before enabling jumbo, verify the link: the physical NIC, vSwitch, and peer must all support jumbo; with an unsupporting link, mid-path drops of large frames are worse than 1500
- Memory-sensitive scenarios: choose scatter — large mode pre-allocates the mbuf pool by max_mtu with significant memory cost; scatter saves memory but requires PMD RX_SCATTER + TX_MULTI_SEGS support
- Just need a smaller MTU: no need to enable mtu_enable — `ff_ifconfig ... mtu 1400` works directly

Further reading:

- Research conclusions overview with three-way evidence: docs/mtu_change_spec/00-overview-index.md
- IPv6 jumbo fragmentation root-cause chain (12 file:line): docs/mtu_change_spec/15-ipv6-jumbo-frame-fragmentation-analysis.md
- Implementation report (M0~M5 + Post-M5): docs/mtu_change_spec/14-implementation-report.md
- Interface and config design: docs/mtu_change_spec/08-interface-and-config-design.md
- Related issues: #239 (set MTU in example), #490 (Why MTU MAX CONF is 1500), #720 (Enabling jumbo frames), #1033 (large-packet performance and MTU)
- Three-layer architecture docs: docs/01-LAYER1-ARCHITECTURE.md
- Knowledge graph: docs/KNOWLEDGE_GRAPH_WIKI.md
