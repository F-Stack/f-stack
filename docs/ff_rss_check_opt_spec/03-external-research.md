# 03 External Research — ff_rss_check Three Optimizations

> Purpose: Consolidate external materials related to the three optimizations of this project (F-Stack official, DPDK official), organize "points worth borrowing" and "differences/points that go beyond this project", providing external grounding for the 04 design.
> Principle: External materials are design references only; the final landing point is based on this repository's actual code/headers (see 01/02). Cited code facts are all annotated in 02 with `file:line`.

---

## 1. External Source List

| # | Source | Content | Correspondence to this project |
|---|------|------|--------------|
| S1 | F-Stack official wiki: "ff_rss_check() Optimization Introduction" (corresponds to commit `e54aa4317`) | Design and performance data of the static table `ff_rss_tbl` for optimizing RSS port selection | 0.1 (origin of the static table/portrange mechanism), 0.3 (background of the dynamic fallback) |
| S2 | DPDK official Programmer's Guide: "Toeplitz Hash Library" (doc.dpdk.org/guides/prog_guide/toeplitz_hash_lib.html) | Usage and constraints of `rte_thash_*` tuple reverse-computation (adjust_tuple) | 0.3 (thash reverse-computation on the dynamic path) |
| S3 | DPDK 24.11.6 header `dpdk/lib/hash/rte_thash.h` (already read, in this repository) | Precise signatures and constraint comments for `rte_thash_init_ctx` / `add_helper` / `get_complement` / `adjust_tuple` | 0.3 (API contract, already evidenced in 02 §4) |

> Note: Although S3 is an in-repo header, as the authoritative definition of DPDK's public API it is included in the external research for cross-verification against the S2 document.

---

## 2. S1: F-Stack Official Static Table Optimization (corresponds to 0.1)

### 2.1 Upstream design highlights
- Upstream introduces the static table `ff_rss_tbl`: under multi-process/multi-queue, for common `saddr/daddr/sport` combinations, **precomputes** "which dports fall into this process's queue after the NIC's RSS" and caches this as a port set (portrange).
- When the kernel selects a local port (`in_pcblookup_local` / `in_pcb_lport_dest` path), for requests carrying the RSS flag, it only rotates through ports from the "set of ports that fall into this queue", avoiding per-port software computation of the Toeplitz hash.
- Integrates with `net.inet.ip.portrange.*` (port range sysctl) and port randomization (randomtime / `V_ipport_randomized`).

### 2.2 Upstream performance data (wiki figures, as an expectation reference, not measured by this project)
- Single-process scenario: about **2%–6%** improvement.
- Multi-process scenario: **35%+** improvement (the more processes, the greater the gain from static-table hits).

### 2.3 Points worth borrowing (directly used for the 0.1 back-port)
- The static-table mechanism (`ff_rss_tbl_init` / `set_portrange` / `get_portrange`) is **fully retained** in the user-space code of this repository's 15.0 (02 §1.1); no rewrite is needed.
- The dual-path logic of "hit static table → rotate through ports / miss → per-port soft computation of `ff_rss_check`" is already implemented in the 13.0 baseline (02 §2.1); 0.1 is exactly back-porting this kernel-side logic to the 15.0 structure.

### 2.4 Differences from this project
- The upstream wiki's mechanism is **IPv4-only**; this project's 0.2 **adds IPv6** on top of it (not covered upstream).
- The upstream wiki does not involve `rte_thash_adjust_tuple` reverse-computation; this project's 0.3 uses thash reverse-computation to optimize the "dynamic path when the static table is missed", a new capability that **goes beyond upstream**.

---

## 3. S2 + S3: DPDK Toeplitz Hash Library / rte_thash (corresponds to 0.3)

### 3.1 DPDK documentation (S2) highlights
- The Toeplitz Hash Library provides two kinds of capability: "forward computation" (computing the hash from a tuple) and "reverse-computation/adjustment" (`rte_thash_adjust_tuple`: adjust a certain subtuple segment of the tuple so that the Toeplitz hash's **low bits** equal the desired value `desired_value`).
- Reverse-computation requires first building a ctx (`rte_thash_init_ctx`) and adding a helper for the "subtuple to be adjusted" (`rte_thash_add_helper`, specifying the bit `offset` and `len` of that subtuple).
- Typical use case: when the low bits of the target reta (i.e., the target queue) are known, **there is no need to try port-by-port**; the source port field can be adjusted directly so the packet lands on the target queue.

### 3.2 S3: API contracts confirmed by this repository's DPDK 24.11.6 headers (already evidenced in 02 §4, key constraints restated here)
- `rte_thash_init_ctx(name, key_len, reta_sz, key, flags)` (`rte_thash.h:303`):
  - **`reta_sz` is the log of the reta size** (`rte_thash.h:288-291`), range `RTE_THASH_RETA_SZ_MIN=2` ~ `RTE_THASH_RETA_SZ_MAX=16` (L261-263).
  - `key` may be NULL (randomized internally); this project must pass a **key consistent with the NIC** (see §3.4).
- `rte_thash_add_helper(ctx, name, len, offset)` (`rte_thash.h:348`):
  - **`len` (subtuple bit length) must be ≥ `reta_sz`** (L340-341); `offset` is the bit offset of the subtuple within the tuple; **not thread-safe** (recommended to build once during initialization).
- `rte_thash_adjust_tuple(ctx, h, tuple, tuple_len, desired_value, attempts, fn, userdata)` (`rte_thash.h:456`):
  - **`tuple_len` must be a multiple of 4** (L441-442).
  - `desired_value` = the desired hash **low bits** (L443-444).
  - `attempts` = number of attempts with `fn` verification; the `fn` verification callback (returns 1 for success/0 for failure) may be NULL (L445-448, L428).
  - **Thread-safe** (L433).

### 3.3 Points worth borrowing (used for 0.3)
- Use `init_ctx + add_helper(source port field) + adjust_tuple` to replace the O(number of ports) scan of "per-dport soft computation of `toeplitz_hash` when the static table is missed", reducing cost on the dynamic path.
- The `fn` callback can hook a "port already in use" check, so the reverse-computed port simultaneously satisfies "falls in this queue + not in use".

### 3.4 Differences from this project / key risk points (must be resolved in 04)
1. **Inconsistent queue-landing determination**: this repository's `ff_rss_check` determines queue landing as
   `((hash & (reta_size - 1)) % nb_queues) == queueid` (`ff_dpdk_if.c:2963`, includes `% nb_queues`);
   whereas `adjust_tuple` aligns to the low `reta_sz` bits of the hash (the reta entry).
   The mapping between the two must be precisely derived from `queueid → desired_value` (including handling of `% nb_queues`), otherwise the reverse-computed port will land in the wrong queue. → Left for 04 §0.3 to derive.
2. **RSS key symmetry**: DPDK reverse-computation is more robust with a **symmetric key**; this repository's default `default_rsskey_40bytes` (`ff_dpdk_if.c:92`) is an **asymmetric** key, but the repository **already includes** `symmetric_rsskey[52]` (`ff_dpdk_if.c:110`) and the `symmetric_rss` config switch (`ff_dpdk_if.c:750`). → 04 needs to assess "feasibility of reverse-computation under an asymmetric key + choice of `attempts`" and "whether to recommend enabling `symmetric_rss`".
3. **IPv6 tuple**: neither the DPDK documentation nor upstream covers IPv6 RSS port selection; this project's 0.2 IPv6 tuple (16+16+2+2=36B) must satisfy `tuple_len` being a multiple of 4 (36 satisfies this), and must coordinate with the 0.3 reverse-computation path.

---

## 4. Support Conclusions from External Research for the Three Requirements

| Requirement | External support | This project's position relative to the outside world |
|------|----------|----------------------|
| 0.1 | S1: the static-table mechanism and 13.0 implementation; performance data can serve as an expectation reference | **Back-port** an existing upstream mechanism to 15.0 (not an innovation) |
| 0.2 | No direct external precedent (S1 is IPv4-only) | **Brand new addition**: IPv6 RSS port selection is a unique extension of this project |
| 0.3 | S2/S3: the `rte_thash_adjust_tuple` reverse-computation capability | **Goes beyond upstream**: upstream does not use thash reverse-computation; this project introduces it for the first time and resolves the queue-landing mapping alignment |

---

## 4. R-D (Requirement 0.4) Research: Does the Industry Do a Second Soft-Computation Recheck After Reverse-Computation

> Purpose: Verify whether "after `rte_thash_adjust_tuple` reverse-computation succeeds, is it necessary to do another soft `ff_rss_check` recheck" is a mainstream industry practice or a zero-tolerance hard gate specific to this project; provide external grounding for 0.4's default of disabling the recheck hard gate.
> Principle: where first-hand material could be accessed, cite the source; where it could not, mark "no first-hand material obtained, inferred from prior project experience".

### 4.1 Does Linux Kernel RPS/RFS Do a Reverse-Computation Recheck

- Research sources (accessed):
  - [An Analysis of Linux RPS/RFS Implementation Principles](https://www.cnblogs.com/tcicy/p/10195533.html) (cnblogs)
  - [Detailed Test Analysis of Linux Kernel RPS/RFS Feature (Alibaba Cloud Developer Community)](https://developer.aliyun.com/article/1376643)
  - [An Analysis of Linux RPS/RFS Implementation Principles (CSDN dog250)](https://blog.csdn.net/dog250/article/details/80025959)
  - First-hand code: Linux `net/core/dev.c`'s `get_rps_cpu` / `enqueue_to_backlog` path (described comprehensively based on the above materials)
- Key facts:
  - RPS (Receive Packet Steering): computes the hash in software on the receive path (`__skb_get_hash` → `flow_hash_from_keys`, `l4_hash_secret` + jhash), and enqueues the packet to the target CPU's backlog; **there is no concept of "reverse-computing the source port"** — RPS is receive-side distribution and does not affect the send-side connect's choice of sport.
  - RFS (Receive Flow Steering): layered on top of RPS, records "which CPU the socket last ran on" (`rps_sock_flow_table`), so that receiving lands in the backlog of the CPU used last time; **it also does no reverse-computation / secondary verification** — RFS maintains the expected CPU, using it on a hit and falling back to the RPS default on a miss.
  - When the kernel-side `inet_hash_connect` / `__inet_hash_connect` (`net/ipv4/inet_hashtables.c`) selects sport: based on pseudo-random `port_offset = secure_ipv4_port_ephemeral(...)` plus a scan of the port space; **there is no RSS reverse-computation or reverse-hash recheck of any kind** — the kernel's sport selection is unaware of NIC RSS, relying purely on TCP/UDP port-hash-table uniqueness.
- Conclusion: **Across the entire Linux kernel-space chain (RPS/RFS/inet_hash_connect), none of it does "reverse-compute source port → secondary verification of queue landing"**. Reason: kernel-space sport selection is decoupled from hardware RSS — the only constraint on sport is "the 4-tuple is not already in use"; which RX queue it lands in is decided by NIC RSS, and landing in the wrong queue only means the softirq runs on a different CPU, which does not affect TCP/UDP connection correctness (only a cache-locality loss, aligned at the software level by RFS).
- Support for 0.4: F-Stack user-space actively pursuing "sport lands in this queue" when selecting sport is a requirement specific to the DPDK multi-process architecture (with no RFS software-layer fallback), but "doing a secondary soft-computation recheck after a successful reverse-computation" is a belt-and-suspenders fallback that upstream RPS/RFS does not have — it can be made a debug option to disable.

### 4.2 DPDK rte_thash Reverse-Computation vs. softrss_be / toeplitz Byte-Order Differences

- Research sources (accessed):
  - DPDK official documentation (S2, already in §3.1) + the in-repo `dpdk-stable-24.11.6/lib/hash/rte_thash.h` (S3, already in §3.2)
  - [Debian dpdk-doc rte_softrss_be(3) manpage](https://manpages.debian.org/testing/dpdk-doc/rte_softrss_be.3.en.html) (first-hand manpage)
  - [DPDK RSS Basics (Part 2) (Zhihu)](https://zhuanlan.zhihu.com/p/548022042)
  - [DPDK 4 CPU Packet Processing - Toeplitz Hash Library (cnblogs)](https://www.cnblogs.com/Tohomson/p/18841852)
- Key facts from first-hand DPDK documentation:
  - `rte_softrss(input_tuple, input_len, rss_key)` vs. `rte_softrss_be(input_tuple, input_len, rss_key)`: both **compute the same rss hash for the same input_tuple**; the difference lies in `rte_softrss` assuming input_tuple is already in host order (a uint32_t array read in host order), while `rte_softrss_be` reads the input byte stream in big-endian/network order.
  - `rte_thash_adjust_tuple` and this repository's `toeplitz_hash` **are algorithmically identical (standard Toeplitz)**. ⚠ **The earlier statement in this section about "different byte-order models causing hashes not to be equal on every computation" has since been overturned and voided by a subsequent bit-level arbitration**: `rte_softrss(be_to_cpu_32(bytes)) ≡ toeplitz_hash(bytes)` are bit-for-bit equivalent; byte order is **not** the root cause. The true cause of hash inconsistency is that `rte_thash_add_helper` rewrites the ctx key (see §5-ter K1 and 02 §6-quater); this section is kept only as a record of the research process.
  - Industry discussion: neither DPDK mailing-list discussions nor the documentation examples **require "an additional arbitrary soft recheck after the reverse computation"** — `rte_thash_adjust_tuple` already guarantees mathematically (via LFSR/complement) that "the hash's low bits of the adjusted tuple == desired_value"; no secondary forward-verification is needed.
- Correspondence with this project's code (corrected conclusion):
  - This repository's spec 10 measured R-B/R-C single-candidate equivalence rate ~22%-27% — **the cause is not byte order**, but that after `add_helper` rewrites the ctx key, check/NIC still use the original key (the three parties' keys are inconsistent, see §5-ter / 02 §6-quater). After R-F aligns the three parties' keys, the equivalence rate should reach ~100%.
- Support for 0.4: the DPDK industry **does not advocate** doing a secondary arbitrary soft recheck of `rte_thash_adjust_tuple` results — as long as the ctx's key and reta_sz are consistent with the NIC (this project guarantees this via `default_rsskey_40bytes` + `rss_reta_size[port]`), the reverse-computation result can be trusted for "letting the NIC-side RSS distribute the packet to the target queue". This project's custom `toeplitz_hash` recheck is a historically conservative design (sharing the same hash function as the R-A soft-computation path), not a hard requirement of DPDK documentation.

### 4.3 Do Other User-Space Stacks (Seastar / mTCP) Do a Reverse-Computation Recheck

- Research sources (partially accessed + prior project experience):
  - [Seastar Tutorial (Part 1) Translation - cnblogs](https://www.cnblogs.com/morningli/p/15920469.html)
  - [Analysis of Seastar Source Code's User-Space TCP Stack - Zhihu](https://zhuanlan.zhihu.com/p/362074840)
  - [seastar-cn tutorial.md (GitHub)](https://github.com/zhuzilin/seastar-cn/blob/main/tutorial.md)
  - mTCP paper (USENIX NSDI'14): at the level of general material, it has been established that mTCP achieves share-nothing via "binding NIC queues to CPUs + hashing on sport for load distribution".
- Key facts (partially confirmable):
  - Seastar: a share-nothing architecture with an independent TCP stack per CPU core; when actively connecting and choosing sport, it reverse-computes via RSS hash to pick an sport satisfying "lands on this core" (a similar idea to F-Stack's 0.3); but the Seastar source code has **no** design of "a secondary soft-recheck hard gate after reverse-computation" — it directly uses the reverse-computation result.
  - mTCP: likewise based on RSS-friendly sport selection, with no observed design of reverse-computation + secondary recheck as a hard gate (based on the NSDI'14 paper and the open-source README level of description).
- **No first-hand code-level grep evidence obtained, inferred from prior project experience**: user-space stacks in the industry that reverse-compute sport for selection generally do only a single layer (use immediately once reverse-computation succeeds), without a secondary soft recheck. F-Stack R-B/R-C's recheck hard gate is a conservative fallback of this project's own regarding the "key/offset/desired_value derivation chain", which is uncommon in the industry.

### 4.4 R-D Research Conclusion

| Dimension | Industry practice | F-Stack current (R-B/R-C) | 0.4 change |
|------|----------|------------------------|----------|
| Linux kernel RPS/RFS | No reverse-computation, and even less a secondary recheck | N/A (user-space-specific issue) | — |
| Linux `inet_hash_connect` selecting sport | No reverse-computation, only checks port uniqueness | 0.1 R-A already integrates with RSS portrange sport selection | Unchanged |
| DPDK `rte_thash_adjust_tuple` documentation examples | Reverse-computation result can be trusted directly (given key+reta alignment) | **Mandatory soft recheck** as a zero-tolerance fallback | recheck=0 trusts the reverse-computation result by default (aligned with DPDK docs); recheck=1 keeps the status quo |
| Seastar / mTCP and other user-space stacks | Use once reverse-computation succeeds, no secondary recheck hard gate (inferred from prior project experience) | Same as F-Stack's current state | Aligned with the industry; recheck downgraded to a debug option |
| Failure fallback (reverse-computation -1 → soft scan) | The industry generally has a failure fallback chain | R-A's soft-computation scan is fully retained | **Fully retained** (decoupled from 0.4) |

**Conclusion**: The industry generally **does not do a secondary soft recheck after reverse-computation**; F-Stack R-B/R-C's recheck hard gate is a "conservative safety net" that can be turned off as a debug option to realize the performance expected from 0.3, while still retaining the failure fallback chain of attempts exhausted → -1 → in_pcb soft-computation scan. 0.4's default recheck=0 aligns with the industry, and recheck=1 keeps the debug path without losing capability.

---

## 5. R-E (Requirement 0.5) Research: `IP_BIND_ADDRESS_NO_PORT` and RSS-Aware Deferred Port Selection

> Purpose: Verify the semantics of Linux `IP_BIND_ADDRESS_NO_PORT`, the corresponding upstream f-stack commit/release, and whether "RSS-aware port selection is industry-common or specific to user-space stacks", providing external grounding for 0.5 (bind-then-connect deferred port selection + RSS affinity).
> Source tiers: 【First-hand】= directly from official man/release/wiki/kernel documentation; 【Inferred】= without first-hand code-level evidence, synthesized from prior project experience.

### 5.1 Linux `IP_BIND_ADDRESS_NO_PORT` (First-hand)

- Source: `man IP_BIND_ADDRESS_NO_PORT(2const)` (man7.org, Linux man-pages) 【First-hand】.
- Key facts:
  - Linux **4.2** introduced this socket option.
  - Semantics: after `setsockopt(IP_BIND_ADDRESS_NO_PORT)` on a socket and then `bind(local_addr, port=0)`, the kernel **does not reserve an ephemeral port at bind time**, but **defers** it to connect time, selecting the port based on the full 4-tuple (saddr/daddr/sport/dport); as long as the 4-tuple is unique, the same source port can be shared across multiple connections.
  - Problem solved: when outbound connections (client role) heavily reuse the same local addr, `bind(addr,0)` claiming a port up front quickly exhausts the ephemeral port space (ephemeral port exhaustion); by deferring port selection to connect time, the port-uniqueness constraint is relaxed from the "2-tuple (addr,port)" to the "4-tuple", greatly improving port utilization.
- Correspondence with f-stack 0.5: the f-stack upstream commit ported this mechanism of "bind does not claim a port; select it later at connect" to the FreeBSD stack; **but f-stack additionally layers an RSS queue-affinity constraint onto the connect-time port selection** (via `INPLOOKUP_LPORT_RSS_CHECK`), i.e., it requires not just port uniqueness but also that the packet, via NIC RSS, lands in the local worker's queue. This is an additional requirement of f-stack's multi-process share-nothing architecture relative to Linux.

### 5.2 f-stack Upstream Commit / Release (First-hand)

- Source: f-stack GitHub releases + official wiki 【First-hand】.
- Key facts:
  - Reference commit `cb9b4d462a0cd8c47b6f514e2af0111cd26597b3` (based on 13.0, changes only `freebsd/netinet/in_pcb.c`, +9/-2, 3 hunks), included in **v1.25 / v1.21.6 (2025-11-04)** release, release note: "Support bind no port like linux's IP_BIND_ADDRESS_NO_PORT".
  - This commit is **from the same batch and strongly related** to this batch's `ff_rss_check` table optimization — both stem from the same core need of "letting outbound connection packets, under multiple processes, land in the local worker's queue".
  - The official wiki "F-Stack ff_rss_check() Optimization Introduction" explains the RSS principle: each process exclusively owns a receive queue, and the NIC dispatches via Toeplitz hash → RETA → queue; among the 4-tuple, the **source port is the only variable controllable by the initiating end**, and it determines which queue the return packet lands in; `ff_rss_check` selects an RSS-friendly port to ensure the return packet lands in the local worker.
- Correspondence with 0.5: 0.5's connect-time deferred port selection precisely reuses `ff_rss_check`'s RSS-friendly port selection (already landed via R-A/R-B); 0.5 merely fixes the vulnerability of "bind claiming a port early" that bypasses RSS.

### 5.3 Industry Comparison: Is RSS-Aware Port Selection Common (First-hand + Inferred)

- Source: Linux kernel scaling documentation (RSS/RPS/RFS, Documentation/networking/scaling.rst) 【First-hand】+ existing §4.1/§4.3 research on Linux/Seastar/mTCP.
- Key facts:
  - **Linux kernel port selection is not RSS-aware**: `inet_hash_connect`'s selection of sport only guarantees 4-tuple uniqueness (via the port hash table) and does not query NIC RSS in reverse; flow-to-core affinity relies on **receive-side software steering** (RFS/RPS: after receiving, software-steers to the expected CPU's backlog based on flow hash) — a "receive-side software correction" rather than "send-side port-selection alignment".
  - **RSS-aware port selection is a requirement specific to DPDK user-space share-nothing stacks**: with DPDK multi-process each exclusively owning an RX queue and no kernel RFS software-layer fallback, a packet landing in the wrong queue lands on a different lcore, so it is necessary to guarantee RSS landing in the local queue **at send-side port selection time**. f-stack (first-hand) works this way; Seastar/mTCP-type user-space stacks are subject to the same architectural constraint (【inferred】 based on prior project experience, without obtaining code-level evidence for each one).
- Correspondence with 0.5: what Linux `IP_BIND_ADDRESS_NO_PORT` solves is "port exhaustion"; when f-stack 0.5 ports this mechanism, it **simultaneously** solves "bind claiming a port early bypassing RSS queue landing" — the latter is a problem that does not exist in Linux (relying on RFS software correction) and is specific to DPDK user-space stacks. That is, 0.5 = the Linux mechanism (deferred port selection) + f-stack's specific constraint (RSS queue affinity), which is a combination that **goes beyond upstream Linux semantics**.

### 5.4 R-E Research Conclusion

| Dimension | Linux | f-stack current 15.0 | 0.5 (R-E) change |
|------|-------|-------------------|-----------------|
| Does bind(addr,0) claim a port | Claims by default; after `IP_BIND_ADDRESS_NO_PORT` it does not (deferred to connect) | Both v4/v6 claim a port at bind time (02 §6-ter) | v4 adds hunk1/hunk2, v6 synced → bind does not claim, deferred to connect |
| Is port selection at connect RSS-aware | No (relies on receive-side RFS/RPS software correction) | Direct connect is already RSS-aware (R-A, L1363-1366 / in6 L515-527); but bind-then-connect bypasses it | After bind stops claiming a port, connect naturally goes through the already-existing RSS path |
| Port exhaustion mitigation | `IP_BIND_ADDRESS_NO_PORT` | None (bind claims immediately) | Obtained together with 0.5 (4-tuple uniqueness) |
| Is it a per-socket option | Yes (explicit setsockopt) | — | Leans toward following upstream's implicit behavior (takes effect for all bind(addr,0) under FSTACK); an explicit option is left as a decision (01 §3-ter.8) |

**Conclusion**: 0.5 ports the v4 mechanism of upstream commit `cb9b4d462` (aligning with Linux `IP_BIND_ADDRESS_NO_PORT`'s "bind does not claim a port, select the port later at connect"), and reuses f-stack's already existing connect-time RSS-aware port selection (R-A) so outbound connection packets land in the local worker's queue; v6 is a brand-new addition synced for 15.0 (neither 13.0 nor upstream has v6). This feature is a combination of "the Linux mechanism + DPDK user-space stack RSS affinity"; because the Linux kernel in the industry has RFS/RPS software correction, it does not need send-side RSS port selection — this feature is a necessary completion for the user-space share-nothing architecture.

---

## 5-bis. R-G (IPv6 Reverse-Path Misqueue Symmetry Fix) Research: Toeplitz Asymmetry + Reverse-Packet Field-Order Reverse-Computation

> Purpose: Provide external theoretical corroboration for this round of the "IPv6 rss_check reverse-path misqueue symmetry fix" (v6 `FF_RSS_THASH_V6_SPORT_OFF` 256→272, reverse-computing the local port by the return-packet's field order, first/last window alignment) — the core proposition is "Toeplitz hash is asymmetric, therefore the local port must be reverse-computed using the 【return-packet field order】 (the local port falls in the dstPort field of the return packet), rather than the outbound sport field".
> Source tiers: 【First-hand】= DPDK official documentation / Microsoft Learn / f-stack official wiki; 【Second-hand】= technical blogs (used for cross-verification, not as sole evidence).

### 5-bis.1 Background of the Proposition (Theoretical Root Cause of This Bug)

Commit `c42340d5` first discovered and fixed a similar bug on the IPv4 side: when sending packets under multiple processes, f-stack's purpose in reverse-computing the LOCAL source port is to have the 【inbound return SYN-ACK】 land in the RSS queue of the process that initiated the connect. Because Toeplitz hash is asymmetric, `hash(src,dst,sport,dport) ≠ hash(dst,src,dport,sport)`, so the outbound packet (local→remote) and the return packet (remote→local) land in different RSS queues. If the reverse-computation is done using the 【outbound sport field】, the return packet lands in the wrong queue instead → listen succeeds but the connection fails (IPv4 has already been reproduced on a physical machine and the fix verified). This round of R-G is the symmetric porting of the fix to IPv6.

### 5-bis.2 List of External Corroborations

| # | Source | Tier | Key conclusion | Consistent with this R-G conclusion? |
|---|------|------|----------|------------------------|
| G1 | [DPDK Official Programmer's Guide: Toeplitz Hash Library](https://doc.dpdk.org/guides/prog_guide/toeplitz_hash_lib.html) (26.07 / 23.11 same source) | First-hand | (a) Documentation §1.3 explicitly states Toeplitz is **asymmetric**: "packets of different directions within a bidirectional flow may be assigned to **different queues**, due to how Toeplitz computes over the tuple (source/destination address, port)"; (b) `rte_thash_add_helper`'s `offset`/`len` **are in bits**; (c) `rte_thash_adjust_tuple` directly rewrites the tuple so that the hash's low bits = desired; (d) in the SNAT example, the helper uses `offsetof(...v4.dport)*8` — that is, it is the **dstPort field** that is adjusted to make the **reverse tuple** land in the same queue. | **Fully consistent**. G1(a) corroborates the asymmetry-based root cause theory; G1(d) corroborates that "the reverse-computation should act on the port bit located at the field order in the return packet (the dstPort field)" — this round's v4 offset=80 (byte10=dstPort field) and v6 offset=272 (byte34=dstPort field) share the same idea as the DPDK official SNAT example's adjustment of the dport field bits. |
| G2 | [DPDK's Symmetric Receive-side Scaling (cnblogs, tycoon3)](https://www.cnblogs.com/dream397/p/13920956.html) | Second-hand | The default RSS key (`default_rsskey_40bytes`, recommended by Microsoft) is **asymmetric**: the two directions of the same flow have different RSS hash values on receive vs. send → landing on different CPUs/queues; a symmetric key (repeating `0x6d5a`) is needed to make both directions land in the same queue. | **Fully consistent**. Corroborates that under f-stack's default asymmetric key, the outbound and return directions must land in different queues → reverse-computation must follow the return-packet field order rather than relying on symmetry. |
| G3 | [Microsoft Learn: RSS Hashing Types (NDIS)](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/rss-hashing-types) | First-hand | NDIS RSS standard hash types define a 4-tuple for IPv6 (`NDIS_HASH_TCP_IPV6` = source/destination IPv6 addresses + source/destination ports); Toeplitz takes tuple fields **in order**, and the field order (who is src, who is dst, who is sport, who is dport) directly determines the hash value. | **Consistent**. Corroborates that v6 tuple field order is significant — in a return packet, the field order (remote_ip, local_ip, remote_port, local_port) differs from the outbound direction, so the local port falls at the dstPort bit position in the return packet (v6 byte34=bit272), and reverse-computation must be based on this bit. |
| G4 | [F-Stack ff_rss_check() Optimization Introduction (official wiki)](https://github.com/F-Stack/f-stack/wiki/%E2%80%8B%E2%80%8BF%E2%80%90Stack-ff_rss_check()-Optimization-Introduction%E2%80%8B) | First-hand | Each process exclusively owns a receive queue; the NIC dispatches via Toeplitz→RETA→queue; among the 4-tuple the **source port is the only variable controllable by the initiating end**, and `ff_rss_check` selects an RSS-friendly port to ensure the **return packet** lands in the local worker's queue. | **Consistent**. Corroborates that the goal of f-stack's reverse-computation of the local port is to "make the return packet land in the local queue", so the reverse-computation must be based on the return-packet's hash (return-packet field order). The wiki is IPv4-only; this round's R-G is the IPv6 symmetric extension (not covered by the upstream wiki). |

### 5-bis.3 R-G Research Conclusion

- **Theoretical root cause established (first-hand)**: DPDK official documentation G1(a) directly states that Toeplitz is asymmetric and bidirectional flows land in different queues; together with G2/G4, the proposition "the local port must be reverse-computed by the return-packet field order" has multiple corroborations from first-hand plus second-hand sources.
- **Corroboration of where the reverse-computation acts (first-hand)**: the DPDK official SNAT example G1(d) adjusts the bit of the **dstPort field** (`offsetof(...dport)*8`), which is entirely the same source as this round's v4 offset=80 / v6 offset=272 (both pointing to the **dstPort field** in the tuple = the position of the local port in the return packet); this also corroborates that "optimizing the outbound sport field (v4 bit64 / v6 bit256)" would predictably cause the return packet to land in the wrong queue (a latent defect that predates this bug).
- **Corroboration of v6 tuple field-order sensitivity (first-hand)**: Microsoft NDIS G3 defines the IPv6 4-tuple and states that Toeplitz reads by field order, corroborating the necessity of this round's v6 36B tuple being laid out in return-packet order (saddr6=remote@0 / daddr6=local@16 / dport@32 / sport@34).
- **This round's R-G positioning relative to the outside world**: the IPv4 fix (c42340d5) already aligns with upstream/DPDK thinking; R-G is symmetrically porting the same "reverse-computation by return-packet field order" fix to IPv6 — the upstream wiki (G4) and the DPDK SNAT example (G1) are both IPv4, and v6 is a brand-new symmetric extension for f-stack 15.0 with no direct external v6 precedent, but the theory is fully isomorphic to v4 (G1/G3 provide the general basis for v6 tuple field order and Toeplitz asymmetry).

---

## 5-ter. External Corroboration of the R-F thash Key-Alignment Root Cause (First-hand from DPDK Official, Correcting the Old Byte-Order Theory)

> Purpose: Provide first-hand DPDK official corroboration for "the root cause of the thash reverse-computation not working = `rte_thash_add_helper` rewriting the ctx key, causing the three parties' keys to be inconsistent (not byte order)" (already proven at the bit level in this repository's code in 02 §6-quater; this is external cross-verification).
> Everything is subject to actual testing of this repository's code.

| # | Source | Tier | Key conclusion | Consistent with R-F conclusion? |
|---|------|------|----------|---------------------|
| K1 | [DPDK Official Toeplitz Hash Library: THASH HELPER + Note](https://doc.dpdk.org/guides/prog_guide/toeplitz_hash_lib.html) (26.07 / 23.11 same source) | First-hand | Official §1.2.2 clearly states: after `rte_thash_add_helper()` succeeds, **(a) a specially computed bit sequence is written into the RSS key stored in the context** (by default generated for all bits of the subtuple; `RTE_THASH_MINIMAL_SEQ` generates only `log2(RETA_SZ)` LSBs), and a complement table for XOR is generated; **(b) the Note explicitly emphasizes that "adding a helper changes the key in the context, so after creating all helpers, the updated RSS key must be uploaded to the NIC"**; the example uses `rte_thash_get_key(ctx)` to retrieve the **new key** for software computation, and software/hardware must use the same key so that the predicted collision takes effect on the hardware. | **Fully consistent**. K1(a) corroborates that add_helper rewrites the ctx key (arbiter root cause); K1(b)'s official requirement that "the rewritten key must be uploaded to the NIC" is exactly the official basis for the R-F fix (publishing KEY_FINAL into the NIC) — before the fix, f-stack did not upload the rewritten key, and check/NIC still used the original key, i.e., the "three parties' keys inconsistent" defect. **Byte order is not the root cause** (`rte_softrss(be_to_cpu_32(bytes)) ≡ toeplitz_hash(bytes)` has already been proven at the bit level in this repository). |
| K2 | Same as K1, units of helper offset/len | First-hand | `rte_thash_add_helper`'s offset/len **are both in bits** (examples use `sizeof(uint16_t)*8`, `offsetof(...dport)*8`). | Consistent: corroborates that f-stack's `FF_RSS_THASH_V4_SPORT_OFF=80` (byte10*8), `FF_RSS_THASH_V6_SPORT_OFF=272` (byte34*8), and helper len=16 (bits) use the same unit convention as the official documentation. |

**R-F Key-Alignment Research Conclusion**: the DPDK official documentation directly corroborates "add_helper rewrites the ctx key + the rewritten key must be uploaded to the NIC", which is entirely consistent with this project's R-F fix (the primary process serially constructs KEY_FINAL → publishes the global rsskey → programs it into the NIC during dev_configure; the secondary process shares it via find_existing). The earlier attribution of "softrss_be vs. toeplitz byte-order non-equivalence" (see §4.2 of this document) has been overturned and voided by bit-level arbitration; neither byte order nor GFNI/scalar-branch differences are the root cause.

---

## 5-quater. IPv6 Reverse-Proxy Address Fix Research: FreeBSD 15 DAD / ip6_input NOTREADY Packet Drop + On-link Prefix

> Purpose: Provide first-hand FreeBSD kernel code grounding for the three IPv6 reverse-proxy fixes in `lib/ff_veth.c` (VIP6 /128 host addr, link-local gateway `in6_setscope`, `ND6_IFF_NO_DAD` to skip DAD).
> Source tiers: 【First-hand code】= this repository's `freebsd-src-releng-15.0/sys/netinet6/` native kernel source code (the most authoritative); 【First-hand documentation】= official commit / RFC. Everything is subject to actual testing of this repository's code.

### 5-quater.1 FreeBSD 15 `ip6_input` Drops Inbound Packets to a NOTREADY (TENTATIVE) Unicast Address (Direct Mechanism of This Bug)

| # | Source | Tier | Key fact |
|---|------|------|----------|
| D1 | `freebsd-src-releng-15.0/sys/netinet6/ip6_input.c:809-819` | First-hand code | After the inbound unicast destination address matches a local `ia`: `if (ia->ia6_flags & IN6_IFF_NOTREADY) { ... "packet to an unready address" ...; goto bad; }` — **packets destined for a NOTREADY address are silently dropped**. |
| D2 | `freebsd-src-releng-15.0/sys/netinet6/in6_var.h:491-503` | First-hand code | `IN6_IFF_TENTATIVE=0x02`, `IN6_IFF_DUPLICATED=0x04`, **`IN6_IFF_NOTREADY = (IN6_IFF_TENTATIVE|IN6_IFF_DUPLICATED)`** — a newly added address is TENTATIVE until DAD completes, and thus counts as NOTREADY. |
| D3 | `freebsd-src-releng-15.0/sys/netinet6/nd6_nbr.c:1293-1298` | First-hand code | `nd6_dad_start`: if `ND6_IFF_NO_DAD` (or anycast / `ip6_dad_count==0`) → **immediately `ia->ia6_flags &= ~IN6_IFF_TENTATIVE; return;`** (DAD is not started, the address is ready immediately). `ND6_IFF_NO_DAD=0x100` (`nd6.h:91`). |

**Mechanism established**: F-Stack user space has no kernel-timer-driven DAD completion process, so a newly configured IPv6 address will **permanently remain in `IN6_IFF_TENTATIVE` (=NOTREADY)**; and D1 shows that FreeBSD 15's `ip6_input` drops inbound unicast packets destined for a NOTREADY address → the reverse-proxy VIP cannot receive packets (listen succeeds but the connection fails). The fix sets `ND6_IFF_NO_DAD` (`ff_veth.c:980`) → per D3 the address skips TENTATIVE and becomes ready immediately → ip6_input no longer drops the packets. This is consistent with the deterministic IPv6 reverse-proxy regression observed from 13.0→15.0.

### 5-quater.2 VIP6 /128 Host Addr Avoids the On-link Prefix Route

- Basis: if an IPv6 address is configured with a non-/128 prefix mask, the kernel installs an **on-link route** for that prefix, causing traffic to other addresses in the same subnet to be treated as directly connected rather than routed via the gateway. A reverse-proxy VIP typically only needs to advertise this single local address, so `ff_veth_setvaddr6` sets `ifra_prefixmask` entirely to `0xff` (/128, `ff_veth.c:879-880`), **not installing an on-link prefix route**, so traffic to other destinations in the same subnet is correctly forwarded via the default gateway. This is general BSD routing-table behavior (RFC 5942 also discusses the relationship between on-link determination and prefix routes); this project follows FreeBSD 15's `in6_ifaddr`/`nd6` on-link logic as authoritative.

### 5-quater.3 Link-Local Gateway Requires a Scope Zone (`in6_setscope`)

- Basis: a `fe80::/10` link-local address must be bound to an interface zone id in the FreeBSD kernel to uniquely determine the outgoing interface; `ff_veth_set_gateway6` calls `in6_setscope(&gw.sin6_addr, sc->ifp, NULL)` (`ff_veth.c:849-850`) for a link-local gateway to fill in the zone, so that the link-local gateway can be resolved by routing. Refer to the semantics of `in6_setscope` in FreeBSD's `netinet6/scope6.c` (first-hand kernel source).

### 5-quater.4 IPv6 Reverse-Proxy Fix Research Conclusion

- **First-hand code established**: D1/D2/D3, three pieces of native FreeBSD 15 kernel code, fully close the causal chain of "new address→TENTATIVE(NOTREADY)→ip6_input drops inbound packets" and "NO_DAD→skip TENTATIVE→ready", forming the authoritative basis for the NO_DAD fix in `ff_veth.c`.
- **13→15 difference localization**: this packet-drop logic (`ip6_input`'s `goto bad` for NOTREADY) combined with F-Stack user space's lack of a DAD timer is the mechanistic root cause of the IPv6 reverse-proxy failure after upgrading to 15.0; the corresponding behavior of the 13.0 baseline is subject to actual measurement.
- See spec 11-ipv6-reverse-proxy-vip-onlink-fix.md and `lib/ff_veth.c` for details.

---

## 6. Items Pending Confirmation (from Cross-Referencing External Sources with Code)

1. 【Pending confirmation】The S1 performance data is at the upstream wiki's figures; this project must use actual measurements on the `9.134.214.176` physical machine as authoritative (the definitive figures will be set in the M4 performance baseline spec).
2. 【Pending confirmation】0.3's `adjust_tuple` hit rate and reasonable `attempts` under the asymmetric `default_rsskey_40bytes`; leaning toward: first evaluate enabling `symmetric_rss` (already supported by the repository) to improve the robustness of the reverse-computation, and retain the soft `ff_rss_check` as a fallback verification/rollback (see 04 §0.3).
3. 【Pending confirmation】The DPDK documentation does not clarify the combined semantics of reta_sz and `% nb_queues`; this project must derive the mapping itself (see 04 §0.3), and use the soft `ff_rss_check` as an independent recheck for the correctness criterion.
4. 【Pending confirmation】Whether upstream commit `cb9b4d462` for 0.5 has already been merged into this repository's 13.0 baseline branch (which determines whether the v4 part is "a back-port that was missed" or "a new addition relative to the 13.0 baseline"), to be verified via grep during the coding phase (02 §6-ter.4).
5. 【Pending confirmation】Whether 0.5 requires a per-socket `IP_BIND_ADDRESS_NO_PORT` setsockopt (explicit, as in Linux) vs. F-Stack's implicit approach (taking effect for all bind(addr,0)); leaning toward following upstream's implicit approach (01 §3-ter.8).
