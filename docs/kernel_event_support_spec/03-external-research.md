# 03 External Solution Research: User-Space Stacks' "Single API + Marker-Based Selection / Client-Side Selection / Kernel-Stack Coexistence"

> **Document ID**: SPEC-KE-03
> **Version**: v3 (paradigm-correction rework)
> **Date**: 2026-06-15
> **Status**: Drafting
> **Scope**: Research how other DPDK/user-space protocol-stack programs use a "**single API + marker/config-based selection**" to transparently split application traffic between the user-space stack and the kernel stack, and how they handle "an application acting as a client connecting to local/external kernel services"; extract reusable points and limitations. Every entry carries an **accessible URL**.
> **Paradigm note (v3)**: this feature does **not** create a new `ff_local_*` dual API; instead it reuses and standardizes F-Stack's existing "**single API + `SOCK_KERNEL`/`SOCK_FSTACK` markers + glue auto-adaptation**", plus one **global default-stack switch** in config.ini; it does **not** do thread-level stack selection (the multi-process model distinguishes by different config files). KNI/packet reinjection is boundary clarification only.

---

## 1. Problem Background

After DPDK takes over the NIC, the kernel no longer sees that NIC's traffic, and local `ping`/`curl`/`ssh` cannot access services running on the user-space stack; conversely, when an application on the user-space stack acts as a **client** to `connect` to a local or external kernel-stack service, it also needs to make explicit "which stack this connection goes to". The industry has two lines of thinking:

- **Approach A (packet reinjection, not adopted by this feature)**: reinject the user-space-unconsumed packets into the kernel via KNI/virtio-user/TAP — solving "raw packets back to the kernel".
- **Approach B (stack selection, adopted by this feature)**: the application **proactively** also creates/listens/connects sockets on the kernel-stack side, selecting per-fd whether to go through the user-space stack or the kernel stack, and handling both uniformly in the same event loop.

F-Stack's own nginx `kernel_network_stack` and the `FF_KERNEL_EVENT` of `adapter/syscall` both belong to **Approach B**, and its syscall adaptation layer is already in the "**single POSIX API + `SOCK_KERNEL`/`SOCK_FSTACK` markers**" form — this feature **standardizes** it into something usable by any application, and adds the config.ini default switch and the client direction.

---

## 2. Per-Item External Research

### 2.1 F-Stack LD_PRELOAD (`libff_syscall.so`, the primary v3 reference — single API + markers + transparent takeover)
- **URL (Tencent Cloud: introduction to the F-Stack LD_PRELOAD test version)**: https://cloud.tencent.com/developer/article/2278480
- **URL (F-Stack multi-process/config notes, community)**: https://lovelyping.com/?tag=f-stack
- **Reusable points**:
  - LD_PRELOAD takes over libc's `socket/bind/connect/epoll_*`, etc., so the application **does not need to switch to multiple API sets** — exactly the model for v3's "single API + glue auto-adaptation".
  - The adaptation layer decides which stack to go to using the `SOCK_FSTACK`/`SOCK_KERNEL` markers on socket `type` (see `02` for the code measurement), defaulting to F-Stack; with `SOCK_KERNEL` it goes to the kernel stack.
  - "fstack applications run the same way as ordinary F-Stack applications, including the config file and multi-process (one instance per process)" — corroborates that v3's "**multi-process differentiation by different config files**, no thread-level selection needed" holds.
- **Limitations/boundaries**: the markers are currently embedded in the syscall adaptation layer semantics, lacking a "config.ini global default switch" and systematic documentation of "client connecting to local/external" — exactly what this feature aims to complete.

### 2.2 openEuler gazelle (reference: POSIX transparent takeover + kernel-stack coexistence)
- **URL (official user guide)**: https://docs.openeuler.org/zh/docs/24.03_LTS_SP2/server/network/gazelle/gazelle_user_guide.html
- **URL (architecture analysis)**: https://blog.csdn.net/charmingcj/article/details/144722641
- **URL (source on gitee)**: https://gitee.com/openeuler/gazelle
- **Reusable points**:
  - POSIX takeover: LD_PRELOAD (`liblstack.so`) + `GAZELLE_BIND_PROCNAME`, the application needs no code changes — the same paradigm as F-Stack syscall adaptation (single API, application-transparent).
  - `listen_shadow` shadow fd: a dispatch reference for the single-listen, multi-stack-thread case.
  - System prerequisite: `rp_filter=1` is the key sysctl for "traffic really going to user space" — a hint that this feature must document the system prerequisites for stack selection.
- **Explicitly not borrowed**: gazelle's **thread-level stack selection** (`GAZELLE_THREAD_NAME`: specify which thread goes user-space, the rest go kernel). F-Stack is a **multi-process** model; v3 already covers the needs with "process default (config.ini) + per-fd markers", **without introducing thread-level**.
- **Limitations/boundaries**: gazelle's `kni_switch` (rte_kni) and ltran mode are already **deprecated/no longer supported** in newer versions — again corroborating **not using KNI as the solution**.

### 2.3 mTCP / other user-space stacks (counterexample reference: the cost of a dual API)
- **URL (mTCP)**: https://github.com/mtcp-stack/mtcp
- **Notes**: mTCP provides separate `mtcp_socket`/`mtcp_epoll_*`, and the application must **explicitly choose** mTCP or kernel sockets — i.e., a "dual API/dual namespace". This is exactly the form v3 **wants to avoid** (v2 mistakenly took this path); v3 changes to "single API + markers", so the application need not be aware of multiple API sets. This entry is kept as a counterexample reference for "why not choose a dual API".

### 2.4 F-Stack Official (the parent project)
- **URL (GitHub)**: https://github.com/F-Stack/f-stack
- **URL (official site)**: http://f-stack.org/
- **URL (DeepWiki)**: https://deepwiki.com/F-Stack/f-stack
- **URL (Tencent Cloud: common F-Stack config parameters, including the `[kni]` section)**: https://cloud.tencent.com/developer/article/1976948
- **Reusable points**: F-Stack provides Posix APIs (Socket/Epoll/Kqueue) and ports the FreeBSD stack; config.ini already has section paradigms like `[kni]` — v3's "global default-stack switch" can mimic it by adding a section/item.

### 2.5 DPDK Official (boundary clarification, not this feature's solution)
- **URL (DPDK KNI, deprecated/removed)**: https://doc.dpdk.org/guides/prog_guide/kernel_nic_interface.html
- **URL (virtio_user as an exception path)**: https://doc.dpdk.org/guides/howto/virtio_user_as_exception_path.html
- **Notes**: Approach A (packet reinjection), **unrelated to this feature**; `rte_kni` was removed in DPDK 23.11.

---

## 3. Research Conclusions (guidance for v3)

1. **Paradigm correctness**: the F-Stack syscall adaptation layer is already "single API + marker-based selection + transparent takeover", and gazelle also takes the POSIX transparent-takeover route; mTCP's "dual API" is a counterexample — **v3's reusing and standardizing F-Stack's existing single API + markers is the right choice**, and v2's `ff_local_*` dual API should be abandoned.
2. **Client direction is feasible**: stack selection is fixed by the marker/config **at socket creation time**, and subsequent `connect` (including to local 127.0.0.1/host kernel-stack IP and external kernel-stack services) auto-routes by fd ownership — client-side selection and server-side selection are two directions of the same mechanism.
3. **Configuration plane**: one **global default-stack switch** in config.ini (mimicking the `[kni]` paradigm) suffices for "which stack the process defaults to", with fine-grained override by the app marker; multi-process differentiation relies on different config files — **no thread-level selection, no port lists needed**.
4. **System prerequisites**: must be documented (e.g., `rp_filter`, address/port conflicts, reachability of local loopback via the kernel stack).

> Cross-validation note: all external information in this document is annotated with source URLs; on conflict with the F-Stack actual code, the code is authoritative (see `02-current-state-analysis.md`).
