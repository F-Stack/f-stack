# 03 External Solution Research: User-Space Stacks' "Single API + Kernel-Stack Coexistence / Automatic Dual-Stack / Client-Side Selection"

> **Document ID**: SPEC-KE-03
> **Version**: v6 (native automatic dual-stack coexistence paradigm)
> **Date**: 2026-06-17
> **Status**: Drafting
> **Authoritative full text**: `zh_cn/03-external-research.md`.

> **v6 sync (key points; see `zh_cn/03-external-research.md` for full detail; all low-trust, code is authoritative)**:
> - **F-Stack adapter/syscall README** (https://github.com/F-Stack/f-stack/blob/dev/adapter/syscall/README.md): `FF_KERNEL_EVENT` supports both stacks at once via `fstack_kernel_fd_map[65536]` (bare array, lock-free) — v6 native `ff_native_fd_map` borrows this structure; but hook dual-builds only at the **epoll layer** (socket/listen NOT auto dual-built), so v6's "socket/bind/listen also auto dual-build" is a NEW paradigm to implement and test. "kernel epoll fd leak fix" → native `ff_close` must clean up the `ff_epoll_pairs` host-epoll pairing.
> - **F-Stack GitHub issues/wiki** (https://github.com/F-Stack/f-stack/issues?q=FF_KERNEL_EVENT , https://github.com/F-Stack/f-stack/wiki), **F-Stack site** (https://www.f-stack.org/): corroborate the kernel-bypass + attached-kernel-side-path positioning.
> - **"One logical port, multiple parallel sockets" analogy (low-trust)**: Linux `SO_REUSEPORT` (https://man7.org/linux/man-pages/man7/socket.7.html , https://lwn.net/Articles/542629/) — concept analogy for v6's "one `listen(80)` served by two independent per-stack sockets, a connection belongs to a single stack once established" (server-side only; does NOT apply to client connect data duplexing — see `zh_cn/05 §6` ambiguity).
> **Paradigm note (v6)**: this feature aims at **automatic dual-stack coexistence** — with no marker, build BOTH F-Stack and kernel stacks, dual-drive both, one-listen-many-uses; markers override to single-stack. Do not create a side socket that bypasses F-Stack, do not add a whole-process default-to-kernel switch, do not create a dual API, do not do thread-level selection. Cross-reference = hook `FF_KERNEL_EVENT` (epoll dual-build merge; socket/listen NOT dual-built — v6 native diverges here), reference = nginx `kernel_network_stack`. KNI/packet reinjection is boundary clarification only.

---

## 1. Problem Background

After DPDK takes over the NIC, the kernel no longer sees that NIC's traffic, and local `ping`/`curl`/`ssh` cannot reach services on the user-space stack; conversely, when an application on the user-space stack acts as a **client** to `connect` to a local or external kernel-stack service, it also needs to make explicit "which stack this connection goes to". The industry has two lines of thinking:

- **Approach A (packet reinjection, not adopted here)**: reinject user-space-unconsumed packets into the kernel via KNI/virtio-user/TAP.
- **Approach B (stack selection, adopted here)**: the application **proactively** also creates/listens/connects sockets on the kernel-stack side, selects per-fd whether to use the user-space stack or the kernel stack, and handles both uniformly in the same event loop.

F-Stack's own nginx `kernel_network_stack` and the `FF_KERNEL_EVENT` of `adapter/syscall` both belong to **Approach B**, and its syscall adaptation layer is already in the "**single POSIX API + `SOCK_KERNEL`/`SOCK_FSTACK` markers**" form — this feature **standardizes** it into something usable by any application and completes the config switch and the client direction.

---

## 2. Per-Item External Research

### 2.1 F-Stack LD_PRELOAD (`libff_syscall.so`, the primary reference — single API + markers + transparent takeover)
- **URL (Tencent Cloud: introduction to the F-Stack LD_PRELOAD test version)**: https://cloud.tencent.com/developer/article/2278480
- **URL (F-Stack multi-process/config notes, community)**: https://lovelyping.com/?tag=f-stack
- **Reusable points**:
  - LD_PRELOAD takes over libc's `socket/bind/connect/epoll_*`, etc., so the application **does not need multiple API sets** — the model for "single API + glue auto-adaptation".
  - The adaptation layer decides which stack to use via the `SOCK_FSTACK`/`SOCK_KERNEL` markers on socket `type` (see `02` for the code measurement), defaulting to F-Stack; with `SOCK_KERNEL` it uses the kernel stack.
  - "fstack applications run the same way as ordinary F-Stack applications, including the config file and multi-process (one instance per process)" — corroborates that "multi-process differentiation by different config files, no thread-level selection needed" holds.
- **Limitations/boundaries**: the markers are currently embedded in the syscall adaptation layer semantics, lacking a config-level coexistence switch and systematic documentation of "client connecting to local/external" — exactly what this feature completes.

### 2.2 openEuler gazelle (reference: POSIX transparent takeover + kernel-stack coexistence)
- **URL (official user guide)**: https://docs.openeuler.org/zh/docs/24.03_LTS_SP2/server/network/gazelle/gazelle_user_guide.html
- **URL (architecture analysis)**: https://blog.csdn.net/charmingcj/article/details/144722641
- **URL (source on gitee)**: https://gitee.com/openeuler/gazelle
- **Reusable points**:
  - POSIX takeover: LD_PRELOAD (`liblstack.so`) + `GAZELLE_BIND_PROCNAME`, no code changes — the same paradigm as F-Stack syscall adaptation (single API, application-transparent).
  - `listen_shadow` shadow fd: a dispatch reference for the single-listen, multi-stack-thread case.
  - System prerequisite: `rp_filter=1` is the key sysctl for "traffic really going to user space" — a hint that this feature must document the system prerequisites for stack selection.
- **Explicitly not borrowed**: gazelle's **thread-level selection** (`GAZELLE_THREAD_NAME`). F-Stack is a **multi-process** model; "process default (config.ini) + per-fd markers" already covers the needs, **without introducing thread-level**.
- **Limitations/boundaries**: gazelle's `kni_switch` (rte_kni) and ltran mode are already **deprecated/no longer supported** in newer versions — again corroborating **not using KNI as the solution**.

### 2.3 mTCP / other user-space stacks (counterexample reference: the cost of a dual API)
- **URL (mTCP)**: https://github.com/mtcp-stack/mtcp
- **Notes**: mTCP provides separate `mtcp_socket`/`mtcp_epoll_*`, and the application must **explicitly choose** mTCP or kernel sockets — i.e., a "dual API/dual namespace". This is exactly the form this feature **wants to avoid**; we use "single API + markers", so the application need not be aware of multiple API sets. Kept as a counterexample reference for "why not a dual API".

### 2.4 F-Stack Official (the parent project)
- **URL (GitHub)**: https://github.com/F-Stack/f-stack
- **URL (official site)**: http://f-stack.org/
- **URL (DeepWiki)**: https://deepwiki.com/F-Stack/f-stack
- **URL (Tencent Cloud: common F-Stack config parameters, incl. the `[kni]` section)**: https://cloud.tencent.com/developer/article/1976948
- **Reusable points**: F-Stack provides Posix APIs (Socket/Epoll/Kqueue) and ports the FreeBSD stack; config.ini already has section paradigms like `[kni]` — the coexistence-capability switch can mimic it by adding a section/item.

### 2.5 DPDK Official (boundary clarification, not this feature's solution)
- **URL (DPDK KNI, deprecated/removed)**: https://doc.dpdk.org/guides/prog_guide/kernel_nic_interface.html
- **URL (virtio_user as an exception path)**: https://doc.dpdk.org/guides/howto/virtio_user_as_exception_path.html
- **Notes**: Approach A (packet reinjection), **unrelated to this feature**; `rte_kni` was removed in DPDK 23.11.

---

## 3. Research Conclusions (guidance for v4)

1. **Paradigm correctness**: the F-Stack syscall adaptation layer is already "single API + marker selection + transparent takeover", and gazelle also takes the POSIX transparent-takeover route; mTCP's "dual API" is a counterexample — **reusing and standardizing F-Stack's existing single API + markers, with the two stacks coexisting, is the right choice**. The v3 raw-bypass approach is abandoned.
2. **Client direction is feasible**: selection is fixed by the marker/config **at socket creation time**, and subsequent `connect` (including to local 127.0.0.1/host kernel-stack IP and external kernel-stack services) auto-routes by fd ownership — client-side and server-side selection are two directions of the same mechanism.
3. **Configuration plane**: one **coexistence-capability switch** in config.ini (mimicking the `[kni]` paradigm) suffices for "whether the process may use the kernel side-path"; fine-grained selection is per-fd via markers; multi-process differentiation relies on different config files — **no thread-level selection, no port lists, no whole-process default-to-kernel**.
4. **System prerequisites**: must be documented (e.g., `rp_filter`, address/port conflicts, reachability of local loopback via the kernel stack).

> Cross-validation note: all external information here is annotated with source URLs; on conflict with the F-Stack actual code, the code is authoritative (see `02-current-state-analysis.md`).
