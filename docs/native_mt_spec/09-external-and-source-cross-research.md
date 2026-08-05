# 09 External and Source Cross-Research

> Source `_material_D_cross.md` + old `_material_web.md`. Principles: source conclusions carry file:line; external un-fetchable items are honestly marked; conflicts resolved in favor of code.

## 1. FreeBSD VNET/VIMAGE = Native "Multi-Stack-Instance" Mechanism (Decisive)

### 1.1 Source-Verified
| Fact | file:line |
|---|---|
| `struct vnet` is a complete stack instance, hung on the global vnets list | `freebsd-src-releng-15.0/sys/net/vnet.h:69-75` |
| `vnet_alloc()` allocates a stack instance | declared `vnet.h:169`, implemented `sys/net/vnet.c:239` |
| Startup creates the default instance vnet0 | `sys/net/vnet.c:336` (`curvnet=prison0.pr_vnet=vnet0=vnet_alloc()`) |
| Jail creation allocates an independent stack instance | `sys/kern/kern_jail.c:1814` (`pr->pr_vnet=vnet_alloc()`) |
| **Stack-instance selection is per-thread** | `sys/net/vnet.h:176` (`#define curvnet curthread->td_vnet`) |
| thread struct carries td_vnet | `sys/kern/kern_fork.c:473-474` |
| `VNET_DEFINE` globals virtualized by vnet data segment | `vnet.h:279-306` |

### 1.2 Degraded Behavior Without VIMAGE
- `vnet.h:51-53` comment: without VIMAGE, virtualized globals→ordinary globals, virtualized sysinit→ordinary sysinit.
- `vnet.h:398-458` (`!VIMAGE` branch): `curvnet≡NULL`(:403), `CURVNET_SET/RESTORE` no-op(:406-408), `VNET_DEFINE(t,n)≡t n`(:429), `VNET_SYSINIT`→ordinary sysinit(:442-444).
- f-stack's current `opt_global.h` has no VIMAGE (`_material_A §0.2`), so all `V_*` degrade to process-level globals.

### 1.3 External Corroboration
- vimage(9) man page (unix.com): VNET = "list of virtual network stack instances", `VNET_FOREACH` iterates, protected by a read lock.
- vnet(9) (betterman): *"To start or tear down a virtual network stack instance the internal functions vnet_alloc() and vnet_destroy() are provided and called from the jail framework."*

### 1.4 Conclusion
> VNET/VIMAGE is the native subsystem FreeBSD created for "running N isolated complete network-stack instances in one address space"; instance selection = `curthread->td_vnet` (per-thread), matching f-stack's already-TLS `pcurthread`. → **Preferred technical path for native multi-stack-instance**. ⚠️ But VIMAGE availability in f-stack's emasculated userspace **requires runtime validation** (`04 §2`/`11`).

## 2. DPDK per-lcore (Cross-Validated, Consistent with `06`)
- `RTE_DEFINE_PER_LCORE(t,n) ≡ __thread t per_lcore_##n` (`rte_per_lcore.h:33`).
- `rte_lcore_id() ≡ RTE_PER_LCORE(_lcore_id)` (`rte_lcore.h:77-81`, TLS).
- lcore=pthread+core pinning; `rte_eal_remote_launch` launch primitive (`rte_launch.h:37-99`).
- External (old material, summary level): lcore is essentially a pthread wrapper + CPU affinity; mempool/ring support MP/MC and SP/SC.

## 3. Industry thread-per-core Comparison

### 3.1 mTCP (fetched, NSDI 2014 + official site)
- thread-per-core + share-nothing: each application thread pairs with a dedicated TCP thread pinned to the same core; all APIs take `mctx` (thread stack context); avoids a shared accept queue; near-linear scaling on 8 cores.
- Insight: `mctx` ≈ f-stack's per-thread stack-instance handle (VNET/per-thread context); "one complete stack context per thread + same-core pinning" is an industry-validated scalable model.

### 3.2 Seastar / VPP (community common knowledge, not deep-fetched, no fabricated details)
- Seastar: thread-per-core + share-nothing, one reactor per core, lock-free inter-core messaging, paired with DPDK.
- VPP: main + multiple worker threads, RSS/handoff flow splitting, graph-node vector batch processing.
- Honest note: official docs were not deep-fetched this round; look up details separately when needed.

### 3.3 f-stack Official (fetched, multiple sources)
- Official model = multi-process share-nothing (primary/secondary + rte_ring + shared hugepages); **no official "single-process multi-thread stack run mode" design doc or PR found** (no fabrication).

## 4. issue #430 Special Topic (mandatory goal, application-side evidence)
- Metadata + body fetched: incapdns 2019-08-25, libuv+pthread, socket type with `SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC` combined flags hit the old bare comparison and wrongly fell back to socket_raw; status Closed[SOLVED].
- Comment section/maintainer reply/fix commit **not fetched** (GitHub dynamic loading + API 403 rate limiting), honestly marked.
- **Verified against code**: current repo `linux2freebsd_socket_flags` (`ff_syscall_wrapper.c:672-684`) converts NONBLOCK/CLOEXEC; `ff_socket` (`:943`)/`ff_accept4` (`:1679`) go through the same path; combined flag handling is complete.
- **Positioning**: application-side multi-threaded API calls (already ready), a different layer from the stack-side native multi-threaded run model; not this round's conclusion anchor.

## 5. Cross-Validation Conclusions (for the Solution)
1. Native multi-stack-instance = VNET/VIMAGE (preferred path), per-thread matching `pcurthread`.
2. VIMAGE only covers `VNET_DEFINE` network-stack globals; f-stack self-made globals need separate per-thread-ization.
3. DPDK per-lcore/launch/ring/mempool all ready, consistent with `06`.
4. Industry mTCP/Seastar both use thread-per-core + share-nothing, corroborating the direction.
5. No adapter involvement throughout (application-side mechanism, not a stack-side run model).

## 6. Fetch/Forensics Status (Honest Marking)
| Target | Status |
|---|---|
| VNET struct/vnet_alloc/curvnet=td_vnet | ✅ Source-verified |
| VIMAGE degraded behavior | ✅ Source-verified |
| VIMAGE availability in f-stack userspace | ⚠️ Requires runtime validation |
| DPDK per-lcore/launch | ✅ Source-verified |
| mTCP thread-per-core | ✅ Fetched (NSDI2014+official site) |
| Seastar/VPP details | ❌ Not deep-fetched (community common knowledge, no fabrication) |
| f-stack official single-process multi-thread stack mode | ❌ Not found (no fabrication) |
| issue #430 metadata+body | ✅ Fetched |
| issue #430 comment section/fix commit | ❌ Not fetched (code side verified) |
