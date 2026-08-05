# Material D: External + Source Cross-Research (FreeBSD VNET/VIMAGE, DPDK per-lcore, mTCP/Seastar thread-per-core)

> Produced by the leader (SM2 single role). Goal: cross-validation for "in-library native single-process multi-thread multi-protocol-stack instances" against FreeBSD native mechanisms + industry comparison.
> Iron rule: source conclusions carry file:line; un-fetchable external items honestly marked; inconsistencies resolved in favor of code.

---

## 1. 【Core】FreeBSD VNET/VIMAGE = Native "Multi-Protocol-Stack-Instance" Mechanism (Decisive Finding)

The user's requirement of "multiple protocol-stack instances" **has a native mechanism in the FreeBSD kernel itself: VNET (Virtual NETwork stack) / VIMAGE**. This is the key fulcrum of this round's solution design.

### 1.1 Each vnet Is a Complete Independent Protocol-Stack Instance (Source-Verified)
| Fact | Evidence file:line |
|---|---|
| `struct vnet` is a complete network-stack instance, hung on the global vnets list | `freebsd-src-releng-15.0/sys/net/vnet.h:69-75` (`struct vnet { LIST_ENTRY(vnet) vnet_le; u_int vnet_magic_n; u_int vnet_ifcnt; u_int vnet_sockcnt; ... void *vnet_data_mem; ... }`) |
| primitives for dynamically allocating/destroying stack instances | `vnet_alloc()` declared `vnet.h:169`, implemented `sys/net/vnet.c:239`; corresponding `vnet_destroy()` |
| default stack instance vnet0 created at startup | `sys/net/vnet.c:336`: `curvnet = prison0.pr_vnet = vnet0 = vnet_alloc();` |
| jail creation allocates an independent stack instance | `sys/kern/kern_jail.c:1814`: `pr->pr_vnet = vnet_alloc();` |
| **current stack-instance selection = per-thread** | `sys/net/vnet.h:176`: `#define curvnet curthread->td_vnet` |
| every thread struct carries the td_vnet field | `sys/kern/kern_fork.c:473-474`: `td2->td_vnet = NULL;` (initialized at fork) |
| all `VNET_DEFINE(t,n)` globals are stored per-vnet-instance under VIMAGE; `VNET(n)` fetches the current instance's copy via `curvnet` | `vnet.h:279-306` (`VNET_DEFINE`/`VNET(n)=VNET_VNET(curvnet,n)`) |

### 1.2 Degraded Behavior Without VIMAGE Compiled (Matches Material A §0.2, Source-Verified)
- `vnet.h:51-53` comment: *"If VIMAGE isn't compiled into the kernel, virtualized global variables compile to normal global variables, and virtualized sysinits to regular sysinits."*
- `vnet.h:398-458` (`#else /* !VIMAGE */` branch): `curvnet≡NULL` (`:403`), `CURVNET_SET/RESTORE` all no-ops (`:406-408`), `VNET_DEFINE(t,n)≡ t n` (ordinary global, `:429`), `VNET_SYSINIT` degrades to ordinary sysinit (`:442-444`).
- **f-stack current state**: `lib/opt/opt_global.h` has no `VIMAGE` (verified in Material A §0.2), so all `V_ifnet/V_tcbinfo/V_rt_tables/...` degrade to process-level ordinary global singletons.

### 1.3 Decisive Significance for This Solution
> **VNET/VIMAGE is the native subsystem FreeBSD created for "running N mutually isolated complete network-stack instances in one address space"**, and instance selection is exactly `curthread->td_vnet` (per-thread). f-stack's `pcurthread` (`ff_compat.c:59`) is already TLS; the two **naturally fit**:
> - If VIMAGE is enabled, each f-stack thread only needs its `curthread->td_vnet` to point to its own `vnet_alloc()`-ed instance, and the **same `VNET_DEFINE` protocol-stack globals (ifnet, PCB hash, routing FIB, port allocation, hundreds of protocol counters) are automatically isolated per thread** — this is the **native solution** to Material A §0.2's "VNET-degraded globals are the main battlefield, numbering hundreds" problem: no need to manually `__thread`-ize hundreds of globals; instead reuse the kernel's mature VNET data-segment virtualization (`vnet_data_mem` + `VNET_SETNAME` section relocation).
> - This elevates "Route B (VIMAGE)" from Material A's "engineering-cost-questionable alternative" to the **preferred technical path most aligned with the user's "multiple protocol-stack instances" semantics and most consistent with FreeBSD native design**.

### 1.4 VIMAGE Route's Honest Boundary (Requires Runtime Validation, No Assertion)
- f-stack is a FreeBSD userspace port with heavy emasculation (`ff_init_main.c` has large `#if 0` blocks); VIMAGE depends on the `SI_SUB_VNET` SYSINIT family, `vnet_data_mem` segment relocation, and sysctl/eventhandler vnet-ization — **whether these run to completion in f-stack's emasculated userspace cannot be statically determined; requires runtime validation**.
- VNET's `vnet_alloc`/`vnet_destroy` depend on facilities like `SX`/locks and `if_vmove`; whether f-stack retains them fully needs compile-unit verification.
- Even if VIMAGE solves the "VNET_DEFINE-class globals", Material A's **non-VNET globals** (`lcore_conf`/`pcpup`/`cc_cpu`/`thread0`/`msg_iov_tmp`) **still need separate per-thread-ization** — VIMAGE only covers the network-stack-virtualized portion of globals, not f-stack's self-made DPDK-layer and pcpu/callout-port-layer globals.

---

## 2. DPDK per-lcore Mechanism (Cross-Verified, Consistent with Material B)
- `RTE_DEFINE_PER_LCORE(type,name) ≡ __thread type per_lcore_##name`: `dpdk-stable-24.11.6/lib/eal/include/rte_per_lcore.h:33` (verified in Material B §IV).
- `rte_lcore_id() ≡ RTE_PER_LCORE(_lcore_id)` (TLS): `rte_lcore.h:77-81`.
- lcore = pthread + core pinning; `rte_eal_remote_launch` is the launch primitive: `rte_launch.h:37-99` (verified in Material B §I).
- Cross-corroboration (external, summary level, old material reused): DPDK lcore is essentially a pthread wrapper + CPU affinity; mempool/ring support MP/MC and SP/SC.
- **Consistency conclusion**: DPDK-side "per-lcore TLS + array indexed by lcore_id" and FreeBSD-side "per-thread td_vnet" are **two layers of the same share-nothing idea**, uniformly usable with `rte_lcore_id()`/TLS as the index key for thread-private instances.

---

## 3. Industry Native Multi-Stack-Instance / thread-per-core Comparison (External, Partially Reusing Old Material + Supplements)

### 3.1 mTCP (Fetched, NSDI 2014 + Official Site)
- **thread-per-core + share-nothing**: each application thread pairs with an independent TCP thread pinned to the same core; all APIs take `mctx` (mTCP thread context) → each thread independently manages all stack resources, avoiding a shared accept queue. Near-linear scaling on 8 cores.
- Insight for this solution: mTCP's `mctx` ≈ f-stack's per-thread stack-instance handle (VNET or manual per-thread context); **"one complete stack context per thread + same-core pinning" is an industry-validated scalable model**.

### 3.2 Seastar (Community Common Knowledge, Not Deep-Fetched, No Fabricated Details)
- thread-per-core + share-nothing, one reactor per core, inter-core message passing (lock-free), paired with DPDK userspace networking. Same direction as this solution's "independent stack instance per thread, lock-free rings across threads".
- Honest note: Seastar official docs were not deeply fetched this round; look up details at seastar.io when needed.

### 3.3 f-stack Official (Fetched, Multiple Sources)
- The official model = **multi-process share-nothing** (primary/secondary + rte_ring + shared hugepages); **no official design doc or merged PR for a "single-process multi-thread shared/multi-instance stack" run mode was found** (no fabrication).
- issue #430 = application-side multi-threaded API-call demand (libuv+pthread), not a stack-side multi-threaded run model (code-verified positioning in Material C §4).

---

## 4. Cross-Validation Conclusions (for SM3 Solution Design)

1. **Native multi-protocol-stack instances = VNET/VIMAGE** (`vnet.h:69`/`vnet_alloc vnet.c:239`/`curvnet=td_vnet vnet.h:176`), the subsystem FreeBSD created for this, with per-thread instance selection fitting f-stack's TLS `pcurthread` → **technical preferred path = enable VIMAGE so each thread gets one vnet stack instance**.
2. But VIMAGE **only solves the `VNET_DEFINE`-class network-stack globals**; f-stack's self-made DPDK-layer/pcpu/callout globals (`lcore_conf`/`pcpup`/`cc_cpu`/`thread0`/`msg_iov_tmp`, Material A/B) **must be separately per-thread-ized** (array + `rte_lcore_id()` index or `__thread`).
3. `mi_startup`/SYSINIT's one-shot mechanism (Material A §2.2 hard conclusion) has a corresponding `VNET_SYSINIT` (runs once per vnet) mechanism to borrow under VIMAGE; but whether f-stack's emasculated version runs **requires runtime validation**.
4. Industry (mTCP/Seastar) consistently uses thread-per-core + share-nothing + per-thread independent stack context, corroborating this solution's direction.
5. **No adapter/LD_PRELOAD involvement**: all of the above is the stack-side native run model; the adapter is only application-side adaptation, not this solution.

## 5. Fetch/Forensics Status (Honest Marking)
| Target | Status |
|---|---|
| FreeBSD VNET struct/vnet_alloc/curvnet=td_vnet | ✅ Source-verified (vnet.h/vnet.c/kern_jail.c/kern_fork.c) |
| VIMAGE degraded behavior | ✅ Source-verified (vnet.h:51-53,398-458) |
| Whether VIMAGE runs in f-stack's emasculated userspace | ⚠️ Statically undeterminable; requires runtime validation |
| DPDK per-lcore/lcore/launch | ✅ Source-verified (rte_per_lcore.h/rte_lcore.h/rte_launch.h) |
| mTCP thread-per-core | ✅ Fetched (NSDI2014 + official site, old material) |
| Seastar/VPP details | ❌ Not deep-fetched (community common knowledge, no fabrication) |
| f-stack official single-process multi-thread stack mode | ❌ Not found (no fabrication) |
