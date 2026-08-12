# 02 - Architecture Code Investigation Report

> f-stack issue #1076: FreeBSD native CC (Concurrent Connections) limiting mechanism code completeness investigation
> Investigation scope: `/data/workspace/f-stack/`
> Investigation method: Read-only code analysis, no files modified
> Code baseline: FreeBSD 15.0-based f-stack (including native-mt modifications)

---

## 1. maxsockets (Mechanism A)

### 1.1 Code Path

| Location | Line | Description |
|----------|------|-------------|
| `freebsd/kern/uipc_socket.c` | 314 | `int maxsockets;` global variable definition |
| `freebsd/kern/uipc_socket.c` | 320 | `maxsockets = uma_zone_set_max(socket_zone, maxsockets);` (SYSINIT) |
| `freebsd/kern/uipc_socket.c` | 689 | `maxsockets = uma_zone_set_max(socket_zone, maxsockets);` (socket_init SYSINIT) |
| `freebsd/kern/uipc_socket.c` | 690 | `uma_zone_set_warning(socket_zone, "kern.ipc.maxsockets limit reached");` |
| `freebsd/kern/uipc_socket.c` | 744-750 | `init_maxsockets()` reads `kern.ipc.maxsockets` from tunable |

### 1.2 UMA Zone Max Enforcement Verification

**Conclusion: UMA zone max is truly enforced in f-stack userspace stack.**

Evidence chain:

1. `socreate()` calls `soalloc()` to allocate socket (`uipc_socket.c:948-950`): returns `ENOBUFS` on NULL.
2. `soalloc()` uses `uma_zalloc(socket_zone, M_NOWAIT | M_ZERO)` (`uipc_socket.c:797`).
3. `uma_zalloc` ultimately calls `zone_alloc_item()` (`uma_core.c:4457`), which has explicit max check:
```c
4461: if (zone->uz_max_items > 0 && zone_alloc_limit(zone, 1, flags) == 0) {
4462:     counter_u64_add(zone->uz_fails, 1);
4463:     return (NULL);
4464: }
```
4. `zone_alloc_limit()` (`uma_core.c:4311-4338`) uses `atomic_fetchadd_64` to atomically increment allocated count, compared with `uz_max_items`.
5. `uma_zone_set_max()` (`uma_core.c:4992-5017`) sets `zone->uz_max_items = nitems` and sets `UMA_ZFLAG_LIMIT` flag.

**Therefore: when socket_zone allocation count reaches maxsockets, `uma_zalloc` returns NULL → `soalloc` returns NULL → `socreate` returns `ENOBUFS`. Enforcement chain complete.**

### 1.3 F-stack Configuration Path

F-stack's `config.ini` configures `kern.ipc.maxsockets` via `[freebsd.boot]` section as a boot tunable.

Loading chain:
1. `lib/ff_config.c:171-209` `freebsd_conf_handler()` parses `[freebsd.boot]` section.
2. `lib/ff_freebsd_init.c:286-294` writes each boot config item to kenv via `kern_setenv`.
3. `uipc_socket.c:747` `init_maxsockets()` reads from kenv via `TUNABLE_INT_FETCH`.
4. `uipc_socket.c:689` `socket_init()` SYSINIT applies the limit via `uma_zone_set_max`.

### 1.4 Conclusion

**Fully usable.** maxsockets variable definition, UMA zone max setting, tunable reading, sysctl runtime modification paths all complete. UMA zone max truly enforced in f-stack userspace. Socket allocation returns `ENOBUFS` at limit.

---

## 2. ipfw limit (Mechanism B)

### 2.1 Tool-side Rule Compilation

`tools/ipfw/ipfw2.c` has complete limit rule compilation path:
- `limit_masks[]` (`ipfw2.c:213-220`): supports `all`/`src-addr`/`src-port`/`dst-addr`/`dst-port`
- `O_LIMIT` rule compilation (`ipfw2.c:4867-4894`): `match_token(limit_masks, *av)` + `GET_UINT_ARG`
- F-stack's `ff_ipfw` tool compiles from same-source `ipfw2.c` as FreeBSD native

### 2.2 Kernel-side O_LIMIT Handling

`freebsd/netpfil/ipfw/ip_fw2.c:2937-2948`:
```c
case O_LIMIT:
    if (ipfw_dyn_install_state(chain, f, (ipfw_insn_limit *)cmd, ...)) {
        retval = IP_FW_DENY;  // error or limit violation → deny
    }
```

### 2.3 Dynamic State Tracking Completeness

`freebsd/netpfil/ipfw/ip_fw_dynamic.c` has complete (non-stub) dynamic state tracking:

| Function | Line | Description |
|----------|------|-------------|
| `dyn_alloc_parent()` | 1492-1516 | Allocate limit parent state from `V_dyn_parent_zone` |
| `dyn_alloc_ipv4_state()` | 1546-1564 | Allocate IPv4 dynamic state from `V_dyn_ipv4_zone` |
| `ipfw_dyn_install_state()` | 2025-2050 | Install state entry, distinguish O_LIMIT and O_KEEP_STATE |
| `dyn_tick()` | 2795 | Aging callout callback (every hz) |
| `dyn_expire_states()` | 2282 | State expiration cleanup |

Initialization (`ipfw_dyn_init`, `ip_fw_dynamic.c:3182-3245`):
```c
V_dyn_max = 16384;           /* max # of states */
V_dyn_parent_max = 4096;     /* max # of parent states */
uma_zone_set_max(V_dyn_data_zone, V_dyn_max);
uma_zone_set_max(V_dyn_parent_zone, V_dyn_parent_max);
callout_reset(&V_dyn_timeout, hz, dyn_tick, curvnet);  /* start aging */
```

### 2.4 Limit-Reached Behavior

`ip_fw_dynamic.c:1873-1884`:
```c
if (DPARENT_COUNT(p) >= limit) {
    return (NULL);  // → ipfw_dyn_install_state returns non-zero → IP_FW_DENY
}
```

`DPARENT_COUNT(p)` (`:158`): `#define DPARENT_COUNT(p) ck_pr_load_32(&(p)->count)` — atomic read of parent state's child connection count.

**Limit-reached behavior: returns NULL → `IP_FW_DENY` (packet denied/dropped).**

### 2.5 F-stack Integration Path

Packet path (SYN through ipfw engine):
```
rte_eth_rx_burst() → process_packets() → ff_veth_input() → ether_input → ip_input
  → pfil_mbuf_in() → ipfw_check_packet() → ipfw_chk() → case O_LIMIT → ipfw_dyn_install_state()
```

ff_ipfw tool integration:
- `lib/ff_dpdk_if.c:2258` `handle_ipfw_msg()` handles FF_IPFW_GET/FF_IPFW_SET messages from ff_ipfw tool
- User sets limit rules via `ff_ipfw` command line → ff_ipc message → `handle_ipfw_msg` → `ff_setsockopt_freebsd` → kernel ipfw setsockopt handler → rules written to ipfw chain → subsequent packets hit `O_LIMIT` rule via pfil hook

### 2.6 Conclusion

**Fully usable.** Tool-side limit syntax compilation complete, kernel-side O_LIMIT handling complete, dynamic state tracking (allocation/lookup/insert/aging) complete non-stub. Limit-reached behavior is `IP_FW_DENY`. F-stack integration path complete.

---

## 3. somaxconn (Mechanism C)

### 3.1 Code Path

| Location | Line | Description |
|----------|------|-------------|
| `uipc_socket.c` | 242 | `VNET_DEFINE_STATIC(u_int, somaxconn) = SOMAXCONN;` (default 128) |
| `uipc_socket.c` | 246-267 | `sysctl_somaxconn()` runtime modification |
| `uipc_socket.c` | 1538-1540 | `solisten_proto()` backlog truncation: `if (backlog > V_somaxconn) backlog = V_somaxconn;` |

### 3.2 Queue Full Behavior

**Incomplete queue full** (`uipc_socket.c:1280-1293`): drops oldest entry (`soabort`).

**Complete queue overflow** (`uipc_socket.c:1030`): `over = (head->sol_qlen > 3 * head->sol_qlimit / 2)` — when completed connections exceed 1.5 × sol_qlimit, `sonewconn()` returns NULL.

### 3.3 Conclusion

**Fully usable.** backlog truncation, incomplete queue drop, complete queue 1.5× check all present. Configured via `config.ini [freebsd.sysctl]` runtime.

---

## 4. syncache (Mechanism D)

### 4.1 Code Path

| Location | Line | Description |
|----------|------|-------------|
| `tcp_syncache.c` | 162-163 | Default `TCP_SYNCACHE_HASHSIZE=512`, `TCP_SYNCACHE_BUCKETLIMIT=30` |
| `tcp_syncache.c` | 249-296 | `syncache_init()` — sets defaults from tunables, creates zones, `uma_zone_set_max(zone, hashsize * bucket_limit)` |
| `tcp_syncache.c` | 254-257 | `TUNABLE_INT_FETCH` for hashsize/bucketlimit |

### 4.2 Bucket Full Behavior

`tcp_syncache.c:377-384`:
```c
if (sch->sch_length >= V_tcp_syncache.bucket_limit) {
    syncache_pause(&sc->sc_inc);        // trigger syncookies fallback
    sc2 = TAILQ_LAST(&sch->sch_bucket, sch_head);
    syncache_drop(sc2, sch);            // drop oldest entry
}
```

**Zone exhaustion** (`tcp_syncache.c:1584-1611`): drop oldest + retry → degrade to syncookies (if enabled) or drop SYN.

### 4.3 Conclusion

**Fully usable.** Bucket full drops oldest + syncache_pause. Zone exhaustion degrades to syncookies or drops SYN. Configured via `config.ini [freebsd.boot]` tunables.

---

## 5. mbuf Pool Water Level Check (Mechanism E)

### 5.1 Receive Path Analysis

F-stack receive main loop (`lib/ff_dpdk_if.c:2810-2844`):
```
rte_eth_rx_burst() → process_packets() → protocol_filter() → ff_veth_input()
  → ff_mbuf_gethdr() → ff_veth_process_packet() → if_input → netisr → ip_input → TCP stack
```

**No mbuf pool water level check exists anywhere in the receive path.** Full-path search for `rte_mempool_avail`/`rte_mempool_count` in `lib/ff_dpdk_if.c` yields zero hits.

### 5.2 mbuf Pool Creation and Size Calculation

mbuf pool size formula (`lib/ff_dpdk_if.c:583-593`):
```c
unsigned nb_mbuf = RTE_ALIGN_CEIL(
    nb_rx_queue * (max_portid + 1) * 2 * RX_QUEUE_SIZE +
    nb_ports * (max_portid + 1) * 2 * nb_lcores * MAX_PKT_BURST +
    nb_ports * (max_portid + 1) * 2 * nb_tx_queue * TX_QUEUE_SIZE +
    nb_lcores * MEMPOOL_CACHE_SIZE +
    nb_lcores * nb_ports * DISPATCH_RING_SIZE,
    (unsigned)8192);
```

**Note: This formula is statically calculated and does not consider runtime concurrent connections.**

### 5.3 ff_ipc mbuf Dependency

**ff_ipc does not depend on pktmbuf_pool; uses independent message_pool.**

| Object | Creation Location | Purpose |
|--------|------------------|---------|
| `pktmbuf_pool` | `ff_dpdk_if.c:632` `rte_pktmbuf_pool_create()` | DPDK receive/transmit mbuf pool |
| `message_pool` | `ff_dpdk_if.c:750` `rte_mempool_create(FF_MSG_POOL, ...)` | ff_ipc message communication pool |

**Therefore: pktmbuf_pool exhaustion does not affect ff_ipc communication** (ff_ipc uses independent message_pool). However, if system memory is generally tight, both pools may be affected.

### 5.4 Water Level Check Insertion Points (If f-stack-specific Solution Needed)

**Insertion point 1**: `process_packets()` entry (`ff_dpdk_if.c:2024`) — recommended. Before protocol stack, doesn't affect existing connections. Can check at burst level.

**Insertion point 2**: `ff_veth_input()` entry (`ff_dpdk_if.c:1839`) — knows original mbuf source.

**Insertion point 3**: TCP SYN processing entry — most precise but requires deep TCP stack modification.

**Recommended: Insertion point 1** (`process_packets` entry) with SYN packet early identification.

---

## 6. Summary Table

| Mechanism | Completeness | Usability | Limitation |
|-----------|--------------|-----------|------------|
| **A. maxsockets** | Complete | **Fully usable** | UMA zone max enforcement chain complete (`uma_core.c:4461`). config.ini via `[freebsd.boot]` tunable. No limitations. |
| **B. ipfw limit** | Complete | **Fully usable** | Tool-side compilation complete, kernel-side O_LIMIT handling complete, dynamic state tracking complete non-stub. Limit behavior = `IP_FW_DENY`. No limitations. |
| **C. somaxconn** | Complete | **Fully usable** | Backlog truncation, incomplete queue drop, complete queue 1.5× check. config.ini via `[freebsd.sysctl]`. No limitations. |
| **D. syncache** | Complete | **Fully usable** | Bucket full drops oldest + syncache_pause, zone exhaustion degrades to syncookies. config.ini via `[freebsd.boot]`. No limitations. |
| **E. mbuf water level** | Incomplete | **Not available (no water level check)** | Receive path has no `rte_mempool_avail/count` check. mbuf pool size is static formula. ff_ipc uses independent message_pool. Insertion point identified (`process_packets` entry). |

### Key Findings

1. **Mechanisms A-D are all fully usable** — f-stack's FreeBSD userspace stack retains all native FreeBSD CC limiting mechanisms with complete code paths and unbroken enforcement chains.

2. **Mechanism E (mbuf water level check) is the only missing item** — this is a mechanism FreeBSD native also lacks (FreeBSD kernel relies on mbuf zone max and emergency allocation). If f-stack-specific CC protection is needed, add water level check at `process_packets()` entry.

3. **ff_ipc is not affected by mbuf exhaustion**: ff_ipc uses independent `message_pool` (`FF_MSG_POOL`), different from `pktmbuf_pool`. Even if mbuf pool exhausts, ff_ipc tools (e.g., `ff_ipc netstat`) can still communicate (unless message_pool also exhausts).

4. **config.ini configuration paths are correct**: maxsockets and syncache as boot tunables (`[freebsd.boot]`); somaxconn as runtime sysctl (`[freebsd.sysctl]`).
