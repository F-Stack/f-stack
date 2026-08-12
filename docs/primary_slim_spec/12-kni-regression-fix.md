# 12. KNI Regression Fix: primary_slim=0 owner_proc_id Breaks KNI

## I. Problem Symptom

Issue #1078's new primary_slim feature introduced KNI regression:

- `primary_slim=0` (slimming not enabled), `[kni] enable=1, owner_proc_id=1`
- Start helloworld, run `dkdns_ospf.sh` to configure veth0 IP and routes
- Ping DPDK NIC IP from f-stack-client fails (both CVM and physical machine)

## II. Root Cause Analysis

### 2.1 Regression-Introducing Commit

`1c28aaa2d` (issue #1078 M1) changed two KNI call conditions in `lib/ff_dpdk_if.c` from `ff_kni_is_owner_thread()` to `ff_kni_is_runtime_owner()`:

- `ff_dpdk_if.c:2186` — KNI packet clone in `process_packets()`
- `ff_dpdk_if.c:2906` — `ff_kni_process()` call in `main_loop()`

### 2.2 Semantic Difference Between Two Functions

```c
/* ff_kni_is_owner_thread() — traditional: non-thread_mode only primary is owner */
int ff_kni_is_owner_thread(void) {
    if (ff_global_cfg.dpdk.thread_mode)
        return rte_lcore_id() == ff_global_cfg.dpdk.proc_lcore[0];
    return rte_eal_process_type() == RTE_PROC_PRIMARY;
}

/* ff_kni_is_runtime_owner() — #1078 new: match by owner_proc_id */
int ff_kni_is_runtime_owner(void) {
    if (ff_global_cfg.dpdk.thread_mode)
        return rte_lcore_id() == ff_global_cfg.dpdk.proc_lcore[0];
    return ff_global_cfg.dpdk.proc_id == ff_global_cfg.kni.owner_proc_id;
}
```

### 2.3 Regression Mechanism

With `primary_slim=0` + `owner_proc_id=1`:

| Scenario | proc_id | ff_kni_is_runtime_owner() | Result |
|----------|---------|---------------------------|--------|
| Single process | 0 | `0 == 1` → false | KNI never executes → fails |
| Multi-process secondary | 1 | `1 == 1` → true | KNI by secondary, but vdev/ring creation still primary-only → half-initialized → fails |
| Multi-process primary | 0 | `0 == 1` → false | KNI not by primary → fails |

While `ff_kni_is_owner_thread()` always returns `RTE_PROC_PRIMARY` for non-thread_mode — the traditional pre-#1078 behavior.

### 2.4 Complete Call Point List

`ff_kni_is_runtime_owner()` has 4 call points (code-explorer sub-agent full trace confirmed):

| # | File:Line | Function | Context | After Fix |
|---|-----------|----------|---------|------------|
| R1 | `ff_dpdk_kni.c:395` | `ff_kni_init()` | `ff_kni_is_owner_thread() \|\| ff_kni_is_runtime_owner()` | primary \|\| primary = primary (redundant but harmless) |
| R2 | `ff_dpdk_kni.c:442` | `ff_kni_alloc()` | Same OR combination | Same |
| R3 | `ff_dpdk_if.c:2186` | `process_packets()` | `enable_kni && ff_kni_is_runtime_owner()` | **Core fix point**: fallback to primary when primary_slim=0 |
| R4 | `ff_dpdk_if.c:2906` | `main_loop()` | Same | **Core fix point**: same |

## III. Fix

### 3.1 Approach Selection

**Option A (minimal intrusion, fix function itself)**: Add `primary_slim=0` short-circuit before `proc_id == owner_proc_id` check in `ff_kni_is_runtime_owner()`.

Selected: Only changes one function, covers all 4 call points (R1~R4), minimal blast radius.

### 3.2 Actual Change

`lib/ff_dpdk_kni.c`, `ff_kni_is_runtime_owner()` function, +2 lines:

```diff
 int
 ff_kni_is_runtime_owner(void)
 {
     if (ff_global_cfg.dpdk.thread_mode)
         return rte_lcore_id() == ff_global_cfg.dpdk.proc_lcore[0];
+    if (!ff_global_cfg.dpdk.primary_slim)
+        return rte_eal_process_type() == RTE_PROC_PRIMARY;
     return ff_global_cfg.dpdk.proc_id == ff_global_cfg.kni.owner_proc_id;
 }
```

### 3.3 Semantic Explanation

After fix:
```
thread_mode=1 → lcore check (unchanged)
thread_mode=0, primary_slim=0 → primary check (restores pre-#1078 behavior)
thread_mode=0, primary_slim=1 → proc_id == owner_proc_id (#1078 new behavior, unchanged)
```

Core idea: `owner_proc_id` only makes sense when `primary_slim=1` (let secondary take over KNI); when `primary_slim=0`, should ignore `owner_proc_id`, KNI handled by primary.

## IV. Compilation Verification

- `make clean` + `make` (f-stack/lib/) clean build passed
- `libfstack.a` generated successfully
- helloworld example compiled and linked successfully

## V. Regression Test

### 5.1 Test Environment

| Item | Value |
|------|-------|
| Test program | `example/helloworld` (HTTP keep-alive, port 80) |
| Config | `primary_slim=0` (commented/default), `[kni] enable=1, method=reject, owner_proc_id=1` |
| DPDK port | 1, exclusive NIC (virtio, `igb_uio`) |
| Server | `<DPDK_NIC_IP>:80` |
| Client | `f-stack-client` (`<CLIENT_IP>`) |

### 5.2 Test Results

**Ping test (f-stack-client → DPDK NIC IP)**:
```
PING <DPDK_NIC_IP> (<DPDK_NIC_IP>) 56(84) bytes of data.
64 bytes from <DPDK_NIC_IP>: icmp_seq=1 ttl=64 time=1.11 ms
64 bytes from <DPDK_NIC_IP>: icmp_seq=2 ttl=64 time=0.281 ms
64 bytes from <DPDK_NIC_IP>: icmp_seq=3 ttl=64 time=0.252 ms

--- <DPDK_NIC_IP> ping statistics ---
3 packets transmitted, 3 received, 0% packet loss
```

**Conclusion**: KNI regression fix verified. With `primary_slim=0` + `owner_proc_id=1`, KNI path restored; ICMP packets flow f-stack-client → DPDK NIC → f-stack stack → KNI veth0 → kernel stack normally.

## VI. Zero Regression Guarantee

- `primary_slim=0` (default): `ff_kni_is_runtime_owner()` degrades to `ff_kni_is_owner_thread()` semantics, restores pre-#1078 behavior
- `primary_slim=1`: `ff_kni_is_runtime_owner()` behavior unchanged, still matches by `owner_proc_id`
- `thread_mode=1`: Unaffected (lcore check first)
- Zero performance impact: Added one O(1) `if` branch

## VII. Traceability

- **Regression-introducing commit**: `1c28aaa2d` (issue #1078 M1)
- **Fix commit**: see git log
- **Modified file**: `lib/ff_dpdk_kni.c` (`ff_kni_is_runtime_owner()` function, +2 lines)
- **Verification**: clean build PASS + hands-on ping test PASS
