# 01 Requirements Specification

## 1. Background and Motivation

f-stack currently supports only the DPDK Primary-Secondary **multi-process** model (one process, one lcore, one stack instance, share-nothing). The user requires in-library **native** support for a new run mode: **multiple threads within a single process, each thread running an independent stack instance** (multi-stack-instance, share-nothing, lock-free).

Requirement source: the multi-process model is inconvenient in some deployment scenarios (process management, shared hugepages and IPC overhead, difficulty integrating into the host application's process); the industry (mTCP/Seastar) commonly adopts the single-process multi-thread model of thread-per-core + share-nothing; issue #430 reflects real users' demand for using f-stack in a pthread multi-threaded environment (application-side evidence).

## 2. Goals (In Scope)

| # | Goal |
|---|---|
| G1 | Natively add the "single-process multi-thread multi-stack-instance" run mode inside `lib/`: one process starts N pthreads (each pinned to one lcore), each running an independent FreeBSD stack instance |
| G2 | Share-nothing, lock-free between instances (data plane splits queues via RSS, cross-thread dispatch uses lock-free rings) |
| G3 | Reuse FreeBSD native VNET/VIMAGE as the isolation foundation for "multi-stack-instance" (preferred technical path) |
| G4 | Per-thread-ize the non-VNET f-stack self-made globals (`lcore_conf`/`pcpup`/`cc_cpu`/`thread0`/`msg_iov_tmp`, etc.) |
| G5 | Config-layer opt-in switch, **mutually exclusive** with the existing multi-process mode and **zero regression** |
| G6 | Keep backward compatibility for existing `ff_api.h` application interfaces |

## 3. Non-Goals (Out of Scope)

| # | Non-Goal |
|---|---|
| N1 | **Do not adopt the LD_PRELOAD adapter / multi-worker route** as the solution (current-state record only) |
| N2 | **Do not adopt "shared single stack + fine-grained locking"** (violates share-nothing; rejected comparison only) |
| N3 | This round does no actual coding or compilation; research + spec only |
| N4 | Do not change existing behavior of the multi-process mode (zero-regression red line) |
| N5 | This round does not generate English-version documents |

## 4. Terminology

| Term | Definition |
|---|---|
| **Stack instance** | A complete, independent FreeBSD userspace network-stack state (ifnet, PCB tables, routing FIB, port allocation, protocol counters, callouts, etc.) |
| **Application-side multi-threading** | An application uses multiple pthreads to call f-stack socket APIs (issue #430 scenario); unrelated to the stack run model |
| **Stack-side multi-threaded run model** | The protocol stack itself runs in a multi-threaded manner, one independent instance per thread (**this round's goal**) |
| **VNET/VIMAGE** | FreeBSD's native virtual network-stack subsystem; N mutually isolated complete network-stack instances can run in one address space |
| **Per-thread-ization** | Transforming a global singleton variable into an independent copy per thread (`__thread` / `RTE_PER_LCORE` / lcore_id-indexed arrays) |
| **share-nothing** | Execution units share no mutable state; lock-free, linear scalability |
| **thread_mode** | The run-mode switch this solution proposes to add (opt-in, off by default) |

## 5. Acceptance Criteria

| # | Acceptance Item |
|---|---|
| A1 | Spec fully covers: global-state inventory, stack-instance init mechanism, architecture solution, DPDK integration, config interface, KNI/IPC ownership, milestones, testing, risks |
| A2 | All key technical assertions carry actual file:line and are consistent with the code (gate spot-check) |
| A3 | Solution focuses on native multi-stack-instance; no "recommend adapter" conclusion residue |
| A4 | Clearly distinguishes application-side multi-threading vs stack-side multi-threaded run model; issue #430 correctly positioned |
| A5 | Multi-process zero-regression argument closed-loop; opt-in switch off by default |
| A6 | Honestly mark items that static analysis cannot conclude and require runtime validation; no speculation |
| A7 (subsequent coding phase) | With thread_mode switch off, multi-process behavior byte-identical; with it on, N threads each start an independent stack instance and send/receive normally (lo 127.0.0.1 kernel-stack comparison + DPDK NIC <DPDK_NIC_IP> tested via f-stack-client) |

## 6. Constraints

- Code is the source of truth; cross-validation conflicts resolved in favor of code; honest boundaries, no speculation.
- Subsequent coding follows: lib minimal comments, run `make clean` before compiling after code changes, commit message in English 1-3 sentences, config.ini local test values not committed, rm/kill/chmod through the scripts.
