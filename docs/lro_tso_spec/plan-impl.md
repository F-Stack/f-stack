# f-stack Software LRO Implementation and Testing plan.md

> Status: Complete | Generated: 2026-07-22 | Physical machine test: 2026-07-23 | Per spec: 11/12/13

## I. Objectives

Per spec documents (11-software-lro-solution/12-software-tso-and-segmentation-solution/13-software-hardware-offload-integration) implement user-space protocol stack software LRO: hardware preferred, fallback to software LRO when hardware unsupported (local virtio). Software TSO confirmed by spec as protocol stack inherent MSS segmentation, no development needed.

## II. Core Design Decisions (Gate Passed)

1. **Switch Option A**: Single `lro` switch auto-select, `sw_lro` included in `ff_hw_features`, strictly mutually exclusive with `rx_lro` (`rx_lro & sw_lro == 0` always holds)
2. **1261 Avoidance Option A**: Classic mode (`tcp_lro_init`+`tcp_lro_rx`+`tcp_lro_flush_inactive`+`tcp_lro_free`) naturally doesn't contain `tcp_lro.c:1261` bare-call to NULL `tcp_hpts_softclock`
3. **Software TSO no development needed**: Protocol stack MSS segmentation inherent (`tcp_output.c:558` `tso` requires `TF_TSO`, NIC without TSO→`TF_TSO` not set→send segment by segment)
4. **Zero regression**: When `lro=0`, all new branches unreachable

## III. Milestones (SM1-SM5)

### SM1: sw_lro field and derivation
- Add `uint8_t sw_lro;` after `ff_config.h:117`
- Add `pconf->hw_features.sw_lro=1` + log in `ff_dpdk_if.c:901-903` else branch

### SM2: Software LRO integration into ff_veth_input
- Add `struct lro_ctrl lro;` after `ff_memory.h:64` (handle tcp_lro.h type visibility)
- `ff_dpdk_if.c:233-251` ff_dpdk_register_if: when sw_lro, `tcp_lro_init` + set ifp
- `ff_dpdk_if.c:325-329` ff_dpdk_deregister_if: when sw_lro, `tcp_lro_free`
- `ff_dpdk_if.c:1753` ff_veth_input: insert `tcp_lro_rx` (ctx parameter remove const)
- `ff_dpdk_if.c:2676` main_loop end of each round: `tcp_lro_flush_inactive`
- process_packets/process_dispatch_ring ctx parameter remove const

### SM3: IFCAP_LRO condition extension + 1261 avoidance verification
- `ff_veth.c:945` `if(rx_lro)` → `if(rx_lro || sw_lro)`
- Statically confirm classic mode path doesn't contain 1261 bare-call

### SM4: Testing
- Unit tests: sw_lro derivation/mutual exclusion/IFCAP (tests/unit/test_ff_dpdk_if.c)
- Integration tests: local virtio lro=1 software fallback + IPv4/IPv6 HTTP 200 + no crash

### SM5: Independent gate + commit
- code-explorer sub-agent independent review (write/review separation)
- git commit English 1-3 sentences, config.ini not committed

## IV. Key Code Locations (file:line verified)

> Note: Line numbers in the table below are planning-phase values; after implementation, some line numbers shifted due to new code (e.g., IFCAP_LRO `:945`→`:984`, ff_veth_input `:1706`→`:1717`); use latest code as authoritative.

| Modification Point | File:Line | Description |
|--------|---------|------|
| sw_lro field | ff_config.h:112-118 | ff_hw_features add uint8_t sw_lro |
| LRO detection block | ff_dpdk_if.c:891-906 | else branch add sw_lro=1 |
| lro_ctrl field | ff_memory.h:60-68 | ff_dpdk_if_context add struct lro_ctrl lro |
| lro init | ff_dpdk_if.c:233-251 | ff_dpdk_register_if |
| lro free | ff_dpdk_if.c:325-329 | ff_dpdk_deregister_if |
| rx integration | ff_dpdk_if.c:1706-1754 | ff_veth_input before :1753 |
| flush timing | ff_dpdk_if.c:2648-2687 | main_loop end of each round |
| IFCAP_LRO | ff_veth.c:945-947 | extend rx_lro\|\|sw_lro |
| tcp_lro API | tcp_lro.h:215-222 | init/rx/flush_inactive/free |

## V. Agent Team Division (Write/Review Separation)

- **leader** (this agent): Coordination + SM1-SM4 coding + test execution + spec document update
- **code-explorer** (sub-agent): SM5 independent gate review (strict write/review separation with leader)

## VI. Conventions (Zero Tolerance)

- rm→rm_tmp_file.sh, kill→kill_process.sh, chmod→chmod_modify.sh
- lib minimal comments, commit English 1-3 sentences, config.ini local values not committed
- make clean before make for code changes
- Write/review separation iron rule, bounce≤3, leader doesn't exit early

## VII. Completion Status (2026-07-23)

- **Implementation**: commit `8e320eeee` (software LRO main body) + `e6d64d266` (NULL timeout fix), gate review passed.
- **Physical machine test**: 2026-07-23 complete, no issues for now. Software LRO fallback path (`sw_lro=1`) IPv4/IPv6 normal, 1261 avoidance effective, `lro=0` zero regression.
- **Pending**: Physical machine NIC also doesn't support hardware LRO (virtio class), hardware LRO end-to-end aggregated receive path (`rx_lro=1` branch / `IT-SWLRO-13` hardware branch / `HB-1`) has no runtime evidence to date, requires replacement with a physical NIC supporting `RTE_ETH_RX_OFFLOAD_TCP_LRO` to verify. See `00` final status, `02` §6.5, `07` §8.2.
