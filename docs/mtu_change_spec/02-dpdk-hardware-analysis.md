# DPDK Hardware Layer Analysis: Port / mbuf / rxmode Config Gaps

> This document analyzes f-stack's current MTU/jumbo-related implementation at the DPDK port init/config stage. All references are actual code `file:line` (`lib/ff_dpdk_if.c`, DPDK 24.11.6).

## 1. No rte_eth_dev_set_mtu Call

Full-text search of `lib/ff_dpdk_if.c` for `mtu` / `rte_eth_dev_set_mtu` / `max_rx_pkt_len` / `jumbo` / `RTE_ETHER_MTU`: **0 matches** (only matches `rte_pktmbuf_pool_create`, `rte_eth_dev_configure`, `rxmode.offloads` and other MTU-unrelated items).

Conclusion: **f-stack never calls `rte_eth_dev_set_mtu`**; port MTU is always the PMD default (standard Ethernet 1500), and the protocol-stack `if_mtu` software value has **no linkage** to the hardware MTU.

## 2. mbuf Pool Created at Standard Frame Size

`lib/ff_dpdk_if.c`:
```c
425:        if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
426:            snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
427:            pktmbuf_pool[socketid] =
428:                rte_pktmbuf_pool_create(s, nb_mbuf,
429:                    MEMPOOL_CACHE_SIZE, 0,
430:                    RTE_MBUF_DEFAULT_BUF_SIZE, socketid);   // 2048B per mbuf data area
431:        } else {
432:            ... rte_mempool_lookup(s);   // secondary reuses
433:        }
```

- `RTE_MBUF_DEFAULT_BUF_SIZE = 2048` (DPDK definition = `RTE_PKTMBUF_HEADROOM(128) + 1920`, actual usable data area ~1920B).
- Sufficient for standard Ethernet frames (1500 + 14 header + FCS/overhead), but **far insufficient for jumbo frames (9000+)**.
- No `data_room_size` enlargement by large MTU, no scatter receive enabled, so a single mbuf cannot hold a jumbo frame.

## 3. Port rxmode Has No jumbo / max_rx_pkt_len Config

`lib/ff_dpdk_if.c` port config section (around L700-923), `port_conf.rxmode` settings:
```c
733:      port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;          // RSS
781-782:  ... RTE_ETH_RX_OFFLOAD_VLAN_STRIP                       // VLAN strip
787:      port_conf.rxmode.offloads &= ~RTE_ETH_RX_OFFLOAD_KEEP_CRC;
791-793:  ... DEV_RX_OFFLOAD_TCP_LRO                              // LRO (conditional)
799-803:  ... RTE_ETH_RX_OFFLOAD_CHECKSUM                        // checksum
807-809:  ... RTE_ETH_RX_OFFLOAD_TIMESTAMP                       // timestamp
```
```c
856:      ret = rte_eth_dev_configure(port_id, nb_queues, nb_queues, &port_conf);
...
885:          rxq_conf.offloads = port_conf.rxmode.offloads;
886:          ret = rte_eth_rx_queue_setup(port_id, q, nb_rxd, ...);
```

- `rxmode` has **no** `mtu` field set (in DPDK 24.x `rte_eth_dev_configure` uses `port_conf.rxmode.mtu`; f-stack leaves it unset → defaults to `RTE_ETHER_MTU=1500`).
- **No** jumbo-related offload (e.g., `RTE_ETH_RX_OFFLOAD_SCATTER`) for receiving large frame segments.
- Therefore the DPDK port initializes with standard 1500 MTU; the PMD's jumbo send/receive capability is never enabled.

> Note: The local DPDK NIC is virtio; its jumbo/scatter capability is limited by the PMD. Even if f-stack code adds the above config, the PMD and underlying NIC/vSwitch must jointly support jumbo to truly enable it (see `04-external-research.md`).

## 4. External API Has No MTU Item

- `lib/ff_api.h`: search `mtu` = 0 matches, **no external MTU get/set interface**.
- `config.ini`: search `mtu`/`jumbo` = 0 matches, **no MTU config item**.

f-stack neither reads any MTU config at init nor exposes a programming interface for upper layers to set hardware MTU.

## Summary (DPDK Hardware Layer)

| Check Item | Status | Impact |
|---|---|---|
| `rte_eth_dev_set_mtu` | Never called | Software `if_mtu` not propagated to hardware |
| mbuf `data_room_size` | Fixed 2048 (`RTE_MBUF_DEFAULT_BUF_SIZE`) | Cannot hold >~1920B jumbo frames |
| `rxmode.mtu` / jumbo offload | Unset (defaults to 1500) | Port initializes at standard frame |
| scatter (segmented receive) | Not enabled | Single mbuf cannot assemble jumbo frame |
| `config.ini` MTU item / `ff_api` MTU interface | None | No config/programming entry point |

**Conclusion**: The DPDK hardware layer has no MTU wiring or jumbo support whatsoever. Combined with the protocol-stack 1500 upper bound, this forms the "decrease MTU works, increase MTU unsupported" software/hardware gap (see `03-software-hardware-gap-analysis.md`).
