# Test Plan and Environment

## Test Environment

| Item | Content |
|------|---------|
| F-Stack version | 1.26 (locally compiled, FreeBSD 15.0 based) |
| DPDK version | 24.11.6 LTS |
| Host type | Physical machine (VM in virtualized environment) |
| DPDK port | 0000:00:09.0 Virtio (igb_uio), IP <DPDK_NIC_IP> |
| Kernel NIC | 0000:00:05.0 Virtio (virtio-pci), eth1, IP <CLIENT_IP> |
| Test client | f-stack-client (<CLIENT_IP>), connected via ssh |
| TCP test port | 15200 |

## Environment Limitations

This machine is a physical machine + DPDK environment (virtio NIC), not VMware ESXi. Cannot directly reproduce the VMware "virtual NIC claims support but does not compute" issue. But can verify:
1. TX checksum offload behavior under default config
2. Software-computed checksum correctness when `tx_csum_offoad_skip=1`
3. New `tx_csum_ip_skip=1` fine-grained control works correctly

virtio NIC does not support TX IP/L4 checksum offload (F-Stack log has no "TX ip checksum offload supported" message); FreeBSD software-computes all checksums.

## Test Matrix

| Test | Config | Verification Method | Expected |
|------|--------|---------------------|----------|
| T1 | Default (skip=0) | TCP connection + tcpdump capture | Connection succeeds, checksums correct |
| T2 | skip=1 | Same | Connection succeeds, checksums correct (software-computed) |
| T3 | ip_skip=1, l4_skip=0 | Same | Connection succeeds, checksums correct (software-computed IP) |

## Test Programs

### F-Stack TCP Echo Server (`csum_test_server.c`)

- Uses F-Stack API: `ff_socket`/`ff_bind`/`ff_listen`/`ff_kqueue`/`ff_kevent`/`ff_accept`/`ff_recv`/`ff_send`
- Listens on port 15200, receives data and echoes it back
- Key: `ff_bind` and `ff_accept` need `(struct linux_sockaddr *)` cast

### Python TCP Client (`csum_test_client.py`)

- Connects to F-Stack server, sends "hello-csum-test" (15 bytes), verifies echo data correctness

### tcpdump Capture

- Execute on f-stack-client: `tcpdump -i eth1 -n -v 'host <DPDK_NIC_IP> and tcp port 15200'`
- Verify IP checksum and TCP checksum of packets sent by F-Stack server are correct
