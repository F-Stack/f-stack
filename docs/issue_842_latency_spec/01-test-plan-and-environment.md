# 01 - Test Plan and Environment

## Test Matrix

| Test | Stack | idle_sleep | pkt_tx_delay | delayed_ack | recvspace | Compile | Purpose |
|------|-------|-----------|-------------|-------------|-----------|---------|---------|
| T1 | Kernel | N/A | N/A | N/A | N/A | -O2 | Kernel baseline |
| T2 | F-Stack | 20 | 100 | 1 | 8192 | -O2 | Current config baseline |
| T3 | F-Stack | 0 | 0 | 0 | 1677721 | -O2 | #842 optimized config |
| T4 | F-Stack | 0 | 0 | 0 | 8192 | -O2 | Isolate recvspace |
| T5 | F-Stack | 0 | 0 | 1 | 8192 | -O2 | Isolate delayed_ack |

Each test run 3 times taking median (T2/T5 failed unable to repeat, T4 only 1 run due to time constraints).

## Test Programs

### Python Echo Server (`example/echo_server.py`)

- Binds `0.0.0.0:12373`, sends 1 million timestamp messages after accepting connection
- Each message `str(time.time_ns()) * 200` (~3800 bytes)
- Total data ~3.8GB
- Exception handling (BrokenPipeError/ConnectionResetError)

### Kernel Client (`example/echo_client_kernel.c`)

- Standard Linux socket + epoll(ET) + recv
- Non-blocking socket, epoll_wait for EPOLLOUT (connect complete) → send GET → switch to EPOLLIN
- recv buffer 4096, measures first-to-last latency and total time
- `-O2` compiled

### F-Stack Client (`example/echo_client_fstack.c`)

- ff_socket/ff_connect/ff_kqueue/ff_kevent/ff_recv
- **Uses kqueue native API** instead of ff_epoll (due to ff_epoll EPOLLOUT instability)
- Non-blocking socket, kqueue EVFILT_WRITE (connect complete) → send GET → deregister EVFILT_WRITE
- EVFILT_READ event → ff_recv loop
- `-O2` compiled

## Network Topology

```
f-stack-client (<CLIENT_IP>, eth1)
    ↑
    | TCP connect + recv 1 million messages
    |
Local (dual NIC)
  ├── DPDK NIC (<DPDK_NIC_IP>, igb_uio) ← F-Stack client
  └── eth1 (<KERNEL_NIC_IP>, virtio-pci)  ← Kernel client
```

All three are on the same /21 subnet (<NETWORK_PREFIX>/21), directly reachable.

## F-Stack Configuration (#842 optimized config, for T3)

```ini
[dpdk]
lcore_mask=1
idle_sleep=0
pkt_tx_delay=0
port_list=0

[port0]
addr=<DPDK_NIC_IP>
netmask=255.255.248.0
gateway=<GATEWAY_IP>

[freebsd.sysctl]
net.inet.tcp.sendspace=1677721
net.inet.tcp.recvspace=1677721
net.inet.tcp.delayed_ack=0
```
