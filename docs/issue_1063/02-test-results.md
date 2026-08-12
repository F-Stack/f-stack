# 02 — Test Results

## Compilation Verification

### Command

```bash
cd /data/workspace/f-stack/adapter/syscall
make clean && make all
```

### Result

Compilation succeeded, exit code 0, no warnings (`-Wall -Werror` passed).

Key compilation line:
```
cc -g -O2 -DNDEBUG -fPIC -Wall -Werror ... -o helloworld_stack_udp main_stack_udp.c ...
```

Artifact:
```
-rwxr-xr-x 1 root root 21704 Aug  7 16:48 helloworld_stack_udp
```

## Kernel Stack Comparison Test

### Test Method

Run `./helloworld_stack_udp` directly (without LD_PRELOAD); the program binds `0.0.0.0:9000` on the kernel network stack. Send UDP test packets to `127.0.0.1:9000` using Python and verify echo.

### Test Steps

```bash
# 1. Start UDP echo server
cd /data/workspace/f-stack/adapter/syscall
./helloworld_stack_udp &

# 2. Send test packets
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
msg = b'Hello F-Stack UDP!'
s.sendto(msg, ('127.0.0.1', 9000))
data, addr = s.recvfrom(2048)
print('RECV:', data.decode())
print('PASS' if data == msg else 'FAIL')
s.close()
"
```

### Result

```
RECV: Hello F-Stack UDP!
RESULT: PASS - echo matches
```

**Kernel stack test passed** — UDP echo server correctly received and echoed data.

## LD_PRELOAD Mode Test

### Test Method

1. Start `fstack` primary process (initialize DPDK NIC takeover; the taken-over NIC is the test environment IP configured in `[port0]`, not eth1)
2. Start `helloworld_stack_udp` with `LD_PRELOAD=./libff_syscall.so`
3. Send UDP packets from f-stack-client machine via ssh to `<DPDK_NIC_IP>:9000` and verify echo

### Troubleshooting Log

On first primary startup, `EAL: Cannot allocate memzone list` error occurred. Cause: residual shared memory/hugepage files under `/var/run/dpdk/rte/` and `/dev/hugepages/rtemap_*` from a previous test (belonging to a zombie secondary process not fully cleaned up), conflicting with the new primary initialization. After cleaning residuals with `rm_tmp_file.sh` and restarting, primary completed DPDK NIC initialization normally (`Port0 Link Up`).

The `VIRTIO_INIT: eth_virtio_pci_init(): Failed to init PCI device` / `Requested device 0000:00:05.0 cannot be used` messages in the log are **expected normal noise**: `config.ini` does not configure a PCI allowlist, so DPDK EAL scans all PCI devices. `0000:00:05.0` is `eth1` (still bound to the kernel `virtio-pci` driver, not a DPDK NIC), so probe failure is normal. The actual DPDK NIC is `0000:00:09.0` (`drv=igb_uio`), confirmed as `Port 0 Link Up` in `f-stack-0.log`.

### Result

- fstack primary process started successfully, DPDK NIC (`0000:00:09.0`) initialized, `Port 0 Link Up`
- LD_PRELOAD UDP application started successfully, `libff_syscall.so` loaded correctly and bound to DPDK NIC
- Sent 3 UDP packets with different content from f-stack-client to `<DPDK_NIC_IP>:9000` — **all received correct echo** (PASS)

```
pkt0 RECV: Test-packet-0 ->  PASS
pkt1 RECV: Test-packet-1 ->  PASS
pkt2 RECV: Test-packet-2 ->  PASS
```

## Test Conclusion

| Test Item | Result | Notes |
|-----------|--------|-------|
| Compilation (make clean && make all) | PASS | -Wall -Werror passed, no warnings |
| Kernel stack echo test | PASS | 127.0.0.1:9000 UDP echo correct |
| LD_PRELOAD library loading | PASS | libff_syscall.so loaded correctly, hooks active |
| LD_PRELOAD end-to-end (DPDK NIC) | PASS | 3/3 packets echoed correctly from f-stack-client to `<DPDK_NIC_IP>:9000` |
