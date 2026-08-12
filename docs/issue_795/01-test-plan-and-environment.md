# Test Plan and Environment

## I. Test Environment

| Item | Config |
|------|--------|
| Server | Physical machine + DPDK 24.11.6 |
| DPDK NIC | virtio PCI 0000:00:09.0, IP <DPDK_NIC_IP> |
| Client | f-stack-client (ssh connection), eth1 interface |
| Test program | `example/csum_test_server` (TCP echo, port 15200) |
| Client script | `example/csum_test_client.py` |
| Config file | `/data/workspace/config.ini` (for testing, not committed) |

## II. Test Matrix

| Test | Config | Verification Points | Expected |
|------|--------|---------------------|----------|
| T1 | Default (no extra_eal_args) | F-Stack startup + EAL argv without extra params + TCP connection | Normal (regression) |
| T2 | `extra_eal_args=--log-level=pmd:8` | EAL argv contains this parameter | Parameter passthrough success |
| T3 | `extra_eal_args=--allow=0000:00:09.0,scalar_enable=1` | EAL argv contains this parameter + devargs passthrough + TCP connection | Parameter passthrough success |

## III. Verification Method

1. **EAL argv verification**: `printf` in `dpdk_args_setup()` prints final argv (`lib/ff_config.c:1303-1305`), check `f-stack ...` line in log.
2. **TCP connection verification**: Run `csum_test_client.py` from f-stack-client, verify echo.
3. **DPDK initialization verification**: Check `Port 0 Link Up` and `Successed to register dpdk interface` in `f-stack-0.log`.

## IV. Test Programs

Reuses issue #520's `csum_test_server.c` (TCP echo server) and `csum_test_client.py` (TCP client), already verified working.

### Startup Command
```bash
cd /data/workspace/f-stack/example
./csum_test_server --conf=/data/workspace/config.ini --proc-type=primary --proc-id=0
```

### Client Command (f-stack-client)
```bash
python3 /tmp/csum_test_client.py <DPDK_NIC_IP> 15200
```

## V. config.ini Test Value Handling

- During testing, add `extra_eal_args=xxx` to `/data/workspace/config.ini` (workspace root, not in repository)
- After testing, remove the line with `sed` to restore default config
- Repository `config.ini` only adds comments (commented out by default), no local test values
