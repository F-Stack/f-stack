# Test Results and Data Analysis

## I. T1 Test (Default Config, Regression Test)

### Config
```ini
[dpdk]
# no extra_eal_args
```

### EAL argv Output
```
f-stack -c1 -n4 --proc-type=primary
```

### TCP Connection
```
[CLIENT] connected to <DPDK_NIC_IP>:15200
[CLIENT] sent 15 bytes: b'hello-csum-test'
[CLIENT] PASS: received 15 bytes echo: b'hello-csum-test'
```

### Conclusion
**PASS** — Under default config, F-Stack starts normally, EAL argv contains no extra parameters (backward compatible), TCP echo correct.

---

## II. T2 Test (--log-level=pmd:8)

### Config
```ini
[dpdk]
extra_eal_args=--log-level=pmd:8
```

### EAL argv Output
```
f-stack -c1 -n4 --proc-type=primary --log-level=pmd:8
```

### Conclusion
**PASS** — `--log-level=pmd:8` successfully appended to EAL argv end; parameter passthrough successful.

---

## III. T3 Test (--allow=0000:00:09.0,scalar_enable=1, devargs Passthrough)

### Config
```ini
[dpdk]
extra_eal_args=--allow=0000:00:09.0,scalar_enable=1
```

### EAL argv Output
```
f-stack -c1 -n4 --proc-type=primary --allow=0000:00:09.0,scalar_enable=1
```

### DPDK Initialization Log
```
EAL: Detected NUMA nodes: 1
EAL: Detected static linkage of DPDK
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
EAL: Selected IOVA mode 'PA'
[SERVER] listening on port 15200 fd=1025
```

### TCP Connection
```
[CLIENT] connected to <DPDK_NIC_IP>:15200
[CLIENT] sent 15 bytes: b'hello-csum-test'
[CLIENT] PASS: received 15 bytes echo: b'hello-csum-test'
```

### Conclusion
**PASS** — devargs `scalar_enable=1` successfully passed through to DPDK EAL via `--allow=<bdf>,<devargs>`. virtio PMD ignored the unsupported `scalar_enable` parameter (no error), device probed normally, TCP echo correct.

---

## IV. --device Parameter Test (Error Format Verification)

### Config
```ini
[dpdk]
extra_eal_args=--device=0000:00:09.0,scalar_enable=1
```

### EAL argv Output
```
f-stack -c1 -n4 --proc-type=primary --device=0000:00:09.0,scalar_enable=1
```

### DPDK Error
```
EAL: Invalid 'command line' arguments.
EAL: Error - exiting with code: 1
Error with EAL initialization
```

### Conclusion
`--device` is not a standard DPDK EAL parameter and is rejected by EAL. This verifies the passthrough mechanism works correctly (parameters are indeed appended to argv), and confirms that the correct DPDK devargs format is `--allow=<bdf>,<devargs>` or `-a <bdf>,<devargs>`.

**Note**: This test proves extra_eal_args is a pure passthrough mechanism with no parameter validation — users must ensure correct parameter format (consistent with DPDK native behavior).

---

## V. Test Summary

| Test | EAL argv Passthrough | TCP Connection | Result |
|------|---------------------|----------------|--------|
| T1 Default | N/A (no extra params) | PASS | PASS |
| T2 --log-level | PASS | N/A | PASS |
| T3 --allow devargs | PASS | PASS | PASS |

All three tests passed; the extra_eal_args generic EAL parameter passthrough mechanism works correctly.
