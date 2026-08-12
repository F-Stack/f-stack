# 02 — Test Results and Data Analysis

## I. Bug Reproduction Results

### 1.1 Basic Functionality Verification (5 rules)

```
$ tools/sbin/ipfw -P 0 flush
Flushed all rules.

$ tools/sbin/ipfw -P 0 add 100 allow ip from any to any
00100 allow ip from any to any

$ tools/sbin/ipfw -P 0 list
00100 allow ip from any to any
65535 count ip from any to any not // orphaned dynamic states counter
65535 allow ip from any to any
```

**Conclusion**: With a small number of rules, ff_ipfw works normally. The list output includes user rules + 2 default rules (65535 count + 65535 allow).

### 1.2 Binary Search for Breaking Point

| User Rules | Total Rules (including defaults) | list Result | Error |
|-----------|--------------------------------|-------------|-------|
| 100 | 102 | Success (102 lines) | 0 |
| 150 | 152 | Success (152 lines) | 0 |
| 200 | 202 | Success (202 lines) | 0 |
| 250 | 252 | Success (252 lines) | 0 |
| 251 | 253 | Success (253 lines) | 0 |
| **252** | **254** | **Failed** | **EINVAL** |
| 260 | 262 | Failed | EINVAL |
| 300 | 302 | Failed | EINVAL |
| 500 | 502 | Failed | EINVAL |

### 1.3 Exact Breaking Point

**252 user rules (+2 defaults = 254 total)** is the exact breaking point.

### 1.4 Failure Error Message

```
$ tools/sbin/ipfw -P 0 list
ipfw: retrieving config failed: Invalid argument
```

"Invalid argument" = EINVAL, from `tools/ipfw/compat.c:61`'s `errno = EINVAL`.

### 1.5 Per-Rule Binary Size Estimation

- Available buffer size ≈ 10112 bytes (MAX_MSG_BUF_SIZE - sizeof(struct ff_msg))
- Minus overhead: sizeof(struct ff_ipfw_args) + sizeof(socklen_t) ≈ 40 bytes
- Available for rule data: ≈ 10072 bytes
- 253 rules pass, 254 rules fail
- **Each rule is approximately 39.8 bytes in binary**

### 1.6 helloworld Log Check

During reproduction, checked helloworld primary process logs; no EAL allocation errors. EINVAL failure occurs on the secondary process (ff_ipfw tool) side; the primary process did not receive the oversized request.

## II. Fix Verification Results

### 2.1 252 Rules (Original Breaking Point)

```
$ tools/sbin/ipfw -P 0 list
01000 allow tcp from any to any
01001 allow tcp from any to any
...
01251 allow tcp from any to any
65535 count ip from any to any not // orphaned dynamic states counter
65535 allow ip from any to any
```

- Total lines: 254
- Errors: 0
- **Fix successful**

### 2.2 500 Rules

```
$ tools/sbin/ipfw -P 0 list
01000 allow tcp from any to any
...
01499 allow tcp from any to any
65535 count ip from any to any not // orphaned dynamic states counter
65535 allow ip from any to any
```

- Total lines: 502
- Errors: 0
- **Fix successful** (original issue #535 reported 400+ scenario)

### 2.3 1000 Rules

- Total lines: 1002
- Errors: 0
- **Fix successful**

## III. Performance Regression Results

### 3.1 Test Configuration

- lcore_mask=10 (1 core, CPU#4)
- idle_sleep=20
- wrk: t4 c100 d30s --latency

### 3.2 Result Data

| Test | Requests/sec | p50 | p99 | Transfer |
|------|-------------|-----|-----|----------|
| T1 warmup (t2c10 d5s) | 28,840 | 352us | 432us | 91.04MB |
| T2 Trial 1 (t4c100 d30s) | **192,933** | 491us | 757us | 3.50GB |
| T2 Trial 2 (t4c100 d30s) | **193,140** | 491us | 776us | 3.50GB |
| **T2 median** | **193,036** | 491us | **767us** | — |

### 3.3 Baseline Comparison

| Metric | This Run (after #535 fix) | Baseline (after #331 fix) | Deviation |
|--------|--------------------------|---------------------------|-----------|
| T2 median req/s | 193,036 | 193,405 | -0.19% |
| T2 median p99 | 767us | 762us | +0.66% |

### 3.4 Conclusion

- Throughput deviation -0.19%, far below the 6-10% cross-day noise range documented in the baseline report
- p99 latency deviation +0.66%, within noise range
- **Fix has zero performance impact** (as expected: only modified `tools/ipfw/compat.c` tool layer, does not affect lib/ data-plane hot path)
