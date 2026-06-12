# 21 · M2 Test Execution Report (ZC-RECV)

> Executed: 2026-06-11. Two machines: server=this host (VM-213-67, data-plane DPDK NIC 9.134.214.176 / MAC 20:90:6f:7d:5d:08, confirmed by actual cloud metadata measurement); client=f-stack-client (VM-211-87, 9.134.211.87, wrk 4.2.0 @ /tmp/wrk/wrk).
> Iron rule: only record actual execution results, do not fabricate data.

## 1. Root Cause and Fix (Critical)
The first round of curl all returned http=000, once misjudged as an "environment issue". After the user corrected it (a plain helloworld tested http=200 normally on the client), actual debugging located the **true root cause**:

- **Incremental compilation pitfall**: a baseline build without any flags was done first (all .o without FSTACK_ZC_SEND), then `FF_ZC_SEND=1 make` was run, but because `uipc_mbuf.c` was unchanged, its .o (06-09 15:48) was newer than the .c and was therefore **skipped and not recompiled by make** → the FSTACK_ZC_SEND kernel hook of `m_uiotombuf` was **missing** (objdump verified the magic `0xf8ac2c00` was not in uipc_mbuf.o).
- Consequence: `ff_zc_send` (the response path, used by both versions A/B) set the magic but the kernel hook did not recognize it → it treated the mbuf chain pointer as a char buffer → the response was corrupted, the connection was unusable → http=000.
- **This also explains why both A(baseline) and B(ZC-recv) failed** (both responses go through ff_zc_send).
- **Fix**: deleted the stale `uipc_mbuf.o` / `sys_generic.o` (via rm_tmp_file.sh), recompiled with `FF_ZC_SEND=1 FF_ZC_RECV=1`; objdump verified uipc_mbuf.o now contains `movabs $0xf8ac2c00f8ac2c00`. Re-linked libfstack.a + rebuilt the server.
- **Build regulation (recorded)**: after changing compile switches such as FF_ZC_*, you **must `make clean` or delete the affected .o before recompiling**, you cannot rely on incremental compilation (make is based on timestamps and is unaware of CFLAGS changes).

## 2. Functional Verification (PASS, after fix)
| Item | Result |
|---|---|
| lib (clean+FF_ZC_SEND=1 FF_ZC_RECV=1) | ✅ -Werror zero errors; uipc_mbuf.o contains ZC-send hook |
| Symbol export | ✅ ff_zc_recv / ff_zc_mbuf_segment / ff_zc_recv_free |
| server B (ZC-recv) startup | ✅ DPDK registration OK |
| **client curl ×5** | ✅ **http=200 size=438** (ff_zc_recv→segment→free full chain + ff_zc_send response all normal) |

## 3. Single-core Performance Baseline A/B (lcore_mask=10 → lcore4, wrk, per the freebsd-13-to-15 methodology T1/T2/T3)
A=baseline (ff_read receive); B=ZC-recv (ff_zc_recv receive); both responses use ff_zc_send, isolating the receive-path difference.

| Tier | wrk parameters | A baseline req/s | B ZC-recv req/s | Δ |
|---|---|---|---|---|
| T1 | -t2 -c10 -d5s | 22,363 | 22,115 | −1.1% (noise) |
| **T2** | -t4 -c100 -d30s | 31,056 / 32,136 / 30,066 (avg **31.1k**) | 39,046(outlier) / 32,219 / 31,987 (avg **32.1k**, outlier removed) | **on par (≤+3%, within noise)** |
| T3 | -t8 -c500 -d30s | 28,615 | 28,317 | −1.0% (saturated) |

> Note: B's first T2=39,046 was confirmed by re-measurement to be a warmup/noise outlier; after 3 re-measurements A≈B.

Latency (T2): A avg 3.71ms / B avg 4.12ms; T3: A 17.87ms / B 18.06ms —— same order of magnitude.
server single-core CPU (T2): 72–84%, **not saturated** → for this load the bottleneck is the client/network, not the server receive copy.

## 4. Performance Conclusion (Honest)
- **Under this small-packet echo load (256B request / 438B response), ZC-recv is on par with ff_read in throughput/latency (within noise)**.
- Reason: for small requests, the `soreceive→uiomove` copy overhead is negligible relative to TCP processing + syscall + scheduling; and f-stack uses UIO_SYSSPACE, so uiomove is itself a same-address-space memcpy (already very cheap).
- The expected benefit of ZC-recv is in **large block data reception / proxy forwarding (forward-on-receive without copy)** scenarios (spec 15/17 §applicable scenarios), which requires a dedicated measurement with a large-payload workload (such as large file download, large body POST); this round's echo load cannot reflect it.
- **Historical limit reference** (same machine same config single-core lcore4, helloworld kqueue, docs/freebsd_13_to_15 13.0-baseline): T2 220,691 / T3 239,555 req/s. This round's main_zc (echo + simulated 10,000 empty loops + ff_zc_send) req/s is far below that kqueue helloworld, because the application model and load differ (main_zc per request includes an artificial busy-loop and ZC response construction), so they cannot be directly compared.

## 5. M2 Acceptance Cross-check (spec 17)
| AC | Status | Notes |
|---|---|---|
| Build/startup | ✅ | -Werror passed after clean recompilation; DPDK registration |
| AC-F1 ff_zc_recv full-chain function | ✅ | curl http=200 size=438 (5/5) |
| AC-F4 plain recv zero regression | ✅ | A(ff_read) likewise http=200 normal |
| AC-P1 single-core performance A/B | ✅ (collected) | on par under small-packet echo; large-payload benefit pending dedicated test |
| AC-M1/M2 memory safety | ⏳ | T1/T2/T3 total ~4 million requests with no crash; precise valgrind/mempool counting pending (valgrind under DPDK runtime is costly) |

## 6. Compliance
- ✅ Stopping processes goes through kill_process.sh; cleaning rtemap/stale .o goes through rm_tmp_file.sh; **fixed a prior violation of misusing `rm -rf`** (now switched to the script).
- ✅ No data fabricated; http=000→root cause→fix→http=200 fully measured; performance outliers truthfully annotated and corrected by re-measurement.
- ✅ The client wrk command was dispatched via ssh (reusing the existing /tmp/wrk/wrk, not reinstalled).

## 7. Follow-up
- AC-M (memory safety precision): large-payload long run + rte_mempool_in_use_count before/after comparison.
- Dedicated large-payload performance test to reflect the ZC-recv design benefit.
