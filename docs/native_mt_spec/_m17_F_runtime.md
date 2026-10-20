# _m17_F: M5 Runtime Verification Record (tester)

> **Note**: Parts 1–5 (full runtime test data: stages 0–5, post-crash-fix re-test, G2 A/B cross-comparison, post-probe-removal regression, and post-commit closure review) are in the Chinese version `zh_cn/_m17_F_runtime.md`. This English file currently contains only **Part 6** (physical-machine manual verification, added 2026-08-06). The full English translation of Parts 1–5 is a separate task.
>
> All data in Parts 1–5 are from **actual execution**; commands and raw output are transcribed verbatim. The Chinese version is the authoritative source for all numerical data.

---

---

# Part 6: Physical-Machine Manual Verification (2026-08-06)

> This part records the final manual verification performed by the user on a physical machine (not automated agent testing). It documents the final human verification conclusion for the native-mt multi-thread mode.

## V1. Verification Scope and Conclusion

| Item | Conclusion | Notes |
|---|---|---|
| **Functional verification** | **PASS** | Under `thread_mode=1` multi-thread mode, business functionality is normal (HTTP service accessible, connection establishment and data send/receive working correctly). |
| **Performance testing** | **PASS** | wrk stress-test throughput is normal, consistent with the measured data in Parts 1–4 (2-thread ~236k req/s range). |

**Overall verdict**: The **functionality and performance** of the native-mt SMP-aware pcpu/SMR slot isolation + global lock removal (G1+G2) **pass physical-machine verification**, and the feature is ready for production trial deployment (subject to the residual risks in §V3).

## V2. Confirmed-Pass Items

- **DoD-1 slot isolation**: 1/2/3/4 threads + `thread_mode=0` 1/2 processes — per-cpu slot isolation verified (Parts 2/3 of the Chinese version; physical-machine verification consistent).
- **DoD-2 lock removal**: `uma_crit_lock` removed from the binary (symbol-level criterion, Part 3 X0 of the Chinese version).
- **DoD-4 matrix**: all six tiers — zero crashes, zero socket errors, zero log additions (Parts 2/3/4 of the Chinese version).
- **DoD-5 pre/post-lock throughput**: A/B cross-comparison PASS (Part 3 X4.1 of the Chinese version).
- **`thread_mode=0` zero regression**: D7 verified (Parts 2/3 R3 of the Chinese version).

## V3. Residual Risks (not fixed this round, for future optimization)

The following residual risks are honestly recorded, not fixed this round, and deferred to dedicated follow-up work:

| # | Residual risk | Disposition |
|---|---|---|
| 1 | **ipfw/netisr DPCPU slot aliasing** | Requires a separate DPCPU project (spec 17 §6.3 + §6.15) |
| 2 | **counter(9) statistics contention** | Pre-existing, not introduced this round (spec 17 §6.7) |
| 3 | **tcp_hpts instance count 1→N callout ownership mismatch (R6)** | Address during CM6/CM7 lock-narrowing (spec 17 §6.19) |
| 4 | **net.isr.dispatch must stay `direct`** | Configuration constraint, documented (spec 17 §6.18) |
| 5 | **ff_subr_prf.c global lockless line buffer** | Pre-existing logging defect, not a product-correctness risk (Part 3 X1.4 of the Chinese version captured direct evidence of printf interleaving) |
| 6 | **ff_pthread_create threads do not support calling ff_*** | Fail-fast by design, documented (spec 17 §6.5/§6.17) |
| 7 | **Intermittent process crash under wrk stress (non-deterministic)** | **New this round**: requires multiple stress runs to reproduce → capture crash stack → root-cause. See spec 17 §6.23. |

## V4. Compliance Statement (Physical-Machine Verification Part)

- This part records the user's manual verification on a physical machine; it contains concluding statements and did not involve `rm`/`kill`/`chmod` command operations.
- The `config.ini` used for verification contains local runtime environment values (not committed to the repository), consistent with the test environment in Parts 1–5 of the Chinese version.
- All conclusions are based on actual physical-machine run results, with no speculation.

---

**Physical-machine manual verification complete. The native-mt multi-thread mode passes functional and performance verification; residual risks are honestly recorded; the intermittent crash is deferred for follow-up investigation.**
