# Phase-2 M9 Spec — FF_USE_PAGE_ARRAY + FF_ZC_SEND combo (P1c)

> Chinese version: ./zh_cn/phase2-M9-spec.md (authoritative)

> Status: DRAFT → ready
> Upstream basis: M8 commit `add33a04a`
> Complexity: S (1 line of Makefile + reuses the M7/M8 acceptance path)

---

## 1. Goal / Scope

### in-scope

- `lib/Makefile` enables `FF_USE_PAGE_ARRAY=1` + `FF_ZC_SEND=1` together
- Reuses code already in place from M7 + M8 (no new code)
- G1 build + G2 smoke + G3 end-to-end + G4 perf observation
- Doc anchor + execution log

### out-of-scope

- Any source-code change (already done in M7/M8)
- Perf NFR-2 calibration (OQ-2 default-allowed; full baseline deferred to its own phase)

---

## 2. Acceptance Criteria

| ID | Criterion |
|---|---|
| AC-M9-1 | `lib/Makefile` uncomments both `FF_USE_PAGE_ARRAY=1` + `FF_ZC_SEND=1` |
| AC-M9-2 | `lib/ make clean && make`: exit=0 / 0 errors / warnings ≤ 60 |
| AC-M9-3 | `example/ make`: all 3 binaries produced |
| AC-M9-4 | helloworld_zc primary alive ≥ 12 s; log contains `ff_mmap_init mmap 65536 pages, 256 MB.` (PA) + ipfw2 init line (ZC path independent, no conflict) |
| AC-M9-5 | ssh f-stack-client single curl returns HTTP 200 + the real HTML body |
| AC-M9-6 | 100× short-conn: 100/100 PASS |
| AC-M9-7 | Doc anchor follows the M6/M7/M8 pattern |

---

## 3. Risks

| ID | Risk | Mitigation |
|---|---|---|
| R-M9-1 | After PA mmap, the ZC fast-path mbuf comes from m_getm2 — possible cross-interaction with the PA pool | M7 PA only affects mbuf data-cluster origin (mmap vs malloc); orthogonal to ZC fast-path mbuf-chain interpretation; no theoretical conflict |
| R-M9-2 | 256 MB mmap occupancy + ZC magic check might miss an edge case | reuse the M7 baseline + 100× pressure |

---

## 4. Acceptance Commands

```sh
# G1
cd /data/workspace/f-stack/lib && make clean && make
cd /data/workspace/f-stack/example && /data/workspace/rm_tmp_file.sh ./helloworld ./helloworld_zc ./helloworld_epoll && make

# G2/G3
/data/workspace/rm_tmp_file.sh /var/run/dpdk/rte/{config,fbarray_*,hugepage_info}
sudo ./helloworld_zc -c ../config.ini --proc-type=primary --proc-id=0 &
sleep 12 && [ -d /proc/$PID ] && echo ALIVE
ssh f-stack-client 'curl -sS -o /dev/null -w "%{http_code}\n" http://9.134.214.176/'
ssh f-stack-client 'OK=0; for i in $(seq 1 100); do CODE=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 http://9.134.214.176/); [ "$CODE" = 200 ] && OK=$((OK+1)); done; echo $OK/100'
/data/workspace/kill_process.sh $PID
```

---

> Next: Phase C — 1-line Makefile diff + rebuild + Gate run.
