# Stage-7 Test Cases & Acceptance

| Field | Value |
|---|---|
| Spec ID | 72-stage7-test-cases-and-acceptance |
| Version | v0.1-skeleton (Phase 1) — to be filled by Phase 3-6 |
| Status | DRAFT |
| Reference | 70-plan / 71-gap-analysis |

---

## §1 命名规范

`test_<func>_<scenario>_<expected>`

示例：
- `test_ff_load_config_vlan_rebind_no_leak`
- `test_ff_ini_parser_bom_skipped`
- `test_ff_kni_proto_filter_null_arg_returns_neg_one`

---

## §2 New TC List (待 Phase 3-6 填充)

### Phase 3 — ff_config.c (TC-S7-CFG-*)

| TC ID | Name | Source-of-need (71 §A.x) | Expected branch Δ |
|---|---|---|---|
| TC-S7-CFG-01 | (待 phase 3) | A.1 | +1.x pp |
| TC-S7-CFG-02 | (待 phase 3) | A.2 | +x.x pp |
| ... | | | |

### Phase 4 — ff_ini_parser.c (TC-S7-INI-*)

| TC ID | Name | Source-of-need | Expected branch Δ |
|---|---|---|---|
| TC-S7-INI-01 | (待 phase 4) | D.1 | – |
| ... | | | |

### Phase 5 — ff_dpdk_pcap + ff_epoll (TC-S7-PCAP-* / TC-S7-EPOLL-*)

| TC ID | Name | Source-of-need | Expected branch Δ |
|---|---|---|---|
| TC-S7-PCAP-01 | (待 phase 5) | B.1 | – |
| TC-S7-EPOLL-01 | (待 phase 5) | C.1 | – |
| ... | | | |

### Phase 6 — ff_dpdk_kni + ff_host_interface (TC-S7-KNI-* / TC-S7-HIF-*)

| TC ID | Name | Source-of-need | Expected branch Δ |
|---|---|---|---|
| TC-S7-KNI-01 | (待 phase 6) | E.1 | – |
| TC-S7-HIF-01 | (待 phase 6) | F.1 | – |
| ... | | | |

---

## §3 Acceptance Gates (引自 70 plan §1.2)

| Gate | 度量 | 起点 | 目标 | Phase 8 actual |
|---|---|---|---|---|
| G-CB-7-1 | merged project branch | 57.2% | ≥ 65% | (待) |
| G-CB-7-2 | per-headroom +10~15pp | 见 70 §2 | 见 70 §2 | (待) |
| G-CB-7-3 | TC PASS | 150 | ≥ 175 | (待) |
| G-CB-7-4 | valgrind 0 leak | 12/12 | 12/12 | (待) |
| G-CB-7-5 | G8 ratchet up | 10/10 | 10/10 | (待) |
| G-CB-7-6 | lib patch ≤30 行/commit | n/a | enforced | (待) |
| G-CB-7-7 | TC↔gap 1:1 traceability | n/a | enforced | (待) |

EOF
