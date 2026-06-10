#!/usr/bin/env bash
#
# coverage_threshold.sh — verify F-Stack lib/ unit-test coverage thresholds.
#
# Usage:   bash coverage_threshold.sh <coverage.info>
#
# Parses the lcov info file directly (SF/LF/LH/BRF/BRH records) so the result
# is independent of `lcov --list` output format quirks across versions.
#
# Per-file thresholds (extended Stage-5; P0/P1 anchored to spec 06 §6.1,
# P2/P3 anchored to plan-stage4 + plan-stage5 actual measurements - 5pp):
#   P0 ff_ini_parser.c    : line >= 80%, branch >= 70%   (actual ~95/81%)
#   P0 ff_log.c           : line >= 80%, branch >= 70%   (actual 100/100%)
#   P1 ff_host_interface.c: line >= 60%, branch >= 50%   (actual ~93/89%)
#   P1 ff_epoll.c         : line >= 60%, branch >= 50%   (actual ~75/54%)
#   P1 ff_config.c        : line >= 50%, branch >= 40%   (actual ~60/60%)
#   P2 ff_thread.c        : line >= 80%, branch >= 30%   (actual ~91/50%)
#   P2 ff_init.c          : line >= 70%, branch >= 50%   (actual ~90/75%)
#   P2 ff_dpdk_pcap.c     : line >= 80%, branch >= 60%   (actual ~96/78%)
#   P3 ff_dpdk_if.c       : line >=  2%, branch >=  0%   (actual ~3/1%)
#                           (subset only: 7 trivial + 3 in_pcbladdr)
#   P3 ff_dpdk_kni.c      : line >=  8%, branch >= 10%   (actual ~11/14%)
#                           (subset only: ff_kni_enqueue ratelimit branches)
#
# Exit 0 if all 10 tracked files meet thresholds (G8 PASS).
# Exit 1 if any file under threshold (G8 FAIL — caller should bounce).
#
# coverage.info SF block format (lcov 1.x / 2.x):
#   SF:<absolute path to .c>
#   FN:line,name      (function declarations)
#   FNDA:hit,name     (function hit counts)
#   DA:line,hit       (line execution count; one per executable line)
#   BRDA:line,bb,branch_no,taken
#   LF:<total executable lines>
#   LH:<hit lines>
#   BRF:<total branches>
#   BRH:<hit branches>
#   end_of_record

set -u
INFO="${1:-coverage.info}"

if [ ! -f "$INFO" ]; then
    echo "[FAIL] coverage info '$INFO' not found"
    exit 1
fi

echo ""
echo "==> Threshold check (spec 06 §6.1)"

awk '
function rate(hit, total) {
    if (total == 0) return -1   # sentinel: no data
    return (hit * 100.0) / total
}

BEGIN {
    # threshold tables, keyed by file basename
    # P0 (spec 06 §6.1, post-Stage-6 actual - 5pp)
    tline["ff_ini_parser.c"]    = 92;  tbr["ff_ini_parser.c"]    = 78
    tline["ff_log.c"]           = 100; tbr["ff_log.c"]           = 100
    # P1 (spec 06 §6.1, post-Stage-6 actual - 5pp)
    tline["ff_host_interface.c"]= 95;  tbr["ff_host_interface.c"]= 87
    tline["ff_epoll.c"]         = 95;  tbr["ff_epoll.c"]         = 84
    tline["ff_config.c"]        = 70;  tbr["ff_config.c"]        = 65
    # P2 (Stage-6 actual - 5pp)
    tline["ff_thread.c"]        = 95;  tbr["ff_thread.c"]        = 95
    tline["ff_init.c"]          = 95;  tbr["ff_init.c"]          = 95
    tline["ff_dpdk_pcap.c"]     = 95;  tbr["ff_dpdk_pcap.c"]     = 84
    # P3 (Stage-5 subset only — most of the file is out-of-scope by design)
    tline["ff_dpdk_if.c"]       =  4;  tbr["ff_dpdk_if.c"]       =  2
    tline["ff_dpdk_kni.c"]      = 40;  tbr["ff_dpdk_kni.c"]      = 35

    pass = 0; fail = 0; total_files = 0
}

/^SF:/ {
    sf = substr($0, 4)
    n = split(sf, parts, "/")
    cur_basename = parts[n]
    cur_lf = 0; cur_lh = 0; cur_brf = 0; cur_brh = 0
}

/^LF:/ { cur_lf = substr($0, 4) + 0 }
/^LH:/ { cur_lh = substr($0, 4) + 0 }
/^BRF:/ { cur_brf = substr($0, 5) + 0 }
/^BRH:/ { cur_brh = substr($0, 5) + 0 }

/^end_of_record/ {
    if (cur_basename in tline) {
        lr = rate(cur_lh, cur_lf)
        br = rate(cur_brh, cur_brf)
        tl = tline[cur_basename]
        tb = tbr[cur_basename]

        line_str  = sprintf("%5.1f%%/%d%%", lr, tl)
        if (br < 0) {
            br_str = sprintf("    -/%-3d%%", tb)
            br_ok  = "Y"   # no branches => trivially satisfied
        } else {
            br_str = sprintf("%5.1f%%/%d%%", br, tb)
            br_ok  = (br >= tb) ? "Y" : "N"
        }

        line_ok = (lr >= tl) ? "Y" : "N"

        total_files++
        if (line_ok == "Y" && br_ok == "Y") {
            verdict = "[PASS]"
            pass++
        } else {
            verdict = "[FAIL]"
            fail++
        }
        printf "  %s %-22s line=%s  branch=%s  (lh=%d/%d  brh=%d/%d)\n",
               verdict, cur_basename, line_str, br_str, cur_lh, cur_lf, cur_brh, cur_brf
    }
}

END {
    print ""
    printf "==> Coverage threshold summary: %d/%d files passed\n", pass, total_files
    if (fail > 0) {
        print  "==> G8 FAIL: " fail " file(s) below threshold"
        exit 1
    }
    if (total_files == 0) {
        print  "==> G8 FAIL: no tracked F-Stack lib/ files found in info"
        exit 1
    }
    print  "==> G8 PASS"
    exit 0
}
' "$INFO"
