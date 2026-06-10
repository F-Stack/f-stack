#!/bin/bash
# F-Stack lib/ full coverage report (FU-CB-DPDKIF-INTEGRATION).
# Runs both unit and integration test suites and merges the .info trace
# files into a single report rooted at tests/full_coverage_report/.
#
# Per Stage-6 G-CB-3/G-CB-4 acceptance:
#   - Project line cov target: >= 50%
#   - ff_dpdk_if.c line cov target: >= 25%
#
# Usage:
#   tests/run_full_coverage.sh         - build + run both, merge, report
#   tests/run_full_coverage.sh --quick - skip rebuild, reuse existing .info
#   tests/run_full_coverage.sh --clean - remove all coverage artifacts

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UNIT_DIR="$SCRIPT_DIR/unit"
INT_DIR="$SCRIPT_DIR/integration"
MERGED_INFO="$SCRIPT_DIR/full_coverage.info"
MERGED_DIR="$SCRIPT_DIR/full_coverage_report"

case "${1:-}" in
  --clean)
    echo "==> cleaning unit + integration + merged coverage"
    (cd "$UNIT_DIR" && make coverage_clean >/dev/null 2>&1 || true)
    (cd "$INT_DIR"  && make coverage_clean >/dev/null 2>&1 || true)
    if [ -f "$MERGED_INFO" ]; then
      /data/workspace/rm_tmp_file.sh "$MERGED_INFO" >/dev/null
    fi
    if [ -d "$MERGED_DIR" ]; then
      /data/workspace/rm_tmp_file.sh "$MERGED_DIR" >/dev/null
    fi
    echo "[OK] full coverage clean"
    exit 0
    ;;
esac

QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

if [ "$QUICK" -eq 0 ]; then
  echo "==> [1/3] unit coverage (G8 thresholds via run_coverage.sh)"
  (cd "$UNIT_DIR" && ./run_coverage.sh 2>&1) | tail -20
  echo ""
  echo "==> [2/3] integration coverage"
  (cd "$INT_DIR" && make coverage 2>&1) | tail -10
  echo ""
fi

if [ ! -f "$UNIT_DIR/coverage.info" ] || [ ! -f "$INT_DIR/coverage.info" ]; then
  echo "ERROR: missing coverage.info from unit ($UNIT_DIR) or integration ($INT_DIR)" >&2
  exit 1
fi

echo "==> [3/3] merging .info files via lcov --add-tracefile"
lcov --add-tracefile "$UNIT_DIR/coverage.info" \
     --add-tracefile "$INT_DIR/coverage.info" \
     --output-file "$MERGED_INFO" \
     --rc branch_coverage=1 \
     --ignore-errors inconsistent,empty,unused 2>&1 | tail -5

echo ""
echo "==> generating merged HTML report at $MERGED_DIR/"
genhtml "$MERGED_INFO" --output-directory "$MERGED_DIR" \
    --branch-coverage \
    --title "F-Stack lib/ unit+integration full coverage" \
    --ignore-errors source,inconsistent,corrupt 2>&1 | tail -6

echo ""
echo "==> per-file merged coverage breakdown"
awk '
  /^SF:.*\/lib\// {
    sf = $0; sub(/^SF:/, "", sf)
    n = split(sf, parts, "/"); base = parts[n]
    flag = 1; lh = 0; lf = 0; bh = 0; bf = 0
  }
  flag && /^DA:/ { lf++; if ($0 !~ /,0$/) lh++ }
  flag && /^BRDA:/ { bf++; split($0, a, ","); if (a[4] != "-" && a[4]+0 > 0) bh++ }
  flag && /^end_of_record/ {
    if (lf > 0) {
      lr = 100 * lh / lf
      br = (bf > 0) ? 100 * bh / bf : 0
      printf "  %-30s line=%6.2f%% (%4d/%4d)  branch=%6.2f%% (%4d/%4d)\n",
             base, lr, lh, lf, br, bh, bf
    }
    flag = 0
  }
' "$MERGED_INFO" | sort

echo ""
echo "==> overall merged summary"
lcov --summary "$MERGED_INFO" --rc branch_coverage=1 2>&1 \
    | grep -E "lines\.\.|branches\.\.|functions\.\."

echo ""
echo "==> Stage-6 G-CB acceptance gates (FU-CB-DPDKIF-INTEGRATION)"
ff_dpdk_if_line=$(awk '/^SF:.*ff_dpdk_if\.c$/{flag=1; lh=0; lf=0} flag && /^DA:/{lf++; if(!/,0$/) lh++} flag && /^end_of_record/{if(lf>0) printf "%.1f", 100*lh/lf; flag=0}' "$MERGED_INFO")
proj_line=$(lcov --summary "$MERGED_INFO" --rc branch_coverage=1 2>&1 | awk '/lines\.\./{gsub("%",""); print $2; exit}')

printf "  G-CB-3  ff_dpdk_if.c  line >= 25%%   actual=%-6s  " "${ff_dpdk_if_line}%"
[ "$(echo "$ff_dpdk_if_line >= 25" | bc -l)" = "1" ] && echo "[PASS]" || echo "[FAIL]"
printf "  G-CB-4  project       line >= 50%%   actual=%-6s  " "${proj_line}%"
[ "$(echo "$proj_line >= 50" | bc -l)" = "1" ] && echo "[PASS]" || echo "[FAIL]"

echo ""
echo "[OK] merged report: $MERGED_DIR/index.html"
