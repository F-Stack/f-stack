#!/usr/bin/env bash
#
# run_coverage.sh — F-Stack lib/ unit-test coverage one-shot runner.
#
# Usage:
#   ./run_coverage.sh              # full coverage: build + test + report + summary
#   ./run_coverage.sh --quick      # skip rebuild if .gcda already exist
#   ./run_coverage.sh --file <c>   # show per-line gcov detail for one file
#                                  # (e.g. --file ff_log.c)
#   ./run_coverage.sh --serve      # also start an HTTP server on :8080 to view
#                                  # the HTML report (Ctrl-C to stop)
#   ./run_coverage.sh --clean      # remove all coverage artifacts and exit
#   ./run_coverage.sh -h | --help  # show this help
#
# Exit codes:
#   0   success, all G8 thresholds met
#   1   coverage build/test failure or G8 threshold violation
#   2   bad CLI arguments
#

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --- ANSI helpers ---------------------------------------------------------
if [ -t 1 ] && [ "${TERM:-}" != "dumb" ]; then
    C_BOLD=$'\033[1m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_RED=$'\033[31m'
    C_CYAN=$'\033[36m'
    C_RESET=$'\033[0m'
else
    C_BOLD=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_CYAN=""; C_RESET=""
fi

banner() { printf "\n${C_BOLD}${C_CYAN}===== %s =====${C_RESET}\n" "$1"; }
ok()     { printf "${C_GREEN}[ OK ]${C_RESET} %s\n" "$1"; }
warn()   { printf "${C_YELLOW}[WARN]${C_RESET} %s\n" "$1"; }
err()    { printf "${C_RED}[FAIL]${C_RESET} %s\n" "$1" >&2; }

# --- preflight ------------------------------------------------------------
check_tools() {
    local missing=0
    for t in gcc make pkg-config lcov genhtml awk; do
        if ! command -v "$t" >/dev/null 2>&1; then
            err "required tool missing: $t"
            missing=1
        fi
    done
    if ! pkg-config --exists cmocka; then
        err "cmocka pkg-config not found (try: dnf install -y libcmocka-devel)"
        missing=1
    fi
    if ! pkg-config --exists libdpdk; then
        warn "libdpdk pkg-config not found — test_ff_dpdk_{if,kni} may fail"
    fi
    [ "$missing" -eq 0 ]
}

# --- per-file gcov detail -------------------------------------------------
show_file_detail() {
    local f="$1"
    if [ -z "$f" ]; then
        err "--file requires a filename (e.g. --file ff_log.c)"
        exit 2
    fi

    local lib_obj_dir="$SCRIPT_DIR/lib_objs"
    if [ ! -f "$lib_obj_dir/${f%.c}.gcno" ]; then
        warn "$lib_obj_dir/${f%.c}.gcno not found; running 'make coverage' first..."
        run_coverage_full
    fi
    banner "Per-line gcov detail for $f"
    cd "$lib_obj_dir"
    gcov "$f" 2>/dev/null | head -20
    if [ -f "${f}.gcov" ]; then
        echo ""
        printf "${C_BOLD}Showing first 60 lines of ${f}.gcov:${C_RESET}\n"
        printf "  ${C_GREEN}<n>${C_RESET}  : executed n times\n"
        printf "  ${C_RED}#####${C_RESET} : NOT covered\n"
        printf "  ${C_YELLOW}-${C_RESET}    : not executable (comment / decl)\n\n"
        head -60 "${f}.gcov"
    else
        warn "no .gcov output produced (maybe ${f%.c}.gcda missing)"
    fi
}

# --- full coverage flow ---------------------------------------------------
run_coverage_full() {
    banner "1/4  Run make coverage (build + test + lcov + threshold check)"
    if make coverage; then
        ok "make coverage exit=0"
    else
        local rv=$?
        err "make coverage exit=$rv"
        return $rv
    fi

    banner "2/4  Project-wide summary (all files including P2/P3 partials)"
    lcov --summary coverage.info --rc branch_coverage=1 2>&1 \
        | grep -E "lines|functions|branches" \
        | sed 's/^/   /'

    banner "3/4  Per-file thresholds (10 files: P0 + P1 + P2 + P3 subset)"
    bash ./coverage_threshold.sh coverage.info 2>&1 \
        | grep -E "PASS|FAIL|threshold|G8" \
        | sed 's/^/   /'

    banner "4/4  Reports"
    if [ -f "$SCRIPT_DIR/coverage_report/index.html" ]; then
        ok "HTML  : $SCRIPT_DIR/coverage_report/index.html"
    else
        warn "HTML report not produced"
    fi
    [ -f "$SCRIPT_DIR/coverage.info" ] && ok "lcov  : $SCRIPT_DIR/coverage.info"
    return 0
}

# --- quick: reuse existing .gcda --------------------------------------------
run_coverage_quick() {
    if ! find lib_objs -name '*.gcda' -print -quit 2>/dev/null | grep -q '.'; then
        warn "no .gcda found; falling back to full coverage flow"
        run_coverage_full
        return
    fi
    banner "Quick mode: reusing existing .gcda (no rebuild)"
    rm_via_wrapper coverage.info
    rm_via_wrapper coverage_report
    lcov --capture --directory lib_objs --directory . \
        --output-file coverage.info --rc branch_coverage=1 \
        --ignore-errors mismatch,negative,inconsistent,empty,unused,source 2>&1 \
        | tail -3
    lcov --remove coverage.info \
        '/usr/*' '*/cmocka.h' '*/tests/unit/test_*.c' '*/tests/unit/common/*' \
        --output-file coverage.info.clean --rc branch_coverage=1 \
        --ignore-errors unused,inconsistent,empty 2>&1 | tail -3
    mv coverage.info.clean coverage.info
    genhtml coverage.info --output-directory coverage_report \
        --branch-coverage \
        --title "F-Stack lib/ unit-test coverage" \
        --ignore-errors source,inconsistent,corrupt 2>&1 | tail -3
    bash ./coverage_threshold.sh coverage.info
}

# --- helper: remove via workspace wrapper (NFR-U-7) ------------------------
rm_via_wrapper() {
    local tgt="$1"
    if [ -e "$tgt" ]; then
        /data/workspace/rm_tmp_file.sh "$(realpath "$tgt")" >/dev/null 2>&1
    fi
}

run_clean() {
    banner "Cleaning coverage artifacts"
    make coverage_clean
    ok "done"
}

# --- argument parsing ------------------------------------------------------
ACTION="full"
FILE_ARG=""
SERVE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --quick)  ACTION="quick" ;;
        --file)   ACTION="file"; FILE_ARG="${2:-}"; shift ;;
        --serve)  SERVE=1 ;;
        --clean)  ACTION="clean" ;;
        -h|--help)
            sed -n '2,20p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            err "unknown argument: $1"
            echo "Try: $0 --help" >&2
            exit 2
            ;;
    esac
    shift
done

# --- dispatch --------------------------------------------------------------
check_tools || exit 1

case "$ACTION" in
    full)   run_coverage_full || exit 1 ;;
    quick)  run_coverage_quick || exit 1 ;;
    file)   show_file_detail "$FILE_ARG" ;;
    clean)  run_clean; exit 0 ;;
esac

# --- optional HTTP server for HTML viewing --------------------------------
if [ "$SERVE" -eq 1 ] && [ -d "$SCRIPT_DIR/coverage_report" ]; then
    PORT="${COVERAGE_PORT:-8080}"
    banner "Serving HTML report on http://0.0.0.0:${PORT} (Ctrl-C to stop)"
    cd "$SCRIPT_DIR/coverage_report"
    if command -v python3 >/dev/null 2>&1; then
        python3 -m http.server "$PORT"
    elif command -v python2 >/dev/null 2>&1; then
        python2 -m SimpleHTTPServer "$PORT"
    else
        err "no python found; cannot start HTTP server"
        exit 1
    fi
fi
