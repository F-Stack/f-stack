#!/bin/bash
# M6 graceful-reload real-machine harness (B group, C-NR-601).
#
# Real execution + per-case verdict + aggregated exit code. Unlike the
# description-only test_mtu.sh, this script actually starts nginx/f-stack,
# drives reloads and fails loudly when a criterion is not met.
#
# Mandated workspace rules honoured everywhere in this file:
#   - every process stop goes through /data/workspace/kill_process.sh
#   - every removal    goes through /data/workspace/rm_tmp_file.sh
#   - every mode change goes through /data/workspace/chmod_modify.sh
# No direct stop / delete / mode-change command is ever issued, including in
# comments and in the embedded templates.
#
# Exit codes:
#   0        every executed case passed
#   100+N    N cases failed (N >= 1, capped at 150)
#   2        usage / parameter error (missing TARGET_IP, unknown option, ...)
#   3        environment precondition not met (three-check gate)
#   4        required dependency missing
#   5        aborted (signal or internal failure)
#
# No address is stored in this file. TARGET_IP is a mandatory argument; use
# the placeholders <DPDK_NIC_IP> / <CLIENT_IP> / <KERNEL_NIC_IP> in reports.

set -u
set -o pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
CHECKS="$SCRIPT_DIR/common/reload_checks.py"
SUPERVISOR="$SCRIPT_DIR/common/reload_supervisor.py"
STACK_ID=""
BUILD_MANIFEST=""
RUN_ID=""
EAL_PREFIX=""
REMOTE_DIR=""
PROBES_PUSHED=0
REMOTE_CREATED=0
STACK_STARTED=0
CLEANUP_FAILED=0
CURRENT_PROBE=""
STOP_RT=0
STOP_HP=0
declare -a PROBE_JOBS=()

KILLTOOL=/data/workspace/kill_process.sh
RMTMP=/data/workspace/rm_tmp_file.sh
CHMODTOOL=/data/workspace/chmod_modify.sh

# ---- defaults -------------------------------------------------------------
TARGET_IP=""
ROUNDS=100
INTERVAL=15
POLL=5
CASES="precheck,rt01,rv9"
OUT=""
NGINX_BIN=/usr/local/nginx_fstack/sbin/nginx
FSTACK_TPL="$REPO_ROOT/config.ini"
PROBE_DIR="$SCRIPT_DIR/common/reload_probes"
CLIENT=f-stack-client
WORKERS=2
LCORE_MASK=""
LCORE_MASK_SET=0
LCORE_LIST=""
LCORE_LIST_SET=0
SHUTDOWN_TIMEOUT=0
GRACEFUL=1
DRAIN_TIMEOUT=120
STARTUP_WAIT=28
BASELINE=0
BASELINE_DURATION=330
STREAM_MB=8
# Life span of the active-stream probe. It has to outlive the reload: the
# drain ends exactly when the in-flight streams end, so a probe whose life is
# one download can never be seen "still running" after the reload. Kept below
# the 180 s summary wait and the 300 s remote probe budget.
STREAM_DURATION=120
KERNEL_NIC_IP=""
# Runtime fault injection (FF_FAULT). Empty = production form; a non-empty name
# requires a fault-injection build manifest (checked by reload_checks.verify-build).
FAULT=""
FAULT_DELAY_MS=15000
ZC_BUILD=auto
RTE_FRESH_MIN=10
# KNI owner must be a *secondary* proc_id, never the resident primary (0):
# lib/ff_config.c:1445-1460 refuses a config whose lcore_list still holds the
# primary lcore, and :1462-1477 then demands that proc_lcore[owner_proc_id] be
# inside that very lcore_list. proc_id 0 is the primary, so its lcore is
# exactly the one excluded -- only a worker proc_id satisfies both checks.
# proc_lcore[] is filled in ascending lcore order, so proc_id 1 is always the
# first worker (the shipped config.ini default owner_proc_id is 1 as well).
KNI_OWNER_PROC_ID=1

ALL_CASES="precheck,baseline,rt01,rt02,rv9,gr0,rt12,rt13"

# ---- globals shared between helpers ---------------------------------------
ERRLOG=""
PIDFILE=""
STREAM_MD5=""
HUP_SUMMARY="NA"
HUP_DRAIN="NA"
HUP_FWD="NA"
HUP_REL="NA"
HUP_FSM="0"
FAILED=0

declare -a C_NAME=()
declare -a C_VERDICT=()
declare -a C_CRIT=()
declare -a C_MEAS=()

# ---- small helpers --------------------------------------------------------
hp_free()      { grep HugePages_Free /proc/meminfo | awk '{print $2}'; }
rtemap_count() { find /dev/hugepages -maxdepth 1 -name "${EAL_PREFIX}map_*" -printf '.\n' 2>/dev/null | wc -l; }
master_pid()   { cat "$OUT/nginx.pid" 2>/dev/null; }

record() { # name verdict criterion measured
    C_NAME+=("$1"); C_VERDICT+=("$2"); C_CRIT+=("$3"); C_MEAS+=("$4")
    printf '[%s] %s\n' "$1" "$2"
    printf '    criterion: %s\n' "$3"
    printf '    measured : %s\n' "$4"
}

print_summary() {
    local i n=${#C_NAME[@]}
    say ""
    say "================ SUMMARY ================"
    say "$(printf '%-10s %-8s %s' CASE VERDICT MEASURED)"
    say "$(printf '%-10s %-8s %s' '----------' '--------' '-------------------------------------')"
    for ((i = 0; i < n; i++)); do
        say "$(printf '%-10s %-8s %s' "${C_NAME[$i]}" "${C_VERDICT[$i]}" "${C_MEAS[$i]}")"
    done
    say "-----------------------------------------"
    say "failed=$FAILED out=$OUT"
}

usage() {
    cat <<'USAGE'
Usage: test_graceful_reload.sh -t <TARGET_IP> [options]

  -t, --target-ip <ip>        REQUIRED. Address of the f-stack/DPDK NIC under
                              test (write <DPDK_NIC_IP> in any report).
  -c, --cases <list>          Comma-separated case list, or 'all'.
                              available: precheck,baseline,rt01,rt02,rv9,gr0,
                                         rt12,rt13,rt20,rt20b,rt21,rt22,rt23
  --fault <name>            runtime fault injection (FF_FAULT); requires a
                            fault-injection build manifest. rt23 is the only
                            fault case that runs on the production form
  --fault-delay-ms <n>      FF_FAULT_DELAY_MS for ready_delay (1..59000)
                              default  : precheck,rt01,rv9
  -r, --rounds <n>            reload-loop rounds for rv9 (default 100)
  -i, --interval <s>          reload-loop cadence in seconds (default 15)
  -p, --poll <s>              G_old-exit poll period in seconds (default 5)
  -o, --out <dir>             new, private runtime directory (outside docs)

  --nginx <path>              nginx binary
  --build-manifest <path>     REQUIRED. Source/build commands and artifact SHA256s
  --fstack-conf <path>        f-stack config template (default <repo>/config.ini);
                              NIC addresses are taken from the template as-is,
                              only [dpdk] / [portN] / [freebsd.sysctl] keys are
                              patched
  --probe-dir <dir>           directory holding m4_lc.py / m4_cps.py /
                              m4_stream.py / m4_outage.py
  --client <ssh-host>         client machine running the probes
  --workers <n>               nginx worker_processes (default 2)
  --lcore-mask <hex>          default: (2^(workers+1))-1 with graceful=1,
                              (2^workers)-1 with graceful=0 (no primary)
  --lcore-list <csv>          default: mask minus the lowest set bit with
                              graceful=1 (the resident primary lcore), the
                              whole mask with graceful=0
  --shutdown-timeout <s>      0 = omit worker_shutdown_timeout (default);
                              10..20 recommended for the rv9 loop gate
  --graceful <0|1>            graceful_reload value for the main cases
  --drain-timeout <s>         per-reload completion timeout (default 120)
  --startup-wait <s>          f-stack readiness wait after start (default 28)
  --baseline                  run the gARP / long-run control case
  --baseline-duration <s>     control-probe duration (default 330)
  --stream-mb <n>             size of the active-stream payload (default 8)
  --kernel-nic-ip <ip>        KNI (virtio_user) kernel-side address, rt12
  --zc-build <auto|0|1>       zc build form (default auto: probed from the
                              installed f-stack archive)
  --rte-fresh-min <min>       /var/run/dpdk/rte freshness gate (default 10)

Exit: 0 all pass | 100+N N cases failed | 2 usage | 3 preconditions
      | 4 dependency missing | 5 aborted
USAGE
}

die_usage() { printf 'ERROR: %s\n\n' "$1" >&2; usage >&2; exit 2; }
die_dep()   { printf 'FATAL: %s\n' "$1" >&2; exit 4; }
die_abort() { printf 'FATAL: aborted: %s\n' "$1" >&2; exit 5; }

# ---- argument parsing -----------------------------------------------------
parse_args() {
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help|--baseline) ;;
        *) [ "$#" -ge 2 ] && [ -n "$2" ] || die_usage "missing option value" ;;
    esac
    case "$1" in
        -t|--target-ip)      TARGET_IP="${2:-}"; shift 2 ;;
        -c|--cases)          CASES="${2:-}"; shift 2 ;;
        -r|--rounds)         ROUNDS="${2:-}"; shift 2 ;;
        -i|--interval)       INTERVAL="${2:-}"; shift 2 ;;
        -p|--poll)           POLL="${2:-}"; shift 2 ;;
        -o|--out)            OUT="${2:-}"; shift 2 ;;
        --nginx)             NGINX_BIN="${2:-}"; shift 2 ;;
        --build-manifest)    BUILD_MANIFEST="${2:-}"; shift 2 ;;
        --fstack-conf)       FSTACK_TPL="${2:-}"; shift 2 ;;
        --probe-dir)         PROBE_DIR="${2:-}"; shift 2 ;;
        --client)            CLIENT="${2:-}"; shift 2 ;;
        --workers)           WORKERS="${2:-}"; shift 2 ;;
        --lcore-mask)        LCORE_MASK="${2:-}"; LCORE_MASK_SET=1; shift 2 ;;
        --lcore-list)        LCORE_LIST="${2:-}"; LCORE_LIST_SET=1; shift 2 ;;
        --shutdown-timeout)  SHUTDOWN_TIMEOUT="${2:-}"; shift 2 ;;
        --graceful)          GRACEFUL="${2:-}"; shift 2 ;;
        --drain-timeout)     DRAIN_TIMEOUT="${2:-}"; shift 2 ;;
        --startup-wait)      STARTUP_WAIT="${2:-}"; shift 2 ;;
        --baseline)          BASELINE=1; shift ;;
        --baseline-duration) BASELINE_DURATION="${2:-}"; shift 2 ;;
        --stream-mb)         STREAM_MB="${2:-}"; shift 2 ;;
        --kernel-nic-ip)     KERNEL_NIC_IP="${2:-}"; shift 2 ;;
        --fault)             FAULT="${2:-}"; shift 2 ;;
        --fault-delay-ms)   FAULT_DELAY_MS="${2:-}"; shift 2 ;;
        --zc-build)          ZC_BUILD="${2:-}"; shift 2 ;;
        --rte-fresh-min)     RTE_FRESH_MIN="${2:-}"; shift 2 ;;
        -h|--help)           usage; exit 0 ;;
        *)                   die_usage "unknown option: $1" ;;
    esac
done

[ -n "$TARGET_IP" ] || die_usage "TARGET_IP is mandatory (-t <DPDK_NIC_IP>)"
[ "$CASES" = "all" ] && CASES="$ALL_CASES"
[ "$BASELINE" = "1" ] && case ",$CASES," in *",baseline,"*) ;; *) CASES="$CASES,baseline" ;; esac
local n
local -a values=()
for n in TARGET_IP CLIENT CASES ROUNDS INTERVAL POLL WORKERS DRAIN_TIMEOUT STARTUP_WAIT \
    STREAM_MB RTE_FRESH_MIN SHUTDOWN_TIMEOUT BASELINE_DURATION GRACEFUL ZC_BUILD FAULT \
    FAULT_DELAY_MS \
    NGINX_BIN FSTACK_TPL PROBE_DIR OUT BUILD_MANIFEST KERNEL_NIC_IP LCORE_MASK LCORE_LIST; do
    values+=("$n=${!n}")
done
python3 -B "$CHECKS" validate "${values[@]}" || die_usage "invalid harness parameters"
TARGET_URL=$(python3 -B "$CHECKS" url "$TARGET_IP") || return 2
}

# ---- output dir / log -----------------------------------------------------
init_output() {
    umask 077
    RUN_ID="gr_$(date +%Y%m%d_%H%M%S)_$$_$(python3 -B -c 'import secrets; print(secrets.token_hex(4))')"
    EAL_PREFIX="container-$RUN_ID"
    REMOTE_DIR="/tmp/$RUN_ID"
    [ -n "$OUT" ] || OUT="/data/workspace/.nginx-reload-audit/$RUN_ID"
    case "$OUT" in "$REPO_ROOT/docs/"*) die_usage "runtime output must be outside docs" ;; esac
    [ ! -e "$OUT" ] && [ ! -L "$OUT" ] || die_usage "output directory already exists"
    mkdir -p "$(dirname "$OUT")" || return 1
    mkdir "$OUT" || return 1
    LOG="$OUT/harness.log"
    : > "$LOG"
    : > "$OUT/results.jsonl"
    printf '[]\n' > "$OUT/processes.json"
}

say()  { printf '%s\n' "${*//$TARGET_IP/<DPDK_NIC_IP>}" | tee -a "$LOG"; }

# RV9 runs for 30-60 minutes; an interrupt must still release the DPDK NIC
# and the hugepages, otherwise the next start is blocked by the three-check
# and needs manual cleanup. Drop the handlers first so the cleanup itself
# cannot re-enter the trap.
on_signal() {
    trap - INT TERM
    say "!!! interrupted -- running emergency cleanup"
    cleanup_epilogue
    die_abort "received a termination signal"
}

# ---- derived topology -----------------------------------------------------
# graceful=1 reserves the lowest set bit of the mask for the resident slim
# primary and gives the remaining bits to the workers. graceful=0 has no
# primary at all, so every bit of the mask must be a worker: reusing the =1
# topology (or leaving the port lcore_list untouched) puts the =0 instance on a
# degraded form -- F-M6-3(1), where gr0 measured ok=89/windows=38 against the
# 20024/1 baseline form of the =0 control. --lcore-mask / --lcore-list always
# win over the derived values.
derive_lcores() { # graceful(0|1)
    local g="$1"
    local l
    if [ "$LCORE_MASK_SET" != "1" ]; then
        if [ "$g" = "1" ]; then
            LCORE_MASK=$(awk -v n="$WORKERS" 'BEGIN { printf "%x", (2^(n+1))-1 }')
        else
            LCORE_MASK=$(awk -v n="$WORKERS" 'BEGIN { printf "%x", (2^n)-1 }')
        fi
    fi
    MASK_DEC=$(printf '%d' "0x$LCORE_MASK" 2>/dev/null) || MASK_DEC=0
    [ "${MASK_DEC:-0}" -gt 0 ] || die_usage "--lcore-mask is not a valid hex mask: $LCORE_MASK"

    # The resident slim primary owns the lowest set bit; the workers own the
    # rest (with graceful=0 there is no primary, so they own all of it).
    PRIMARY_LCORE=0
    while [ $(( (MASK_DEC >> PRIMARY_LCORE) & 1 )) -eq 0 ]; do
        PRIMARY_LCORE=$(( PRIMARY_LCORE + 1 ))
    done
    if [ "$LCORE_LIST_SET" != "1" ]; then
        LCORE_LIST=""
        for ((l = 0; l < 32; l++)); do
            [ $(( (MASK_DEC >> l) & 1 )) -eq 1 ] || continue
            [ "$g" = "1" ] && [ "$l" = "$PRIMARY_LCORE" ] && continue
            LCORE_LIST="${LCORE_LIST:+$LCORE_LIST,}$l"
        done
    fi
}

# ---- process / state observation ------------------------------------------
worker_count() {
    local m; m=$(master_pid)
    [ -n "$m" ] || { echo 0; return; }
    ps -eo pid,ppid,stat,comm 2>/dev/null \
        | awk -v m="$m" '$2==m && $1!=m && $3 !~ /^Z/ && $4 ~ /^nginx/ {c++} END {print c+0}'
}

nginx_residue() {
    ps -eo pid,stat,comm 2>/dev/null | awk '$2 !~ /^Z/ && $3 ~ /^nginx/ {print}'
}

# Newest FSM transition; empty when no reload has happened yet.
last_fsm() { grep 'graceful reload fsm:' "$ERRLOG" 2>/dev/null | tail -1; }

# A reload is in flight when the newest FSM transition has not come back to
# T0_IDLE. This is the log-visible mirror of the shared reload state; the
# worker count is used by the caller as an independent corroboration.
reload_in_flight() {
    local l; l=$(last_fsm)
    [ -n "$l" ] || return 1
    case "$l" in *"-> T0_IDLE"*) return 1 ;; *) return 0 ;; esac
}

worker_psr_list() {
    local m; m=$(master_pid)
    [ -n "$m" ] || { echo ""; return; }
    ps -eo pid,ppid,psr,comm 2>/dev/null \
        | awk -v m="$m" '$2==m && $1!=m && $3 !~ /^Z/ && $4 ~ /^nginx/ {print $3}' \
        | sort | tr '\n' ','
}


# ---- f-stack ini generation -----------------------------------------------
ini_set() { # file section key value -- insert under the header, drop later dupes
    local f="$1" sec="$2" key="$3" val="$4" tmp="$1.tmp$$"
    awk -v sec="$sec" -v key="$key" -v kv="$key=$val" '
        /^\[/ { cur=$0; gsub(/[][]/,"",cur); print; if (cur==sec) print kv; next }
        { if (cur==sec && index($0, key "=")==1) next; print }
    ' "$f" > "$tmp" && mv "$tmp" "$f"
    grep -q "^$key=" "$f" || say "WARN ini_set: key $key not present after patching [$sec]"
}

# Workers must not sit on the resident primary lcore when graceful_reload=1;
# with graceful_reload=0 there is no primary, so the whole mask is the worker
# set. The harness always writes the list it derived instead of inheriting
# whatever the template happens to carry.
ini_force_port_lcores() { # file csv
    local f="$1" ll="$2" tmp="$1.tmp$$"
    awk -v ll="$ll" '
        /^\[/ { inport = ($0 ~ /^\[port[0-9]+\]/)
                if (inport) { print; print "lcore_list=" ll; next } }
        inport && /^lcore_list=/ { next }
        { print }
    ' "$f" > "$tmp" && mv "$tmp" "$f"
}

# Drop any [kni] section a template may carry.
ini_strip_kni() { # file
    local f="$1" tmp="$1.tmp$$"
    awk '
        /^#?\[kni\]/ { skip=1; next }
        /^\[/       { skip=0 }
        skip == 0   { print }
    ' "$f" > "$tmp" && mv "$tmp" "$f"
}

# RT-12: KNI in this tree is a virtio_user vdev, driven by [kni] enable=1.
ini_force_kni() { # file owner_proc_id
    local f="$1" owner="$2"
    ini_strip_kni "$f"
    cat >> "$f" <<KNI

[kni]
enable=1
method=reject
owner_proc_id=$owner
tcp_port=80,443
udp_port=53
KNI
}

# The f-stack library owns the EAL proc-type; the harness only guarantees that
# nobody smuggles an 'auto' proc-type in through extra_eal_args.
ini_drop_proc_type_auto() { # file -> 1 when an auto proc-type is found
    local f="$1" hits
    hits=$(grep -n 'proc[-_]type' "$f" 2>/dev/null | grep -v '^[0-9]*:#' || true)
    [ -n "$hits" ] || return 0
    case "$hits" in
        *auto*) say "PROCTYPE-FAIL: auto proc-type in the f-stack config:"; say "$hits"; return 1 ;;
    esac
    return 0
}

gen_fstack_ini() { # tag graceful kni(0|1)
    # Two separate declarations on purpose: bash expands every word of a
    # `local` statement before running it, so $tag would still be unset in
    # `local tag=$1 ini=$OUT/...$tag...` and set -u would abort the function.
    local tag="$1" g="$2" kni="${3:-0}"
    local ini="$OUT/fstack_$tag.ini"
    # The topology follows the graceful form of THIS case, not the global
    # default: rv9/rt02/rt12/rt13 always run =1 while gr0 and a --graceful 0
    # rt01/baseline run =0 (F-M6-3(1)).
    derive_lcores "$g"
    # Log-only on purpose: gen_fstack_ini's stdout is the ini path, so a say()
    # here (tee to stdout + log) would end up inside the caller's variable.
    printf 'topology tag=%s graceful=%s lcore_mask=0x%s primary_lcore=%s worker_lcores=[%s]\n' \
        "$tag" "$g" "$LCORE_MASK" "$PRIMARY_LCORE" "$LCORE_LIST" >> "$LOG"
    cp -f "$FSTACK_TPL" "$ini" || die_dep "cannot copy the f-stack template"
    ini_set "$ini" dpdk graceful_reload "$g"
    ini_set "$ini" dpdk file_prefix "$RUN_ID"
    if [ "$g" = "1" ]; then
        ini_set "$ini" dpdk primary_slim 1
    else
        ini_set "$ini" dpdk primary_slim 0
    fi
    ini_force_port_lcores "$ini" "$LCORE_LIST"
    ini_set "$ini" dpdk lcore_mask "$LCORE_MASK"
    # The template's log prefix may be a relative path, which would drop
    # f-stack-<proc_id>.log into whatever directory the harness was started
    # from (i.e. inside the repo). Keep every artifact under $OUT.
    ini_set "$ini" dpdk fstack_log_file_prefix "$OUT/fstack-"
    if [ "$BASELINE" = "1" ]; then
        ini_set "$ini" freebsd.sysctl net.link.ether.inet.garp_rexmit_count 8
    fi
    [ "$kni" = "1" ] && ini_force_kni "$ini" "$KNI_OWNER_PROC_ID"
    # A local template may carry [kni] enable=1; kni=0 cases must strip it or
    # they silently run with KNI, contradicting the documented harness design.
    [ "$kni" != "1" ] && ini_strip_kni "$ini"
    ini_drop_proc_type_auto "$ini" || return 1
    printf '%s' "$ini"
}

# ---- nginx conf generation ------------------------------------------------
gen_nginx_conf() { # tag shutdown_timeout_seconds
    # See gen_fstack_ini: $tag must be bound before it is used in a path.
    local tag="$1" st="$2" stline=""
    local conf="$OUT/ngx_$tag.conf" listen="80"
    case "$TARGET_IP" in *:*) listen="[::]:80 ipv6only=on" ;; esac
    [ "$st" != "0" ] && stline="worker_shutdown_timeout  ${st}s;"
    cat > "$conf" <<CONF

user  root;
daemon on;
master_process on;
# RT-05/RT-07 fault-injection whitelist: nginx drops inherited environment
# variables in workers unless listed here, so without these lines a worker
# never sees FF_FAULT and injected faults stay inert.
env FF_FAULT;
env FF_FAULT_DELAY_MS;
env FF_RELOAD_RUN_ID;
worker_processes  $WORKERS;
# worker_shutdown_timeout is deliberately absent for the active-drain verdicts
# (RT-02 / RT-04 class): the shutdown timer caps the G_old QUIT wait and would
# mask the natural drain completion. The rv9 loop gate sets it explicitly
# (10..20 s) to keep the machine time bounded.
$stline

error_log  $OUT/err_$tag.log  notice;
pid        $OUT/nginx.pid;

fstack_conf $OUT/fstack_$tag.ini;

events {
    worker_connections  102400;
    use kqueue;
}

http {
    include       /usr/local/nginx_fstack/conf/mime.types;
    default_type  application/octet-stream;
    access_log    off;
    sendfile      off;

    keepalive_timeout  300;

    server {
        listen       $listen;
        server_name  localhost;

        location / {
            root   html;
            index  index.html index.htm;
        }

        # active-stream payload root (RT-02 / F-M4-7)
        location /dl/ {
            root   $OUT/www;
        }
    }
}
CONF
    printf '%s' "$conf"
}

# ---- start / stop ---------------------------------------------------------
start_stack() { # tag graceful shutdown_timeout [kni]
    local tag="$1" g="$2" st="$3" kni="${4:-0}" conf ini rc
    ini=$(gen_fstack_ini "$tag" "$g" "$kni") || return 1
    conf=$(gen_nginx_conf "$tag" "$st")
    ERRLOG="$OUT/err_$tag.log"
    PIDFILE="$OUT/nginx.pid"
    : > "$ERRLOG"
    say "--- start_stack tag=$tag graceful=$g shutdown_timeout=${st}s kni=$kni"
    say "    ini=$ini conf=$conf"
    if [ -z "$ini" ] || [ -z "$conf" ] || [ ! -f "$conf" ]; then
        say "start_stack: generated artifacts missing (ini=[$ini] conf=[$conf])"
        return 1
    fi
    verify_build_identity || return 1
    STACK_STARTED=1
    STACK_ID="$tag"
    python3 -B "$SUPERVISOR" start "$STACK_ID" \
        "$(sha256sum "$NGINX_BIN" | awk '{print $1}')" "$NGINX_BIN" -c "$conf" >> "$LOG" 2>&1
    rc=$?
    collect_owned || return 1
    [ "$rc" = "0" ] || { say "start_stack: nginx exited rc=$rc"; return 1; }
    sleep "$STARTUP_WAIT"
    collect_owned || return 1
    wait_http || return 1
    say "start_stack: master=$(master_pid) workers=$(worker_count)"
    return 0
}


# ---- three-check ----------------------------------------------------------
# dual=1 is the USR2 (RT-04/04b) form: two masters coexist by design, so the
# check records the live master list instead of failing. The current case set
# has no USR2 scenario, so nothing calls it yet -- it is the documented hook
# point for RT-04/04b; stop_stack already handles the nginx.pid.oldbin pair.
three_check() { # [dual]  dual=1 -> two masters expected (USR2), record only
    local dual="${1:-0}" res=0 left z sp rt fresh p
    if [ "$dual" = "1" ]; then
        say "CHECK3-DUAL masters on duty (expected during USR2):"
        ps -eo pid,ppid,stat,comm 2>/dev/null | awk '$2 != 1 && $4 ~ /^nginx:/ {print}'
        for p in $(cat "$OUT/nginx.pid" "$OUT/nginx.pid.oldbin" 2>/dev/null); do
            ps -p "$p" -o pid,stat,comm 2>/dev/null | tail -1
        done
    else
        left=$(nginx_residue)
        if [ -n "$left" ]; then
            say "CHECK3-FAIL: nginx process residue"; say "$left"; res=1
        fi
    fi
    z=$(ps -eo stat,comm 2>/dev/null | awk '$1 ~ /^Z/ && $2 ~ /^nginx/ {c++} END {print c+0}')
    [ "$z" != "0" ] && say "CHECK3-NOTE: $z zombie nginx (bypassed, holds no resources)"
    sp=$(ps -eo stat,comm 2>/dev/null | awk '$1 !~ /^Z/ && $2 ~ /^ff_slim/ {c++} END {print c+0}')
    [ "$sp" != "0" ] && say "CHECK3-NOTE: $sp resident slim primary (by design, not residue)"
    rt=$(rtemap_count)
    [ "$rt" != "0" ] && { say "CHECK3-FAIL: $rt rtemap files in /dev/hugepages"; res=1; }
    if [ -d /var/run/dpdk/rte ]; then
        # -mindepth 1: an empty leftover directory holds nothing and is a NOTE,
        # only entries with a fresh mtime mean a live/aborted EAL is around.
        fresh=$(find /var/run/dpdk/rte -mindepth 1 -mmin -"$RTE_FRESH_MIN" -print 2>/dev/null)
        if [ -n "$fresh" ]; then
            say "CHECK3-FAIL: fresh /var/run/dpdk/rte entries:"; say "$fresh"; res=1
            # /var/run/dpdk/rte is the DEFAULT file-prefix home, so it is held
            # either by our own f-stack stack or by tests/unit, whose
            # equiv_eal_init_once() calls rte_eal_init() with no --file-prefix.
            # Cross-checking the process table tells the two apart: no nginx
            # alive means the lock is a concurrent unit-test EAL, not residue.
            if [ -z "$(nginx_residue)" ]; then
                say "CHECK3-HINT: no nginx alive -- likely a concurrent tests/unit EAL"
                say "CHECK3-HINT: (equiv_eal_init_once() uses the default file-prefix)"
            else
                say "CHECK3-HINT: nginx is alive -- real residue, stop it before retrying"
            fi
        fi
    fi
    # Private file-prefix directories (ff_int_test / ff_kni_int / ff_kni_test /
    # ff_reload_it) come from the unit and integration binaries, use --no-huge
    # and hold no hugepage, so they never conflict: recorded, never judged.
    if [ -d /var/run/dpdk ]; then
        local others
        others=$(find /var/run/dpdk -mindepth 1 -maxdepth 1 -type d \
                      ! -name rte -printf '%f ' 2>/dev/null)
        [ -n "$others" ] && say "CHECK3-NOTE: private prefix dirs in /var/run/dpdk: $others (no conflict)"
    fi
    say "CHECK3 ps_ok rtemap=$rt hp_free=$(hp_free) res=$res"
    return $res
}

# ---- probe plumbing -------------------------------------------------------
have_probe() { [ -f "$PROBE_DIR/$1" ]; }


prep_stream_payload() {
    mkdir -p "$OUT/www/dl" || return 1
    [ -f "$OUT/www/dl/big.bin" ] || \
        dd if=/dev/zero of="$OUT/www/dl/big.bin" bs=1M count="$STREAM_MB" status=none
    STREAM_MD5=$(md5sum "$OUT/www/dl/big.bin" | awk '{print $1}')
    say "stream payload ${STREAM_MB}MB md5=$STREAM_MD5"
}

# ===========================================================================
# CASES
# ===========================================================================

case_precheck() {
    local miss=0 f
    say "=== case precheck (three-check + dependency gate) ==="
    for f in "$KILLTOOL" "$RMTMP" "$CHMODTOOL"; do
        [ -x "$f" ] || { say "MISSING wrapper $f"; miss=1; }
    done
    [ -x "$NGINX_BIN" ] || { say "MISSING nginx binary $NGINX_BIN"; miss=1; }
    [ -f "$FSTACK_TPL" ] || { say "MISSING f-stack template $FSTACK_TPL"; miss=1; }
    validate_probe_package || miss=1
    [ "$miss" != "0" ] && {
        record "precheck" "FAIL" "wrappers + nginx + f-stack template present" \
               "missing artifacts, see $LOG"
        return 1; }
    if ! remote_precheck; then
        record "precheck" "FAIL" "client $CLIENT reachable over ssh" "client unreachable"
        return 1
    fi
    if three_check; then
        record "precheck" "PASS" \
          "ps empty + rtemap=0 + /var/run/dpdk/rte untouched for ${RTE_FRESH_MIN} min" \
          "ps_ok rtemap=$(rtemap_count) hp_free=$(hp_free)"
        return 0
    fi
    record "precheck" "FAIL" \
      "ps empty + rtemap=0 + /var/run/dpdk/rte untouched for ${RTE_FRESH_MIN} min" \
      "precondition violated, see CHECK3-FAIL lines"
    return 1
}

case_baseline() {
    local tag="base" conf out summary fails recon freshf rc fetch=0
    say "=== case baseline (no-takeover long-run control) ==="
    conf=$(gen_nginx_conf "$tag" 0)
    push_probes || return 1
    if ! start_stack "$tag" "$GRACEFUL" 0; then
        stop_stack "$tag" "$conf" || rc=1
        record "baseline" "FAIL" "stack starts and serves 200" "start failed"
        return 1
    fi
    if have_probe m4_lc.py; then
        local budget
        budget=$(python3 -B -c 'import math,sys; print(math.ceil(float(sys.argv[1]))+60)' "$BASELINE_DURATION")
        if launch_probe baseline "$budget" m4_lc.py --server "$TARGET_IP" --conns 24 \
            --interval 0.5 --duration "$BASELINE_DURATION" --fresh 0.5 --timeout 2; then
            fetch=0
            summary=$(wait_client_summary baseline LC_SUMMARY "$budget") || fetch=$?
            if [ "$fetch" = "1" ]; then
                summary="NO_DATA (probe failed or timed out)"; rc=2
            elif [ "$fetch" = "2" ]; then
                # The probe judged itself failed: a real FAIL, never SKIP/PASS.
                say "baseline probe reported a summary but failed its own criterion"
                rc=1
            else
                check_summary lc "$summary" && rc=0 || rc=1
            fi
        else
            summary="NO_DATA (probe failed or timed out)"; rc=2
        fi
    else
        summary="NO_DATA (m4_lc.py absent from $PROBE_DIR)"; rc=2
    fi
    stop_stack "$tag" "$conf" || rc=1
    case $rc in
        0) record "baseline" "PASS" "control probe fail=0 reconnects=0 fresh_fail=0" "$summary"; return 0 ;;
        2) record "baseline" "SKIP" "control probe fail=0 reconnects=0 fresh_fail=0" "$summary"; return 0 ;;
        *) record "baseline" "FAIL" "control probe fail=0 reconnects=0 fresh_fail=0" "$summary"; return 1 ;;
    esac
}

# One HUP against the stack that is currently running. Results land in the
# HUP_* globals.
hup_once() { # conf
    local conf="$1" mark w line n drain fwd rel fsm nworkers
    mark=$(wc -l < "$ERRLOG")
    nginx_signal "$conf" reload || return 1
    w=0
    while [ "$w" -lt "$DRAIN_TIMEOUT" ]; do
        tail -n +$((mark + 1)) "$ERRLOG" | grep -q 'graceful reload complete' && break
        sleep 1; w=$((w + 1))
    done
    line=$(tail -n +$((mark + 1)) "$ERRLOG" | grep 'graceful reload complete' | tail -1)
    n=$(tail -n +$((mark + 1)) "$ERRLOG" | grep -c 'graceful reload complete')
    fsm=$(tail -n +$((mark + 1)) "$ERRLOG" | grep -c 'graceful reload fsm:')
    drain=$(printf '%s' "$line" | sed -n 's/.*drain \([0-9]*\) ms.*/\1/p')
    fwd=$(printf '%s' "$line" | sed -n 's/.*drain forwarded \([0-9]*\).*/\1/p')
    rel=$(printf '%s' "$line" | sed -n 's/.*relayed \([0-9]*\) pkts.*/\1/p')
    nworkers=$(worker_count)
    HUP_FSM="$fsm"
    HUP_DRAIN="${drain:-NA}"
    HUP_FWD="${fwd:-NA}"
    HUP_REL="${rel:-NA}"
    say "HUP fsm=$fsm/6 complete=$n drain=${HUP_DRAIN}ms forwarded=${HUP_FWD} relayed=${HUP_REL} workers=$nworkers"
    [ -n "$line" ] || { say "HUP: no 'graceful reload complete' within ${DRAIN_TIMEOUT}s"; return 1; }
    [ "$n" = "1" ] || { say "HUP: $n completion lines, expected exactly 1"; return 1; }
    [ "$fsm" -ge 6 ] || { say "HUP: only $fsm/6 FSM transitions"; return 1; }
    [ "$nworkers" = "$WORKERS" ] || { say "HUP: workers=$nworkers != $WORKERS (G_old still alive)"; return 1; }
    return 0
}

# start -> probe -> one HUP -> judge -> stop
# Returns: 0 pass / 1 fail / 2 the reload passed but the traffic criterion has
# no data. A missing probe must never be silently counted as a pass, and never
# as a regression either, hence the dedicated code.
do_hup_case() { # tag graceful shutdown_timeout probe-kind(none|stream|lc|cps)
    local tag="$1" g="$2" st="$3" probe="$4"
    local conf out rc=0 nodata=0 wave=0 fetch=0 summary="no traffic probe"
    conf=$(gen_nginx_conf "$tag" "$st")
    push_probes || return 1
    if ! start_stack "$tag" "$g" "$st"; then
        stop_stack "$tag" "$conf" || rc=1
        HUP_SUMMARY="start failed"
        return 1
    fi
    # F-M4-7: the drain verdict needs ACTIVE connections -- a continuously
    # streaming set or a high-rate fresh-connection probe, never idle ones.
    case "$probe" in
        stream)
            prep_stream_payload || return 1
            # One wave costs payload / (chunk per gap) seconds; the probe lives
            # STREAM_DURATION and then finishes the wave in flight. Refuse a
            # payload that cannot fit the 300 s remote probe budget instead of
            # letting the probe be killed and the case decay into NO_DATA/SKIP.
            wave=$(( STREAM_MB * 1048576 / 163840 ))
            if [ $(( STREAM_DURATION + wave )) -gt 300 ]; then
                say "stream payload ${STREAM_MB}MB needs ~$(( STREAM_DURATION + wave ))s > 300s probe budget"
                return 1
            fi
            launch_probe "$tag" 300 m4_stream.py --server "$TARGET_IP" \
                --path /dl/big.bin --streams 12 --chunk 16384 --gap 0.1 \
                --timeout 5 --stall 3.0 --duration "$STREAM_DURATION" \
                --expect-md5 "$STREAM_MD5" || return 1
            sleep 3 ;;
        lc)
            launch_probe "$tag" 120 m4_lc.py --server "$TARGET_IP" --conns 12 \
                --interval 0.1 --duration 90 --fresh 0.5 --timeout 2 || return 1
            sleep 3 ;;
        cps)
            launch_probe "$tag" 120 m4_cps.py --server "$TARGET_IP" --threads 1 \
                --duration 90 --timeout 2 || return 1
            sleep 3 ;;
    esac

    [ "$probe" = none ] || probe_running || rc=1
    hup_once "$conf" || rc=1
    [ "$probe" = none ] || probe_running || rc=1

    # wait_client_summary reports 1 = no data (timeout / summary absent) and
    # 2 = the probe reported a summary but failed its own criterion. Only the
    # first is NO_DATA (SKIP); the second keeps the real summary so the case
    # fails on evidence instead of hiding behind "no data".
    case "$probe" in
        stream)
            fetch=0
            summary=$(wait_client_summary "/tmp/gr_${tag}_stream.log" 'STREAM_SUMMARY' 180) \
                || fetch=$?
            if [ "$fetch" = "1" ]; then
                summary="NO_DATA (m4_stream.py did not report within 180 s)"; nodata=1
            elif [ "$fetch" = "2" ]; then
                say "stream probe reported a summary but failed its own criterion"
                rc=1
            fi
            if [ "$nodata" = "0" ]; then
                check_summary stream "$summary" \
                    || { say "stream verdict below target: $summary"; rc=1; }
                # F-M4-7 sanity: an active-stream drain cannot finish in <100 ms
                if [ "$HUP_DRAIN" != "NA" ] && [ "$HUP_DRAIN" -lt 100 ]; then
                    say "drain ${HUP_DRAIN}ms too short for an active stream (F-M4-7)"; rc=1
                fi
            else
                say "stream criterion has no data: $summary"
            fi ;;
        lc)
            fetch=0
            summary=$(wait_client_summary "/tmp/gr_${tag}_lc_out.log" 'LC_SUMMARY' 180) \
                || fetch=$?
            if [ "$fetch" = "1" ]; then
                summary="NO_DATA (m4_lc.py did not report within 180 s)"; nodata=1
            elif [ "$fetch" = "2" ]; then
                say "lc probe reported a summary but failed its own criterion"
                rc=1
            fi
            if [ "$nodata" = "0" ]; then
                check_summary lc "$summary" || { say "lc verdict below target"; rc=1; }
            else
                say "lc criterion has no data: $summary"
            fi ;;
        cps)
            fetch=0
            summary=$(wait_client_summary "/tmp/gr_${tag}_cps.log" 'CPS_SUMMARY' 180) \
                || fetch=$?
            if [ "$fetch" = "1" ]; then
                summary="NO_DATA (m4_cps.py did not report within 180 s)"; nodata=1
            elif [ "$fetch" = "2" ]; then
                say "cps probe reported a summary but failed its own criterion"
                rc=1
            fi
            if [ "$nodata" = "0" ]; then
                check_summary cps "$summary" || { say "cps verdict below target"; rc=1; }
            else
                say "cps criterion has no data: $summary"
            fi ;;
    esac

    stop_stack "$tag" "$conf" || rc=1
    HUP_SUMMARY="$summary"
    [ "$rc" != "0" ] && return 1
    [ "$nodata" != "0" ] && return 2
    return 0
}

# ---- fault-injection cases (F1) ------------------------------------------
# These need a fault-injection build (FF_RELOAD_FAULT_INJECTION=1) and a
# manifest that declares it; reload_checks.verify-build enforces the pairing in
# both directions. They never contribute to functional acceptance: rt23 is the
# only one that runs on the production form.
fault_case() { # tag fault expect(ok|abort) criterion [abort-signature]
    local tag="$1" fault="$2" expect="$3" crit="$4" sig="${5:-}"
    local rc=0 conf out before
    # The --fault option drives the build-form gate; it must name the same
    # fault the case injects, otherwise a verdict could be labelled wrongly.
    if [ "$FAULT" != "$fault" ]; then
        say "$tag: --fault=$FAULT does not match the case fault $fault"
        record "$tag" "FAIL" "$crit" "fault option/case mismatch ($FAULT vs $fault)"
        return 1
    fi
    export FF_FAULT="$fault"
    if [ "$fault" = "ready_delay" ]; then
        export FF_FAULT_DELAY_MS="$FAULT_DELAY_MS"
    else
        unset FF_FAULT_DELAY_MS
    fi
    conf=$(gen_nginx_conf "$tag" 0)
    push_probes || { unset FF_FAULT; unset FF_FAULT_DELAY_MS; return 1; }
    if ! start_stack "$tag" 1 0; then
        stop_stack "$tag" "$conf" || rc=1
        unset FF_FAULT
        record "$tag" "FAIL" "$crit" "start failed (fault=$fault)"
        return 1
    fi
    before=$(worker_count)
    if have_probe m4_lc.py; then
        launch_probe "$tag" 120 m4_lc.py --server "$TARGET_IP" --conns 12 \
            --interval 0.1 --duration 45 --fresh 0.5 --timeout 2 \
            || { unset FF_FAULT; unset FF_FAULT_DELAY_MS; stop_stack "$tag" "$conf"; record "$tag" "FAIL" "$crit" "probe launch failed"; return 1; }
        sleep 3
    fi
    probe_running || rc=1
    local hrc=0
    if [ "$expect" = abort ]; then
        # An aborted reload never prints the completion line, so waiting for it
        # would only burn the drain timeout. Wait for the abort signature
        # instead, bounded by the READY/park budget plus a margin.
        nginx_signal "$conf" reload || hrc=1
        local deadline=$((SECONDS + 90)) found=0
        while [ "$SECONDS" -lt "$deadline" ]; do
            if [ -n "$sig" ]; then
                if grep -q "graceful reload aborted: $sig" "$ERRLOG"; then found=1; break; fi
            elif grep -q "graceful reload aborted" "$ERRLOG"; then
                found=1; break
            fi
            sleep 1
        done
        if [ "$found" != "1" ]; then
            say "$tag: no bounded abort within 90 s (errlog: $ERRLOG)"
            hrc=1
        fi
    else
        hup_once "$conf" || hrc=1
    fi
    # hrc == 0 means the expected event happened: the bounded abort signature
    # for expect=abort, the completion line for expect=ok.
    [ "$hrc" = "0" ] || { say "$tag: expect=$expect not satisfied (rc=$hrc)"; rc=1; }
    # NB: no probe_running check here -- by the time the bounded abort/completion
    # is observed the probe (45 s) has normally finished; the probe's own
    # summary below is the evidence that G_old kept serving, not a liveness bit.
    # G_old must have kept serving: the probe's own verdict must be clean.
    local summary="no probe" fetch=0
    if ! have_probe m4_lc.py; then
        # No probe means no evidence that G_old kept serving: never a silent
        # pass (same rule as the other cases in this harness).
        unset FF_FAULT
        unset FF_FAULT_DELAY_MS
        stop_stack "$tag" "$conf" || rc=1
        record "$tag" "SKIP" "$crit" "NO_DATA (m4_lc.py absent from $PROBE_DIR)"
        return 0
    fi
    if have_probe m4_lc.py; then
        summary=$(wait_client_summary /tmp/gr_${tag}_lc_out.log 'LC_SUMMARY' 120) || fetch=$?
        if [ "$fetch" = "1" ]; then
            summary="NO_DATA (m4_lc.py did not report within 120 s)"; rc=1
        elif [ "$fetch" = "2" ]; then
            say "$tag: probe reported a summary but failed its own criterion"; rc=1
        fi
        check_summary lc "$summary" || { say "$tag: lc verdict below target: $summary"; rc=1; }
    fi
    # no double master and no lost generation: the count must be back to
    # exactly the pre-reload set.
    if [ "$(worker_count)" -ne "$before" ]; then
        say "$tag: worker count changed ($before -> $(worker_count))"
        rc=1
    fi
    unset FF_FAULT
    unset FF_FAULT_DELAY_MS
    stop_stack "$tag" "$conf" || rc=1
    if [ "$rc" = "0" ]; then
        record "$tag" "PASS" "$crit" \
          "fault=$fault expect=$expect hrc=$hrc workers_before=$before traffic=$summary (fault-injection build)"
    else
        record "$tag" "FAIL" "$crit" \
          "fault=$fault expect=$expect hrc=$hrc workers_before=$before traffic=$summary (fault-injection build)"
    fi
    return $rc
}

case_rt20() {
    say "=== case rt20 (READY never arrives -> bounded abort) ==="
    fault_case "rt20" ready_never abort \
      "READY wait times out within NGX_FF_RELOAD_READY_WAIT_SEC (60s); reload aborts to T0_IDLE; G_old keeps serving; no second master" \
      "READY wait timed out"
}
case_rt20b() {
    say "=== case rt20b (READY late but reachable -> completes) ==="
    fault_case "rt20b" ready_delay ok \
      "READY delayed by FF_FAULT_DELAY_MS (<60s) still completes: 6/6 FSM, workers back to N, service restored"
}
case_rt21() {
    say "=== case rt21 (handover flip fails -> T2/T_ERROR/T0) ==="
    fault_case "rt21" flip_fail abort \
      "T2 -> T_ERROR -> T0 with 'rx ownership flip failed'; G_old keeps serving; no half-handover" \
      "rx ownership flip failed"
}
case_rt22() {
    say "=== case rt22 (park never confirmed -> bounded abort) ==="
    fault_case "rt22" park_never abort \
      "park budget (FF_RELOAD_HANDOVER_TIMEOUT_MS_DEFAULT 100U) expires: T_ERROR -> T0 with 'G_old park confirmation timed out'" \
      "G_old park confirmation timed out"
}
case_rt23() {
    say "=== case rt23 (reload re-entry during drain is refused) ==="
    local rc=0 conf out
    # rt23 is the only fault-matrix case that runs on the PRODUCTION form:
    # --fault/BUILD_MANIFEST are per-run globals, so refuse the mixed form and
    # drop any inherited fault variables.
    if [ -n "$FAULT" ]; then
        say "rt23: requires the production form (--fault=$FAULT)"
        record "rt23" "FAIL" "second HUP during T3 is refused; first reload still completes" \
          "fault form not allowed for rt23"
        return 1
    fi
    unset FF_FAULT
    unset FF_FAULT_DELAY_MS
    conf=$(gen_nginx_conf "rt23" 0)
    prep_stream_payload || return 1
    push_probes || return 1
    if ! start_stack "rt23" 1 0; then
        stop_stack "rt23" "$conf" || rc=1
        record "rt23" "FAIL" "second HUP during T3 is refused; first reload still completes" "start failed"
        return 1
    fi
    launch_probe rt23 300 m4_stream.py --server "$TARGET_IP" \
        --path /dl/big.bin --streams 12 --chunk 16384 --gap 0.1 \
        --timeout 5 --stall 3.0 --duration "$STREAM_DURATION" \
        --expect-md5 "$STREAM_MD5" || return 1
    sleep 3
    probe_running || rc=1
    # The second HUP must land WHILE the first one is draining (T3), not after
    # it finished, otherwise it simply starts a second reload.
    nginx_signal "$conf" reload || rc=1
    sleep 5
    nginx_signal "$conf" reload || rc=1
    local deadline=$((SECONDS + 150)) done=0
    while [ "$SECONDS" -lt "$deadline" ]; do
        if grep -q "graceful reload complete" "$ERRLOG"; then done=1; break; fi
        sleep 1
    done
    [ "$done" = "1" ] || { say "rt23: first reload did not complete within 150 s"; rc=1; }
    grep -q "graceful reload rejected: previous reload still in progress" "$ERRLOG" \
        || { say "rt23: re-entry refusal not found in $ERRLOG"; rc=1; }
    HUP_SUMMARY=$(wait_client_summary /tmp/gr_rt23_stream.log 'STREAM_SUMMARY' 120) \
        || HUP_SUMMARY="NO_DATA (m4_stream.py did not report within 120 s)"
    stop_stack "rt23" "$conf" || rc=1
    if [ "$rc" = "0" ]; then
        record "rt23" "PASS" "second HUP during T3 is refused; first reload still completes" \
          "fsm=$HUP_FSM/6 drain=${HUP_DRAIN}ms traffic=$HUP_SUMMARY"
    else
        record "rt23" "FAIL" "second HUP during T3 is refused; first reload still completes" \
          "fsm=$HUP_FSM/6 drain=${HUP_DRAIN}ms traffic=$HUP_SUMMARY"
    fi
    return $rc
}

case_rt01() {
    say "=== case rt01 (unloaded HUP) ==="
    local rc=0
    do_hup_case "rt01" "$GRACEFUL" 0 none || rc=1
    if [ "$rc" = "0" ]; then
        record "rt01" "PASS" \
          "reload complete + 6/6 FSM transitions + worker count back to $WORKERS" \
          "fsm=$HUP_FSM/6 drain=${HUP_DRAIN}ms fwd=${HUP_FWD} rel=${HUP_REL} traffic=$HUP_SUMMARY"
    else
        record "rt01" "FAIL" \
          "reload complete + 6/6 FSM transitions + worker count back to $WORKERS" \
          "fsm=$HUP_FSM/6 drain=${HUP_DRAIN}ms fwd=${HUP_FWD} rel=${HUP_REL} traffic=$HUP_SUMMARY"
    fi
    return $rc
}

case_rt02() {
    say "=== case rt02 (HUP under active streams, F-M4-7) ==="
    local rc=0
    if ! have_probe m4_stream.py; then
        record "rt02" "SKIP" "12 active streams ok/md5_ok/eof_clean=12 and stalls=0" \
               "NO_DATA: m4_stream.py absent from $PROBE_DIR"
        return 0
    fi
    local hrc=0
    do_hup_case "rt02" 1 0 stream || hrc=$?
    if [ "$hrc" = "2" ]; then
        record "rt02" "SKIP" \
          "12 active streams ok=12 md5_ok=12 eof_clean=12 stalls=0; drain>=100ms; conf without worker_shutdown_timeout" \
          "NO_DATA: reload itself completed (drain=${HUP_DRAIN}ms fwd=${HUP_FWD} rel=${HUP_REL}) but $HUP_SUMMARY"
        return 0
    fi
    [ "$hrc" != "0" ] && rc=1
    if [ "$rc" = "0" ]; then
        record "rt02" "PASS" \
          "12 active streams ok=12 md5_ok=12 eof_clean=12 stalls=0; drain>=100ms; conf without worker_shutdown_timeout" \
          "drain=${HUP_DRAIN}ms fwd=${HUP_FWD} rel=${HUP_REL} traffic=$HUP_SUMMARY"
    else
        record "rt02" "FAIL" \
          "12 active streams ok=12 md5_ok=12 eof_clean=12 stalls=0; drain>=100ms; conf without worker_shutdown_timeout" \
          "drain=${HUP_DRAIN}ms fwd=${HUP_FWD} rel=${HUP_REL} traffic=$HUP_SUMMARY"
    fi
    return $rc
}

trend_slope() { # file of one value per line -> least-squares slope
    awk '{ n++; sx+=NR; sy+=$1; sxy+=NR*$1; sxx+=NR*NR }
         END { if (n<2) { print 0; exit }
               d = n*sxx - sx*sx; if (d==0) { print 0; exit }
               printf "%.6f", (n*sxy - sx*sy)/d }' "$1"
}

case_rv9() {
    say "=== case rv9 (reload loop) rounds=$ROUNDS interval=${INTERVAL}s poll=${POLL}s ==="
    local conf ok=0 bad=0 rejected=0 r waited idle_ok w n line drain fwd rel
    local rt hp base_hp final_rt final_hp pre_hp traffic="no probe" fetch=0
    local rt_slope hp_slope rt_min rt_max hp_min
    local st="$SHUTDOWN_TIMEOUT"
    [ "$st" = "0" ] && st=15   # bound the drain; 0 lets T3 stretch to 90 s

    pre_hp=$(hp_free)
    conf=$(gen_nginx_conf "rv9" "$st")
    push_probes || return 1
    if ! start_stack "rv9" 1 "$st"; then
        stop_stack "rv9" "$conf"
        record "rv9" "FAIL" "stack starts for the loop" "start failed"
        return 1
    fi

    # S7 rev-2 form: fresh-only probe. Parking keep-alive connections on G_old
    # is what turns every round into a 90 s deadline run; high-rate fresh
    # connections keep the drain verdict meaningful and the machine time sane.
    if have_probe m4_lc.py; then
        local dur=$(( ROUNDS * INTERVAL + 90 ))
        launch_probe rv9 "$((dur + 30))" m4_lc.py --server "$TARGET_IP" --conns 0 \
            --interval 0.5 --duration "$dur" --fresh 0.2 --timeout 2 || return 1
    else
        record rv9 BLOCKED 'fresh-connection probe required' 'probe missing'
        return 1
    fi

    base_hp=$(hp_free)
    : > "$OUT/rv9_rt.series"; : > "$OUT/rv9_hp.series"; : > "$OUT/rv9_dr.series"
    say "loop conf=[$conf] errlog=[$ERRLOG] master=$(master_pid)"

    for r in $(seq 1 "$ROUNDS"); do
        local t0; t0=$(date +%s)
        idle_ok=0; waited=0
        while [ "$waited" -lt "$DRAIN_TIMEOUT" ]; do
            if ! reload_in_flight && [ "$(worker_count)" = "$WORKERS" ]; then
                idle_ok=1; break
            fi
            sleep "$POLL"; waited=$((waited + POLL))
        done
        if [ "$idle_ok" != "1" ]; then
            bad=$((bad + 1))
            say "ROUND r=$r INCOMPLETE reason=not-idle workers=$(worker_count)"
        else
            local mark; mark=$(wc -l < "$ERRLOG")
            probe_running || { bad=$((bad + 1)); break; }
            nginx_signal "$conf" reload || { bad=$((bad + 1)); break; }
            w=0
            while [ "$w" -lt "$DRAIN_TIMEOUT" ]; do
                tail -n +$((mark + 1)) "$ERRLOG" | grep -q 'graceful reload complete' && break
                sleep 1; w=$((w + 1))
            done
            line=$(tail -n +$((mark + 1)) "$ERRLOG" | grep 'graceful reload complete' | tail -1)
            n=$(tail -n +$((mark + 1)) "$ERRLOG" | grep -c 'graceful reload complete')
            rejected=$(( rejected + $(tail -n +$((mark + 1)) "$ERRLOG" \
                         | grep -c 'previous reload still in progress') ))
            if [ "$n" = "1" ]; then
                ok=$((ok + 1))
                drain=$(printf '%s' "$line" | sed -n 's/.*drain \([0-9]*\) ms.*/\1/p')
                fwd=$(printf '%s' "$line" | sed -n 's/.*drain forwarded \([0-9]*\).*/\1/p')
                rel=$(printf '%s' "$line" | sed -n 's/.*relayed \([0-9]*\) pkts.*/\1/p')
                say "ROUND r=$r OK drain=${drain:-NA}ms forwarded=${fwd:-NA} relayed=${rel:-NA}"
            else
                bad=$((bad + 1)); drain=""
                say "ROUND r=$r INCOMPLETE n_complete=$n workers=$(worker_count)"
            fi
            echo "${drain:-0}" >> "$OUT/rv9_dr.series"
        fi
        rt=$(rtemap_count); hp=$(hp_free)
        echo "$rt" >> "$OUT/rv9_rt.series"
        echo "$hp" >> "$OUT/rv9_hp.series"
        if [ "$r" = "1" ] || [ $((r % 10)) -eq 0 ] || [ "$r" = "$ROUNDS" ]; then
            say "MILESTONE r=$r ok=$ok/$r bad=$bad psr=[$(worker_psr_list)] rtemap=$rt hp_free=$hp"
        fi
        local el=$(( $(date +%s) - t0 ))
        while [ "$el" -lt "$INTERVAL" ]; do sleep 1; el=$(( $(date +%s) - t0 )); done
    done

    sleep 3
    if have_probe m4_lc.py; then
        if traffic=$(wait_client_summary /tmp/gr_rv9_lc_out.log 'LC_SUMMARY' 180); then
            :
        else
            fetch=$?
            # 2 = the probe reported but failed its own criterion: keep the
            # real summary so the failure shows up in the verdict instead of
            # being relabelled "did not report".
            [ "$fetch" = "1" ] && traffic="NO_DATA (probe did not report within 180 s)"
            # fetch=2: the probe judged itself failed -- the verdict keeps the
            # summary, and the reload criterion below still applies.
            [ "$fetch" = "2" ] && traffic="PROBE_FAILED $traffic"
        fi
    fi
    stop_stack "rv9" "$conf" || bad=$((bad + 1))
    final_rt=$RECLAIM_RT; final_hp=$RECLAIM_HP

    # Leak is judged on the TREND, never on a single sample.
    rt_slope=$(trend_slope "$OUT/rv9_rt.series")
    hp_slope=$(trend_slope "$OUT/rv9_hp.series")
    rt_min=$(sort -n "$OUT/rv9_rt.series" | head -1)
    rt_max=$(sort -n "$OUT/rv9_rt.series" | tail -1)
    hp_min=$(sort -n "$OUT/rv9_hp.series" | head -1)
    say "TREND rtemap slope=$rt_slope min=$rt_min max=$rt_max | hp_free slope=$hp_slope min=$hp_min base=$base_hp"

    local rc=0 notes=""
    check_summary lc "$traffic" || { rc=1; notes="${notes}invalid_traffic;"; }
    [ "$bad" != "0" ] && { rc=1; notes="${notes}incomplete_rounds=$bad;"; }
    [ "$rejected" != "0" ] && notes="${notes}reentrancy_rejections=$rejected;"
    awk -v s="$rt_slope" 'BEGIN{exit !(s>0.05)}' && { rc=1; notes="${notes}rtemap_slope=$rt_slope;"; }
    [ $(( rt_max - rt_min )) -gt 32 ] && { rc=1; notes="${notes}rtemap_range=$((rt_max-rt_min));"; }
    [ $(( base_hp - hp_min )) -gt 64 ] && { rc=1; notes="${notes}hp_drop=$((base_hp-hp_min));"; }
    [ "$final_rt" != "0" ] && { rc=1; notes="${notes}rtemap_after_stop=$final_rt;"; }
    [ $(( pre_hp - final_hp )) -gt 32 ] && { rc=1; notes="${notes}hp_unreclaimed=$((pre_hp-final_hp));"; }
    [ -z "$notes" ] && notes="none"

    local meas="ok=$ok/$ROUNDS bad=$bad rtemap[min=$rt_min max=$rt_max slope=$rt_slope] hp[base=$base_hp min=$hp_min final=$final_hp] traffic=$traffic notes=$notes"
    if [ "$rc" = "0" ]; then
        record "rv9" "PASS" \
          "$ROUNDS reloads all complete; rtemap/hp trend flat; drain + forwarded/relayed recorded every round" \
          "$meas"
    else
        record "rv9" "FAIL" \
          "$ROUNDS reloads all complete; rtemap/hp trend flat; drain + forwarded/relayed recorded every round" \
          "$meas"
    fi
    return $rc
}

case_gr0() {
    say "=== case gr0 (graceful_reload=0 native control, RG-NR-01) ==="
    local conf out summary windows longest rl rc=0 fetch=0
    conf=$(gen_nginx_conf "gr0" 0)
    push_probes || return 1
    if ! start_stack "gr0" 0 0; then
        stop_stack "gr0" "$conf"
        record "gr0" "FAIL" "stack starts with graceful_reload=0" "start failed"
        return 1
    fi
    if have_probe m4_outage.py; then
        launch_probe gr0 45 m4_outage.py --server "$TARGET_IP" --duration 25 --timeout 0.5 || return 1
        sleep 5
        probe_running || rc=1
        nginx_signal "$conf" reload || rc=1
        fetch=0
        summary=$(wait_client_summary gr0 OUTAGE_SUMMARY 45) || fetch=$?
        [ "$fetch" = "1" ] && summary="NO_DATA"
        if [ "$fetch" = "2" ]; then
            say "gr0 outage probe reported a summary but failed its own criterion"
            rc=1
        fi
        check_summary outage "$summary" || rc=1
    else
        sleep 5
        nginx_signal "$conf" reload
        sleep 8
        summary="NO_DATA (m4_outage.py absent from $PROBE_DIR)"
    fi
    rl=$(grep -c 'graceful reload complete\|graceful reload fsm:' "$ERRLOG")
    stop_stack "gr0" "$conf"

    if [ "${summary#NO_DATA}" != "$summary" ]; then
        if [ "$rl" = "0" ]; then
            record "gr0" "SKIP" "legacy outage window measured; zero graceful-reload log lines" \
                   "$summary reload_log_lines=$rl"
            return 0
        fi
        record "gr0" "FAIL" "legacy outage window measured; zero graceful-reload log lines" \
               "$summary reload_log_lines=$rl (expected 0)"
        return 1
    fi
    windows=$(printf '%s' "$summary" | sed -n 's/.*windows=\([0-9]*\).*/\1/p')
    longest=$(printf '%s' "$summary" | sed -n 's/.*longest_outage=\([0-9.]*\)s.*/\1/p')
    [ "$rl" = "0" ] || { rc=1; say "gr0: $rl graceful-reload log lines under =0"; }
    [ "${windows:-0}" -ge 1 ] 2>/dev/null || { rc=1; say "gr0: no outage window measured"; }
    awk -v v="${longest:-0}" 'BEGIN{exit !(v>=0.3 && v<=2.5)}' \
        || { rc=1; say "gr0: longest_outage=${longest}s outside the 0.3..2.5 s band"; }
    if [ "$rc" = "0" ]; then
        record "gr0" "PASS" \
          "legacy two-phase outage present and inside the 0.3..2.5 s baseline band; zero graceful-reload log lines" \
          "$summary reload_log_lines=$rl"
    else
        record "gr0" "FAIL" \
          "legacy two-phase outage present and inside the 0.3..2.5 s baseline band; zero graceful-reload log lines" \
          "$summary reload_log_lines=$rl"
    fi
    return $rc
}

# RT-12. This tree has no rte_kni: KNI is a virtio_user vdev hot-plugged by
# ff_dpdk_kni.c, the kernel-side netif is veth<port_id>, and it needs
# /dev/vhost-net. The verdict is written for that form, not for rte_kni.
case_rt12() {
    say "=== case rt12 (KNI / virtio_user management plane) ==="
    local reason="" conf before after rc=0 crit mp_note=""
    local ping_client="not-checked" ping_local="not-checked" mp_state="" ctrl=""
    [ -c /dev/vhost-net ] || reason="no /dev/vhost-net device"
    if [ -n "$reason" ]; then
        record "rt12" "SKIP" \
          "veth<port_id> present before and after reload; management plane reachable after reload" \
          "LIMITED: $reason"
        return 0
    fi
    # Without --kernel-nic-ip the case still runs and still proves the real
    # KNI form (virtio_user netif survives the reload); only the management
    # plane leg is dropped, and the criterion line says so explicitly.
    if [ -z "$KERNEL_NIC_IP" ]; then
        mp_note="management plane NOT checked (--kernel-nic-ip not supplied)"
        say "rt12: $mp_note"
    fi
    conf=$(gen_nginx_conf "rt12" 0)
    push_probes || return 1
    if ! start_stack "rt12" 1 0 1; then
        stop_stack "rt12" "$conf"
        record "rt12" "FAIL" "stack starts with [kni] enable=1" "start failed, see $LOG"
        return 1
    fi
    before=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -c '^veth[0-9][0-9]*$')
    if have_probe m4_lc.py; then
        # Keep the probe shorter than the wait below, otherwise it can never
        # report and the KNI verdict gets buried under a NO_DATA skip.
        launch_probe rt12 90 m4_lc.py --server "$TARGET_IP" --conns 0 \
            --interval 0.5 --duration 45 --fresh 0.5 --timeout 2 || return 1
        sleep 3
    fi
    probe_running || rc=1
    hup_once "$conf" || rc=1
    probe_running || rc=1
    local summary="no probe" nodata=0 fetch=0
    if have_probe m4_lc.py; then
        summary=$(wait_client_summary /tmp/gr_rt12_lc_out.log 'LC_SUMMARY' 120) \
            || fetch=$?
        if [ "$fetch" = "1" ]; then
            summary="NO_DATA (m4_lc.py did not report within 120 s)"; nodata=1
        elif [ "$fetch" = "2" ]; then
            say "rt12: lc probe reported a summary but failed its own criterion"
            rc=1
        fi
        if [ "$nodata" = "0" ]; then
            check_summary lc "$summary" || rc=1
        else
            say "rt12: traffic criterion has no data: $summary"
        fi
    fi
    after=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -c '^veth[0-9][0-9]*$')
    if [ -n "$KERNEL_NIC_IP" ]; then
        # F-M6-3(2): the management-plane probe is issued from the CLIENT, so
        # the ICMP really crosses the KNI path (physical rx -> f-stack -> KNI
        # -> kernel) instead of looping inside the server. The server-local
        # ping is kept only as a clearly labelled weak observation: an address
        # configured on the server is answered by its own kernel and never
        # leaves the host.
        ping -c 2 -W 2 "$KERNEL_NIC_IP" >/dev/null 2>&1 \
            && ping_local="ok(local-scope,weak)" || ping_local="fail"
        if run_client "ping -c 3 -W 2 $KERNEL_NIC_IP >/dev/null 2>&1"; then
            ping_client="ok"
        else
            # Control probe: HTTP, not ICMP. Under [kni] method=reject an ICMP
            # echo to the f-stack address is diverted into the kernel, which
            # does not own that address, so it is silently dropped -- pinging
            # the control would make a perfectly healthy stack look dead (the
            # traffic probe and wait_http both prove the data path is up).
            ctrl=$(run_client "curl -s -m 3 -o /dev/null -w '%{http_code}' '$TARGET_URL'" 2>/dev/null)
            if [ "$ctrl" = "200" ]; then
                # The control address serves, so the client does reach the host
                # and only <KERNEL_NIC_IP> is undeliverable -- a cloud fabric
                # that delivers platform-assigned addresses only (M6 S2.4).
                # That is an environment limit, not a reload regression, so the
                # criterion is downgraded instead of failed.
                ping_client="unreachable"; mp_state="LIMITED"
            else
                ping_client="unreachable"; mp_state="DOWN"
            fi
        fi
    fi
    stop_stack "rt12" "$conf"
    [ "$before" -ge 1 ] || { rc=1; say "rt12: no veth netif before reload"; }
    [ "$after" -ge 1 ]  || { rc=1; say "rt12: no veth netif after reload"; }
    if [ "$mp_state" = "DOWN" ]; then
        rc=1
        say "rt12: management plane down: <KERNEL_NIC_IP> does not answer the client ping and the control address <DPDK_NIC_IP> does not serve HTTP either (ctrl=${ctrl:-none})"
    elif [ "$mp_state" = "LIMITED" ]; then
        say "rt12: LIMITED: <KERNEL_NIC_IP> unreachable from the client while the control address answers -- the management-plane criterion is NOT judged (environment: only platform-assigned addresses are delivered, M6 S2.4)"
    fi
    crit="veth<port_id> present before and after the reload + reload completes"
    if [ -n "$KERNEL_NIC_IP" ]; then
        if [ "$mp_state" = "LIMITED" ]; then
            crit="$crit + management plane (<KERNEL_NIC_IP>) reachable from the client [NOT JUDGED: undeliverable from the client while the control address answers; the server-local ping below is a local-scope weak observation only]"
        else
            crit="$crit + management plane (<KERNEL_NIC_IP>) reachable from the client afterwards"
        fi
    else
        crit="$crit ($mp_note)"
    fi
    # The KNI-specific criteria (netif + management plane) are independent of
    # the traffic probe, so missing probe data downgrades only the traffic part.
    if [ "$rc" = "0" ] && [ "$nodata" != "0" ]; then
        record "rt12" "SKIP" "$crit" \
          "NO_DATA: KNI criteria passed (veth_before=$before veth_after=$after ping_client=$ping_client control_http=${ctrl:-n/a} ping_local=$ping_local drain=${HUP_DRAIN}ms) but $summary"
        return 0
    fi
    if [ "$rc" = "0" ] && { [ "$mp_state" = LIMITED ] || [ -z "$KERNEL_NIC_IP" ]; }; then
        record rt12 LIMITED "$crit" 'management-plane criterion not verified'
        return 6
    fi
    if [ "$rc" = "0" ]; then
        record "rt12" "PASS" "$crit" \
          "veth_before=$before veth_after=$after ping_client=$ping_client control_http=${ctrl:-n/a} ping_local=$ping_local drain=${HUP_DRAIN}ms traffic=$summary"
    else
        record "rt12" "FAIL" "$crit" \
          "veth_before=$before veth_after=$after ping_client=$ping_client control_http=${ctrl:-n/a} ping_local=$ping_local drain=${HUP_DRAIN}ms traffic=$summary"
    fi
    return $rc
}

# RT-13. zc in this tree is the FSTACK_ZC_RECV / FSTACK_ZC_SEND compile switch
# over the stack<->application zero-copy read/write path; there is no zc
# config key and nginx never calls ff_zc_*. The case therefore judges the
# build form, and uses the drain forwarded/relayed pair as the observable
# proof that the dispatcher verdict does not depend on the mbuf source
# (hardware rx vs drain_ring).

case_rt13() {
    say "=== case rt13 (zc build form) ==="
    local zc="$ZC_BUILD" rc=0 src_ok=1
    [ "$zc" = "auto" ] && zc=$(detect_zc_build)
    if [ "$zc" != "1" ]; then
        record "rt13" "SKIP" \
          "zc build form reloads without regression; drain forwarded>0 and relayed>0 prove source independence" \
          "LIMITED: zc not compiled in (rebuild with FF_ZC_RECV=1); the case skeleton is in place"
        return 0
    fi
    local hrc=0
    do_hup_case "rt13" 1 0 stream || hrc=$?
    [ "${HUP_FWD:-0}" -gt 0 ] 2>/dev/null || src_ok=0
    [ "${HUP_REL:-0}" -gt 0 ] 2>/dev/null || src_ok=0
    [ "$src_ok" = "1" ] || { rc=1; say "rt13: forwarded/relayed pair incomplete"; }
    if [ "$hrc" = "2" ]; then
        record "rt13" "SKIP" \
          "zc build form reloads without regression; forwarded>0 and relayed>0 prove source independence" \
          "NO_DATA: reload completed (drain=${HUP_DRAIN}ms fwd=${HUP_FWD} rel=${HUP_REL}) but $HUP_SUMMARY"
        return 0
    fi
    [ "$hrc" != "0" ] && rc=1
    if [ "$rc" = "0" ]; then
        record "rt13" "PASS" \
          "zc build form reloads without regression; forwarded>0 and relayed>0 prove source independence" \
          "drain=${HUP_DRAIN}ms forwarded=${HUP_FWD} relayed=${HUP_REL} traffic=$HUP_SUMMARY"
    else
        record "rt13" "FAIL" \
          "zc build form reloads without regression; forwarded>0 and relayed>0 prove source independence" \
          "drain=${HUP_DRAIN}ms forwarded=${HUP_FWD} relayed=${HUP_REL} traffic=$HUP_SUMMARY"
    fi
    return $rc
}


# ===========================================================================
# main
# ===========================================================================
need_case() { case ",$CASES," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

source "$SCRIPT_DIR/common/reload_runtime.sh"

main() {
    parse_args "$@" || return $?
    derive_lcores "$GRACEFUL"
    if [ -z "${GR_SUPERVISOR_FD:-}" ]; then
        init_output || return 4
        GR_SUPERVISOR_LOCK=/data/workspace/.nginx-reload-harness.lock \
            exec python3 -B "$SUPERVISOR" run "$OUT" "$RUN_ID" 14400 -- \
            /bin/bash "${BASH_SOURCE[0]}" "$@"
    fi
    python3 -B "$SUPERVISOR" hello "${GR_SUPERVISOR_RUN:-}" >/dev/null || return 5
    OUT="$GR_SUPERVISOR_ROOT"
    RUN_ID="$GR_SUPERVISOR_RUN"
    EAL_PREFIX="container-$RUN_ID"
    REMOTE_DIR="/tmp/$RUN_ID"
    LOG="$OUT/harness.log"
    trap on_signal INT TERM
    trap 'cleanup_epilogue || true' EXIT
    local t
    for t in "$KILLTOOL" "$RMTMP" "$CHMODTOOL"; do
        [ -x "$t" ] || return 4
    done
    [ "$("$KILLTOOL" --capabilities)" = pidfd-identity-v1 ] || return 4
    zc_probe_selftest || return 4
    run_case precheck || { print_summary; return 3; }
    for t in baseline rt01 rt02 rv9 gr0 rt12 rt13 rt20 rt20b rt21 rt22 rt23; do
        need_case "$t" || continue
        run_case "$t"
        [ "$CLEANUP_FAILED" = 0 ] || break
    done
    cleanup_epilogue || CLEANUP_FAILED=1
    trap - EXIT
    print_summary
    [ "$CLEANUP_FAILED" = 0 ] || return 5
    python3 -B "$CHECKS" aggregate "$OUT/results.jsonl" "$CASES"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
    exit $?
fi
