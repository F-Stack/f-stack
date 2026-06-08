#!/bin/bash
# F-Stack Phase-5b: Perf baseline matrix harness
# Author: Phase-5b Leader
# Last update: 2026-06-08
#
# Usage:
#   ./p5b_perf_matrix.sh --config <C0|C7|C8|C9|C10> --tc <TC1|TC2|TC3> [--trials 3]
#
# Output:
#   /tmp/p5b/<config>_<tc>.csv         per-trial timings
#   /tmp/p5b/<config>_<tc>.summary     median + jitter + pass_rate
#
# Methodology:
#   TC1 = 100  serial curl from f-stack-client (short-conn)
#   TC2 = 1000 serial curl from f-stack-client (short-conn)
#   TC3 = 100  serial ping inside IPIP tunnel (10.10.10.1 from 10.10.10.2)
#
#   Each config runs `--trials` repetitions; we report median(T_total)
#   to dampen single-shot noise. Absolute QPS includes ssh round-trip
#   and is only valid for cross-config delta comparison.
#
# Constraints:
#   * Client (f-stack-client) only has curl + ping (no iperf3/wrk/ab).
#   * Server has 1× virtio NIC also carrying SSH (DPDK shared use).
#   * Compliance: no direct rm/kill/chmod — uses workspace wrappers.

set -e

CONFIG="${CONFIG:-}"
TC="${TC:-}"
TRIALS="${TRIALS:-3}"
SERVER_IP="${SERVER_IP:-9.134.214.176}"
TUNNEL_IP="${TUNNEL_IP:-10.10.10.1}"
OUT_DIR="${OUT_DIR:-/tmp/p5b}"

usage() {
    sed -n '2,30p' "$0"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --config) CONFIG="$2"; shift 2;;
        --tc) TC="$2"; shift 2;;
        --trials) TRIALS="$2"; shift 2;;
        --server-ip) SERVER_IP="$2"; shift 2;;
        --tunnel-ip) TUNNEL_IP="$2"; shift 2;;
        -h|--help) usage;;
        *) echo "Unknown arg: $1" >&2; usage;;
    esac
done

[[ -z "$CONFIG" || -z "$TC" ]] && usage

mkdir -p "$OUT_DIR"
CSV="$OUT_DIR/${CONFIG}_${TC}.csv"
SUM="$OUT_DIR/${CONFIG}_${TC}.summary"

echo "trial,t_total_s,pass_count,n,fail_rate" > "$CSV"

run_curl_trial() {
    local n="$1"
    # Returns: t_total_s pass_count
    timeout $((n / 10 + 30)) ssh f-stack-client "
        OK=0
        T0=\$(date +%s.%N)
        for i in \$(seq 1 $n); do
            CODE=\$(curl -sS -o /dev/null -w '%{http_code}' \\
                --connect-timeout 3 --max-time 5 \\
                http://${SERVER_IP}/ 2>/dev/null)
            [ \"\$CODE\" = '200' ] && OK=\$((OK+1))
        done
        T1=\$(date +%s.%N)
        echo \"\$(echo \"\$T1 - \$T0\" | bc) \$OK\"
    " 2>&1 | tail -1
}

run_ping_trial() {
    local n="$1"
    # ping the tunnel IP, return: t_total_s pass_count rtt_avg_ms
    timeout $((n + 20)) ssh f-stack-client "
        OUT=\$(ping -c $n -W 2 -i 0.2 ${TUNNEL_IP} 2>/dev/null | tail -3)
        T_TOTAL=\$(echo \"\$OUT\" | grep -oP 'time \K[0-9]+(?=ms)' | head -1)
        OK=\$(echo \"\$OUT\" | grep -oP '\d+(?= received)' | head -1)
        RTT=\$(echo \"\$OUT\" | grep -oP 'rtt min/avg/max[^=]*= [^/]+/\K[^/]+')
        echo \"\$(echo \"scale=3; \${T_TOTAL:-0} / 1000\" | bc) \${OK:-0} \${RTT:-NaN}\"
    " 2>&1 | tail -1
}

case "$TC" in
    TC1) N=100; KIND=curl;;
    TC2) N=1000; KIND=curl;;
    TC3) N=100; KIND=ping;;
    *) echo "Unknown TC: $TC" >&2; exit 1;;
esac

echo "[p5b] config=$CONFIG tc=$TC kind=$KIND n=$N trials=$TRIALS"

declare -a T_VALS

for ((t=1; t<=TRIALS; t++)); do
    echo "  trial $t/$TRIALS ..."
    if [[ "$KIND" == "curl" ]]; then
        RESULT=$(run_curl_trial "$N")
        T=$(echo "$RESULT" | awk '{print $1}')
        OK=$(echo "$RESULT" | awk '{print $2}')
        FR=$(awk -v ok="$OK" -v n="$N" 'BEGIN{printf "%.3f", (n-ok)/n}')
        echo "$t,$T,$OK,$N,$FR" >> "$CSV"
        echo "    t=${T}s pass=$OK/$N fail_rate=$FR"
        T_VALS+=("$T")
    else
        RESULT=$(run_ping_trial "$N")
        T=$(echo "$RESULT" | awk '{print $1}')
        OK=$(echo "$RESULT" | awk '{print $2}')
        RTT=$(echo "$RESULT" | awk '{print $3}')
        FR=$(awk -v ok="$OK" -v n="$N" 'BEGIN{printf "%.3f", (n-ok)/n}')
        echo "$t,$T,$OK,$N,$FR,$RTT" >> "$CSV"
        echo "    t=${T}s pass=$OK/$N rtt_avg_ms=$RTT fail_rate=$FR"
        T_VALS+=("$T")
    fi
done

# Compute median + min/max jitter
MEDIAN=$(printf '%s\n' "${T_VALS[@]}" | sort -n | awk 'BEGIN{c=0} {a[c++]=$1} END{ if(c%2) print a[int(c/2)]; else printf "%.3f\n", (a[c/2-1]+a[c/2])/2 }')
TMIN=$(printf '%s\n' "${T_VALS[@]}" | sort -n | head -1)
TMAX=$(printf '%s\n' "${T_VALS[@]}" | sort -n | tail -1)
JITTER=$(awk -v mx="$TMAX" -v mn="$TMIN" 'BEGIN{printf "%.3f", mx-mn}')

cat > "$SUM" <<EOF
config=$CONFIG
tc=$TC
n=$N
trials=$TRIALS
median_s=$MEDIAN
min_s=$TMIN
max_s=$TMAX
jitter_s=$JITTER
csv=$CSV
EOF

echo
echo "[p5b summary]"
cat "$SUM"
