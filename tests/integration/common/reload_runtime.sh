# Bounded execution helpers for the graceful-reload harness.

check_summary() {
    printf '%s\n' "$2" | python3 -B "$CHECKS" summary "$1" >/dev/null
}

run_client() {
    python3 -B "$CHECKS" bounded "${CLIENT_TIMEOUT:-30}" \
        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=yes \
        -o ConnectTimeout=5 -o ConnectionAttempts=1 \
        -o ServerAliveInterval=2 -o ServerAliveCountMax=3 "$CLIENT" "$@"
}

collect_owned() {
    [ "$STACK_STARTED" = 1 ] || return 0
    python3 -B "$SUPERVISOR" status "$STACK_ID" >/dev/null
}

nginx_signal() {
    local conf="$1" sig="$2" pid
    [ -f "$conf" ] || return 1
    case "$conf" in "$OUT"/ngx_*.conf) ;; *) return 1 ;; esac
    case "$sig" in reload) sig=HUP ;; stop) sig=TERM ;; quit) sig=QUIT ;; *) return 1 ;; esac
    collect_owned || return 1
    pid=$(master_pid)
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    python3 -B "$SUPERVISOR" signal "$STACK_ID" "$pid" "$sig" >/dev/null
}

stop_stack() {
    local tag="$1" conf="$2" rc=0
    RECLAIM_RT=-1
    RECLAIM_HP=0
    [ "$STACK_STARTED" = 1 ] || return 0
    python3 -B "$SUPERVISOR" stop "$STACK_ID" >/dev/null || rc=1
    python3 -B "$SUPERVISOR" assert-stopped "$STACK_ID" >/dev/null || rc=1
    STOP_RT=$(rtemap_count)
    STOP_HP=$(hp_free)
    say "NATURAL_RELEASE tag=$tag rtemap=$STOP_RT hp_free=$STOP_HP"
    [ "$rc" = 0 ] || { CLEANUP_FAILED=1; return 1; }
    clean_rte_runtime || { CLEANUP_FAILED=1; return 1; }
    RECLAIM_RT=$(rtemap_count)
    RECLAIM_HP=$(hp_free)
    [ "$RECLAIM_RT" = 0 ] || { CLEANUP_FAILED=1; return 1; }
    STACK_STARTED=0
    say "CONTROLLED_RECLAIM tag=$tag natural_rtemap=$STOP_RT natural_hp=$STOP_HP rtemap=$RECLAIM_RT hp_free=$RECLAIM_HP"
}

clean_rte_runtime() {
    python3 -B "$SUPERVISOR" assert-stopped "$STACK_ID" >/dev/null || return 1
    GR_SUPERVISOR_STACK="$STACK_ID" python3 -B "$CHECKS" reclaim "$EAL_PREFIX" "$OUT/processes.json" >> "$LOG" 2>&1
}

validate_probe_package() {
    local p
    for p in http_probe.py m4_lc.py m4_cps.py m4_stream.py m4_outage.py; do
        [ -r "$PROBE_DIR/$p" ] || return 1
    done
    [ -r "$SCRIPT_DIR/common/reload_remote.py" ] && [ -r "$CHECKS" ]
}

remote_precheck() {
    local expected actual
    expected=$(sha256sum "$KILLTOOL" | awk '{print $1}') || return 1
    actual=$(run_client "test -x '$KILLTOOL' && test -x '$RMTMP' && test -x '$CHMODTOOL' && '$KILLTOOL' --capabilities && sha256sum '$KILLTOOL'") || return 1
    [ "$actual" = "pidfd-identity-v1
$expected  $KILLTOOL" ]
}

push_probes() {
    [ "$PROBES_PUSHED" = 1 ] && return 0
    local p
    validate_probe_package && remote_precheck || return 1
    run_client "umask 077; mkdir '$REMOTE_DIR'" || return 1
    REMOTE_CREATED=1
    for p in http_probe.py m4_lc.py m4_cps.py m4_stream.py m4_outage.py; do
        have_probe "$p" || return 1
        python3 -B "$CHECKS" bounded 30 scp -q -o BatchMode=yes \
            -o StrictHostKeyChecking=yes -o ConnectTimeout=5 \
            "$PROBE_DIR/$p" "$CLIENT:$REMOTE_DIR/$p" || return 1
    done
    for p in reload_checks.py reload_remote.py; do
        python3 -B "$CHECKS" bounded 30 scp -q -o BatchMode=yes \
            -o StrictHostKeyChecking=yes -o ConnectTimeout=5 \
            "$SCRIPT_DIR/common/$p" "$CLIENT:$REMOTE_DIR/$p" || return 1
    done
    PROBES_PUSHED=1
}

launch_probe() {
    local name="$1" duration="$2" script="$3" command
    shift 3
    push_probes || return 1
    printf -v command '%q ' python3 -B "$REMOTE_DIR/reload_remote.py" \
        run "$REMOTE_DIR" "$name" "$duration" "$script" "$@"
    PROBE_JOBS+=("$name")
    CURRENT_PROBE="$name"
    run_client "nohup $command </dev/null >/dev/null 2>&1 &" || return 1
    local until=$((SECONDS + 10))
    while [ "$SECONDS" -lt "$until" ]; do
        probe_running && return 0
        sleep 1
    done
    return 1
}

probe_running() {
    [ -n "$CURRENT_PROBE" ] || return 1
    run_client "python3 -B '$REMOTE_DIR/reload_remote.py' running '$REMOTE_DIR' '$CURRENT_PROBE'" >/dev/null 2>&1
}

wait_client_summary() {
    local ignored_path="$1" pattern="$2" seconds="$3" output rc until
    [ -n "$CURRENT_PROBE" ] || return 1
    until=$((SECONDS + seconds))
    while [ "$SECONDS" -lt "$until" ]; do
        output=$(CLIENT_TIMEOUT=$((until - SECONDS)) run_client \
            "python3 -B '$REMOTE_DIR/reload_remote.py' result '$REMOTE_DIR' '$CURRENT_PROBE'")
        rc=$?
        if [ "$rc" != 75 ]; then
            printf '%s\n' "$output" > "$OUT/client_${CURRENT_PROBE}.log" || return 1
            # The remote returns the probe's own exit code: 0 = finished and
            # passed its internal checks. A non-zero code WITH the summary
            # present is a real verdict failure, not missing data, so it must
            # not collapse into the same "NO_DATA" path as a timeout (2 vs 1).
            printf '%s\n' "$output" | grep -E "^${pattern} " || return 1
            [ "$rc" = 0 ] || return 2
            return 0
        fi
        sleep 1
    done
    return 1
}

stop_probes() {
    [ "$REMOTE_CREATED" = 1 ] || return 0
    local job rc=0
    if [ "${#PROBE_JOBS[@]}" = 0 ]; then
        run_client "'$RMTMP' '$REMOTE_DIR'" || return 1
        REMOTE_CREATED=0
        return 0
    fi
    for job in "${PROBE_JOBS[@]}"; do
        run_client "python3 -B '$REMOTE_DIR/reload_remote.py' stop '$REMOTE_DIR' '$job'" || rc=1
    done
    [ "$rc" = 0 ] || return 1
    # The manager must have recorded termination before its directory is reclaimed.
    run_client "python3 -B '$REMOTE_DIR/reload_remote.py' cleanup '$REMOTE_DIR' all" || return 1
    REMOTE_CREATED=0
}

cleanup_epilogue() {
    local rc=0
    stop_probes || rc=1
    stop_stack epilogue "${OUT}/ngx_epilogue.conf" || rc=1
    [ "$rc" = 0 ] || CLEANUP_FAILED=1
    return "$rc"
}

wait_http() {
    local until=$((SECONDS + 120)) code
    while [ "$SECONDS" -lt "$until" ]; do
        code=$(run_client "curl -s -m 3 -o /dev/null -w '%{http_code}' '$TARGET_URL'") || code=""
        [ "$code" = 200 ] && return 0
        sleep 1
    done
    return 1
}

verify_build_identity() {
    [ -n "$BUILD_MANIFEST" ] || return 1
    python3 -B "$CHECKS" verify-build "$BUILD_MANIFEST" "$NGINX_BIN" \
        "$(git -C "$REPO_ROOT" rev-parse HEAD)" "$FAULT" > "$OUT/build-verified.json"
}

zc_archive() {
    python3 -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["libfstack"]["path"])' "$OUT/build-verified.json"
}

detect_zc_build() {
    local symbols
    verify_build_identity || return 1
    symbols=$(nm --defined-only "$NGINX_BIN") || return 1
    printf '%s\n' "$symbols" | awk '$NF == "kern_zc_recvit" { found=1 } END { print found+0 }'
}

zc_probe_selftest() {
    local actual declared
    verify_build_identity || { say 'BUILD_IDENTITY_REQUIRED'; return 1; }
    actual=$(detect_zc_build) || return 1
    declared=$(python3 -B -c 'import json,sys; print(int(json.load(open(sys.argv[1]))["zc_recv"]))' "$OUT/build-verified.json") || return 1
    [ "$actual" = "$declared" ] || return 1
    [ "$ZC_BUILD" = auto ] || [ "$ZC_BUILD" = "$actual" ] || return 1
}

run_case() {
    local name="$1" before=${#C_NAME[@]} rc=0 verdict=FAIL
    "case_$name" || rc=$?
    if [ "${#C_NAME[@]}" -ne "$((before + 1))" ]; then
        record "$name" FAIL 'exactly one result required' 'missing or multiple case results'
        rc=1
    elif [ "${C_NAME[$before]}" != "$name" ]; then
        record "$name" FAIL 'result must belong to invoked case' 'case identity mismatch'
        rc=1
    fi
    if [ "$CLEANUP_FAILED" != 0 ]; then
        C_VERDICT[${#C_VERDICT[@]}-1]=FAIL
        C_MEAS[${#C_MEAS[@]}-1]+='; cleanup_failed'
        rc=1
    fi
    verdict="${C_VERDICT[${#C_VERDICT[@]}-1]}"
    python3 -B "$CHECKS" record "$OUT/results.jsonl" "$name" "$verdict" \
        "${C_CRIT[${#C_CRIT[@]}-1]}" "${C_MEAS[${#C_MEAS[@]}-1]}" "$rc" || { rc=1; CLEANUP_FAILED=1; }
    [ "$rc" = 0 ] && [ "$verdict" = PASS ] || FAILED=$((FAILED + 1))
    return "$rc"
}
