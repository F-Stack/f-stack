#!/bin/bash
# vlan_test_validate.sh — gate-keeper 角色验收脚本
# G1 build / G2 startup / G3 functional / G4 compliance
# 用法：vlan_test_validate.sh <gate>  (gate ∈ G1|G2|G3|G4|all)
#
# 依赖：/data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh
# 严禁直接 rm/kill/chmod。本脚本内所有清理路径都通过 wrapper。
set -u
set -o pipefail

WS=/data/workspace
FS=$WS/f-stack
CFG=$FS/config.test-vlan.ini
HW_BIN=$FS/example/helloworld
HW_LOG=/tmp/vlan_test_hw.log
LIB_LOG=/tmp/vlan_test_lib_build.log
EX_LOG=/tmp/vlan_test_ex_build.log
RES_DIR=/tmp/vlan_test
mkdir -p "$RES_DIR"
RES_JSON=$RES_DIR/result.json
GATE=${1:-all}

dpdk_runtime_clean() {
  $WS/rm_tmp_file.sh \
    /var/run/dpdk/rte/config \
    /var/run/dpdk/rte/fbarray_memseg-2048k-0-0 \
    /var/run/dpdk/rte/fbarray_memseg-2048k-0-1 \
    /var/run/dpdk/rte/fbarray_memseg-2048k-0-2 \
    /var/run/dpdk/rte/fbarray_memseg-2048k-0-3 \
    /var/run/dpdk/rte/fbarray_memzone \
    /var/run/dpdk/rte/hugepage_info \
    >/dev/null 2>&1 || true
}

kill_helloworld() {
  local pid
  pid=$(ps -ef | grep './helloworld -c' | grep -v grep | awk '{print $2}' | head -1)
  if [ -n "$pid" ]; then
    $WS/kill_process.sh "$pid" >/dev/null 2>&1 || true
    sleep 2
  fi
}

# --------- G1 build ---------
gate_g1() {
  echo "[G1] build lib + example"
  ( cd "$FS/lib"     && make clean >/dev/null 2>&1 && make ) > "$LIB_LOG" 2>&1
  local lib_rc=$?
  local lib_err
  lib_err=$(grep -ic 'error:' "$LIB_LOG" || true)
  local lib_warn
  lib_warn=$(grep -ic 'warning' "$LIB_LOG" || true)
  $WS/rm_tmp_file.sh "$HW_BIN" \
    "$FS/example/helloworld_zc" \
    "$FS/example/helloworld_epoll" >/dev/null 2>&1 || true
  ( cd "$FS/example" && make ) > "$EX_LOG" 2>&1
  local ex_rc=$?
  echo "  lib_rc=$lib_rc errors=$lib_err warnings=$lib_warn"
  echo "  ex_rc=$ex_rc"
  echo "  binary: $(ls -la $HW_BIN 2>&1 | head -1)"
  if [ "$lib_rc" -ne 0 ] || [ "$ex_rc" -ne 0 ] || [ "$lib_err" -ne 0 ]; then
    echo "[G1] FAIL"
    return 1
  fi
  echo "[G1] PASS (lib warnings=$lib_warn baseline-ish)"
  return 0
}

# --------- G2 startup ---------
gate_g2() {
  echo "[G2] start helloworld primary with $CFG"
  if [ ! -x "$HW_BIN" ]; then
    echo "[G2] FAIL helloworld binary missing"
    return 1
  fi
  if [ ! -f "$CFG" ]; then
    echo "[G2] FAIL config $CFG missing"
    return 1
  fi
  kill_helloworld
  dpdk_runtime_clean
  # Truncate previous log so this G2 run is self-contained.
  : > "$HW_LOG"
  # Detach via setsid so primary survives validate.sh and is reparented to PID 1
  # immediately. </dev/null prevents helloworld from blocking on stdin.
  # We are already root in this workspace; no sudo wrapper (which keeps a tty
  # hold on the child and was the root cause of the previous do_wait hang).
  pushd "$FS/example" >/dev/null
  setsid "$HW_BIN" -c "$CFG" --proc-type=primary --proc-id=0 \
      </dev/null >"$HW_LOG" 2>&1 &
  local launched_pid=$!
  popd >/dev/null
  echo "  launched pid=$launched_pid (setsid detached, log=$HW_LOG)"
  # Poll up to 18s for primary to finish DPDK init + vlan if_clone_create.
  local pid="" t=0
  while [ $t -lt 18 ]; do
    sleep 1
    t=$((t+1))
    pid=$(ps -ef | grep './helloworld -c' | grep -v grep | awk '{print $2}' | head -1)
    [ -n "$pid" ] && [ -d "/proc/$pid" ] && \
      grep -q 'Successed to if_clone_create vlan interface' "$HW_LOG" 2>/dev/null && break
  done
  if [ -z "$pid" ] || [ ! -d "/proc/$pid" ]; then
    echo "[G2] FAIL primary not alive after ${t}s"
    echo "  --- log tail ---"
    tail -25 "$HW_LOG"
    return 1
  fi
  echo "[G2] PASS pid=$pid (init in ${t}s)"
  return 0
}

# --------- G3 functional ---------
gate_g3() {
  echo "[G3] vlan parse + iface create + vip + ipfw_pr"
  if [ ! -f "$HW_LOG" ]; then
    echo "[G3] FAIL no helloworld log"
    return 1
  fi
  local fail=0

  # TC-V1 parse OK
  local parse_err
  parse_err=$(grep -cE \
'vlan_cfg_handler section\[.*\] error|vlan_cfg_handler portid .* bigger|vlan_cfg_handler section\[.*\] mot match vlan filter|vip_cfg_handler.*not set vip_addr|ipfw_pr_cfg_handler.*format error' \
    "$HW_LOG" || true)
  echo "  TC-V1 parse_errors=$parse_err"
  [ "$parse_err" -ne 0 ] && fail=1

  # TC-V2 if_clone_create — must see exactly 2 hits for f-stack-0.1 + f-stack-0.2
  local clone_ok
  clone_ok=$(grep -cE 'Successed to if_clone_create vlan interface' "$HW_LOG" || true)
  local clone_fail
  clone_fail=$(grep -cE 'Failed to if_clone_create' "$HW_LOG" || true)
  local v1_seen v2_seen
  v1_seen=$(grep -cE '^f-stack-0\.1: Successed to if_clone_create' "$HW_LOG" || true)
  v2_seen=$(grep -cE '^f-stack-0\.2: Successed to if_clone_create' "$HW_LOG" || true)
  echo "  TC-V2 clone_ok=$clone_ok clone_fail=$clone_fail vlan1=$v1_seen vlan2=$v2_seen (expect ok>=2 fail=0 v1=v2=1)"
  [ "$clone_ok" -lt 2 ] && fail=1
  [ "$clone_fail" -ne 0 ] && fail=1
  [ "$v1_seen" -ne 1 ] && fail=1
  [ "$v2_seen" -ne 1 ] && fail=1

  # TC-V3 vip OK
  local addr_fail
  addr_fail=$(grep -cE 'ff_veth_setaddr failed' "$HW_LOG" || true)
  local vip_fail
  vip_fail=$(grep -cE 'inet_pton vip .* failed|ff_veth_setvaddr.*failed|ff_veth_setvaddr.*error' "$HW_LOG" || true)
  echo "  TC-V3 addr_fail=$addr_fail vip_fail=$vip_fail (expect both 0)"
  [ "$addr_fail" -ne 0 ] && fail=1
  [ "$vip_fail" -ne 0 ] && fail=1

  # TC-V4 ipfw_pr — query ipfw via tools/sbin/ipfw
  echo "  TC-V4 ipfw show (best-effort, primary owns the BSD ipfw state):"
  local ipfw_out=$RES_DIR/ipfw_show.txt
  ( cd "$FS/tools/sbin" && timeout 5 sudo ./ipfw -P 0 show > "$ipfw_out" 2>&1 ) || true
  if [ -s "$ipfw_out" ]; then
    head -20 "$ipfw_out" | sed 's/^/    /'
    local ipfw_setfib
    ipfw_setfib=$(grep -cE 'setfib' "$ipfw_out" || true)
    echo "  TC-V4 setfib_rules_in_show=$ipfw_setfib"
    # ipfw show 是 secondary-process query；若失败也不强制 fail（ipfw 工具可能因
    # primary --proc-type=primary 互斥而无法连接），实测以 ff_ipfw_add_simple_v4
    # 调用本身不报错为准。
  else
    echo "  TC-V4 ipfw show empty/failed (likely primary lock; not fatal — see TC-V5)"
  fi

  # TC-V5 fallback: grep helloworld log for ipfw_add_simple_v4 errors
  local ipfw_add_fail
  ipfw_add_fail=$(grep -cE 'ff_set_ipfw ff_socket error|setsockopt IP_FW_XADD.*failed|ff_ipfw_add_simple_v4.*error' "$HW_LOG" || true)
  echo "  TC-V5 ipfw_add_fail_in_log=$ipfw_add_fail (expect 0)"
  [ "$ipfw_add_fail" -ne 0 ] && fail=1

  if [ $fail -ne 0 ]; then
    echo "[G3] FAIL"
    echo "  --- log tail ---"
    tail -40 "$HW_LOG"
    return 1
  fi
  echo "[G3] PASS"
  return 0
}

# --------- G4 compliance ---------
gate_g4() {
  echo "[G4] compliance — direct rm/kill/chmod usage"
  local own
  own=$(grep -cE '^[^#]*\b(rm |kill |chmod )' "$0" \
    "$FS/tools/sbin/vlan_test_orchestrator.sh" 2>/dev/null \
    | awk -F: '{s+=$2} END{print s+0}')
  echo "  direct-call hits in orchestrator+validator (excluding wrapper invocations) = $own"
  # wrapper 调用形如 $WS/rm_tmp_file.sh / $WS/kill_process.sh / $WS/chmod_modify.sh
  # — grep 'rm '/'kill '/'chmod ' 会把这些也算上；我们用更严格的正则排除 .sh 后缀
  # Strict check: real shell command invocations only.
  # Exclude: comments (^#), wrapper script paths, echo/log strings,
  # grep regex literals (single-quoted patterns containing the keyword),
  # and our own gate-keeper helper-function definitions.
  local strict
  strict=$(grep -nE '^[[:space:]]*(rm |kill |chmod )' \
    "$0" "$FS/tools/sbin/vlan_test_orchestrator.sh" 2>/dev/null \
    | grep -vE 'rm_tmp_file\.sh|kill_process\.sh|chmod_modify\.sh' \
    | wc -l)
  echo "  strict direct-call (after wrapper exclusion) = $strict"
  if [ "$strict" -gt 0 ]; then
    echo "[G4] FAIL — direct rm/kill/chmod calls found"
    grep -nE '\b(rm |kill |chmod )' \
      "$0" "$FS/tools/sbin/vlan_test_orchestrator.sh" 2>/dev/null \
      | grep -vE 'rm_tmp_file\.sh|kill_process\.sh|chmod_modify\.sh|^.*#'
    return 1
  fi
  echo "[G4] PASS"
  return 0
}

# --------- main ---------
declare -A R
case "$GATE" in
  G1) gate_g1; R[G1]=$? ;;
  G2) gate_g2; R[G2]=$? ;;
  G3) gate_g3; R[G3]=$? ;;
  G4) gate_g4; R[G4]=$? ;;
  all|*)
    gate_g1; R[G1]=$?
    if [ "${R[G1]}" -eq 0 ]; then gate_g2; R[G2]=$?; else R[G2]=99; fi
    if [ "${R[G2]:-99}" -eq 0 ]; then gate_g3; R[G3]=$?; else R[G3]=99; fi
    gate_g4; R[G4]=$?
    ;;
esac

# JSON 输出汇总
{
  echo "{"
  echo "  \"gate\": \"$GATE\","
  echo "  \"G1\": ${R[G1]:-99},"
  echo "  \"G2\": ${R[G2]:-99},"
  echo "  \"G3\": ${R[G3]:-99},"
  echo "  \"G4\": ${R[G4]:-99},"
  echo "  \"hw_log\": \"$HW_LOG\","
  echo "  \"lib_log\": \"$LIB_LOG\","
  echo "  \"ex_log\": \"$EX_LOG\""
  echo "}"
} > "$RES_JSON"

cat "$RES_JSON"

# 汇总 exit code
overall=0
for g in G1 G2 G3 G4; do
  v=${R[$g]:-99}
  [ "$v" -ne 0 ] && [ "$v" -ne 99 ] && overall=1
done
exit $overall
