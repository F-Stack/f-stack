#!/bin/bash
# vlan_test_orchestrator.sh — leader 编排脚本
# 维护 BOUNCE_COUNT；调用 vlan_test_validate.sh；BOUNCE_COUNT>=4 触发 escalation。
#
# 用法：vlan_test_orchestrator.sh
# 依赖：/data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh
#       /data/workspace/f-stack/tools/sbin/vlan_test_validate.sh
set -u
set -o pipefail

WS=/data/workspace
FS=$WS/f-stack
VAL=$FS/tools/sbin/vlan_test_validate.sh
ORCH_LOG=/tmp/vlan_test/orch.log
mkdir -p /tmp/vlan_test
: > "$ORCH_LOG"

BOUNCE_COUNT=0
PHASE=spec_writing  # spec_writing | coding | reviewing | gating | done | escalation
MAX_BOUNCE=3        # escalation when count >= MAX_BOUNCE+1 = 4

log() { echo "[$(date -u +%FT%TZ)] $*" | tee -a "$ORCH_LOG"; }

bounce() {
  BOUNCE_COUNT=$((BOUNCE_COUNT + 1))
  local from=$1 to=$2 reason=$3
  log "BOUNCE #$BOUNCE_COUNT  $from -> $to  ($reason)"
  if [ "$BOUNCE_COUNT" -gt "$MAX_BOUNCE" ]; then
    log "BOUNCE_COUNT($BOUNCE_COUNT) > MAX_BOUNCE($MAX_BOUNCE) — ESCALATION"
    PHASE=escalation
    return 99
  fi
  PHASE=$to
  return 0
}

run_gates() {
  log "PHASE=gating — invoking validator (G1+G2+G3+G4)"
  if "$VAL" all >> "$ORCH_LOG" 2>&1; then
    log "all gates PASS"
    PHASE=done
    return 0
  fi
  log "gates FAIL — see $ORCH_LOG and /tmp/vlan_test/result.json"
  return 1
}

# ---- 简化的 leader 流程：spec/coder 已离线完成（由 main agent 写完文档），
# 本脚本仅 orchestrate review→gating 与可选的 RCA-fix 循环。

PHASE=gating
log "PHASE -> gating (spec/coder artifacts considered ready by main agent)"
if run_gates; then
  log "DONE — all green"
  exit 0
fi

# 第一次 gate 失败：bounce -> coder
bounce gating coding "G1/G2/G3 fail (run-1)" || { log "ESCALATION immediate"; exit 99; }
log "Manual coder retry needed; this orchestrator does NOT auto-mutate code."
log "Re-run validator after main agent fixes:"
log "  $VAL all"
exit 1
