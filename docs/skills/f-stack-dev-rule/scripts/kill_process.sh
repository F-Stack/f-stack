#!/usr/bin/env bash
# 所有需要kill的进程都必须通过/data/workspace/kill_process.sh脚本执行，严禁直接调用kill/pkill/killall等shell命令
#
# Usage:
#   /data/workspace/kill_process.sh <pid_or_name> [<pid_or_name> ...]
#
# 行为：
#   1. 对每个参数：纯数字视为 PID；否则视为进程名/正则 → pgrep -f 解析为 PID 列表
#   2. 对每个 PID：先 SIGTERM 优雅退出，等待 GRACE_SEC（默认 5s）；仍存活则 SIGKILL 强杀
#   3. 杀前快照 /proc/<pid>/{comm,cmdline,status} → 留档 /tmp/.trash/<UTC时间戳>/kill_<pid>.snap
#   4. 全程审计追加到 /tmp/.kill_audit.log
#   5. 任一未找到目标或杀失败 → 返回非零退出码并继续处理其他参数
#
# 不接受 stdin；需要显式传参数。
# 保护：拒绝 kill PID 1 / PID $$（自身）/ PID $PPID（父 shell）等关键进程

set -u

AUDIT=/tmp/.kill_audit.log
TRASH_ROOT=/tmp/.trash
TS=$(date -u +%Y%m%d-%H%M%S)
TRASH_DIR="${TRASH_ROOT}/${TS}-$$-kill"
GRACE_SEC="${KILL_GRACE_SEC:-5}"

if [ "$#" -lt 1 ]; then
  echo "ERROR: 需要至少一个 PID 或进程名参数" >&2
  echo "Usage: $0 <pid_or_name> [<pid_or_name> ...]" >&2
  exit 2
fi

# 关键 PID 保护（self / parent / init）
SELF_PID=$$
PARENT_PID=$PPID

is_protected_pid() {
  local p="$1"
  case "$p" in
    1|"$SELF_PID"|"$PARENT_PID") return 0 ;;
  esac
  return 1
}

snapshot_proc() {
  local pid="$1"
  local out="$TRASH_DIR/kill_${pid}.snap"
  mkdir -p "$TRASH_DIR"
  {
    echo "=== snapshot pid=$pid ts=$(date -Iseconds) ==="
    echo "--- comm ---"
    cat "/proc/$pid/comm" 2>/dev/null
    echo "--- cmdline ---"
    tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null; echo
    echo "--- status (head 20) ---"
    head -20 "/proc/$pid/status" 2>/dev/null
    echo "--- task list ---"
    ls "/proc/$pid/task" 2>/dev/null
  } > "$out" 2>&1
}

kill_one_pid() {
  local pid="$1"
  if ! [ -d "/proc/$pid" ]; then
    echo "  [SKIP] pid $pid not exist"
    echo "  SKIP not_exist pid=$pid" >> "$AUDIT"
    return 1
  fi
  if is_protected_pid "$pid"; then
    echo "  [BLOCK] protected pid refused: $pid" >&2
    echo "  BLOCK protected pid=$pid" >> "$AUDIT"
    return 2
  fi

  snapshot_proc "$pid"

  # Step 1: SIGTERM
  if kill -TERM "$pid" 2>/dev/null; then
    echo "  [TERM] sent SIGTERM to pid=$pid; waiting ${GRACE_SEC}s ..."
    echo "  TERM pid=$pid" >> "$AUDIT"
    local i=0
    while [ $i -lt "$GRACE_SEC" ]; do
      if ! [ -d "/proc/$pid" ]; then
        echo "  [OK]   pid=$pid exited after SIGTERM"
        echo "  OK term_exit pid=$pid" >> "$AUDIT"
        return 0
      fi
      sleep 1
      i=$((i+1))
    done
  fi

  # Step 2: SIGKILL fallback
  if [ -d "/proc/$pid" ]; then
    if kill -KILL "$pid" 2>/dev/null; then
      echo "  [KILL] sent SIGKILL to pid=$pid (no exit after ${GRACE_SEC}s)"
      echo "  KILL pid=$pid" >> "$AUDIT"
      sleep 1
      if ! [ -d "/proc/$pid" ]; then
        echo "  [OK]   pid=$pid killed"
        echo "  OK kill_exit pid=$pid" >> "$AUDIT"
        return 0
      else
        echo "  [FAIL] pid=$pid still alive after SIGKILL" >&2
        echo "  FAIL still_alive pid=$pid" >> "$AUDIT"
        return 3
      fi
    else
      echo "  [FAIL] kill -KILL $pid syscall failed" >&2
      echo "  FAIL kill_syscall pid=$pid" >> "$AUDIT"
      return 4
    fi
  fi
  return 0
}

mkdir -p "$TRASH_DIR"
echo "[$(date -Iseconds)] BEGIN $$ pwd=$PWD argv=$* grace=${GRACE_SEC}s" >> "$AUDIT"

rc=0
for raw in "$@"; do
  # 纯数字 → 视为 PID
  if [[ "$raw" =~ ^[0-9]+$ ]]; then
    kill_one_pid "$raw" || rc=$?
  else
    # 进程名 → pgrep -f 解析
    pids=$(pgrep -f -- "$raw" 2>/dev/null || true)
    if [ -z "$pids" ]; then
      echo "  [SKIP] no process matches name/regex: $raw"
      echo "  SKIP no_match name=$raw" >> "$AUDIT"
      rc=1
      continue
    fi
    echo "  [MATCH] name=$raw → pids: $(echo $pids | tr '\n' ' ')"
    for p in $pids; do
      kill_one_pid "$p" || rc=$?
    done
  fi
done

echo "[$(date -Iseconds)] END   $$ rc=$rc trash=$TRASH_DIR" >> "$AUDIT"

if [ "$rc" -eq 0 ]; then
  echo "[OK] all targets handled, trash=$TRASH_DIR"
else
  echo "[PARTIAL] some failures, rc=$rc, trash=$TRASH_DIR" >&2
fi
exit $rc
