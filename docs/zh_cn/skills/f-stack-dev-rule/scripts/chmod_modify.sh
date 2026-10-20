#!/usr/bin/env bash
# 所有chmod将文件增加执行权限等操作都必须通过扩展和执行/data/workspace/chmod_modify.sh脚本执行，严禁直接调用chmod等shell命令直接增加文件权限
#
# Usage:
#   /data/workspace/chmod_modify.sh <mode> <path> [<path> ...]
#
# 参数：
#   <mode>   chmod 模式参数，与 chmod(1) 完全兼容：
#              - 八进制：0755, 644, 600, +x 等
#              - 符号式：u+x, g-w, o=r, a+rx 等
#   <path>   一个或多个目标路径（文件或目录）
#
# 行为：
#   1. 对每个目标 path：先校验存在 → 快照变更前权限到 /tmp/.trash/<UTC时间戳>/chmod_<basename>.snap
#   2. 调用 chmod <mode> <path> 实际修改权限
#   3. 全程审计追加到 /tmp/.chmod_audit.log
#   4. 任一目标不存在或操作失败 → 返回非零退出码，继续处理其他目标
#
# 不接受 stdin；需要显式传参数。
# 保护：拒绝对以下高危路径执行 chmod（防误改系统关键权限）：
#   /  /etc  /usr  /var  /home  /root  /data  /data/workspace（顶级目录本身）
#   /etc/passwd  /etc/shadow  /etc/sudoers
# 拒绝 mode 中含递归 +s / setuid 类危险位时给出警告（不阻止，仅记录）。

set -u

AUDIT=/tmp/.chmod_audit.log
TRASH_ROOT=/tmp/.trash
TS=$(date -u +%Y%m%d-%H%M%S)
SNAP_DIR="${TRASH_ROOT}/${TS}-$$-chmod"

if [ "$#" -lt 2 ]; then
  echo "ERROR: 至少需要 <mode> 和一个 <path> 参数" >&2
  echo "Usage: $0 <mode> <path> [<path> ...]" >&2
  echo "       e.g. $0 +x /data/workspace/foo.sh" >&2
  echo "            $0 0755 /data/workspace/bar.sh /data/workspace/baz.sh" >&2
  exit 2
fi

MODE="$1"
shift

# 高危路径黑名单
BLOCKED=(
  "/" "/etc" "/usr" "/var" "/home" "/root" "/data" "/data/workspace"
  "/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/group"
)

is_blocked() {
  local p="$1"
  for b in "${BLOCKED[@]}"; do
    if [ "$p" = "$b" ]; then return 0; fi
  done
  return 1
}

# 危险 mode 检测（含 setuid / setgid 类）
case "$MODE" in
  *[sS]*|*4[0-7][0-7][0-7]*|*2[0-7][0-7][0-7]*|*6[0-7][0-7][0-7]*)
    echo "  [WARN] mode '$MODE' 包含 setuid/setgid 位，记录但继续" >&2
    echo "  WARN setuid_or_setgid mode=$MODE" >> "$AUDIT"
    ;;
esac

snapshot_perm() {
  local p="$1"
  local out="$SNAP_DIR/chmod_$(echo "$p" | tr '/' '_' | sed 's/^_//').snap"
  mkdir -p "$SNAP_DIR"
  {
    echo "=== snapshot path=$p ts=$(date -Iseconds) ==="
    echo "--- before chmod ---"
    ls -ld -- "$p" 2>/dev/null
    echo "--- stat ---"
    stat -c 'mode=%a (%A)  owner=%U:%G  size=%s' -- "$p" 2>/dev/null
  } > "$out" 2>&1
}

mkdir -p "$SNAP_DIR"
echo "[$(date -Iseconds)] BEGIN $$ pwd=$PWD mode=$MODE argv=$*" >> "$AUDIT"

rc=0
for raw in "$@"; do
  # 规范化路径（不解符号链接）
  if [ -e "$raw" ] || [ -L "$raw" ]; then
    abs=$(readlink -m -- "$raw" 2>/dev/null || echo "$raw")
  else
    echo "  [SKIP] not exist: $raw" >&2
    echo "  SKIP not_exist $raw" >> "$AUDIT"
    rc=1
    continue
  fi

  if is_blocked "$abs"; then
    echo "  [BLOCK] high-risk path refused: $abs" >&2
    echo "  BLOCK high_risk $abs" >> "$AUDIT"
    rc=2
    continue
  fi

  # 快照变更前权限
  snapshot_perm "$abs"
  before=$(stat -c '%a' -- "$abs" 2>/dev/null)

  # 执行 chmod
  if chmod -- "$MODE" "$abs" 2>/dev/null; then
    after=$(stat -c '%a' -- "$abs" 2>/dev/null)
    echo "  [OK]   $abs : ${before} -> ${after} (mode=$MODE)"
    echo "  OK chmod ${before}->${after} mode=$MODE path=$abs" >> "$AUDIT"
  else
    echo "  [FAIL] chmod $MODE $abs failed" >&2
    echo "  FAIL chmod mode=$MODE path=$abs" >> "$AUDIT"
    rc=3
  fi
done

echo "[$(date -Iseconds)] END   $$ rc=$rc snap=$SNAP_DIR" >> "$AUDIT"

if [ "$rc" -eq 0 ]; then
  echo "[OK] all $# path(s) chmod'd, snapshot=$SNAP_DIR"
else
  echo "[PARTIAL] some failures, rc=$rc, snapshot=$SNAP_DIR" >&2
fi
exit $rc
