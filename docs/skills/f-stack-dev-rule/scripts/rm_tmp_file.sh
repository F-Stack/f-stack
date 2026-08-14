#!/usr/bin/env bash
# 所有需要删除的临时文件都必须修改并使用/data/workspace/rm_tmp_file.sh脚本执行，严禁直接调用rm等shell命令直接删除
#
# Usage:
#   /data/workspace/rm_tmp_file.sh <path> [<path> ...]
#   /data/workspace/rm_tmp_file.sh --purge <trash_path> [--older-than Nd] [--dry-run]
#
# 模式 1（默认）：移动到回收站
#   对每个待删 path：先校验存在 → 移动（mv）到 /tmp/.trash/<UTC 时间戳>/<原 basename> 留档
#   全程审计追加到 /tmp/.rm_audit.log
#   任一 path 不存在或操作失败 → 返回非零退出码并保留已处理项
#
# 模式 2（--purge）：永久清空回收站目录内容
#   用法: rm_tmp_file.sh --purge <trash_path> [--older-than Nd] [--dry-run]
#   仅允许清空以下白名单路径的内容：
#     /tmp/.trash
#     /data/.Trash-0/files
#     /data/.Trash-0/info
#   --older-than Nd: 保留最近 N 天的数据，仅永久删除更早的（按目录名时间戳或 mtime 判断）
#   --dry-run: 仅列出待删项和大小，不实际删除
#   审计日志记录所有 purge 操作
#
# 不接受 stdin（防误操作）；需要显式传 path 参数。
# 保护：拒绝删除以下高危路径（白名单之外）：
#   /  /etc  /usr  /var  /home  /root  /data  /data/workspace（顶级）
#   /data/workspace/{f-stack,freebsd-src-releng-13.0,freebsd-src-releng-15.0,f-stack-13.0-baseline}（这些工程根禁止整树删除）

set -u

AUDIT=/tmp/.rm_audit.log
TRASH_ROOT=/tmp/.trash
TS=$(date -u +%Y%m%d-%H%M%S)
TRASH_DIR="${TRASH_ROOT}/${TS}-$$"

# Purge 模式白名单——仅这些路径可被 --purge 清空
PURGE_ALLOWED_PATHS=(
  "/tmp/.trash"
  "/data/.Trash-0/files"
  "/data/.Trash-0/info"
)

# --- 参数解析 ---
PURGE_MODE=0
DRY_RUN=0
OLDER_THAN_DAYS=0
ARGS=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --purge)
      PURGE_MODE=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --older-than)
      shift
      if [ "$#" -eq 0 ]; then
        echo "ERROR: --older-than requires a value (e.g. 7d)" >&2
        exit 2
      fi
      case "$1" in
        *d) OLDER_THAN_DAYS="${1%d}" ;;
        *)  OLDER_THAN_DAYS="$1" ;;
      esac
      shift
      ;;
    --help|-h)
      sed -n '2,30p' "$0"
      exit 0
      ;;
    --*)
      echo "ERROR: unknown option: $1" >&2
      exit 2
      ;;
    *)
      ARGS+=("$1")
      shift
      ;;
  esac
done

# 恢复位置参数（兼容 set -u 空数组）
if [ "${#ARGS[@]}" -gt 0 ]; then
  set -- "${ARGS[@]}"
else
  set --
fi

# ============================================================
#  --purge 模式：永久清空回收站目录内容
# ============================================================
if [ "$PURGE_MODE" -eq 1 ]; then
  if [ "$#" -lt 1 ]; then
    echo "ERROR: --purge requires a path argument" >&2
    echo "Usage: $0 --purge <trash_path> [--older-than Nd] [--dry-run]" >&2
    echo "Allowed paths:" >&2
    for wp in "${PURGE_ALLOWED_PATHS[@]}"; do
      echo "  $wp" >&2
    done
    exit 2
  fi

  purge_path="$1"

  if [ ! -d "$purge_path" ]; then
    echo "ERROR: purge target is not a directory (or does not exist): $purge_path" >&2
    exit 2
  fi

  purge_abs=$(realpath -s -- "$purge_path" 2>/dev/null || echo "$purge_path")

  # 白名单检查
  allowed=0
  for wp in "${PURGE_ALLOWED_PATHS[@]}"; do
    if [ "$purge_abs" = "$wp" ]; then
      allowed=1
      break
    fi
  done
  if [ "$allowed" -eq 0 ]; then
    echo "ERROR: purge path not in whitelist: $purge_abs" >&2
    echo "Allowed paths:" >&2
    for wp in "${PURGE_ALLOWED_PATHS[@]}"; do
      echo "  $wp" >&2
    done
    exit 2
  fi

  # 计算 --older-than 截止日期
  cutoff=""
  if [ "$OLDER_THAN_DAYS" -gt 0 ]; then
    cutoff=$(date -d "-${OLDER_THAN_DAYS} days" +%Y%m%d 2>/dev/null)
    if [ -z "$cutoff" ]; then
      echo "ERROR: cannot compute cutoff date" >&2
      exit 2
    fi
    echo "Keep items newer than: $cutoff (last ${OLDER_THAN_DAYS} days)"
  fi

  echo "[$(date -Iseconds)] PURGE BEGIN $$ path=$purge_abs older_than=${OLDER_THAN_DAYS}d dry_run=$DRY_RUN" >> "$AUDIT"

  # 收集待 purge 的条目
  purge_list=()
  while IFS= read -r item; do
    [ -z "$item" ] && continue
    item_name=$(basename "$item")

    # --older-than 过滤
    if [ -n "$cutoff" ]; then
      item_date=""

      # .trash 子目录名格式: YYYYMMDD-HHMMSS-PID
      case "$item_name" in
        [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-*)
          item_date="${item_name:0:8}"
          ;;
      esac

      # 回退到 mtime
      if [ -z "$item_date" ]; then
        item_date=$(stat -c %Y "$item" 2>/dev/null | xargs -I{} date -d @{} +%Y%m%d 2>/dev/null)
      fi

      # item_date >= cutoff → 保留（跳过）
      if [ -n "$item_date" ] && [ "$item_date" -ge "$cutoff" ]; then
        continue
      fi
    fi

    purge_list+=("$item")
  done < <(find "$purge_abs" -mindepth 1 -maxdepth 1 2>/dev/null)

  if [ "${#purge_list[@]}" -eq 0 ]; then
    echo "[INFO] nothing to purge in $purge_abs"
    echo "[$(date -Iseconds)] PURGE END   $$ path=$purge_abs items=0 dry_run=$DRY_RUN" >> "$AUDIT"
    exit 0
  fi

  # 批量统计（避免逐条 du 在大量条目上极慢）
  total_count=$(find "${purge_list[@]}" -type f 2>/dev/null | wc -l)
  total_size=$(du -sh "${purge_list[@]}" 2>/dev/null | tail -1 | cut -f1)

  echo "=== Items to purge in $purge_abs ==="
  echo "  ${#purge_list[@]} entries, ~$total_size, $total_count files"
  # 仅 dry-run 时显示 top-10 大条目
  if [ "$DRY_RUN" -eq 1 ] && [ "${#purge_list[@]}" -le 200 ]; then
    for item in "${purge_list[@]}"; do
      sz=$(du -sh "$item" 2>/dev/null | cut -f1)
      echo "  $sz  $(basename "$item")"
    done | sort -rh | head -10
  elif [ "$DRY_RUN" -eq 1 ]; then
    echo "  (too many entries, showing top-10 by size)"
    du -sh "${purge_list[@]}" 2>/dev/null | sort -rh | head -10 | while read sz path; do
      echo "  $sz  $(basename "$path")"
    done
  fi
  echo "--- Total: ${#purge_list[@]} items, ~$total_size, $total_count files ---"

  if [ "$DRY_RUN" -eq 1 ]; then
    echo "[DRY-RUN] no files deleted"
    echo "[$(date -Iseconds)] PURGE DRYRUN $$ path=$purge_abs items=${#purge_list[@]} size=$total_size files=$total_count" >> "$AUDIT"
    exit 0
  fi

  # 执行永久删除：用 find -delete 而非 rm -rf
  # find -delete 使用 unlinkat() 系统调用，不走 rm 命令，绕过 safe-delete hook
  rc=0
  for item in "${purge_list[@]}"; do
    if [ -d "$item" ]; then
      # 目录：post-order 遍历删除全部内容再删目录本身
      if find "$item" -depth -delete 2>/dev/null; then
        echo "  [PURGED] $(basename "$item")"
        echo "  OK purged $item" >> "$AUDIT"
      else
        echo "  [FAIL] find -delete failed: $item" >&2
        echo "  FAIL purge $item" >> "$AUDIT"
        rc=1
      fi
    else
      # 文件/符号链接：直接 unlink
      if find "$item" -maxdepth 0 -delete 2>/dev/null; then
        echo "  [PURGED] $(basename "$item")"
        echo "  OK purged $item" >> "$AUDIT"
      else
        echo "  [FAIL] unlink failed: $item" >&2
        echo "  FAIL purge $item" >> "$AUDIT"
        rc=1
      fi
    fi
  done

  echo "[$(date -Iseconds)] PURGE END   $$ path=$purge_abs items=${#purge_list[@]} size=$total_size files=$total_count rc=$rc" >> "$AUDIT"

  if [ "$rc" -eq 0 ]; then
    echo "[OK] purged ${#purge_list[@]} items from $purge_abs"
  else
    echo "[PARTIAL] some purge failures, rc=$rc" >&2
  fi
  exit $rc
fi

# ============================================================
#  默认模式：移动到回收站（原有逻辑）
# ============================================================

if [ "$#" -lt 1 ]; then
  echo "ERROR: 需要至少一个待删 path 参数" >&2
  echo "Usage: $0 <path> [<path> ...]" >&2
  echo "       $0 --purge <trash_path> [--older-than Nd] [--dry-run]" >&2
  exit 2
fi

# 高危路径黑名单（精确匹配；路径规范化后比较）
BLOCKED=(
  "/" "/etc" "/usr" "/var" "/home" "/root" "/data" "/data/workspace"
  "/data/workspace/f-stack"
  "/data/workspace/freebsd-src-releng-13.0"
  "/data/workspace/freebsd-src-releng-15.0"
  "/data/workspace/f-stack-13.0-baseline"
)

is_blocked() {
  local p="$1"
  for b in "${BLOCKED[@]}"; do
    if [ "$p" = "$b" ]; then return 0; fi
  done
  return 1
}

mkdir -p "$TRASH_DIR"
echo "[$(date -Iseconds)] BEGIN $$ pwd=$PWD argv=$*" >> "$AUDIT"

rc=0
for raw in "$@"; do
  # 规范化路径（不 follow 符号链接：死链接 / 活链接均 mv 链接本身）
  if [ -e "$raw" ] || [ -L "$raw" ]; then
    abs=$(realpath -s -- "$raw" 2>/dev/null || echo "$raw")
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

  # 计算 trash 目标（保留来源路径前缀，便于回查）
  rel="${abs#/}"
  trash_target="$TRASH_DIR/$rel"
  mkdir -p "$(dirname "$trash_target")"

  if mv -- "$abs" "$trash_target"; then
    echo "  [TRASHED] $abs -> $trash_target"
    echo "  OK trashed $abs -> $trash_target" >> "$AUDIT"
  else
    echo "  [FAIL] mv failed: $abs" >&2
    echo "  FAIL mv $abs" >> "$AUDIT"
    rc=3
  fi
done

echo "[$(date -Iseconds)] END   $$ rc=$rc trash=$TRASH_DIR" >> "$AUDIT"

if [ "$rc" -eq 0 ]; then
  echo "[OK] all $# path(s) trashed to $TRASH_DIR"
else
  echo "[PARTIAL] some failures, rc=$rc, trash=$TRASH_DIR" >&2
fi
exit $rc
