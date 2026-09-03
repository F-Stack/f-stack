#!/bin/sh
# Assert that the msg ring name builder used by the tools is byte-identical
# to the one the stack uses (lib/ff_reload.c ff_reload_msg_ring_name()).
#
# The tools cannot link lib/ff_reload.c (it pulls in ff_global_cfg), so the
# builder is mirrored as ff_msg_ring_name() in ff_ipc.c. A silent divergence
# would make a tool address a ring of the wrong generation and report it as
# fact, which is worse than a failed lookup.
#
# Usage: tools/compat/check_ring_name_mirror.sh
# Exit:  0 identical, 1 divergent or unusable (safe to wire into a gate).

set -u

TOPDIR=$(cd "$(dirname "$0")/../.." && pwd)
LIB_SRC="$TOPDIR/lib/ff_reload.c"
TOOLS_SRC="$TOPDIR/tools/compat/ff_ipc.c"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

for f in "$LIB_SRC" "$TOOLS_SRC"; do
    if [ ! -f "$f" ]; then
        echo "check_ring_name_mirror: missing $f" >&2
        exit 1
    fi
done

# body after the argument list, i.e. everything from the first '{'
sed -n '/^ff_reload_msg_ring_name(char /,/^}/p' "$LIB_SRC" | sed '1d' > "$TMP/lib"
sed -n '/^ff_msg_ring_name(char /,/^}/p'        "$TOOLS_SRC" | sed '1d' > "$TMP/tools"

if [ ! -s "$TMP/lib" ] || [ ! -s "$TMP/tools" ]; then
    echo "check_ring_name_mirror: could not extract both functions" >&2
    exit 1
fi

if diff -u "$TMP/lib" "$TMP/tools" > "$TMP/diff"; then
    echo "check_ring_name_mirror: OK (MIRROR-IDENTICAL)"
    exit 0
fi

echo "check_ring_name_mirror: FAILED - ring name builders diverged" >&2
sed 's/^/  /' "$TMP/diff" >&2
exit 1
