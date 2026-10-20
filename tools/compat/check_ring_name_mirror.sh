#!/bin/bash
# Assert that the msg ring name builder used by the tools is byte-identical
# to the one the stack uses (lib/ff_reload.c ff_reload_msg_ring_name_e();
# ff_reload_msg_ring_name() is its epoch-0 wrapper).
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

for f in "$LIB_SRC" "$TOOLS_SRC"; do
    if [ ! -f "$f" ]; then
        echo "check_ring_name_mirror: missing $f" >&2
        exit 1
    fi
done

# body after the argument list, i.e. everything from the first '{'
LIB_BODY=$(sed -n '/^ff_reload_msg_ring_name_e(char /,/^}/p' "$LIB_SRC" | sed '1d')
TOOLS_BODY=$(sed -n '/^ff_msg_ring_name(char /,/^}/p' "$TOOLS_SRC" | sed '1d')

if [ -z "$LIB_BODY" ] || [ -z "$TOOLS_BODY" ]; then
    echo "check_ring_name_mirror: could not extract both functions" >&2
    exit 1
fi

if [ "$LIB_BODY" = "$TOOLS_BODY" ]; then
    echo "check_ring_name_mirror: OK (MIRROR-IDENTICAL)"
    exit 0
fi

echo "check_ring_name_mirror: FAILED - ring name builders diverged" >&2
diff -u <(printf '%s\n' "$LIB_BODY") <(printf '%s\n' "$TOOLS_BODY") \
    | sed 's/^/  /' >&2
exit 1
