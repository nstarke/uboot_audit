#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"

# shellcheck source=tests/agent/qemu/common.sh
. "$SCRIPT_DIR/common.sh"

rc=0

for test_script in \
    "$SCRIPT_DIR/arm32-le.sh" \
    "$SCRIPT_DIR/arm32-be.sh" \
    "$SCRIPT_DIR/aarch64-le.sh" \
    "$SCRIPT_DIR/aarch64-be.sh" \
    "$SCRIPT_DIR/mips-le.sh" \
    "$SCRIPT_DIR/mips-be.sh" \
    "$SCRIPT_DIR/mips64-le.sh" \
    "$SCRIPT_DIR/mips64-be.sh" \
    "$SCRIPT_DIR/powerpc-le.sh" \
    "$SCRIPT_DIR/powerpc-be.sh" \
    "$SCRIPT_DIR/x86.sh" \
    "$SCRIPT_DIR/x86_64.sh" \
    "$SCRIPT_DIR/riscv32.sh" \
    "$SCRIPT_DIR/riscv64.sh"
do
    echo
    echo "===== Running $(basename "$test_script") ====="
    /bin/sh "$test_script" "$@"
    if [ "$?" -ne 0 ]; then
        rc=1
    fi
done

exit "$rc"