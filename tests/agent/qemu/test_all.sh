#!/bin/bash

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"

# shellcheck source=tests/agent/qemu/common.sh
. "$SCRIPT_DIR/common.sh"

rc=0
pass_count=0
fail_count=0

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
    test_log="$(mktemp /tmp/ela-qemu-test-all.XXXXXX)"
    /bin/sh "$test_script" "$@" 2>&1 | tee "$test_log"
    test_rc=${PIPESTATUS[0]}

    test_passes="$(sed -n 's/^Passed: //p' "$test_log" | tail -n 1)"
    test_fails="$(sed -n 's/^Failed: //p' "$test_log" | tail -n 1)"

    if [ -n "$test_passes" ]; then
        pass_count="$(expr "$pass_count" + "$test_passes")"
    fi

    if [ -n "$test_fails" ]; then
        fail_count="$(expr "$fail_count" + "$test_fails")"
    fi

    rm -f "$test_log"

    if [ "$test_rc" -ne 0 ]; then
        rc=1
    fi
done

echo
echo "Total test cases passed: $pass_count"
echo "Total test cases failed: $fail_count"

exit "$rc"