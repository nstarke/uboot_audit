#!/bin/bash

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
RELEASE_BUILD_SCRIPT="$REPO_ROOT/tests/compile_release_binaries_locally.sh"

# shellcheck source=tests/agent/qemu/common.sh
. "$SCRIPT_DIR/common.sh"

usage() {
    echo "Usage: $0 [--clean] [qemu-test-args...]" >&2
    exit 1
}

rc=0
pass_count=0
fail_count=0
clean_release_binaries=0

count_matches() {
    pattern="$1"
    log_path="$2"

    grep -c -- "$pattern" "$log_path" 2>/dev/null || true
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --clean)
            clean_release_binaries=1
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            break
            ;;
    esac
done

if [ "$clean_release_binaries" -eq 1 ]; then
    require_file "$RELEASE_BUILD_SCRIPT"
    build_jobs="$(cpu_jobs_for_build)"
    echo "Rebuilding all release binaries via tests/compile_release_binaries_locally.sh --clean --jobs=$build_jobs"
    if ! /bin/sh "$RELEASE_BUILD_SCRIPT" --clean --jobs="$build_jobs"; then
        echo "error: failed to rebuild release binaries" >&2
        exit 1
    fi
fi

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

    test_passes="$(count_matches '^\[PASS\]' "$test_log")"
    test_fails="$(count_matches '^\[FAIL\]' "$test_log")"

    if [ "$test_passes" -eq 0 ]; then
        test_passes="$(sed -n 's/^Passed: //p' "$test_log" | tail -n 1)"
    fi

    if [ "$test_fails" -eq 0 ]; then
        test_fails="$(sed -n 's/^Failed: //p' "$test_log" | tail -n 1)"
    fi

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
