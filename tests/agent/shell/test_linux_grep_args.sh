#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SCRIPT_DIR/common.sh"

require_binary "$BIN"
print_section "linux grep subcommand argument coverage"

TMP_DIR="$(mktemp -d /tmp/test_linux_grep.XXXXXX)"
TMP_SUBDIR="$TMP_DIR/subdir"
TOP_MATCH="$TMP_DIR/top.txt"
TOP_NO_MATCH="$TMP_DIR/no-match.txt"
SUB_MATCH="$TMP_SUBDIR/nested.txt"
mkdir -p "$TMP_SUBDIR"

cat >"$TOP_MATCH" <<'EOF_TOP'
alpha
needle here
omega
EOF_TOP

cat >"$TOP_NO_MATCH" <<'EOF_NOMATCH'
beta
gamma
EOF_NOMATCH

cat >"$SUB_MATCH" <<'EOF_SUB'
nested needle value
EOF_SUB

run_exact_case "linux grep --help" 0 "$BIN" linux grep --help
run_exact_case "linux grep missing --search" 2 "$BIN" linux grep --path "$TMP_DIR"
run_exact_case "linux grep missing --path" 2 "$BIN" linux grep --search needle
run_exact_case "linux grep relative path" 2 "$BIN" linux grep --search needle --path ./relative
run_exact_case "linux grep file path" 2 "$BIN" linux grep --search needle --path "$TOP_MATCH"
run_exact_case "linux grep extra positional argument" 2 "$BIN" linux grep --search needle --path "$TMP_DIR" extra
run_exact_case "linux grep invalid global --output-http" 2 "$BIN" --output-http ftp://127.0.0.1:1 linux grep --search needle --path "$TMP_DIR"
run_exact_case "linux grep invalid global --output-http" 2 "$BIN" --output-http http://127.0.0.1:1 linux grep --search needle --path "$TMP_DIR"
run_exact_case "linux grep both global http+https" 2 "$BIN" --output-http http://127.0.0.1:1 --output-http https://127.0.0.1:1 linux grep --search needle --path "$TMP_DIR"
run_exact_case "linux grep invalid global --output-tcp" 2 "$BIN" --output-tcp invalid-target linux grep --search needle --path "$TMP_DIR"

run_accept_case "linux grep local directory" "$BIN" linux grep --search needle --path "$TMP_DIR"
run_accept_case "linux grep --recursive" "$BIN" linux grep --search needle --path "$TMP_DIR" --recursive
run_accept_case "linux grep global --output-http" "$BIN" --output-http http://127.0.0.1:1 linux grep --search needle --path "$TMP_DIR"
run_accept_case "linux grep global --output-http" "$BIN" --output-http https://127.0.0.1:1 linux grep --search needle --path "$TMP_DIR"
run_accept_case "--insecure linux grep global --output-http" "$BIN" --insecure --output-http https://127.0.0.1:1 linux grep --search needle --path "$TMP_DIR"
run_accept_case "linux grep with --output-format txt" "$BIN" --output-format txt linux grep --search needle --path "$TMP_DIR"
run_accept_case "linux grep with --output-format csv" "$BIN" --output-format csv linux grep --search needle --path "$TMP_DIR"
run_accept_case "linux grep with --output-format json" "$BIN" --output-format json linux grep --search needle --path "$TMP_DIR"

local_log="$(mktemp /tmp/test_linux_grep_local.XXXXXX)"
TEST_DISABLE_OUTPUT_OVERRIDE=1 run_with_output_override "$BIN" linux grep --search needle --path "$TMP_DIR" >"$local_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -F "$TOP_MATCH:2:needle here" "$local_log" >/dev/null 2>&1 && ! grep -F "$SUB_MATCH:1:nested needle value" "$local_log" >/dev/null 2>&1; then
    echo "[PASS] linux grep default search stays non-recursive"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux grep default search stays non-recursive (rc=$rc)"
    print_file_head_scrubbed "$local_log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$local_log"

recursive_log="$(mktemp /tmp/test_linux_grep_recursive.XXXXXX)"
TEST_DISABLE_OUTPUT_OVERRIDE=1 run_with_output_override "$BIN" linux grep --search needle --path "$TMP_DIR" --recursive >"$recursive_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -F "$TOP_MATCH:2:needle here" "$recursive_log" >/dev/null 2>&1 && grep -F "$SUB_MATCH:1:nested needle value" "$recursive_log" >/dev/null 2>&1; then
    echo "[PASS] linux grep --recursive includes nested files"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux grep --recursive includes nested files (rc=$rc)"
    print_file_head_scrubbed "$recursive_log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$recursive_log"

warn_log="$(mktemp /tmp/test_linux_grep_warn.XXXXXX)"
run_with_output_override "$BIN" --output-format json linux grep --help >"$warn_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q "Warning: --output-format has no effect for grep" "$warn_log"; then
    echo "[PASS] linux grep warns when --output-format is set"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux grep warns when --output-format is set (rc=$rc)"
    print_file_head_scrubbed "$warn_log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$warn_log"

rm -rf "$TMP_DIR"
finish_tests