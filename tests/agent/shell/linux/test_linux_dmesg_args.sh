#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

TEST_OUTPUT_HTTP="${TEST_OUTPUT_HTTP:-}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --output-http)
            if [ "$#" -lt 2 ]; then
                echo "error: --output-http requires a value"
                exit 2
            fi
            TEST_OUTPUT_HTTP="$2"
            shift 2
            ;;
        --output-http=*)
            TEST_OUTPUT_HTTP="${1#*=}"
            shift
            ;;
        *)
            echo "error: unknown argument: $1"
            exit 2
            ;;
    esac
done

export TEST_OUTPUT_HTTP

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "linux dmesg subcommand argument coverage"

run_exact_case "linux dmesg --help" 0 "$BIN" linux dmesg --help
run_accept_case "linux dmesg" "$BIN" linux dmesg
run_accept_case "linux dmesg default verbose" "$BIN" linux dmesg
run_accept_case "linux dmesg global --quiet" "$BIN" --quiet linux dmesg
run_accept_case "linux dmesg --head 5" "$BIN" linux dmesg --head 5
run_accept_case "linux dmesg --tail 5" "$BIN" linux dmesg --tail 5
run_exact_case "linux dmesg invalid --head zero" 2 "$BIN" linux dmesg --head 0
run_exact_case "linux dmesg invalid --head negative" 2 "$BIN" linux dmesg --head -1
run_exact_case "linux dmesg invalid --tail zero" 2 "$BIN" linux dmesg --tail 0
run_exact_case "linux dmesg invalid --tail negative" 2 "$BIN" linux dmesg --tail -1
run_exact_case "linux dmesg rejects both --head and --tail" 2 "$BIN" linux dmesg --head 5 --tail 5
run_exact_case "linux dmesg extra positional arg" 2 "$BIN" linux dmesg extra
run_exact_case "linux dmesg invalid global --output-tcp" 2 "$BIN" --output-tcp invalid-target linux dmesg
run_exact_case "linux dmesg global --output-tcp + --help" 0 "$BIN" --output-tcp 127.0.0.1:9 linux dmesg --help
run_accept_case "linux dmesg global --output-http" "$BIN" --output-http http://127.0.0.1:1/dmesg linux dmesg
run_accept_case "linux dmesg global --output-http" "$BIN" --output-http https://127.0.0.1:1/dmesg linux dmesg
run_exact_case "linux dmesg invalid global --output-http" 2 "$BIN" --output-http ftp://127.0.0.1:1/dmesg linux dmesg
run_accept_case "linux dmesg valid global --output-http with unreachable endpoint" "$BIN" --output-http http://127.0.0.1:1/dmesg linux dmesg
run_accept_case "linux dmesg repeated global --output-http" "$BIN" --output-http http://127.0.0.1:1/dmesg --output-http https://127.0.0.1:1/dmesg linux dmesg
run_accept_case "global --insecure linux dmesg" "$BIN" --insecure linux dmesg

run_accept_case "linux dmesg with --output-format txt" "$BIN" --output-format txt linux dmesg
run_accept_case "linux dmesg with --output-format csv" "$BIN" --output-format csv linux dmesg
run_accept_case "linux dmesg with --output-format json" "$BIN" --output-format json linux dmesg

log="$(mktemp /tmp/test_dmesg_warn.XXXXXX)"
run_with_output_override "$BIN" --output-format json linux dmesg --help >"$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q "Warning: --output-format has no effect for dmesg" "$log"; then
    echo "[PASS] linux dmesg warns when --output-format is set"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux dmesg warns when --output-format is set (rc=$rc)"
    print_file_head_scrubbed "$log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

json_log="$(mktemp /tmp/test_dmesg_lifecycle_json.XXXXXX)"
TEST_DISABLE_OUTPUT_OVERRIDE=1 run_with_output_override "$BIN" --output-format json linux dmesg --help >"$json_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q 'Warning: --output-format has no effect for dmesg' "$json_log"; then
    echo "[PASS] linux dmesg retains warning behavior with output-format set"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux dmesg retains warning behavior with output-format set (rc=$rc)"
    print_file_head_scrubbed "$json_log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$json_log"

head_tail_log="$(mktemp /tmp/test_dmesg_head_tail_validation.XXXXXX)"
run_with_output_override "$BIN" linux dmesg --head 3 --tail 3 >"$head_tail_log" 2>&1
rc=$?
if [ "$rc" -eq 2 ] && grep -q "Use only one of --head or --tail" "$head_tail_log"; then
    echo "[PASS] linux dmesg validates mutually exclusive --head/--tail"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux dmesg validates mutually exclusive --head/--tail (rc=$rc)"
    print_file_head_scrubbed "$head_tail_log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$head_tail_log"

# dmesg watch subcommand tests
run_exact_case "linux dmesg watch --help" 0 "$BIN" linux dmesg watch --help
run_exact_case "linux dmesg watch no args" 2 "$BIN" linux dmesg watch
run_exact_case "linux dmesg watch invalid action" 2 "$BIN" linux dmesg watch foo
run_exact_case "linux dmesg watch extra arg" 2 "$BIN" linux dmesg watch on extra

# stop when not running should return non-zero but not crash
run_accept_case "linux dmesg watch off when not running" "$BIN" linux dmesg watch off

# watch on then off lifecycle
# Note: the daemon may exit quickly if dmesg -w reads existing messages and exits (no new
# messages in a quiet test environment), so we only verify the start handshake, not long-lived state.
watch_log="$(mktemp /tmp/test_dmesg_watch_lifecycle.XXXXXX)"
"$BIN" linux dmesg watch on >"$watch_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q "dmesg watch started" "$watch_log"; then
    echo "[PASS] linux dmesg watch on starts daemon"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux dmesg watch on starts daemon (rc=$rc)"
    print_file_head_scrubbed "$watch_log" 40
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi

# Try to stop the daemon; accept either "stopped" (daemon still running) or
# "not running" (daemon already exited — acceptable in a quiet test environment).
"$BIN" linux dmesg watch off >"$watch_log" 2>&1
rc=$?
if grep -q "dmesg watch stopped" "$watch_log" || grep -q "not running" "$watch_log"; then
    echo "[PASS] linux dmesg watch off responds correctly after watch on"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux dmesg watch off responds correctly after watch on (rc=$rc)"
    print_file_head_scrubbed "$watch_log" 40
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$watch_log"

# output-format should NOT warn for dmesg watch
warn_log="$(mktemp /tmp/test_dmesg_watch_no_warn.XXXXXX)"
"$BIN" --output-format json linux dmesg watch --help >"$warn_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && ! grep -q "Warning: --output-format has no effect for dmesg" "$warn_log"; then
    echo "[PASS] linux dmesg watch does not emit output-format warning"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux dmesg watch does not emit output-format warning (rc=$rc)"
    print_file_head_scrubbed "$warn_log" 40
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$warn_log"

finish_tests