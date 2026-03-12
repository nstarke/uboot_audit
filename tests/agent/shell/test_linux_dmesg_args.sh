#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
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
. "$SCRIPT_DIR/common.sh"

require_binary "$BIN"
print_section "linux dmesg subcommand argument coverage"

run_exact_case "linux dmesg --help" 0 "$BIN" linux dmesg --help
run_accept_case "linux dmesg" "$BIN" linux dmesg
run_accept_case "linux dmesg default verbose" "$BIN" linux dmesg
run_accept_case "linux dmesg global --quiet" "$BIN" --quiet linux dmesg
run_exact_case "linux dmesg extra positional arg" 2 "$BIN" linux dmesg extra
run_exact_case "linux dmesg invalid global --output-tcp" 2 "$BIN" --output-tcp invalid-target linux dmesg
run_exact_case "linux dmesg global --output-tcp + --help" 0 "$BIN" --output-tcp 127.0.0.1:9 linux dmesg --help
run_accept_case "linux dmesg global --output-http" "$BIN" --output-http http://127.0.0.1:1/dmesg linux dmesg
run_accept_case "linux dmesg global --output-http" "$BIN" --output-http https://127.0.0.1:1/dmesg linux dmesg
run_exact_case "linux dmesg invalid global --output-http" 2 "$BIN" --output-http ftp://127.0.0.1:1/dmesg linux dmesg
run_exact_case "linux dmesg invalid global --output-http" 2 "$BIN" --output-http http://127.0.0.1:1/dmesg linux dmesg
run_exact_case "linux dmesg both global http+https" 2 "$BIN" --output-http http://127.0.0.1:1/dmesg --output-http https://127.0.0.1:1/dmesg linux dmesg
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

finish_tests