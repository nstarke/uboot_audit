#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="$REPO_ROOT/embedded_linux_audit"

TEST_OUTPUT_HTTP="${TEST_OUTPUT_HTTP:-}"
TEST_OUTPUT_HTTPS="${TEST_OUTPUT_HTTPS:-}"

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
        --output-https)
            if [ "$#" -lt 2 ]; then
                echo "error: --output-https requires a value"
                exit 2
            fi
            TEST_OUTPUT_HTTPS="$2"
            shift 2
            ;;
        --output-https=*)
            TEST_OUTPUT_HTTPS="${1#*=}"
            shift
            ;;
        *)
            echo "error: unknown argument: $1"
            exit 2
            ;;
    esac
done

if [ -n "$TEST_OUTPUT_HTTP" ] && [ -n "$TEST_OUTPUT_HTTPS" ]; then
    echo "error: set only one of --output-http or --output-https"
    exit 2
fi

export TEST_OUTPUT_HTTP
export TEST_OUTPUT_HTTPS

# shellcheck source=tests/agent/common.sh
. "$SCRIPT_DIR/common.sh"

require_binary "$BIN"
print_section "linux dmesg subcommand argument coverage"

run_exact_case "linux dmesg --help" 0 "$BIN" linux dmesg --help
run_accept_case "linux dmesg" "$BIN" linux dmesg
run_accept_case "linux dmesg --verbose" "$BIN" linux dmesg --verbose
run_exact_case "linux dmesg --output-tcp + --help" 0 "$BIN" linux dmesg --output-tcp 127.0.0.1:9 --help
run_accept_case "linux dmesg --output-http" "$BIN" linux dmesg --output-http http://127.0.0.1:1/dmesg
run_accept_case "linux dmesg --output-https" "$BIN" linux dmesg --output-https https://127.0.0.1:1/dmesg
run_accept_case "linux dmesg --insecure" "$BIN" linux dmesg --insecure

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
    sed -n '1,80p' "$log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

finish_tests