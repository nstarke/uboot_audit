#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
BIN="/tmp/embedded_linux_audit"

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
run_exact_case "linux dmesg extra positional arg" 2 "$BIN" linux dmesg extra
run_exact_case "linux dmesg invalid global --output-tcp" 2 "$BIN" --output-tcp invalid-target linux dmesg
run_exact_case "linux dmesg global --output-tcp + --help" 0 "$BIN" --output-tcp 127.0.0.1:9 linux dmesg --help
run_accept_case "linux dmesg global --output-http" "$BIN" --output-http http://127.0.0.1:1/dmesg linux dmesg
run_accept_case "linux dmesg global --output-https" "$BIN" --output-https https://127.0.0.1:1/dmesg linux dmesg
run_exact_case "linux dmesg invalid global --output-http" 2 "$BIN" --output-http ftp://127.0.0.1:1/dmesg linux dmesg
run_exact_case "linux dmesg invalid global --output-https" 2 "$BIN" --output-https http://127.0.0.1:1/dmesg linux dmesg
run_exact_case "linux dmesg both global http+https" 2 "$BIN" --output-http http://127.0.0.1:1/dmesg --output-https https://127.0.0.1:1/dmesg linux dmesg
run_accept_case "--insecure linux dmesg" "$BIN" --insecure linux dmesg

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