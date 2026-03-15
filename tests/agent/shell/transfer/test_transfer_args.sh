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
print_section "transfer subcommand argument coverage"

run_exact_case "transfer --help" 0 "$BIN" transfer --help
run_exact_case "transfer no args" 2 "$BIN" transfer
run_exact_case "transfer extra arg" 2 "$BIN" transfer host:1234 extra
run_accept_case "transfer unreachable target" "$BIN" transfer 127.0.0.1:1

# Live daemon lifecycle: verify transfer daemonizes and prints "Transfer started"
if command -v nc >/dev/null 2>&1; then
    transfer_port=19874
    nc -l "$transfer_port" >/dev/null 2>&1 &
    NC_PID=$!
    sleep 0.2

    transfer_log="$(mktemp /tmp/test_transfer_lifecycle.XXXXXX)"
    "$BIN" transfer "127.0.0.1:$transfer_port" >"$transfer_log" 2>&1
    rc=$?

    if [ "$rc" -eq 0 ] && grep -q "Transfer started" "$transfer_log"; then
        echo "[PASS] transfer daemonizes and reports started when connection succeeds"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] transfer daemonizes and reports started when connection succeeds (rc=$rc)"
        print_file_head_scrubbed "$transfer_log" 40
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi
    rm -f "$transfer_log"

    # Close nc; daemon will receive SIGPIPE and exit
    kill "$NC_PID" 2>/dev/null
    wait "$NC_PID" 2>/dev/null
    sleep 0.5
else
    echo "[SKIP] transfer daemon lifecycle test (nc not available)"
fi

finish_tests
