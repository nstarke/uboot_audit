#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$SCRIPT_DIR"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
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
print_section "top-level CLI and uncovered extra argument coverage"

run_exact_case "top-level --help" 0 "$BIN" --help
run_exact_case "top-level help" 0 "$BIN" help
run_exact_case "top-level invalid --output-format" 2 "$BIN" --output-format yaml linux dmesg
run_exact_case "top-level missing --output-format value" 2 "$BIN" --output-format
run_exact_case "top-level missing --output-tcp value" 2 "$BIN" --output-tcp
run_exact_case "top-level missing --output-http value" 2 "$BIN" --output-http
run_exact_case "top-level missing --script value" 2 "$BIN" --script
run_exact_case "top-level invalid --output-http URI" 2 "$BIN" --output-http ftp://127.0.0.1:1 linux dmesg
run_exact_case "top-level unknown command group" 2 "$BIN" unknown-group
run_exact_case "top-level rejects --script with direct command" 2 "$BIN" --script /tmp/nonexistent-script.ela linux dmesg
run_exact_case "top-level missing local script path" 2 "$BIN" --script /tmp/nonexistent-script.ela
run_accept_case "top-level ELA_API_URL http" env ELA_API_URL=http://127.0.0.1:1/upload "$BIN" linux dmesg --help
run_accept_case "top-level ELA_API_URL https + ELA_API_INSECURE=true" env ELA_API_URL=https://127.0.0.1:1/upload ELA_API_INSECURE=true "$BIN" linux dmesg --help
run_exact_case "top-level invalid ELA_API_URL" 2 env ELA_API_URL=ftp://127.0.0.1:1/upload "$BIN" linux dmesg --help
run_accept_case "top-level ELA_OUTPUT_FORMAT json" env ELA_OUTPUT_FORMAT=json "$BIN" linux dmesg --help
run_exact_case "top-level invalid ELA_OUTPUT_FORMAT" 2 env ELA_OUTPUT_FORMAT=xml "$BIN" linux dmesg --help
run_accept_case "top-level ELA_QUIET true" env ELA_QUIET=true "$BIN" linux dmesg --help
run_exact_case "top-level invalid ELA_OUTPUT_TCP" 2 env ELA_OUTPUT_TCP=invalid-target "$BIN" linux dmesg --help

TMP_SCRIPT="$(mktemp /tmp/ela-top-level-script.XXXXXX)"
cat >"$TMP_SCRIPT" <<'EOF_SCRIPT'
# whole-line comment should be ignored
linux dmesg --help # inline comment should be ignored
embedded_linux_audit linux execute-command --help # inline comment should be ignored
ela linux download-file --help # inline comment should be ignored
EOF_SCRIPT
run_exact_case "top-level --script accepts whole-line and inline comments" 0 "$BIN" --script "$TMP_SCRIPT"
run_accept_case "top-level ELA_SCRIPT local file" env ELA_SCRIPT="$TMP_SCRIPT" "$BIN"
rm -f "$TMP_SCRIPT"

run_exact_case "linux ssh client --help" 0 "$BIN" linux ssh client --help
run_exact_case "linux ssh copy --help" 0 "$BIN" linux ssh copy --help
run_exact_case "linux ssh tunnel --help" 0 "$BIN" linux ssh tunnel --help
run_exact_case "top-level missing --api-key value" 2 "$BIN" --api-key
run_accept_case "top-level --api-key with value" "$BIN" --api-key mysecrettoken linux dmesg --help
run_accept_case "top-level --api-key= form" "$BIN" --api-key=mysecrettoken linux dmesg --help
run_accept_case "top-level ELA_API_KEY env var" env ELA_API_KEY=mysecrettoken "$BIN" linux dmesg --help

run_exact_case "top-level missing --remote value" 2 "$BIN" --remote
run_exact_case "top-level --remote cannot be combined with command" 2 "$BIN" --remote 127.0.0.1:1 linux dmesg
run_accept_case "top-level --remote unreachable target" "$BIN" --remote 127.0.0.1:1
run_accept_case "top-level --remote ws:// unreachable target" "$BIN" --remote ws://127.0.0.1:1
run_accept_case "top-level --remote wss:// unreachable target" "$BIN" --remote wss://127.0.0.1:1
run_accept_case "top-level --insecure --remote wss:// unreachable target" "$BIN" --insecure --remote wss://127.0.0.1:1
run_exact_case "top-level --remote ws:// cannot be combined with command" 2 "$BIN" --remote ws://127.0.0.1:1 linux dmesg

# Live daemon lifecycle: verify --remote daemonizes and prints "Remote session started"
if command -v nc >/dev/null 2>&1; then
    remote_port=19873
    nc -l "$remote_port" >/dev/null 2>&1 &
    NC_PID=$!
    sleep 0.2

    remote_log="$(mktemp /tmp/test_remote_lifecycle.XXXXXX)"
    "$BIN" --remote "127.0.0.1:$remote_port" >"$remote_log" 2>&1
    rc=$?

    if [ "$rc" -eq 0 ] && grep -q "Remote session started" "$remote_log"; then
        echo "[PASS] --remote starts daemon when connection succeeds"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] --remote starts daemon when connection succeeds (rc=$rc)"
        print_file_head_scrubbed "$remote_log" 40
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi
    rm -f "$remote_log"

    # Close nc; daemon will receive SIGPIPE and exit
    kill "$NC_PID" 2>/dev/null
    wait "$NC_PID" 2>/dev/null
    sleep 0.5
else
    echo "[SKIP] --remote daemon lifecycle test (nc not available)"
fi

# Live WebSocket daemon lifecycle: verify --remote ws:// daemonizes and prints "Remote session started"
TERMINAL_SERVER_JS="$(cd "$REPO_ROOT/api/terminal" 2>/dev/null && pwd)/server.js"
if command -v node >/dev/null 2>&1 && [ -f "$TERMINAL_SERVER_JS" ] && \
   [ -d "$(dirname "$TERMINAL_SERVER_JS")/node_modules/ws" ]; then
    ws_port=19875
    ws_log="$(mktemp /tmp/test_ws_server.XXXXXX)"
    ELA_TERMINAL_PORT="$ws_port" node "$TERMINAL_SERVER_JS" >"$ws_log" 2>&1 &
    WS_SERVER_PID=$!
    sleep 0.3

    remote_ws_log="$(mktemp /tmp/test_remote_ws_lifecycle.XXXXXX)"
    "$BIN" --remote "ws://127.0.0.1:$ws_port" >"$remote_ws_log" 2>&1
    rc=$?

    if [ "$rc" -eq 0 ] && grep -q "Remote session started" "$remote_ws_log"; then
        echo "[PASS] --remote ws:// starts daemon when connection succeeds"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] --remote ws:// starts daemon when connection succeeds (rc=$rc)"
        print_file_head_scrubbed "$remote_ws_log" 40
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi
    rm -f "$remote_ws_log"

    kill "$WS_SERVER_PID" 2>/dev/null
    wait "$WS_SERVER_PID" 2>/dev/null
    rm -f "$ws_log"
    sleep 0.3
else
    echo "[SKIP] --remote ws:// daemon lifecycle test (node or api/terminal/node_modules not available)"
fi

run_exact_case "linux ssh copy extra arg after required args" 2 "$BIN" linux ssh copy 127.0.0.1 --local-path /tmp/src --remote-path /tmp/dst extra
run_accept_case "linux ssh copy --port" "$BIN" linux ssh copy 127.0.0.1 --local-path /tmp/src --remote-path /tmp/dst --port 2022

run_accept_case "uboot env parse-vars alias --size" "$BIN" uboot env parse-vars --size "$TEST_SIZE"
run_accept_case "uboot env legacy --parse-vars flag --size" "$BIN" uboot env --parse-vars --size "$TEST_SIZE"

run_exact_case "uboot image pull extra global parser coverage via --help" 0 \
    "$BIN" --output-http http://127.0.0.1:1/image uboot image pull --dev /dev/null --offset 0x0 --help
run_exact_case "uboot audit extra parser coverage via --help" 0 \
    "$BIN" uboot audit --dev /dev/null --offset 0x0 --size "$TEST_SIZE" --signature-alg sha512 --help

finish_tests