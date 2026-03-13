#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "linux ssh subcommand argument coverage"

TMP_DIR="$(mktemp -d /tmp/test_linux_ssh_args.XXXXXX)"
TMP_FILE="$TMP_DIR/file.txt"
mkdir -p "$TMP_DIR/sub"
echo "payload" >"$TMP_FILE"
echo "nested" >"$TMP_DIR/sub/nested.txt"

run_exact_case "linux ssh --help" 0 "$BIN" linux ssh --help
run_exact_case "linux ssh no args" 2 "$BIN" linux ssh
run_exact_case "linux ssh unknown mode" 2 "$BIN" linux ssh unknown

run_exact_case "linux ssh client no host" 2 "$BIN" linux ssh client
run_exact_case "linux ssh client extra arg" 2 "$BIN" linux ssh client 127.0.0.1 extra
run_accept_case "linux ssh client host" "$BIN" linux ssh client 127.0.0.1
run_accept_case "linux ssh client host --port" "$BIN" linux ssh client 127.0.0.1 --port 2222

run_exact_case "linux ssh copy no host" 2 "$BIN" linux ssh copy --local-path "$TMP_FILE" --remote-path /tmp/file.txt
run_exact_case "linux ssh copy missing local-path" 2 "$BIN" linux ssh copy 127.0.0.1 --remote-path /tmp/file.txt
run_exact_case "linux ssh copy missing remote-path" 2 "$BIN" linux ssh copy 127.0.0.1 --local-path "$TMP_FILE"
run_accept_case "linux ssh copy file args" "$BIN" linux ssh copy 127.0.0.1 --local-path "$TMP_FILE" --remote-path /tmp/file.txt
run_accept_case "linux ssh copy recursive dir args" "$BIN" linux ssh copy 127.0.0.1 --local-path "$TMP_DIR" --remote-path /tmp/dir --recursive

run_exact_case "linux ssh tunnel no host" 2 "$BIN" linux ssh tunnel
run_exact_case "linux ssh tunnel extra arg" 2 "$BIN" linux ssh tunnel 127.0.0.1 extra
run_accept_case "linux ssh tunnel host" "$BIN" linux ssh tunnel 127.0.0.1
run_accept_case "linux ssh tunnel host --port" "$BIN" linux ssh tunnel 127.0.0.1 --port 2222

run_exact_case "linux ssh socks no host" 2 "$BIN" linux ssh socks --remote-host 127.0.0.1 --remote-port 80 --local-port 1080
run_exact_case "linux ssh socks missing remote-host" 2 "$BIN" linux ssh socks 127.0.0.1 --remote-port 80 --local-port 1080
run_exact_case "linux ssh socks missing remote-port" 2 "$BIN" linux ssh socks 127.0.0.1 --remote-host 127.0.0.1 --local-port 1080
run_exact_case "linux ssh socks missing local-port" 2 "$BIN" linux ssh socks 127.0.0.1 --remote-host 127.0.0.1 --remote-port 80
run_exact_case "linux ssh socks extra arg" 2 "$BIN" linux ssh socks 127.0.0.1 --remote-host 127.0.0.1 --remote-port 80 --local-port 1080 extra
run_accept_case "linux ssh socks args" "$BIN" linux ssh socks 127.0.0.1 --remote-host 127.0.0.1 --remote-port 80 --local-port 1080
run_accept_case "linux ssh socks args --port" "$BIN" linux ssh socks 127.0.0.1 --port 2222 --remote-host 127.0.0.1 --remote-port 80 --local-port 1080

rm -rf "$TMP_DIR"
finish_tests
