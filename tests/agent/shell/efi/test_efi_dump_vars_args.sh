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
print_section "efi dump-vars argument coverage"

run_exact_case "efi dump-vars --help" 0 "$BIN" efi dump-vars --help
run_exact_case "efi dump-vars extra positional arg" 2 "$BIN" efi dump-vars extra
run_accept_case "efi dump-vars default output" "$BIN" efi dump-vars
run_accept_case "efi dump-vars --output-tcp" "$BIN" --output-tcp 127.0.0.1:9 efi dump-vars
run_accept_case "efi dump-vars --output-http" "$BIN" --output-http http://127.0.0.1:1 efi dump-vars
run_accept_case "efi dump-vars --output-http" "$BIN" --output-http https://127.0.0.1:1 efi dump-vars
run_accept_case "efi dump-vars --output-format txt" "$BIN" --output-format txt efi dump-vars
run_accept_case "efi dump-vars --output-format csv" "$BIN" --output-format csv efi dump-vars
run_accept_case "efi dump-vars --output-format json" "$BIN" --output-format json efi dump-vars

python_bin="$(find_python_bin || true)"

case "${ELA_TEST_ISA:-}" in
    ""|x86|x86_64|aarch64-le|aarch64-be) : ;;
    *)
        echo "[PASS] efi dump-vars HTTP POST upload skipped (ELA_TEST_ISA=${ELA_TEST_ISA:-} does not support EFI)"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
        python_bin=""
        ;;
esac

if [ -n "$python_bin" ]; then
    efi_vars_http_path="$(mktemp /tmp/test_efi_vars_http_path.XXXXXX)"
    efi_vars_http_type="$(mktemp /tmp/test_efi_vars_http_type.XXXXXX)"
    efi_vars_http_body="$(mktemp /tmp/test_efi_vars_http_body.XXXXXX)"
    efi_vars_http_server_log="$(mktemp /tmp/test_efi_vars_http_server.XXXXXX)"

    REQUEST_PATH_FILE="$efi_vars_http_path" REQUEST_TYPE_FILE="$efi_vars_http_type" REQUEST_BODY_FILE="$efi_vars_http_body" \
        "$python_bin" - <<'PY' >"$efi_vars_http_server_log" 2>&1 &
import http.server
import os
import socketserver
import threading

path_file = os.environ['REQUEST_PATH_FILE']
type_file = os.environ['REQUEST_TYPE_FILE']
body_file = os.environ['REQUEST_BODY_FILE']

class OneShotTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length)
        with open(path_file, 'w', encoding='utf-8') as fh:
            fh.write(self.path)
        with open(type_file, 'w', encoding='utf-8') as fh:
            fh.write(self.headers.get('Content-Type', ''))
        with open(body_file, 'wb') as fh:
            fh.write(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok\n')
        if '/upload/efi-vars' in self.path:
            threading.Thread(target=self.server.shutdown, daemon=True).start()

    def log_message(self, format, *args):
        pass

with OneShotTCPServer(('127.0.0.1', 0), Handler) as httpd:
    print(f'ready:{httpd.server_address[1]}', flush=True)
    httpd.serve_forever()
PY
    efi_vars_http_server_pid=$!

    efi_vars_ready=0
    efi_vars_http_port=""
    i=0
    while [ "$i" -lt 50 ]; do
        efi_vars_http_port="$(sed -n 's/^ready://p' "$efi_vars_http_server_log" 2>/dev/null | head -n 1)"
        if [ -n "$efi_vars_http_port" ]; then
            efi_vars_ready=1
            break
        fi
        if ! kill -0 "$efi_vars_http_server_pid" 2>/dev/null; then
            break
        fi
        sleep 0.1
        i="$(expr "$i" + 1)"
    done

    efi_vars_http_post_log="$(mktemp /tmp/test_efi_vars_http_post.XXXXXX)"
    if [ "$efi_vars_ready" -eq 1 ]; then
        TEST_DISABLE_OUTPUT_OVERRIDE=1 run_with_output_override \
            "$BIN" --output-format json --output-http "http://127.0.0.1:$efi_vars_http_port" efi dump-vars >"$efi_vars_http_post_log" 2>&1
        rc=$?
        kill "$efi_vars_http_server_pid" 2>/dev/null || true
        wait "$efi_vars_http_server_pid" 2>/dev/null || true

        if [ "$rc" -ne 2 ] && \
           grep -F "/upload/efi-vars" "$efi_vars_http_path" >/dev/null 2>&1 && \
           grep -F "application/x-ndjson; charset=utf-8" "$efi_vars_http_type" >/dev/null 2>&1; then
            echo "[PASS] efi dump-vars performs HTTP POST upload honoring --output-format json"
            PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
        else
            echo "[FAIL] efi dump-vars performs HTTP POST upload honoring --output-format json (rc=$rc)"
            print_file_head_scrubbed "$efi_vars_http_post_log" 120
            echo "--- request path ---"
            print_file_head_scrubbed "$efi_vars_http_path" 20
            echo "--- request content-type ---"
            print_file_head_scrubbed "$efi_vars_http_type" 20
            echo "--- request body ---"
            print_file_head_scrubbed "$efi_vars_http_body" 20
            FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
        fi
    else
        echo "[FAIL] efi dump-vars performs HTTP POST upload honoring --output-format json (server did not start)"
        print_file_head_scrubbed "$efi_vars_http_server_log" 80
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
        kill "$efi_vars_http_server_pid" 2>/dev/null || true
        wait "$efi_vars_http_server_pid" 2>/dev/null || true
    fi

    rm -f "$efi_vars_http_path" "$efi_vars_http_type" "$efi_vars_http_body" \
        "$efi_vars_http_server_log" "$efi_vars_http_post_log"
fi

finish_tests