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
print_section "efi/bios orom argument coverage"

run_exact_case "efi dump-vars --help" 0 "$BIN" efi dump-vars --help
run_exact_case "efi orom --help" 0 "$BIN" efi orom --help
run_exact_case "bios orom --help" 0 "$BIN" bios orom --help

run_exact_case "efi dump-vars extra positional arg" 2 "$BIN" efi dump-vars extra
run_accept_case "efi dump-vars default output" "$BIN" efi dump-vars
run_accept_case "efi dump-vars --output-tcp" "$BIN" --output-tcp 127.0.0.1:9 efi dump-vars
run_accept_case "efi dump-vars --output-http" "$BIN" --output-http http://127.0.0.1:1 efi dump-vars
run_accept_case "efi dump-vars --output-http" "$BIN" --output-http https://127.0.0.1:1 efi dump-vars
run_accept_case "efi dump-vars --output-format txt" "$BIN" --output-format txt efi dump-vars
run_accept_case "efi dump-vars --output-format csv" "$BIN" --output-format csv efi dump-vars
run_accept_case "efi dump-vars --output-format json" "$BIN" --output-format json efi dump-vars

run_exact_case "efi orom pull missing output target" 2 "$BIN" efi orom pull
run_exact_case "bios orom pull missing output target" 2 "$BIN" bios orom pull

run_exact_case "efi orom pull invalid --output-http" 2 "$BIN" efi orom pull --output-http ftp://127.0.0.1:1/orom
run_exact_case "bios orom pull invalid --output-http" 2 "$BIN" bios orom pull --output-http ftp://127.0.0.1:1/orom
run_exact_case "efi orom pull both http+https" 2 "$BIN" efi orom pull --output-http http://127.0.0.1:1/orom --output-http https://127.0.0.1:1/orom
run_exact_case "bios orom pull both http+https" 2 "$BIN" bios orom pull --output-http http://127.0.0.1:1/orom --output-http https://127.0.0.1:1/orom
run_exact_case "efi orom pull extra positional arg" 2 "$BIN" efi orom pull extra
run_exact_case "bios orom list extra positional arg" 2 "$BIN" bios orom list extra

run_exact_case "efi orom invalid action" 2 "$BIN" efi orom invalid
run_exact_case "bios orom invalid action" 2 "$BIN" bios orom invalid

run_accept_case "efi orom pull --output-tcp" "$BIN" efi orom pull --output-tcp 127.0.0.1:9
run_accept_case "efi orom pull --output-http" "$BIN" efi orom pull --output-http http://127.0.0.1:1/orom
run_accept_case "efi orom pull --output-http" "$BIN" efi orom pull --output-http https://127.0.0.1:1/orom
run_accept_case "efi orom pull default verbose" "$BIN" efi orom pull --output-http http://127.0.0.1:1/orom

run_accept_case "bios orom pull --output-tcp" "$BIN" bios orom pull --output-tcp 127.0.0.1:9
run_accept_case "bios orom pull --output-http" "$BIN" bios orom pull --output-http http://127.0.0.1:1/orom
run_accept_case "bios orom pull --output-http" "$BIN" bios orom pull --output-http https://127.0.0.1:1/orom
run_accept_case "bios orom pull default verbose" "$BIN" bios orom pull --output-http http://127.0.0.1:1/orom

run_accept_case "efi orom list --output-tcp" "$BIN" efi orom list --output-tcp 127.0.0.1:9
run_accept_case "efi orom list --output-http" "$BIN" efi orom list --output-http http://127.0.0.1:1/orom
run_accept_case "bios orom list --output-http" "$BIN" bios orom list --output-http https://127.0.0.1:1/orom
run_accept_case "bios orom list default verbose" "$BIN" bios orom list --output-http http://127.0.0.1:1/orom
run_accept_case "efi orom list --output-http" "$BIN" efi orom list --output-http http://127.0.0.1:1/orom
run_accept_case "bios orom pull --insecure" "$BIN" --insecure bios orom pull --output-http https://127.0.0.1:1/orom

run_accept_case "efi orom list with --output-format csv" "$BIN" --output-format csv efi orom list --output-http http://127.0.0.1:1/orom
run_accept_case "bios orom list with --output-format json" "$BIN" --output-format json bios orom list --output-http http://127.0.0.1:1/orom

isa_gate_log="$(mktemp /tmp/test_efi_bios_isa_gate.XXXXXX)"
ELA_TEST_ISA=riscv64 TEST_DISABLE_OUTPUT_OVERRIDE=1 run_with_output_override "$BIN" efi orom list >"$isa_gate_log" 2>&1
rc=$?
if [ "$rc" -eq 1 ] && grep -F "Unsupported ISA for efi group: riscv64" "$isa_gate_log" >/dev/null 2>&1; then
    echo "[PASS] efi group rejects unsupported ISA with error log"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] efi group rejects unsupported ISA with error log (rc=$rc)"
    print_file_head_scrubbed "$isa_gate_log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi

ELA_TEST_ISA=riscv64 TEST_DISABLE_OUTPUT_OVERRIDE=1 run_with_output_override "$BIN" bios orom list >"$isa_gate_log" 2>&1
rc=$?
if [ "$rc" -eq 1 ] && grep -F "Unsupported ISA for bios group: riscv64" "$isa_gate_log" >/dev/null 2>&1; then
    echo "[PASS] bios group rejects unsupported ISA with error log"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] bios group rejects unsupported ISA with error log (rc=$rc)"
    print_file_head_scrubbed "$isa_gate_log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$isa_gate_log"

python_bin="$(find_python_bin || true)"

if [ -n "$python_bin" ]; then
    run_efi_vars_http=1
    case "${ELA_TEST_ISA:-}" in
        ""|x86|x86_64|aarch64-le|aarch64-be) : ;;
        *)
            echo "[PASS] efi dump-vars HTTP POST upload skipped (ELA_TEST_ISA=${ELA_TEST_ISA:-} does not support EFI)"
            PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
            run_efi_vars_http=0
            ;;
    esac

    if [ "$run_efi_vars_http" -eq 1 ]; then
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
    fi # run_efi_vars_http

    no_result_mode=""
    no_result_log="$(mktemp /tmp/test_orom_no_result_probe.XXXXXX)"

    TEST_DISABLE_OUTPUT_OVERRIDE=1 run_with_output_override "$BIN" efi orom list >"$no_result_log" 2>&1
    rc=$?
    if [ "$rc" -eq 1 ] && grep -F "No matching efi option ROM payloads found" "$no_result_log" >/dev/null 2>&1; then
        no_result_mode="efi"
        no_result_message="No matching efi option ROM payloads found"
    else
        TEST_DISABLE_OUTPUT_OVERRIDE=1 run_with_output_override "$BIN" bios orom list >"$no_result_log" 2>&1
        rc=$?
        if [ "$rc" -eq 1 ] && grep -F "No matching bios option ROM payloads found" "$no_result_log" >/dev/null 2>&1; then
            no_result_mode="bios"
            no_result_message="No matching bios option ROM payloads found"
        fi
    fi
    rm -f "$no_result_log"

    if [ -n "$no_result_mode" ]; then
        http_req_path="$(mktemp /tmp/test_orom_http_path.XXXXXX)"
        http_req_type="$(mktemp /tmp/test_orom_http_type.XXXXXX)"
        http_req_body="$(mktemp /tmp/test_orom_http_body.XXXXXX)"
        http_server_log="$(mktemp /tmp/test_orom_http_server.XXXXXX)"

        REQUEST_PATH_FILE="$http_req_path" REQUEST_TYPE_FILE="$http_req_type" REQUEST_BODY_FILE="$http_req_body" NEEDLE="$no_result_message" \
            "$python_bin" - <<'PY' >"$http_server_log" 2>&1 &
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
        needle = os.environ.get('NEEDLE', '')
        if needle and body.find(needle.encode()) != -1:
            threading.Thread(target=self.server.shutdown, daemon=True).start()

    def log_message(self, format, *args):
        pass

with OneShotTCPServer(('127.0.0.1', 0), Handler) as httpd:
    print(f'ready:{httpd.server_address[1]}', flush=True)
    httpd.serve_forever()
PY
        http_server_pid=$!

        ready=0
        http_port=""
        i=0
        while [ "$i" -lt 50 ]; do
            http_port="$(sed -n 's/^ready://p' "$http_server_log" 2>/dev/null | head -n 1)"
            if [ -n "$http_port" ]; then
                ready=1
                break
            fi
            if ! kill -0 "$http_server_pid" 2>/dev/null; then
                break
            fi
            sleep 0.1
            i="$(expr "$i" + 1)"
        done

        http_post_log="$(mktemp /tmp/test_orom_http_post.XXXXXX)"
        if [ "$ready" -eq 1 ]; then
            TEST_DISABLE_OUTPUT_OVERRIDE=1 run_with_output_override \
                "$BIN" "$no_result_mode" orom list --output-http "http://127.0.0.1:$http_port" >"$http_post_log" 2>&1
            rc=$?
            wait "$http_server_pid" 2>/dev/null || true

            if [ "$rc" -eq 1 ] && \
               grep -F "/upload/log" "$http_req_path" >/dev/null 2>&1 && \
               grep -F "text/plain; charset=utf-8" "$http_req_type" >/dev/null 2>&1 && \
               grep -F "$no_result_message" "$http_req_body" >/dev/null 2>&1; then
                echo "[PASS] $no_result_mode orom list no-result log is sent over HTTP upload/log"
                PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
            else
                echo "[FAIL] $no_result_mode orom list no-result log is sent over HTTP upload/log (rc=$rc)"
                print_file_head_scrubbed "$http_post_log" 80
                echo "--- request path ---"
                print_file_head_scrubbed "$http_req_path" 20
                echo "--- request content-type ---"
                print_file_head_scrubbed "$http_req_type" 20
                echo "--- request body ---"
                print_file_head_scrubbed "$http_req_body" 20
                FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
            fi
        else
            echo "[FAIL] $no_result_mode orom list no-result log is sent over HTTP upload/log (server did not start)"
            print_file_head_scrubbed "$http_server_log" 80
            FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
            kill "$http_server_pid" 2>/dev/null || true
            wait "$http_server_pid" 2>/dev/null || true
        fi

        rm -f "$http_req_path" "$http_req_type" "$http_req_body" "$http_server_log" "$http_post_log"
    else
        echo "[PASS] skipped no-result OROM HTTP log test (host has matching EFI and BIOS OROM results or no deterministic no-result case)"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    fi
fi

finish_tests
