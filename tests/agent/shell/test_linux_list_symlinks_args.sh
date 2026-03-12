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
print_section "linux list-symlinks subcommand argument coverage"

TMP_DIR="$(mktemp -d /tmp/test_list_symlinks_args.XXXXXX)"
TMP_SUBDIR="$TMP_DIR/subdir"
TMP_FILE="$TMP_DIR/plain.txt"
TMP_LINK_TOP="$TMP_DIR/top-link"
TMP_LINK_SUB="$TMP_SUBDIR/nested-link"
mkdir -p "$TMP_SUBDIR"
cat >"$TMP_FILE" <<'EOF_PLAIN'
plain
EOF_PLAIN
ln -s /tmp/target-top "$TMP_LINK_TOP"
ln -s ../plain.txt "$TMP_LINK_SUB"

run_exact_case "linux list-symlinks --help" 0 "$BIN" linux list-symlinks --help
run_exact_case "linux list-symlinks relative path" 2 "$BIN" linux list-symlinks ./relative
run_exact_case "linux list-symlinks file path" 2 "$BIN" linux list-symlinks "$TMP_FILE"
run_exact_case "linux list-symlinks invalid global --output-http" 2 "$BIN" --output-http ftp://127.0.0.1:1/symlink-list linux list-symlinks "$TMP_DIR"
run_exact_case "linux list-symlinks invalid global --output-http" 2 "$BIN" --output-http http://127.0.0.1:1/symlink-list linux list-symlinks "$TMP_DIR"
run_exact_case "linux list-symlinks both global http+https" 2 "$BIN" --output-http http://127.0.0.1:1/symlink-list --output-http https://127.0.0.1:1/symlink-list linux list-symlinks "$TMP_DIR"
run_exact_case "linux list-symlinks invalid global --output-tcp" 2 "$BIN" --output-tcp invalid-target linux list-symlinks "$TMP_DIR"
run_exact_case "linux list-symlinks extra positional argument" 2 "$BIN" linux list-symlinks "$TMP_DIR" /tmp/extra

run_exact_case "linux list-symlinks no directory argument defaults to /" 0 "$BIN" linux list-symlinks
run_exact_case "linux list-symlinks default directory" 0 "$BIN" linux list-symlinks "$TMP_DIR"
run_exact_case "linux list-symlinks --recursive" 0 "$BIN" linux list-symlinks "$TMP_DIR" --recursive
run_accept_case "linux list-symlinks global --output-http" "$BIN" --output-http http://127.0.0.1:1/symlink-list linux list-symlinks "$TMP_DIR"
run_accept_case "linux list-symlinks global --output-http" "$BIN" --output-http https://127.0.0.1:1/symlink-list linux list-symlinks "$TMP_DIR"

python_bin="$(find_python_bin || true)"

if [ -n "$python_bin" ]; then
    http_req_path="$(mktemp /tmp/test_list_symlinks_http_path.XXXXXX)"
    http_req_type="$(mktemp /tmp/test_list_symlinks_http_type.XXXXXX)"
    http_req_body="$(mktemp /tmp/test_list_symlinks_http_body.XXXXXX)"
    http_server_log="$(mktemp /tmp/test_list_symlinks_http_server.XXXXXX)"

    REQUEST_PATH_FILE="$http_req_path" REQUEST_TYPE_FILE="$http_req_type" REQUEST_BODY_FILE="$http_req_body" \
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

    http_post_log="$(mktemp /tmp/test_list_symlinks_http_post.XXXXXX)"
    if [ "$ready" -eq 1 ]; then
        "$BIN" --output-http "http://127.0.0.1:$http_port" linux list-symlinks "$TMP_DIR" >"$http_post_log" 2>&1
        rc=$?
        wait "$http_server_pid" 2>/dev/null || true

        if [ "$rc" -eq 0 ] && \
           grep -F "/upload/symlink-list?filePath=%2F" "$http_req_path" >/dev/null 2>&1 && \
           grep -F "text/plain; charset=utf-8" "$http_req_type" >/dev/null 2>&1 && \
           file_has_exact_line "$TMP_LINK_TOP -> /tmp/target-top" "$http_req_body"; then
            echo "[PASS] linux list-symlinks global --output-http performs HTTP POST upload"
            PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
        else
            echo "[FAIL] linux list-symlinks global --output-http performs HTTP POST upload (rc=$rc)"
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
        echo "[FAIL] linux list-symlinks global --output-http performs HTTP POST upload (server did not start)"
        print_file_head_scrubbed "$http_server_log" 80
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
        kill "$http_server_pid" 2>/dev/null || true
        wait "$http_server_pid" 2>/dev/null || true
    fi

    rm -f "$http_req_path" "$http_req_type" "$http_req_body" "$http_server_log" "$http_post_log"
fi

tcp_log="$(mktemp /tmp/test_list_symlinks_tcp.XXXXXX)"
"$BIN" --output-tcp 127.0.0.1:9 linux list-symlinks "$TMP_DIR" >"$tcp_log" 2>&1
rc=$?
if [ "$rc" -eq 2 ] && grep -q "Invalid/failed output target (expected IPv4:port): 127.0.0.1:9" "$tcp_log"; then
    echo "[PASS] linux list-symlinks global --output-tcp reaches TCP output validation path"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-symlinks global --output-tcp reaches TCP output validation path (rc=$rc)"
    print_file_head_scrubbed "$tcp_log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$tcp_log"
run_accept_case "--insecure linux list-symlinks global --output-http" "$BIN" --insecure --output-http https://127.0.0.1:1/symlink-list linux list-symlinks "$TMP_DIR"
run_exact_case "linux list-symlinks with --output-format txt" 0 "$BIN" --output-format txt linux list-symlinks "$TMP_DIR"
run_exact_case "linux list-symlinks with --output-format csv" 0 "$BIN" --output-format csv linux list-symlinks "$TMP_DIR"
run_exact_case "linux list-symlinks with --output-format json" 0 "$BIN" --output-format json linux list-symlinks "$TMP_DIR"

txt_log="$(mktemp /tmp/test_list_symlinks_txt.XXXXXX)"
run_with_output_override "$BIN" --output-format txt linux list-symlinks "$TMP_DIR" >"$txt_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && file_has_exact_line "$TMP_LINK_TOP -> /tmp/target-top" "$txt_log" && ! file_has_exact_line "$TMP_LINK_SUB -> ../plain.txt" "$txt_log"; then
    echo "[PASS] linux list-symlinks default listing stays non-recursive"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-symlinks default listing stays non-recursive (rc=$rc)"
    print_file_head_scrubbed "$txt_log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$txt_log"

recursive_log="$(mktemp /tmp/test_list_symlinks_recursive.XXXXXX)"
run_with_output_override "$BIN" --output-format txt linux list-symlinks "$TMP_DIR" --recursive >"$recursive_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && file_has_exact_line "$TMP_LINK_TOP -> /tmp/target-top" "$recursive_log" && file_has_exact_line "$TMP_LINK_SUB -> ../plain.txt" "$recursive_log"; then
    echo "[PASS] linux list-symlinks --recursive includes nested symlinks"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-symlinks --recursive includes nested symlinks (rc=$rc)"
    print_file_head_scrubbed "$recursive_log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$recursive_log"

csv_log="$(mktemp /tmp/test_list_symlinks_csv.XXXXXX)"
run_with_output_override "$BIN" --output-format csv linux list-symlinks "$TMP_DIR" >"$csv_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && file_has_exact_line "\"$TMP_LINK_TOP\",\"/tmp/target-top\"" "$csv_log"; then
    echo "[PASS] linux list-symlinks csv output matches expected format"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-symlinks csv output matches expected format (rc=$rc)"
    print_file_head_scrubbed "$csv_log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$csv_log"

json_log="$(mktemp /tmp/test_list_symlinks_json.XXXXXX)"
run_with_output_override "$BIN" --output-format json linux list-symlinks "$TMP_DIR" >"$json_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && file_has_exact_line "{\"link_path\":\"$TMP_LINK_TOP\",\"location_path\":\"/tmp/target-top\"}" "$json_log"; then
    echo "[PASS] linux list-symlinks json output matches expected format"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-symlinks json output matches expected format (rc=$rc)"
    print_file_head_scrubbed "$json_log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$json_log"

rm -rf "$TMP_DIR"
finish_tests