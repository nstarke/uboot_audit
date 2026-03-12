#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SCRIPT_DIR/common.sh"

require_binary "$BIN"
print_section "linux download-file subcommand argument coverage"

run_exact_case "linux download-file --help" 0 "$BIN" linux download-file --help
run_exact_case "linux download-file no args" 2 "$BIN" linux download-file
run_exact_case "linux download-file missing output path" 2 "$BIN" linux download-file https://example.com/file.bin
run_exact_case "linux download-file invalid scheme" 2 "$BIN" linux download-file ftp://example.com/file.bin /tmp/file.bin
run_exact_case "linux download-file extra positional arg" 2 "$BIN" linux download-file https://example.com/file.bin /tmp/file.bin extra
run_accept_case "linux download-file http url" "$BIN" linux download-file http://127.0.0.1:1/file.bin /tmp/file.bin
run_accept_case "linux download-file https url" "$BIN" --insecure linux download-file https://127.0.0.1:1/file.bin /tmp/file.bin

python_bin="$(find_python_bin || true)"

if [ -n "$python_bin" ]; then
download_src="$(mktemp /tmp/test_download_file_src.XXXXXX)"
download_dst="$(mktemp /tmp/test_download_file_dst.XXXXXX)"
rm -f "$download_dst"
download_server_log="$(mktemp /tmp/test_download_file_server.XXXXXX)"
download_port_file="$(mktemp /tmp/test_download_file_port.XXXXXX)"
download_log="$(mktemp /tmp/test_download_file_run.XXXXXX)"

printf 'firmware-download-payload' >"$download_src"

"$python_bin" -c '
import http.server
import socketserver
import sys

payload_path = sys.argv[1]
port_file = sys.argv[2]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open(payload_path, "rb") as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, format, *args):
        pass

with socketserver.TCPServer(("127.0.0.1", 0), Handler) as httpd:
    with open(port_file, "w", encoding="utf-8") as fh:
        fh.write(str(httpd.server_address[1]))
    httpd.handle_request()
' "$download_src" "$download_port_file" >"$download_server_log" 2>&1 &
download_server_pid=$!

download_port=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if [ -s "$download_port_file" ]; then
        download_port="$(cat "$download_port_file")"
        break
    fi
    sleep 1
done

if [ -n "$download_port" ]; then
    "$BIN" linux download-file "http://127.0.0.1:$download_port/file.bin" "$download_dst" >"$download_log" 2>&1
    rc=$?
    if [ "$rc" -eq 0 ] && cmp -s "$download_src" "$download_dst" && \
       grep -q "download-file downloaded 25 bytes success=true" "$download_log"; then
        echo "[PASS] linux download-file downloads file and logs byte count"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] linux download-file downloads file and logs byte count (rc=$rc)"
        print_file_head_scrubbed "$download_log" 120
        echo "--- server log ---"
        print_file_head_scrubbed "$download_server_log" 80
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi
else
    echo "[FAIL] linux download-file downloads file and logs byte count (server did not start)"
    print_file_head_scrubbed "$download_server_log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi

wait "$download_server_pid" 2>/dev/null || true
rm -f "$download_src" "$download_dst" "$download_server_log" "$download_port_file" "$download_log"
else
    echo "[SKIP] linux download-file test requires python3 or python"
fi

failure_log="$(mktemp /tmp/test_download_file_failure.XXXXXX)"
missing_dst="$(mktemp /tmp/test_download_file_failure_dst.XXXXXX)"
rm -f "$missing_dst"
"$BIN" linux download-file http://127.0.0.1:1/missing.bin "$missing_dst" >"$failure_log" 2>&1
rc=$?
if [ "$rc" -ne 0 ] && grep -q "download-file downloaded 0 bytes success=false" "$failure_log"; then
    echo "[PASS] linux download-file logs failed download result"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux download-file logs failed download result (rc=$rc)"
    print_file_head_scrubbed "$failure_log" 120
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$failure_log" "$missing_dst"

finish_tests