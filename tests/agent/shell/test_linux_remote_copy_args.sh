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
print_section "linux remote-copy subcommand argument coverage"

TMP_DIR="$(mktemp -d /tmp/test_remote_copy_args.XXXXXX)"
TMP_FILE="$TMP_DIR/sample.bin"
echo "remote copy payload" >"$TMP_FILE"

run_exact_case "linux remote-copy --help" 0 "$BIN" linux remote-copy --help
run_exact_case "linux remote-copy no args" 2 "$BIN" linux remote-copy
run_exact_case "linux remote-copy relative path" 2 "$BIN" --output-tcp 127.0.0.1:9 linux remote-copy ./relative.bin
run_exact_case "linux remote-copy missing output target" 2 "$BIN" linux remote-copy "$TMP_FILE"
run_exact_case "linux remote-copy subcommand --output-http rejected" 2 "$BIN" linux remote-copy "$TMP_FILE" --output-http ftp://127.0.0.1:1/file
run_exact_case "linux remote-copy subcommand --output-http rejected" 2 "$BIN" linux remote-copy "$TMP_FILE" --output-http http://127.0.0.1:1/file
run_exact_case "linux remote-copy subcommand --output-tcp rejected" 2 "$BIN" linux remote-copy "$TMP_FILE" --output-tcp invalid-target
run_exact_case "linux remote-copy both http+https" 2 "$BIN" --output-http http://127.0.0.1:1/file --output-http https://127.0.0.1:1/file linux remote-copy "$TMP_FILE"
run_exact_case "linux remote-copy multiple transport kinds" 2 "$BIN" --output-tcp 127.0.0.1:9 --output-http http://127.0.0.1:1/file linux remote-copy "$TMP_FILE"
run_exact_case "linux remote-copy extra positional argument" 2 "$BIN" --output-tcp 127.0.0.1:9 linux remote-copy "$TMP_FILE" /tmp/extra
run_exact_case "linux remote-copy /proc without allow flag" 2 "$BIN" --output-http http://127.0.0.1:1 linux remote-copy /proc/cmdline
run_exact_case "linux remote-copy /dev without allow flag" 2 "$BIN" --output-http http://127.0.0.1:1 linux remote-copy /dev/null

TMP_SUBDIR="$TMP_DIR/subdir"
mkdir -p "$TMP_SUBDIR"
echo "nested payload" >"$TMP_SUBDIR/nested.bin"
ln -sf "$TMP_FILE" "$TMP_DIR/sample.link"

# Prefer smaller restricted subdirectories over virtual filesystem roots so
# remote-copy argument coverage stays fast and avoids traversing very large,
# highly dynamic trees like /proc.
DEV_REMOTE_COPY_DIR=""
for candidate in /dev/shm /dev/mqueue /dev/pts /dev; do
    if [ -d "$candidate" ]; then
        DEV_REMOTE_COPY_DIR="$candidate"
        break
    fi
done

SYS_REMOTE_COPY_DIR=""
for candidate in /sys/kernel /sys/fs /sys/module /sys; do
    if [ -d "$candidate" ]; then
        SYS_REMOTE_COPY_DIR="$candidate"
        break
    fi
done

PROC_REMOTE_COPY_DIR=""
for candidate in /proc/sys/kernel /proc/sys /proc/fs /proc; do
    if [ -d "$candidate" ]; then
        PROC_REMOTE_COPY_DIR="$candidate"
        break
    fi
done

run_exact_case "linux remote-copy directory over tcp" 2 "$BIN" --output-tcp 127.0.0.1:9 linux remote-copy "$TMP_DIR"
run_accept_case "linux remote-copy symlink without --allow-symlinks" "$BIN" --output-http http://127.0.0.1:1 linux remote-copy "$TMP_DIR/sample.link"
run_accept_case "linux remote-copy directory http --allow-dev" "$BIN" --output-http http://127.0.0.1:1 linux remote-copy "$TMP_DIR" --allow-dev
run_accept_case "linux remote-copy directory http --allow-sysfs" "$BIN" --output-http http://127.0.0.1:1 linux remote-copy "$TMP_DIR" --allow-sysfs
run_accept_case "linux remote-copy directory http --allow-proc" "$BIN" --output-http http://127.0.0.1:1 linux remote-copy "$TMP_DIR" --allow-proc

run_accept_case "linux remote-copy --output-tcp" "$BIN" --output-tcp 127.0.0.1:9 linux remote-copy "$TMP_FILE"
run_accept_case "linux remote-copy --output-http" "$BIN" --output-http http://127.0.0.1:1 linux remote-copy "$TMP_FILE"
run_accept_case "linux remote-copy --output-http" "$BIN" --output-http https://127.0.0.1:1 linux remote-copy "$TMP_FILE"
run_accept_case "global --insecure linux remote-copy --output-http" "$BIN" --insecure --output-http https://127.0.0.1:1 linux remote-copy "$TMP_FILE"
run_accept_case "linux remote-copy --quiet" "$BIN" --quiet --output-http http://127.0.0.1:1 linux remote-copy "$TMP_FILE"
run_accept_case "linux remote-copy directory http" "$BIN" --output-http http://127.0.0.1:1 linux remote-copy "$TMP_DIR"
run_accept_case "linux remote-copy directory http --recursive" "$BIN" --output-http http://127.0.0.1:1 linux remote-copy "$TMP_DIR" --recursive
run_accept_case "linux remote-copy directory https --recursive" "$BIN" --output-http https://127.0.0.1:1 linux remote-copy "$TMP_DIR" --recursive
run_accept_case "linux remote-copy symlink http --allow-symlinks" "$BIN" --output-http http://127.0.0.1:1 linux remote-copy "$TMP_DIR/sample.link" --allow-symlinks

if [ -n "$DEV_REMOTE_COPY_DIR" ]; then
    run_accept_case "linux remote-copy restricted /dev directory http --allow-dev" \
        "$BIN" --output-http http://127.0.0.1:1 linux remote-copy "$DEV_REMOTE_COPY_DIR" --allow-dev
fi

if [ -n "$SYS_REMOTE_COPY_DIR" ]; then
    run_exact_case "linux remote-copy /sys without allow flag" 2 \
        "$BIN" --output-http http://127.0.0.1:1 linux remote-copy /sys
    run_accept_case "linux remote-copy restricted /sys directory http --allow-sysfs" \
        "$BIN" --output-http http://127.0.0.1:1 linux remote-copy "$SYS_REMOTE_COPY_DIR" --allow-sysfs
fi

if [ -r /proc/cmdline ]; then
    run_accept_case "linux remote-copy /proc/cmdline over http (non-sized stream-like file)" \
        "$BIN" --output-http http://127.0.0.1:1 linux remote-copy /proc/cmdline --allow-proc
fi

if [ -n "$PROC_REMOTE_COPY_DIR" ]; then
    run_accept_case "linux remote-copy restricted /proc directory http --allow-proc" \
        "$BIN" --output-http http://127.0.0.1:1 linux remote-copy "$PROC_REMOTE_COPY_DIR" --allow-proc
    run_accept_case "linux remote-copy restricted /proc directory http --recursive --allow-proc" \
        "$BIN" --output-http http://127.0.0.1:1 linux remote-copy "$PROC_REMOTE_COPY_DIR" --recursive --allow-proc
fi

run_accept_case "linux remote-copy with --output-format txt" "$BIN" --output-format txt --output-http http://127.0.0.1:1 linux remote-copy "$TMP_FILE"
run_accept_case "linux remote-copy with --output-format csv" "$BIN" --output-format csv --output-http http://127.0.0.1:1 linux remote-copy "$TMP_FILE"
run_accept_case "linux remote-copy with --output-format json" "$BIN" --output-format json --output-http http://127.0.0.1:1 linux remote-copy "$TMP_FILE"

python_bin="$(find_python_bin || true)"

if [ -n "$python_bin" ]; then
remote_http_req_path="$(mktemp /tmp/test_remote_copy_http_path.XXXXXX)"
remote_http_req_type="$(mktemp /tmp/test_remote_copy_http_type.XXXXXX)"
remote_http_req_body="$(mktemp /tmp/test_remote_copy_http_body.XXXXXX)"
remote_http_server_log="$(mktemp /tmp/test_remote_copy_http_server.XXXXXX)"

REQUEST_PATH_FILE="$remote_http_req_path" REQUEST_TYPE_FILE="$remote_http_req_type" REQUEST_BODY_FILE="$remote_http_req_body" \
    "$python_bin" - <<'PY' >"$remote_http_server_log" 2>&1 &
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
remote_http_server_pid=$!

remote_http_ready=0
remote_http_port=""
i=0
while [ "$i" -lt 50 ]; do
    remote_http_port="$(sed -n 's/^ready://p' "$remote_http_server_log" 2>/dev/null | head -n 1)"
    if [ -n "$remote_http_port" ]; then
        remote_http_ready=1
        break
    fi
    if ! kill -0 "$remote_http_server_pid" 2>/dev/null; then
        break
    fi
    sleep 0.1
    i="$(expr "$i" + 1)"
done

remote_http_post_log="$(mktemp /tmp/test_remote_copy_http_post.XXXXXX)"
if [ "$remote_http_ready" -eq 1 ]; then
    "$BIN" --output-http "http://127.0.0.1:$remote_http_port" linux remote-copy "$TMP_FILE" >"$remote_http_post_log" 2>&1
    rc=$?
    wait "$remote_http_server_pid" 2>/dev/null || true

    if [ "$rc" -eq 0 ] && \
       grep -F "/upload/file?filePath=%2F" "$remote_http_req_path" >/dev/null 2>&1 && \
       grep -F "application/octet-stream" "$remote_http_req_type" >/dev/null 2>&1 && \
       cmp -s "$TMP_FILE" "$remote_http_req_body"; then
        echo "[PASS] linux remote-copy --output-http performs HTTP POST upload via /upload/file"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] linux remote-copy --output-http performs HTTP POST upload via /upload/file (rc=$rc)"
        print_file_head_scrubbed "$remote_http_post_log" 120
        echo "--- request path ---"
        print_file_head_scrubbed "$remote_http_req_path" 20
        echo "--- request content-type ---"
        print_file_head_scrubbed "$remote_http_req_type" 20
        echo "--- request body (hex) ---"
        od -An -tx1 "$remote_http_req_body" 2>/dev/null || true
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi
else
    echo "[FAIL] linux remote-copy --output-http performs HTTP POST upload via /upload/file (server did not start)"
    print_file_head_scrubbed "$remote_http_server_log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    kill "$remote_http_server_pid" 2>/dev/null || true
    wait "$remote_http_server_pid" 2>/dev/null || true
fi

rm -f "$remote_http_req_path" "$remote_http_req_type" "$remote_http_req_body" "$remote_http_server_log" "$remote_http_post_log"
fi

warn_log="$(mktemp /tmp/test_remote_copy_warn.XXXXXX)"
run_with_output_override "$BIN" --output-format json linux remote-copy "$TMP_FILE" --help >"$warn_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q "Warning: --output-format has no effect for remote-copy" "$warn_log"; then
    echo "[PASS] linux remote-copy warns when --output-format is set"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux remote-copy warns when --output-format is set (rc=$rc)"
    print_file_head_scrubbed "$warn_log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$warn_log"

verbose_server_log="$(mktemp /tmp/test_remote_copy_verbose_server.XXXXXX)"
verbose_log="$(mktemp /tmp/test_remote_copy_verbose.XXXXXX)"
verbose_port_file="$(mktemp /tmp/test_remote_copy_verbose_port.XXXXXX)"

if [ -n "$python_bin" ]; then
"$python_bin" -c '
import http.server
import socketserver
import sys

port_file = sys.argv[1]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, format, *args):
        pass

with socketserver.TCPServer(("127.0.0.1", 0), Handler) as httpd:
    with open(port_file, "w", encoding="utf-8") as f:
        f.write(str(httpd.server_address[1]))
    httpd.handle_request()
' "$verbose_port_file" >"$verbose_server_log" 2>&1 &
verbose_server_pid=$!

verbose_port=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if [ -s "$verbose_port_file" ]; then
        verbose_port="$(cat "$verbose_port_file")"
        break
    fi
    sleep 1
done

if [ -n "$verbose_port" ]; then
    "$BIN" --output-http "http://127.0.0.1:$verbose_port/upload" linux remote-copy "$TMP_FILE" >"$verbose_log" 2>&1
    rc=$?
    if [ "$rc" -eq 0 ] && grep -q "remote-copy copied path $TMP_FILE (1 file copied)" "$verbose_log"; then
        echo "[PASS] linux remote-copy verbose output includes path and copied file count"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] linux remote-copy verbose output includes path and copied file count (rc=$rc)"
        print_file_head_scrubbed "$verbose_log" 120
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi
else
    echo "[FAIL] linux remote-copy verbose output test could not start local HTTP server"
    print_file_head_scrubbed "$verbose_server_log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi

wait "$verbose_server_pid" 2>/dev/null || true
else
    echo "[SKIP] linux remote-copy verbose output test requires python3 or python"
fi

rm -f "$verbose_server_log" "$verbose_log" "$verbose_port_file"

rm -rf "$TMP_DIR"
finish_tests
