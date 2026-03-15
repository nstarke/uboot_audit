#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$SCRIPT_DIR"
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
print_section "--api-key argument and 401 warning coverage"

# ---------------------------------------------------------------------------
# Static /tmp/ela.key source test (no HTTP server required)
# ---------------------------------------------------------------------------

# Preserve any pre-existing /tmp/ela.key so we don't disturb the environment
ELA_KEY_FILE=/tmp/ela.key
ELA_KEY_BACKUP=""
if [ -f "$ELA_KEY_FILE" ]; then
    ELA_KEY_BACKUP="$(mktemp /tmp/ela-key-backup.XXXXXX)"
    cp "$ELA_KEY_FILE" "$ELA_KEY_BACKUP"
fi

printf 'staticfiletoken\n' > "$ELA_KEY_FILE"
run_accept_case "/tmp/ela.key file source accepted" "$BIN" linux dmesg --help
rm -f "$ELA_KEY_FILE"

if [ -n "$ELA_KEY_BACKUP" ]; then
    mv "$ELA_KEY_BACKUP" "$ELA_KEY_FILE"
fi

# ---------------------------------------------------------------------------
# Behavioral tests: mock HTTP server via Python3
#
# Uses Python's built-in http.server — no third-party packages required.
# The server is started in the background, the agent makes one HTTP POST,
# then the server is killed.  Ports chosen to avoid conflicts with other
# tests (19873-19876 are used elsewhere).
# ---------------------------------------------------------------------------

PYTHON_BIN="$(find_python_bin)"

if [ -z "$PYTHON_BIN" ]; then
    echo "[SKIP] behavioral --api-key tests (python3 not available)"
    finish_tests
    exit 0
fi

# Helper: start an HTTP server that always returns STATUS_CODE.
# Usage: start_always_server <port> <status_code>
# Prints the PID to stdout.
start_always_server() {
    _port="$1"
    _code="$2"
    "$PYTHON_BIN" - "$_port" "$_code" <<'EOF_PY' >/dev/null 2>&1 &
import http.server, socketserver, sys

code = int(sys.argv[2])

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0') or '0'))
        self.send_response(code)
        self.end_headers()
    def log_message(self, *args): pass

class S(socketserver.TCPServer):
    allow_reuse_address = True

with S(('127.0.0.1', int(sys.argv[1])), H) as s:
    s.serve_forever()
EOF_PY
    echo $!
}

# Helper: start an HTTP server that returns 200 only when the Authorization
# header exactly matches "Bearer <token>", and 401 otherwise.
# Usage: start_auth_server <port> <expected_token>
# Prints the PID to stdout.
start_auth_server() {
    _port="$1"
    _token="$2"
    "$PYTHON_BIN" - "$_port" "$_token" <<'EOF_PY' >/dev/null 2>&1 &
import http.server, socketserver, sys

expected = 'Bearer ' + sys.argv[2]

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0') or '0'))
        auth = self.headers.get('Authorization', '')
        self.send_response(200 if auth == expected else 401)
        self.end_headers()
    def log_message(self, *args): pass

class S(socketserver.TCPServer):
    allow_reuse_address = True

with S(('127.0.0.1', int(sys.argv[1])), H) as s:
    s.serve_forever()
EOF_PY
    echo $!
}

stop_server() {
    _pid="$1"
    kill "$_pid" 2>/dev/null
    wait "$_pid" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Test: no API key set + server returns 401 → warning on stderr
# ---------------------------------------------------------------------------
api_port=19877
SRV_PID="$(start_always_server "$api_port" 401)"
sleep 0.3

api_log="$(mktemp /tmp/test_api_key_no_key.XXXXXX)"
ELA_API_KEY= "$BIN" \
    --output-http "http://127.0.0.1:$api_port/upload" \
    linux execute-command "echo hello" \
    >"$api_log" 2>&1

stop_server "$SRV_PID"

if grep -q "401 Unauthorized" "$api_log"; then
    echo "[PASS] no api-key + 401 server prints 401 Unauthorized warning"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] no api-key + 401 server prints 401 Unauthorized warning"
    print_file_head_scrubbed "$api_log" 40
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$api_log"
sleep 0.2

# ---------------------------------------------------------------------------
# Test: wrong --api-key + server returns 401 → warning on stderr
# ---------------------------------------------------------------------------
SRV_PID="$(start_always_server "$api_port" 401)"
sleep 0.3

api_log="$(mktemp /tmp/test_api_key_wrong_key.XXXXXX)"
"$BIN" \
    --api-key wrongtoken \
    --output-http "http://127.0.0.1:$api_port/upload" \
    linux execute-command "echo hello" \
    >"$api_log" 2>&1

stop_server "$SRV_PID"

if grep -q "401 Unauthorized" "$api_log"; then
    echo "[PASS] wrong --api-key + 401 server prints 401 Unauthorized warning"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] wrong --api-key + 401 server prints 401 Unauthorized warning"
    print_file_head_scrubbed "$api_log" 40
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$api_log"
sleep 0.2

# ---------------------------------------------------------------------------
# Test: correct --api-key + auth-checking server → no warning
# ---------------------------------------------------------------------------
auth_port=19878
TEST_TOKEN="ela-test-secret-token-$$"
SRV_PID="$(start_auth_server "$auth_port" "$TEST_TOKEN")"
sleep 0.3

api_log="$(mktemp /tmp/test_api_key_correct_key.XXXXXX)"
"$BIN" \
    --api-key "$TEST_TOKEN" \
    --output-http "http://127.0.0.1:$auth_port/upload" \
    linux execute-command "echo hello" \
    >"$api_log" 2>&1

stop_server "$SRV_PID"

if ! grep -q "401 Unauthorized" "$api_log"; then
    echo "[PASS] correct --api-key + auth server produces no 401 warning"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] correct --api-key + auth server produces no 401 warning"
    print_file_head_scrubbed "$api_log" 40
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$api_log"
sleep 0.2

# ---------------------------------------------------------------------------
# Test: correct ELA_API_KEY env var + auth-checking server → no warning
# ---------------------------------------------------------------------------
SRV_PID="$(start_auth_server "$auth_port" "$TEST_TOKEN")"
sleep 0.3

api_log="$(mktemp /tmp/test_api_key_env_var.XXXXXX)"
ELA_API_KEY="$TEST_TOKEN" "$BIN" \
    --output-http "http://127.0.0.1:$auth_port/upload" \
    linux execute-command "echo hello" \
    >"$api_log" 2>&1

stop_server "$SRV_PID"

if ! grep -q "401 Unauthorized" "$api_log"; then
    echo "[PASS] ELA_API_KEY env var passes correct token to auth server"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] ELA_API_KEY env var passes correct token to auth server"
    print_file_head_scrubbed "$api_log" 40
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$api_log"
sleep 0.2

# ---------------------------------------------------------------------------
# Test: correct /tmp/ela.key + auth-checking server → no warning
# ---------------------------------------------------------------------------

# Preserve any pre-existing /tmp/ela.key
ELA_KEY_BACKUP2=""
if [ -f "$ELA_KEY_FILE" ]; then
    ELA_KEY_BACKUP2="$(mktemp /tmp/ela-key-backup2.XXXXXX)"
    cp "$ELA_KEY_FILE" "$ELA_KEY_BACKUP2"
fi

printf '%s\n' "$TEST_TOKEN" > "$ELA_KEY_FILE"
SRV_PID="$(start_auth_server "$auth_port" "$TEST_TOKEN")"
sleep 0.3

api_log="$(mktemp /tmp/test_api_key_file.XXXXXX)"
ELA_API_KEY= "$BIN" \
    --output-http "http://127.0.0.1:$auth_port/upload" \
    linux execute-command "echo hello" \
    >"$api_log" 2>&1

stop_server "$SRV_PID"

rm -f "$ELA_KEY_FILE"
if [ -n "$ELA_KEY_BACKUP2" ]; then
    mv "$ELA_KEY_BACKUP2" "$ELA_KEY_FILE"
fi

if ! grep -q "401 Unauthorized" "$api_log"; then
    echo "[PASS] /tmp/ela.key passes correct token to auth server"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] /tmp/ela.key passes correct token to auth server"
    print_file_head_scrubbed "$api_log" 40
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$api_log"
sleep 0.2

# ---------------------------------------------------------------------------
# Test: multi-source fallback — wrong ELA_API_KEY, correct /tmp/ela.key
# The server returns 401 for the wrong key, then 200 for the correct key.
# ---------------------------------------------------------------------------

# Preserve any pre-existing /tmp/ela.key
ELA_KEY_BACKUP3=""
if [ -f "$ELA_KEY_FILE" ]; then
    ELA_KEY_BACKUP3="$(mktemp /tmp/ela-key-backup3.XXXXXX)"
    cp "$ELA_KEY_FILE" "$ELA_KEY_BACKUP3"
fi

printf '%s\n' "$TEST_TOKEN" > "$ELA_KEY_FILE"
SRV_PID="$(start_auth_server "$auth_port" "$TEST_TOKEN")"
sleep 0.3

api_log="$(mktemp /tmp/test_api_key_fallback.XXXXXX)"
ELA_API_KEY="wrongtoken" "$BIN" \
    --output-http "http://127.0.0.1:$auth_port/upload" \
    linux execute-command "echo hello" \
    >"$api_log" 2>&1

stop_server "$SRV_PID"

rm -f "$ELA_KEY_FILE"
if [ -n "$ELA_KEY_BACKUP3" ]; then
    mv "$ELA_KEY_BACKUP3" "$ELA_KEY_FILE"
fi

if ! grep -q "401 Unauthorized" "$api_log"; then
    echo "[PASS] multi-source fallback: wrong ELA_API_KEY, correct /tmp/ela.key succeeds"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] multi-source fallback: wrong ELA_API_KEY, correct /tmp/ela.key succeeds"
    print_file_head_scrubbed "$api_log" 40
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$api_log"

finish_tests
