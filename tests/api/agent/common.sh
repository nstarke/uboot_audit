#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# shellcheck source=tests/system_package_helpers.sh
. "$REPO_ROOT/tests/system_package_helpers.sh"

PASS_COUNT=0
FAIL_COUNT=0

TEST_WEB_SERVER_PID=""
TEST_WEB_SERVER_LOG=""
TEST_WEB_BASE_URL=""
TEST_WEB_TMPDIR=""

has_curl() {
    command -v curl >/dev/null 2>&1
}

has_node() {
    command -v node >/dev/null 2>&1
}

print_section() {
    printf '\n==== %s ====\n' "$1"
}

pass_case() {
    PASS_COUNT=$(expr "$PASS_COUNT" + 1)
    printf '[PASS] %s\n' "$1"
}

scrub_sensitive_stream() {
    while IFS= read -r line || [ -n "$line" ]; do
        lower_line="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"
        case "$lower_line" in
            *efi-var*|*efi_vars*|*efivars*)
                printf '[REDACTED EFI VARS]\n'
                continue
                ;;
        esac

        printf '%s\n' "$line" | sed -E \
            -e 's/(([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll][Ss]?|[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn])[[:space:]]*[:=][[:space:]]*)[^[:space:],;"}]+/\1<REDACTED>/g' \
            -e 's/(([?&]([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll][Ss]?|[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn]))=)[^&[:space:]]+/\1<REDACTED>/g' \
            -e 's/(("([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll][Ss]?|[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn])"[[:space:]]*:[[:space:]]*")[^"]+/
\1<REDACTED>/g'
    done
}

print_file_head_scrubbed() {
    path="$1"
    lines="${2:-80}"

    if [ -f "$path" ]; then
        sed -n "1,${lines}p" "$path" 2>/dev/null | scrub_sensitive_stream
    fi
}

report_curl_case_failure() {
    expected_status="$1"
    actual_status="$2"
    expected_body="$3"
    actual_body="$4"
    headers_file="$5"

    printf 'expected status: %s\nactual status: %s\nexpected body: %s\nactual body: %s\n' \
        "$expected_status" "$actual_status" "$expected_body" "$actual_body" | scrub_sensitive_stream
    printf '\nheaders:\n'
    print_file_head_scrubbed "$headers_file" 40
}

report_curl_body_contains_failure() {
    expected_status="$1"
    actual_status="$2"
    expected_substring="$3"
    body_file="$4"
    headers_file="$5"

    printf 'expected status: %s\nactual status: %s\nexpected body to contain: %s\n\nbody:\n' \
        "$expected_status" "$actual_status" "$expected_substring" | scrub_sensitive_stream
    print_file_head_scrubbed "$body_file" 120
    printf '\nheaders:\n'
    print_file_head_scrubbed "$headers_file" 40
}

report_assert_file_contains_failure() {
    needle="$1"
    path="$2"

    printf 'expected file to contain: %s\npath: %s\n' "$needle" "$path" | scrub_sensitive_stream
    print_file_head_scrubbed "$path" 120
}

fail_case() {
    FAIL_COUNT=$(expr "$FAIL_COUNT" + 1)
    printf '[FAIL] %s\n' "$1"
    shift
    if [ "$#" -gt 0 ]; then
        "$@"
    fi
}

require_web_test_tools() {
    if ! ela_ensure_command curl; then
        echo "error: curl is required"
        exit 1
    fi
    if ! ela_ensure_command node; then
        echo "error: node is required"
        exit 1
    fi
}

create_web_test_layout() {
    TEST_WEB_TMPDIR="$(mktemp -d /tmp/fw_web_tests.XXXXXX)"
    mkdir -p "$TEST_WEB_TMPDIR/assets" "$TEST_WEB_TMPDIR/data/env" "$TEST_WEB_TMPDIR/tests/agent/shell" "$TEST_WEB_TMPDIR/tests/agent/scripts" "$TEST_WEB_TMPDIR/tests/api" "$TEST_WEB_TMPDIR/tests/scripts"

    printf 'asset-one\n' > "$TEST_WEB_TMPDIR/assets/embedded_linux_audit-arm64"
    printf 'asset-two\n' > "$TEST_WEB_TMPDIR/assets/custom-tool.bin"
    printf '{"release":"v1"}\n' > "$TEST_WEB_TMPDIR/assets/.release_state.json"
    mkdir -p "$TEST_WEB_TMPDIR/assets/not_a_file"

    printf '#!/bin/sh\necho test-one\n' > "$TEST_WEB_TMPDIR/tests/agent/shell/test_one.sh"
    printf 'linux dmesg\n' > "$TEST_WEB_TMPDIR/tests/agent/scripts/test_linux_dmesg_args.ela"
    printf 'linux execute-command "echo scripted"\nlinux execute-command "printf second"\n' > "$TEST_WEB_TMPDIR/tests/scripts/sample-script.txt"
    printf '#!/bin/sh\necho test-two\n' > "$TEST_WEB_TMPDIR/tests/api/test_two.sh"
    mkdir -p "$TEST_WEB_TMPDIR/tests/scripts/not_a_file"
    chmod +x "$TEST_WEB_TMPDIR/tests/agent/shell/test_one.sh" "$TEST_WEB_TMPDIR/tests/api/test_two.sh"
    mkdir -p "$TEST_WEB_TMPDIR/tests/not_a_file" "$TEST_WEB_TMPDIR/tests/agent/shell/not_a_file" "$TEST_WEB_TMPDIR/tests/agent/scripts/not_a_file"

    printf 'bootdelay=3\n' > "$TEST_WEB_TMPDIR/data/env/fw_env.txt"
    mkdir -p "$TEST_WEB_TMPDIR/data/env/not_a_file"
}

start_web_test_server() {
    REPO_ROOT="$1"
    PORT="$2"
    TEST_WEB_SERVER_LOG="$TEST_WEB_TMPDIR/server.log"

    TEST_WEB_PORT="$PORT" TEST_WEB_TMPDIR="$TEST_WEB_TMPDIR" REPO_ROOT="$REPO_ROOT" \
        node - <<'NODE' >"$TEST_WEB_SERVER_LOG" 2>&1 &
const http = require('http');
const path = require('path');

const repoRoot = process.env.REPO_ROOT;
const tmpDir = process.env.TEST_WEB_TMPDIR;
const port = Number(process.env.TEST_WEB_PORT);
const { createApp } = require(path.join(repoRoot, 'api', 'agent', 'server.js'));

const app = createApp({
  logPrefix: path.join(tmpDir, 'post_requests'),
  assetsDir: path.join(tmpDir, 'assets'),
  dataDir: path.join(tmpDir, 'data'),
  testsDir: path.join(tmpDir, 'tests'),
  verbose: false
});

const server = http.createServer(app);
server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`ready:${port}\n`);
});

function shutdown() {
  server.close(() => process.exit(0));
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
NODE
    TEST_WEB_SERVER_PID=$!
    TEST_WEB_BASE_URL="http://127.0.0.1:$PORT"

    i=0
    while [ "$i" -lt 50 ]; do
        if grep -q "^ready:$PORT$" "$TEST_WEB_SERVER_LOG" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$TEST_WEB_SERVER_PID" 2>/dev/null; then
            echo "error: test server exited unexpectedly"
            print_file_head_scrubbed "$TEST_WEB_SERVER_LOG" 120
            exit 1
        fi
        sleep 0.1
        i=$(expr "$i" + 1)
    done

    echo "error: timed out waiting for test server"
    print_file_head_scrubbed "$TEST_WEB_SERVER_LOG" 120
    exit 1
}

stop_web_test_server() {
    if [ -n "$TEST_WEB_SERVER_PID" ]; then
        kill "$TEST_WEB_SERVER_PID" 2>/dev/null || true
        wait "$TEST_WEB_SERVER_PID" 2>/dev/null || true
        TEST_WEB_SERVER_PID=""
    fi
}

cleanup_web_test() {
    stop_web_test_server
    if [ -n "$TEST_WEB_TMPDIR" ] && [ -d "$TEST_WEB_TMPDIR" ]; then
        rm -rf "$TEST_WEB_TMPDIR"
    fi
}

setup_web_test_env() {
    REPO_ROOT="$1"
    PORT="$2"
    require_web_test_tools
    create_web_test_layout
    trap cleanup_web_test EXIT INT TERM
    start_web_test_server "$REPO_ROOT" "$PORT"
}

run_curl_case() {
    name="$1"
    method="$2"
    url="$3"
    expected_status="$4"
    expected_body="$5"
    shift 5

    body_file="$(mktemp /tmp/fw_web_body.XXXXXX)"
    headers_file="$(mktemp /tmp/fw_web_headers.XXXXXX)"

    status="$(curl -sS -D "$headers_file" -o "$body_file" -X "$method" "$url" "$@" -w '%{http_code}')"
    rc=$?
    body="$(cat "$body_file")"

    if [ "$rc" -eq 0 ] && [ "$status" = "$expected_status" ] && [ "$body" = "$expected_body" ]; then
        pass_case "$name"
    else
        fail_case "$name" report_curl_case_failure "$expected_status" "$status" "$expected_body" "$body" "$headers_file"
    fi

    rm -f "$body_file" "$headers_file"
}

run_curl_body_contains_case() {
    name="$1"
    method="$2"
    url="$3"
    expected_status="$4"
    expected_substring="$5"
    shift 5

    body_file="$(mktemp /tmp/fw_web_body.XXXXXX)"
    headers_file="$(mktemp /tmp/fw_web_headers.XXXXXX)"

    status="$(curl -sS -D "$headers_file" -o "$body_file" -X "$method" "$url" "$@" -w '%{http_code}')"
    rc=$?

    if [ "$rc" -eq 0 ] && [ "$status" = "$expected_status" ] && grep -F "$expected_substring" "$body_file" >/dev/null 2>&1; then
        pass_case "$name"
    else
        fail_case "$name" report_curl_body_contains_failure "$expected_status" "$status" "$expected_substring" "$body_file" "$headers_file"
    fi

    rm -f "$body_file" "$headers_file"
}

assert_file_contains() {
    name="$1"
    path="$2"
    needle="$3"
    if [ -f "$path" ] && grep -F "$needle" "$path" >/dev/null 2>&1; then
        pass_case "$name"
    else
        fail_case "$name" report_assert_file_contains_failure "$needle" "$path"
    fi
}

assert_symlink_target() {
    name="$1"
    path="$2"
    expected="$3"
    if [ -L "$path" ] && [ "$(readlink "$path")" = "$expected" ]; then
        pass_case "$name"
    else
        fail_case "$name" sh -c "printf 'expected symlink: %s -> %s\n' \"$path\" \"$expected\"; if [ -e \"$path\" ] || [ -L \"$path\" ]; then ls -ld \"$path\"; readlink \"$path\" 2>/dev/null || true; fi"
    fi
}

finish_web_tests() {
    echo
    echo "Passed: $PASS_COUNT"
    echo "Failed: $FAIL_COUNT"
    [ "$FAIL_COUNT" -eq 0 ]
}