#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

# shellcheck source=tests/api/agent/common.sh
. "$SCRIPT_DIR/../common.sh"

setup_web_test_env "$REPO_ROOT" 5310

print_section "api GET route coverage"

SCRIPT_BODY='#!/bin/sh
echo test-one'

run_curl_body_contains_case "GET / includes release binaries" GET "$TEST_WEB_BASE_URL/" 200 "ela-arm64"
run_curl_body_contains_case "GET / includes custom assets" GET "$TEST_WEB_BASE_URL/" 200 "custom-tool.bin"
run_curl_body_contains_case "GET / includes agent shell test scripts" GET "$TEST_WEB_BASE_URL/" 200 "tests/agent/shell/test_one.sh"
run_curl_body_contains_case "GET / includes agent argument scripts" GET "$TEST_WEB_BASE_URL/" 200 "tests/agent/scripts/test_linux_dmesg_args.ela"
run_curl_body_contains_case "GET / includes command scripts" GET "$TEST_WEB_BASE_URL/" 200 "scripts/sample-script.txt"
run_curl_case "GET /tests/agent/shell/test_one.sh" GET "$TEST_WEB_BASE_URL/tests/agent/shell/test_one.sh" 200 "$SCRIPT_BODY"
run_curl_body_contains_case "GET /tests/agent/scripts/test_linux_dmesg_args.ela" GET "$TEST_WEB_BASE_URL/tests/agent/scripts/test_linux_dmesg_args.ela" 200 "linux dmesg"
run_curl_case "GET /tests/agent/invalid/test_one.sh rejects invalid type" GET "$TEST_WEB_BASE_URL/tests/agent/invalid/test_one.sh" 400 "invalid type"
run_curl_case "GET /tests/agent/shell/test_one rejects missing .sh suffix" GET "$TEST_WEB_BASE_URL/tests/agent/shell/test_one" 400 "invalid path"
run_curl_case "GET /tests/agent/scripts/test_linux_dmesg_args.sh rejects wrong suffix" GET "$TEST_WEB_BASE_URL/tests/agent/scripts/test_linux_dmesg_args.sh" 400 "invalid path"
run_curl_case "GET /tests/agent/scripts/..%2F..%2Fescape blocks traversal" GET "$TEST_WEB_BASE_URL/tests/agent/scripts/..%2F..%2Fescape" 400 "invalid path"

run_curl_case "GET /ela-arm64 serves asset" GET "$TEST_WEB_BASE_URL/ela-arm64" 200 "asset-one"
run_curl_case "GET /custom-tool.bin serves custom asset" GET "$TEST_WEB_BASE_URL/custom-tool.bin" 200 "asset-two"
run_curl_case "GET /assets/not_a_file returns 404" GET "$TEST_WEB_BASE_URL/not_a_file" 404 "not found"

run_curl_case "GET /scripts/sample-script.txt serves script" GET "$TEST_WEB_BASE_URL/scripts/sample-script.txt" 200 "linux execute-command \"echo scripted\"
linux execute-command \"printf second\""
run_curl_case "GET /scripts/..%2Fescape rejects invalid segment" GET "$TEST_WEB_BASE_URL/scripts/..%2Fescape" 400 "invalid path"
run_curl_case "GET /scripts/missing returns 404" GET "$TEST_WEB_BASE_URL/scripts/missing.txt" 404 "not found"
run_curl_case "GET /scripts/not_a_file returns 404" GET "$TEST_WEB_BASE_URL/scripts/not_a_file" 404 "not found"
run_curl_case "GET /not_a_file returns 404" GET "$TEST_WEB_BASE_URL/not_a_file" 404 "not found"

REPO_ROOT="$REPO_ROOT" node - <<'NODE' >/tmp/fw_route_fallback.log 2>&1 &
const http = require('http');
const path = require('path');
const { createApp } = require(path.join(process.env.REPO_ROOT, 'api', 'agent', 'server.js'));
const app = createApp({
  logPrefix: path.join('/tmp', 'fw_route_fallback_post_requests'),
  assetsDir: path.join('/tmp', 'fw_route_fallback_assets'),
  dataDir: path.join('/tmp', 'fw_route_fallback_data'),
  testsDir: path.join('/tmp', 'fw_route_fallback_missing_tests'),
  verbose: false
});
const server = http.createServer(app);
server.listen(5312, '127.0.0.1', () => {
  process.stdout.write('ready\n');
});
NODE
fallback_pid=$!
trap 'kill "$fallback_pid" 2>/dev/null || true; wait "$fallback_pid" 2>/dev/null || true; rm -f /tmp/fw_route_fallback.log' EXIT INT TERM
i=0
while [ "$i" -lt 50 ]; do
    if grep -q '^ready$' /tmp/fw_route_fallback.log 2>/dev/null; then
        break
    fi
    sleep 0.1
    i=$(expr "$i" + 1)
done

run_curl_body_contains_case "GET /tests/agent/shell/download_tests.sh falls back to repo tests dir" GET "http://127.0.0.1:5312/tests/agent/shell/download_tests.sh" 200 "usage: \$0 --webserver <url>"
run_curl_body_contains_case "GET /tests/agent/scripts/test_linux_dmesg_args.ela falls back to repo tests dir" GET "http://127.0.0.1:5312/tests/agent/scripts/test_linux_dmesg_args.ela" 200 "linux dmesg"

finish_web_tests