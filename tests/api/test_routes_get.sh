#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=tests/api/common.sh
. "$SCRIPT_DIR/common.sh"

setup_web_test_env "$REPO_ROOT" 5310

print_section "api GET route coverage"

SCRIPT_BODY="$(printf '#!/bin/sh\necho test-one')"

run_curl_body_contains_case "GET / includes release binaries" GET "$TEST_WEB_BASE_URL/" 200 "embedded_linux_audit-arm64"
run_curl_body_contains_case "GET / includes agent test scripts" GET "$TEST_WEB_BASE_URL/" 200 "tests/agent/test_one.sh"
run_curl_body_contains_case "GET / includes command scripts" GET "$TEST_WEB_BASE_URL/" 200 "scripts/sample-script.txt"
run_curl_case "GET /tests/agent/test_one.sh" GET "$TEST_WEB_BASE_URL/tests/agent/test_one.sh" 200 "$SCRIPT_BODY"
run_curl_case "GET /tests/agent/..%2Fescape rejects invalid segment" GET "$TEST_WEB_BASE_URL/tests/agent/..%2Fescape" 400 "invalid path"
run_curl_case "GET /tests/api/test_two.sh returns 404" GET "$TEST_WEB_BASE_URL/tests/api/test_two.sh" 404 "not found"
run_curl_case "GET /tests/agent/missing.sh returns 404" GET "$TEST_WEB_BASE_URL/tests/agent/missing.sh" 404 "not found"
run_curl_case "GET /tests/agent/not_a_file returns 400" GET "$TEST_WEB_BASE_URL/tests/agent/not_a_file" 400 "invalid path"
run_curl_case "GET /tests/agent/test_one rejects missing .sh suffix" GET "$TEST_WEB_BASE_URL/tests/agent/test_one" 400 "invalid path"

run_curl_case "GET /uboot-env/fw_env.txt" GET "$TEST_WEB_BASE_URL/uboot-env/fw_env.txt" 200 "bootdelay=3"
run_curl_case "GET /uboot-env/..%2F..%2Fescape blocked" GET "$TEST_WEB_BASE_URL/uboot-env/..%2F..%2Fescape" 404 "not found"
run_curl_case "GET /uboot-env/missing returns 404" GET "$TEST_WEB_BASE_URL/uboot-env/missing.txt" 404 "not found"
run_curl_case "GET /uboot-env/not_a_file returns 404" GET "$TEST_WEB_BASE_URL/uboot-env/not_a_file" 404 "not found"

run_curl_case "GET /isa/arm64 serves matching asset" GET "$TEST_WEB_BASE_URL/isa/arm64" 200 "asset-one"
run_curl_case "GET /isa/..%2Fescape rejects invalid segment" GET "$TEST_WEB_BASE_URL/isa/..%2Fescape" 400 "invalid path"
run_curl_case "GET /isa/missing returns 404" GET "$TEST_WEB_BASE_URL/isa/missing" 404 "not found"

run_curl_case "GET /embedded_linux_audit-arm64 serves asset" GET "$TEST_WEB_BASE_URL/embedded_linux_audit-arm64" 200 "asset-one"
run_curl_case "GET /scripts/sample-script.txt serves script" GET "$TEST_WEB_BASE_URL/scripts/sample-script.txt" 200 "linux execute-command \"echo scripted\"
linux execute-command \"printf second\""
run_curl_case "GET /scripts/..%2Fescape rejects invalid segment" GET "$TEST_WEB_BASE_URL/scripts/..%2Fescape" 400 "invalid path"
run_curl_case "GET /scripts/missing returns 404" GET "$TEST_WEB_BASE_URL/scripts/missing.txt" 404 "not found"
run_curl_case "GET /scripts/not_a_file returns 404" GET "$TEST_WEB_BASE_URL/scripts/not_a_file" 404 "not found"
run_curl_case "GET /not_a_file returns 404" GET "$TEST_WEB_BASE_URL/not_a_file" 404 "not found"
run_curl_case "GET /missing-asset returns 404" GET "$TEST_WEB_BASE_URL/missing-asset" 404 "not found"

finish_web_tests