#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

# shellcheck source=tests/api/agent/common.sh
. "$SCRIPT_DIR/../common.sh"

setup_web_test_env "$REPO_ROOT" 5311

print_section "api upload route coverage"

MAC="aa:bb:cc:dd:ee:ff"
MAC_DIR="$TEST_WEB_TMPDIR/data/$MAC"

run_curl_case "POST upload rejects invalid mac" POST "$TEST_WEB_BASE_URL/not-a-mac/upload/log" 400 "invalid mac address" -H "Content-Type: text/plain" --data-binary "hello"
run_curl_case "POST upload rejects symlink on non-file type" POST "$TEST_WEB_BASE_URL/$MAC/upload/log?symlink=true&symlinkPath=/tmp/t" 400 "symlink arguments only allowed for /upload/file" -H "Content-Type: text/plain" --data-binary "hello"
run_curl_case "POST upload rejects invalid symlink value" POST "$TEST_WEB_BASE_URL/$MAC/upload/file?symlink=maybe" 400 "invalid symlink value" -H "Content-Type: text/plain" --data-binary "hello"
run_curl_case "POST upload symlink requires filePath and symlinkPath" POST "$TEST_WEB_BASE_URL/$MAC/upload/file?symlink=true" 400 "symlink uploads require filePath and symlinkPath" -H "Content-Type: text/plain" --data-binary "hello"
run_curl_case "POST upload symlinkPath requires symlink=true" POST "$TEST_WEB_BASE_URL/$MAC/upload/file?symlinkPath=dest" 400 "symlinkPath requires symlink=true" -H "Content-Type: text/plain" --data-binary "hello"
run_curl_case "POST upload rejects invalid type" POST "$TEST_WEB_BASE_URL/$MAC/upload/not-real" 404 "invalid upload type" -H "Content-Type: text/plain" --data-binary "hello"
run_curl_body_contains_case "POST upload rejects unsupported content type" POST "$TEST_WEB_BASE_URL/$MAC/upload/log" 415 "unsupported content type; expected one of:" -H "Content-Type: application/json" --data-binary '{"x":1}'
run_curl_case "POST file upload without valid filePath falls back to file log" POST "$TEST_WEB_BASE_URL/$MAC/upload/file?filePath=../../etc/passwd" 200 "ok" -H "Content-Type: text/plain" --data-binary "hello"
assert_file_contains "file upload with invalid filePath is logged in file.text_plain.log" "$MAC_DIR/file/file.text_plain.log" "hello"

run_curl_case "POST file symlink rejects unsafe filePath" POST "$TEST_WEB_BASE_URL/$MAC/upload/file?symlink=true&filePath=../../etc/passwd&symlinkPath=target" 400 "symlink uploads require filePath and symlinkPath" -H "Content-Type: text/plain" --data-binary "ignored"

run_curl_case "POST file upload stores regular file" POST "$TEST_WEB_BASE_URL/$MAC/upload/file?filePath=etc/config.txt" 200 "ok" -H "Content-Type: text/plain" --data-binary "plain text"
assert_file_contains "file upload writes file contents" "$MAC_DIR/fs/etc/config.txt" "plain text"

run_curl_case "POST file upload stores symlink" POST "$TEST_WEB_BASE_URL/$MAC/upload/file?symlink=true&filePath=etc/current&symlinkPath=../target" 200 "ok" -H "Content-Type: text/plain" --data-binary "ignored"
assert_symlink_target "file upload writes symlink" "$MAC_DIR/fs/etc/current" "../target"

run_curl_case "POST file-list requires absolute filePath" POST "$TEST_WEB_BASE_URL/$MAC/upload/file-list?filePath=relative/path" 400 "file-list uploads require absolute filePath" -H "Content-Type: text/plain" --data-binary "entry"
run_curl_case "POST file-list stores newline-terminated content" POST "$TEST_WEB_BASE_URL/$MAC/upload/file-list?filePath=/var/log/messages" 200 "ok" -H "Content-Type: text/plain" --data-binary "first-entry"
file_list_log="$(find "$MAC_DIR/file-list" -maxdepth 1 -type f -name 'var-log-messages*' | head -n 1)"
assert_file_contains "file-list writes transformed filename" "$file_list_log" "first-entry"

run_curl_case "POST file-list stores root path as root-fs filename" POST "$TEST_WEB_BASE_URL/$MAC/upload/file-list?filePath=/" 200 "ok" -H "Content-Type: text/plain" --data-binary "root-entry"
root_fs_log="$(find "$MAC_DIR/file-list" -maxdepth 1 -type f -name 'root-fs*' | head -n 1)"
assert_file_contains "file-list writes root-fs filename" "$root_fs_log" "root-entry"

run_curl_case "POST symlink-list requires absolute filePath" POST "$TEST_WEB_BASE_URL/$MAC/upload/symlink-list?filePath=relative/path" 400 "symlink-list uploads require absolute filePath" -H "Content-Type: text/plain" --data-binary "entry"
run_curl_case "POST symlink-list stores newline-terminated content" POST "$TEST_WEB_BASE_URL/$MAC/upload/symlink-list?filePath=/var/lib" 200 "ok" -H "Content-Type: text/plain" --data-binary "link -> target"
symlink_list_log="$(find "$MAC_DIR/symlink-list" -maxdepth 1 -type f -name 'var-lib*' | head -n 1)"
assert_file_contains "symlink-list writes transformed filename" "$symlink_list_log" "link -> target"

run_curl_case "POST symlink-list stores root path as root-fs filename" POST "$TEST_WEB_BASE_URL/$MAC/upload/symlink-list?filePath=/" 200 "ok" -H "Content-Type: text/plain" --data-binary "root-link -> target"
root_symlink_log="$(find "$MAC_DIR/symlink-list" -maxdepth 1 -type f -name 'root-fs*' | head -n 1)"
assert_file_contains "symlink-list writes root-fs filename" "$root_symlink_log" "root-link -> target"

run_curl_case "POST log stores plain-text log" POST "$TEST_WEB_BASE_URL/$MAC/upload/log" 200 "ok" -H "Content-Type: text/plain" --data-binary "log line"
plain_log="$(find "$MAC_DIR/logs" -maxdepth 1 -type f -name 'log*.text_plain.log' | head -n 1)"
assert_file_contains "log upload appends to text log" "$plain_log" "log line"

run_curl_case "POST cmd stores plain-text log" POST "$TEST_WEB_BASE_URL/$MAC/upload/cmd" 200 "ok" -H "Content-Type: text/plain" --data-binary "echo hello
hello"
cmd_text_log="$(find "$MAC_DIR/cmd" -maxdepth 1 -type f -name 'cmd.*.text_plain.log' | head -n 1)"
if [ -n "$cmd_text_log" ]; then
    pass_case "cmd upload creates timestamped text log"
else
    fail_case "cmd upload creates timestamped text log" sh -c "find \"$MAC_DIR/cmd\" -maxdepth 1 -type f -print 2>/dev/null || true"
fi
assert_file_contains "cmd upload stores command text payload" "$cmd_text_log" "echo hello"
assert_file_contains "cmd upload stores command output payload" "$cmd_text_log" "hello"

run_curl_case "POST cmd stores json log" POST "$TEST_WEB_BASE_URL/$MAC/upload/cmd" 200 "ok" -H "Content-Type: application/json" --data-binary '{"command":"echo hello","output":"hello"}'
cmd_json_log="$(find "$MAC_DIR/cmd" -maxdepth 1 -type f -name 'cmd.*.application_json.log' | head -n 1)"
if [ -n "$cmd_json_log" ]; then
    pass_case "cmd upload creates timestamped json log"
else
    fail_case "cmd upload creates timestamped json log" sh -c "find \"$MAC_DIR/cmd\" -maxdepth 1 -type f -print 2>/dev/null || true"
fi
assert_file_contains "cmd upload stores json command key" "$cmd_json_log" '"command":"echo hello"'
assert_file_contains "cmd upload stores json output key" "$cmd_json_log" '"output":"hello"'

run_curl_case "POST logs alias stores in same directory" POST "$TEST_WEB_BASE_URL/$MAC/upload/logs" 200 "ok" -H "Content-Type: text/csv" --data-binary "col1,col2"
csv_log="$(find "$MAC_DIR/logs" -maxdepth 1 -type f -name 'log*.text_csv.log' | head -n 1)"
assert_file_contains "logs upload appends csv log" "$csv_log" "col1,col2"

run_curl_case "POST ndjson augments object payload" POST "$TEST_WEB_BASE_URL/$MAC/upload/dmesg" 200 "ok" -H "Content-Type: application/x-ndjson" --data-binary '{"event":"boot"}'
dmesg_log="$(find "$MAC_DIR/dmesg" -maxdepth 1 -type f -name 'dmesg.*.application_x_ndjson.log' | head -n 1)"
if [ -n "$dmesg_log" ]; then
    pass_case "ndjson upload creates timestamped dmesg log"
else
    fail_case "ndjson upload creates timestamped dmesg log" sh -c "find \"$MAC_DIR/dmesg\" -maxdepth 1 -type f -print 2>/dev/null || true"
fi
assert_file_contains "ndjson upload records api timestamp" "$dmesg_log" '"api_timestamp"'
assert_file_contains "ndjson upload records source ip" "$dmesg_log" '"src_ip"'

run_curl_case "POST invalid json falls back to raw body" POST "$TEST_WEB_BASE_URL/$MAC/upload/orom" 200 "ok" -H "Content-Type: text/plain" --data-binary '{not-json}'
assert_file_contains "invalid json payload remains raw" "$MAC_DIR/orom/orom.text_plain.log" "{not-json}"

binary_payload="$TEST_WEB_TMPDIR/binary_payload.bin"
printf '\001\002\003\004' > "$binary_payload"
run_curl_case "POST binary upload stores octet-stream file" POST "$TEST_WEB_BASE_URL/$MAC/upload/uboot-image" 200 "ok" -H "Content-Type: application/octet-stream" --data-binary "@$binary_payload"

binary_count="$(find "$MAC_DIR/uboot/image" -type f -name 'upload_*.bin' | wc -l | tr -d ' ')"
if [ "$binary_count" = "1" ]; then
    pass_case "binary upload creates generated .bin file"
else
    fail_case "binary upload creates generated .bin file" sh -c "find \"$MAC_DIR/uboot/image\" -maxdepth 1 -type f -print"
fi

run_curl_case "POST uboot-environment stores text log" POST "$TEST_WEB_BASE_URL/$MAC/upload/uboot-environment" 200 "ok" -H "Content-Type: text/plain" --data-binary "env line"
assert_file_contains "uboot-environment upload writes env log" "$MAC_DIR/uboot/env/uboot-environment.text_plain.log" "env line"

run_curl_case "POST efi-vars stores timestamped ndjson log" POST "$TEST_WEB_BASE_URL/$MAC/upload/efi-vars" 200 "ok" -H "Content-Type: application/x-ndjson" --data-binary '{"guid":"g","name":"n"}'
efi_vars_log="$(find "$MAC_DIR/efi-vars" -maxdepth 1 -type f -name 'efi-vars.*.application_x_ndjson.log' | head -n 1)"
if [ -n "$efi_vars_log" ]; then
    pass_case "efi-vars upload creates timestamped log in efi-vars directory"
else
    fail_case "efi-vars upload creates timestamped log in efi-vars directory" sh -c "find \"$MAC_DIR/efi-vars\" -maxdepth 2 -print 2>/dev/null || true"
fi
assert_file_contains "efi-vars upload stores ndjson payload" "$efi_vars_log" '"guid":"g"'
assert_file_contains "efi-vars upload records source ip" "$efi_vars_log" '"src_ip"'

finish_web_tests