#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
BIN="/tmp/embedded_linux_audit"

TEST_OUTPUT_HTTP="${TEST_OUTPUT_HTTP:-}"
TEST_OUTPUT_HTTPS="${TEST_OUTPUT_HTTPS:-}"

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
        --output-https)
            if [ "$#" -lt 2 ]; then
                echo "error: --output-https requires a value"
                exit 2
            fi
            TEST_OUTPUT_HTTPS="$2"
            shift 2
            ;;
        --output-https=*)
            TEST_OUTPUT_HTTPS="${1#*=}"
            shift
            ;;
        *)
            echo "error: unknown argument: $1"
            exit 2
            ;;
    esac
done

if [ -n "$TEST_OUTPUT_HTTP" ] && [ -n "$TEST_OUTPUT_HTTPS" ]; then
    echo "error: set only one of --output-http or --output-https"
    exit 2
fi

export TEST_OUTPUT_HTTP
export TEST_OUTPUT_HTTPS

# shellcheck source=tests/agent/common.sh
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

run_exact_case "linux list-symlinks --help" 0 "$BIN" --verbose linux list-symlinks --help
run_exact_case "linux list-symlinks relative path" 2 "$BIN" --verbose linux list-symlinks ./relative
run_exact_case "linux list-symlinks file path" 2 "$BIN" --verbose linux list-symlinks "$TMP_FILE"
run_exact_case "linux list-symlinks invalid --output-http" 2 "$BIN" --verbose linux list-symlinks "$TMP_DIR" --output-http ftp://127.0.0.1:1/symlink-list
run_exact_case "linux list-symlinks invalid --output-https" 2 "$BIN" --verbose linux list-symlinks "$TMP_DIR" --output-https http://127.0.0.1:1/symlink-list
run_exact_case "linux list-symlinks both http+https" 2 "$BIN" --verbose linux list-symlinks "$TMP_DIR" --output-http http://127.0.0.1:1/symlink-list --output-https https://127.0.0.1:1/symlink-list
run_exact_case "linux list-symlinks extra positional argument" 2 "$BIN" --verbose linux list-symlinks "$TMP_DIR" /tmp/extra

run_exact_case "linux list-symlinks no directory argument defaults to /" 0 "$BIN" --verbose linux list-symlinks
run_exact_case "linux list-symlinks default directory" 0 "$BIN" --verbose linux list-symlinks "$TMP_DIR"
run_exact_case "linux list-symlinks --recursive" 0 "$BIN" --verbose linux list-symlinks "$TMP_DIR" --recursive
run_accept_case "linux list-symlinks --output-http" "$BIN" --verbose linux list-symlinks "$TMP_DIR" --output-http http://127.0.0.1:1/symlink-list
run_accept_case "linux list-symlinks --output-https" "$BIN" --verbose linux list-symlinks "$TMP_DIR" --output-https https://127.0.0.1:1/symlink-list
run_accept_case "linux list-symlinks --output-https --insecure" "$BIN" --verbose linux list-symlinks "$TMP_DIR" --output-https https://127.0.0.1:1/symlink-list --insecure
run_exact_case "linux list-symlinks with --output-format txt" 0 "$BIN" --output-format txt --verbose linux list-symlinks "$TMP_DIR"
run_exact_case "linux list-symlinks with --output-format csv" 0 "$BIN" --output-format csv --verbose linux list-symlinks "$TMP_DIR"
run_exact_case "linux list-symlinks with --output-format json" 0 "$BIN" --output-format json --verbose linux list-symlinks "$TMP_DIR"

txt_log="$(mktemp /tmp/test_list_symlinks_txt.XXXXXX)"
"$BIN" --output-format txt --verbose linux list-symlinks "$TMP_DIR" >"$txt_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && file_has_exact_line "$TMP_LINK_TOP -> /tmp/target-top" "$txt_log" && ! file_has_exact_line "$TMP_LINK_SUB -> ../plain.txt" "$txt_log"; then
    echo "[PASS] linux list-symlinks default listing stays non-recursive"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-symlinks default listing stays non-recursive (rc=$rc)"
    sed -n '1,80p' "$txt_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$txt_log"

recursive_log="$(mktemp /tmp/test_list_symlinks_recursive.XXXXXX)"
"$BIN" --output-format txt --verbose linux list-symlinks "$TMP_DIR" --recursive >"$recursive_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && file_has_exact_line "$TMP_LINK_TOP -> /tmp/target-top" "$recursive_log" && file_has_exact_line "$TMP_LINK_SUB -> ../plain.txt" "$recursive_log"; then
    echo "[PASS] linux list-symlinks --recursive includes nested symlinks"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-symlinks --recursive includes nested symlinks (rc=$rc)"
    sed -n '1,80p' "$recursive_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$recursive_log"

csv_log="$(mktemp /tmp/test_list_symlinks_csv.XXXXXX)"
"$BIN" --output-format csv --verbose linux list-symlinks "$TMP_DIR" >"$csv_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && file_has_exact_line "\"$TMP_LINK_TOP\",\"/tmp/target-top\"" "$csv_log"; then
    echo "[PASS] linux list-symlinks csv output matches expected format"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-symlinks csv output matches expected format (rc=$rc)"
    sed -n '1,80p' "$csv_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$csv_log"

json_log="$(mktemp /tmp/test_list_symlinks_json.XXXXXX)"
"$BIN" --output-format json --verbose linux list-symlinks "$TMP_DIR" >"$json_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && file_has_exact_line "{\"link_path\":\"$TMP_LINK_TOP\",\"location_path\":\"/tmp/target-top\"}" "$json_log"; then
    echo "[PASS] linux list-symlinks json output matches expected format"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-symlinks json output matches expected format (rc=$rc)"
    sed -n '1,80p' "$json_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$json_log"

rm -rf "$TMP_DIR"
finish_tests