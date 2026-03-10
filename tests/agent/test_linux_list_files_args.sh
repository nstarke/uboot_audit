#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="$REPO_ROOT/embedded_linux_audit"

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
print_section "linux list-files subcommand argument coverage"

TEST_DISABLE_OUTPUT_OVERRIDE=1
export TEST_DISABLE_OUTPUT_OVERRIDE

TMP_DIR="$(mktemp -d /tmp/test_list_files_args.XXXXXX)"
TMP_SUBDIR="$TMP_DIR/subdir"
TMP_FILE="$TMP_SUBDIR/sample.txt"
TMP_SUID_FILE="$TMP_SUBDIR/suid-sample.sh"
mkdir -p "$TMP_SUBDIR"
printf 'sample\n' >"$TMP_FILE"
printf '#!/bin/sh\nexit 0\n' >"$TMP_SUID_FILE"
chmod 4755 "$TMP_SUID_FILE"

run_exact_case "linux list-files --help" 0 "$BIN" --verbose linux list-files --help
run_exact_case "linux list-files relative path" 2 "$BIN" --verbose linux list-files ./relative
run_exact_case "linux list-files file path" 2 "$BIN" --verbose linux list-files "$TMP_FILE"
run_exact_case "linux list-files invalid --output-http" 2 "$BIN" --verbose linux list-files "$TMP_DIR" --output-http ftp://127.0.0.1:1/file-list
run_exact_case "linux list-files invalid --output-https" 2 "$BIN" --verbose linux list-files "$TMP_DIR" --output-https http://127.0.0.1:1/file-list
run_exact_case "linux list-files both http+https" 2 "$BIN" --verbose linux list-files "$TMP_DIR" --output-http http://127.0.0.1:1/file-list --output-https https://127.0.0.1:1/file-list
run_exact_case "linux list-files extra positional argument" 2 "$BIN" --verbose linux list-files "$TMP_DIR" /tmp/extra

run_exact_case "linux list-files local directory" 0 "$BIN" --verbose linux list-files "$TMP_DIR"
run_exact_case "linux list-files --suid-only" 0 "$BIN" --verbose linux list-files "$TMP_DIR" --suid-only
run_accept_case "linux list-files --output-http" "$BIN" --verbose linux list-files "$TMP_DIR" --output-http http://127.0.0.1:1/file-list
run_accept_case "linux list-files --output-https" "$BIN" --verbose linux list-files "$TMP_DIR" --output-https https://127.0.0.1:1/file-list
run_accept_case "linux list-files --output-https --insecure" "$BIN" --verbose linux list-files "$TMP_DIR" --output-https https://127.0.0.1:1/file-list --insecure

run_accept_case "linux list-files with --output-format txt" "$BIN" --output-format txt --verbose linux list-files "$TMP_DIR"
run_accept_case "linux list-files with --output-format csv" "$BIN" --output-format csv --verbose linux list-files "$TMP_DIR"
run_accept_case "linux list-files with --output-format json" "$BIN" --output-format json --verbose linux list-files "$TMP_DIR"

suid_log="$(mktemp /tmp/test_list_files_suid.XXXXXX)"
"$BIN" --verbose linux list-files "$TMP_DIR" --suid-only >"$suid_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -Fxq "$TMP_SUID_FILE" "$suid_log" && ! grep -Fxq "$TMP_FILE" "$suid_log"; then
    echo "[PASS] linux list-files --suid-only filters non-SUID files"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-files --suid-only filters non-SUID files (rc=$rc)"
    sed -n '1,80p' "$suid_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$suid_log"

warn_log="$(mktemp /tmp/test_list_files_warn.XXXXXX)"
"$BIN" --output-format json --verbose linux list-files --help >"$warn_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q "Warning: --output-format has no effect for list-files" "$warn_log"; then
    echo "[PASS] linux list-files warns when --output-format is set"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-files warns when --output-format is set (rc=$rc)"
    sed -n '1,80p' "$warn_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$warn_log"

rm -rf "$TMP_DIR"
finish_tests