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
print_section "linux remote-copy subcommand argument coverage"

TMP_DIR="$(mktemp -d /tmp/test_remote_copy_args.XXXXXX)"
TMP_FILE="$TMP_DIR/sample.bin"
echo "remote copy payload" >"$TMP_FILE"

run_exact_case "linux remote-copy --help" 0 "$BIN" linux remote-copy --help
run_exact_case "linux remote-copy no args" 2 "$BIN" linux remote-copy
run_exact_case "linux remote-copy relative path" 2 "$BIN" linux remote-copy ./relative.bin --output-tcp 127.0.0.1:9
run_exact_case "linux remote-copy missing output target" 2 "$BIN" linux remote-copy "$TMP_FILE"
run_exact_case "linux remote-copy invalid --output-http" 2 "$BIN" linux remote-copy "$TMP_FILE" --output-http ftp://127.0.0.1:1/file
run_exact_case "linux remote-copy invalid --output-https" 2 "$BIN" linux remote-copy "$TMP_FILE" --output-https http://127.0.0.1:1/file
run_exact_case "linux remote-copy both http+https" 2 "$BIN" linux remote-copy "$TMP_FILE" --output-http http://127.0.0.1:1/file --output-https https://127.0.0.1:1/file
run_exact_case "linux remote-copy multiple transport kinds" 2 "$BIN" linux remote-copy "$TMP_FILE" --output-tcp 127.0.0.1:9 --output-http http://127.0.0.1:1/file
run_exact_case "linux remote-copy extra positional argument" 2 "$BIN" linux remote-copy "$TMP_FILE" /tmp/extra --output-tcp 127.0.0.1:9
run_exact_case "linux remote-copy /proc without allow flag" 2 "$BIN" linux remote-copy /proc/cmdline --output-http http://127.0.0.1:1/upload

TMP_SUBDIR="$TMP_DIR/subdir"
mkdir -p "$TMP_SUBDIR"
echo "nested payload" >"$TMP_SUBDIR/nested.bin"
ln -sf "$TMP_FILE" "$TMP_DIR/sample.link"
run_exact_case "linux remote-copy directory over tcp" 2 "$BIN" linux remote-copy "$TMP_DIR" --output-tcp 127.0.0.1:9
run_accept_case "linux remote-copy symlink without --allow-symlinks" "$BIN" linux remote-copy "$TMP_DIR/sample.link" --output-http http://127.0.0.1:1/upload
run_accept_case "linux remote-copy directory http --allow-dev" "$BIN" linux remote-copy "$TMP_DIR" --output-http http://127.0.0.1:1/upload --allow-dev
run_accept_case "linux remote-copy directory http --allow-sysfs" "$BIN" linux remote-copy "$TMP_DIR" --output-http http://127.0.0.1:1/upload --allow-sysfs
run_accept_case "linux remote-copy directory http --allow-proc" "$BIN" linux remote-copy "$TMP_DIR" --output-http http://127.0.0.1:1/upload --allow-proc

run_accept_case "linux remote-copy --output-tcp" "$BIN" linux remote-copy "$TMP_FILE" --output-tcp 127.0.0.1:9
run_accept_case "linux remote-copy --output-http" "$BIN" linux remote-copy "$TMP_FILE" --output-http http://127.0.0.1:1/upload
run_accept_case "linux remote-copy --output-https" "$BIN" linux remote-copy "$TMP_FILE" --output-https https://127.0.0.1:1/upload
run_accept_case "linux remote-copy --output-https --insecure" "$BIN" linux remote-copy "$TMP_FILE" --output-https https://127.0.0.1:1/upload --insecure
run_accept_case "linux remote-copy --verbose" "$BIN" linux remote-copy "$TMP_FILE" --output-http http://127.0.0.1:1/upload --verbose
run_accept_case "linux remote-copy directory http" "$BIN" linux remote-copy "$TMP_DIR" --output-http http://127.0.0.1:1/upload
run_accept_case "linux remote-copy directory http --recursive" "$BIN" linux remote-copy "$TMP_DIR" --output-http http://127.0.0.1:1/upload --recursive
run_accept_case "linux remote-copy symlink http --allow-symlinks" "$BIN" linux remote-copy "$TMP_DIR/sample.link" --output-http http://127.0.0.1:1/upload --allow-symlinks

if [ -d /dev ]; then
    run_accept_case "linux remote-copy /dev directory http --allow-dev" \
        "$BIN" linux remote-copy /dev --output-http http://127.0.0.1:1/upload --allow-dev
fi

if [ -d /sys ]; then
    run_exact_case "linux remote-copy /sys without allow flag" 2 \
        "$BIN" linux remote-copy /sys --output-http http://127.0.0.1:1/upload
    run_accept_case "linux remote-copy /sys directory http --allow-sysfs" \
        "$BIN" linux remote-copy /sys --output-http http://127.0.0.1:1/upload --allow-sysfs
fi

if [ -r /proc/cmdline ]; then
    run_accept_case "linux remote-copy /proc/cmdline over http (non-sized stream-like file)" \
        "$BIN" linux remote-copy /proc/cmdline --output-http http://127.0.0.1:1/upload --verbose --allow-proc
fi

if [ -d /proc ]; then
    run_accept_case "linux remote-copy /proc directory http --allow-proc" \
        "$BIN" linux remote-copy /proc --output-http http://127.0.0.1:1/upload --allow-proc
    run_accept_case "linux remote-copy /proc directory http --recursive --allow-proc" \
        "$BIN" linux remote-copy /proc --output-http http://127.0.0.1:1/upload --recursive --allow-proc
fi

run_accept_case "linux remote-copy with --output-format txt" "$BIN" --output-format txt linux remote-copy "$TMP_FILE" --output-http http://127.0.0.1:1/upload
run_accept_case "linux remote-copy with --output-format csv" "$BIN" --output-format csv linux remote-copy "$TMP_FILE" --output-http http://127.0.0.1:1/upload
run_accept_case "linux remote-copy with --output-format json" "$BIN" --output-format json linux remote-copy "$TMP_FILE" --output-http http://127.0.0.1:1/upload

warn_log="$(mktemp /tmp/test_remote_copy_warn.XXXXXX)"
run_with_output_override "$BIN" --output-format json linux remote-copy "$TMP_FILE" --help >"$warn_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q "Warning: --output-format has no effect for remote-copy" "$warn_log"; then
    echo "[PASS] linux remote-copy warns when --output-format is set"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux remote-copy warns when --output-format is set (rc=$rc)"
    sed -n '1,80p' "$warn_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$warn_log"

rm -rf "$TMP_DIR"
finish_tests
