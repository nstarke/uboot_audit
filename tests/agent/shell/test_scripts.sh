#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"
SCRIPTS_DIR="$SCRIPT_DIR/../scripts"

TEST_OUTPUT_HTTP="${TEST_OUTPUT_HTTP:-}"

# shellcheck source=tests/agent/shell/common.sh
. "$SCRIPT_DIR/common.sh"

require_binary "$BIN"
print_section "interactive script file coverage"

REMOTE_HTTP_SERVER_PID=""
REMOTE_HTTP_SERVER_TMPDIR=""
REMOTE_API_SERVER_PID=""
REMOTE_API_SERVER_TMPDIR=""

cleanup_remote_http_server() {
    if [ -n "$REMOTE_HTTP_SERVER_PID" ]; then
        kill "$REMOTE_HTTP_SERVER_PID" 2>/dev/null || true
        wait "$REMOTE_HTTP_SERVER_PID" 2>/dev/null || true
        REMOTE_HTTP_SERVER_PID=""
    fi

    if [ -n "$REMOTE_HTTP_SERVER_TMPDIR" ] && [ -d "$REMOTE_HTTP_SERVER_TMPDIR" ]; then
        rm -rf "$REMOTE_HTTP_SERVER_TMPDIR"
        REMOTE_HTTP_SERVER_TMPDIR=""
    fi

    if [ -n "$REMOTE_API_SERVER_PID" ]; then
        kill "$REMOTE_API_SERVER_PID" 2>/dev/null || true
        wait "$REMOTE_API_SERVER_PID" 2>/dev/null || true
        REMOTE_API_SERVER_PID=""
    fi

    if [ -n "$REMOTE_API_SERVER_TMPDIR" ] && [ -d "$REMOTE_API_SERVER_TMPDIR" ]; then
        rm -rf "$REMOTE_API_SERVER_TMPDIR"
        REMOTE_API_SERVER_TMPDIR=""
    fi
}

start_remote_http_server() {
    python_bin="$(find_python_bin)" || {
        echo "error: python or python3 is required for remote script HTTP test"
        exit 1
    }

    REMOTE_HTTP_SERVER_TMPDIR="$(mktemp -d /tmp/ela_remote_script.XXXXXX)"
    cp "$SCRIPTS_DIR/test_linux_dmesg_args.ela" "$REMOTE_HTTP_SERVER_TMPDIR/remote_test_linux_dmesg_args.ela"

    REMOTE_HTTP_SERVER_LOG="$REMOTE_HTTP_SERVER_TMPDIR/http.log"
    "$python_bin" -m http.server 5320 --bind 127.0.0.1 --directory "$REMOTE_HTTP_SERVER_TMPDIR" >"$REMOTE_HTTP_SERVER_LOG" 2>&1 &
    REMOTE_HTTP_SERVER_PID=$!

    i=0
    while [ "$i" -lt 50 ]; do
        if ! kill -0 "$REMOTE_HTTP_SERVER_PID" 2>/dev/null; then
            echo "error: remote HTTP test server exited unexpectedly"
            print_file_head_scrubbed "$REMOTE_HTTP_SERVER_LOG" 120
            exit 1
        fi

        if curl -fsS "http://127.0.0.1:5320/remote_test_linux_dmesg_args.ela" >/dev/null 2>&1; then
            return 0
        fi

        sleep 0.1
        i=$(expr "$i" + 1)
    done

    echo "error: timed out waiting for remote HTTP test server"
    print_file_head_scrubbed "$REMOTE_HTTP_SERVER_LOG" 120
    exit 1
}

start_remote_api_server() {
    python_bin="$(find_python_bin)" || {
        echo "error: python or python3 is required for remote script HTTP fallback test"
        exit 1
    }

    REMOTE_API_SERVER_TMPDIR="$(mktemp -d /tmp/ela_remote_api_script.XXXXXX)"
    mkdir -p "$REMOTE_API_SERVER_TMPDIR/scripts"
    cp "$SCRIPTS_DIR/test_linux_dmesg_args.ela" "$REMOTE_API_SERVER_TMPDIR/scripts/fallback_test_linux_dmesg_args.ela"

    REMOTE_API_SERVER_LOG="$REMOTE_API_SERVER_TMPDIR/http.log"
    "$python_bin" -m http.server 5321 --bind 127.0.0.1 --directory "$REMOTE_API_SERVER_TMPDIR" >"$REMOTE_API_SERVER_LOG" 2>&1 &
    REMOTE_API_SERVER_PID=$!

    i=0
    while [ "$i" -lt 50 ]; do
        if ! kill -0 "$REMOTE_API_SERVER_PID" 2>/dev/null; then
            echo "error: remote API fallback test server exited unexpectedly"
            print_file_head_scrubbed "$REMOTE_API_SERVER_LOG" 120
            exit 1
        fi

        if curl -fsS "http://127.0.0.1:5321/scripts/fallback_test_linux_dmesg_args.ela" >/dev/null 2>&1; then
            return 0
        fi

        sleep 0.1
        i=$(expr "$i" + 1)
    done

    echo "error: timed out waiting for remote API fallback test server"
    print_file_head_scrubbed "$REMOTE_API_SERVER_LOG" 120
    exit 1
}

trap 'cleanup_remote_http_server' EXIT INT TERM

while [ "$#" -gt 0 ]; do
    case "$1" in
        --output-http)
            if [ "$#" -lt 2 ]; then
                echo "error: --output-http requires a value"
                echo "usage: $0 [--output-http <url>]"
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
            echo "usage: $0 [--output-http <url>]"
            exit 2
            ;;
    esac
done

for test_script in \
    "$SCRIPTS_DIR/test_efi_dump_vars_args.ela" \
    "$SCRIPTS_DIR/test_linux_dmesg_args.ela" \
    "$SCRIPTS_DIR/test_linux_download_file_args.ela" \
    "$SCRIPTS_DIR/test_linux_execute_command_args.ela" \
    "$SCRIPTS_DIR/test_linux_grep_args.ela" \
    "$SCRIPTS_DIR/test_linux_list_files_args.ela" \
    "$SCRIPTS_DIR/test_linux_list_symlinks_args.ela" \
    "$SCRIPTS_DIR/test_linux_remote_copy_args.ela" \
    "$SCRIPTS_DIR/test_efi_bios_orom_args.ela" \
    "$SCRIPTS_DIR/test_uboot_audit_args.ela" \
    "$SCRIPTS_DIR/test_uboot_image_args.ela" \
    "$SCRIPTS_DIR/test_uboot_env_args.ela"
do
    run_accept_case "script $(basename "$test_script")" "$BIN" --script "$test_script"
done

start_remote_http_server
run_accept_case "script remote_test_linux_dmesg_args.ela via HTTP URL" \
    "$BIN" --script "http://127.0.0.1:5320/remote_test_linux_dmesg_args.ela"

start_remote_api_server
run_accept_case "script fallback_test_linux_dmesg_args.ela via --output-http /scripts route fallback" \
    "$BIN" --output-http "http://127.0.0.1:5321/upload" --script "fallback_test_linux_dmesg_args.ela"
run_accept_case "script nested/path/fallback_test_linux_dmesg_args.ela uses basename for --output-http /scripts route fallback" \
    "$BIN" --output-http "http://127.0.0.1:5321/upload" --script "nested/path/fallback_test_linux_dmesg_args.ela"

finish_tests