#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# shellcheck source=tests/system_package_helpers.sh
. "$REPO_ROOT/tests/system_package_helpers.sh"

TEST_OUTPUT_HTTP="${TEST_OUTPUT_HTTP:-}"

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

rc=0
pass_count=0
fail_count=0

if command -v zig >/dev/null 2>&1; then
    ela_ensure_command llvm-objcopy >/dev/null 2>&1 || true
fi

for test_script in \
    "$SCRIPT_DIR/test_cli_and_extra_args.sh" \
    "$SCRIPT_DIR/efi/test_efi_dump_vars_args.sh" \
    "$SCRIPT_DIR/linux/test_linux_dmesg_args.sh" \
    "$SCRIPT_DIR/linux/test_linux_download_file_args.sh" \
    "$SCRIPT_DIR/linux/test_linux_execute_command_args.sh" \
    "$SCRIPT_DIR/linux/test_linux_grep_args.sh" \
    "$SCRIPT_DIR/test_scripts.sh" \
    "$SCRIPT_DIR/linux/test_linux_list_files_args.sh" \
    "$SCRIPT_DIR/linux/test_linux_list_symlinks_args.sh" \
    "$SCRIPT_DIR/linux/test_linux_remote_copy_args.sh" \
    "$SCRIPT_DIR/linux/test_linux_ssh_args.sh" \
    "$SCRIPT_DIR/tpm2/test_tpm2_args.sh" \
    "$SCRIPT_DIR/efi/test_efi_bios_orom_args.sh" \
    "$SCRIPT_DIR/uboot/test_uboot_audit_args.sh" \
    "$SCRIPT_DIR/uboot/test_uboot_image_args.sh" \
    "$SCRIPT_DIR/uboot/test_uboot_env_args.sh" \
    "$SCRIPT_DIR/transfer/test_transfer_args.sh" \
    "$SCRIPT_DIR/test_api_key.sh"
do
    echo
    echo "===== Running $(basename "$test_script") ====="
    test_log="$(mktemp /tmp/ela-shell-test-all.XXXXXX)"
    if [ -n "$TEST_OUTPUT_HTTP" ]; then
        /bin/sh "$test_script" --output-http "$TEST_OUTPUT_HTTP" >"$test_log" 2>&1
    else
        /bin/sh "$test_script" >"$test_log" 2>&1
    fi
    test_rc=$?
    cat "$test_log"

    test_passes="$(sed -n 's/^Passed: //p' "$test_log" | tail -n 1)"
    test_fails="$(sed -n 's/^Failed: //p' "$test_log" | tail -n 1)"

    if [ -n "$test_passes" ]; then
        pass_count="$(expr "$pass_count" + "$test_passes")"
    fi

    if [ -n "$test_fails" ]; then
        fail_count="$(expr "$fail_count" + "$test_fails")"
    fi

    rm -f "$test_log"

    if [ "$test_rc" -ne 0 ]; then
        rc=1
    fi
done

echo
echo "Total test cases passed: $pass_count"
echo "Total test cases failed: $fail_count"

exit "$rc"