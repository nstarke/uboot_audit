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
    "$SCRIPT_DIR/linux/test_linux_tpm2_args.sh" \
    "$SCRIPT_DIR/efi/test_efi_bios_orom_args.sh" \
    "$SCRIPT_DIR/uboot/test_uboot_audit_args.sh" \
    "$SCRIPT_DIR/uboot/test_uboot_image_args.sh" \
    "$SCRIPT_DIR/uboot/test_uboot_env_args.sh"
do
    echo
    echo "===== Running $(basename "$test_script") ====="
    if [ -n "$TEST_OUTPUT_HTTP" ]; then
        /bin/sh "$test_script" --output-http "$TEST_OUTPUT_HTTP"
    else
        /bin/sh "$test_script"
    fi

    if [ "$?" -ne 0 ]; then
        rc=1
    fi
done

exit "$rc"