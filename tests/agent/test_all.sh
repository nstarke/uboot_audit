#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"

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

for test_script in \
    "$SCRIPT_DIR/test_linux_dmesg_args.sh" \
    "$SCRIPT_DIR/test_linux_download_file_args.sh" \
    "$SCRIPT_DIR/test_linux_execute_command_args.sh" \
    "$SCRIPT_DIR/test_linux_grep_args.sh" \
    "$SCRIPT_DIR/test_linux_list_files_args.sh" \
    "$SCRIPT_DIR/test_linux_list_symlinks_args.sh" \
    "$SCRIPT_DIR/test_linux_remote_copy_args.sh" \
    "$SCRIPT_DIR/test_efi_bios_orom_args.sh" \
    "$SCRIPT_DIR/test_uboot_audit_args.sh" \
    "$SCRIPT_DIR/test_uboot_image_args.sh" \
    "$SCRIPT_DIR/test_uboot_env_args.sh" 
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