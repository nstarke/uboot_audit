#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

TEST_OUTPUT_HTTP="${TEST_OUTPUT_HTTP:-}"

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
        *)
            echo "error: unknown argument: $1"
            exit 2
            ;;
    esac
done

export TEST_OUTPUT_HTTP

# shellcheck source=tests/agent/shell/common.sh
. "$SCRIPT_DIR/common.sh"

require_binary "$BIN"
print_section "uboot image subcommand argument coverage"

run_exact_case "uboot image --help" 0 "$BIN" uboot image --help
run_exact_case "uboot image pull --help" 0 "$BIN" uboot image pull --help
run_exact_case "uboot image find-address --help" 0 "$BIN" uboot image find-address --help
run_exact_case "uboot image list-commands --help" 0 "$BIN" uboot image list-commands --help

run_accept_case "uboot image --output-format txt" "$BIN" --output-format txt uboot image
run_accept_case "uboot image --output-format csv" "$BIN" --output-format csv uboot image
run_accept_case "uboot image --output-format json" "$BIN" --output-format json uboot image
run_accept_case "uboot image default verbose" "$BIN" uboot image
run_accept_case "uboot image --dev" "$BIN" uboot image --dev /dev/null
run_accept_case "uboot image --step" "$BIN" uboot image --step 0x1000
run_accept_case "uboot image --step 0 falls back to default" "$BIN" uboot image --step 0
run_accept_case "uboot image --allow-text" "$BIN" uboot image --allow-text
run_accept_case "uboot image --allow-text=<text>" "$BIN" uboot image --allow-text=BootROM
run_accept_case "uboot image --allow-text <text>" "$BIN" uboot image --allow-text BootROM
run_accept_case "uboot image --skip-remove" "$BIN" uboot image --skip-remove
run_accept_case "uboot image --skip-mtd" "$BIN" uboot image --skip-mtd
run_accept_case "uboot image --skip-ubi" "$BIN" uboot image --skip-ubi
run_accept_case "uboot image --skip-sd" "$BIN" uboot image --skip-sd
run_accept_case "uboot image --skip-emmc" "$BIN" uboot image --skip-emmc
run_accept_case "global --insecure uboot image" "$BIN" --insecure uboot image

run_accept_case "uboot image find-address --offset" \
    "$BIN" uboot image find-address --dev /dev/null --offset 0x0

run_accept_case "uboot image list-commands --offset" \
    "$BIN" uboot image list-commands --dev /dev/null --offset 0x0

run_accept_case "uboot image --send-logs + global --output-tcp" \
	"$BIN" --output-tcp 127.0.0.1:9 uboot image --send-logs

run_accept_case "uboot image pull global --output-tcp" \
    "$BIN" --output-tcp 127.0.0.1:9 uboot image pull --dev /dev/null --offset 0x0

run_accept_case "uboot image pull global --output-http" \
    "$BIN" --output-http http://127.0.0.1:1/image uboot image pull --dev /dev/null --offset 0x0

run_accept_case "uboot image pull global --output-http" \
    "$BIN" --output-http https://127.0.0.1:1/image uboot image pull --dev /dev/null --offset 0x0

run_exact_case "uboot image --step invalid" 2 \
    "$BIN" uboot image --step nope

run_exact_case "uboot image --output-http invalid URI" 2 \
    "$BIN" uboot image --output-http ftp://127.0.0.1/image uboot image

run_exact_case "uboot image --output-http invalid URI" 2 \
    "$BIN" uboot image --output-http http://127.0.0.1/image uboot image

run_exact_case "uboot image --output-http with --output-http is rejected" 2 \
    "$BIN" uboot image --output-http http://127.0.0.1:1/image --output-http https://127.0.0.1:1/image uboot image

run_exact_case "uboot image --send-logs requires --output-tcp" 2 \
    "$BIN" uboot image --send-logs

run_exact_case "uboot image pull requires --dev" 2 \
    "$BIN" uboot image pull --offset 0x0 --output-tcp 127.0.0.1:9

run_exact_case "uboot image pull requires --offset" 2 \
    "$BIN" uboot image pull --dev /dev/null --output-tcp 127.0.0.1:9

run_exact_case "uboot image pull invalid --offset value" 2 \
    "$BIN" uboot image pull --dev /dev/null --offset nope --output-tcp 127.0.0.1:9

run_exact_case "uboot image pull requires one global remote target" 2 \
    "$BIN" uboot image pull --dev /dev/null --offset 0x0

run_exact_case "uboot image pull rejects --send-logs" 2 \
    "$BIN" uboot image pull --dev /dev/null --offset 0x0 --send-logs --output-tcp 127.0.0.1:9

run_exact_case "uboot image pull rejects both global http and https targets" 2 \
    "$BIN" --output-http http://127.0.0.1:1/image --output-http https://127.0.0.1:1/image uboot image pull --dev /dev/null --offset 0x0

run_exact_case "uboot image pull rejects multiple global transport targets" 2 \
    "$BIN" --output-tcp 127.0.0.1:9 --output-http http://127.0.0.1:1/image uboot image pull --dev /dev/null --offset 0x0

run_exact_case "uboot image pull invalid global --output-http URI" 2 \
    "$BIN" --output-http ftp://127.0.0.1:1/image uboot image pull --dev /dev/null --offset 0x0

run_exact_case "uboot image pull invalid global --output-http URI" 2 \
    "$BIN" --output-http http://127.0.0.1:1/image uboot image pull --dev /dev/null --offset 0x0

run_exact_case "uboot image pull rejects trailing positional arg" 2 \
    "$BIN" uboot image pull --dev /dev/null --offset 0x0 --output-tcp 127.0.0.1:9 extra

run_exact_case "uboot image find-address requires --dev" 2 \
    "$BIN" uboot image find-address --offset 0x0

run_exact_case "uboot image find-address requires --offset" 2 \
    "$BIN" uboot image find-address --dev /dev/null

run_exact_case "uboot image find-address invalid --offset value" 2 \
    "$BIN" uboot image find-address --dev /dev/null --offset nope

run_exact_case "uboot image find-address rejects global --output-tcp without --send-logs" 2 \
    "$BIN" --output-tcp 127.0.0.1:9 uboot image find-address --dev /dev/null --offset 0x0

run_exact_case "uboot image find-address rejects --send-logs without global --output-tcp even with global http output" 2 \
    "$BIN" --output-http http://127.0.0.1:1/image uboot image find-address --dev /dev/null --offset 0x0 --send-logs

log="$(mktemp /tmp/test_image_find_address_send_logs.XXXXXX)"
run_with_output_override "$BIN" --output-tcp 127.0.0.1:9 uboot image find-address --dev /dev/null --offset 0x0 --send-logs >"$log" 2>&1
rc=$?
if [ "$rc" -eq 2 ] && grep -q "Unable to connect to log output target 127.0.0.1:9" "$log"; then
    echo "[PASS] uboot image find-address accepts --send-logs with --output-tcp and reaches log connection path"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] uboot image find-address accepts --send-logs with --output-tcp and reaches log connection path (rc=$rc)"
    print_file_head_scrubbed "$log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

run_exact_case "uboot image find-address invalid global --output-http URI" 2 \
    "$BIN" --output-http ftp://127.0.0.1:1/image uboot image find-address --dev /dev/null --offset 0x0

run_exact_case "uboot image find-address invalid global --output-http URI" 2 \
    "$BIN" --output-http http://127.0.0.1:1/image uboot image find-address --dev /dev/null --offset 0x0

run_exact_case "uboot image find-address rejects both global http and https targets" 2 \
    "$BIN" --output-http http://127.0.0.1:1/image --output-http https://127.0.0.1:1/image uboot image find-address --dev /dev/null --offset 0x0

run_exact_case "uboot image find-address rejects trailing positional arg" 2 \
    "$BIN" uboot image find-address --dev /dev/null --offset 0x0 extra

run_exact_case "uboot image list-commands requires --dev" 2 \
    "$BIN" uboot image list-commands --offset 0x0

run_exact_case "uboot image list-commands requires --offset" 2 \
    "$BIN" uboot image list-commands --dev /dev/null

run_exact_case "uboot image list-commands invalid --offset value" 2 \
    "$BIN" uboot image list-commands --dev /dev/null --offset nope

run_exact_case "uboot image list-commands rejects global --output-tcp without --send-logs" 2 \
    "$BIN" --output-tcp 127.0.0.1:9 uboot image list-commands --dev /dev/null --offset 0x0

run_exact_case "uboot image list-commands rejects --send-logs without global --output-tcp even with global https output" 2 \
    "$BIN" --output-http https://127.0.0.1:1/image uboot image list-commands --dev /dev/null --offset 0x0 --send-logs

log="$(mktemp /tmp/test_image_list_commands_send_logs.XXXXXX)"
run_with_output_override "$BIN" --output-tcp 127.0.0.1:9 uboot image list-commands --dev /dev/null --offset 0x0 --send-logs >"$log" 2>&1
rc=$?
if [ "$rc" -eq 2 ] && grep -q "Unable to connect to log output target 127.0.0.1:9" "$log"; then
    echo "[PASS] uboot image list-commands accepts --send-logs with --output-tcp and reaches log connection path"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] uboot image list-commands accepts --send-logs with --output-tcp and reaches log connection path (rc=$rc)"
    print_file_head_scrubbed "$log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

run_exact_case "uboot image list-commands invalid global --output-http URI" 2 \
    "$BIN" --output-http ftp://127.0.0.1:1/image uboot image list-commands --dev /dev/null --offset 0x0

run_exact_case "uboot image list-commands invalid global --output-http URI" 2 \
    "$BIN" --output-http http://127.0.0.1:1/image uboot image list-commands --dev /dev/null --offset 0x0

run_exact_case "uboot image list-commands rejects both global http and https targets" 2 \
    "$BIN" --output-http http://127.0.0.1:1/image --output-http https://127.0.0.1:1/image uboot image list-commands --dev /dev/null --offset 0x0

run_exact_case "uboot image list-commands rejects trailing positional arg" 2 \
    "$BIN" uboot image list-commands --dev /dev/null --offset 0x0 extra

help_log="$(mktemp /tmp/test_image_help.XXXXXX)"
run_with_output_override "$BIN" uboot image --help >"$help_log" 2>&1
if grep -q "/dev/mtd\*" "$help_log"; then
    echo "[FAIL] uboot image --help should not advertise /dev/mtd* scan targets"
    print_file_head_scrubbed "$help_log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
else
    echo "[PASS] uboot image --help only advertises /dev/mtdblock* for MTD scans"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
fi
rm -f "$help_log"

finish_tests
