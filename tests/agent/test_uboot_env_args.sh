#!/bin/sh

set -u
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
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
print_section "uboot env subcommand argument coverage"

run_exact_case "uboot env --help" 2 "$BIN" uboot env --help
run_accept_case "uboot env --output-format txt --size $TEST_SIZE" "$BIN" --output-format txt uboot env --size "$TEST_SIZE" --verbose
run_accept_case "uboot env --output-format csv --size $TEST_SIZE" "$BIN" --output-format csv uboot env --size "$TEST_SIZE" --verbose
run_accept_case "uboot env --output-format json --size $TEST_SIZE" "$BIN" --output-format json uboot env --size "$TEST_SIZE" --verbose
run_accept_case "uboot env --verbose --size $TEST_SIZE" "$BIN" uboot env --verbose --size "$TEST_SIZE"
run_accept_case "uboot env --size" "$BIN" uboot env --size "$TEST_SIZE"
run_accept_case "uboot env --hint --size $TEST_SIZE" "$BIN" uboot env --hint bootcmd= --size "$TEST_SIZE"
run_accept_case "uboot env --dev --size $TEST_SIZE" "$BIN" uboot env --dev /dev/null --size "$TEST_SIZE"
run_accept_case "uboot env --bruteforce --size $TEST_SIZE" "$BIN" uboot env --bruteforce --size "$TEST_SIZE"
run_accept_case "uboot env --skip-remove --size $TEST_SIZE" "$BIN" uboot env --skip-remove --size "$TEST_SIZE"
run_accept_case "uboot env --skip-mtd --size $TEST_SIZE" "$BIN" uboot env --skip-mtd --size "$TEST_SIZE"
run_accept_case "uboot env --skip-ubi --size $TEST_SIZE" "$BIN" uboot env --skip-ubi --size "$TEST_SIZE"
run_accept_case "uboot env --skip-sd --size $TEST_SIZE" "$BIN" uboot env --skip-sd --size "$TEST_SIZE"
run_accept_case "uboot env --skip-emmc --size $TEST_SIZE" "$BIN" uboot env --skip-emmc --size "$TEST_SIZE"
run_accept_case "uboot env read-vars --size $TEST_SIZE" "$BIN" uboot env read-vars --size "$TEST_SIZE"
run_accept_case "uboot env --output-config (implicit path) --size $TEST_SIZE" "$BIN" uboot env --output-config --size "$TEST_SIZE"
run_accept_case "uboot env --output-config=path --size $TEST_SIZE" "$BIN" uboot env --output-config="$REPO_ROOT/tests/.tmp_fw_env.config" --size "$TEST_SIZE"
run_accept_case "uboot env global --output-tcp --size $TEST_SIZE" "$BIN" --output-tcp 127.0.0.1:9 uboot env --size "$TEST_SIZE"
run_accept_case "uboot env global --output-http --size $TEST_SIZE" "$BIN" --output-http http://127.0.0.1:1/env uboot env --size "$TEST_SIZE"
run_accept_case "uboot env global --output-https --size $TEST_SIZE" "$BIN" --output-https https://127.0.0.1:1/env uboot env --size "$TEST_SIZE"
run_accept_case "--insecure uboot env --size $TEST_SIZE" "$BIN" --insecure uboot env --size "$TEST_SIZE"
run_exact_case "uboot env invalid --size" 2 "$BIN" uboot env --size nope
run_accept_case "uboot env invalid global --output-http reaches pre-root path" "$BIN" --output-http ftp://127.0.0.1:1/env uboot env --size "$TEST_SIZE"
run_accept_case "uboot env invalid global --output-https reaches pre-root path" "$BIN" --output-https http://127.0.0.1:1/env uboot env --size "$TEST_SIZE"
run_accept_case "uboot env both global http+https reaches pre-root path" "$BIN" --output-http http://127.0.0.1:1/env --output-https https://127.0.0.1:1/env uboot env --size "$TEST_SIZE"
run_accept_case "uboot env rejects raw mtd char device after root check path" "$BIN" uboot env --dev /dev/mtd0 --size "$TEST_SIZE"

if [ "$(current_uid)" -ne 0 ]; then
    run_accept_case "uboot env write-vars https URL (accepted before root check)" \
        "$BIN" uboot env write-vars https://127.0.0.1/fw_setenv_script.txt
fi

run_accept_case "uboot env write missing path reaches pre-root path" "$BIN" uboot env write

if [ "$(current_uid)" -eq 0 ]; then
    TMP_ENV_IMAGE="$(mktemp /tmp/uboot_env_parse_vars.XXXXXX.bin)"
    python3 - "$TMP_ENV_IMAGE" <<'PY'
import binascii
import struct
import sys

path = sys.argv[1]
env_size = 0x10000
data = bytearray(b'\x00' * (env_size - 4))
payload = b'bootcmd=run distro_bootcmd\x00baudrate=115200\x00\x00'
data[:len(payload)] = payload
crc = binascii.crc32(data) & 0xFFFFFFFF
image = struct.pack('<I', crc) + data

with open(path, 'wb') as f:
    f.write(image)
PY
    run_exact_case "uboot env read-vars synthetic image" 0 \
        "$BIN" --output-format txt uboot env read-vars --size "$TEST_SIZE" "$TMP_ENV_IMAGE:0x10000"
    rm -f "$TMP_ENV_IMAGE"
fi

rm -f "$REPO_ROOT/tests/.tmp_fw_env.config"
finish_tests
