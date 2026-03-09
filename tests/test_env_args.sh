#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$REPO_ROOT/uboot_audit"

# shellcheck source=tests/common.sh
. "$SCRIPT_DIR/common.sh"

require_binary "$BIN"
print_section "env subcommand argument coverage"

run_exact_case "env --help" 2 "$BIN" env --help
run_accept_case "env --output-format txt --size $TEST_SIZE" "$BIN" --output-format txt env --size "$TEST_SIZE" --verbose
run_accept_case "env --output-format csv --size $TEST_SIZE" "$BIN" --output-format csv env --size "$TEST_SIZE" --verbose
run_accept_case "env --output-format json --size $TEST_SIZE" "$BIN" --output-format json env --size "$TEST_SIZE" --verbose
run_accept_case "env --verbose --size $TEST_SIZE" "$BIN" env --verbose --size "$TEST_SIZE"
run_accept_case "env --size" "$BIN" env --size "$TEST_SIZE"
run_accept_case "env --hint --size $TEST_SIZE" "$BIN" env --hint bootcmd= --size "$TEST_SIZE"
run_accept_case "env --dev --size $TEST_SIZE" "$BIN" env --dev /dev/null --size "$TEST_SIZE"
run_accept_case "env --bruteforce --size $TEST_SIZE" "$BIN" env --bruteforce --size "$TEST_SIZE"
run_accept_case "env --skip-remove --size $TEST_SIZE" "$BIN" env --skip-remove --size "$TEST_SIZE"
run_accept_case "env --skip-mtd --size $TEST_SIZE" "$BIN" env --skip-mtd --size "$TEST_SIZE"
run_accept_case "env --skip-ubi --size $TEST_SIZE" "$BIN" env --skip-ubi --size "$TEST_SIZE"
run_accept_case "env --skip-sd --size $TEST_SIZE" "$BIN" env --skip-sd --size "$TEST_SIZE"
run_accept_case "env --skip-emmc --size $TEST_SIZE" "$BIN" env --skip-emmc --size "$TEST_SIZE"
run_accept_case "env --parse-vars --size $TEST_SIZE" "$BIN" env --parse-vars --size "$TEST_SIZE"
run_accept_case "env --output-config (implicit path) --size $TEST_SIZE" "$BIN" env --output-config --size "$TEST_SIZE"
run_accept_case "env --output-config=path --size $TEST_SIZE" "$BIN" env --output-config="$REPO_ROOT/tests/.tmp_fw_env.config" --size "$TEST_SIZE"
run_accept_case "env --output-tcp --size $TEST_SIZE" "$BIN" env --output-tcp 127.0.0.1:9 --size "$TEST_SIZE"
run_accept_case "env --output-http --size $TEST_SIZE" "$BIN" env --output-http http://127.0.0.1:1/env --size "$TEST_SIZE"
run_accept_case "env --output-https --size $TEST_SIZE" "$BIN" env --output-https https://127.0.0.1:1/env --size "$TEST_SIZE"
run_accept_case "env --insecure --size $TEST_SIZE" "$BIN" env --insecure --size "$TEST_SIZE"

if [ "$(id -u)" -ne 0 ]; then
    run_accept_case "env --write https URL (accepted before root check)" \
        "$BIN" env --write https://127.0.0.1/fw_setenv_script.txt
fi

if [ "$(id -u)" -eq 0 ]; then
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
    run_exact_case "env --parse-vars synthetic image" 0 \
        "$BIN" --output-format txt env --parse-vars --size "$TEST_SIZE" "$TMP_ENV_IMAGE:0x10000"
    rm -f "$TMP_ENV_IMAGE"
fi

rm -f "$REPO_ROOT/tests/.tmp_fw_env.config"
finish_tests
