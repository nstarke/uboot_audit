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

rm -f "$REPO_ROOT/tests/.tmp_fw_env.config"
finish_tests
