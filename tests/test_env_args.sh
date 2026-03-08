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
run_accept_case "env --verbose" "$BIN" env --verbose
run_accept_case "env --size" "$BIN" env --size "$TEST_SIZE"
run_accept_case "env --hint" "$BIN" env --hint bootcmd=
run_accept_case "env --dev" "$BIN" env --dev /dev/null
run_accept_case "env --brutefoce" "$BIN" env --brutefoce
run_accept_case "env --bruteforce" "$BIN" env --bruteforce
run_accept_case "env --skip-remove" "$BIN" env --skip-remove
run_accept_case "env --skip-mtd" "$BIN" env --skip-mtd
run_accept_case "env --skip-ubi" "$BIN" env --skip-ubi
run_accept_case "env --skip-sd" "$BIN" env --skip-sd
run_accept_case "env --skip-emmc" "$BIN" env --skip-emmc
run_accept_case "env --parse-vars" "$BIN" env --parse-vars
run_accept_case "env --output-config (implicit path)" "$BIN" env --output-config
run_accept_case "env --output-config=path" "$BIN" env --output-config="$REPO_ROOT/tests/.tmp_fw_env.config"
run_accept_case "env --output-tcp" "$BIN" env --output-tcp 127.0.0.1:9
run_accept_case "env --output-http" "$BIN" env --output-http http://127.0.0.1:1/env
run_accept_case "env --output-https" "$BIN" env --output-https https://127.0.0.1:1/env
run_accept_case "env --insecure" "$BIN" env --insecure

rm -f "$REPO_ROOT/tests/.tmp_fw_env.config"
finish_tests
