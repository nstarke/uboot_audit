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
print_section "linux execute-command subcommand argument coverage"

script_file="$(mktemp /tmp/ela-script.XXXXXX)"
cat >"$script_file" <<'EOF_SCRIPT'
linux execute-command "echo hello"
linux execute-command "printf second"
EOF_SCRIPT
script_file_with_alias="$(mktemp /tmp/ela-script-alias.XXXXXX)"
cat >"$script_file_with_alias" <<'EOF_SCRIPT'
ela --output-format json linux execute-command "echo hello"
embedded_linux_audit --quiet linux execute-command "printf second"
EOF_SCRIPT
missing_script="/tmp/ela-missing-script-$$.txt"

trap 'rm -f "$script_file" "$script_file_with_alias"' EXIT INT TERM

run_exact_case "linux execute-command --help" 0 "$BIN" linux execute-command --help
run_exact_case "linux execute-command no args" 2 "$BIN" linux execute-command
run_exact_case "linux execute-command extra positional arg" 2 "$BIN" linux execute-command "echo hello" extra
run_exact_case "top-level --script missing value" 2 "$BIN" --script
run_exact_case "top-level --script cannot be combined with direct command" 2 "$BIN" --script "$script_file" linux execute-command "echo hello"
run_exact_case "top-level --script missing file" 2 "$BIN" --script "$missing_script"
run_accept_case "top-level --script local file" "$BIN" --script "$script_file"
run_accept_case "top-level --script local file with ela aliases" "$BIN" --script "$script_file_with_alias"
run_exact_case "linux execute-command invalid global --output-http" 2 "$BIN" --output-http ftp://127.0.0.1:1 linux execute-command "echo hello"
run_exact_case "linux execute-command invalid global --output-http" 2 "$BIN" --output-http http://127.0.0.1:1 linux execute-command "echo hello"
run_exact_case "linux execute-command both global http+https" 2 "$BIN" --output-http http://127.0.0.1:1 --output-http https://127.0.0.1:1 linux execute-command "echo hello"
run_exact_case "linux execute-command invalid global --output-tcp" 2 "$BIN" --output-tcp invalid-target linux execute-command "echo hello"
run_accept_case "linux execute-command ELA_API_URL http" env ELA_API_URL=http://127.0.0.1:1 "$BIN" linux execute-command "echo hello"
run_accept_case "linux execute-command ELA_API_URL https + ELA_API_INSECURE=true" env ELA_API_URL=https://127.0.0.1:1 ELA_API_INSECURE=true "$BIN" linux execute-command "echo hello"
run_exact_case "linux execute-command invalid ELA_API_URL" 2 env ELA_API_URL=ftp://127.0.0.1:1 "$BIN" linux execute-command "echo hello"
run_accept_case "linux execute-command ELA_OUTPUT_FORMAT json" env ELA_OUTPUT_FORMAT=json "$BIN" linux execute-command "echo hello"
run_exact_case "linux execute-command invalid ELA_OUTPUT_FORMAT" 2 env ELA_OUTPUT_FORMAT=xml "$BIN" linux execute-command "echo hello"
run_accept_case "linux execute-command ELA_QUIET true" env ELA_QUIET=true "$BIN" linux execute-command "echo hello"
run_exact_case "linux execute-command invalid ELA_OUTPUT_TCP" 2 env ELA_OUTPUT_TCP=invalid-target "$BIN" linux execute-command "echo hello"
run_accept_case "top-level ELA_SCRIPT local file" env ELA_SCRIPT="$script_file" "$BIN"

interactive_set_log="$(mktemp /tmp/test_interactive_set_env.XXXXXX)"
printf 'set ELA_OUTPUT_FORMAT json\nset ELA_QUIET true\nset ELA_OUTPUT_TCP 127.0.0.1:9\nset ELA_SCRIPT %s\nquit\n' "$script_file" | "$BIN" >"$interactive_set_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && \
   grep -q "ELA_OUTPUT_FORMAT=json" "$interactive_set_log" && \
   grep -q "ELA_QUIET=true" "$interactive_set_log" && \
   grep -q "ELA_OUTPUT_TCP=127.0.0.1:9" "$interactive_set_log" && \
   grep -q "ELA_SCRIPT=$script_file" "$interactive_set_log"; then
    echo "[PASS] interactive set updates global argument environment variables"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] interactive set updates global argument environment variables (rc=$rc)"
    print_file_head_scrubbed "$interactive_set_log" 120
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$interactive_set_log"

run_accept_case "linux execute-command txt" "$BIN" --output-format txt linux execute-command "echo hello"
run_accept_case "linux execute-command csv" "$BIN" --output-format csv linux execute-command "echo hello"
run_accept_case "linux execute-command json" "$BIN" --output-format json linux execute-command "echo hello"
run_accept_case "linux execute-command with --output-http" "$BIN" --output-http http://127.0.0.1:1 linux execute-command "echo hello"
run_accept_case "linux execute-command with --output-http" "$BIN" --output-http https://127.0.0.1:1 linux execute-command "echo hello"
run_accept_case "global --insecure linux execute-command" "$BIN" --insecure --output-http https://127.0.0.1:1 linux execute-command "echo hello"

log="$(mktemp /tmp/test_execute_command_lifecycle.XXXXXX)"
TEST_DISABLE_OUTPUT_OVERRIDE=1 run_with_output_override "$BIN" linux execute-command "echo hello" >"$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && \
   grep -Eq 'log agent_timestamp=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{4} phase=start command=linux execute-command echo hello rc=0' "$log" && \
   grep -Eq 'log agent_timestamp=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{4} phase=complete command=linux execute-command echo hello rc=0' "$log"; then
    echo "[PASS] linux execute-command emits lifecycle logs"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux execute-command emits lifecycle logs (rc=$rc)"
    print_file_head_scrubbed "$log" 120
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

finish_tests