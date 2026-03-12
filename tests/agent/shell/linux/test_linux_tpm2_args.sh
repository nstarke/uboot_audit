#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "linux tpm2 subcommand argument coverage"

run_exact_case "linux tpm2 --help" 0 "$BIN" linux tpm2 --help
run_exact_case "linux tpm2 no args" 2 "$BIN" linux tpm2
run_exact_case "linux tpm2 list-commands extra arg" 2 "$BIN" linux tpm2 list-commands extra

tpm2_fake_dir="$(mktemp -d /tmp/ela-tpm2-path.XXXXXX)"
trap 'rm -rf "$tpm2_fake_dir"' EXIT INT TERM

cat >"$tpm2_fake_dir/tpm2_getcap" <<'EOF_GETCAP'
#!/bin/sh
echo "fake getcap:$*"
exit 0
EOF_GETCAP
chmod +x "$tpm2_fake_dir/tpm2_getcap"

cat >"$tpm2_fake_dir/tpm2_pcrread" <<'EOF_PCRREAD'
#!/bin/sh
echo "fake pcrread:$*"
exit 0
EOF_PCRREAD
chmod +x "$tpm2_fake_dir/tpm2_pcrread"

cat >"$tpm2_fake_dir/tpm2_createprimary" <<'EOF_CREATEPRIMARY'
#!/bin/sh
echo "fake createprimary:$*"
exit 0
EOF_CREATEPRIMARY
chmod +x "$tpm2_fake_dir/tpm2_createprimary"

log="$(mktemp /tmp/test_linux_tpm2_getcap.XXXXXX)"
env PATH="$tpm2_fake_dir:$PATH" "$BIN" linux tpm2 getcap properties-fixed >"$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q 'fake getcap:properties-fixed' "$log"; then
    echo "[PASS] linux tpm2 delegates getcap to tpm2_getcap"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux tpm2 delegates getcap to tpm2_getcap (rc=$rc)"
    print_file_head_scrubbed "$log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

log="$(mktemp /tmp/test_linux_tpm2_list_commands.XXXXXX)"
env PATH="$tpm2_fake_dir:$PATH" "$BIN" linux tpm2 list-commands >"$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && \
   grep -q '^createprimary$' "$log" && \
   grep -q '^getcap$' "$log" && \
   grep -q '^pcrread$' "$log"; then
    echo "[PASS] linux tpm2 list-commands enumerates installed tpm2 tools"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux tpm2 list-commands enumerates installed tpm2 tools (rc=$rc)"
    print_file_head_scrubbed "$log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

run_exact_case "linux tpm2 missing delegated command" 127 env PATH="$tpm2_fake_dir:$PATH" "$BIN" linux tpm2 nvreadpublic

finish_tests