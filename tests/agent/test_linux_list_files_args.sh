#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
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
print_section "linux list-files subcommand argument coverage"

TMP_DIR="$(mktemp -d /tmp/test_list_files_args.XXXXXX)"
TMP_SUBDIR="$TMP_DIR/subdir"
TMP_TOP_FILE="$TMP_DIR/top.txt"
TMP_TOP_SUID_FILE="$TMP_DIR/top-suid.sh"
TMP_TOP_600_FILE="$TMP_DIR/top-600.txt"
TMP_FILE="$TMP_SUBDIR/sample.txt"
TMP_SUID_FILE="$TMP_SUBDIR/suid-sample.sh"
CURRENT_USER="$(current_user_name)"
CURRENT_GROUP="$(current_group_name)"
mkdir -p "$TMP_SUBDIR"
cat >"$TMP_TOP_FILE" <<'EOF_TOP'
top
EOF_TOP
cat >"$TMP_TOP_SUID_FILE" <<'EOF_TOP_SUID'
#!/bin/sh
exit 0
EOF_TOP_SUID
chmod 4755 "$TMP_TOP_SUID_FILE"
cat >"$TMP_TOP_600_FILE" <<'EOF_TOP_600'
private
EOF_TOP_600
chmod 0600 "$TMP_TOP_600_FILE"
cat >"$TMP_FILE" <<'EOF_SAMPLE'
sample
EOF_SAMPLE
cat >"$TMP_SUID_FILE" <<'EOF_SUID'
#!/bin/sh
exit 0
EOF_SUID
chmod 4755 "$TMP_SUID_FILE"

run_exact_case "linux list-files --help" 0 "$BIN" --verbose linux list-files --help
run_exact_case "linux list-files relative path" 2 "$BIN" --verbose linux list-files ./relative
run_exact_case "linux list-files file path" 2 "$BIN" --verbose linux list-files "$TMP_FILE"
run_exact_case "linux list-files invalid global --output-http" 2 "$BIN" --verbose --output-http ftp://127.0.0.1:1/file-list linux list-files "$TMP_DIR"
run_exact_case "linux list-files invalid global --output-https" 2 "$BIN" --verbose --output-https http://127.0.0.1:1/file-list linux list-files "$TMP_DIR"
run_exact_case "linux list-files both global http+https" 2 "$BIN" --verbose --output-http http://127.0.0.1:1/file-list --output-https https://127.0.0.1:1/file-list linux list-files "$TMP_DIR"
run_exact_case "linux list-files invalid global --output-tcp" 2 "$BIN" --verbose --output-tcp invalid-target linux list-files "$TMP_DIR"
run_exact_case "linux list-files extra positional argument" 2 "$BIN" --verbose linux list-files "$TMP_DIR" /tmp/extra
run_exact_case "linux list-files invalid --permissions" 2 "$BIN" --verbose linux list-files "$TMP_DIR" --permissions invalid
run_exact_case "linux list-files invalid symbolic --permissions" 2 "$BIN" --verbose linux list-files "$TMP_DIR" --permissions u+
run_exact_case "linux list-files invalid --user" 2 "$BIN" --verbose linux list-files "$TMP_DIR" --user this-user-should-not-exist-fw-scan
run_exact_case "linux list-files invalid --group" 2 "$BIN" --verbose linux list-files "$TMP_DIR" --group this-group-should-not-exist-fw-scan

run_exact_case "linux list-files no directory argument defaults to /" 0 "$BIN" --verbose linux list-files
run_exact_case "linux list-files local directory" 0 "$BIN" --verbose linux list-files "$TMP_DIR"
run_exact_case "linux list-files --recursive" 0 "$BIN" --verbose linux list-files "$TMP_DIR" --recursive
run_exact_case "linux list-files --suid-only" 0 "$BIN" --verbose linux list-files "$TMP_DIR" --suid-only
run_exact_case "linux list-files --recursive --suid-only" 0 "$BIN" --verbose linux list-files "$TMP_DIR" --recursive --suid-only
run_exact_case "linux list-files --permissions octal" 0 "$BIN" --verbose linux list-files "$TMP_DIR" --permissions 0600
run_exact_case "linux list-files --permissions symbolic" 0 "$BIN" --verbose linux list-files "$TMP_DIR" --permissions u+rw,go-rwx
run_exact_case "linux list-files --user" 0 "$BIN" --verbose linux list-files "$TMP_DIR" --user "$CURRENT_USER"
run_exact_case "linux list-files --group" 0 "$BIN" --verbose linux list-files "$TMP_DIR" --group "$CURRENT_GROUP"
run_accept_case "linux list-files global --output-http" "$BIN" --verbose --output-http http://127.0.0.1:1/file-list linux list-files "$TMP_DIR"
run_accept_case "linux list-files global --output-https" "$BIN" --verbose --output-https https://127.0.0.1:1/file-list linux list-files "$TMP_DIR"
tcp_log="$(mktemp /tmp/test_list_files_tcp.XXXXXX)"
"$BIN" --verbose --output-tcp 127.0.0.1:9 linux list-files "$TMP_DIR" >"$tcp_log" 2>&1
rc=$?
if [ "$rc" -eq 2 ] && grep -q "Invalid/failed output target (expected IPv4:port): 127.0.0.1:9" "$tcp_log"; then
    echo "[PASS] linux list-files global --output-tcp reaches TCP output validation path"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-files global --output-tcp reaches TCP output validation path (rc=$rc)"
    sed -n '1,80p' "$tcp_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$tcp_log"
run_accept_case "--insecure linux list-files global --output-https" "$BIN" --insecure --verbose --output-https https://127.0.0.1:1/file-list linux list-files "$TMP_DIR"

run_accept_case "linux list-files with --output-format txt" "$BIN" --output-format txt --verbose linux list-files "$TMP_DIR"
run_accept_case "linux list-files with --output-format csv" "$BIN" --output-format csv --verbose linux list-files "$TMP_DIR"
run_accept_case "linux list-files with --output-format json" "$BIN" --output-format json --verbose linux list-files "$TMP_DIR"

local_log="$(mktemp /tmp/test_list_files_local.XXXXXX)"
"$BIN" --verbose linux list-files "$TMP_DIR" >"$local_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && file_has_exact_line "$TMP_TOP_FILE" "$local_log" && ! file_has_exact_line "$TMP_FILE" "$local_log"; then
    echo "[PASS] linux list-files default listing stays non-recursive"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-files default listing stays non-recursive (rc=$rc)"
    sed -n '1,80p' "$local_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$local_log"

recursive_log="$(mktemp /tmp/test_list_files_recursive.XXXXXX)"
"$BIN" --verbose linux list-files "$TMP_DIR" --recursive >"$recursive_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && file_has_exact_line "$TMP_TOP_FILE" "$recursive_log" && file_has_exact_line "$TMP_FILE" "$recursive_log"; then
    echo "[PASS] linux list-files --recursive includes nested files"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-files --recursive includes nested files (rc=$rc)"
    sed -n '1,80p' "$recursive_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$recursive_log"

suid_log="$(mktemp /tmp/test_list_files_suid.XXXXXX)"
"$BIN" --verbose linux list-files "$TMP_DIR" --suid-only >"$suid_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && file_has_exact_line "$TMP_TOP_SUID_FILE" "$suid_log" && ! file_has_exact_line "$TMP_SUID_FILE" "$suid_log" && ! file_has_exact_line "$TMP_FILE" "$suid_log"; then
    echo "[PASS] linux list-files --suid-only filters non-SUID files"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-files --suid-only filters non-SUID files (rc=$rc)"
    sed -n '1,80p' "$suid_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$suid_log"

recursive_suid_log="$(mktemp /tmp/test_list_files_recursive_suid.XXXXXX)"
"$BIN" --verbose linux list-files "$TMP_DIR" --recursive --suid-only >"$recursive_suid_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && file_has_exact_line "$TMP_TOP_SUID_FILE" "$recursive_suid_log" && file_has_exact_line "$TMP_SUID_FILE" "$recursive_suid_log" && ! file_has_exact_line "$TMP_FILE" "$recursive_suid_log"; then
    echo "[PASS] linux list-files --recursive --suid-only includes nested SUID files only"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-files --recursive --suid-only includes nested SUID files only (rc=$rc)"
    sed -n '1,80p' "$recursive_suid_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$recursive_suid_log"

perm_octal_log="$(mktemp /tmp/test_list_files_perm_octal.XXXXXX)"
"$BIN" --verbose linux list-files "$TMP_DIR" --permissions 0600 >"$perm_octal_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && file_has_exact_line "$TMP_TOP_600_FILE" "$perm_octal_log" && ! file_has_exact_line "$TMP_TOP_FILE" "$perm_octal_log" && ! file_has_exact_line "$TMP_TOP_SUID_FILE" "$perm_octal_log"; then
    echo "[PASS] linux list-files --permissions octal filters exact mode"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-files --permissions octal filters exact mode (rc=$rc)"
    sed -n '1,80p' "$perm_octal_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$perm_octal_log"

perm_symbolic_log="$(mktemp /tmp/test_list_files_perm_symbolic.XXXXXX)"
"$BIN" --verbose linux list-files "$TMP_DIR" --permissions u+rw,go-rwx >"$perm_symbolic_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && file_has_exact_line "$TMP_TOP_600_FILE" "$perm_symbolic_log" && ! file_has_exact_line "$TMP_TOP_FILE" "$perm_symbolic_log" && ! file_has_exact_line "$TMP_TOP_SUID_FILE" "$perm_symbolic_log"; then
    echo "[PASS] linux list-files --permissions symbolic filters matching permissions"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-files --permissions symbolic filters matching permissions (rc=$rc)"
    sed -n '1,80p' "$perm_symbolic_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$perm_symbolic_log"

user_log="$(mktemp /tmp/test_list_files_user.XXXXXX)"
"$BIN" --verbose linux list-files "$TMP_DIR" --user "$CURRENT_USER" >"$user_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && file_has_exact_line "$TMP_TOP_FILE" "$user_log" && file_has_exact_line "$TMP_TOP_SUID_FILE" "$user_log" && file_has_exact_line "$TMP_TOP_600_FILE" "$user_log"; then
    echo "[PASS] linux list-files --user filters by owner"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-files --user filters by owner (rc=$rc)"
    sed -n '1,80p' "$user_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$user_log"

group_log="$(mktemp /tmp/test_list_files_group.XXXXXX)"
"$BIN" --verbose linux list-files "$TMP_DIR" --group "$CURRENT_GROUP" >"$group_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && file_has_exact_line "$TMP_TOP_FILE" "$group_log" && file_has_exact_line "$TMP_TOP_SUID_FILE" "$group_log" && file_has_exact_line "$TMP_TOP_600_FILE" "$group_log"; then
    echo "[PASS] linux list-files --group filters by group"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-files --group filters by group (rc=$rc)"
    sed -n '1,80p' "$group_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$group_log"

warn_log="$(mktemp /tmp/test_list_files_warn.XXXXXX)"
"$BIN" --output-format json --verbose linux list-files --help >"$warn_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q "Warning: --output-format has no effect for list-files" "$warn_log"; then
    echo "[PASS] linux list-files warns when --output-format is set"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-files warns when --output-format is set (rc=$rc)"
    sed -n '1,80p' "$warn_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$warn_log"

rm -rf "$TMP_DIR"
finish_tests