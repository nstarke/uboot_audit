#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
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

print_section "linux tpm2 output format coverage"

run_accept_case "linux tpm2 --output-format txt" env PATH="$tpm2_fake_dir:$PATH" "$BIN" --output-format txt linux tpm2 getcap
run_accept_case "linux tpm2 --output-format csv" env PATH="$tpm2_fake_dir:$PATH" "$BIN" --output-format csv linux tpm2 getcap
run_accept_case "linux tpm2 --output-format json" env PATH="$tpm2_fake_dir:$PATH" "$BIN" --output-format json linux tpm2 getcap
run_exact_case "linux tpm2 invalid ELA_OUTPUT_FORMAT" 2 env PATH="$tpm2_fake_dir:$PATH" ELA_OUTPUT_FORMAT=xml "$BIN" linux tpm2 getcap

log="$(mktemp /tmp/test_linux_tpm2_fmt_txt.XXXXXX)"
env PATH="$tpm2_fake_dir:$PATH" "$BIN" --output-format txt linux tpm2 getcap >"$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q '^tpm2_getcap$' "$log" && grep -q 'fake getcap:' "$log"; then
	echo "[PASS] linux tpm2 txt format prefixes command name on its own line"
	PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
	echo "[FAIL] linux tpm2 txt format prefixes command name on its own line (rc=$rc)"
	print_file_head_scrubbed "$log" 80
	FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

log="$(mktemp /tmp/test_linux_tpm2_fmt_csv.XXXXXX)"
env PATH="$tpm2_fake_dir:$PATH" "$BIN" --output-format csv linux tpm2 getcap >"$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q '"tpm2_getcap"' "$log"; then
	echo "[PASS] linux tpm2 csv format wraps command name in CSV field"
	PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
	echo "[FAIL] linux tpm2 csv format wraps command name in CSV field (rc=$rc)"
	print_file_head_scrubbed "$log" 80
	FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

log="$(mktemp /tmp/test_linux_tpm2_fmt_json.XXXXXX)"
env PATH="$tpm2_fake_dir:$PATH" "$BIN" --output-format json linux tpm2 getcap >"$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q '"command":"tpm2_getcap"' "$log"; then
	echo "[PASS] linux tpm2 json format wraps output as JSON object"
	PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
	echo "[FAIL] linux tpm2 json format wraps output as JSON object (rc=$rc)"
	print_file_head_scrubbed "$log" 80
	FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

log="$(mktemp /tmp/test_linux_tpm2_list_fmt_txt.XXXXXX)"
env PATH="$tpm2_fake_dir:$PATH" "$BIN" --output-format txt linux tpm2 list-commands >"$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q '^list-commands$' "$log" && grep -q '^getcap$' "$log"; then
	echo "[PASS] linux tpm2 list-commands txt format prefixes list-commands header"
	PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
	echo "[FAIL] linux tpm2 list-commands txt format prefixes list-commands header (rc=$rc)"
	print_file_head_scrubbed "$log" 80
	FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

log="$(mktemp /tmp/test_linux_tpm2_list_fmt_json.XXXXXX)"
env PATH="$tpm2_fake_dir:$PATH" "$BIN" --output-format json linux tpm2 list-commands >"$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q '"command":"list-commands"' "$log"; then
	echo "[PASS] linux tpm2 list-commands json format"
	PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
	echo "[FAIL] linux tpm2 list-commands json format (rc=$rc)"
	print_file_head_scrubbed "$log" 80
	FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

print_section "linux tpm2 additional command delegation coverage"

cat >"$tpm2_fake_dir/tpm2_nvreadpublic" <<'EOF_NVREADPUBLIC'
#!/bin/sh
echo "fake nvreadpublic:$*"
exit 0
EOF_NVREADPUBLIC
chmod +x "$tpm2_fake_dir/tpm2_nvreadpublic"

cat >"$tpm2_fake_dir/tpm2_getrandom" <<'EOF_GETRANDOM'
#!/bin/sh
echo "fake getrandom:$*"
exit 0
EOF_GETRANDOM
chmod +x "$tpm2_fake_dir/tpm2_getrandom"

cat >"$tpm2_fake_dir/tpm2_readpublic" <<'EOF_READPUBLIC'
#!/bin/sh
echo "fake readpublic:$*"
exit 0
EOF_READPUBLIC
chmod +x "$tpm2_fake_dir/tpm2_readpublic"

cat >"$tpm2_fake_dir/tpm2_quote" <<'EOF_QUOTE'
#!/bin/sh
echo "fake quote:$*"
exit 0
EOF_QUOTE
chmod +x "$tpm2_fake_dir/tpm2_quote"

cat >"$tpm2_fake_dir/tpm2_pcrextend" <<'EOF_PCREXTEND'
#!/bin/sh
echo "fake pcrextend:$*"
exit 0
EOF_PCREXTEND
chmod +x "$tpm2_fake_dir/tpm2_pcrextend"

cat >"$tpm2_fake_dir/tpm2_flushcontext" <<'EOF_FLUSHCONTEXT'
#!/bin/sh
echo "fake flushcontext error:$*" >&2
exit 1
EOF_FLUSHCONTEXT
chmod +x "$tpm2_fake_dir/tpm2_flushcontext"

log="$(mktemp /tmp/test_linux_tpm2_pcrread_delegation.XXXXXX)"
env PATH="$tpm2_fake_dir:$PATH" "$BIN" linux tpm2 pcrread sha256:0,1,2 >"$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q 'fake pcrread:sha256:0,1,2' "$log"; then
	echo "[PASS] linux tpm2 delegates pcrread with bank:pcr selector args"
	PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
	echo "[FAIL] linux tpm2 delegates pcrread with bank:pcr selector args (rc=$rc)"
	print_file_head_scrubbed "$log" 80
	FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

log="$(mktemp /tmp/test_linux_tpm2_createprimary_delegation.XXXXXX)"
env PATH="$tpm2_fake_dir:$PATH" "$BIN" linux tpm2 createprimary -C o -g sha256 -G rsa >"$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q 'fake createprimary:-C o -g sha256 -G rsa' "$log"; then
	echo "[PASS] linux tpm2 delegates createprimary with multiple flags"
	PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
	echo "[FAIL] linux tpm2 delegates createprimary with multiple flags (rc=$rc)"
	print_file_head_scrubbed "$log" 80
	FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

log="$(mktemp /tmp/test_linux_tpm2_nvreadpublic.XXXXXX)"
env PATH="$tpm2_fake_dir:$PATH" "$BIN" linux tpm2 nvreadpublic >"$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q 'fake nvreadpublic:' "$log"; then
	echo "[PASS] linux tpm2 delegates nvreadpublic to tpm2_nvreadpublic"
	PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
	echo "[FAIL] linux tpm2 delegates nvreadpublic to tpm2_nvreadpublic (rc=$rc)"
	print_file_head_scrubbed "$log" 80
	FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

log="$(mktemp /tmp/test_linux_tpm2_getrandom.XXXXXX)"
env PATH="$tpm2_fake_dir:$PATH" "$BIN" linux tpm2 getrandom 32 >"$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q 'fake getrandom:32' "$log"; then
	echo "[PASS] linux tpm2 delegates getrandom with byte count arg"
	PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
	echo "[FAIL] linux tpm2 delegates getrandom with byte count arg (rc=$rc)"
	print_file_head_scrubbed "$log" 80
	FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

log="$(mktemp /tmp/test_linux_tpm2_readpublic.XXXXXX)"
env PATH="$tpm2_fake_dir:$PATH" "$BIN" linux tpm2 readpublic -c 0x81010001 >"$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q 'fake readpublic:-c 0x81010001' "$log"; then
	echo "[PASS] linux tpm2 delegates readpublic with handle arg"
	PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
	echo "[FAIL] linux tpm2 delegates readpublic with handle arg (rc=$rc)"
	print_file_head_scrubbed "$log" 80
	FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

log="$(mktemp /tmp/test_linux_tpm2_quote.XXXXXX)"
env PATH="$tpm2_fake_dir:$PATH" "$BIN" linux tpm2 quote -l sha256:0,1,2 >"$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q 'fake quote:-l sha256:0,1,2' "$log"; then
	echo "[PASS] linux tpm2 delegates quote with PCR selection arg"
	PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
	echo "[FAIL] linux tpm2 delegates quote with PCR selection arg (rc=$rc)"
	print_file_head_scrubbed "$log" 80
	FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

log="$(mktemp /tmp/test_linux_tpm2_pcrextend.XXXXXX)"
env PATH="$tpm2_fake_dir:$PATH" "$BIN" linux tpm2 pcrextend 0:sha256=0000000000000000000000000000000000000000000000000000000000000000 >"$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q 'fake pcrextend:' "$log"; then
	echo "[PASS] linux tpm2 delegates pcrextend with pcr:alg=value arg"
	PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
	echo "[FAIL] linux tpm2 delegates pcrextend with pcr:alg=value arg (rc=$rc)"
	print_file_head_scrubbed "$log" 80
	FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

run_exact_case "linux tpm2 propagates non-zero exit from delegated command" 1 \
	env PATH="$tpm2_fake_dir:$PATH" "$BIN" linux tpm2 flushcontext

log="$(mktemp /tmp/test_linux_tpm2_list_extended.XXXXXX)"
env PATH="$tpm2_fake_dir:$PATH" "$BIN" linux tpm2 list-commands >"$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && \
   grep -q '^nvreadpublic$' "$log" && \
   grep -q '^getrandom$' "$log" && \
   grep -q '^readpublic$' "$log" && \
   grep -q '^quote$' "$log" && \
   grep -q '^pcrextend$' "$log" && \
   grep -q '^flushcontext$' "$log"; then
	echo "[PASS] linux tpm2 list-commands includes all installed tools"
	PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
	echo "[FAIL] linux tpm2 list-commands includes all installed tools (rc=$rc)"
	print_file_head_scrubbed "$log" 80
	FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

print_section "linux tpm2 output transport and global flag coverage"

run_exact_case "linux tpm2 invalid --output-http scheme" 2 "$BIN" --output-http ftp://127.0.0.1:1 linux tpm2 list-commands
run_exact_case "linux tpm2 invalid --output-tcp target" 2 env PATH="$tpm2_fake_dir:$PATH" "$BIN" --output-tcp invalid-target linux tpm2 getcap
run_exact_case "linux tpm2 invalid ELA_OUTPUT_TCP" 2 env PATH="$tpm2_fake_dir:$PATH" ELA_OUTPUT_TCP=invalid-target "$BIN" linux tpm2 getcap
run_accept_case "linux tpm2 --output-http unreachable endpoint" env PATH="$tpm2_fake_dir:$PATH" "$BIN" --output-http http://127.0.0.1:1 linux tpm2 getcap
run_accept_case "linux tpm2 --insecure with --output-http" env PATH="$tpm2_fake_dir:$PATH" "$BIN" --insecure --output-http https://127.0.0.1:1 linux tpm2 getcap
run_accept_case "linux tpm2 --quiet" env PATH="$tpm2_fake_dir:$PATH" "$BIN" --quiet linux tpm2 getcap
run_accept_case "linux tpm2 ELA_QUIET=true" env PATH="$tpm2_fake_dir:$PATH" ELA_QUIET=true "$BIN" linux tpm2 getcap
run_accept_case "linux tpm2 ELA_API_URL http unreachable" env PATH="$tpm2_fake_dir:$PATH" ELA_API_URL=http://127.0.0.1:1 "$BIN" linux tpm2 getcap

finish_tests
