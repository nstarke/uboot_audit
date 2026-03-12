#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
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
print_section "uboot audit subcommand argument coverage"

TMP_DIR="$(mktemp -d /tmp/test_audit_args.XXXXXX)"
TMP_BLOB="$TMP_DIR/sample.fit"
TMP_PEM="$TMP_DIR/sample.pem"
TMP_AUDIT_DEV="$TMP_DIR/audit_input.bin"
echo 'fit-placeholder' >"$TMP_BLOB"
dd if=/dev/zero of="$TMP_AUDIT_DEV" bs=1 count=65536 >/dev/null 2>&1
cat >"$TMP_PEM" <<'PEM'
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK6y8l6P0w8Q3Xj2sI8hXk7wQ+9QmVqX
FJdGAr5e3g7r5gq2k4J2Y9h6QvVQ6j0S6s7n4i4Nf2n2PqY9sI7rXgsCAwEAAQ==
-----END PUBLIC KEY-----
PEM

run_exact_case "uboot audit --help" 0 "$BIN" uboot audit --help
run_accept_case "uboot audit --list-rules" "$BIN" uboot audit --list-rules

for output_format in txt csv json
do
    run_accept_case "uboot audit --list-rules with --output-format ${output_format}" \
        "$BIN" --output-format "$output_format" uboot audit --list-rules
done

run_accept_case "uboot audit required args: --dev --size" \
    "$BIN" uboot audit --dev /dev/null --size "$TEST_SIZE"

run_accept_case "uboot audit defaults --size to 0x10000 when omitted" \
    "$BIN" uboot audit --dev /dev/null

run_accept_case "uboot audit without --dev scans devices and writes fw_env.config" \
    "$BIN" uboot audit

run_exact_case "uboot audit without --dev but with --size requires --dev" 2 \
    "$BIN" uboot audit --size "$TEST_SIZE"

for output_format in txt csv json
do
    run_accept_case "uboot audit (no --rule) with --output-format ${output_format}" \
        "$BIN" --output-format "$output_format" uboot audit --dev /dev/null --size "$TEST_SIZE"

    run_accept_case "uboot audit --offset (no --rule) with --output-format ${output_format}" \
        "$BIN" --output-format "$output_format" uboot audit --dev /dev/null --offset 0x0 --size "$TEST_SIZE"
done

run_accept_case "uboot audit --rule uboot_validate_crc32" \
    "$BIN" uboot audit --rule uboot_validate_crc32 --dev /dev/null --size "$TEST_SIZE"

run_accept_case "uboot audit --rule uboot_validate_env_writeability" \
    "$BIN" uboot audit --rule uboot_validate_env_writeability --dev /dev/null --size "$TEST_SIZE"

run_accept_case "uboot audit --rule uboot_validate_env_security" \
    "$BIN" uboot audit --rule uboot_validate_env_security --dev /dev/null --size "$TEST_SIZE"

run_accept_case "uboot audit --rule uboot_validate_cmdline_init_writeability" \
    "$BIN" uboot audit --rule uboot_validate_cmdline_init_writeability --dev /dev/null --size "$TEST_SIZE"

run_accept_case "uboot audit --rule uboot_validate_secureboot" \
    "$BIN" uboot audit --rule uboot_validate_secureboot --dev /dev/null --size "$TEST_SIZE"

for rule in \
    uboot_validate_crc32 \
    uboot_validate_env_writeability \
    uboot_validate_env_security \
    uboot_validate_cmdline_init_writeability \
    uboot_validate_secureboot
do
    for output_format in txt csv json
    do
        run_accept_case "uboot audit --rule ${rule} with --output-format ${output_format}" \
            "$BIN" --output-format "$output_format" uboot audit --rule "$rule" --dev /dev/null --size "$TEST_SIZE"
    done
done

run_accept_case "uboot audit --offset" \
    "$BIN" uboot audit --dev /dev/null --offset 0x0 --size "$TEST_SIZE"

run_accept_case "uboot audit --signature-blob" \
    "$BIN" uboot audit --dev /dev/null --size "$TEST_SIZE" --signature-blob "$TMP_BLOB"

run_accept_case "uboot audit --signature-pubkey" \
    "$BIN" uboot audit --dev /dev/null --size "$TEST_SIZE" --signature-pubkey "$TMP_PEM"

run_accept_case "uboot audit --scan-signature-devices" \
    "$BIN" uboot audit --dev /dev/null --size "$TEST_SIZE" --scan-signature-devices

run_accept_case "uboot audit --scan-signature-blob" \
    "$BIN" uboot audit --dev /dev/null --size "$TEST_SIZE" --scan-signature-blob "$TMP_DIR/*.fit"

run_accept_case "uboot audit --scan-signature-pubkey" \
    "$BIN" uboot audit --dev /dev/null --size "$TEST_SIZE" --scan-signature-pubkey "$TMP_DIR/*.pem"

run_accept_case "uboot audit --signature-alg" \
    "$BIN" uboot audit --dev /dev/null --size "$TEST_SIZE" --signature-alg sha256

run_accept_case "uboot audit default verbose" \
    "$BIN" uboot audit --dev /dev/null --size "$TEST_SIZE"

run_accept_case "uboot audit --output-tcp" \
    "$BIN" uboot audit --dev /dev/null --size "$TEST_SIZE" --output-tcp 127.0.0.1:9

run_accept_case "uboot audit --output-http" \
    "$BIN" uboot audit --dev /dev/null --size "$TEST_SIZE" --output-http http://127.0.0.1:1/audit

run_accept_case "uboot audit --output-http" \
    "$BIN" uboot audit --dev /dev/null --size "$TEST_SIZE" --output-http https://127.0.0.1:1/audit

run_accept_case "--insecure uboot audit" \
    "$BIN" --insecure uboot audit --dev /dev/null --size "$TEST_SIZE"

run_exact_case "uboot audit invalid --size" 2 \
    "$BIN" uboot audit --dev /dev/null --size nope

run_exact_case "uboot audit invalid --offset" 2 \
    "$BIN" uboot audit --dev /dev/null --offset nope --size "$TEST_SIZE"

run_exact_case "uboot audit invalid --output-http" 2 \
    "$BIN" uboot audit --dev /dev/null --size "$TEST_SIZE" --output-http ftp://127.0.0.1:1/audit

run_exact_case "uboot audit invalid --output-http" 2 \
    "$BIN" uboot audit --dev /dev/null --size "$TEST_SIZE" --output-http http://127.0.0.1:1/audit

run_exact_case "uboot audit both http+https" 2 \
    "$BIN" uboot audit --dev /dev/null --size "$TEST_SIZE" --output-http http://127.0.0.1:1/audit --output-http https://127.0.0.1:1/audit

run_accept_case "uboot audit unknown rule reaches no-match/root-prep path" \
    "$BIN" uboot audit --dev /dev/null --size "$TEST_SIZE" --rule not_a_real_rule

for output_format in txt csv json
do
    verbose_log="$(mktemp /tmp/test_audit_verbose.${output_format}.XXXXXX)"
    printf '/dev/null 0x0 0x1000\n' >"$REPO_ROOT/fw_env.config"
    run_with_output_override "$BIN" --output-format "$output_format" uboot audit --dev "$TMP_AUDIT_DEV" --size "$TEST_SIZE" --rule uboot_validate_crc32 >"$verbose_log" 2>&1
    rc=$?

    case "$output_format" in
        txt)
            begin_pattern='audit rule begin: uboot_validate_crc32'
            end_pattern='audit run end: rc='
            ;;
        csv)
            begin_pattern='audit_rule_progress,uboot_validate_crc32,begin,rule execution started'
            end_pattern='audit_run,,end,audit completed with rc='
            ;;
        json)
            begin_pattern='"record":"audit_rule_progress","rule":"uboot_validate_crc32","status":"begin"'
            end_pattern='"record":"audit_run","status":"end","message":"audit completed with rc='
            ;;
    esac

    if [ "$rc" -eq 2 ] || ! grep -q "$begin_pattern" "$verbose_log" || ! grep -q "$end_pattern" "$verbose_log"; then
        echo "[FAIL] uboot audit verbose begin/end emits in ${output_format} output stream"
        print_file_head_scrubbed "$verbose_log" 120
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    else
        echo "[PASS] uboot audit verbose begin/end emits in ${output_format} output stream"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    fi

    rm -f "$verbose_log"
done

rm -f "$REPO_ROOT/fw_env.config"

rm -rf "$TMP_DIR"
finish_tests
