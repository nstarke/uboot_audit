#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$REPO_ROOT/uboot_audit"

# shellcheck source=tests/common.sh
. "$SCRIPT_DIR/common.sh"

require_binary "$BIN"
print_section "audit subcommand argument coverage"

TMP_DIR="$(mktemp -d /tmp/test_audit_args.XXXXXX)"
TMP_BLOB="$TMP_DIR/sample.fit"
TMP_PEM="$TMP_DIR/sample.pem"
echo 'fit-placeholder' >"$TMP_BLOB"
cat >"$TMP_PEM" <<'PEM'
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK6y8l6P0w8Q3Xj2sI8hXk7wQ+9QmVqX
FJdGAr5e3g7r5gq2k4J2Y9h6QvVQ6j0S6s7n4i4Nf2n2PqY9sI7rXgsCAwEAAQ==
-----END PUBLIC KEY-----
PEM

run_exact_case "audit --help" 0 "$BIN" audit --help
run_accept_case "audit --list-rules" "$BIN" audit --list-rules

run_accept_case "audit required args: --dev --size" \
    "$BIN" audit --dev /dev/null --size "$TEST_SIZE"

run_accept_case "audit --rule uboot_validate_crc32" \
    "$BIN" audit --rule uboot_validate_crc32 --dev /dev/null --size "$TEST_SIZE"

run_accept_case "audit --rule uboot_validate_env_writeability" \
    "$BIN" audit --rule uboot_validate_env_writeability --dev /dev/null --size "$TEST_SIZE"

run_accept_case "audit --rule uboot_validate_env_security" \
    "$BIN" audit --rule uboot_validate_env_security --dev /dev/null --size "$TEST_SIZE"

run_accept_case "audit --rule uboot_validate_secureboot" \
    "$BIN" audit --rule uboot_validate_secureboot --dev /dev/null --size "$TEST_SIZE"

run_accept_case "audit --offset" \
    "$BIN" audit --dev /dev/null --offset 0x0 --size "$TEST_SIZE"

run_accept_case "audit --signature-blob" \
    "$BIN" audit --dev /dev/null --size "$TEST_SIZE" --signature-blob "$TMP_BLOB"

run_accept_case "audit --signature-pubkey" \
    "$BIN" audit --dev /dev/null --size "$TEST_SIZE" --signature-pubkey "$TMP_PEM"

run_accept_case "audit --scan-signature-devices" \
    "$BIN" audit --dev /dev/null --size "$TEST_SIZE" --scan-signature-devices

run_accept_case "audit --scan-signature-blob" \
    "$BIN" audit --dev /dev/null --size "$TEST_SIZE" --scan-signature-blob "$TMP_DIR/*.fit"

run_accept_case "audit --scan-signature-pubkey" \
    "$BIN" audit --dev /dev/null --size "$TEST_SIZE" --scan-signature-pubkey "$TMP_DIR/*.pem"

run_accept_case "audit --signature-alg" \
    "$BIN" audit --dev /dev/null --size "$TEST_SIZE" --signature-alg sha256

run_accept_case "audit --verbose" \
    "$BIN" audit --dev /dev/null --size "$TEST_SIZE" --verbose

run_accept_case "audit --output-tcp" \
    "$BIN" audit --dev /dev/null --size "$TEST_SIZE" --output-tcp 127.0.0.1:9

run_accept_case "audit --output-http" \
    "$BIN" audit --dev /dev/null --size "$TEST_SIZE" --output-http http://127.0.0.1:1/audit

run_accept_case "audit --output-https" \
    "$BIN" audit --dev /dev/null --size "$TEST_SIZE" --output-https https://127.0.0.1:1/audit

run_accept_case "audit --insecure" \
    "$BIN" audit --dev /dev/null --size "$TEST_SIZE" --insecure

rm -rf "$TMP_DIR"
finish_tests
