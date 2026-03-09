#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$REPO_ROOT/uboot_audit"

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

# shellcheck source=tests/common.sh
. "$SCRIPT_DIR/common.sh"

require_binary "$BIN"
print_section "efi/bios orom argument coverage"

run_exact_case "efi orom --help" 0 "$BIN" efi orom --help
run_exact_case "bios orom --help" 0 "$BIN" bios orom --help

run_exact_case "efi orom pull missing output target" 2 "$BIN" efi orom pull
run_exact_case "bios orom pull missing output target" 2 "$BIN" bios orom pull

run_exact_case "efi orom pull invalid --output-http" 2 "$BIN" efi orom pull --output-http ftp://127.0.0.1:1/orom
run_exact_case "bios orom pull invalid --output-https" 2 "$BIN" bios orom pull --output-https http://127.0.0.1:1/orom
run_exact_case "efi orom pull both http+https" 2 "$BIN" efi orom pull --output-http http://127.0.0.1:1/orom --output-https https://127.0.0.1:1/orom

run_exact_case "efi orom invalid action" 2 "$BIN" efi orom invalid
run_exact_case "bios orom invalid action" 2 "$BIN" bios orom invalid

run_accept_case "efi orom pull --output-tcp" "$BIN" efi orom pull --output-tcp 127.0.0.1:9
run_accept_case "efi orom pull --output-http" "$BIN" efi orom pull --output-http http://127.0.0.1:1/orom
run_accept_case "efi orom pull --output-https" "$BIN" efi orom pull --output-https https://127.0.0.1:1/orom
run_accept_case "efi orom pull --verbose" "$BIN" efi orom pull --output-http http://127.0.0.1:1/orom --verbose

run_accept_case "bios orom pull --output-tcp" "$BIN" bios orom pull --output-tcp 127.0.0.1:9
run_accept_case "bios orom pull --output-http" "$BIN" bios orom pull --output-http http://127.0.0.1:1/orom
run_accept_case "bios orom pull --output-https" "$BIN" bios orom pull --output-https https://127.0.0.1:1/orom
run_accept_case "bios orom pull --verbose" "$BIN" bios orom pull --output-http http://127.0.0.1:1/orom --verbose

run_accept_case "efi orom list --output-tcp" "$BIN" efi orom list --output-tcp 127.0.0.1:9
run_accept_case "efi orom list --output-http" "$BIN" efi orom list --output-http http://127.0.0.1:1/orom
run_accept_case "bios orom list --output-https" "$BIN" bios orom list --output-https https://127.0.0.1:1/orom
run_accept_case "bios orom list --verbose" "$BIN" bios orom list --output-http http://127.0.0.1:1/orom --verbose

run_accept_case "efi orom list with --output-format csv" "$BIN" --output-format csv efi orom list --output-http http://127.0.0.1:1/orom
run_accept_case "bios orom list with --output-format json" "$BIN" --output-format json bios orom list --output-http http://127.0.0.1:1/orom

finish_tests
