#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"

TEST_OUTPUT_HTTP="${TEST_OUTPUT_HTTP:-}"
TEST_OUTPUT_HTTPS="${TEST_OUTPUT_HTTPS:-}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --output-http)
            if [ "$#" -lt 2 ]; then
                echo "error: --output-http requires a value"
                echo "usage: $0 [--output-http <url> | --output-https <url>]"
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
                echo "usage: $0 [--output-http <url> | --output-https <url>]"
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
            echo "usage: $0 [--output-http <url> | --output-https <url>]"
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

rc=0

for test_script in \
    "$SCRIPT_DIR/test_env_args.sh" \
    "$SCRIPT_DIR/test_image_args.sh" \
    "$SCRIPT_DIR/test_audit_args.sh"
do
    echo
    echo "===== Running $(basename "$test_script") ====="
    if ! bash "$test_script"; then
        rc=1
    fi
done

exit "$rc"