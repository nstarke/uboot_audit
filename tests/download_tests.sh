#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SCRIPT_NAME="$(basename "$0")"

WEB_SERVER=""

usage() {
    echo "usage: $0 --webserver <url>"
    echo "   or: $0 --webserver=<url>"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --webserver)
            if [ "$#" -lt 2 ]; then
                echo "error: --webserver requires a value"
                usage
                exit 2
            fi
            WEB_SERVER="$2"
            shift 2
            ;;
        --webserver=*)
            WEB_SERVER="${1#*=}"
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1"
            usage
            exit 2
            ;;
    esac
done

if [ -z "$WEB_SERVER" ]; then
    echo "error: --webserver is required"
    usage
    exit 2
fi

BASE_URL="${WEB_SERVER%/}"

if command -v curl >/dev/null 2>&1 || which curl >/dev/null 2>&1; then
    downloader="curl"
elif command -v wget >/dev/null 2>&1 || which wget >/dev/null 2>&1; then
    downloader="wget"
else
    echo "error: neither curl nor wget is installed"
    exit 1
fi

fetch_to_file() {
    url="$1"
    out_file="$2"

    if [ "$downloader" = "curl" ]; then
        curl -fsSL "$url" -o "$out_file"
    else
        wget -qO "$out_file" "$url"
    fi
}

INDEX_FILE="$(mktemp /tmp/download_tests_index.XXXXXX)"
SCRIPT_LIST_FILE="$(mktemp /tmp/download_tests_list.XXXXXX)"
cleanup() {
    rm -f "$INDEX_FILE" "$SCRIPT_LIST_FILE"
}
trap cleanup EXIT HUP INT TERM

echo "fetching index: $BASE_URL/"
fetch_to_file "$BASE_URL/" "$INDEX_FILE"

sed 's/[^A-Za-z0-9_./-]/\
/g' "$INDEX_FILE" | \
    grep '^/*tests/.*\.sh$' | \
    sed 's#^/*##' >"$SCRIPT_LIST_FILE"

if [ ! -s "$SCRIPT_LIST_FILE" ]; then
    echo "error: no test shell scripts found in index at $BASE_URL/"
    exit 1
fi

while IFS= read -r rel_path; do
    script_file="$(basename "$rel_path")"

    if [ "$script_file" = "$SCRIPT_NAME" ]; then
        continue
    fi

    url="$BASE_URL/$rel_path"
    dest="$SCRIPT_DIR/$script_file"

    echo "downloading $url -> $dest"

    fetch_to_file "$url" "$dest"
done <"$SCRIPT_LIST_FILE"

echo "done"
