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

for script_path in "$SCRIPT_DIR"/*.sh; do
    script_file="$(basename "$script_path")"

    if [ "$script_file" = "$SCRIPT_NAME" ]; then
        continue
    fi

    url="$BASE_URL/$script_file"
    dest="$SCRIPT_DIR/$script_file"

    echo "downloading $url -> $dest"

    if [ "$downloader" = "curl" ]; then
        curl -fsSL "$url" -o "$dest"
    else
        wget -qO "$dest" "$url"
    fi
done

echo "done"
