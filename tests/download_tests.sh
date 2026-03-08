#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SCRIPT_NAME="$(basename "$0")"

WEB_SERVER=""
OUTPUT_DIRECTORY=""
TEMP_OUTPUT_DIRECTORY=""
ISA=""
LIST_ISA=0

# Remove stale temporary download directories from previous runs.
for stale_dir in /tmp/download_tests_output.*; do
    [ -d "$stale_dir" ] || continue
    rm -rf -- "$stale_dir"
done

usage() {
    echo "usage: $0 --webserver <url> --isa <arch> [--output-directory <path>]"
    echo "   or: $0 --webserver=<url> --isa=<arch> [--output-directory=<path>]"
    echo "   or: $0 --webserver <url> --list-isa"
}

list_valid_isas_from_index_file() {
    index_file="$1"

    sed 's/[^A-Za-z0-9_./-]/\
/g' "$index_file" | \
        grep '^/*uboot_audit-[A-Za-z0-9._-]\+$' | \
        sed 's#^/*##' | \
        sed 's#^uboot_audit-##' | \
        sort -u
}

print_valid_isas() {
    list_valid_isas
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
        --output-directory)
            if [ "$#" -lt 2 ]; then
                echo "error: --output-directory requires a value"
                usage
                exit 2
            fi
            OUTPUT_DIRECTORY="$2"
            shift 2
            ;;
        --output-directory=*)
            OUTPUT_DIRECTORY="${1#*=}"
            shift
            ;;
        --isa)
            if [ "$#" -lt 2 ]; then
                echo "error: --isa requires a value"
                usage
                exit 2
            fi
            ISA="$2"
            shift 2
            ;;
        --isa=*)
            ISA="${1#*=}"
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        --list-isa)
            LIST_ISA=1
            shift
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

list_valid_isas() {
    list_valid_isas_from_index_file "$INDEX_FILE"
}

if [ "$LIST_ISA" -eq 1 ]; then
    if ! list_valid_isas | grep . >/dev/null 2>&1; then
        echo "error: no release binaries found in index at $BASE_URL/" >&2
        exit 1
    fi

    print_valid_isas
    exit 0
fi

if [ -z "$ISA" ]; then
    echo "error: --isa is required"
    usage
    exit 2
fi

if ! list_valid_isas | grep -Fx "$ISA" >/dev/null 2>&1; then
    echo "error: invalid --isa '$ISA'"
    echo "valid values:"
    print_valid_isas
    exit 2
fi

if [ -n "$OUTPUT_DIRECTORY" ]; then
    mkdir -p "$OUTPUT_DIRECTORY"
    DEST_DIR="$OUTPUT_DIRECTORY"
else
    TEMP_OUTPUT_DIRECTORY="$(mktemp -d /tmp/download_tests_output.XXXXXX)"
    DEST_DIR="$TEMP_OUTPUT_DIRECTORY"
fi

echo "output directory: $DEST_DIR"

sed 's/[^A-Za-z0-9_./-]/\
/g' "$INDEX_FILE" | \
    grep '^/*tests/.*\.sh$' | \
    sed 's#^/*##' | sort -u >"$SCRIPT_LIST_FILE"

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
    dest="$DEST_DIR/$script_file"

    echo "downloading $url -> $dest"

    fetch_to_file "$url" "$dest"
    chmod +x "$dest"
done <"$SCRIPT_LIST_FILE"

AUDIT_BINARY_NAME="uboot_audit-$ISA"
AUDIT_BINARY_URL="$BASE_URL/$AUDIT_BINARY_NAME"
AUDIT_BINARY_TMP="$(mktemp /tmp/uboot_audit.XXXXXX)"
AUDIT_BINARY_DEST="/tmp/uboot_audit"

echo "downloading $AUDIT_BINARY_URL -> $AUDIT_BINARY_DEST"
fetch_to_file "$AUDIT_BINARY_URL" "$AUDIT_BINARY_TMP"
chmod +x "$AUDIT_BINARY_TMP"
mv -f "$AUDIT_BINARY_TMP" "$AUDIT_BINARY_DEST"

echo "done"
if [ -n "$TEMP_OUTPUT_DIRECTORY" ]; then
    echo "files written to temporary directory: $TEMP_OUTPUT_DIRECTORY"
fi
