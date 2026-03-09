#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SCRIPT_NAME="$(basename "$0")"

WEB_SERVER=""
OUTPUT_DIRECTORY=""
TEMP_OUTPUT_DIRECTORY=""
ISA=""
LIST_ISA=0
AUTO_START=0

# Remove stale temporary download directories from previous runs.
for stale_dir in /tmp/download_tests_output.*; do
    [ -d "$stale_dir" ] || continue
    rm -rf -- "$stale_dir"
done

usage() {
    echo "usage: $0 --webserver <url> --isa <arch> [--output-directory <path>] [--auto-start]"
    echo "   or: $0 --webserver=<url> --isa=<arch> [--output-directory=<path>] [--auto-start]"
    echo "   or: $0 --webserver <url> --list-isa"
}

has_printf() {
    cmd_exists printf
}

cmd_exists() {
    cmd_name="$1"

    # Prefer `command -v`, but fall back when `command` is unavailable.
    if command -v "$cmd_name" >/dev/null 2>&1; then
        return 0
    elif which "$cmd_name" >/dev/null 2>&1; then
        return 0
    elif type "$cmd_name" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

json_query_file() {
    index_file="$1"
    query="$2"

    if cmd_exists jq; then
        jq -r "$query" "$index_file"
        return $?
    fi

    if cmd_exists python3; then
        python3 - "$index_file" "$query" <<'PY'
import json
import sys

index_file = sys.argv[1]
query = sys.argv[2]

with open(index_file, 'r', encoding='utf-8') as f:
    data = json.load(f)

if query == '.binaries[].isa':
    for item in data.get('binaries', []):
        isa = item.get('isa')
        if isinstance(isa, str):
            print(isa)
elif query == '.tests[]':
    for item in data.get('tests', []):
        if isinstance(item, str):
            print(item)
else:
    prefix = '.binaries[] | select(.isa == "'
    suffix = '") | .url'
    if query.startswith(prefix) and query.endswith(suffix):
        want = query[len(prefix):-len(suffix)]
        for item in data.get('binaries', []):
            if item.get('isa') == want:
                url = item.get('url')
                if isinstance(url, str):
                    print(url)
    else:
        raise SystemExit(f'unsupported query: {query}')
PY
        return $?
    fi

    echo "error: need jq or python3 to parse JSON index" >&2
    return 1
}

list_valid_isas_from_index_file() {
    index_file="$1"

    json_query_file "$index_file" '.binaries[].isa' | \
        tr -d '\r' | sed 's/[[:space:]]*$//' | sed '/^$/d' | sort -u
}

find_release_binary_url_for_isa() {
    index_file="$1"
    isa="$2"

    json_query_file "$index_file" ".binaries[] | select(.isa == \"$isa\") | .url" | \
        tr -d '\r' | sed 's/[[:space:]]*$//' | sed '/^$/d' | head -n 1
}

resolve_url() {
    base_url="$1"
    rel_or_abs="$2"

    case "$rel_or_abs" in
        http://*|https://*)
            echo "$rel_or_abs"
            ;;
        /*)
            base_origin="$(echo "$base_url" | sed 's#^\(https\{0,1\}://[^/]*\).*#\1#')"
            echo "$base_origin$rel_or_abs"
            ;;
        *)
            echo "${base_url%/}/$rel_or_abs"
            ;;
    esac
}

normalize_isa_value() {
    value="$1"
    # Strip carriage returns/newlines that may be introduced by copy/paste or CRLF sources.
    if has_printf; then
        printf '%s' "$value" | tr -d '\r\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
    else
        # shell fallback when printf is unavailable
        cat <<EOF_NORMALIZE_ISA | tr -d '\r\n'
$value
EOF_NORMALIZE_ISA
    fi | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
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
        --auto-start)
            AUTO_START=1
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

if cmd_exists curl; then
    downloader="curl"
elif cmd_exists wget; then
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

ISA="$(normalize_isa_value "$ISA")"

isa_valid=1
for valid_isa in $(list_valid_isas | tr -d '\r' | sed 's/[[:space:]]*$//' | sed '/^$/d'); do
    if [ "$valid_isa" = "$ISA" ]; then
        isa_valid=0
        break
    fi
done

if [ "$isa_valid" -ne 0 ]; then
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

json_query_file "$INDEX_FILE" '.tests[]' | \
    tr -d '\r' | sed 's/[[:space:]]*$//' | sed '/^$/d' | sort -u >"$SCRIPT_LIST_FILE"

if [ ! -s "$SCRIPT_LIST_FILE" ]; then
    echo "error: no test shell scripts found in index at $BASE_URL/"
    exit 1
fi

while IFS= read -r rel_path; do
    script_url="$(resolve_url "$BASE_URL" "$rel_path")"
    script_file="$(basename "$rel_path")"

    if [ "$script_file" = "$SCRIPT_NAME" ]; then
        continue
    fi

    dest="$DEST_DIR/$script_file"

    echo "downloading $script_url -> $dest"

    fetch_to_file "$script_url" "$dest"
    chmod +x "$dest"
done <"$SCRIPT_LIST_FILE"

AUDIT_BINARY_PATH="$(find_release_binary_url_for_isa "$INDEX_FILE" "$ISA")"
if [ -z "$AUDIT_BINARY_PATH" ]; then
    echo "error: could not find a release binary URL for ISA '$ISA' in index at $BASE_URL/"
    exit 1
fi

AUDIT_BINARY_URL="$(resolve_url "$BASE_URL" "$AUDIT_BINARY_PATH")"
AUDIT_BINARY_TMP="$(mktemp /tmp/embedded_linux_audit.XXXXXX)"
AUDIT_BINARY_DEST="/tmp/embedded_linux_audit"

echo "downloading $AUDIT_BINARY_URL -> $AUDIT_BINARY_DEST"
fetch_to_file "$AUDIT_BINARY_URL" "$AUDIT_BINARY_TMP"
chmod +x "$AUDIT_BINARY_TMP"
mv -f "$AUDIT_BINARY_TMP" "$AUDIT_BINARY_DEST"

echo "done"
if [ -n "$TEMP_OUTPUT_DIRECTORY" ]; then
    echo "files written to temporary directory: $TEMP_OUTPUT_DIRECTORY"
fi

if [ "$AUTO_START" -eq 1 ]; then
    TEST_ALL_SCRIPT="$DEST_DIR/test_all.sh"
    if [ ! -x "$TEST_ALL_SCRIPT" ]; then
        echo "error: --auto-start requested but $TEST_ALL_SCRIPT is missing or not executable"
        exit 1
    fi

    echo "auto-start: running $TEST_ALL_SCRIPT --output-http $WEB_SERVER"
    /bin/sh "$TEST_ALL_SCRIPT" --output-http "$WEB_SERVER"
fi
