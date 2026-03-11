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
SKIP_REMOVE=0

usage() {
    echo "usage: $0 --webserver <url> [--isa <arch>] [--output-directory <path>] [--auto-start] [--skip-remove]"
    echo "   or: $0 --webserver=<url> [--isa=<arch>] [--output-directory=<path>] [--auto-start] [--skip-remove]"
    echo "   or: $0 --webserver <url> --list-isa [--skip-remove]"
}

has_printf() {
    cmd_exists printf
}

delete_cr_stream() {
    if cmd_exists tr; then
        tr -d '\r'
    else
        awk '{ gsub(/\r/, ""); print }'
    fi
}

delete_crlf_stream() {
    if cmd_exists tr; then
        tr -d '\r\n'
    else
        awk '{ gsub(/\r/, ""); printf "%s", $0 }'
    fi
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

list_valid_isas_from_index_file() {
    index_file="$1"

    sed -n 's#.*href="/isa/\([^"]*\)".*#\1#p' "$index_file" | \
        delete_cr_stream | sed 's/%2F/\//g' | sed 's/[[:space:]]*$//' | sed '/^$/d' | sort -u
}

find_release_binary_url_for_isa() {
    index_file="$1"
    isa="$2"

    sed -n "s#.*href=\"\(/isa/${isa}\)\".*#\1#p" "$index_file" | \
        delete_cr_stream | sed 's/[[:space:]]*$//' | sed '/^$/d' | head -n 1
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
    if has_printf; then
        printf '%s' "$value" | delete_crlf_stream | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
    else
        cat <<EOF_NORMALIZE_ISA | delete_crlf_stream | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
$value
EOF_NORMALIZE_ISA
    fi
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
        --skip-remove)
            SKIP_REMOVE=1
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

if [ "$SKIP_REMOVE" -ne 1 ]; then
    # Remove stale temporary download directories from previous runs.
    for stale_dir in /tmp/download_tests_output.*; do
        [ -d "$stale_dir" ] || continue
        rm -rf -- "$stale_dir"
    done
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

can_run_binary() {
    binary_path="$1"

    "$binary_path" --help >/dev/null 2>&1
    status=$?

    case "$status" in
        126|127)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

INDEX_FILE="$(mktemp /tmp/download_tests_index.XXXXXX)"
SCRIPT_LIST_FILE="$(mktemp /tmp/download_tests_list.XXXXXX)"
TEMP_BINARY_DIRECTORY=""

cleanup() {
    rm -f "$INDEX_FILE" "$SCRIPT_LIST_FILE"
    if [ -n "$TEMP_BINARY_DIRECTORY" ] && [ -d "$TEMP_BINARY_DIRECTORY" ]; then
        rm -rf -- "$TEMP_BINARY_DIRECTORY"
    fi
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

if [ -n "$ISA" ]; then
    ISA="$(normalize_isa_value "$ISA")"

    isa_valid=1
    for valid_isa in $(list_valid_isas | delete_cr_stream | sed 's/[[:space:]]*$//' | sed '/^$/d'); do
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
fi

if [ -n "$OUTPUT_DIRECTORY" ]; then
    mkdir -p "$OUTPUT_DIRECTORY"
    DEST_DIR="$OUTPUT_DIRECTORY"
else
    TEMP_OUTPUT_DIRECTORY="$(mktemp -d /tmp/download_tests_output.XXXXXX)"
    DEST_DIR="$TEMP_OUTPUT_DIRECTORY"
fi

echo "output directory: $DEST_DIR"

sed -n 's#.*href="\(/tests/[^"]*\.sh\)".*#\1#p' "$INDEX_FILE" | \
    delete_cr_stream | sed 's/[[:space:]]*$//' | sed '/^$/d' | sort -u >"$SCRIPT_LIST_FILE"

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

AUDIT_BINARY_DEST="/tmp/embedded_linux_audit"

if [ -n "$ISA" ]; then
    AUDIT_BINARY_PATH="$(find_release_binary_url_for_isa "$INDEX_FILE" "$ISA")"
    if [ -z "$AUDIT_BINARY_PATH" ]; then
        echo "error: could not find a release binary URL for ISA '$ISA' in index at $BASE_URL/"
        exit 1
    fi

    AUDIT_BINARY_URL="$(resolve_url "$BASE_URL" "$AUDIT_BINARY_PATH")"
    AUDIT_BINARY_TMP="$(mktemp /tmp/embedded_linux_audit.XXXXXX)"

    echo "downloading $AUDIT_BINARY_URL -> $AUDIT_BINARY_DEST"
    fetch_to_file "$AUDIT_BINARY_URL" "$AUDIT_BINARY_TMP"
    chmod +x "$AUDIT_BINARY_TMP"
    mv -f "$AUDIT_BINARY_TMP" "$AUDIT_BINARY_DEST"
else
    TEMP_BINARY_DIRECTORY="$(mktemp -d /tmp/download_tests_binaries.XXXXXX)"
    echo "ISA not specified; downloading release binaries for auto-discovery to: $TEMP_BINARY_DIRECTORY"

    DISCOVERED_ISA=""
    DISCOVERED_BINARY=""

    for candidate_isa in $(list_valid_isas | delete_cr_stream | sed 's/[[:space:]]*$//' | sed '/^$/d'); do
        candidate_path_rel="$(find_release_binary_url_for_isa "$INDEX_FILE" "$candidate_isa")"
        [ -n "$candidate_path_rel" ] || continue

        candidate_url="$(resolve_url "$BASE_URL" "$candidate_path_rel")"
        candidate_file="$TEMP_BINARY_DIRECTORY/embedded_linux_audit-$candidate_isa"

        echo "downloading $candidate_url -> $candidate_file"
        fetch_to_file "$candidate_url" "$candidate_file"
        chmod +x "$candidate_file"
    done

    for candidate_isa in $(list_valid_isas | delete_cr_stream | sed 's/[[:space:]]*$//' | sed '/^$/d'); do
        candidate_file="$TEMP_BINARY_DIRECTORY/embedded_linux_audit-$candidate_isa"
        [ -f "$candidate_file" ] || continue

        echo "probing ISA candidate: $candidate_isa"
        if can_run_binary "$candidate_file"; then
            DISCOVERED_ISA="$candidate_isa"
            DISCOVERED_BINARY="$candidate_file"
            break
        fi
    done

    if [ -z "$DISCOVERED_ISA" ] || [ -z "$DISCOVERED_BINARY" ]; then
        echo "error: could not discover a working ISA from release binaries at $BASE_URL/"
        exit 1
    fi

    mv -f "$DISCOVERED_BINARY" "$AUDIT_BINARY_DEST"
    ISA="$DISCOVERED_ISA"
    echo "detected proper ISA for this system: $ISA"
fi

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

    case "$WEB_SERVER" in
        https://*)
            AUTO_OUTPUT_FLAG="--output-http"
            ;;
        http://*)
            AUTO_OUTPUT_FLAG="--output-http"
            ;;
        *)
            echo "error: unsupported webserver URL scheme for --auto-start: $WEB_SERVER"
            exit 1
            ;;
    esac

    echo "auto-start: running $TEST_ALL_SCRIPT $AUTO_OUTPUT_FLAG $WEB_SERVER"
    /bin/sh "$TEST_ALL_SCRIPT" "$AUTO_OUTPUT_FLAG" "$WEB_SERVER"
fi
