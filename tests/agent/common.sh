#!/bin/sh

set -u

PASS_COUNT=0
FAIL_COUNT=0

# Shared test size used by --size argument coverage tests.
TEST_SIZE=0x10000

has_printf() {
    command -v printf >/dev/null 2>&1
}

append_line() {
    line="$1"
    if has_printf; then
        printf '%s\n' "$line"
    else
        cat <<EOF_APPEND_LINE
$line
EOF_APPEND_LINE
    fi
}

run_with_output_override() {
    if [ "${TEST_DISABLE_OUTPUT_OVERRIDE:-0}" = "1" ]; then
        has_verbose=0
        for arg in "$@"; do
            case "$arg" in
                --verbose|--verbose=*)
                    has_verbose=1
                    break
                    ;;
            esac
        done
        if [ "$has_verbose" -eq 0 ]; then
            set -- "$@" --verbose
        fi
        "$@"
        return $?
    fi

    override_flag=""
    override_value=""

    if [ -n "${TEST_OUTPUT_HTTP:-}" ] && [ -n "${TEST_OUTPUT_HTTPS:-}" ]; then
        echo "error: set only one of TEST_OUTPUT_HTTP or TEST_OUTPUT_HTTPS"
        return 2
    fi

    if [ -n "${TEST_OUTPUT_HTTP:-}" ]; then
        override_flag="--output-http"
        override_value="$TEST_OUTPUT_HTTP"
    elif [ -n "${TEST_OUTPUT_HTTPS:-}" ]; then
        override_flag="--output-https"
        override_value="$TEST_OUTPUT_HTTPS"
    fi

    if [ -z "$override_flag" ]; then
        has_verbose=0
        for arg in "$@"; do
            case "$arg" in
                --verbose|--verbose=*)
                    has_verbose=1
                    break
                    ;;
            esac
        done
        if [ "$has_verbose" -eq 0 ]; then
            set -- "$@" --verbose
        fi
        "$@"
        return $?
    fi

    original_args_file="$(mktemp /tmp/test_args.XXXXXX)"
    for arg in "$@"; do
        append_line "$arg" >>"$original_args_file"
    done

    replaced=0
    has_remote_copy=0
    set --
    while IFS= read -r arg; do
        case "$arg" in
            remote-copy)
                has_remote_copy=1
                set -- "$@" "$arg"
                ;;
            --output-http|--output-https)
                set -- "$@" "$override_flag" "$override_value"
                IFS= read -r next_arg || true
                replaced=1
                ;;
            --output-http=*|--output-https=*)
                set -- "$@" "$override_flag" "$override_value"
                replaced=1
                ;;
            *)
                set -- "$@" "$arg"
                ;;
        esac
    done <"$original_args_file"

    rm -f "$original_args_file"

    if [ "$replaced" -eq 0 ] && [ "$has_remote_copy" -eq 0 ]; then
        set -- "$@" "$override_flag" "$override_value"
    fi

    has_verbose=0
    for arg in "$@"; do
        case "$arg" in
            --verbose|--verbose=*)
                has_verbose=1
                break
                ;;
        esac
    done
    if [ "$has_verbose" -eq 0 ]; then
        set -- "$@" --verbose
    fi

    "$@"
}

print_section() {
    title="$1"
    if has_printf; then
        printf '\n==== %s ====\n' "$title"
    else
        echo
        echo "==== $title ===="
    fi
}

require_binary() {
    bin="$1"
    if [ ! -x "$bin" ]; then
        echo "error: missing executable: $bin"
        echo "hint: build first with: make"
        exit 1
    fi
}

run_exact_case() {
    name="$1"
    expected_rc="$2"
    shift 2

    log="$(mktemp /tmp/test_log.XXXXXX)"
    if [ "$expected_rc" -eq 2 ]; then
        TEST_DISABLE_OUTPUT_OVERRIDE=1 run_with_output_override "$@" >"$log" 2>&1
    else
        run_with_output_override "$@" >"$log" 2>&1
    fi
    rc=$?

    if [ "$rc" -eq "$expected_rc" ]; then
        echo "[PASS] $name (rc=$rc)"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] $name (rc=$rc, expected=$expected_rc)"
        sed -n '1,80p' "$log"
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi

    rm -f "$log"
}

run_accept_case() {
    name="$1"
    shift

    log="$(mktemp /tmp/test_log.XXXXXX)"
    run_with_output_override "$@" >"$log" 2>&1
    rc=$?

    if [ "$rc" -ne 2 ]; then
        echo "[PASS] $name (rc=$rc)"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] $name (rc=$rc, parser/usage failure)"
        sed -n '1,80p' "$log"
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi

    rm -f "$log"
}

finish_tests() {
    echo
    echo "Passed: $PASS_COUNT"
    echo "Failed: $FAIL_COUNT"
    [ "$FAIL_COUNT" -eq 0 ]
}
