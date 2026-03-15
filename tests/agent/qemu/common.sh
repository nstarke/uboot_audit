#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# shellcheck source=tests/system_package_helpers.sh
. "$REPO_ROOT/tests/system_package_helpers.sh"
# shellcheck source=tests/common_redaction.sh
. "$REPO_ROOT/tests/common_redaction.sh"

RELEASE_BINARIES_DIR="${RELEASE_BINARIES_DIR:-$REPO_ROOT/api/data/release_binaries}"
TEST_SCRIPTS_DIR="$REPO_ROOT/tests/agent/scripts"
RELEASE_BUILD_SCRIPT="$REPO_ROOT/tests/compile_release_binaries_locally.sh"
SUPPORTED_ISAS="arm32-le arm32-be aarch64-le aarch64-be mips-le mips-be mips64-le mips64-be powerpc-le powerpc-be x86 x86_64 riscv32 riscv64"
PASS_COUNT=0
FAIL_COUNT=0

should_run_qemu_as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        return 0
    fi

    case "${ELA_QEMU_RUN_AS_ROOT:-${GITHUB_ACTIONS:-}}" in
        1|true|TRUE|yes|YES)
            sudo -n true >/dev/null 2>&1
            return "$?"
            ;;
    esac

    return 1
}

run_host_command() {
    if should_run_qemu_as_root; then
        sudo -n "$@"
    else
        "$@"
    fi
}

print_file_scrubbed() {
    path="$1"

    if [ -f "$path" ]; then
        scrub_sensitive_stream <"$path"
    fi
}

detect_qemu_runtime_failure() {
    script_log="$1"
    script_rc="$2"

    case "$script_rc" in
        132)
            echo "Illegal Instruction"
            return 0
            ;;
        139)
            echo "Segmentation fault"
            return 0
            ;;
    esac

    if [ -f "$script_log" ]; then
        if grep -Eiq '(^|[^[:alpha:]])illegal instruction([^[:alpha:]]|$)' "$script_log"; then
            echo "Illegal Instruction"
            return 0
        fi

        if grep -Eiq 'segmentation fault|\bsegfault\b' "$script_log"; then
            echo "Segmentation fault"
            return 0
        fi
    fi

    return 1
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

require_command() {
    if ! ela_ensure_command "$1"; then
        echo "error: missing required command: $1"
        exit 1
    fi
}

require_file() {
    if [ ! -f "$1" ]; then
        echo "error: missing required file: $1"
        exit 1
    fi
}

cpu_jobs_for_build() {
    jobs=1

    if command_exists nproc; then
        jobs="$(nproc)"
    fi

    jobs=$((jobs - 4))
    if [ "$jobs" -lt 1 ]; then
        jobs=1
    fi

    echo "$jobs"
}

resolve_qemu_mode() {
    qemu_static_cmd="$1"
    qemu_binfmt_cmd="$2"

    if ! command_exists "$qemu_static_cmd" && ! command_exists "$qemu_binfmt_cmd"; then
        ela_ensure_command "$qemu_static_cmd" >/dev/null 2>&1 || ela_ensure_command "$qemu_binfmt_cmd" >/dev/null 2>&1 || true
    fi

    if command_exists "$qemu_static_cmd"; then
        echo "static:$(command -v "$qemu_static_cmd")"
        return 0
    fi

    if command_exists "$qemu_binfmt_cmd"; then
        echo "binfmt:$qemu_binfmt_cmd"
        return 0
    fi

    echo "error: missing required command: $qemu_static_cmd (or fallback $qemu_binfmt_cmd)" >&2
    exit 1
}

ensure_release_binaries() {
    requested_isa="${1:-}"
    missing=0

    if [ -n "$requested_isa" ]; then
        isa_list="$requested_isa"
    else
        isa_list="$SUPPORTED_ISAS"
    fi

    for isa_name in $isa_list; do
        if [ ! -x "$RELEASE_BINARIES_DIR/$isa_name/ela-$isa_name" ]; then
            missing=1
            break
        fi

    done

    if [ "$missing" -eq 1 ]; then
        case "${ELA_QEMU_REQUIRE_RELEASE_BINARIES:-0}" in
            1|true|TRUE|yes|YES)
                if [ -n "$requested_isa" ]; then
                    echo "error: required prebuilt release binary missing for $requested_isa in $RELEASE_BINARIES_DIR" >&2
                else
                    echo "error: required prebuilt release binaries missing in $RELEASE_BINARIES_DIR" >&2
                fi
                echo "hint: download artifacts from the release build workflow into $RELEASE_BINARIES_DIR" >&2
                exit 1
                ;;
        esac

        require_file "$RELEASE_BUILD_SCRIPT"
        build_jobs="$(cpu_jobs_for_build)"
        if [ -n "$requested_isa" ]; then
            echo "Release binary missing for $requested_isa; compiling via tests/compile_release_binaries_locally.sh --jobs=$build_jobs $requested_isa"
            if ! /bin/sh "$RELEASE_BUILD_SCRIPT" --jobs="$build_jobs" "$requested_isa"; then
                echo "error: failed to compile release binary for $requested_isa" >&2
                exit 1
            fi
        else
            echo "Release binaries missing; compiling all ISAs via tests/compile_release_binaries_locally.sh --jobs=$build_jobs"
            if ! /bin/sh "$RELEASE_BUILD_SCRIPT" --jobs="$build_jobs"; then
                echo "error: failed to compile release binaries" >&2
                exit 1
            fi
        fi
    fi
}

create_chroot_tree() {
    rootfs_dir="$1"
    isa="$2"
    binary_path="$3"
    qemu_static_path="${4:-}"

    mkdir -p \
        "$rootfs_dir/bin" \
        "$rootfs_dir/etc" \
        "$rootfs_dir/usr/bin" \
        "$rootfs_dir/tmp" \
        "$rootfs_dir/tests/agent/scripts"

    cp "$binary_path" "$rootfs_dir/bin/embedded_linux_audit"

    if [ -n "$qemu_static_path" ]; then
        cp "$qemu_static_path" "$rootfs_dir/usr/bin/$(basename "$qemu_static_path")"
    fi

    find "$TEST_SCRIPTS_DIR" -type f -name '*.ela' | while IFS= read -r script_file; do
        relative_path="${script_file#"$TEST_SCRIPTS_DIR"/}"
        dest_path="$rootfs_dir/tests/agent/scripts/$relative_path"
        mkdir -p "$(dirname "$dest_path")"
        cp "$script_file" "$dest_path"
    done

    cat >"$rootfs_dir/etc/passwd" <<EOF_PASSWD
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
EOF_PASSWD

    cat >"$rootfs_dir/etc/group" <<EOF_GROUP
root:x:0:
nobody:x:65534:
EOF_GROUP

    cat >"$rootfs_dir/etc/hosts" <<EOF_HOSTS
127.0.0.1 localhost
EOF_HOSTS

    cat >"$rootfs_dir/isa.env" <<EOF_ISA
ELA_TEST_ISA=$isa
EOF_ISA

    cat >"$rootfs_dir/fw_env.config" <<EOF_FW_ENV
/dev/null 0x0 0x1000
EOF_FW_ENV

    cp "$rootfs_dir/fw_env.config" "$rootfs_dir/uboot_env.config"
}

create_qemu_script_runtime_dir() {
    runtime_dir="$1"

    mkdir -p "$runtime_dir"

    cat >"$runtime_dir/fw_env.config" <<EOF_FW_ENV
/dev/null 0x0 0x1000
EOF_FW_ENV

    cp "$runtime_dir/fw_env.config" "$runtime_dir/uboot_env.config"
}

QEMU_SCRIPT_TIMEOUT="${ELA_QEMU_SCRIPT_TIMEOUT:-120}"

run_qemu_script_in_chroot() {
    qemu_mode="$1"
    qemu_runner="$2"
    rootfs_dir="$3"
    script_path="$4"

    if [ "$qemu_mode" = "static" ]; then
        run_host_command bwrap \
            --bind "$rootfs_dir" / \
            --proc /proc \
            --dev /dev \
            --ro-bind /sys /sys \
            --tmpfs /run \
            --setenv HOME /root \
            --setenv TMPDIR /tmp \
            --setenv ELA_TEST_ISA "$(sed -n 's/^ELA_TEST_ISA=//p' "$rootfs_dir/isa.env")" \
            --chdir / \
            "/usr/bin/$qemu_runner" /bin/embedded_linux_audit --script "$script_path"
    else
        run_host_command bwrap \
            --bind "$rootfs_dir" / \
            --proc /proc \
            --dev /dev \
            --ro-bind /sys /sys \
            --tmpfs /run \
            --setenv HOME /root \
            --setenv TMPDIR /tmp \
            --setenv ELA_TEST_ISA "$(sed -n 's/^ELA_TEST_ISA=//p' "$rootfs_dir/isa.env")" \
            --chdir / \
            /bin/embedded_linux_audit --script "$script_path"
    fi
}

bwrap_supports_qemu_chroot() {
    probe_dir="$(mktemp -d /tmp/ela-bwrap-probe.XXXXXX)"

    if bwrap \
        --ro-bind / / \
        --proc /proc \
        --dev /dev \
        --ro-bind /sys /sys \
        --tmpfs /run \
        --setenv HOME /root \
        --setenv TMPDIR /tmp \
        --chdir / \
        /bin/sh -c 'mkdir -p "$1"' /bin/sh "$probe_dir" >/dev/null 2>&1; then
        rm -rf "$probe_dir"
        return 0
    fi

    rm -rf "$probe_dir"
    return 1
}

run_qemu_script_direct() {
    qemu_mode="$1"
    qemu_runner="$2"
    binary_path="$3"
    script_path="$4"
    runtime_dir="$5"

    if [ "$qemu_mode" = "static" ]; then
        if should_run_qemu_as_root; then
            sudo -n env HOME=/tmp TMPDIR=/tmp ELA_TEST_ISA="${ELA_TEST_ISA:-}" \
                /bin/sh -c 'cd "$1" && exec "$2" "$3" --script "$4"' \
                /bin/sh "$runtime_dir" "$qemu_runner" "$binary_path" "$script_path"
        else
            HOME=/tmp TMPDIR=/tmp ELA_TEST_ISA="${ELA_TEST_ISA:-}" \
                /bin/sh -c 'cd "$1" && exec "$2" "$3" --script "$4"' \
                /bin/sh "$runtime_dir" "$qemu_runner" "$binary_path" "$script_path"
        fi
    else
        if should_run_qemu_as_root; then
            sudo -n env HOME=/tmp TMPDIR=/tmp ELA_TEST_ISA="${ELA_TEST_ISA:-}" \
                /bin/sh -c 'cd "$1" && exec "$2" --script "$3"' \
                /bin/sh "$runtime_dir" "$binary_path" "$script_path"
        else
            HOME=/tmp TMPDIR=/tmp ELA_TEST_ISA="${ELA_TEST_ISA:-}" \
                /bin/sh -c 'cd "$1" && exec "$2" --script "$3"' \
                /bin/sh "$runtime_dir" "$binary_path" "$script_path"
        fi
    fi
}

run_qemu_binary_tests() {
    isa="$1"
    binary_path="$2"
    binary_label="$3"
    qemu_mode="$4"
    qemu_runner="$5"
    use_bwrap="$6"

    rc=0
    rootfs_dir=""
    runtime_dir=""

    cleanup_qemu_binary_wrapper() {
        if [ -n "${rootfs_dir:-}" ]; then
            rm -rf "$rootfs_dir"
        fi
        if [ -n "${runtime_dir:-}" ]; then
            rm -rf "$runtime_dir"
        fi
    }

    trap cleanup_qemu_binary_wrapper EXIT INT TERM HUP

    if [ "$use_bwrap" -eq 1 ]; then
        rootfs_dir="$(mktemp -d /tmp/ela-qemu-rootfs-${isa}.XXXXXX)"
        if [ "$qemu_mode" = "static" ]; then
            create_chroot_tree "$rootfs_dir" "$isa" "$binary_path" "$qemu_runner"
        else
            create_chroot_tree "$rootfs_dir" "$isa" "$binary_path"
        fi
    else
        runtime_dir="$(mktemp -d /tmp/ela-qemu-runtime-${isa}.XXXXXX)"
        create_qemu_script_runtime_dir "$runtime_dir"
    fi

    echo "Running agent script coverage for ISA '$isa' ($binary_label) via $qemu_mode:$qemu_runner"
    echo "Release binary: $binary_path"
    if [ "$use_bwrap" -eq 1 ]; then
        echo "Chroot rootfs: $rootfs_dir"
    else
        echo "Host script execution mode enabled"
    fi

    if [ "$use_bwrap" -eq 1 ]; then
        script_list_root="$rootfs_dir/tests/agent/scripts"
    else
        script_list_root="$TEST_SCRIPTS_DIR"
    fi

    script_list_file="$(mktemp /tmp/ela-qemu-script-list.${isa}.XXXXXX)"
    find "$script_list_root" -type f -name '*.ela' | sort >"$script_list_file"

    while IFS= read -r script_file; do
        if [ "$use_bwrap" -eq 1 ]; then
            case "$script_file" in
                "$rootfs_dir/tests/agent/scripts/linux/test_linux_ssh_args.ela")
                    echo
                    echo "===== Skipping /tests/agent/scripts/linux/test_linux_ssh_args.ela ====="
                    echo "Skipping SSH script coverage under QEMU; it depends on a reachable/authenticating SSH server and can hang in CI."
                    continue
                    ;;
                "$rootfs_dir/tests/agent/scripts/uboot/test_uboot_env_args.ela" | \
                "$rootfs_dir/tests/agent/scripts/uboot/test_uboot_image_args.ela")
                    echo
                    echo "===== Skipping ${script_file#"$rootfs_dir/tests/agent/scripts"/} ====="
                    echo "Skipping uboot env/image scan under QEMU; host block devices exposed via bwrap cause multi-GB scans that time out."
                    continue
                    ;;
            esac
        else
            case "$script_file" in
                "$TEST_SCRIPTS_DIR/linux/test_linux_ssh_args.ela")
                    echo
                    echo "===== Skipping ${script_file#"$TEST_SCRIPTS_DIR"/} ====="
                    echo "Skipping SSH script coverage under QEMU; it depends on a reachable/authenticating SSH server and can hang in CI."
                    continue
                    ;;
                "$TEST_SCRIPTS_DIR/uboot/test_uboot_env_args.ela" | \
                "$TEST_SCRIPTS_DIR/uboot/test_uboot_image_args.ela")
                    echo
                    echo "===== Skipping ${script_file#"$TEST_SCRIPTS_DIR"/} ====="
                    echo "Skipping uboot env/image scan under QEMU; host block devices exposed via bwrap cause multi-GB scans that time out."
                    continue
                    ;;
            esac
        fi
        script_log="$(mktemp /tmp/ela-qemu-script-log.${isa}.XXXXXX)"
        if [ "$use_bwrap" -eq 1 ]; then
            script_path="/tests/agent/scripts/${script_file#"$rootfs_dir/tests/agent/scripts"/}"
        else
            script_path="$script_file"
        fi
        echo
        echo "===== Running ${script_path#"$TEST_SCRIPTS_DIR"/} ====="
        if [ "$use_bwrap" -eq 1 ]; then
            run_qemu_script_in_chroot "$qemu_mode" "$(basename "$qemu_runner")" "$rootfs_dir" "$script_path" >"$script_log" 2>&1 &
        else
            run_qemu_script_direct "$qemu_mode" "$qemu_runner" "$binary_path" "$script_path" "$runtime_dir" >"$script_log" 2>&1 &
        fi
        script_pid=$!
        (sleep "$QEMU_SCRIPT_TIMEOUT" && kill "$script_pid" 2>/dev/null) >/dev/null 2>/dev/null &
        timeout_pid=$!
        wait "$script_pid"
        script_rc=$?
        kill "$timeout_pid" 2>/dev/null
        wait "$timeout_pid" 2>/dev/null

        runtime_failure=""
        if [ "$script_rc" -eq 143 ] || [ "$script_rc" -eq 124 ]; then
            runtime_failure="timeout after ${QEMU_SCRIPT_TIMEOUT}s"
        elif runtime_failure="$(detect_qemu_runtime_failure "$script_log" "$script_rc")"; then
            :
        else
            runtime_failure=""
        fi

        if [ "$script_rc" -eq 0 ] && [ -z "$runtime_failure" ]; then
            echo "[PASS] script ${script_path#"$TEST_SCRIPTS_DIR"/} ($binary_label, isa=$isa, rc=$script_rc)"
            PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
        else
            if [ -n "$runtime_failure" ]; then
                echo "[FAIL] script ${script_path#"$TEST_SCRIPTS_DIR"/} ($binary_label, isa=$isa, rc=$script_rc, $runtime_failure)"
            elif [ "$script_rc" -eq 2 ]; then
                echo "[FAIL] script ${script_path#"$TEST_SCRIPTS_DIR"/} ($binary_label, isa=$isa, rc=$script_rc, parser/usage failure)"
            else
                echo "[FAIL] script ${script_path#"$TEST_SCRIPTS_DIR"/} ($binary_label, isa=$isa, rc=$script_rc)"
            fi
            print_file_scrubbed "$script_log"
            FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
        fi

        if [ "$script_rc" -eq 2 ]; then
            echo "error: script parser/usage failure for $script_path" >&2
            rc=1
        elif [ -n "$runtime_failure" ]; then
            echo "error: qemu runtime failure detected for $script_path" >&2
            rc=1
        elif [ "$script_rc" -ne 0 ]; then
            rc=1
        fi
        rm -f "$script_log"
    done <"$script_list_file"

    rm -f "$script_list_file"

    cleanup_qemu_binary_wrapper
    trap - EXIT INT TERM HUP

    return "$rc"
}

SHELL_TESTS_DIR="$REPO_ROOT/tests/agent/shell"
QEMU_SHELL_TEST_TIMEOUT="${ELA_QEMU_SHELL_TEST_TIMEOUT:-120}"

run_qemu_shell_tests() {
    isa="$1"
    binary_path="$2"
    binary_label="$3"
    qemu_mode="$4"
    qemu_runner="$5"

    rc=0
    bin_wrapper="$(mktemp /tmp/ela-qemu-bin-wrapper.${isa}.XXXXXX)"

    if [ "$qemu_mode" = "static" ]; then
        printf '#!/bin/sh\nexec "%s" "%s" "$@"\n' "$qemu_runner" "$binary_path" >"$bin_wrapper"
    else
        printf '#!/bin/sh\nexec "%s" "$@"\n' "$binary_path" >"$bin_wrapper"
    fi
    chmod +x "$bin_wrapper"

    echo "Running shell test coverage for ISA '$isa' ($binary_label) via $qemu_mode:$qemu_runner"

    shell_test_list="$(mktemp /tmp/ela-qemu-shell-test-list.${isa}.XXXXXX)"
    find "$SHELL_TESTS_DIR" -type f -name '*.sh' | sort >"$shell_test_list"

    while IFS= read -r test_script; do
        case "$test_script" in
            "$SHELL_TESTS_DIR/common.sh" | \
            "$SHELL_TESTS_DIR/test_all.sh" | \
            "$SHELL_TESTS_DIR/test_scripts.sh" | \
            "$SHELL_TESTS_DIR/download_tests.sh")
                continue
                ;;
            "$SHELL_TESTS_DIR/linux/test_linux_ssh_args.sh")
                echo
                echo "===== Skipping linux/test_linux_ssh_args.sh ====="
                echo "Skipping SSH shell test coverage under QEMU; it depends on a reachable/authenticating SSH server and can hang in CI."
                continue
                ;;
            "$SHELL_TESTS_DIR/test_cli_and_extra_args.sh")
                echo
                echo "===== Skipping test_cli_and_extra_args.sh ====="
                echo "Skipping under QEMU; WebSocket/ws:// curl connections and nc-based lifecycle tests hang under QEMU user-mode networking."
                continue
                ;;
            "$SHELL_TESTS_DIR/transfer/test_transfer_args.sh")
                echo
                echo "===== Skipping transfer/test_transfer_args.sh ====="
                echo "Skipping under QEMU; WebSocket/ws:// curl connections and nc-based lifecycle tests hang under QEMU user-mode networking."
                continue
                ;;
        esac

        test_log="$(mktemp /tmp/ela-qemu-shell-test-log.${isa}.XXXXXX)"
        rel_path="${test_script#"$SHELL_TESTS_DIR"/}"
        echo
        echo "===== Running shell/$rel_path ====="

        BIN="$bin_wrapper" /bin/sh "$test_script" >"$test_log" 2>&1 &
        test_pid=$!
        (sleep "$QEMU_SHELL_TEST_TIMEOUT" && kill "$test_pid" 2>/dev/null) >/dev/null 2>/dev/null &
        timeout_pid=$!
        wait "$test_pid"
        test_rc=$?
        kill "$timeout_pid" 2>/dev/null
        wait "$timeout_pid" 2>/dev/null

        cat "$test_log"

        sub_passes="$(sed -n 's/^Passed: //p' "$test_log" | tail -n 1)"
        sub_fails="$(sed -n 's/^Failed: //p' "$test_log" | tail -n 1)"
        if [ -n "$sub_passes" ]; then
            PASS_COUNT="$(expr "$PASS_COUNT" + "$sub_passes")"
        fi
        if [ -n "$sub_fails" ]; then
            FAIL_COUNT="$(expr "$FAIL_COUNT" + "$sub_fails")"
        fi

        if [ "$test_rc" -ne 0 ]; then
            rc=1
        fi

        rm -f "$test_log"
    done <"$shell_test_list"

    rm -f "$shell_test_list" "$bin_wrapper"
    return "$rc"
}

run_qemu_isa_tests() {
    isa="$1"
    qemu_static_cmd="$2"
    qemu_binfmt_cmd="$3"
    shift 3

    clean_release_binary=0

    binary_path="${BIN:-$RELEASE_BINARIES_DIR/$isa/ela-$isa}"
    rc=0
    use_bwrap=0

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --clean)
                clean_release_binary=1
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [--clean]" >&2
                exit 1
                ;;
            --)
                shift
                break
                ;;
            -*)
                echo "error: unsupported argument: $1" >&2
                echo "Usage: $0 [--clean]" >&2
                exit 1
                ;;
            *)
                echo "error: unexpected argument: $1" >&2
                echo "Usage: $0 [--clean]" >&2
                exit 1
                ;;
        esac
    done

    if [ "$clean_release_binary" -eq 1 ]; then
        require_file "$RELEASE_BUILD_SCRIPT"
        build_jobs="$(cpu_jobs_for_build)"
        echo "Rebuilding release binary for $isa via tests/compile_release_binaries_locally.sh --clean --jobs=$build_jobs $isa"
        if ! /bin/sh "$RELEASE_BUILD_SCRIPT" --clean --jobs="$build_jobs" "$isa"; then
            echo "error: failed to rebuild release binary for $isa" >&2
            exit 1
        fi
    fi

    ensure_release_binaries "$isa"
    require_file "$binary_path"
    require_file "$TEST_SCRIPTS_DIR/linux/test_linux_dmesg_args.ela"
    require_file "$TEST_SCRIPTS_DIR/linux/test_linux_ssh_args.ela"

    qemu_resolution="$(resolve_qemu_mode "$qemu_static_cmd" "$qemu_binfmt_cmd")"
    qemu_mode="${qemu_resolution%%:*}"
    qemu_runner="${qemu_resolution#*:}"

    ELA_TEST_ISA="$isa"
    export ELA_TEST_ISA

    if command_exists bwrap && bwrap_supports_qemu_chroot; then
        use_bwrap=1
    else
        echo "warning: bwrap sandbox unavailable on this host; running qemu tests without chroot isolation" >&2
    fi

    if ! run_qemu_binary_tests "$isa" "$binary_path" "default" "$qemu_mode" "$qemu_runner" "$use_bwrap"; then
        rc=1
    fi

    if ! run_qemu_shell_tests "$isa" "$binary_path" "default" "$qemu_mode" "$qemu_runner"; then
        rc=1
    fi

    echo
    echo "Passed: $PASS_COUNT"
    echo "Failed: $FAIL_COUNT"

    return "$rc"
}
