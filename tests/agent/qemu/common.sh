#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# shellcheck source=tests/system_package_helpers.sh
. "$REPO_ROOT/tests/system_package_helpers.sh"

RELEASE_BINARIES_DIR="${RELEASE_BINARIES_DIR:-$REPO_ROOT/api/data/release_binaries}"
TEST_SCRIPTS_DIR="$REPO_ROOT/tests/agent/scripts"
RELEASE_BUILD_SCRIPT="$REPO_ROOT/tests/compile_release_binaries_locally.sh"
SUPPORTED_ISAS="arm32-le arm32-be aarch64-le aarch64-be mips-le mips-be mips64-le mips64-be powerpc-le powerpc-be x86 x86_64 riscv32 riscv64"

scrub_sensitive_stream() {
    while IFS= read -r line || [ -n "$line" ]; do
        lower_line="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"
        case "$lower_line" in
            *efi-var*|*efi_vars*|*efivars*)
                printf '[REDACTED EFI VARS]\n'
                continue
                ;;
        esac

        printf '%s\n' "$line" | sed -E \
            -e 's/(([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll][Ss]?|[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn])[[:space:]]*[:=][[:space:]]*)[^[:space:],;"}]+/\1<REDACTED>/g' \
            -e 's/(([?&]([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll][Ss]?|[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn]))=)[^&[:space:]]+/\1<REDACTED>/g' \
            -e 's/(("([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll][Ss]?|[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn])"[[:space:]]*:[[:space:]]*")[^"]+)/\1<REDACTED>/g'
    done
}

print_file_scrubbed() {
    path="$1"

    if [ -f "$path" ]; then
        scrub_sensitive_stream <"$path"
    fi
}

isa_has_compat_binary() {
    case "$1" in
        aarch64-le|aarch64-be|mips-le|mips-be|mips64-le|mips64-be|powerpc-le|powerpc-be|x86|x86_64|riscv32|riscv64)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
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

        if isa_has_compat_binary "$isa_name" && [ ! -x "$RELEASE_BINARIES_DIR/$isa_name/ela-$isa_name-compat" ]; then
            missing=1
            break
        fi
    done

    if [ "$missing" -eq 1 ]; then
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
FW_AUDIT_TEST_ISA=$isa
EOF_ISA
}

run_qemu_script_in_chroot() {
    qemu_mode="$1"
    qemu_runner="$2"
    rootfs_dir="$3"
    script_path="$4"

    if [ "$qemu_mode" = "static" ]; then
        bwrap \
            --bind "$rootfs_dir" / \
            --proc /proc \
            --dev /dev \
            --ro-bind /sys /sys \
            --tmpfs /run \
            --setenv HOME /root \
            --setenv TMPDIR /tmp \
            --setenv FW_AUDIT_TEST_ISA "$(sed -n 's/^FW_AUDIT_TEST_ISA=//p' "$rootfs_dir/isa.env")" \
            --chdir / \
            "/usr/bin/$qemu_runner" /bin/embedded_linux_audit --script "$script_path"
    else
        bwrap \
            --bind "$rootfs_dir" / \
            --proc /proc \
            --dev /dev \
            --ro-bind /sys /sys \
            --tmpfs /run \
            --setenv HOME /root \
            --setenv TMPDIR /tmp \
            --setenv FW_AUDIT_TEST_ISA "$(sed -n 's/^FW_AUDIT_TEST_ISA=//p' "$rootfs_dir/isa.env")" \
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

    if [ "$qemu_mode" = "static" ]; then
        HOME=/tmp TMPDIR=/tmp FW_AUDIT_TEST_ISA="${FW_AUDIT_TEST_ISA:-}" \
            "$qemu_runner" "$binary_path" --script "$script_path"
    else
        HOME=/tmp TMPDIR=/tmp FW_AUDIT_TEST_ISA="${FW_AUDIT_TEST_ISA:-}" \
            "$binary_path" --script "$script_path"
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

    cleanup_qemu_binary_wrapper() {
        if [ -n "${rootfs_dir:-}" ]; then
            rm -rf "$rootfs_dir"
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
        script_log="$(mktemp /tmp/ela-qemu-script-log.${isa}.XXXXXX)"
        if [ "$use_bwrap" -eq 1 ]; then
            script_path="/tests/agent/scripts/${script_file#"$rootfs_dir/tests/agent/scripts"/}"
        else
            script_path="$script_file"
        fi
        echo
        echo "===== Running ${script_path#"$TEST_SCRIPTS_DIR"/} ====="
        if [ "$use_bwrap" -eq 1 ]; then
            run_qemu_script_in_chroot "$qemu_mode" "$(basename "$qemu_runner")" "$rootfs_dir" "$script_path" >"$script_log" 2>&1
        else
            run_qemu_script_direct "$qemu_mode" "$qemu_runner" "$binary_path" "$script_path" >"$script_log" 2>&1
        fi
        script_rc=$?
        print_file_scrubbed "$script_log"
        rm -f "$script_log"
        if [ "$script_rc" -eq 2 ]; then
            echo "error: script parser/usage failure for $script_path" >&2
            rc=1
        fi
    done <"$script_list_file"

    rm -f "$script_list_file"

    cleanup_qemu_binary_wrapper
    trap - EXIT INT TERM HUP

    return "$rc"
}

run_qemu_isa_tests() {
    isa="$1"
    qemu_static_cmd="$2"
    qemu_binfmt_cmd="$3"
    shift 3

    binary_path="${BIN:-$RELEASE_BINARIES_DIR/$isa/ela-$isa}"
    compat_binary_path="$RELEASE_BINARIES_DIR/$isa/ela-$isa-compat"
    rc=0
    use_bwrap=0

    ensure_release_binaries "$isa"
    require_file "$binary_path"
    require_file "$TEST_SCRIPTS_DIR/linux/test_linux_dmesg_args.ela"
    require_file "$TEST_SCRIPTS_DIR/linux/test_linux_ssh_args.ela"

    qemu_resolution="$(resolve_qemu_mode "$qemu_static_cmd" "$qemu_binfmt_cmd")"
    qemu_mode="${qemu_resolution%%:*}"
    qemu_runner="${qemu_resolution#*:}"

    FW_AUDIT_TEST_ISA="$isa"
    export FW_AUDIT_TEST_ISA

    if command_exists bwrap && bwrap_supports_qemu_chroot; then
        use_bwrap=1
    else
        echo "warning: bwrap sandbox unavailable on this host; running qemu tests without chroot isolation" >&2
    fi

    if ! run_qemu_binary_tests "$isa" "$binary_path" "default" "$qemu_mode" "$qemu_runner" "$use_bwrap"; then
        rc=1
    fi

    if [ -z "${BIN:-}" ] && [ -x "$compat_binary_path" ]; then
        if ! run_qemu_binary_tests "$isa" "$compat_binary_path" "compat" "$qemu_mode" "$qemu_runner" "$use_bwrap"; then
            rc=1
        fi
    fi

    return "$rc"
}