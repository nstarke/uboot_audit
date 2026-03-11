#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
RELEASE_BINARIES_DIR="${RELEASE_BINARIES_DIR:-$REPO_ROOT/api/data/release_binaries}"
TEST_SCRIPTS_DIR="$REPO_ROOT/tests/agent/scripts"
RELEASE_BUILD_SCRIPT="$REPO_ROOT/tests/compile_release_binaries_locally.sh"
SUPPORTED_ISAS="arm32-le arm32-be aarch64-le aarch64-be mips-le mips-be mips64-le mips64-be powerpc-le powerpc-be x86 x86_64 riscv32 riscv64"

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

require_command() {
    if ! command_exists "$1"; then
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
        if [ ! -x "$RELEASE_BINARIES_DIR/$isa_name/embedded_linux_audit-$isa_name" ]; then
            missing=1
            break
        fi
    done

    if [ "$missing" -eq 1 ]; then
        require_file "$RELEASE_BUILD_SCRIPT"
        build_jobs="$(cpu_jobs_for_build)"
        if [ -n "$requested_isa" ]; then
            echo "Release binary missing for $requested_isa; compiling via tests/compile_release_binaries_locally.sh -j$build_jobs $requested_isa"
            /bin/sh "$RELEASE_BUILD_SCRIPT" -j"$build_jobs" "$requested_isa"
        else
            echo "Release binaries missing; compiling all ISAs via tests/compile_release_binaries_locally.sh -j$build_jobs"
            /bin/sh "$RELEASE_BUILD_SCRIPT" -j"$build_jobs"
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

    cp "$TEST_SCRIPTS_DIR"/*.ela "$rootfs_dir/tests/agent/scripts/"

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

run_qemu_isa_tests() {
    isa="$1"
    qemu_static_cmd="$2"
    qemu_binfmt_cmd="$3"
    shift 3

    binary_path="${BIN:-$RELEASE_BINARIES_DIR/$isa/embedded_linux_audit-$isa}"
    rootfs_dir="$(mktemp -d /tmp/ela-qemu-rootfs-${isa}.XXXXXX)"
    rc=0
    qemu_resolution=""
    qemu_mode=""
    qemu_runner=""

    ensure_release_binaries "$isa"
    require_command bwrap
    require_file "$binary_path"
    require_file "$TEST_SCRIPTS_DIR/test_linux_dmesg_args.ela"

    qemu_resolution="$(resolve_qemu_mode "$qemu_static_cmd" "$qemu_binfmt_cmd")"
    qemu_mode="${qemu_resolution%%:*}"
    qemu_runner="${qemu_resolution#*:}"

    cleanup_qemu_wrapper() {
        rm -rf "$rootfs_dir"
    }

    trap cleanup_qemu_wrapper EXIT INT TERM HUP

    if [ "$qemu_mode" = "static" ]; then
        create_chroot_tree "$rootfs_dir" "$isa" "$binary_path" "$qemu_runner"
    else
        create_chroot_tree "$rootfs_dir" "$isa" "$binary_path"
    fi

    echo "Running agent script coverage for ISA '$isa' via $qemu_mode:$qemu_runner"
    echo "Release binary: $binary_path"
    echo "Chroot rootfs: $rootfs_dir"

    for script_file in "$rootfs_dir"/tests/agent/scripts/*.ela; do
        script_path="/tests/agent/scripts/$(basename "$script_file")"
        echo
        echo "===== Running $(basename "$script_file") ====="
        if ! run_qemu_script_in_chroot "$qemu_mode" "$(basename "$qemu_runner")" "$rootfs_dir" "$script_path" "$@"; then
            rc=1
        fi
    done

    return "$rc"
}