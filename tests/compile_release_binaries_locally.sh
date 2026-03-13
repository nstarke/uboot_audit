#!/bin/sh

set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=tests/system_package_helpers.sh
. "$SCRIPT_DIR/system_package_helpers.sh"

DEST_RELEASE_DIR="${RELEASE_BINARIES_DIR:-$REPO_ROOT/api/data/release_binaries}"
TOOLS_CACHE_DIR="$REPO_ROOT/.cache/tools"
ZIG_VERSION="0.14.0"
SUPPORTED_ISAS="arm32-le arm32-be aarch64-le aarch64-be mips-le mips-be mips64-le mips64-be powerpc-le powerpc-be x86 x86_64 riscv32 riscv64"

REQUIRED_SUBMODULE_PATHS="
third_party/libcsv/libcsv.c
third_party/json-c/CMakeLists.txt
third_party/curl/CMakeLists.txt
third_party/openssl/Configure
third_party/libubootenv/CMakeLists.txt
third_party/zlib/CMakeLists.txt
third_party/readline/readline.h
third_party/ncurses/configure
third_party/libefivar/src/include/efivar/efivar.h
third_party/wolfssl/configure.ac
"

usage() {
    echo "Usage: $0 [--clean] [-j jobs|--jobs jobs|--jobs=jobs] [isa ...]" >&2
    exit 1
}

clean_outputs() {
    rm -rf "$DEST_RELEASE_DIR"
}

require_command() {
    if ! ela_ensure_command "$1"; then
        echo "error: missing required command: $1" >&2
        exit 1
    fi
}

ensure_required_submodules() {
    missing_paths=""

    for required_path in $REQUIRED_SUBMODULE_PATHS; do
        if [ ! -e "$REPO_ROOT/$required_path" ]; then
            missing_paths="$missing_paths $required_path"
        fi
    done

    if [ -z "$missing_paths" ]; then
        return 0
    fi

    if [ -d "$REPO_ROOT/.git" ] || [ -f "$REPO_ROOT/.git" ]; then
        require_command git
        echo "Required third_party sources are missing; initializing git submodules" >&2
        if git -C "$REPO_ROOT" submodule update --init --recursive; then
            missing_paths=""
            for required_path in $REQUIRED_SUBMODULE_PATHS; do
                if [ ! -e "$REPO_ROOT/$required_path" ]; then
                    missing_paths="$missing_paths $required_path"
                fi
            done
            if [ -z "$missing_paths" ]; then
                return 0
            fi
        fi
    fi

    echo "error: required third_party sources are missing:$missing_paths" >&2
    echo "hint: run 'git submodule update --init --recursive' from $REPO_ROOT" >&2
    exit 1
}

download_file() {
    url="$1"
    output_path="$2"

    ela_ensure_any_command curl wget >/dev/null 2>&1 || {
        echo "error: need curl or wget to download $url" >&2
        exit 1
    }

    if command -v curl >/dev/null 2>&1; then
        curl -fL "$url" -o "$output_path"
        return 0
    fi

    if command -v wget >/dev/null 2>&1; then
        wget -O "$output_path" "$url"
        return 0
    fi

    echo "error: need curl or wget to download $url" >&2
    exit 1
}

ensure_zig() {
    if command -v zig >/dev/null 2>&1; then
        return 0
    fi

    host_os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    host_arch="$(uname -m)"

    case "$host_os" in
        linux)
            ;;
        *)
            echo "error: zig not found on PATH and automatic Zig download is unsupported on host OS: $host_os" >&2
            exit 1
            ;;
    esac

    case "$host_arch" in
        x86_64|amd64)
            zig_host="x86_64-linux"
            zig_download_host="linux-x86_64"
            ;;
        aarch64|arm64)
            zig_host="aarch64-linux"
            zig_download_host="linux-aarch64"
            ;;
        *)
            echo "error: zig not found on PATH and automatic Zig download is unsupported on host arch: $host_arch" >&2
            exit 1
            ;;
    esac

    zig_dir="$TOOLS_CACHE_DIR/zig/$ZIG_VERSION/$zig_host"
    zig_bin="$zig_dir/zig"

    if [ ! -x "$zig_bin" ]; then
        archive_name="zig-$zig_download_host-$ZIG_VERSION.tar.xz"
        archive_url="https://ziglang.org/download/$ZIG_VERSION/$archive_name"
        tmp_dir="$TOOLS_CACHE_DIR/zig/tmp"
        archive_path="$tmp_dir/$archive_name"
        extract_dir="$tmp_dir/extract-$zig_host-$ZIG_VERSION"
        extracted_root="$extract_dir/zig-$zig_download_host-$ZIG_VERSION"

        echo "zig not found on PATH; downloading Zig $ZIG_VERSION for $zig_host"
        mkdir -p "$tmp_dir"
        rm -rf "$extract_dir"
        download_file "$archive_url" "$archive_path"
        mkdir -p "$extract_dir"
        tar -xJf "$archive_path" -C "$extract_dir"

        if [ ! -x "$extracted_root/zig" ]; then
            echo "error: downloaded Zig archive did not contain expected binary: $extracted_root/zig" >&2
            exit 1
        fi

        mkdir -p "$(dirname "$zig_dir")"
        rm -rf "$zig_dir"
        mv "$extracted_root" "$zig_dir"
        rm -rf "$extract_dir"
        rm -f "$archive_path"
    fi

    PATH="$zig_dir:$PATH"
    export PATH
}

set_isa_config() {
    isa="$1"

    case "$isa" in
        arm32-le)
            zig_targets="arm-linux-musleabi"
            ;;
        arm32-be)
            zig_targets="armeb-linux-musleabi,armeb-linux-gnueabi"
            ;;
        aarch64-le)
            zig_targets="aarch64-linux-musl"
            ;;
        aarch64-be)
            zig_targets="aarch64_be-linux-musl"
            ;;
        mips-le)
            zig_targets="mipsel-linux-musleabi,mipsel-linux-musleabihf"
            ;;
        mips-be)
            zig_targets="mips-linux-musleabi,mips-linux-musleabihf"
            ;;
        mips64-le)
            zig_targets="mips64el-linux-muslabi64,mips64el-linux-gnuabi64"
            ;;
        mips64-be)
            zig_targets="mips64-linux-muslabi64,mips64-linux-gnuabi64"
            ;;
        powerpc-le)
            zig_targets="powerpc64le-linux-musl,powerpc64le-linux-gnu"
            ;;
        powerpc-be)
            zig_targets="powerpc-linux-musleabi,powerpc-linux-musleabihf,powerpc-linux-gnueabi,powerpc-linux-gnueabihf"
            ;;
        x86)
            zig_targets="x86-linux-musl"
            ;;
        x86_64)
            zig_targets="x86_64-linux-musl"
            ;;
        riscv32)
            zig_targets="riscv32-linux-musl,riscv32-linux-gnu"
            ;;
        riscv64)
            zig_targets="riscv64-linux-musl,riscv64-linux-gnu"
            ;;
        *)
            echo "error: unsupported isa: $isa" >&2
            echo "supported: $SUPPORTED_ISAS" >&2
            exit 1
            ;;
    esac
}

build_with_targets() {
    output_path="$1"
    target_list="$2"

    old_ifs="$IFS"
    IFS=,
    set -- $target_list
    IFS="$old_ifs"

    for target in "$@"; do
        echo "Trying target: $target"
        if [ "$clean_before_build" -eq 1 ]; then
            if ! make clean; then
                build_ok=0
                echo "Clean failed before target: $target"
                continue
            fi
        fi

        build_ok=1
        make static \
            JOBS="$jobs_arg" \
            ELA_USE_READLINE=0 \
            CMAKE_C_COMPILER="$(command -v zig)" \
            CMAKE_C_COMPILER_ARG1=cc \
            CMAKE_C_COMPILER_TARGET="$target" \
            CC="zig cc -target $target" || build_ok=0

        if [ "$build_ok" -eq 1 ]; then
            cp "$REPO_ROOT/embedded_linux_audit" "$output_path"
            chmod 755 "$output_path"
            return 0
        fi
        echo "Target failed: $target"
    done

    return 1
}

build_release_binary() {
    isa="$1"
    dest_dir="$DEST_RELEASE_DIR/$isa"
    dest="$dest_dir/ela-$isa"

    set_isa_config "$isa"

    mkdir -p "$dest_dir"

    export CFLAGS=
    export CPPFLAGS=
    export CXXFLAGS=
    export LDFLAGS=

    test -f "$REPO_ROOT/agent/embedded_linux_audit.c"
    test -f "$REPO_ROOT/agent/embedded_linux_audit_cmd.h"
    test -f "$REPO_ROOT/third_party/libefivar/src/include/efivar/efivar.h"
    test -f "$REPO_ROOT/third_party/ncurses/configure"
    test -f "$REPO_ROOT/third_party/readline/readline.h"

    echo "Building release binary for $isa"
    if ! build_with_targets "$dest" "$zig_targets"; then
        echo "error: failed to build default static binary for $isa" >&2
        exit 1
    fi

}

clean_before_build=0
jobs_arg="${JOBS:-4}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --clean)
            clean_before_build=1
            shift
            ;;
        --jobs)
            [ "$#" -ge 2 ] || usage
            jobs_arg="$2"
            shift 2
            ;;
        --jobs=*)
            jobs_arg="${1#--jobs=}"
            [ -n "$jobs_arg" ] || usage
            shift
            ;;
        -j)
            [ "$#" -ge 2 ] || usage
            jobs_arg="$2"
            shift 2
            ;;
        -j*)
            jobs_arg="${1#-j}"
            [ -n "$jobs_arg" ] || usage
            shift
            ;;
        --)
            shift
            break
            ;;
        -*)
            usage
            ;;
        *)
            break
            ;;
    esac
done

if [ "$clean_before_build" -eq 1 ]; then
    clean_outputs
fi

ensure_required_submodules
ensure_zig
require_command cmake
require_command tar
require_command cc
require_command ar
require_command ranlib
require_command perl
require_command libtool
require_command aclocal
require_command autoconf

require_command python3
require_command bash
require_command make

if [ "$#" -gt 0 ]; then
    for isa in "$@"; do
        build_release_binary "$isa"
    done
else
    for isa in $SUPPORTED_ISAS; do
        build_release_binary "$isa"
    done
fi

echo "Release binaries compiled under $DEST_RELEASE_DIR"