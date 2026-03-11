#!/usr/bin/env bash
set -uo pipefail

ZIG_VERSION="${ZIG_VERSION:-0.14.0}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
CLEAN_ONLY=0

usage() {
  echo "Usage: $0 [--clean] [-j jobs] [target_name ...]" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clean)
      CLEAN_ONLY=1
      shift
      ;;
    --)
      shift
      break
      ;;
    -*)
      break
      ;;
    *)
      break
      ;;
  esac
done

while getopts ":j:" opt; do
  case "$opt" in
    j) JOBS="$OPTARG" ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))

SELECTED_TARGETS=("$@")

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${ROOT_DIR}/api/data/release_binaries"
WORK_DIR="${ROOT_DIR}/.build-release-static"
LOG_DIR="${WORK_DIR}/logs"
STATUS_DIR="${WORK_DIR}/status"
ZIG_DIR="${ROOT_DIR}/.tools/zig-linux-x86_64-${ZIG_VERSION}"
ZIG_BIN="${ZIG_DIR}/zig"

TARGETS_TABLE='
arm32-le|arm-linux-musleabi|arm32|arm-linux-musleabi
arm32-be|armeb-linux-musleabi,armeb-linux-gnueabi|armeb|armeb-linux-musleabi,armeb-linux-gnueabi
aarch64-le|aarch64-linux-musl|aarch64|aarch64-linux-musl
aarch64-be|aarch64_be-linux-musl|aarch64_be|aarch64_be-linux-musl
mips-le|mipsel-linux-musleabi,mipsel-linux-musleabihf|mipsel|mipsel-linux-musleabi
mips-be|mips-linux-musleabi,mips-linux-musleabihf|mips|mips-linux-musleabi
mips64-le|mips64el-linux-muslabi64,mips64el-linux-muslabin32,mips64el-linux-gnuabi64,mips64el-linux-gnuabin32|mips64el|mips64el-linux-muslabi64,mips64el-linux-gnuabi64
mips64-be|mips64-linux-muslabi64,mips64-linux-muslabin32,mips64-linux-gnuabi64,mips64-linux-gnuabin32|mips64|mips64-linux-muslabi64,mips64-linux-gnuabi64
powerpc-le|powerpc64le-linux-musl,powerpc64le-linux-gnu|powerpc64le|powerpc64le-linux-musl,powerpc64le-linux-gnu
powerpc-be|powerpc-linux-musleabi,powerpc-linux-musleabihf,powerpc-linux-gnueabi,powerpc-linux-gnueabihf|powerpc|powerpc-linux-musleabi,powerpc-linux-gnueabi
x86|x86-linux-musl|x86|x86-linux-musl
x86_64|x86_64-linux-musl|x86_64|x86_64-linux-musl
riscv32|riscv32-linux-musl,riscv32-linux-gnu|riscv32|riscv32-linux-musl,riscv32-linux-gnu
riscv64|riscv64-linux-musl,riscv64-linux-gnu|riscv64|riscv64-linux-musl,riscv64-linux-gnu
'

require_file() {
  local f="$1"
  [[ -f "$f" ]] || {
    echo "Missing required file: $f" >&2
    exit 1
  }
}

clean_outputs() {
  echo "Removing build output directories..."
  rm -rf "${WORK_DIR}" "${DIST_DIR}"
}

install_zig() {
  if [[ -x "${ZIG_BIN}" ]]; then
    echo "Using existing Zig: ${ZIG_BIN}"
    "${ZIG_BIN}" version
    return
  fi

  mkdir -p "${ROOT_DIR}/.tools"
  cd "${ROOT_DIR}/.tools" || exit 1

  local tarball="zig-linux-x86_64-${ZIG_VERSION}.tar.xz"
  local url="https://ziglang.org/download/${ZIG_VERSION}/${tarball}"

  echo "Downloading Zig ${ZIG_VERSION}..."
  curl -fsSL -o "${tarball}" "${url}"
  tar -xf "${tarball}"

  "${ZIG_BIN}" version
  cd "${ROOT_DIR}" || exit 1
}

should_build() {
  local name="$1"

  if [[ ${#SELECTED_TARGETS[@]} -eq 0 ]]; then
    return 0
  fi

  local t
  for t in "${SELECTED_TARGETS[@]}"; do
    [[ "$t" == "$name" ]] && return 0
  done
  return 1
}

job_log() {
  echo "${LOG_DIR}/$1.log"
}

job_status_file() {
  echo "${STATUS_DIR}/$1.status"
}

build_one_variant() {
  local build_kind="$1"
  local name="$2"
  local zig_targets_csv="$3"
  local compat_cpu="${4:-}"
  local output_path="$5"
  local repo_copy="$6"

  mkdir -p "$(dirname "$output_path")"
  IFS=',' read -r -a targets <<< "${zig_targets_csv}"

  local built=0
  local t
  for t in "${targets[@]}"; do
    if [[ "$build_kind" == "compat" ]]; then
      echo "Trying CPU_COMPAT target: ${t} (COMPAT_CPU=${compat_cpu})"
    else
      echo "Trying default target: ${t}"
    fi

    if (
      cd "${repo_copy}" || exit 1
      make clean &&
      env \
        CFLAGS= \
        CPPFLAGS= \
        CXXFLAGS= \
        LDFLAGS= \
        make static \
          ELA_USE_READLINE=0 \
          ${compat_cpu:+COMPAT_CPU=${compat_cpu}} \
          CMAKE_C_COMPILER="${ZIG_BIN}" \
          CMAKE_C_COMPILER_ARG1=cc \
          CMAKE_C_COMPILER_TARGET="${t}" \
          CC="${ZIG_BIN} cc -target ${t}"
    ); then
      cp "${repo_copy}/embedded_linux_audit" "${output_path}"
      echo "Built ${build_kind} successfully with target: ${t}"
      built=1
      break
    fi

    echo "${build_kind} target failed: ${t}"
  done

  [[ "$built" -eq 1 ]]
}

copy_repo_tree() {
  local repo_copy="$1"

  rm -rf "${repo_copy}"
  mkdir -p "${repo_copy}"

  if command -v rsync >/dev/null 2>&1; then
    rsync -a \
      --exclude '.git' \
      --exclude '.tools' \
      --exclude 'dist' \
      --exclude 'api/data/release_binaries' \
      --exclude '.build-release-static' \
      "${ROOT_DIR}/" "${repo_copy}/"
  else
    cp -a "${ROOT_DIR}/." "${repo_copy}/"
    rm -rf \
      "${repo_copy}/.git" \
      "${repo_copy}/.tools" \
      "${repo_copy}/dist" \
      "${repo_copy}/api/data/release_binaries" \
      "${repo_copy}/.build-release-static"
  fi
}

write_status() {
  local status_file="$1"
  local name="$2"
  local default_ok="$3"
  local compat_ok="$4"

  {
    printf 'name=%s\n' "${name}"
    printf 'default=%s\n' "${default_ok}"
    printf 'compat=%s\n' "${compat_ok}"
  } > "${status_file}"
}

build_target() {
  local name="$1"
  local zig_targets="$2"
  local cpu_compat="$3"
  local cpu_compat_zig_targets="$4"

  local log_file status_file repo_copy
  log_file="$(job_log "$name")"
  status_file="$(job_status_file "$name")"
  repo_copy="${WORK_DIR}/src-${name}"

  {
    echo "============================================================"
    echo "Building matrix target: ${name}"
    echo "zig_targets=${zig_targets}"
    echo "cpu_compat=${cpu_compat}"
    echo "cpu_compat_zig_targets=${cpu_compat_zig_targets}"
    echo "repo_copy=${repo_copy}"
    echo "============================================================"

    copy_repo_tree "${repo_copy}"

    local default_ok=0
    local compat_ok=0

    if build_one_variant \
      "default" \
      "${name}" \
      "${zig_targets}" \
      "" \
      "${DIST_DIR}/${name}/embedded_linux_audit-${name}" \
      "${repo_copy}"
    then
      default_ok=1
    else
      echo "All candidate default targets failed for ${name}" >&2
    fi

    if build_one_variant \
      "compat" \
      "${name}" \
      "${cpu_compat_zig_targets}" \
      "${cpu_compat}" \
      "${DIST_DIR}/${name}/embedded_linux_audit-${name}-compat" \
      "${repo_copy}"
    then
      compat_ok=1
    else
      echo "All candidate compat targets failed for ${name}" >&2
    fi

    write_status "${status_file}" "${name}" "${default_ok}" "${compat_ok}"
    rm -rf "${repo_copy}"
  } > "${log_file}" 2>&1
}

run_parallel() {
  local -a pids=()
  local -a names=()
  local running=0

  enqueue() {
    local name="$1"
    local zig_targets="$2"
    local cpu_compat="$3"
    local cpu_compat_zig_targets="$4"

    build_target "${name}" "${zig_targets}" "${cpu_compat}" "${cpu_compat_zig_targets}" &
    pids+=("$!")
    names+=("${name}")
    running=$((running + 1))
  }

  wait_one() {
    local pid="$1"
    local name="$2"

    if wait "${pid}"; then
      echo "[done] ${name}"
    else
      echo "[job error] ${name} (see $(job_log "${name}"))" >&2
    fi
  }

  maybe_wait() {
    while [[ "$running" -ge "$JOBS" ]]; do
      wait_one "${pids[0]}" "${names[0]}"
      pids=("${pids[@]:1}")
      names=("${names[@]:1}")
      running=$((running - 1))
    done
  }

  local line name zig_targets cpu_compat cpu_compat_zig_targets
  while IFS='|' read -r name zig_targets cpu_compat cpu_compat_zig_targets; do
    [[ -n "${name}" ]] || continue
    should_build "${name}" || continue

    maybe_wait
    enqueue "${name}" "${zig_targets}" "${cpu_compat}" "${cpu_compat_zig_targets}"
  done <<< "${TARGETS_TABLE}"

  while [[ "${#pids[@]}" -gt 0 ]]; do
    wait_one "${pids[0]}" "${names[0]}"
    pids=("${pids[@]:1}")
    names=("${names[@]:1}")
  done
}

print_summary() {
  local any_fail=0
  local st name default_ok compat_ok

  echo
  echo "Build summary"
  echo "============="

  for st in "${STATUS_DIR}"/*.status; do
    [[ -e "$st" ]] || continue

    name="$(awk -F= '/^name=/{print $2}' "$st")"
    default_ok="$(awk -F= '/^default=/{print $2}' "$st")"
    compat_ok="$(awk -F= '/^compat=/{print $2}' "$st")"

    echo "${name}: default=${default_ok} compat=${compat_ok}"

    if [[ "$default_ok" != "1" || "$compat_ok" != "1" ]]; then
      any_fail=1
      echo "  log: $(job_log "${name}")"
    fi
  done

  echo
  echo "Artifacts written to:"
  echo "  ${DIST_DIR}"

  echo
  echo "Built files:"
  find "${DIST_DIR}" -type f | sort || true

  return "${any_fail}"
}

main() {
  if [[ "${CLEAN_ONLY}" -eq 1 ]]; then
    clean_outputs
    return 0
  fi

  require_file "${ROOT_DIR}/agent/embedded_linux_audit.c"
  require_file "${ROOT_DIR}/agent/embedded_linux_audit_cmd.h"
  require_file "${ROOT_DIR}/third_party/libefivar/src/include/efivar/efivar.h"
  require_file "${ROOT_DIR}/third_party/ncurses/configure"
  require_file "${ROOT_DIR}/third_party/readline/readline.h"

  if ! [[ "${JOBS}" =~ ^[0-9]+$ ]] || [[ "${JOBS}" -lt 1 ]]; then
    echo "Invalid JOBS value: ${JOBS}" >&2
    exit 1
  fi

  mkdir -p "${DIST_DIR}" "${WORK_DIR}" "${LOG_DIR}" "${STATUS_DIR}"

  install_zig
  run_parallel

  if ! print_summary; then
    exit 1
  fi
}

main "$@"