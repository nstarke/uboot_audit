# embedded_linux_audit

![embedded_linux_audit logo](images/logo.png)

`embedded_linux_audit` is a Linux host-side C utility for U-Boot discovery and validation workflows on embedded systems. It focuses on three tasks:

- **Environment discovery** (`embedded_linux_audit uboot env`): scans flash/block devices for valid U-Boot environment candidates and can emit `fw_env.config` entries.
- **Image discovery/extraction** (`embedded_linux_audit uboot image`): scans for likely U-Boot image headers, resolves load addresses, and can pull image bytes.
- **Rule-based auditing** (`embedded_linux_audit uboot audit`): runs compiled rules against selected bytes to validate security and configuration expectations.
- **Linux utilities** (`embedded_linux_audit linux dmesg`, `embedded_linux_audit linux remote-copy`): collect kernel logs and transfer files.

Running `embedded_linux_audit` with no arguments starts an interactive shell that exposes the same command groups/subcommands, supports tab completion when built with readline, supports up/down command history navigation, and provides a `set` helper for configuring `ELA_API_URL` and `ELA_API_INSECURE` in the current process.

## How it works

At runtime, `embedded_linux_audit` probes MTD/UBI and block devices (including SD/eMMC patterns), applies U-Boot-aware parsers/validators (CRC, FIT/uImage structure checks, rule engines), and produces human-readable or machine-readable output (`txt`, `csv`, `json`).

This makes it useful for field diagnostics, incident response, and recovery validation where you need a single tool to identify environments/images and assess boot-policy risk.

## Portable static GitHub release builds

GitHub Releases are produced by a cross-build workflow (`.github/workflows/release-cross-static.yml`) that compiles **fully static** binaries across many architectures using **Zig + musl** targets. Release artifacts are uploaded as per-architecture `embedded_linux_audit-*` binaries.

Why this matters:

- No target-side dependency installation required for common use cases.
- Better portability across minimal/older Linux environments.
- Easier drop-in usage for triage and recovery workflows.

For older targets that are sensitive to CPU baseline differences, the build also
supports `COMPAT_CPU=<profile>` to add conservative ISA-specific compiler flags
for the selected architecture family. This is especially useful when testing on
older MIPS and PowerPC systems that may otherwise fail with `Illegal Instruction`.

Examples:

```bash
make clean && make static ELA_USE_READLINE=0 COMPAT_CPU=mips \
  CMAKE_C_COMPILER=$(command -v zig) \
  CMAKE_C_COMPILER_ARG1=cc \
  CMAKE_C_COMPILER_TARGET=mips-linux-musleabi \
  CC='zig cc -target mips-linux-musleabi'

make clean && make static ELA_USE_READLINE=0 COMPAT_CPU=powerpc \
  CMAKE_C_COMPILER=$(command -v zig) \
  CMAKE_C_COMPILER_ARG1=cc \
  CMAKE_C_COMPILER_TARGET=powerpc-linux-musleabi \
  CC='zig cc -target powerpc-linux-musleabi'
```

See [docs/build.md](docs/build.md) for the full build matrix and supported
compatibility profiles.

## Documentation

The full usage and reference material has moved to the `docs/` folder:

- [Documentation index](docs/index.md)

## Companion API

This repository also includes a companion Node.js helper API in [`api/`](api/) for local collection and test workflows. The helper server is useful when you want a lightweight HTTP/HTTPS endpoint for agent uploads and a simple way to serve downloaded release binaries and agent test scripts.

Key capabilities:

- Accepts uploads for command output, `dmesg`, file contents, file lists, symlink lists, option ROM data, U-Boot images, and U-Boot environment data.
- Validates upload content types and stores runtime data under timestamped directories in `api/data/`.
- Adds timestamp and source IP metadata to JSON command uploads.
- Serves a simple index at `GET /` plus helper routes for release binaries, agent test scripts, ISA assets, and U-Boot environment files.
- Can automatically download and cache the latest GitHub release binaries for `embedded_linux_audit`.

To start the companion API:

```bash
cd api && npm install && npm start -- --host 0.0.0.0 --port 5000
```

Common options include:

- `--https` to enable HTTPS with a self-signed localhost certificate
- `--data-dir` to change the runtime storage location
- `--clean` to remove previous runtime upload data before startup
- `--force-download` to refresh cached release binaries
- `--verbose` to enable per-request console logging

For more detail, see [docs/api-helper-server.md](docs/api-helper-server.md).