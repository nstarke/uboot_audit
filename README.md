# embedded_linux_audit

![embedded_linux_audit logo](images/logo.png)

`embedded_linux_audit` is a Linux host-side C utility for U-Boot discovery and validation workflows on embedded systems. It focuses on three tasks:

- **Environment discovery** (`embedded_linux_audit uboot env`): scans flash/block devices for valid U-Boot environment candidates and can emit `fw_env.config` entries.
- **Image discovery/extraction** (`embedded_linux_audit uboot image`): scans for likely U-Boot image headers, resolves load addresses, and can pull image bytes.
- **Rule-based auditing** (`embedded_linux_audit uboot audit`): runs compiled rules against selected bytes to validate security and configuration expectations.
- **Linux utilities** (`embedded_linux_audit linux dmesg`, `embedded_linux_audit linux download-file`, `embedded_linux_audit linux execute-command`, `embedded_linux_audit linux grep`, `embedded_linux_audit linux list-files`, `embedded_linux_audit linux list-symlinks`, `embedded_linux_audit linux remote-copy`): collect logs, fetch files, execute commands, search directories, enumerate files/symlinks, and transfer files.
- **EFI utilities** (`embedded_linux_audit efi dump-vars`, `embedded_linux_audit efi orom`): dump EFI variables and work with EFI PCI option ROMs.

Running `embedded_linux_audit` with no arguments starts an interactive shell that exposes the same command groups/subcommands, supports tab completion when built with readline, supports up/down command history navigation, and provides a `set` helper for configuring `ELA_API_URL` and `ELA_API_INSECURE` in the current process.

## How it works

At runtime, `embedded_linux_audit` probes MTD/UBI and block devices (including SD/eMMC patterns), applies U-Boot-aware parsers/validators (CRC, FIT/uImage structure checks, rule engines), and produces human-readable or machine-readable output (`txt`, `csv`, `json`).

This makes it useful for field diagnostics, incident response, and recovery validation where you need a single tool to identify environments/images and assess boot-policy risk.

## Portable static GitHub release builds

GitHub Releases are produced by a cross-build workflow (`.github/workflows/release-cross-static.yml`) that compiles **fully static** binaries across many architectures using **Zig + musl** targets. Release artifacts are uploaded as per-architecture `ela-*` binaries.

Why this matters:

- No target-side dependency installation required for common use cases.
- Better portability across minimal/older Linux environments.
- Easier drop-in usage for triage and recovery workflows.

See [docs/agent/getting-started/build.md](docs/agent/getting-started/build.md) for the full build matrix.

## Documentation

The full usage and reference material has moved to the `docs/` folder:

- [Documentation index](docs/index.md)

## Companion API

This repository also includes a companion Node.js helper API in [`api/agent/`](api/agent/) for local collection and test workflows. The helper server is useful when you want a lightweight HTTP/HTTPS endpoint for agent uploads and a simple way to serve downloaded release binaries and agent test scripts.

Key capabilities:

- Accepts uploads for command output, `dmesg`, file contents, file lists, symlink lists, option ROM data, U-Boot images, and U-Boot environment data.
- Validates upload content types and stores runtime data under timestamped directories in `api/agent/data/`.
- Adds timestamp and source IP metadata to JSON command uploads.
- Serves a simple index at `GET /` plus helper routes for release binaries, agent test scripts, ISA assets, and U-Boot environment files.
- Can automatically download and cache the latest GitHub release binaries for `embedded_linux_audit`.

To start the companion API:

```bash
cd api/agent && npm install && npm start -- --host 0.0.0.0 --port 5000
```

Common options include:

- `--https` to enable HTTPS with a self-signed localhost certificate
- `--data-dir` to change the runtime storage location
- `--clean` to remove previous runtime upload data before startup
- `--force-download` to refresh cached release binaries
- `--verbose` to enable per-request console logging

For more detail, see [docs/api/agent/helper-server.md](docs/api/agent/helper-server.md).

## Licensing

This repository is split-license:

- The `embedded_linux_audit` agent and its associated build/test material are
  licensed under **GPL-3.0-or-later**. See [COPYING](COPYING).
- The helper API under `api/agent/` and other non-agent repository files are
  licensed under **MIT** unless noted otherwise. See [LICENSE.api](LICENSE.api).
- Third-party code under `third_party/` remains under its own licenses.

See [LICENSE](LICENSE) for the repository licensing breakdown.