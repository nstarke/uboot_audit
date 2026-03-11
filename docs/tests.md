# Tests

This repository includes shell-based argument coverage tests under `tests/agent/`.

- `tests/agent/` contains the existing agent shell tests.
- `tests/api/agent/` is reserved for api-related tests.

## Prerequisites

- Build the binary first:

```bash
make
```

- Test scripts expect `./embedded_linux_audit` at the repo root.

## Run all tests

Use either:

```bash
make test
```

or directly:

```bash
bash tests/agent/test_all.sh
```

`test_all.sh` executes:
- `tests/agent/test_uboot_env_args.sh`
- `tests/agent/test_uboot_image_args.sh`
- `tests/agent/test_uboot_audit_args.sh`
- `tests/agent/test_linux_dmesg_args.sh`
- `tests/agent/test_linux_list_files_args.sh`
- `tests/agent/test_linux_remote_copy_args.sh`
- `tests/agent/test_efi_bios_orom_args.sh`

It returns non-zero if any test group fails.

## Run individual test groups

```bash
sh tests/agent/test_uboot_env_args.sh
sh tests/agent/test_uboot_image_args.sh
sh tests/agent/test_uboot_audit_args.sh
sh tests/agent/test_linux_dmesg_args.sh
sh tests/agent/test_linux_list_files_args.sh
sh tests/agent/test_linux_remote_copy_args.sh
sh tests/agent/test_efi_bios_orom_args.sh
```

## What each test script covers

- `test_uboot_env_args.sh`: validates accepted/expected behavior of `uboot env` arguments.
- `test_uboot_image_args.sh`: validates accepted/expected behavior of `uboot image` arguments and mode combinations.
- `test_uboot_audit_args.sh`: validates accepted/expected behavior of `uboot audit` arguments, output formats, and rule selections.
- `test_linux_dmesg_args.sh`: validates accepted/expected behavior of `linux dmesg` arguments and `--output-format` warning behavior.
- `test_linux_list_files_args.sh`: validates accepted/expected behavior of `linux list-files` arguments, directory requirements, `--recursive` traversal, remote output options, `--suid-only` filtering, and `--output-format` warning behavior.
- `test_linux_remote_copy_args.sh`: validates accepted/expected behavior of `linux remote-copy` arguments and transfer-target constraints.
- `test_efi_bios_orom_args.sh`: validates accepted/expected behavior of `efi/bios orom` arguments.

These are argument/CLI behavior coverage tests, not full hardware integration tests.

## Optional HTTP/HTTPS output override while testing

`test_all.sh` supports:

```bash
bash tests/agent/test_all.sh --output-http http://127.0.0.1:5000/test
bash tests/agent/test_all.sh --output-http https://127.0.0.1:5443/test
```

You can also set environment variables used by shared test helpers:

- `TEST_OUTPUT_HTTP`
- `TEST_OUTPUT_HTTP`

Set only one of them at a time.

## Download helper for release-binary test runs

`tests/agent/download_tests.sh` can download test scripts and a selected release binary from a api server.

List supported ISAs (derived from `tools/release_binaries/embedded_linux_audit-*`):

```bash
sh tests/agent/download_tests.sh --list-isa
```

Download scripts + binary:

```bash
sh tests/agent/download_tests.sh --webserver http://<host>:<port> --isa <arch>
```

Optional output directory:

```bash
sh tests/agent/download_tests.sh --webserver http://<host>:<port> --isa <arch> --output-directory /tmp/fw-tests
```
