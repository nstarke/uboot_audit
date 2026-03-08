# uboot_audit

This repo provides a Linux host-side C utility for U-Boot-related flash analysis:

- `uboot_audit env`: find U-Boot environment candidates and print `fw_env.config` lines.
- `uboot_audit image`: find likely U-Boot image headers, optionally pull image bytes, or resolve load address.
- `uboot_audit audit`: run audit rules (from `audit-rules/*.c`) against selected bytes.

Both tools are intended for embedded/Linux recovery and diagnostics workflows.

Global option:

- `--output-format <csv|json|txt>` — select requested output format at the `uboot_audit` wrapper level (default: `txt`)
  - `txt`: existing human-readable output
  - `csv`: comma-separated records (header + rows)
  - `json`: newline-delimited JSON objects (one JSON object per line)
  - when `--verbose` is enabled with `csv`/`json`, verbose messages are emitted as structured `verbose` records (instead of plain text lines)
- `env --output-tcp <ip:port>` sends the same formatted stream selected by `--output-format` over TCP.
- `env --output-http <http://host:port/path>` sends the same formatted stream selected by `--output-format` in a single HTTP POST request.
- `env --output-https <https://host:port/path>` sends the same formatted stream selected by `--output-format` in a single HTTPS POST request using embedded CA certificates.
- `env --insecure` disables TLS certificate and hostname verification for HTTPS output.
- `image --output-tcp` is used for `--pull` binary streaming; for formatted scan/find-address output over TCP, use `image --send-logs --output-tcp ...`.
- `image --output-http <http://host:port/path>` can be used to POST formatted scan/find-address output, or to POST pulled image bytes when used with `--pull`.
- `image --output-https <https://host:port/path>` can be used to POST formatted scan/find-address output, or to POST pulled image bytes when used with `--pull`, using embedded CA certificates.
- `image --insecure` disables TLS certificate and hostname verification for HTTPS output.

---

## Build

Build binary:

```bash
make env
```

Build binary (alias):

```bash
make image
```

Build both:

```bash
git submodule update --init --recursive
make
```

Notes:

- `libcsv` is built from source directly from `third_party/libcsv/libcsv.c`.
- `json-c` is built from source from the `third_party/json-c` submodule via CMake, and linked statically (`third_party/json-c/build/libjson-c.a`).
- `libcurl` is built from source from the `third_party/curl` submodule via CMake, and linked statically (`third_party/curl/build/lib/libcurl.a`).
- `OpenSSL` is built from source from the `third_party/openssl` submodule (`libcrypto` static) and used for audit signature verification.
- The default CA bundle is fetched from `https://curl.se/ca/cacert.pem` at build time and embedded into the binary.
- Override bundle source with:
  - `CA_BUNDLE_URL=<url>` to change download URL
  - `CA_BUNDLE_PEM=<path>` to use a local PEM file instead of downloading

Static build:

```bash
make static
```

Clean:

```bash
make clean
```

Cross compile example:

```bash
make CC=arm-linux-gnueabi-gcc
```

Cross compile with Zig + musl (recommended for fully static output):

```bash
make clean && make static \
  CMAKE_C_COMPILER=$(command -v zig) \
  CMAKE_C_COMPILER_ARG1=cc \
  CMAKE_C_COMPILER_TARGET=arm-linux-musleabi \
  CC='zig cc -target arm-linux-musleabi'
```

Generic Zig target form:

```bash
make clean && make static \
  CMAKE_C_COMPILER=$(command -v zig) \
  CMAKE_C_COMPILER_ARG1=cc \
  CMAKE_C_COMPILER_TARGET=<zig-target-triple> \
  CC='zig cc -target <zig-target-triple>'
```

Examples:

```bash
# x86_64 static musl
make clean && make static \
  CMAKE_C_COMPILER=$(command -v zig) \
  CMAKE_C_COMPILER_ARG1=cc \
  CMAKE_C_COMPILER_TARGET=x86_64-linux-musl \
  CC='zig cc -target x86_64-linux-musl'

# aarch64 static musl
make clean && make static \
  CMAKE_C_COMPILER=$(command -v zig) \
  CMAKE_C_COMPILER_ARG1=cc \
  CMAKE_C_COMPILER_TARGET=aarch64-linux-musl \
  CC='zig cc -target aarch64-linux-musl'
```

---

## `uboot_audit env`

Scans MTD/UBI plus block devices (SD/eMMC such as `/dev/sd*` and `/dev/mmcblk*`) for blocks that resemble a valid U-Boot environment (CRC-verified by default), then prints candidate `fw_env.config` lines.

### `env` arguments

- `--verbose` — print scan progress and non-hit details
- `--size <env_size>` — fixed environment size (for example `0x10000`)
- `--hint <hint>` — override hint string used for positive labeling
- `--dev <device>` — scan only one device (step inferred from sysfs/proc)
- `--brutefoce` / `--bruteforce` — skip CRC checks and match by hint strings only
- `--skip-remove` — keep any created helper `/dev/mtdblock*`/UBI device nodes after run
- `--skip-mtd` — skip MTD/mtdblock scan targets and helper node handling
- `--skip-ubi` — skip UBI/ubiblock scan targets and helper node handling
- `--skip-sd` — skip `/dev/sd*` scan targets
- `--skip-emmc` — skip `/dev/mmcblk*` scan targets
- `--parse-vars` — print parsed key/value variables from candidate environments
- `--output-config[=<path>]` — write discovered `fw_env.config` lines to file (default `fw_env.config`)
- `--output-tcp <IPv4:port>` — duplicate output to TCP destination
- `--output-http <http://host:port/path>` — duplicate output to HTTP endpoint via POST
- `--output-https <https://host:port/path>` — duplicate output to HTTPS endpoint via POST
- `--insecure` — disable TLS certificate and hostname verification for HTTPS output
- `--write <path>` — apply env updates from text file (native `fw_setenv`-style behavior)

### `--write` behavior

- Uses `./fw_env.config` for write settings.
  - If `./fw_env.config` exists, it is used directly.
  - If it does not exist, the tool first runs scan logic to generate it, then writes.
- Input file format (similar to `fw_setenv -s`):
  - `name=value` or `name value` → set variable
  - `name` (no value) → delete variable
  - blank lines and `#` comments are ignored
- Validations performed:
  - variable name must be non-empty
  - variable name must not contain `=`
  - variable name must not contain whitespace or control characters
  - sensitive variable updates/deletes require interactive confirmation:
    - prompt: `Modifying $ENVIRONMENT_VARIABLE_NAME might render the host unbootable.  Do you wish to proceed?`
    - only `Y`/`y` proceeds; any other response skips that variable write/delete
  - existing environment CRC must be valid before writing
  - updated environment must fit configured environment size
- CRC is recalculated and written back (standard or redundant layout detected from existing env data).

### `env` examples

```bash
./uboot_audit env
./uboot_audit --output-format json env
./uboot_audit env --verbose
./uboot_audit env --size 0x10000
./uboot_audit env --dev /dev/mtd3 --size 0x10000
./uboot_audit env --size 0x10000 /dev/mtd0:0x10000 /dev/mtd1:0x20000
./uboot_audit env --output-tcp 192.168.1.50:5000 --verbose
./uboot_audit env --output-http http://192.168.1.50:5000/env --verbose
./uboot_audit env --output-https https://192.168.1.50:5443/env --verbose
./uboot_audit env --write ./new_env.txt
```

For machine-readable output:

```bash
./uboot_audit --output-format csv env
./uboot_audit --output-format json env
```

Example candidate line:

```text
fw_env.config line: /dev/mtd0 0x40000 0x10000 0x10000 0x1
```

---

## `uboot_audit image`

Scans MTD/UBI and block devices (SD/eMMC such as `/dev/sd*` and `/dev/mmcblk*`) for likely U-Boot image signatures. FIT/uImage checks are validated structurally to reduce false positives.

### `image` arguments

- `--verbose` — print scan progress
- `--dev <device>` — restrict scan or action to one device
- `--step <bytes>` — scan stride (default `0x1000`)
- `--allow-text` — also match plain `U-Boot` text (higher false-positive risk)
- `--skip-remove` — keep any helper `/dev` nodes created during scan
- `--skip-mtd` — skip MTD/mtdblock scan targets
- `--skip-ubi` — skip UBI/ubiblock scan targets
- `--skip-sd` — skip `/dev/sd*` scan targets
- `--skip-emmc` — skip `/dev/mmcblk*` scan targets
- `--send-logs` — send tool logs over TCP using `--output-tcp <IPv4:port>`
- `--pull` — pull image bytes from `--dev` at `--offset` and send over TCP to `--output-tcp`
- `--offset <bytes>` — image offset used by `--pull` or `--find-address`
- `--output-tcp <IPv4:port>` — TCP destination used by `--pull`
- `--output-http <http://host:port/path>` — HTTP destination used by `--pull` (POST body contains image bytes), or for posting normal command output
- `--output-https <https://host:port/path>` — HTTPS destination used by `--pull` (POST body contains image bytes), or for posting normal command output
- `--insecure` — disable TLS certificate and hostname verification for HTTPS output
- `--find-address` — parse image at `--offset` and print load address (uImage/FIT)

### `image` argument constraints

- `--pull` **requires**:
  - `--dev`
  - `--offset`
  - exactly one of `--output-tcp`, `--output-http`, or `--output-https`
- `--find-address` **requires**:
  - `--dev`
  - `--offset`
- `--find-address` **cannot** be combined with:
  - `--pull`
  - `--output-tcp` (unless `--send-logs` is also set)
- `--send-logs` **requires**:
  - `--output-tcp`
- `--send-logs` **cannot** be combined with:
  - `--pull`

### `image` examples

Scan all MTD devices:

```bash
./uboot_audit image --verbose
./uboot_audit --output-format csv image --verbose
```

For machine-readable output:

```bash
./uboot_audit --output-format json image --verbose
./uboot_audit --output-format csv image --find-address --dev /dev/mtdblock4 --offset 0x200
```

Scan one device:

```bash
./uboot_audit image --dev /dev/mtdblock4 --step 0x1000
```

Find load address at known offset:

```bash
./uboot_audit image --find-address --dev /dev/mtdblock4 --offset 0x200
```

Send scan logs over TCP:

```bash
./uboot_audit image --verbose --send-logs --output-tcp 192.168.1.50:5000
```

Pull image bytes to TCP listener:

```bash
./uboot_audit image --pull --dev /dev/mtdblock4 --offset 0x200 --output-tcp 192.168.1.50:5000
./uboot_audit image --pull --dev /dev/mtdblock4 --offset 0x200 --output-http http://192.168.1.50:5000/image
./uboot_audit image --pull --dev /dev/mtdblock4 --offset 0x200 --output-https https://192.168.1.50:5443/image
./uboot_audit image --verbose --output-http http://192.168.1.50:5000/image
./uboot_audit image --verbose --output-https https://192.168.1.50:5443/image
```

---

## `uboot_audit audit`

Runs compiled audit rules that are defined under `audit-rules/` (one `.c` file per rule).

### `audit` arguments

- `--list-rules` — list available compiled rules
- `--rule <name>` — run a single rule by name
- `--dev <device>` — input device/file to audit
- `--offset <bytes>` — read offset (default `0`)
- `--size <bytes>` — number of bytes to read and pass to rules
- `--signature-blob <path>` — blob file used by signature-verifying rules
- `--signature-pubkey <path>` — PEM public key used by signature-verifying rules
- `--scan-signature-devices` — force scan of MTD/UBI/eMMC/SD devices to auto-discover a FIT blob and embedded PEM public key
- if `--signature-blob` or `--signature-pubkey` is missing, device scan is attempted automatically to fill missing artifact(s)
- `--signature-alg <name>` — digest algorithm for signature verification; if omitted, tries likely digests in order: `sha256`, `sha384`, `sha512`, `sha1`, `sha224`
- `--verbose` — enable verbose rule behavior where supported

### `audit` examples

```bash
./uboot_audit audit --list-rules
./uboot_audit audit --dev /dev/mtdblock4 --offset 0x0 --size 0x10000
./uboot_audit audit --rule uboot_validate_crc32 --dev /dev/mtdblock4 --offset 0x0 --size 0x10000
./uboot_audit audit --rule uboot_validate_secureboot --dev /dev/mtdblock4 --offset 0x0 --size 0x10000 --signature-blob ./fit-image.bin --signature-pubkey ./pubkey.pem --signature-alg sha256
./uboot_audit audit --rule uboot_validate_secureboot --dev /dev/mtdblock4 --offset 0x0 --size 0x10000 --scan-signature-devices --signature-alg sha256
```

Initial rules included:

- `uboot_validate_crc32` — validates U-Boot environment CRC32 using standard and redundant layouts.
- `uboot_validate_secureboot` — validates secure boot related env variables (`secureboot`, `verify`, `bootm_verify_sig`), parses one signature variable (`signature`, `boot_signature`, or `fit_signature`), and cryptographically verifies that signature against `--signature-blob` using `--signature-pubkey` (OpenSSL libcrypto).

---

## Notes / cautions

- Run as root (raw flash/block reads and device-node operations typically require it).
- Both tools report candidates and parsed results; always validate before destructive operations.
- Be careful with `fw_setenv` on production hardware.