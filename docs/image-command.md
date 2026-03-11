# `embedded_linux_audit uboot image` Command

Scans mtdblock/UBI and block devices (SD/eMMC such as `/dev/sd*` and `/dev/mmcblk*`) for likely U-Boot image signatures. FIT/uImage checks are validated structurally to reduce false positives.

## `image` arguments

- verbose logging is enabled by default; use top-level `--quiet` to suppress scan progress
- `--dev <device>` — restrict scan or action to one device
- `--step <bytes>` — scan stride (default `0x1000`)
- `--allow-text[=<text>]` — also match plain text (default `U-Boot`; higher false-positive risk)
- `--skip-remove` — keep any helper `/dev` nodes created during scan
- `--skip-mtd` — skip `/dev/mtdblock*` scan targets
- `--skip-ubi` — skip UBI/ubiblock scan targets
- `--skip-sd` — skip `/dev/sd*` scan targets
- `--skip-emmc` — skip `/dev/mmcblk*` scan targets
- `--send-logs` — send tool logs over TCP using `--output-tcp <IPv4:port>`
- `pull` subcommand — pull image bytes from `--dev` at `--offset` and send to one remote destination (`--output-tcp`, `--output-http`, or `--output-http`)
- `--offset <bytes>` — image offset used by `--pull` or `--find-address`
- `--output-tcp <IPv4:port>` — TCP destination used by `pull`; preferred at the top level
- `--output-http <http://host:port/path>` — HTTP destination used by `pull` (POST body contains image bytes), or for posting normal command output; preferred at the top level
- `--output-http <https://host:port/path>` — HTTPS destination used by `pull` (POST body contains image bytes), or for posting normal command output; preferred at the top level
- `--insecure` — top-level global option to disable TLS certificate and hostname verification for HTTPS output
- `find-address` subcommand — parse image at `--offset` and print load address (uImage/FIT)
- `list-commands` subcommand — best-effort static extraction of likely U-Boot command names from image bytes at `--offset`; emits confidence labels (`high`/`medium`/`low`)

## `image` argument constraints

- `pull` **requires**:
  - `--dev`
  - `--offset`
  - exactly one of `--output-tcp`, `--output-http`, or `--output-http`
- `find-address` **requires**:
  - `--dev`
  - `--offset`
- `list-commands` **requires**:
  - `--dev`
  - `--offset`
- `find-address` **cannot** be combined with:
  - `pull`
  - `--output-tcp` (unless `--send-logs` is also set)
- `list-commands` **cannot** be combined with:
  - `pull`
  - `--output-tcp` (unless `--send-logs` is also set)
- `find-address` and `list-commands` are separate subcommands and cannot be combined with each other
- `--send-logs` **requires**:
  - `--output-tcp`
- `--send-logs` **cannot** be combined with:
  - `--pull`

## `image` examples

Scan all MTD devices:

```bash
./embedded_linux_audit uboot image
./embedded_linux_audit --output-format csv uboot image
```

For machine-readable output:

```bash
./embedded_linux_audit --output-format json uboot image
./embedded_linux_audit --output-format csv uboot image find-address --dev /dev/mtdblock4 --offset 0x200
```

Scan one device:

```bash
./embedded_linux_audit uboot image --dev /dev/mtdblock4 --step 0x1000
```

Find load address at known offset:

```bash
./embedded_linux_audit uboot image find-address --dev /dev/mtdblock4 --offset 0x200
```

List likely commands at known offset:

```bash
./embedded_linux_audit uboot image list-commands --dev /dev/mtdblock4 --offset 0x200
./embedded_linux_audit --output-format json uboot image list-commands --dev /dev/mtdblock4 --offset 0x200
```

Send scan logs over TCP:

```bash
./embedded_linux_audit --output-tcp 192.168.1.50:5000 uboot image --send-logs
```

Pull image bytes to TCP listener:

```bash
./embedded_linux_audit --output-tcp 192.168.1.50:5000 uboot image pull --dev /dev/mtdblock4 --offset 0x200
./embedded_linux_audit --output-http http://192.168.1.50:5000/image uboot image pull --dev /dev/mtdblock4 --offset 0x200
./embedded_linux_audit --output-http https://192.168.1.50:5443/image uboot image pull --dev /dev/mtdblock4 --offset 0x200
./embedded_linux_audit --output-http http://192.168.1.50:5000/image uboot image
./embedded_linux_audit --output-http https://192.168.1.50:5443/image uboot image
```
