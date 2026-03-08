# `uboot_audit image` Command

Scans mtdblock/UBI and block devices (SD/eMMC such as `/dev/sd*` and `/dev/mmcblk*`) for likely U-Boot image signatures. FIT/uImage checks are validated structurally to reduce false positives.

## `image` arguments

- `--verbose` — print scan progress
- `--dev <device>` — restrict scan or action to one device
- `--step <bytes>` — scan stride (default `0x1000`)
- `--allow-text[=<text>]` — also match plain text (default `U-Boot`; higher false-positive risk)
- `--skip-remove` — keep any helper `/dev` nodes created during scan
- `--skip-mtd` — skip `/dev/mtdblock*` scan targets
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
- `--list-commands` — best-effort static extraction of likely U-Boot command names from image bytes at `--offset`; emits confidence labels (`high`/`medium`/`low`)

## `image` argument constraints

- `--pull` **requires**:
  - `--dev`
  - `--offset`
  - exactly one of `--output-tcp`, `--output-http`, or `--output-https`
- `--find-address` **requires**:
  - `--dev`
  - `--offset`
- `--list-commands` **requires**:
  - `--dev`
  - `--offset`
- `--find-address` **cannot** be combined with:
  - `--pull`
  - `--output-tcp` (unless `--send-logs` is also set)
- `--list-commands` **cannot** be combined with:
  - `--pull`
  - `--output-tcp` (unless `--send-logs` is also set)
- `--find-address` and `--list-commands` cannot be combined with each other
- `--send-logs` **requires**:
  - `--output-tcp`
- `--send-logs` **cannot** be combined with:
  - `--pull`

## `image` examples

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

List likely commands at known offset:

```bash
./uboot_audit image --list-commands --dev /dev/mtdblock4 --offset 0x200
./uboot_audit --output-format json image --list-commands --dev /dev/mtdblock4 --offset 0x200
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
