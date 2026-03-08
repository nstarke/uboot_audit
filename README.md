# fw_env_scan / fw_image_scan

This repo provides two Linux host-side C utilities for U-Boot-related flash analysis:

- `fw_env_scan`: find U-Boot environment candidates and print `fw_env.config` lines.
- `fw_image_scan`: find likely U-Boot image headers, optionally pull image bytes, or resolve load address.

Both tools are intended for embedded/Linux recovery and diagnostics workflows.

---

## Build

Build environment scanner only:

```bash
make env
```

Build image scanner only:

```bash
make image
```

Build both:

```bash
make
```

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
make CC=arm-linux-gnueabi-gcc env
make CC=arm-linux-gnueabi-gcc image
```

---

## `fw_env_scan`

Scans MTD/UBI devices for blocks that resemble a valid U-Boot environment (CRC-verified by default), then prints candidate `fw_env.config` lines.

### `fw_env_scan` arguments

- `--verbose` — print scan progress and non-hit details
- `--size <env_size>` — fixed environment size (for example `0x10000`)
- `--hint <hint>` — override hint string used for positive labeling
- `--dev <device>` — scan only one device (step inferred from sysfs/proc)
- `--brutefoce` / `--bruteforce` — skip CRC checks and match by hint strings only
- `--output <IPv4:port>` — duplicate output to TCP destination

### `fw_env_scan` examples

```bash
./fw_env_scan
./fw_env_scan --verbose
./fw_env_scan --size 0x10000
./fw_env_scan --dev /dev/mtd3 --size 0x10000
./fw_env_scan --size 0x10000 /dev/mtd0:0x10000 /dev/mtd1:0x20000
./fw_env_scan --output 192.168.1.50:5000 --verbose
```

Example candidate line:

```text
fw_env.config line: /dev/mtd0 0x40000 0x10000 0x10000 0x1
```

---

## `fw_image_scan`

Scans MTD block/char devices for likely U-Boot image signatures. FIT/uImage checks are validated structurally to reduce false positives.

### `fw_image_scan` arguments

- `--verbose` — print scan progress
- `--dev <device>` — restrict scan or action to one device
- `--step <bytes>` — scan stride (default `0x1000`)
- `--allow-text` — also match plain `U-Boot` text (higher false-positive risk)
- `--send-logs` — send tool logs over TCP using `--output <IPv4:port>`
- `--pull` — pull image bytes from `--dev` at `--offset` and send over TCP to `--output`
- `--offset <bytes>` — image offset used by `--pull` or `--find-address`
- `--output <IPv4:port>` — TCP destination used by `--pull`
- `--find-address` — parse image at `--offset` and print load address (uImage/FIT)

### `fw_image_scan` argument constraints

- `--pull` **requires**:
  - `--dev`
  - `--offset`
  - `--output`
- `--find-address` **requires**:
  - `--dev`
  - `--offset`
- `--find-address` **cannot** be combined with:
  - `--pull`
  - `--output`
- `--send-logs` **requires**:
  - `--output`
- `--send-logs` **cannot** be combined with:
  - `--pull`

### `fw_image_scan` examples

Scan all MTD devices:

```bash
./fw_image_scan --verbose
```

Scan one device:

```bash
./fw_image_scan --dev /dev/mtdblock4 --step 0x1000
```

Find load address at known offset:

```bash
./fw_image_scan --find-address --dev /dev/mtdblock4 --offset 0x200
```

Send scan logs over TCP:

```bash
./fw_image_scan --verbose --send-logs --output 192.168.1.50:5000
```

Pull image bytes to TCP listener:

```bash
./fw_image_scan --pull --dev /dev/mtdblock4 --offset 0x200 --output 192.168.1.50:5000
```

---

## Notes / cautions

- Run as root (raw flash/block reads and device-node operations typically require it).
- Both tools report candidates and parsed results; always validate before destructive operations.
- Be careful with `fw_setenv` on production hardware.