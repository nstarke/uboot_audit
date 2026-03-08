# Audit Rules Reference

This project currently builds and registers the following audit rules from `agent/audit-rules/*.c`.

## How to list available rules

```bash
./uboot_audit audit --list-rules
```

## How to run a specific rule

```bash
./uboot_audit audit --rule <rule-name> --dev <device> --size <bytes>
```

Example:

```bash
./uboot_audit audit --rule uboot_validate_crc32 --dev /dev/mtdblock4 --offset 0x0 --size 0x10000
```

---

## `uboot_validate_crc32`

**Purpose:** Validate U-Boot environment CRC32 for both standard and redundant env layouts.

**Behavior:**
- Ensures an environment config exists (generates `uboot_env.config` via env scan if needed).
- Computes CRC32 for:
  - standard layout (`data + 4`)
  - redundant layout (`data + 5`)
- Compares computed CRCs against stored little-endian and big-endian CRC fields.

**Result semantics:**
- Pass (`0`): CRC match found.
- Warn/Fail (`1`): CRC mismatch.
- Error (`-1`): input too small or pre-check failure.

---

## `uboot_validate_env_writeability`

**Purpose:** Detect whether the environment block appears writable.

**Behavior:**
- Ensures `uboot_env.config` exists (runs env scan if needed).
- Attempts `open(device, O_RDWR)` on the input device.

**Result semantics:**
- Pass (`0`): not writable (`EACCES`, `EPERM`, or `EROFS`).
- Warn/Fail (`1`): writable block device.
- Error (`-1`): missing device path, env-config generation failure, or unknown open error.

---

## `uboot_validate_env_security`

**Purpose:** Enforce policy checks for security-sensitive U-Boot environment settings.

**Behavior:**
- Validates environment CRC/layout before parsing key/value pairs.
- Evaluates policy items including:
  - `bootdelay` present and `<= 0`
  - `preboot` unset/empty
  - network-boot indicators in `boot_targets`, `bootcmd`, `altbootcmd`, `preboot`
  - presence of network boot variables like `bootfile`, `serverip`, `ipaddr`
  - factory-reset indicators/variables such as `factory_reset`, `reset_to_defaults`, `resetenv`, `eraseenv`

**Result semantics:**
- Pass (`0`): no policy issues detected.
- Warn/Fail (`1`): one or more policy violations detected.
- Error (`-1`): parse/CRC/input failures.

---

## `uboot_validate_cmdline_init_writeability`

**Purpose:** Warn when a valid kernel `init=` override exists and the env device is writable.

**Behavior:**
- Validates environment CRC/layout and parses env variables.
- Extracts `bootargs`, then looks for `init=<path>`.
- Validates `init` path shape (absolute path, no whitespace/control/quotes).
- Checks whether the environment device can be opened writable.

**Result semantics:**
- Pass (`0`): no valid `init=`, invalid `init=`, or env block not writable.
- Warn/Fail (`1`): valid `init=` found and env block appears writable.
- Error (`-1`): parse/CRC/input failures.

---

## `uboot_validate_secureboot`

**Purpose:** Validate secure-boot-related env variables and cryptographically verify a signature field.

**Behavior:**
- Validates environment CRC/layout and parses env variables.
- Checks secure boot toggles:
  - `secureboot` enabled
  - `verify` not disabled
  - `bootm_verify_sig` enabled
- Locates one signature variable from: `signature`, `boot_signature`, `fit_signature`.
- Verifies signature against `--signature-blob` using `--signature-pubkey`.
  - Supports hex or base64 encoded signature values.
  - Uses `--signature-alg` if provided.
  - If omitted, attempts: `sha256`, `sha384`, `sha512`, `sha1`, `sha224`.

**Result semantics:**
- Pass (`0`): variables satisfy policy and signature verifies.
- Warn/Fail (`1`): misconfiguration or verification failure.
- Error (`-1`): parse/input/verification processing error.

**Example:**

```bash
./uboot_audit audit \
  --rule uboot_validate_secureboot \
  --dev /dev/mtdblock4 \
  --offset 0x0 \
  --size 0x10000 \
  --signature-blob ./fit-image.bin \
  --signature-pubkey ./pubkey.pem \
  --signature-alg sha256
```
