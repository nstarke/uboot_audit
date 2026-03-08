# `uboot_audit audit` Command

Runs compiled audit rules that are defined under `agent/audit-rules/` (one `.c` file per rule).

Before running rules, `audit` ensures `./fw_env.config` exists for follow-on environment operations:

- if `./fw_env.config` already exists, it is reused
- else if `./uboot_env.config` exists, it is copied to `./fw_env.config`
- else an env scan is run automatically to generate `./fw_env.config`

## `audit` arguments

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

## `audit` examples

```bash
./uboot_audit audit --list-rules
./uboot_audit audit --dev /dev/mtdblock4 --offset 0x0 --size 0x10000
./uboot_audit audit --rule uboot_validate_crc32 --dev /dev/mtdblock4 --offset 0x0 --size 0x10000
./uboot_audit audit --rule uboot_validate_env_security --dev /dev/mtdblock4 --offset 0x0 --size 0x10000
./uboot_audit audit --rule uboot_validate_cmdline_init_writeability --dev /dev/mtdblock4 --offset 0x0 --size 0x10000
./uboot_audit audit --rule uboot_validate_secureboot --dev /dev/mtdblock4 --offset 0x0 --size 0x10000 --signature-blob ./fit-image.bin --signature-pubkey ./pubkey.pem --signature-alg sha256
./uboot_audit audit --rule uboot_validate_secureboot --dev /dev/mtdblock4 --offset 0x0 --size 0x10000 --scan-signature-devices --signature-alg sha256
```

Initial rules included:

- `uboot_validate_crc32` — validates U-Boot environment CRC32 using standard and redundant layouts.
- `uboot_validate_env_security` — validates security-sensitive environment policy, network-boot indicators, and factory-reset indicators (`bootdelay <= 0`, `preboot` unset, checks for network-boot hints, and checks for factory-reset hints such as `factory_reset`, `reset_to_defaults`, `resetenv`, `eraseenv`, or reset-like commands in `bootcmd`/`altbootcmd`/`preboot`).
- `uboot_validate_cmdline_init_writeability` — parses Linux kernel command-line parameters from `bootargs`; if `init=` is present and syntactically valid and the environment device is writable, it emits a warning result.
- `uboot_validate_secureboot` — validates secure boot related env variables (`secureboot`, `verify`, `bootm_verify_sig`), parses one signature variable (`signature`, `boot_signature`, or `fit_signature`), and cryptographically verifies that signature against `--signature-blob` using `--signature-pubkey` (OpenSSL libcrypto).
