# `embedded_linux_audit uboot env` Command

Scans MTD/UBI plus block devices (SD/eMMC such as `/dev/sd*` and `/dev/mmcblk*`) for blocks that resemble a valid U-Boot environment (CRC-verified by default), then prints candidate `fw_env.config` lines.

## `env` arguments

- verbose logging is enabled by default; use top-level `--quiet` to suppress scan progress and non-hit details
- `--size <env_size>` — fixed environment size (for example `0x10000`)
- `--hint <hint>` — override hint string used for positive labeling
- `--dev <device>` — scan only one device (step inferred from sysfs/proc)
- `--bruteforce` — skip CRC checks and match by hint strings only
- `--skip-remove` — keep any created helper `/dev/mtdblock*`/UBI device nodes after run
- `--skip-mtd` — skip MTD/mtdblock scan targets and helper node handling
- `--skip-ubi` — skip UBI/ubiblock scan targets and helper node handling
- `--skip-sd` — skip `/dev/sd*` scan targets
- `--skip-emmc` — skip `/dev/mmcblk*` scan targets
- `read-vars` — subcommand to print parsed key/value variables from candidate environments (parsed via `libubootenv`)
- `--output-config[=<path>]` — write discovered `fw_env.config` lines to file (default `fw_env.config`)
- `--output-tcp <IPv4:port>` — duplicate output to TCP destination; preferred at the top level
- `--output-http <http://host:port/path>` — duplicate output to HTTP endpoint via POST; preferred at the top level
- `--output-http <https://host:port/path>` — duplicate output to HTTPS endpoint via POST; preferred at the top level
- `--insecure` — top-level global option to disable TLS certificate and hostname verification for HTTPS output
- `write-vars <path|http(s)://...>` — subcommand to apply env updates from a local text file or fetch the script from HTTP(S)

## `write-vars` behavior

- Uses `./fw_env.config` for write settings and applies updates through `libubootenv` (built from source in `third_party/libubootenv`).
  - If `./fw_env.config` exists, it is used directly.
  - If it does not exist, the tool first runs scan logic to generate it, then writes.
- When `write-vars` argument begins with `http://` or `https://`, the script is downloaded to a temporary file and then processed as a normal write script.
  - HTTPS certificate/hostname verification uses the embedded CA bundle by default.
- top-level `--insecure` can be used to disable HTTPS verification for `write-vars` URL downloads.
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
- Environment persistence (including CRC/redundant handling) is performed by `libubootenv`.

## `env` examples

```bash
./embedded_linux_audit uboot env
./embedded_linux_audit --output-format json uboot env
./embedded_linux_audit --quiet uboot env
./embedded_linux_audit uboot env --size 0x10000
./embedded_linux_audit uboot env --dev /dev/mtd3 --size 0x10000
./embedded_linux_audit uboot env --size 0x10000 /dev/mtd0:0x10000 /dev/mtd1:0x20000
./embedded_linux_audit --output-tcp 192.168.1.50:5000 uboot env
./embedded_linux_audit --output-http http://192.168.1.50:5000/env uboot env
./embedded_linux_audit --output-http https://192.168.1.50:5443/env uboot env
./embedded_linux_audit --insecure --output-http https://192.168.1.50:5443/env uboot env
./embedded_linux_audit uboot env read-vars --size 0x10000
./embedded_linux_audit uboot env write-vars ./new_env.txt
```

For machine-readable output:

```bash
./embedded_linux_audit --output-format csv uboot env
./embedded_linux_audit --output-format json uboot env
```

Example candidate line:

```text
fw_env.config line: /dev/mtd0 0x40000 0x10000 0x10000 0x1
```