# `uboot_audit bios orom` Command

BIOS option ROM utilities for listing and pulling payloads from PCI sysfs ROM nodes.

## `bios orom` subcommands

- `pull` — send matching BIOS option ROM payload bytes to remote output
- `list` — enumerate matching BIOS option ROM candidates and emit formatted records

## `bios orom` arguments

- `--verbose` — print progress and mirror verbose messages to configured network output
- `--output-tcp <IPv4:port>` — send each ROM over TCP
- `--output-http <http://host:port/path>` — send each ROM via HTTP POST
- `--output-https <https://host:port/path>` — send each ROM via HTTPS POST
- `--insecure` — disable TLS certificate/hostname verification for HTTPS output

## Constraints

- exactly one transport output is required: `--output-tcp`, `--output-http`, or `--output-https`
- use only one of `--output-http` and `--output-https`

## Examples

```bash
./uboot_audit bios orom pull --output-tcp 192.168.1.50:5000 --verbose
./uboot_audit bios orom pull --output-http http://192.168.1.50:5000/orom --verbose
./uboot_audit bios orom pull --output-https https://192.168.1.50:5443/orom --insecure --verbose
./uboot_audit --output-format json bios orom list --output-http http://192.168.1.50:5000/orom --verbose
```
