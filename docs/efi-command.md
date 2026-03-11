# `embedded_linux_audit efi` Commands

EFI utilities for dumping variables and working with PCI sysfs option ROM nodes.

## `efi dump-vars`

Enumerate EFI variables available through efivarfs/libefivar and emit them in the selected top-level `--output-format`.

For full `dump-vars` details, see [EFI vars command reference](efi-vars-command.md).

- supported output formats: `txt`, `csv`, and `json`
- when top-level `--output-http` or `--output-http` is configured, results are POSTed to `/:mac/upload/efi-vars`
- when top-level `--output-tcp` is configured, formatted records are streamed over TCP as they are emitted

Each emitted record includes:

- variable GUID
- variable name
- EFI attribute bitmask
- payload size
- payload bytes as lowercase hexadecimal

## `efi orom` subcommands

- `pull` — send matching EFI option ROM payload bytes to remote output
- `list` — enumerate matching EFI option ROM candidates and emit formatted records

## `efi orom` arguments

- verbose logging is enabled by default; use top-level `--quiet` to suppress progress and mirrored verbose messages
- `--output-tcp <IPv4:port>` — send each ROM over TCP; preferred at the top level
- `--output-http <http://host:port/path>` — send each ROM via HTTP POST; preferred at the top level
- `--output-http <https://host:port/path>` — send each ROM via HTTPS POST; preferred at the top level
- `--insecure` — top-level global option to disable TLS certificate/hostname verification for HTTPS output

## Constraints

- exactly one transport output is required: `--output-tcp`, `--output-http`, or `--output-http`
- use only one of `--output-http` and `--output-http`

## Examples

```bash
./embedded_linux_audit efi dump-vars
./embedded_linux_audit --output-format csv efi dump-vars
./embedded_linux_audit --output-format json --output-http http://192.168.1.50:5000 efi dump-vars
./embedded_linux_audit --output-tcp 192.168.1.50:5000 efi orom pull
./embedded_linux_audit --output-http http://192.168.1.50:5000/orom efi orom pull
./embedded_linux_audit --insecure --output-http https://192.168.1.50:5443/orom efi orom pull
./embedded_linux_audit --output-format csv --output-http http://192.168.1.50:5000/orom efi orom list
```
