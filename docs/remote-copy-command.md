# `embedded_linux_audit linux remote-copy` Command

Copies a local file, device-like path, proc/sysfs path, or directory contents to a remote destination using one of:

- TCP (`--output-tcp`)
- HTTP POST (`--output-http`)
- HTTPS POST (`--output-https`)

The source path must be a full absolute OS path. Directory uploads are supported only with HTTP(S).

## `remote-copy` arguments

- `<absolute-path>` — required source path (must start with `/`)
- `--output-tcp <IPv4:port>` — send file bytes over TCP
- `--output-http <http://host:port/path>` — send file bytes in HTTP POST body
- `--output-https <https://host:port/path>` — send file bytes in HTTPS POST body
- `--recursive` — recurse into subdirectories when `<absolute-path>` is a directory
- `--allow-dev` — allow copying paths under `/dev`
- `--allow-sysfs` — allow copying paths under `/sys`
- `--allow-proc` — allow copying paths under `/proc`
- `--allow-symlinks` — upload symlinks as symlinks over HTTP(S)
- `--insecure` — disable TLS certificate and hostname verification for HTTPS output
- `--verbose` — print transfer progress

## Constraints

- Exactly one remote output target is required:
  - `--output-tcp` **or** `--output-http` **or** `--output-https`
- `--output-http` and `--output-https` are mutually exclusive
- Directory uploads require `--output-http` or `--output-https`
- Paths under `/dev`, `/sys`, and `/proc` require their corresponding allow flags
- Symlinks are skipped unless `--allow-symlinks` is provided
- `--output-format` does not affect this subcommand; transfers are raw file bytes

## Examples

```bash
./embedded_linux_audit linux remote-copy /tmp/fw.bin --output-tcp 192.168.1.50:5000
./embedded_linux_audit linux remote-copy /tmp/fw.bin --output-http http://192.168.1.50:5000/upload
./embedded_linux_audit linux remote-copy /tmp/fw.bin --output-https https://192.168.1.50:5443/upload
./embedded_linux_audit linux remote-copy /tmp/fw.bin --output-https https://192.168.1.50:5443/upload --insecure --verbose
./embedded_linux_audit linux remote-copy /tmp/fw_dir --output-http http://192.168.1.50:5000/upload --recursive
./embedded_linux_audit linux remote-copy /proc/device-tree --output-http http://192.168.1.50:5000/upload --recursive --allow-proc
./embedded_linux_audit linux remote-copy /tmp/link_to_fw --output-http http://192.168.1.50:5000/upload --allow-symlinks
```
