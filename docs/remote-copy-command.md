# `embedded_linux_audit linux remote-copy` Command

Copies a local file, device-like path, proc/sysfs path, or directory contents to a remote destination using one of:

- TCP (`--output-tcp`, passed as a top-level `embedded_linux_audit` option)
- HTTP POST (`--output-http`, passed as a top-level option)
- HTTPS POST (`--output-http`, passed as a top-level option)

The source path must be a full absolute OS path. Directory uploads are supported only with HTTP(S).

## `remote-copy` arguments

- `<absolute-path>` — required source path (must start with `/`)
- `--recursive` — recurse into subdirectories when `<absolute-path>` is a directory
- `--allow-dev` — allow copying paths under `/dev`
- `--allow-sysfs` — allow copying paths under `/sys`
- `--allow-proc` — allow copying paths under `/proc`
- `--allow-symlinks` — upload symlinks as symlinks over HTTP(S)
- `--insecure` — top-level global option to disable TLS certificate and hostname verification for HTTPS output
- `--quiet` — disable transfer progress logging at the top level (verbose logging is enabled by default)

## Constraints

- Exactly one top-level remote output target is required:
  - `--output-tcp` **or** `--output-http` **or** `--output-http`
- `--output-http` and `--output-http` are mutually exclusive
- Directory uploads require `--output-http` or `--output-http`
- Paths under `/dev`, `/sys`, and `/proc` require their corresponding allow flags
- Symlinks are skipped unless `--allow-symlinks` is provided
- `--output-format` does not affect this subcommand; transfers are raw file bytes
- For HTTP(S), use the server base URL; the client constructs `/{mac_address}/upload/{type}` automatically
- Regular file uploads from `linux remote-copy` are sent to `/{mac_address}/upload/file?filePath=<absolute-path>`
- Symlink uploads from `linux remote-copy --allow-symlinks` also use `/{mac_address}/upload/file`, with `symlink=true` and `symlinkPath=<target>` query parameters

## Examples

```bash
./embedded_linux_audit --output-tcp 192.168.1.50:5000 linux remote-copy /tmp/fw.bin
./embedded_linux_audit --output-http http://192.168.1.50:5000 linux remote-copy /tmp/fw.bin
./embedded_linux_audit --output-http https://192.168.1.50:5443 linux remote-copy /tmp/fw.bin
./embedded_linux_audit --insecure --output-http https://192.168.1.50:5443 linux remote-copy /tmp/fw.bin
./embedded_linux_audit --quiet --insecure --output-http https://192.168.1.50:5443 linux remote-copy /tmp/fw.bin
./embedded_linux_audit --output-http http://192.168.1.50:5000 linux remote-copy /tmp/fw_dir --recursive
./embedded_linux_audit --output-http http://192.168.1.50:5000 linux remote-copy /proc/device-tree --recursive --allow-proc
./embedded_linux_audit --output-http http://192.168.1.50:5000 linux remote-copy /tmp/link_to_fw --allow-symlinks
```
