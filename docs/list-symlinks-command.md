# `embedded_linux_audit linux list-symlinks` Command

Lists symlinks under a directory and emits each symlink together with its target path.

By default only the top-level directory is scanned. With `--recursive`, nested directories are also traversed.

## `list-symlinks` arguments

- `[absolute-directory]` — optional absolute directory path; defaults to `/`
- `--recursive` — recurse into subdirectories
- `--output-format <txt|csv|json>` — top-level global option controlling local and remote formatting
- `--output-tcp <IPv4:port>` — top-level global option to duplicate output to TCP
- `--output-http <http://host:port/path>` — top-level global option to POST output to the helper API
- `--output-http <https://host:port/path>` — top-level global option to POST output to the helper API over HTTPS
- `--insecure` — top-level global option to disable TLS certificate and hostname verification for HTTPS output

## Output formats

- `txt` — one line per symlink as `<link> -> <target>`
- `csv` — one CSV row per symlink as `"<link>","<target>"`
- `json` — newline-delimited JSON objects with `link_path` and `location_path`

When HTTP(S) output is configured, the client POSTs to `/{mac_address}/upload/symlink-list?filePath=<absolute-path>` using:

- `text/plain; charset=utf-8` for `txt`
- `text/csv; charset=utf-8` for `csv`
- `application/x-ndjson; charset=utf-8` for `json`

## Notes

- The directory path must be absolute when provided.
- Only one of `--output-http` or `--output-http` may be used at a time.
- Errors reading directories or symlink targets are reported to stderr and may also be sent as helper log messages when HTTP(S) output is enabled.

## Examples

```bash
./embedded_linux_audit linux list-symlinks
./embedded_linux_audit linux list-symlinks /etc
./embedded_linux_audit linux list-symlinks /etc --recursive
./embedded_linux_audit --output-format csv linux list-symlinks /lib
./embedded_linux_audit --output-format json linux list-symlinks /usr --recursive
./embedded_linux_audit --output-http http://192.168.1.50:5000 linux list-symlinks /etc
./embedded_linux_audit --insecure --output-http https://192.168.1.50:5443 linux list-symlinks /etc --recursive
```