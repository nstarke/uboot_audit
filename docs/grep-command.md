# `embedded_linux_audit linux grep` Command

Searches regular files in a directory for a literal string and emits matches in `path:line-number:line` format.

By default the search is non-recursive. With `--recursive`, nested directories are traversed.

## `grep` arguments

- `--search <string>` — required literal search string
- `--path <absolute-directory>` — required absolute directory path to scan
- `--recursive` — recurse into subdirectories
- `--output-tcp <IPv4:port>` — top-level global option to duplicate match output to TCP
- `--output-http <http://host:port/path>` — top-level global option to POST match output to the helper API
- `--output-http <https://host:port/path>` — top-level global option to POST match output to the helper API over HTTPS
- `--insecure` — top-level global option to disable TLS certificate and hostname verification for HTTPS output

## Notes

- `--path` must be an absolute directory path.
- `--output-format` does not affect `grep`; output is always plain text.
- If `--output-format` is explicitly set, the tool warns that it has no effect for this subcommand.
- When HTTP(S) output is configured, matches are POSTed to `/{mac_address}/upload/grep?filePath=<absolute-path>` with `Content-Type: text/plain; charset=utf-8`.
- Non-regular files are skipped.
- Directory and file access errors are reported to stderr; when HTTP(S) output is enabled, error messages may also be POSTed as helper log messages.

## Examples

```bash
./embedded_linux_audit linux grep --search bootcmd --path /etc
./embedded_linux_audit linux grep --search needle --path /var/log --recursive
./embedded_linux_audit --output-http http://192.168.1.50:5000 linux grep --search root --path /etc --recursive
./embedded_linux_audit --insecure --output-http https://192.168.1.50:5443 linux grep --search password --path /config
./embedded_linux_audit --output-format json linux grep --search console --path /boot
```