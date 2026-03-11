# `embedded_linux_audit linux list-files` Command

Lists regular filesystem entries under a directory and can filter results by recursion, SUID bit, ownership, or permissions.

Output is always newline-delimited absolute paths.

## `list-files` arguments

- `[absolute-directory]` — optional absolute directory path; defaults to `/`
- `--recursive` — recurse into subdirectories
- `--suid-only` — only emit entries with the SUID bit set
- `--permissions <mode>` — filter by exact octal mode (for example `0600`, `4755`) or symbolic permissions (for example `u+rw,go-rwx`)
- `--user <name|uid>` — filter by owner name or numeric UID
- `--group <name|gid>` — filter by group name or numeric GID
- `--output-tcp <IPv4:port>` — top-level global option to duplicate output to TCP
- `--output-http <http://host:port/path>` — top-level global option to POST output to the helper API
- `--output-http <https://host:port/path>` — top-level global option to POST output to the helper API over HTTPS
- `--insecure` — top-level global option to disable TLS certificate and hostname verification for HTTPS output

## Notes

- The directory path must be absolute when provided.
- `--output-format` does not affect `list-files`; output is always plain text.
- If `--output-format` is explicitly set, the tool warns that it has no effect for this subcommand.
- When HTTP(S) output is configured, results are POSTed to `/{mac_address}/upload/file-list?filePath=<absolute-path>` with `Content-Type: text/plain; charset=utf-8`.
- Non-recursive mode lists matching non-directory entries only in the top-level directory.
- Symbolic permission filters support `u`, `g`, `o`, `a` with `+`, `-`, or `=` and permission bits `r`, `w`, `x`, `s`, `t`.

## Examples

```bash
./embedded_linux_audit linux list-files
./embedded_linux_audit linux list-files /etc
./embedded_linux_audit linux list-files /usr/bin --recursive --suid-only
./embedded_linux_audit linux list-files /tmp --permissions 0600
./embedded_linux_audit linux list-files /srv --permissions u+rw,go-rwx
./embedded_linux_audit linux list-files /home --user root
./embedded_linux_audit linux list-files /var --group adm
./embedded_linux_audit --output-http http://192.168.1.50:5000 linux list-files /etc
./embedded_linux_audit --output-format json linux list-files /etc
```