# Output Formats and Remote Output

Global options:

- `--output-format <csv|json|txt>` — select requested output format at the `embedded_linux_audit` wrapper level (default: `txt`)
- `--quiet` — disable verbose logging; commands/subcommands are verbose by default
- `--output-tcp <ip:port>` — configure a TCP remote output destination at the `embedded_linux_audit` wrapper level
- `--output-http <http(s)://host:port/path>` — configure an HTTP or HTTPS remote output destination at the `embedded_linux_audit` wrapper level
- `--script <path|http(s)://...>` — execute commands from a local or remote script file at the wrapper level
  - `txt`: existing human-readable output
  - `csv`: comma-separated records (header + rows)
  - `json`: newline-delimited JSON objects (one JSON object per line)
  - by default, verbose messages are emitted; with `csv`/`json`, they appear as structured `verbose` records (instead of plain text lines)

These wrapper-level options apply to all commands and subcommands. Pass them before the command group, for example:

- `./embedded_linux_audit uboot env`
- `./embedded_linux_audit --output-http http://127.0.0.1:5000/dmesg linux dmesg`
- `./embedded_linux_audit --output-tcp 127.0.0.1:5001 bios orom list`
- `./embedded_linux_audit --output-format json --script ./commands.txt`

Script execution notes:

- `--script` is a wrapper-level feature, so it can be combined with `--output-format`, `--quiet`, `--output-http`, `--output-tcp`, and `--insecure`.
- The script source may be a local file or an `http://` / `https://` URL.
- Remote script downloads over HTTPS use the embedded CA bundle by default.
- `--insecure` also applies to HTTPS script downloads.
- Use either `--script` or a direct command, not both.
- See [`embedded_linux_audit --script` Feature](script-feature.md) for the full script file format and examples.

Remote output notes:

- `./embedded_linux_audit --output-tcp <ip:port> uboot env` sends the same formatted stream selected by `--output-format` over TCP.
- `./embedded_linux_audit --output-http <http://host:port/path> uboot env` sends the same formatted stream selected by `--output-format` in a single HTTP POST request.
- `./embedded_linux_audit --output-http <https://host:port/path> uboot env` sends the same formatted stream selected by `--output-format` in a single HTTPS POST request using embedded CA certificates.
- `./embedded_linux_audit --insecure --output-http <https://host:port/path> uboot env` disables TLS certificate and hostname verification for HTTPS output.
- `./embedded_linux_audit --output-tcp ... uboot image pull ...` is used for `pull` binary streaming; for formatted scan/find-address output over TCP, use `./embedded_linux_audit --output-tcp ... uboot image --send-logs ...`.
- `./embedded_linux_audit --output-http <http://host:port/path> uboot image ...` can be used to POST formatted scan/find-address output, or to POST pulled image bytes when used with `pull`.
- `./embedded_linux_audit --output-http <https://host:port/path> uboot image ...` can be used to POST formatted scan/find-address output, or to POST pulled image bytes when used with `pull`, using embedded CA certificates.
- `./embedded_linux_audit --insecure --output-http <https://host:port/path> uboot image ...` disables TLS certificate and hostname verification for HTTPS output.
- `./embedded_linux_audit --output-tcp <ip:port> linux dmesg` sends dmesg text output to TCP.
- `./embedded_linux_audit --output-http <http://host:port/path> linux dmesg` sends dmesg text output in a single HTTP POST request with `Content-Type: text/plain; charset=utf-8`.
- `./embedded_linux_audit --output-http <https://host:port/path> linux dmesg` sends dmesg text output in a single HTTPS POST request with `Content-Type: text/plain; charset=utf-8`, using embedded CA certificates.
- `./embedded_linux_audit --insecure --output-http <https://host:port/path> linux dmesg` disables TLS certificate and hostname verification for HTTPS output.
- `--output-format` does not affect `linux dmesg`; if specified, a warning is emitted.
- `./embedded_linux_audit --output-tcp <ip:port> linux remote-copy <path>` sends raw file bytes over TCP.
- `./embedded_linux_audit --output-http <http://host:port/path> linux remote-copy <path>` sends raw file bytes in a single HTTP POST request with `Content-Type: application/octet-stream`, using the API upload type `file` and including the absolute source path as `filePath`.
- `./embedded_linux_audit --output-http <https://host:port/path> linux remote-copy <path>` sends raw file bytes in a single HTTPS POST request with `Content-Type: application/octet-stream`, using the API upload type `file` and including the absolute source path as `filePath`, using embedded CA certificates.
- `./embedded_linux_audit --insecure --output-http <https://host:port/path> linux remote-copy <path>` disables TLS certificate and hostname verification for HTTPS output.
- `--output-format` does not affect `linux remote-copy`; if specified, a warning is emitted.
- `./embedded_linux_audit --output-tcp <ip:port> efi orom pull` sends matching EFI option ROM payloads over TCP.
- `./embedded_linux_audit --output-http <http://host:port/path> efi orom pull` sends matching EFI option ROM payloads via HTTP POST with `Content-Type: application/octet-stream`.
- `./embedded_linux_audit --output-http <https://host:port/path> efi orom pull` sends matching EFI option ROM payloads via HTTPS POST with `Content-Type: application/octet-stream`, using embedded CA certificates.
- `./embedded_linux_audit --output-tcp <ip:port> bios orom pull` sends matching BIOS option ROM payloads over TCP.
- `./embedded_linux_audit --output-http <http://host:port/path> bios orom pull` sends matching BIOS option ROM payloads via HTTP POST with `Content-Type: application/octet-stream`.
- `./embedded_linux_audit --output-http <https://host:port/path> bios orom pull` sends matching BIOS option ROM payloads via HTTPS POST with `Content-Type: application/octet-stream`, using embedded CA certificates.
- `efi orom list` and `bios orom list` honor `--output-format` and emit list records in txt/csv/json format.
- `./embedded_linux_audit --insecure --output-http <https://host:port/path> efi orom pull`
- `./embedded_linux_audit --insecure --output-http <https://host:port/path> bios orom pull`
  disable TLS certificate and hostname verification for HTTPS output.
- `efi|bios orom` sends emitted output records and all log lines (including verbose logs) to the configured `--output-{tcp,http,https}` destination.
