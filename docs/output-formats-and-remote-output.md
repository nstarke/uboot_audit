# Output Formats and Remote Output

Global option:

- `--output-format <csv|json|txt>` — select requested output format at the `uboot_audit` wrapper level (default: `txt`)
  - `txt`: existing human-readable output
  - `csv`: comma-separated records (header + rows)
  - `json`: newline-delimited JSON objects (one JSON object per line)
  - when `--verbose` is enabled with `csv`/`json`, verbose messages are emitted as structured `verbose` records (instead of plain text lines)

Remote output notes:

- `uboot env --output-tcp <ip:port>` sends the same formatted stream selected by `--output-format` over TCP.
- `uboot env --output-http <http://host:port/path>` sends the same formatted stream selected by `--output-format` in a single HTTP POST request.
- `uboot env --output-https <https://host:port/path>` sends the same formatted stream selected by `--output-format` in a single HTTPS POST request using embedded CA certificates.
- `uboot env --insecure` disables TLS certificate and hostname verification for HTTPS output.
- `uboot image --output-tcp` is used for `--pull` binary streaming; for formatted scan/find-address output over TCP, use `uboot image --send-logs --output-tcp ...`.
- `uboot image --output-http <http://host:port/path>` can be used to POST formatted scan/find-address output, or to POST pulled image bytes when used with `--pull`.
- `uboot image --output-https <https://host:port/path>` can be used to POST formatted scan/find-address output, or to POST pulled image bytes when used with `--pull`, using embedded CA certificates.
- `uboot image --insecure` disables TLS certificate and hostname verification for HTTPS output.
- `linux dmesg --output-tcp <ip:port>` sends dmesg text output to TCP.
- `linux dmesg --output-http <http://host:port/path>` sends dmesg text output in a single HTTP POST request with `Content-Type: text/plain; charset=utf-8`.
- `linux dmesg --output-https <https://host:port/path>` sends dmesg text output in a single HTTPS POST request with `Content-Type: text/plain; charset=utf-8`, using embedded CA certificates.
- `linux dmesg --insecure` disables TLS certificate and hostname verification for HTTPS output.
- `--output-format` does not affect `linux dmesg`; if specified, a warning is emitted.
- `linux remote-copy --output-tcp <ip:port>` sends raw file bytes over TCP.
- `linux remote-copy --output-http <http://host:port/path>` sends raw file bytes in a single HTTP POST request with `Content-Type: application/octet-stream`.
- `linux remote-copy --output-https <https://host:port/path>` sends raw file bytes in a single HTTPS POST request with `Content-Type: application/octet-stream`, using embedded CA certificates.
- `linux remote-copy --insecure` disables TLS certificate and hostname verification for HTTPS output.
- `--output-format` does not affect `linux remote-copy`; if specified, a warning is emitted.
- `efi orom pull --output-tcp <ip:port>` sends matching EFI option ROM payloads over TCP.
- `efi orom pull --output-http <http://host:port/path>` sends matching EFI option ROM payloads via HTTP POST with `Content-Type: application/octet-stream`.
- `efi orom pull --output-https <https://host:port/path>` sends matching EFI option ROM payloads via HTTPS POST with `Content-Type: application/octet-stream`, using embedded CA certificates.
- `bios orom pull --output-tcp <ip:port>` sends matching BIOS option ROM payloads over TCP.
- `bios orom pull --output-http <http://host:port/path>` sends matching BIOS option ROM payloads via HTTP POST with `Content-Type: application/octet-stream`.
- `bios orom pull --output-https <https://host:port/path>` sends matching BIOS option ROM payloads via HTTPS POST with `Content-Type: application/octet-stream`, using embedded CA certificates.
- `efi orom list` and `bios orom list` honor `--output-format` and emit list records in txt/csv/json format.
- `efi|bios orom --insecure` disables TLS certificate and hostname verification for HTTPS output.
- `efi|bios orom` sends emitted output records and all log lines (including verbose logs) to the configured `--output-{tcp,http,https}` destination.
