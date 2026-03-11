# `embedded_linux_audit linux dmesg` Command

Runs `dmesg` and emits kernel ring buffer output.

## `dmesg` arguments

- verbose logging is enabled by default; use top-level `--quiet` to disable command execution and remote HTTP(S) POST verbosity
- `--output-tcp <IPv4:port>` — preferred as a top-level option; duplicate dmesg output to TCP destination
- `--output-http <http://host:port/path>` — preferred as a top-level option; duplicate dmesg output to HTTP endpoint via POST
- `--output-http <https://host:port/path>` — preferred as a top-level option; duplicate dmesg output to HTTPS endpoint via POST
- `--insecure` — top-level global option to disable TLS certificate and hostname verification for HTTPS output

## Notes

- `--output-format` does not change `dmesg` output behavior.
- For this subcommand, HTTP/HTTPS remote output always uses `Content-Type: text/plain; charset=utf-8`.
- If `--output-format` is explicitly set with `dmesg`, a warning is logged.

## `dmesg` examples

```bash
./embedded_linux_audit linux dmesg
./embedded_linux_audit --quiet linux dmesg
./embedded_linux_audit --output-tcp 192.168.1.50:5001 linux dmesg
./embedded_linux_audit --output-http http://192.168.1.50:5000/dmesg linux dmesg
./embedded_linux_audit --output-http https://192.168.1.50:5443/dmesg linux dmesg
./embedded_linux_audit --insecure --output-http https://192.168.1.50:5443/dmesg linux dmesg
./embedded_linux_audit --output-format json linux dmesg
```