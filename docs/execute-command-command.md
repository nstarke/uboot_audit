# `embedded_linux_audit linux execute-command` Command

Executes a shell command string on the local host, captures its stdout, prints formatted output locally, and can optionally duplicate that formatted output to TCP or HTTP(S) remote destinations.

## `execute-command` arguments

- `<command-string>` — required shell command string passed to `popen(3)`
- `--output-format <txt|csv|json>` — top-level global option controlling local and remote formatting for this subcommand
- `--output-tcp <IPv4:port>` — top-level global option to duplicate formatted output to a TCP destination
- `--output-http <http://host:port/path>` — top-level global option to POST formatted output to the helper API
- `--output-http <https://host:port/path>` — top-level global option to POST formatted output to the helper API over HTTPS
- `--insecure` — top-level global option to disable TLS certificate and hostname verification for HTTPS output

## Output formats

- `txt` — emits the command string, a newline, then the captured command output
- `csv` — emits a single CSV row: `"<command>","<output>"`
- `json` — emits one JSON object with `command` and `output` fields

When HTTP(S) output is configured, the client POSTs to `/{mac_address}/upload/cmd` using:

- `text/plain; charset=utf-8` for `txt`
- `text/csv; charset=utf-8` for `csv`
- `application/json; charset=utf-8` for `json`

## Notes

- Only one of `--output-http` or `--output-http` may be used at a time.
- If `--output-tcp` is also set, the same formatted payload is sent to TCP in addition to local stdout.
- The command exit status affects the overall subcommand result: non-zero command exit or signal termination causes a non-zero return.
- Output capture is based on stdout from the shell command string.

## Examples

```bash
./embedded_linux_audit linux execute-command "uname -a"
./embedded_linux_audit --output-format csv linux execute-command "id"
./embedded_linux_audit --output-format json linux execute-command "cat /proc/cpuinfo"
./embedded_linux_audit --output-http http://192.168.1.50:5000 linux execute-command "ps"
./embedded_linux_audit --insecure --output-http https://192.168.1.50:5443 linux execute-command "dmesg | tail"
./embedded_linux_audit --output-tcp 192.168.1.50:5001 linux execute-command "mount"
```