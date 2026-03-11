# `embedded_linux_audit efi dump-vars` Command

Enumerates EFI variables available through efivarfs/libefivar and emits one formatted record per variable.

This command supports local stdout output plus optional TCP or HTTP(S) upload of the same formatted records.

## `efi dump-vars` arguments

- `--help` — show command usage
- `--output-format <txt|csv|json>` — top-level global option controlling output formatting
- `--output-tcp <IPv4:port>` — top-level global option to stream formatted records to TCP
- `--output-http <http://host:port/path>` — top-level global option to POST formatted records to the helper API
- `--output-http <https://host:port/path>` — top-level global option to POST formatted records to the helper API over HTTPS
- `--insecure` — top-level global option to disable TLS certificate and hostname verification for HTTPS output

## Emitted record fields

Each EFI variable record includes:

- variable GUID
- variable name
- EFI attribute bitmask
- payload size in bytes
- payload bytes encoded as lowercase hexadecimal

## Output formats

- `txt` — one line per variable in `guid=... name=... attributes=... size=... data_hex=...` form
- `csv` — one CSV row per variable containing GUID, name, attributes, size, and hex payload
- `json` — newline-delimited JSON objects with fields `record`, `guid`, `name`, `attributes`, `size`, and `data_hex`

When HTTP(S) output is configured, the client POSTs to `/{mac_address}/upload/efi-vars` using:

- `text/plain; charset=utf-8` for `txt`
- `text/csv; charset=utf-8` for `csv`
- `application/x-ndjson; charset=utf-8` for `json`

## Notes

- Only one of `--output-http` or `--output-http` may be used at a time.
- If `--output-tcp` is set, formatted records are streamed as they are emitted.
- The command fails when EFI variables are not supported on the current system.
- The command also fails if no EFI variables are found or enumeration/read operations fail.
- Error messages are printed to stderr and, when HTTP(S) output is enabled, may also be uploaded as helper log messages.

## Examples

```bash
./embedded_linux_audit efi dump-vars
./embedded_linux_audit --output-format csv efi dump-vars
./embedded_linux_audit --output-format json efi dump-vars
./embedded_linux_audit --output-http http://192.168.1.50:5000 efi dump-vars
./embedded_linux_audit --insecure --output-http https://192.168.1.50:5443 efi dump-vars
./embedded_linux_audit --output-tcp 192.168.1.50:5001 efi dump-vars
```