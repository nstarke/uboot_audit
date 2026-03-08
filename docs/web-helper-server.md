# Web Helper Server

Use `tools/web_server_helper.py` as a local helper for testing HTTP/HTTPS POST output and serving downloaded release binaries/test scripts.

Example:

```bash
python3 tools/web_server_helper.py --host 0.0.0.0 --port 5000 --log-prefix post_requests
```

POST handling notes:

- accepted `Content-Type` values:
  - `text/plain`
  - `text/csv`
  - `application/x-ndjson`
  - `application/octet-stream`
- invalid or missing `Content-Type` values are rejected with HTTP `415`.
- log output is split by content type into files derived from `--log-prefix` (for example `post_requests.text_plain.log`, `post_requests.text_csv.log`, and `post_requests.application_octet_stream.log`).
- `application/octet-stream` uploads are additionally written as raw `.bin` files for later analysis (default directory: `<log-prefix>.binary_files`, override with `--binary-out-dir`).
