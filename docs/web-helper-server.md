# Web Helper Server

Use the Node.js helper in `web/` as the local helper for testing HTTP/HTTPS POST output and serving downloaded release binaries/test scripts.

Example:

```bash
cd web && npm start -- --host 0.0.0.0 --port 5000 --log-prefix post_requests
```

You can also enable verbose per-request console logging with either:

```bash
cd web && npm start --verbose
```

or:

```bash
cd web && npm start -- --verbose
```

Additional server options:

- `--https` enables HTTPS with a self-signed localhost certificate.
- `--clean` deletes everything under `web/data` before startup.
- `--force-download` refreshes the cached release binaries in `web/data/release_binaries`.

POST handling notes:

- accepted `Content-Type` values:
  - `text/plain`
  - `text/csv`
  - `application/x-ndjson`
  - `application/octet-stream`
- invalid or missing `Content-Type` values are rejected with HTTP `415`.
- log output is split by content type into files derived from `--log-prefix` (for example `post_requests.text_plain.log`, `post_requests.text_csv.log`, and `post_requests.application_octet_stream.log`).
- `application/octet-stream` uploads are additionally written as raw `.bin` files for later analysis (default directory: `<log-prefix>.binary_files`, override with `--binary-out-dir`).
- runtime upload data is stored under `web/data/<startup_timestamp>/...` for `fs`, `env`, `logs`, `dmesg`, `orom`, `uboot/image`, and `uboot/env`.
- downloaded release binaries are cached separately under `web/data/release_binaries`.
- `GET /` returns an HTML index of release binaries and test scripts.
- `GET /tests/:name`, `GET /isa/:isa`, and `GET /uboot-env/:env_filename` serve test scripts, ISA binaries, and U-Boot environment helper files respectively.
