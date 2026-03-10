# API Helper Server

Use the Node.js helper in `api/` as the local helper for testing HTTP/HTTPS POST output and serving downloaded release binaries/test scripts.

Example:

```bash
cd api && npm start -- --host 0.0.0.0 --port 5000 --log-prefix post_requests
```

You can also enable verbose per-request console logging with either:

```bash
cd api && npm start --verbose
```

or:

```bash
cd api && npm start -- --verbose
```

Additional server options:

- `--https` enables HTTPS with a self-signed localhost certificate.
- `--clean` deletes everything under `api/data` before startup.
- `--force-download` refreshes the cached release binaries in `api/data/release_binaries`.

POST handling notes:

- accepted `Content-Type` values:
  - `text/plain`
  - `text/csv`
  - `application/x-ndjson`
  - `application/octet-stream`
- invalid or missing `Content-Type` values are rejected with HTTP `415`.
- log output is split by content type into files derived from `--log-prefix` (for example `post_requests.text_plain.log`, `post_requests.text_csv.log`, and `post_requests.application_octet_stream.log`).
- `application/octet-stream` uploads are additionally written as raw `.bin` files under the per-host runtime upload directories for later analysis.
- runtime upload data is stored under `api/data/<startup_timestamp>/<mac_address>/...` for `fs`, `file-list`, `env`, `logs`, `dmesg`, `orom`, `uboot/image`, and `uboot/env`.
- `/upload/log` and `/upload/logs` are both accepted and stored under `api/data/<startup_timestamp>/<mac_address>/logs/`.
- downloaded release binaries are cached separately under `api/data/release_binaries`.
- `GET /` returns an HTML index of release binaries and agent test scripts.
- `GET /tests/agent/:name` serves `.sh` files from `tests/agent/` (for example `/tests/agent/download_tests.sh`). `GET /isa/:isa` and `GET /uboot-env/:env_filename` serve ISA binaries and U-Boot environment helper files respectively.
