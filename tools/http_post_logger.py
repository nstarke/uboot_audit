#!/usr/bin/env python3
"""HTTP(S) POST logger that also serves latest GitHub release binaries over GET."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import mimetypes
import os
import shutil
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def github_json_get(url: str, token: str | None = None) -> dict:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "fw_env_scan-http_post_logger",
            "Accept": "application/vnd.github+json",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def download_latest_release_assets(
    repo: str,
    out_dir: Path,
    token: str | None = None,
    force_download: bool = False,
) -> tuple[list[Path], list[Path]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    release_url = f"https://api.github.com/repos/{repo}/releases/latest"
    release = github_json_get(release_url, token=token)
    assets = release.get("assets", [])

    downloaded: list[Path] = []
    skipped_existing: list[Path] = []
    for asset in assets:
        name = asset.get("name")
        download_url = asset.get("browser_download_url")
        if not name or not download_url:
            continue

        dest = out_dir / name
        if dest.exists() and not force_download:
            skipped_existing.append(dest)
            continue

        req = urllib.request.Request(
            download_url,
            headers={
                "User-Agent": "fw_env_scan-http_post_logger",
                **({"Authorization": f"Bearer {token}"} if token else {}),
            },
        )
        with urllib.request.urlopen(req) as resp, dest.open("wb") as fp:
            shutil.copyfileobj(resp, fp)
        downloaded.append(dest)

    return downloaded, skipped_existing


def build_handler(log_path: Path, assets_dir: Path, tests_dir: Path):
    class PostLoggerHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args):
            # Keep server console quiet; requests are written to log_path.
            return

        def _send_bytes(self, status: int, body: bytes, content_type: str = "text/plain; charset=utf-8"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _safe_asset_path(self) -> Path | None:
            parsed = urllib.parse.urlparse(self.path)
            rel = urllib.parse.unquote(parsed.path).lstrip("/")
            if not rel:
                return None

            if rel.startswith("tests/"):
                test_rel = rel[len("tests/") :]
                if not test_rel:
                    return None
                candidate = (tests_dir / test_rel).resolve()
                root = tests_dir.resolve()
                if root == candidate or root in candidate.parents:
                    return candidate
                return None

            candidate = (assets_dir / rel).resolve()
            root = assets_dir.resolve()
            if root == candidate or root in candidate.parents:
                return candidate
            return None

        def _build_index(self) -> bytes:
            asset_entries = sorted(p.name for p in assets_dir.iterdir() if p.is_file())
            test_entries = sorted(p.name for p in tests_dir.glob("*.sh") if p.is_file())

            asset_items = "\n".join(
                f'<li><a href="/{urllib.parse.quote(name)}">{name}</a></li>' for name in asset_entries
            )
            test_items = "\n".join(
                f'<li><a href="/tests/{urllib.parse.quote(name)}">tests/{name}</a></li>'
                for name in test_entries
            )

            html = f"""<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\" />
    <title>Release Binaries and Test Scripts</title>
  </head>
  <body>
    <h1>Release Binaries</h1>
    <p>Serving files from: {assets_dir}</p>
    <ul>
      {asset_items if asset_items else '<li><em>No binaries downloaded.</em></li>'}
    </ul>

    <h1>Test Scripts</h1>
    <p>Serving scripts from: {tests_dir}</p>
    <ul>
      {test_items if test_items else '<li><em>No test shell scripts found.</em></li>'}
    </ul>
  </body>
</html>
"""
            return html.encode("utf-8")

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/":
                self._send_bytes(200, self._build_index(), "text/html; charset=utf-8")
                return

            asset_path = self._safe_asset_path()
            if asset_path is None or not asset_path.is_file():
                self._send_bytes(404, b"not found\n")
                return

            content_type, _ = mimetypes.guess_type(asset_path.name)
            if content_type is None:
                content_type = "application/octet-stream"

            data = asset_path.read_bytes()
            self._send_bytes(200, data, content_type)

        def do_POST(self):
            content_len = int(self.headers.get("Content-Length", "0"))
            payload = self.rfile.read(content_len)
            timestamp = dt.datetime.now(dt.timezone.utc).isoformat()

            with log_path.open("ab") as fp:
                fp.write(f"[{timestamp}] {self.client_address[0]} {self.path}\n".encode("utf-8"))
                for key, value in self.headers.items():
                    fp.write(f"{key}: {value}\n".encode("utf-8"))
                fp.write(b"\n")
                fp.write(payload)
                fp.write(b"\n\n---\n\n")

            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"ok\n")

    return PostLoggerHandler


def ensure_self_signed_cert(cert_path: Path, key_path: Path) -> None:
    if cert_path.exists() and key_path.exists():
        return

    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError(
            "--https requires openssl to generate a self-signed certificate when cert/key are missing"
        )

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        openssl,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-days",
        "3650",
        "-nodes",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
    ]

    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main() -> int:
    parser = argparse.ArgumentParser(description="Receive HTTP POST requests and log them to a file")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Bind port (default: 5000)")
    parser.add_argument("--log", default="post_requests.log", help="Log file path")
    parser.add_argument(
        "--repo",
        default="nstarke/U-Boot-fw_env_scan",
        help="GitHub repo in owner/name form (default: nstarke/U-Boot-fw_env_scan)",
    )
    parser.add_argument(
        "--assets-dir",
        default="tools/release_binaries",
        help="Directory to store latest release binaries (default: tools/release_binaries)",
    )
    parser.add_argument(
        "--tests-dir",
        default="tests",
        help="Directory to serve test shell scripts from (default: tests)",
    )
    parser.add_argument(
        "--github-token",
        default=os.environ.get("GITHUB_TOKEN", ""),
        help="Optional GitHub token (defaults to GITHUB_TOKEN env var)",
    )
    parser.add_argument(
        "--force-download",
        action="store_true",
        help="Force re-download of release binaries even if files already exist locally",
    )
    parser.add_argument("--https", action="store_true", help="Enable HTTPS with TLS")
    parser.add_argument("--cert", default="tools/certs/localhost.crt", help="TLS cert path")
    parser.add_argument("--key", default="tools/certs/localhost.key", help="TLS private key path")
    args = parser.parse_args()

    log_path = Path(args.log)
    assets_dir = Path(args.assets_dir)
    tests_dir = Path(args.tests_dir)
    token = args.github_token or None

    try:
        downloaded, skipped_existing = download_latest_release_assets(
            args.repo,
            assets_dir,
            token=token,
            force_download=args.force_download,
        )
    except urllib.error.HTTPError as exc:
        print(f"Failed to fetch/download release assets from {args.repo}: HTTP {exc.code}")
        return 1
    except urllib.error.URLError as exc:
        print(f"Failed to fetch/download release assets from {args.repo}: {exc.reason}")
        return 1

    print(f"Downloaded {len(downloaded)} release asset(s) from {args.repo} into {assets_dir}")
    if skipped_existing:
        print(
            "Skipped "
            f"{len(skipped_existing)} existing release asset(s) in {assets_dir} "
            "(use --force-download to replace them)"
        )

    handler = build_handler(log_path, assets_dir, tests_dir)
    server = HTTPServer((args.host, args.port), handler)

    scheme = "http"
    if args.https:
        cert_path = Path(args.cert)
        key_path = Path(args.key)
        ensure_self_signed_cert(cert_path, key_path)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"

    print(f"Listening on {scheme}://{args.host}:{args.port}/")
    print(f"Logging POST requests to: {log_path}")
    print("GET / shows index of downloaded release binaries and test shell scripts")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
