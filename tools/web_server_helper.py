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


RELEASE_STATE_FILE = ".release_state.json"
VALID_CONTENT_TYPES: dict[str, str] = {
    "text/plain": "text_plain",
    "text/csv": "text_csv",
    "application/octet-stream": "application_octet_stream",
}


def normalize_content_type(content_type_header: str) -> str:
    """Extract and normalize MIME type from a Content-Type header."""
    return content_type_header.split(";", 1)[0].strip().lower()


def log_path_for_content_type(log_prefix: Path, content_type_header: str) -> Path:
    """Build a content-type-specific log file path from the configured log prefix."""
    content_type = normalize_content_type(content_type_header)
    suffix = VALID_CONTENT_TYPES.get(content_type)
    if not suffix:
        return log_prefix.with_name(f"{log_prefix.name}.unknown.log")

    filename = f"{log_prefix.name}.{suffix}.log"
    return log_prefix.with_name(filename)


def augment_json_payload(payload: bytes, timestamp: str, src_ip: str) -> bytes:
    """Add timestamp/src_ip fields to JSON object payloads (supports NDJSON)."""
    text = payload.decode("utf-8", errors="strict")
    stripped = text.strip()
    if not stripped:
        return payload

    # NDJSON support: one JSON object per non-empty line.
    lines = text.splitlines()
    if len(lines) > 1:
        out_lines: list[str] = []
        changed = False
        for line in lines:
            if not line.strip():
                continue
            obj = json.loads(line)
            if not isinstance(obj, dict):
                return payload
            obj["timestamp"] = timestamp
            obj["src_ip"] = src_ip
            out_lines.append(json.dumps(obj, separators=(",", ":")))
            changed = True
        if changed:
            return ("\n".join(out_lines) + "\n").encode("utf-8")
        return payload

    obj = json.loads(stripped)
    if not isinstance(obj, dict):
        return payload
    obj["timestamp"] = timestamp
    obj["src_ip"] = src_ip
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


def github_json_get(url: str, token: str | None = None) -> dict:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "fw_env_scan-web_server_helper",
            "Accept": "application/vnd.github+json",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def get_latest_release(repo: str, token: str | None = None) -> dict:
    release_url = f"https://api.github.com/repos/{repo}/releases/latest"
    return github_json_get(release_url, token=token)


def release_identity(release: dict) -> str:
    tag_name = release.get("tag_name")
    if tag_name:
        return str(tag_name)
    release_id = release.get("id")
    if release_id is not None:
        return str(release_id)
    return ""


def load_cached_release_identity(out_dir: Path) -> str | None:
    state_path = out_dir / RELEASE_STATE_FILE
    if not state_path.exists():
        return None

    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    cached = state.get("release")
    if isinstance(cached, str) and cached:
        return cached
    return None


def save_cached_release_identity(out_dir: Path, release: str) -> None:
    state_path = out_dir / RELEASE_STATE_FILE
    state = {
        "release": release,
        "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


def clear_downloaded_assets(out_dir: Path) -> None:
    for child in out_dir.iterdir():
        if child.name == RELEASE_STATE_FILE:
            continue
        if child.is_file() or child.is_symlink():
            child.unlink()


def download_release_assets(
    release: dict,
    out_dir: Path,
    token: str | None = None,
    force_download: bool = False,
) -> tuple[list[Path], list[Path]]:
    out_dir.mkdir(parents=True, exist_ok=True)
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
                "User-Agent": "fw_env_scan-web_server_helper",
                **({"Authorization": f"Bearer {token}"} if token else {}),
            },
        )
        with urllib.request.urlopen(req) as resp, dest.open("wb") as fp:
            shutil.copyfileobj(resp, fp)
        downloaded.append(dest)

    return downloaded, skipped_existing


def build_handler(log_prefix: Path, assets_dir: Path, tests_dir: Path, verbose: bool = False):
    class PostLoggerHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args):
            # Keep server console quiet; requests are written to content-type log files.
            return

        def _verbose_request_log(self) -> None:
            if not verbose:
                return
            timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
            print(f"[{timestamp}] {self.client_address[0]} {self.command} {self.path}", flush=True)

        def _verbose_response_log(self, status: int, size: int) -> None:
            if not verbose:
                return
            timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
            print(
                f"[{timestamp}] {self.client_address[0]} {self.command} {self.path} -> {status} ({size} bytes)",
                flush=True,
            )

        def _send_bytes(self, status: int, body: bytes, content_type: str = "text/plain; charset=utf-8"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            self._verbose_response_log(status, len(body))

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
            self._verbose_request_log()
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
            self._verbose_request_log()
            content_len = int(self.headers.get("Content-Length", "0"))
            payload = self.rfile.read(content_len)
            timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
            src_ip = self.client_address[0]
            content_type_header = self.headers.get("Content-Type", "")
            normalized_content_type = normalize_content_type(content_type_header)

            if normalized_content_type not in VALID_CONTENT_TYPES:
                allowed = ", ".join(sorted(VALID_CONTENT_TYPES.keys()))
                body = (
                    "unsupported content type; expected one of: "
                    f"{allowed}\n"
                ).encode("utf-8")
                self._send_bytes(415, body)
                return

            target_log_path = log_path_for_content_type(log_prefix, content_type_header)

            payload_to_log = payload
            should_try_json = "json" in normalized_content_type
            if not should_try_json:
                # Also attempt JSON parse heuristically for clients that omit content-type.
                try:
                    payload.decode("utf-8", errors="strict")
                    should_try_json = True
                except UnicodeDecodeError:
                    should_try_json = False

            if should_try_json:
                try:
                    payload_to_log = augment_json_payload(payload, timestamp, src_ip)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    payload_to_log = payload

            target_log_path.parent.mkdir(parents=True, exist_ok=True)
            with target_log_path.open("ab") as fp:
                fp.write(f"[{timestamp}] {src_ip} {self.path}\n".encode("utf-8"))
                fp.write(f"Content-Type: {normalized_content_type}\n".encode("utf-8"))
                fp.write(payload_to_log)
                fp.write(b"\n\n---\n\n")

            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"ok\n")
            self._verbose_response_log(200, 3)

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
    parser.add_argument(
        "--log-prefix",
        default="post_requests",
        help="Log filename prefix (content-type logs are written as <prefix>.<type>.log)",
    )
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
    parser.add_argument("--verbose", action="store_true", help="Log each incoming web request to stdout")
    parser.add_argument("--cert", default="tools/certs/localhost.crt", help="TLS cert path")
    parser.add_argument("--key", default="tools/certs/localhost.key", help="TLS private key path")
    args = parser.parse_args()

    log_prefix = Path(args.log_prefix)
    assets_dir = Path(args.assets_dir)
    tests_dir = Path(args.tests_dir)
    token = args.github_token or None

    try:
        latest_release = get_latest_release(args.repo, token=token)
        latest_release_id = release_identity(latest_release)
        cached_release_id = load_cached_release_identity(assets_dir)
        is_new_release = bool(latest_release_id) and latest_release_id != cached_release_id

        if args.force_download:
            print("Force download enabled; refreshing release binaries")
            clear_downloaded_assets(assets_dir)
            downloaded, skipped_existing = download_release_assets(
                latest_release,
                assets_dir,
                token=token,
                force_download=True,
            )
            if latest_release_id:
                save_cached_release_identity(assets_dir, latest_release_id)
        elif is_new_release:
            prev = cached_release_id or "<none>"
            print(f"New release detected ({prev} -> {latest_release_id}); refreshing binaries")
            clear_downloaded_assets(assets_dir)
            downloaded, skipped_existing = download_release_assets(
                latest_release,
                assets_dir,
                token=token,
                force_download=True,
            )
            save_cached_release_identity(assets_dir, latest_release_id)
        else:
            print("No new release detected; keeping existing binaries")
            downloaded, skipped_existing = download_release_assets(
                latest_release,
                assets_dir,
                token=token,
                force_download=False,
            )
            if latest_release_id and cached_release_id != latest_release_id:
                save_cached_release_identity(assets_dir, latest_release_id)
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

    handler = build_handler(log_prefix, assets_dir, tests_dir, verbose=args.verbose)
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
    print(f"Logging POST requests with prefix: {log_prefix}")
    print("Per-type logs: <prefix>.text_plain.log, <prefix>.text_csv.log, <prefix>.application_octet_stream.log")
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
