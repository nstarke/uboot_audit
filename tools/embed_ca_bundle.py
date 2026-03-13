#!/usr/bin/env python3
"""Embed a PEM CA bundle into a C translation unit."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Embed CA bundle PEM as C byte array")
    parser.add_argument("--input", required=True, help="Path to PEM bundle")
    parser.add_argument("--output", required=True, help="Path to generated C file")
    args = parser.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)

    data = in_path.read_bytes()
    if not data.endswith(b"\n"):
        data += b"\n"

    out_path.parent.mkdir(parents=True, exist_ok=True)

    lines = []
    for i, b in enumerate(data):
        if i % 12 == 0:
            lines.append("    ")
        lines[-1] += f"0x{b:02x}, "

    body = "\n".join(lines) if lines else ""

    out_path.write_text(
        "// Generated file. Do not edit manually.\n"
        "#include <stddef.h>\n\n"
        "const unsigned char ela_default_ca_bundle_pem[] = {\n"
        f"{body}\n"
        "};\n"
        "const size_t ela_default_ca_bundle_pem_len = sizeof(ela_default_ca_bundle_pem);\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
