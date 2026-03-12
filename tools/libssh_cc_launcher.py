#!/usr/bin/env python3

import os
import subprocess
import sys


DROP_FLAGS = {
    "-D_GNU_SOURCE",
    "-fstack-clash-protection",
    "-Wstrict-prototypes",
    "-Werror=strict-prototypes",
}

REWRITE_FLAGS = {
    "-Werror=strict-prototypes": "-Wno-error=strict-prototypes",
    "-Wstrict-prototypes": "-Wno-strict-prototypes",
}


def needs_stdio_include(args: list[str]) -> bool:
    for arg in args:
        normalized = arg.replace("\\", "/")
        if normalized.endswith("/third_party/libssh/src/dh.c") or normalized.endswith("/libssh/src/dh.c") or normalized == "dh.c":
            return True
    return False


def main() -> int:
    if len(sys.argv) < 2:
        print("libssh_cc_launcher.py: missing compiler command", file=sys.stderr)
        return 1

    original_args = sys.argv[1:]
    filtered = []
    for arg in original_args:
        replacement = REWRITE_FLAGS.get(arg)
        if replacement is not None:
            filtered.append(replacement)
            continue
        if arg in DROP_FLAGS:
            continue
        filtered.append(arg)

    if needs_stdio_include(original_args):
        filtered.extend(["-include", "stdio.h"])

    return subprocess.call(filtered, env=os.environ.copy())


if __name__ == "__main__":
    raise SystemExit(main())