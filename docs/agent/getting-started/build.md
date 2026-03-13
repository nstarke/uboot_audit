# Build and Release Notes

## Build

Build binary:

```bash
make env
```

Build binary (alias):

```bash
make image
```

Build both:

```bash
git submodule update --init --recursive
make
```

Notes:

- Project C sources and headers now live under `agent/`, grouped by command family:
  - `agent/uboot/` for U-Boot command implementations and `agent/uboot/audit-rules/` for audit rule sources.
  - `agent/linux/` for Linux command implementations.
  - `agent/embedded_linux_audit.c` is the top-level CLI entrypoint.
- `libcsv` is built from source directly from `third_party/libcsv/libcsv.c`.
- `zlib` is built from source from the `third_party/zlib` submodule and linked statically.
- `libubootenv` is built from source from the `third_party/libubootenv` submodule and linked statically.
- `json-c` is built from source from the `third_party/json-c` submodule via CMake, and linked statically (`third_party/json-c/build/libjson-c.a`).
- `libcurl` is built from source from the `third_party/curl` submodule via CMake, and linked statically (`third_party/curl/build/lib/libcurl.a`).
- `OpenSSL` is built from source from the `third_party/openssl` submodule (`libcrypto` static) and used for audit signature verification.
- Official U-Boot source is tracked as submodule at `third_party/u-boot`.
- The default CA bundle is fetched from `https://curl.se/ca/cacert.pem` at build time and embedded into the binary.
- Override bundle source with:
  - `CA_BUNDLE_URL=<url>` to change download URL
  - `CA_BUNDLE_PEM=<path>` to use a local PEM file instead of downloading

Static build:

```bash
make static
```

Clean:

```bash
make clean
```

Run argument-coverage tests:

```bash
make test
```

Cross compile example:

```bash
make CC=arm-linux-gnueabi-gcc
```

Cross compile with Zig + musl (recommended for fully static output):

```bash
make clean && make static \
  CMAKE_C_COMPILER=$(command -v zig) \
  CMAKE_C_COMPILER_ARG1=cc \
  CMAKE_C_COMPILER_TARGET=arm-linux-musleabi \
  CC='zig cc -target arm-linux-musleabi'
```

Generic Zig target form:

```bash
make clean && make static \
  CMAKE_C_COMPILER=$(command -v zig) \
  CMAKE_C_COMPILER_ARG1=cc \
  CMAKE_C_COMPILER_TARGET=<zig-target-triple> \
  CC='zig cc -target <zig-target-triple>'
```

Examples:

```bash
# x86_64 static musl
make clean && make static \
  CMAKE_C_COMPILER=$(command -v zig) \
  CMAKE_C_COMPILER_ARG1=cc \
  CMAKE_C_COMPILER_TARGET=x86_64-linux-musl \
  CC='zig cc -target x86_64-linux-musl'

# aarch64 static musl
make clean && make static \
  CMAKE_C_COMPILER=$(command -v zig) \
  CMAKE_C_COMPILER_ARG1=cc \
  CMAKE_C_COMPILER_TARGET=aarch64-linux-musl \
  CC='zig cc -target aarch64-linux-musl'
```

## GitHub release static builds

Release artifacts are produced by `.github/workflows/release-cross-static.yml`, which cross-compiles static binaries with Zig for multiple architectures and uploads them to GitHub Releases.
