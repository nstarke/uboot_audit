// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke
//
// This file has been split into the following modules:
//   agent/util/str_util.c      - String/buffer utilities
//   agent/util/isa_util.c      - ISA detection, SIGILL handling, PowerPC compat
//   agent/util/crc32_util.c    - CRC32 table init and calculation
//   agent/net/tcp_util.c       - TCP networking helpers
//   agent/net/http_client.c    - HTTP/HTTPS client (OpenSSL, WolfSSL, curl)
//   agent/lifecycle.c          - Lifecycle event emission
//   agent/device/device_scan.c - Device node scanning (MTD, UBI, eMMC, SD)
//
// This file is intentionally empty and excluded from the build.
// It is retained to preserve git history for the original monolithic implementation.
