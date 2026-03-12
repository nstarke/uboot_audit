#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../../../.." && pwd)"

# shellcheck source=tests/api/agent/common.sh
. "$SCRIPT_DIR/../common.sh"

print_section "api clean behavior"

TMPDIR_CLEAN="$(mktemp -d /tmp/fw_api_clean.XXXXXX)"
trap 'rm -rf "$TMPDIR_CLEAN"' EXIT INT TERM

mkdir -p "$TMPDIR_CLEAN/data/release_binaries" "$TMPDIR_CLEAN/data/old_run/subdir"
printf 'cached-release\n' > "$TMPDIR_CLEAN/data/release_binaries/ela-arm64"
printf 'stale\n' > "$TMPDIR_CLEAN/data/old_run/subdir/file.txt"
printf 'root-stale\n' > "$TMPDIR_CLEAN/data/stale.txt"

TEST_TMPDIR_CLEAN="$TMPDIR_CLEAN" REPO_ROOT="$REPO_ROOT" node - <<'NODE'
const path = require('path');
const repoRoot = process.env.REPO_ROOT;
const tmpDir = process.env.TEST_TMPDIR_CLEAN;
const { removeDirectoryContents } = require(path.join(repoRoot, 'api', 'agent', 'server.js'));

removeDirectoryContents(path.join(tmpDir, 'data'), new Set(['release_binaries']))
  .catch((err) => {
    console.error(err.stack || err.message);
    process.exit(1);
  });
NODE

if [ -f "$TMPDIR_CLEAN/data/release_binaries/ela-arm64" ]; then
    pass_case "--clean preserves release_binaries contents"
else
    fail_case "--clean preserves release_binaries contents" sh -c "find '$TMPDIR_CLEAN/data' -maxdepth 3 -print"
fi

if [ ! -e "$TMPDIR_CLEAN/data/old_run" ] && [ ! -e "$TMPDIR_CLEAN/data/stale.txt" ]; then
    pass_case "--clean removes non-release runtime data"
else
    fail_case "--clean removes non-release runtime data" sh -c "find '$TMPDIR_CLEAN/data' -maxdepth 3 -print"
fi

finish_web_tests