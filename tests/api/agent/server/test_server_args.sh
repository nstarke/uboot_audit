#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../../../.." && pwd)"

# shellcheck source=tests/api/agent/common.sh
. "$SCRIPT_DIR/../common.sh"

print_section "api server argument parsing"

TMPDIR_ARGS="$(mktemp -d /tmp/fw_api_args.XXXXXX)"
trap 'rm -rf "$TMPDIR_ARGS"' EXIT INT TERM

TEST_TMPDIR_ARGS="$TMPDIR_ARGS" REPO_ROOT="$REPO_ROOT" node - <<'NODE'
const path = require('path');
const fs = require('fs');
const repoRoot = process.env.REPO_ROOT;
const tmpDir = process.env.TEST_TMPDIR_ARGS;
const { parseArgs, printHelp } = require(path.join(repoRoot, 'api', 'agent', 'server.js'));

function fail(message) {
  console.error(message);
  process.exit(1);
}

const args = parseArgs(['--data-dir', path.join(tmpDir, 'custom-data')]);
if (args.dataDir !== path.join(tmpDir, 'custom-data')) {
  fail(`expected parseArgs to preserve --data-dir, got: ${args.dataDir}`);
}

const serverModule = require(path.join(repoRoot, 'api', 'agent', 'server.js'));
if (serverModule.PROJECT_ROOT !== repoRoot) {
  fail(`expected PROJECT_ROOT to resolve to repo root, got: ${serverModule.PROJECT_ROOT}`);
}

if (serverModule.resolveProjectPath('tests') !== path.join(repoRoot, 'tests')) {
  fail(`expected resolveProjectPath('tests') to resolve under repo root, got: ${serverModule.resolveProjectPath('tests')}`);
}

if (!fs.existsSync(serverModule.resolveProjectPath('tests/agent/shell/download_tests.sh'))) {
  fail(`expected download_tests.sh to exist at resolved path, got: ${serverModule.resolveProjectPath('tests/agent/shell/download_tests.sh')}`);
}

let help = '';
const originalLog = console.log;
console.log = (line) => {
  help += `${line}\n`;
};
printHelp();
console.log = originalLog;

if (!help.includes('--data-dir DIR')) {
  fail('expected help output to include --data-dir DIR');
}
NODE

if [ "$?" -eq 0 ]; then
    pass_case "server paths resolve from repo root and --data-dir is accepted and shown in help"
else
    fail_case "server paths resolve from repo root and --data-dir is accepted and shown in help"
fi

finish_web_tests