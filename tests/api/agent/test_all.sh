#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"

rc=0

for test_script in \
    "$SCRIPT_DIR/server/test_server_args.sh" \
    "$SCRIPT_DIR/server/test_server_clean.sh" \
    "$SCRIPT_DIR/routes/test_routes_get.sh" \
    "$SCRIPT_DIR/routes/test_routes_upload.sh"
do
    echo
    echo "===== Running $(basename "$test_script") ====="
    /bin/sh "$test_script"
    if [ "$?" -ne 0 ]; then
        rc=1
    fi
done

exit "$rc"