#!/bin/sh
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
exec python3 "$root/e2e/v2/installed_ladder.py" "$@"
