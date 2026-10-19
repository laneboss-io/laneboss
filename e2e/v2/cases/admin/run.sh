#!/usr/bin/env bash
# Only the disposable Linux harness executes this case.
set -euo pipefail
case_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
exec python3 -I "$case_dir/run.py" "$@"
