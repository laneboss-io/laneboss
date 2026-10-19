#!/bin/sh
set -eu
dirty_case_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
exec python3 -E "$dirty_case_dir/run.py" "$@"
