#!/bin/sh
set -eu
case_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
exec python3 "$case_dir/../../ladder_case.py" "$@"
