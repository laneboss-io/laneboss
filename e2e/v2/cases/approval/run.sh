#!/bin/sh
set -eu
case_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
exec python3 -B "$case_dir/case.py" "$@"
