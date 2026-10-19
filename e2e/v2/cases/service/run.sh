#!/bin/bash
set -eu
case_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$case_dir/run.py" "$@"
