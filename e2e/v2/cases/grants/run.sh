#!/bin/sh
set -eu
grants_case_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
exec python3 -E "$grants_case_dir/run.py" "$@"
