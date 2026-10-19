#!/bin/bash
set -eu
case_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
GOWORK=off exec python3 "$case_dir/mutations.py" "$@"
