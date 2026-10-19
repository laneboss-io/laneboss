#!/bin/sh
set -eu
umask 077
case_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
source_dir=$(CDPATH= cd -- "$case_dir/../../../.." && pwd -P)
scratch=$(mktemp -d /tmp/lb-v2-case-dashboard.XXXXXX)
python3 -B "$case_dir/focus.py" --source "$source_dir" --evidence "$scratch/controls"
