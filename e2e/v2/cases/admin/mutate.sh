#!/usr/bin/env bash
# Executes project code only on the supervisor's disposable Linux test box.
set -euo pipefail
admin_case_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
exec python3 -I "$admin_case_dir/mutate.py" "$@"
