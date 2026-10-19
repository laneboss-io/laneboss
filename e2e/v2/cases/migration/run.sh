#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 4 ] || [ "$1" != "--context" ] || [ "$3" != "--result" ]; then
    printf 'usage: %s --context CONTEXT_FILE --result RESULT_FILE\n' "$0" >&2
    exit 2
fi

context_file="$2"
result_file="$4"

case "$context_file" in
    /*) ;;
    *)
        printf 'context path must be absolute\n' >&2
        exit 2
        ;;
esac

case "$result_file" in
    /*) ;;
    *)
        printf 'result path must be absolute\n' >&2
        exit 2
        ;;
esac

case_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
exec python3 -I "$case_dir/driver.py" --context "$context_file" --result "$result_file"
