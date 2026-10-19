#!/usr/bin/env bash
set -euo pipefail

context_file=""
result_file=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --context)
            if [ "$#" -lt 2 ]; then
                echo "missing value for --context" >&2
                exit 2
            fi
            context_file="$2"
            shift 2
            ;;
        --result)
            if [ "$#" -lt 2 ]; then
                echo "missing value for --result" >&2
                exit 2
            fi
            result_file="$2"
            shift 2
            ;;
        *)
            echo "unexpected argument: $1" >&2
            exit 2
            ;;
    esac
done

if [ -z "$context_file" ] || [ -z "$result_file" ]; then
    echo "usage: run.sh --context CONTEXT_FILE --result RESULT_FILE" >&2
    exit 2
fi

case_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$case_dir/case.py" --context "$context_file" --result "$result_file"
