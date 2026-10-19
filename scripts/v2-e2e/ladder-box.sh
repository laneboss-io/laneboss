#!/bin/sh
# The supervising operator runs this only on its authorized disposable box.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
ladder_mode=run
for ladder_argument do
    case "$ladder_argument" in
        --check-termination|--check-termination=*) ladder_mode=collect ;;
    esac
done
if [ "$ladder_mode" = run ]; then
    if [ -z "${LANEBOSS_LADDER_BUNDLE:-}" ]; then
        echo 'prerequisite_missing: bundle absent' >&2
        echo 'owner: lb-v2-secrets' >&2
        exit 69
    fi
fi
exec python3 -B "$root/e2e/v2/ladder_box.py" "$@"
