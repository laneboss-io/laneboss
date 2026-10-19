#!/usr/bin/env bash
# Run only on the authorized Ubuntu box.
set -euo pipefail
umask 077

serve_case=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
serve_driver="$serve_case/../../../.."
serve_driver="$serve_driver/scripts/v2-serve/run.py"
serve_pid=

serve_cleanup() {
    local serve_exit=$?
    trap - EXIT HUP INT TERM
    if [[ -n $serve_pid ]]; then
        if kill -0 "$serve_pid" 2>/dev/null; then
            kill -TERM "$serve_pid"
        fi
        if wait "$serve_pid"; then
            if (( serve_exit != 0 )); then
                serve_exit=1
            fi
        else
            serve_exit=1
        fi
    fi
    exit "$serve_exit"
}
trap serve_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM

# The driver retains exact argv, bytes, exits and a
# fail result for every check that cannot be run.
python3 -I -B "$serve_driver" "$@" &
serve_pid=$!
if wait "$serve_pid"; then
    serve_pid=
else
    serve_exit=$?
    serve_pid=
    exit "$serve_exit"
fi
