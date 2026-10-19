#!/usr/bin/env bash
# Laneboss launches this entry on the authorized disposable Linux box.
set -euo pipefail

canary_case=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
exec bash "$canary_case/../serve/run.sh" "$@" \
    --real-claudock --egress-anthropic --canary-api-key
