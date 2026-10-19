#!/usr/bin/env bash
# Static analysis only; no installs, downloads, builds, or test execution.
# LB_STATICCHECK and LB_EXHAUSTIVE must name executable files.
# Counts are unique diagnostics across Linux and the root canary build.
# Exit codes: 0 report/clean, 1 strict findings, 2 missing tool,
# 3 analyzer/output failure, 64 invalid arguments.
set -euo pipefail

strict=false
case "${1:-}" in
    '') ;;
    --strict) strict=true; shift ;;
    *) printf 'usage: bash scripts/lint.sh [--strict]\n' >&2; exit 64 ;;
esac
if (( $# != 0 )); then
    printf 'usage: bash scripts/lint.sh [--strict]\n' >&2
    exit 64
fi

root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$root"
bin_dir="$HOME/.local/state/laneboss-top"
bin_dir="$bin_dir/runs/bin"
static_bin=${LB_STATICCHECK:-$bin_dir/staticcheck}
exhaust_bin=${LB_EXHAUSTIVE:-$bin_dir/exhaustive}
for name in staticcheck exhaustive; do
    case "$name" in
        staticcheck) tool=$static_bin ;;
        exhaustive) tool=$exhaust_bin ;;
    esac
    if [[ $tool != */* || ! -f $tool || ! -x $tool ]]; then
        printf 'lint: missing executable analyzer: %s\n' "$name" >&2
        exit 2
    fi
done
if ! command -v jq >/dev/null 2>&1; then
    printf 'lint: jq is required to validate analyzer output\n' >&2
    exit 2
fi

# Pin the target and cache, and prohibit module/toolchain downloads.
export GOOS=linux GOCACHE=/private/tmp/lb-shared-gocache
export GOFLAGS=-trimpath GOPROXY=off GOSUMDB=off
export GONOPROXY=none GOVCS='*:off'
export GOTOOLCHAIN=local GOTELEMETRY=off
# Staticcheck has a separate cache. Preserve a caller's explicit location.
export STATICCHECK_CACHE=${STATICCHECK_CACHE:-$root/.lane-gocache/staticcheck}
mkdir -p -- "$STATICCHECK_CACHE"

analyze() {
    local name=$1 tags=$2 raw parsed flags=-trimpath
    if [[ -n $tags ]]; then
        flags+=" -tags=$tags"
    fi
    case "$name" in
        staticcheck)
            # Empty -fail keeps findings successful; tool failures still fail.
            if raw=$(GOFLAGS="$flags" "$static_bin" -f json -fail= \
                ./internal/v2/... 2>&1); then
                if parsed=$(printf '%s\n' "$raw" | jq -sc '
                    if all(.[]; .code != "compile" and
                        (.code | type) == "string" and
                        (.message | type) == "string" and
                        (.location.file | type) == "string" and
                        (.location.line | type) == "number" and
                        (.location.column | type) == "number") then
                        map("\(.location.file):\(.location.line):" +
                            "\(.location.column): \(.message) (\(.code))")
                    else error("invalid or failed staticcheck result") end
                '); then
                    printf '%s\n' "$parsed"
                    return
                fi
            fi
            ;;
        exhaustive)
            # The analysis driver uses GOFLAGS for tags; its -tags is a no-op.
            if raw=$(GOFLAGS="$flags" "$exhaust_bin" -json \
                -default-signifies-exhaustive=false ./internal/v2/... 2>&1); then
                if parsed=$(printf '%s\n' "$raw" | jq -sce '
                    if length != 1 or (.[0] | type) != "object" then
                        error("invalid exhaustive result")
                    else .[0] | [to_entries[] | .value | to_entries[] |
                        if .key == "exhaustive" and
                            (.value | type) == "array" then
                            .value[] |
                            if (.posn | type) == "string" and
                                (.message | type) == "string" then
                                "\(.posn): \(.message)"
                            else error("invalid exhaustive diagnostic") end
                        else error("exhaustive analysis failed") end]
                    end
                '); then
                    printf '%s\n' "$parsed"
                    return
                fi
            fi
            ;;
    esac
    printf 'lint: %s failed (tags: %s)\n' "$name" "${tags:-none}" >&2
    printf '%s\n' "$raw" >&2
    exit 3
}

static_base=$(analyze staticcheck '')
static_canary=$(analyze staticcheck laneboss_root_canary)
exhaust_base=$(analyze exhaustive '')
exhaust_canary=$(analyze exhaustive laneboss_root_canary)

combine() {
    printf '%s\n' "$1" "$2" | jq -sc --arg root "$root/" \
        'add | map(ltrimstr($root)) | unique'
}
static_all=$(combine "$static_base" "$static_canary")
exhaust_all=$(combine "$exhaust_base" "$exhaust_canary")
static_count=$(printf '%s\n' "$static_all" | jq 'length')
exhaust_count=$(printf '%s\n' "$exhaust_all" | jq 'length')
printf 'scope: GOOS=linux; tags: none + laneboss_root_canary\n'
printf 'staticcheck: %s findings (unique)\n' "$static_count"
printf '%s\n' "$static_all" | jq -r '.[:10][]'
printf 'exhaustive: %s findings (unique)\n' "$exhaust_count"
printf '%s\n' "$exhaust_all" | jq -r '.[:10][]'
if [[ $strict == true ]] && (( static_count + exhaust_count > 0 )); then
    exit 1
fi
