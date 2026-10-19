#!/usr/bin/env bash
# Linux box entry point. Do not run the capture on a workstation.
set -euo pipefail
umask 077

fail() {
    printf 'FAIL: %s\n' "$1"
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

run_logged() {
    local demo_step=$1 demo_log=$2 demo_code
    shift 2
    if "$@" > "$demo_log" 2>&1; then
        return
    else
        demo_code=$?
        printf 'FAIL OUTPUT %s (exit %s):\n' "$demo_step" "$demo_code"
        cat "$demo_log"
        exit "$demo_code"
    fi
}

[[ $(uname -s) == Linux ]] || fail 'use a disposable Ubuntu box, never macOS'

if [[ ${1:-} != --isolated ]]; then
    [[ $# == 0 ]] || fail 'usage: bash scripts/demo-screenshots.sh'
    [[ -f go.mod && -f cmd/laneboss/main.go ]] || fail 'run from the release tree root'
    demo_source=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
    [[ $(pwd -P) == "$demo_source" ]] || fail 'run from the release tree root'
    [[ ! -e /tmp/shots && ! -L /tmp/shots ]] || fail 'preserve the existing /tmp/shots; use a fresh box'
    demo_go=$(command -v go) || fail 'Go must already be installed on the box'
    command -v python3 >/dev/null || fail 'Python 3 must already be installed on the box'
    command -v apt-get >/dev/null || fail 'Ubuntu apt-get is required'
    [[ -r /etc/os-release ]] || fail 'Ubuntu release metadata is required'
    grep -q '^ID=ubuntu$' /etc/os-release || fail 'use a fresh disposable Ubuntu box'
    demo_work=$(mktemp -d /tmp/lb-dash-shots.XXXXXX)
    demo_copy=$demo_work/source
    mkdir "$demo_copy" "$demo_work/home" "$demo_work/bin" \
        "$demo_work/tmp" "$demo_work/evidence"
    # Called through the EXIT trap below, which shellcheck does not follow.
    # shellcheck disable=SC2329
    demo_exit() {
        demo_exit_code=$?
        trap - EXIT
        printf '%s\n' "$demo_exit_code" > "$demo_work/exit-code"
        printf 'Evidence retained: %s\n' "$demo_work"
        exit "$demo_exit_code"
    }
    trap demo_exit EXIT
    demo_apt=(apt-get)
    if [[ $(id -u) != 0 ]]; then
        command -v sudo >/dev/null || fail 'noninteractive sudo is required for browser dependencies'
        demo_apt=(sudo -n apt-get)
    fi
    run_logged apt-update "$demo_work/evidence/apt-update.log" "${demo_apt[@]}" update
    run_logged apt-install "$demo_work/evidence/apt-install.log" \
        "${demo_apt[@]}" install -y git tmux jq python3-venv tesseract-ocr
    for demo_tool in git tmux jq python3 tar sha256sum timeout base64 tesseract; do
        command -v "$demo_tool" >/dev/null || fail "missing prerequisite: $demo_tool"
    done

    run_logged source-archive "$demo_work/evidence/source-archive.log" \
        tar -cf "$demo_work/source.tar" -C "$demo_source" \
        go.mod go.sum cmd internal scripts plugins examples integrations docs e2e-rows \
        README.md AGENTS.md LICENSE NOTICE
    run_logged source-extract "$demo_work/evidence/source-extract.log" \
        tar -xf "$demo_work/source.tar" -C "$demo_work/source"
    if [[ -e .git ]]; then
        run_logged source-revision "$demo_work/evidence/source-revision.txt" git rev-parse HEAD
    else
        printf 'Release archive; revision belongs to the harvesting run.\n' \
            > "$demo_work/evidence/source-revision.txt"
    fi
    run_logged source-hash "$demo_work/evidence/INPUTS.sha256" sha256sum "$demo_work/source.tar"

    # A separate, empty-environment process preserves the caller's live binding.
    # Only executable search locations cross this boundary, never credentials.
    demo_result=0
    if timeout --signal=TERM --kill-after=30s 1800s \
        env -i HOME="$demo_work/home" PATH="$demo_work/bin:$PATH" \
        TMPDIR="$demo_work/tmp" LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC \
        GOENV=off GOTOOLCHAIN=go1.26.0 GOCACHE="$demo_work/go-cache" \
        GOMODCACHE="$demo_work/go-modules" LANEBOSS_TEST_CLAIMS_DIR="$demo_work/claims" \
        bash --noprofile --norc "$demo_copy/scripts/demo-screenshots.sh" \
            --isolated "$demo_work" "$demo_go" \
            > "$demo_work/transcript.log" 2>&1; then
        demo_result=0
    else
        demo_result=$?
    fi
    printf '%s\n' "$demo_result" > "$demo_work/evidence/isolated-exit-code"
    cat "$demo_work/transcript.log"
    [[ $demo_result == 0 ]] || exit "$demo_result"

    # The helper holds demo processes until all four 1440x900 captures finish,
    # then collects them. The archive contains only screened publication assets.
    # Keep the single SHOTS line intact in the harvested log.
    run_logged shots-archive "$demo_work/evidence/shots-archive.log" \
        tar -czf "$demo_work/shots.tar.gz" -C /tmp/shots .
    run_logged shots-hash "$demo_work/evidence/SHOTS.sha256" sha256sum "$demo_work/shots.tar.gz"
    run_logged shots-encode "$demo_work/evidence/shots-base64.txt" base64 -w 0 "$demo_work/shots.tar.gz"
    printf 'SHOTS:'
    cat "$demo_work/evidence/shots-base64.txt"
    printf '\nPASS: demo dashboard screenshots\n'
    exit 0
fi

[[ $# == 3 ]] || fail 'invalid isolated invocation'
demo_work=$2
demo_go=$3
[[ $demo_work == /tmp/lb-dash-shots.* && -d $demo_work/home ]] \
    || fail 'invalid isolated directory'
[[ -z ${LANEBOSS_CONFIG:-} && -z ${LANEBOSS_HOME:-} && -z ${LANEBOSS_STATE_HOME:-} ]] \
    || fail 'set'
cd "$demo_work/source"
run_logged go-version "$demo_work/evidence/go-version.txt" "$demo_go" version
run_logged go-build "$demo_work/evidence/go-build.log" \
    "$demo_go" build -trimpath -buildvcs=false -o "$demo_work/bin/laneboss" ./cmd/laneboss
run_logged build-info "$demo_work/evidence/build-info.txt" "$demo_go" version -m "$demo_work/bin/laneboss"
run_logged dashboard-tests "$demo_work/evidence/dashboard-tests.log" \
    "$demo_go" test -v ./internal/dashboard
cat "$demo_work/evidence/dashboard-tests.log"
run_logged binary-hash "$demo_work/evidence/TESTED.sha256" sha256sum "$demo_work/bin/laneboss"
run_logged python-venv "$demo_work/evidence/python-venv.log" python3 -m venv "$demo_work/venv"
run_logged playwright-install "$demo_work/evidence/playwright-install.log" \
    "$demo_work/venv/bin/python" -m pip install 'playwright==1.58.0'
if [[ $(id -u) == 0 ]]; then
    run_logged browser-deps "$demo_work/evidence/browser-deps.log" \
        "$demo_work/venv/bin/python" -m playwright install-deps chromium
else
    run_logged browser-deps "$demo_work/evidence/browser-deps.log" \
        sudo -n "$demo_work/venv/bin/python" -m playwright install-deps chromium
fi
run_logged browser-install "$demo_work/evidence/browser-install.log" \
    "$demo_work/venv/bin/python" -m playwright install chromium
run_logged event-level-row "$demo_work/evidence/event-level-row.log" \
    env LANEBOSS_BIN="$demo_work/bin/laneboss" "$demo_work/venv/bin/python" -I \
    e2e-rows/test_report_dashboard.py ReportDashboardTest.test_r9_event_level_cells
cat "$demo_work/evidence/event-level-row.log"
"$demo_work/venv/bin/python" -I scripts/demo_shots.py "$demo_work"
