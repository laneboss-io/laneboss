#!/bin/sh
# Run on the authorized disposable Ubuntu host; installed E2E is separate.
set +x
set +e
set -u
exec 2>&1
umask 077
suite_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
suite_root=$(CDPATH='' cd -- "$suite_dir/../../../.." && pwd -P)
if [ -x "$HOME/go-toolchain/go/bin/go" ]; then
    PATH="$HOME/go-toolchain/go/bin:$PATH"
    export PATH
fi
export GOFLAGS=-trimpath

step() {
    step_name=$1
    shift
    printf 'BEGIN: %s\n' "$step_name"
    if "$@"; then
        step_rc=0
    else
        step_rc=$?
    fi
    printf 'END: %s exit %s\n' "$step_name" "$step_rc"
    return "$step_rc"
}

platform() {
    [ "$(uname -s)" = Linux ] || return 1
    case "$(uname -m)" in
        x86_64|aarch64) : ;;
        *) printf '%s\n' 'Unsupported architecture'; return 1 ;;
    esac
    . /etc/os-release
    [ "$ID" = ubuntu ] && [ "$VERSION_ID" = 24.04 ]
}

go_available() {
    command -v go >/dev/null 2>&1
}

suite() {
    step checkout cd "$suite_root" || return $?
    step platform platform || return $?
    step sudo sudo -n true || return $?
    step go-available go_available || return $?
    step go-version go version || return $?
    step package-index sudo -n apt-get update || return $?
    step packages sudo -n apt-get install -y --no-install-recommends \
        python3 git gcc libc6-dev || return $?
    step shell-syntax sh -n "$suite_dir/BOX-SUITE.sh" || return $?
    step vet sudo -n env PATH="$PATH" GOFLAGS=-trimpath \
        GOCACHE=/private/tmp/lb-shared-gocache \
        go vet -tags laneboss_root_canary ./e2e/v2/cases/linux || return $?
    step case-tests sudo -n env PATH="$PATH" GOFLAGS=-trimpath \
        GOCACHE=/private/tmp/lb-shared-gocache \
        go test -count=1 -v -tags laneboss_root_canary \
        ./e2e/v2/cases/linux || return $?
}

printf '%s\n' 'SCOPE: Linux producer and G0 wiring units'
if suite; then
    rc=0
else
    rc=$?
fi
printf 'SUITE EXIT: %s\n' "$rc"
if [ "$rc" -eq 0 ]; then
    printf '%s\n' 'PASS: Linux producer box suite'
else
    printf '%s\n' 'FAIL: Linux producer box suite'
fi
(exit "$rc")
