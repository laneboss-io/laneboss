#!/bin/sh
# Run only on the supervisor's fresh disposable Ubuntu 24.04 installation.
set +x
set +e
set -u
umask 077
exec 2>&1

suite_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
suite_root=$(CDPATH='' cd -- "$suite_dir/../../../.." && pwd -P)
suite_evidence=${1-/opt/lb-v2-case-watchdog-$(date -u +%s)}
export GOFLAGS=-trimpath

step() {
    step_name=$1
    shift
    printf 'BEGIN: %s\n' "$step_name"
    "$@"
    step_rc=$?
    printf 'END: %s exit %s\n' "$step_name" "$step_rc"
    return "$step_rc"
}

platform() {
    [ "$(uname -s)" = Linux ] || return 69
    case "$(uname -m)" in aarch64|x86_64) ;; *) return 69 ;; esac
    [ -r /etc/os-release ] || return 69
    . /etc/os-release
    [ "$ID" = ubuntu ] && [ "$VERSION_ID" = 24.04 ] || return 69
    [ -d /run/systemd/system ] && [ -r /sys/fs/cgroup/cgroup.controllers ] || return 69
    case "$suite_evidence" in /*) ;; *) return 64 ;; esac
    [ ! -e "$suite_evidence" ] || return 73
}

run() {
    step checkout cd "$suite_root" || return $?
    step platform platform || return $?
    step go go version || return $?
    step sudo sudo -n true || return $?
    step package-index sudo -n apt-get update || return $?
    step prerequisites sudo -n apt-get install -y python3 git jq curl ca-certificates \
        gcc libc6-dev pkg-config libseccomp-dev iproute2 nftables bubblewrap || return $?
    step serve-units sudo -n env "PATH=$PATH" python3 -B -m unittest discover -s scripts/v2-serve -p '*_test.py' || return $?
    step watchdog-boot-inventory sudo -n env "PATH=$PATH" go test -count=1 \
        -tags laneboss_root_canary,laneboss_partial,laneboss_e2e_authenticator \
        -run '^TestWatchdogBootBundle$' ./scripts/v2-serve/bundle || return $?
    step watchdog-components go test -count=1 -tags laneboss_partial,laneboss_e2e_authenticator \
        ./internal/v2/api ./internal/v2/store ./internal/v2/secrets/... ./internal/v2/admin \
        ./internal/v2/service ./internal/v2/assembly ./internal/v2/identity \
        ./internal/v2/grants/... ./internal/v2/dataworker ./internal/v2/lifecycle \
        ./internal/v2/reviewjob ./internal/v2/cli ./internal/v2/watchdog \
        ./internal/v2/runner/claudock ./internal/v2/runner/codex ./e2e/v2/cases/watchdog \
        ./e2e/v2/cases/watchdog/native || return $?
    step native-review-check sudo -n env "PATH=$PATH" go test -count=1 \
        -tags laneboss_root_canary,laneboss_partial,laneboss_e2e_authenticator \
        -run '^(TestCheckLaunchNative|TestReviewLaunchNative|TestWorkerLaunchNative|TestArchiveLaunchNative)$' \
        ./internal/v2/admin || return $?
    step installed-watchdog sudo -n env "PATH=$PATH" python3 -I -B scripts/v2-serve/run.py \
        --source "$suite_root" --evidence "$suite_evidence" --item-case watchdog || return $?
}

run
rc=$?
if [ "$rc" -eq 0 ]; then
    printf '%s\n' 'PASS: watchdog installed box suite'
else
    printf 'FAIL: watchdog box suite exit %s\n' "$rc"
fi
(exit $rc)
