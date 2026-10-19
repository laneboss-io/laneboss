#!/bin/sh
# Run only on the authorized fresh Ubuntu test box. Retain output externally.
set -u
rc=0
policy_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../../../.." && pwd -P)
cd "$policy_root" || exit 1

phase() {
    if [ "$rc" -ne 0 ]; then
        return
    fi
    if "$@"; then
        :
    else
        rc=$?
    fi
}

phase test "$(uname -s)" = Linux
phase test "$(id -u)" -ne 0
phase grep -Eq '^ID=ubuntu$' /etc/os-release
phase grep -Eq '^VERSION_ID="24\.04"$' /etc/os-release
phase sudo -n true
if [ "$rc" -eq 0 ] && ! command -v python3 >/dev/null 2>&1; then
    phase sudo -n apt-get update
    phase sudo -n apt-get install -y python3
fi
if [ "$rc" -eq 0 ] && ! command -v go >/dev/null 2>&1; then
    phase sudo -n apt-get update
    phase sudo -n apt-get install -y golang-go
fi
if [ "$rc" -eq 0 ]; then
    policy_go=$(command -v go) || rc=$?
fi
if [ "$rc" -eq 0 ]; then
    export GOFLAGS=-trimpath
    export GOTOOLCHAIN=auto
    phase "$policy_go" version
    phase "$policy_go" mod download
    phase python3 -I -m unittest discover -s e2e/v2/cases/policy -p 'test_*.py' -v
    phase sudo -n env PATH="$PATH" python3 -I -m unittest discover -s scripts/v2-serve -p '*_test.py' -v
    phase "$policy_go" vet ./e2e/v2/cases/policy ./e2e/v2 \
        ./scripts/v2-serve/policy_agent ./scripts/v2-serve/policy_skip
    phase "$policy_go" test -count=1 -v ./e2e/v2/cases/policy ./e2e/v2 \
        ./scripts/v2-serve/policy_agent ./scripts/v2-serve/policy_skip
    phase sudo -n env PATH="$PATH" GOFLAGS=-trimpath "$policy_go" vet \
        -tags laneboss_root_canary ./e2e/v2/cases/policy
    phase sudo -n env PATH="$PATH" GOFLAGS=-trimpath "$policy_go" test \
        -count=1 -v -tags laneboss_root_canary ./e2e/v2/cases/policy
fi
(exit $rc)
