#!/usr/bin/env bash
# Laneboss launches this suite on its fresh authorized Ubuntu 24.04 box.
set -uo pipefail
umask 077

main() (
    set -e
    case_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
    source_dir=$(CDPATH= cd -- "$case_dir/../../../.." && pwd -P)
    cd "$source_dir"
    test "$(uname -s)" = Linux
    command -v go >/dev/null
    command -v sudo >/dev/null
    sudo -n true
    sudo -n apt-get update
    sudo -n apt-get install -y python3 jq git tmux iproute2 nftables \
        bubblewrap uidmap util-linux acl ca-certificates openssl
    sh "$case_dir/check.sh"
    go test -count=1 ./e2e/v2/cases/dashboard
    go test -count=1 ./internal/v2/service ./internal/v2/assembly ./internal/v2/cli \
        ./internal/v2/assembly/credn ./cmd/laneboss ./internal/v2/dashboard \
        ./internal/v2/store ./internal/v2/admin ./internal/v2/grants ./internal/v2/policy \
        ./internal/v2/templates ./internal/v2/messaging ./internal/v2/judge ./internal/v2/secrets \
        ./internal/v2/guidance ./internal/v2/dataworker ./internal/v2/lifecycle ./internal/v2/identity \
        ./e2e/v2/cases/identity ./e2e/v2/cases/approval ./e2e/v2/cases/lifecycle \
        ./e2e/v2/cases/dashboard/actor
    sudo -n env PATH="$PATH" go test -count=1 -tags laneboss_root_canary \
        -run '^TestDashboardSharedControls$|^TestDashboardNativeChildLaunchControl$' ./e2e/v2/cases/dashboard
    sudo -n env PATH="$PATH" go test -count=1 ./scripts/v2-serve/bundle
    evidence=$(mktemp -d /tmp/lb-v2-case-dashboard-box.XXXXXX)
    printf 'dashboard evidence: %s\n' "$evidence"
    sudo -n env PATH="$PATH" python3 -I -B scripts/v2-serve/run.py \
        --source "$source_dir" --evidence "$evidence/installed" \
        --item-case dashboard
)

main
rc=$?
(exit $rc)
