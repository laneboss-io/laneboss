#!/bin/sh
# Fresh authorized AWS Ubuntu 24.04; Go, sudo and public package egress.
set -u
rc=0
secret_source=$(pwd -P)
secret_evidence=/opt/lb-secrets
if [ "$(id -u)" -eq 0 ]; then
    printf '%s\n' 'Run the suite as the disposable nonroot user with sudo available' >&2
    rc=69
fi
if ! command -v go >/dev/null 2>&1; then
    printf '%s\n' 'Go is required on the authorized test box' >&2
    rc=69
fi
if [ "$rc" -eq 0 ]; then
    sudo env DEBIAN_FRONTEND=noninteractive apt-get update
    rc=$?
fi
if [ "$rc" -eq 0 ]; then
    sudo env DEBIAN_FRONTEND=noninteractive apt-get --assume-yes --no-install-recommends install git jq tmux bubblewrap iproute2 nftables libcap2-bin python3 ca-certificates
    rc=$?
fi
if [ "$rc" -eq 0 ]; then
    go test -mod=readonly -count=1 ./e2e/v2/cases/secrets/... ./internal/v2/store ./internal/v2/service ./internal/v2/grants/... ./internal/v2/secrets/native ./internal/v2/admin ./internal/v2/assembly
    rc=$?
fi
if [ "$rc" -eq 0 ]; then
    go test -mod=readonly -count=1 -tags laneboss_faults ./e2e/v2/cases/secrets/... ./internal/v2/store ./internal/v2/service ./internal/v2/grants/... ./internal/v2/secrets/native ./internal/v2/admin ./internal/v2/assembly
    rc=$?
fi
if [ "$rc" -eq 0 ]; then
    sudo env -i PATH="$PATH" HOME=/root LANG=C.UTF-8 go test -mod=readonly -count=1 -tags laneboss_root_canary -run '^TestCredentialGuardCloseAcknowledgement$' ./internal/v2/admin
    rc=$?
fi
if [ "$rc" -eq 0 ]; then
    printf '%s\n' 'secrets BOX-SUITE: installed stand-in starting; failures and sanitized journal tails follow'
    sudo env -i PATH="$PATH" HOME=/root LANG=C.UTF-8 LB_SRC_REV="${LB_SRC_REV-}" python3 -I -B e2e/v2/cases/secrets/installed.py --source "$secret_source" --evidence "$secret_evidence"
    rc=$?
    printf 'secrets BOX-SUITE: installed stand-in exit %s\n' "$rc"
fi
(exit $rc)
