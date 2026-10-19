#!/bin/sh
# Prepared Ubuntu box, either arm64 or amd64. No package or vendor downloads.
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
    if [ "$step_rc" -ne 0 ]; then
        printf '%s\n' "FAIL: grants box suite exit $step_rc" >&2
        exit "$step_rc"
    fi
    return "$step_rc"
}

require_tool() {
    if command -v "$1" >/dev/null 2>&1; then
        printf 'available: %s\n' "$1"
    else
        printf 'missing: %s\n' "$1"
        printf 'prep package: %s\n' "$2"
        return 127
    fi
}

require_compiler() {
    if command -v cc >/dev/null 2>&1; then
        printf '%s\n' 'compiler: cc'
    elif command -v gcc >/dev/null 2>&1; then
        printf '%s\n' 'compiler: gcc'
    else
        printf '%s\n' 'missing: cc' 'missing: gcc' 'prep package: gcc and libc6-dev'
        return 127
    fi
}

require_sudo_python() {
    if sudo -n env PATH="$PATH" python3 --version; then
        return 0
    else
        sudo_python_rc=$?
        if [ "$sudo_python_rc" -eq 127 ]; then
            printf '%s\n' 'missing: python3 under sudo env PATH' 'prep package: python3'
        fi
        return "$sudo_python_rc"
    fi
}

root_enrollment_controls() {
    if root_proof_directory=$(mktemp -d /tmp/lb-v2-case-grants-r10.XXXXXX); then
        printf 'retained root enrollment controls: %s\n' "$root_proof_directory"
    else
        return "$?"
    fi
    set -- python3 -B "$suite_dir/prove-red.py" --source "$suite_root" \
        --evidence "$root_proof_directory/proof" --tags "$1"
    for root_mutation in operator-stage-empty-range operator-stage-range-binding \
        operator-stage-correlation operator-stage-projection operator-secret-projection \
        operator-stage-uncommitted operator-stage-abort operator-enroll-stub operator-enroll-proof \
        operator-enroll-handle operator-enroll-union operator-enroll-secret-source \
        operator-secret-owner operator-secret-generation operator-writer-owner operator-writer-scope \
        g3-enrolled-stub g3-enrolled-resource-retain \
        g3-enrolled-secret-retain g3-enrolled-order g3-enrolled-digest \
        g3-enrolled-owner g3-enrolled-scope \
        g3-enrolled-stale g3-enrolled-origin g3-enrolled-life \
        g3-enrolled-delegation g3-enrolled-expiry g3-enrolled-resource-scope \
        g3-enrolled-resource-cost g3-enrolled-secret-version g3-enrolled-recheck \
        g3-enrolled-network-gate g3b-capability-codes; do
        set -- "$@" --mutation "$root_mutation"
    done
    sudo -n env PATH="$PATH" "$@"
}

step checkout cd "$suite_root"
step platform test "$(uname -s)" = Linux
step python3 require_tool python3 python3
step compiler require_compiler
step git require_tool git git
step go require_tool go 'prepared Go toolchain'
step sudo require_tool sudo sudo
step env require_tool env coreutils
step sudo-python3 require_sudo_python
step go-version go version
step root-enrollment-red root_enrollment_controls ''
step root-enrollment-red-faults root_enrollment_controls laneboss_faults
step prove-wiring sudo -n env PATH="$PATH" python3 -B e2e/v2/cases/grants/prove-wiring.py
step secrets-session-wire sudo -n env PATH="$PATH" go test -count=1 -v \
    -tags laneboss_root_canary,laneboss_gate_integration ./internal/v2/cli -run '^TestSessionWire/secrets$'
step serve-units sudo -n env PATH="$PATH" python3 -B -m unittest discover \
    -s scripts/v2-serve -p '*_test.py' -v
step grants-catalog sudo -n env PATH="$PATH" python3 -B -m unittest discover \
    -s e2e/v2/cases/grants -p catalog_test.py -v
step grants-flow-dispatch go test -count=1 -v ./internal/v2/service -run '^TestGrantsFlowDispatch$'
step grants-flow-dispatch-faults go test -count=1 -tags laneboss_faults -v ./internal/v2/service -run '^TestGrantsFlowDispatch$'
step secrets-units go test -count=1 -v ./internal/v2/secrets
step secrets-units-faults go test -count=1 -tags laneboss_faults -v ./internal/v2/secrets
step store-units go test -count=1 -v ./internal/v2/store
step store-units-faults go test -count=1 -tags laneboss_faults -v ./internal/v2/store
step go-vet go vet ./internal/v2/grants ./internal/v2/grants/manifest ./internal/v2/store ./scripts/v2-serve/bundle ./scripts/v2-serve/grants_actor ./scripts/v2-serve/grants_seal
step grants-normal go test -count=1 -v ./internal/v2/grants ./internal/v2/grants/manifest
step grants-faults go test -count=1 -tags laneboss_faults -v ./internal/v2/grants ./internal/v2/grants/manifest
step grants-root sudo -n env PATH="$PATH" go test -count=1 -v ./internal/v2/grants ./internal/v2/grants/manifest
step grants-root-faults sudo -n env PATH="$PATH" go test -count=1 -tags laneboss_faults -v ./internal/v2/grants ./internal/v2/grants/manifest
step enrollment-store go test -count=1 -v ./internal/v2/store -run 'TestCapabilityEnrollment|TestSecretCapabilityEnrollmentSource|TestEnrollRefusesUnapproved'
step enrollment-store-faults go test -count=1 -tags laneboss_faults -v ./internal/v2/store -run 'TestCapabilityEnrollment|TestSecretCapabilityEnrollmentSource|TestEnrollRefusesUnapproved'
step enrollment-store-root sudo -n env PATH="$PATH" go test -count=1 -v ./internal/v2/store -run 'TestCapabilityEnrollment|TestSecretCapabilityEnrollmentSource|TestEnrollRefusesUnapproved'
step enrollment-store-root-faults sudo -n env PATH="$PATH" go test -count=1 -tags laneboss_faults -v ./internal/v2/store -run 'TestCapabilityEnrollment|TestSecretCapabilityEnrollmentSource|TestEnrollRefusesUnapproved'
step go-tests sudo -n env PATH="$PATH" go test -count=1 -v ./scripts/v2-serve/bundle ./scripts/v2-serve/grants_actor ./scripts/v2-serve/grants_seal
printf '%s\n' 'PASS: grants box suite'
