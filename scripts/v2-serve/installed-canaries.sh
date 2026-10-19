#!/usr/bin/env bash
# Run the installed Linux canaries in the fixed helper's delegated control leaf.
set -euo pipefail

readonly ADMIN_DIR=/etc/laneboss-v2/admin
readonly CGROUP_ROOT=/sys/fs/cgroup
readonly RESULT_PATTERN='^(TestInstalled.*|TestNativeBwrapDescriptorInheritance|TestAgentOwnerNativeCanary)$'

mode=${1:-}
if [[ -n "$mode" && "$mode" != "--dry-run" ]] || [[ "$mode" == "--dry-run" && $# -ne 1 ]]; then
    printf '%s\n' 'usage: installed-canaries.sh [--dry-run]' >&2
    exit 2
fi

if [[ "$mode" == "--dry-run" ]]; then
    printf '%s\n' \
        'dry-run: locate exactly one root-owned JSON binding under /etc/laneboss-v2/admin' \
        'dry-run: ensure laneboss-helper@<config>.service is running' \
        'dry-run: wait for the helper-created /sys/fs/cgroup/system.slice/laneboss-helper@<config>.service/control leaf' \
        'dry-run: build internal/v2/admin with laneboss_root_canary,laneboss_gate_integration and CGO_ENABLED=0' \
        'dry-run: stop the ordinary helper, run the static binary in the same shipped unit, and let its setupCgroups create control' \
        'dry-run: run the selected tests, print result lines/counts, then restore the helper state'
    exit 0
fi

if [[ $(id -u) -ne 0 || $(uname -s) != Linux ]]; then
    printf '%s\n' 'installed canaries require Linux root' >&2
    exit 2
fi
if ! command -v systemctl >/dev/null 2>&1 || ! command -v go >/dev/null 2>&1; then
    printf '%s\n' 'installed canaries require systemctl and go on PATH' >&2
    exit 2
fi
if [[ ! -d "$ADMIN_DIR" ]]; then
    printf '%s\n' 'exactly one installed admin binding is required' >&2
    exit 2
fi

shopt -s nullglob
admin_files=("$ADMIN_DIR"/*.json)
shopt -u nullglob
if (( ${#admin_files[@]} != 1 )); then
    printf 'expected exactly one installed admin binding, found %d\n' "${#admin_files[@]}" >&2
    exit 2
fi
admin_file=${admin_files[0]}
if [[ -L "$admin_file" || ! -f "$admin_file" ]]; then
    printf '%s\n' 'installed admin binding must be a regular non-symlink file' >&2
    exit 2
fi
if [[ $(stat -c '%u:%g:%h' "$admin_file" 2>/dev/null) != 0:0:1 ]]; then
    printf '%s\n' 'installed admin binding must be a root-owned single-link file' >&2
    exit 2
fi
binding_name=${admin_file##*/}
config=${binding_name%.json}
if [[ "$binding_name" != "$config.json" || ! "$config" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]]; then
    printf '%s\n' 'installed admin binding has an invalid configuration name' >&2
    exit 2
fi
fixture_catalog="/etc/laneboss-v2/boot/${config}.json"
if [[ ! -f "$fixture_catalog" || -L "$fixture_catalog" ]]; then
    printf '%s\n' 'installed fixture account catalog is missing' >&2
    exit 2
fi

unit="laneboss-helper@${config}.service"
control_path="${CGROUP_ROOT}/system.slice/${unit}/control"
helper_was_active=0
helper_started_by_runner=0
helper_stopped_for_canary=0
work_dir=''

# shellcheck disable=SC2329 # invoked through the EXIT trap below
finish() {
    local status=$?
    trap - EXIT

    if (( helper_stopped_for_canary )); then
        if (( helper_was_active )); then
            if ! systemctl start "$unit" || ! systemctl is-active --quiet "$unit"; then
                printf 'could not restore running helper unit: %s\n' "$unit" >&2
                if (( status == 0 )); then
                    status=1
                fi
            fi
        fi
    elif (( helper_started_by_runner )); then
        if ! systemctl stop "$unit"; then
            printf 'could not restore stopped helper unit: %s\n' "$unit" >&2
            if (( status == 0 )); then
                status=1
            fi
        fi
    fi
    if [[ -n "$work_dir" ]]; then
        if ! rm -r -- "$work_dir"; then
            printf '%s\n' 'cannot remove the canary temporary directory' >&2
            if (( status == 0 )); then
                status=1
            fi
        fi
    fi
    exit "$status"
}
trap finish EXIT

control_has_process() {
    local processes
    processes=$(cat -- "$control_path/cgroup.procs" 2>/dev/null) || return 1
    [[ -n "$processes" ]]
}

unit_loaded() {
    local listed
    listed=$(systemctl list-units --all --full --no-legend "$unit" 2>/dev/null) || return 1
    [[ -n "$listed" ]]
}

if systemctl is-active --quiet "$unit"; then
    helper_was_active=1
    printf 'helper unit %s is already running\n' "$unit"
else
    printf 'starting helper unit %s for installed canaries\n' "$unit"
    helper_started_by_runner=1
    systemctl start "$unit"
fi

remaining=100
while (( remaining > 0 )); do
    if [[ -d "$control_path" && ! -L "$control_path" && -f "$control_path/cgroup.procs" ]] && control_has_process; then
        break
    fi
    if ! systemctl is-active --quiet "$unit"; then
        printf 'helper unit %s stopped before its control cgroup appeared\n' "$unit" >&2
        exit 1
    fi
    sleep 0.1
    remaining=$((remaining - 1))
done
if [[ ! -d "$control_path" || -L "$control_path" || ! -f "$control_path/cgroup.procs" || ! -w "$control_path/cgroup.procs" ]] || ! control_has_process; then
    printf 'helper unit %s did not create its delegated control cgroup\n' "$unit" >&2
    exit 1
fi
printf 'using helper control cgroup %s\n' "$control_path"

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd -P)
if [[ ! -f "$source_root/go.mod" ]]; then
    printf '%s\n' 'laneboss source root with go.mod was not found' >&2
    exit 2
fi

work_dir=$(mktemp -d /tmp/laneboss-installed-canaries.XXXXXX)
test_binary="$work_dir/admin.test"
test_output="$work_dir/test-output.log"
printf '%s\n' 'building static tagged installed canary binary (CGO_ENABLED=0)' \
    'tags: laneboss_root_canary,laneboss_gate_integration'
(
    cd "$source_root"
    CGO_ENABLED=0 go test -c \
        -tags=laneboss_root_canary,laneboss_gate_integration \
        -o "$test_binary" ./internal/v2/admin
)

printf 'stopping helper unit %s for exclusive-lock canary maintenance\n' "$unit"
systemctl stop "$unit"
helper_stopped_for_canary=1
remaining=100
while (( remaining > 0 )) && unit_loaded; do
    sleep 0.1
    remaining=$((remaining - 1))
done
if unit_loaded; then
    printf 'helper unit %s remained loaded after stopping\n' "$unit" >&2
    exit 1
fi

test_status=0
(
    # TestCanaryLauncher starts the child under the shipped unit properties;
    # its init calls setupCgroups, which creates the fixed control leaf.
    exec "$test_binary" -test.run='^TestCanaryLauncher$' -test.v -- "$config" "$RESULT_PATTERN" "$fixture_catalog" installed-canary-launch
) >"$test_output" 2>&1 || test_status=$?

awk '
    /^--- (PASS|FAIL|SKIP):/ {
        print
        if ($2 == "PASS:") pass++
        else if ($2 == "FAIL:") fail++
        else if ($2 == "SKIP:") skip++
    }
    END {
        printf "result counts: pass=%d fail=%d skip=%d\n", pass + 0, fail + 0, skip + 0
    }
' "$test_output"

# A run where no test passed (none selected, or every one skipped) is a failure, never a vacuous pass.
if ! awk '/^--- PASS:/ { found = 1 } END { exit(found ? 0 : 1) }' "$test_output"; then
    printf '%s\n' 'installed canary binary produced no passing test' >&2
    if (( test_status == 0 )); then
        test_status=1
    fi
fi
printf 'installed canary test exit: %d\n' "$test_status"
exit "$test_status"
