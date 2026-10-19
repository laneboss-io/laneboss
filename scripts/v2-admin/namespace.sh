#!/usr/bin/env bash
# Ubuntu namespace prerequisite setup. No service, model, account or sysctl setup.
set -euo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

ns_mode=
ns_base=/var/tmp/"lb-v2-admin-namespace-evidence"
while (( $# )); do
    case "$1" in
        --check|--install)
            [[ -z $ns_mode ]] || { printf '%s\n' 'FAIL: choose one mode.' >&2; exit 2; }
            ns_mode=${1#--}
            shift
            ;;
        --evidence)
            [[ $# -ge 2 && $2 == /* ]] || { printf '%s\n' 'FAIL: absolute evidence directory required.' >&2; exit 2; }
            ns_base=$2
            shift 2
            ;;
        *) printf '%s\n' 'Usage: namespace.sh --check|--install [--evidence ABSOLUTE_DIRECTORY]' >&2; exit 2 ;;
    esac
done
[[ -n $ns_mode ]] || { printf '%s\n' 'FAIL: --check or --install is required.' >&2; exit 2; }
[[ $(uname -s) == Linux && $UID == 0 && $EUID == 0 ]] || {
    printf '%s\n' 'FAIL: run this administrator entry as root on authorized Ubuntu 24.04.' >&2
    exit 2
}
ns_safe_path() {
    local ns_path=$1 ns_kind=$2 ns_mode_bits
    [[ ! -L $ns_path && $(stat -c %u "$ns_path") == 0 ]] || return 1
    ns_mode_bits=$(stat -c %a "$ns_path")
    if [[ $ns_kind == source ]]; then
        (( (8#$ns_mode_bits & 0022) == 0 )) || return 1
    else
        # Root-owned sticky system temp ancestors cannot replace our root leaf.
        (( (8#$ns_mode_bits & 0022) == 0 || (8#$ns_mode_bits & 01000) != 0 )) || return 1
    fi
    if [[ $ns_path != / ]]; then ns_safe_path "$(dirname -- "$ns_path")" "$ns_kind"; fi
}
ns_safe_path "$(dirname -- "$ns_base")" evidence || {
    printf '%s\n' 'FAIL: untrusted evidence ancestor.' >&2; exit 3;
}
[[ ! -L $ns_base ]] || { printf '%s\n' 'FAIL: linked evidence directory refused.' >&2; exit 3; }
if [[ ! -e $ns_base ]]; then
    mkdir -p -- "$ns_base" # The explicit umask 077 creates every new parent private.
fi
[[ -d $ns_base && $(stat -c %u "$ns_base") == 0 && $(stat -c %a "$ns_base") == 700 ]] || {
    printf '%s\n' 'FAIL: evidence directory must be ordinary, root-owned and mode 0700.' >&2
    exit 3
}
ns_run=$(mktemp -d "$ns_base/lb-v2-admin-namespace.XXXXXX")
ns_stage=facts
ns_ready=false
ns_unchanged=false
ns_restriction=null
ns_action=not_checked
ns_baseline=not_run
ns_packages=false
ns_probe_uid=0
ns_probe_gid=0
ns_probe_dir=
ns_restrict_path=/proc/sys/kernel/"apparmor_restrict_unprivileged_userns"
ns_clone_path=/proc/sys/kernel/"unprivileged_userns_clone"
ns_profile=/etc/apparmor.d/"laneboss-bwrap"
ns_source=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
ns_profile_source="$ns_source/packaging/v2/linux"/laneboss-bwrap.apparmor
ns_last_code=0

ns_finish() {
    local ns_status=$1 ns_same=true
    trap - EXIT
    if [[ -f $ns_run/restriction.before && -r $ns_restrict_path ]]; then
        cat -- "$ns_restrict_path" > "$ns_run/restriction.after"
        if ! cmp -s -- "$ns_run/restriction.before" "$ns_run/restriction.after"; then ns_same=false; fi
        if [[ -f $ns_run/clone.before ]]; then
            cat -- "$ns_clone_path" > "$ns_run/clone.after"
            if ! cmp -s -- "$ns_run/clone.before" "$ns_run/clone.after"; then ns_same=false; fi
        fi
        ns_unchanged=$ns_same
        if [[ $ns_same != true && $ns_status == 0 ]]; then ns_status=3; fi
    fi
    if [[ $ns_status != 0 || $ns_unchanged != true ]]; then ns_ready=false; fi
    if [[ $ns_status == 0 && $ns_ready != true ]]; then ns_status=3; fi
    printf '{"schema":"laneboss.namespace-setup.v2","mode":"%s","stage":"%s","exit_code":%s,"ready":%s,"restriction":%s,"profile_action":"%s","baseline":"%s","switches_unchanged":%s,"packages_installed":%s,"probe_uid":%s,"probe_gid":%s,"probe_directory":"%s"}\n' \
        "$ns_mode" "$ns_stage" "$ns_status" "$ns_ready" "$ns_restriction" "$ns_action" \
        "$ns_baseline" "$ns_unchanged" "$ns_packages" "$ns_probe_uid" "$ns_probe_gid" "$ns_probe_dir" \
        > "$ns_run/result.json"
    if [[ $ns_status == 0 && $ns_ready == true ]]; then
        printf '%s\n' 'PASS: unprivileged bwrap namespace prerequisites; evidence retained.'
    else
        printf '%s\n' 'FAIL: namespace prerequisite check stopped; retain the invocation evidence.' >&2
    fi
    exit "$ns_status"
}
trap 'ns_finish "$?"' EXIT

ns_fail() { printf '%s\n' "$2" >&2; exit "$1"; }
ns_capture() {
    local ns_label=$1
    shift
    if "$@" > "$ns_run/$ns_label.stdout" 2> "$ns_run/$ns_label.stderr"; then
        ns_last_code=$?
    else
        ns_last_code=$?
    fi
    printf '%s\n' "$ns_last_code" > "$ns_run/$ns_label.exit"
}
ns_need() {
    ns_capture "$@"
    [[ $ns_last_code == 0 ]] || ns_fail 69 'FAIL: a required OS command failed; inspect its retained stdout/stderr/exit.'
}
ns_drop() (
    cd /
    exec /usr/bin/timeout --kill-after=2s 15s /usr/bin/setpriv \
        --reuid="$ns_probe_uid" --regid="$ns_probe_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        /usr/bin/env -i PATH=/usr/bin:/bin LANG=C "$@"
)
ns_permission_failure() {
    local ns_label=$1
    [[ $ns_last_code == 1 ]] || ns_fail 69 'FAIL: namespace control did not reach an ordinary permission refusal.'
    if ! LC_ALL=C grep -Eiq 'permission denied|operation not permitted|no permissions' "$ns_run/$ns_label.stderr"; then
        ns_fail 69 'FAIL: namespace refusal lacks a permission diagnostic; preserve it without attempting recovery.'
    fi
}
ns_loaded() {
    [[ -r /sys/kernel/security/apparmor/profiles ]] &&
        awk '$0 == "laneboss-bwrap (unconfined)" { found=1 } END { exit !found }' /sys/kernel/security/apparmor/profiles
}

ns_os=$(awk -F= '$1 == "ID" { gsub(/"/, "", $2); print $2 }' /etc/os-release)
ns_os_version=$(awk -F= '$1 == "VERSION_ID" { gsub(/"/, "", $2); print $2 }' /etc/os-release)
[[ $ns_os == ubuntu && $ns_os_version == 24.04 ]] || ns_fail 69 'FAIL: this entry requires actual Ubuntu 24.04.'
uname -srm > "$ns_run/kernel.stdout"
[[ -r $ns_restrict_path ]] || ns_fail 69 'FAIL: actual AppArmor restriction is unavailable.'
cat -- "$ns_restrict_path" > "$ns_run/restriction.before"
ns_switch_value=$(cat -- "$ns_run/restriction.before")
[[ $ns_switch_value == 0 || $ns_switch_value == 1 ]] || ns_fail 69 'FAIL: unknown actual AppArmor restriction.'
ns_restriction=$ns_switch_value
if [[ -r $ns_clone_path ]]; then cat -- "$ns_clone_path" > "$ns_run/clone.before"; fi

ns_stage=source.profile
ns_safe_path "$ns_source/scripts/v2-admin/apparmor.sh" source || ns_fail 3 'FAIL: profile loader source must be root-owned without shared-writable ancestors.'
ns_safe_path "$ns_profile_source" source || ns_fail 3 'FAIL: profile source must be root-owned without shared-writable ancestors.'
printf '%s\n' 'abi <abi/4.0>,' 'include <tunables/global>' '' \
    'profile laneboss-bwrap /usr/bin/bwrap flags=(unconfined) {' '  userns,' '}' > "$ns_run/canonical.profile"
[[ -f $ns_profile_source && ! -L $ns_profile_source ]] || \
    ns_fail 3 'FAIL: regular reviewed bwrap profile source required.'
if ! cmp -s -- "$ns_run/canonical.profile" "$ns_profile_source"; then
    ns_fail 3 'FAIL: source profile differs from the bwrap-only administrator policy.'
fi
cp -- "$ns_run/canonical.profile" "$ns_run/profile.input"
if [[ -e $ns_profile || -L $ns_profile ]]; then
    [[ -f $ns_profile && ! -L $ns_profile && $(stat -c %u "$ns_profile") == 0 && $(stat -c %h "$ns_profile") == 1 ]] || \
        ns_fail 3 'FAIL: unsafe existing administrator profile; preserve it.'
    ns_profile_mode=$(stat -c %a "$ns_profile")
    (( (8#$ns_profile_mode & 0022) == 0 )) || ns_fail 3 'FAIL: writable existing profile refused.'
    cmp -- "$ns_run/canonical.profile" "$ns_profile" || ns_fail 3 'FAIL: existing profile differs; preserve it for administrator review.'
    cp -- "$ns_profile" "$ns_run/profile.before"
fi

ns_stage=prerequisites
ns_wanted=()
if [[ ! -x /usr/bin/bwrap ]]; then ns_wanted+=(bubblewrap); fi
if ! command -v getcap > "$ns_run/getcap.tool"; then ns_wanted+=(libcap2-bin); fi
if [[ ! -x /usr/bin/setpriv ]]; then ns_wanted+=(util-linux); fi
if [[ $ns_restriction == 1 ]] && ! command -v apparmor_parser > "$ns_run/parser.tool"; then ns_wanted+=(apparmor); fi
if (( ${#ns_wanted[@]} )); then
    [[ $ns_mode == install ]] || ns_fail 69 'FAIL: missing OS prerequisites; run this entry with --install.'
    ns_need apt-update env DEBIAN_FRONTEND=noninteractive apt-get update
    ns_need apt-install env DEBIAN_FRONTEND=noninteractive apt-get --assume-yes --no-install-recommends \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install "${ns_wanted[@]}"
    ns_packages=true
fi
[[ -x /usr/bin/timeout && -x /usr/bin/setpriv && -x /usr/bin/unshare ]] || ns_fail 69 'FAIL: util-linux and coreutils namespace tools are unavailable.'
ns_need packages dpkg-query -W bubblewrap util-linux coreutils
ns_stage=bwrap.metadata
[[ -f /usr/bin/bwrap && ! -L /usr/bin/bwrap && -x /usr/bin/bwrap && ! -u /usr/bin/bwrap && ! -g /usr/bin/bwrap ]] || \
    ns_fail 3 'FAIL: regular non-setuid/non-setgid distro bwrap is required.'
[[ $(stat -c %u /usr/bin/bwrap) == 0 && $(stat -c %h /usr/bin/bwrap) == 1 ]] || ns_fail 3 'FAIL: unsafe bwrap ownership or links.'
ns_binary_mode=$(stat -c %a /usr/bin/bwrap)
(( (8#$ns_binary_mode & 0022) == 0 )) || ns_fail 3 'FAIL: writable bwrap refused.'
ns_need bwrap-capabilities getcap /usr/bin/bwrap
[[ ! -s $ns_run/bwrap-capabilities.stdout ]] || ns_fail 3 'FAIL: file-capability bwrap workaround refused.'
sha256sum /usr/bin/bwrap /usr/bin/unshare > "$ns_run/tools.sha256"
cp -- /usr/bin/bwrap "$ns_run/bwrap.input"
cp -- /usr/bin/unshare "$ns_run/unshare.input"

ns_stage=unprivileged.identity
ns_need nobody getent passwd nobody
ns_probe_uid=$(awk -F: 'NF == 7 {print $3}' "$ns_run/nobody.stdout")
ns_probe_gid=$(awk -F: 'NF == 7 {print $4}' "$ns_run/nobody.stdout")
[[ $ns_probe_uid =~ ^[0-9]+$ && $ns_probe_gid =~ ^[0-9]+$ && $ns_probe_uid != 0 && $ns_probe_gid != 0 ]] || \
    ns_fail 3 'FAIL: a real nonroot probe UID/GID is required.'
ns_need probe-uid ns_drop /usr/bin/id -u
[[ $(cat "$ns_run/probe-uid.stdout") == "$ns_probe_uid" ]] || ns_fail 3 'FAIL: probe did not drop root UID.'
ns_need probe-groups ns_drop /usr/bin/id -G
[[ $(cat "$ns_run/probe-groups.stdout") == "$ns_probe_gid" ]] || ns_fail 3 'FAIL: probe retained supplementary groups.'
ns_need probe-privileges ns_drop /usr/bin/awk -v expected_uid="$ns_probe_uid" -v expected_gid="$ns_probe_gid" "
  /^Uid:/ { uids++; for (i=2; i<=5; i++) if (\$i != expected_uid) bad=1 }
  /^Gid:/ { gids++; for (i=2; i<=5; i++) if (\$i != expected_gid) bad=1 }
  /^CapEff:|^CapPrm:|^CapAmb:/ { caps++; if (\$2 !~ /^0+$/) bad=1 }
  /^NoNewPrivs:/ { nnp++; if (\$2 != 1) bad=1 }
  END { if (uids != 1 || gids != 1 || caps != 3 || nnp != 1 || bad) exit 1; print \"identity: unprivileged; capabilities: empty; no_new_privs: enabled\" }
" /proc/self/status
ns_need bwrap-version ns_drop /usr/bin/bwrap --version
ns_version=$(cat "$ns_run/bwrap-version.stdout")
[[ $ns_version =~ ^bubblewrap[[:space:]]+([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || ns_fail 69 'FAIL: unrecognized bubblewrap version.'
(( 10#${BASH_REMATCH[1]} > 0 || 10#${BASH_REMATCH[2]} >= 8 )) || ns_fail 69 'FAIL: bubblewrap 0.8 or newer is required.'
ns_probe_dir=$(mktemp -d /var/tmp/lb-v2-admin-probe.XXXXXX)
chown "0:$ns_probe_gid" "$ns_probe_dir"
chmod 0750 "$ns_probe_dir"
install -o root -g root -m 0555 /usr/bin/unshare "$ns_probe_dir/unprofiled-unshare"
cmp -- /usr/bin/unshare "$ns_probe_dir/unprofiled-unshare"
ns_probe_args=(--die-with-parent --unshare-user --unshare-pid --ro-bind / / -- /usr/bin/true)

ns_stage=namespace.baseline
ns_capture bwrap-before ns_drop /usr/bin/bwrap "${ns_probe_args[@]}"
ns_bwrap_before=$ns_last_code
ns_capture control-before ns_drop "$ns_probe_dir/unprofiled-unshare" --user --map-root-user --mount -- /usr/bin/true
if [[ $ns_restriction == 1 ]]; then
    ns_permission_failure control-before
    if [[ $ns_bwrap_before == 0 ]]; then
        ns_baseline=already_permitted
    else
        ns_last_code=$ns_bwrap_before
        ns_permission_failure bwrap-before
        ns_baseline=denied
    fi
    ns_stage=profile.readiness
    if [[ -f $ns_profile ]] && ns_loaded && [[ $ns_bwrap_before == 0 ]]; then
        ns_action=unchanged
    else
        [[ $ns_mode == install ]] || ns_fail 69 'FAIL: bwrap profile is missing/unloaded or namespace unavailable; run --install.'
        ns_stage=profile.install
        ns_need profile-install bash "$ns_source/scripts/v2-admin/apparmor.sh" --evidence "$ns_run/profile-install"
        ns_action=installed_reloaded
    fi
    cmp -- "$ns_run/canonical.profile" "$ns_profile" || ns_fail 3 'FAIL: installed bwrap profile read-back differs.'
    ns_loaded || ns_fail 69 'FAIL: bwrap-only profile is not present in the kernel profile registry.'
    cp -- "$ns_profile" "$ns_run/profile.after"
else
    [[ $ns_bwrap_before == 0 && $ns_last_code == 0 ]] || ns_fail 69 'FAIL: restriction-zero unprivileged namespace control failed.'
    ns_baseline=unrestricted
    ns_action=not_needed
fi

ns_stage=namespace.after
ns_need bwrap-after ns_drop /usr/bin/bwrap "${ns_probe_args[@]}"
ns_capture control-after ns_drop "$ns_probe_dir/unprofiled-unshare" --user --map-root-user --mount -- /usr/bin/true
if [[ $ns_restriction == 1 ]]; then
    ns_permission_failure control-after
else
    [[ $ns_last_code == 0 ]] || ns_fail 69 'FAIL: restriction-zero namespace control stopped working.'
    if [[ -f $ns_run/profile.before ]]; then
        cmp -- "$ns_run/profile.before" "$ns_profile" || ns_fail 3 'FAIL: restriction-zero profile was changed.'
    else
        [[ ! -e $ns_profile && ! -L $ns_profile ]] || ns_fail 3 'FAIL: restriction-zero setup installed an unnecessary profile.'
    fi
fi
cmp -- "$ns_run/bwrap.input" /usr/bin/bwrap || ns_fail 3 'FAIL: bwrap executable changed during setup.'
cmp -- "$ns_run/unshare.input" /usr/bin/unshare || ns_fail 3 'FAIL: namespace control executable changed during setup.'
ns_stage=switches.readback
cat -- "$ns_restrict_path" > "$ns_run/restriction.after"
cmp -- "$ns_run/restriction.before" "$ns_run/restriction.after" || ns_fail 3 'FAIL: host restriction changed.'
if [[ -f $ns_run/clone.before ]]; then
    cat -- "$ns_clone_path" > "$ns_run/clone.after"
    cmp -- "$ns_run/clone.before" "$ns_run/clone.after" || ns_fail 3 'FAIL: host clone policy changed.'
fi
ns_stage=completed
ns_ready=true
