#!/usr/bin/env bash
# Administrator-only, executable-specific userns setup. Never changes sysctls.
set -euo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

fail() { printf '%s\n' "$1" >&2; exit 1; }
[[ $(uname -s) == Linux && $EUID == 0 ]] || fail 'FAIL: administrator setup requires disposable/authorized Linux root.'
[[ $# == 2 && $1 == --evidence && $2 == /* ]] || fail 'Usage: apparmor.sh --evidence ABSOLUTE_NEW_DIRECTORY'
admin_evidence=$2
admin_safe_evidence() {
    local admin_path=$1 admin_mode
    [[ -d $admin_path && ! -L $admin_path && $(stat -c %u "$admin_path") == 0 ]] || fail 'FAIL: untrusted profile evidence parent.'
    admin_mode=$(stat -c %a "$admin_path")
    (( (8#$admin_mode & 0022) == 0 || (8#$admin_mode & 01000) != 0 )) || fail 'FAIL: shared-writable non-sticky profile evidence parent.'
    if [[ $admin_path != / ]]; then admin_safe_evidence "$(dirname -- "$admin_path")"; fi
}
admin_safe_evidence "$(dirname -- "$admin_evidence")"
[[ ! -e $admin_evidence && ! -L $admin_evidence ]] || fail 'FAIL: preserve the existing evidence directory.'
mkdir -m 0700 -- "$admin_evidence"
admin_step=facts
admin_finish() {
    local admin_status=$1
    trap - EXIT
    printf '{"schema":"laneboss.admin-step.v2","stage":"%s","exit_code":%s}\n' \
        "$admin_step" "$admin_status" > "$admin_evidence/result.json"
    exit "$admin_status"
}
trap 'admin_finish "$?"' EXIT
admin_source=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
profile_source="$admin_source/packaging/v2/linux"/laneboss-bwrap.apparmor
admin_safe_source() {
    local admin_path=$1 admin_mode
    [[ ! -L $admin_path && $(stat -c %u "$admin_path") == 0 ]] || fail 'FAIL: administrator source ownership differs.'
    admin_mode=$(stat -c %a "$admin_path")
    (( (8#$admin_mode & 0022) == 0 )) || fail 'FAIL: administrator source or ancestor is writable.'
    if [[ $admin_path != / ]]; then admin_safe_source "$(dirname -- "$admin_path")"; fi
}
admin_safe_source "$admin_source/scripts/v2-admin/apparmor.sh"
admin_safe_source "$profile_source"
profile_target=/etc/apparmor.d/laneboss-bwrap
restrict_path=/proc/sys/kernel/"apparmor_restrict_unprivileged_userns"
[[ -f $restrict_path ]] || fail 'FAIL: actual AppArmor restriction is unavailable; no Ubuntu cell can be inferred.'
cat -- "$restrict_path" > "$admin_evidence/restriction.before"
if [[ -f /proc/sys/kernel/"unprivileged_userns_clone" ]]; then
    cat /proc/sys/kernel/"unprivileged_userns_clone" > "$admin_evidence/clone.before"
fi
restriction=$(cat -- "$admin_evidence/restriction.before")
case "$restriction" in
    0)
        admin_step=profile.not-needed
        printf '%s\n' 'not_needed: restriction=0; no profile installed or reloaded' > "$admin_evidence/profile.status"
        ;;
    1)
        admin_step=bwrap.metadata
        [[ -f /usr/bin/bwrap && ! -L /usr/bin/bwrap && -x /usr/bin/bwrap ]] || fail 'FAIL: the regular distro /usr/bin/bwrap is required.'
        [[ ! -u /usr/bin/bwrap && ! -g /usr/bin/bwrap ]] || fail 'FAIL: setuid/setgid bwrap workaround refused.'
        [[ $(stat -c %u /usr/bin/bwrap) == 0 ]] || fail 'FAIL: bwrap must be administrator owned.'
        bwrap_mode=$(stat -c %a /usr/bin/bwrap)
        (( (8#$bwrap_mode & 0022) == 0 )) || fail 'FAIL: writable bwrap refused.'
        command -v getcap > "$admin_evidence/getcap.tool"
        getcap /usr/bin/bwrap > "$admin_evidence/bwrap.capabilities"
        [[ ! -s $admin_evidence/bwrap.capabilities ]] || fail 'FAIL: file-capability bwrap workaround refused.'
        [[ -f $profile_source && ! -L $profile_source ]] || fail 'FAIL: reviewed bwrap-only source profile is missing.'
        admin_step=profile.source
        cp -- "$profile_source" "$admin_evidence/profile.input"
        sha256sum -- "$admin_evidence/profile.input" > "$admin_evidence/profile.sha256"
        profile_source=$admin_evidence/profile.input
        if [[ -e $profile_target || -L $profile_target ]]; then
            admin_step=profile.existing
            [[ -f $profile_target && ! -L $profile_target ]] || fail 'FAIL: unsafe existing bwrap profile; preserve it.'
            cmp -- "$profile_source" "$profile_target"
            [[ $(stat -c %u "$profile_target") == 0 ]] || fail 'FAIL: existing profile has unsafe ownership.'
            profile_mode=$(stat -c %a "$profile_target")
            (( (8#$profile_mode & 0022) == 0 )) || fail 'FAIL: existing profile is writable.'
            printf '%s\n' 'already_present: exact bytes retained' > "$admin_evidence/profile.before"
        else
            admin_step=profile.install
            install -o root -g root -m 0644 -- "$profile_source" "$profile_target"
            printf '%s\n' 'absent: installed only the bwrap profile' > "$admin_evidence/profile.before"
        fi
        admin_step=profile.readback
        cmp -- "$profile_source" "$profile_target"
        cp -- "$profile_target" "$admin_evidence/profile.readback"
        command -v apparmor_parser > "$admin_evidence/parser.tool"
        admin_step=profile.reload
        if apparmor_parser -r "$profile_target" > "$admin_evidence/reload.stdout" 2> "$admin_evidence/reload.stderr"; then
            admin_reload_exit=$?
        else
            admin_reload_exit=$?
        fi
        printf '%s\n' "$admin_reload_exit" > "$admin_evidence/reload.exit"
        [[ $admin_reload_exit == 0 ]] || exit "$admin_reload_exit"
        admin_step=profile.loaded
        awk '$0 == "laneboss-bwrap (unconfined)" { found=1 } END { exit !found }' \
            /sys/kernel/security/apparmor/profiles
        printf '%s\n' 'loaded: only /usr/bin/bwrap userns exception' > "$admin_evidence/profile.status"
        ;;
    *) fail 'FAIL: unknown actual namespace restriction.' ;;
esac
admin_step=switches.readback
cat -- "$restrict_path" > "$admin_evidence/restriction.after"
cmp -- "$admin_evidence/restriction.before" "$admin_evidence/restriction.after"
if [[ -e $admin_evidence/clone.before ]]; then
    cat /proc/sys/kernel/"unprivileged_userns_clone" > "$admin_evidence/clone.after"
    cmp -- "$admin_evidence/clone.before" "$admin_evidence/clone.after"
fi
admin_step=completed
printf '%s\n' 'PASS: bwrap-only administrator setup; namespace execution remains an unprivileged check.'
