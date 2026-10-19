#!/usr/bin/env bash
# Complete protected boot provisioning; execute only on authorized Linux.
set -euo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

[[ $(uname -s) == Linux && $UID == 0 && $EUID == 0 ]] || {
    printf '%s\n' 'FAIL: administrator installation requires authorized Linux root.' >&2
    exit 2
}
admin_source=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
admin_entry=$admin_source/scripts/v2-admin/boot.py
admin_safe_source() {
    local admin_path=$1 admin_mode
    [[ ! -L $admin_path && $(stat -c %u "$admin_path") == 0 ]] || {
        printf '%s\n' 'FAIL: root requires a protected administrator source bundle.' >&2; exit 3;
    }
    admin_mode=$(stat -c %a "$admin_path")
    (( (8#$admin_mode & 0022) == 0 )) || {
        printf '%s\n' 'FAIL: administrator source or ancestor is shared writable.' >&2; exit 3;
    }
    if [[ $admin_path != / ]]; then admin_safe_source "$(dirname -- "$admin_path")"; fi
}
admin_safe_source "$admin_entry"
exec /usr/bin/python3 -I -B "$admin_entry" "$@"
