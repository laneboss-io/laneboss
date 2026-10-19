package boxguest

import (
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/boxcore"
)

const metadataRoot = "http://metadata.google.internal/" +
	"computeMetadata/v1/instance/"

// GuardScript returns the text of /usr/local/bin/lb-box-guard for a spec.
func GuardScript(spec boxcore.GuestSpec) string {
	spec = defaults(spec)
	var b strings.Builder
	b.WriteString("#!/bin/bash\nset -u\n")
	assignment(&b, "TAG", spec.Tag)
	assignment(&b, "OUT_DIR", spec.OutDir)
	assignment(&b, "IDLE_MIN", strconv.Itoa(spec.IdleMin))
	array(&b, "DONE_FILES", spec.DoneFiles)
	array(&b, "BUSY_FILES", spec.BusyFiles)
	b.WriteString("RUN=${LB_GUARD_RUN_DIR:-" + quote("/run/"+spec.Tag) + "}\n")
	b.WriteString(`LOADAVG=${LB_GUARD_LOADAVG:-'/proc/loadavg'}
SHUTDOWN=${LB_GUARD_SHUTDOWN:-'shutdown'}
NOW=${LB_GUARD_NOW:-$(date +%s)}
mkdir -p -- "$RUN" || exit 1
`)
	if spec.Provider == "gcp" {
		assignment(&b, "BUCKET", spec.Bucket)
		assignment(&b, "PREFIX", spec.ObjectPrefix)
		assignment(&b, "RUN_ID", spec.RunID)
		assignment(&b, "SYNC_SECONDS", strconv.Itoa(spec.SyncSeconds))
		assignment(&b, "TOKEN_URL", metadataRoot+"service-accounts/default/token")
		assignment(&b, "PREEMPT_URL", metadataRoot+"preempted")
		b.WriteString(harvestScript)
	} else {
		b.WriteString(`sync_out() {
    return 0
}
sync_final() {
    return 0
}
sync_due() {
    return 0
}
`)
	}
	b.WriteString(`case "${1:-}" in
    sync)
        if sync_out; then exit 0; fi
        logger -t "$TAG" 'harvest sync failed'
        exit 1
        ;;
    final)
        result=0
        if ! sync_out; then
            logger -t "$TAG" 'harvest sync failed'
            result=1
        fi
        if ! sync_final; then
            logger -t "$TAG" 'final harvest failed'
            result=1
        fi
        exit "$result"
        ;;
    '') ;;
    *)
        logger -t "$TAG" 'unknown guard mode'
        exit 2
        ;;
esac
if ! sync_due; then
    logger -t "$TAG" 'harvest sync failed'
fi
for file in "${DONE_FILES[@]}"; do
    if [ -e "$file" ]; then
        logger -t "$TAG" 'done marker: shutting down'
        "$SHUTDOWN" -h now
        exit 0
    fi
done
busy=0
if awk '{exit !($1 > 0.3)}' "$LOADAVG"; then
    busy=1
else
    load_status=$?
    if [ "$load_status" -ne 1 ]; then
        logger -t "$TAG" 'load check failed'
    fi
fi
if [ "$busy" -eq 0 ] && command -v docker > /dev/null 2>&1; then
    if ! containers=$(docker ps -q); then
        logger -t "$TAG" 'container check failed'
    fi
    if [ -n "$containers" ]; then busy=1; fi
fi
if [ "$busy" -eq 0 ]; then
    for file in "${BUSY_FILES[@]}"; do
        if [ -e "$file" ]; then
            if mtime=$(stat -c %Y -- "$file"); then
                if [ "$((NOW - mtime))" -lt 600 ]; then
                    busy=1
                    break
                fi
            else
                logger -t "$TAG" 'busy file stat failed'
            fi
        fi
    done
fi
if [ "$busy" -eq 1 ]; then
    rm -f -- "$RUN/idle-since" || exit 1
    exit 0
fi
if [ ! -f "$RUN/idle-since" ]; then
    printf '%s\n' "$NOW" > "$RUN/idle-since" || exit 1
    exit 0
fi
since=$(cat "$RUN/idle-since") || exit 1
if [ "$((NOW - since))" -ge "$((IDLE_MIN * 60))" ]; then
    logger -t "$TAG" "idle $IDLE_MIN min: shutting down"
    "$SHUTDOWN" -h now
fi
`)
	return b.String()
}

const harvestScript = `TOKEN=''
get_token() {
    TOKEN=''
    if ! reply=$(curl -fsS --max-time 5 \
        -H 'Metadata-Flavor: Google' "$TOKEN_URL"); then
        return 1
    fi
    TOKEN=$(printf '%s\n' "$reply" |
        sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p') || return 1
    [ -n "$TOKEN" ]
}
upload_file() {
    encoded=$(printf '%s' "$1" | sed 's|/|%2F|g') || return 1
    curl -fsS --max-time 20 -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H 'Content-Type: application/octet-stream' \
        --data-binary "@$2" \
        "https://storage.googleapis.com/upload/storage/v1/b/` +
	`$BUCKET/o?uploadType=media&name=$encoded" > /dev/null
}
sync_out() {
    if [ -z "$BUCKET" ]; then return 0; fi
    get_token || return 1
    touch "$RUN/synced.new" || return 1
    find_args=("$OUT_DIR" -type f)
    if [ -f "$RUN/synced" ]; then
        find_args+=(-newer "$RUN/synced")
    fi
    failed=0
    while IFS= read -r -d '' file; do
        # An empty record carries a find failure into this shell.
        if [ -z "$file" ]; then
            failed=1
            continue
        fi
        relative=${file#"$OUT_DIR"}
        relative=${relative#/}
        case "$relative" in
            *[!A-Za-z0-9._/-]*)
                if ! printf '%s\n' "$relative" >> "$RUN/skipped"; then
                    failed=1
                fi
                continue
                ;;
        esac
        if ! upload_file "$PREFIX/out/$relative" "$file"; then
            failed=1
        fi
    done < <(
        if ! find "${find_args[@]}" -print0; then
            printf '\000'
        fi
    )
    if [ "$failed" -ne 0 ]; then
        return 1
    fi
    mv -f -- "$RUN/synced.new" "$RUN/synced"
}
sync_due() {
    if [ -z "$BUCKET" ]; then return 0; fi
    if [ -f "$RUN/synced" ]; then
        last_sync=$(stat -c %Y -- "$RUN/synced") || return 1
        if [ "$((NOW - last_sync))" -lt "$SYNC_SECONDS" ]; then
            return 0
        fi
    fi
    sync_out
}
sync_final() {
    if [ -z "$BUCKET" ]; then return 0; fi
    if [ -z "$TOKEN" ]; then get_token || return 1; fi
    preempted=unknown
    if answer=$(curl -fsS --max-time 3 \
        -H 'Metadata-Flavor: Google' "$PREEMPT_URL"); then
        case "$answer" in
            TRUE|FALSE) preempted=$answer ;;
        esac
    fi
    at=$(date -u +%Y-%m-%dT%H:%M:%SZ) || return 1
    printf '{"preempted":"%s","at":"%s","run_id":"%s"}\n' \
        "$preempted" "$at" "$RUN_ID" > "$RUN/shutdown.json" || return 1
    final_failed=0
    if ! upload_file "$PREFIX/shutdown.json" "$RUN/shutdown.json"; then
        final_failed=1
    fi
    if [ -f "$RUN/skipped" ]; then
        if ! upload_file "$PREFIX/sync-skipped.txt" "$RUN/skipped"; then
            final_failed=1
        fi
    fi
    [ "$final_failed" -eq 0 ]
}
`
