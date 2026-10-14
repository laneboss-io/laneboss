#!/bin/sh
# Execute the getting-started shell blocks against real launcher output on Linux.
# Usage: sh docs/check-bootstrap.sh [BUILT_LANEBOSS_BINARY]
# No cloud provisioning, model calls, owner messages or caller credentials.
set -eu

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

if [ "${1:-}" != --isolated ]; then
    [ "$#" -le 1 ] || fail 'usage: check-bootstrap.sh [BUILT_LANEBOSS_BINARY]'
    [ "$(uname -s)" = Linux ] || fail 'run this E2E check on a disposable Linux machine'
    for bootstrap_tool in git tmux go jq timeout tar sha256sum awk sed; do
        command -v "$bootstrap_tool" > /dev/null 2>&1 \
            || fail "missing prerequisite: $bootstrap_tool"
    done
    if [ "$#" -eq 1 ]; then
        case "$1" in
            /*) ;;
            *) fail 'supply an absolute path to the built binary' ;;
        esac
        [ -f "$1" ] && [ -x "$1" ] || fail 'the supplied binary must be an executable regular file'
    fi

    bootstrap_source=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
    bootstrap_run=$(mktemp -d /tmp/lb-docs-bootstrap-check.XXXXXX)
    bootstrap_run=$(CDPATH= cd -- "$bootstrap_run" && pwd -P)
    mkdir "$bootstrap_run/source" "$bootstrap_run/home" "$bootstrap_run/tmp"
    bootstrap_candidate=
    if [ "$#" -eq 1 ]; then
        mkdir "$bootstrap_run/candidate"
        cp "$1" "$bootstrap_run/candidate/laneboss"
        chmod 555 "$bootstrap_run/candidate/laneboss"
        bootstrap_candidate=$bootstrap_run/candidate/laneboss
    fi

    # Archive only the source inputs used by this check and the installer.
    # The workflow runs from the kept snapshot, not a changing caller checkout.
    tar -cf "$bootstrap_run/source.tar" -C "$bootstrap_source" \
        go.mod go.sum cmd internal scripts plugins examples integrations \
        docs README.md AGENTS.md
    tar -xf "$bootstrap_run/source.tar" -C "$bootstrap_run/source"
    (
        cd "$bootstrap_run"
        sha256sum source.tar > INPUTS.sha256
        if [ -n "$bootstrap_candidate" ]; then
            sha256sum candidate/laneboss >> INPUTS.sha256
        fi
    )

    # Preserve executable search locations, not the caller's environment or HOME.
    # GOENV=off in the actual installer also excludes saved Go build settings.
    # A separate process receives the explicitly requested temporary HOME.
    bootstrap_search_path=$PATH
    bootstrap_source=$bootstrap_run/source
    bootstrap_result=0
    if timeout --signal=TERM --kill-after=15s 1800s \
        env -i HOME="$bootstrap_run/home" PATH="$bootstrap_search_path" \
        TMPDIR="$bootstrap_run/tmp" LANG=C LC_ALL=C TZ=UTC \
        GOCACHE="$bootstrap_run/go-cache" GOMODCACHE="$bootstrap_run/go-modules" \
        sh "$bootstrap_source/docs/check-bootstrap.sh" --isolated \
            "$bootstrap_run" "$bootstrap_run/source" "$bootstrap_candidate" \
            > "$bootstrap_run/transcript.log" 2>&1; then
        bootstrap_result=0
    else
        bootstrap_result=$?
    fi
    printf '%s\n' "$bootstrap_result" > "$bootstrap_run/exit-code"
    cat "$bootstrap_run/transcript.log"
    printf 'Evidence retained: %s\n' "$bootstrap_run"
    if [ "$bootstrap_result" -ne 0 ]; then
        echo 'FAIL: walkthrough stopped; preserve its state and inspect the last CHECK line' >&2
    fi
    exit "$bootstrap_result"
fi

# This branch is reached only in the clean subprocess started above.
[ "$#" -eq 4 ] || fail 'invalid isolated-check invocation'
bootstrap_run=$2
bootstrap_source=$3
bootstrap_candidate=$4
bootstrap_doc_line=0
bootstrap_blocks_ran=0

bootstrap_exit() {
    bootstrap_exit_code=$?
    trap - 0
    if [ "$bootstrap_exit_code" -ne 0 ]; then
        printf 'FAIL: getting-started.md shell block at line %s (exit %s)\n' \
            "$bootstrap_doc_line" "$bootstrap_exit_code" >&2
    fi
    exit "$bootstrap_exit_code"
}
trap bootstrap_exit 0
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# A supplied candidate is a real binary, kept and hashed above. The source
# installer is still executed. All walkthrough CLI invocations use this exact
# candidate; without one, they use the command that the installer publishes.
laneboss() {
    if [ -n "$bootstrap_candidate" ]; then
        "$bootstrap_candidate" "$@"
    else
        command laneboss "$@"
    fi
}

# The guide is the command source. Extraction rejects empty, unfinished or
# differently labelled shell blocks rather than silently skipping them.
awk '
    /^```/ {
        if (fence == "") {
            fence = substr($0, 4)
            if (fence == "sh") {
                shell_block = 1
                blocks++
                lines = 0
                print "bootstrap_doc_line=" NR
                print "printf '\''CHECK: getting-started.md shell block at line " NR "\\n'\''"
            } else if (fence ~ /^(sh|bash|shell)([[:space:]]|$)/) {
                print "unsupported shell fence at line " NR > "/dev/stderr"
                bad = 1
                exit 1
            }
        } else if ($0 == "```") {
            if (shell_block) {
                if (lines == 0) {
                    print "empty shell block at line " NR > "/dev/stderr"
                    bad = 1
                    exit 1
                }
                print "bootstrap_blocks_ran=$((bootstrap_blocks_ran + 1))"
                print ""
            }
            fence = ""
            shell_block = 0
        }
        next
    }
    shell_block { print; lines++ }
    END {
        if (bad || fence != "" || blocks == 0) {
            print "invalid or missing walkthrough shell blocks" > "/dev/stderr"
            exit 1
        }
        print "bootstrap_blocks_expected=" blocks
    }
' "$bootstrap_source/docs/getting-started.md" > "$bootstrap_run/walkthrough.sh"
sh -n "$bootstrap_run/walkthrough.sh"
cd "$bootstrap_source"
# Keep this a plain source operation: using it as an if-condition would disable
# POSIX errexit inside the sourced commands and could hide a failed check.
. "$bootstrap_run/walkthrough.sh"
[ "$bootstrap_blocks_ran" -eq "$bootstrap_blocks_expected" ] \
    || fail 'not all walkthrough shell blocks finished'

command laneboss --version > "$bootstrap_run/installed-version.json"
jq -e '.program == "laneboss" and .version == "0.6.0-dev4" and
       .protocol_version == "1.3.0"' "$bootstrap_run/installed-version.json"
if [ -n "$bootstrap_candidate" ]; then
    cp "$bootstrap_candidate" "$bootstrap_run/tested-laneboss"
else
    cp "$HOME/.local/bin/laneboss" "$bootstrap_run/tested-laneboss"
fi
go version -m "$bootstrap_run/tested-laneboss" > "$bootstrap_run/build-info.txt"
(
    cd "$bootstrap_run"
    sha256sum tested-laneboss > TESTED.sha256
)

printf 'PASS: getting-started walkthrough\n'
