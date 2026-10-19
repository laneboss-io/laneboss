#!/bin/sh
# Run only on the authorized disposable Linux machine; this script launches no box.
set -eu
if [ "$(uname -s)" != Linux ]; then
    echo 'job hook E2E requires the designated disposable Linux machine' >&2
    exit 2
fi
jh_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
jh_evidence=$(mktemp -d /tmp/lb-integrate-070-jobs.XXXXXX)
cd "$jh_root"
tar -czf "$jh_evidence/source.tar.gz" --exclude=.git --exclude=__pycache__ .
sha256sum "$jh_evidence/source.tar.gz" > "$jh_evidence/source.sha256"
if [ "$#" -eq 2 ]; then
    case "$1:$2" in /*:/*) ;; *) echo 'both supplied builds must be absolute paths' >&2; exit 2 ;; esac
    cp "$1" "$jh_evidence/laneboss"
    cp "$2" "$jh_evidence/laneboss-faults"
elif [ "$#" -eq 0 ]; then
    sh scripts/install.sh --prefix "$jh_evidence/installed" > "$jh_evidence/install.json"
    cp "$jh_evidence/installed/bin/laneboss" "$jh_evidence/laneboss"
    GOTOOLCHAIN=go1.26.0 GOWORK=off CGO_ENABLED=0 GOENV=off GOFLAGS='' \
        go build -tags laneboss_faults -trimpath -buildvcs=false \
        -o "$jh_evidence/laneboss-faults" ./cmd/laneboss
else
    echo 'usage: check-job-hook.sh [ABSOLUTE_RELEASE ABSOLUTE_FAULT_BUILD]' >&2
    exit 2
fi
sha256sum "$jh_evidence/laneboss" "$jh_evidence/laneboss-faults" > "$jh_evidence/binaries.sha256"
mkdir "$jh_evidence/cases"
jh_exit=0
LANEBOSS_GUIDE_BINARY="$jh_evidence/laneboss" \
LANEBOSS_GUIDE_FAULTS_BINARY="$jh_evidence/laneboss-faults" \
LANEBOSS_GUIDE_EVIDENCE="$jh_evidence/cases" \
    python3 -m unittest discover -s e2e-rows -p test_job_hook.py -v \
    > "$jh_evidence/transcript.log" 2>&1 || jh_exit=$?
printf '%s\n' "$jh_exit" > "$jh_evidence/exit-code.txt"
cat "$jh_evidence/transcript.log"
printf 'Job hook evidence: %s\n' "$jh_evidence"
if [ "$jh_exit" -ne 0 ]; then
    exit "$jh_exit"
fi
echo 'PASS: job hook rows'
