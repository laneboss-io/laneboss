#!/bin/sh
# Run only on the authorized disposable Linux test machine. Retain every input,
# installed build, fault build, command transcript and isolated case state.
set -eu
if [ "$(uname -s)" != Linux ]; then
    echo 'decision guide E2E requires the designated disposable Linux machine' >&2
    exit 2
fi
gd_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
gd_evidence=$(mktemp -d /tmp/lb-guide-evidence.XXXXXX)
cd "$gd_root"
tar -czf "$gd_evidence/source.tar.gz" --exclude=.git --exclude=__pycache__ .
sha256sum "$gd_evidence/source.tar.gz" > "$gd_evidence/source.sha256"
sh scripts/install.sh --prefix "$gd_evidence/installed" > "$gd_evidence/install.json"
GOTOOLCHAIN=go1.26.0 GOWORK=off CGO_ENABLED=0 GOENV=off GOFLAGS='' \
    go build -tags laneboss_faults -trimpath -buildvcs=false \
    -o "$gd_evidence/laneboss-faults" ./cmd/laneboss
gd_release="installed/bin/laneboss"
sha256sum "$gd_evidence/$gd_release" "$gd_evidence/laneboss-faults" \
    > "$gd_evidence/binaries.sha256"
mkdir "$gd_evidence/cases"
gd_exit=0
LANEBOSS_GUIDE_BINARY="$gd_evidence/$gd_release" \
LANEBOSS_GUIDE_FAULTS_BINARY="$gd_evidence/laneboss-faults" \
LANEBOSS_GUIDE_EVIDENCE="$gd_evidence/cases" \
    python3 -m unittest discover -s e2e-rows -p test_decision_guide.py -v \
    > "$gd_evidence/transcript.log" 2>&1 || gd_exit=$?
printf '%s\n' "$gd_exit" > "$gd_evidence/exit-code.txt"
cat "$gd_evidence/transcript.log"
printf 'Decision guide evidence: %s\n' "$gd_evidence"
if [ "$gd_exit" -ne 0 ]; then
    exit "$gd_exit"
fi
echo 'PASS: decision guide rows'
