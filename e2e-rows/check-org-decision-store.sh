#!/bin/sh
# Run only on the authorized disposable Linux test machine. Keep source bytes,
# installed release/fault builds, row inputs, transcripts and isolated stores.
set -eu
if [ "$(uname -s)" != Linux ]; then
    echo 'org decision-store E2E requires the disposable Linux test machine' >&2
    exit 2
fi
os_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
os_evidence=$(mktemp -d /tmp/lb-int-fix1-org-store-evidence.XXXXXX)
cd "$os_root"
tar -czf "$os_evidence/source.tar.gz" --exclude=.git --exclude=__pycache__ .
sha256sum "$os_evidence/source.tar.gz" > "$os_evidence/source.sha256"
sh scripts/install.sh --prefix "$os_evidence/installed" > "$os_evidence/install.json"
GOTOOLCHAIN=go1.26.0 GOWORK=off CGO_ENABLED=0 GOENV=off GOFLAGS='' \
    go build -tags laneboss_faults -trimpath -buildvcs=false \
    -o "$os_evidence/laneboss-faults" ./cmd/laneboss
os_release="installed/bin/laneboss"
sha256sum "$os_evidence/$os_release" "$os_evidence/laneboss-faults" \
    > "$os_evidence/binaries.sha256"
mkdir "$os_evidence/cases"
os_exit=0
LANEBOSS_ORG_STORE_BINARY="$os_evidence/$os_release" \
LANEBOSS_ORG_STORE_FAULTS_BINARY="$os_evidence/laneboss-faults" \
LANEBOSS_ORG_STORE_EVIDENCE="$os_evidence/cases" \
    python3 -m unittest discover -s e2e-rows -p test_org_decision_store.py -v \
    > "$os_evidence/transcript.log" 2>&1 || os_exit=$?
printf '%s\n' "$os_exit" > "$os_evidence/exit-code.txt"
cat "$os_evidence/transcript.log"
printf 'Org decision-store evidence: %s\n' "$os_evidence"
if [ "$os_exit" -ne 0 ]; then
    exit "$os_exit"
fi
echo 'PASS: org decision-store scan rows'
