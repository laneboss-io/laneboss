#!/bin/sh
# Run only on the authorized disposable Linux test machine. Retain every input,
# installed build, fault build, command transcript and isolated case state.
set -eu
if [ "$(uname -s)" != Linux ]; then
    echo 'role E2E requires the designated disposable Linux machine' >&2
    exit 2
fi
lb_roles_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
lb_roles_evidence=$(mktemp -d /tmp/lb-roles-evidence.XXXXXX)
cd "$lb_roles_root"
tar -czf "$lb_roles_evidence/source.tar.gz" --exclude=.git --exclude=__pycache__ .
sha256sum "$lb_roles_evidence/source.tar.gz" > "$lb_roles_evidence/source.sha256"
sh scripts/install.sh --prefix "$lb_roles_evidence/installed" > "$lb_roles_evidence/install.json"
GOTOOLCHAIN=go1.26.0 GOWORK=off CGO_ENABLED=0 GOENV=off GOFLAGS= \
    go build -tags laneboss_faults -trimpath -buildvcs=false \
    -o "$lb_roles_evidence/laneboss-faults" ./cmd/laneboss
lb_roles_binary_rel="installed/bin/laneboss"
sha256sum "$lb_roles_evidence/$lb_roles_binary_rel" "$lb_roles_evidence/laneboss-faults" \
    > "$lb_roles_evidence/binaries.sha256"
mkdir "$lb_roles_evidence/cases"
if [ "${LANEBOSS_TICKET_SERVICE_ROWS:-0}" = 1 ]; then
    # Configuration path checks open these fixture-only parent directories.
    # Actors need read and search permission; only the root driver may write.
    # Individual case files keep their own ownership and permissions.
    chmod 755 "$lb_roles_evidence" "$lb_roles_evidence/cases"
fi
lb_roles_exit=0
LANEBOSS_ROLES_BINARY="$lb_roles_evidence/$lb_roles_binary_rel" \
LANEBOSS_ROLES_FAULTS_BINARY="$lb_roles_evidence/laneboss-faults" \
LANEBOSS_ROLES_EVIDENCE="$lb_roles_evidence/cases" \
    python3 -m unittest discover -s e2e-rows -p test_roles.py -v \
    > "$lb_roles_evidence/transcript.log" 2>&1 || lb_roles_exit=$?
printf '%s\n' "$lb_roles_exit" > "$lb_roles_evidence/exit-code.txt"
cat "$lb_roles_evidence/transcript.log"
printf 'Role evidence: %s\n' "$lb_roles_evidence"
if [ "$lb_roles_exit" -ne 0 ]; then
    exit "$lb_roles_exit"
fi
echo 'PASS: role templates and driver gates'
