#!/bin/sh
# Supplied binaries only. Run on the designated disposable Linux machine;
# never launch a machine or obtain credentials from this checker.
set -eu
if [ "$(uname -s)" != Linux ]; then
    echo 'layered settings rows require the disposable Linux test machine' >&2
    exit 2
fi
if [ "$#" -ne 3 ]; then
    echo 'usage: sh e2e-rows/check-layered-settings.sh /absolute/laneboss /absolute/laneboss-faults /absolute/laneboss-pre-1.0' >&2
    exit 2
fi
case "$1" in /*) ;; *) echo 'release binary path must be absolute' >&2; exit 2 ;; esac
case "$2" in /*) ;; *) echo 'fault binary path must be absolute' >&2; exit 2 ;; esac
case "$3" in /*) ;; *) echo 'historic binary path must be absolute' >&2; exit 2 ;; esac
test -f "$1"
test -x "$1"
test -f "$2"
test -x "$2"
test -f "$3"
test -x "$3"
lb_settings_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
lb_settings_evidence=$(mktemp -d /tmp/lb-layered-config-evidence.XXXXXX)
cp "$1" "$lb_settings_evidence/laneboss"
cp "$2" "$lb_settings_evidence/laneboss-faults"
cp "$3" "$lb_settings_evidence/laneboss-pre-1.0"
cd "$lb_settings_root"
tar --exclude=.git --exclude=__pycache__ -czf "$lb_settings_evidence/source.tar.gz" .
sha256sum "$lb_settings_evidence/source.tar.gz" "$lb_settings_evidence/laneboss" \
    "$lb_settings_evidence/laneboss-faults" "$lb_settings_evidence/laneboss-pre-1.0" > "$lb_settings_evidence/inputs.sha256"
mkdir "$lb_settings_evidence/cases"
lb_settings_exit=0
LANEBOSS_SETTINGS_BINARY="$lb_settings_evidence/laneboss" \
LANEBOSS_SETTINGS_FAULTS_BINARY="$lb_settings_evidence/laneboss-faults" \
LANEBOSS_SETTINGS_EVIDENCE="$lb_settings_evidence/cases" \
LANEBOSS_SETTINGS_LEGACY_BINARY="$lb_settings_evidence/laneboss-pre-1.0" \
    python3 -m unittest discover -s e2e-rows -p test_layered_settings.py -v \
    > "$lb_settings_evidence/transcript.log" 2>&1 || lb_settings_exit=$?
printf '%s\n' "$lb_settings_exit" > "$lb_settings_evidence/exit-code.txt"
cat "$lb_settings_evidence/transcript.log"
printf 'Layered settings evidence: %s\n' "$lb_settings_evidence"
if [ "$lb_settings_exit" -ne 0 ]; then
    exit "$lb_settings_exit"
fi
echo 'PASS: layered settings'
