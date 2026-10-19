#!/bin/bash
# gcp-fence-proof.sh: the behavioural proof that the launcher's rights on a SHARED GCP project are fenced by name. Run it before
# the first launch and before every change to the launcher's roles or conditions.
#
# As the LAUNCHER (by impersonation) it sends one read-only GET per machine and disk and keeps only the HTTP status:
#   - every instance and every disk of the project whose name does not start with the prefix: 403;
#   - an instance and a disk named <prefix>probe in each fenced zone: 404 (permitted, but not there);
#   - a decoy name (not-<prefix>decoy) in the first fenced zone: 403;
#   - <prefix>probe in a zone outside the fence: 403.
# One role and one condition cover every right of the launcher, so the name gate shown on a read holds for delete, stop and
# the rest. The script creates, changes and deletes nothing, and prints names and codes, never a body.
#
# usage: GCP_PROJECT=<project id> LAUNCHER_SA=<email of the launcher account> [NAME_PREFIX=lb-spot-] \
#          [ZONES="zone-a zone-b zone-c"] [OUTSIDE_ZONE=zone-elsewhere] bash gcp-fence-proof.sh
# The caller's own gcloud login must be allowed to list the project's instances and disks and to impersonate LAUNCHER_SA
# (roles/iam.serviceAccountTokenCreator on it).
#
# Exit codes: 0 clean; 1 STOP (a machine or disk that is not ours, or a decoy, answered anything but 403);
#             2 the positive check failed (a <prefix>probe in a fenced zone did not answer 404: the condition does not match);
#             3 usage or tool error (nothing was proven).
set -u

PROJECT=${GCP_PROJECT:?GCP_PROJECT is required}
SA=${LAUNCHER_SA:?LAUNCHER_SA is required}
PREFIX=${NAME_PREFIX:-lb-spot-}
ZONES=${ZONES:-"asia-east1-a asia-east1-b asia-east1-c"}
OUTSIDE=${OUTSIDE_ZONE:-asia-southeast1-b}
FIRST_ZONE=${ZONES%% *}
API="https://compute.googleapis.com/compute/v1/projects/$PROJECT"

stop=0; positive_failed=0; toolerr=0; instances=0; disks=0

say() { printf '%s\n' "$*"; }
for tool in gcloud curl; do
  command -v "$tool" > /dev/null 2>&1 || { say "TOOL ERROR: $tool is not on the PATH"; exit 3; }
done

TOKEN=$(gcloud auth print-access-token --impersonate-service-account="$SA" 2> /dev/null)
if [ -z "$TOKEN" ]; then say "TOOL ERROR: cannot get a token for the launcher account by impersonation"; exit 3; fi

# status <path under the project>: the HTTP status the launcher gets for a read-only GET (000 when curl itself failed).
status() {
  local code
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 25 -H "Authorization: Bearer $TOKEN" "$API/$1" 2> /dev/null)
  printf '%s' "${code:-000}"
}

# expect <403|404> <kind> <path> <label>: checks one answer and records a stop, a failed positive check or a tool error.
expect() {
  local want=$1 kind=$2 path=$3 label=$4 got
  got=$(status "$path")
  if [ "$got" = "$want" ]; then
    say "ok    $kind $label: $got"
  elif [ "$got" = "000" ]; then
    say "TOOL ERROR: no answer for $kind $label"; toolerr=1
  elif [ "$want" = "404" ]; then
    say "FAIL  $kind $label: $got, want 404 (permitted, not found): the condition does not match"; positive_failed=1
  else
    say "STOP: the launcher gets $got (want 403) on $kind $label"; stop=1
  fi
}

say "== every instance that is not ${PREFIX}*  (must answer 403)"
while IFS=$'\t' read -r name zone; do
  [ -n "$name" ] || continue
  case "$name" in "$PREFIX"*) continue;; esac
  instances=$((instances + 1))
  expect 403 instance "zones/$zone/instances/$name" "$name ($zone)"
done < <(gcloud compute instances list --project "$PROJECT" --format='value(name,zone.basename())' 2> /dev/null)
[ "$instances" -gt 0 ] || say "note: no instance outside ${PREFIX}* was found (nothing to test, or the list is not allowed to the caller)"

say "== every disk that is not ${PREFIX}*  (must answer 403)"
while IFS=$'\t' read -r name zone region; do
  [ -n "$name" ] || continue
  case "$name" in "$PREFIX"*) continue;; esac
  disks=$((disks + 1))
  if [ -n "$zone" ]; then
    expect 403 disk "zones/$zone/disks/$name" "$name ($zone)"
  else
    expect 403 disk "regions/$region/disks/$name" "$name ($region)"
  fi
done < <(gcloud compute disks list --project "$PROJECT" --format='value(name,zone.basename(),region.basename())' 2> /dev/null)

say "== ${PREFIX}probe in each fenced zone  (must answer 404: permitted, not found)"
for zone in $ZONES; do
  expect 404 instance "zones/$zone/instances/${PREFIX}probe" "${PREFIX}probe ($zone)"
  expect 404 disk "zones/$zone/disks/${PREFIX}probe" "${PREFIX}probe ($zone)"
done

say "== decoys  (must answer 403)"
expect 403 instance "zones/$FIRST_ZONE/instances/not-${PREFIX}decoy" "not-${PREFIX}decoy ($FIRST_ZONE)"
expect 403 instance "zones/$OUTSIDE/instances/${PREFIX}probe" "${PREFIX}probe (outside the fence: $OUTSIDE)"

say "== summary: instances checked $instances, disks checked $disks, stop=$stop, positive_failed=$positive_failed, tool_errors=$toolerr"
if [ "$toolerr" -ne 0 ]; then say "RESULT: tool error, nothing is proven"; exit 3; fi
if [ "$stop" -ne 0 ]; then say "RESULT: STOP"; exit 1; fi
if [ "$positive_failed" -ne 0 ]; then say "RESULT: the positive check failed"; exit 2; fi
say "RESULT: clean"
exit 0
