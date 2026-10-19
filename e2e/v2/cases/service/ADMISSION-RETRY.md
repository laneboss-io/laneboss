# Connection admission after a refused frame

Suspected: on base a282b26, an otherwise valid first request with the wrong
configuration is refused before authentication, but the loop has already consumed
its first-frame admission callback. A valid second frame can therefore reach
dispatch while retaining its temporary UID slot. A lane/worker request for a
human-only method has the same pre-authentication return. This is a source
finding; no runtime canary or security impact is claimed from this Mac session.

Malformed shapes are distinct: wire.DecodeRequest already validates the decoded
request, and serveConnection closes on its error. Those frames do not enter the
ordinary dispatch loop a second time.

The candidate keeps a connection-local admitted flag. Every native dispatch
receives the real authenticatedAdmission callback until the transfer succeeds.
Only successful transfer changes that flag and the slot key used at teardown.
Public health remains a one-frame connection. Authentication/admission failures
still return their owned entry refusal and close; later successful connections
retain ordinary per-request authentication and authorization checks.

TestAdmissionAfterInvalidFirstFrame, in the service package's
admission_retry_linux_test.go, uses real Unix sockets, kernel writer credentials
and trusted fixture peer registrations. The request cannot select containment.
The registration isolates admission; it does not prove installed enrollment or
real cgroup membership. Both wrong_config and endpoint_class cases require:

1. The first request passes common wire validation, then receives the actual
   pre-authentication forbidden response. No handler runs and the real slot map
   still contains exactly its one temporary UID slot.
2. A valid second request succeeds with the registered authority on the same
   connection. The handler reads the actual admission map at entry: zero public
   UID slots and exactly one containment slot. The deciding failure is
   "valid second frame did not move UID slot to containment".
3. A third valid request uses the same single containment slot, and teardown
   collects the native worker, connection and slot. An early refusal, parse
   error, wrong authority, timeout or cleanup failure cannot satisfy the test.

Each new mutation changes only the candidate admission condition by adding the
first-frame requirement. This restores the original ordering defect while
leaving the unchanged regression in place. The existing mutation driver builds
and executes the red first, requires exit 1 and the exact selected assertion,
then requires the unchanged candidate to pass. No compile failure, race, skip,
panic or timeout earns red credit.

The existing TestContainmentAdmissionIsolation still checks eight established
slots, sibling isolation and an over-limit ninth caller. Its close assertion now
first consumes and validates the service's actual correlated, service-owned
unavailable refusal at admission, then requires closure and zero extra dispatch.
The containment-admission-transfer mutation targets the current transfer call
and retains its original sibling-starvation diagnostic.

Run only as an unprivileged UID on the authorized disposable Linux box, with
new evidence directories outside the composed source:

```sh
set -eu
bash e2e/v2/cases/service/run-mutations.sh \
  --source /test/source --evidence /tmp/lb-v2-serve2-admission-config \
  --mutation admission-invalid-first-config --variant both
bash e2e/v2/cases/service/run-mutations.sh \
  --source /test/source --evidence /tmp/lb-v2-serve2-admission-class \
  --mutation admission-invalid-first-class --variant both
bash e2e/v2/cases/service/run-mutations.sh \
  --source /test/source --evidence /tmp/lb-v2-serve2-admission-transfer \
  --mutation containment-admission-transfer --variant both
go test -race -count=1 \
  -run '^(TestAdmissionAfterInvalidFirstFrame|TestContainmentAdmissionIsolation|TestPublicHealthUIDAdmission|TestOpenedConnectionRejectsHealth|TestPublicHealthClosesBeforeSecond)$' \
  ./internal/v2/service
go test -race -count=1 -tags laneboss_faults \
  -run '^(TestAdmissionAfterInvalidFirstFrame|TestContainmentAdmissionIsolation|TestPublicHealthUIDAdmission|TestOpenedConnectionRejectsHealth|TestPublicHealthClosesBeforeSecond)$' \
  ./internal/v2/service
```

Retain both normal/faults red and candidate test binaries, source inputs, actual
output, exit, exact reached FAIL/PASS paths and process quiescence using the
mutation driver's records. Stop at any failed setup or candidate check. These
commands have not run on the authoring Mac; static vet is not red-before-green
evidence. The finding remains suspected until the Linux canary and controls run.
