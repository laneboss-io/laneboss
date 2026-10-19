# Service input registration and containment admission

The d4val round starts at 294d40c. The preceding public Health change and its
mechanical formatting correction are committed by the supervisor. This round
does not stage, commit, merge, provision a machine or run project code on the
Mac. Runtime acceptance remains with the composed Linux checks.

## Owned CLI file inputs

All eight service methods register an input validator during CLI initialization.
Registration failures panic rather than leaving a partially initialized CLI.
The callback, the --file adapter and each typed service handler call the same
I/O-free wire.ValidateServiceInput function. The original BlobBegin guard and
all authorization/receipt/proof checks remain in place. A semantic input check
grants no object, frozen-snapshot or mutation authority.

| Method | Shared local validation / invalid test cell |
| --- | --- |
| health | Closed HealthRequest, valid digest and nonblank client version. The invalid cell omits the version value; compatibility against the running artifact is still a service check. |
| operation.get | Closed request and valid opaque operation ID. The invalid cell has an empty ID. |
| blob.begin | Closed class catalog, digest and 0..64-MiB declared size. The invalid cell uses an unknown class. |
| blob.chunk | Valid object ID/digest, bounded decoded chunk and offset/overflow checks, with SHA-256 computed over the supplied bytes. The invalid cell changes the digest while retaining the bytes. |
| blob.commit | Valid object ID and digest. The invalid cell has an empty ID. |
| blob.read | Valid object ID and bounded offset/read limit. The invalid cell has limit zero. |
| store.verify | A nonblank scope and, when supplied, a valid object ID. Scope selection remains a backend capability check; the existing store scope used by common CLI tests is not rejected locally. |
| store.rebuild | A valid, nonempty bounded snapshot reference with manifest/archive class. The invalid cell exceeds the object bound. The frozen rebuild executor remains unavailable and local validation supplies no freeze proof. |

TestServiceFileInputs covers both --request and --file forms for every method:
32 cases total. Each invalid body is first shown to pass the common structural
decoder, then must return exit 2 with the exact service-owned invalid_request
message. It also supplies an unreadable proof path and invalid request/key IDs,
so those later stages cannot supply the credited refusal. Each valid body
supplies proper retained request/key IDs and must reach the installed-client
boundary with empty stdout and exit 69 in this uninstalled fixture.

The valid control explicitly rejects a service-owned error and invalid_request.
Its accepted boundary refusals are prerequisite_missing with "protected binding
is missing or unsafe", unavailable, unsupported, or not_implemented owned by
lb-v2-client. It does not pin another implementation lane's stub text. The
current concrete client is expected to take the missing-binding prerequisite
path. No test creates a real binding, grants authority or opens state directly.
An existing session binding is read and respected without changing or printing
its value.

TestServiceHandlerInputs directly invokes all eight typed service methods with
the same invalid cases. Each must return the same owned semantic error before
requiring request authority or state. Malformed JSON/types remain closed in the
common structural decoder. None of these eight request types is Empty; their
required fields prevent an empty object from being accepted.

The service-file-registration red control removes only health from the init
registration list. TestServiceFileInputs must then fail at "valid service file
did not reach transport: health" because the common file path returns the
owning not_implemented gate. Missing registration, a proof/key error or a
service-owned unavailable response cannot be credited as transport.

## Admission after authentication

Public Health and incomplete first frames retain the eight-connection kernel
UID limit. Once a different first method authenticates, transport reads the
verified peer's live facts, checks the kernel UID/GID/PID and process lifetime,
and requires containment for lane/worker bindings. Under one mutex it acquires
the UID+containment slot and releases the temporary UID slot. The connection's
close defer releases whichever slot it currently owns. A failed transfer keeps
the old slot until closure; no path decrements a slot it did not acquire.

TestContainmentAdmissionIsolation uses real native sockets and kernel credentials
with a trusted fixture registration for two different containment identities.
It holds eight authenticated connections for the first containment and requires
two successful metadata calls from the sibling sharing that UID. Counters must
show 8 and 1 containment slots and no remaining public UID slot. A ninth first-
containment connection must close before dispatch, and cleanup must collect all
slots/workers/connections. Request bytes cannot choose the fixture registration.
This is a component admission check, not measured cgroup/enrollment isolation.

On the base, the eight established connections retain the plain UID slots and
the sibling fails with "same-UID sibling lane was starved". The added
containment-admission-transfer red control removes the production transfer and
requires that same reached assertion. Existing TestPublicHealthUIDAdmission
continues to check the public eight/ninth limit and slot release.

## Required runtime and static evidence

The mutation inventory is now 62 controls, each under both variants: 124
targeted red/candidate pairs and ten final package/tag suites. No red or
candidate unit result is claimed from a static check. The required focused
Linux commands are:

```sh
go test -race -count=1 -run '^(TestServiceFileInputs|TestServiceHandlerInputs|TestContainmentAdmissionIsolation|TestPublicHealthUIDAdmission)$' ./internal/v2/service
go test -race -count=1 -tags laneboss_faults -run '^(TestServiceFileInputs|TestServiceHandlerInputs|TestContainmentAdmissionIsolation|TestPublicHealthUIDAdmission)$' ./internal/v2/service
```

The Mac only runs permitted static checks. Protected evidence retains the exact
source/brief, static commands and outputs, mutation inputs and hashes. The
supervisor reruns the combined unit suites and the installed serve E2E; neither
authenticated service operation nor installed readiness is inferred here.
