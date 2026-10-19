# Protected stand-in profile enrollment

Run 23 starts at e9e2f660. The brief reports green21 at 38/78 PASS, with
human.claudock.grants returning lb-v2-secrets/not_found and the message
"encrypted secret record is absent". This change has static verification only;
it does not claim another installed run or authenticated vendor access.

The cause is the missing enrollment bridge. run.py's fixture.enrollment checks
the protected installed executable, manifest, digest, size and mode. It never
installs credential-profile records. Before this change, production callers of
secrets.InstallProfile were absent. assembly already gives the same native
backend instance to grants.Profiles and secrets.Backend. InstallProfile writes
the same ("profile", ProfileID) key that grants.root reads. There is no evidence
of a divergent key, configuration, backend instance or records directory.

The existing native initial publication now performs the omitted step before
root grants. In the dedicated partial/authenticator build, assembly validates
the actual protected fixture enrollment and binds a private planner plus the
real secrets.InstallProfile method to the server. Production builds do not bind
the stand-in planner. No public RPC or additional harness store writer exists.

The planner uses the actual immutable root selectors and installed runtime pin.
It requires both declared drivers, matching configuration/runtime, unique drivers,
unpaid serve-fixture selectors and no issued member/parent IDs. It derives
separate canonical metadata selectors from configuration and ProfileID. Executable,
model/version and expiry come from the installed fixture and validated input.
The source handles are unavailable stand-in metadata; no secret bytes, account,
slot, refresh lease or login material are created or fetched.

The native publisher produces credential_evidence with Available=false, exact
profile / login / driver / configuration / generation, publication time and a maximum
five-minute observation window. It retains those bytes in the already sealed
initial transaction under the service audience and successful initial operation.
These are generated outputs; the original protected input inventory and its
digest remain unchanged. The store accepts this audience only for exact copied
objects from that native verified transaction, with matching store, scope,
class, key, bytes, ACL and provenance. BlobRef recognizes the existing private
evidence class; BlobBeginRequest still rejects public uploads of that class.

Publication read-back re-derives the observations using the persisted
PublishedAt, checks exact metadata and every byte, rechecks the native channel,
then calls the real InstallProfile on the shared encrypted backend. That method
retains all existing metadata, protected observation, successful-producer and
generation checks. An installer error prevents the success receipt even if the
initial transaction is durable. Exact retries verify the same outputs and
finish interrupted installation; an identical encrypted profile is not rewritten.
An observation that has expired still fails the ordinary secrets gate.

The harness continues to use real grants.root replies. bind_root_launch already
compares both complete profile/data inventories against the immutable approved
manifest, checks selectors and unique freshly issued IDs, and rejects an empty
or substituted profile set. No grants resolver or harness assertion is weakened.

The cross-lane file list is:

| Owner area | Files |
| --- | --- |
| Administrator publication | internal/v2/admin/initial.go, initial_commit.go, initial_profiles.go, initial_profiles_test.go |
| Installed assembly | internal/v2/assembly/assembly.go, profiles_partial.go, profiles_partial_test.go, profiles_release.go |
| Service composition | internal/v2/service/initial.go, server.go |
| Store authority | internal/v2/store/initial.go, objects.go, initial_profiles_linux_test.go |
| Private reference codec | internal/v2/client/wire/schema.go, credential_evidence_test.go |
| Regression controls | e2e / v2 / cases / integrate / contract-controls.json |
| Handoff | This file, REQUESTS.md and scripts/v2-serve/README |

The added regressions must run on the authorized Linux box. Their failure
conditions are concrete; none has runtime qualification from this Mac.

| Test | What must make it fail |
| --- | --- |
| admin.TestInitialProfileEnrollment | Dropping the binding prevents real InstallProfile calls and exact encrypted reads. Wrong metadata, missing retained observations, available room or changed replay bytes also fail. |
| admin.TestInitialProfileEnrollmentRecovery | Hiding the actual installer error credits a receipt after a durable commit; failing to complete the same publication leaves a required encrypted profile absent. |
| admin.TestInitialProfileEvidenceGuard | An observation with a human audience reaches the installer or credits a receipt. |
| store.TestInitialPrivateProfileObjects | The real store cannot retain the sealed observation, accepts a missing/foreign capability or changed scope/key/bytes/class/ACL, or leaves an object after refusal. Calling CommitInitial without the native seal must refuse. |
| client/wire.TestCredentialEvidenceClass | The retained private reference fails to round-trip, or public blob.begin accepts that private class. |
| assembly.TestInitialStandInSelectors | The tagged planner ignores actual custom profile selectors/runtime/model pins, aliases their canonical selectors, or accepts configuration / runtime / provider / paid / driver / enrollment drift. |

Seven serve-profile-* mutations are registered in the existing integrate
contract control loader. They omit the binding, swallow installer failure,
weaken evidence ACL checks, remove the store audience authority, weaken its
byte comparison, omit the private reference class, or permit public upload.
The cloud runner must require each named reached failure before its candidate
pass. These controls were checked as data only here; no mutant was compiled or
vetted. The tagged selector test additionally needs the dedicated fixture tags.

Candidate-only go vet passed on Linux amd64 and arm64 with default tags,
laneboss_faults, partial/authenticator tags, and all three tags; Darwin arm64
passed default and partial/authenticator tags. The scope includes all changed
packages, their transitive production/test importers, and the called grants and
secrets/native packages. Every Go command used the shared cache, local Go
1.26.5, readonly modules and disabled downloads. gofmt -l and git diff --check
also passed. Unit tests, project binaries, model requests and installed services
were not run on this Mac.

Green22 should retain the earlier publication, validation and human-session
passes, complete native profile enrollment and exact retry, then issue the real
root grant set with both unchanged profile selectors and fresh member IDs.
The Claudock ticket challenge/confirm/issue should become reachable. The next
source-derived launch gate is service launch admission, then the still-unbound
independent helper isolation evidence in service.Server.Probe. Report whichever
actual gate runs first, with its real owner/code; no exact PASS count is predicted.
If later work reaches credential acquisition, the stand-in's room remains
unavailable and cannot authorize a slot. Presence remains simulated,
human_approval remains not_proven, and this is not an authenticated AI-service test.
