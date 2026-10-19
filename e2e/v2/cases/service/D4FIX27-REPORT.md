# Draft.4 fix 27 report

This round starts at f5736f7. The three
reported installed blockers and the replay frame omission have source
corrections. The complete requested source comparison is in
[D4FIX27-AUDIT.md](D4FIX27-AUDIT.md). Final whole-tree vet compiles the candidate
and applicable tests cleanly in all six platform/tag combinations. New Linux
runtime, mutation and installed acceptance results remain unestablished.

The brief reports full unit success and approval of the preceding delta on the
base. It attributes installed enrollment/publication success to the pinned
serve2 revision 6cd128f. Those are supervisor
observations. This round did not independently run or collect those jobs.

## P0-1: initial publication uses the shared native verifier

internal/v2/admin/initial_linux.go takes serve2's actual local socket comparison
and wire.VerifyAdministrator call. InitialContext no longer opens the root
helper's mapped executable through the unprivileged peer.verifyEnrollmentHelper
path. Installation loading, real service UID/GID verification, installed binding,
frame/method/params validation, installation re-check and protected socket
checks remain.

The shared verifier still requires the actual root connector, pinned frame,
fixed helper unit, protected installed artifact and process lifetime. No native
peer check was mocked, disabled or replaced by a unit fixture to claim this fix.
The reference's optional timing instrumentation was not needed for the
correction and was not imported.

The deciding installed Linux check remains the real service UID processing an
initial_publish frame from the actual root helper. Record the actual old refusal
and candidate receipt under the same protected installation. A component test
that avoids the root peer cannot credit the previous EACCES path. This round
claims source adoption and compilation only for that native path.

## P0-2: configuration events and published snapshots read back

internal/v2/store/read.go takes serve2's complete configurationEvents change.
Only an internal scope with empty LifeID and Run zero can select configuration
journal events. Public selectors still need a valid life/run. The SQL and final
selection checks use the same distinction, while visibility, bounded pages,
exclusive since/cursors and the store's live authority checks remain.

internal/v2/store/contract_stubs.go takes the concrete OrgSnapshot reader. It
requires this configuration and a nonzero requested generation, reads through
the authenticated/pinned projection path, checks retained configuration/OrgID,
and requires the exact published generation. Wrong retained identity is integrity;
a different current generation is conflict.

The broader comparison exposed the next dependent installed gate:
wire.ValidateEvent still expected ConfigView for every org.bootstrapped payload,
while the protected publication emits its closed marker. The candidate takes
serve2's strict marker branch in internal/v2/client/wire/schema.go. It binds
schema, configuration, manifest class/bounds, event/operation IDs, service origin
and actor. Ordinary bootstrap keeps its ConfigView decoder.

The required shared InitialPublicationMarker declaration is taken from
internal/v2/api/sources.go. internal/v2/admin/initial.go uses it in the two
places that previously declared the same anonymous shape. Field names/order
and serialized marker meaning are unchanged. This small contract dependency
does not import the reference's identity/read-session API feature tree.

TestConfigurationEvents commits an actual SQLite configuration publication,
reads the exact event with an empty internal selector, checks exclusive since,
and refuses the same selection under a component human read session.
TestOrgSnapshotRead checks the actual published projection and wrong org,
zero/stale generation and corrupted retained identity/configuration. Each
corruption case owns a fresh store. TestInitialMarkerEvent checks the exact
marker and changed configuration, event, operation, class, schema and unknown
fields. These tests are authored and compiled, not run here.

## P0-3: expose only the root control cgroup's read facts

internal/v2/admin/resources_linux.go takes serve2's complete change. After
creating control, it verifies the protected path and explicitly sets that one
directory to exactly 0755. This corrects creation under the helper's 0077 umask.
Root retains directory write permission; group/other gain read and traverse.
The helper unit's umask, lane directory policy and control files are unchanged.
No recursive chmod or broader writable permission is introduced.

The deciding installed Linux check remains the actual unprivileged service
traversing control and reading its kernel process inventory, with the root
helper in its real cgroup-v2 unit. The old 0700 result must refuse that same
reader; the candidate must expose the required facts and keep writes denied.
An ordinary temporary-directory mode test or mocked peer cannot credit this
native permission path. No such substitute pass is claimed here.

## P2: replay binds the exact complete frame

internal/v2/store/enrollment_ceremony.go now calls checkEnrollmentFrame on replay
before reading a receipt or validation. The exported ReplayEnrollment entry
still performs the real native verification first. Its private continuation
replayEnrollment binds the frame and then runs the unchanged retained request
comparison. The strict parser from fix 26 remains.

TestEnrollmentReplayFrame exercises that post-native continuation against real
SQLite receipt/validation projections. A matching frame must read the actual
receipt. Changed params, method, configuration, generation and the old frame
must refuse while leaving the receipt unchanged. The private-stage fixture does
not claim root-helper verification and does not mock that verifier. Removing
the new guard must make unchanged retained rows replay for an unrelated frame.

## Broader adoption, per file

All 294 paths in the union of the requested five subtrees were classified:
9 taken, 249 already equal and 36 not taken. All three packaging files are
already equal. The audit lists every path, decision and reason; its external
JSON also retains base/reference/candidate Git blob identities and modes.

| Adopted file | What was taken |
| --- | --- |
| internal/v2/admin/initial_linux.go | Native verifier and actual endpoint socket check; timing wrappers omitted. |
| internal/v2/admin/resources_linux.go | Whole pinned file, including protected control-directory chmod 0755. |
| internal/v2/store/read.go | Whole pinned file, including internal configuration event selection. |
| internal/v2/store/contract_stubs.go | Whole pinned file, including exact protected OrgSnapshot read-back. |
| internal/v2/client/wire/schema.go | Whole pinned file, including the closed publication marker event form. |
| internal/v2/admin/initial.go | Shared marker type at emission/matching; timing instrumentation omitted. |
| internal/v2/service/capture.go | Whole pinned file; capture reauthentication uses authenticateConnection. |
| internal/v2/service/dispatch_mutation.go | Whole pinned file; pre-reply reauthentication uses authenticateConnection. |
| internal/v2/service/stream.go | Whole pinned file; stream-frame reauthentication uses authenticateConnection. |
| internal/v2/api/sources.go | Whole pinned file; required shared marker DTO only differs from the base. |

The three reauthentication changes consistently use the existing bounded
connection adapter, including its optional current-scope capability and
deferred close behavior. They add no public method or new identity feature.

The reference would also remove reviewed view bindings, typed interruption
handling, exact receipt-byte controls, visibility-before-load and cache bounds.
Those changes were not taken. Its codec helpers match the local enroll_json.go
definitions exactly; moving them into json.go would only duplicate declarations.
Optional timing diagnostics and overlapping component tests were not needed
for an installed correctness fix.

The new human_policy.go and challenge_generation_linux_test.go belong to the
separate credential/read-session feature. In particular, human_policy.go requires
api.HumanPolicySource and the identity/session integration absent from this base.
They are explicitly recorded as not taken, with the credential feature left to
its owner. No harness, E2E driver, credential feature or other-lane feature tree
was copied.

The local replay guard is an additional requested change, not a serve2
adoption. New test files are internal / v2 / store / config_read_linux_test.go,
internal / v2 / store / replay_frame_linux_test.go and
internal / v2 / client / wire / initial_marker_test.go.

## Regression controls and remaining Linux proof

All 285 prior mutation rows, edits, tests/leaves and assertions remain unchanged.
Eleven additions reach 296 unique controls and 312 sequential edit anchors.
Every anchor matches exactly once. All four new test declarations have names
under 40 characters, have a deciding control and contain each required assertion.
The audit parses literals as data in orchestration JavaScript and never imports
or executes project code.

| Control | Test / leaf | Deciding assertion |
| --- | --- | --- |
| config-events-internal | TestConfigurationEvents | internal configuration event read was refused or changed |
| config-events-public | TestConfigurationEvents | public event reader acquired configuration selection |
| config-events-query | TestConfigurationEvents | internal configuration event read was refused or changed |
| org-snapshot-generation | TestOrgSnapshotRead/generation | org snapshot accepted a foreign selection |
| org-snapshot-config | TestOrgSnapshotRead/config | org snapshot accepted a foreign selection |
| org-snapshot-stub | TestOrgSnapshotRead | published org snapshot did not read back |
| enrollment-replay-params | TestEnrollmentReplayFrame/params | replay accepted an unrelated administrator frame |
| enrollment-replay-method | TestEnrollmentReplayFrame/method | replay accepted an unrelated administrator frame |
| initial-event-schema | TestInitialMarkerEvent | exact initial marker event was refused |
| initial-event-config | TestInitialMarkerEvent/config | initial marker event lost its closed binding |
| initial-event-operation | TestInitialMarkerEvent/operation | initial marker event lost its closed binding |

These controls have not run here. Each must build and reach its exact failing
assertion/FAIL path with exit 1, then the unchanged candidate must pass that same
path on Linux. An unrelated setup failure, compiler error, panic, skip, race,
test-process timeout or survivor earns no credit. The full inventory is now
592 targeted red/candidate pairs and twelve final component package/tag suites.
It still requires complete_inventory=true, exit 0 and
PASS: service component mutation controls.

Installed native enrollment and initial publication/read-back must run on the
composed candidate with the actual root helper and unprivileged service.
Retain the red permission observations, opposite controls and candidate receipt;
no mocked peer or widened permission can substitute for them.

## Static verification and evidence

gofmt -w ran before checks. The final complete matrix ran after isolating the
snapshot corruption fixtures. Every following command exited 0 with empty output:

| GOOS | GOARCH | Tags | Scope |
| --- | --- | --- | --- |
| linux | amd64 | none | go vet ./... |
| linux | arm64 | none | go vet ./... |
| linux | amd64 | laneboss_faults | go vet -tags laneboss_faults ./... |
| linux | arm64 | laneboss_faults | go vet -tags laneboss_faults ./... |
| darwin | arm64 | none | go vet ./... |
| darwin | amd64 | none | go vet ./... |

Every vet command used GOCACHE=/private/tmp/lb-shared-gocache, GOWORK=off,
GOPROXY=off and GOSUMDB=off. The shared cache worked; no fallback or permission
override was needed. Whole-tree vet covers every changed package, its importers
and applicable test files. Compilation/static analysis do not establish runtime
outcomes or a tested product binary.

Formatting, Python byte-compilation, shell syntax, whitespace and data-only
catalog/test/source-comparison checks pass. Exact commands, outputs and exits
are retained in the external d4fix27-f5736f7 lane evidence with governing inputs,
starting/candidate source archives, pinned adopted files, source decisions,
all eleven new mutant snapshots, diff/status and SHA-256 manifest. There is no
tested product binary from this static-only round.

No runtime tests, product builds, cloud jobs/machines, real model requests,
additional agents/sessions, staging or commits were started. The checkout
remains based on f5736f7 with all changes unstaged and uncommitted.
