# Grants boundary case

Run this case only on the disposable Ubuntu 24.04 acceptance box, through
the shared case runner. It requires an installed service, authentic L5 caller,
an L3 child of that caller, the Linux confinement/helper and the lifecycle
worker reconciler. It uses synthetic data and makes no model request. A
missing dependency is a failing case, not a skipped or successful cell. The
installed binding must name contract_revision v2.0-draft.4, the matching binary
digest, configuration and actual L5 launch/endpoint generation. Its full bytes
are hashed for evidence without printing a settings object.

The harness supplies the frozen context and, under its test_root, a file named
`grants-fixture.json`. The fixture contains names and committed object handles:

- `parent_life_id`, `parent_grant_set_id`, `policy_generation`;
- `data_grant_id`: a delegable read-only snapshot rooted at `.` containing
  `child/input.txt`, the parent-only `private/canary`, and an internal symlink
  `alias` targeting `private/canary`. The alias is outside `child`;
- `nondelegable_grant_id`: a second data grant for a distinct source object
  with delegation false. Supply one synthetic resource capability in the
  parent's grants to exercise actual cost and concurrency bounds;
- `child`: a LifeRef for an actual quiescent L3 child with a grant for `child`;
- `candidate`, `test_plan`: committed BlobRefs. The candidate contains the
  supplied `child_probe.c`, `child_task.sh`, `pre-commit.sh` and input.txt with
  the child's original content reference. The candidate and new file contents
  must be committed uploads by this exact child/run. The WorkerPlan executes
  argv `["sh", "child_task.sh", canary_path]` inside that child's boundary;
- `canary_path`: the parent's absolute logical path to private/canary;
- `canary_observer`: the independently readable synthetic canary file;
- `revocation_request`, `resume_request`: frozen typed request bodies for
  revoking this child's grants and attempting its next resume.

Worker output collection is a contract dependency. Until it is wired, this
case fails CHILD-CODE. The case reads stdout only through authentic primary
capture.appended events correlated to the returned operation and exact
child/run, follows all pages, and verifies offsets and blob hashes. A prewritten
expected stdout file is never evidence.

The test plan must pass canary_path as the first argument to child_task.sh.
Keep the case observer outside the child boundary. It reads the canary before
and after the test and verifies its hash against the parent's committed object.
It compiles and runs the same probe against that observable file; exit 41
proves the read works. The source, binary, stdout/stderr and exit are retained.
Inside, the candidate builds in private scratch and a real Git commit in its
new disposable repository invokes pre-commit.sh. The candidate files must match
the supplied probe/scripts exactly; replacing them with printed answers fails.

The runner exercises grants.validate through the CLI with real retained
request files. It checks narrow selection, L5 to L3, path/access/delegation/
expiry and unknown-secret/resource refusals, destination overlap, and source
aliases. It compares current grants before and after every refused request.
It then executes the child candidate through grants.test-child, reads primary
capture, checks actual errno results, verifies quiescence and independently
reads the canary. Revocation must block resume and leave no survivors.

The shared harness's private observer supplies collection only after independently
checking the actual worker/fixture process and lease collection. The consumer
requests it after its operations, then retains collection.json in the evidence
directory. The dispatcher independently validates the same receipt after the
entry exits, in addition to its real systemd scope observation. The receipt includes
processes_quiescent, temporary_resources_collected and the correlated
operation_ids, plus its retained observation evidence. An absent receipt,
unknown survivor count or stale operation receipt prevents acceptance.

G0's final interface is in `../serve/ITEM-CONTRACT.md`. The producer is
`scripts/v2-serve/case_grants.py`; its enrolled Go relay retains the
original actor's sealed binding and invokes the installed CLI there.
Authenticated public mail carries private instructions. The original actor
commits readiness and response reports through its sealed blob API; the
observer checks the committing actor, life/run, nonce and exact report bytes.
The native capture spool is published during release, so live coordination
does not wait for stdout EOF. The actor also writes the same messages to stdout.
After archive verification and before clean, the observer compares the reports
with the original primary ranges and both actual EOF acknowledgements. These
reports grant no capture or tool-coverage authority. The outside binding file
is metadata only. The L3 child commits the supplied candidate and worker
plan itself before a normal exit. The observer verifies real helper
release receipts, protected journal bytes, cgroup and leased-UID facts,
native workspace/branch removal and archive read-back.

The root resource source handle requires a genuine protected enrollment
record. The grants resolver reads the existing immutable store metadata
and bytes as documented in `internal/v2/grants/ROOT-ENROLLMENT.md`.
The fixture uses `grants enroll` with exact human proofs to create those
records through the installed service. Its secret is a disposable random
canary created on the test box and passed through secret.key/stage/import;
plaintext stays inside the client-side sealing process. It verifies the
actual returned record bytes before uploading a root manifest naming the
handles. Boot publishes empty resource/secret families, without placeholders.

Enrollment proposals omit service-issued id and parent_grant_id fields. The
resource request also omits source_handle until the service assigns it; the
secret request uses the exact nonempty handle returned by the real import.
TestGrantsEnrollmentInputs passes both actual Python request builders' retained
bytes through the installed client's wire decoder and request preparation,
plus the shared semantic validator. Its synthetic import metadata checks input
serialization only. prove-wiring.py runs the named invalid-ID/field/source/
delivery RED controls before the unchanged candidate and logs exact request
bytes as base64 with their digests. BOX-SUITE.sh includes this regression;
Mac static checks do not execute it or establish installed enrollment success.

The secret upload now runs key, stage and import through the existing installed
`human session --flow` command. All three use one live socket and read session;
the upload key and stage cannot cross into a later human.read CLI process.
The import still requires its own exact operation proof, supplied as a file
while the original flow waits. The canary sealing binary builds before issuing
the 120-second key. Plans, encrypted input bytes, correlated replies, stderr
and the owned process's exit are retained under grants-upload. Refusals stop
the original flow without another mutation route.

TestSessionWire/grants adds a disposable Linux native staging regression using
the actual Python flow/canary producer, CLI decoder and registered secrets
service path. Its human authentication and read authority are component facts;
staging does not prove persistent import, hardware presence or secret decryption.
The candidate must refuse the same input on a fresh connection. prove-wiring
requires the session-reset, substituted-key and invalid-nonce controls to reach
their named failures before the same native candidate passes. The two plan
controls separately require the absence of a stage proof and the presence of
the independent import proof. The suite also retains the original secrets
adapter's native case. These tests use laneboss_root_canary and
laneboss_gate_integration on the authorized Linux root observer.

The printed /tmp/lb-v2-case-grants-upload-* directory retains the native proof's
source bytes, CLI test binary, each sealing binary, RED/candidate output and
exit records. Request bytes and hashes are included in the transcript. Copy
that directory back with the existing proof directories before collection.

The dispatcher regression TestGrantsFlowDispatch runs the actual case plan,
sealed-canary output and import-input builder through the registered owners,
dispatcher, SQLite receipts and protected encrypted backend. Its test key signs
actual challenge replies. Prior enrollment and peer authentication are declared
component inputs; session creation, confirmation, stage reply, proof consumption
and import are not prewritten fixtures. No hardware or installed acceptance is
credited by these components.

The stage owner now hands its allocated metadata to a private writer method
separately from the proposed RPC reply. That transaction projects secret_stage
with its owner, connection/session authority, request, key and operation, then
reads the projection and compares every returned stage field before sealing the
receipt. A mismatch rolls the allocation and reply back together. Ciphertext
and the private upload key remain session-owned; a durable metadata record does
not recreate an importable upload after a restart. secret.key stays read-only.
Import and rotation compare their committed secret_source and secret_head
records, including operation and causal source; absent metadata is an integrity
fault. The default correlated-reply refusal and dispatcher gate remain strict.

The dispatcher case immediately replays stage and import with the original
proof/frame and requires identical receipt bytes with no owner invocation.
TestSecretStageReplyProjection changes persisted allocation fields while
retaining the original request/reply, and also corrupts a proposed reply before
publication to require atomic rollback. TestSecretInfoReplyProjection changes
source/head records independently of the reply for both import and rotation.
Each negative requires the exact integrity code, owner and message.

Stage publication has no journal event, so its successful SQLite operation and
receipt retain the empty sequence range (0, 0). The owner accepts that range only
when it equals the committed operation's range and the exact reply matches its
allocated metadata. Store.Transact saves and returns the operation's own range;
its global journal head can include unrelated earlier events. Using that head
as the receipt/commit LastSeq produced (0, N) for an operation with no events.
The strict owner rejected the completed reply and cleared the ciphertext, while
dispatcher replay returned its saved success. Import then had no encrypted stage.
The writer now retains the actual operation range without changing the journal.
Import/rotation ranges are checked against their real journal rows, and read and
health snapshots must still return the real global head. Journal append/chain,
pending effect-state watermarks, BeginRead, Events and HealthSnapshot retain
their existing global-head reads. Connection/session/actor/endpoint checks,
expiry, allocation correlation and failed-publication cleanup remain enforced.

operator-stage-empty-range restores the old sequence check and must reproduce
`grants flow secret.import: not_found: encrypted stage is absent for this live
human session` in the complete dispatcher/SQLite flow. The candidate must import
on its original session after exact stage replay. operator-stage-range-binding
bypasses only the range checks and must fail both malformed-range component
cases. The direct real-store projection fixtures also require a successful
eventless operation. These new RED/GREEN runs remain required on Linux.

The Linux Go entry TestGrantsCaseHarness lets the Go-only box queue run this
case directory. It executes the existing prove-wiring.py RED/candidate controls
and catalog_test.py against the actual source, requires their successful exits
and pass records, and retains full transcripts in a printed temporary directory.
Use the disposable root observer for this entry because the existing proof
includes installer initial validation and native socket canaries. These are
harness/component proofs; no installed grants acceptance or AI-service request
is credited by the entry.

The case's root data grants deliver to /data/parent and /data/fixed, and its
launch builder preserves those issued destinations. Launch admission uses the
same destination grammar as grant issuance and subset validation: /work/ID or
/data/ID. The store previously applied a separate /work/-only fence, refusing
these exact authorised selections. The store now calls manifest.Destination;
it still checks the selected grant ID, relative source path, access, delivery,
expiry, publication and delegation against the unchanged current ceiling.
TestGrantsCaseLaunchCeiling reads the actual Python case proposal and exercises
real SQLite launch reservation with those fields. It also requires foreign
parent IDs, write upgrades and expiry extensions to refuse without planning
effects, and compares the complete ceiling and generation after admission.
Prior issuance/task/peer facts remain explicit component inputs; this focused
regression does not claim an installed running lane or an AI-service test.

operator-stage-correlation removes only the stage switch case and must reproduce
`grants flow secret.stage: not_implemented: projection-correlated reply for
method is not implemented`. operator-stage-projection and
operator-secret-projection bypass only the corresponding projection comparison
and must fail every named negative in the two projection matrices. The runner
retains the actual Python producer files and the sealing helper's Go dependency
closure alongside the test sources. Its extra source permissions are limited
to the service/secrets test packages and the private stage commit adapter.
The dispatcher builds its helper from pinned modules with downloads disabled.
These controls are prepared for Linux; no RED/GREEN result is implied here.

The producer controls deliberately remove context levels and root data/profile
IDs, and inject empty/invalid enrollment handles. Those decoder refusals must
be read with their `phase: red` records and the following unchanged candidate
pass. The boot producer already supplies a level on each context and an empty
ID on each root grant row. Enrollment proposals omit issued IDs, resource
proposals omit the service-assigned handle, and secret proposals select the
actual imported source. The proof prints a structured GREEN record only after
the original producer passes the same test. A later native helper build failure
remains a failed prerequisite and does not invalidate or replace those earlier
producer results. Both native/dispatcher tests build their helper offline from
the prepared module cache; an incomplete vendor tree cannot select another mode.

operator-stage-uncommitted restores the old memory-only stage return and must
fail with `grants flow secret.stage: integrity: mutation handler did not commit
its exact reply`. operator-stage-abort must fail TestStageCommitFailure when a
failed reply publication leaves its allocation. Both are included in the
normal/fault RED controls. The dispatcher guard itself remains unchanged.
The printed /tmp/lb-v2-case-grants-dispatch-* directories retain the exact
producer inputs and sealing binary; copy them with the control proof and logs.

BOX-SUITE.sh now runs the focused dispatcher case, secrets tests and the full
internal/v2/store package in both builds. Its focused enrollment matrix also
includes TestEnrollRefusesUnapproved, including union. That union fixture has
valid resource and secret proposal arms, ensuring its failure is the intended
semantic union refusal after the strict wire decoder.

Harness controls run separately on the authorized disposable Linux box:

```sh
sh e2e/v2/cases/grants/check-wiring.sh
```

The wrapper delegates to `BOX-SUITE.sh`, which runs on prepared Ubuntu
24.04 with Python 3.12, a C compiler and headers, Git, systemd and Go.
It supports arm64 and amd64 and performs no package installation.
Run it as the login user with noninteractive sudo. It adds the prepared
home-relative Go toolchain when present and passes only PATH through
sudo so the vendor retention unit can find that same toolchain.
The suite prints every step's name and exit status, with stderr included
in stdout, and stops at the first nonzero step. It reports missing commands
by name, selects cc or gcc for
the compiler probes, checks Go after selecting the prepared toolchain,
and verifies Python under sudo with the same PATH. It first retains the
root-enrollment mutation failures and focused candidate passes for both
normal and fault-tagged builds. It runs the harness proof controls, both
unittest discoveries, Go vet, and normal/fault-tagged grants package tests
as the login user and under sudo, plus the installed-harness Go tests and
the real-store operator enrollment cases. Each step must succeed before the
next begins; a failed step retains its status and ends the suite.
The printed `/tmp/lb-v2-case-grants-r10.*` directories retain the enrollment
proof inputs, source manifests, test binaries, raw output and exact exits;
copy both proof directories back with the box log before collection.
Missing compilers require the gcc and libc6-dev prep packages. The
architecture-specific `apt.sources` file was removed because this suite
does not use it.

They exercise schema retention, source and executable pinning, native
compiler observation, actual local child/temporary-file collection,
primary capture parsing and first-refusal preservation. Their unit
fixtures establish harness behavior only. They never establish installed
GRANT-BOUND or CHILD-CODE acceptance or vendor authentication.

Mutable-volume symlink-swap/hardlink/nested-mount and requested Git-history
cells remain pending the source-handle/export/Git contracts. A nonexistent
path refusal does not certify those cells. This case must be extended with
those actual operations before the complete lane's acceptance can be claimed.

Red artifacts must separately remove parent-subset enforcement, descriptor
resolution, or worker confinement. The same candidate case must reach and fail
the corresponding assertion. A setup error is not a killed mutation. The
case never treats the `red` phase as an expected success.

Example entry invocation (absolute paths are supplied by the harness):

```sh
sh e2e/v2/cases/grants/run.sh \
  --context /test/grants/context.json \
  --result /test/grants/result.json
```

CLI transport convention used by this case is `--request FILE` and
`--binding FILE`. Draft.3's common CLI provides that exact typed-file route
for grants and the service/lifecycle methods; `--binding-file` remains an alias.
Both aliases together refuse. Blob verification reads an authentic exact-end
chunk, including for empty objects; a valid prefix cannot substitute for the
complete committed reference.

The confined Python caller forwards only its two fixed sealed lane projections
through `e2e/v2/lane_handoff.py`, using `pass_fds` at their original numbers and
`close_fds=True`. Keep that helper at its repository-relative location when
preparing the actor. The helper checks configuration, seals and the pinned
socket; native service identity still authorizes every request. The subprocess
regression is not an installed `identity.self` or child-code acceptance result.

MUTATIONS.md maps each acceptance rule to its named controls and remaining OS
proof. mutations.json is the executable catalog. Select one mutation to run
its red assertion, followed by the same focused test in the unchanged source:

```sh
python3 -E e2e/v2/cases/grants/prove-red.py \
  --source /test/source --evidence /test/grants-unit-red \
  --mutation data-access
```

Require exit 0 and `PASS: grants unit red controls`. A build failure or failure
before the named assertion is not a killed mutation. These unit controls do
not substitute for the external GRANT-BOUND or CHILD-CODE canaries. Use
`--mutation all-ready` for all implemented unit mutations; use a new evidence
directory with `--tags laneboss_faults` for the tagged variant. A blocked OS
selection returns 69, and the unit result always records the pending OS list.
The G11 catalog has 247 distinct ready mutations, eleven selectable
legacy aliases and eight blocked OS plans. Each alias runs its whole grouped
validator control and every required subcase. The runner rejects duplicate
deciding test/diagnostic pairs and duplicate source patch sets.
The runner checks the source's contract revision before compiling. All retained
evidence directories are ordinary, owned by the test identity and explicitly
0700. No dependency discovery, test binary or mutation is executed on the Mac.

For G3 alone, require both encrypted-journal profile cases and all thirteen
new controls, in each build, on the authorized Linux box. Use the shared Go
cache for every Go command, including the Go commands the proof runner invokes.
On Linux the example shared location is /tmp/lb-shared-gocache; this round's
Mac static checks use /private/tmp/lb-shared-gocache. Run each red control before claiming its
same-candidate focused green result:

```sh
export GOCACHE=/tmp/lb-shared-gocache
python3 -E e2e/v2/cases/grants/prove-red.py \
  --source "$PWD" --evidence /test/lb-v2-grants-g3-red \
  --mutation g3-profile-stub --mutation g3-profile-retention \
  --mutation g3-profile-only --mutation g3-profile-missing \
  --mutation g3-profile-foreign --mutation g3-profile-identity \
  --mutation g3-profile-driver --mutation g3-profile-provider \
  --mutation g3-profile-paid --mutation g3-profile-generation \
  --mutation g3-profile-exclusion --mutation g3-profile-ceiling \
  --mutation g3-profile-policy
go test -mod=readonly -count=1 ./internal/v2/grants/... \
  ./internal/v2/dataworker/... ./internal/v2/cli/...
```

Repeat both commands with -tags laneboss_faults for Go and
--tags laneboss_faults for the proof runner, retaining a fresh evidence directory.
Require every named red assertion, the unchanged focused green, and unit exit 0.
The root tests use synthetic protected metadata and a fresh test encryption key;
they create no vendor credential or profile lease. Installed root grants still
require the actual backend wiring, protected unlock/enrollment and real human
proof. The serve lifecycle must retain both fixture selectors and bind only the
returned member IDs. Missing enrollment is a failure, never a passing stand-in.

G3 round b fixes evidence-class validation, the unwired-profile error
expectation, provider/usage metadata and authority changes during source reads.
Run its eleven new controls in both builds before crediting the regressions:

```sh
export GOCACHE=/tmp/lb-shared-gocache
python3 -E e2e/v2/cases/grants/prove-red.py \
  --source "$PWD" --evidence /test/lb-v2-grants-g3b-red \
  --mutation g3b-evidence-valid --mutation g3b-evidence-fields \
  --mutation g3b-unwired-code --mutation g3b-capability-codes \
  --mutation g3b-export-code --mutation g3b-provider-name \
  --mutation g3b-usage-fields --mutation g3b-release-view \
  --mutation g3b-release-policy --mutation g3b-release-exclusions \
  --mutation g3b-release-scope --mutation g3-profile-exclusion
```

Repeat with --tags laneboss_faults and a fresh evidence directory. Require
the exact named red failures and same-candidate green, exit 0 and the pass
line. TestProfileEvidence's valid case must issue both profiles; its malformed
cases must return integrity. Existing expired, ceiling and source-expiry cases
must still return forbidden. TestProfileMeta includes accepted optional Usage
and invalid provider/usage pins. TestProfileRelease observes actual fixture
data/channel reads and refuses changed scope, policy or exclusions before
Transact. TestRootCapabilityGates retains the separate unimplemented families.
These are Linux runtime requirements, not results measured by Mac vet.

G7 adds service-only ResolveProfile for the retained original start/adopt
selector. Its eight controls cover exact issued IDs across both drivers and
root/adopt/child starts, choosing the requested second profile, refusing unknown
or ambiguous selectors, driver mismatch, paid scope, exclusions and fresh
authority after source reads. Run on the authorized Linux box:

```sh
export GOCACHE=/tmp/lb-shared-gocache
python3 -E e2e/v2/cases/grants/prove-red.py \
  --source "$PWD" --evidence /test/lb-v2-grants-g7-red \
  --mutation g7-issued-member --mutation g7-profile-choice \
  --mutation g7-selector-fallback --mutation g7-selector-ambiguity \
  --mutation g7-profile-driver --mutation g7-profile-spend \
  --mutation g7-profile-excluded --mutation g7-profile-fresh
```

Repeat with --tags laneboss_faults and a fresh evidence directory. Require
exit 0, PASS: grants unit red controls, every listed deciding assertion and
the unchanged focused green. The existing full grants/dataworker/CLI unit
commands above remain required. Metadata/slot/worker fixtures do not prove
vendor authentication or installed start/archive/clean acceptance.

The G11 store/service CleanupObjectStore and independent readback adapter now
exist, and dataworker.CollectCleanup implements their orchestration with the
installed WorkspaceCollector. Native administrator bindings and installed
deletion proof are still required. No helper process collection, stub reply or
empty receipt counts as workspace/branch removal or lane.cleaned. The current
protocol and limits are in dataworker/CLEANUP-GAP.md.

On the authorized Linux machine, run the nine collector red controls first:

```sh
export GOCACHE=/tmp/lb-shared-gocache
python3 -E e2e/v2/cases/grants/prove-red.py \
  --source "$PWD" --evidence /test/lb-v2-grants-g11-red \
  --mutation g11-collector-stub --mutation g11-independent-readback \
  --mutation g11-protected-objects --mutation g11-workspace-fence \
  --mutation g11-object-fence --mutation g11-original-intent \
  --mutation g11-receipt-read --mutation g11-claim-executor \
  --mutation g11-dirty-gate
go test -mod=readonly -count=1 ./internal/v2/dataworker/... \
  ./internal/v2/grants/... ./internal/v2/store/... ./internal/v2/service/...
```

Repeat with --tags laneboss_faults for the proof runner, -tags laneboss_faults
for Go and fresh evidence directories. Require every named red assertion, the
unchanged focused green, unit exit 0 and PASS: grants unit red controls. Mac
candidate vet does not execute these assertions; no mutant/control overlays
are vetted on this Mac. No fixture pass is installed workspace/Git deletion.

Round 2 adds the object-result gate before administrator removal and refused
inputs for every previously uncovered collector boundary. Its eight controls
also require exact codes, owners, gate messages and operation counts:

```sh
python3 -E e2e/v2/cases/grants/prove-red.py \
  --source "$PWD" --evidence /test/lb-v2-grants-g11-r2-red \
  --mutation g11-object-readbacks --mutation g11-replay-echo \
  --mutation g11-replay-order --mutation g11-dirty-result \
  --mutation g11-retained-match --mutation g11-readback-match \
  --mutation g11-object-count --mutation g11-object-order
```

Repeat with --tags laneboss_faults and a fresh evidence directory. Run the same
unit commands above. The grouped object-readbacks control requires all four
bad-state/decision cases; a later refusal after an administrator call fails.
The replay fixtures use the same claim and preserve the original journal;
the successor-claim cases below use the merged store/API replay contract.

Round 3 retains the original removing claim A and returns a new receipt bound
to current claim B. The store port authenticates A and the exact journal;
the collector uses shared replay validators without relabeling the journal.
These six controls include both crash points and each requested refusal:

```sh
export GOCACHE=/tmp/lb-shared-gocache
python3 -E e2e/v2/cases/grants/prove-red.py \
  --source "$PWD" --evidence /test/lb-v2-grants-g11-r3-red \
  --mutation g11-reclaim-live --mutation g11-strict-current \
  --mutation g11-reclaim-proof --mutation g11-reclaim-effect \
  --mutation g11-reclaim-generation --mutation g11-reclaim-intent
```

Repeat with --tags laneboss_faults and a fresh evidence directory, then run the
unit commands above. The live control requires after-remove and after-receipt;
the proof control requires unknown-remover and no-removal-reads. Each nominated
diagnostic and unchanged focused green must be reached. The supervisor also
runs runs/v2-grants-par-suite.sh on its authorized Linux box. Static candidate
vet does not execute these controls or establish native installed cleanup.

On the authorized Linux box, also run the proof-catalog regression cases:

```sh
python3 -E -m unittest discover -s e2e/v2/cases/grants -p catalog_test.py
```

Require all four cases to pass. They reject a duplicated deciding assertion,
duplicated source patches and a colliding alias, and retain the real catalog's
grouped required cases. Mutating those parser guards must fail the corresponding
case before the unchanged parser passes. Python compile on the Mac is only a
syntax check.

The final draft.4 case retains explicit random request and idempotency keys
before every invocation. Both nondelegable requests, delegate false and true,
must refuse. The false case selects the parent grant root and its own expiry
so a different path or expiry error cannot mask broken delegation enforcement.
GRANT-BOUND and CHILD-CODE each have their own setup and evidence list; a prior
failure does not skip the next assertion or turn an unreached row into a pass.

The unit runner must use the supervisor-composed candidate after 74354cd is
merged, along with the grants Human verifier wiring described in CONTRACT-GAPS.
The grants and serve external cases remain failing/incomplete until the real
worker/publication/revocation dependencies are installed. No successful unit
run substitutes for those installed-CLI and process/filesystem observations.

Every grants method registers a shared semantic input check at CLI
initialization: root, validate, get, revoke and test-child. Registration failure
stops initialization. Both --request and the positional-file adapter use the
same checks as the service, before proof reads, request metadata or transport.
The service retains its current authority and hidden-target refusal ordering.

TestCLIFileValidators covers an invalid and valid body for every method in
both file forms. Invalid bodies must return this lane's invalid_request with
exit 2 before missing proof/key/binding inputs can mask it. Valid bodies must
get past the grants validator; the explicit accepted downstream refusals are
not_implemented, prerequisite_missing and unavailable, with exit 69 and an
Owner other than lb-v2-grants. The test does not require another lane's error
message. Its missing binding is an absolute path inside an ordinary private
test directory; it never opens a real installed service or changes a binding.

Fix 9 separates the public grant preview from internal reserved-launch
resolution. New launch controls cover exact reservation/life/grant IDs,
original-frame provenance/digest, root-ticket authority, parent creation,
current ceilings, retained bindings/history/base, source/executable selection,
storage ownership/replay and immutable output bytes. Launch input reads retain
fixed byte and object-count bounds independent of requested DiskBytes.

MaterializeLaunch's positive unit is verification of an already retained
materialization after restart. The journal fixture checks real test-owned 0700
directories and fixture snapshot bytes; allocation/identity/session records
remain synthetic. No worker or agent is launched by that replay fixture. The
fix-11 units additionally exercise actual tree/home work in test-owned 0700
roots. Their native claim/process/zero-exit records remain synthetic. A sourced
allocation cannot count as completion without real stage/result/read-back data.

Fix 10 retains all 116 previous catalog entries and adds 41 unit controls.
They cover stored start/adopt level/role/driver/ticket pins, consumed proof,
authentic starter records, prepared agent identity, retained pins and capture,
current D6 capture policy and recheck, one continuation operation, fixed worker
lease/claim/provenance, channel input/runtime/binding, review candidate classes
and the still-closed runtime boundaries. MUTATIONS.md maps each family to its
named assertions. Every positive launch fixture calls the actual fix-10
reservation/request/plan/binding validators; none bypasses a validator to keep
an older fixture green.

Channel/review tests exercise read-only preflight and explicit missing-backend
errors. Synthetic identity, claim, capture and provider-input records are not
installed runtime proof. The review input remains opaque because no independent
worker bootstrap/result schema is specified for it; the verifier cannot return
coverage from that input. A preflight not_implemented is a stopped gate, never
successful verification, preparation, credential injection or delivery.

Run the unchanged candidate and every catalog mutant on the authorized Linux
machine in both builds, using fresh evidence directories. Mac vet/anchor output
cannot show a reached assertion. The fix-11 stage ports now exist and are
consumed; actual service/admin/identity backends and the private worker client
bridge still refuse. Reachable Git needs protected export/runtime pins.

Every previous ready control ID remains. resource-total removes only the upper
ceiling; its old replacement duplicated an existing negative clause and failed
the test build's bool vet gate. Its original test/diagnostic are unchanged.
launch-data-barrier follows the real missing MaterializationControl binding.
The 25 f11-data-* controls add actual tree/home/bootstrap/result/read-back fault
cells. The proof runner rejects unrelated failing subtests and prints its
retained failure category. No control is removed or marked blocked.
