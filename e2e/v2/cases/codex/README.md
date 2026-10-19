# Codex live acceptance

This case consumes the draft.4 adapter contract. It runs only on the authorized Ubuntu
24.04 box, using the installed service, public file-backed CLI requests, real
Codex bytes and delegated login grants. It never signs in or imports credentials.
Missing service, lifecycle, isolation or credential support is a failing result,
including a typed `not_implemented` response. Fixtures are not live evidence.

The shared harness invokes `sh run.sh --context CONTEXT --result RESULT` using
the frozen v2 case/context/result formats. Before invocation it installs the
binding for the context's configuration and puts `setup.json` in `test_root`.
The context's `binding_file` must be the protected, matched draft.4 human-class
binding for the configuration/artifact. The case passes it explicitly on every
CLI invocation and never changes a session's configuration. Root L6 acceptance
and reads across independently started roots require human authority; a lane
binding does not gain those rights from setup labels.
The setup file contains no secrets and is retained as input evidence. It supplies:

* `proof_directory`: an absolute ordinary directory beneath test_root, outside
  all lane grants. An independent harness proof supplier must be active before
  the case starts. For each CLI call needing a proof, the case atomically retains
  `NNNN-authorization-request.json` with schema `laneboss.codex-proof-input.v1`,
  configuration/binding, command, exact request file/hash, retained idempotency
  key, new request ID, `proof_method`, `proof_params` and `proof_output`.
  The supplier reads and validates those exact inputs, obtains a real scoped
  challenge/confirmation through the installed service and atomically writes
  the resulting **ProofRef JSON only** to proof_output. It retains its own
  challenge/assertion receipts independently; no authenticator key or assertion
  secret enters this case. This is a file-backed fixture input rendezvous, not
  an additional public RPC, generic harness control or authority granted by a
  filename. Missing input fails after a bounded 120 seconds; there is no skip.
  For every read and blob begin/chunk/commit staging call, the requested proof
  is for `human.session` with params `{}` (api.HumanSessionMethod).
  Common CLI processing opens that session and performs the read on the same
  socket. The proof is not attached to the content read or staging mutation.
  Other proof-bearing mutations used by this case,
  including `lane check`, need a proof for their exact method/params. Every
  connection gets a fresh proof; replaying a session ID/proof does not transfer
  read authority. Credential-free authenticator-fixture evidence remains
  separate from hardware-presence and real vendor evidence.

* `start_a` and `start_b`: full `api.StartRequest` objects for independent
  workspaces, each with a Codex file-login grant. The grants are aliases of the
  same canonical login, so overlapping start requests must serialize its refresh
  lease. Both tasks are replaced by uploaded case prompts. Use a sufficient,
  explicitly approved finite budget and the full supported model name. Each
  root start/adopt request must carry its own current `root_ticket_id`, issued
  to the same principal/configuration/endpoint generation and requested
  level/role/grants. The harness retains the complete draft.4 Ticket and
  ticket.issued provenance (including principal_id, config and
  endpoint_generation). A root launch uses that ticket; the case does not add
  an unrelated envelope proof. An identical start is retried with the same
  ticket and retained mutation key on a new invocation; its exact durable reply
  must remain unchanged and no second launch may occur.
* `plant_a` and `plant_b`: `{source, logical}`. Source is a harness-planted UTF-8
  file beneath test_root, containing an independent unpredictable word. Logical
  is its path in that start request's writable data copy. Only its own lane gets
  each file. The first prompt asks the real CLI to read and delete its copy;
  the second prompt contains neither answer. The case requires an agent message
  containing that same answer on explicit resume and on a later turn.
  Both initial runs and credential releases finish before either continuation
  begins. The case then adds a separate workspace write/read turn for each lane:
  an unpredictable file name and bytes, an actual separate file-read command,
  a successful tool exit and exact output bytes read through event/blob CLI
  calls are required. Model text or a printf lookalike is insufficient. The two
  memory-only continuation turns still forbid command execution. Each lane uses
  its own approved budget; provide enough delegated writable workspace and room
  for the additional turn. No host file read or new server-path RPC is used.
* `outside_canary`: an absolute path beneath test_root, absent from lane grants.
  The harness plants a random canary there. Its parent must be ungranted too.
  It is a normal other-readable file with other-traversable ancestors, including
  test_root; keep credentials/state outside this public canary scope. Mode bits
  alone are insufficient: `outside_control` names a retained JSON file beneath
  test_root with schema `laneboss.codex-outer-control.v1`, actual `exit_code: 0`,
  `survivors: 0`, `same_lane_uid: true`, `outer_boundary: "disabled"`, and
  `stdout` as base64 of the real same-UID unconfined read. The harness retains
  the actual helper/control bytes, UID and command/exit evidence and independently
  validates this receipt. A fixture returning a constant is not such a control.
  The prompt asks for a real read attempt; the case requires a captured command
  with a nonzero exit, and rejects a leaked canary in any primary output. A model
  saying access was denied is insufficient.
* `negative`: four entries keyed `session`, `helper`, `auth`, `coverage`, each
  `{command, request, code, stage, owner, message, failure_path}`. Command is `lane adopt`, `lane start`, or
  `lane review`, with a frozen request object. The harness prepares respectively
  a forged vendor session in a real adoption manifest, an installed artifact
  whose named self-helper is absent, a sibling-only profile grant, and a raw
  inventory that falsely claims complete tool coverage. The expected codes are
  respectively `integrity`, `prerequisite_missing`, `forbidden`, `integrity`.
  Each fixture fixes its failure_path before candidate/red runs. A `preflight`
  fixture requires the exact synchronous error and no newly created lane for
  that name. An `effect` fixture requires a successful initial CLI Operation,
  its durable failed result, and one correlated service-origin `launch.failed`
  with the named stage, exact error and `agent_executed: false`. Only session
  and helper launch fixtures can select effect; auth and review are preflight.
  The case never falls back between these paths. The public Error transaction
  can carry no state/events/effects, so it cannot also create a failed launch.
  Owner and message are the exact screened target diagnostic. These cells must
  not be substituted with malformed-request/setup failures. Each request must
  have a fresh ticket if its public operation consumes one. Do not reuse a
  successful start's consumed ticket. An effect fixture must reach its committed
  launch intent; a preflight fixture must reach the named validator's exact
  diagnostic without one. Generic auth, malformed-request and setup failures
  cannot substitute for the targeted refusal.
  Every Session in an adoption manifest includes the required history_id bound
  to its actual imported private history. Omitting the new field is a setup
  failure, not the intended forged-session control.
  Request values may use `$life_a`, `$run_a`, `$generation_a` (and the `_b`
  equivalents) to bind a control to the observed live result, without guessing
  IDs or editing the fixture manifest after the run.
* `supervisors`: three complete StartRequest objects with levels 4, 5 and 6.
  Their file-backed tasks exercise actual lower-level spawn, explicit turn and
  event wait through Laneboss, then return their child's planted answer. Each
  request includes `expected_answer` and `expected_child_level` as case metadata,
  stripped before submission. Answers come from independent harness plant files;
  they must be nonempty alphanumeric strings, not product constants. Only Codex
  supervisors with a strictly lower child level pass. The case checks actual starter edges and
  successful child end events as well as the supervisor's final answer.

The harness must retain the exact vendor executable/helper bytes and their
hashes, help/version and official resume/auth/sandbox documentation, the outer
boundary's measured permit, and credential-worker refresh/collection receipts.
The case checks public events/captures, not a private runner settings object.
Only the frozen harness paths and grant IDs enter the standard context file;
proof references and additional fixture inputs remain separate files.

Every invocation retains its exact request, request ID, mutation/read key,
argv, proof input when required, stdout/stderr and actual exit. Prompts/messages
are committed through blob begin/chunk/commit before the exact `--request FILE`
form references them; there is no inline upload paired with an old proof. This
form is the contract's alternative to `--content-ref FILE`, so no shared CLI
flag implementation is duplicated here. Lane pages use the supported maximum
of 200 and preserve the life filter across cursors. Event waits retain the
initial EventPage, every correlated increasing StreamFrame and a real end
frame. A disconnect, foreign life/run/request, stale until event, incomplete
page or repeated cursor fails. Collection waits name the actual current run.
helper.released payloads are measured ReleaseReceipts, with exact causal/run
binding and known zero process/connection/job/export counts; credential release
events retain their distinct CredentialEvent shape. Both concurrent lanes must
have distinct nonempty history IDs as well as homes and vendor sessions.
Credential serialization compares complete service-recorded timestamp intervals
at nanosecond precision, without deriving cross-life time order from seq. The
contract also defines seq as configuration-wide commit order; the time check is
an independent required observation.

Each distinct assertion needs a separate red artifact run, with the mutation ID
recorded in context: drop or replace the captured thread ID; share a home; allow
overlapping canonical-login leases; remove the outer boundary; trust a forged
adoption; omit helper verification; borrow sibling auth; mark partial output
complete; omit supervisor child turn/wait. The red run must reach and fail the
target assertion. A crash or prerequisite failure before it is not a killed
mutation. The same case runs unchanged against the candidate. No cell is skipped.
The fixed mutation IDs are drop-session, shared-home, overlap-refresh,
outer-boundary, forged-session, omit-helper, borrow-auth, complete-coverage and
supervisor-turn-wait; tool-approval and inner-sandbox target the workspace probe
inside CODEX-TWO-TURN. Unknown IDs fail setup. A failure in another assertion
never counts as a reached target for the selected mutation. The coverage
pass-through control counts a real ReviewReceipt even though it has no life ID.

The result's collection flags are earned by public `lane check` observations
and lane archive/clean receipts for every created lane, including descendants.
The independent harness reviewer/collector watches `collection-request.json`
in evidence_root, makes the real abandonment or reviewed merge decisions through
the service, and retains those receipts. The case first attempts every owned
stop and verifies all known processes quiescent, retaining and reporting every
failure before requesting review. It waits through intermediate `lane.state`
transitions within a deadline and
refuses to clean any life lacking that decision. It never manufactures a review
receipt. The frozen MarkRequest requires a ReviewReceipt even for abandonment;
the integration owner must clarify that encoding or supply the independent
reviewer before this collection cell can pass. Missing collection support fails.
Clean waits for its durable Operation and actual lane.cleaned event before the
cleaned flag is accepted. Neither a pending clean nor an accepted intermediate
state is treated as completed collection.
On failure, the case stops further acceptance steps, attempts public stop and
collection, retains failed responses, and exits nonzero. Failure to collect is
also a failure. The harness remains responsible for verified credential-worker
revocation and destruction of the disposable box.

Run package unit tests separately with `go test -race ./internal/v2/runner/codex`.
On Linux, `python3 e2e/v2/cases/codex/check_red.py --source . --evidence
/test/evidence/lb-v2-codex-red` makes retained minimal package/API snapshots and runs
170 deliberately broken unit artifacts, each with and without
`laneboss_faults`. The selected red assertion must actually run and fail for the
intended reason before the unchanged candidate test may run and pass. The
driver checks Go's JSON test events and rejects skipped tests, empty test
selections, compile failures and setup failures with the wrong diagnostic.
The parent-mode mutation removes only the production parent privacy condition;
the parent-type mutation removes only its ordinary-directory condition. The
candidate's production checks remain unchanged. These join the existing
audit / digest / revocation / root / reason / partial-swap / restart controls. A complete run
has 340 red/candidate result rows in `results.json` and prints
`PASS: Codex unit red/candidate checks`. This is unit regression evidence only;
it does not replace any live black-box assertion.

The artifact-digest control selects `TestArtifactPins/changed-bytes` and removes
only the executable digest comparison in its red copy. The test first requires
the original artifact to plan successfully, then creates a fresh 0500 file in
the same private directory and renames it over the pinned executable. It checks
the replacement inode, mode and exact bytes before requiring an integrity
refusal. The original file never needs to be opened for writing, so this setup
also works for the ordinary test login identity. The red case must reach the
integrity assertion and fail when the digest gate is absent.

The four draft.4 Go controls are `session-history`, `capture-history`,
`record-history` and `blob-metadata`. They respectively remove request/home
history equality, capture/home history equality, protected reopened history
equality, and committed object metadata comparison. Each valid control first
uses the real fixture bytes/state successfully. The red assertion fails when
a changed history or a self-consistent prefix reference is accepted.

The case reader has a separate Linux-only unit suite and retained mutation
driver. Run on the authorized Linux test machine:

```sh
python3 e2e/v2/cases/codex/check_protocol_red.py --source . --evidence /test/evidence/lb-v2-codex-protocol-red
```

Its 20 controls include snapshot retention, end-frame enforcement,
request correlation, event-life checking, human.session proof selection,
zero resource-count enforcement, duplicate-key checking and evidence path
confinement. It retains both source copies, input hashes, selected command,
stdout/stderr and exits for each red/candidate pair. It requires the exact
selected unittest to execute, red exit 1 with the intended assertion, and
candidate exit 0 with a real completed test. Import/syntax errors, skipped
tests, wrong-assertion failures and missing evidence cannot count. A complete
run has 20 result rows and prints
`PASS: Codex case protocol red/candidate checks`. These fixtures test only
the reader and use no service or authenticated provider; they cannot satisfy
any of the nine live assertion IDs.
The exact original 28 Go rows, original eight protocol rows and all additional
review rows are listed in the runner's REVIEW-FIXES.md. Its per-item report
distinguishes authored controls from executed evidence. Pinned exec/resume
help, actual effective approval/sandbox policy, a real retained limit sample
and the nine live rows remain Linux acceptance prerequisites. The authoring
Mac did not run the vendor or these drivers.

Every Go test-created directory goes through `canonicalTemp`, including named
service records, leases, workspaces, runtime children and home replacements.
The helper establishes mode 0700, resolves physical paths and verifies ordinary
directory type, ownership by the test identity and stable filesystem identity.
Its no-path form obtains a new TempDir; its path form creates a fresh named
directory under an existing fixture parent. Raw TempDir and Mkdir calls are
confined to this helper. This does not depend on TempDir's umask-derived mode.
Separate production rejection
tests use group-accessible, world-accessible, regular-file and symlink parents;
the valid private-directory control still creates a home and preserves history
when a repeated creation is refused. No test flag weakens production privacy.
Neither unit tests nor this case may run on the authoring Mac. In this scaffold,
the public case is expected to fail until its listed dependencies are integrated;
it must never turn an unavailable dependency into a passing assertion.


Draft.4 fix 11 retains 77 fix-9 literal launch/capture controls in launch_red.json
and retains 25 fix-10 pin/authority/policy/binding controls and adds 26 fix-11 controls to the original 42 Go controls,
for 340 ordinary/faults red/candidate result rows. The
driver retains that exact catalog, names each mutation and rejects an ambiguous
anchor or wrong reached assertion. Its unit snapshot includes actual admin/store
source for dependency-refusal tests. Current consumer wiring and all new rows
are in the runner's LAUNCH-PLAN.md; REVIEW-FIXES.md retains the historical rows.
The 21 protocol mutations now use an explicit edit catalog. The launch-effect
anchor includes its function definition, and diagnostics identify the mutation
and actual anchor count. Every selected protocol assertion must exist once.

Real fix-11 setup must use retained sourced reservations, enrolled executable
pins, helper-owned private storage and the complete launch/capture recovery
records. Supply the operation-scoped runner dependencies and pre-binding
prompt/session selections through the real owners. Missing ports remain failed
gates. No ready Lane, host path, copied binding or synthetic receipt is a
substitute. Reservations retain store-derived Level/Role/Driver and consumed
Authority. helper_prepare retains Kind=agent, complete recovery, bound plan and
ready Lane/events together; omitting LaunchPlans must refuse. A capture refusal
requires explicit D6 approval/generation metadata, the retained policy snapshot
and matching protected current policy; actual approval consumption and release
revocation checks belong to the publisher/store. The exception is visible
incomplete evidence and cannot satisfy session/limit continuation. LP-CAPTURE-IO-1 and the unverified pinned
resume argv / real provider-limit sample remain open. This authoring round did
not execute any unit, mutation, installed-service or live case on the Mac.

The supplied ca1e78f Linux run failed both race builds in shared capture setup
with invalid launch reservation shape, and the Go driver failed because its
candidate was red. Protocol tests and all protocol reds passed there. The
shared fixture now uses a valid hyphenated config, complete pins/authority and
agent Kind while retaining every assertion and the shared validators. This
candidate still requires an exact-source Linux rerun. No runtime result is
inferred from Mac static checks or earlier revisions.

Fix 11 requires completed materialization before Codex argv, a historical sealed
grant snapshot for opened capture with current control rights, and fresh outside
usage before every LimitSignal. Install the actual MaterializationControl,
UsageWindowSource and protected native/profile bindings; unavailable owner ports
remain typed failures. The exact private five-column TSV and normalized
usage_window object must match authenticated post-exit from-profile exhaustion.
The adapter emits UsageEvidence and has version codex-exec-v4. No Codex usage
command or alternate source format is guessed. The case accepts stdout/vendor;
structured is not a registered API stream. The protocol driver now has 21 rows,
including vendor-stream. All 340 Go rows and 21 protocol rows need a fresh Linux
run for this source. The earlier supplied green boxes are historical evidence.
