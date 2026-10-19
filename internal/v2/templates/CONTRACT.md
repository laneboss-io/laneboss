# Templates integration against draft.4

Port-read base: `7d498c5`, the supervisor's committed templates d4fix2 with
contract fixes 9–11. This delta corrects the r3 fixture and matched-plan findings.
Contract revision: `v2.0-draft.4`. This note describes the working-tree port;
it is not a runtime acceptance or a claim that another lane's stubs work.
No shared API, assembly, dispatch, main or dependency file is edited here.

## Implemented paths

For lane and worker callers, `BriefRender` first resolves `StateStore.Lane`
using the authenticated life. It compares the claimed grant set and role with
that current lane before calling `BriefingInput` or reading selected sources,
objects or receipts. `BriefStart` rejects a foreign life claim before input
lookup and resolves its own life the same way. Both compare the original
Lane.Task, grant set, run and generation with the authentic current projection.
Render separately binds request.Task to the active/reserved BriefingInput.Task;
Start requires that input task to remain the original Lane.Task.
Service and authorized human callers use the scoped briefing-input port.
That snapshot supplies the authentic current or reserved life, retained
task, grants, effective policy, approved source selection, capability checks and
already-authorized lane groups. A readable task object cannot substitute for
the life’s retained assignment. Public lane rendering remains self scoped.

The receipt-backed service rendering path requires the real pending/running
lifecycle receipt, matching configuration, request key/digest and
reserved life. Its prompt-retention intent carries that operation,
request, life/run, logical turn and cancellation epoch. A lifecycle method
label does not bypass a lane or worker's own-life rule. Service actors require
the actual reservation's lane/human requester and carry that actor in the
retention intent. An unrelated service read label refuses. The trusted store
must resolve the original reservation for the bound lifecycle component without
weakening public receipt domains, as requested in `CONTRACT-GAPS.md`.
Queued pending replies must correlate with the active operation and life.

Before any service BriefingInput lookup, public lifecycle calls validate their
prepared envelope and digest. An unrelated service method refuses immediately.
Internal continuations may have no public method or proof. They must resolve a
real current PlanLaunch effect and LaunchPlanRecord in phase reserved or sourced.
PendingEffects supplies at most 256 selectors; each selected Effect and plan is
reloaded under the service scope. The actual held, unexpired claim, bound service
actor, config, reservation ID, operation/request/requester, target and epoch must
agree. Multiple matching plans conflict. No effect is claimed or advanced here.
After a public lifecycle CauseRequestID matches, a different grant set or
launch ID is an integrity failure before input lookup or receipt fallback.
For internal continuation searches, only a different grant set may be skipped;
a matching grant set with another launch ID is still an integrity failure.
The store input must match that reservation's life/run/generation, lineage,
driver, grants and policy. Internal service/scheduler/watchdog requesters are
valid only for mode continue, and retention uses the reservation's original
requester and request/operation IDs. No fabricated public request is needed.

For existing lives, policy generations satisfy positive grant issuance record
<= live lane record <= current policy. The current policy must match a nonzero
authenticated scope generation. A read never rewrites historical grants or
refreshes the lane. New lives (run 1 preparing, or start/adopt preparation)
require exact equality across grants, lane and policy. Invalid generation order
returns conflict, preserving the lane's original grant assignment.

`resolveApproved` checks the current scoped org snapshot, configuration,
renderer pin, ownership reference and complete inventory. It compares the exact
role selection returned by `TemplateSources`, checks explicit absent/present
local status against the inventory, resolves source identities through
`Source`, and reads actual committed content. Partial, malformed, stale,
wrong-role and unsupported-driver pairs refuse; an entirely absent local pair
inherits the explicit org pair.

Source generation is the current approved snapshot generation.
`ResourceFile.RevisionGeneration` may be older for unchanged file history, but
must be positive and cannot exceed that snapshot. Org and policy generations
remain distinct. The component tests deliberately use org generation 7,
policy generation 9 and file revision 2, with different source and object IDs.

`readBlob` checks the actual `ObjectMetadata` reference, configuration and
committed provenance before reading. Object visibility remains the store's ACL
decision, including its participant rules. `ReadVerifiedBlob` checks bounded
contiguous chunks, cancellation, chunk and full hashes, and an exact-end read
with the empty-byte hash. A valid prefix digest cannot conceal a longer object.

`renderBriefing` passes the authentic inputs to the existing literal formatter,
resolves every consumed source, and calls the trusted `RetainObject` port with
the exact rendered bytes, input refs and scoped ACL. Only the real retained
prompt reference is returned. Its key is a SHA-256 of canonical render identity:
config, life/run/lane generation, policy/org generation, rendered digest, ACL,
exact input refs and causal requester/operation. Identical reads reuse a key;
different owners or source identities cannot alias it. Store must atomically
return the existing matching object and reject collisions. Retention errors and mismatched receipts fail.
There is no filesystem or source-ID-to-object-ID fallback.

`BriefStart` uses the same snapshot and rendering path. An authenticated lane
gets its retained assignment; a human without a life gets an explicit overview
with no invented task, workspace, grants or launch. Both retain an immutable
output object and perform no lifecycle transaction, worker start or agent
launch. Unavailable checks or input storage fail instead of printing success.

`OrgValidate` compares the requested generation with the actual org snapshot,
preserves real policy validation failures, verifies source and derived content,
and validates every discovered role pair, including unselected roles. Both org
validation and bootstrap require WorkflowPath and parse its real twelve-entry
seed pack, including identity, band, critical flag, routes and tmux wording.
Threshold selection stays in the SeedRules wrapper. The production parse does
not insert seeds or change the effective blacklist. Org validation does
not equate a valid policy with complete template validity or seed an existing
org during validation.

`OrgBootstrap` implements a real pending publication intent. The dispatcher
must authenticate, look up retries and durably reserve the exact request before
module preflight. Templates verifies the exact frame/reservation, resolves the
authorization target, checks scoped `HumanVerifier.CheckProof` facts, rejects
existing orgs, verifies the source manifest and every source object, and binds
the protected renderer/ownership pins. One `Transact` carries absent-org CAS,
`ProofUse`, the typed `BootstrapEffect` and the generalized `RPCReply`.
A queued effect returns only its actual pending operation. It does not emit
`org.bootstrapped`, install a canonical projection, or claim publication
success. The service outbox, confined publisher and `CompleteEffect` own that
measured completion and crash recovery. A stored reply replays before proof
consumption or base preflight. Proof ID shape and the exact request/proof
digest are checked before lookup; the returned receipt must preserve its
configuration, key and actor domain. A consumed proof is not verified or used
again on retry. The transport/store still own current authorization.
VerifiedHumanProof.SimulatedPresence must equal its ProofRef mark, and a marked
reservation cannot be downgraded by an unmarked proof. The queued operation
preserves the union of the reserved operation and verified proof marks. Both
the durable reply and non-replayed commit operation must retain that mark.
Replay compares the reply with the durable receipt/operation provenance; it
neither reuses the proof nor upgrades hardware provenance from a caller bool.

`New` validates the common read dependencies and `Register` registers exactly
the four assigned methods. The owned service methods contain no unconditional
`not_implemented` return. Missing or unfinished external ports still return
their original typed errors. Bootstrap returns `prerequisite_missing` if its
protected installation dependencies are absent.

## Exact integration work still required

The current assembly supplies Store, Policy, Publisher and Clock to templates.
It does not supply these additional, service-only constructor inputs:

- `Human: identities`, for scoped `CheckProof`;
- `BootstrapRenderer`, the installed confined **org renderer** executable pin;
- `BootstrapOwnership`, the service-committed initial ownership manifest.

These fields are now explicit in templates' owned Dependencies. They are not
new RPC fields or caller-selectable executables. The integration owner must
wire them from protected installation data, or provide an approved internal
bootstrap-plan resolver that supplies the same facts. The existing RuntimeManifest
bootstrap executable must not be assumed to be the org renderer without an
actual enrollment proving that role. Draft.3 has no absent-org snapshot from
which templates could safely discover those two pins itself. Supplying a
Publisher interface alone does not resolve them.

Service/store must implement the amended source, metadata, briefing-input,
retention, receipt, proof-guard and bootstrap-effect ports. In this checkout
they remain other lanes' typed failing implementations. The outbox must reserve
and reconcile publication through the pinned Publisher and stamp the actual
result/sequence; templates does not substitute a constant success receipt.

The following internal string/selector conventions need coordinated consumer
confirmation because their Go fields are strings or zero-valued selectors:

- `BriefingInput.Mode` is `lane` or `overview`.
- Org validation and approved rendering send both exact OrgSnapshotRequest
  selectors. OrgID is the configuration's org identity and Generation is the
  expected publication; zero or omitted selectors never mean current.
- Bootstrap performs no snapshot read. Its private authorization target supplies
  the org baseline, which must be zero; publication retains the absent-org CAS.
  A nonzero baseline conflicts and a failed target lookup propagates.
- The shared org kind gate uses the snapshot generation: generation 1 requires
  a non-nil empty Derived array, and later generations require nonempty file
  outputs. Initial and full validation delegate that rule to the same gate.
- New prompt ACL audience is `life` for an authentic life and `self` for a
  human overview. Owner, config and optional life are retained independently.
- `TemplateRef.ID` is the selected Markdown SourceRef.ID. A SourceRef.ID is
  never interpreted as a BlobRef.ID.

These conventions do not create a generic source-path or authority API. If an
integration producer uses different values, freeze and adapt both producer
and consumer together. The current renderer supports retained regular source
files; bootstrap does not accept directory/link/part-assembly entries as source
files or treat their labels as paths to execute.

Store BriefingInput must resolve the active/reserved TurnSnapshot.Task for
BriefRender and the initial Lane.Task for BriefStart. It must return the
authentic reserved life view before helper_prepare commits the ready Lane row.
Templates checks that view against the reloaded launch reservation and current
claim; it does not create a ready Lane projection. Consumers are lifecycle,
store, templates, guidance and launch/turn E2E setup. Missing current plan or
claim data remains an owning error, never a legacy continuation fallback.

## CLI and acceptance integration

The feature adapter registers four owned semantic input validators and shares
them with ergonomic preflight. It delegates typed calls to `Invocation.Invoke`
and retained file bytes to `InvokeRaw`, preserving
file request bytes and carries common request/idempotency IDs and proof input
into the main RPC. All subcalls share the invocation's socket; an explicitly
supplied already-open Client remains borrowed. Only the owning invocation (or
an owned standalone fallback) closes its connection, preserving close errors.
A read or HumanSessionMethod mutation's `--proof` establishes `human.session` once on that same connection;
the proof is not attached to subsequent reads. Returned envelopes require exact request correlation
and one result/error. Render verifies actual prompt and task bytes before
printing JSON or Markdown. Start resolves the original Lane.Task and performs
the same comparison. Ergonomic `--brief FILE` defaults to the original Lane.Task;
for an active follow-up, `--task-ref FILE` supplies its committed task reference.
Local bytes must match that exact reference and service-side render must still
match the active/reserved task. The CLI never uploads or assigns a replacement
task. The exact `--request-file` form can also carry the active task reference.

Proof-bound bootstrap uses `--name NAME --content-ref FILE` or an exact
`--request-file`; the committed source-manifest reference is part of the intent
confirmed before execution. Optional `--manifest FILE` must match its exact
size and digest. A proof-bearing invocation cannot upload a new manifest first
and thereby change the confirmed reference. The legacy unproved upload path
requires a retained parent mutation key; stage/offset keys derive from it and
exclude content so changed bytes conflict. It supplies no authorization bypass.

The common `--request FILE` path bypasses feature handlers and prints raw typed
JSON. The owned adapter therefore adds `--request-file FILE` for verified
template JSON/Markdown output and uses that form in the E2E. Integration may
instead route the common file form through the feature handler. Its generic
help still needs to advertise the feature flags. No dispatch file is changed.

The common client Open/Call/Close and installed service hosting remain external
dependencies. Human read commands additionally need a real
connection-bound read session; a binding filename or a prior CLI session ID
cannot confer one on a new process. The case setup must provide an actually
authorized transport/containment or the common interactive human connection
flow. Neither fixtures nor a label in JSON supplies that authority.

The outside-in case retains all commands, requests, outputs and exits. It checks
source and rendered bytes, both CLI forms, original-task association, fallback,
negative source controls and actual launch/turn delivery references. Setup must
provide `expected.template_id` and `start_expected` in addition to its retained
source/task receipt. Test/evidence roots must be private and owned by the test
identity. A missing dependency, authentication failure or missing delivery
receipt fails its cell; it is never a passing skip.

The draft.4 case supplies an explicit retained key to each CLI invocation.
Human reads consume independently issued `session_proofs`, one per CLI process;
subcalls within a feature command retain that connection's session. Human
non-session mutations instead use `mutation_inputs` with the exact request, retained key
and operation-bound proof. Proof references are retained with command evidence,
and duplicate proof IDs across connections refuse. policy.evaluate and blob
staging use session proofs even though they are mutations. Fallback and negative
rows can select independently enrolled bindings and corresponding reader kinds;
each is verified against identity.self. D6 proposal negatives require L6.
These fixture inputs never
replace actual authentication; `identity.self` must match `reader_kind`.

Source hash/role/generation errors can occur at committed metadata, retained-task
or snapshot validation before the old formatter error. The case recognizes a
closed set of these validation messages and checks that public hash/role
requests change only their intended fields. Public stale-generation requests
may use org.validate. Malformed-source and unsupported-driver setup must still
reach real D6 staging validation; it must not edit invalid canonical state.
TemplateRequest has no source-inventory override. Pure SourceRef faults remain
explicit component controls, separate from those public request observations.

The component mutation runner preserves all 91 draft.3 controls for assignment,
current snapshot/source mapping, committed
metadata, exact-end reads, retention provenance, reserved lifecycle causality,
full-org validation and atomic bootstrap. It adds 20 draft.4 controls for
own-life claim ordering, current projection consistency, receipt domains and
proof validation before replay. Its exact test/assertion mapping is
in `MUTATIONS.md`. It still rejects compile/setup errors, skips, panics,
unrelated assertions and abnormal exits as mutation kills, and keeps distinct
tested Linux binaries for red and green.

The first port-read fixes preserved all 111 control entries and added 24 for
registrations, semantic input checks, truthful service causes, workflow seed
production gates, stable prompt keys and CLI transport/file boundaries. The
five CLI-package controls compile the owned `_cli_test.go` asset through a
retained overlay, keeping production/common files untouched. Classification
still requires the exact selected package/test/assertion and rejects compile
or setup failures. The public task-hash/org-generation observations do not
prove template-source metadata checks; case coverage.json records that limit.
Fixes 9–11 add 15 controls, for 150 total. The policy-generation control now
rejects a historical grant record ahead of the lane, and original-task targets
the Start-only gate. Replay/commit-error anchors follow the presence-aware
helper signature. Their IDs, selected assertions and classifier requirements
remain intact. The sixth CLI-package control checks active-turn file inputs.
The r3 delta adds five controls, for 155 total, preserving all 150 earlier
definitions. Start/turn flow controls now select their actual TestPlanRender
subtests, including reserved and sourced phases. TestPlanFrames shares the
fixture body builders, requires non-null required arrays, and verifies that
the unchanged strict decoder still rejects deliberately null arrays. Matched
plan tests keep a usable receipt available, then require mismatch failure before
that fallback can run, including failed plans and expired claims.

## Evidence limits

Only permitted Mac static checks are run by this lane. New Linux unit tests,
the complete mutation matrix and the real socket/launch E2E must be executed by
the supervisor on the disposable Ubuntu 24.04 machine. Earlier reported
slice-1 unit passes do not verify this port. The independently reported draft.3
baseline build/test passes do not verify this port either. Draft.4 integration
baseline results also do not verify these templates changes. No live AI-service,
real publication, prompt consumption, ordinary-tool execution, containment or
release acceptance is claimed from component fixtures or static checks.
