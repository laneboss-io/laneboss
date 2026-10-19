# Draft.4 service/store handoff

The store adoption of integrate contract fix 13 on 7fdbad36 now selects
ValidateFailedPlanWrite at both internal preflights only for FailPlan's frozen
private API cleanup batch. Ordinary transactions retain ValidateTransactionShape
and its failed-planner refusal. The API and contract sources are unchanged.
Atomic/guard fixtures use the shared failed-write preflight, retain every
state/claim/cancellation/selector check, and keep changed retries well typed.
Launch authority uses a valid reserved-to-sourced transaction with exact
read-back and replay. Name reuse first commits the failed revision and full
cleanup batch through FailPlan and retains those jobs after fresh reservation.

[CONTRACT13-REPORT.md](CONTRACT13-REPORT.md) reports each supplied failing test
group and every control's deciding diagnostic. All 309 IDs remain; only the
selector and generic controls change, accounting for both shared preflight and
existing store barriers. All 329 sequential anchors match once. Six final
candidate-only whole-tree vet variants pass after correcting the missing
reflect import found by the initial vet. Format/syntax/whitespace and unchanged
shared-contract checks pass. No runtime test or mutant compilation ran here;
the Linux normal/faults rerun and deciding controls remain required. Nothing
is staged or committed.

## Prior group merge

The group merge on 4d84291 takes integrate's incoming plan_cleanup.go exactly,
removes the obsolete launch-control stubs and retains the real guarded Probe
and constructors. Assembly already passes the administrator evidence provider
to both constructors. All eight provider/worker production files checked are
byte-identical to group candidate 354cd86. The incoming probe fixture is adapted
exactly from serve2 6a019007; its old unverified host could not enter the real
provider. The administrator probe control and its exact-file allowlist now
target launch_control.go. All 333 union rows remain, with only that row changed.

[GROUP-MERGE.md](GROUP-MERGE.md) records each file and remaining proof. All six
whole-tree candidate vet variants pass; no further compile/vet break was found.
Formatting, Python syntax, whitespace and source comparisons pass. No runtime
or mutation execution ran. The index entries remain exactly as supplied, with
the three unmerged paths left for the supervisor to stage and conclude.

## Prior fix 31 handoff

Fix 31 on dae09253 replaces the legacy enrollment service's root-process
executable inspection with the shared administrator verifier and pinned native
frame. Root UID/GID, pidfd liveness, installation and endpoint checks remain.
Worker request/delivery rechecks now share one bounded reply window per frame;
stream rechecks write their terminal refusal before honoring Close.
The old store suite declaration included TestTaggedInventoryRetainsPresence
without enabling laneboss_e2e_authenticator. Expected tests now come from Go's
selected files for the binary's race/tag flags, with strict ran/passed equality
and retained expected/missing/unexpected inventories.

[D4FIX31-REPORT.md](D4FIX31-REPORT.md) names each deciding regression/control
and the installed proof still required. All 303 previous mutation rows remain
unchanged; six additions reach 309 controls and 327 sequential edit anchors.
The full Linux inventory requires 618 targeted pairs and fourteen final suites,
plus the six-method Python diagnostics/inventory suite and its control. All six
candidate-only whole-tree vet variants pass, as do format/syntax/whitespace
checks. No runtime tests, mutant builds or installed canaries ran here.
Nothing is staged or committed.

## Prior fix 30 handoff

Fix 30 on 0dc5def repairs case (b): all three new pipe tests set their
read deadlines after the expected synchronous remote close. The original
SetReadDeadline calls were auth_bound_test.go:47 and :68, and
auth_capture_linux_test.go:43. Go's net/pipe.go:219-221 returns ErrClosedPipe
there. Deadlines now precede the close trigger, while typed refusal and exact
EOF assertions remain. TestAuthenticationRefusalPrivacy already reads and
decodes the correlated native refusal before checking close; it is retained.
Production code, all 303 controls and all deciding diagnostics are unchanged.
The six candidate-only whole-tree vet variants, gofmt -l and diff whitespace
checks pass. The supplied Linux failures are retained as input evidence;
corrected normal/faults runtime results remain pending. Nothing is staged or
committed.

## Prior fix 29 handoff

Fix 29 on 9ec1de8 corrects the three assigned gread7 findings. Identity's
CurrentConnectionScope is adopted exactly from serve2 e9e2f660; bound service
rechecks require that port and never fall back to fresh authentication. Close
reaches the transport, with a private bounded reply window only where the
native dispatcher owns the subsequent close. Both protected lane cgroup
directories are explicitly chmodded to exactly 0755. Configuration event SQL
selects only empty life/run zero before its scan and page limits.

[D4FIX29-REPORT.md](D4FIX29-REPORT.md) names the five new tests, seven new
controls and strengthened configuration-query control, with every deciding
assertion. All 296 earlier IDs remain; only config-events-query is reanchored.
The catalog has 303 controls and 320 edits across seven component packages:
606 targeted pairs and fourteen final suites are required on Linux. All six
candidate-only whole-tree vet variants pass, after correcting a missing import
found by the initial vet. Formatting, Python/shell syntax, whitespace and
literal-anchor checks pass. No tests or mutants ran here. Native peer lifetime,
installed root-helper cgroup traversal and composed acceptance remain Linux
requirements. The separate legacy ServeEnrollment review item is outside this
brief and is unchanged. Nothing is staged or committed.

## Prior fix 28 handoff

Fix 28 on f02a492 corrects TestInitialMarkerEvent's missing RequestID and
requested/observed timestamps. Publication/manifest IDs use NewID; actor,
event and operation IDs follow production prefixes. Each negative case now
requires its exact typed refusal. Production validation is unchanged. All six
whole-tree vet variants pass; the corrected runtime test still needs Linux.

## Prior fix 27 handoff

The current round is [D4FIX27-REPORT.md](D4FIX27-REPORT.md), based on f5736f7.
InitialContext now uses the real shared native verifier. Internal configuration
events and exact OrgSnapshot reads support publication/enrollment read-back.
The root helper control directory is explicitly 0755 after its 0077 umask,
with root-only write permission. Replay binds its complete administrator frame
before reading any retained receipt. The broader comparison also adopts strict
initial marker event decoding and three bounded authentication rechecks.

[D4FIX27-AUDIT.md](D4FIX27-AUDIT.md) classifies all 294 requested paths: 9 taken,
249 already equal and 36 not taken, plus the required shared marker DTO.
Reviewed views, typed errors, cache bounds and byte gates remain. Credential
features, optional timing instrumentation and harness/E2E files were not copied.
Whole-tree vet compiles the final code/tests cleanly for Linux amd64/arm64 in
normal/faults modes and Darwin arm64/amd64 using the shared cache. Static
format/syntax/whitespace/literal checks pass. Eleven new controls reach 296
controls and 312 edits, preserving all 285 earlier rows. Linux still needs
592 targeted pairs, twelve final suites and real installed root-helper/service
permission and enrollment/publication proof. No mocked peer or wider chmod is
credited. Nothing is staged or committed.

## Prior fix 26 handoff

The current round is [D4FIX26-REPORT.md](D4FIX26-REPORT.md), based on c9ce9592.
All four gread5 findings have source corrections and prepared deciding controls.
The native administrator listener/store use the shared frame contract and all
three handlers, with bounded replies for refusals. Helper verification adopts
the pinned serve2 control-unit / socket / installed-artifact / lifetime checks. The
publication adapter is in initial_commit.go under its merged names, and all
seven other listed readers bind object views. Failed SQL reads preserve their
context or database cause; successful reads and integrity refusals stay intact.
Views authorize before payload retention and keep at most 16 objects/64 MiB.

Whole-tree vet compiles the final code and test files cleanly for Linux amd64
and arm64 in normal/faults modes, plus Darwin arm64 and amd64. The shared cache
worked. Formatting, Python/shell syntax, whitespace and literal audits passed.
All 262 earlier controls remain unchanged; 23 additions reach 285 controls and
301 edits, with six component packages. The complete Linux inventory now needs
570 targeted pairs and twelve final suites. New runtime kills/passes and
installed enrollment/publication acceptance remain unmeasured in this round.
The earlier initial-read.patch is historical; do not reapply it to the source.
The report lists each adopted/cross-lane file and each deciding assertion.
Nothing is staged or committed.

## Prior fix 25 handoff

The current round is [D4FIX25-REPORT.md](D4FIX25-REPORT.md), based on aa60d80.
The failed receipt query was being classified as a byte mismatch. Query
failures now preserve deadline/cancellation or the real database error, while
missing receipts and successfully read different bytes retain the exact
integrity refusal. The same faulty condition was present in aa60d80; the
relevant source paths have no diff from 9a484ef. No fixture re-encoding was
found by source tracing. The existing 10 ms deadline and typed expectations
remain, with receipt/original-object byte checks before and after failures.
Deterministic SQL-boundary cases and an actual LaunchPlan receipt-corruption
control keep the error and integrity paths separate. All 256 previous rows
remain; six additions reach 262 controls and 277 edits. Formatting and
Python/shell syntax, whitespace and literal checks passed. Linux vet exited 1
on Go cache permission refusals; remaining variants were skipped under the
brief's explicit route. Compilation and runtime remain unestablished by this
round. Exact outputs and limits are in the current report's evidence. Nothing
is staged or committed.

The supervisor reports green15 passed initial publication on the previous
linear-read change, with initial_publish at 2373 ms and read_back at 480 ms.
Those observations come from the brief; this round did not independently run
or collect that job. The still-running unit job supplies no new result here.

## Prior fix 24 handoff

The current round is [D4FIX24-REPORT.md](D4FIX24-REPORT.md), based on 9a484ef.
ObjectMetadata and Blob share fully verified persisted bytes only inside a
store-owned request view. Live authority and ACL checks remain on each access;
caller/request bindings, cancellation, close and returned-buffer ownership
fence reuse. Eleven complete-read helpers now bind or borrow such a view, and
worker manifest reuse is invocation-local. No public range bound or budget
changed. A context-local counting hook and eight new controls cover actual
full-load counts, tampered bytes/metadata, isolation, copies, release and
revocation. All 248 prior rows are unchanged; the catalog is 256 controls and
270 edits. Runtime results remain for Linux.

Installed integration is required: this checkout's admin package is a stub.
Apply [initial-read.patch](initial-read.patch) to the full 179f3f0 owner file
when integrating the native implementation. The patch opens a post-commit
view, reselects the receipt marker, shares verified bytes through complete
read-back, and keeps the native channel, pins, receipt/event/operation and
final digest checks. It passes applicability checking against retained exact
bytes. The whole adapted file is in external evidence. Hosted Store wrappers
must forward the private BeginObjectRead capability; unsupported backends keep
their checked per-range path. No installed speedup or pass is claimed here.

Formatting, Python/shell syntax, whitespace, all literal anchors and the owner
patch applicability check passed. Linux vet exited 1 on Go cache permission
refusals; remaining variants were skipped under the brief's explicit route.
Exact output is retained externally. Compilation and runtime remain
unestablished. No tests or product builds ran on this Mac. Nothing is staged
or committed.

## Prior fix 23 handoff

The current round is [D4FIX23-REPORT.md](D4FIX23-REPORT.md), based on 22c7dd9.
The serve2 b41fa46 refusal fix, unchanged whole-frame native canary and both
required red controls are adopted. server.go and worker_listener.go match
that owner source exactly. Public refusal fields contain fixed stage text;
typed cause detail goes to the private journal. Disclosure remains suspected
until Linux runs the canary and controls. The failed-plan failure still needed
repair: private requests were incorrectly copied through RPC shape validation.
The copy now preserves real absent/unknown values through the store decoder,
and the fixture explicitly checks its required IDs and known slot. Both
rollback assertions and the original atomicity mutant remain. All 245 previous
rows are unchanged; three additions reach 248 controls and 260 edits.

API owner handoff: no API file changed in this round. Compared with the current
plan_cleanup.go, integrate 39ac09e has the same PlanCleanup field names, order
and types and the same two FailedPlanStore method signatures. Its differences
are a context/reflect import block, shorter declaration comments, removal of
the inline Kind comment, and the added ValidateFailedPlanWrite preflight for
failed revision/cause/resource correlation, issue shape and complete batches.
Once fix 13 lands, keep integrate's whole file and drop this lane's version.
The existing lifecycle aliases still target the same API names. Do not add a
second local DTO, interface or validator while the API change is under review.

Formatting, Python/shell syntax, diff whitespace, all literal anchors and the
source comparisons passed. Linux vet exited 1 on Go cache permission refusals;
remaining variants were skipped under the brief's explicit route. Exact
outputs are retained in the report's external evidence. Compilation, Linux
red/candidate and installed results remain unestablished. Nothing is staged or
committed.

## Prior fix 22 handoff

The current round is [D4FIX22-REPORT.md](D4FIX22-REPORT.md), based on 4e361ce.
Materialization now selects the exact reservation's PlanLaunch parent before
the existing claim validation. Its replay regression forces both retained
inventory orders, and a completed-parent control keeps the original-claim
requirement explicit. The runner retains early FAIL lines, assertion context
and the same diagnostic in its final failure record. All 243 previous control
rows remain unchanged; two additions reach 245 controls and 257 edits.
The failed-plan DTO and interface now live in API's plan_cleanup.go, and the
local lifecycle declarations subset is removed. Lifecycle's full file must
win on integration, with lifecycle-port.patch changing its declarations to
API aliases so the method signatures have identical types. No second
lifecycle declaration file is left behind. Formatting, all literal anchors,
the owner patch applicability check and Python/shell syntax passed. Vet hit
the Go cache permission refusal; remaining variants were skipped as authorized.
Compilation and runtime proof remain for Linux. The report records the static-check
limits, exact owner handoff and required deciding failures. Nothing is staged
or committed.

## Prior fix 21 handoff

The current round is [D4FIX21-REPORT.md](D4FIX21-REPORT.md), based on 72087aa.
The serve2 admission fix and its native-socket regression are adopted, including
both required invalid-first-frame controls and their exact second-frame slot
assertion. The store implements lifecycle's exact failed-plan private port;
failed revision, pending cleanup requests and replay receipt share the existing
SQL transaction. Actual claim/CAS/epoch/stage/projection checks precede commit,
and pending jobs remain visible to drain and recovery. Atomicity regression
injects a real append error; its red moves the append to a second transaction.
All 228 prior control IDs remain; fifteen additions reach 243 controls and 254
edits. New runtime evidence remains for Linux. Native cleanup dispatch and
measured completion remain owning-component integration work; pending requests
do not claim erased credentials. Formatting and Python/shell syntax passed.
Linux vet hit three cache access refusals, so remaining variants were skipped
by the explicit brief route. Compilation and runtime results are unestablished.
The report retains the exact scope, merge note and acceptance requirements.
Nothing is staged or committed.

## Prior fix 20 handoff

The current round is [D4FIX20-REPORT.md](D4FIX20-REPORT.md), based on 420237d.
The continuation-claimed-epoch row and its exact assertion remain unchanged.
Its setup failed because the ended-session observation used helper_open without
the fix-12 plan fence. The fixture now uses the existing lifecycle observation
row with shape preflight, lane CAS, cancellation guard and real read-back.
The epoch test requires an actual claimed effect, typed conflicts, an unchanged
pending intent after refusal and successful original-input claim afterward.
A source sweep covers 27 state/claim/reconciler controls. Eleven have normal
red/candidate passes reported in the supplied prior transcript; no corrected
runtime result is claimed. The inventory remains 228 controls and 238 edits.
Formatting and Python/shell syntax passed. Linux vet hit a Go cache access
refusal, so the remaining variants were skipped under the explicit brief route.
Compilation remains unestablished. The current report and external evidence
retain the exact failure, per-row scope, checks and Linux rerun requirements.
Nothing is staged or committed.

## Prior fix 19 handoff

The current round is [D4FIX19-REPORT.md](D4FIX19-REPORT.md), based on 1d9921b
with the 2a55fa8 merge still open. CurrentApprovedPolicy is implemented and
fresh prepare/open writes receive the private API stamp under the writer lock;
exact committed replay precedes a fresh policy read. Effect persistence uses
the closed typed vocabulary and separates completed state from succeeded
outcome. Reclaimed claims keep EffectClaimed and use their durable generation
for recovery. Three merged secrets/Codex consumers and their positive fixtures
are adapted. Turn envelopes join their real protected snapshot. The thirteen
new controls retain all 215 merged IDs, reaching 228 controls and 238 edits.
Candidate and mutant tests are bounded at ten minutes, with a 660-second parent
bound; timeout still earns no red credit. Native credential projection storage
and native producer ports remain explicit owner-named refusals with no active
store caller; they are OPEN, not accepted delivery. Formatting and Python/shell
syntax passed. Linux vet failed on a missing standard-library dependency and
Go cache access; the brief's explicit route skips the remaining variants.
Compilation and runtime results remain unestablished. Exact outputs and limits
are retained in the current report and external evidence. The merge is
left for the supervisor to conclude; nothing is staged or committed here.

## Prior fix 18 handoff

The current round is [D4FIX18-REPORT.md](D4FIX18-REPORT.md), based on 2a46490.
Expired ownerless preflight reservations now retain an atomic failed receipt
and event; opaque live invocation tracking prevents cleanup of live owners.
Recovery runs before the freeze pause gate. Execution-stage forbidden errors
now commit failed outcomes under the actual live claim. Per-effect backoff and
compiled build visibility in health are also implemented. Three older P3s
remain open with reasons in the report. The catalog retains all prior IDs and
adds thirteen, for 199 controls. New runtime proof remains for Linux. This
candidate is uncommitted. Formatting, all 206 literal anchors and Python/shell
syntax passed. Linux vet hit two Go cache access refusals, so the remaining
variants were skipped under the brief's explicit recovery instruction. The
report and external evidence retain exact outputs and runtime limits.

## Prior fix 17 handoff

The current round is [D4FIX17-REPORT.md](D4FIX17-REPORT.md), based on a54319c.
The guidance-unscored-item canary now uses a complete source reference, asserts
schema/shape/owner preflight, requires the exact forbidden error code and proves
binding-only completion afterward. Its production guard and mutation remain
in place. The sweep covers all 75 rows beyond the survivor across 28 test
groups; no further concrete masking fixture was found by source inspection.
The supplied log records 110 normal pairs, including natural-measured-process,
before this survivor; it supplies no later/faults result. The supervisor's
api.Launcher correction is retained. Formatting, the literal anchor review and
Python/shell syntax passed. Linux vet hit a Go cache access refusal; the
remaining variants were skipped under the brief's explicit recovery route.
The current report and external evidence retain exact outputs and Linux
limits. This candidate is uncommitted.

## Prior fix 16 handoff

The current round is [D4FIX16-REPORT.md](D4FIX16-REPORT.md), based on 5e613b9.
Health is served only on the public first-frame path; ordinary dispatch refuses
it and the handler requires the private observation context. The client gives
health a separate one-request socket while preserving an authenticated primary
and read session. Reconciliation skips per-effect forbidden/conflict refusals
without a host fault, while other failures remain fatal. Fifteen new controls
bring the inventory to 186; two existing auth anchors only change indentation.
All new runtime tests and deciding red/candidate pairs await Linux execution.
Formatting, all 193 literal anchors and Python/shell syntax passed. Linux vet
hit two cache access refusals; the remaining variants were skipped under the
brief's explicit recovery route. The report and external evidence retain the
exact outputs and limits. This candidate is uncommitted.

## Prior fix 15 handoff

The current round is [D4FIX15-REPORT.md](D4FIX15-REPORT.md), based on c4e3cf5.
The surviving natural-measured-process control now uses complete typed event
evidence, a valid zero-survivor completion control and an exact containment
error assertion. The production measurement guard and catalog row are retained.
The other d4fix14-affected rows have a per-control source-path review in the
report. The supplied log records 107 normal pairs before the surviving row;
later rows and faults results are not established by that log. Formatting,
literal anchor review and Python/shell syntax passed. Linux vet exited 1 on
Go cache access; the remaining variants were skipped under the brief's
recovery route. The corrected red/candidate pair still requires Linux execution.
The current report and external evidence retain the full handoff. This
candidate is uncommitted.

## Prior fix 14 handoff

The current round is [D4FIX14-REPORT.md](D4FIX14-REPORT.md), based on 9e3a8ed.
The capture mutant keeps facts used while bypassing the intended comparison.
Four launch selectors were already correct and are retained. The store now
exposes ReserveMutation's atomic winner; the dispatcher supplies OwnsMutation
only to that winning invocation and awaits a loser. Assembly wires Dispatch
to the server, with a minimal field bridge in the current lifecycle stub for
the approved 0b139e1 implementation. Hosted stores must forward the new private
port. No assembled lifecycle runtime result is claimed before that integration.

The 171-control anchor audit, formatting and Python/shell syntax passed.
Linux vet hit the cache refusal, so remaining candidate/mutant vet was skipped.
The new tests and controls need Linux execution. This candidate is uncommitted.

## Prior fix 13 handoff

The current round is [D4FIX13-REPORT.md](D4FIX13-REPORT.md), based on 5eef5d2.
The service input test now emits real method/form/validity nodes for the exact
selected mutation path. Catalog assertions and strict runner checks are
unchanged. A static review of all 160 mappings found no further mismatch of
this kind; the 99 later controls still need runtime execution. Formatting and
Python/shell syntax passed. Linux vet hit the cache permission refusal, so
remaining vet variants were skipped as instructed. This candidate is uncommitted.

## Prior fix 12 handoff

The current round is [D4FIX12-REPORT.md](D4FIX12-REPORT.md), based on a34d672.
It repairs the supplied fixture failures, the ChangeEvent receipt lookup and
the runner's dependency discovery. Formatting and Python/shell syntax passed.
Linux Go list hit the existing cache permission refusal, so no reduced-snapshot
or vet result is claimed. The 160 authored controls await Linux execution.
The earlier merge is concluded; this candidate remains uncommitted.

## Prior fix 11 handoff

The current uncommitted candidate starts at 01c866a with the incoming cf894d1
merge open. [D4FIX11-REPORT.md](D4FIX11-REPORT.md) is the current per-item source,
failure and remaining-work report. The shared lane fixtures now reserve and
plan before binding identity; the production plan requirement remains intact.
Group A source is implemented. Group B has durable refresh, causal revocation
and guidance ownership support, with worker mapping/materialization and full
scored guidance still incomplete. Native composition and runtime results remain
unmeasured. The 155 authored controls have not run or passed anchor validation.

Validation stopped when the py_compile invocation named nonexistent actor.py.
Formatting and both shell syntax checks passed. Vet and further validation were
not started. The supervisor owns recovery, Linux verification and merge staging.
The following fix-10 and earlier sections are historical context; the current
report supersedes their inventories and port-status descriptions.

## Earlier fix 10 delta

The current source starts at fbbf771.
[D4FIX10-REPORT.md](D4FIX10-REPORT.md) is the current per-finding report.
The planner issuance fence reloads the retained starter ceiling and original
start/adopt request, including separate grant staging. Lane identities need
a launch plan; there is no declared historical identity-import exception.
Failed plans without a Lane projection release their name. Internal operation
events omit a nonexistent public request digest through the matching optional
wire schema. The four reviewed guard tables now emit a unique assertion for
each subtest, and mutation execution requires that exact subtest's FAIL path.

The inventory has 98 controls, 196 red/candidate pairs and ten final package/tag
suites. Eleven new controls cover issued grants, identity reservation/history,
failed-name reuse, claimants, foreign cause, both producer-generation sources
and internal operation-digest provenance. The supervisor reported the previous
fix-9 unit run green in both builds; that is not runtime evidence for this
uncommitted fix-10 candidate. Findings 6/7 remain documented performance work.

## Earlier fix 9 and enrollment addendum

The authorized recovery repaired pending-key-digest; all 87 controls now have
unique anchors. Final formatting and Python/shell syntax checks pass. Linux
vet hit the existing cache's operation-not-permitted refusal; faults and
Darwin vet were skipped as explicitly permitted. See
[D4FIX9-REPORT.md](D4FIX9-REPORT.md). Compilation and runtime acceptance remain
unverified.

The current source handoff is [LAUNCH-PLAN.md](LAUNCH-PLAN.md), based on
e4e125c. It describes the implemented one-store
launch/capture fences, concrete startup inventory/ceremony ports, 25 new
mutation controls and the exact remaining owner wiring. Its source/static
scope supersedes older launch and child-ancestry stub notes in this file.
Actual Linux unit/red/candidate and installed launch acceptance are pending.

## Earlier installed host and atomic state handoff

The current d4val round starts at 294d40c, including the public Health change
and its supervisor-applied formatting correction. INPUT-ADMISSION.md records
the eight shared CLI/service validators and containment admission transfer.
PUBLIC-HEALTH.md retains the first-frame exception and its regression cases;
HOST2-REPORT.md retains the earlier dispatch report. The shared API, identity,
assembly and other lanes remain read-only.
No Git staging, commit, merge or remote operation was performed. Candidate
runtime verification remains outstanding.

The installed Linux host, client and core receipt/object paths now have real
implementations. Their Linux runtime behavior is unmeasured in this lane.
The round remains incomplete and must not be accepted from static checks or
component suites. Acceptance requires the composed installed serve E2E to fail
on the base for its intended reason and pass on the candidate.

## Implemented paths

- The client loads protected bindings without following links, checks owners,
  modes, ancestors, compiled compatibility and executable digest, and pins the
  mapped service credentials. Calls share one serialized connection so a human
  session remains on its opening socket. Streams exclusively own their connections; a human stream takes the socket
  that opened its read session.
- NewServer validates the protected installed binding, executable and dedicated
  service identity. BindRuntime checks dependency identity and every incomplete
  effect, including unexpired claims, through the concrete store's private
  inventory. It restores the durable freeze before enabling admission.
  ServeInstalled enables Linux credentials, binds the socket,
  applies ownership/mode before listening, and preserves existing paths.
  Close cancels admission, connections and reconciliation, waits for registered
  workers and closes owned state only after a successful drain.
- ConnectionContext owns the peer handle and read authority. Transport reads one
  credential-pinned native frame before authentication. A first health request
  receives no Scope, uses only HealthSnapshot and closes after one response.
  Every other valid first method authenticates before dispatch; refusal closes
  the connection. Admission is bounded by kernel UID before reading; a successful
  authentication moves the slot to kernel UID plus verified containment. Every
  recvmsg fragment must contain exactly one matching SCM_CREDENTIALS tuple;
  missing/mixed/truncated controls and SCM_RIGHTS refuse. Received descriptors
  are closed. FrameContext retains exact input bytes.
- The dispatcher uses LookupReceipt, pending AwaitReceipt and ReserveRequest
  before module preflight. Handler failures commit a typed error receipt. Exact
  replies and snapshot/receipt LastSeq are returned after delivery authorization.
  The store rejects changed content under completed or pending keys and keeps
  the original reserved frame bytes.
- Immutable objects, upload begin/contiguous chunk/commit, digests, ownership and
  audience checks are implemented. BlobBegin, BlobChunk, BlobCommit and BlobRead
  use those ports. Human reads require a live retained session; mutation
  preflight may use its exact unconsumed operation proof. Worker scopes require
  a retained live launch/lease. Lane connections must match launch UID and
  containment; connector lifetimes are pinned independently by the transport.
- BeginRead opens a separate read-only SQLite transaction and pins its head.
  Generic typed projection writes have generation fences; proof, ticket,
  challenge, session, counter, approval and cancellation checks run under the
  writer boundary. IdentityCommit and decision SourceSeq are stamped from actual
  appended events. The closed internal emitter matrix is enforced by API
  preflight and the store's authority checks.
- Effect claim, expiry/reconciliation state and measured completion are retained.
  Current operation status is verified against effect outcomes, not just its
  mutable label. The host executes stop, initial helper allocation/preparation/
  release/abort and channel delivery/reconciliation paths. Unknown outcomes stay
  unknown; lost allocation/release/abort replies are not blindly repeated.
- Records and event reads filter before bounded pages. Canonical decisions are
  visible to lanes. Private human/ticket/secret/channel events are filtered from
  both snapshots and live frames. Delivery visibility uses recipient/sender
  records. Event cursors resume without Since, and selected end events must be
  newer than the original Since.
- Watchers retain queued frames before a producer error, emit one terminal frame,
  bound writes and producer collection, and have per-principal limits. Attach
  Initial is the snapshot; Next begins with the subsequent frame at index one.
- Service CLI adapters use ReadInput and the common InvokeRaw path. Mutation
  preparation already requires the caller's retained idempotency key. Health
  combines real store verification, binding/artifact/peer observations, listener
  state, route registration, active reconciliation and launcher probe results.
- FreezeDispatch persists an exact receipt and monotonic dispatch epoch with
  the retained deployment operation/phase and committed reason. It stops new
  request admission and effect claims and cancels retained watchdog targets.
  Existing reservations and claimed/capture completion can finish; completed
  replies and authorized reads remain available. Freeze failures retain the
  committed barrier. Thaw checks the retained receipt/epoch and executor
  availability before reopening. These paths have authored component controls,
  not measured installed deployment evidence.

## Typed incomplete paths and limits

| Path | Remaining work or reason |
| --- | --- |
| DrainDispatch | Waits for admitted requests and checks all retained reservations/incomplete effects, including claims. It still returns typed not_implemented for the missing measured capture/process inventory. No QuiescenceReceipt success is produced. Freeze/thaw have durable implementations; the whole deployment is unfinished. |
| Service.StoreRebuild | A frozen rebuild executor and its recovery/read-back handoff remain unavailable. DataWorker has no rebuild method. |
| Host Launch, Clean, Swap, Worker, Deliver, ApplyChange, Bootstrap, Upgrade, Migration and Rebuild effects | Their coordinator/executor handoffs are not wired here. Typed interfaces exist for some of these; this is also implementation backlog, not solely a contract problem. |
| Lost helper allocation/release/abort replies | The typed recovery surface cannot retrieve all measured receipts by causal effect, particularly when allocation lost the lease ID. |
| Store.OrgSnapshot, TemplateSources, Source, BriefingInput | Retained-source selection/history and briefing assembly remain unfinished. Resource kind/path selection needs agreement with the templates owner. |
| DecisionCandidates, ReserveGuidance, ClaimContinuation and StateWrites.Guidance | Authoritative candidate snapshots, reservation/claim transitions and guidance completion remain unfinished. Decision and retained turn/audit getters are implemented. |
| ChannelJob, MailForTurn and StateWrites.Deliveries | Complete delivery-job, turn and receipt projection transitions remain unfinished. Mail/channel/lease/relation getters and scoped lists are implemented. |
| Store.FrozenBackup | Backup projection and durable freeze recovery remain unfinished. DeploymentPlan lookup is implemented. |
| Child launch identity projection | Authentic parent-created/adopted event validation remains unfinished; child ancestry is refused. Root binding and prepared identity stamping are implemented. |
| Mutable org change events | ChangeRequest has no explicit mutable projection generation. These events still refuse pending a clarified CAS/version handoff. |
| Same event ID under a new reservation | Exact-event linkage to another receipt is deliberately unavailable. Changed bytes conflict; completed key replay works. |
| Content/vector/hybrid search, partial verification, nonempty outbox cursor | These remain typed not_implemented. Empty keyword metadata/exact-ID reads, all-store verification and the initial bounded outbox page are implemented. |
| Frozen deployment execution | New effect claims stop during a freeze, including deployment effects. Owning deployment phase persistence is permitted, but the coordinator's drain/stage/migration execution handoff is unfinished. |
| Darwin installed transport | Equivalent native per-message writer evidence is unavailable. Darwin compilation is supported; installed opening refuses rather than using connector-only identity. |
| Existing draft.3 state files | The expanded schema is verified exactly. No in-place migration is provided; old incompatible state is retained/refused. |
| General typed business transitions | The generic projection machinery does not establish that every lifecycle, grant, approval, delivery or deployment workflow is complete. Unimplemented paths must remain stopped. |

## Required Linux work

The source contains 98 component mutations in both tag variants, 196 targeted
red/candidate pairs and ten final package/tag suites including CLI. The runner
preflights every anchor and names the failing variant, mutation, stage, exit and
diagnostic on stdout. This inventory has not run in this lane.

```sh
bash e2e/v2/cases/service/run-mutations.sh --source /test/source --evidence /tmp/lb-v2-service-mut-r6
go test -race -count=1 ./...
go test -race -count=1 -tags laneboss_faults ./...
bash e2e/v2/cases/serve/run.sh --context /test/cases/serve/context.json --result /test/cases/serve/result.json
```

The supervisor supplies the exact composed source, installed artifact and
genuine enrolled caller on the disposable Linux machine. Do not run these on
the authoring Mac. The service case now drives installed upload/read, dropped
reply, observed record commit, controller restart, exact retry, changed-key
refusal and strict socket inputs. It still stops explicitly at the unresolved
receipt/outbox cardinality gate; boundary, watcher and outage rows remain
not_run. CONTRACT-GAPS.md assigns those dependencies and remaining case work.
REVIEW-RESPONSE.md maps every finding to code/tests or an explicit open reason.
