# LIFECYCLE-TREE

The discoverable entry is `run.sh --context CONTEXT --result RESULT` using
`case.json` and the frozen harness contract. It consumes the actual authenticated
`test_root/plan.json` and an outside collection command, retains incomplete
prerequisites as typed waits, and independently reads collected records before
setting collection flags. The direct plan/evidence entry below remains supported.
See [ITEM-3-HANDOFF.md](ITEM-3-HANDOFF.md) for the supplied workload, collector,
mail hooks, owner-in-person waits and remaining installed acceptance gates.

Fix 16 starts at aa0419c. The stop regression keeps its original reserved
invocation frame; receipt cancellation tests use real cancellation notifications,
not a reduced suite timeout. Input now queues a fixed channel-worker intent,
loop configuration persists with a life CAS, attach streams registered raw
capture with scoped exact-range cursors, and the internal supervisor drains its
authenticated native job's actual pipes. Native InputControl/bootstrap wiring,
automatic scheduler dispatch and installed acceptance remain explicit owner
integration work in CONTRACT-GAPS.md. No unit fixture closes those rows.

Fix 21 adds counted-review regressions for atomic failed-plan cleanup requests,
one effect transition table used by writer fixtures, partial-bind and actual
prepare-effect integrity, opened withdrawal history, and lane/turn/resource
recovery. The prepared fixture retains its API-private policy fence. There
are 441 guards and ten blocked physical rows. Native cleanup still requires
service/store to implement the shared api.FailedPlanStore atomic writer/outbox
port; absence is an explicit failure. Runtime results remain pending Linux.

Fix 23 adds 29 controls for strict prepared-gate lookup, prepare projection
pins, transient reconciliation, retained resource evidence, historical holding
proof, cleanup authority, credential-stage replay and entry claim provenance.
The current catalog has 366 distinct source edits. The capture recovery test calls the
existing configured CaptureControl; no success-only fixture adapter is added.
The production shared prepare validator remains an integrate request, and
runtime RED/GREEN remains required for the new controls and regressions.

Fix 26 adopts the shared draft.4 fix 13 cleanup types and strict atomic
preflight. A missing real slot-result receipt preserves the prior plan and
allocation until producer reconciliation; the fixture does not invent a
receipt or weaken the validator. The private ReserveLoop entry requires the
installed scheduler scope and exact setting/end selectors, and planning reads
the canonical loop manifest while preserving new-turn and resource pins.
The model tests cover reservation/replay/refusal and planner/open audit;
native scheduler identity, durable dispatch and cleanup completion remain
owner integrations. Eleven added controls still require named Linux RED/GREEN.

This case runs from outside the installed service on a disposable Ubuntu
24.04 box. It uses only the public CLI and its JSON results. It must fail on
the scaffold; a dependency error, timeout, incomplete operation, absent
evidence or absent fixture is a failure, never a skip.

Run `python3 e2e/v2/cases/lifecycle/run.py --plan PLAN --evidence DIR`.
The integration harness supplies PLAN after installing the exact candidate,
creating authenticated actors and uploading the real input files through the
blob API. No login material belongs in PLAN or the evidence directory.

PLAN is a JSON object with these fields:

- `config`: the isolated test configuration.
- `actors`: `parent`, `executor`, `reviewer`, `sender` and `sibling` are argv
  prefixes which execute the installed CLI inside each actor's actual
  service-created containment. `observer` is an outside authenticated human
  transport with its genuine same-connection read session, able to observe both
  independent starter trees. Keep that observer available through collection
  read-back. These are test transport wrappers, not agent drivers. The `executor`
  prefix additionally accepts
  `--life ID --run N --`, then executes the CLI in that actual live run.
  The case verifies its identity during run 3, before stopping it. A socket
  name, environment label or UID alone
  must not impersonate an actor. The case checks `identity self` first.
  The transport stages each exact request file into that actor's readable
  client-input area; it cannot grant access to the controller's host directory.
- `start`: a complete StartRequest with an uploaded task, explicit grants,
  budget, production driver and expected policy generation. The task must
  complete run 1, complete the resumed run, and hold the mail-triggered run
  until stopped. Both actual adapters must be exercised in separate runs of
  this case. Credential-free fixtures are wiring evidence only.
- `message`: a committed task BlobRef for the resume input.
- `reason`: a committed task BlobRef for stopping the held run.
- `mail`: a MailSendRequest without `recipient_life_id`; its real content
  asks the held run to spawn a double-forked, setsid child. The harness's
  outside observer must identify that child before stop.
- `self_review`: a ReviewRequest without `target`, used for the live
  executor's malicious self-review/self-acceptance probes. Its input objects
  must exist; they confer no review authority.
- `prepare_review`: an argv command for the trusted, confined fixture
  evidence worker. After stop, it accepts `--life ID --run N` and returns a
  ReviewRequest with actual diff/check/inventory references for that ended
  workspace. A text file saying passed cannot substitute for these receipts.
- `idle_message`: a committed task BlobRef.
- `controls`: request objects for `archive_failure`, `dirty_clean`,
  `unowned_clean`, `unknown_resume`, `gate_failure`, `hidden_tail` and
  `observed_tail`. Each contains `actor`, `method`, `params` and nonempty
  `codes`, the expected typed refusal codes. The harness prepares the real
  failed read-back, modified work, unowned object, unknown observation,
  unavailable launch prerequisite, sibling selection and observation-only
  end conditions. It must not manufacture service-origin lifecycle events.
- `observe`: an argv command for the outside canary observer. It accepts
  `--phase before-stop|after-stop|after-clean --life ID --run N` and returns JSON with
  `child_seen`, `survivors` and `containment_known`. It examines actual OS
  processes, not service database internals. `after-clean` instead returns
  `workspace_present`, `branch_present`, `records_present` and
  `archive_readback_ok`, from actual disposable objects and archive content.
- `verify_control`: an argv command for independent negative-control
  preservation checks. It accepts `--name CONTROL --phase before|after` and
  returns `ready`, a nonempty `objects` map of scoped actual object identities
  to content hashes, and the fixture's actual `launch_count`. It must inspect
  disposable Git/data/process canaries, not service database internals. The
  two maps and counts must match after refusal, even if CLI state looks intact.
- `load`: twenty real LifeRef objects in two concurrently active starter
  trees. The main test life is additional. The harness maintains healthy
  load until the case finishes.
- `timing`: an argv command for the outside service commit observer. Given
  `--life ID --run N --seq N`, it returns `commit_monotonic_ns` from the
  actual durable commit. It must share the case's monotonic clock domain.
  Wall clock event timestamps cannot stand in for this measurement.

The case retains every request, request/key correlation, stdout, stderr, exit code and the follow
receive/commit measurements. It observes start → end → resume (run 2) →
mail turn → stop → independent review → accepted → merged → archive →
clean, then refuses cleaned resume. Manual turn actor must equal the
requester and differ from the carried sender. A selected old run, hidden
sibling end or observation cannot satisfy the selected follow.

Required mutation runs use the identical plan and inputs on separate
disposable configurations: remove actor selection, tree filtering, the
nonexecuting launch gate or receipt-before-delete checks. Each mutated run
must fail this case. The harness also places an older end before the saved
sequence and emits unrelated/observation events while follow is active.
Read-back failure must preserve the work; dirty/unowned removal must refuse;
unknown containment must preserve leases. The OS observer is an independent
check of detached-child containment, including after stop.

The installed CLI targets draft.4 fix 11 and uses common `--request`, `--request-id` and
`--idempotency-key` options. Actor transports must preserve those exact options.
Follow stdout is JSONL: one typed EventPage initial snapshot, then correlated,
consecutively indexed StreamFrames ending in a separate real end frame. The
case rejects lost/repeated snapshots, leaked event selections, changed request
IDs and EOF without end. Blob reads also check an actual empty range at EOF.
Status and follow exercise the ergonomic flag handlers; the first quiescent
status is also compared with its exact request-file form. Each request and
its selected input form are retained. The CLI delegates all transport and
human-read session setup to the common Invocation, sharing its socket through
uploads and the final call. A supplied Client remains borrowed.
All 16 lifecycle methods register a shared semantic validator at initialization.
Invalid request-file values return lifecycle's invalid_request before proof,
key or socket work. The per-method valid-file controls require an explicit
foreign-owner binding/transport refusal: prerequisite_missing, unavailable or
unauthenticated. They do not pin another module's not_implemented message.
Mutations require an explicit retained idempotency key; upload begin, each
offset and commit derive stable subkeys from it. Existing operation proofs
require precommitted input references via the exact request-file form.

Lane outputs must include Task / LaunchID / CancellationEpoch / Counters and
Session.HistoryID. Load is twenty distinct running lives in at least two
authentic starter trees.

Full runtime dependencies are service/store/client, identity, admin, Linux,
grants/data worker, secrets, both runners, templates/guidance and assembly.
Draft.4 supplies general receipts, proof/ticket guards, effect completion,
object metadata, own-life briefing, continuation and delivery interfaces. Remaining
contract requests and unfinished implementations are distinguished in
[CONTRACT-GAPS.md](CONTRACT-GAPS.md). The case does not claim those dependencies
ran. Do not run it on a development Mac.

Use `--control NAME` (repeatable) to exercise just prepared negative fixtures
without starting the full lifecycle flow. It still requires the actual
authenticated CLI and outside preservation observer. A missing implementation
code cannot satisfy a refusal control. A focused PASS line says full acceptance
was not run; only the full scenario emits `PASS: LIFECYCLE-TREE`.

[MUTATIONS.md](MUTATIONS.md) contains the named rule/mutation/test matrix.
`red.py --suite guards` has 441 prepared controls, retaining every earlier
control. It runs one source mutation per disposable copy, reports
the exact failed test and assertion, then runs the unmodified focused packages.
Surviving mutations are retained in summary.json with their IDs and reasons;
the runner continues through every selected guard and exits 1 if any survived.
Build failures, missing named tests, panics and unfinished tests remain fatal
invalid evidence. A survivor never produces a PASS, even if baseline tests pass.
It retains source manifests, before/after bytes, JSON test output and exit data.
Default `--suite all` includes ten production rows blocked by contracts or implementations
and exits 69/incomplete; no skipped row is promoted to a pass. The runner only
executes on Linux. Source-level namespace/catalog tests are fixture checks,
not black-box acceptance evidence. Evidence and copied source/test directories
used by production privacy checks are created private (0700). CLI fixture tests
use an existing configuration binding when present, without changing it.

On the authorized Linux box, run the runner's unit regressions with
`python3 -m unittest discover -s e2e/v2/cases/lifecycle -p test_red.py -v`.
They feed explicit Go JSON histories into the real aggregation path and check
all selected rows, survivor reasons, nonzero exit, unchanged baseline gating,
fatal build/missing-test evidence and the actual retained mutation bytes.
These are runner tests; the real Go mutation run still establishes named RED.

The planner resolves only store-issued reservations. Its fixture cases cover
both drivers, registered/refused capture, exact pending replies, adoption,
retained private edits/history, current claims/policy/grants, ordered mail and
guidance source bytes, child failure receipts and restart with complete bindings.
These are dependency fixture checks, not installed agent or kernel evidence.
Fix 10 adds authority and reserved-role pins, same-transaction prepared bindings,
an explicit natural state event, current D6 capture gating, one continuation
operation, and the verifier-backed review path. Review reads actual object
bytes, retained worker operations and primary capture positions. Complete
evidence uses the shared acceptance validator; partial evidence remains visible
without authorizing acceptance. The installed service still must implement the
subject and job preparation described in CONTRACT-GAPS item 5. The 49 added
controls and every earlier deciding assertion still require Linux runtime
RED/GREEN; static vet does not provide that evidence.

Fix 11 repairs the starter fixture's closed event encoding and explicit epoch
tracking without weakening production fences. The self-accept mutation row
is unchanged; its test also checks that the early refusal precedes actual
target-store reads. Fresh launches refresh the live Lane policy projection
and resolve current grants, while exact receipts and retained turn selections
read their actual approved historical snapshots. Sealed unopened plans still
refuse policy drift; opened reconciliation preserves its authenticated binding.

Materialization uses the service-owned retained child stage, its narrow fixed
worker and actual completion bytes/observation. The private Stop revocation
stage commits the causal binding/endpoint decision before identity closes
transport and preserves incomplete closes for retry. Protected endpoint reads,
Stop outbox invocation, real materialization execution and native worker/close
implementations remain integration dependencies listed in CONTRACT-GAPS.
The 30 new guards and 193 retained guards span 191 distinct source forms,
statically vetted in normal and faults Linux targets. No runtime mutation,
installed-service, physical-presence or authenticated model acceptance is
claimed from these Mac checks.

The fix-12 box corrections initialize the briefing and refused-policy fixture
arrays required by the closed wire schema, so replay reaches the original
capture error and refused review reaches its capture gate. Retained-run checks
preserve private task state while requiring a fresh current-policy grant set
and immutable prior authority. A retained watchdog slot uses its actual claimed
intent and prior grants before fresh issuance, with exact life/epoch fences.
Malformed protected reservation responses are integrity failures. The unchanged
internal-only mutation now observes that its early refusal precedes operation
reads using the private call shape. The additional classification control makes
224 guards and 192 source forms; every runtime assertion still needs Linux.

The fix-13 delta adds explicit private dispatcher ownership for pending receipts.
An owning fresh invocation proceeds; a different invocation awaits before a
life gate even with an identical request ID. The original reserved operation
is reused. Service must supply MutationDispatch through Dependencies.Dispatch
or the protected store facet; shared DTOs have no winner/retry marker. Missing
support fails explicitly. The pre-reserved stop/mark regression was written
first and its old-source bytes retained, but runtime RED remains unmeasured.
Human root launches now check current policy before ticket reservation. The
grants owner's retained source still needs the fix-11 fresh snapshot adaptation;
historical grant bytes and the new-plan current-policy fence remain intact.
There are 229 guards and 197 source forms, with five new dispatch/root controls.
The retained check-generation row now changes its deciding error return to nil;
deleting the guard was masked by the later exact-integer decoder. Its original
test and expected assertion remain, and production generation checks are intact.

Fix 14 rejects an uninitialized planner and zero effect lease with typed errors
before dependency dereference. The dispatcher fixture reserves finalized public
requests and distinguishes invocation ownership from connection/request identity.
Completed replies keep their exact result and never query pending ownership.
Interactive serialization retains its 50 ms bound and observes actual target
access/writes. Direct launch replay now awaits other invocations; a public commit
requires its existing reservation. The retained-runtime assertion observes the
early credential boundary despite a later runner refusal. Seven new controls
make 236 guards and 204 source forms; runtime assertions still require Linux.
