# Lifecycle integration status after fix 16

Fix 16 starts at `aa0419c`. The stop hang was a fixture invocation mismatch:
TestStopAtomicContext replaced Frame after ReserveRequest, so the original
operation belonged to a different invocation. The test now keeps the reserved
frame, verifies actual ownership and requires zero awaits plus the original
pending stop transaction. No deadline was shortened. AwaitReceipt checks caller
cancellation before reading, after its wait and before returning cached data.

LaneLoop persists the exact lane.loop setting and advances the life generation
under CAS. LoopDue reads that durable configuration after restart and enforces
the actual quiescent end/backoff. Due means eligibility, not an executed turn.
Draft.4 fix 13 now supplies the private Loop alternative. ReserveLoop requires
its API-bound scheduler scope and selects the actual setting/end; planning
retains the canonical cause and original resource pins. The installed scheduler
producer and durable native writer/dispatcher still need wiring. This module
does not relabel the scheduler as its previous lane requester.

LaneInput now commits a fixed channel Worker/WorkerLease and the original pending
Operation before IO. Dependencies.Input (or the Store InputControl facet) must
provide the protected immutable plan/original frame, current native channel and
idempotent WriteInput. ApplyInput checks current effect, life/epoch/channel,
current narrow grants, confined worker, exact bytes/resize, measured zero exit
and retained evidence. It does not open a caller-selected PTY/socket/path.

Attach reads actual registered capture events and committed raw objects. Signed
cursors bind service instance, config, actor, endpoint generation, target/mode,
capture generation, record and exact byte offset. An old service-instance cursor
refuses explicitly. Partial blobs never advance to the page end. Every delivery
reauthorizes, gaps remain errors, and end requires all committed stream EOFs.
The pinned ordinary binding snapshot is separate from the following stream's
index sequence, matching ResponseStream.Initial and the shared CLI convention.

RunInternal drains the authenticated job's exact registered pipes through the
private SupervisorBootstrap/SupervisorIngress capability installed with
WithSupervisor. It checks the native principal/peer/claim, retains exact raw
chunks, verifies each append acknowledgement and commits real EOFs. Read, sink,
acknowledgement and close failures remain failures with capture gaps where
needed. The installed process entry must bind that native bootstrap; a CLI
lease/label cannot supply authority. Missing wiring returns the service owner.

All new runtime/regression/RED claims remain pending Linux. These dependency
ports are explicit owner integration requests, not native acceptance results.

The earlier fix-14 round started at `a21ef7f`, containing lifecycle fix 13 and the shared follow-up
and shared draft.4 fix 11 contracts. Only lifecycle-owned files and this case
folder are authored here. No index writes or commits are part of this round.

The preview's service test passed a valid effect lease to an uninitialized
lifecycle.Service. Entry guards now return the lifecycle-owned typed dependency
failure before any store access. A zero/incomplete PlanLaunch request returns
invalid_request. Core readiness guards cover public authorization and internal
Continue/RevokeLaunch; planner tests remove each used port and require its
owner-named failure. No recover masks the supplied panic.

The dispatcher fixture now prepares and reserves every finalized public mutation
through ReserveRequest. Its protected ownership record identifies one invocation
frame, independent of request ID or connection; an identical same-connection
retry gets another frame and does not own it. Completion closes the actual wait
channel and removes ownership even when the replied operation's physical effect
is pending. Synthetic event staging does not reserve a public request.

Completed-reply assertions retain exact result equality, no observation/writes,
and no pending-ownership query. The obsolete single-read counter was replaced
with those contract boundaries: authorization and handler replay may both read
the receipt. Interactive tests keep their 50 ms deadline and require zero target
reads/writes while the life gate is held; an authorization receipt read is not
an interactive target access. Optional-empty input is reserved only after final
bytes and digest are prepared, preserving exact-key conflict semantics.

launchReplay now independently checks ownership for nil replies and awaits a
different invocation. Public commits without a dispatcher reservation return
integrity, and nonmutation public methods cannot publish an internal commit.
The retained-runtime test also observes attempted credential acquisition before
its existing named assertion: removing the early pin check may reach a later
runner refusal, but that does not excuse crossing the earlier boundary. The
plan-retained-runtime row/test/diagnostic and production pin checks are unchanged.

The fix-12 box reports green normal/faults unit suites, including all earlier
22 failures. Its check-generation mutation survived because the later state
decoder independently refused maxInteger+1 with integrity. That control now
changes the same early guard's error return to nil, reaching its original
named assertion. Product generation fences and the test expectation are intact.

The suspected first-execution self-wait has a pre-reserved stop/mark regression
fixture written before the product correction. Its AwaitReceipt blocks on the
actual committed-reply channel or a bounded context deadline. The test-first
source and unchanged product bytes are retained for Linux RED. No test ran on
the Mac, so the suspected installed behavior is not a measured canary result.

lookupReply now skips a nil reply only when the private MutationDispatch
capability confirms that this dispatcher invocation owns the actual pending
operation. A matching key, request ID, frame or source label does not establish
ownership. A distinct invocation carrying the identical request still awaits
the original receipt. Authorization performs that await before taking the life
gate; commit reuses the original reserved operation ID. Completed receipts keep
their existing current-authorization and exact historical-policy checks.

Exact remaining service wiring: supply lifecycle.Dependencies.Dispatch, or a
Store implementing the same private OwnsMutation(context.Context, api.Scope,
api.RequestKey, api.ID) (bool, error) capability. It must use the real atomic
dispatcher winner/current invocation, return false for concurrent/retried
observers, and preserve the original operation. Shared Scope/MutationReceipt
has no dispatcher retry/winner marker today. Missing capability is an explicit
lb-v2-service dependency failure rather than permission to execute or self-wait.
No public DTO, RPC or client-chosen marker is added.

Human root spawn now reads Store.Policy before launch availability and any
ReserveLaunch/TicketUse call. A stale authenticated generation returns conflict
without consuming the ticket or creating a launch reservation. Its test advances
policy after authentication and checks the exact original unredeemed ticket.

The grants owner's retained fix-11 source still requires the previous binding
and Lane grant ID to equal the new reservation ID, and requires stored grant
generation to equal current. Revalidate returns unchanged stored issuance and
also compares its generation with current policy. It therefore does not yet
implement fix 11's fresh retained-launch snapshot. Current checkout grants are
typed stubs. This is an owner compatibility dependency, not resolved by changing
an old object's generation/digest locally. The lifecycle D6 resume test requires
unchanged historical revalidation, a fresh current-policy resolved snapshot,
same private task state and unchanged original grant/binding bytes. The real
grants owner must implement that handoff; installed D6 continuation is pending.

The fix-11 Linux box reached the launch assertions and exposed two more fixture
wire-shape defects. Briefing.Sources, Checks and LaneGroups arrays were null,
so a capture-failure retry stopped while decoding the preceding briefing.
EffectivePolicy's required arrays were also null inside the refused plan's
committed launch.planned payload, stopping review before its capture gate.
Both fixtures now emit explicit empty arrays. Strict decoding and capture-error
retention remain unchanged. Refused review additionally checks that its actual
committed plan decodes and retains the same refused binding and policy.

The retained-run test now separates private session/home/workspace/budget
preservation from fix 11's fresh grant-snapshot identity. It requires the new
reserved current-policy grant set and unchanged prior grant/binding bytes.
The pre-planning retained-slot fixture resolves authority from the actual
claimed continuation and prior grants while checking the current life, base,
launch, policy and explicit cancellation fence. It never treats an absent new
grant snapshot as issued. Missing/changed epochs, cancelled intent, changed
launch and revoked grants refuse without producing a slot.

A malformed ReserveLaunch result is classified as integrity at lifecycle's
protected store-response boundary. The public request is already validated;
the caller supplies no parent IDs to repair. The parent test keeps its original
integrity expectation and requires this shared-validation boundary to decide.
Actual owning ReserveLaunch errors still propagate unchanged.

The internal-only row is unchanged. Its test now uses the private call shape
and observes actual operation-store reads, so a separate public-method guard
cannot mask deletion of the actor/source authorization gate. It preserves the
original forbidden expectation and named diagnostic while requiring refusal
before operation access. No production continuation gate was relaxed.

Earlier Linux failures stopped in fixture reservation before establishing
a cancellation fence. The seeded lane.created LaunchEvent serialized required
inventory and trigger arrays as null, so the closed decoder rejected it and the
starter scan left StarterEventSeq unset. The fixture now retains explicit empty
arrays and validates the seed immediately. It records CancellationEpoch as an
explicit map entry, distinguishes it from Lane.Generation and plan revision,
and synchronizes public committed cancellation updates from the retained Lane.
Missing and changed epochs still refuse; the production fence is unchanged.
The self-accept row, selected test and required forbidden assertion remain.
Its test additionally observes actual Lane reads, exposing a crossed early
independence gate even if a later receipt defense also returns forbidden.
These are static diagnoses and authored checks; Linux must still demonstrate
that every launch case reaches its own assertion and each mutation is killed.

The lifecycle launch-plan implementation now calls the real typed owner ports.
It does not supply a permissive replacement for another owner's stub. A public
pending Operation acknowledges the durable intent; a complete LaunchPlan is a
pre-execution plan. Neither proves that Prepare, identity binding, OpenGate or
an authenticated agent has run. Those composed paths and their Linux runtime
RED/GREEN evidence remain required.

1. **Initial launch plan and recovery: contract resolved; consumers pending.**
   LaneStart, LaneAdopt, LaneResume and LaneTurn authorize and validate the
   original request, then call StateStore.ReserveLaunch with its pending
   dispatcher OperationID. The fresh executor does not await its own nil reply.
   The handler reads back the exact retained pending reply, even if the live
   operation has already advanced. Retries reauthorize and replay that reply
   before changed preflight. The store issues the child/run/reservation IDs,
   consumes root-ticket or operation authority and owns name/life/epoch locks.

   Fix 10 supplies the closed reservation request validator and authority
   fields. Lifecycle submits exact TicketUse for a human root, cancellation
   and operation ProofUse for a retained human life, and no human proof for a
   lane. It compares the returned Authority and Level, Role and Driver pins
   with the authorized original request or retained life, then carries the
   reservation's pins to source, template and adapter selection. The store
   must consume and authenticate actual authority under its reservation lock.

   PlanLaunch requires the authentic service scope and current running
   EffectLease. It reloads Effect and LaunchPlan, checks claim ID, claimant,
   revision, expiry, causal requester/request/operation, target and epoch, then
   reads the original private service-origin launch_request bytes. Public
   inputs are decoded as their retained Request; Continue consumes the exact
   retained ContinuationRequest and matching claimed intent. Caller paths,
   executable choices and pre-resolved plans are absent from this port.

   The planner resolves and commits the reserved grants with CAS, revalidates
   current policy/grants and pins the actual admin sources at sourced. It
   records and claims HelperAllocate and retains its actual completion through
   CompleteEffect with read-back. For materialization it calls the actual
   DataWorker.MaterializeLaunch; service/outbox owns creation, scheduling,
   claiming and launching of that distinct child Worker. Lifecycle does not
   guess its stage/effect IDs, reuse agent grants, claim it as the planner or
   execute copy/Git as the service account.

   The retained LaunchDataStage is read from StateStore and shared-validated
   against the exact reservation, original parent effect, inputs, narrow
   source-only grants, fixed materialize argv, held-storage projection and
   agent lease. Lifecycle checks its actual worker lease and consumed worker
   LaunchRecord: its own worker principal, zero level/role, distinct nonzero
   UID and matching process/grants/runtime. The job budget cannot exceed the
   remaining task budget. Its real child Effect must retain successful known
   zero exit and zero survivors, and its worker_result output must be exact
   canonical LaunchData with the original operation provenance. Lifecycle
   reads that output and manifest and compares the returned data with it.
   A retained DataStageID with a missing stage refuses instead of allocating
   a replacement. An unfinished child remains containment_unknown for the
   owning outbox to await/reconcile; it is never completed by the planner.

   Exact remaining service/dataworker handoff: CompleteEffect.Output must
   reference the acknowledged canonical worker_result LaunchData and retain
   the correlated terminal Observation. Service/dataworker must independently
   validate LaunchDataResult, actual result acknowledgement and manifest
   read-back before that commit. The consumer does not turn fixture storage
   identities or process labels into native measurements.
   Template, guidance, credential, injection, runner and capture stages retain
   immutable input/result journals under the original plan claim. Missing
   outcomes refuse as containment_unknown; they do not license another slot,
   producer, workspace or private home. Helper/worker reconciliation uses the
   same original stage IDs and owner journals.

   LaunchData must match the reserved life/run/lease/source and measured
   materialization. The logical cwd is /work/main and branch is lane/<LifeID>.
   The enrolled adapter receives the exact private home, session, prompt,
   profile slot, executable and budget. Retained runs preserve workspace/home/
   history/session and refuse changed runtime or project pins without an
   explicit migration. Adoption preserves the imported vendor identity while
   using the helper's newly allocated private storage IDs.

   The complete measured plan and explicit capture disposition precede the
   canonical private launch_spec bytes. The spec_retained record contains the
   full PreparedSpecHandoff, and an immutable recovery journal contains PlanID,
   OriginalRequest, handoff, private home and capture. Restart rechecks original
   allocation/data receipts, registered storage, prompt/manifests and capture;
   bound/opened recovery requires the actual complete LaunchBinding and
   ValidateLaunchBindingPlan. Missing bindings never become legacy launches.
   A per-reservation gate does not hold the manual-control life gate across a
   worker wait. Store cancellation guards remain authoritative.

   Current owning dependencies are lb-v2-service/store ReserveLaunch,
   LaunchPlan, Effect/ClaimEffect/CompleteEffect, Transact/RetainObject and
   LaunchBinding, LaunchDataStage and the service MaterializationControl;
   lb-v2-grants Resolve/Revalidate/MaterializeLaunch;
   lb-v2-admin ResolveLaunchSources, Helper.Allocate, ResolveLaunchStorage and
   CaptureControl; templates/guidance, secrets and both actual D8 adapters.
   Their typed not_implemented results propagate. After plan completion, the
   service must execute its real post-spec helper stages, atomically commit
   the exact prepared identity/recovery plus ready Lane/TurnSnapshot, obtain
   the matching permit and reconcile that one gate. Lifecycle never fabricates
   those prepared, identity, process or permit receipts.

   Fix 10 also requires Kind=agent, the valid bound LaunchPlan, complete
   IdentityBinding and ready Lane in one helper_prepare transaction even if
   the producer omits LaunchPlans. The lifecycle fixtures supply that complete
   transaction, with sequence and IdentityCommit derived by the fixture store
   from the actual staged identity event under the same lock. Recovery calls
   ValidateLaunchBindingPlan. The installed service, identity and store must
   implement the corresponding commit; fixture success cannot establish it.

2. **Human proofs and tickets: contract resolved; store handoff required.**
   Root start/adopt require the installed human endpoint and a current unused
   ticket bound to principal / config / endpoint / level / role / grants. The store must
   atomically consume that ticket with ReserveLaunch, exactly once. Lifecycle
   does not consume it ahead of reservation or infer authority from an ID.
   Mark/stop/check keep their exact proof and cancellation guards. Receipt
   metadata binds config, method/key/digest and authentic principal/life; no
   active configuration or caller binding is changed.

3. **Outside capture: minimum start contract resolved; installed job pending.**
   The planner commits the narrow capture WorkerLease before calling
   the actual RegisterCapture. It validates the complete reservation/helper/
   worker / operation / request / requester / producer / stream disposition and commits
   capture.bound or the helper's explicit capture.refused with launch.planned.
   A typed helper error is never converted into refusal/discard. Authentication,
   integrity and unknown ownership stop the plan. Failure to retain a producer
   error returns both the original owning error and the retention failure.

   Registered capture recovery calls the real ReconcileCapture and refuses a
   changed producer or pipe. Refused has no producer, streams, primary records
   or complete coverage claim. Explicit refused capture blocks new independent
   review and accepted/merged marking even when a later receipt claims complete
   coverage. It also blocks capture-dependent continuation before reservation.
   Refusal is disabled by default. Lifecycle calls ValidateCapturePolicy with
   protected current D6 policy, retains its generation and approval snapshot in
   the refused plan, and rechecks it on recovery and before returning the final
   handoff. The policy publisher and release consumer must authenticate the
   actual consumed D6 approval and recheck revocation at the real gate opening.
   Lifecycle does not turn an approval ID into that provenance.
   LaneCheck preserves actual exit/signal and
   capture gaps, and never invents EOF at process end. CapturePipe keeps exact
   acknowledged ranges and reports read/sink/close/cancellation failures.

   RunInternal now executes the registered drain through a process-bound
   SupervisorBootstrap and SupervisorIngress. The installed CLI/process entry
   must supply the actual authenticated endpoint, native worker/peer/claim,
   protected inherited pipe/spool handles and durable append/gap methods. A
   missing native binding remains an owning service failure. argv, an fd number
   or a lane label cannot create that capability. Fix 9's registration/offset/
   EOF contract is retained. Input transport uses InputControl; independent live
   vendor tool/session/limit interpretation still needs LP-CAPTURE-IO-1 evidence.

4. **Outbox and stop: contract resolved; physical execution pending.**
   LaneStop commits stopping, the advanced cancellation epoch, pending reply
   and correlated Stop effect before physical work. Actual stop, capture drain,
   injection revocation, independent zero-survivor observation and lease
   collection belong to the service/helper/secrets consumers.

   Lifecycle's private RevokeLaunch stage requires the authentic current
   original Stop EffectLease, current life/epoch and actual retained binding.
   It atomically commits the revoked binding and endpoint plus the real
   identity.revoked event under that original cause, with life/endpoint CAS and
   a cancellation guard. It validates the causal LaunchRevocation read-back
   and current revoked record before calling identity's existing ID-only
   RevokeLaunch. Identity must validate actual transport close counts; a close
   error leaves the same original Stop effect pending for retry. Revocation
   neither stops a process nor completes/collects the Stop effect.

   Exact remaining service/store wiring: invoke this private lifecycle stage
   from the original Stop outbox claim and implement the protected
   RevocationEndpoint(context.Context, api.Scope, api.ID)
   (api.EndpointProjection, error) store read. The shared API currently has no
   endpoint-projection getter. Missing support returns the typed service
   dependency; a request/socket label is never used as a substitute. Store
   must retain LaunchRevocation from the actual committed event/cause and
   identity/service must perform the real bound-connection and pending-stream
   close and validate its zero-completion receipt, including old generations.
   Assembly's transport binder and the native boundaries remain owner work.

   A new run can read a revoked prior run's private history through its actual
   immutable identity.bound event and matching causal revocation. The original
   record must differ only in its revoked projection. This read does not
   rewrite the live binding/endpoint or authorize reopening it.
   Failed and unknown end observations remain failures; a log or successful
   planner result is not quiescence. The service must complete the original
   PlanLaunch effect with its actual measured plan or owning error and preserve
   the pending public reply. No competing full Launch is enqueued by lifecycle.

5. **Independent review: schema resolved; exact service preparation request.**
   Fix 10 supplies ReviewSubject, ReviewEvidence, the closed complete, partial,
   unsupported and missing values, ReviewVerifier and both shared validators.
   The earlier coverage-schema request is closed. LaneReview calls the real
   ReviewVerifier with a read-back retained WorkerLease and exact subject input,
   bound to the original pending dispatcher operation. It authenticates the
   ended run and end event, retained CaptureState binding, streams, offsets and
   actual EOF; reads snapshot, diff, checks, inventory, tools and resolutions;
   checks object provenance and actual test-worker operations; and calls
   ValidateReviewAcceptance for a complete result. The exact service-issued
   receipt is committed with lane.reviewed and the original reply. Partial
   evidence can be retained and replayed but cannot authorize acceptance.
   The life gate is released during verification and current authorization,
   generation, cancellation, end and frozen context are checked again afterward.

   Exact remaining request to lb-v2-service and lb-v2-grants: bind the Go-only
   lifecycle.ReviewControl integration handoff. PrepareReview(ctx, Scope,
   ReviewRequest, Generation, endEventID, endSeq) returns ReviewVerifyRequest;
   ResolveReview(ctx, Scope, LifeRef) returns the current frozen ReviewSubject
   and protected required-check names. Preparation must use the existing
   service-only object and fixed test/export worker path under the exact
   pending lane.review operation. Resolution must derive the post-run snapshot,
   drained capture, inventory sequence and authenticated refusal facts from
   retained state and actual sources; required checks come from protected
   current project/policy. The public request supplies none of that authority.
   A Store implementing those exact methods is recognized at construction;
   otherwise assembly must supply Dependencies.ReviewControl. The shared API
   currently provides neither this preparation handoff nor a protected required
   check selector. The local interface records the needed integration without
   adding public write authority or relabelling the caller as a service.

   Missing preparation returns lb-v2-service's typed `installed review subject
   and worker preparation`; a missing real verifier returns lb-v2-grants's
   ReviewVerifier error. Assembly supplies Review but does not yet implement
   ReviewControl. LaneMark rereads the actual evidence and current subject and
   requirements, verifies the exact stored receipt, then calls the shared
   acceptance validator. Historical receipts without Evidence, changed runs,
   ends or snapshots, failed checks, gaps, missing EOF and unresolved refusals
   cannot authorize a new acceptance. No installed-service review pass is claimed.

6. **Archive and owned cleanup: lifecycle composition; native wiring pending.**
   Fix 15 added the private ArchiveControl reservation/read-back handoff and
   OwnedCollector completion stage. Archive waits outside the life gate and
   validates actual worker/chunk/read-back/event evidence. Clean commits a
   pending Clean effect; CollectClean sets Cleaned and emits lane.cleaned only
   after an owned removal/retention receipt. Service must implement the atomic
   archive handoff/completion and dispatch CollectClean. Grants/data ownership
   must supply unforced dirty/unowned-safe removal with native journal recovery.
   These ports are not implemented by a permissive local fallback. Launcher.Collect
   alone still cannot attest workspace/branch deletion. Installed acceptance
   remains pending both producer wiring and real Linux observations.

7. **Turns and delivery: composition implemented; observation still required.**
   Task, actual rendered briefing, selected guidance/source bytes, complete
   UTF-8 follow-up/idle input and authenticated ordered mail are composed into
   one private prompt. MailForTurn must return the exact lease-bound IDs,
   sender, recipient, logical turn and causal sequences. Preparation never
   acknowledges mail. Real prompt observation and RecordDelivery remain with
   messaging/capture/service. The service must publish the matching ready
   TurnSnapshot from these retained inputs at the real helper binding stage.

   Continue reuses the prior TurnSnapshot's exact prompt and guidance choice;
   it neither selects again nor acknowledges mail at a profile-limit exit.
   New public resume/turn reservations retain their authentic manual/scheduler
   requester separately from carried senders.

   Exact assembly request: construct the existing messaging service before
   lifecycle and pass it as lifecycle.Dependencies.Delivery. Messaging has no
   lifecycle construction dependency. BeginDelivery is called through that
   actual port; a missing binding returns lb-v2-messaging's typed error. This
   is an implementation wiring dependency and adds no public command or DTO.

8. **Current policy and quota continuation: fix-11 rule adopted.**
   The exact sentence governing old issuance is: "A new launch resolves a fresh
   reserved grant-set snapshot at current policy; it does not compare the previous
   run's historical issuance generation to current and stop there."
   Generation-1 issuance survives a generation-2 policy advance and projection
   refresh. A fresh resumed reservation resolves a distinct generation-2 set;
   prior grant/binding bytes remain unchanged. Equality in resumeReady against
   that prior generation-1 set would stop before the new snapshot can be issued.
   TestPolicyFreshFence preserves this case; TestFreshReservedGrantPolicy refuses
   a stale newly reserved snapshot before allocation. Neither permits a fresh
   unopened plan under an old authenticated scope or old current-policy snapshot.
   Fresh start/adopt/resume/turn/continuation uses current approved policy.
   After receipt lookup proves fresh work, lifecycle calls the protected
   RefreshLanePolicy coordinator before taking launch fences, shared-validates
   the advance and reads back the exact retained Lane. The store must update
   only that policy projection and Lane.Generation with one lane.policy event
   under life CAS/epoch. A submitted stale generation or proof base legitimately
   conflicts after refresh and must be reloaded. Historical GrantSet issuance
   need not equal current generation: actual current authority, expiry and
   revocation are still revalidated. Fresh reservations resolve a new current
   grant snapshot without rewriting historical grant or launch bytes.

   Exact receipts choose their retained PolicyGeneration through
   PolicyGenerationForReplay and the actual protected PolicyAt history after
   current authorization. Existing continuation selection/prompt uses its
   retained turn generation while the new launch binds current policy. Unknown,
   future or foreign history refuses. A policy change after sealing an unopened
   plan fails ValidateLaunchPolicyCurrent; service must reconcile/abort that
   immutable plan and retain the failed receipt before a fresh authorized
   reservation. Already-opened reconciliation uses the historical binding
   with current control rights and no fresh allocation, slot or selection.
   The named continuation-epoch assertion and control remain intact.

   Policy/store, identity, watchdog, grants and the native opening gate must
   implement the same rule. The lifecycle fixtures model approved history and
   actual projection/event updates, but do not measure installed D6-mid-run
   authorization, selection, continuation or opening.

   Continue compares its sole Swap fence with the durable intent/life under
   the per-life gate, checks provider / driver / model / history / eligibility, profile
   expiry/exclusions and remaining spend, then calls ReserveLaunch with the
   exact ContinuationID. The store owns the atomic claim/reservation handoff.
   The plan consumes that claimed intent and the same logical turn. A retained
   slot is reused; a new slot is durably journaled before release. No paid
   fallback, budget/counter reset or new history is introduced. Registered
   capture is required for capture-dependent continuation; unsupported actual
   vendor interpretation stays with LP-CAPTURE-IO-1 and its owning adapter.
   ValidateContinuationOperation now checks the one store-stamped operation
   across intent, swap and result. Pending and running return the same retained
   operation; completed replays its succeeded result without a new reservation
   or slot. Waiting, cancelled and inconsistent results refuse. Replay rereads
   the operation and intent and checks current cancellation, grants and capture.

9. **Streaming and remaining physical gates.**
   Initial snapshot/lifetime, selected-event filtering, saved sequence,
   revocation, cursor progress, bounded frames and separate stream end checks
   remain. Store.Events still supplies only a page-end cursor; exact attach
   now has a scoped signed capture-range cursor in lifecycle. Input uses the
   protected channel-worker handoff; its native control remains owner wiring.
   Fixture watcher timing is not twenty-agent production latency.

10. **Check state event: contract request resolved.**
    Fix 10 permits lane.state in lane.check's public write row. Lifecycle now
    commits run.observed, measured lane.ended, explicit lane.state and the
    verifying projection with generation advanced once, under the same life
    CAS and cancellation guard. All events carry the actual observation time
    and original requester. No extra public method or emitter authority is added.

The mutation catalog retains all prior controls and has 430 guard rows after
the 34 fix-16 additions, two fix-17 retained-target regressions and 43 fix-18
review/worker/cleanup/attach/replay regressions, plus 21 fix-19 shared-state,
policy-fence, turn and credential-recovery controls, 29 fix-21 counted-review
controls and 29 fix-23 recovery/cleanup controls. The fix-17 controls
restore the incorrect first-run-only replay rule and select the unchanged
start/adopt assertions from TestReplayBeforeChangedState. The requested private
scheduler authority is specified in internal/v2/lifecycle/CONTRACT-GAPS.md.
Fix 18 accepts a wholly unassigned pending verifier operation only during its
original lane.review path, checks archive grant expiry and the retained worker
completion, rechecks input claims immediately before writes, and validates
worker observations and separate principals. Clean replay independently reads
the committed end, verified structured archive and full retained-object
inventory. Attach drains remaining event pages before EOF and uses the current
lane projection. Typed and stale operation replay both require the exact
requested run; archive replay validates its complete receipt metadata.
Fix 19 adopts the shared effect-state vocabulary and validates child state
against outcome on completion and replay. Bound recovery reads the protected
credential projection through identity and the store; assembly retains the
single helper binding. The fixture writer binds the locked approved policy
head for prepare/open, and turn emission requires its actual logical ID.
plan-retained-home keeps its original catalog edit/test/assertion and now
observes credential access before a later refusal can mask that boundary.
Static compilation and named Linux runtime RED/GREEN remain
separate requirements. Its 10 physical acceptance rows remain blocked. Ported controls use the
deciding current gates; their original names and intended assertions are retained.
Each executable row names the exact source edit, focused test and required
assertion. Compile errors, panics, unrelated failures and surviving mutations
are not RED evidence.

New positive fixture cases issue reservations from retained frames, resolve
protected enrollment, journal allocations and derive measured data/runner/
capture results from their actual selectors. They cover both drivers and both
capture dispositions, adoption, resume, turn, continuation, interrupted
allocation acknowledgement and restart after a prepared binding. They do not
prove real helper/kernel/Git/credential/vendor behavior. Runtime RED/GREEN and
LIFECYCLE-TREE/OS-LINUX/installed serve acceptance remain unmeasured here.

On the authorized Ubuntu box, from the exact candidate bytes, run:

```sh
go test -count=1 ./internal/v2/lifecycle
go test -race -count=1 ./internal/v2/lifecycle
go test -tags laneboss_faults -count=1 ./internal/v2/lifecycle
go test -count=1 ./e2e/v2/cases/lifecycle
python3 e2e/v2/cases/lifecycle/red.py --source . --suite guards --evidence /tmp/lb-lifecycle-f11-red
python3 e2e/v2/cases/lifecycle/red.py --source . --suite guards --faults --evidence /tmp/lb-lifecycle-f11-faults
python3 e2e/v2/cases/lifecycle/run.py --plan /tmp/lb-plan.json --evidence /tmp/lb-lifecycle-f11-tree
```

Use fresh evidence directories. The focused mutation runner must reach and fail
each named assertion, then pass the unchanged packages. Default all remains
69/incomplete for blocked physical rows. The composed case must not emit
PASS: LIFECYCLE-TREE until every actual dependency, adapter and physical control
passes. This is not an authenticated AI-service test. The supervisor owns Linux
execution, any staging and the publication scan; this executor
does not run models, remote commands, binaries, builds, tests or Git index writes.

Fix-21 cleanup integration is part of the service/outbox work in item 4.
Lifecycle supplies FailedPlanStore.FailPlan with the terminal plan transaction
and original withdrawal or release/injection-revoke requests. The existing
single writer must atomically retain both and dispatch the real broker/helper
cleanup, with no collection before measured quiescence. The production store
does not implement this shared api.FailedPlanStore port, so the native failed-plan leak
finding remains open. The exact request is in the product CONTRACT-GAPS.md.
All new fixture, opened-history and effect-transition regressions still need
named Linux RED/GREEN; static source checks cannot close native rows.

Fix 23 keeps the recovery pins and requests an explicit shared bound-write
validator obligation: Workspace, LogicalTurnID and PolicyGeneration must be
committed with the matching TurnSnapshot at prepare. The local fixture writer
enforces those pins; this does not implement the production shared validator.
The original resource journal survives transient errors, and terminal cleanup
retains input-only, carried and planned slot evidence. Historical projection
checks correlate original receipts and fences without granting a fresh permit.
The current catalog has 441 guard rows, 366 distinct edits and ten blocked
physical rows; native owner wiring and named runtime assertions remain required.
Fix 26 applies the strict shared failure-batch preflight: without a real slot
result, the original phase and resource journal remain until actual producer
reconciliation. No fake result is added to obtain a cleanup commit.
