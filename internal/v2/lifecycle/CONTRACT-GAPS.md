# Automatic loop-turn reservation request

To: lb-v2-integrate

Status: the shared contract is adopted by lifecycle. The Linux installed
producer, private durable reservation writer and host scheduler loop are now
implemented; full native automatic prepare/open acceptance remains open.
The numbered requirements below retain the original integration obligations.
No public RPC or permission to act as a lane is added.

`LaneLoop` durably records the authenticated `lane.loop` setting and advances
the lane generation under its existing transaction fences. `LoopDue` reads
that setting across runs and checks the committed quiescent end and backoff.
Its result is eligibility only; it does not reserve or dispatch a turn.

`ReserveLoop` now requires a scope privately bound by `api.BindSchedulerScope`,
selects actual setting/end IDs and calls `StateStore.ReserveLaunch` with only
the shared Loop alternative. It validates the returned causal reservation.
The planner reads canonical LoopTurnCause bytes, preserves the selected idle
task, budget, home/session and new logical turn, and pins PlanEffectID. Manual
frames and same-turn profile continuation remain separate. The model fixture
validates the shared contracts; it is not native scheduler authentication.

The shared types and validation are in api/loop_turn.go. The implementation is
in service/sched.go, service/sched_linux.go, service/sched_loop.go and
store/loop_write.go. Real-store tests cover due input, canonical readers,
replay, restart and the manual-turn race. TestSchedNative measures the actual
Linux producer through a scheduling tick and durable reservation, with a
component ended workload. This proves no authenticated vendor turn or full
native automatic opening. The numbered requirements remain acceptance
obligations; the other-platform producer still refuses explicitly.

1. **Actor and caller.** Only the configuration's installed scheduler, reached
   through the authenticated private service dependency, may reserve an
   automatic loop turn. Its actual actor is `api.Actor{Kind: "scheduler",
   ID: <installed scheduler identity>}`. Service assembly must authenticate
   that identity/capability; an actor string, ID, source label or public request
   does not grant the capability. Human and lane callers continue to use the
   public manual paths. A generic service or watchdog actor cannot acquire
   automatic scheduling rights merely through the continuation selector.

2. **Protected selector and idempotency.** Add a loop-turn alternative to the
   private reservation request, distinct from the public original-frame and
   profile-swap continuation alternatives. Select the exact durable loop
   setting by config, life, setting event ID/sequence and setting operation ID,
   together with the causing run and its committed end event ID/sequence.
   Bind the expected current life generation, cancellation epoch and previous
   launch ID. Derive the next run and new logical turn from those stored facts.
   The store issues the operation/reservation/launch IDs and an immutable
   causal input record. One causing end may reserve at most one next turn,
   including races between scheduler instances and a manual resume/turn.
   A retry reads that same reservation/result after current authorization;
   it cannot reserve another operation or substitute a newer setting.

3. **Current authorization and atomic fences.** The store must verify the
   installed scheduler capability, the real setting record and its original
   authenticated configurator, and that current policy/grants still authorize
   automatic turns for this life. Historical permission to enable a loop is
   insufficient after revocation. Recheck the latest setting is enabled,
   expected generation/epoch/previous launch still match, the current run is
   idle or verifying and uncleaned, and the exact committed end is quiescent
   with zero survivors and no later lost/running observation. Derive due time
   from that end and the retained backoff with the trusted clock; refuse an
   early turn. Check available remaining budget, history/driver/model/profile
   eligibility and grants without resetting counters or adding paid fallback.
   Verify/consume these fences, claim the causal end once, retain the pending
   operation reply and enqueue the ordinary launch-plan effect in one atomic
   reservation. Concurrent disable, stop, cancellation, policy change, manual
   launch or restart cannot create a second or stale turn. Planner/opening
   gates must still revalidate current authority and cancellation before any
   physical side effect.

4. **Retained inputs.** Derive the exact idle-input blob and digest from the
   selected durable setting; a scheduler supplies no replacement text. Retain
   the selected input bytes, backoff/due time, prior launch/session/history,
   remaining budget and new logical-turn identity. Use the normal protected
   turn/mail snapshot and delivery path for any mail; reservation does not
   acknowledge delivery. A fresh reserved grant snapshot binds current policy
   without rewriting earlier issuance, request or launch bytes.

5. **Audit and causality.** Retain the actual scheduler actor/identity and
   authenticated service capability provenance, config, selected loop setting
   event and operation, original configurator actor, causing life/run/launch
   and end event, expected/base and resulting life generations, cancellation
   epoch, policy and grant-set generations/IDs, exact input digest/byte count,
   backoff/due/reservation times, budget/history pins, next run/logical turn,
   operation/reservation/launch/effect IDs and idempotency correlation.
   Reservation and launch audit events must carry the real scheduler as actor
   and requester, with the configurator and setting/end as separate causal
   fields. Retain a canonical immutable scheduler input record/digest rather
   than inventing an authenticated public frame. Refusals and duplicate replay
   outcomes must preserve the same causal correlation without consuming a new
   turn. Specify the exact closed DTO/event fields and validation in the shared
   contract so store, identity, lifecycle and service enforce the same pins.

Do not clone the prior lane's `Scope`, borrow its endpoint/launch identity,
redeem a human proof/ticket as the scheduler, or relabel the scheduler as the
original configurator. Do not reuse `ContinuationID` to bypass the missing
loop-turn authorization. Until this private contract and its implementations
are installed, `LoopDue` remains a read and no automatic dispatch is claimed.

Acceptance needs Linux runtime evidence for a due authorized turn, exact retry
replay, two-scheduler/manual-launch races, restart, disabled/revoked/stale
settings, epoch/policy changes, nonquiescent ends, early backoff and exhausted
budget. Each negative case must refuse before reservation/opening and identify
its deciding gate; a later unrelated refusal is not proof of that gate.

## Draft.4 fix 12 adoption

The shared fix-12 contracts are merged in the fix-19 baseline. Lifecycle now
uses api.EffectPending, EffectClaimed, EffectCompleted and EffectFailed for
effect records throughout planner, archive/data completion, revocation,
collection and their fixtures. Outcome and operation statuses retain their
own succeeded/failed/pending/running vocabulary; no string coercion maps one
domain into the other. Child receipts are checked against their terminal
effect state on both first completion and replay.

Every emitted lane.turn requires its actual nonempty logical turn ID.
Service.event propagates the selected lane turn, and planExecution.event
carries the protected reservation/effect turn through to the event. Prepared
Lane and TurnSnapshot fixtures retain that same turn. The shared transaction
validator independently rejects a missing turn ID.

The prepared-binding fixture writer calls api.BindCurrentLaunchPolicy under
its writer mutex, with a CurrentApprovedPolicy view of the actual protected
head. Both prepare and open transactions receive a fresh private policy fence
before validation and intent/state access. The regressions preserve a
historical Scope.PolicyGeneration while advancing the head, and observe that
the write is refused before later intent checks. A missing open fence is
covered separately. Lifecycle's earlier policy read is still a preflight
check; it cannot substitute for the writer-owned fence or manufacture that
private transaction field.

Lifecycle Dependencies accepts CredentialProjectionIdentity and infers it
from the installed Authenticator when available. Bound recovery calls
CheckLaunchCredentials, validates the fresh held record with the shared
validator, compares the retained handoff/home/lease/epoch/logical turn, and
reads back the full protected record. Opened recovery instead selects the
original prepared gate through CredentialProjection and accepts correlated
held, withdrawing or withdrawn history without fresh opening authority.
Both paths verify the actual retained HelperPrepare effect and original
claim. Missing identity for fresh binding, missing records, replaced claims,
foreign producer records and owner errors refuse. Recovery does not acquire
another slot, copy descriptors or rebind the helper.

Assembly's existing projectionLauncher remains the single owner of the
one-use helper/broker/identity binding. It is already installed in launcher
consumers and the private runtime service handoff. Lifecycle preserves that
composition rather than binding the same helper a second time. The owning
identity/helper/broker APIs still control native transfer, projection,
LockCredentialProjection through actual OpenGate, source refresh and
withdrawal. This round adds no alternate credential transport or public DTO.

Remaining owner integration is concrete: the production store writer must
implement its locked CurrentApprovedPolicy fence on actual prepare/open
commits, and identity/helper/broker must implement their existing projection
ports and native guard/withdrawal receipts. Those owner implementations are
currently typed dependency refusals in the merged tree. Fixture records
model correlation only; they are not native peer, descriptor, filesystem or
credential observations. No absent producer is replaced by a passing receipt.

The authorized Linux phase must verify the merged source's runtime
regressions and named mutation controls. Native/service acceptance additionally
requires real policy advancement between prepare/open, exact turn pins,
claimed/completed effect transitions, projection/revocation and withdrawal
with the actual installed owners. The scheduler request above remains open.

## Failed-plan cleanup writer

Lifecycle now invokes FailedPlanStore.FailPlan after a pre-opening error
with a retained credential-slot result. It supplies the failed LaunchPlan
revision and private PlanCleanup requests in one writer call under the
original planning intent, claim, operation and cancellation fence. A bound
or uncertain projection requests withdrawal; a confirmed unprojected slot
requests release and injection revocation. Stage bytes remain immutable.
Failed replay returns the retained error without another acquisition.
Unknown slot/injection results and lookup problems remain explicit pending
reconciliation facts; no fabricated quiescence or cleanup receipt is supplied.

The service/store owner must implement the shared api.FailedPlanStore port
on its existing single transaction writer and durable cleanup outbox. The
current closed api.Effect union has no credential-withdrawal, credential-slot
release or injection-revoke alternative, and the InternalLaunchPlan catalog
cannot enqueue helper abort/release. An independent enqueue after Transact
does not implement this port. Lifecycle's names are exact aliases to the API
types, with no local field/interface copy. Both planner preflight and the
fixture's locked failed writer call api.ValidateFailedPlanWrite. Ordinary
Transact keeps its refusal of failed planner revisions. Lifecycle does not
overload PlanLaunch/Worker effects with cleanup semantics.
The production store in this tree has not implemented FailedPlanStore.
Absence returns the original error joined with the named service dependency
failure and retains the allocation. Therefore the native failed-plan leak
finding remains open at service/store integration, despite the implemented
lifecycle trigger and transactional fixture regressions.

The writer must recheck the original service claim and immutable reservation,
the current cancellation fence and original projection selector under its
lock, then commit failed state and every cleanup request together or neither.
Advancing launch policy does not authorize fresh opening; it also must not
erase the authenticated teardown request. The outbox consumer uses the
existing BeginCredentialWithdrawal, helper WithdrawCredentials and measured
FinishCredentialWithdrawal path before broker Release/RevokeInjection under
real helper quiescence. An unavailable projection lookup is not absence.
Uncertain collection retains the exact allocation and rotation requirement.
No native cleanup completion or service wiring is claimed by map fixtures.

## Prepare projection pins

To lb-v2-integrate and the service/store writer: recovery requires the bound
Lane's Workspace, LogicalTurnID and PolicyGeneration before opening. The
current shared validLaunchPlanWrite bound rule requires only life, run,
generation, grant set and launch ID. Extend that shared bound-write rule so
the same InternalHelperPrepare transaction must set Workspace equal to
record.Plan.Data.Workspace, LogicalTurnID equal to its original planning
intent's nonempty logical turn, and PolicyGeneration equal to the reservation.
The same transaction must retain the corresponding TurnSnapshot task, prompt
and policy generation. These fields must be committed at prepare rather than
deferred until OpenGate. Opened historical reconciliation retains the same pins.

Lifecycle keeps the recovery comparisons and now models this obligation in
the fixture's locked preparePins check. TestPrepareFields checks a valid
fenced transaction and rejects omission of each field before intent access.
The production shared-validator change belongs to integrate and remains
pending; this request does not claim that the shared API already enforces it.

## Retryable planning and historical proof

Cancellation, deadline, unavailable, containment uncertainty and explicit
retryability retain the same plan and stage resources. The planner does not
persist failed or enqueue cleanup for those transient results. A joined
transport error keeps its retryability through retained typed stage errors.
Transient allocation errors keep their claimed child rather than sealing a
failed outcome. Reconciliation fills the original journal; an input without
a result never licenses a second Acquire. The promoted API requires a real
SlotResult manifest and has no SlotInput field. Input-only, carried-slot and
retained-plan evidence still trigger failure preflight, but an absent result
refuses that preflight, retains the prior plan/allocation and joins the actual
validation error with the original refusal. The original input bytes stay in
their protected journal. Only reconciliation of an actual producer receipt
permits the failed revision and cleanup batch to commit; no result reference
or empty allocation is invented to satisfy the validator. A carried slot is
journaled through the existing production stage without another Acquire.

Bound credential read-back uses the prepared gate key only and separately
compares authority identity. Opened history verifies original receipt metadata,
derived targets, source correlation and withdrawal fences at their retained
measurement time without obtaining a fresh permit. Native holding/withdrawal
observations and the atomic cleanup writer remain their existing owners' work.
