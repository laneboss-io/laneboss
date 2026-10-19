# Watchdog draft.4 integration note

The current integration changes, regression scope and remaining native gates
are recorded in [the item-7 handoff](../../../e2e/v2/cases/watchdog/IT7-HANDOFF.md).
The original draft notes below describe their historical package-only phase.

This package uses v2.0-draft.4 fix 11 on 824e3f4e, including the cf894d10 merge.
The obsolete stub and wave-0 runnerhome package stay removed.
Only the assigned watchdog and watchdog-case subtrees are authored here. The
shared API and composition root are unchanged by this lane.

Draft.3 supplies the former missing capabilities: StateStore internal intents,
typed writes and CAS/cancellation guards; lifecycle-owned continuation claims
and slot handoff; typed model/session/profile eligibility; task counters and
private history identities. The former draft.1 blockers are superseded. No
watchdog-owned validation or journal method intentionally returns
not_implemented. Actual dependency errors remain intact.

## Implemented responsibility

ObserveLimit validates outside actor/capture/launch/exit provenance, actual
zero survivors, the running retained turn/task, current grants/profile policy,
exhausted A, fresh outside room and exact typed model/session/history eligibility. It commits
one continuation identity per configuration/life/causing run. The transaction
compares the life, current grant generation and absent/current continuation,
checks the cancellation epoch, and atomically writes the life, intent and
watchdog events. Preparation preserves task, turn, session/history, workspace,
counters and remaining budget.

The store stamps the actual operation and sequence facts. A committed wait
returns that journal operation; it is not a claim that a new run launched.
Pending selection is submitted through ContinuationRequest only after durable
read-back. No loose credential slot is acquired by watchdog. No swapped event,
mail acknowledgment, process exit or successful launch is invented here.
ContinuationRequest contains only IntentID and Swap. The selected grant,
eligibility ID, expected generation and cancellation epoch travel in Swap;
the stored intent must agree with that one submitted fence.

All current-life reads use Store.Lane's documented internal run-zero lookup,
then compare the actual run/turn/epoch against the causing target. A historical
exact-run snapshot is not current authority. The shared draft.4 transaction
catalog is checked before calling the writer. The writer still performs actual
identity/provenance, CAS, expiry, revocation and epoch checks atomically.
Free-to-paid automatic selection is ineligible even with a delegated paid grant
and remaining spend; an already paid source still requires positive budget.

Reconcile uses the retained intent. Durable waits use the actual waiting
event's commit time and exponential delay, bounded from 5 seconds to 5 minutes.
A repeated signal or restart cannot reset that delay. A claimed handoff is
submitted unchanged to lifecycle, including if its next run is already visible;
it is never reassessed into a second slot acquisition. Completed intent replay
reads its actual operation. Changed life/turn/generation or cancellation epoch
refuses. Unknown intent statuses fail closed.

Before pending replay, current grants and both profile expiries, revalidation,
effective exclusions, live turn, room and eligibility are checked against the
clock after dependency reads. Expired pending receipts refuse without a new
Continue of the old Swap or acquisition. Expired room/eligibility instead enters
fresh assessment under the observed continuation CAS. A winning concurrent claim
cannot be overwritten. Malformed, foreign or future receipts still refuse.
Waiting history must include the current
intent's waiting operation, nondecreasing delays and records no earlier than
the previous deadline. Service-origin control events from all catalogued
actors and life-scoped controls precede backoff; a later turn, including one
on the next run, supersedes the causing launch. Observation-origin records
provide no authoritative launch, capture, grant or lifecycle evidence.

Cancel returns without a write for absent/completed/cancelled intents. A live
intent is cancelled under life/continuation CAS and the old-epoch guard. It
advances generation/epoch only if control has not already advanced them, and
leaves profile_wait for verifying. A claimed old-run intent can be cancelled
when its next run is current; this writes only the old intent under the current
life fence, preserving the next run's entire life projection and epoch. An executing run remains running until lifecycle
proves otherwise. Cancel never stops a process or releases a slot. An advanced
epoch still paired with profile_wait refuses as incomplete manual control.
Lifecycle must settle that projection and cancel claims before replying.

## Shared consumer requirements and remaining contract precision

The public Go signatures needed for selection/journaling now exist. The
following integration details still need coordinated confirmation and actual
Linux execution; they are not excuses to restore the old stubs.

1. Cancel(context, LifeRef) has no caller Scope/InternalIntent. Its marker
   therefore records watchdog as actor/requester and leaves unavailable cause
   request/operation IDs empty. It cannot truthfully reconstruct the manual
   stop/resume/revocation requester. Lifecycle must retain that real cause in
   its own control transaction. If cancellation markers must carry that same
   causal tuple, extend Cancel with the internal cause in a coordinated API
   amendment. Consumers: lifecycle, grants/service, watchdog and assembly.
2. Lifecycle owns ClaimContinuation under the same serialization used by manual
   control/revocation, current authority/eligibility rechecks, exactly one slot
   acquisition and its persisted handoff, old-slot refresh/release after actual
   exit, and the real launch/watchdog.swapped receipts. It must preserve logical
   turn/task/history/mail, counters and remaining budgets. Watchdog never calls
   Acquire or claims these responsibilities completed. This checkout still has
   typed lifecycle/store/broker/service stubs outside this lane.
3. The service RuntimeBinder must discover/reconcile durable pending and waiting
   lives after restart and respect their persisted delay. Watchdog starts no
   private background scheduler or parallel state database. Deployment freeze
   must stop scheduling; store/lifecycle must reject dispatch under that freeze.
   Actual scheduling, consume-once slots and OS protection require the installed
   Linux service gates, not the in-memory transaction test fixture.

## Adopted fix 10 operation and launch facts

The store stamps Commit.Operation.ID into both intent and Swap, leaving the
authored precommit fields empty. That one profile_continue operation spans
pending selection, claim, slot handoff, swapped event, continued launch and
reconciliation. Waiting journals and cancellation retain their own operations.
api.ValidateContinuationOperation is the deciding identity/phase check for
selection receipts, Continue replies and completed replay. Pending/claimed
accept pending/running; only the retained completed phase accepts succeeded.
Continue's durable intent is read back because the phase may complete during
the call. No InternalIntent.ID alias or old local acceptance rule is used.
Generic life/run/sequence/error checks remain in addition to the shared rule.

Before dispatch or completed replay, the operation lookup is followed by a
fresh retained-intent read. The shared validator compares that intent's two
operation fields and the actual operation record against the original
observation's request. Replacing the operation after that observation refuses
with invalid_request before lifecycle is called. Both reads precede final
pending authority/clock checks. Lifecycle still owns the atomic claim check
under the life lock; this preflight does not replace that serialization.

Assessment and pending recovery read the actual LaunchBinding, retained opened
LaunchPlan and CaptureState. Shared plan/binding validators check the retained
handoff, agent kind and reserved pins; watchdog compares level, role, driver,
session and workspace with the current life. Missing legacy bindings cannot
authorize a new continuation. Registered capture needs the same binding and
known EOF positions for every bound stream. A refused capture returns its
actual owning refusal, even with an approved D6 launch exception. New live
records require BindingID, and capture.refused is honored before backoff.
These metadata/shape checks do not authenticate a native producer or consume
D6 authority themselves; the store/helper remain responsible for those facts.

## Fix 11 usage and policy adoption

A limit requires an exact committed usage_window reference. Watchdog reads its
strict normalized envelope and exact usage_raw TSV, verifies private scoped
object provenance, and applies ValidateUsageSource and ValidateUsageWindow.
The latter checks the actual usage worker mapping, enrollment pins, successful
command, from-profile exhaustion, known future reset and a post-exit observation
at most thirty seconds old. Capture provenance and unavailable room alone do
not authenticate vendor-shaped quota bytes. Final dependency reads cannot age
usage evidence past its accepted lifetime.

Dependencies.ResolveUsage is a required installation binding for accepting a
limit. It supplies retained worker/native facts and protected profile/executable/
runtime enrollment by immutable envelope reference. Missing binding returns the
owning secrets not_implemented; the envelope cannot certify its own producer.
The exact required owner handoff is in CONTRACT-GAPS.md. No public method or
shared schema was added by this lane.

Reassessment can call the real UsageWindowSource when the original usage result
has aged. It reads the new result's actual committed envelope, compares it with
the source reply and repeats all byte/source/producer/freshness checks. The new
immutable reference is retained in the new intent/Swap. Causing capture, profile,
run, adapter, exit and original watchdog.limit remain fixed; only the separately
validated usage reference may change. No old measurement is relabelled current.

Fresh continuation planning resolves current approved policy and calls protected
RefreshLanePolicy before taking life/eligibility fences. ValidatePolicyAdvance
and a read-back check its exact receipt. Historical launch/grant hashes remain
unchanged; retained turn snapshots use PolicyRetainedSelection and PolicyAt.
Pending work whose policy fence advanced is reassessed under continuation CAS.
Completed operation replay retains its original receipt/snapshot. Current
revocation and actual capability checks remain owning-store obligations.

lane.turn cancellation compares a later service event's logical turn and run.
The same turn may follow its launch or continue on the next run. A different
later turn on this/newer run, or life scope, supersedes it. Historical older-run
announcements do not. The test-before-fix source for TestOwnTurnAfterLaunch was
retained; runtime confirmation of that suspected false cancellation is pending.

## Verification boundary

The component tests model submitted CAS/epoch comparisons and retain actual
test writes/receipts; their Continue probe observes the request only. They do
not implement or prove a production lifecycle claim, credential refresh lease,
real process, live provider or OS boundary. The earlier supervising Linux pass
covers the prior slice, not this port. New positive/red tests await Linux.

The CLI case uses explicit installed draft.4 bindings and the shared CLI's
client.PrepareRequest path. It checks counters, task/history, selected grant,
eligibility and epochs, plus actual capture/room/mail/launch receipts. Its new
restart and independent tamper cells consume only the frozen harness controller
protocol. Missing controller/fixture support fails the dependent row. The
external harness must enroll the fixed canary and retain real target/syscall,
process-generation and restart evidence. Neither a stand-in nor observer-unit
success is authenticated AI-service acceptance.

The exact remaining requests to other owners, including the missing independent
human reader for dashboard observations, are in [CONTRACT-GAPS.md](CONTRACT-GAPS.md).
The case prepares human.session proof inputs and refuses absent fixtures, but
that plumbing alone cannot change an L6 process's kernel-derived identity.

## d4fix13 policy/backoff and pending usage

Waiting recovery checks durable backoff before entering any fresh-policy write.
Early ObserveLimit/Reconcile after a policy publish keeps the waiting intent and
life fence unchanged. After the deadline, planning validates the limit, refreshes
approved policy once and commits a matching intent under life/continuation CAS.
Pending policy drift is a read-only decision to reassess.

Assessment validates capture/exit, from-profile room, normalized usage and
candidate receipts before freshPolicy. It pins the approved snapshot used for
selection and updates Swap's expected generation from the returned life.
Historical turn policy is verified read-only under current authorization before
that write; no historical snapshot is relabelled.

Pending dispatch rereads exact usage_window bytes and checks their causing life
and profile. The final clock reading follows that I/O. Future data refuses; age
over thirty seconds reassesses and obtains a new outside measurement. Exactly
thirty seconds remains fresh. The old envelope's bytes, hash and time stay fixed.
