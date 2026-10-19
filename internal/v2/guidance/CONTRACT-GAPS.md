# Guidance fix 11 consumer handoff

Base: 0fd61a6, the merge containing fix 11. The earlier winner/await/recovery
representation request is closed by api/guidance_claim.go and the additions
to turns.go. This lane now consumes those ports; it no longer returns its own
reservation-contract not_implemented refusal.

## Implemented consumer behavior

GuidanceSelect checks current self/session authority before reads. Completed
exact public receipts use PolicyGenerationForReplay and PolicyAt before mutable
turn preflight. Existing logical-turn claims retain their original policy after
current authorization, including a D6 advance from generation 3 to 4. They never
refresh the lane, fetch fresh candidates or judge again. New selection uses
PolicyNewSelection and current approved policy, and validates RefreshLanePolicy
only after lookup has proved there is no existing claim.

Fresh input retrieval is complete and authoritative. The reservation receives
a fresh cryptographic AttemptID, expected turn generation, life epoch, fixed
entry deadline and positive Lane.BudgetRemaining.SpendMicros. Only Acquired
plus GuidanceCanEvaluate permits fit/inference. An observer uses AwaitGuidance
with the retained ID/deadline; an identical key/attempt does not grant rights.

Completion uses the original owner attempt, operation, request, requester,
target and epoch. ValidateGuidanceCompletion and ValidateTransactionShape run
before Transact. Guidance/Turn/event are committed together with CompareGuidance
and cancellation guard, then read back before a public reply is sealed. A CAS
loser reads a completed identical claim; it never retries inference.

Recovery creates unavailable with the retained binding items, a truthful notice,
no judgment IDs and no score. It requires the original deadline to have passed
and the epoch to remain current. RecoverGuidance is a private reconciliation
entry, not a public RPC; it cannot allocate a missing claim. Completed recovery
replays. An interrupted owner leaves its durable pending record for the
post-deadline scheduler or a currently authorized expired-claim observer.

## Required service/store integration

The real store/outbox still owns atomic creation, invocation-specific Acquired,
public receipt serialization, bounded AwaitGuidance, current ACL/revocation,
immutable PolicyAt, policy refresh and durable CAS/epoch enforcement. These
remain actual owning dependencies; their typed errors are preserved.

The dispatcher must await same-key pending public receipts before dispatching
another handler. A handler can see its own pending receipt, so the guidance
completed-reply fast path does not await that record and deadlock itself.
ReserveGuidance must still return Acquired=false for every retry/observer.
The store stamps a replay reply's PolicyGeneration from its retained guidance
result, while Scope.PolicyGeneration continues to describe current authority.

The store retains complete BindingItems, using an explicit empty slice for an
empty binding snapshot. Recovery preserves that snapshot exactly; the shared
recovery validator compares it exactly, while public receipt arrays must be
present arrays. Missing binding projection is an integrity error.

The store/outbox schedules reconciliation at the original deadline. It can
invoke the private recovery consumer with currently authorized bound scope or
use expired-claim observation; this package does not create a background
scheduler or another execution session. Cancellation/closed authority refuses
instead of reviving the turn. Real scheduler wiring and native/store evidence
belong to their owners.

## Internal calling convention and acceptance

An RPC Scope with a method must be guidance.select. In-process callers use an
empty Request.Method and no human operation proof, retain the authenticated
actor/config/connection, and use the bound store's original pending cause.
They must not pass lane.turn or erase a live session binding to bypass a
refusal. TestInternalMethodContract pins refusal of lane.turn and acceptance
of an authorized empty-method retained replay. Public replay sealing occurs
only for guidance.select.

No guidance-owned fix11_stubs.go exists in this tree. The prior service.go
refusal was replaced. External service/store stubs are not converted into
success. Installed lifecycle delivery, native identity, actual store/outbox
restart/concurrency, provider accuracy and full GUIDE-TURN remain acceptance
dependencies. Stateful fixtures and static Mac checks establish none of those.
