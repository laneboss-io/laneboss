# Item 3 implementation handoff

This candidate adds public lane event admission, reserved-turn mail selection,
and a queue-effect completion coordinator. Component tests and native descriptor
canaries are separate from installed multi-actor acceptance. No authenticated
vendor turn, human confirmation, D6 approval, root installation or owner send is
asserted by those tests.

The lifecycle case is now discoverable through `case.json` and `run.sh` using
the frozen context/result interface. The harness must supply `test_root/plan.json`
with the existing real actors, twenty loaded lives in two trees, uploaded inputs,
timing observer, review producer and controls. It must also supply `collect`, an
outside collector command array. The collector receives `--config NAME` and must
return measured `survivors`, `containment_known`, `temporary_resources_collected`
and `lives` records containing actual `life_id`, `run`, `cleaned`, `containment`.
The entry independently reads every collected life through the authenticated
outside observer and requires all loaded lives and the created subject. A missing
prerequisite writes `wait.json`, an unreached failing result and exit 69. An entry
or collector failure cannot become a passed or collected assertion.
The outside human read transport must remain authenticated and available until
that read-back finishes; collecting its connection first is an incomplete run.

The inside messaging actor retains exactly the fixed sealed binding and connected
Unix socket descriptor numbers with `pass_fds`. Its native primitive tests cover
actual memfd seals, socket transfer, missing/foreign/stale projections, descriptor
grammar and exclusion of an ambient inheritable descriptor. An installed
`identity.self` and both driver cells are still required; this primitive canary
does not provide them.

The messaging observer resolves the actual current run through lane.status and
pages each exact run through public event.tail. It never uses run zero on that
public event route. Missing human confirmation transport or D6 channel selectors
retain a typed owner-wait.json, return exit 69, and leave the corresponding
assertion unpassed. A confirmation label is not a human bridge or an approval.

`store.publicLaneEvents` joins the method's closed transaction shape to the actual
requester and target lineage. Public records retain observation-only authority.
`messaging.replayMail` uses the store's `OwnsMutation` capability for the actual
dispatcher invocation, while other invocations await the original receipt.
Queue effects and events carry one stable operation correlation; reports retain
the original `mail.queued` sequence. D7 routing uses a narrow relation projection
without exposing a sibling or ancestor's task/session/capture through `Lane`.

The planner's existing `MailDelivery.BeginDelivery` hook resolves a sourced
reservation through `store.MailForTurn` and `BeginLaunchDelivery`. The latter
rechecks every sender, the manual requester, current grants, exact order, claim,
generation and cancellation epoch before atomically retaining the selection and
advancing mail once to `delivering`. A replay reauthorizes and returns that same
selection. It does not acknowledge mail.

The only installed service execution hooks changed are the Deliver branch in
`supportsEffect`, the Deliver branch in `runEffect`, and transient retry handling
for Deliver effects. They call `messaging.ReconcileDelivery` under the actual
queue effect claim. That coordinator waits for a real requested/scheduled turn,
checks primary capture and prompt/end observations, leaves provider-limit runs
pending, and records the logical receipt once. Store completion independently
checks the retained receipt and actual terminal observation. Recovery reads a
committed receipt instead of writing another one. Item-1 admin capture,
materialization and agent launch code is unchanged.

Round 2 implements the Linux private scheduler producer in service/sched.go
and service/sched_linux.go. It rechecks the protected installation binding,
dedicated UID/GID, executable identity, boot and process lifetime. Its actor is
a scheduler with no lane fields. Capability expiry stays fixed within a
generation; renewal invalidates old scopes. Closed, frozen, replaced and
serialized producers cannot retain that private authority. Darwin's native
producer remains an explicit dependency refusal.

The installed host starts a bounded scheduler loop alongside reconciliation.
It selects actual durable settings and ends through lifecycle.ReserveLoop.
store/loop_write.go owns the single-writer reservation, including the canonical
cause, private receipt, fresh sealed grant snapshot, unique causal-end claim,
pending operation and one PlanLaunch effect. It preserves the configurator
separately from the scheduler and retains the task, budget and private history.
Replay checks the original bytes and receipt; manual turns share the next-run
fence. The loop.reserved event remains private. Grant, helper, broker, prompt
and guidance readers have a private canonical-input path; no public request,
proof or prior configurator scope is fabricated.

The real-store tests include TestLoopWrite, TestLoopInput, TestLoopInputs,
TestLoopOriginal, TestLoopReopen, TestLoopRace and TestLoopFences. TestSchedDue
exercises the scheduling and reservation path with an explicit component
observation. TestSchedNative uses an actual dedicated Linux UID and root-owned
binding through the native producer, scheduler tick and durable writer. Its
ended workload and configurator are component inputs. These tests establish
neither an authenticated vendor turn nor native automatic prepare/open across
the full installed lifecycle. Gate 3G therefore remains partial as an installed
acceptance gate. The strict approved role-policy guard is retained.

Round 3 implements inert channel preparation in store/channel_stubs.go and
the atomic public queue in messaging/channel_queue.go. Preparation reloads the
pending public request and stored actor, current grants and channel enrollment,
retains canonical payload/input bytes, and assigns one stable worker lease,
effect and provider key. It publishes no executable lease or mail before the
public commit. The public transaction commits the mail, lease, Channel effect
and exact reply together. The current queue supports one enrolled destination;
multiple destinations remain an explicit prerequisite.

The fixed entry in dataworker/channel_worker.go reads the exact sealed input,
resolves selected credential metadata on its private worker connection, and
submits measured evidence. The native material reader requires the distinct
worker UID and reads only the selected projected environment or file source.
The private context/receipt operations are wired through client, identity,
service and store. The store joins a committed worker identity, installed
endpoint, assigned lease and current Channel claim, retains actual response
bytes as owner-private observations, and journals a correlated result event.
These ports do not allocate a helper worker or open a native gate.

The HTTP JSON provider exchange sends the exact retained payload, uses the
original provider key, and requires matching acknowledgement and read-back.
Read-only recovery performs no POST. Provider-key and receipt-ID read-back are
distinct capabilities; an unavailable original receipt remains a prerequisite.
Integrity failures keep their actual error classification. Loopback provider
tests measure real request/response bytes and lost-acknowledgement recovery.
They establish neither third-party provider compatibility nor native credential
confinement. D6 enrollment in the store tests is a component prerequisite,
never an owner confirmation.

TestChannelPrep, TestChannelPrepWait and TestChannelQueue cover real durable
staging, inert publication, exact replay and the one-effect queue. Their intended
red was the missing preparation writer, followed by three passing Linux tests.
TestChannelHTTP covers real send/read-back and a lost acknowledgement with one
POST. TestChannelReceiptMode and TestChannelDigest first failed on the incorrect
query capability and discarded error classification. TestChannelWorker first
failed on the missing fixed-entry dispatch, then passed with byte-backed private
ports and a live loopback provider. These remain component measurements.

TestChannelWorkerStore commits a component worker identity through the real
writer, resolves the actual retained Channel principal and input, performs a
live loopback provider exchange, and retains its acknowledgement/read-back and
result in SQLite. It requires a new correlated blob event and exact replay.
Restoring the former archive-only principal lookup makes this test fail with
the missing fixed-job error; restoring the Channel branch passes. The fixture
supplies process facts and an unopened-gate tuple, so this is not a native
helper or installed-worker canary. A compile mistake and two incomplete fixture
tuples were repaired before measuring that intended red.

The first broad Linux run found an audience regression in the fixed-worker
preflight. The producer now retains channel input/payload with the existing
private audience, and the original preflight assertions remain unchanged.
The focused channel set then passed ten tests with no failures or skips.

The final transport control warms an actual provider connection before losing
its POST acknowledgement. It exposed Go HTTP's implicit POST replay under the
idempotency header: the lost-acknowledgement cell incorrectly confirmed a second
POST. The request now has no replay body; recovery uses only GET and the original
provider key. This is part of the design's no-blind-resend behavior.

The store result test also checks that its acknowledged next worker generation
is actually committed. This assertion first failed against the draft writer.
Result retention, the correlated event, the worker generation and the exact
acknowledgement now commit atomically. Principal lookup checks that committed
advance against the retained original submission so an exact result retry
continues to return the original receipt.

Round 3 started from da1586f2 and was committed by the supervisor as 2efff4f7.
All execution
checks used the authorized Linux box. The whole plain package set passed in
box request 1792254461457-66728. The broad fault-tagged set passed 1,028 tests
with no failures or skips in request 1792254462708-66956. After the transport
fix, all dataworker/store/grants tests passed 434 tests in request
1792254935674-50112. After the final lease-generation fix, the fault-tagged
channel set passed ten tests in request 1792255097095-74874. The final complete
store rerun passed 281 tests with no failures or skips in request
1792255095864-74659. Static vet of touched packages and direct importers passed
Linux amd64, Linux amd64 with fault tags and Darwin arm64. Formatting and diff
whitespace checks passed.

Round 4 resolves the source conflict with 3fb03fd8 as the union of materialize,
archive, usage and channel in dataworker/internal.go. Each kind retains its own
input class, native branch and RunInternalJob dispatch. The worktree's merge
index remains the supervisor's responsibility; this lane does not stage or
commit. The inherited sealed-input reader also omitted usage/channel. The
four-kind descriptor test first failed on those two classes, then passed with
exact bytes for every kind. The matching helper seal utility accepts the same
closed class set without relabelling a channel as materialization.

The native preparation path now has a channel-owned helper journal. It reserves
a distinct installed pool UID and cgroup once, registers exact spec/input and
endpoint bytes, and prepares the actual fixed channel executable behind an
unopened native gate. Its original memfds, pinned socket inode, bootstrap PID,
pidfds, namespaces and cgroup are measured. The existing worker launch source
can resolve the Channel registration's common identity tuple; this is not a
materialization job or an archive. Private helper operations expose allocation,
registration, preparation, prepared-state reconciliation and cancellation.

TestChannelGateNative first failed on the missing native allocation. The root
canary then passed real distinct-UID preparation, sealed descriptor read-back,
native lifetime and namespace checks, containment lookup and exact replay.
A separate helper owner over the retained journal cannot create a replacement
gate after losing the original live descriptors. Prepared-state reconciliation
returns the actual unopened gate, with no process or consumed permit claimed.
Cancellation first kills the actual cgroup, then closes/waits, measures UID and
cgroup quiescence, removes resources and releases that pool UID durably.
Collection replay retains the original measured record. Its initial stop-order
failure was repaired before the passing collection run.

The canary's service claim and channel enrollment are explicit component inputs.
It measures native preparation and collection, not a D6 approval, provider send,
credential injection into the child or an installed-service delivery success.
The current native client does not expose a channel gate-open operation.

store/channel_launch.go reserves the worker ID/actor and bounded frozen plan,
retains the canonical spec and helper allocation, assigns the original lease,
and commits the actual identity event, binding and endpoint. Exact retries return
the same IDs, spec bytes and identity receipt. TestChannelNativeStage first
failed without its private writer port, then passed the real SQLite lifecycle
and full store verification with component native allocation/prepared facts.
The broker and protected credential inventory now accept the actual Channel
effect via that frozen plan. TestChannelEffectInjection first failed because a
Worker payload was required; its passing path fetches and encrypts the selected
source and retains the exact original lease/plan in the real broker journal.

Round 4 Linux evidence is retained in this lane's box queue. Request
1792257637259-99500 passed the whole plain package set. Request
1792257638501-99749 passed 1,472 fault-tagged tests, with no failures or skips.
Request 1792257639743-137 passed TestChannelGateNative, TestWorkerLaunchNative
and TestArchiveLaunchNative as root with the root/integration tags. The merge's
initial dataworker run passed thirty tests; the repaired four-kind reader and
dataworker set passed fifty-nine. The focused native-writer, broker and existing
credential-inventory run passed three tests in request 1792257480702-85494.
Static vet passed touched packages/direct importers on Linux amd64, Linux amd64
with fault tags and Darwin arm64, plus the changed admin native tag configuration.
Formatting and diff whitespace checks passed. All project execution stayed on
the authorized Linux box. No merge index changes, commits or owner sends were
performed by this lane.

Still open: the authentic load/topology producers (3A), installed complete mail
flow and failed-planner selection recovery (3C), installed channel orchestration,
credential projection, retained gate opening, post-send reconciliation and
verified delivery completion (3D), and frozen review subject/job preparation
and native measured verifier (3E). The channel coordinator and dataworker
orchestrator still return their owning not_implemented errors. Preparation and
collection now have native helper ports, and the credential selectors accept
the actual Channel effect. Their full installed-service sequence remains open.
A service-UID HTTP fallback is not supplied.

The next 3D step is to connect the new native preparation and writer ports to
service/dataworker PrepareChannel, using the actual installed worker listener.
Prepare selected broker slots before consuming the original lease, then retain
the original handoff for exact preparation retries. Channel's native credential
projection needs its own actual worker home/file mappings and a held broker
guard, followed by the measured exec handoff. Bind the actual worker identity
and obtain its permit through the existing native launch source before adding
the channel gate-release operation. Connect SendChannel and ReadBackChannel
to that retained execution. The result reader and outbox
completion must validate the retained worker evidence before committing
delivered. Reclaimed claims need an actual recovery result path; the current
single immutable result acknowledgement does not yet advance an uncertain
result to a later confirmed read-back. Receipt-ID recovery also needs its
original retained provider receipt supplied to the worker. Collection of
abandoned inert staging remains open. No installed delivery gate is passed.
The strict-level public handler controls cover lower/equal/higher/L3 requests
and unchanged ticket/reservation/launch counts (3F); installed tree coverage still needs
the authentic producers. None of these remaining gates is represented as passed.

Owner-in-person waits remain: authorized root installation, genuine operation-bound
HUMAN-SEND/dashboard confirmation, D6 approval of the disposable channel sink,
browser gestures, and hardware presence if claimed. The harness must stop on the
owning typed prerequisite/refusal until the actual step occurs. It must never
prewrite a proof, approved decision, successful review or sink acknowledgment.
