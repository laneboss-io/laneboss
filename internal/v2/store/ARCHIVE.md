# Archive and collection writer handoff

The archive and G11 collection adapters use the existing SQLite writer,
projections, projection history, immutable objects and effect outbox. There is
no second database writer or independent journal. These are private installed
capabilities, not public request fields or new public RPC methods.

`ReserveArchive` checks the actual `TrackMutation` insertion winner and the
original retained request, life/run/generation/epoch, current policy and grants,
and the committed end plus independent process observation. It consumes the
original human proof once and retains a stable `freezing` record before asking
the storage owner to withdraw writable access. `RecoverArchives` reuses that
record. The native producer must return the current workspace, required history
and capture bytes and known zero storage writers and writable exports. The
store retains and reopens that snapshot, freeze and exact worker input, then
atomically issues one fixed worker effect and read-only grant set. An old launch
snapshot or process exit alone cannot supply this storage measurement.

The native worker helper must implement the methods of `service.archiveHelper`:
`ArchiveWorkerLease`, `RegisterArchiveWorker`, `PrepareArchiveWorker`,
`OpenArchiveWorker` and `ObserveArchiveWorker`. They resolve the same original
job and actual current effect claim on every retry. `ArchiveHandoff` seals the
distinct UID/containment, fixed runtime/argv and worker-only endpoint before
preparation. `BindArchiveWorker` atomically retains the prepared identity and
endpoint before the helper may open the gate. No worker supplies its own ACL,
object ID, receipt ID, store ID or host pathname.

The private socket operations `principal.read`, `input.read`, `object.read`,
`archive.part` and `result.append` authenticate the actual native worker and its
current claim, lease, policy, source grants, cancellation and expiry. The client
bridge supplies `dataworker.ArchiveJob.Bootstrap`, `Read` and `Sink` to the fixed
worker entry. Materialization still requires its separate projected-root bridge.
Part indexes append sequentially; an exact retry reopens identical persisted
bytes. Each part and result is retained before acknowledgement. The worker
cannot read objects outside its frozen inventory and its own persisted parts.

`CompleteArchive` rechecks the native storage fence, requires the acknowledged
result and measured successful exit with known zero survivors, and regenerates
the canonical tar from independently reopened SQL content. Every tar byte,
part boundary, digest and exact EOF must match. It commits the original typed
public reply, effect outcome and `archive.verified` together. Generic effect
completion and generic transaction replies cannot bypass this port. A timed-out
public waiter leaves the original archive operation pending. A lost reply after
commit reads the original completion and does not append another archive event.
Expiry or an unknown native outcome retains the original records and workspace;
it never grants a replacement job or widens authority to make a retry succeed.

`BeginCleanup` resolves the original claimed Clean effect, terminal decision,
verified archive, genuine committed helper release and protected workspace
identity before retaining its stable cleanup intent. `CleanupInventory` reads
the actual object namespace and complete reference sources, including immutable
events, retained requests/replies, projection history, object content references
and declared `InputRefs`. It pins the archive input/result/freeze, frozen
manifest, source content and archive parts through collection. It refuses an
oversized graph rather than truncating it. Foreign, referenced, audit and unknown
objects remain retained. Only owned, unreferenced transient artifacts are
eligible for SQL deletion.

Older writers checked declared `InputRefs` without retaining that relationship.
New artifact writes retain even an empty reference observation. An older
artifact without this provenance remains unknown and cannot complete collection;
opening the old schema never invents a zero-reference observation for it.

The object trigger permits a deletion only beside its exact protected metadata
journal. The before read, deletion, absence read and object disposition commit
in one writer transaction. Deleted IDs cannot be reused or acquire new
references. Open upgrades only the exact previous schema's unconditional object
deletion trigger after checking that entire known schema; an unknown or weakened
schema is refused. Archive and collection integrity are checked again on open.
This SQL change does not grant native directory or Git removal authority.

The administrator must implement `store.CleanupNative`: protected workspace
resolution, the unforced removal journal and an independent current workspace
and branch read. It must also supply `api.WorkspaceCollector` to the grants
collector. The service checks known clean workspace observations before object
deletion. An already removed workspace can replay only the original protected
object journals and administrator removal; missing journals remain uncertain.
Dirty or unknown work is retained and cannot complete `Lane.Cleaned`.

The grants owner must implement `api.CleanupDataWorker.CollectCleanup`, using
`api.CleanupObjectStore` and the administrator's `api.WorkspaceCollector`. It
must propagate refusals, retain the real receipt and return its exact bytes.
The service verifies that retained receipt through its installed SQL/native
readback adapter. `CompleteCleanup` repeats independent reads, holds the writer's
current claim/life/policy/reference fence, validates the private verification,
and commits fresh evidence, the original effect/operation, `lane.cleaned` and
the exact generation/Cleaned transition together. Reclaimed claims require a
fresh receipt and verification; an old receipt is never relabeled for a claim.

The optional native interfaces have no implementation installed by this lane.
Missing administrator freeze/worker/storage ports or the grants collector keep
the installed workflow unavailable with the owning lane named. Native workspace
or branch removal is not implemented here. Installed steps 51–53 and 75–77 still
require those owners and Linux acceptance evidence.

`arch_test.go`, `collect_test.go`, the private client tests and the service port
tests compile against the real store/service code. Their native observations
are explicitly component fixtures. `store-controls.json` is loaded by the
integration red runner and names the deciding assertion for every mutation.
The authoring host runs candidate static checks only. Every runtime control must
reach its nominated failure on the authorized Linux runner, then pass on the
same candidate; compilation or an unrelated refusal does not count. No
authenticated AI-service or native deletion acceptance is claimed by static vet.

## Recovery and concurrent collection

The collection fence hashes selected objects, their outgoing edges, identities,
retention roles and actual reference counts. Its content-addressed generation
does not depend on the global history head. Other lanes' captures, heartbeats
and projections can continue between inventory and completion. A new reference
to a selected object still refuses the original inventory.

Archive preparation retains freezing, sealed, verified or failed under the
original operation. Moved first-attempt fences, unknown/nonzero writers and
expired budgets seal operation.failed and the original typed error reply.
Temporary native unavailability retains the same intent with durable retry
delays of 1, 2, 4, 8, 16 and then 30 seconds. Live attempts are exclusive.
Recovery continues after a recorded per-record failure; failure to retain the
outcome remains a writer error.

FailOwnedEffect is a new private port beside successful archive/cleanup
completion. It atomically retains the reason, next step, actual observation,
immutable evidence and original failed effect/operation/reply. Ordinary exits,
signals, budgets, deadlines, absent consumers and invalid results do not retire
the reconciler. A real authority/claim fence remains refused. CleanupNativeReady
lets dispatch refuse cleanup without installed protected native ports.

Before returning object journals to the native remover, the writer retains the
exact removing claim. Reclaim preserves journal claim A and authorizes current
reads/completion under B. Historical authority is validated at the measured
removal time and namespace readback is repeated now. CleanupRemovalReadbacks
resolves this protected claim for VerifyCleanup. An unretained removing claim
or missing historical provenance refuses; the store never invents authority.

Dependencies.ArchiveLimits is protected installation configuration. Explicit
snapshot and collection limits have a 4096-entry floor; zero derives them from
approved memory/disk budgets, including 256 KiB archive parts. Preparation has
a 60-second floor. Lease time includes the approved wall budget and preparation;
OwnedEffectDeadline sizes the claim to that retained budget. Source grant expiry
still narrows authority. Byte/format bounds and configured refusals remain
budget failures rather than truncation or empty success.

The design states no ended-lane exception for expired/revoked source grants,
so current checks remain pending the owning policy decision. Graph construction
still scans reference sources and object bytes. Whole-root buffering and global
digest coupling are removed; indexed graph cost remains unimplemented. Startup
still verifies every acknowledged archive's bytes. These remaining cost items
need separate measurement. Cleaned events now carry the lane's starter chain
while retaining the cause actor required by the existing API.

## Retained JSON and failed-worker quiescence

Collection graphs, inventories, receipts, verification digests and persisted
collection records use the immutable-object JSON bound, including strict
duplicate-member, Unicode and nesting checks. They are not bounded as single
RPC frames. The RPC decoder/canonicalizer and wire frame limit remain 1 MiB;
retained objects/state remain bounded at 64 MiB and oversize is a budget refusal.

FailOwnedEffect accepts an absent process observation only before any worker
handoff. After handoff, missing process evidence is uncertain. A started worker
requires the original process handle, a measured exited state, exactly one exit
code or signal and a known zero survivor count. Running, unknown or surviving
workers cannot seal a failed operation or its reply. The original claim,
worker lease and containment allocation stay retained. A direct containment
refusal from this writer keeps that effect pending while reconciliation of
unrelated effects continues; a joined storage failure remains fatal. Native
observation or containment release must resolve the pending worker before its
resources can be retired. This port performs no native release itself.

Cleanup failure after a known remove_clean journal or absent/unknown workspace
remains pending for the original journals. A fresh independent read of the
original present workspace permits a terminal measured failure, including dirty
work, a moved HEAD or a renamed directory before removal. Presence requires the
same WorkspaceID, RootIdentity and GitIdentity, a fresh nonfuture native read,
present worktree and branch, and a known dirty decision. HEAD and directory
identity remain removal fences, but their movement does not make a measured
failure immortal. The writer rechecks the retained remover/journal before
sealing; the administrator must serialize/fence removal by the current claim.
The grants collector must use the retained historical claim replay API when
current and removing claims differ. This guard does not replace that integration.

The fresh launch fixture includes a three-letter budget currency, as required
by the real archive producer. Its tests still use the actual public reservation,
worker handoff, authenticated store reads, producer and completion before the
first cleanup intent; no producer validation is relaxed for the fixture.

## Bounded verification and liveness

Each CleanupReadbacks value owns one verification pass. It decodes the complete
collection record once, indexes inventory members, and checks the actual current
claim and collection generation on subsequent reads. A concurrent generation
change or a changed job refuses the cached pass. Object namespace/content and
native workspace reads remain fresh. CompleteCleanup starts another independent
pass. The large-store regression retains its original 4097-object size and timeout;
an observed SQL-read counter also guards against quadratic record decoding.

Before any object journal exists, CleanupInventory recomputes a changed graph
and retains a fresh complete inventory; workers cannot reuse its superseded
inventory. After journaling it preserves the original evidence and reports a
prerequisite failure. OwnedFenceFailure classifies a permanent domain/graph
change only for the current original claim. ClaimOwnedRecovery can reclaim the
same owned effect after its domain epoch moved, solely for measurement and failed
completion. Execution ports retain their original life/grant/expiry checks.
An actually removed workspace still requires the original journal replay.
Related graph changes after actual removal remain the one unresolved automatic
store/service recovery case. This round adds no journal adoption or waiver of
the reference fence. The proposed path is a private atomic terminal-failure
writer for the same original intent, not successful cleanup: authenticate the
current measurement-only claim, independently read back the original protected
unforced removal journal and current absence, and recheck every original object
disposition against its immutable deletion journal. Recompute the related graph
to classify new or newly referenced objects as retained; never delete them or
rewrite the old inventory. Retain both graph snapshots, the native measurements
and the reason in immutable failure evidence, then commit the original failed
effect/operation/reply with Cleaned still false. A later explicitly authorized
cleanup would need a separate intent that acknowledges the terminal record and
retained historical removal; it cannot relabel the old removal as its own.

Implementing this safely requires a new protected native/SQL verification
capability and validation of historical remover claims, including concurrent
remover fencing. Existing failure completion intentionally refuses actual
removal, and successful completion intentionally requires its unchanged graph.
Weakening either check is not a small recovery fix. Until that capability is
implemented and covered by accepted/refused Linux regressions, preserve the
original pending operation, removal journal and remaining objects for supervisor
recovery. No automatic terminal escape for that case is claimed here.

The first native freeze uses a context bounded by the retained worker lease,
independent of the requesting RPC's cancellation/deadline. An expired lease is
still refused, and it does not allocate another intent. Effect outcomes are now
reference roots, so an output held only in effect_states cannot be collected.

## Native archive retirement handoff

The existing helper methods and successor-claim APIs are unchanged. The additive
archive.RetirementHelper method is:

    RetireArchiveWorker(context.Context, archive.Job, api.EffectLease) (archive.Retirement, error)

The administrator implementation must reconcile the original job/allocation,
including a lost allocation reply. It observes real native state, stops and
reaps an opened worker through containment release, or aborts an unopened gate,
and collects its UID, namespace, storage/network grants and writable exports.
It must never allocate, reopen or widen worker authority on this path. Expiry
or a moved life fence cannot forbid measurement/collection of an existing
allocation. The current effect claim remains required. A replay returns the
original retained release/abort; absence is independently measured by original
job selector, never inferred from a missing service reply.

BeginArchiveAllocation retains the original intent before ArchiveWorkerLease.
RecordArchiveAllocation retains the actual UID/containment immediately after
the reply. Any later error, including one between grant and handoff, reaches
retirement before failure completion. An uncertain allocation intent cannot
seal a nil-observation error. ArchiveRecovery grants measurement only;
RecordArchiveRetirement correlates the original job, allocation, process binding,
native release/abort and zero-survivor counters. It rejects foreign or incomplete
evidence. Retained retirement cuts worker socket authority. A lost public reply
does not create another allocation or reopen a retired worker.

The service asks for observation even after worker expiry, drains that lease's
listener, requests retirement and retains the native evidence before sealing
the original failed operation. Successful archives retire their worker before
verified completion too. Per-lease listener cancellation removes its socket and
flight entry without stopping another lease. Unknown native resource state
remains pending; it never becomes a fabricated zero-survivor release.

These seven rules are enforced at the retirement boundary and must be followed
by a native RetireArchiveWorker implementation:

1. A release's ObservedAt equals Quiescence.ObservedAt. Both are valid, nonzero
   timestamps at or before Retirement.ObservedAt, which cannot be in the future.
2. The same timestamp equality and ordering apply to an abort receipt and its
   quiescence observation.
3. A release reports exactly one of ExitCode or Signal. Signal is an integer
   from 1 through 64. State is exited; survivors, live connections, queued jobs
   and writable exports are all independently measured and known zero.
4. A release Backend is exactly linux-bwrap-landlock or darwin-seatbelt, and
   its lease, UID and containment match the original installed allocation.
5. The release Quiescence.Handle.ID is the original worker launch ID; its
   nonempty Generation matches the process generation from PrepareArchiveWorker
   and the installed binding. An already recorded process must match exactly.
6. An abort's handle carries the original Target and allocation ContainmentID,
   State is not_started, AgentExecuted is false and survivors are known zero.
   A recorded process cannot be replaced by an abort.
7. The service gives observation, socket drain, retirement and evidence retention
   one shared 30-second context. It closes and drains that lease's worker socket
   before calling RetireArchiveWorker. The helper must honor the context; the
   call grants measurement and collection only, even after worker expiry.

RecordArchiveRetirement reports separate timestamp, selector, binding and
counter mismatches for incomplete or foreign evidence. Absence is accepted only
without a recorded allocation, handoff or process and without a release/abort.
A cleanup-context timeout while the service parent is live returns a direct
ContainmentUnknown pending refusal and uses the existing effect backoff (250 ms,
500 ms, 1, 2, 4, 8, 16, then at most 30 seconds). No timeout supplies a process
observation or permits sealing. The same original allocation is reconciled on
retry, including a lost evidence-retention reply. A joined storage failure from
the evidence-retention writer stays fatal. Parent cancellation returns through
shutdown without recording a host fault or completing the owned effect.

This lane supplies the store/service bridge and strict retirement DTOs, not the
administrator's native implementation. Installed acceptance requires that
implementation and Linux native canaries. Dispatch refuses missing retirement
ports before granting an allocation. The administrator owns the zombie-remover
fence as part of its native collection work.

The remaining low-priority costs are explicit. RecoverArchives still calls
native freeze synchronously: moving it off the reconcile loop needs supervised
background lifetimes, close/drain semantics and durable error delivery, not an
untracked goroutine. Whole-store reference scans and startup archive byte
readback still cost linear work per independent check. Early deadline-selection
errors and untyped native error diagnostics retain their prior handling; no
retry-policy expansion is claimed for those advisory paths.
