# G11 cleanup collector

The G11 store/service contracts are now present. dataworker.Service implements
api.CleanupDataWorker.CollectCleanup. The former missing-port routing note is
superseded by this implementation; native administrator support remains required.

The collector accepts only a CleanupJob, validates its complete live claimed
Clean effect, checks the installed configuration, and resolves the same job via
CleanupObjectStore.BeginCleanup. The current claim executor supplies the private
writer scope. The original cause Actor and RequestedBy remain unchanged. A fresh
outbox claimant may differ from that cause Actor; equating them would reject the
actual service path. The writer authenticates the complete lease and intent;
configuration, claimant or worker labels alone never authorize deletion.

The installed store must provide CleanupObjectStore and CleanupReadbacks(scope).
The administrator must provide WorkspaceCollector either in Dependencies.Workspace
or on the existing Helper capability. No public setter, shared API change,
launcher fallback or new cleanup RPC is added. Missing ports return their owning
not_implemented; no project/native collection is run on the authoring Mac.

Before object collection the collector checks the real workspace parent,
directory/Git identities, pinned head, known present branch/worktree and clean
status after archive verification. Dirty or unknown work stops before deletion.
The single writer owns the complete inventory, reference graph, deletion journal
and actual object operations. Referenced, foreign, unowned and audit objects stay
retained; a removal report for them returns forbidden. Claim/context/expiry and
reference fences are checked at each destructive boundary. Namespace paths are
never reconstructed from logical Workspace fields and no force option is used.

The administrator performs the unforced workspace/branch operation. Its result
must pass the shared removal validator, with actual absence/read-back and sync.
An already absent workspace can replay only the original protected removal
journal and a distinct current observation. Missing journal is uncertainty, not
permission to recreate a before observation or start an alternate deletion.

Before calling the administrator, ValidateCleanupObjectResults checks every
writer disposition against the complete inventory: present original bytes,
required removal of each eligible artifact, present retention of every other
object, exact after state/content/identity, and distinct ordered observations.
Count/order and forbidden-removal checks retain their existing typed boundaries.
A later receipt validation cannot substitute for this pre-removal gate.

Receipt IDs are deterministic for intent/claim/generation; reclaimed claims
cannot inherit the previous receipt's identity. The writer retains the proposed
exact operations and supplies the actual manifest. The collector validates the
full receipt, reopens it, requires exact equality, then calls api.VerifyCleanup.
That verifier independently reads the retained inventory/receipt, every protected
object operation journal and fresh object namespace, administrator journal and
fresh branch/worktree namespace, and the current fence again. Only its receipt
copy is returned. The collector does not call CompleteCleanup, emit lane.cleaned
or set Cleaned; the service/writer independently verify and commit those.

## Regression and source reasoning

TestCleanupCollector requires actual fixture transient-byte removal, retained
archive/reference/foreign/audit bytes, every independent object read, exact
retained receipt and replay with fresh reads and no second workspace removal.
TestCleanupHelperPort exercises the installed helper extension. The positive
fixture deliberately gives the cause and claimant different service IDs.

TestCleanupRefusals covers foreign configuration, invalid/forged executor,
substituted intent, dirty/unknown/replaced workspace, claim loss during inspection
or object work, attempted referenced/unowned removal, forced/missing-branch
results, a reappearing removed object and exact owner errors. It checks typed
codes, no returned receipt, retained bytes and the appropriate operation boundary.
TestCleanupUnavailable covers missing bindings, cancellation and absence without
the original journal. Fixture records are validated by the actual API validators.
Their byte-backed namespaces, canonical retained blobs and journals are component
fixtures, not native Git, SQLite durability or authenticated installed proof.

Accepted source path: a matching protected claim and inventory, known clean
workspace, owned unreferenced transient artifact and measured absence can proceed
to exact retention and independent verification. Retained objects must still be
present. Refused paths: dirty/unknown identity or a changed claim stops operations;
referenced/unowned removal reports return forbidden; a missing or changed actual
read-back returns an owning error and no usable receipt. A retained receipt alone
cannot pass a fresh namespace check when removed bytes reappear.

Nine g11-* controls name the stub, independent read-back, protected objects,
pre-workspace/pre-object fences, original intent, retained lookup, actual claim
executor and dirty-work gates. Their source anchors are checked on the Mac;
mutants are compiled and executed only by the authorized Linux red runner.

The round-2 refused inputs in cleanup_gate_test.go cover invalid before/after
states, retention of an eligible artifact, echoed/older replay observations,
newly dirty administrator retention, valid substituted retained/read-back
receipts, and omitted/reordered writer results. Every case requires the exact
code, owner and gate message, no returned receipt, protected fixture bytes and
the exact writer / admin / retention / lookup / verification call counts. This prevents
an earlier unrelated refusal or a later receipt check from satisfying the case.
Eight additional g11-* controls name their deciding assertions. The omission
and order controls also bypass the shared preflight, so the late receipt
validator cannot hide an administrator call made past the original gate.

The merged store/API successor-claim contract is now consumed by the collector.
A journal naming the current claim uses strict ValidateWorkspaceRemoval and
ValidateCleanupReceipt. When the journal names an earlier claim A, the writer
first replays its protected object journals and retains the native journal;
the collector then fetches A only through CleanupRemovalReadbacks. This order
also covers a crash immediately after removal, before receipt retention.
Missing proof support or an unretained journal/claim refuses. The returned A
is never rewritten: ValidateWorkspaceRemovalReplay checks it at the original
removal time and checks the current observation now. Receipt validation uses
ValidateCleanupReceiptWithRemoval while the receipt's ClaimID remains B.
VerifyCleanup independently fetches A again and repeats current namespace reads.
The round-2 writer-result, freshness, dirty-work and receipt gates remain.

cleanup_reclaim_test.go adds serialized component restarts after removal and
after receipt retention, expires A and installs successor B in the fixture
writer. TestCleanupReclaim requires an unchanged A journal, a B receipt, two
store-port claim reads, all fresh object reads, explicit VerifyCleanup, identical
B retry bytes and no repeated workspace removal. A's earlier receipt bytes
remain intact. The fixture cannot supply A directly to CollectCleanup.
TestCleanupStrictClaim works without the optional historical port when the
journal names the current claim. TestCleanupReclaimRefusals requires exact
codes, owners, messages and operation/claim-read counts for an unretained
remover, foreign effect, later generation, different intent and missing port.
Six controls nominate these assertions. Byte-backed restart and corrupted
return fixtures do not establish native process or SQLite durability.
