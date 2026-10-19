# Native archive and cleanup ports

Round 25 adds archive.RetirementHelper.RetireArchiveWorker. The service wrapper
reads the actual current effect and ArchiveRecovery job, then passes the known
allocation/process selectors over authenticated private helper IPC. A current
live effect claim can collect an expired original worker or a moved domain
fence; this path never grants allocation, preparation, opening or replacement.
The native helper resolves the protected original allocation and seals a durable
retirement intent before stopping anything. Every execution port refuses that
one-way fence. Foreign jobs, allocations, processes and expired current claims
refuse before collection.

An opened worker is observed through its original native gate, stopped through
the exact cgroup, reaped by its actual command.Wait owner and reobserved. A saved
actual terminal wait can reconcile a helper restart; a missing wait stays unknown.
Unopened allocations require a closed/unconsumed gate or proof that no gate was
created, plus fresh native quiescence, and return an abort with AgentExecuted
false. Prepared bootstrap processes are stopped/reaped too. Signal/nonzero exits
are retirement outcomes, never successful archive-worker output. The original
job, authorization, terminal observation and immutable proof remain in the
protected helper journal. A never-allocated job can return measured absence
only when neither the native record nor the writer's known selectors contain
an allocation.

The service drains its per-lease listener before calling retirement. The helper
then checks the private socket pathname and bounded /proc/net/unix inventory,
including unlinked but still-open sockets, and closes/measures its readiness
connection. Fresh cgroup/UID observations and the existing native job/export
inventories must all be zero. Archive children have no capture jobs or projected
source storage; their sealed grants/runtime permit no writable export. Empty
inventories do not replace the required process and socket measurements. The
exact cgroup is removed, quiescence is checked again, and Collected plus the
proof commit together before either the UID or acknowledgement is released.
The public wrapper also revokes its matching containment registry entry.
Replay checks original cgroup/socket absence and returns the same proof; it does
not scan a UID that may now have been legitimately reassigned. Workspace,
home/history and archive source retention are unchanged. Darwin returns the
typed unsupported result for native retirement.

The round-24 root failure occurred before claim validation: Objects was nil in
the archived record, encoded as explicit JSON null, and rejected by the frozen
strict reader. Other optional private archive/cleanup members and an absent
workspace's Dirty pointer had the same representational mismatch. They now omit
absent fields while retaining their existing field names and nil semantics.
Zero optional request variants also omit their unused structs. Explicit null,
duplicate and unknown members remain refused. fileLeaseStore verifies its exact
encoded bytes with the strict reader before publishing them. Existing malformed
records are preserved/refused rather than silently rewritten. The old native
root assertions and actual five-second claim expiry setup are unchanged.

Service implements archive.Native, the five methods of service.archiveHelper,
store.CleanupNative and api.WorkspaceCollector. Operations use the existing
authenticated helper transport and protected helper lease journal. They do not
complete service effects, publish archive receipts, delete service objects or
set Lane.Cleaned.

## Storage freeze

FreezeArchive resolves the latest native allocation for the exact life, run,
launch, workspace and cancellation epoch. It reads current workspace, private
home and required history bytes from the three allocated opaque roots under
/var/lib/laneboss-v2/lanes/CONFIG/LEASE. For each original outside-capture binding,
it includes actual stdout, stderr and marker files from the protected helper
spool. The producer must have an actual successful native wait, known zero
survivors, both pipe EOFs, complete range hashes and no reconciliation failure.
Archiving a spool does not grant a service drain acknowledgement.

Successful process release now retains private storage and withdraws its UID
ownership. Failed-launch abort keeps its separate authorized storage removal
path. Retained storage cannot reacquire writable launch access. The archive
transition journals its current inventory before withdrawing remaining write
modes. Descriptor reads check content, device/inode, owner, permissions, links
and attributes. Independent native scans cover descriptors, mappings, thread
cwd/root and mount namespaces. Read references also retain storage; unknown
observations cannot become zero. Measurement descriptors close before scanning.
CheckArchiveFreeze repeats the content, identity, permission and reference
measurements against the original intent without recursively calling SQLite.

Original per-entry modes and device/inode identities are retained durably before
ownership or permission withdrawal. The manifest restores those recorded modes,
including group permissions and executable bits; physical storage keeps its
withdrawn permissions. A replaced inode or restored physical permission refuses.
Old unarchived withdrawn storage without an original-mode record refuses rather
than inventing historical modes. Existing immutable archives are not rewritten.

A measured nonzero reference count has private code archive_live_writer,
Retryable false, and message "archive freeze measured N live storage references;
writable access remains", where N is the actual count. The conservative count
includes read references. Scan and quiescence failures retain their own existing
codes and are not relabeled as a measured writer. The helper response diagnostic
preserves the new code. The store must terminalize or explicitly schedule this
outcome instead of blindly selecting freezing jobs forever.

The object manifest and source pins remain in the protected helper journal;
source files stay withdrawn. The service reads bounded ranges of those exact
sources and checks complete hashes. There is no second database writer or
native archive-completion journal. Bounds are 4096 entries, 4096 objects including
the manifest, 64 MiB per file, the original disk budget capped at 128 MiB, and
the existing helper journal/frame bound. Oversized storage refuses without
truncation. Hard links, special files, attributes and unsafe symlinks refuse.

A root workspace .git entry is accepted only as the exact enrolled linked
worktree pointer. It is checked, withdrawn and included in the native reference
inventory. Git administration is excluded from the user manifest; required
private history is a separate measured root. Unenrolled Git entries refuse.

## Fixed worker

Every worker method resolves the original ArchiveJob and actual current effect.
ArchiveWorkerID supplies the writer's policy/grants/life/epoch fence each time.
The helper retains one distinct UID and cgroup before allocation, one immutable
handoff before preparation and the original gate before release. Runtime,
installed executable hash, fixed argv, exact input and worker-only endpoint are
sealed. No writable source mount or credential projection enters the child.

BindArchiveWorker commits the actual worker actor and prepared identity before
OpenArchiveWorker consumes the permit. The helper verifies that binding and
does not manufacture a principal. The containment ticket binds endpoint class,
worker lease and parent. Observation requires the original native wait owner
plus independent cgroup/UID quiescence. Only exit zero, no signal and known zero
survivors count as success. Lost gates and uncertain release outcomes refuse
replacement. Revocation journals invalidation and stops the original child.
All allocation paths, including isolation probes, reserve the UID. Authorized
cleanup collects the empty archive cgroup/gate using the original successful
wait and fresh quiescence before releasing its pool reservation.
Collection also precedes an unmerged retained outcome. A live or unknown worker
blocks that outcome, keeps both UID reservations and leaves its cgroup intact.
Terminal retained_unmerged and complete records release the lane UID only when
the archive worker has a durable Collected fact. Retained replay also collects
workers left by the older ordering before returning its original refusal.

## Workspace and branch collection

Cleanup reads helper-authored WORKSPACE.json enrollment from
 / var / lib / laneboss-v2 / helper / CONFIG / workspaces. The installer provisions the
configuration's helper state root as root:root 0700; the helper creates the
registry child as root:root 0700 and publishes root:root 0444 records there.
This runtime registry is inside the shipped unit's existing config-scoped
ReadWritePaths, so ProtectSystem=strict and the read-only /etc installation
namespace remain unchanged. Ancestors and records stay root-owned, unlinked
and not group/world writable; exact bytes, allocation identities and replay
checks still apply. This is protected helper state, not a public request or
generated org rule. No deletion RPC takes paths.

The private cleanupEnrollment has these fields:

- Schema is laneboss.workspace-native.v2; Config is the installed configuration.
- LeaseID names the retained native allocation. Workspace is api.CleanupWorkspace:
  distinct opaque workspace/root/repository IDs, exact current target/generation,
  actual root/directory/Git device:inode identities and the fixed lane/LIFE branch.
  An empty enrollment Head is resolved from real Git when creating the intent;
  that intent then pins the observed head.
- Parent equals the helper's protected storage base. Repository is the protected
  common Git directory. GitDir equals Repository/worktrees/WORKSPACE.
- GitPath and GitArtifact pin the root-owned executable, digest and byte count.
  Neither the lane nor the cleanup job selects these paths or argv.

Inspection reopens the protected parents, actual directory, Git registration,
exact linked-worktree pointer, symbolic branch, worktree/branch heads and status
including ignored/untracked files. Git metadata and reference parents are
protected; hooks and fsmonitor are disabled and the subprocess inherits only a
fixed environment. Private native command diagnostics are not returned.
Before status, the full bounded index is read with ls-files --stage -z. Mode
160000 entries refuse as unknown work; root never runs status in a lane-authored
nested repository. Reopened retained inodes are checked again for device/inode
and ctime before ownership changes.

Removal remeasures the original dirty-work decision and journals it durably.
Dirty work returns retain_dirty with directory, branch and head preserved.
Both destructive Git calls revalidate the sealed cleanup job against current
time and its enrolled workspace. Each command runs with a context deadline at
the original claim expiry, including metadata and executable checks before
process startup. Expiry returns CodeConflict with message "native cleanup
removal claim expired" and Retryable false. The claim that began collection
has no exemption. Expiry before worktree removal keeps both namespaces; expiry
after worktree removal stops before branch deletion and preserves the original
worktree_removed journal and remaining branch. A command interrupted at expiry
may have partially changed a namespace; no completion or rollback is invented.
The existing unfinished-journal refusal prevents a successor from restarting it.
Before workspace or branch removal, both actual branch tips are resolved and merge-base
--is-ancestor checks the lane tip against the common HEAD. An unreachable tip
keeps both worktree and branch. The native journal records retained_unmerged,
branch_not_merged, both measured tips and independent before/after presence,
with private code cleanup_branch_unmerged and Retryable false. The store can
record failed cleanup without marking the lane cleaned. Clean reachable work
uses unforced worktree removal and branch -d. Git refusals propagate
without force or fallback. Workspace/Git reference parents and packed refs are
synced, then directory, worktree registry and branch absence are independently
read back. The native result journal is saved and reopened before acknowledgement.
Store readbacks reopen that journal and current namespaces with fresh observation
IDs; they never echo a proposed receipt.

Ancestry takes precedence over dirty retention for an unmerged branch. Both
namespaces and dirty bytes remain, while retained_unmerged records the stronger
terminal reason: unreachable commits require an explicit collection disposition.
Reporting retain_dirty first would hide that branch decision behind an ordinary
dirty retry. A merged dirty workspace continues to return retain_dirty.

Completion publication validates the original removal claim at the measured
After.ObservedAt, after rejecting malformed, zero or future result times. Entry
authorization and each destructive command still require a live claim. A delay
between a valid native result and its first completion write can outlive that
claim without converting finished work into an interrupted journal. Helper
journal reads also reject future decision, retained and removal timestamps.

An exact completed retry remeasures its original disposition. Reads and completed
replay accept a live successor claim only for the identical stable Intent and
effect, with a strictly newer claim generation. The administrator reads the
actual current effect and BeginCleanup through the installed store capability;
a same-shaped nominal claim grants nothing. The original native job, journal,
claim ID and observations are returned unchanged. Historical removal authority
is checked at the measured operation time, while current authority is checked
now. An interrupted unfinished removal cannot restart under a new claim.
Unknown reads, substitutions and dirty retention cannot complete Lane.Cleaned.
Home/history, capture and native audit data remain.
Terminal retained replay likewise skips the released lane UID's quiescence
check after collection, since another life may now own it. It still authenticates
the live reader, reopens the namespaces and preserves the original journal.

The API/store alignment must allow a fresh CleanupReceipt under the live current
claim while its WorkspaceRemoval.ClaimID remains the claim that actually removed
the workspace. ValidateWorkspaceRemoval must authenticate that original claim
through the retained native journal and join the same intent/effect; it must not
require equality with the successor ID or accept an arbitrary ID. Original
before/after records stay immutable. Current authority, cancellation and graph
fences still govern independent verification and final completion. The only API
source adjustment is Dirty's optional JSON tag, matching its existing nil
semantics for absent/unknown readbacks; no method signature or disposition
changes. The public error-code whitelist is also unchanged;
service/API owners must recognize the two private codes if exposing them on the
public wire, or preserve them in native failure evidence when mapping a reply.

Follow-up for L6: removing an abandoned worktree while retaining its unmerged
branch requires a new authorized contract disposition and independent evidence.
That disposition and any forced branch deletion are not implemented here.

## Installation and acceptance handoff

The composition root is owned by lb-v2-integrate and is unchanged. It must pass
ArchiveNative and CleanupNative to store.New. Cleanup read callbacks now require
the live bound store capability; a client with a nil Store fails closed. The
composition owner must resolve constructor ordering with a private deferred
binding rather than treating caller-provided claim labels as authority. The
grants collector must receive the normal helper as api.WorkspaceCollector and
implement CleanupDataWorker.CollectCleanup. Missing wiring/enrollment still
refuses installed operations. Capture release continues to require the separate
authenticated drain acknowledgement.

The catalog retains all 380 preceding controls unchanged and adds sixteen
round-25 controls, for 396 total. Twelve require the new native root test;
four exercise strict wire publication/query shapes and actual recovery authority.
The root cases include a live worker, exited worker, actually expired worker
under a new live recovery claim, unopened/prepared allocations, absence,
foreign selectors, an expired claim, a lost wait owner, a surviving process
outside the original cgroup and an unlinked live socket. Each refusal has its
deciding control; positive cases require actual release/abort/absence, removed
cgroup, free worker UID and unchanged replay proof. The suite selects all sixteen
controls and TestArchiveRetire. These are authored native component canaries,
not evidence that the installed service/archive composition has passed.

Round 24 retained all 370 round-23 control identities and added ten controls.
clean-retained-reason now targets the root native path;
the hand-built retained journal fixture is removed. The new native path fixture
supplies the preceding launch/release/archive protocol records, then uses actual
protected enrollment, fileLeaseStore, Git, process start/wait, UID scans and
cgroup removal. It observes a surviving archive process refusing collection,
then reaps that process and requires no reserved UID or archive cgroup. New and
legacy unmerged outcomes are produced by the production ancestry and retention
writers. Replay under a reused UID must preserve the original job and journal,
and an actually changed dirty decision must refuse. Dirty unmerged bytes remain
with the documented ancestry-first reason. The measured-time case uses the
production native producer and completion writer, delays the first publication
until after actual claim expiry, and requires an unchanged measured result.
These are native component observations awaiting Linux execution, not a full
installed archive-service composition proof. The suite includes the new root
test and controls, and moves the existing reason control to its root list.

Unforced-removal and branch-absence controls keep their
identities and assertions, with anchors updated to the claim-fenced calls. The
changed-decision control and comparison remain unchanged. Its fixture first
passes ancestry and index preflights, then adds real untracked work while HEAD
stays pinned, and requires the exact changed-decision refusal. A later unforced
Git refusal cannot satisfy that assertion. Expiry fixtures include an already
expired input, a live original claim expiring after its removing journal write,
and a live original claim expiring after worktree_removed. They wait on the real
wall clock and independently reopen the kept namespaces. The existing clean
case requires successful removal with a live original claim. The box suite's
explicit root selectors include all three new controls.
Protocol claim/UID tests use explicit component fixtures. Real filesystem,
ownership/write, process-wait and Git fixtures require laneboss_root_canary and
fail without the disposable root Linux environment; there are no skips. The
wait fixture includes actual cgroup-v2 population and UID observations at the
native helper cgroup path, first with a surviving process and then after reaping
it. This remains a component fixture, not a full installed helper-unit proof.
The Git fixture starts with an empty commit and creates a real additional lane
commit for the unmerged refusal. It uses its own disposable repository and a
pinned copy of the actual Linux Git executable.

The authoring host runs candidate static checks only. Every new control still
requires its nominated Linux failure and passing candidate run. Installed
archive/cleanup acceptance remains required before checklist item 3 can close.
