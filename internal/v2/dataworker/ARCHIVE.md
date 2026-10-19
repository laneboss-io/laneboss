# Archive worker handoff

The archive producer is `RunArchive` in `archive.go`, selected by
`RunInternalJob` only for an `ArchiveJob` supplied by the native worker bridge.
This is a private capability bundle. It adds no public RPC, service-side file
copy, shell command, credential projection or ambient filesystem access.

The protocol types live in `internal/v2/archive`. Lifecycle retains aliases for
its existing `ArchiveControl`, `ArchiveIntent`, `ArchiveJob`, `ArchiveFreeze`
and `ArchiveCompletion` names. Worker input is now an `archive.Input` with schema
`laneboss.archive-input.v2`. It pins the original intent, job ID, protected
freeze object, allocated receipt/store IDs and exact worker budget. An old bare
intent is not an executable archive input.

The frozen snapshot and final receipt use the same immutable manifest object.
Its schema is `laneboss.objects.v2`; files reference artifact objects or bounded
large-file assemblies. The snapshot producer must retain actual current owned
workspace, required history and record/capture bytes. An initial workspace
snapshot, task-only inventory or the agent's zero-survivor observation cannot
stand in for that complete measured snapshot. The producer must remove all
writable access and measure known zero writers and writable exports. Unknown
counts fail. The worker does not manufacture this evidence.

Archive bytes are a deterministic uncompressed PAX tar. Its first member is
`manifest.json`, containing the canonical frozen object manifest, followed by
the sorted inventory under `data/`. Files contain the actual referenced bytes;
directories and safe internal symlinks retain their declared mode and target.
There are no host paths, user names, timestamps or executed Git commands in the
format. Both source part hashes and complete large-file hashes are checked.

`archive.PartSink.ArchivePart` is the required native service/store adapter. It
receives only the actual connection's lease, sequential index and at most
`api.MaxChunkBytes` bytes. The receiver must check the real worker principal,
current claim, lease, life generation, cancellation epoch, policy, revocation
and expiry on every append. It must atomically retain the part as an immutable
artifact under the original operation and life, then acknowledge those exact
persisted bytes. Repeating an index is allowed only for identical bytes. The
worker supplies no ACL, object ID, path, receipt identity or store identity.
The granted reader must include this job's persisted parts, frozen manifest
and its exact content inventory; it must not serve an upload buffer as read-back.

After closing the tar stream, the worker regenerates the canonical tar with the
same writer from the frozen manifest and committed file content, and compares
it byte for byte with every independently reloaded archive part. It hashes all
retained archive bytes, including padding, and requires exact EOF for every
part and the full stream. Parsed tar headers never decide equivalence. Added
PAX/xattrs, names, times, device numbers, alternative formats, sparse or extended
headers and even extra zero padding differ from the canonical bytes and fail.
Canonical long names and links use exactly the PAX records the writer emits.
The reader therefore needs the exact frozen content inventory as well as this
job's archive parts; lifecycle preserves the original scoped Store ACL checks
for both. A second archive/trailer, missing tar terminator,
extra/missing member, altered mode/link/file content, source mismatch, part
corruption, early EOF, reordering, budget failure or sink error prevents result
submission. The resulting SHA-256 is the hash of the tar, never the manifest.
The result is submitted through the original `WorkerBootstrap.WorkerResult`
with the exact input digest and lease generation. Process exit alone is not a
result.

The store/service adapter now implements the durable reservation, private
worker socket/part sink and atomic byte-exact completion described below. Its
native storage producer and administrator worker helper remain required
installed dependencies. See `../store/ARCHIVE.md` for the exact handoff and
collection ports; missing native support keeps the workflow unavailable:

1. `archive.Control.ReserveArchive` must atomically check the actual dispatcher
   winner and retained request bytes, consume the original proof once, fence
   the current run/generation/epoch and committed end, retain the measured
   freeze/snapshot and input, issue narrow read-only worker grants and a lease,
   and enqueue exactly one fixed worker effect under the original operation.
   Its public reply remains pending. `ArchiveJob` must read that durable record
   back, including after service restart. No second database writer or separate
   journal is introduced by this worker implementation.
2. The native helper must bind a distinct worker UID, enrolled runtime and fixed
   argv, current claim and worker-only endpoint to this exact job. The native
   client bridge must supply `ArchiveJob.Bootstrap`, `Read` and `Sink`. The
   existing `RunInternal` refuses the absent native bridge; it must retain that
   refusal until the real bridge exists.
3. The outbox must reconcile this same job after interruption. It must obtain a
   measured successful worker exit with zero survivors, load the retained
   result and independently use `archive.ReadBack` on persisted parts. Before
   committing, it must recheck the current claim and original life, policy,
   generation, cancellation, freeze and input fences under the original
   writer's transaction. It must atomically seal that operation's typed reply
   and `archive.verified` event. The org-only `DeferredReply` contract remains
   unchanged. Failed/unknown work keeps the workspace and cannot emit a verified
   receipt.
4. Lifecycle additionally verifies the completed worker principal, exact input,
   reserved receipt/store identities, unchanged frozen manifest, every part's
   original operation/configuration/life provenance, actual tar contents and
   independent full-stream digest before returning the receipt. Its final life
   fence is read again after the wait. G11 collection still requires the real
   committed verified receipt; this worker never marks work cleaned. The
   native archive store/collector must pin the result, all archive parts, the
   frozen manifest and its content references through collection. The public
   receipt alone does not enumerate those transitive retained objects.

The earlier serve2 request revision `6cd128f7` supplied the SQLite writer and
outbox. The archive adapter adds `ReserveArchive`, the archive `runEffect`
branch, the private native client bridge and durable part append. It does not
implement the administrator's current workspace/history/capture freeze,
native worker gate or workspace/branch removal. Installed G10 and dependent
G11 remain pending those native dependencies, the grants collector and their
Linux evidence. No adapter asserts a zero writer count on the native owner's
behalf.

The new tests retain actual bytes and include corrupt persisted-part and file
controls, raw-manifest substitution, missing/extra members, reordered parts,
early EOF, budgets, cancellation, foreign worker identity, unknown/nonzero
writers, sink failures and changed acknowledgements. They are unit protocol
fixtures, not native acceptance. Runtime qualification and omission red/pass
controls must run on the authorized disposable Linux machine. Static vet does
not execute them.
