# D6 draft.4 port status

This correction starts at the supervisor-provided merge `a1ba694`, containing
draft.4 fixes 3–7. The deferred-reply and fix-5 canonical parameter rules were
read. The duplicate draft.3 stub remains removed. No shared API, dispatcher,
composition, transport or other lane source is edited here.

The resolved deferred-reply contract and remaining integration needs are in
[CONTRACT-GAPS.md](CONTRACT-GAPS.md). Static consistency is not installed
acceptance, and the original positive application assertions remain intact.

## Receipt and proof adaptation

Lookup and await now compare retained MutationReceipt.Config in addition to the
exact method/key/digest, actor and original operation. Neither path reconstructs
config from the current caller. Component fixture storage uses config, actor
kind/principal/life, method and key, retains the original frame/metadata and
refuses changed intent under the same key. Completed replay still precedes
clock freshness, current base and proof consumption.

Only org.change.approve accepts an envelope proof. It first passes the common
human-kind and exact proof ID/intent/timestamp-shape preflight before receipt lookup. A lane proof is refused
even when an original receipt exists. Approve reuses those same helpers, so the
existing human-kind and proof-digest mutation controls still remove the actual
shared check rather than being masked by duplicate checks. This does not
re-authenticate native peers: transport creates ConnectionContext, peer verifies
kernel/binding/containment facts, and identity supplies the authentic Scope.
The module consumes that result and the verifier's real immutable proof facts.

## Transaction behavior and deferred publication

Propose retains the explicit approved base snapshot, renderer and ownership,
checks actual blob metadata/bytes, renders an independent input and commits
the exact staged change/event/reply with org and absent-change CAS. Approve
commits its verified key/nonce facts, exact ProofUse, org/absent-approval CAS and
approval/event/reply. These transactions obey the draft.4 public write catalog.

Apply preserves its current-L6, requester, base/provenance, approval lifetime,
identical revalidation and full blob checks. It constructs the same org-CAS,
ApprovalUse and causally bound ApplyChange intent. It submits Deferred with the
original reservation key/operation and that exact effect ID. The shared shape
validator checks this transaction before Transact. The pending Commit must
retain the same Deferred, nil Reply and pending/running status; a queued commit
is never returned as ChangeReceipt. AwaitReceipt supplies the real recorded
publication reply, whose scope, operation, retained deferred provenance and
completion status are checked before its typed result is returned.

Independent revalidation compares derived/diff content and metadata while
allowing fresh retention identities. Each rendered manifest remains validated
against its own references, and the module reads/hashes every fresh derived
After/Diff object before publication. The original approved references and
manifest remain the publication authority. A valid digest or equal metadata
without those fresh byte reads is insufficient.

Completed original replay still precedes freshness checks. A retained pending
Deferred now also bypasses apply preflight and awaits that same reservation.
Deadline/unavailable/cancelled waits preserve the original operation reference
and return no success receipt. They do not seal a final publication error or
create a second transaction. A final error reply cannot carry fresh effects.

Original transport bytes remain in RawRequest. The module compares the envelope
exactly and Params canonically, accepting equivalent whitespace/key ordering
while refusing changed intent or metadata. The store remains responsible for
frame verification and comparison against its original reservation.

The publisher still belongs to the service outbox/runtime. The module never
opens canonical paths, invents a publisher lease or relabels a public request
as a trusted internal job. The real store must enforce current authority, CAS,
one-use guards, publication serialization/gates and completion/reconciliation.

## CLI and human reads

The owned file-form adapter now opens or borrows the common invocation socket.
An explicit Invocation.Client is already open and is never closed here. The
common invocation owns its shared socket; a standalone owned connection closes
with errors preserved. Request preparation uses the current bound client and
retains explicit mutation keys.

A proof on change get is a proof for human.session with params {}, not a proof
for the read. It is shape/intent checked, submitted through the same connection,
and its typed response is checked before the proof-free read. Read results still
pass the owned exact request/result validators. The E2E case requires a fresh
real session confirmation for each human CLI read and compares the human's get
result with the exact staged proposal.

The module itself now requires a supplied bound ReadAuthority and a current
ConnectionContext read-session check for human get. It compares the stable
connection / session / key / principal / config / endpoint facts with the refreshed live
authority and uses that refreshed scope for the store read. Human scopes may
carry no lane fields/launch ID and must have a valid endpoint generation.

The generic common --request route now registers all four approval methods at
initialization through its fail-closed feature hook. Strict decoding wraps the
same exported semantic validator used by the ergonomic command and service.
Registration errors stop initialization. Invalid-file cases poison proof/key/
binding inputs and still require the exact owned semantic refusal; valid-file
cases require an explicitly permitted transport/binding error from another
owner. The authoritative service checks remain required for every route.

Both propose and apply call currentL6 before receipt lookup or protected work.
That helper checks the authenticated actor's lane kind/level/life and the
current recorded launch, including config, actor, endpoint generation and
revocation. Direct handler tests cover human and L5 actors for both methods,
with matching recorded facts and misleading L6-shaped labels. A role or ID
label alone never supplies L6 authority.

## Checks and acceptance

Existing tests and all earlier recipe definitions remain. New component tests
cover retained receipt config/domains, proof rejection before completed replay,
scoped await bytes and local read-session proof validation. Directory privacy
fixtures remain ordinary, test-owned and explicitly 0700.

All four retained application recipes execute again: apply_guard,
publication_wait, await_status and deadline_operation. Additional recipes cover
the deferred transaction/commit binding, pending retry, foreign deferred
metadata and canonical parameter encoding. Every selected recipe still
requires its exact semantic red assertion and the same restored test green.
Pending installed rows remain blocked/69 under --require-complete.

The supervisor observed all four TestApplyCompletion subtests failing on the
old not_implemented path. Their original outcome assertions remain intact;
the fixture now asserts and returns Commit.Deferred. Only Mac static checks
are permitted here. Full unit/red/installed results on this correction remain
unverified until laneboss runs the exact Linux tree.
