# Draft.4 approval integration needs

Source: the supervisor-provided baseline `f020839`, with draft.4 fixes 3–7.
These are source-observed contract/integration issues, not claims of an
exploited vulnerability. This lane edits no shared API, transport or dispatcher.

## Resolved contract: deferred synchronous publication

Draft.4 fix 3 defines `DeferredReply` on Transaction, Commit and MutationReceipt.
Apply now submits the original key/operation and its causal publication effect
ID in Deferred, alongside org CAS and ApprovalUse. The validator remains in the
production path. The returned pending commit must retain that exact binding,
nil Reply and a pending/running operation. Apply then awaits the store's actual
durable reply. A pending retry awaits its original reservation without repeating
approval, snapshot, rendering or transaction work. Fix 5's canonical Params rule
is honored while RawRequest retains the exact original transport bytes.

The local not_implemented path for the old representation gap is removed. Every
original completion assertion remains, and the four application recipes execute
again. Runtime acceptance still requires the service/store/outbox/publisher to
persist the guarded effect, org gate and deferred binding atomically, complete
it under its real claim once, and return its measured durable reply. Static
checks and port fixtures do not establish that installed behavior.

## Resolved: shared generic approval CLI validation

The owned adapter registers all four org.change methods at initialization with
`RegisterInputValidator`; a registration error stops initialization. Each hook
strictly decodes the body and calls the same ValidatePropose/Get/Approve/Apply
function used by its ergonomic command and service handler. The common file
path therefore performs these checks before proof, metadata or socket work.

Per-method file cases require the exact owned invalid_request and a valid body
that reaches transport. The latter accepts only a non-approval not_implemented
or prerequisite_missing refusal at the deliberately missing binding; it does
not pin a dependency's stub message. A dropped-registration control targets
the same get invalid-file case. Real transport, identity and publication remain
part of installed acceptance, not these local input fixtures.

## Runtime acceptance

The installed serve path still needs the real identity, store, worker,
publisher and service fixtures plus the independent review required by the
brief. Human read proofs establish human.session on the same live connection;
session IDs or a label in fixture data never replace that authority. No runtime
or authenticated AI-service result is claimed by this lane's Mac checks.

The service/object ACL and grants integration must permit the proposing L6 to
read the renderer-produced Diff, derived after objects and service-produced
OwnershipManifest used by verifyChangeBlobs at propose/apply. Human review
must also read every retained reason/source/derived/diff/ownership object under
its current session. An object reference alone confers no visibility; missing
ACLs correctly refuse and cannot be fixed by broadening this module's scope.

Independent apply rendering may retain identical output bytes under fresh IDs.
The proposing L6 must also be able to read those fresh Diff/derived objects in
verifyRenderedBlobs. Both new and approved references are checked against
committed metadata, all bytes and EOF. Revalidation compares derived path,
action, mode, before SHA and after SHA/size/class, plus diff SHA/size/class;
it does not require object ID or newly computed manifest equality. Each
manifest must still validate against its own references. Publication retains
the original approved change/manifest/references and never substitutes the
fresh render's object IDs.

The store must preserve a nonnil empty Derived array through persistence and
rebuild: [] remains [], never null. ValidateChange deliberately rejects nil;
readChange does not silently normalize invalid retained data. The round-trip
and null refusal are pinned by TestRetainedEmptyDerived. This is a store
integration requirement, not a claim that the fixture implements persistence.

For human org.change.get dispatch, bind Scope.ReadAuthority from the current
ConnectionContext before invoking the approval module, using
api.WithReadAuthority. This applies to the change-owner method even though it
is not classified as a human staging/preview method. A session on the socket
alone is insufficient: the module requires the already bound scope facts,
refreshes the connection's live authority and compares them. The dispatcher
must check current connection/session lifetime and revocation; request fields
cannot supply authority. Perform this transport work outside store locks.

## Proof expiry and challenge lifetime

The chosen integration rule keeps the module's secondary expiry-minus-
VerifiedAt sanity bound and makes its assumption explicit: ProofRef.ExpiresAt
equals the original HumanChallenge.ExpiresAt. Identity/CheckProof must enforce
the actual challenge lifetime from issuance (at most 120 seconds), require
verification within that challenge, and retain the same expiry in the proof.
It must not give a confirmed proof a new longer lifetime. The shared
human.confirm evidence check in api/assertion.go already requires that expiry
equality as part of the identity transaction contract.

VerifiedAt is the later confirmation instant, not the challenge issuance time;
the module's subtraction is not evidence that the issuance window was valid.
VerifiedHumanProof does not carry issuance, so the approval module relies on
the verifier's original challenge record for that check. The module separately
requires now before proof expiry and keeps the approval's independent ten-minute
window, clamped only by stage expiry. The overlong-facts test is defense in
depth against inconsistent verifier facts, not a challenge-issuance test.

## Dispatcher reservation ownership (Gemini item 5)

The requested feature-owned ReserveRequest/serialization change is inconsistent
with the frozen division of responsibility. Section 14, "Durable requests,
guards, objects and read snapshots", says: "For a public mutation the
dispatcher authenticates the current connection/frame and object authority,
prepares the exact Request, then LookupReceipt **before calling module
preflight**, proof consumption or base comparisons." It continues:
"ReserveRequest persists a pending operation and exact frame before external
work" and "A pending retry awaits that operation through AwaitReceipt, never
executes it twice."

ReceiptStore.ReserveRequest returns MutationReceipt without a reservation-owner
or replay flag, and Scope carries no reservation-owner token. The module cannot
distinguish its dispatcher's fresh pending reservation from another in-flight
retry. Awaiting every pending receipt would await its own first request;
reserving again would not solve that ambiguity. Direct ApprovalAPI invocation
without the dispatcher's authenticated reservation is intentionally incomplete.

Section 14 also requires: "A failed module preflight after reservation is
completed by an empty state/effect transaction carrying its typed Error."
Service/dispatcher must serialize dispatch, await competing retries and seal
final preflight errors on the original reservation. Transient errors leave it
pending (section 2); a committed Deferred must never be double-sealed by the
dispatcher when a publication wait ends. This lane returns the original typed
error and retains the Deferred wait semantics. The integrated dispatcher must
demonstrate these obligations with concurrent propose/approve, typed final
preflight failure, transient retry and post-Deferred timeout cells. No feature
fallback or invented ownership token is added in the exclusive approval files.

## Immutable replay and publication binding (Gemini item 4)

The fresh apply path verifies the measured publication manifest against its
retained change, now covered by TestApplyHandlerGuards/publication. Completed
replay and pending Deferred retry intentionally do not read current Change
projections. Section 14 says: "Replay returns those bytes, not a later
projection." Its completion rules require the store to authenticate the real
Publication and typed reply "against the approved change and filesystem
marker; matching shapes alone are not publication evidence."

That immutable completion binding belongs in CompleteEffect/store. Reading a
current Change from the replay path would make the original durable reply
depend on later projection availability and rerun preflight after publication.
TestCompletedReplay and TestDeferredRetry retain their zero Change/blob-read
assertions. Integration must reject a wrong-manifest completion against the
original retained approved change before it ever becomes a replayable reply.
The feature's result-shape validator cannot replace that store obligation.

## CLI integration and initialization

The canonical installed-case calls use --request and --proof. The owned
--request-file/--proof-file adapters remain compatible and use the same shared
raw-byte api.RequestDigest. RegisterInputValidator receives method/raw only;
it cannot see an alias command path. Alias intent routing belongs to common
CLI integrateValidateAlias (commands_integrate.go). Integration must validate
org channel/instance/roles/render alias targets before routing a proposal; this
lane cannot infer alias intent or invent a resource-kind allowlist from Params.
No shared CLI file is edited here. A duplicate validator registration still
panics at initialization by design, including in a composed serve process.

## Frozen installed harness

The owned case now supplies case.json and run.sh, consumes --context/--result,
and writes the frozen atomic result in candidate and red phases. It constructs
all eight defects and observes the installed CLI's actual stderr and exit.
The E2E owner must enroll the fixed cli_canary.py and write_job.py under the
authentic recorded L6/L5 targets; protect root-owned job settings and control
bindings; pin the exact binary/adapter/job bytes; and return their real framed,
peer-authenticated controller observations. No arbitrary fixture command can
replace a product call. Unknown or missing jobs/clocks/UI are unreached setup
failures, never a skip or a killed mutation.

The current fixed-job input/output conventions and data fixture are documented
in the case README. In particular the extra-effect fixture must independently
produce a different derived inventory, mode or byte/diff after the enrolled
fixture Clock advances while its renderer pin and source/base remain fixed.
A new object ID with identical bytes does not establish that defect. The
policy cell stages actual schema-valid approval-policy source bytes and uses
an unverified operation proof under current policy; no invented waiver key is
introduced. Hardware/live-human confirmation is a separate enrollment/evidence
mode. This credential-free installed case is not an authenticated AI-service
test and has not been run on this Mac.
