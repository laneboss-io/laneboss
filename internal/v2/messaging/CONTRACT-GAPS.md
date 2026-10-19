# Messaging final draft.4 review closure

This is the current d4fix1 handoff for the review of c33d1d8 on the final
contract merge c6c68ca. Earlier requests in CONTRACTS.md and the draft.4
checkpoint are historical. Shared contracts and composition files are untouched.

## 1. CLI semantic validators (P0)

commands_messaging.go registers mail.send, mail.list and report.submit at Go
initialization using RegisterInputValidator. Each wrapper calls the same
DecodeMailSend / DecodeMailList / DecodeReport checks used by the service. Registration
errors stop initialization. No accepting stub or alternate file parser is added.

TestCLIFileInputs exercises one semantic-invalid and one valid file per method.
Invalid data must return the messaging owner's exact invalid_request before a
missing proof, key or socket can mask it. Valid data must reach a different
owner's binding/transport boundary. Accepted refusal codes are exactly
prerequisite_missing, not_implemented, unavailable and unsupported, all exit 69.
No other owner's stub message is pinned. cli-input-registration drops the actual
mail.send registration and requires the named invalid-file assertion to fail.

## 2. Contracted construction and canonical authority (P0)

New requires StateStore and Clock only. Authenticator, Grants and Human are
optional component adapters, rather than extra required composition inputs.
The contract's Launcher and Credentials are checked when channel execution is
requested. Assembly can construct messaging with its existing four-field call.

When optional adapters are absent, public requests require their transport-owned
connection/frame and verified live peer. Lane binding, containment, launch,
current life and grants come from StateStore. Current ancestor grants are checked
through Relation/Grants. Human operations resolve verified Proof and Enrollment
facts; reads use WithReadAuthority on the same connection. ProofUse remains an
atomic transaction guard, not a separate consuming call. Label-only Scopes do
not authorize public operations. TestContractDependencies and TestHumanStoreProof
exercise this contracted path and current revocation on replay. They model the
trusted connection/store ports and establish no kernel or WebAuthn acceptance.

## 3. Receipt ordering (P0 review correction)

The proposed move of all target/channel/relation preflights before replay is not
the frozen order. docs/design/v2-contracts.md:1769-1779 requires current
authentication/object authority, then LookupReceipt **before calling module
preflight**, proof consumption or base comparisons; pending operations use
AwaitReceipt. Lines 175-178 additionally forbid leaking receipts after current
revocation. Both obligations apply.

authorize now performs the live caller/connection/launch/grant gate before
enqueue. StateStore.LookupReceipt/AwaitReceipt must enforce current receipt
visibility under the authenticated scope and their errors are propagated.
The exact retained reply is then checked before target/content/base preflight
or another ProofUse. Current own-grant or credential revocation refuses a retry;
an unavailable target preflight cannot override an already completed visible
receipt. TestReplayOrderAndAuthority, TestContractDependencies and
TestHumanStoreProof cover these separate gates. Recomputing a changed target's
mutation eligibility before lookup would break the specified receipt-first
preflight order. No authority failure is swallowed.

## 4. Channel execution: exact request to lb-v2-integrate (P0 open input)

The prior channel branch committed a Deliver payload with an empty target and
no executable channel job. That invalid intent is removed: after exact level,
grant and enrollment checks, channel enqueue returns
not_implemented: channel.job.prepare before any event, mail write or effect.
It does not report a successful send or leave a permanently unexecutable queue
entry. L3/L4, missing, expired and borrowed grants still refuse earlier.

The shared contract already has ChannelJob, WorkerLease, WorkerLeases writes,
InjectWorker, Launcher and typed EffectOutcome.Delivery. The missing inputs are
narrower than the earlier note claimed:

* Enqueue receives an enrolled destination/credential handle, but no prepared
  worker lease or approved worker runtime manifest. ChannelJobRequest requires
  an existing EffectLease. A reviewed service-only preparation operation must
  resolve/mint the channel job's real Input/RuntimeManifest/grants, worker
  endpoint and per-destination effect/provider key before committing it.
  A task, channel source file or zero BlobRef is not a runtime manifest.
* DeliverChannel needs the fixed installed worker executable/bootstrap role and
  launch-spec handoff, committed identity/permit and protected input mapping.
  Launcher.Prepare consumes an already constructed LaunchSpec; it does not
  resolve the manifest/worker entry from an enrolled channel ID. No worker
  executable selector or binding-reference CLI grammar is frozen for RunInternal.
* Define the fixed channel worker's bounded input/output and measured provider
  receipt/read-back protocol, including uncertain outcomes and unsupported
  reconciliation. InjectWorker supplies scoped credentials, not a send result.
  A process exit cannot be converted into external-delivery success.
* Existing EffectStore.Effect/EffectOutcome.Delivery can retain a destination's
  confirmed result when its ChannelJob is bound to that effect. No new generic
  delivery database is requested. The preparation/executor must specify the
  claim/consumption and reconciliation correlation before a confirmed receipt
  can be replayed safely or an uncertain send retried.

Consumers: integrate/assembly, service/store/outbox, messaging, lifecycle/admin/
isolation, secrets and the E2E delivery fixture. DeliverChannel,
ReconcileChannel and RunInternal retain typed failures for the missing fixed
execution/read-back/entry handoff. They perform no credential injection,
process launch, direct service-UID send or fabricated receipt. The existing
constructor requires neither launcher nor broker merely to register ordinary
mail/report methods.

## 5. Parent turns and private mail (P1)

The uncontracted ValidateTurn helper and obsolete RecordReceipt stub are removed;
no other package consumed them. Existing tests and controls are migrated to the
contracted BeginDelivery/RecordDelivery ports. BeginDelivery uses the service-only
lease-bound MailForTurn read, retains the actual manual requester, and checks
self/authentic-ancestor control separately from each carried sender. It never
changes a parent Scope into a sender or widens public Mail ACLs.

TestParentTurnPrivacy requires that a parent have no participant mailbox entry
yet dispatch the authentic leased turn; a same-level sibling requester refuses.
TestTurnChecksEverySender, TestDeliveryRelationRecheck and
TestTurnRejectsRetiredSender retain their original refusal obligations on the
real delivery path. findMail's only lane caller is reply linkage; receipt calls
use the bound internal observer. receipt-open now removes the actual durable
mail write rather than testing a removed not-implemented compatibility method.

## 6. Continuation receipts (P1)

BeginDelivery requires the exact prepared run. RecordDelivery permits a later
run of the same immutable life/logical turn/epoch/cause, requires Intent.Target
equal Receipt.Target, and resolves TurnSnapshot/prompt/captures for that
completing run. Current life run/turn, epoch, mail CAS and authentic outside end
observations still apply. A profile-limit end still cannot acknowledge mail.
TestReceiptContinuation constructs an initial limited run and a final run-2
completion, and includes cancelled and stale-target refusals.

## 7. Internal actor and queued provenance (P1)

Enqueue effects use the bound module principal service/mail-delivery, with the
public caller retained as RequestedBy. Manual delivery fixtures use the actual
parent turn requester and its request ID, distinct from the first carried sender.
BeginDelivery checks and fences that requester's current control rights.

Lane-authored queue/report events describe their authentic sending life/run,
parent/root/chain and StarterEventSeq; their Mail payload separately retains
the recipient. Human sends use the actual target-life provenance. No recipient
starter sequence is guessed from RelationFacts (which does not expose one).
TestQueuedProvenance pins these facts. The outside E2E controller joins
independently authorized sender and recipient event views by immutable event ID,
so receiving actors gain no sibling lifecycle/raw-history access.

## 8. Human reply linkage (P1)

A lane with an exact granted channel can validate a reply to human mail addressed
to that lane. A human can reply to a visible report from the target L3/L4 without
requiring that lower lane to have a forbidden human-channel grant. Normal D7,
participant visibility and fresh human proof still apply. TestHumanReplyLinks
includes actual human-to-L3 enqueue and validation-only lane-to-human linkage,
plus wrong-kind and hidden-participant refusals. It claims no channel send.

## 9. Shared content screen (P2)

CheckContent now calls internal/credentialtext.HasCredential. Its nonempty
UTF-8/size, launcher-block and terminal-control checks remain. The divergent
private regex/assignment parser is gone. TestSharedCredentialScreen covers
punctuation and Unicode folded forms plus a granted-name reference.

## 10. E2E reporting and isolated CLI tests (P2)

bridge/control mark the active assertion reached before the first call can fail.
Observer failure writes a nonzero assertion exit while retaining the actual
operation result in the transcript. The real fail_active/finish path and first
failed bridge have focused observer tests. Existing CLI tests explicitly bind
their isolated test process to parser-case; no live session binding is changed.

## 11. Human mailbox reads (P2)

mail.list rejects an operation ProofRef on a read, verifies and carries
WithReadAuthority for a human connection, and rejects out-of-filter rows with
integrity. TestHumanMailboxBoundary covers a valid bound session, a foreign
connection session, closed connection, ambient proof and foreign life output.

## 12. Receipt event integrity (P2)

ValidateReceipt requires the causal turn sequence strictly after QueuedSeq.
receiptCaptures checks event schema/ID/range, duplicate IDs and strict sequence
order across pages before using prompt/capture observations. TestReceiptAfterQueue
and TestCaptureEventEnvelopes exercise these independently of other receipt gates.

## Verification and remaining gates

All new/updated tests and controls require Linux execution on the exact overlay.
Static checks establish no unit, mutation, transport, OS, vendor or installed
serve success. The current brief explicitly permits skipping vet after a cache
permission refusal; the actual refusal and static results are retained outside
the checkout. No tests/builds/project interpreter runs or remote calls occur
on this Mac, and nothing is staged or committed by this lane.

Internal exact replay/recovery after already committed BeginDelivery or
RecordDelivery still needs the store/lifecycle owner's reconciled intent rule;
duplicate direct calls currently conflict. Canonical verified-human/D6
DecisionAnswer production and authentic E2E/hardware/vendor fixtures also remain
their separate gates. No actor label or source-only review closes those gates.
