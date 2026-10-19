# Messaging contract amendments requested

Historical amendment requests follow. For current draft.4 status, resolved
requests, remaining typed failures and integration needs, read
[CONTRACT-GAPS.md](CONTRACT-GAPS.md). The earlier missing-type descriptions are
retained as history and do not describe the current shared API.

This file requests integration-owner decisions. It does not amend the frozen
API or grant authority. Shared sources and composition remain unchanged.

1. **Channel enrollment and authenticated worker lease.** `ChannelGrant` names
   a channel, but no frozen type or interface resolves its enrolled destination,
   credential handle, generation or fixed worker capability. `WorkerPlan.kind`
   omits channel, and `internal channel` has no binding/lease input contract.
   Add the narrow enrolled-channel resolver and single-use authenticated job
   lease, with selected credential/runtime output only. Define how one selected
   channel maps to multiple destinations if partial multi-channel reporting is
   retained. Delivery needs a stable provider idempotency key, per-destination
   durable receipt and reconciliation after a lost reply. A transport with no
   deduplication/read-back cannot blindly retry an uncertain send. Consumers:
   messaging, service/store, approval, admin/isolation, secrets, assembly and
   the delivery fixture. `MailSend`/`ReportSubmit` validate L5/L6 plus the exact
   effective grant, then return `not_implemented: channel.delivery.lease`.
   `RunInternal` remains a typed failure and performs no delivery.

2. **Internal delivery and logical-turn receipts.** `MessagingAPI` exposes
   send/list/report only. `Store.Transact` is bound to a public Request, but no
   internal transaction identity or mail phase/CAS interface is defined for
   beginning delivery, acknowledging it or returning it. Mail has no generation.
   Add a service-only port binding the original queued mail, recipient life,
   logical turn, causal observation and immutable effect ID. Atomic commit must
   recheck every sender and current grants while preserving the real manual/
   scheduler actor. Manual control of a child must not require granting that
   parent raw access to all of the child's private mail: a service-only mail
   read is needed without changing the original requester into a carried sender.
   Consumers: lifecycle, watchdog, messaging, store/service and assembly.
   `ValidateTurn` and `ValidateReceipt` perform preflight/observation validation
   only. `RecordReceipt` returns `not_implemented: mail.receipt.transaction`
   after validation; no successful receipt or delivery is manufactured.

3. **Report artifacts and questions.** `ReportRequest.artifacts` is absent from
   `Mail`, `report.submitted` (whose frozen payload is Mail), and the deliver
   effect. Silently discarding it would lose retained output. Provide a typed
   durable report/attachment object and ACLs, or another reviewed storage port.
   Also define the replacement for legacy `report --ask`: ReportRequest has no
   Ask field or decided-answer result. Consumers: messaging, records, store,
   lifecycle/archive, dashboard, CLI and migration. Artifact-bearing reports
   and `report --ask` currently return typed not-implemented errors.

Integration must also confirm these existing internal-store semantics used by
the component. They do not require a different public request shape:

* `Compare.Kind` values `lane` and `grants` compare the returned generations.
  Authority/revocation/expiry/proof are rechecked atomically, before effects;
  completed idempotency replay precedes base-generation/proof consumption.
* Event sequence, commit time and operation ID are assigned by Transact. The
  `mail.queued` intent initially has queued_seq zero; commit stamps the Mail
  payload/projection/effect with the actual queue event sequence atomically.
  The module reads back the committed projection and refuses a missing,
  unstamped, changed or out-of-range receipt. It never guesses FirstSeq.
* `Store.Mail` includes a participant's incoming and outgoing mail, uses
  increasing queue order, and provides current projected status while retaining
  original sender/source/content. A message addressed to the caller is visible
  independently of access to the other participant's raw lifecycle/history.
* `Store.Blob` permits a bounded read at the exact object end and returns an
  empty chunk with its real empty-byte hash. The 256 KiB boundary uses this
  read to reject an oversized object paired with a forged prefix reference.
* `Store.Lane` in the service's relation validator can resolve authentic
  relation metadata for a proposed peer, without exposing a public sibling
  lane.status/raw-history capability. Current scoped metadata reads alone may
  otherwise make legitimate sibling sends unavailable; do not widen public ACLs.
* `Client.Call` supplies the canonical request digest from the typed Request
  params (or integration supplies the shared request-preparation helper). The
  feature adapter supplies random request IDs, stable idempotency keys and
  exact typed bodies, and owns no alternative framing/canonicalizer. Common
  proof input and human CLI confirmation remain with client/service/identity.

The case fixture still needs the real installed identity/lifecycle setup,
human confirmation bridge, dashboard route, narrow channel sink and verified
collection from the shared E2E/integration lanes. No unit fixture proves those
dependencies. The run-2 brief reports that the combined wave-1 tree built on
Ubuntu 24.04 and passed the slice-1 messaging component tests with and without
laneboss_faults. That supervisor report does not establish full messaging E2E
or execution of the new slice-2 tests/mutations.

Slice 2 changes only contract-independent work: shared CLI private declarations
now use the lbV2Messaging prefix (the frozen dispatch entry names stay fixed);
focused tests cover grant selection/expiry, delivery relationship rechecks,
retired senders and receipt run/origin binding; and the acceptance case shares
strict content/actor/receipt/partial-delivery observers with its mutation tests.
The disposable-copy mutation runner records component and observer evidence
separately. It cannot prove the unimplemented producer paths by passing a data
fixture. The human raw-view and exact destination inventory now also need to
be supplied by the already-required dashboard/channel test fixtures.

Still required for this section are actual channel worker/outbox reconciliation,
internal delivery/receipt persistence and lifecycle wiring, durable report
attachments, question/decided-answer behavior, the common client digest/proof
adapter, and full CLI/dashboard/inside-process black-box acceptance. The existing
typed not-implemented paths are unchanged; no shared contract has been edited.

The run-3 brief reports that combined tree 2e661e2 built and passed the slice-2
messaging component tests on Ubuntu 24.04, with and without laneboss_faults.
The supervisor is running the mutation matrix separately; no matrix outcome
has been supplied to this slice. These reports do not close full E2E or live
vendor/human authentication gates.

Slice 3 completes more validation within the existing types. The CLI's result
decoders reject malformed Mail/MailPage/BlobUpload/BlobRef bodies, return no
partial decoded data on an integrity error, and keep the shared transport
responsibility unchanged. JSON body decoding rejects unpaired Unicode escapes
instead of silently replacing them. Receipt validation requires exact run-end
payloads, closed prompt/cause enums, UTC timestamps, causal mail/queue references,
ordered unique events and one authentic end for the selected run. A known exit
needs exactly one bounded exit code or termination signal. These are validation
checks, not a receipt-persistence implementation.

Integration's lifecycle producer must retain Trigger.mail_ids and the original
queued sequences in Trigger.causing_seqs for a carried-mail turn. Mailbox results
use ascending queue order, as described above. The pending internal delivery
port still needs atomic validation/commit and a service-only read without
borrowing a sender's authority. None of those missing capabilities is supplied
by a permissive local fallback or a new parallel wire object.
