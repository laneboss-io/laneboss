# Prepare-stage audits and preview batching

These are open contract limitations from the counted port review. No shared
API, store schema, policy behavior or composition file is changed by this lane.

Before request retention, a credential screen, cap, question-count or cost gate
can return an unavailable reply. Fit returns a typed `unscored` error for a
withheld request; Evaluate returns `status: unavailable`, an explicit reason,
no probabilities and no request/raw ref. This is a failed observation, never a
judgment or policy allow. `TestStructuredFragmentsStillWithhold` asserts the
typed Fit result, unavailable Evaluate result, no retention/HTTP and rejection
by ScoredReply. The configured outage behavior belongs to the policy consumer:
contracts section 7 requires applicable critical refuse-band rules to fail
closed; other entries allow with notice/audit, and warn never blocks. The policy
implementation here is still its owner's not_implemented stub, so no composed
outage-policy pass is claimed. That owner must retain an unavailable outcome
and apply its configured policy rather than substituting probability zero.

`JudgeAudit.Request` is currently a mandatory BlobRef. CommitAudit requires the
same nonnil reply Request and independently reads those exact bytes. AuditReply
also requires the full request length, a fit observation and a complete result
set. A pre-retention withheld request has none of that evidence. Retaining its
secret-bearing content merely to obtain a ref would defeat the credential
screen. Empty refs or invented probabilities/fit proofs would be false evidence.
Thus prepare-stage audit completion remains unsupported by this API.

The requested amendment is a typed audit stage/outcome that permits an absent
request ref for prepare-stage unscored outcomes, with a digest and byte count of
the exact prepared input when serialization succeeded, a fixed safe reason,
question-ID coverage, explicit not-sent/unknown usage-cost status, provenance,
times and the same authenticated cancellation/CAS boundary. It must define
validation for serialization/batch-bound failures where no provider body exists.
Only the screened, retained stage may carry BlobRefs or a serving-token proof.
Store and event consumers must accept the same stage union before this lane can
consume it. CONTRACT.md lists the related persisted dispatch/accounting gap.

Preview currently supports one complete batch, up to the configured MaxQuestions
(at most twelve). resolveRequest includes every approved policy rule; Payload
returns typed unscored for thirteen rather than dropping any rule. The adapter
returns unavailable with `complete question set exceeds batch bound`, no score,
no BatchIDs and no retention/HTTP. TestSingleBatchPreviewBound pairs twelve
scored rules with thirteen explicitly unavailable rules. TestScopedPreviewSingleBatch
checks the real scoped Fit/JudgeAsk boundary. These tests document the limit;
they do not claim batching has been implemented or that the defect is closed.

An honest multi-batch preview needs a typed list of batch observations, each
with its request/raw refs, exact question IDs, model/pins, full fit, usage/cost,
deadline and status, plus aggregate completeness and original receipt links.
Current JudgeReply has one Request, Raw and InputBytes/InputTokens/CostMicros;
BatchIDs alone cannot identify or validate those per-batch receipts. The adapter
retains blobs but has no authenticated audit-publishing/dispatch callback, and
the scoped service is gated on the missing egress lease. Repeating HTTP and
selecting one batch's refs for a merged score would violate exact evidence
validation. The contract owner must define aggregate/per-batch reads and writes,
atomic policy/result semantics and one total deadline/cost reservation. Then
the dispatch/completion owner can publish the batches and this lane can aggregate
them without inventing refs. Until then preview is explicitly single-batch.
