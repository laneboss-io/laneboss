# Draft.4 review corrections

Historical record restored from f64e2ea. Current source and installed readiness
are maintained in cases/ladder/READY.md and plan.json; old missing-port claims
and prior test counts below are not current acceptance results.

This ledger describes the earlier d4fix1 review. Draft.4 fixes 10 and 11 now
supersede its initial launch transaction/ticket timing and persistent-reader
limits. See cases/ladder/READY.md and ladder/README.md for the current contract,
installed commands, normalization and still-unlanded consumer ports.

Authoring base: 500fe6e, containing c6c68ca. This is an implementation and
static-review ledger, not a Linux or authenticated service acceptance result.
The supervisor reported the previous 136-unit port green on its Linux box.
This round adds review controls and changes fixtures; that old result does not
cover these changes. No unit or project interpreter runs on the authoring Mac.

| Review item | Change and regression |
| --- | --- |
| independent Claude reviewer 1; Gemini 2 | SESSION_MUTATIONS follows api.HumanSessionMethod, including all seven rows. Session rows reject Proof/Ticket/Approval; other ladder rows reject unrelated authority guards. CLI staging validates human.session intent; human authority mutations validate the exact operation proof, expiry and reuse. SessionShapeRegressions and LiveReadRegressions exercise the inverse guard rule and wrong/expired/reused proofs before dispatch. |
| independent Claude reviewer 2; Gemini 6 ticket portion | ticket_events binds redemption to the original root lane.start operation and receipt sequence interval. Issuance precedes creation; root grant, level and role match the ticket. The fixture emits creation then redemption. TicketRegressions tests that conforming order and foreign operation/out-of-range/grant controls. |
| independent Claude reviewer 3; Gemini 4 | run.py adds --red-check. result_file requires the expected failure.json check_id, a reached assertion and normal non-prerequisite exit. A generic exception or another named check cannot kill the mutation. Missing fields inside verification become shape failures. NamedRedRegressions checks unrelated/generic failures, exact matches, missing targets and exit 69. |
| independent Claude reviewer 4 | The observer proof-provider action is removed. Until the installed CLI supports an approved persistent event/blob/projection workflow, run_pair refuses before observer polling, human proofs or root start. The refusal uses not_implemented with owner lb-v2-identity. LiveReadRegressions checks no CLI/observer calls and the retained zero-proof/zero-start receipt. This is the review's permitted refusal route, not a completed persistent CLI implementation. |
| independent Claude reviewer 5; Gemini 1 | Obsolete ownership trees were already removed at the supplied HEAD. They are not restored. README no longer claims they remain unchanged. |
| independent Claude reviewer 6; Gemini 8 Deferred portion | Transaction.Deferred and Commit.Deferred exist at c6c68ca, as do typed completion validators. Documentation now says the missing piece is observer normalization for deferred completion. The ladder applies no org change. The E2E-owned normalization gap is named accurately. |
| independent Claude reviewer 7 | Non-JSON CLI stderr now produces integrity with the actual exit code, lb-v2-service and the retained command receipt path. Raw stderr remains unchanged. LiveReadRegressions checks exit 2 plain text against that owner/receipt. |
| independent Claude reviewer 8 | zero_exit requires prompt completion only when selected_end validates lane.ended. Clean-time quiescence retains successful exit, zero-survivor and no-signal checks. WholeReviewRegressions pairs an empty clean prompt with an incomplete ended prompt. |
| Gemini 3 | The incompatible alternate service boot was removed from the canary helper. Private runtime/state/secrets directories use 0700 with the service UID/group. Client wrappers require actual class-specific installed bindings and validate startup session proofs. The admin install.sh and composed serve case cited by the review are absent from this HEAD. The source fixture refuses before privileged provisioning; reuse of that installation handoff remains open with lb-v2-admin. No second production installer or guessed file protocol is added. |
| Gemini 4 smoke portion | Smoke command collection runs on assertion failure as well as success. Named ladder failures count as reached at the point of failure; missing prerequisites reset reached. SmokeCollectionRegressions and NamedRedRegressions exercise these paths. |
| Gemini 5 | Every retained blob is rehashed, every public BlobRef in events/lanes/archive readbacks is checked, and root_answers must match L6's retained RESULT. Blob evidence failures carry transcript. Copied inputs and observer bytes are retained/read back. Source/download/fixture archives verify all retained member bytes. Root helper writes also read back their descriptors. WholeReviewRegressions, EvidenceRegressions and descriptor controls cover byte corruption and inventories. |
| Gemini 6 remaining portions | Session, ticket, turn, loop and blob event coverage is required alongside prior mutations. Original/replayed root CLI intents and read intents cannot be empty. Replays return the original receipt without new writes/events/effects/guards. Session event/ID/proof bind to one socket and an atomic proof-use event before the read response. The fixture now includes these histories and an internal root turn caused by its loop. WholeReviewRegressions exercises the missing receipts/intents, replay guards, early reads and session changes. |
| Gemini 7 | Continuation fences compare the previous and following epoch, distinct profiles and complete LimitSignal/Room shapes. Resumed runs require vendor identity and valid launch kinds; normal exits forbid a following profile swap. Releases correlate allocation, binding, target/run and preceding end. Every child run must belong to an allocated/released lease. Merged and cleaned children need both cancellation events and epoch advances. Lane/GrantSet replies require full public fields. Existing Draft4ShapeControls plus WholeReviewRegressions exercise these invariants. |
| Gemini 8 controls portion | Optional controls is accepted only as a protected absolute file; --controls passes the original binding and retains its bytes. EvidenceRegressions tests the optional field and protection. The real closed controller/discovery remains explicitly absent in CONTRACT-GAPS; dependent integration cases cannot pass without it. |
| Gemini 9 | prep returns the resolved compiler; the unit process receives LANEBOSS_GO and local toolchain policy. resolve_go honors that one named selector. Installation precedes Observer construction and the observer uses the install result. BoxOrderRegressions checks a binding that only exists after installation and the unit environment selector. |
| Gemini 10 | Kernel and privacy measurements match actual bound containment IDs. Failed lifecycle/worker/operation and refused/incomplete policy events reject. Digest fields require SHA-256 hex, including source inventories. Case.finish rejects links and writes a single current failure receipt before hashing. WholeReviewRegressions and EvidenceRegressions exercise these failures. |

The proposed receipt and transaction observations remain harness normalization,
not extra public service DTOs. Their real protected producer remains a named
prerequisite. Test fixtures do not satisfy any installed acceptance case.

Two review recommendations need the contract qualifications recorded in
CONTRACT-GAPS. Store-owned redemption follows submitted creation within the
atomic start receipt. Lease IDs are life-scoped and may remain bound over
multiple runs; conflicting binding history must fail, while consistent history
must not be rejected solely for repeating a lease ID. Internal lifecycle and
worker completions retain their public cause; event kind alone cannot imply a
second public request or a second idempotency reservation.

Read-authority proof count in the current ladder refusal is zero per tree and
zero per pair. An installed smoke snapshot consumes one. Four active session
windows per tree would be the minimum for a future 6900-second run under the
30-minute absolute limit; a five-minute idle gap requires earlier renewal.
This is planning arithmetic, not an observed authenticated AI-service result.

On the authorized Linux test box, run the candidate harness controls with:

    bash scripts/v2-e2e/unit.sh --out /var/tmp/lb-v2-ladder-review-units

The supervisor must also show baseline failures for the changed regression
targets before claiming red-to-green evidence, then run normal/fault product
tests and installed service cases. Static compilation does not demonstrate
those failures or passes. Continuous ladder acceptance remains stopped at the
persistent read prerequisite, and the old source fixture at the admin handoff.
