# Dashboard review correction handoff

This source overlay starts at 0e85355. It addresses the new delta findings and
the six findings from the second counted review. The earlier thirteen findings
were reported closed by the delta review. These new source changes still need
Linux candidate/red execution and both counted reviewers' approval. No lane was
accepted, staged or committed by this run.

## Per-item changes and deciding assertions

| Review item | Source behavior | Regression and red control |
| --- | --- | --- |
| N1 / review 1: stale-cookie lockout | Unauthenticated session cookies are expired on HTTP responses. Authentication staging clears and strips the stale cookie, then reaches the protected bootstrap transport without a session claim. Forbidden labels/configuration and valid-cookie connection binding still refuse. | TestDashReauth completes challenge, confirmation, a new native fixture connection/session and an authenticated read after idle expiry, local/identity revocation, restart and an unknown cookie. d5-reauth-stage, d5-reauth-cookie and d5-reauth-forward fail its named ceremony/browser assertions. TestDashReauthLabels and d5-reauth-label retain hard header-label refusal. |
| N2: attestation request, dashboard half | The page requests direct attestation and passes the complete clientDataJSON and attestationObject byte arrays unchanged. The dashboard does not parse or verify the attestation statement. Identity's server refusal is displayed as inert text. | enrollment-test.cjs checks direct mode, exact forwarded bytes and the exact server refusal. d3-real-attestation now removes the direct request; d5-web-refusal hides the refusal. The earlier accept-none control was replaced, not reported as hardware verification. |
| N3: policy advance | A policy conflict permits one reload from the protected live policy store and one recheck, while preserving the connection/principal/session binding. The verified generation is retained in the cookie cache. Passive recovery never refreshes read-session deadlines. | The fixture now rejects stale policy generations in authorization and IdentitySelf. TestDashPolicyReload checks durable session facts remain unchanged during cookie recovery and a subsequent foreground read succeeds. d5-policy-reload prevents adoption of the current generation. |
| N4: SSE overflow | Recoverable end frames leave EventSource open so the browser can reconnect with Last-Event-ID. Authentication, forbidden and deadline errors close it. | review-test.cjs checks recoverable overflow and hard authentication closure without background fetches; d5-web-overflow restores unconditional closure. |
| N5 / review 6: stopping projection | lane.stopping sets stopping even without payload.to. Missing/zero generation leaves the current generation intact. Policy events must advance policy generation and exactly the next lane generation with the same grant set. | The web fixture exercises missing fields, invalid policy advances and a valid advance. d5-web-stopping, d5-web-generation and d5-web-policy name the deciding assertions. |
| Review 2: pre-filtered history | Raw, refusal and lifecycle reconciliation reads all runs before selecting display rows. Resource reconciliation includes org approvals/applications and worker materialization across life IDs. Decision supersession is collected across scope/level/run before active candidates are filtered. | TestDashViewHistory, TestDashDecisionScope and TestDashResourcePresence. d5-history-*, d5-decision-scope and d5-resource-history restore early filtering. |
| Review 3: presence provenance | Resource rows retain their approval ID from prior approved events even when an applied receipt omits it. HTTP resources require service-computed presence metadata. SSE headers inspect the initial event payloads; later frames update cached UI provenance. Empty approval IDs cannot taint unrelated views. Enrollment completion uses the shared reporting headers. Human approval always remains not_proven. | TestDashResourcePresence, TestDashResourceMetadata, TestDashEnrollConsume and the web fixture. d5-resource-presence, d5-presence-required, d5-sse-presence, d5-enroll-presence, d5-web-empty-id and d5-web-live-mark remove the corresponding gates/marks. |
| Review 4: enrollment lifecycle | A valid browser completion handle is removed under the mutex before calling the protected transport. Success and failure clear the cookie. New begin requests replace the prior browser/ceremony entry before enforcing the capacity bound. Receipt operation/event/blob IDs, digest, artifact class, size and simulation status are validated. | TestDashEnrollConsume races two requests with a controlled in-flight transport; only one may be forwarded. TestDashEnrollFailure refuses reuse after a service error. TestDashEnrollRetry performs 24 retries across browser/ceremony replacement. TestDashEnrollReceipt rejects six malformed receipt variants. d5-enroll-*, d5-receipt-* name their own assertions. |
| Review 5: truncation and replay | Mail and record inventories follow every store cursor without increasing the 200-item request limit. Repeated cursors/incomplete nonadvancing event pages refuse. Terminal mail state and newer resource generations survive historical replay; delete generations prevent resurrection. Time-bounded views exclude missing/invalid observation timestamps. | TestDashAllPages uses 205 items and a store capped at 37 per page. TestDashPageCycle, TestDashEventCycle, TestDashSnapshotWins and TestDashMissingTimes cover the other cases. d5-pages-*, d5-page-cycle, d5-event-cycle, d5-resource-snapshot, d5-mail-snapshot and d5-time-* name the deciding diagnostics. |
| Review 6: canonical decisions/change errors | Every normalized projected decision field must match the verified canonical document. Change lookup errors other than not_found propagate, including an empty change-index probe. | TestDashDecisionCanonical alters binding, effective time, applicability and source metadata after a positive canonical read. TestDashChangeErrors checks both known and empty inventories. d5-decision-canonical, d5-change-probe and d5-change-error remove the checks. |

## Resource provenance transport contract

ResourceView has no simulated-presence field in the frozen RPC schema. The
HTTP adapter therefore creates request-scoped response metadata before calling
HumanTransport.Dispatch. Dashboard resource projection records its per-path
provenance while it reconciles the same authorized store read, then marks only
the returned resource page. No global approval cache or extra unauthenticated
store read supplies this metadata.

An installed transport must preserve the dispatch context into the registered
handler. A transport which crosses a process boundary must carry provenance
from that same authorized pinned response and call the public dashboard-local
RecordHTTPPresence helper on the original dispatch context. Missing metadata
returns lb-v2-service not_implemented; it never becomes a not_proven success.
This adds no browser request field or frozen RPC field. The helper cannot turn
an already simulated response back into an unmarked response. The separate
non-refreshing SSE capability remains unchanged.

## Attestation boundary still pending identity

Requesting direct attestation is necessary but does not verify a device. A
browser may withhold it, and a self-attestation alone does not establish a
hardware manufacturer. Identity owns release refusal of none/untrusted/software
attestation, certificate/signature/AAGUID checks against protected trust pins,
and any supported-format changes. The admin/service owners still own the
durable single-use registration commit and owner-only ceremony. No frontend
certificate verifier or trust bypass was added.

The browser-to-identity integration fixture now forwards signed packed bytes
instead of requesting acceptance of none. Modified origin and UV cases are
re-signed so the intended origin/UV gate, rather than an accidental bad
signature, decides their negative result. Its generated self-attestation is a
component fixture, not release hardware-trust acceptance. The generic software
authenticator concern remains SUSPECTED until the real canary and its refusal
control execute against the installed identity implementation. The owner alone
enrolls the real hardware key at final acceptance.

## Validation and retained evidence

The manifest contains 120 source controls, including 44 additions. Each names
its own regression and intended diagnostic; test/subtest names stay under forty
characters. Controls that touched changed code were updated, including the
enrollment decoder mutant's import and the service-dispatch context. Source
anchor inspection is not a compiling-mutant or runtime result.

Only static checks are authorized on this Mac. Linux must run the candidate
packages, the retained red controls and the installed browser/service rows.
The source baseline, exact briefs/reviews, overlay, full patch, source hashes
and check outputs are preserved outside the checkout in the run-5 manifest.
No production credential, model request, cloud action or browser runtime was
started here. Both counted reviewers still decide acceptance after the required
Linux evidence exists.

Observed checks in this run: gofmt -w completed for eleven changed Go files,
and gofmt -l printed no paths with exit 0. Linux go vet exited 1 at the default
Go-cache permission boundary with operation not permitted. Per the explicit
brief recovery route, Linux/faults and Darwin vet were skipped without a cache
override or retry. No passing Go type-check, unit test, renderer, red mutant,
generic-software-authenticator canary or installed acceptance result is claimed.
