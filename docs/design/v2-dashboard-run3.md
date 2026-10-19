# Dashboard review and real-device enrollment handoff

The [run-5 review correction](v2-dashboard-run5.md) supersedes this slice's
enrollment attestation mode and resource-presence transport details. Hardware
trust remains an identity-owned acceptance boundary.

The [run-4 polling correction](v2-dashboard-run4.md) supersedes the poll-rate
test's timing/code assertion and updates the control count to 76.

This run starts at 9b795e9 on lb-v2-dashboard. The retained changes are an
uncommitted source overlay. The review examined 9766281; the run also preserves
run 2's non-refreshing SSE capability and five-minute idle/thirty-minute absolute
session contract. No shared RPC DTO, method catalog or frozen store port changes.

All findings below have source changes and named regressions. Runtime closure is
pending the authorized Linux red/candidate and installed-service runs. Suspected
security effects remain SUSPECTED until the actual canary and control execute.
Source inspection, generated fixture keys and a static check do not establish an
installed service, native peer verification or physical authenticator presence.

## Review items

| Finding | Resulting source behavior | Regression and red control |
| --- | --- | --- |
| P1-1: external transport | HumanTransport.Scope receives a public SessionClaim containing the dashboard-resolved SessionID, Actor, original native ConnectionID and EndpointGeneration. A claim selects the service's protected registry entry; the service must independently recheck it. The native connection remains bound for its lifetime; browser TCP connections may change. A cookie on a staging request also supplies the claim. | TestDashPublicTransport is in package dashboard_test, uses only public APIs, establishes its cookie over HTTP, and reads through six distinct HTTP connections. d3-public-claim omits the claim and must fail with “public transport lost cookie claim across connections”. The test also refuses a returned foreign principal. |
| P1-2: service event over cookie SSE | The HTTP regression stops a lane, reads lane.status, and parses the actual SSE event. Installed acceptance records the pre-stop sequence, executes the exact authorized stop, reads the final lane, and requires a later lane.state event with service origin, matching life/run, ID, state/generation and committed sequence. It retains original SSE bytes. Both DASH-STOP and DASH-LIFECYCLE depend on this observation. | TestDashServiceEvent; d3-service-event drops the StreamFrame event pointer. CaseTests.test_service_event rejects terminal-only, foreign-origin, foreign-target/run, historical, uncommitted and mismatched-state frames; d3-e2e-terminal and d3-e2e-origin name the deciding assertions. |
| P2-3: missing pins | All HTTP routes return dashboard-owned prerequisite/503 until configuration, HTTPS origin, Host and RP pins exist. ConfigureHTTP rejects HTTP, userinfo, query/fragment, foreign RP and changes to already installed pins. Host and Origin have no empty-pin fallback. | TestDashUnconfiguredPins and TestDashHTTPSPins; d3-default-pins substitutes client-selected pins, and d3-https-pins admits HTTP. |
| P2-4: 50 ms polling | Follow streams have one initial bounded read and at most one scheduled batch per second. A batch performs one non-refreshing cookie check, Scope and PollEvents call. Cancelled/deadline-expired ticks cannot start another batch. | TestDashPollRate observes the real stream's service calls; d3-poll-rate restores a 50 ms ticker. Existing passive-idle, foreground-refresh, revocation and absolute-cap controls remain. |
| P2-5: expired proof | Shape/digest checks precede a dashboard clock comparison. Expired proofs never enter Dispatch. A separate optional HumanReceiptTransport.ReplayCompleted may look up an already completed exact receipt after current authentication/revocation/visibility checks; it cannot reserve, await, execute or consume a proof. Absence or a missing receipt refuses with 403. This preserves the frozen receipt-first retry rule. | TestDashExpiredDispatch counts normal dispatcher calls at the exact expiry boundary; d3-expired-dispatch removes the clock gate. TestDashExpiredReplay requires the original receipt without a second stop and refuses a fresh key; d3-expired-replay wrongly rejects every expired retry. |
| P2-6: stale tokens | Replacing a session binding removes its old token. Each successful tracking operation sweeps absolute-expired token/ID entries and elapsed revocation tombstones. Reuse of the same binding retains its token and original absolute deadline. Cached idle deadlines never drive the sweep. | TestDashTokenLifecycle/replacement and /sweep; d3-token-replace retains the previous token and d3-session-sweep omits cleanup. |
| P3-7: route ordering | Unknown GET routes return 404 before cookie/transport lookup. Known views parse their query and create exactly one bound read request. | TestDashUnknownRoute and TestDashScopeCount; d3-unknown-route and d3-scope-count remove ordering or repeat Scope. |
| P3-8: empty-cookie helpers | Every SSE helper requires a cookie and the non-refreshing service capability. Empty-token snapshot/direct-module alternatives are removed. | TestDashCookieOnly; d3-cookie-only admits the helper's empty-cookie argument. |
| P3-9: cursor MAC | SSE cursors use full HMAC-SHA256 and constant-time MAC comparison. | TestDashCursorMAC; d3-cursor-mac restores a prefix-keyed hash. |
| P3-10: EventSource reconnect | Last-Event-ID supersedes the initial URL's since value. Conflicting explicit cursor/header values still refuse. | TestDashCursorReconnect; d3-cursor-reconnect retains the original offset. |
| P3-11: filtered pages | The service read position advances across filtered events. The emitted reconnect cursor remains at the last matching event. | TestDashFilteredPage supplies an unrelated bounded page followed by a selected event; d3-filter-progress moves advancement below the filter. |
| P3-12: inline scripts | The embedded dashboard and enrollment scripts have cached SHA-256 CSP hashes of the exact script-tag contents. script-src has no unsafe-inline allowance. | TestDashCSPHeader and TestScriptCSP; d3-csp-header permits arbitrary inline code and d3-script-hash omits the script-tag whitespace. |
| P3-13: E2E details | Presence checks use the final operation poll's headers, which are retained with its reply. The two-second view threshold and unseeded forged-role assertion are removed. Service-origin event assertions now provide positive provenance evidence. | CaseTests.test_poll_headers; d3-e2e-poll-headers retains initial headers while returning a simulated final result. |

The external transport fixture retains actual in-memory session/binding state,
validates exact request frames and derives its response from the selected
principal and decoded query. Unreached operations return owning not_implemented
errors. It does not implement a native peer or software/hardware authenticator.

## Owner-operated real security-key enrollment

The dashboard links to `/enroll`. After an owner-authorized administrator
ceremony has been opened, the page calls the protected browser adapter's begin
route and uses `navigator.credentials.create`. The RP ID, HTTPS origin, challenge
and stable 32-byte user handle come from the protected installed
`api.AdminEnrollmentEndpoint` and its service-issued challenge. The browser
cannot select a principal, configuration, RP, origin, helper or challenge ID.

The browser requests a cross-platform FIDO2 security key with user verification
required, ES256/Ed25519/RS256 and `attestation: 'none'`. This uses the identity
verifier's existing real WebAuthn registration format without requiring a
manufacturer certificate trust store. A key must support the required UV
ceremony. The origin must have a browser-trusted HTTPS certificate. The page
does not authenticate a service, enroll a credential or access a device merely
by being served.

`ConfigureEnrollment(endpoint, transport)` validates the protected installed
admin_enrollment record, pins the handler to it, and binds a private
BrowserEnrollmentTransport. The service implements AuthorizeEnrollment using a
current, owner-only, helper-opened browser authorization. Possession of the page,
same-origin headers or a public human RPC cannot supply this authority. Begin
and complete both recheck it. The adapter's random Secure/HttpOnly/SameSite=Strict
cookie separately binds the selected challenge to this browser. Up to sixteen
short-lived browser ceremonies are retained, with expiry sweeping.

The complete body has exactly client_data_json and attestation_object, encoded
as canonical base64 byte fields. Unknown fields, including attestation_marker,
refuse. The adapter forwards their original decoded bytes to
CompleteHumanEnrollment with its retained service ceremony/challenge, omitting
the software marker. It refuses a simulated or unbound receipt and clears the
browser ceremony after success. The UI also refuses an uncommitted/simulated
receipt or a service error.

TestBrowserEnrollment exercises this adapter with identity's production
BeginEnrollment and ValidateEnrollment, including real generated ES256/CBOR
registration bytes. Its protected service/admin transaction is an explicitly
in-memory fixture ledger: it only consumes and records a receipt after identity
verification and ValidateInitialEnrollment. This is not an installed admin
helper or a hardware-presence test. Controls d3-enroll-* cover installation pins,
exact forwarded bytes, marker fields, foreign client origin, missing UV, reserved
software AAGUID, foreign cookie, withdrawn administrator authorization and current
challenge expiry. d3-real-attestation checks the existing none-format verifier;
d3-production-software checks the production build's dedicated software-marker
refusal. The Linux web fixture drives the actual enrollment.js, inspects its
WebAuthn options and sent bytes, and exercises origin, error and simulated-receipt
refusals through d3-browser-* controls.

### Exact owner additions still needed

The wire DTO already accepts browser attestation: no identity registration DTO
addition is needed. The following installed pieces remain absent in this tree:

1. **lb-v2-service:** implement Server.BeginHumanEnrollment and
   Server.CompleteHumanEnrollment in service/fix11_stubs.go. Bind them to
   identity.BeginEnrollment/ValidateEnrollment and the durable protected ceremony
   store. Under the commit boundary, prove the complete configuration enrollment
   inventory is absent, validate the initial baseline, consume the actual
   challenge once, preserve private exact registration evidence, and atomically
   write the enrollment, receipt and causal event. Exact retries must reconcile;
   a later key change requires the existing human/D6 path.
2. **lb-v2-admin:** implement BindEnrollment and the fixed helper
   `--enroll-begin FILE` / `--enroll-complete FILE` modes. RunInternal currently
   returns not_implemented. Authenticate the dedicated service/control channel
   using the installed UID, canonical socket, installation generation and pinned
   helper executable; never run a browser-selected command.
3. **lb-v2-service and lb-v2-admin:** implement the helper-opened, owner-only
   browser ceremony authorization behind BrowserEnrollmentTransport. Bind the
   browser authorization to the protected ceremony/principal/generation, expire
   or revoke it, and recheck it on both requests. The dashboard's challenge cookie
   cannot replace that initial administrative authorization.
4. **lb-v2-integrate:** bind the real HumanTransport, HumanLivenessTransport,
   optional completed-receipt lookup and BrowserEnrollmentTransport. Pass the
   protected installed admin_enrollment record to ConfigureEnrollment and serve
   the handler on that exact trusted HTTPS origin. Current assembly.Build has no
   dashboard Transport/HTTP server binding. Keep production startup inventory
   checks and the reserved software AAGUID/marker rejection. There is no config,
   environment or laneboss_faults bypass.
5. **Identity owner only if broader device formats are required:** the existing
   verifier accepts none and packed self-attestation. Certificate-based packed,
   FIDO-U2F and other attestation formats require reviewed verification/trust
   support; they are not silently accepted. The browser's none request is the
   supported path for this slice.

The owner personally enrolls a real key only at final installed acceptance.
Until these owner pieces and runtime evidence exist, enrollment actions fail
with an owning error; this run does not claim installed enrollment acceptance.

## Validation and evidence

The control manifest contains 74 unique controls, with test names including
subtests under forty characters. Source inspection found one unambiguous anchor
for every sequential edit. This is a source audit, not a compiled-mutant result.
The runner retains each mutant's source, mutation bytes/hashes, argv, outputs,
exit and exact named verdict. It rejects compile/setup errors, skips, crashes,
unrelated failures and wrong diagnostics. The added webgo target checks the
embedded asset Go package through the same named Go verdict parser.

On the authorized disposable Linux test machine, the supervisor must run the
retained candidate and every red control before acceptance:

```sh
python3 e2e/v2/cases/dashboard/red-controls.py --source /absolute/candidate --evidence /absolute/lb-v2-dashboard-cx-red
go test ./internal/v2/dashboard ./internal/v2/identity ./internal/v2/api ./internal/v2/cli ./web/v2
python3 -m unittest discover -s e2e/v2/cases/dashboard -p test_case.py
node e2e/v2/cases/dashboard/web-test.cjs
```

Then run the installed dashboard case against the real service/native session
and exact isolated positive-controls file. Preserve baseline/read-back/SSE bytes,
native identity/session evidence and the device enrollment ceremony separately.
No refusal-only action, terminal-only SSE frame or simulated presence label is
an installed acceptance result.

Mac validation is limited to formatting, Linux/Linux-faults/Darwin vet,
Python byte-compilation and shell parsing. The final run evidence records the
observed commands/exits and any cache refusal. No tests, builds, project Python,
Node, browser runtime, real key, cloud action or red mutant runs on this Mac.

Observed in this run: gofmt -w completed for fourteen changed Go files; gofmt -l
returned no paths and exit 0. Python -I -S byte-compilation of case.py,
test_case.py and red-controls.py exited 0, with bytecode outside the checkout.
bash -n of the dashboard case runner exited 0. GOOS=linux GOARCH=amd64 go vet
of internal/v2/... and web/v2/... exited 1 when default Go-cache access was
refused with “operation not permitted”; stderr also included a vendor package
resolution diagnostic. No cache override or retry followed. Per the explicit
brief recovery route, Linux/faults and Darwin vet were skipped for the supervisor.
This is not a passing Go type-check result.
