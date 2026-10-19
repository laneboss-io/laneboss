# Dashboard run 2: fixture failures and passive idle activity

The input revision is 97662816. The supplied Linux verification log reports
TestSessionAuthFailClosed and TestIdentityRevocationAndIdle failing on malformed
structured decisions, and TestHTTPControlsAndSSE failing on its obsolete
one-hour/eight-hour idle expectation, in both builds. Those fixture mistakes
were left in the previous slice. The strict decoder and current expiry rules
were correct.

## 1. Decision JSON

The two authentication tests seeded only id, text, effective_at and binding.
That object is neither the complete DecisionCandidate projection nor the
DecisionDocument required by the current contract. The fixtures were wrong.
They now use putDecisionDocument to marshal the actual api.DecisionDocument,
including schema=laneboss.decision.v2 and the complete applies_to arrays. Blob
hashes come from those actual bytes. The production decoder remains strict.

TestDashDecisionJSON verifies that this document decodes with its text, binding,
time and applicability intact, and that the old partial object still returns
invalid_request. The d2-decision-doc control restores the old partial shape and
must fail with "decision fixture violated strict document shape".

## 2. Idle and absolute expiry

docs/design/v2-contracts.md:229–231 and :2031–2034 require five idle minutes and
a thirty-minute absolute maximum on the same connection. The fix-11 rules at
:3349–3368 retain the absolute expiry while advancing the durable revision and
setting idle expiry to min(now+5 minutes, absolute expiry).
identity/read_refresh.go:28 and :71–84 implement that committed refresh.

The old test's HTTP 200 after one idle hour was invalid under both limits.
TestHTTPControlsAndSSE now requires HTTP 200 at four minutes, observes the
foreground read refresh, then requires HTTP 401 at exactly five more idle
minutes. It does not accept an arbitrary failure or remove an idle gate.
TestDashAbsoluteCap keeps making foreground reads before idle expiry and checks
that the absolute deadline remains the original thirty-minute value, including
the final clamp and refusal at that boundary.

TestDashIdleBoundary isolates the dashboard snapshot deadline check from the
poll port's independent check. The d2-idle-five control admits equality at that
check and must fail "passive SSE survived the committed idle deadline". The
d2-absolute-cap control changes the fixture's initial expiry to thirty-one
minutes and must fail "read session exceeded its thirty-minute absolute cap".

## 3. Scan disposition and correction

**CONFIRMED for the source-level refreshing call path.** On 97662816,
internal/v2/dashboard/transport.go:199 checked a cookie without refreshing, but
:211 then called ordinary Transport.Dispatch for event.tail. The normal human
read branch in internal/v2/identity/service.go:271–272 calls refreshReadSession.
Thus the false cookie argument did not make the following event read passive.
The thirty-minute absolute cap still applied; the source finding is not an
unbounded session extension or proven native authentication exploit.

**Runtime security status remains SUSPECTED until the Linux canary/control is
executed.** This run is authorized for static checks on the Mac. No canary,
unit test, renderer, installed transport or native peer was executed here.
Source inspection is not a measured security reproduction.

The corrected path is:

1. authenticateCookie obtains a non-refreshing identity/store snapshot, checks
   its exact session/connection revision and enforces the last committed idle
   and absolute deadlines. It does not trust a stale cached idle deadline.
2. SSE invokes the separate HumanLivenessTransport.PollEvents private
   capability. Its implementation must keep the ordinary native/frame,
   revocation, visibility and pinned-read checks without changing activity.
   Missing capability fails with not_implemented owned by lb-v2-service.
   Ordinary Dispatch and direct lifecycle/store reads are not fallbacks.
3. The stream repeats non-refreshing checks and emits a terminal unauthenticated
   frame when idle expiry or revocation occurs. The browser closes a terminal
   stream and applies authenticated service events to retained lane/tree data;
   it no longer issues background foreground-view GETs on SSE messages.
4. Foreground view/RPC requests retain their normal durable bounded refresh.

The public method catalog, request JSON, identity implementation and frozen
ports are unchanged. The new capability is local to the dashboard dependency
boundary; the service owner must supply its installed implementation.

| Check | Deciding assertion and control |
| --- | --- |
| TestDashSSERefreshCanary | Intentionally calls the old ordinary event.tail dispatch. It must observe actual fixture revision/idle extension, unchanged absolute expiry and survival past the original idle deadline. d2-canary-control removes that dispatch's activity refresh; "refreshing canary did not demonstrate idle extension" must fail. |
| TestDashSSEIdle/passive | Four passive polls must leave the complete stored session and connection authority unchanged; the fifth-minute poll must return unauthenticated. d2-sse-refresh restores ordinary dispatch and d2-cookie-refresh restores a refreshing cookie check. Both must reach "passive SSE refreshed durable read authority". |
| TestDashSSEIdle/foreground | A foreground read must advance revision/idle within the original absolute cap. Later passive polls cannot advance either; the refreshed idle boundary still refuses. |
| TestDashSSEIdle/revoked | Identity-side revocation alone must prevent the next passive read with unauthenticated. |
| TestDashStreamIdle | A running follow stream must preserve stored session facts across polls, then end with a real terminal unauthenticated frame at idle expiry. d2-stream-refresh must reach "SSE stream refreshed durable read authority". |
| TestDashPollCapability | A transport without the non-refreshing capability must return HTTP 503 with lb-v2-service not_implemented. d2-poll-owner changes only the owner and must fail "missing non-refreshing poll lost its owning failure". |
| web-test.cjs | The actual renderer must apply the SSE state event, perform no additional fetch, and close a terminal stream. d2-web-background restores the background fetch; d2-web-convergence drops the state update. Their diagnostics identify those separate assertions. |

All new Go test/subtest names are below forty characters. controls.json now
contains 37 controls, including the ten run-2 additions. The existing
dash-sse-dispatch control was adapted to the private poll interface and still
requires the service poll before emitting stream headers.

The Linux owner should run the dashboard tests and the existing Linux-only
red-controls.py workflow against the exact retained candidate bytes, in both
required builds. Compilation/setup failure, skip, panic or an unrelated failure
does not count as a reached canary/red assertion. The renderer test uses the
actual app script with an inert DOM; it is not an installed-browser or physical
presence test. Source and evidence archives remain outside the repository.
