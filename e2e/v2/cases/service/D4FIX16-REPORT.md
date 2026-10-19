# Draft.4 fix 16 report

This candidate starts at 5e613b9.
The brief reports the prior fix committed and its red box still running; no
result from that box was consumed in this round. All three requested source
changes and their regression controls are authored here. Runtime effects and
the suspected authentication gap still require Linux canaries. Source review
alone does not establish an installed exploit or a passing E2E.

## 1. Health is confined to the first public frame

The ordinary dispatcher now refuses health with CodeForbidden after envelope
and configuration validation, before authentication, a handler or scoped state
access. serveConnection's first-frame publicHealth path still returns its
single response and closes. Every ordinary dispatched RPC now unconditionally
uses Authenticate, Frame.Verify, Authorize, its scoped read view and delivery
rechecks; the old health exemptions and health postprocessing branch are gone.

Service.Health also requires the private publicHealthObservation context that
only the transport supplies. Its full Store.Verify fallback is removed. It
uses the already-observed bounded HealthSnapshot and native transport facts;
the ordinary authenticated store.verify operation remains separate. Semantic
input/version checks still precede the private-context refusal.

TestOpenedConnectionRejectsHealth first proves an unenrolled native caller
receives public health. It then opens another native connection with explicit
component authentication, completes identity.self, sends health as frame two
and requires the typed refusal without any additional handler, snapshot,
scoped read or authentication call. A subsequent identity.self on that same
connection must still work. The read-view fixture uses the actual SQLite
snapshot head; its authentication is an explicit component registration,
not production enrollment evidence.

Removing the dispatch refusal must reach "opened connection dispatched health"
because the valid established connection reaches a handler or scoped read.
That assertion precedes response-code checks, so the separate handler context
fence cannot mask this row. TestHealthNeedsPublicContext separately requires
the typed handler refusal without state access, then proves first-frame public
health still works. Its mutation must reach
"health without public context was accepted". The existing native public-health
tests remain as positive and malformed-input/writer/admission controls.

## 2. Health sockets are never retained for ordinary calls

Client.Call gives health a fresh, nonpersistent connection and releases it
after the exchange, including a typed error response. Existing authenticated
primary connections and their human read-session flags remain available for
ordinary calls and streams. Health therefore always arrives as the first
request on its own socket, including when called between authenticated RPCs.
The next ordinary call cannot select a health socket that the server closed.

TestCallAfterHealth exercises both successful and refused health replies.
It requires the health descriptor to leave the client ownership map and
primary slot, then performs a real framed blob read on a fresh connection
and checks bytes derived from that request. Restoring health persistence
must reach "health call retained its one-request socket" before a stale-socket
transport error could obscure the failure.

TestHealthKeepsSession first opens a human read session, calls health and
requires the same session socket/flag to remain with only two total dials.
A following blob read must reuse that original session connection. Sending
health on the primary instead must reach
"health interrupted the existing read session". The transport fixture closes
only health sockets and validates/derives its replies from framed requests;
it is not an installed client/service authentication run.

## 3. Effect fences do not retire the reconciler

ClaimEffect, the execution recheck and CompleteEffect now skip only per-effect
CodeForbidden/CodeConflict refusals without recording a host fault. A skipped
effect remains retained and incomplete; no success receipt or external-action
claim is synthesized. A fresh claimant is still generated for each attempt.
The concurrent durable-freeze path remains intact.

The classifier unwraps normal wrapped errors and accepts a joined error only
when every cause is an allowed fence. Integrity errors, raw store failures,
mixed fence/store errors and all other failures still recordFault and return.
The previous runEffect non-fence fault-and-continue branch now returns too,
so an execution-path store/integrity failure cannot keep processing effects.
Guidance recovery, pending inventory and the preclaim Effect read remain
fatal on failure, including CodeForbidden at those global boundaries.

TestReconcileSkipsEffectFences injects the selected boundary error for one
effect in real SQLite state, then requires another retained effect to acquire
its real claim and commit its actual completion. The first effect must remain
incomplete. The loop must still be active without s.fault at that commit;
only then does the fixture cancel it. Forbidden/conflict cases cover claim,
execution and completion; a wrapped claim refusal is also covered.

TestReconcileKeepsStoreFailures requires the exact injected error to remain
reachable through s.fault, with no later completion. It covers typed integrity,
raw and joined failures at claim/execution/completion, plus inventory, lookup
and guidance-recovery failures. Component launcher observations are explicit
DTO fixtures bound to each requested handle. They do not measure real process
quiescence, helper revocation or native containment.

The loop tests use separate deadline/setup failure messages. Mutation credit
requires the deciding missing-completion, latched-fault or lost-failure marker;
a setup error, timeout, panic, race or other refusal earns no credit.

## Mutation inventory and verification handoff

The catalog retains all 171 existing IDs and adds fifteen controls, for 186
controls and 372 targeted red/candidate pairs across normal and faults builds,
followed by the existing ten package/tag suites. read-entry-auth and
read-delivery-binding only change their anchor indentation after removal of
the dispatcher health wrappers; their tests, selectors and markers stay the
same. No test reads a mutant's literal or special-cases source text.

MUTATIONS.md lists each new exact test/subtest and marker. The named assertions
must fail under the corresponding source edit and pass unchanged on Linux.
These are authored controls, not measured red/candidate results. The local
literal source review and check records are retained in external evidence.

Implementation was complete before the authorized static checks. The authoring
environment was Darwin arm64, Go 1.26.5 and Python 3.13.11. All seven changed
Go files were formatted first and have no trailing blank lines.

| Check | Observed result | What makes it fail |
| --- | --- | --- |
| Literal catalog review | All 193 edits across 186 controls have one anchor; all 171 prior IDs retained; no no-op or test-file mutation | Missing/duplicate anchor, no-op edit, duplicate/removed ID or a mutated test file |
| New control declarations | All fifteen tests/markers and selected subtest literals found; no test name exceeds 40 characters | Missing named declaration/assertion/selector or oversized test name |
| gofmt -w | Exit 0 for all seven changed Go files before the checks | Go parse/format error |
| gofmt -l | Exit 0, empty output | Any listed path or nonzero exit |
| Python py_compile | Exit 0 for mutations.py, run.py and scenario.py | Missing source or syntax error |
| bash -n | Both service entry scripts exit 0 | Shell syntax error |
| Linux amd64 vet | Exit 1: two existing Go build-cache entries refused access with operation not permitted | Vet/compiler diagnostic or unavailable cache |
| Linux laneboss_faults and Darwin vet | Skipped under the brief's explicit cache-refusal route | Not measured |
| Unit/mutation/native/installed execution | Not run on this Mac | Linux must reach the exact named red and unchanged candidate green, plus installed E2E |

The vet command was GOWORK=off GOOS=linux GOARCH=amd64 GOPROXY=off GOSUMDB=off
go vet ./internal/v2/client/... ./internal/v2/service ./internal/v2/store.
The exact refused cache paths and command output are retained verbatim in
vet-linux.json and vet-linux.log. No cache was changed, redirected or retried.
Only reporting and evidence collection followed the refusal; no implementation
edit or further source check followed. Compilation and deciding runtime results
are not claimed. The syntax checks do not supply mutation credit.

The supervisor must run both normal and laneboss_faults tests and mutation
controls, then the composed installed E2E with health followed by commands on
one client. The existing native first-frame health controls must remain green.
No installed pass, authenticated AI-service result or native isolation claim
is made here. This candidate is uncommitted; no Git staging or commit was done.

Evidence is retained under d4fix16-5e613b9 in the lane's external evidence root:
brief and rules, starting revision/source archive, phase/final source bytes,
diff/status, literal review, check commands/outputs/exits and manifest. There
is no tested binary to hash in this static authoring round.
