# Draft.4 fix 17 report

This candidate starts at a54319c.
The brief identifies that revision as fix 16 plus the supervisor's correction
of the prior fixture interface from api.IsolationLauncher to api.Launcher.
That correction is retained. This round changes the guidance test fixture
and documentation only. The protected server/client/reconciler production
files and the other lane's materialization files are not edited.

## 1. Surviving control and live guard

The supplied 5e613b9 red log records 110 normal kills with candidate passes,
including natural-measured-process and guidance-score-provenance. It then
shows TestGuidanceMeasuredScoreGate (nonbinding_item) passing under the
guidance-unscored-item mutation, exit 0. The runner stops with
"red did not reach its intended failing assertion". The log establishes no
later-row or faults result, and no result from the running fix-16 box was
consumed for this round.

The mutation still removes the live CodeForbidden return in writeGuidance's
unscored-item loop. The guard did not move. The old fixture appended a
GuidanceItem with only DecisionID, leaving SourceRef.ID and SHA256 empty.
The owner/completion validators allow that item to reach the intended guard.
When the return is removed, the transaction writes provisional projections
and then validates its guidance.selected event with wire.ValidateEvent.
Strict payload decoding rejects SourceRef.ID; its empty SHA256 is independently
invalid. The transaction rolls back and the old test accepted that unrelated
error, so the named acceptance assertion was never reached.

This diagnosis follows the retained source and supplied mutant log. It is
not a new runtime execution or a claim that the corrected mutant was killed.

## 2. Fixture correction and deciding assertion

The nonbinding item now has weight 1 and a complete SourceRef using the retained
task's actual ID and digest, a short task.md path and generation 1. It
remains nonbinding with no score; no measured judgment is invented.
The test explicitly requires the submitted payload to pass wire.Decode, the
transaction to pass ValidateTransactionShape and the current claim/cause to
pass ValidateGuidanceCompletion before it invokes the real store transaction.
Each preflight has its own fixture failure message and cannot earn red credit.

The unchanged store must return api.CodeForbidden. A schema or owner error is
no longer accepted as success. After refusal, a binding-only completion must
commit through the same genuine claim; reading GuidanceReservation must show
the completed result with exactly the retained binding-item count. This checks
that the refusal preserved the claim and that valid completion still works.

With the item refusal removed, the source trace passes the unchanged
provenance, owner, event-equality, turn-generation and event-schema gates and
reaches a nil transaction error. The selected test must then fail at exactly
"unscored guidance accepted a nonbinding historical item". The catalog ID,
selected subtest, marker and production edit remain unchanged. No test reads
source text, detects a mutant or substitutes a constant validation result.

Both the deciding red and unchanged candidate green still need Linux execution
under normal and laneboss_faults builds. A setup error, different assertion,
compiler error, panic, race or harness timeout is not red credit.

## 3. Sweep beyond the stopped row

The sweep covers every one of the 75 current controls after the survivor,
across 28 package/test groups. It checks whether the selected canary keeps
the other guards and payload shape valid when its mutation is applied, and
whether a setup or sibling refusal could conceal the named assertion. No
additional concrete masking fixture was found. These are source traces, not
observed kills, executable compilation or installed acceptance.

| Group | Rows | Scope checked for unrelated refusal |
| --- | --- | --- |
| Enrollment ceremony | 3 | A valid challenge precedes the canary; generation 1 remains within the shared shape bound, while expiry/consumption are tested at the selected final validator. |
| Credential presence | 2 | A real enrolled credential passes first; each changed mark leaves the companion equality consistent after its selected edit. |
| Submitted presence propagation | 4 | The direct helper uses one retained marked approval and changes one submitted collection, with no later event decoder. |
| Pending operation presence | 1 | A real reservation finishes and the returned operation flag supplies the assertion. |
| Presence evolution | 1 | Valid operation tuples differ only in the guarded flag; an unchanged positive comparison is retained. |
| Policy history | 2 | First-insertion hash corruption and genuine generation/CAS publication avoid immutable-history setup failures. |
| Prepared identity | 2 | A complete prepared binding/event control precedes a valid foreign ID or missing-event canary. |
| Private plan reads | 2 | Fully valid foreign records and stale inventory expose the actual reservation/claim checks while keeping original bytes intact. |
| Natural completion | 6 | Controlled-child observations/events are complete; each selected predicate or budget relation is isolated, and the head assertion reads the real commit sequence. |
| Reservation authority | 2 | Normalized inferred ticket guards remain valid; the authority-ID row's deciding assertion is on its later valid reservation. |
| Durable session refresh | 4 | Retained session/authority DTOs stay aligned; expiry/revocation and installed binding config reach their selected validators. |
| Transport authority refresh | 4 | A valid initial bind and four-minute idle deadline preserve the non-target identity/expiry gates. |
| Guidance owner fences | 5 | Empty item lists are schema-valid; changed owner IDs remain valid IDs, requester event causality is aligned and operation metadata is restamped. |
| Guidance deadline | 1 | The expired retained interval is valid; removing the clamp reaches the distinct raw caller-context error rather than the required API deadline. |
| Capture publication | 7 | Full event DTOs remain schema-valid; canaries isolate approval/policy/application/event relations, and event selection uses the receipt ID. |
| Guidance winner evidence | 2 | Actual same-turn claims expose the Acquired flag through winner counting before later completion/await behavior. |
| Enrollment channel recheck | 1 | A valid install/capability changes only its native channel; removing the selected check leaves the validated commit path intact. |
| Atomic reservation winners | 2 | Actual identical reservations expose eight or zero reported winners, with separate setup and operation-consistency failures. |
| Dispatcher loser waiting | 1 | Genuine absent lookups race at the sole writer; a second preflight supplies the marker instead of a timeout. |
| Mutation owner boundaries | 5 | A valid live owner is checked first; retirement keeps the actual receipt pending to avoid a masking completed-receipt refusal. |
| Missing atomic port | 1 | The real store is wrapped without the private port; the handler call flag precedes the typed-refusal check. |
| Reservation DTO pins | 2 | A real winning reservation changes only returned config/frame metadata, so handler invocation is observable independently. |
| Later-frame health | 1 | Public health and the ordinary first RPC are positive controls; handler/state counters precede the separate context/response checks. |
| Health handler context | 1 | The canary uses the measured executable digest/version, and native public health remains a positive control. |
| Client health release | 2 | Valid success/refusal replies precede an immediate ownership assertion, before another socket exchange can fail. |
| Client session preservation | 1 | A genuine framed session response precedes health; the original socket/flag and later read are observed. |
| Reconciler effect fences | 6 | Only one selected boundary is injected; a later effect uses real SQLite claims/completion, with distinct missing-work and latched-fault markers. |
| Reconciler fatal errors | 4 | The exact failure must remain reachable and later work must stay incomplete; timeout/setup paths use other messages. |

The external sweep-review.json lists every control ID, exact test/subtest,
required marker and its source reasoning. The previously completed 110 normal
pairs are attributed to the supplied 5e613b9 log only. All 186 controls and 193
edits are retained, for 372 red/candidate pairs and ten final package/tag
suites. The current fix-16 controls remain dependent on its Linux verification.

## Checks and handoff

Implementation was complete before the authorized static checks. The authoring
environment was Darwin arm64, Go 1.26.5 and Python 3.13.11. The changed Go file
was formatted first and has no trailing blank lines; its test names remain
within 40 characters.

| Check | Observed result | What makes it fail |
| --- | --- | --- |
| Literal catalog review | All 193 edits across 186 controls have one anchor; IDs unique, no no-op or test-file mutation | Missing/duplicate anchor, duplicate ID, no-op edit or mutated test target |
| Scope/source review | Only the owned guidance test and documentation changed; all 75 later controls traced | Protected source edit, unreviewed later row or a concrete masking path requiring repair |
| gofmt -w | Exit 0 before the checks | Go parse/format error |
| gofmt -l | Exit 0, empty output | Any listed path or nonzero exit |
| Python py_compile | Exit 0 for mutations.py, run.py and scenario.py | Missing input or syntax error |
| bash -n | Both service entry scripts exit 0 | Shell syntax error |
| Linux amd64 vet | Exit 1 on one existing Go build-cache entry: operation not permitted | Vet/compiler diagnostic or unavailable cache |
| Linux laneboss_faults and Darwin vet | Skipped under the brief's explicit cache-refusal route | Not measured |
| Unit/mutation/native/installed execution | Not run on this Mac | Linux must reach the exact selected red and pass the unchanged candidate |

The vet command was:

```sh
GOWORK=off GOOS=linux GOARCH=amd64 GOPROXY=off GOSUMDB=off go vet ./internal/v2/store ./internal/v2/service ./internal/v2/client/...
```

Its exact command and refused cache path are retained verbatim in vet-linux.json
and vet-linux.log. No cache was changed, redirected or retried. Only reporting
and evidence collection followed; no implementation edit or further source
check followed the refusal. No one-line compiler diagnostic was observed to
repair. Compilation and red/candidate success are not established.

The supervisor can first run the selected pair in both builds on Linux, then
the full inventory:

```sh
bash e2e/v2/cases/service/run-mutations.sh --source /test/source --evidence /tmp/lb-v2-service-mut-f17 --mutation guidance-unscored-item --variant both
```

Evidence is retained under d4fix17-a54319c in the lane's external evidence
root: the complete brief/rules, supplied log, starting source archive, final
input bytes/diff/status, sweep, literal catalog review, exact check outputs
and manifest. No tested binary exists for this static round. This is not an
authenticated AI-service test. The candidate remains uncommitted; the
supervisor owns Linux verification, review and commit.
