# Verification scope and red controls

Fix 10 closes the counted delta reviews' three P3s in source. Decision metadata
now has explicit ownership paths, decision text keeps caller joins, and the
second request pass resets only its node counter. CONTRACT.md assigns the
remaining rule-approval and synthesized-CWD requirements to policy and lifecycle.
Six new mutations bring the total to 43; the prior 37 controls remain.
The shared CLI-validator registry is present at the merged c5617a3 checkpoint.
Use the ordinary merged source for checks; no shared-source overlay is needed.
CLI-INPUT.md records the accepted transport/binding refusals and focused commands.

No fix-10 runtime result is claimed here. The supervisor is running the merged
c5617a3 checkpoint and rerunning cebe469 with a longer race timeout after the
earlier run passed its other checks. Those pending runs do not establish the
new candidate's tests, differential, benchmark or mutation results.

Runtime tests and builds run only on the authorized disposable Ubuntu 24.04 box.
The Mac permits the brief's static checks. The supervisor's slice-1 box report
records judge package PASS and wire package FAIL in `TestInputCredentialCanary`
under the suffix subcase, both normally and with fault tags. That report is red
evidence for the previous screen, not a green result for this repair. The
candidate and added cases have not been executed by this Mac session.
The supervisor must retain each deliberate mutation's source/hash, reached
failure, restored candidate source/hash and passing output before acceptance.
Do not call a setup failure or typed dependency error a killed feature mutation.
There are no production fixture flags or bypasses.

Earlier supplied box observations cover `f9bf8cf`, before this draft.4 port:
Ubuntu 24.04, c5.large, 2 vCPU amd64; build, normal/fault tests, the long
differential (149 seconds) and eight unit mutations passed. Both unchanged
262,144-byte benchmark cases exceeded 500 ms. The report supplied no actual
duration. Race did not execute because the supervisor suite lacked cgo; its
configuration is now repaired, but no race result for this candidate is claimed.
These are supplied runtime observations, distinct from local static checks.

The subsequent supervisor run on `f3b9236`, Ubuntu 24.04/c5.large amd64,
passed build, the long differential and both unchanged benchmark cases:
many-fields-deep 121.2 max-ms and assignment-tails 162.4 max-ms. Unit, fault and
race runs failed in audit fixture setup, and mutations.py failed its candidate
run for the same reason. The setup emitted an unsupported top-level `note`
member for padding; decodeResponse correctly rejects unknown root members before
CommitAudit is called. Fix 6 replaces that member with 270,000 bytes of legal
JSON whitespace, preserves the multi-chunk response, and independently compares
the HTTP response with retained raw bytes, size and digest. Error diagnostics
now include actual returned errors (including typed code/message), or the
unscored status/reason. CommitAudit and the contract write validators are
unchanged. The top-note negative response control plus allow-unknown-root
mutation require strict rejection to remain in force. Candidate runtime
confirmation still belongs to the supervisor's Linux run.

The next supplied run on `e221aff` passed build, the long differential and the
unchanged benchmark (123.7 / 162.3 max-ms). Unit/fault/race now reach CommitAudit
and fail its actual metadata scan. There is no screened flag in JudgeReply.
The fixture's hand-written ask-one ID contains sk-; the complete value join
continues it through raw-object class/ID/digest and creates a digit-bearing
credential shape. Fix 7 used client.NewRequestID once, without retries/filtering,
and still went through the adapter and CommitAudit screen. The counted fix-8
review identifies the joined-ID refusal as a false positive, not an unsafe ID.
The new control must commit ask-one with its score intact; full credential-shaped
IDs and credential-bearing reasons must still fail the exact metadata integrity
gate after passing byte/fit/score preflight, with no transaction. E2E ask IDs now
use the shared generator's 16-byte random hex encoding rather than an ask- prefix.

The latest supplied run on `fb25f5b` is all green on Ubuntu 24.04: unit, fault,
race, long differential and twenty mutations. Its unchanged benchmark maxima
are 120.6 / 163.0 ms. These are the supervisor's base observations, not fix-8
candidate results. No new red/green runtime execution or latency was observed
on this Mac. New checks must be exercised by the supervisor before acceptance.

The run-6 reference is the complete screen at `7328683`, copied into a test-only
file with identifier prefixes. Its patterns, literal/reference heuristics,
recursive JSON walk and stable joins remain independent of production. The
original source bytes are retained outside the checkout for review. Do not
adjust that reference to make a production failure disappear.

From the source root on the test box, run:

```sh
go test -count=1 ./internal/v2/judge/...
go test -count=1 -tags laneboss_faults ./internal/v2/judge/...
CGO_ENABLED=1 go test -race -count=1 ./internal/v2/judge/...
go test -run '^$' -bench '^BenchmarkScreenBudget$' -benchtime=5x -count=1 ./internal/v2/judge/wire
bash e2e/v2/cases/judge/run.sh --context /test/lb-v2-judge2/context.json --result /test/lb-v2-judge2/result.json
```

Retain every generated request and its reference/production/cap verdict with
the test-only evidence flag. Its directory is owned by the test identity and
0700, and its files are 0600/exclusive. Use a new directory per invocation:

```sh
go test -count=1 -v -run '^TestScreenDifferential$' ./internal/v2/judge/wire -args -judge-screen-evidence /test/lb-v2-judge2/screen-normal
go test -count=1 -v -tags laneboss_judge_screen_long -run '^TestScreenDifferentialLong$' ./internal/v2/judge/wire -args -judge-screen-evidence /test/lb-v2-judge2/screen-long
python3 e2e/v2/cases/judge/mutations.py --source /test/lb-v2-judge2/source --evidence /test/lb-v2-judge2/mutations
```

The normal differential test checks 4,175 frames and the long tag checks 32,847:
the unchanged 2,048/16,384 seeded row pairs, 54 original controls, seven benign
requests, nine caller-field canaries and nine unknown-field/container canaries.
Seed remains 0x7328683; all original shapes, placements, scripts, quotes, cap
edges and the 262,144-byte / 500 ms benchmark remain unchanged.

The ownership table is in CONTRACT.md. Unknown fields and every caller string
default to joining. Only listed schema keys and approved/service scalar values
are removed from the join views; each remains individually screened.
structured-join is narrowed to a whole-reference hit absent from an independent
frozen caller projection in both orders. That projection retains all caller
keys/values, raw and decoded documents, and execution-order adjacency. A
caller-only hit can never be excused. The JSONL records its verdict and the
excluded paths beside the exact frame and both screens' verdicts.
The four allowed non-cap extras are quote-tail, spaced-tail, reference-tail and
caller-join. The last requires a real frozen-grammar hit in the independent
caller projection; it permits more detection, never a caller omission.

TestCallerJoins covers cwd/command, command/argv, argv/declared-paths, two caller
state strings (context CWD/task), caller/embedded JSON and tool/CWD. Every
individual leaf must first be non-sensitive. Its real loopback HTTP fixture
checks exact bytes if the old source sends, while the repaired source must have
zero retention/HTTP, an unavailable reply and typed unscored Fit.
TestUnknownCallerJoins covers separate unknown state strings, metadata-like
names inside caller data and a container at a scalar metadata path.
TestOmissionCallerJoins requires that those inputs cannot receive the omission;
it includes an actual full-reference hit, not just a hypothetical classifier.
TestCallerServiceBoundary allows only the benign caller CWD plus computed-digest
shape and still rejects a full credential in an excluded field.
TestBenignStructuredRequestsScore preserves the six prior scored controls and
adds a complete guidance candidate with source.path /decisions/task-7 and a
64-hex source digest. It must score through HTTP with exact retained bytes,
request references and independently recomputed per-ID probabilities.
The three new caller canaries join decision text to task text, decoded task JSON
and a second decision. Six new unknown/container cases retain joins for scalar
metadata containers, list containers, unexpected text levels and unknown fields.
TestDecisionServiceBoundary requires all thirteen excluded decision scalar/list
locations to withhold complete credentials, decoded split credentials and exact
supplied-key echoes. The frozen reference file remains byte-identical.

TestConformingRequestNodeBoundary independently counts value/key nodes in actual
Payload output and fills argv with empty strings to reach exactly 65,535,
65,536 and 65,537 nodes within the 262,144-byte judge bound. The first two must
pass screenOutgoing; the last must return typed unscored with ScreenCapReason.
Its evidence ledger retains exact bytes and the node counts. Each of the two
passes has 65,536 visits at most, including embedded scopes, for 131,072 overall.
TestRequestPassesShareWork uses the screen's separate 1 MiB serialized envelope
before the judge byte/fit gate. Both fixed passes fit individually; together
they must exhaust the same 8 MiB work allowance and withhold. This pins the
bound rather than raising it with the node reset. All other caps are unchanged.

The six fix-10 mutations and required reached failures are:

| Mutation | Reached assertion |
| --- | --- |
| decision-metadata-joins | benign structured input withheld, specifically guidance-task-7 |
| drop-node-reset | conforming request lost per-pass node allowance |
| reset-shared-work | request passes reset the shared work budget |
| isolate-decision-text | caller split reached retention or HTTP in the three decision subcases |
| exempt-list-containers | unknown caller field escaped |
| drop-excluded-string-screen | decision metadata escaped complete-field screening |

Run mutations.py on the authorized Ubuntu source and require each mutant's exit
1 with that named assertion, exact restoration and a green candidate. Build or
setup failure is not red evidence. Keep the unchanged long differential and
262,144-byte / 500 ms benchmark commands above as acceptance gates.

To demonstrate red on 36753879, extract the retained fix-9 base-source.tar into
a separate disposable Linux directory. Overlay only the candidate's new
screen_caller_test.go and screen_ownership_reference_test.go. Leave production
and the old omission helper untouched, then run:

```sh
go test -count=1 -v -run '^(TestCallerJoins|TestUnknownCallerJoins|TestOmissionCallerJoins)$' ./internal/v2/judge/wire
```

Require all six TestCallerJoins subcases to reach caller split reached retention
or HTTP, the unknown-field check to reach unknown caller field escaped and the
omission control to reach caller-only split was excused. A compile/setup failure
is not red evidence. Run that same command on the candidate and require PASS,
then all normal / fault / race / differential / benchmark / mutation commands above.
Positive benign/boundary controls also pass on the base; they protect against
over-withholding and do not by themselves establish this regression repair.
No red or green runtime execution is claimed on the authoring Mac.

Fix 9 defined thirty-five controls. The original
twenty-seven remain, with drop-scoped-joins retargeted to remove the new second
caller view. Eight new controls widen the omission or individually detach CWD,
command, argv, paths, task, tool and unknown state from caller joins. Detachment
keeps individual/embedded-document screening and leaves HTTP bytes unchanged.
Each must reach its named failure and the restored candidate must pass. Draft.4
then added two CLI registration controls and fix 10 adds six, for 43 total.
The runner archives complete sources/corpus, source hashes, changed sources,
compiled binaries/hashes, outputs/exits, differential cases and quiescent
process collection. A setup failure or a successful mutant is a failed run.
Public CLI mutations remain separate integration gates.

Unit tests are expected to pass after the actual runtime run; this is an
expectation, not a measured result. The E2E case must currently fail nonzero at
the missing service/client/composition or authenticated worker dependency. Once
integration supplies those capabilities and its protected fixture configuration,
the candidate requires exit 0 and all three reached passing assertions, verified
evidence hashes and quiescent collection. See the case README for provisioning.

| Unit check | Deliberate fault that must fail it |
| --- | --- |
| `TestWireBatchAndNamedState` | Drop a rule, make twelve HTTP calls, move command/rule text into instructions, change command bytes, map a probability to another ID, alias answer pointers, or omit retained request/provider-request bytes. |
| `TestResponseFailuresAreUnscored` | Accept any missing/duplicate answer, out-of-range decimal, negative tiny decimal, wrong type/model, partial/withheld metadata, missing usage, trailing JSON, invalid Unicode, extra answer/root member, failed HTTP, oversized body or truncated input usage as scored. top-note must reach the strict shape gate with screened raw bytes retained. |
| `TestFitAndBudgetBeforeHTTP` | Send unknown / failed / expired / mutating / wrong-pin fit, overflow, zero-token proof, byte overflow, exhausted budget, cancelled context or malformed UTF-8 to HTTP. |
| `TestWholeByteAndTokenBoundary` | Count command characters rather than complete bytes; reject exact byte fit; accept one byte over; accept the safe token ceiling instead of requiring strict less-than. |
| `TestProxyAndTransportControls` | Keep a remote TypeSafe proxy: the explicit real proxy control must first be observed, then judge traffic must reach the TLS target directly while preserving its caller transport. |
| `TestUnusualTransports` | Reintroduce a type assertion on replaced DefaultTransport or Clone on a typed-nil transport; fail the real exchange after the distinct default-transport control. |
| `TestDecodedCredentialEcho` | Inspect only raw bytes, or omit recursive string/key screening: quote, backslash, slash and Unicode-escaped echoes must never reach retention, even if shape validation later rejects them. |
| `TestInputCredentialCanary` | Miss the withholding reason, retain input, or perform HTTP for a fake bearer in command / rule / role / task / decision / argv / path, the unchanged oversize suffix, prefix/middle, JSON text or split argv fields. Each effect now has its own assertion. The benign reference control must still be recognized as a reference. |
| `TestCredentialStringPositions` | Restore external word boundaries on credential signatures, shorten the long canary, or withhold the benign/credential-reference controls. |
| `TestOutgoingFieldCoverage` | Ignore a credential at any tested position in rule text, command, context key/value, question instruction, true/false criterion/key, decision text, task, argv or declared path; or reject the original clean serialized body. It calls the same complete-body gate as provider preparation. |
| `TestNestedJSONCredentialScreen` | Miss nested object keys/values or JSON text with Unicode-escaped credentials, or reject the benign JSON credential reference. |
| `TestSplitCredentialFields` | Scan leaves only and miss a marker/token split across adjacent fields/keys/values, or reject the clean-field control. |
| `TestAssignmentRegionsAreLinear` | Reinspect overlapping suffixes, treat repeated redacted assignments as secrets, or miss a final real-shaped value/nested assignment. The benchmark supplies the fixed-time requirement. |
| `TestScreenCapsWithhold` | Let raw-input, shared-work, depth or node exhaustion pass; drop the benign control; or get the byte-budget boundary wrong. |
| `TestFragmentWindowBoundaries` | Lose required split markers or an exact 8,192-byte key at the original block offsets, exceed the buffer bound, or withhold the unchanged 4,096-byte clean stream. |
| `TestAssignmentValueNotTruncated` | Restore the next-assignment cutoff: each complete value starts beyond 1 KiB of padding and contains assignment-like text. Quoted, unquoted and spaced cases must all withhold. No signature alone matches them. |
| `TestAssignmentExtensionControls` / `TestNamedExtraGrammar` | Remove any named quote/reference tail detection, let it reach retention/HTTP, change the frozen reference verdict, or withhold complete benign references/quoted redactions and normal separators. Each extra has an individual WITHHELD subtest. |
| `TestAssignmentMatchEnds` | Change an assignment's end/value position relative to the frozen grammar, including prefixed names, separators and Unicode folds. Removing the redundant name prefix must preserve every value start. |
| `TestScreenFoldedShapes` | Use case-sensitive literal prefilters or lose RE2's long-s/Kelvin/dotted-i variants while the independent reference still detects the shape. |
| `TestCredentialShapeBranches` | Drop any GitHub, Slack, Discord, AWS or Stripe alternative from the signature matcher/prefilter; the independent reference must match each generated branch. |
| `TestPaddedAssignmentControls` | Withhold padded references, placeholders, code references or prose, or miss the paired literal. These negative controls intentionally pass on the baseline too; they cannot establish the regression fix by themselves. |
| `TestWideFragmentCredentials` | Restore 512-byte rolling overlap: marker/token fragments straddle its discarded byte with a 513-byte separator, long URL userinfo or JWT segment. It also covers the authorization assignment key and split keys/values. Benign long separators and complete references must pass. |
| `TestCompleteFragmentViewCap` | Discard part of an exact-cap view, allocate beyond its cap, withhold the benign view, or allow a one-byte overflow without exhaustion. |
| `TestAssignmentValueByteCap` | Withhold an exact-1-MiB benign padded placeholder, or pass the next byte without inspection. |
| `TestRegressionBeforeEgress` | Let a regression canary reach retention/HTTP, or use a later fit/HTTP failure as the credential-withholding result. Assignment subcases are expected to fail on the baseline; wide splits at this additional embedding/alignment protect pipeline coverage. |
| `TestRadixKeysKeepStableOrder` | Change deterministic key ordering or ignore work exhaustion while sorting. |
| `TestScreenCapsBeforeEgress` | Retain bytes or perform HTTP after a depth/node/input cap, or miss the distinct cap reason; a later byte/token failure cannot count as a pass. |
| `TestConformingRequestNodeBoundary` | Charge the second pass against the first pass's node allowance, reject a complete 65,536-node request or allow 65,537 nodes without the typed cap reason. |
| `TestRequestPassesShareWork` | Reset the byte/work allowance between request passes and allow a body whose combined work exceeds 8 MiB; both isolated passes must first be clean and fit alone. |
| `TestScreenDifferential` / `TestScreenDifferentialLong` | Miss a genuine frozen-reference hit or named extra, omit a reference hit without the independently proved structured-join classification, add an unlisted non-cap detection, report an unproved cap, omit a named class/pattern/position/script/quote, or withhold an explicit clean control. |
| `TestBenignStructuredRequestsScore` | Restore whole-frame joins: the real rule-ID/path/schema/hash combinations must reach HTTP, retain exact bytes and preserve each actual probability; the frozen reference verdict is asserted separately. |
| `TestStructuredFragmentsStillWithhold` | Drop text-scope joins or report withholding as scored: the same prefixes completed into signatures must return typed unscored Fit, unavailable Evaluate, no probabilities/retention/HTTP, and fail scored validation. |
| `TestCallerJoins` | Isolate any caller command/CWD/argv/path/task/tool field or suppress decoded/execution adjacency; the real loopback transport must observe zero requests and retention must remain empty. All leaves are independently checked as benign. |
| `TestUnknownCallerJoins` / `TestOmissionCallerJoins` | Treat unknown fields/metadata-like names as service-authored, exclude an unexpected container, or excuse a caller-only reference hit. |
| `TestCallerServiceBoundary` | Join caller CWD to a service-computed digest and withhold an ordinary request, or stop screening a complete credential in an excluded value. |
| `TestDecisionServiceBoundary` | Lose the independent provenance explanation for the task-7/digest reference hit, or stop complete-string, embedded-document or exact-key screening at any excluded decision metadata location. |
| `TestSplitResponseKeyEcho` | Drop exact-key joins: the split echo must withhold before raw retention even when no raw contiguous key exists; the paired normal response must score. |
| `TestPositiveReservationRequired` | Restore acceptance of ReserveMicros zero: both providers must reject zero/negative reservations at construction with the exact typed error; a positive reservation must score through actual HTTP. |
| `TestSingleBatchPreviewBound` / `TestScopedPreviewSingleBatch` | Truncate/drop a thirteenth rule or turn overflow into success: twelve complete rules work, thirteen return explicit typed unscored/unavailable with no HTTP/retention. These document the open batching limit in CONTRACT-GAPS.md. |
| `TestScreenBudgetDifferential` / `TestAssignmentOverlapBudget` | Discard a view without withholding, ignore remaining work, inspect overlapping values beyond the linear allowance, or cap disjoint redacted controls. |
| `BenchmarkScreenBudget` | Run more than 500 ms on any exact-262,144-byte sample, withhold its benign input, or pass its credential-tail control. It covers 4,096 small fields/24 embedded JSON levels and repeated assignment tails. Run without race instrumentation on the named Ubuntu box and retain ns/op, max-ms, allocations, command and artifact identity. |
| `TestResponseCredentialShapes` | Retain a decoded credential-valued metadata field before rejecting its shape. |
| `TestPinsEndpointsAndRedaction` | Accept whitespace pins, trailing-dot hosted API, remote plaintext, model alias, excess bounds or absent margin; print key text or its recoverable byte-array representation. |
| `TestRetentionAndCostFailures` | Send without exact retention, accept a false content receipt or score failed/over-cap actual cost calculation. |
| `TestDeadlineAndRedirect` | Extend the total request deadline or follow the redirected provider request. |
| `TestGuidanceStateAndQuestionIDs` | Lose the decision list/binding/context, put decision text in instructions, or treat an ID named partial as metadata. |
| `TestQuestionCoverageAndZero` | Drop a valid scored zero or accept duplicate/empty/oversize/invalid-ID question sets or changed command digest. |
| `TestStrictFrozenJSON` | Accept unknown/duplicate/missing/null fields, trailing JSON or negative unsigned metadata. |
| `TestNormalizedSuccessIsComplete` | Publish a score with missing probability/raw/request reference/usage, wrong request hash/class/length, invalid/duplicate batch IDs, changed model, wrong question ID or duplicate result. |
| `TestTypedDependencyIsPreserved` | Swallow a tokenizer's typed not-implemented error or perform HTTP past it. |
| `TestCacheKeysAndCopies` | Reuse changed rule / source / criteria / role / instance / grants / policy / raw bytes/argv/task/deployment/tokenizer data, or permit caller mutation of retained probabilities or object references. |
| `TestCacheAcrossAsks` | Include per-ask ID/deadline/cost ceilings in the key: changed asks must use one provider call and retain the original observation ID, exact request ref and probabilities. |
| `TestCacheExpiryBytesAndFailures` | Reuse expired or byte-evicted entries; cache an unavailable result; borrow a score after budget exhaustion. |
| `TestCacheCoalescesMisses` | Execute multiple identical concurrent provider calls; the waiter observation is bounded and cleanup releases the fixture leader. |
| `TestCacheRejectsTypedNil` | Accept a typed-nil judge and panic later. |
| `TestServiceScopesAndWorkerGate` | Invoke a provider from state authority, accept a forged life/role/provider/stale generation/revoked grant or swallow the store stub error. This is a refusal-boundary test, not proof of a working worker. |
| `TestScopedFitUsesLiveState` / `TestScopedFitRejectsChangedFacts` | Lose actual turn/task or decision authority, or reach fit after a changed connection / frame / revision / run / launch / task / metadata / blob / rule / decision fact. The fixture deliberately returns unproved fit data; it never substitutes a token proof. |
| `TestCacheDecisionBindings` | Reuse a score after a changed decision receipt, source sequence or applicability. |
| `TestScopedProviderPins` | Compare unresolved default spellings, accept any changed approved pin/limit/generation, select an unapproved provider, or use a missing/typed-nil alternative. |
| `TestScopedProviderNeverFallsBack` | Call the other provider after an outage or replace the selected provider's typed error with a fit result. |
| `TestAuditWriteMatrix` | Drop JudgeAudits or judge.completed, publish an uncommitted result, lose chunked readback/CAS/cancellation, allow audit writes under public judge.ask, allow a missing mutation reply, or alias the stored probability. This is an explicit isolated completion fixture, not composed service acceptance. |
| `TestAuditRejectsChangedEvidence` | Accept a changed emitter/requester/epoch/time, request/raw bytes, normalized probability, tokenizer proof or stored projection, or swallow a commit failure/missing audit. |
| `TestAuditUnscreenedMetadata` | Restore whole-metadata joins and refuse benign ask-one, omit the actual serialized-reply screen and accept a complete credential-shaped ID or credential-bearing reason, refuse poison at a different preflight gate, or write before refusing. The scored control must commit all original probabilities. |
| `TestRegisterStrictRPCAndErrors` | Lose a frozen method, accept an unknown field or hide registrar failure. |
| `TestInternalLeaseCannotBeAnArg` | Treat an arbitrary job argument as authority or accept missing dependencies/cancelled internal work. |
| `TestProviderFactoriesAndSecrets` | Fail a real local provider exchange through either factory or the default Clef selection, drop bearer auth, or print credential bytes through dependency/service formatting. |
| `TestCorpusRowsReachPayload` | Accept unknown question types/invalid option IDs/missing labels or provenance, fail constructing any of the 282 Noul rows, or lose the fixed 120/32/90/20/40 inventory. Twenty Choice rows receive structural checks only; no Choice runtime/evaluation success is claimed. |

The E2E mutations and three assertion IDs are described under the case directory.
It observes the public CLI, actual HTTP fixture, protected-object read receipts
and paired sent/outcome egress records. Its fit checker is explicitly synthetic.
Fixture timings cannot establish the approved live endpoint's 1/12-question
p50/p95 or accuracy. The Clef-only fixed corpus calibration, actual serving
formatter/tokenizer, crash recovery and red executions remain separate
supervisor-run gates. Draft.3's R108 clarification removes the old comparison
and shadow-promotion prerequisites. The legacy package and evaluator/corpus
files were left unchanged.

Run 4's scan-cost review is suspected until the supervisor records a behavioral
timing/control result. Source inspection found whole-tail value rescans; no
measured DoS is claimed. The repaired screen charges all nested scans to one
8 MiB work allowance, caps depth at 32 and nodes at 65,536 per pass, and uses six complete
fragment views capped at 1 MiB each. Do not relax the benchmark threshold or remove
fix-1 detection cases if a runtime check fails. A deliberate red mutation can
restore whole-tail assignment slicing, discard view prefixes, or return an unscreened
pass on cap exhaustion; retain reached failures before the restored candidate.

Run 5's assignment-truncation and cross-field findings remain suspected until
behavioral evidence is returned. To establish red evidence, extract the retained
`210d004` base-source archive into a separate disposable Linux directory, copy
the candidate's `wire/screen_regression_test.go` and frozen
`wire/screen_reference_test.go` into that source, and run:

```sh
go test -count=1 -run '^(TestAssignmentValueNotTruncated|TestWideFragmentCredentials)$' ./internal/v2/judge/wire
```

Require reached failures with `assignment value was truncated` and
`wide split credential escaped`, not a compilation/setup failure. Keep the
baseline archive, test bytes, command, exit and complete output. Run the same
command on the restored candidate and require PASS, then the complete commands
above. All four original fix-1 split cases remain unchanged in
`wire/screen_test.go`; they must pass along with the long-suffix canary. The
262,144-byte workload construction and 500 ms benchmark bound are unchanged.
No red execution, green execution or latency result was observed on this Mac.

Run 6's new bypass report remains suspected. Its static review found extra
non-cap detections for nested code/reference forms and the three unconfirmed
run-5 extensions; no runtime bypass or false-positive measurement is claimed.
The production scanner now preserves the frozen value semantics with charged
inspection and complete capped joins. The wide-fragment wire fixtures now use
valid JSON object roots, so their assertion reaches credential screening rather
than failing at object decoding. Fixed alignment still crosses the old overlap.
All original fix-1 payloads and positions remain. The decision canary only adds
contract-required authority/applicability metadata; it keeps the same credential.
The latest comparison correction explicitly restores the three named tail
extras; they are no longer benign controls or an implicit exception. The
reference remains byte-identical. The wave-0 item-by-item closure ledger is in
REVIEW-CLOSURE.md; source closure and pending runtime/composition gates are
reported separately.
