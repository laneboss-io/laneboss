# Draft.4 fix 23 report

This round starts at 22c7dd9. The active brief, rules, clean starting status,
source archive, complete serve2 inputs and supplied red-verifier log are kept
in external evidence. All verification in this authoring round is static.

## 1. Connection refusal privacy

Suspected: the starting connectionRefusal copies the original typed error,
including its message, advice, operation selector and retryability, onto the
unauthenticated peer's response. Source identifies this path; no runtime
disclosure or canary result is claimed on this Mac.

The fix from serve2 b41fa46 is adopted. connectionRefusal now creates a fresh
error carrying the typed code and owner and the fixed text service connection
refused at the selected stage. It does not copy the cause's other fields.
The main connection and both worker-listener refusal paths pass the typed
original cause separately to the private journal. That journal retains the
original message, code and owner with its fixed stage. A refusal still returns
one correlated response, closes, and cannot reach dispatch or state.

After formatting, server.go, worker_listener.go, the new native regression and
admission_linux_test.go are byte-identical to those files at b41fa46. The
connectionRefusal and journalConnection implementations are also identical.
The earlier structural current-scope interface remains because this checkout's
API lacks serve2's named ConnectionScopeSource; it declares the same method.
The first-method regression now checks the actual correlated refusal before
closure, and admission requires the exact fixed message rather than a prefix
that allowed cause text.

TestAuthenticationRefusalPrivacy is adopted unchanged. It sends identity.self
through real Linux socket framing to the refusing authenticator. A fresh
harmless canary occupies the cause's message, advice and operation selector.
The assertion examines the entire received frame, checks the fixed public
fields and empty result/head, verifies closure, zero dispatch/state/authorization,
and verifies that creating the response did not mutate the original cause.

The authentication-refusal-cause control restores the original error copy.
The authentication-refusal-other-field control keeps the fixed message but
puts cause text in instead. Both must fail at the exact assertion:

```text
authentication refusal disclosed internal cause
```

Both then require the unchanged candidate to pass the same test in normal and
faults builds. The native canary, all four pairs and installed behavior remain
unmeasured here. CONNECTION-REFUSALS.md retains the complete focused handoff;
only its evidence-directory lane labels were adapted from the upstream text.

## 2. Failed-plan atomicity control

The fix was still needed after d4fix22: that round changed the port's package
and type references, not its cleanup copying or fixture values. The supplied
4e361ce log contains a normal failed-plan-atomic red-test failure at rollback:

```text
cleanup rollback refused before its intended append invalid_request: invalid object ID
```

The brief reports this in both builds. The supplied copied log establishes
the normal failure; it does not establish a faults red/candidate result. No
new candidate runtime result is inferred from the supervisor's prior run.

The source trace identifies a production serialization mismatch before any
append. FailPlan JSON-encodes its private typed batch and then calls the RPC
shape decoder. The real planning effect issued by ReserveLaunch has no
logical turn at this stage. Its service actor can also lack a life selector,
and private cleanup requests retain nil unused resource fields or a zero
unknown slot. RPC shape validation treats empty IDs as invalid and explicit
null as forbidden. Filling those fields with synthetic IDs would change the
original causal or resource facts.

The copy now uses the existing decodeStored path: bounded strict JSON
parsing and a decoder that refuses unknown fields, while preserving the
private DTO's actual zero/nil values. No public decoder or RPC schema changed.
The writer still resolves the original current claim, immutable reservation,
CAS, cancellation epoch, exact protected slot/injection references and real
projection selector under its sole lock. Atomic append placement is unchanged.

The fixture now explicitly checks all required job/cause/object selectors,
present stage IDs, the known slot's complete wire shape and the original
planning turn before exercising atomicity. It never synthesizes a selector
for absent or unknown state. A specific invalid-request assertion identifies
rejection at the private-copy boundary. The new failed-plan-private-copy red
restores the faulty decoder and must reach:

```text
private cleanup copy rejected retained selectors
```

The existing failed-plan-atomic row and both rollback assertions remain.
The SQL trigger must still produce its exact append-denied error. Candidate
rollback requires the original plan and no outbox; the red still commits the
plan first, appends through a second SQL transaction, and must fail at cleanup
append failure left a partial plan. Removing only the test trigger then proves
the same original input can commit. A setup refusal is never credited as a kill.
These corrected red/candidate results remain required on Linux.

## 3. Pending API owner file

No API source was edited this round. The full file at integrate 39ac09e was
compared with the current API plan_cleanup.go and retained as input evidence.
Its PlanCleanup fields, order and types and both FailedPlanStore method
signatures are identical. The difference list is also in HANDOFF.md.

The incoming file uses a context/reflect import block, shorter declaration
comments and no inline cleanup-kind comment. It additionally defines
ValidateFailedPlanWrite(Transaction, []PlanCleanup) error. That preflight checks
transaction shape, failed revision correlation, valid cause/resource selectors,
known/unknown slot shape, cleanup kind and batch completeness, matching
allocation fields, injection/prepared/withdrawal correlation and issue ownership.
It is correlation preflight; it does not replace writer-side live state checks.

Once fix 13 lands, integrate's complete file wins and this lane's declaration
file is dropped in favor of it. No temporary duplicate type or validator is
introduced. The existing lifecycle alias handoff continues to refer to the
same API names and signatures. The pending validator is not claimed to be
present or invoked in this checkout.

## 4. Static checks and remaining proof

gofmt -w ran on all eight changed Go files before checks. gofmt -l then exited
0 with empty output. Python py_compile for mutations.py and test_diagnostics.py,
bash -n for run-mutations.sh and git diff --check each exited 0. The authoring
host is Darwin arm64, Go 1.26.5 and Python 3.13.11.

Data-only literal inspection found 248 unique controls and 260 sequential edit
anchors. Every anchor matched exactly once. All 245 prior rows, edits, selected
tests/leaves and deciding diagnostics are unchanged. There are three new rows:
the two adopted refusal controls and the private-copy regression. No project
Python code was imported or executed by that inspection.

The sole vet attempt was:

```sh
GOWORK=off GOOS=linux GOARCH=amd64 GOPROXY=off GOSUMDB=off go vet ./internal/v2/store ./internal/v2/service
```

It exited 1 with two Go build-cache operation-not-permitted refusals. Both
lines and the exact command are retained verbatim in external vet.log and
checks.json. The command was not retried, no alternate cache or permission
change was attempted, and remaining vet variants were skipped under the
brief's explicit recovery route. Only reporting and evidence collection
continued after that refusal.

Compilation, Linux unit results, all new red/candidate results and installed
acceptance remain unestablished. No tests, product builds, cloud jobs, real
model requests, extra agents, sessions, staging or commits were started on this
Mac.

The external lb-v2-service evidence round d4fix23-22c7dd9 retains full inputs,
owner comparison, catalog/anchor observations, candidate and four mutant source
snapshots, exact static command outputs/exits, source archives, diff, status and
a SHA-256 manifest. The fourth retained mutant is the unchanged atomicity row
applied to the corrected source. No tested product binary exists in this round.

The Linux verifier must run the two adopted privacy controls, the private-copy
control and failed-plan-atomic in both variants, then the full inventory of
496 targeted red/candidate pairs and ten final Go package/tag suites. The
composed installed service E2E remains the acceptance gate. These component
fixtures are not an authenticated AI-service test.
