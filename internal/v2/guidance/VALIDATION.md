# Guidance fix 11 verification handoff

Base: 4cb2373. The Linux unit and faults runs on that base failed invalid replay
fixtures and pending observation before the regression assertions. Fix 11
requires owner/deadline facts on every retained claim; the fixtures' zero-byte
task violated the shared reservation validator. The new fixture reserves and
completes through stateful contract ports with nonempty task bytes. Current
Linux runtime results for this correction are unmeasured.

## Authorized Mac checks

Before checking, run gofmt -w on changed Go files and remove trailing blank
lines through the file editor. Use lane-owned caches outside the checkout.
Run only these static checks here:

```sh
gofmt -l .
GOOS=linux go vet ./...
GOOS=linux go vet -tags laneboss_faults ./...
GOOS=darwin go vet ./...
python3 -m py_compile e2e/v2/cases/guidance/guide_turn.py \
  e2e/v2/cases/guidance/mutate.py \
  e2e/v2/cases/guidance/test_mutate.py \
  e2e/v2/cases/guidance/test_guide_turn.py
bash -n e2e/v2/cases/guidance/run.sh
git diff --check
```

Empty formatting output and zero exits are required. The brief explicitly
permits skipping refused Go cache access and reporting it to the supervisor;
do not bypass a refusal. Do not run unit tests, project Python, a project
binary, remote commands, staging or commits on this Mac.

## Linux runtime and red-before-green

Run on the exact retained source under the ordinary disposable Linux identity.
Keep real privacy/authority checks active and retain all input/output bytes.

```sh
set -eu
go test -count=1 ./internal/v2/guidance
go test -count=1 -tags laneboss_faults ./internal/v2/guidance
go test -race -count=1 -run '^(TestTwoClaimKeys|TestPendingDoesNotRejudge)$' ./internal/v2/guidance
python3 -m unittest discover \
  -s e2e/v2/cases/guidance -p 'test_*.py' -v
python3 e2e/v2/cases/guidance/mutate.py \
  --source /test/source --evidence /test/lb-v2-guidance-f11-plain --components
python3 e2e/v2/cases/guidance/mutate.py \
  --source /test/source --evidence /test/lb-v2-guidance-f11-faults --components --faults
```

Each ready control must reach its exact named assertion under the compiling
mutant, then pass the identical focused test on restored bytes. Expected
counts are 111 kills per build, 222 across two builds; these are targets, not
measured results. Nine installed-integration entries remain pending/exit 69.
Build/setup errors, panic, skip, unrelated errors and phase timeout never kill.

## Per-item tests and required failures

| Item | Tests | What must fail |
| --- | --- | --- |
| Retained generation after D6 | TestFreshGuidanceClaim, TestReplayPolicyGeneration, TestExactReceiptAfterD6 | Generation-3 results must survive current generation 4, including human preview and exact receipt before mutable task/turn preflight. No new candidate/reserve/judge call may occur. |
| Fresh approved generation | TestFreshPolicyGeneration | A fresh claim/judge must use generation 4; lane refresh validates the exact policy-only projection. |
| Invocation rights and observer | TestClaimObserver, TestClaimOwnerMismatch | Acquired=false must call protected await, not merely return an arbitrary error. Wrong attempt must refuse before fit/judge. |
| Two concurrent request keys | TestTwoClaimKeys | The winner blocks in evaluation until the second caller enters await. Both must receive the same result with one evaluator, one completion and one event. Premature second return is the named failure; timeout is setup failure. |
| Interrupted recovery | TestClaimRecovery | The interrupted original claim remains pending, then after its fixed deadline recovery uses the original cause, retains bindings and writes unavailable once with no new judge/score/IDs. A second recovery replays. |
| Cancellation and no takeover | TestClaimEpochCancellation, TestRecoveryDoesNotReserve, TestEarlyRecoveryRefused | Changed epoch, absent claim or early recovery cannot create a new evaluator or commit a replacement. |
| Budget and actual inputs | TestClaimBudget, TestFreshGuidanceClaim | Zero remaining life budget refuses before reserve/fit. Full nonempty task bytes, positive cap and actual grant context must reach the judge. |
| Atomic event and reply | TestFreshGuidanceClaim, TestClaimEventBytes | Completion must carry original operation/requester/request, claim CAS and epoch, exact event bytes and a durable read-back. |
| Internal method convention | TestInternalMethodContract | lane.turn is refused before reads; authorized empty-method retained replay succeeds without sealing a public reply. |
| Known empty corpus | TestEmptyAfterRankingCancel | Context cancellation after ranking must not turn a known empty corpus into an outage or invoke the judge. |
| Retained owner and deadline | TestReplayClaimContract | Missing owner attempt/operation/request/key/requester, absent or reset deadline, and zero budget must refuse pending, completed and exact replay before reply, reserve, await or evaluation. |
| Pending observation | TestPendingDoesNotRejudge | The observer must enter protected await before the owner completes, then receive the same result with one selection event and no new reservation/judge. Premature return is the named failure; timeout is setup failure. |
| Continuation exact reply | TestSelectRetainedReplay | A run-2 request seals the original run-1 selection, then its same-key retry returns the exact retained result without another transaction. |
| Exact target bound | TestExactReceiptTarget | Foreign life, zero run and future run refuse at the authenticated-request target check before any claim read. |

All previous ranking, fit, model/deployment audit, request/CLI, provenance and
receipt-shape tests remain. The scored-without-judgments fixture still uses
an explicit empty array with wire-shape preflight and exact error; scored-null
remains separate. Current errors cannot masquerade as the intended assertion.

## Installed acceptance still required

The in-memory fixture is not a production store or native boundary. The real
service/store must implement pending public receipt serialization, invocation-
specific acquisition, actual turn/epoch CAS, protected historical policy and
bounded await/recovery scheduling. Store reply receipts retain the result's
historical policy while authorization stays current. Those owning stubs remain
typed errors; guidance does not convert them into success.

The installed workload must still prove actual start, resume, mail and loop delivery,
profile continuation, restart and two-key behavior under authenticated scopes,
real scoped judge audits, prompt bytes and independently measured collection.
Run the frozen case only after those dependencies/workload exist:

```sh
sh e2e/v2/cases/guidance/run.sh \
  --context /test/guidance/context.json --result /test/guidance/result.json
```

Require exit zero, GUIDE-TURN reached=true/pass and collection evidence.
Component success and the integration DTO controls are not full GUIDE-TURN.
Archive source revision/bytes/hashes, brief/handoffs/review inputs, exact
commands/output/exits and control mutations outside the checkout. The Mac
produces no tested project binary.
