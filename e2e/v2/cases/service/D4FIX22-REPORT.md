# Draft.4 fix 22 report

This round starts at 4e361ce. The active brief, starting source archive and
supplied unit-verifier log are retained in external evidence. Work on this Mac
is limited to source changes and static checks. No unit test, runner execution,
binary build, cloud job, agent session, staging or commit was performed.

## 1. Original materialization planning claim

The supplied log for 72087aa records this failure in one build and a passing
service package in the other build:

```text
--- FAIL: TestDataStageDispatch (0.26s)
    materialization_linux_test.go:196: materialization dispatch repeated a retained launch conflict: materialization requires the original planning claim
```

The source cause is production selection, rather than a missing fixture claim.
DispatchEffects orders retained rows by generated effect ID. The first call
creates and claims the materialization Worker child while its PlanLaunch
parent remains claimed. Both records deliberately share the reservation's
target, configuration, requester, operation, request and cancellation epoch.
The generic inputClaimRecord lookup returns the first qualifying live record.
On replay, a child that sorts before its parent therefore reaches the existing
PlanLaunch check and refuses. Generated IDs explain the order dependence;
the original parent was never removed from the store.

MaterializationStage now calls planningClaimRecord. It filters inventory for
PlanLaunch with the exact reservation ID before using the existing claim
lookup checks. Expiry, claimant, outcome, all causal pins and the store's
ValidateLaunchControlClaim recheck remain. The final PlanLaunch guard remains
as well. Generic input reads retain their existing stage and cleanup behavior.
There is no sleep, retry-until-pass or relaxed claim check.

TestDataStageDispatch now has parent_first and child_first cases. Its wrapper
only reorders actual DispatchEffects records from the real store. Each case
requires both real claimed records in the chosen order, calls replay exactly
once, and requires identical stage bytes and one registration, preparation and
open. TestDataParentClaim completes the actual parent with a typed failed
outcome, proves the live child can still authorize a generic plan read, and
requires materialization replay to refuse before any helper call.

The two new strict red controls are:

| Control | Test and leaf | Deciding diagnostic |
| --- | --- | --- |
| data-parent-select | TestDataStageDispatch, child_first | materialization dispatch repeated a retained launch |
| data-parent-completed | TestDataParentClaim | materialization child replaced a completed planning claim |

The first mutant restores generic selection, so child_first deterministically
selects the wrong record. The second also removes the final type guard, so a
completed parent's child can incorrectly replay the opened stage. Tests are
unchanged in both mutants. Their Linux failures and candidate passes remain
required; source inspection supplies no runtime credit.

The red runner now puts FAIL lines and nearby assertion context before its
bounded output tail. It handles assertions before a verbose FAIL header and
after a nonverbose header. The diagnostic remains at most 12,000 characters;
the original complete test.log bytes remain retained. The outer exception
report also retains that diagnostic for the same step, and result.json records
it. A new step cannot inherit an unrelated earlier failure.

The five Python regression methods in test_diagnostics.py cover early failure
in both output orders, short output, build-output tails, the outer failure
report and separation between steps. They import the real runner. The retained
diagnostics-red directory pairs the same tests with the starting runner; it
must fail on the missing early FAIL lines and discarded final diagnostic.
The diagnostics-candidate directory must pass. Neither was executed here.

## 2. Failed-plan port ownership

The canonical PlanCleanup and FailedPlanStore declarations now live in
internal/v2/api/plan_cleanup.go. The store and its regressions use those API
types directly. Its compile-time assertion names api.FailedPlanStore. The
store no longer imports lifecycle for this private port. Request fields, JSON
names, field order and the atomic writer behavior are unchanged. This private
in-process extension adds no RPC, StateWrites field or effect-union member.

The local 42-line lifecycle/plan_fail.go subset is deleted. No alternative
lifecycle declaration shim is added. Lifecycle's full implementation must win
when it lands. Simply keeping its old named PlanCleanup alongside the API
named type would make FailPlan's signatures incompatible even though their
fields match.

[lifecycle-port.patch](lifecycle-port.patch) is the concrete integration delta
against the full 186-line file at 87f5dad. After retaining that full file,
replace its two declarations with these aliases:

```go
type PlanCleanup = api.PlanCleanup
type FailedPlanStore = api.FailedPlanStore
```

The supplied patch makes exactly that conversion; its full resulting file is
retained externally. Every byte from the first implementation method onward
matches 87f5dad. The full lifecycle planner is not imported into this stub
checkout. Applying the alias patch when the owning implementation lands is
required integration work; copying its old declarations unchanged would not
implement the store port. No duplicate lifecycle file should be restored.

## 3. Verification and retained evidence

gofmt -w was run on all six changed Go files before checks. gofmt -l then
exited 0 with empty output. Python py_compile of the runner and its regression
file exited 0, and bash -n of run-mutations.sh exited 0. The authoring host is
Darwin arm64, Go 1.26.5 and Python 3.13.11.

Data-only literal inspection in orchestration JavaScript found 245 unique
controls and 257 edits. All 243 prior rows, including their tests, leaves,
edits and deciding diagnostics, are unchanged. Every sequential literal anchor
matches exactly once. This does not import or execute project code.

git apply --check of lifecycle-port.patch against the retained complete
87f5dad input exited 0. It did not alter the input or apply an implementation
to this checkout.

The sole vet attempt was:

```sh
GOWORK=off GOOS=linux GOARCH=amd64 GOPROXY=off GOSUMDB=off go vet ./internal/v2/api ./internal/v2/store ./internal/v2/service ./internal/v2/lifecycle
```

It exited 1 with operation-not-permitted refusals for three Go build-cache
paths, one repeated at lifecycle's continuation import. The exact command and
all four refusal lines are retained verbatim in external checks.json and
vet.log. No cache location or permissions were changed, and the command was
not retried. Remaining vet variants were skipped under the brief's explicit
recovery route. No further source change or dependent check followed that
refusal; only reporting and evidence collection continued.

Compilation, Linux behavior and red/candidate results remain unestablished.
Native cleanup consumption and measured completion from the previous round
remain outside this change.

External evidence is the lb-v2-service evidence round d4fix22-4e361ce. It keeps
the full input brief and rules, starting archive, supplied log, exact check
commands/outputs/exits, catalog audit, candidate and mutant source bytes,
diagnostic red/candidate inputs, lifecycle before/after bytes, final archive,
diff, status and SHA-256 manifest. No tested product binary exists for this
round because product builds were not authorized here.

On the disposable Linux verifier, run both new controls in both tag variants,
then the complete mutation inventory and both required package/tag suites.
The inventory is now 490 targeted red/candidate pairs and ten final Go suites.
Run python3 test_diagnostics.py once in each retained diagnostic directory:
the starting runner must fail at the named missing-diagnostic assertions and
the candidate must pass all five methods. Retain both exact outputs and exits.
The composed installed service E2E remains the acceptance gate. These component
fixtures do not execute an authenticated AI-service test.
