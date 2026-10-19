# Draft.4 fix 20 report

This round starts at 420237d. The complete brief, rules, starting source and
supplied verification transcript are retained in external evidence. This is
a static Mac authoring round; the corrected candidate has not run on Linux.

## 1. The continuation control's masking failure

The retained transcript stops at continuation-claimed-epoch before its intended
assertion. Its normal-build diagnostic is:

```text
component retained session transition failed invalid_request: invalid typed transaction shape
```

That is a fixture policy-authority mismatch, not a demonstrated effect-state
comparison failure. continuationSetup first opens and ends a real stored launch.
Fixture.Ended then tried to retain the ended session using InternalHelperOpen,
writing a Lane without a LaunchPlans entry. The fix-12 private policy fence
requires the matching retained plan for this opening authority, so shape
validation stopped setup before ClaimContinuation could check the changed epoch.

The fixture now records that already-ended process observation under the
existing InternalLifecycleEffect row. That row explicitly permits Lanes and
runner.session. The helper's exited observation is retained first. The session
write uses the actual prior lane generation for CAS and its cancellation guard,
passes the shared shape preflight, commits through the real store and reads
the actual lane back to require its ended state, generation and session.

The actual fresh gate-opening fixture still uses InternalHelperOpen and its
retained plan. No production emitter, policy fence or epoch guard is changed.
No native gate is opened by the corrected observation fixture.

## 2. Preserve the deciding assertion

The row, exact mutation, selector and diagnostic remain unchanged:

- Control: continuation-claimed-epoch.
- Test: TestContinuationLaunchGuards/old_epoch.
- Mutation: remove only the retained-versus-request cancellation epoch comparison.
- Required diagnostic: continuation claim accepted old_epoch.

Before the negative input, the test now reads the actual effect and requires
EffectClaimed, no outcome and its authentic claimant. Every guard case requires
the typed conflict error, so a generic shape/storage refusal cannot pass as
the expected authorization refusal.

For old_epoch, the candidate also requires that refusal leaves the original
continuation pending at generation one. It then submits the original current
epoch and requires that same continuation/operation to become claimed at the
next generation. This positive control runs after the refused attempt; it does
not pre-claim the intent and move the mutant into a different replay guard.

With the named comparison removed, all unchanged setup and other fences still
use the original retained lane/intent/claim. The altered request epoch therefore
reaches the existing accepted-old-epoch assertion. That is the required Linux
red, not a result measured here. The unchanged candidate must pass this exact
leaf, including the restored-input positive control.

## 3. State and claim control sweep

The source sweep covers 27 controls: direct state/claim/outcome edit anchors,
the measured-operation row, the continuation row and the related reconciler
fence/fatal controls. The external sweep-review.json lists every row, mutation,
test, diagnostic, source rationale and prior transcript scope.

| Scope | Rows | Source finding |
| --- | --- | --- |
| Terminal state mapping, reclaim and four state readers | 7 | Real store fixtures expect shared pending/claimed/completed/failed states. Legacy labels occur only as intentional corruption or regression inputs. |
| Reclaimed allocation | 1 | The real claim advances to the shared claimed state; the deciding assertion observes generation-based recovery without another allocation. |
| Measured operation inventory | 1 | Operation succeeded is deliberately corrupted while its effect remains pending. It is not an effect-state success label. |
| Frozen claimed inventory | 1 | Actual claims populate the outbox; the mutation hides claimed rows rather than comparing incompatible labels. |
| Claim expiry | 1 | The fixture expires a real claimed record; original claim/plan data stay intact. |
| Continuation epoch | 1 | Corrected ended-session setup and strengthened the typed refusal/positive control as described above. |
| Launch claim/completion claimant and private plan read | 3 | Real claims and completed outcomes are used; no old running/succeeded effect label selects the deciding branch. |
| Reconciler claim/run/completion fences | 6 | Later work requires EffectCompleted plus a succeeded outcome. Execution Forbidden retains a failed outcome; unowned/stale claims stay unfinished. |
| Reconciler fatal errors | 4 | Original storage/integrity errors must latch and stop later work; they are not credited as fence/state refusals. |
| Execution refusal, plain and joined | 2 | Both require a terminal failed effect/operation and exactly one matching failure event. |

No additional concrete state-label masking mismatch was found in this source
scope. The seven direct state controls, reclaimed allocation, measured operation,
frozen inventory and claim expiry already have normal red/candidate passes
reported in the supplied transcript. These eleven prior pairs belong to
420237d, not to this edited candidate.

The full retained transcript reports 113 normal pairs before the continuation
failure. The brief reports the failure in both builds; the retained transcript
contains only the normal run, so no faults result is inferred from it.

The shared Ended helper also serves TestLaunchRetainedReservation and
TestLaunchRetainedGuards, plus both continuation tests. Those full candidate
tests must be rerun on Linux. No other control or production predicate is
changed. The inventory remains 228 controls and 238 edits, with all prior IDs.
No assertion, row, strict red diagnostic, timeout bound or runtime gate is removed.

## 4. Checks, evidence and remaining limits

The implementation was complete before the permitted checks. The environment
was Darwin arm64, Go 1.26.5 and Python 3.13.11. Observed results are:

| Check | Observed result | What makes it fail |
| --- | --- | --- |
| Literal catalog review | All 228 IDs retained; all 238 anchors unique; all tests present; catalog bytes unchanged | Missing/duplicate anchor or ID, removed row, no-op, absent test or mutated test file |
| New documentation source review | No full commit ID or long slash token introduced | A newly introduced forbidden token |
| gofmt -w | Exit 0 for both changed Go files | Parse/format error |
| gofmt -l | Exit 0, empty output | A listed path or nonzero exit |
| Python py_compile | All three service scripts exit 0 | Syntax or missing-input error |
| bash -n | Both service wrappers exit 0 | Shell syntax error |
| Linux amd64 vet | Exit 1 on Go cache access refusal | Cache failure or vet/compiler diagnostic |
| Linux faults and Darwin vet | Skipped by the brief's explicit cache-refusal route | Not measured |
| Unit/red/candidate/native/installed | Not run on this Mac | The exact repaired red and unchanged candidate green remain required |

The attempted command was:

```sh
GOWORK=off GOOS=linux GOARCH=amd64 GOPROXY=off GOSUMDB=off \
  go vet ./internal/v2/store ./internal/v2/service ./internal/v2/client/...
```

The exact single-line command, refusal, output and exit are retained in
vet-linux.json and vet-linux.log. No cache was changed, redirected or retried.
Only reporting and evidence collection followed the refusal; no implementation
edit or further source check followed. Compilation is not established.
No runtime test, project interpreter execution, product build, remote machine
or authenticated AI-service request ran in this round.

The supervisor must demonstrate the exact continuation red and unchanged green
in normal and faults, rerun the 27 swept rows and complete the package/inventory
suites. Compilation, a reached repaired red and corrected candidate success
remain unmeasured in this authoring round. The supplied no-timeout observation
belongs to the prior run; the ten-minute bound is retained without claiming
another measured duration. No authenticated AI-service test is claimed.

Evidence retains the complete input log, source archives, literal controls,
derived mutant bytes, per-row sweep, static results, final diff/status and a
SHA-256 manifest. The candidate remains unstaged and uncommitted. No additional
agent, worktree, branch, account, machine or session was started.
