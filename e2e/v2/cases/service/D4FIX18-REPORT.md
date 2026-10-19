# Draft.4 fix 18 report

This candidate starts at 2a46490.
The complete active brief and delta review are retained in external evidence.
This round implements both P2 recovery paths, per-effect retry backoff and
compiled build visibility in health. Runtime behavior remains unmeasured in
this authoring round; no result from the running fix-17 box was consumed.

## 1. Crash-orphaned reservations

The concrete store now exposes TrackMutation and RecoverReservations as private
in-process ports, without changing the public API or database schema. The
dispatcher creates a tracker before atomic reservation and retires it only
when that invocation returns. ReserveMutation binds the insertion winner to
that opaque tracker under the same writer mutex that commits the reservation.
A losing invocation's retirement cannot clear another owner's entry.
Cancellation and deadline expiry do not retire a live invocation. Callers that
do not forward tracking are conservatively pinned for this writer's lifetime.

Recovery runs before the reconciler's pause gate, including during a durable
deployment freeze. It scans bounded reservation batches, requires deadline
expiry and absence of a live current-writer owner, and preserves any durable
effect handoff for its owning reconciler. A reopened writer holds the existing
exclusive OS writer lock; the old writer can no longer commit. Owner tracking
is deliberately separate from the persistent store ID, which survives reopen.

Each eligible orphan gets one atomic failed operation, operation.failed event,
exact typed unavailable reply and original receipt/key/raw bytes. Its pending
reservation is removed in the same transaction and waiters are notified. A
retry replays that failed receipt; it does not run preflight again. Recovery
does not authenticate a missing caller or execute a request. Storage/integrity
errors remain failures instead of being converted to empty success.

New reservations retain the full actor DTO in immutable projection history.
Legacy reservations reconstruct their original principal; lane level/role
come from retained immutable life attributes. Malformed/mismatched identities
refuse recovery. The terminal receipt preserves policy/presence provenance.

TestReservationRecovery covers reopen, a live cancelled owner, a retired owner,
an unexpired reservation and an untracked live caller. The live case also
retires a genuine losing reservation and requires the winner to stay pending.
Finalized cases require exact bytes/identity, empty request-drain inventory,
failed replay and successful whole-store verification. The legacy fixture
installs the old representation once before reopen without disabling history
triggers. TestRecoveryKeepsEffectHandoff requires a real staged effect to remain
pending. These are SQLite writer-lifetime component tests, not a measured
process kill or installed restart.

TestMutationRetirementRecovery observes an actual dispatched handler that
deliberately omits its required commit. Dispatch must return integrity, then
retire the invocation so expired reservation recovery can finish it. The
freeze-preparation and closed-store tests call the same preparation function
used by the loop; their deciding assertions need no timeout or sleep.

Hosted store wrappers must forward TrackMutation and RecoverReservations in
addition to ReserveMutation to provide same-writer retirement and automatic
recovery. Wrappers that omit tracking retain conservative live ownership until
writer close. Durable effects are not discarded by orphan cleanup; their
completion/reconciliation route remains authoritative.

## 2. Execution-stage refusal becomes terminal

A Forbidden returned by runEffect under its current claim now becomes a failed
EffectOutcome carrying that exact typed refusal and is passed to the real
CompleteEffect. The store still checks claimant, claim ID/generation and expiry
before committing. Its existing failed-outcome path writes operation.failed,
updates operation/effect status and retains the owning refusal. A stale claim
cannot be completed by this conversion.

Conflict remains a nonterminal fence. Joined/wrapped errors become terminal
only when every cause is an allowed fence and a Forbidden cause exists; mixed
store/integrity errors still stop and latch the executor fault. Claim-stage
and completion-stage fences keep their existing ownership-sensitive behavior.
The executor does not invent a measured successful external action.

TestExecutionRefusalTerminal covers plain, wrapped and joined refusals. A later
effect must still finish through real SQLite claim/completion. The refused
effect and operation must reach failed, retain the Forbidden message, leave
no pending retry and produce exactly one matching operation.failed event.
The prior fence test now expects terminal execution Forbidden while retaining
its unchanged latched-fault assertion before that outcome check. Its expected
state comes from fixture error data, not the production classifier.

## 3. P3 follow-ups

| Item | Current status and reason |
| --- | --- |
| Retry backoff | Implemented in source. The loop keys exponential delays by immutable effect ID, starts at 250 ms, caps at 30 seconds and resets on successful completion. A retry receives no new claimant before it is eligible. The regression checks independent IDs, growth/cap and reset using controlled times. State is in memory and resets on process restart, as the review requested. |
| Build variant visible in health | Implemented in source. Public health includes build-variant with normal, laneboss_faults, laneboss_e2e_authenticator or their combination. Actual compiler build tags choose the flags; they are not environment guesses. Test builds make that capability unavailable and cannot report production readiness. Mutually exclusive tagged tests compare real native health responses with the build selected for that test. |
| Four launch selectors | Already closed in the supplied review; retained. |
| Full journal verification at open | OPEN. Removing it needs an integrity-preserving checkpoint/recovery design and benchmark/regression evidence; this round does not weaken verification to improve startup latency. |
| One SQLite handle per read | OPEN. Pooling must preserve per-view transaction snapshots, descriptor ownership and close/replacement behavior; that performance/resource-lifecycle change is not implemented here. |
| ReserveEnrollment caller gate | OPEN. The shared port carries a ceremony request but no caller Scope/native frame. A safe gate needs the identity/admin producer to forward verified administrator authority through an agreed port; inventing an ambient caller or blocking the valid enrollment path is not a fix. |

The remaining P3s are not presented as fixed or as failing authorization
canaries. They remain explicit follow-ups for their store/API/identity owners.

## Controls, checks and handoff

All 186 existing control IDs are retained. Thirteen new controls bring the
inventory to 199 controls, 398 red/candidate pairs across normal and faults,
plus ten final package/tag suites. Seven reconciler anchors follow the new
backoff/terminal branches; their existing tests, selectors and markers remain.
MUTATIONS.md lists every new row's exact test/subtest and deciding assertion.

The orphan-finalization mutant must reach "orphan reservation remained pending"
after real reopen. The execution skip mutant must reach
"execution refusal remained pending" after the later real effect finishes.
Live/unexpired-owner controls require the opposite safety assertion. Setup,
schema, compiler, panic, race and harness timeout failures earn no red credit.
No test reads a mutant's literal. Compile-time variant flags reflect build
inputs; the variant tests still inspect the actual framed health response.

Implementation was complete before the permitted static checks. The authoring
environment was Darwin arm64, Go 1.26.5 and Python 3.13.11. All twenty changed
Go files were formatted first and have no trailing blank lines. Test names
remain under 40 characters.

| Check | Observed result | What makes it fail |
| --- | --- | --- |
| Literal catalog review | All 206 edits across 199 controls have one anchor; all 186 prior IDs retained; no no-op or mutated test file | Missing/duplicate anchor, removed/duplicate ID, no-op edit or mutated test target |
| gofmt -w | Exit 0 for all twenty changed Go files | Go parse/format error |
| gofmt -l | Exit 0, empty output | Any listed path or nonzero exit |
| Python py_compile | Exit 0 for mutations.py, run.py and scenario.py | Missing input or syntax error |
| bash -n | Both service entry scripts exit 0 | Shell syntax error |
| Linux amd64 vet | Exit 1: two existing Go cache entries refused access with operation not permitted | Vet/compiler diagnostic or unavailable cache |
| Linux laneboss_faults and Darwin vet | Skipped under the brief's explicit cache-refusal route | Not measured |
| Unit/mutation/native/installed execution | Not run on this Mac | Exact new red assertions, unchanged candidate greens and installed recovery/drain behavior |

The attempted vet command was:

```sh
GOWORK=off GOOS=linux GOARCH=amd64 GOPROXY=off GOSUMDB=off go vet ./internal/v2/store ./internal/v2/service ./internal/v2/client/...
```

Exact paths/output/exits are retained in vet-linux.json and vet-linux.log.
No cache was changed, redirected or retried. Only reporting and evidence
collection followed the refusal; no implementation edit or further source
check followed. No one-line compiler diagnostic was observed. Compilation,
new runtime test success and mutation kills are not established.

The supervisor must prove the new reds and unchanged candidate greens in both
tag modes, rerun the full package/inventory suites and perform the installed
crash/refusal/drain E2E. The authenticator-tag health tests also need their
separate tagged Linux run. Static source review does not establish those
results or an authenticated AI-service test.

Evidence is retained under d4fix18-2a46490 in the lane's external evidence root:
complete brief/review/rules, source revision and starting archive, phase/final
source bytes, exact mutant text, catalog review, check commands/outputs/exits,
diff/status and manifest. There is no tested binary in this static round.
The materialization files and transaction.go are not edited. No Git staging,
commit, merge, push or branch change occurred. No test machine was provisioned
and no additional agent was used. The candidate remains uncommitted.
