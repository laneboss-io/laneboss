# Store adoption of shared contract fix 13

The candidate starts at 7fdbad3. The supplied
group run failed only the store package, in normal and laneboss_faults modes.
The store's two internal preflights still used ordinary transaction validation
even for the private failed-plan writer. Cleanup fixtures also called ordinary
validation, while two launch tests submitted failed revisions through Transact.
The API now correctly refuses all of those ordinary failed planner writes.

The shared API sources and docs/design/v2-contracts.md are unchanged. No
ValidateTransactionShape, ValidateFailedPlanWrite or plan-write rule is relaxed.
This round performed static checks only. Corrected runtime outcomes remain
pending Linux execution; no candidate runtime pass or mutation kill is claimed.

## TestFailedPlanAtomic

The existing writer now selects the shared preflight through a private helper.
Only FailPlan can bind its store-owned context capability, after freezing the
complete []api.PlanCleanup batch with the existing internal decoder. Both
transactInternal preflights use ValidateFailedPlanWrite for that capability,
and ValidateTransactionShape otherwise. The public port and persisted jobs use
the API's types, with the api.FailedPlanStore compile-time assertion retained.
FailPlan's local blanket event rejection is replaced by the shared closed
failure-event catalog; ordinary effects and non-plan writes remain refused.

The complete batch is constructed before fixture preflight. Each base fixture
must pass ValidateFailedPlanWrite and must be rejected by ordinary preflight
with CodeInvalid. Unknown fields/slots remain unknown and retain their actual
reconciliation errors. No invented selector makes them look complete.

Commit, rollback, policy, withdraw and unknown leaves remain. The real SQLite
append-failure trigger, exact rollback/read-back, same-commit outbox, original
dispatch selectors, Verify/reopen, expired-claim exact replay and changed-byte
conflict checks remain. The transaction still writes the failed revision,
every job and private receipt before its single commit.

Changed retries now add the same owned issue to every job and explicitly pass
shared preflight, so common-batch validation cannot mask the intended digest
conflict. The deciding diagnostics remain cleanup append failure left a partial
plan, failed plan and cleanup did not commit together, failed plan lost an
atomic cleanup request and cleanup replay accepted changed request bytes.

## TestFailedPlanGuards

All seven leaves remain: claim, epoch, selector, injection, projection,
unbound_projection and generic. Live claim expiry, cancellation, exact CAS,
immutable reservation/stage bytes, projection generation and complete teardown
checks remain in production. Every refusal still requires its exact typed
code, unchanged original plan and empty pending-cleanup inventory.

Selector mismatch and an ordinary generic failed write now require the shared
contract's CodeInvalid. They do not silently fall through to a weaker store
guard. Other deliberately state-invalid requests explicitly pass shared batch
preflight before reaching their intended persistent-state guard. The injection
omission is applied consistently to both release/revoke jobs; omitting only
one job's fields would fail common-batch validation before the stage-ref guard.

Two controls account for overlapping barriers while preserving their IDs,
selectors and exact failed-plan cleanup guard accepted selector/generic
diagnostics. The selector control disables the store's shared preflight call
and its duplicate original-selector comparison. The generic control disables
ordinary preflight at the store boundary and its separate required-outbox guard.
Each changes only plan_cleanup.go. Neither changes an API validator, and the
candidate retains both checks. A shared refusal under a one-barrier mutant
would not count as reaching the intended assertion.

## TestLaunchPlanAuthority

The positive fixture uses the existing real SourceTransaction for a valid
reserved-to-sourced issuance, with an explicit ordinary shared preflight.
It no longer fabricates a failed planner revision through Transact.
All eight authority faults remain: foreign reservation, stale policy, stale
starter grants, expired claim, changed claimant, missing plan CAS, missing
cancellation and attempted new reservation. The missing-CAS case removes only
the plan comparison and retains the grant issuance comparison. The new-
reservation case omits unrelated grant writes/events. Refusals compare the
entire persisted plan with the actual original reserved record.

The valid control must commit, read back its exact submitted sourced plan,
replay the same transaction and reject a retry with changed comparisons.
The existing launch-plan-reservation and launch-plan-policy controls retain
their source edits, selected leaves and launch plan accepted foreign_reservation
and launch plan accepted stale_policy deciding diagnostics.

## TestFailedLaunchNameReuse

The test now builds an actual retained credential-stage failure fixture and
commits its failed plan plus complete cleanup batch through FailPlan. It then
records the real claimed effect's failed outcome before making a fresh root
request. It retains the no-ready-Lane assertion and requires fresh reservation,
life and launch IDs. The original failed record must remain equal to the
submitted DTO, and every pending cleanup job must remain unchanged after reuse.
No resource collection or old allocation reuse is claimed.

The production name-reservation guard is unchanged. The deciding control
remains launch-failed-name-release and must fail failed unbound launch kept
its lane name reserved. A failed revision without a cleanup batch is not used
as a fixture shortcut.

## Static verification and Linux handoff

All 309 controls remain, with only the two paired-barrier controls changed.
The 329 sequential source anchors match once, and no prior ID is missing.
Every other row is unchanged. The full inventory still requires 618 targeted
normal/faults pairs and fourteen final package/tag suites; this static round
credits none of those executions. Existing test names and leaf selectors remain.

Six final candidate-only whole-tree go vet variants passed with empty output:
Linux amd64/arm64 normal and laneboss_faults, plus Darwin arm64/amd64. Every
Go vet used GOCACHE=/private/tmp/lb-shared-gocache, GOWORK=off, GOPROXY=off and
GOSUMDB=off. The initial vet found launch_delta_linux_test.go:148:21: undefined:
reflect; that missing import was corrected before the clean matrix. Its failure
output and both corrected matrices are retained. The final matrix includes the
subsequent CAS/read-back refinement.

gofmt -l, Python py_compile, whitespace and unchanged shared-source checks pass.
No runtime test, product binary build, project interpreter execution, mutant
compilation/vet, cloud job, staging or commit occurred. The supervisor must
rerun all four named test groups in both variants, require each deciding
red/candidate pair to reach its exact assertion, then rerun the full group.

Evidence is retained under lb-v2-service-evidence / contract13-7fdbad3, with exact
governing inputs, supplied failure log, base/final source archives, static
commands/results, unchanged API/contract comparisons, control mappings and
verified manifest. No product binary was built here, so there are no tested
product binary bytes or hash to claim. All changes remain unstaged/uncommitted.
