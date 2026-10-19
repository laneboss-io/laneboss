# Draft.4 fix 21 report

This round starts at 72087aa. It adopts the admission change from serve2
1327cef and the private failed-plan port specified by lifecycle 87f5dad.
Complete inputs and starting source bytes are retained in external evidence.
No result from the still-running fix-20 red box was consumed.

## 1. Native admission after an invalid first request

The server now retains a connection-local admitted flag. A native dispatch
receives its authenticated admission callback until the UID slot actually
moves to the authenticated containment. Only successful transfer updates the
flag and teardown key. Configuration and endpoint-class refusals precede
authentication, so they cannot consume the only opportunity to move the slot.
Authentication and admission failures receive one bounded correlated refusal,
then close. Public health remains a separate single-frame path.

The earlier serve2 entry helpers were required because this baseline still
performed first-frame authentication outside dispatch. Those helpers and the
correlated over-limit refusal regression are adopted with the connection loop.
The optional current-scope capability is expressed as the same private
structural interface because this API baseline has no named scope-source port.
The new regression is named TestAdmissionRetry to keep selected paths short;
its socket, kernel-credential, slot-map and teardown assertions are preserved.

Both admission-invalid-first-config and admission-invalid-first-class retain
the exact deciding assertion:

```text
valid second frame did not move UID slot to containment
```

The regression sends a schema-valid refused first request, then valid second
and third requests over the same real native socket. At handler entry it reads
the actual admission map, requiring one containment slot, no temporary UID slot,
no repeated transfer and complete connection/worker/slot collection. Trusted
peer registration isolates admission; it is not installed enrollment or actual
cgroup membership. The security finding remains suspected until Linux runs
the canary and controls. No runtime security impact is claimed here.

## 2. Atomic failed-plan credential cleanup writer

The store implements lifecycle.FailedPlanStore exactly: FailPlan and PlanCleanup.
Only the upstream private DTO/interface declarations are introduced in the
local lifecycle plan_fail.go; the owning lane's planner implementation is not
copied. A later lifecycle merge must retain its full file with these declarations
once. A compile-time interface assertion binds the store to the exact port.

FailPlan takes the existing single writer lock, freezes the cleanup request
bytes and passes a store-bound private capability into the existing internal
transaction. Failed plan state, every pending cleanup request, operation and
replay receipt commit in that one SQL transaction. There is no enqueue after
commit. The cleanup bytes participate in the replay digest. A private receipt
key coexists with an earlier generic stage receipt using lifecycle's same
deterministic write cause; the original intent, operation and claim remain
retained. Normal transactions retain their previous digest bytes.

The writer rechecks the real current planning claim, immutable reservation and
stage bytes, exact plan CAS, current cancellation fence, original requester and
operation, deterministic request IDs, slot/injection result selectors and
prepared/projection identity. A changed retry refuses. A generic failed-plan
transaction cannot omit cleanup after a credential-slot result exists.
Current policy advancement or a dispatch freeze cannot erase an authenticated
teardown request; neither grants fresh launch authority. The ordinary opening
and fresh stage-retention gates still require current authority.

The store accepts lifecycle's service-private manifest/spec stage records only
through an actual planning claim and reserved owner, life and generation. That
private capability is not an RPC field. Cleanup reads retain exact immutable
metadata references, never descriptors or credential values.

A bound, uncertain or protected unbound projection requires withdrawal before
release. Missing binding is not sufficient evidence of an unprojected gate.
Unknown slot/projection facts and their issues remain pending reconciliation
data. Release and injection revocation are retained as a complete pair when
the original protected state is unprojected. No cleanup receipt or quiescence
is manufactured.

PendingPlanCleanup exposes the private durable inventory. Pending operations
and targets appear in drain inventory even before a Lane exists. Whole-store
verification joins pending jobs to their failed plan, original stage object and
same-commit receipt. Restart retains those same requests and exact replay.

## 3. Atomicity and guard regressions

TestFailedPlanAtomic covers normal commit, outbox append rollback, policy
advancement, bound withdrawal and unknown slot results. Its failure trigger
aborts an actual cleanup history append after the failed revision was written
inside the transaction. The test requires the original plan and no queued jobs,
checks the exact injected append failure, then removes only its own trigger and
requires the same input to commit. Production immutability triggers remain.
The test also checks exact job read-back, drain visibility, verification,
writer reopen, replay after claim expiry and changed-request rejection.

The failed-plan-atomic mutation moves the outbox append into a second real SQL
transaction after the first commit. The deciding diagnostic is:

```text
cleanup append failure left a partial plan
```

This specifically detects the forbidden two-transaction implementation.
It does not count a timeout, schema setup refusal or unrelated diagnostic.
The omitted-outbox control separately requires exact retained cleanup requests.

TestFailedPlanGuards covers stale claim and epoch, foreign launch selector,
missing injection selector, stale projection revision, a protected projection
before binding and generic-transaction bypass. Each requires its typed refusal
and unchanged plan/outbox. Epoch has both the private writer check and ordinary
transaction cancellation guard; no isolated mutation kill is claimed for
removing only one of those independent fences.

## 4. Controls, checks and remaining integration

Fifteen controls are added and all 228 prior IDs remain: 243 controls and 254
edit anchors, or 486 targeted normal/faults pairs and ten final package/tag
suites. The existing containment-transfer and launch-replay-comparisons rows
are retargeted to the new source while preserving their tests and diagnostics.
MUTATIONS.md lists every new control's deciding assertion. Static anchor review
does not prove a reached red or candidate success.

The implementation was complete before the permitted checks. The environment
was Darwin arm64, Go 1.26.5 and Python 3.13.11. Observed results are:

| Check | Observed result | What makes it fail |
| --- | --- | --- |
| Literal source review | 243 unique controls, 254 unique edit anchors, all 228 prior IDs retained, all named tests present; new selected paths at most 39 characters | Missing/duplicate anchor or ID, removed row, no-op, absent test or mutated test file |
| New documentation source review | No forbidden full commit ID or long slash token introduced | A newly introduced forbidden token |
| gofmt -w | Exit 0 for all 13 changed Go files | Parse/format error |
| gofmt -l | Exit 0 with empty output | Listed path or nonzero exit |
| Python py_compile | All three service scripts exit 0 | Syntax or missing-input error |
| bash -n | Both service wrappers exit 0 | Shell syntax error |
| Linux amd64 vet | Exit 1 on three Go cache access refusals | Cache failure or vet/compiler diagnostic |
| Linux faults and Darwin vet | Skipped under the brief's explicit cache-refusal route | Not measured |
| Unit/red/candidate/native/installed | Not run on this Mac | Exact new red and unchanged candidate assertions remain required |

The attempted command targeted store, service, client and lifecycle:

```sh
GOWORK=off GOOS=linux GOARCH=amd64 GOPROXY=off GOSUMDB=off \
  go vet ./internal/v2/store ./internal/v2/service \
  ./internal/v2/client/... ./internal/v2/lifecycle
```

The exact single-line command, refusal text, output and exit are retained in
vet-linux.json and vet-linux.log. No cache was changed, redirected or retried.
Only reporting and evidence collection followed the refusal; no implementation
edit or further source check followed. Compilation is not established, including
the port's interface assertion. No runtime test, product build, project Python
import, remote machine, additional agent or authenticated model request ran.

Native cleanup dispatch/completion is not implemented by this store writer.
Requests remain pending and block drain; they do not assert that credentials
were erased or a lease was released. The actual consumer must reconcile the
original selectors, invoke BeginCredentialWithdrawal, helper withdrawal and
measured FinishCredentialWithdrawal, then Release/RevokeInjection only after
real helper quiescence. The existing native projection/broker/helper owner
ports still refuse where not implemented. Native leak closure is not claimed.

The supervisor must merge the lifecycle producer, run all new exact red and
unchanged candidate paths in normal/faults, rerun admission isolation/public
health and the full service/store inventories, and then exercise installed
native cleanup/restart with the owning components. The adopted admission
fixtures and SQLite cleanup tests are not an authenticated AI-service test.

Evidence contains complete input patches/contracts, source archives, literal
control data, derived mutant bytes, exact static results, final diff/status
and a SHA-256 manifest. No staging, commit, merge, branch switch, extra worktree,
model request or test machine was started. The candidate is uncommitted.
