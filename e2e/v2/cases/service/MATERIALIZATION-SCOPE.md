# Materialization generic-scope review

The reviewed source is 09163272. The source-review verdict is **CONFIRMED**
for the scanner's fixed-operation short-circuit: transaction.go:473-475
authorized a materialize connection as input.read without checking which
generic store operation it was entering. This is a source-level finding,
not a measured security exploit. The runtime security status remains
**SUSPECTED / unmeasured** until the harmless Linux canaries below run with
their opposite controls. This authoring brief permits static checks only.

The decisive source chain is Policy (read.go:491-493) → scopedProjection
(projection_reads.go:11-25) → readScope (snapshot.go:108-114) → scope.
After the original shortcut succeeded, a worker skipped the human-session
branch and read the protected current policy without another worker operation
gate. BeginRead (snapshot.go:49-92) similarly acquired a real snapshot after
readScope. These paths accept a correctly correlated worker even when its
frame names policy.get or result.append. dataWorkerScope
(worker_bootstrap.go:102-123) verifies the principal and the operation supplied
by its caller; the shortcut supplied input.read unconditionally.

This does not establish that a native worker can call Policy over the installed
socket. The private worker listener's closed switch
(service/worker_listener.go:192-221) routes only input.read, result.append and
object.read, and refuses other names. The service's dedicated handlers verify
the matching framed operation, digest and parameters before authorization
(service/materialization.go:326-354). No new socket or public route is added
by this fix, and no installed reachability claim is made from code inspection.

The fix in store/transaction.go:473 rejects every materialize lease in generic
scope with forbidden and the message "materialization workers must use
dedicated job operations". It rejects result.append there as well. It does
not infer authority from a private method name. The dedicated store handlers
remain separate: WorkerInput calls dataWorkerScope with WorkerInputRead
(worker_bootstrap.go:132), WorkerResult with WorkerResultAppend (:156), and
WorkerObject with WorkerObjectRead (worker_objects.go:19).

All paths below are under internal/v2/store. Line references describe the
reviewed source; the central refusal is the only production change. The table
lists all 18 direct calls to scope, including helpers and the preflight-blocked
ReserveLaunch call, so a caller with an additional gate is not mistaken for an
additional successful worker operation. "Reaches" means a worker Scope supplied
to the Go store method reaches that call; it does not mean a socket route exists.

| Direct caller / scope call | Worker reach and remaining checks in 09163272 |
| --- | --- |
| Transact, transaction.go:17 / :23 | Reaches. Public requests still pass wire.ValidateRequest and mutation/write/event gates. Internal input still passes the internal emitter/intent catalog. The shortcut itself grants no method-specific protection. |
| RetainObject, objects.go:82 / :88 | Reaches. Later checks require an allowed internal object-retain intent and causal operation; capture objects additionally require the registered capture producer. |
| Upload, objects.go:250 / :256 | Reaches. Later checks require the upload's matching actor and unexpired lease. |
| AuthorizationTarget, contract_stubs.go:12 / :18 | Reaches. authorizationTarget (projection_reads.go:51-54) subsequently requires a human endpoint. |
| claimContinuation, continuation_claim.go:20 / :26 | Reaches through ClaimContinuation (contract_stubs.go:169). Internal-only gate at :29 subsequently refuses a worker connection. |
| identityProjection, projection_reads.go:27 / :33 | Reaches through Enrollment, Challenge, Proof, Ticket and ReadSession (contract_stubs.go:24, :65, :73, :81, :92). Human/internal-only gate at :36 refuses a worker. |
| readScope, snapshot.go:108 / :109 | Reaches through the full indirect read inventory below. Worker returns nil at :112-114 after the original shortcut. |
| dataScope, materialization.go:45 / :49 | Reaches through LaunchDataStage (:91), DataStage (:333), SealDataStage (:347), RecordDataClaim (:447), DataHandoff (:482), BindDataWorker (:537), RecordDataProcess (:574), DataReceipt (worker_bootstrap.go:279), DataResult (:300), and CompleteMaterialization (:327 → recordDataMeasurement :338). All except initial LaunchDataStage delegate through loadDataStage (materialization.go:300). The private service-only gate at :52 refuses a worker. |
| LookupReceipt, receipts.go:49 / :55 | Reaches directly and through AwaitReceipt (:235 → :240). Later public metadata/key checks and principal-scoped receipt lookup remain. |
| ReserveMutation, receipts.go:142 / :148 | Reaches directly and through ReserveRequest (:135). Later checks require a valid public mutation/frame/deadline and reserve under its principal. Private result.append fails the public catalog later, which is not sufficient generic authorization. |
| Effect, effects.go:35 / :41 | Reaches; internalScope at :44 subsequently refuses a worker connection. |
| ClaimEffect, effects.go:49 / :55 | Reaches; internalScope/claimant/deadline gate at :58 subsequently refuses a worker connection. |
| CompleteEffect, effects.go:180 / :186 | Reaches; internalScope at :189 subsequently refuses a worker connection. |
| LaunchPlan, launch_plan.go:14 / :20 | Reaches; internalScope at :23 subsequently refuses a worker connection. |
| RefreshLanePolicy, policy_generation.go:88 / :95 | Reaches; private service-only gate at :98 subsequently refuses a worker connection. |
| CaptureState, capture.go:53 / :59 | Reaches. Later captureWorker check (:68-70; :22-50) requires the registered producer and capture_supervisor lease. A materialize lease cannot satisfy it. |
| AppendCapture, capture.go:76 / :82 | Reaches. Later capture append/intent checks and captureWorker (:100) refuse a materialize lease. |
| ReserveLaunch, launch_reservation.go:37 / :46 | A materialize actor is rejected before scope by ValidateLaunchReservationRequest (:43; api/launch_authority.go:41-55), which allows human/lane or the separate internal continuation authority. Included for complete call-site accounting. |

The complete indirect read inventory is as follows. Every listed path goes
through readScope to the same central scope check unless an explicitly named
precheck rejects the worker first.

| Read entry / helper | Consequence after the original shortcut |
| --- | --- |
| BeginRead, snapshot.go:49 → :55 | Acquires a real private read snapshot without another operation check. The result.append canary targets this path so an unknown-public-method error cannot mask the finding. |
| ObjectMetadata, objects.go:60 → :66 | Additional objectVisible ACL remains at :77. |
| Operation, read.go:84 → :91 | Principal/administrative visibility remains at :107. |
| Lane, read.go:163 → :170; Relation, contract_stubs.go:209 → Lane | visibleLife excludes worker actors at read.go:125, so a target lane is refused. |
| Events, read.go:208 → :215 | visibleLife refuses worker access at :226-231. |
| EventVisible, read.go:322 → :328 | Event-specific visibility and mail-receipt checks remain; no operation-level worker grant is added. |
| Records, read.go:350 → :357 | Per-record collection/life/visibility checks remain. |
| Blob, read.go:520 → :527 | Range and objectVisible ACL checks remain. This is distinct from the sealed-job-only WorkerObject handler. |
| PolicyAt, policy_generation.go:11 → :17 | Reads retained policy after generation/hash/history validation, without an additional worker-operation gate. |
| listProjection, list.go:11 → :17; called by Lanes (read.go:191) and Mail (:496) | Page/cursor and life/recipient filters remain. |
| scopedProjection, projection_reads.go:11 → :17 | Policy (read.go:491), Approval, Application, Turn, Decision, JudgeAudit, ContinuationIntent and own WorkerLease (contract_stubs.go:145, :149, :153, :161, :165, :173, :197) reach it. Most have no additional worker-class gate; Turn also compares its target. WorkerLease rejects foreign lease selectors first. |
| Change (read.go:513), Channel and Deployment (contract_stubs.go:181, :217) → scopedProjection | Their human/L6/internal prechecks refuse the materialize actor before scopedProjection. |
| guidanceScope (guidance.go:26 → :30), used by DecisionCandidates (:33), GuidanceReservation (:167), ReserveGuidance (:184), AwaitGuidance (:333) | guidanceScope rejects worker actors at :27-28 before reaching readScope. |

Methods with no Scope, private helpers that do not invoke scope, and
not_implemented stubs are not inferred to be worker routes merely because
they are exported Go methods. WorkerBinding is a protected identity lookup;
the three dedicated job handlers intentionally use dataWorkerScope directly.

TestDataGenericScope has two real subtests, both with complete test paths
under 40 characters. non_worker proves dedicated input and sealed object
reads can return actual retained bytes, then compares a generic policy read
against the protected service read. It requires the exact central refusal and
zero returned policy. result_append supplies a complete result submission and
matching frame to generic BeginRead and Transact, requires the same central
refusal with no view or commit, then proves dedicated WorkerResult and its
exact receipt replay still work.
The helper/native identities are explicit component doubles, not native
authentication evidence. No digest is hard-coded and no check skips a failure.

| Mutation | Exact assertion path | Required reached assertion |
| --- | --- | --- |
| materialize-generic-non-worker | TestDataGenericScope/non_worker | materialize worker entered generic policy read |
| materialize-generic-result | TestDataGenericScope/result_append | materialize result entered generic read scope |

Both mutations restore the original two-line input.read shortcut in the
single production scope function, leaving every test unchanged. The first
marker is reached only after the canary reads the same actual policy as the
service control. The second marker follows a real read snapshot with the
expected configuration and nonempty ID; the view is closed before failing.
An unrelated refusal instead fails the exact gate assertion, and an unrelated
data/view mismatch fails its own diagnostic, so neither receives red credit.

The two controls must compile and reach those assertions on the authorized
Linux machine in normal and laneboss_faults variants, followed by the unchanged
candidate passing the same paths. The existing run-mutations.sh supports each
--mutation name with --variant both and retains the bytes and observations.
No runtime canary, red/candidate result or installed-service result is claimed
by this static authoring report. The background mat-red1 run predates these
two controls and cannot establish their result.

The authoring checks on Darwin arm64 with Go 1.26.5 passed: gofmt -w and
gofmt -l for both changed Go files; go vet for ./internal/v2/store/... and
./internal/v2/service targeting Linux, Linux with laneboss_faults and Darwin;
python3 -m py_compile for mutations.py; bash -n for both service drivers;
and git diff --check. The new mutation return anchor occurs once and the
inventory has 183 rows. The reserved server.go, client.go and reconcile.go
files are unchanged. These are static results only.
