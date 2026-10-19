# Component mutation controls

The current Run 45 inventory in `mutations.py` contains 325 controls. Both
normal and `laneboss_faults` variants require 650 reached reds and 650 unchanged
candidate controls, followed by fourteen package/tag suites. The five added
rows cover stale lane socket recovery, live/replaced/foreign socket retention
and strict abandoned-mark target grammar. Older round counts below describe
their historical source inventories and do not replace this current total.

Run 37 unions serve2 `bec6bf14` with lb-v2 `3bff4a3d`: all 260 serve2
and 309 lb-v2 control IDs remain as 313 unique controls. The four session
finalization/receipt controls remain alongside archive ownership, worker,
enrollment and streaming controls. Initial object-view, private blob-class and
non-owned reconcile-fence anchors follow the merged code without changing
their selected tests or failure diagnostics. The source histories below are
retained; merged runtime red/candidate and installed E2E results remain pending.

Run these only as an unprivileged user on the supervisor's disposable Linux
machine. The candidate is the working tree based on 7fdbad36, including the
store's adoption of the shared atomic failed-plan contract. Unit tests and mutation execution
have not run in this authoring lane. The composed installed serve E2E remains
the acceptance gate.

```sh
bash e2e/v2/cases/service/run-mutations.sh --source /test/source --evidence /tmp/lb-service-contract13
```

Use a fresh absolute evidence directory outside that source. A selected pair
uses --mutation NAME and --variant normal, faults or both. --list names its
exact test, optional subtest and required assertion. A selected pair does not
credit the full inventory.

The current inventory contains 325 controls: 650 targeted red/candidate pairs
across the normal and laneboss_faults variants, followed by fourteen final package/tag
suites for wire, client, service, store, CLI, admin and identity. Only complete_inventory=true,
exit 0 and PASS: service component mutation controls credit the inventory.
The dedicated laneboss_e2e_authenticator enrollment/presence tests need their
separate tagged Linux run; those tests are outside these two mutation variants.

Each source anchor must match exactly once before any build. Each mutant
changes only its named production file and leaves every test unchanged. It
must build and exit 1 with the exact required assertion and selected FAIL path.
The unchanged candidate must pass the same path. A sibling refusal, compiler
error, panic, race, skip, timeout or surviving process group earns no credit.
Declared subtests require the leaf and every ancestor FAIL path. Top-level
controls require only their named top-level failure.

Contract fix 13 adoption retains all 309 IDs and every test selector/deciding
assertion. Only failed-plan-selector and failed-plan-generic change their edits.
The former bypasses the store's shared batch preflight as well as the duplicate
persisted-selector comparison; the latter bypasses both ordinary shared-shape
preflight and the existing cleanup-outbox guard. Both controls change only
plan_cleanup.go, and neither edits the API validator. These paired barriers
must be disabled together to reach the same intended refusal assertion; an
earlier shared refusal earns no kill. All 329 anchors match once. Injection
faults apply the same omission to both jobs so shared batch consistency cannot
hide the retained-selector check. Changed retry issues carry an owner and are
consistent across the batch, with explicit shared preflight before retry.
Launch authority uses real valid source issuance, and name reuse uses FailPlan
with its complete retained cleanup. CONTRACT13-REPORT.md records every group,
the exact source trace and required Linux proof. No new runtime kill is claimed.

Fix 31 retains all 303 previous rows unchanged and adds six controls for the
shared legacy enrollment verifier, bound worker entry/delivery/later-request
refusals, stream terminal refusal delivery and stream close. D4FIX31-REPORT.md
names their tests/leaves and exact deciding assertions. All 327 sequential
anchors match once. Expected final-suite tests use Go's TestGoFiles and
XTestGoFiles with the same race/tag flags as the binary. The tagged presence
test remains for its separately tagged run; normal/faults do not declare it.
No ran/passed filtering or skip relaxation is added. The retained observation
now names expected, missing and unexpected tests. The six-method Python suite
adds actual Go file-selection coverage, with the assertion build constraints
changed declared test inventory and a separate broad-selection control.
Candidate vet and syntax checks pass; all new runtime proof remains pending.

Fix 30 moves the read-deadline setup in TestBoundScopeRequiresPort,
TestAuthClosePropagation and TestCaptureAuthClose before their close trigger.
The supplied normal/faults run failed at net.Pipe's post-close deadline setter,
before reaching the EOF assertions. Every deadline error remains fatal, and
every exact refusal/EOF assertion and mutation row is retained. The native
TestAuthenticationRefusalPrivacy still reads and validates the refusal frame
before checking closure. No new runtime result or control kill is claimed.

Fix 29 retains all 296 prior IDs, adds seven controls and reanchors only
config-events-query to the new exact SQL selectors. Identity is now included
in dependency discovery and final suites. All 320 sequential anchors match
once. D4FIX29-REPORT.md names each control and deciding assertion. The actual
identity component test counts peer verification/binding and checks changed
durable policy. Transport regressions require actual pipe EOF. The cgroup
test changes a real 0700 directory to exactly 0755 on the same inode; it does
not establish installed root ownership or cgroup traversal. The event fixture
commits 1,205 lane events before its requested configuration event, exceeding
both page and scan limits. Restoring broad SQL selection must fail even with
the final decoded-event filter retained. All six candidate-only vet variants
pass; red/candidate executions and native installed proof remain pending.

Fix 27 retains all 285 prior rows and adds eleven controls for internal/public
configuration-event selection, SQL selection, exact snapshot read-back and
generation/configuration gates, replay frame params/method, and closed initial
marker event validation. D4FIX27-REPORT.md names every test/leaf and deciding
assertion. All 312 anchors match once, and all four new short test names have a
deciding control. Whole-tree vet compiles the final candidate cleanly in all six
platform/tag combinations. Native root-helper EACCES and cgroup permission
proof remain installed Linux requirements; no mocked-peer unit pass is credited.

Fix 26 retains all 262 previous rows and adds 23 controls covering administrator
refusal replies, expired/oversized replies, initial publication dispatch,
enrollment parameter binding, fixed helper membership, initial read views,
failed-read context causes, successful-read preservation, allocation SQL errors,
and cache visibility/bounds/release. D4FIX26-REPORT.md names every test/leaf and
deciding assertion. All 301 sequential edit anchors match once. The 13 new test
names are under 40 characters; every test has a deciding red control. Whole-tree
vet compiles the candidate for all six required platform/tag combinations.
Linux red/candidate and installed results remain required.

Fix 25 adds six launch-receipt controls. Deadline and cancellation must fail
at receipt read lost its context failure when the erroneous integrity mask is
restored. Byte and missing-row mutations must fail the exact integrity-gate
assertion; the SQL-error mutant must fail its actual connection-error check.
The call-site mutant must reach launch plan accepted changed receipt bytes
through the real reserved launch and modified receipt. The timed service test
keeps its typed deadline assertion and checks unchanged raw input around each
failure. All 256 prior rows are unchanged, with 277 total edit anchors.
D4FIX25-REPORT.md gives the source trace and required Linux proof. New runtime
results remain unestablished in this static-only authoring round.

Fix 24 adds eight object-read controls. object-read-linear restores per-range
full loading and must fail the exact counted assertion multi-chunk read
repeated full verification. Tamper, metadata, request binding, metadata/chunk
copies, request-view release and live revocation have their own deciding
assertions in D4FIX24-REPORT.md. Test data comes from real retained objects and
actual SQLite corruption fixtures. No timer credits the complexity check.
All 248 prior rows are unchanged; there are now 270 edit anchors. The native
publication adapter was initially supplied as initial-read.patch; fix 26 applies
it directly to the merged source names. Do not reapply the historical patch.
No new runtime or installed result is claimed here.

Fix 23 adopts authentication-refusal-cause and
authentication-refusal-other-field from serve2 b41fa46. Each targets
TestAuthenticationRefusalPrivacy and requires authentication refusal disclosed
internal cause. The first restores the cause copy; the second discloses through
instead while retaining fixed message text. failed-plan-private-copy restores
RPC decoding of private cleanup data and targets TestFailedPlanAtomic/commit
at private cleanup copy rejected retained selectors. The original
failed-plan-atomic row still requires cleanup append failure left a partial
plan at rollback; its trigger and assertions are retained. All 245 previous
rows are unchanged. There are now 260 edit anchors. D4FIX23-REPORT.md records
the source cause, owner handoff and required Linux proof.

Fix 22 adds data-parent-select, targeting TestDataStageDispatch/child_first
with the unchanged diagnostic materialization dispatch repeated a retained
launch, and data-parent-completed, targeting TestDataParentClaim with
materialization child replaced a completed planning claim. The first restores
generic claim selection; the second also removes its final PlanLaunch guard.
The replay fixture orders actual store records explicitly and makes one replay
per case. Every prior row is unchanged. The catalog now has 257 edit anchors.
FAIL headers and nearby assertions survive the bounded runner diagnostic and
the outer failure report. The separate five-method Python diagnostics suite
must fail on the starting runner and pass on the candidate on Linux.
D4FIX22-REPORT.md records the cause, owner alias patch and remaining proof.

Fix 21 adds both serve2 invalid-first-frame admission controls and thirteen
failed-plan cleanup controls. All 228 prior IDs remain. The containment-transfer
and launch-replay-comparisons anchors follow the new source; their assertions
remain unchanged. The fifteen new rows and their exact diagnostics are:

| Control | Test | Leaf | Deciding diagnostic |
| --- | --- | --- | --- |
| admission-invalid-first-config | TestAdmissionRetry | wrong_config | valid second frame did not move UID slot to containment |
| admission-invalid-first-class | TestAdmissionRetry | endpoint_class | valid second frame did not move UID slot to containment |
| failed-plan-atomic | TestFailedPlanAtomic | rollback | cleanup append failure left a partial plan |
| failed-plan-outbox | TestFailedPlanAtomic | commit | failed plan lost an atomic cleanup request |
| failed-plan-policy | TestFailedPlanAtomic | policy | failed plan and cleanup did not commit together |
| failed-plan-claim | TestFailedPlanGuards | claim | failed-plan cleanup guard accepted claim |
| failed-plan-selector | TestFailedPlanGuards | selector | failed-plan cleanup guard accepted selector |
| failed-plan-injection | TestFailedPlanGuards | injection | failed-plan cleanup guard accepted injection |
| failed-plan-projection | TestFailedPlanGuards | projection | failed-plan cleanup guard accepted projection |
| failed-plan-unbound-projection | TestFailedPlanGuards | unbound_projection | failed-plan cleanup guard accepted unbound_projection |
| failed-plan-generic | TestFailedPlanGuards | generic | failed-plan cleanup guard accepted generic |
| failed-plan-drain | TestFailedPlanAtomic | commit | pending cleanup disappeared from drain inventory |
| failed-plan-target | TestFailedPlanAtomic | commit | pending cleanup lost its original dispatch target |
| failed-plan-replay-bytes | TestFailedPlanAtomic | commit | cleanup replay accepted changed request bytes |
| failed-plan-unknown | TestFailedPlanAtomic | unknown | failed plan lost an atomic cleanup request |

The atomicity mutant actually appends in a second transaction after committing
the failed plan. Its trigger failure must reach the partial-plan assertion.
Setup, compiler, panic, timeout, race and unrelated failures earn no red credit.
D4FIX21-REPORT.md records the source adoption and pending native cleanup work.

Fix 20 preserves continuation-claimed-epoch and every prior row. The supplied
run failed during ended-session setup, before its intended epoch assertion:
helper_open incorrectly labelled a historical observation and failed the new
plan fence. The fixture now uses the existing lifecycle observation authority
with preflight, CAS, cancellation and read-back. Its guard test checks the real
claimed effect and typed conflict, then proves unchanged pending state and
valid current-epoch claim. The strict diagnostic remains
continuation claim accepted old_epoch. The 27-row source sweep and prior-log
scope are in D4FIX20-REPORT.md; normal and faults runtime proof is still required.

Fix 19 retains all 215 merged IDs and adds thirteen controls with 238 total
edit anchors. Candidate suites and targeted candidate/mutant invocations share
a ten-minute Go test bound and a 660-second parent bound, followed by the
existing bounded PID-owned cleanup. Builds retain the 300-second default.
Timeouts remain stopped setup/runtime failures and cannot count as a kill.
All new runtime assertions remain pending Linux; D4FIX19-REPORT.md records the
policy, state, turn and native-projection limits.

| New control | Exact test path | Deciding diagnostic |
| --- | --- | --- |
| effect-success-state | TestStoredEffectStates/succeeded | terminal effect confused state and outcome |
| effect-failure-state | TestStoredEffectStates/failed | terminal effect confused state and outcome |
| effect-reclaim-state | TestEffectReclaimState | reclaim left shared claimed state |
| effect-lookup-state | TestEffectStateRefusal/unknown | store accepted a foreign effect state |
| effect-dispatch-state | TestEffectStateRefusal/unknown | dispatch accepted a foreign effect state |
| effect-pending-state | TestEffectStateRefusal/unknown | pending inventory accepted a foreign effect state |
| effect-verify-state | TestEffectStateRefusal/unknown | verification accepted a foreign effect state |
| current-policy-snapshot | TestCurrentApprovedHead | current policy used the historical snapshot |
| current-policy-malformed | TestPolicyHeadRefusal/malformed | policy source invented an approved head |
| writer-open-policy-stamp | TestWriterOpenPolicy | fresh open lost its current policy stamp |
| service-current-policy | TestCurrentPolicySource | service hid current policy source failure |
| reclaimed-allocation-repeat | TestReclaimedAllocation | reclaimed allocation repeated native work |
| turn-envelope-snapshot | TestTurnEnvelopeStore/run | turn envelope escaped its real snapshot |

Fix 18 adds thirteen reservation recovery, owner/deadline/handoff safety,
terminal refusal, backoff and build-variant controls. Seven existing reconcile
anchors follow the new branches without changing their deciding assertions.
All prior IDs remain. D4FIX18-REPORT.md describes the exact source behavior,
new regressions and three remaining P3 follow-ups. New runtime proof is pending.

Fix 17 retains guidance-unscored-item and its exact selected assertion. The
nonbinding item now carries a complete SourceRef derived from retained input;
payload, transaction and owner validation must pass before the store call.
The candidate must return forbidden and then complete a binding-only result.
Strict event decoding can no longer hide the removed unscored-item guard.
The supplied log confirms 110 normal pairs through guidance-score-provenance;
the 75 later current controls were swept by source, without runtime credit.
D4FIX17-REPORT.md and external sweep-review.json give the per-control scope.

Fix 16 adds first-frame-only health, client health socket/session lifetime and
per-effect reconciler refusal controls, including fatal raw/integrity/joined
error controls. The existing read-entry-auth and read-delivery-binding anchors
follow the dispatcher deindentation; their deciding assertions are unchanged.
D4FIX16-REPORT.md records each finding, expected failure and runtime limits.
None of the fifteen new rows has deciding runtime evidence in this authoring
round. Public first-frame health and later ordinary commands must both work.

Fix 15 retains natural-measured-process and its exact marker/subtest. Its
fixture now proves a complete exited/zero-survivor transaction passes before
testing a schema-valid running observation with one survivor. The running end
payload must decode successfully, and the unchanged guard must return
containment_unknown. A later schema error can no longer hide the absent guard.
The measurement guard did not move. D4FIX15-REPORT.md traces every other row
affected by d4fix14 and distinguishes the supplied 107 normal pairs from the
later rows/faults execution that the stopped input log does not show.

Fix 13 keeps the service-file-registration marker and leaf selector unchanged.
Its test now has actual method, form and validity t.Run nodes. A slash inside
one t.Run name does not create an observed ancestor and cannot meet the strict
path-set check. Reordering the form/validity loops avoids duplicate form names.
All input and transport assertions remain. The static review covered all 160
mappings, including the 99 later controls; D4FIX13-REPORT.md records its scope
and why a full runtime rerun is still necessary.

Fix 14 keeps facts used in capture-peer-generation while replacing its exact
comparison with an empty-generation check. A different nonempty generation
passes that mutant and must hit the unchanged peer_generation assertion. The
four launch-plan controls already name their exact subtests and are retained.
Eleven new controls cover atomic insertion ownership, loser waiting, private
invocation boundaries/retirement and missing or inconsistent reservation
support. Every edit anchor matched once in the static audit; runtime red and
unchanged candidate results remain pending. D4FIX14-REPORT.md records the local
cache refusal and concrete lifecycle/store wiring.

The source snapshot discovers main-module dependencies with Go list for all
seven component packages, including CLI, admin and identity, in both tag modes. It retains package
source, embeds and testdata plus separate discovery stdout/stderr and hashes.
A failed discovery stops; there is no partial fixed-root fallback. The fix-12
Mac discovery was refused cache access. The supplied 5eef5d2 red run then built
the reduced candidate on Linux and reached 60 normal pairs before the path
mismatch. This round claims no new runtime result; see D4FIX13-REPORT.md.

All 98 existing control IDs are retained. enrollment-attestation-bytes now
isolates the exact validated registration byte comparison, because the earlier
attestation mutation could be refused by the new retained-validation guard.
The revoked-inventory assertion follows the explicit production/tagged split.
The 57 added controls isolate enrollment capability/nonce/key, live kind,
presence propagation, policy history/sequence, prepared binding, plan reads,
natural completion, durable refresh, guidance ownership/deadline and capture
publication provenance. These are authored controls awaiting deciding runtime
reds and unchanged candidate greens, not observed successes.

Fix 12 retains all prior IDs and adds five publication-event controls below.
The policy-history-ambiguous ID now targets the typed generation guard, after
the fixture stopped attempting to edit immutable history. The hash case uses
one malformed first insertion in a separate corruption fixture. It disables
no trigger and does not claim a raw SQLite error as the expected conflict.

| Mutation | Exact test path | Required failing assertion |
| --- | --- | --- |
| materialize-input-schema | `TestMaterializationSchema/input` | `frozen materialization schema refused` |
| worker-result-schema | `TestMaterializationSchema/result` | `frozen materialization schema refused` |
| materialize-plan-schema | `TestMaterializationSchema/plan` | `frozen materialization schema refused` |
| materialize-grant-schema | `TestMaterializationSchema/grant` | `frozen materialization schema refused` |
| materialize-generic-non-worker | `TestDataGenericScope/non_worker` | `materialize worker entered generic policy read` |
| materialize-generic-result | `TestDataGenericScope/result_append` | `materialize result entered generic read scope` |
| data-stage-grant | `TestDataStagePins` | `data stage accepted drifted grant selector` |
| data-stage-current-grants | `TestDataStageGrantDrift` | `data stage accepted changed issued grants` |
| worker-principal-boot | `TestWorkerPrincipalPins` | `worker principal accepted another native boot` |
| data-registration-pin | `TestDataRegistrationPin` | `materialization accepted a foreign registration receipt` |
| data-await-process | `TestAwaitDataProcess` | `materialization await accepted another observed process` |
| worker-input-own-job | `TestWorkerInputOwnJob` | `worker input read another job selector` |
| worker-result-measurement | `TestWorkerResultMeasurement` | `worker result accepted a changed source measurement` |
| worker-result-own-job | `TestWorkerResultOwnJob` | `worker result submitted another job selector` |
| worker-result-replay | `TestWorkerResultReplay` | `worker result replay accepted changed exact bytes` |
| worker-ingress-frame | `TestWorkerIngressFrame` | `worker ingress accepted changed framed inputs` |
| state-mode | `TestRefuseUnsafeDirectory` | `wanted prerequisite_missing, got <nil>` |
| state-owner | `TestPrivateDirectoryOwner` | `different-owner metadata accepted` |
| duplicate-json | `TestRejectJSONAmbiguity` | `ambiguous JSON case 0 accepted` |
| unknown-field | `TestRequiredAndClosedFields` | `invalid typed case 0 accepted` |
| changed-key | `TestReplayAfterReopen` | `wanted idempotency_conflict, got <nil>` |
| revoked-replay | `TestReplayRechecksRevocation` | `wanted unauthenticated, got <nil>` |
| ancillary | `TestRejectReceivedFD` | `descriptor-bearing request accepted` |
| old-run-end | `TestSelectedEnd` | `old run ended follow` |
| watcher-deadline | `TestStalledWatcherIsolation` | `watcher exceeded its bounded write deadline` |
| mutation-gate | `TestMutationCannotBypassReceipt` | `wanted not_implemented, got integrity: mutation handler should not run` |
| scoped-record-read | `TestSocketScopedRecords` | `scoped socket record leaked or changed` |
| receipt-reservation | `TestLiveRetryKeepsOneIntent` | `retry duplicated durable intent:` |
| state-fd-inherit | `TestStateFDExec` | `state descriptor survived ordinary exec` |
| rpc-schema | `TestWrongSchema` | `wrong schema reached request dispatch` |
| outage-db-open | `TestOutageKeepsStateClosed` | `socket outage opened direct state` |
| watcher-frame-limit | `TestWatcherOverflow/frames` | `watcher accepted frame queue overflow` |
| watcher-byte-limit | `TestWatcherOverflow/bytes` | `watcher accepted byte queue overflow` |
| watcher-error-cursor | `TestWatcherErrorCursor` | `watcher overflow lost resumable cursor` |
| read-entry-auth | `TestAuthorityBeforeAndAfterRead/denied` | `unauthorized read handler ran` |
| read-delivery-binding | `TestAuthorityBeforeAndAfterRead/drift` | `wanted unauthenticated, got <nil>` |
| required-field | `TestRequiredAndClosedFields` | `invalid typed case 1 accepted` |
| frame-zero | `TestFrameBounds` | `invalid or truncated frame accepted` |
| received-fd-close | `TestRejectReceivedFD` | `received descriptor leaked:` |
| call-preparation | `TestCallFramedResult` | `request preparation failed` |
| initial-snapshot | `TestStreamInitialPage` | `initial snapshot changed` |
| initial-copy | `TestStreamInitialPage` | `initial snapshot shares caller storage` |
| typed-write-gate | `TestDraftFieldsStayClosed/writes` | `unsupported draft transaction accepted writes` |
| atomic-guard-gate | `TestDraftFieldsStayClosed/guards` | `unsupported draft transaction accepted guards` |
| exact-reply-gate | `TestDraftFieldsStayClosed/reply` | `unsupported draft transaction accepted reply` |
| raw-frame-match | `TestRawRequestMatchesScope` | `raw request mismatch accepted` |
| raw-frame-retention | `TestRawRequestMatchesScope` | `raw request bytes changed` |
| exact-record-filter | `TestExactRecordLookup` | `exact lookup returned unrelated records` |
| effect-context-count | `TestDurableOutboxIntent` | `outbox was not pending` |
| writer-credentials | `TestPinnedWriterCredentials` | `inherited socket writer was accepted` |
| private-event | `TestPrivateEventVisibility` | `administrative event leaked to lane` |
| receipt-exact-bytes | `TestReservedExactReply` | `restart changed exact receipt` |
| pending-key-digest | `TestPendingKeyRejectsChangedIntent` | `pending key accepted changed intent` |
| endpoint-class | `TestEndpointClassPrecedesActorLabel` | `wanted forbidden, got integrity: wrong endpoint invoked handler` |
| response-head | `TestSocketScopedRecords` | `socket response lost committed head` |
| state-ancestor | `TestRejectWritableAncestor` | `writable ancestor accepted state writer` |
| state-hardlink | `TestPostOpenStateHardlink` | `post-open state hardlink was credited` |
| health-probe | `TestHealthTracksHostObservations` | `failed isolation check left health ready` |
| live-private-event | `TestLivePrivateEventFiltering` | `live private event bypassed visibility policy` |
| identity-receipt | `TestIdentityCommitStamped` | `forged identity commit was accepted` |
| foreign-life-event | `TestBoundLaneCannotEmitForeignLife` | `bound lane emitted foreign-life event` |
| human-read-session | `TestHumanReadRequiresCurrentSession` | `human read without authority exposed state` |
| measured-operation-status | `TestVerifyMeasuredOperationState` | `unmeasured pending operation state was credited` |
| canonical-decisions | `TestCanonicalDecisionsAndFilteredPages` | `canonical decision was hidden from lane` |
| principal-watcher-limit | `TestPrincipalWatcherIsolation` | `principal watcher limit admitted excess producer` |
| producer-join-bound | `TestUncooperativeProducerIsBounded` | `uncooperative producer pinned watcher` |
| object-participant-audience | `TestObjectParticipantAudience` | `owner audience exposed object to an unrelated participant` |
| human-session-stream | `TestHumanStreamKeepsSessionSocket` | `human stream abandoned its session socket` |
| internal-actor-gate | `TestDraftFieldsStayClosed (internal-authority)` | `unsupported draft transaction accepted internal-authority` |
| freeze-public-gate | `TestFreezeSurvivesRestart` | `frozen store committed new public work` |
| freeze-claimed-inventory | `TestFreezeSurvivesRestart` | `dispatch inventory lost a claimed effect` |
| freeze-host-admission | `TestFrozenHostKeepsReads` | `wanted unavailable, got integrity: frozen mutation reached reservation` |
| freeze-reserved-completion | `TestFrozenReservationCanFinish` | `freeze stranded an admitted reservation` |
| freeze-watchdog-targets | `TestHostFreezeDrainThaw` | `host did not cancel observed watchdog targets` |
| freeze-watchdog-error | `TestFreezeCancelFailureStaysClosed` | `wanted unavailable, got <nil>` |
| freeze-health-observation | `TestHealthTracksHostObservations` | `durable dispatch freeze left health ready` |
| service-file-registration | `TestServiceFileInputs (health/--request/valid)` | `valid service file did not reach transport: health` |
| containment-admission-transfer | `TestContainmentAdmissionIsolation` | `same-UID sibling lane was starved` |
| launch-reservation-operation | `TestLaunchReserveGuards (foreign_operation)` | `launch reservation accepted foreign_operation` |
| launch-ticket-provenance | `TestLaunchReserveGuards/foreign_ticket` | `launch reservation accepted foreign_ticket` |
| launch-reserved-name | `TestLaunchReserveGuards/name_claim` | `launch reservation accepted name_claim` |
| launch-plan-reservation | `TestLaunchPlanAuthority (foreign_reservation)` | `launch plan accepted foreign_reservation` |
| launch-plan-policy | `TestLaunchPlanAuthority/stale_policy` | `launch plan accepted stale_policy` |
| launch-starter-grants | `TestLaunchPlanAuthority/stale_grants` | `launch plan accepted stale_grants` |
| launch-claim-expiry | `TestLaunchPlanAuthority/expired_claim` | `launch plan accepted expired_claim` |
| launch-replay-comparisons | `TestLaunchPlanAuthority` | `plan replay accepted changed comparison inputs` |
| launch-recovery-retention | `TestLaunchMissingRecovery` | `restart accepted missing retained recovery` |
| capture-contiguous-offset | `TestCaptureRangeGuards/offset_hole` | `capture range accepted offset_hole` |
| capture-revision-cas | `TestCaptureRangeGuards/stale_revision` | `capture range accepted stale_revision` |
| capture-replay-hash | `TestCaptureRangeGuards/changed_bytes` | `capture range accepted changed_bytes` |
| capture-worker-endpoint-lease | `TestCaptureLeaseFence` | `foreign worker endpoint replayed another capture lease` |
| capture-one-use-pipes | `TestCapturePipeOwnership` | `capture registration reused another binding's one-use pipe` |
| capture-ingress-principal | `TestCaptureAuthenticatedIngress` | `capture ingress accepted a body-supplied principal` |
| launch-required-planner | `TestLaunchRuntimeReadiness` | `pending launch bound without LaunchPlanner` |
| launch-required-running-jobs | `TestLaunchRuntimeReadiness` | `bound dependencies advertised launch readiness without active recovery/capture jobs` |
| capture-actual-recovery-job | `TestLaunchRecoveryJobs` | `recovery skipped actual jobs or opened a second gate` |
| enrollment-absent-baseline | `TestAdminEnrollmentGuards (second_baseline)` | `administrator enrollment accepted second_baseline` |
| enrollment-attestation-bytes | `TestEnrollmentExactBytes (registration_bytes)` | `enrollment validation accepted changed exact registration bytes` |
| enrollment-revoked-inventory | `TestHumanEnrollmentInventory` | `inventory dropped revoked credentials or recorded registration bytes` |
| enrollment-inventory-config | `TestHumanEnrollmentInventory` | `inventory read another configuration` |
| continuation-claimed-epoch | `TestContinuationLaunchGuards/old_epoch` | `continuation claim accepted old_epoch` |
| capture-no-generic-ingress | `TestCaptureIngressCannotBeGeneric` | `generic transaction forged primary capture provenance` |
| launch-private-metadata | `TestLaunchMetadataPrivacy` | `private launch or capture metadata leaked to lane` |
| launch-issued-ceiling | `TestIssuedLaunchGrants/foreign_source` | `planner issued launch grants outside foreign_source` |
| launch-issued-request | `TestIssuedLaunchGrants/request_access` | `planner issued launch grants outside request_access` |
| lane-identity-reservation | `TestLaneIdentityRequiresPlan/service` | `unreserved lane identity accepted service` |
| lane-identity-historical | `TestLaneIdentityRequiresPlan (legacy_import)` | `unreserved lane identity accepted legacy_import` |
| launch-failed-name-release | `TestFailedLaunchNameReuse` | `failed unbound launch kept its lane name reserved` |
| launch-claimant | `TestLaunchClaimantFence` | `foreign claimant acquired a launch effect` |
| launch-completion-claimant | `TestLaunchCompletionClaimant` | `foreign claimant replayed measured launch outcome` |
| launch-foreign-cause | `TestLaunchEffectCause` | `foreign request cause acquired launch effect` |
| capture-peer-generation | `TestCaptureProducerGeneration (peer_generation)` | `capture replay accepted changed peer_generation` |
| capture-launch-generation | `TestCaptureProducerGeneration (launch_generation)` | `capture replay accepted changed launch_generation` |
| internal-operation-digest | `TestOperationDigestProvenance/internal` | `internal completion invented a public request digest` |
| enrollment-native-commit | `TestEnrollmentValidationFences (direct_internal_commit)` | `administrator install accepted direct_internal_commit` |
| enrollment-challenge-config | `TestEnrollmentCeremonyFences (foreign_config)` | `enrollment ceremony accepted foreign_config` |
| enrollment-validated-key | `TestEnrollmentExactBytes/validated_key` | `enrollment validation accepted a different validated key` |
| identity-live-kind | `TestIdentityKindFence/missing_kind` | `live identity accepted missing kind` |
| proof-enrollment-config | `TestProofPresenceFences (foreign_enrollment)` | `proof accepted changed foreign_enrollment` |
| proof-current-credential | `TestProofPresenceFences (revoked_credential)` | `proof accepted changed revoked_credential` |
| policy-history-future | `TestPolicyHistoryIntegrity/future` | `policy history accepted future` |
| policy-refresh-sequence | `TestPolicyRefreshJournal/journal_head` | `policy refresh accepted a caller supplied journal sequence` |
| natural-state-fields | `TestNaturalCompletionCommit (changed_budget)` | `natural completion accepted changed_budget` |
| natural-measured-process | `TestNaturalObservationFence (still_running)` | `natural completion accepted a still running observation` |
| session-refresh-credential | `TestSessionRefreshFences (revoked_credential)` | `durable session refresh accepted revoked_credential` |
| guidance-score-provenance | `TestGuidanceMeasuredScoreGate (missing_judgment)` | `guidance accepted a score without measured judgment provenance` |
| guidance-unscored-item | `TestGuidanceMeasuredScoreGate (nonbinding_item)` | `unscored guidance accepted a nonbinding historical item` |
| enrollment-baseline-generation | `TestEnrollmentCeremonyFences (later_baseline)` | `enrollment ceremony accepted later_baseline` |
| enrollment-expired-nonce | `TestEnrollmentCeremonyFences (expired_nonce)` | `enrollment ceremony accepted expired_nonce` |
| enrollment-consumed-nonce | `TestEnrollmentCeremonyFences (consumed_nonce)` | `enrollment ceremony accepted consumed_nonce` |
| proof-credential-presence | `TestProofPresenceFences/credential_mark` | `proof accepted changed credential_mark` |
| proof-reference-presence | `TestProofPresenceFences/reference_mark` | `proof accepted changed reference_mark` |
| presence-ticket | `TestPresenceWriteFences/ticket` | `presence propagation accepted dropped ticket` |
| presence-session | `TestPresenceWriteFences/session` | `presence propagation accepted dropped session` |
| presence-approval | `TestPresenceWriteFences/approval` | `presence propagation accepted dropped approval` |
| presence-application | `TestPresenceWriteFences/application` | `presence propagation accepted dropped application` |
| presence-pending-operation | `TestPendingPresenceSurvives (pending_operation)` | `pending operation completion dropped retained simulated presence` |
| presence-operation-evolution | `TestPresenceEvolution/retained_mark` | `operation evolution erased retained simulated presence` |
| policy-history-hash | `TestPolicyHistoryIntegrity/hash` | `policy history accepted hash` |
| policy-history-ambiguous | `TestPolicyHistoryIntegrity/ambiguous` | `policy history accepted ambiguous` |
| prepared-foreign-commit | `TestPreparedIdentityBytes (foreign_commit)` | `prepared identity accepted foreign_commit` |
| prepared-missing-event | `TestPreparedIdentityBytes/missing_event` | `prepared identity accepted missing_event` |
| plan-read-foreign-record | `TestPrivatePlanRead/foreign_result` | `private plan source accepted a different retained reservation` |
| plan-read-current-claim | `TestPrivatePlanRead/expired_claim` | `private plan read accepted an expired durable claim` |
| natural-missing-cas | `TestNaturalCompletionCommit/missing_cas` | `natural completion accepted missing_cas` |
| natural-missing-epoch | `TestNaturalCompletionCommit (missing_epoch)` | `natural completion accepted missing_epoch` |
| natural-missing-state | `TestNaturalCompletionCommit (missing_state)` | `natural completion accepted missing_state` |
| natural-foreign-observation | `TestNaturalCompletionCommit (foreign_observation)` | `natural completion accepted foreign_observation` |
| natural-end-budget | `TestNaturalCompletionCommit (changed_end_budget)` | `natural completion accepted changed_end_budget` |
| natural-committed-head | `TestNaturalCompletionCommit/valid` | `natural completion lost its actual committed journal head` |
| reservation-ticket-grant-set | `TestReservationAuthority (foreign_grant_set)` | `reservation accepted authority foreign_grant_set` |
| reservation-authority-id | `TestReservationAuthority/missing_ticket` | `reservation lost its actual consumed authority or child pins` |
| session-refresh-expired-idle | `TestSessionRefreshFences/expired_idle` | `durable session refresh accepted expired_idle` |
| session-refresh-expired-absolute | `TestSessionRefreshFences (expired_absolute)` | `durable session refresh accepted expired_absolute` |
| session-refresh-revoked | `TestSessionRefreshFences/revoked` | `durable session refresh accepted revoked` |
| transport-refresh-principal | `TestReadAuthorityRefresh/principal` | `transport refresh accepted principal` |
| transport-refresh-absolute-expiry | `TestReadAuthorityRefresh (absolute_expiry)` | `transport refresh accepted absolute_expiry` |
| transport-refresh-stale-revision | `TestReadAuthorityRefresh/stale_revision` | `transport refresh accepted stale_revision` |
| transport-session-bind-once | `TestReadAuthorityRefresh/rebind` | `transport rebound a one use read authority` |
| guidance-owner-attempt | `TestGuidanceOwnerFences/attempt` | `guidance completion accepted foreign attempt` |
| guidance-owner-operation | `TestGuidanceOwnerFences/operation` | `guidance completion accepted foreign operation` |
| guidance-owner-requester | `TestGuidanceOwnerFences/requester` | `guidance completion accepted foreign requester` |
| guidance-owner-claim | `TestGuidanceOwnerFences/claim` | `guidance completion accepted foreign claim` |
| guidance-owner-early-recovery | `TestGuidanceOwnerFences/early_recovery` | `guidance completion accepted foreign early_recovery` |
| guidance-await-deadline | `TestGuidanceAwaitDeadline (claim_deadline)` | `guidance await reset its retained claim deadline` |
| capture-policy-foreign-manifest | `TestCaptureRefusalD6Provenance (foreign_manifest)` | `capture refusal accepted unproved D6 foreign_manifest` |
| capture-policy-foreign-generation | `TestCaptureRefusalD6Provenance (foreign_generation)` | `capture refusal accepted unproved D6 foreign_generation` |
| guidance-one-winner | `TestGuidanceOneWinner` | `guidance reservation did not grant exactly one evaluation owner` |
| guidance-observer-no-acquire | `TestGuidanceOneWinner` | `guidance reservation did not grant exactly one evaluation owner` |
| session-refresh-binding-config | `TestSessionRefreshFences (foreign_binding)` | `durable session refresh accepted foreign_binding` |
| enrollment-channel-recheck | `TestEnrollmentValidationFences (commit_channel_recheck)` | `administrator install accepted commit_channel_recheck` |
| capture-publication-event | `TestCaptureRefusalD6Provenance` (`missing_event`) | `capture refusal accepted unproved D6 missing_event` |
| capture-event-receipt | `TestCaptureRefusalD6Provenance` (`event_receipt`) | `capture refusal accepted unproved D6 event_receipt` |
| capture-event-change | `TestCaptureRefusalD6Provenance` (`event_change`) | `capture refusal accepted unproved D6 event_change` |
| capture-event-origin | `TestCaptureRefusalD6Provenance` (`event_origin`) | `capture refusal accepted unproved D6 event_origin` |
| capture-event-approval | `TestCaptureRefusalD6Provenance` (`event_approval`) | `capture refusal accepted unproved D6 event_approval` |
| reservation-one-owner | `TestReservationOneWinner` (`identical_invocations`) | `identical reservations did not have exactly one winner` |
| reservation-insertion-owner | `TestReservationOneWinner` (`identical_invocations`) | `identical reservations did not have exactly one winner` |
| dispatch-await-winner | `TestMutationRetryAwaitsWinner` (`same_request`) | `same request ran mutation preflight twice` |
| mutation-owner-context | `TestMutationOwnerFences` (`fresh_context`) | `mutation ownership accepted fresh_context` |
| mutation-owner-operation | `TestMutationOwnerFences` (`foreign_operation`) | `mutation ownership accepted foreign_operation` |
| mutation-owner-actor | `TestMutationOwnerFences` (`foreign_actor`) | `mutation ownership accepted foreign_actor` |
| mutation-owner-key | `TestMutationOwnerFences` (`foreign_key`) | `mutation ownership accepted foreign_key` |
| mutation-owner-retirement | `TestMutationOwnerFences` (`retired`) | `mutation ownership accepted retired` |
| dispatch-atomic-port | `TestMutationNeedsAtomicStore` (`missing_port`) | `dispatcher without atomic winner ran preflight` |
| dispatch-reservation-config | `TestMutationReservationPins` (`foreign_config`) | `mutation reservation accepted foreign_config` |
| dispatch-reservation-frame | `TestMutationReservationPins` (`foreign_frame`) | `mutation reservation accepted foreign_frame` |
| health-later-frame | `TestOpenedConnectionRejectsHealth` | `opened connection dispatched health` |
| health-public-context | `TestHealthNeedsPublicContext` | `health without public context was accepted` |
| client-health-release | `TestCallAfterHealth` (`success`) | `health call retained its one-request socket` |
| client-health-refusal | `TestCallAfterHealth` (`refusal`) | `health call retained its one-request socket` |
| client-health-session | `TestHealthKeepsSession` | `health interrupted the existing read session` |
| reconcile-claim-forbidden | `TestReconcileSkipsEffectFences` (`claim_forbidden`) | `per-effect refusal stopped later work` |
| reconcile-complete-forbidden | `TestReconcileSkipsEffectFences` (`complete_forbidden`) | `per-effect refusal stopped later work` |
| reconcile-run-forbidden | `TestReconcileSkipsEffectFences` (`run_forbidden`) | `per-effect fence latched host fault` |
| reconcile-claim-conflict | `TestReconcileSkipsEffectFences` (`claim_conflict`) | `per-effect refusal stopped later work` |
| reconcile-complete-conflict | `TestReconcileSkipsEffectFences` (`complete_conflict`) | `per-effect refusal stopped later work` |
| reconcile-run-conflict | `TestReconcileSkipsEffectFences` (`run_conflict`) | `per-effect fence latched host fault` |
| reconcile-integrity-fatal | `TestReconcileKeepsStoreFailures` (`claim_integrity`) | `reconciler lost a store or integrity failure` |
| reconcile-raw-fatal | `TestReconcileKeepsStoreFailures` (`claim_store`) | `reconciler lost a store or integrity failure` |
| reconcile-joined-fatal | `TestReconcileKeepsStoreFailures` (`claim_mixed`) | `reconciler lost a store or integrity failure` |
| reconcile-complete-fatal | `TestReconcileKeepsStoreFailures` (`complete_integrity`) | `reconciler lost a store or integrity failure` |
| orphan-reservation-finalize | `TestReservationRecovery` (`reopen`) | `orphan reservation remained pending` |
| reservation-live-owner | `TestReservationRecovery` (`live_owner`) | `recovery finalized a live or unexpired reservation` |
| reservation-before-deadline | `TestReservationRecovery` (`before_deadline`) | `recovery finalized a live or unexpired reservation` |
| reservation-untracked-owner | `TestReservationRecovery` (`untracked_owner`) | `recovery finalized a live or unexpired reservation` |
| reservation-effect-handoff | `TestRecoveryKeepsEffectHandoff` | `reservation recovery discarded a durable effect handoff` |
| reservation-invocation-retirement | `TestMutationRetirementRecovery` | `returned mutation kept its reservation live` |
| reservation-recovery-freeze | `TestFrozenReservationRecovery` | `deployment freeze prevented reservation recovery` |
| reservation-recovery-fatal | `TestReservationRecoveryFault` | `reservation recovery discarded its store failure` |
| execution-refusal-terminal | `TestExecutionRefusalTerminal` (`plain`) | `execution refusal remained pending` |
| execution-refusal-joined | `TestExecutionRefusalTerminal` (`joined`) | `execution refusal remained pending` |
| effect-retry-backoff | `TestEffectRetryBackoff` | `refused effect retried before its backoff` |
| effect-retry-reset | `TestEffectRetryBackoff` | `completed effect retained its backoff` |
| health-build-variant | `TestHealthBuildVariant` | `health omitted the compiled build variant` |

The fixtures cover component boundaries. They do not establish OS confinement,
actual helper registry/boot identity, physical capture pipes, projected storage,
cryptographic registration, hardware presence, authenticated model access or
installed restart behavior. Native administrator writer/expiry races, complete
worker mapping, materialization and measured scored-guidance controls remain
part of the unfinished Group B/native integration work in D4FIX11-REPORT.md.
