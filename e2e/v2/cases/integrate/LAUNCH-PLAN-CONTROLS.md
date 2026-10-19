# Draft.4 fixes 9 and 10 regression controls

Fix 14b adds seventeen cleanup controls, bringing cleanup-controls.json to 87
and the active inventory to 573 Go controls. Three runner self-controls bring
the non-Go inventory to seven, for 580 total runtime rows. Both stale fix-12
withdrawal controls are retained with unique helper-validator anchors.
All Go anchors are preflighted before execution. Missing, ambiguous, unreadable
or unterminated anchors are reported individually and retained as broken_anchor
failures; constructible controls still execute and any broken row forces a
nonzero final result. No construction error counts as a reached runtime red.
The new cleanup rows enforce service/admin error ownership, known versus
unknown ownership generations, fresh observation IDs, distinct manifests and
timestamps bounded by final verification. The two older fresh-object controls
also remove the new observation-ID gate so their intended readback assertion
remains decisive. Candidate vet is static evidence only. No mutant/control
overlay vet runs on the authoring Mac in this round.

Fix 14 adds 70 G11 cleanup rows from cleanup-controls.json. The active inventory
is 556 Go controls plus four non-Go controls, for 560 runtime rows. The real
loader and loader regression include all five manifests. These new controls
cover exact live claims, run/generation/epoch, bounded complete inventories,
object policies and retained bytes, unforced workspace/branch removal, dirty
retention, independent journals and current read-backs, revocation/expiry,
private verification copy isolation and original completion correlation.
Static overlay vet checks compilation only. All reached runtime reds and
candidate passes remain required on the authorized Linux machine, along with
native service/admin evidence before G11 acceptance.

Fix 13 and its review corrections add 184 rows from contract-controls.json to
all 302 prior Go rows, giving 486 Go controls and 490 total runtime rows.
Thirty-eight cover canonical org kinds and exact selectors, twenty cover protected
attestation policy and copy isolation, ninety-seven cover private scheduler
authority, loop plan fences and causal audit, and twenty-nine cover atomic
failed-plan cleanup requests. Fix 13d removes the obsolete empty-Derived
refusal control and adds twelve controls. Fix 13c added 93 controls and
retargets prior controls where new checks defend the same invariant.
The manifest's nominated
tests and diagnostic strings are authoritative; no runtime result is inferred
from static compilation. The loader regression includes this fourth manifest.

The f13d and f13e controls enforce one generation-selected Derived shape:
generation 1 requires an explicit empty array, later generations require
nonempty file outputs, and invalid generations refuse. Initial and full
consumers use the same gate; it is not shadowed by a second initial shape
check. Template lookup controls inspect
the actual requested org and generation, and the loop control refuses zero
CausingRun. All deciding assertions remain pending the Linux run.

Fix 13e adds seventeen deciding controls and retargets earlier rows to the
current generation and selector predicates. They cover initial null/nonempty
outputs, later empty/non-file outputs, generation bounds, all three template
entry points, initial-validator delegation, foreign returned/requested orgs,
zero snapshot reads during bootstrap, current absence, producer errors and
the atomic absent-org comparison. Native store lookup and CAS enforcement
remain the store owner's pending implementation.

The f13c controls assert exact retained loop grants, budget, session and home;
logical turn and planning effect correlation; rejection of scheduler audits
without an opened loop reservation; empty mail acknowledgements and exact
prompt, causing run and trigger spelling; complete scheduler/configurator/home
metadata and distinct identities; self-signed, distinct-public-key CA roots;
nonempty org arrays; and failure-only cleanup with exact retained resources.
TestCleanupAtomic also refuses ordinary transaction and plan-write paths for
a failed planner revision. Mutants preserve every other deciding gate, and
paired edits remove both checks when they enforce the same invariant.

red-controls.py now loads all 46 Go controls from launch-plan-controls.json:
the original 14 fix-9 entries plus 32 fix-10 entries. They join the existing
70 Go controls. Fix 10 adds launch-controls-loader beside the existing verifier
and two scanner controls, reaching 120 rows at that revision. Fix 11 additionally
loads 50 consumer controls from consumer-controls.json, reaching 166 Go rows
and 170 total runtime rows. Fix 12 loads forty-four additional controls from
credential-controls.json. The fix-12 continuation adds eight policy/turn controls
to that manifest, reaching 218 Go rows and 222 total runtime rows at that point.
The review correction adds nineteen deciding controls, for 71 credential
controls, 237 Go rows and 241 total runtime rows at that revision. Fix 12d adds
65 delta controls, reaching 136 credential controls, 302 Go rows and 306 total
runtime rows. They cover
the native credential projection contract, including selected modes, protected
source descriptors, separate held destinations, gate fences and measured
withdrawal. All runtime assertions remain pending Linux. This wiring
does not claim runtime success. Each targets a named assertion and requires its real
run/fail event, intended diagnostic, then the candidate's run/pass. Static vet
can reject a compile-only mutant but cannot demonstrate a runtime red.

The nineteen review controls are f12-env-tunables, f12-env-malloc,
f12-env-secure, f12-exec-stage, f12-exec-uid, f12-exec-caps,
f12-exec-isolation, f12-exec-earlier, f12-exec-missing, f12-env-anonymous,
f12-startup-binder, f12-prepare-binder, f12-eager-wiring, f12-wrapper-wiring,
f12-state-credential, f12-state-data, f12-state-deferred,
f12-state-vocabulary and f12-state-mail. Each manifest row names its exact
test and diagnostic. Environment controls remove real name or final-exec
predicates. The anonymous control restores the rejected one-link requirement.
Assembly controls restore the shipped stub call at startup, suppress its
Prepare error, restore the eager production call or bypass the wrapper.
State controls restore incompatible running labels or reopen that vocabulary.
The assembly host models the production runtime-binding/start ports; it does
not open an installed listener or authenticate enrollment. The native
NATIVE-TASK-ENVP-1 control and the installed serve regression remain Linux/
native follow-ups and are not inferred from these component tests.

The 65 f12d controls cover one completed Codex allocation, nineteen fail-closed
shape predicates, seven configuration/recovery gates, nine retry/one-use
predicates, fifteen environment authority/mode/fixed-name checks, four
file/worker-state checks and ten code-execution-name refusals. All their
nominated test paths are under 40 characters. Each manifest entry retains the
exact mutation, test and assertion diagnostic. The two previous binder controls
now target the refactored shared gate; no prior control was removed.

| Active fix-9 control | Reached test | Defect it must detect |
| --- | --- | --- |
| launch-reserved-base | TestLaunchReservationShape/new_base | A new life carries a nonzero caller base. |
| launch-reserved-grant | TestLaunchInputReservation/grant_id | Input resolution admits another grant-set ID instead of the store reservation's ID. This direct input test isolates that check from later materialization defence in depth. |
| launch-runtime-manifest | TestLaunchEnrollmentShape/manifest | A driver enrollment selects a runtime manifest different from the installed one. |
| launch-private-history | TestLaunchPlanShape/history | The runner session selects shared/foreign history instead of the prepared private home. |
| launch-spec-runtime | TestAgentSpecPlanBinding / runtime | A spec replaces the plan's selected runtime manifest. |
| launch-original-request | TestLaunchRecoveryBinding/request | Recovery replaces the original retained request reference. |
| launch-retained-handoff | TestLaunchPlanPhases/handoff_required | A merely planned object is called bound without the complete retained spec/handoff. |
| capture-integrity-fallback | TestCaptureBindingShape / fallback | A capture integrity failure becomes an allowed unavailable/refused launch disposition. |
| capture-one-use-pipe | TestCaptureBindingShape/shared_pipe | Different streams claim the same one-use pipe. |
| capture-original-operation | TestCaptureAppendCorrelation/operation | A producer appends capture under another operation. |
| capture-eof-union | TestCaptureAppendCorrelation / eof_data | EOF and a nonempty chunk are accepted together. |
| launch-plan-cas | TestLaunchPlanWriteAuthority | A plan update omits its reservation revision CAS. |
| launch-plan-cancellation | TestLaunchPlanWriteAuthority | A plan update omits its current cancellation fence. |
| launch-plan-d6-outcome | TestDeferredCompletion/launch_plan | A launch-plan result competes with a deferred D6 publication outcome. |

| Active fix-10 control | Reached test | Defect it must detect |
| --- | --- | --- |
| reserve-root-ticket | TestReserveAuthority/root_ticket | The reservation path accepts a human root without a TicketUse. The nil-safe metadata branch keeps this a reached assertion, not a panic. |
| reserve-lane-proof | TestReserveAuthority/lane_proof | A lane carries a frame proof and a ProofUse through reservation. |
| reserve-ticket-principal | TestReserveAuthority/principal | The root ticket names another principal. |
| reserve-retained-ticket | TestReserveRecord/root_ticket | Recovery retains starter authority for a human root. |
| reserve-retained-lane | TestReserveRecord/lane_proof | A lane reservation retains human proof authority. |
| reserve-child-level | TestReserveRecord/child_level | The child reaches its starter's level, contrary to D9. |
| prepare-without-plan-bind | TestLaunchBoundTransaction / no_plan_bind | An agent identity is written without any LaunchPlans entry. |
| prepare-without-plan-lane | TestLaunchBoundTransaction / no_plan_lane | A Lane projection is written without any LaunchPlans entry. |
| launch-level-pin | TestReservedRolePins/level | Bound identity changes the reserved child level while retaining a correct identity hash. |
| launch-role-pin | TestReservedRolePins/role | Bound identity changes the reserved child role while retaining a correct identity hash. |
| launch-driver-pin | TestReservedRolePins/driver | A plan changes only the reserved driver. |
| launch-bound-life-cas | TestLaunchBoundTransaction/life_cas | Prepared/bound readiness omits the actual life CAS. |
| launch-plan-kind-union | TestLaunchPlanEffectUnion/other_kind | PlanLaunch is accepted under object_retain instead of launch_plan. |
| capture-policy-required | TestCaptureRefusalPolicy/disabled | Metadata enables refused capture despite protected policy being disabled. |
| capture-producer-pin | TestCaptureAppendCorrelation/producer | Another producer appends primary bytes. |
| capture-run-pin | TestCaptureAppendCorrelation/run | The producer appends for another run. |
| capture-refused-producer | TestCaptureProducerGate | A refused status passes the producer gate. The direct predicate fixture changes status alone so unrelated empty-producer/stream checks do not mask it. |
| check-natural-state | TestCheckNaturalStateWrite | lane.check loses permission to commit its measured lane.state transition. |
| review-closed-coverage | TestReviewCoverageSchema/coverage | Invented coverage vocabulary is accepted. |
| review-run-end-pin | TestReviewCoverageSchema/end | Only the life/run is compared while the frozen end sequence changes. |
| review-check-snapshot | TestReviewCoverageSchema/snapshot | A successful check refers to a different workspace snapshot. |
| review-tool-coverage | TestReviewAcceptance/tool_gap | Incomplete tool-record coverage becomes acceptance. |
| review-required-check | TestReviewAcceptance/required | All required check facts are omitted. |
| review-stream-eof | TestReviewAcceptance/eof | A primary stream has no EOF. |
| channel-fixed-runtime | TestChannelWorkerHandoff/runtime | The worker executable differs from enrolled runtime. |
| channel-fixed-input | TestChannelWorkerHandoff/input | The worker consumes a different sealed input. |
| channel-fixed-argv | TestChannelWorkerHandoff/argv | The worker accepts a caller command. All handoff mutations recompute valid spec/record hashes first. |
| channel-readback-payload | TestChannelMeasuredResult/payload | Provider read-back names another payload digest. |
| channel-result-operation | TestChannelMeasuredResult/operation | A delivery result belongs to another original operation. |
| continue-swap-operation | TestContinueOperation/swap | The swap uses an intent ID instead of the shared operation. |
| continue-result-operation | TestContinueOperation/result | Lifecycle returns another operation. |
| continue-pending-result | TestContinueOperation/pending_success | An uncompleted continuation claims succeeded. |

The separate launch-controls-loader mutation removes the actual GO_CONTROLS
extension. PlanControlTests.test_loaded must fail with its missing-controls
diagnostic; the unmodified runner must pass the same test. Compilation, setup
errors, panics, skips and unrelated test failures never count as a reached red.

Each edit changes a real input-dependent predicate, preserving locals/imports
and the other production checks. Positive tests cover both D8 driver shapes,
registered capture, all three permitted explicit refusal codes, normal chunks
and EOF, valid plan phases, exact spec/identity recovery and selector decoding.
The new reservation/input/selector/write tests check actual values and a closed
field catalog; no not_implemented result is counted as a successful launch.

The following additional controls require the consumer implementations and a
real installed service/helper. They must be added beside those implementations
before production acceptance, not replaced by these shape tests:

- Concurrent duplicate start/adopt reservations produce exactly one child life,
  pending operation, consumed root ticket/proof and claimed plan effect. A
  changed digest/foreign operation cannot select another child's reservation.
- Parent grant ceiling and D9: an actual level-6 parent can start its authorized
  lower-level child with a genuine subset. Raising the child's level, widening
  one resource / data / secret / profile / network / channel grant, or using an expired or
  revoked parent grant refuses before allocation. Mutating the actual store/grant
  subset predicate must reach that refusal assertion. Shape-level ID/level pins
  do not prove a subset against current installed authority.
- A parent cannot supply child IDs, host workspace/home paths, executable IDs or
  arbitrary manifests through a public request; a valid logical enrolled project
  and D8 policy selector still launches. The actual selected executable is
  matched to protected enrollment bytes, not a caller label or blob class.
- Materialization uses the helper's real pre-spec storage registry, confined
  source/destination identities and granted Git base/history. A foreign/shared
  home or alternate Git object directory fails before an agent executes.
- Crash at reserved / sourced / allocation / spec-retained / bound / opened phases resumes
  the original durable claim and same IDs/binding. Missing recovery, changed
  home/request/runtime or unknown gate never creates another process. A normal
  service restart reconciles the original process and pending reply.
- Helper-created stdout/stderr are readable only by the installed supervisor
  job; a lane or foreign worker cannot register a pipe or append primary bytes.
  Passed descriptors and a fake producer/boot generation fail authentication.
- Restart after chunk commit but before acknowledgement replays the original
  range/receipt once. A changed chunk at the same offset, a hole, post-EOF append
  or stale drain lease fails; original request/run/operation correlation remains.
- Capture unavailable at start is recorded visibly before release, with review
  and capture-dependent continuation blocked, only under explicit current D6
  policy. Disabled, missing, stale or revoked approval stops before release.
  Integrity/authentication failure
  stops launch. Producer loss/full spool records a truthful gap and pauses/stops
  bounded work; an ordinary complete stream retains real bytes and EOF.
- The actual serve E2E, LIFECYCLE-TREE and OS-LINUX use a real launched authorized
  lane and measured helper confinement. Stand-ins, compile success and DTO
  fixtures do not close those rows or authenticate an AI-service session.
- Public health: require no-frame/slow-fragment timeout at two seconds from
  accept, bounded size before authentication, zero reply bytes for malformed
  JSON/oversize/unknown fields/health proof or extras, the one valid health reply,
  and no second-frame dispatch. Linux pins each fragment's credentials; the
  designated Darwin gate pins each frame's audit token and writer lifetime.
  A constant deadline value or scaffold test cannot close this transport row.
- Review: actual confined verifier/check jobs must join the frozen diff snapshot,
  ended run/event sequence, capture/tool inventory and current required checks.
  Caller-labelled blobs, old-run checks, executor self-review and partial capture
  cannot pass. A genuine independent complete review can be accepted under CAS.
- Channel: inert preparation never sends or consumes proof, only final queue
  commit activates the same fixed worker lease. A real authenticated worker
  sends and reads back the exact payload once, retaining provider bytes; interrupt
  after network send/before completion and reconcile that provider key. Unsupported
  reconciliation stays uncertain with no duplicate send. Zero exit cannot pass.
- Continuation: concurrent watchdog/manual control and restart preserve one
  store-stamped operation through claim, slot and launch; a mismatched operation,
  expired pending selection or cancelled epoch never acquires a fresh slot.

LP-CAPTURE-IO-1 remains the named follow-up for scoped input/resize/interactive
attach and real pinned vendor tool/session/limit record schemas. R48 blacklist
policy, D6 approval and D8 drivers remain unchanged.
