# Lifecycle mutation matrix

This matrix names every LIFECYCLE-TREE acceptance obligation and the related
source guard controls. The 430 guard mutations are prepared for Linux fixture
tests. They have not been run by this Mac executor. The 10 production rows
remain blocked on the numbered contract/implementation entries in CONTRACT-GAPS.md.
A fixture result cannot close an OS, authenticated driver, worker or 20-agent
acceptance row.

The runner applies exactly one named mutation to a fresh copy, never to the
candidate. It retains the source bytes/hash manifest, exact before/after file,
mutation hash, invocation, JSON test output, stderr, exit and named failing
tests. A red result requires the exact named test's assertion text. A compile
error, panic, timeout or missing named test stops the run as invalid evidence.
Survivors, including a test failing without its expected assertion, are listed
with reasons while the runner continues. It runs the unmodified focused
packages and exits nonzero if any mutation survived.

Use a new evidence directory outside source on the disposable Linux box:

```sh
python3 e2e/v2/cases/lifecycle/red.py --source . --suite guards --evidence /tmp/lb-lifecycle-red
python3 e2e/v2/cases/lifecycle/red.py --source . --suite guards --faults --evidence /tmp/lb-lifecycle-faults
python3 e2e/v2/cases/lifecycle/red.py --source . --mutation self-accept --evidence /tmp/lb-lifecycle-self
```

The guards suite can exit zero only after the specified assertion failures
and the unmodified tests pass. Its PASS line explicitly says full acceptance
is pending. Default `--suite all` includes blocked production rows and returns
69 with an incomplete summary; it never treats those rows as skips or passes.
The script does not install a mutated service or call a model. Production
mutations need the actual installed candidate and the case's trusted fixture
observers after the remaining launch contracts and actual workers are integrated.
Final draft.4 at `c6c68ca` supplies receipts, guards, metadata, delivery and continuation ports;
their existence is not evidence that the corresponding producer/worker ran.

The red-box finding for snapshot-frame was a non-compiling mutation: removing
the whole guard also removed encoded's only use. Static Go vet reproduces
`declared and not used: encoded`. The repaired edit removes that same whole
guard and keeps only `_ = encoded`; it does not reduce the defect to a special
input or weaken the assertion. The named test now checks a small actual stored
snapshot, the actual oversized page within the queue limit, the exact
snapshot-bound error, and delivery of the same stored first event as a stream.
Both Linux red builds must still reach `oversized snapshot crossed` on this
new edit, followed by the unmodified green test. Static compile success alone
does not satisfy that red result.

The next red-box finding, review-bytes, had the same compile-only failure:
removing the receipt comparison left the sole reflect import unused. The
repaired edit still removes the entire DeepEqual comparison, retaining only
the non-calling `_ = reflect.DeepEqual` reference. It leaves reviewer and
run-order checks unchanged. Its original named test and `wanted forbidden`
assertion remain. The altered case now supplies a second committed, readable
diff with different bytes and digest, and verifies the stored review remains
unchanged. Three additional controls apply that same broad edit to changed
check, inventory and refusal-resolution fields.

In the preceding red-fix round, the review, archive, input/frame and capture
family was audited for unused
imports/locals and other guards masking the intended distinction. All 33
mutant forms pass static Linux-target vet in both normal and faults builds.
Coverage changes keep the stored and submitted receipt equal; archive hash
changes isolate read-back equality; input digest corruption recomputes the
chunk hash; offset corruption preserves bytes/hash. Those controls therefore
reach their intended comparisons. This is a source/static audit, not runtime
red evidence. Setup, compile, panic and unrelated failures remain rejected by
the unchanged red.py verifier.

The counted-review round adds 35 controls while retaining all preceding edits
and assertions. Natural completion controls remove the whole end producer or
its atomic projection, remove the survivor/generation guards, omit the measured
outcome, or repeat an existing end. Parent-policy controls restore the old
cross-life query or remove the authenticated-generation comparison. Worker
visibility restores the former blanket branch. Review controls remove the
committed-end gate or all evidence read-back, with independent diff/check/
inventory cases. That round's complete-coverage schema request is resolved by
fix 10. The remaining service preparation and installed verifier dependencies
are recorded in CONTRACT-GAPS; readable bytes alone cannot close the production row.

Addendum controls restore lost-as-ended, return a filtered-empty raw page,
remove raw cursor progress, remove each added replay or interactive lock, drop
one CLI registration, and remove profile payment/spend/expiry checks. Foreign
cursor tests require refusal on the first raw page; otherwise a later ordering
check could mask the missing progress guard. Paid-fallback uses positive spend,
no-spend uses two paid profiles, and expiry uses an unpaid destination. Optional
empty fields, canonical base64, merged epochs and new prompt/materialization/
lost invalidation have focused controls too. Compile/setup errors and runtime
mutation kills remain separate; all new runtime results require the Linux box.

## Acceptance obligations

| Obligation | Guard mutation/test evidence | Production gate still required |
| --- | --- | --- |
| Start → end → resume run 2 → turn → stop | launch-gate, process-generation, end-observation, resume-session, resume-budget, pending-stop | flow-release; actual launch permit, capture drain, run 2 and turn execution |
| Independent review → accepted → merged | self-accept, review-bytes, review-coverage, review-stale, merge-order; TestReviewedStatePath | review-worker; exact confined diff/check/tool-record provenance |
| Archive → clean with records retained | archive-hash, archive-life, archive-order, archive-stale, clean-state | archive-worker, archive-clean-flow; actual verified archive and owned removal |
| Parent follow, saved sequence, selected committed end | tree-visibility, saved-query, event-since, event-life, event-run, event-origin, follow-delay | two-ladder-load; real two-ladder/20-agent commit-to-receive measurement |
| Older, hidden and observed ends do not terminate follow | event-run, event-life, event-origin and TestFollowIgnoresOtherEnds | repeat through the installed socket under the full case |
| Manual requester differs from carried sender | request-actor and TestTurnRequestActor; immutable ordered trigger references | turn-sender; actual mail delivery revalidation and launch actor |
| Detached children remain contained and stop | known-survivors, missing-survivors, unknown-survivors, process-generation | detached-child; independent actual double-fork/setsid canary |
| Failed archive read-back preserves work | archive-hash, archive-order, archive-stale | archive-worker plus run.py --control archive_failure and outside preservation observer |
| Dirty or unowned work refuses removal | clean-state and archive-life cover intent/receipt checks only | dirty-removal and unowned-removal; run.py --control dirty_clean / unowned_clean |
| Unknown survivors refuse continuation | unknown-survivors, missing-survivors, known-survivors | run.py --control unknown_resume with actual unknown observation |
| Self-acceptance refuses | self-accept with an otherwise valid independent receipt | full case's live executor self-review/self-mark probes |
| Cleaned resume refuses | cleaned-resume | full case after actual owned cleanup |
| Removing actor, visibility, launch or receipt checks must fail | request-actor, tree-visibility, launch-gate, archive-hash and archive-life | turn-sender, flow-release and delete-before-receipt on the actual effect paths |
| Exact draft.3 mutation context | stop-epoch, stop-epoch-guard, effect-requester, human-proof, human-target | actual store atomicity, current connection identity and outbox reconciliation |
| Object/policy/history provenance | input-metadata, target-role, resume-history, ticket-reuse | installed stores, current policy and actual retained runtime |
| Snapshot and receipt lifetime | borrowed-view, initial-cursor, check-replay, unknown-reply | installed transport constructor ordering, replay and live revocation |
| Continuation epoch and runtime binding | continuation-epoch, watchdog-rebind | actual durable claim/slot handoff and cancellation reconciliation |

## Prepared guard mutations

| Mutation | Rule | Exact focused test |
| --- | --- | --- |
| tree-visibility | authentic_tree | `TestTreeVisibility` |
| event-config | selected_config | `TestEventSelectionFields/config` |
| event-life | hidden_end | `TestEventSelectionFields/life` |
| event-run | older_end | `TestEventSelectionFields/run` |
| event-origin | observed_end | `TestEventSelectionFields/origin` |
| event-since | saved_sequence | `TestEventSelectionFields/since` |
| saved-query | saved_sequence | `TestSavedSequence` |
| follow-delay | follow_two_seconds | `TestFollowBatchBound` |
| stream-authority | delivery_revalidation | `TestFollowRechecksRevocation` |
| snapshot-frame | bounded_snapshot | `TestSnapshotFrameBound` |
| event-bound | bounded_stream | `TestStreamBounds` |
| end-observation | truthful_end | `TestObservedEndCannotBeTerminal` |
| launch-gate | failed_launch_gate | `TestLaunchGateCannotBeSkipped` |
| request-actor | manual_requester | `TestTurnRequestActor` |
| self-accept | self_acceptance | `TestSelfAcceptanceRefuses` |
| review-bytes | independent_review | `TestForgedReviewsRefuse/altered` |
| review-checks | exact_review_checks | `TestForgedReviewsRefuse/checks` |
| review-inventory | exact_review_inventory | `TestForgedReviewsRefuse/inventory` |
| review-resolution | exact_review_resolution | `TestForgedReviewsRefuse/resolution` |
| review-coverage | complete_coverage | `TestIncompleteCoverageRefuses` |
| review-stale | current_review | `TestReviewChangesInvalidate` |
| merge-order | accepted_then_merged | `TestMergeRequiresAcceptance` |
| archive-hash | archive_readback | `TestArchiveReadBackBeforeClean/mismatch` |
| archive-life | archive_ownership | `TestArchiveReceiptLifeBound` |
| archive-order | receipt_after_end | `TestArchiveNeedsEndedRun` |
| archive-stale | archive_current | `TestArchiveChangesInvalidate` |
| clean-state | merged_before_clean | `TestCleanNeedsFinalState` |
| unknown-survivors | unknown_containment | `TestUnknownResumeRefuses` |
| known-survivors | survivors_block_resume | `TestTwentySurvivorsRefuse` |
| missing-survivors | missing_count | `TestMissingSurvivorCount` |
| process-generation | process_identity | `TestProcessGenerationBound` |
| pending-stop | stop_intent_order | `TestPendingStopIsNotComplete` |
| cleaned-resume | cleaned_resume | `TestCleanedResumeRefuses` |
| resume-session | same_session | `TestResumeSessionIsRequired` |
| resume-budget | remaining_budget | `TestResumeBudgetDoesNotReset` |
| revoked-grants | current_grants | `TestRevokedGrantsRefuse` |
| strict-lower | strict_lower_spawn | `TestStrictLowerSpawnLevel` |
| internal-only | internal_continuation | `TestInternalContinueRejectsLane` |
| turn-duplicates | ordered_mail | `TestTurnOrderAndIdle` |
| capture-final | exact_capture | `TestCaptureReadErrorKeepsBytes` |
| capture-buffer | immutable_capture | `TestCaptureKeepsExactRanges` |
| capture-sink | capture_failure | `TestCaptureSinkFailureIsVisible` |
| capture-cancel | capture_cancellation | `TestCaptureCancellationClosesPipe` |
| input-digest | exact_inputs | `TestInputDigestIsChecked` |
| input-offset | exact_input_ranges | `TestInputRangeIsChecked` |
| json-duplicate | strict_request | `TestStrictRequestBytes` |
| json-unicode | exact_unicode | `TestStrictRequestBytes` |
| review-provenance | review_verifier_barrier | `TestDirectReviewCannotPass` |
| cli-namespace | shared_cli_names | `TestCLILaneNames` |
| empty-input | committed_empty_input | `TestEmptyInputMustExist` |
| intent-error | failed_commit_stops_effect | `TestFailedIntentDoesNotStop` |
| reviewed-path | record_actual_state_decision | `TestReviewedStatePath` |
| catalog-drift | exact_reviewed_mutation | `TestMutationCatalog` |
| stop-epoch | durable_cancellation | `TestStopAtomicContext` |
| stop-epoch-guard | atomic_cancellation | `TestStopAtomicContext` |
| effect-requester | causal_effect_requester | `TestStopAtomicContext` |
| human-proof | atomic_human_proof | `TestHumanCommitGuard/valid` |
| human-target | exact_human_target | `TestHumanCommitGuard/wrong-target` |
| input-metadata | committed_object_class | `TestInputMetadataBinding/class` |
| resume-history | retained_history | `TestHistoryRequired` |
| target-role | authentic_target_policy | `TestPolicyRoleBinding` |
| borrowed-view | live_read_lifetime | `TestBorrowedReadView` |
| initial-cursor | initial_stream_snapshot | `TestBorrowedReadView` |
| check-replay | receipt_before_observe | `TestCheckReplyReplay` |
| unknown-reply | durable_typed_error | `TestUnknownReplyReplay` |
| continuation-epoch | stale_continuation_epoch | `TestContinuationStaleEpoch` |
| ticket-reuse | unused_root_ticket | `TestRootTicketBinding/redeemed` |
| watchdog-rebind | runtime_binding_once | `TestWatchdogBinding` |
| counter-bound | exact_lifecycle_counters | `TestLaneCounterBounds/retries` |
| release-count | helper_measured_release | `TestReleaseEventEvidence/nonzero` |
| ticket-endpoint | human_class_root_ticket | `TestRootTicketClass/human-on-lane` |
| ticket-provenance | ticket_issuer_binding | `TestRootTicketBinding/principal` |
| proof-replay | proof_before_replay | `TestProofBeforeReplay/empty-id` |
| receipt-config | retained_receipt_config | `TestReceiptBinding/config` |
| check-end | natural_terminal_end | `TestCheckNaturalExit/exit` |
| check-projection | atomic_post_run_state | `TestCheckNaturalExit/exit` |
| check-survivors | zero_survivor_end | `TestCheckSurvivorsRefuse` |
| check-end-once | terminal_fact_once | `TestCheckEndIsStable` |
| check-generation | bounded_end_generation | `TestCheckEndCommitFailure/generation` |
| check-evidence | measured_end_outcome | `TestCheckNaturalExit/exit` |
| parent-policy | authenticated_parent_policy | `TestParentGrantRevalidation/valid` |
| control-policy | current_scope_policy | `TestParentGrantRevalidation/stale` |
| worker-tree | worker_tree_visibility | `TestWorkerTreeVisibility/unrelated` |
| review-end | review_committed_end | `TestReviewRequiresEnd` |
| review-read-diff | review_exact_readback | `TestReviewInputReadBack/diff` |
| review-read-check | review_exact_readback | `TestReviewInputReadBack/check` |
| review-read-inventory | review_exact_readback | `TestReviewInputReadBack/inventory` |
| lost-end | lost_is_not_terminal | `TestLostCanReconcileRealEnd` |
| foreign-pages-snapshot | committed_page_drain | `TestEventsSkipForeignPages/snapshot` |
| foreign-pages-follow | committed_page_drain | `TestEventsSkipForeignPages/follow` |
| foreign-cursor | raw_page_cursor_progress | `TestForeignCursorAdvance/cursor-same` |
| replay-start | receipt_before_preflight | `TestReplayBeforeChangedState/start` |
| replay-adopt | receipt_before_preflight | `TestReplayBeforeChangedState/adopt` |
| replay-review | receipt_before_preflight | `TestReplayBeforeChangedState/review` |
| replay-archive | receipt_before_preflight | `TestReplayBeforeChangedState/archive` |
| replay-input | receipt_before_preflight | `TestReplayBeforeChangedState/input` |
| replay-loop | receipt_before_loop_cas | `TestReplayBeforeChangedState/loop` |
| replay-check-history | historical_check_receipt | `TestReplayBeforeChangedState/check` |
| loop-lock | serialized_interactive_mutation | `TestInteractiveSerializes/loop` |
| input-lock | serialized_interactive_mutation | `TestInteractiveSerializes/input` |
| cli-registration | registered_semantic_input | `TestCLIInputFiles/status/invalid` |
| profile-paid | no_paid_fallback | `TestProfileLimits/paid-fallback` |
| profile-spend | remaining_spend_budget | `TestProfileLimits/no-spend` |
| profile-expiry | unexpired_destination_grant | `TestProfileLimits/expired` |
| optional-empty | decoded_request_equivalence | `TestOptionalEmptyField` |
| canonical-base64 | exact_byte_spelling | `TestInputCanonicalBase64` |
| merged-epoch | cancel_terminal_continuations | `TestMergedCancelsOldIntent` |
| review-fresh | new_evidence_invalidates_receipt | `TestNewWritesInvalidate/prompt` |
| archive-fresh | new_evidence_invalidates_receipt | `TestNewWritesInvalidate/prompt` |

The exact source check removed/inverted and the required assertion evidence
are retained in [mutations.json](mutations.json). Source anchor drift is an
error requiring review, not a reason to broaden a replacement or weaken a test.
The namespace control deliberately renames a helper type and every reference
so that the source still compiles and the namespace assertion detects it.
Exported receiver methods implementing interfaces, such as io.Writer.Write,
retain their interface names; their types and all private declarations still
require the lane prefix. This does not exempt any package-level helper.

## Pending production mutations

| Mutation | Named full-case assertion | Check removed/inverted | Contract/dependency entries |
| --- | --- | --- | --- |
| flow-release | LIFECYCLE-TREE/full-flow | Remove the committed permit check before releasing the prepared gate. | 1, 3, 4 |
| two-ladder-load | LIFECYCLE-TREE/two-ladder-latency | Delay committed selected-end delivery beyond two seconds under both real starter trees. | 1, 3, 4, 9 |
| turn-sender | LIFECYCLE-TREE/manual-turn-actor | Replace the authenticated manual requester with the first carried sender on the actual turn launch. | 1, 3, 7 |
| detached-child | LIFECYCLE-TREE/detached-stop | Remove the run containment stop/observation check so the detached child survives. | 3, 4 |
| review-worker | LIFECYCLE-TREE/independent-review | Trust a lane-authored check or inventory rather than the confined verifier's correlated receipt. | 5 |
| archive-worker | LIFECYCLE-TREE/archive_failure | Remove archive read-back verification in the actual archive completion worker. | 4, 6 |
| dirty-removal | LIFECYCLE-TREE/dirty_clean | Remove the owned cleanup worker's dirty-work check before unforced removal. | 6 |
| unowned-removal | LIFECYCLE-TREE/unowned_clean | Remove the disposable-object ownership check before removal. | 6 |
| delete-before-receipt | LIFECYCLE-TREE/receipt-before-delete | Move actual removal before the verified archive/manifest/read-back receipt gate. | 4, 6 |
| archive-clean-flow | LIFECYCLE-TREE/archive-clean | Omit archive completion or retained-object verification while reporting lane.cleaned. | 4, 6 |

The production assertion labels name the corresponding checks in run.py's
full scenario. Negative controls also have the explicit --control selector.
They are pending definitions, not executable source edits against a missing
worker. Their absence is reported as incomplete. Do not replace these tests
with a unit fixture or a constant success result to close an acceptance row.

## Draft.4 fix 9 launch-plan controls

The launch-gate control now removes the actual probe in launchAvailability;
the start/adopt replay controls remove launchReplay at the same handler entry.
Their existing tests and required assertions remain. The continuation-epoch
control is unchanged, with its valid fixture supplying current policy.
The following 35 additions cover the new actual consumer paths. Source anchors
and static type checking alone are not runtime RED. Each Linux run must reach
the listed assertion, fail there under the one edit and pass unchanged tests.

| Control | Rule | Focused assertion test |
| --- | --- | --- |
| launch-pending-owner | launch_pending_owner | `TestLaunchPendingReply` |
| launch-frame-bytes | launch_frame_bytes | `TestLaunchOriginalFrame` |
| launch-foreign-requester | launch_foreign_requester | `TestLaunchForeignReservation/requester` |
| plan-service-actor | plan_service_actor | `TestPlanLaunchClaim/actor` |
| plan-current-claim | plan_current_claim | `TestPlanLaunchClaim/generation` |
| plan-current-policy | plan_current_policy | `TestPlanLaunchClaim/policy` |
| plan-reserved-grants | plan_reserved_grants | `TestPlanLaunchGrants/life` |
| plan-data-cwd | plan_data_cwd | `TestPlanLaunchData/cwd` |
| plan-data-home | plan_data_home | `TestPlanLaunchData/home_path` |
| plan-runner-executable | plan_runner_executable | `TestPlanLaunchRunner/executable` |
| plan-source-replay | plan_source_replay | `TestPlanLaunchChangedSources` |
| plan-stage-replay | plan_stage_replay | `TestPlanLaunchStageReplay` |
| plan-stage-uncertain | plan_stage_uncertain | `TestPlanLaunchStageReplay` |
| plan-capture-owner-error | plan_capture_owner_error | `TestPlanLaunchCaptureFailure/integrity` |
| plan-capture-reconcile | plan_capture_reconcile | `TestPlanCaptureTuple` |
| plan-capture-error-retain | plan_capture_error_retain | `TestPlanCaptureErrorRetention` |
| plan-recovery-binding | plan_recovery_binding | `TestPlanLaunchRecovery/missing` |
| plan-storage-owner | plan_storage_owner | `TestPlanStorageTuple` |
| plan-life-gate | plan_life_gate | `TestPlanWorkerCancellation` |
| plan-continuation-slot | plan_continuation_slot | `TestPlanContinuation/retained-slot` |
| plan-continuation-prompt | plan_continuation_prompt | `TestPlanContinuation/new-slot` |
| plan-retained-runtime | plan_retained_runtime | `TestPlanRetainedPins/runtime` |
| plan-retained-home | plan_retained_home | `TestPlanRetainedPins/home` |
| plan-positive-body | plan_positive_body | `TestPlanLaunch/codex/registered` |
| launch-adopt-body | launch_adopt_body | `TestLaunchAdopt` |
| launch-resume-body | launch_resume_body | `TestPlanRetainedRuns/resume` |
| launch-turn-body | launch_turn_body | `TestPlanRetainedRuns/turn` |
| plan-mail-order | plan_mail_order | `TestPlanTurnMail/order` |
| plan-mail-requester | plan_mail_requester | `TestPlanTurnMail/requester` |
| plan-guidance-turn | plan_guidance_turn | `TestPlanGuidance/foreign_turn` |
| plan-child-owner-error | plan_child_owner_error | `TestPlanChildErrors/allocate` |
| plan-worker-owner-error | plan_worker_owner_error | `TestPlanChildErrors/materialize` |
| launch-continue-body | launch_continue_body | `TestPlanContinuation/new-slot` |
| plan-refused-review | refused_capture_blocks_review | `TestRefusedCaptureReview/review` |
| plan-refused-mark | refused_capture_blocks_mark | `TestRefusedCaptureReview/mark` |


## Draft.4 fix 10 controls

All 144 preceding controls remain. Fix 10 adds 49 controls, for 193 guard rows and ten unchanged physical acceptance rows. The JSON catalog is the executable source of each exact edit, assertion and selected subtest.

The review byte controls now target the common evidence read-back function; removing only the earlier candidate read would leave the later read in place. Closed coverage targets the shared acceptance gate. End, missing-preparation and refused-capture controls change their deciding refusal into a nil-error result, so a downstream integrity check cannot create an unrelated red. The exact receipt controls retain valid, different measured object bytes and align the submitted evidence fields; refusal resolution changes only the ordering of authenticated resolutions. Their failure therefore still decides exact stored-receipt equality.

The prepared kind, level and role cases recompute the record hash before attempting recovery. They test the reserved pins independently of the digest gate. The unconditional same-transaction prepared-plan rule is also exercised by the complete transaction fixture and its missing-plan, worker-kind and life-CAS cases; its shared source controls belong to the integrate catalog.

The first static mutation batch stopped because removing the refused-capture guard left facts unused. The corrected edit removes the same guard and adds only the nonexecuting `_ = facts` reference. This compiler failure is retained as setup evidence and is never counted as a runtime red. The original brief's recovery route explicitly permits repairing owned vet findings.

| Control | Deciding rule | Required failing test |
| --- | --- | --- |
| check-explicit-state | natural_state_event | `TestCheckNaturalExit/exit` |
| reserve-ticket-guard | reservation_ticket_guard | `TestReservationAuthorityHandoff` |
| reserve-retained-proof | reservation_proof_guard | `TestReservationRetainedProof` |
| reserve-authority-pin | reservation_authority_pin | `TestReservationReturnedPins/authority` |
| reserve-level-pin | reservation_level_pin | `TestReservationReturnedPins/level` |
| reserve-role-pin | reservation_role_pin | `TestReservationReturnedPins/role` |
| reserve-driver-pin | reservation_driver_pin | `TestReservationReturnedPins/driver` |
| prepared-recovery-kind | prepared_binding_kind | `TestPlanLaunchRecovery/kind` |
| prepared-recovery-level | prepared_binding_level | `TestPlanLaunchRecovery/level` |
| prepared-recovery-role | prepared_binding_role | `TestPlanLaunchRecovery/role` |
| capture-refusal-current | capture_refusal_current_d6 | `TestCaptureD6/recovery-disabled` |
| continue-public-method | continuation_internal_scope | `TestContinueOpRefuses/public-method` |
| continue-pending-result | continuation_pending_status | `TestContinueOpRefuses/pending-succeeded` |
| continue-running-replay | continuation_running_replay | `TestContinuationOneOperation` |
| continue-completed-replay | continuation_completed_replay | `TestContinuationOneOperation` |
| continue-refused-capture | capture_refusal_blocks_continuation | `TestContinueOpRefuses/capture-refused` |
| review-verifier-body | review_actual_verifier | `TestReviewVerifiedCommit` |
| review-evidence-run | review_evidence_run | `TestReviewEvidence/run` |
| review-evidence-end | review_evidence_end | `TestReviewEvidence/end` |
| review-evidence-snapshot | review_evidence_snapshot | `TestReviewEvidence/snapshot` |
| review-evidence-inventory | review_evidence_inventory | `TestReviewEvidence/inventory` |
| review-evidence-coverage | review_evidence_coverage | `TestReviewEvidence/coverage` |
| review-accept-failed-check | review_accept_failed_check | `TestReviewEvidence/failed-check` |
| review-accept-required-check | review_accept_required_check | `TestReviewEvidence/required-check` |
| review-accept-tool-gap | review_accept_tool_gap | `TestReviewEvidence/tool-gap` |
| review-accept-eof | review_accept_eof | `TestReviewEvidence/eof` |
| review-accept-stream-gap | review_accept_stream_gap | `TestReviewEvidence/stream-gap` |
| review-accept-refusal | review_accept_refusal | `TestReviewEvidence/refusal` |
| review-extra-bytes | review_inventory_actual_bytes | `TestReviewEvidence/objects` |
| review-worker-job | review_actual_check_job | `TestReviewEvidence/check-job` |
| review-job-operation | review_actual_check_operation | `TestReviewEvidence/job-operation` |
| review-object-provenance | review_object_provenance_logged | `TestReviewEvidence/provenance` |
| review-job-provenance | review_verifier_operation_provenance | `TestReviewEvidence/foreign-verifier` |
| review-historical | review_live_evidence_required | `TestReviewMarkRechecks/historical` |
| review-mark-snapshot | review_current_snapshot | `TestReviewMarkRechecks/snapshot` |
| review-mark-required-check | review_current_required_check | `TestReviewMarkRechecks/required-check` |
| review-primary-eof | review_retained_primary_eof | `TestReviewEvidence/claimed-eof` |
| review-primary-range | review_retained_primary_range | `TestReviewEvidence/range` |
| review-capture-binding | review_actual_capture_binding | `TestReviewEvidence/capture-binding` |
| review-capture-streams | review_actual_capture_streams | `TestReviewEvidence/capture-streams` |
| review-capture-sequence | review_frozen_capture_sequence | `TestReviewEvidence/capture-sequence` |
| review-capture-position | review_actual_capture_positions | `TestReviewEvidence/capture-position` |
| review-lease-target | review_lease_target | `TestReviewLeaseHandoff/target` |
| review-lease-operation | review_lease_operation | `TestReviewLeaseHandoff/operation` |
| review-lease-input | review_lease_input | `TestReviewLeaseHandoff/input` |
| review-event-operation | review_event_verifier_operation | `TestReviewMarkRechecks/operation` |
| review-worker-life-gate | review_worker_wait_life_gate | `TestReviewWaitRechecks` |
| review-partial-replay | review_partial_retained_replay | `TestReviewPartialRetained` |
| review-partial-accept | review_partial_cannot_accept | `TestReviewPartialRetained` |


## Draft.4 fix 11 controls

All 193 preceding guards remain; 30 additions make 223 guard rows. The ten
physical acceptance rows above remain unchanged and incomplete. The current
catalog has 191 distinct source edits. Each edit passed Linux amd64 vet in
normal and laneboss_faults variants on the Mac host; none ran a named test
assertion here. Each row still needs reached RED and unchanged GREEN on Linux.

The fixture fence repair encodes required starter-event arrays as empty arrays,
validates the seed, and keeps explicit cancellation-epoch entries synchronized
with actual public Lane commits. Production fences remain. The self-accept row
is byte-for-byte unchanged, including TestSelfAcceptanceRefuses and wanted
forbidden. The test preserves its original forbidden/no-write checks and also
requires the early refusal before actual target-store reads. Inverting the
independence predicate crosses that boundary even though later receipt checks
also refuse. This is a static reachability argument until Linux confirms it.

The parent/control policy rows now target authenticated current context rather
than equating historical issuance with current policy. The old worker-error
and data cwd/home rows target retained stage completion and returned-data
correlation. Their original IDs, tests and required assertions remain. Fault
cases align duplicated effect/worker/output fields so the nominated predicate
decides the result. Missing-stage checks observe attempted dataworker entry as
well as actual work, so an owning refusal cannot hide an allocation attempt.

| Control | Deciding rule | Required failing test |
| --- | --- | --- |
| policy-refresh-fence | fresh_lane_policy_fence | `TestPolicyFreshFence` |
| policy-replay-unknown | retained_receipt_policy_unknown | `TestPolicyReceiptReplay/unknown` |
| policy-replay-future | retained_receipt_policy_future | `TestPolicyReceiptReplay/future` |
| policy-history-generation | retained_receipt_history_generation | `TestPolicyReceiptReplay/foreign` |
| policy-retained-turn | retained_turn_policy | `TestPolicyContinueTurn/future` |
| policy-opened-reconcile | opened_historical_policy | `TestPolicySealedAndOpened/opened` |
| policy-sealed-current | sealed_launch_current_policy | `TestPolicySealedAndOpened/sealed` |
| data-stage-claim | data_stage_claim | `TestMaterializeStagePins/claim` |
| data-stage-grants | data_stage_grants | `TestMaterializeStagePins/grants` |
| data-stage-parent | data_original_parent_claim | `TestMaterializeStagePins/parent` |
| data-stage-absence | data_missing_stage_no_replacement | `TestMaterializeStagePins/missing` |
| data-worker-lease | data_retained_worker_mapping | `TestMaterializeStagePins/lease` |
| data-worker-principal | data_own_worker_principal | `TestMaterializeStagePins/worker` |
| data-worker-runtime | data_installed_worker_runtime | `TestMaterializeStagePins/executable` |
| data-worker-budget | data_remaining_task_budget | `TestMaterializeStagePins/budget` |
| data-worker-exit | data_measured_worker_exit | `TestMaterializeStagePins/exit` |
| data-measured-completion | data_measured_completion_required | `TestMaterializeStagePins/result` |
| data-output-readback | data_actual_output_bytes | `TestMaterializeStagePins/bytes` |
| capture-worker-kind | capture_fixed_worker_kind | `TestPlanLaunch/codex/registered` |
| revoke-current-claim | revocation_current_claim | `TestRevocationRefuses/claim` |
| revoke-endpoint | revocation_actual_endpoint | `TestRevocationRefuses/endpoint` |
| revoke-original-cause | revocation_original_cause | `TestRevocationRefuses/cause` |
| revoke-event-validation | revocation_actual_committed_event | `TestRevocationRefuses/event` |
| revoke-close-blocked | revocation_close_blocked | `TestRevocationClosePending/blocked` |
| revoke-close-unknown | revocation_close_unknown | `TestRevocationClosePending/unknown` |
| revoke-epoch-refusal | revocation_epoch_fence | `TestRevocationRefuses/epoch` |
| revoke-transport-stage | revocation_transport_required | `TestRevocationCommitBeforeClose` |
| history-identity-event | historical_identity_event_required | `TestRevokedHistoryRead/event` |
| history-revocation | historical_causal_revocation_required | `TestRevokedHistoryRead/record` |
| policy-error-replay | retained_error_policy | `TestPolicyErrorReplay/unknown` |

Successful and failed exact receipts both validate their retained approved
policy before returning the original reply. The error-replay row focuses its
unknown subtest, where removing the direct history call reaches the real
`error receipt bypassed retained policy validation` assertion at the direct
replay boundary before any public authorization path can mask it.

## Fix-12 box corrections

All 223 earlier guards, including their exact edits, named tests and expected
diagnostics, remain unchanged. One store-response error control makes 224 guard
rows and 192 distinct source forms. The ten physical rows remain incomplete.

Capture replay's preceding briefing and refused plans now retain valid required
arrays. Their original error/refusal assertions decide after closed decoding.
Retained-run tests distinguish current grant issuance from private task state,
and require the historical grant/binding bytes to remain unchanged. The retained
slot fixture checks the actual claimed intent, previous grant and life/epoch
instead of requiring the new grant set to have been issued before planning.
TestSlotGrantFence covers the valid handoff plus missing/changed epoch, cancelled
intent, changed launch and revoked-grant refusals without a produced slot.

The unchanged internal-only control removes the actor/source predicate. Its
named test uses an otherwise valid private invocation shape and measures actual
Operation reads. The candidate refuses before that read. The mutant crosses
the boundary, so the same lane principal invoked internal continuation
diagnostic fires even if later independent checks also refuse. This remains a
static trace until Linux executes the mutation and unchanged candidate.

| Control | Deciding rule | Required failing test |
| --- | --- | --- |
| reservation-invalid-error | invalid_store_reservation_integrity | `TestLaunchForeignReservation/parent` |

This control restores propagation of the shared validator's invalid_request for
a malformed protected store result. The original integrity-code assertion must
fail. The valid public input cannot carry or repair a returned parent ID. The
test also requires the shared reservation boundary to decide before the later
foreign-response checks. Ordinary owning store failures still propagate.

## Fix-13 dispatcher and root-policy controls

All 224 previous guards retain their IDs, named tests and diagnostics.
Five additions make 229 guard rows and 197 distinct source forms. The ten
physical rows remain incomplete. All runtime assertions still require Linux.

The self-wait regression was authored before product edits. It calls the actual
fixture ReserveRequest, retains nil Reply and the original operation/frame,
then calls LaneStop or LaneMark with a bounded context. The old lookup path
enters the fixture's real completion wait and reaches the named failure at its
deadline. The retained old-source/test bytes permit that Linux reproduction;
static vet establishes no observed hang or runtime RED.

The fix-12 box reported green unit/faults suites and a surviving check-generation
control. Removing the early guard was masked when maxInteger+1 reached the
separate state-intent decoder's exact-integer bound and still returned integrity.
The repaired control keeps the same source guard, test and diagnostic, but
changes that guard's error return to nil. It now reaches the original typed-error
assertion directly. No production bound or downstream validation is weakened.

The concurrent retry carries the same Scope/request ID but a distinct private
dispatcher invocation. It must enter AwaitReceipt, leave the life gate absent,
and wake only after the original owner commits. The test checks the actual
gate map under its mutex and replays the actual original operation once. No
request ID or caller-supplied bool grants ownership. Root-policy testing advances
the real fixture policy after authentication and requires conflict, zero launch
reservations and an unchanged unredeemed ticket.

| Control | Deciding rule | Required failing test |
| --- | --- | --- |
| pending-own-receipt | fresh_mutation_no_self_wait | `TestFreshMutationReceipt/stop` |
| pending-other-executor | pending_retry_await | `TestPendingMutationRetry` |
| pending-before-life-gate | pending_wait_outside_life_gate | `TestPendingMutationRetry` |
| pending-original-operation | original_dispatch_operation | `TestFreshMutationReceipt/stop` |
| root-current-policy | root_policy_before_ticket | `TestRootPolicyBeforeTicket` |

## Fix-14 entry and dispatcher controls

All 229 earlier guards retain their IDs, rules, tests and expected diagnostics.
launch-pending-owner now targets its owned-pending branch after the independent
ownership check was added to launchReplay. Its edit returns a typed retry error
at that branch, avoiding an unbounded self-await in its existing background
context test. plan-retained-runtime is unchanged. Its named test now observes
the early credential boundary before a later runner check can mask the edit.

Completed replay retains exact reply equality and prohibits pending-ownership
queries; it permits the actual authorization and handler receipt reads. The
serialization test retains the 50 ms deadline and requires no target read or
write before acquiring its gate. No expected reply or error was substituted.
The dispatcher fixture checks a per-invocation frame and ends that ownership
when a reply is sealed. Same request IDs/connections never create another owner.

Seven additions make 236 guards and 204 distinct source forms. The ten physical
rows remain incomplete. Panic/setup failure is never a named runtime RED. The
new entry controls change the deciding typed result without relying on a panic.

| Control | Deciding rule | Required failing test |
| --- | --- | --- |
| planner-zero-shape | typed_zero_planner_request | `TestPlannerZeroRequest` |
| planner-core-required | typed_missing_planner_dependency | `TestPlannerNilDependencies/Store` |
| empty-planner-owner | uninitialized_planner_owner | `TestEmptyPlannerService` |
| launch-direct-owner | direct_launch_retry_ownership | `TestLaunchReplayOtherInvocation` |
| commit-needs-reservation | public_commit_reserved_once | `TestCommitNeedsReservation` |
| dispatch-frame-identity | fixture_invocation_identity | `TestDispatchReceiptStates` |
| completed-reply-order | completed_reply_first | `TestReplayBeforeChangedState/start` |

## Fix-16 receipt and interactive effects

The 34 additions preserve every prior ID/rule/test/diagnostic. TestStopAtomicContext
uses the actual reserved frame and verifies its ownership before LaneStop, so
an ownership regression fails its named assertion before a background wait.
AwaitReceipt cancellation controls keep the real pending channel and inject
success only at its cancellation return; no test/suite deadline is reduced.

Loop controls remove the durable setting/generation/backoff/disabled gates.
Input controls omit the actual worker intent or relax current channel, exact
bytes, enrolled worker, narrow grants, cancellation and measured completion.
The declared IO fixture writes actual bytes and dimensions and journals the
original effect's result; it is not a PTY or native worker acceptance test.

Attach controls alter HMAC/scope/range progress, primary provenance/digest,
current binding, delivery authorization, pinned snapshot and cancellation.
Supervisor controls omit the drain, native peer validation, append ack, EOF,
read error or endpoint close failure. Their actual byte/record/EOF assertions
must be reached on Linux; compilation/setup/panic/timeout is not named RED.
The new selected test names, including subtests, are below 40 characters.

## Fix-21 counted-review controls

All 372 preceding guard IDs and named test/diagnostic pairs remain. The 29
additions make 401 guards and 333 distinct source mutations. Ten physical
acceptance rows remain incomplete. New runtime tests and RED/GREEN controls
have not run on this Mac and still require the authorized Linux phase.

The prepared-transaction regression retains its private policy fence, valid
baseline and all eight negative assertions. The two older effect-state
mutations remove both validators of the same state rule to avoid masking.
The original projection-turn case keeps its actual prepare effect coherent
so the logical-turn comparison decides. The prepared-writer mutation follows
the same locked body into writeLaunch. Fixture edits remain confined to one
declared receiver method and cannot change named Test functions/assertions.

| Controls | Deciding regression |
| --- | --- |
| plan-failure-trigger, plan-failure-bound, plan-failure-pair | TestPlanFailOutbox requires the terminal plan and original cleanup requests in one recorded transaction. |
| plan-failure-separate | TestPlanFailAtomic rejects separate/missing cleanup, checks commit failure and retains the slot on retry. |
| plan-failure-uncertain, plan-failure-writer-port | TestPlanFailUncertain preserves unresolved injection; TestPlanFailPort exposes the missing native writer. |
| opened-withdrawing, opened-projection-state | TestOpenedWithdraw preserves the permit through correlated withdrawal and rejects foreign history. |
| child-pending-insert, terminal-claim-id, terminal-claim-generation | TestChildInsert and TestReceiptClaim reject skipped pending/claimed transitions. |
| data-original-claim, child-claim-input, child-completion-lease, completion-claimant | Child/data tests require the original claim, effect input, claimant and claimed lease. |
| archive-pending-insert, archive-terminal-claim, writer-effect-table | TestArchiveState and TestWriterClaimState enforce the same table in fixtures and readers. |
| partial-bind-recovery, prepare-retained-effect, prepare-service-claim, bound-prepare-effect-call | Recovery tests reject partial bindings and verify the actual service prepare effect. |
| writer-partial-bind, writer-plan-reservation | TestWriterBind rejects overwriting identity or changing a reservation. |
| bound-logical-turn, bound-turn-snapshot, bound-snapshot-call | TestBoundTurn and TestBoundRecovery require the committed lane and turn, including run one. |
| opened-allocation-recovery, opened-capture-recovery | TestOpenedResources checks original allocation/data/capture without acquiring again. |

The product CONTRACT-GAPS.md specifies the private FailedPlanStore atomic
writer/outbox integration. The production store does not implement it here.
Map fixtures establish correlation, not native withdrawal or leak closure.
The missing-port test prevents reporting an absent dependency as an enqueued
request. No new public effect, fake quiescence or model request is introduced.

## Fix-22 policy replay control

The earlier Linux red run stopped at policy-replay-unknown in both builds.
The row removed launchReplay's local receiptPolicy call, but authorize now
calls lookupReply first and checks that same policy. The public-only test
therefore still refused the receipt and masked the omitted launch guard.
The same masking affected policy-replay-future and policy-error-replay.

TestPolicyReceiptReplay and TestPolicyErrorReplay now exercise launchReplay
directly with their actual reserved receipts as well as through LaneStart.
The original public assertions remain intact. Direct retained replay must
return the same operation or exact error without a refresh or reservation;
unknown, future and foreign history must fail with the corresponding typed
policy error. The original named diagnostics still decide these controls.
All catalog rows, edits, test selectors and expected diagnostics remain
unchanged. No production policy or authorization check is removed.

The complete nine-row policy-* source sweep covers refresh, unknown/future
receipt history, foreign history generation, retained turn selection,
opened/sealed policy and target projection generation. The other six rows
already exercise a shared or direct helper, or observe calls before a later
refusal can mask the mutation. This is a source audit. The repaired controls
and unchanged green tests still require Linux runtime RED/GREEN; no such
runtime result is claimed by Mac static checks.

## Fix-23 recovery and cleanup controls

All 401 earlier guard IDs, rules, test selectors and diagnostics remain.
Twenty-nine additions make 430 guards and 355 distinct mutation forms.
Ten physical rows remain blocked. The earlier opened-projection-state edit
now removes both its state predicate and the historical validator for the
same invalid-state case; this prevents the new check from masking that row.
Its ID, rule, focused test and expected diagnostic remain unchanged.

| Controls | Deciding regression |
| --- | --- |
| projection-prepared-key, projection-fixture-key | TestProjectionKey distinguishes the prepared gate from authority identity and rejects an alias. |
| prepare-workspace-pin, prepare-turn-pin, prepare-policy-pin | TestPrepareFields requires each bound recovery field before writer intent access. |
| plan-transient-state, plan-joined-retry, child-transient-state | TestTransientPlan and TestTransientChild preserve the original reservation and claimed child through reconciliation. |
| plan-error-code-value | TestPlanFailAtomic compares full error values after the retained JSON round-trip, including the code. |
| cleanup-slot-input, cleanup-slot-plan, cleanup-slot-bound, cleanup-slot-carried | TestSlotEvidence retains input-only, planned, bound and carried resource selectors in atomic cleanup requests. |
| cleanup-injection-gap, cleanup-injection-value | TestInjectionGap requires explicit uncertainty or integrity issues for missing/corrupt injection outcomes. |
| opened-history-missing, opened-history-home, opened-history-targets, opened-history-source-key, opened-history-no-fence | TestOpenedReceipt rejects corrupted historical proof without requiring fresh opening authority. |
| cleanup-binding-check, cleanup-withdrawal-check, cleanup-prepare-check | TestCleanupGate rejects foreign bindings, invalid new withdrawals and missing original prepare effects. |
| replay-stage-slot, replay-stage-injection, replay-stage-runner | TestPlanStages compares retained results with the plan and never repeats a credential producer. |
| entry-claim-planner, entry-claim-lifecycle, entry-claim-revoke | TestClaimEntry rejects claimed generation one at the entry gate before downstream effects can mask it. |

The transient recovery test uses the existing CaptureControl wired through
Service.deps.Capture to launchFixtureAdmin. That implementation validates the
actual reservation, worker, allocation and cause and retains the resulting
binding. No duplicate fixture method or constant successful reply is added.
The error injection uses planError to retain typed codes and retryability.
Every test and control still needs its named Linux runtime RED/GREEN; static
compilation is a prerequisite rather than a substitute for those assertions.
The shared prepare-validator extension and native cleanup writer remain the
explicit owner requests in the product CONTRACT-GAPS.md.

## Fix-24 materialization-stage controls

The earlier Linux red run stopped at data-stage-claim in both builds. Its
edit removes ValidateLaunchDataStage, but materializedData later passes the
same retained claim to effectCompletion. A pending stage claim therefore
still returns an integrity error, masking the missing stage validator when
the test accepts any error. This downstream check remains at the current
candidate after the claim-entry and effect-table changes.

TestMaterializeStagePins retains its original refusal and worker-entry
assertions. Its claim and grants cases now also require the exact typed
invalid_request error and message from their respective stage validation
rules. A later completion-claim integrity error cannot satisfy the claim
case. The grants case similarly requires the narrow-job grant refusal.
The mutation edits, IDs, rules, test selectors and expected diagnostics are
unchanged; no production validation is removed.

The complete four-row data-stage-* source sweep also covers parent and
absence. The parent edit removes its original-parent comparison and leaves
otherwise coherent stage facts. The absence edit attempts DataWorker entry;
the existing materialize-entry counter detects that attempt even if the
worker independently refuses to replace the retained stage. These rows
need no edit. Counts remain 430 guards, 355 distinct source forms and ten
blocked physical rows. This is source tracing and static verification;
named Linux runtime RED followed by unchanged GREEN is still required.

## Fix-25 full-tail masking sweep and survivor aggregation

The subsequent Linux run reached data-measured-completion after the earlier
claim correction. Its result case removed an outcome from a completed effect,
so effectRecord rejected the malformed terminal record before the deciding
measured-completion guard. The case now replays the actual stage's retained
claimed record, with no completion yet. It retains the original refusal and
worker-entry assertion and also requires the exact containment_unknown
measured-completion error. The mutation edit and deciding diagnostic are intact.

The source sweep covers all 221 guard rows from data-measured-completion
through the end of the catalogue, including 178 distinct edits. The collector
epoch case could reach the later writer fence after native removal and fail
under a different preservation diagnostic. Its named refusal assertion now
also observes zero collector calls for the epoch and claim entry gates, so
a later conflict cannot mask an attempted removal. Both original diagnostics
and the independent object-preservation assertion remain. Other tail rows
retain their edits and assertions. Runtime RED/GREEN is still required for
the whole tail; a static trace is not a runtime pass.

red.py now accumulates each surviving row with its ID and reason, continues
through every selected guard, and still runs the unmodified focused packages.
Any survivor makes the final exit 1 and prevents PASS. Build failures, missing
named tests, panics, malformed output and unfinished tests remain fatal invalid
evidence. The runner unit regressions exercise mixed detected/surviving rows,
normal/faults propagation, fatal evidence and baseline failure with explicit
input event histories. They do not supply Go mutation or native acceptance
evidence. Counts remain 430 guards, 355 distinct source forms and ten blocked
physical rows; the entire catalogue is unchanged.

## Fix-26 shared cleanup and loop adoption

Lifecycle now aliases the promoted api.PlanCleanup/api.FailedPlanStore types
and validates the failed revision and batch before calling the shared port.
The fixture independently validates that same batch under its writer lock;
ordinary Transact still cannot commit a failed planner revision. Existing
runner-pin, receipt/claim, partial-binding and policy assertions remain intact.

The shared batch requires an actual SlotResult reference and has no SlotInput
field. TestSlotEvidence first requires the missing-result preflight refusal
without changes to the original plan, input, resources or outbox. It then
restores the actual retained receipt index, or journals the actual carried
slot through the production stage, and still requires the atomic failed write.
The original deciding diagnostic remains. TestPlanFailAtomic also exercises
the local paired-jobs check directly so the shared ordinary-write refusal
cannot mask that check. The uncertainty edit follows cleanupIssue's owning
error normalization with the same rule, test and diagnostic.
TestPlanStages directly checks a retained slot conflict and unchanged state
when strict shared preflight prevents any cleanup job from committing.

ReserveLoop accepts only an API-bound installed scheduler scope, selects the
actual setting/end and verifies the writer's causal reply. Planning reads a
private canonical LoopTurnCause manifest and preserves its selected idle task,
new logical turn, planning effect and retained budget/session/home. The fixture
models actual retained events, shared validation, a pending PlanLaunch outbox
and an exact scheduler lane.turn audit; it makes no native identity claim.

Eleven additions make 441 guards and 366 distinct source forms. All 430 prior
IDs and rules remain; ten physical rows stay blocked.
The added controls cover shared preflight, error ownership, private scheduler
scope, manifest reading/turn/effect/value, causal writer reply, claim turn,
selected idle bytes and the writer's protected cancellation fence. All need
their named Linux RED followed by unchanged GREEN; static vet is not RED.

## Fix-27 survivor diagnostics

The d4fix27 red run found six controls whose focused test path or expected
diagnostic did not describe the assertion that actually failed. The policy,
fresh-receipt, completed-reply and nil-context rows now select the exact
failing subtest. The collector epoch row records the earlier
`collector published an unverified removal` assertion, which runs before its
later object-preservation message. The loop idle-source row records
`loop planner lost its retained causal pins`, because the retained-task guard
now rejects the missing task before prompt rendering. These catalog changes
keep every mutation and test assertion intact while making the red runner name
the failure it actually measures.
