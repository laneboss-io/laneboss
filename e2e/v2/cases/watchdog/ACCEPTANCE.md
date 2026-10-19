# Watchdog acceptance and mutation map

The supervising Linux run reported the previous package passing in normal and
laneboss_faults modes. That does not cover this draft.4 port. Durable internal
intent/wait/cancellation and typed eligibility are now authored; actual lifecycle
slot/launch, service scheduling and OS protection remain separate runtime gates.
All new positive/red tests below still need Linux execution.

`mutations.py` is the executable catalog: every entry names the source file,
the exact removed/inverted guard, and the focused test. `red.py --mutation ID`
applies exactly that entry to a retained isolated copy, checks that only its
declared source changed, runs the named test, and reports actual failed tests.
No changed anchor, compile/import error, panic, missing test or surviving mutant
earns a kill. Normal candidate checks run before and after the selected red.
Each Go phase compiles and retains watchdog.test, records its bytes/hash and
build output, and runs that exact executable through go tool test2json. The
observer phase retains its source inventory and structured unittest events.

There are two evidence scopes. **Component** means a Go watchdog guard with
fake outside dependencies; it does not prove OS containment or a live runner.
**Observer** means the existing CLI-case assertion is mutated and tested with
bad observation inputs. It proves the acceptance observer rejects those inputs;
it does not prove a service can create the good trace. The public `run.sh` case
still uses the installed CLI, real capture/room blobs, actual processes and the
harness's independent observations. Neither scope substitutes for that case.

## Each clause of the lane's acceptance section

| Rule | Named mutation(s) | Test that must fail | Scope / remaining gate |
| --- | --- | --- | --- |
| A validated external quota is required | `capture`, `adapter`, `L1-stream`, `L1-format` | TestQuotaValidation/quote; TestEvidenceRedControls with no-adapter-limit; TestTextNeverStructured | Component. Pin/authenticate actual vendor output and primary capture on Linux. |
| Real exit, quiescence and process generation precede B | `containment`, `run-binding`, `exit-clock` | TestEvidenceRedControls with nil-survivors or pid-reuse; TestClockReceipts/exit | Component. Actual Stop/drain/endpoint revocation belongs to the coordinated runtime gate. |
| B is current, delegated, same driver/provider and budgeted | `profile-scope`, `grant-live`, `grant-recheck`, `paid-budget`, `budget-empty`, `model-exclusion`, `eligibility-binding` | TestEligibilityDoesNotExpand; TestGrantValidity/revoked; TestEvidenceRedControls with changed-grants; TestLaneGates/budget; TestEligibilityReceipts | Component. Typed model/session/history and exclusion receipts are checked. Lifecycle must recheck current authority at the claim. |
| B has fresh outside room and retained proof | `room`, `room-clock`, `final-room`, `final-grant`, `obs-room` | TestEvidenceRedControls with expired-room; TestClockReceipts room/final-room/final-grant; CheckTests.test_room | Component + observer. Real usage worker/broker receipt remains an E2E dependency. |
| Same logical turn | `obs-turn` | CheckTests.test_turn | Observer. Atomic Continue must consume the same stored logical-turn intent. |
| Same session, private home and history | `obs-history`, `obs-history-id`, `turn-snapshot` | CheckTests.test_history; CheckTests.test_history_id; TestTurnSnapshot | Observer + component. CLI also requires nonempty unchanged history ID, exact retained task, and unpredictable nonce recall. Actual slot/home isolation remains a runtime gate. |
| Exactly one next run | `obs-next-run` | CheckTests.test_run | Observer. `continue-twice` is blocked: no production consumed-once claim exists yet. |
| Quota does not become a task failure/retry | `obs-failure`, `counter-reset`, `obs-counters` | CheckTests.test_quota_failure; TestIntentHandoff; CheckTests.test_counters | Component counter-reset zeros the actual submitted Go accounting. Observer checks counter equality and quota-end annotation independently. |
| Remaining budgets never reset | `budget-reset`, `obs-budget`, `budget-empty`, `paid-budget` | TestIntentHandoff; CheckTests.test_budget; TestLaneGates/budget; TestEligibilityDoesNotExpand | Observer + component. Actual launch accounting must be tested after Continue exists. |
| Exhausted profiles cannot be selected | `no-room` | TestPlanInvariants/no-room; TestWaitJournal | Component selection and durable profile_wait/dashboard event journal. Actual service notification/scheduling still needs integration. |
| Waiting uses bounded service backoff | `backoff`, `backoff-bound`, `obs-wait` | TestRecoveryGates/early; TestBackoffAndInitialization; TestWaitJournal; CheckTests.test_wait | Component durable wait/backoff + observer. Actual service scheduler must call Reconcile across restarts. |
| Restored room resumes once | `obs-restore`, `obs-next-run` | CheckTests.test_restore; CheckTests.test_run | Observer. Actual slot/claim execution is `slot-double-lease` / `continue-twice`, blocked. |
| Manual stop prevents a stale continuation | `cancel-mark`, `cancel-recovery`, `stale-run`, `obs-stop`, `intent-epoch`, `durable-cancel`, `cancelled-intent` | TestRecordedControl/watchdog.cancelled; TestRecoveryGates/cancelled; TestLaneGates/stale-run; CheckTests.test_stop; TestWaitEpoch; TestCancelJournal; TestCancelledIntentPriority | Component durable cancellation/epoch + observer. Actual lifecycle control must use the same store boundary. |
| Manual resume and pending swap cannot duplicate a turn | `manual-cas`, `obs-resume`, `commit-life`, `commit-grants`, `commit-intent`, `commit-epoch`, `intent-replay` | TestEvidenceRedControls with manual-race; CheckTests.test_resume; TestCommitCAS; TestIntentReplay | Component final-read and submitted atomic CAS/guard + observer. Actual consume-once lifecycle claim remains required. |
| Forged or quoted limit cannot trigger rotation | `capture`, `origin`, `actor`, `obs-tamper` | TestQuotaValidation/quote; TestEvidenceRedControls with imported-capture/lane-capture; CheckTests.test_tamper | Component + observer. Actual lane-facing forged RPC/event rejection still needs the service/identity fixture. |
| Lane file/signal/kill attempts cannot disable watchdog | `obs-canary`; `disable-watchdog` | CheckTests.test_canary; WATCHDOG-TAMPER in the actual CLI case | Observer rejects a reported allowed probe. `disable-watchdog` remains blocked until real OS canaries prove targets exist, remain unchanged/alive and probes are confined. |
| A real limit after the attempted tamper still works | `obs-real-limit` | CheckTests.test_real_limit | Observer. The CLI case demands a subsequent actual validated limit and continuation. |
| Actor validation cannot be bypassed or borrow mail sender | `actor`, `obs-actor` | TestEvidenceRedControls with lane-capture; CheckTests.test_actor | Component + observer. Authenticate peer and derive the actual watchdog actor outside the lane. |
| Capture validation cannot be bypassed | `capture`, `blob-hash`, `obs-capture` | TestQuotaValidation/quote; TestCaptureBytesHash; CheckTests.test_capture | Component + observer. Real primary range/hash provenance and gap-free capture still need the outside supervisor. |
| Room validation cannot be bypassed | `room`, `obs-room` | TestEvidenceRedControls with expired-room; CheckTests.test_room | Component + observer. No lane RPC supplies a room receipt. |
| Logical-turn mail is delivered exactly once | `obs-mail` | CheckTests.test_mail | Observer. Actual mailbox claim/acknowledgment must share continuation accounting; quota exit alone cannot acknowledge/return mail. |

The original L2–L4 review guards remain named in `mutations.py` and run with
the same protocol. The current catalog has 108 component and 38 observer
mutations, 146 total. Additional bad inputs are table data rather than new command policy.
`obs-valid` inverts the session-equality assertion and must fail the healthy
observation control; accepting bad traces and rejecting healthy ones are both
failures. `stopped-mark`, `cleaned` and `forged-recovery` cover the remaining
recorded-control variants in the component tests.

## Draft.4 port-review additions

| Review requirement | Named controls | Required failure |
| --- | --- | --- |
| Fresh pending replay | pending-room, pending-eligibility, pending-context, stale-room-reassess, stale-eligibility-reassess, malformed-reassess | TestPendingFreshness requires one new room check for stale receipts, with no old Swap dispatch; current authority failures do not replan. TestPendingReassessment progresses with newly measured receipts under continuation CAS and preserves a concurrent claim. TestPendingMalformed refuses malformed receipts without renewal. |
| Running retained turn | turn-status, turn-snapshot | TestTurnSnapshot/status and /task reject the independent status and task defects. |
| Live-only cancellation | no-live-cancel, terminal-cancel, cancel-next-run, cancel-wait-state, cancel-double-epoch | TestCancelWithoutLiveIntent, TestCancelClaimedNextRun, TestCancelJournal/waiting and TestCancelAdvancedEpoch fail if no-op, run-pair, state or epoch rules are removed. |
| All service controls precede backoff | origin, life-control, turn-control, pending-control, cancel-recovery | TestEvidenceRedControls / observation-capture; TestControlActorsAndScope; TestTurnControlSequence/new-run; TestPendingControl/pending; TestRecoveryGates/cancelled. The initial-turn-before-launch positive must still pass. |
| Own turn follows launch | own-turn-order, turn-run-scope | TestOwnTurnAfterLaunch requires its actual continuation; TestTurnRunScope keeps older-run and continued same-turn announcements from superseding it. The different-turn negative remains. |
| Old-run cancellation preserves next run | cancel-next-epoch | TestCancelClaimedNextRun requires an unchanged life/epoch and no life write while cancelling the retained old intent. |
| Outside usage authenticity | usage-producer, usage-freshness, usage-exhaustion, usage-source, usage-private, obs-usage-retention | TestUsageEvidence rejects changed producer, stale/pre-exit/non-exhausted usage, mismatched rehashed TSV and lane-owned raw bytes. TestUsageRetention and observer reference checks retain the exact normalized evidence. Real worker/native/vendor acceptance remains separate. |
| Current policy and retained replay | policy-refresh, policy-receipt, policy-history, retained-policy-replay | TestFreshPolicy checks refreshed fences and unchanged historical objects; TestPolicyRefreshReceipt and TestPolicyHistory reject changed facts; TestRetainedPolicyReplay preserves the completed snapshot after drift. |
| Human-reader refusal classification | obs-human-refusal | CheckTests.test_human_peer_refusal requires reached Failure for available/unspecified handoff; only explicit context human_reader_handoff_available=false makes the refusal a missing-fixture SetupFailure. |
| Current durable wait, no reset | waiting-record, waiting-delay, waiting-time, waiting-operation | TestWaitingHistory rejects missing/current-orphan waits, shrinking delays and early records. Unrelated outside room receipts remain fresh so they cannot mask a removed history guard. |
| Policy, closed classes, one limit | policy-exclusion, task-class, capture-class, blob-class, limit-duplicates | TestPolicyExclusion, corresponding TestEvidenceRedControls class rows and TestOneLimitEvent. TestSelectedCandidateOnly preserves healthy C when rejected B expires. |
| Reached failure classification | obs-reached, obs-runtime-error, obs-missing-exit | CheckTests.test_reached_failures, test_runtime_cli_errors and test_missing_optional_fields. test_run_error_recording covers full Case.run exception handling. Missing human peers remain setup failures, never kills. |
| Real restore observation and races | obs-restore, obs-stop, obs-resume | test_restore rejects advancement before restoration; test_healthy_restore remains positive. test_stop includes a second stop after the bad launch, exposing any use of the last stop. test_race_receipts_and_quiescence requires operation awaits and the resumed run's quiescence. |

These controls are authored, not measured candidate/red results on this Mac.
The independent human-reader handoff remains an integration request in
CONTRACT-GAPS.md. Fix 10 answers operation stamping/sharing and is consumed
through api.ValidateContinuationOperation. InternalIntent.ID is distinct;
there is no alias acceptance path.

## Fix 10 controls

| Contract fact | Control and deciding assertion |
| --- | --- |
| One actual operation, no foreign or intent-ID fallback | operation-binding retains TestOperationBinding; TestFix10Operation adds returned-ID, internal-ID and changed-operation cases. |
| Pending/claimed never report succeeded | shared-operation-phase targets TestFix10Operation/pending-success; shared-selection-phase targets TestFix10SelectionReceipt's no-Continue assertion. |
| Completed replay needs the same succeeded receipt | completed-receipt retains TestCompletedReplay and now removes the shared validator; a completion-during-Continue positive is separate. |
| Current life matches reserved pins | reserved-life-pins targets TestFix10LaunchPins/role; the table also checks level and driver. |
| A D6 capture exception does not authorize continuation | capture-disposition targets TestFix10LaunchPins/refused; capture-refusal-event targets TestFix10RefusedEvent before backoff and during pending recovery. |
| Registered capture has a known drain and live binding | capture-eof targets TestFix10LaunchPins/eof; live-capture-binding targets TestEvidenceRedControls/capture-binding. |
| Installed CLI observations correlate capture/operation IDs | obs-live-binding and obs-shared-operation target test_live_capture_binding and test_operation_lineage. |

All existing entries remain. New positive/red execution is pending on Linux.

## One mutation or the executable matrix

On the authorized disposable Linux box, from the checkout:

```sh
python3 -B e2e/v2/cases/watchdog/red.py \
  --source-root "$(pwd -P)" \
  --evidence-root /test/evidence/watchdog-one \
  --mutation obs-mail
```

Omit `--mutation` or use `--mutation all` for the executable matrix. Add
`--faults` with another new evidence directory to run Go checks with the
laneboss_faults build tag. Python observer checks are independent of Go tags.
`--list` prints the exact edits/tests plus blocked controls; it still runs only
on the authorized Linux box. Every result explicitly says component/observer
scope and leaves product_acceptance_complete false.

Selecting `slot-double-lease`, `continue-twice` or `disable-watchdog` writes an unreached/not-killed
not_implemented receipt and exits 69. It never changes a nonexistent guard,
skips a required product cell as a pass, or credits setup failure as red.

## Work still required

1. Confirm shared intent status/operation stamping and cancellation cause precision
   in CONTRACT-GAPS.md; the former draft.1 API gaps are superseded.
2. Finish lifecycle's one-owner slot claim/transfer, actual Continue/launch,
   remaining-budget accounting and logical-turn mail using the new ports.
3. Exercise the implemented Cancel/intent recovery against the actual shared
   life/epoch transactions used by manual stop/resume, loops and revocation.
4. Finish the external provider/usage fixture, root grants/binding and actual
   file/signal canaries and independent human dashboard reader, then execute the
   public CLI case. No fixture or
   observer-unit result passes an authenticated live-service cell.
5. Re-run every product guarding mutation against the actual installed final
   binary when those checks exist, retain bytes/hashes and obtain independent
   review. Current unit passes and observer kills are insufficient.

## Draft.3 additions

TestIntentHandoff requires committed life/grants/intent comparisons and the epoch
guard, exact selected eligibility, original causal requester, no loose Acquire,
and unchanged task/counters/budget/history. TestIntentReplay and
TestLostContinuationReply require reuse of the same retained intent and request.
TestClaimRecovery keeps a previously claimed slot and handles an already visible
next run without another acquisition. TestCompletedReplay reads the actual
stored operation; it cannot fabricate one during a store outage or return pending
as completed (completed-receipt). TestCommitRecovery exercises a legitimate
claim/cancellation racing commit read-back (claim-readback). TestOperationBinding
rejects another operation returned by Continue (operation-binding). The
commit-readback mutation must fail TestJournalFailures/missing-write.

The observer additions include obs-task, obs-eligibility and obs-epoch, targeting
test_task, test_eligibility and test_epoch. obs-independent requires the independent
canary to prove a real target existed; obs-restart requires the durable history
to survive restart. The obs-control-nonce, obs-control-exit,
obs-control-containment and obs-control-writer mutations target controls.py and
its corresponding test_control_* checks. These remain observer-scope checks,
with synthetic controller responses and fragment observations in unit tests.
Actual protection, transport, controller execution and restart evidence must
come from the independent Linux harness. WATCHDOG-RESTART is an additional
installed-service assertion; absence of its controller never passes it.

## Draft.4 additions

| Rule | Mutation | Required failing test | Scope |
| --- | --- | --- | --- |
| The single submitted Swap retains every continuation fence | swap-fence | TestIntentHandoff | Component; original generation/epoch/eligibility assertions are retained. |
| Historical exact-run snapshots cannot authorize current work | current-run | TestCurrentRunSnapshot | Component assessment, recovery and cancellation use internal run zero. |
| A free source cannot automatically change to paid | paid-escalation | TestPaidProfileAffinity/free-to-paid | Component; same-payment paid continuation still needs positive spend. |
| The draft.4 write/event/effect/guard catalog is checked before the writer | write-preflight | TestWriteCatalogPreflight | Component with actual submitted continue/cancel positive controls and foreign-domain negative inputs. |
| Human dashboard reads supply a session proof and human binding | obs-human-read, obs-dashboard-scope | CheckTests.test_human_cli | Observer CLI argument/input preparation only. |
| New CLI invocations select fresh human session proofs | obs-fresh-session | CheckTests.test_human_cli | Observer exact proof-file selection; the common CLI owns session setup/lifetime. |

The actual L6 process cannot acquire human kernel identity by selecting those
files. CONTRACT-GAPS.md requests the independent human-reader harness handoff;
the installed case remains incomplete until it exists. No dummy session or
weaker dashboard assertion substitutes for it. The existing no-room restoration
anchor is narrowed to its branch; its assertion is unchanged.

## d4fix13 deciding controls

| Requirement | Recipes | Named assertion |
| --- | --- | --- |
| Policy publish during wait | waiting-policy-backoff | TestWaitingPolicyBackoff keeps life/intent unchanged during backoff, then refreshes once and commits consistent fences. |
| Refused evidence precedes policy writes | limit-policy-order, pending-policy-order | TestRefusedLimitPolicyStable and TestPendingPolicyRefusalStable retain the original life when fresh evidence refuses. |
| Pending usage age | pending-usage-age, pending-usage-boundary | TestPendingUsageAge remeasures fifty-second usage with live room/eligibility and preserves the exact thirty-second positive. |
| Invalid pending envelope | pending-usage-future, pending-usage-target | TestPendingUsageEnvelope refuses future or foreign-target data without dispatch or reassessment. |

The old normalized envelope's bytes/hash must remain unchanged when a real new
measurement is retained. Static checks do not satisfy these runtime assertions.
