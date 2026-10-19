# Wave-0 classifier review disposition

All review security concerns remain suspected until the supervisor runs the
Linux tests/canaries. The changes below are authored fixes and static-checked
code, not a claim that a canary or live vendor test has passed.

| Finding | Change | Regression / deliberate red control |
| --- | --- | --- |
| L1, Claude 4/5 and Gemini 4 | Only JSONLines stdout is parsed as provider JSON. Stderr and headless stdout are text. Outcome records Format. Pretty-printed braces in text do not abort another real limit. | TestTextNeverStructured; L1-stream restores the old trust confusion, L1-format drops the recorded format. |
| L2, Claude 6 | Skip records over 1 MiB before decoding/UTF-8 validation and count OversizedRecords. Continue at the original byte offset and line number. Exactly 1 MiB is parsed. | TestOversizedRecordThenLimit; L2-size restores abort-on-large-record. |
| L3, Gemini 3 | Evaluate message text before codes; replace a candidate with a later sourced signal of the same kind on the same original line. | TestSourcedSignalWins; L3-source disables replacement across result/errors. |
| L4, Gemini 6 | Split CR/LF messages, inspect embedded API Error 401/429 objects only inside structured stdout, and inspect nested error fields through depth 2. Auth/rate diagnostics remain separate from quota. | TestNestedMultilineErrors; L4-lines, L4-api, L4-nested and L4-depth remove each boundary. |
| H6, synthetic credential assignments | No auth/home tests or synthetic login assignments are ported. Classifier and watchdog evidence fixtures contain names/handles and runtime hashes, with no credential values. | Publication/source credential scanning remains the supervisor's gate; staging/scan was assigned to laneboss in the follow-up. |
| Claude 9, unsourced Codex variants | Remove the two undocumented “You have …” variants. Codex wording/codes that remain are candidate diagnostics and cannot authorize Claudock continuation. | TestQuotesAndGenericExits checks both variants stay unmatched. |

The port also rejects duplicate JSON members, trailing JSON and excessive
JSON nesting. Original bytes, including CR/LF, determine all diagnostic
offsets/hashes. Auth/rate outcomes, ordinary assistant/tool/user text, generic
exit codes, malformed capture and a wrong format/driver never become swap
authority. No original diagnostic text is copied into Outcome.

The service assessment requires outside actor/provenance, exact capture blob
hashes, contiguous primary stdout, a matching bound launch/process generation,
an actual exited observation with an explicit zero survivor count, pinned
adapter corroboration, current revalidated grants, same provider/driver,
remaining budget, exhausted A and fresh room receipts. Worker errors remain
errors. Actor/containment/room source mutations exercise those negative tests.

The assessment supports bounded complete capture ranges; the quota envelope
must be covered by the selected CaptureRecord. A quota envelope split across
records is not inferred from a partial adapter record. Cut/unknown/not-written
prompt evidence requires explicit lifecycle recovery. These paths fail and
do not duplicate a prompt or mail. The draft.3 port now journals durable waits,
cancellation and typed internal continuation requests. Actual slot/launch/mail
work still belongs to the lifecycle, broker and messaging consumers described
in CONTRACT.md.

The red runner retains source copies, mutations, command exits and JSON test
events. It requires a named test run and failure, so a compile/setup crash
cannot count as a killed mutation. Neither the unit tests, the mutation
runner nor the public CLI case was executed on the authoring Mac. The
supervisor must run them on the authorized disposable Linux box before
crediting any runtime or red-to-green result.

## Follow-up: changed-byte control and mutation runner

The supervisor's Linux package run reported changed-bytes returning not_found
instead of the expected integrity. The old fixture wrote the correct blob ID,
but replaced its body with a shorter string while retaining the original
BlobRef size. The reader consumed that short chunk and requested the remainder;
the mock then returned not_found before complete-body hash verification.

The fixed control resolves the ID from the CaptureRecord, preserves the
declared length/hash, and changes a trailing JSON newline to a space. It asserts
that the body is still present, has a different digest, and remains recognized
as the same structured quota outcome. Missing-blob is a separate negative
control. TestCaptureBytesHash requires the exact complete-blob verification
error and no returned bytes. Removing only the final blob hash comparison is
the new guarding mutation. The production error ordering and the existing
changed-bytes integrity expectation are unchanged.

The mutation runner also had a source filename shadowed by its module-copy
loop. It now keeps source/module names separate and compares every isolated
input with the retained candidate before testing. Each mutant must change
exactly the intended Go source, with go.mod/go.sum unchanged. Actor, containment
and room mutations target their exact subtests; crashes and compile errors
receive no credit. The runner supports normal and laneboss_faults modes.
These follow-up changes still need execution on Linux; local static checks
alone do not establish that the repaired control or all mutations passed.

## Current mutation coverage and clock receipts

The next supervising brief reports the repaired package passing normally and
with laneboss_faults on Linux. The acceptance-clause map and executable
catalog now separate component guards from observer assertions and leave
unimplemented production mechanisms explicitly blocked. Each selected mutation
must change only its declared file and fail its named test, with no crash or
compile failure credited. New observer inputs are synthetic unit projections;
they are not OS canaries or working-service evidence.

Suspected from source: assessment's pre-call timestamp was used to validate
receipts issued during a later dependency call. The assessment now reads the
clock after observation/room calls and after blob/final reads, rejecting
expired grants/room while accepting fresh receipts generated during the call.
TestClockReceipts covers those cases with advancing dependency callbacks.
The corresponding exit-clock, room-clock, final-room and final-grant mutations
must fail those focused tests. These new changes still need a Linux run.

## Draft.3 port

The latest supervising brief reports the prior slice passing on integration
tree 8716945 in both modes. That result does not cover this draft.3 port.
All L1–L4, H6, byte/hash, provenance, quiescence, scope, clock and recovery red
controls remain. The store/Continuation signatures are ported without deleting
their assertions. Tests that formerly expected a coordination not_implemented
now verify the actual dependency stub fails before any launch/loose lease.

New component tests exercise retained turn/task and typed eligibility receipts,
durable life/grants/intent CAS and epoch guards, no-room backoff/restoration,
restart/lost-reply reuse, cancellation before/after an intent and claimed-slot
reconciliation. Their test store applies the submitted comparisons rather than
rejecting an omitted guard on behalf of the implementation. The lifecycle probe
observes requests and does not simulate a real slot claim or process launch.

The CLI observer now checks the real draft.3 counters/history/task/epoch and
selected-profile receipt fields. It also consumes the frozen harness controller
for restart and independent confined canary evidence. Synthetic observer tests
exercise rejection of missing targets, lost restart history, changed nonces,
unknown containment and mixed response writers. These are observer tests; the
actual controller and OS cells still require the supervising Linux harness.

## Draft.4 port

ContinuationRequest's generation, cancellation epoch and eligibility assertions
move to the sole Swap fence without removal. Current-life reads use the now
specified internal run-zero lookup; historical exact-run snapshots remain useful
history but cannot authorize continuation/cancellation. New component controls
cover that distinction, free-to-paid refusal with positive spend, and draft.4
transaction catalog preflight before the writer. Continue/cancel transactions
remain internal, with no fabricated public method or reply.

The paid-budget negative fixture now uses an already paid source to isolate
its spend check from the independent free-to-paid refusal. Its original nil
selection, A-only usage checks and zero-side-effect assertions remain. A new
free-to-paid test retains that separate rule. The no-room restoration mutation
uses its unique branch context so restart restoration cannot make its anchor
ambiguous; its healthy restoration assertion is unchanged.

CLI case inputs use draft.4 bindings, explicit retained mutation keys and valid
report/task blob classes. Human dashboard reads prepare a separate binding and
fresh session proof per CLI invocation, with recording-only observer tests.
That preparation does not provide the missing independent human peer/harness
handoff; CONTRACT-GAPS.md records the exact owners and acceptance requirement.
No unit/observer result establishes actual authentication, OS isolation or a
working serve E2E. All runtime positive/red verification remains on Linux.

The final-room clock input keeps the independent eligibility receipt live for
one minute while room expires at thirty seconds. This isolates the existing
room guard: removing it cannot be masked by the newly added eligibility expiry.
The expected integrity refusal and zero-side-effect assertions are unchanged.
Neither candidate nor mutant execution on this source is claimed locally.

## Draft.4 d4fix1 review fixes

The supervisor's 0cfb817 baseline already removes all 13 wave-0 runnerhome
files. They are neither restored nor edited. This round changes only the two
assigned subtrees. Fable and Gemini item numbers below refer to their counted
port reviews. No runtime candidate or red result is claimed on this Mac.

| Review item | Result and focused controls |
| --- | --- |
| Fable 2; Gemini 4 | Pending replay rechecks current grant set, both profile expiries, revalidation, policy exclusions, running turn and current life. Room and eligibility use the clock after those reads. TestIntentReplay remains a within-freshness positive; TestPendingFreshness independently expires each receipt, advances time during a read, models an outage, expires grants and excludes the destination. pending-room, pending-eligibility and pending-context remove those guards. Stale pending selection refuses directly, as the brief requires. Claimed recovery instead retains its existing slot, including after a two-hour clock advance. |
| Fable 3; Gemini 5 operation IDs | CONTRACT-GAPS.md gives the exact turns.go/§14 stamping and shared-operation request. InternalIntent.ID is not specified as Operation.ID, so cause.ID is not substituted and arbitrary alternatives are not accepted. Cancellation clears old operation fields for the actual writer to stamp, synchronizes Swap fences, and verifies the stamped commit. TestOperationBinding retains strict refusal. This shared contract remains open. |
| Fable 4; Gemini 5 cancellation | Absent/completed/cancelled intents return without writes. A live cancellation leaves profile_wait, cancels a claimed old-run intent at the next current run, and preserves an executing process's state and slot. An already advanced control epoch is not bumped again. TestCancelWithoutLiveIntent, TestCancelJournal, TestCancelClaimedNextRun, TestCancelAdvancedEpoch and TestCancelUnsettledControl cover these paths. no-live-cancel, terminal-cancel, cancel-next-run, cancel-wait-state and cancel-double-epoch remove their guards. |
| Fable 5; Gemini 6 turn | Only running retained turns qualify. TestTurnSnapshot/task remains; TestTurnSnapshot/status rejects completed, failed, cancelled, empty and unknown values. turn-status removes only that status check. The free-form shared vocabulary still needs freezing. |
| Gemini 2 | Reached failures remain reached on assertion, omitted field, bad time/type and runtime unsupported/unavailable failures. Only named missing fixtures, including the independent human reader, are setup failures. Tests exercise both CLI errors and the full run error-recording path. Capture observation uses event.tail and blob.read; the final dashboard gate and actual refusals remain. obs-reached, obs-runtime-error and obs-missing-exit restore the bad classification/unknown-exit acceptance. |
| Gemini 3 | Authoritative evidence requires service origin. Control actors are not restricted to watchdog; run-zero controls, lane.lost, terminal state and later turns are honored before backoff and during pending/claimed recovery. Tests cover actors/scopes, next-run turns and the earlier initial-turn positive. origin, life-control, turn-control, pending-control and existing cancellation mutations remove these guards. |
| Gemini 4 waiting history | A waiting intent needs its own watchdog.waiting operation. Delays cannot shrink and each record must follow the preceding deadline. TestWaitingHistory and waiting-record/delay/time/operation exercise missing, orphaned and corrupt records without early broker polling. |
| Gemini 6 selection/evidence | Final expiry checks bind the selected destination, preserving healthy C when rejected B expires. TestSelectedCandidateOnly covers that ordering. Policy exclusions are checked before broker selection. Only the initial real limit emits watchdog.limit; no usage diagnostic invents a self-swap. Task/capture classes and the closed evidence class catalog are checked. TestOneLimitEvent, TestPolicyExclusion and the class controls cover those assertions. |
| Gemini 7 | The case awaits turn/stop/resume operations and resumed quiescence. The earliest successful stop fences every later launch, even with a second stopping event. Probe errors are specific to forge/file/signal; ENOENT is not protection. Clock mutations use actual pre-call timestamps. counter-reset and budget-reset now mutate Go journal accounting; obs-counters remains separate. obs-restore removes a guard against run advance while still exhausted; test_healthy_restore retains the positive restoration path. |

All newly authored tests and named red controls require execution on the
authorized disposable Linux machine. Compilation, vet and syntax checks do
not establish that a named mutant reached its assertion or was killed.
The installed case still needs actual store/lifecycle/broker/service behavior,
the independent human-reader handoff, and real OS/controller evidence. No
fixture or component probe is authenticated AI-service acceptance.

The cancelled-intent mutation now targets TestCancelledIntentPriority: after
an actual component cancellation, current life/event reads become unavailable.
The retained cancelled intent must still refuse immediately without those
reads. A cancellation marker therefore cannot mask removal of the direct
terminal-intent guard. The wait-history controls similarly refresh unrelated
room receipts so their guards cannot be masked by later stale-room failures.

## Draft.4 d4fix2 red diagnostics and static audit

The supervising Linux run on 848d152 reports the candidate unit builds/race
green and 45 observer checks passing. The plain/faults red runs stopped at
profile-scope after fifteen kills each. Those observations cover that revision,
not this follow-up's newly authored reporting tests or revised recipes.

The original profile-scope edit was reproduced statically in an isolated copy:
vet refuses evidence.go:125:45 with “redundant or: false || false”. Removing
driver/provider comparisons by inserting adjacent false operands fails vet
before the named test runs. The corrected edit removes those operands cleanly.
The original nil-selection/A-only-read assertions remain unchanged. The live,
unpaid driver/provider rows have no earlier exclusion or expiry guard masking
them; after guard removal they reach B's outside room check and selection.

red.py now derives killed / survived / not_reached / crashed / invalid_result from the
actual named test events and process exit. A survivor requires a named run
and pass with exit zero; build_failed is identified from the saved build exit.
Non-killed entries print bounded last output lines and retain complete logs.
Contradictory pass/fail events cannot earn a kill. New observer tests exercise
classification and build/test output previews without simulating a real swap.

Every recipe from profile-scope onward was applied to its own scratch copy,
outside the worktree. Exact anchors and resulting target bytes were checked.
All 62 Go mutants passed Linux, Linux+laneboss_faults and Darwin vet; all 34
observer mutants passed py_compile. The dependency walk also found that the
presence and operation checks both reject missing waiting history. The revised
waiting-record fault disables missing-history refusal in both while preserving
the present-record operation check. Its named test, expected integrity refusal
and independent waiting-operation entry remain unchanged. Corrected recipes
were re-vetted. No entry or assertion was removed or weakened.

Static validity is not a red kill. The full candidate/red matrix still needs
the authorized Linux run. Compile/setup failures remain stopped outcomes and
cannot satisfy product acceptance or mutation coverage.

## Draft.4 fix 10 consumer adoption

The supervisor reports 7dcd08e's plain/faults matrix green at 222/222 and its
observer checks passing. That is prior-source evidence. This adoption uses the
clean 4ad4c443 merge of fix 10 from 3803f4d; no shared API or other lane's code
is edited, and no commit or runtime test is performed on this Mac.

Fix 10 answers the operation request. CONTRACT-GAPS.md removes that request;
CONTRACT.md records the adopted rule. Authored intent/Swap operation fields
remain empty until the actual writer stamps its Commit.Operation.ID into both.
Pending selection, claim, slot handoff, swapped event, continued launch and
reconciliation use that same operation. Waiting journals and cancellation have
their own operations. InternalIntent.ID is never an accepted alternate ID.

Selection receipts, stored replay and lifecycle replies use the shared
api.ValidateContinuationOperation. A pending/claimed phase accepts only pending
or running, and completed requires succeeded. Continue reads its durable phase
back before interpreting the reply, allowing actual completion during the call.
There is no local-rule fallback after shared validation fails. Generic durable
life/run/sequence/error checks remain. The test journal now retains pending
selection receipts and changes to succeeded only with an explicit completed
test phase. TestFix10Operation, TestFix10SelectionReceipt, TestFix10StoreStamp,
TestOperationBinding and TestCompletedReplay cover these contracts.

The operation lookup happens before final pending authority/clock validation;
it cannot extend stale room/eligibility. TestFix10OperationLookupClock advances
the clock inside that read and requires refusal with no second Continue/slot.
Claimed recovery still reconciles its same existing slot after receipt expiry.
Operation-binding and completed-receipt retain their named tests and now remove
the shared validator. shared-operation-phase and shared-selection-phase cover
the new status rule and the no-dispatch requirement for an invalid stored result.

Assessment/pending recovery consume retained LaunchBinding, opened LaunchPlan
and CaptureState. The shared validators check complete plan/binding correlation,
agent kind, reserved pins and capture policy metadata; watchdog additionally
compares current level/role/driver/session/workspace with that reservation.
Registered capture requires known EOF positions for every bound stream. Refused
capture returns its actual owning error, even with an approved D6 exception for
launch; it never supplies quota evidence. capture.refused precedes backoff, and
new live CaptureRecords require their binding ID. TestFix10LaunchPins,
TestFix10RefusedEvent and the capture-binding evidence row cover those facts.
The complete shape fixtures compute JCS spec/record hashes from their actual
bytes; they are not native execution, D6 approval or OS-capture measurements.

The CLI observer correlates continued-launch OperationID with the swap and
requires live capture binding identity. obs-shared-operation and obs-live-binding
exercise those assertions. The catalog retains all prior entries and now has
108 component plus 38 observer controls. All 146 recipes require unique anchors;
static mutant validity does not establish a named red kill. The full normal/
faults candidate and red run remains required on authorized Linux. Human-reader,
cancellation-cause and turn-status requests remain open, as fix 10 specifies.

## Draft.4 d4fix11 operation read-back

The supervisor's acf0b58 Linux unit, faults and race runs each failed only
TestFix10Operation/swapped-operation: the lifecycle probe received a stale
request and reported integrity instead of the required invalid_request. The
test injected the replacement inside Continue, after watchdog could inspect it.
That reported failure is retained separately from this revision's static checks.

recordedOperation now reads the retained intent after looking up the original
observation's operation. api.ValidateContinuationOperation compares that fresh
intent and its Swap with the frozen original request and actual operation
record. A changed operation refuses directly with the shared typed error;
no lifecycle error is relabelled. Cancellation and dependency failures retain
their own errors. Both reads stay before final pending authority/clock checks.

The swapped-operation case and its typed assertion remain. Its fault now runs
in the operation-read callback, after the observation has retained its request
and before dispatch. It advances to claimed, replaces both operation fields
and retains a replacement operation while preserving the original receipt.
That isolates the fresh comparison: validating only the old snapshot would
pass. The case also requires that the fault ran, exactly one journal write,
zero lifecycle requests and zero acquisitions. The lifecycle probe is unchanged.

claimed-operation removes the fresh shared guard and names that exact case.
Without the guard the old operation remains shape-valid, pending authority
checks pass, and the unchanged probe returns integrity for the different Swap;
the retained invalid_request assertion therefore fails. completed-receipt and
shared-selection-phase follow the same guard's new anchor; all earlier catalog
entries and strict assertions remain. No static result establishes a red kill.

The clean c332c33 merge adds guidance and its CLI registration only. It changes
no watchdog / case / shared-API / continuation-contract source and introduces no
watchdog dependency on guidance. Its source is retained without edits here.
Candidate unit/faults/race and normal/faults red execution remain Linux gates.

## Draft.4 d4fix12 delta and fix 11

The brief reports the 8e5453a candidate unit/faults/race and 121-recipe matrix
green. Gemini approved that delta; Fable identified one suspected own-turn
false cancellation and four P3 changes. This source still requires Linux runs.

TestOwnTurnAfterLaunch was authored and archived with the old production guard
before the fix. The static path reaches the old sequence-only cancelled return;
its expected continuation assertion would fail. No runtime reproduction was
performed on this Mac. controlError now receives the retained turn identity and
compares logical turn, run and later sequence. The run's own post-launch turn
and next-run continuation are retained; a different later turn supersedes it.
The different-turn negative remains. own-turn-order and turn-run-scope name the
deciding assertions; the finding stays suspected until actual Linux execution.

Cancelling a claimed old-run intent under a current next run writes only the
intent under current fences. TestCancelClaimedNextRun requires an unchanged life
and epoch and no life write; cancel-next-epoch removes that boundary. Same-run
manual cancellation still advances its own fence exactly once.

Expired pending room/eligibility is distinguished from malformed/future/foreign
receipts and reassessed under the observed continuation CAS. TestPendingFreshness
requires exactly one new room check and no old Swap dispatch. TestPendingReassessment
models actual newly retained source receipts, successful progress and a concurrent
claim winning CAS. TestPendingMalformed forbids treating corruption as expiry.
stale-room-reassess, stale-eligibility-reassess and malformed-reassess isolate
those assertions. Waiting-history checks remain specific to waiting intents.

The dashboard classification now requires explicit context absence before a
forbidden/unauthenticated reply becomes SetupFailure. Its available and unspecified
contexts retain reached Failure. obs-human-refusal removes that distinction.

Fix 11 outside usage is required and retained by exact committed reference.
ValidateUsageSource checks actual five-column TSV bytes and protected profile
mapping. ValidateUsageWindow checks genuine usage-worker correlation, enrolled
runtime/executable/adapter, successful command, from-profile exhaustion, future
reset and post-exit freshness. Private object metadata is checked independently.
The explicit ResolveUsage installation binding cannot be supplied by envelope
labels; its missing owner implementation is a typed failing dependency. Aged
usage on reassessment is measured again through the real UsageWindowSource,
read back and fully revalidated before its new immutable reference is retained.
The causal capture/profile/run/exit facts and original limit event stay fixed.
Usage controls separate producer / freshness / exhaustion / source / private metadata;
the non-exhaustion fixture updates its raw percent too, so source validation
cannot mask the exhaustion control. The final-room clock fixture expires at
five seconds and advances six, keeping usage and eligibility live. Waiting-history
controls supply a fresh outside query so unrelated usage age cannot mask them.

Fresh planning advances current approved policy through protected RefreshLanePolicy
and validates its receipt/read-back before new fences. Historical launch/grant
hashes remain issuance facts; retained turn policy uses PolicyAt. Exact completed
replay keeps its snapshot. Tests and policy-refresh/receipt/history/replay controls
cover each distinction. No current-policy mismatch is treated as exhausted room.

The current catalog has 108 Go and 38 observer recipes, 146 total. All prior
named entries remain. Static validity does not establish reached red, actual
worker identity, an authenticated AI-service run or installed serve acceptance.

## Draft.4 d4fix13 delta read 2

The brief reports the 824e3f4 unit box green and its red box still running.
DELTA2 closes the five earlier items and refutes both scan suspicions. No
fail-open or gate-field defect is asserted here. Those reports cover the
baseline, not this delta; runtime reproduction and red remain Linux gates.

TestWaitingPolicyBackoff was authored and archived with old production source
first. It records a five-second no-room wait, publishes approved policy,
redelivers the same limit and reconciles during backoff, then requires a second
journal commit after the deadline. Early calls require unchanged life/intent and
zero refreshes. Later work requires exactly one refresh and matching current
life/continuation fences. Old code advances the life during the first early call,
so the unchanged-fence assertion would fail. This is a static trace, not an
executed reproduction. waiting-policy-backoff restores that early write.

Waiting recovery now checks backoff before policy refresh and before demanding
a selected-generation fence. Pending policy drift uses policyForLane and
PolicyGenerationFor read-only, routing to reassessment. TestPendingPolicyRefusalStable
and pending-policy-order check that refused fresh capture does not advance it.

Policy refresh moved after capture/exit/room/usage and candidate corroboration,
immediately before the final life read. It pins the selected approved policy and
updates the proposal's fence. Historical turn policy is checked read-only under
current authorization before that write. TestRefusedLimitPolicyStable covers
capture, usage-producer and room refusals. limit-policy-order restores early
refresh and fails its unchanged-life assertion. The strict policy-receipt error
test now requires the two preceding readonly room checks for this phase order.

Pending usage is read from its immutable normalized envelope before the final
clock check. TestPendingUsageAge isolates fifty-second usage while room and
eligibility remain live for a minute, requires a new outside fixture measurement
and reference, and checks unchanged old bytes/hash. Exact thirty-second, future
and foreign-target controls are separate. pending-usage-age / boundary / future / target
remove the deciding conditions. No stale window is relabelled current.

Room/eligibility controls expire at five seconds and advance six; the separate
new from-profile query is expired too. Their typed error, single new room read
and no-old-Swap assertions stay intact, with usage still younger than thirty
seconds. Removing either guard therefore reaches the old dispatch instead of
being masked by usage age. The two-hour outage remains.

CONTRACT-GAPS.md requests integrate's contract requirement for logical_turn_id
on every lane.turn from trusted retained state, including helper_open/mail_deliver.
The heuristic and hard run/turn/epoch/CAS fences remain unchanged.

The active catalog has 108 Go and 38 observer entries, 146 total. All 139 prior
IDs remain. Static checks establish no runtime assertion, kill, native producer
or installed service acceptance.
