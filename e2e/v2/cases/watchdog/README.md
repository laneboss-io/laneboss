# Watchdog acceptance

Run this case on the disposable Ubuntu 24.04 test box through the shared
v2 case runner. The only entry arguments are `--context FILE --result FILE`.
It never opens the service database, imports a concrete service, synthesizes
an authoritative capture, or invokes a swap API. Every product operation is
an installed CLI command with an explicit configuration and file input.

The case is ported to contracts draft.4. It cannot currently pass on
this checkout's remaining dependency stubs. Missing service, runner, broker, lifecycle, dashboard,
or fixture setup is a failing prerequisite, with `reached: false`. It does
not count as a killed red mutation. No candidate or red result is claimed
until the supervisor executes it on Linux.

## Setup owned by the test harness

`test_root/setup.json` is a retained, names-only setup document prepared by
the harness. It has schema `laneboss.watchdog-case.v2`, a `start` object
containing an authorized `api.StartRequest`, `task_file`/`mail_file` paths,
a `review` object containing authentic `api.ReviewRequest` evidence for the
unchanged disposable fixture workspace, and a `control` relative path
under test_root. The entry fills each review target from the actual life;
the reviewing parent must be distinct from its child executor. The service
must validate the real diff/check/inventory receipts before collection.
`start.driver` must be `claudock-cli` and its selected
profile grant must be in the context's profile_grant_ids, with at least two
explicitly enrolled/delegated same-provider profiles. The start task is an
uploaded immutable task BlobRef. Use a bound L6 test caller able to start
these L3 children; do not substitute a human UID for human authentication.
The installed binding must be the context's binding_file. Every CLI call passes
it explicitly with --binding, alongside --config and the exact --request file.
The common CLI uses client.PrepareRequest; the case does not implement a second
request digest. Random request and idempotency IDs are retained with the input.
The binding must name v2.0-draft.4 and the context's actual artifact digest.
Each mutation has an explicit retained idempotency key and committed BlobRef
input. Mail/reason text uses report and continuation messages use task; no
invented mail/reason/message blob class is submitted.

Dashboard reads use a separately enrolled test reader. The outside harness may
supply `Case(context, human_reader=reader)`, or put an absolute `reader_binding`
file in setup.json for the standalone case. `reader.py` implements that socket
bridge. It checks the kernel peer, preflights the actual session before upload,
retains exact inputs and replies, and closes its reader after lane collection.
Selecting a binding file alone does not create a reader or its identity.

Run `reader.py --setup FILE` in the separately enrolled test identity. This
private setup has schema `laneboss.reader-setup.v1` and fields `config`, `binary`,
`human_binding`, `proof_file`, `evidence_root`, `socket`, and `case_uid`.
The harness creates the private evidence directory and socket parent first;
its socket group permits only the designated case to connect. `binary` is the
matched installed Laneboss executable. The reader invokes its `internal reader`
mode, so the public client's artifact check uses the same installed bytes.
The shared client computes the request digest and the service verifies the
fresh `human.session` on that same connection. No private store or signer is
installed in this adapter.

The case's protected bridge binding has schema `laneboss.watchdog-reader.v1`
and fields `config`, `socket`, `reader_uid`, `case_uid`, `binary_sha256`, and
`simulated_presence: true`. The harness supplies the actual enrolled UIDs and
the tested artifact digest. This mode requires a service-issued test proof
marked `simulated_presence`; a real human remains a typed `human.session` wait.
The bridge returns the actual stdout, stderr and exit from the installed reader,
including failed replies. Its session and process receipts stay with the
outside harness. The case retains its own socket inputs, outputs and close
receipt. The harness collects the exited bridge and its socket afterward.

The existing `human_reads` argument-selection utility retains exact fresh proof
bytes from an absolute installed binding and a private proofs_dir beneath
test_root. Proof files are named 00000001.json, 00000002.json and so on. This
utility can be used by an outside adapter; its observer test establishes only
argument/byte selection. The new native descriptor canary exercises actual
child inheritance and absence of unrelated descriptors, not human identity.
The process bridge has Linux transport tests, including a real reader child,
native socket credentials and measured collection. Those fixtures establish no
service enrollment, physical presence or authenticated vendor compatibility.
All six installed rows and live authentication remain acceptance gates.

The credential-free cell needs the Claudock lane's pinned structured-output
fixture and the secrets lane's external usage worker fixture. The harness
provides an outside-only control consumer for the case's control file. A
control document has `cell`, `phase`, and a random `nonce`. It is a fixture
input, never a product RPC or a lane-writable quota file. Acknowledgments
alone prove nothing: the case observes actual captures, room evidence,
process observations, events, mail receipts and new launches through the CLI.
The fixture phases are:

| Cell | Initial phase | Subsequent phase | Required real fixture behavior |
| --- | --- | --- | --- |
| limit | ready | limit | Execute the task, preserve its random token/history, exhaust A, report fresh external usage for A and room for B, then complete the same logical turn through B. |
| no-room | ready | exhausted, restored | Exhaust all delegated profiles; keep them exhausted through the wait observation, then restore B's room. |
| tamper | ready | attacks, limit | Have the confined task quote provider limit records in model/tool output, try a forged event/swap request, alter lane-local files and attempt an actual write/signal against outside watchdog control. Record syscall errno and targets in primary capture; then produce an authentic provider limit. |
| stop-race | ready | exhausted, restored | Hold exhausted room until manual stop and room restoration race. |
| resume-race | ready | exhausted, restored | Hold exhausted room until manual resume and room restoration race. |
| restart | ready | exhausted, restored | Preserve the durable exhausted-room wait across an actual service restart, then restore B and continue once. |

The fixture must consume the random nonce from the actual task and carry it
into the continued history, without putting the expected continuation answer
in the fixture's output. The tamper task reports its real canary results as
JSON in primary capture with type `watchdog_canary`, one result each for
`quote`, `forge`, `file`, `signal`. Each result contains `attempted: true`
and either the actual nonzero `errno` for an OS operation or a typed refused
RPC `code`. These are checked only alongside external no-swap observations
and the subsequent successful authentic limit. The harness independently
checks the target existed, remained unchanged/alive, and that the probe ran
inside the lane. Missing canaries are failures, not evidence of protection.

The `seed` phase completes run 1 after retaining the random history nonce.
The case then queues real mail and requests one logical turn. The task must
remain running in that mailed turn after ready. The external fixture supplies a
complete primary capture for each phase. It must not put a fake driver or
test-literal branch in production code. A fixture cell is separate from a
live vendor/authentication cell. This manifest authorizes no model request,
new login, paid fallback, machine, or credential transfer. To claim actual
vendor compatibility, repeat with separately authorized pinned real vendor
captures and real external usage evidence; fixture success is insufficient.

## Assertions and red controls

The case generates fresh lane names and control nonces, starts via the CLI,
reads complete event pages and capture blobs, reads the human dashboard lifecycle view, checks actual
containment, and retains every request/stdout/stderr/exit. Continuation must
add exactly one run, preserve session/home/workspace/logical turn, reference
the causing run and exact primary limit hash, preserve finite remaining
budgets, and retain mail on the logical turn until actual completion. No
watchdog event may use a carried mail sender as its actor.

No-room must emit bounded, increasing service backoff while in profile_wait;
restored room resumes exactly once. Stop racing restoration must leave no
running process and no continuation after the stop commits. Manual resume
racing restoration may win or lose the CAS, but total new runs is exactly
one, and an old watchdog cannot resume the new logical turn.

Run each guarding mutation with its distinct source/binary digest and the
same case entry in red phase. Required mutations are missing limit/capture
validation, missing actor validation, stale/forged room acceptance, duplicate
logical-turn mail, missing cancellation, and duplicate continuation. The
independent harness must require the targeted assertion to be reached and
fail for its operation evidence; a setup crash is not a killed mutation.

Draft.4 retains Lane.Counters, CancellationEpoch, Task and Session.HistoryID.
The case requires the exact failure/retry counters and original task to survive,
requires a nonempty unchanged history identity as well as actual random-token
recall, and checks typed selected-grant / eligibility / generation / epoch fields.
The continued LaunchEvent must retain the exact swap and original task.
These fields complement the actual quota end, launch, mail and budget receipts;
they do not establish live authentication by themselves.

## Frozen harness controls

The context's optional controls field names the protected harness binding from
the integration case's control.schema.json. It becomes a required prerequisite
for the dependent tamper/restart rows. setup.json additionally supplies canary_id
and restart with service_id and expected_generation. These are pre-enrolled
selectors. The case accepts no command, PID selector, unit name, host path or
arbitrary worker executable. The external E2E owner supplies the controller.

controls.py validates case/config/artifact/source/UID binding, Linux kernel peer
credentials and every response fragment's writer, bounded four-byte framing,
closed response fields, independently random request/nonce correlation, actual
exit/zero-survivor facts, and retained evidence length/hash. Bindings and evidence
are ordinary private files beneath protected directories; test_root and
evidence_root are ordinary, test-identity-owned 0700 directories. The binding is
root-owned (or owned by the same enrolled controller/case identity). Controller
evidence paths are relative to the case's evidence_root and remain within it.
Every refused controller reply is retained whole and fails the dependent row.

The fixed enrolled canary consumes an uploaded laneboss.watchdog-probe.v2 object
with target and an independent random nonce. It must retain real OS evidence
and exactly one laneboss.watchdog-canary.v2 report with that target/nonce and
three checks, one each for forge, file and signal. Each check records probe,
attempted, confined, target_present, denied and unchanged as actual facts. A
missing target is a failed check. The controller must independently establish
the protection and identity of those targets; lane stdout alone is insufficient.
The case still requires all original confined-task reports, no spurious swap,
and a subsequent real validated limit/continuation. No controller receipt can
replace the independent harness's real syscall/process evidence and review.

Restart consumes restart_service and requires the old process's measured exit
and a strictly newer service generation. The wait's run/session/history/task/
counters/epoch/turn must survive before room restoration. It then requires one
continued run and one mail completion through the same CLI observations.

Collection stops every created life through the authorized CLI and requires
an exited observation with an explicit zero survivor count. It reviews the
unchanged disposable workspace, marks abandoned, archives with matching
read-back hashes, cleans through the normal gate and checks cleaned/zero
survivors. It retains inputs and service records as evidence. It never removes
a dirty workspace or force-cleans a lane. On a failed assertion it stops owned
processes and retains workspaces for the supervisor; collection is incomplete.
A failed collection prevents acceptance.

## Classifier review regressions

The full acceptance-clause map, exact mutation names/tests, evidence scopes,
single-mutation command and remaining work are in [ACCEPTANCE.md](ACCEPTANCE.md).

`red.py --source-root CHECKOUT --evidence-root NEW_DIRECTORY` runs the unit
suite on Linux, then creates retained isolated source copies with deliberate
L1–L4 and actor/containment/room/blob-hash guarding mutations, requires each
named test or subtest to actually run and fail, and reruns the unchanged
candidate. Mutation receipts retain exact source inventories,
changed paths, build tags, exits and JSON test events. The runner checks that
only the intended source changed; module files must remain unchanged.
Compilation/setup failures, panics, a missing target test, or a successful
mutant cannot count as a killed mutation. Add `--faults` to repeat with
`-tags laneboss_faults`, using a different new evidence directory.

Each Go test-binary build and each test command has a separate 180-second
limit. Full Go and observer candidate checks run before mutations and again
after all mutations. A timeout during a focused mutation is not a candidate
failure or a credited kill; inspect its retained command and output.
`TestPendingUsageAge` advances only its injected clock. It asserts its journal
write bound inside the store callback as well as after reconciliation, so the
`pending-usage-boundary` mutation fails on its first unexpected replacement
instead of recursively reassessing at a fixed thirty-second age until timeout.
The expired case still requires one new measurement and replacement; the
boundary case still requires replay of the original request and evidence.

The executable catalog now includes 108 component guards and 38 separate observer
assertions. `--mutation ID` applies exactly one named mutation; the default
`all` runs the executable catalog. Each output names which tests actually
failed, whether the mutant was killed, and its component/observer scope.
Observer-unit checks use synthetic projections and do not establish a working
service, a controller transport or successful OS canaries. Counter-reset and
model-exclusion are executable now; slot-double-lease, continue-twice and
disable-watchdog still require their actual installed runtime mutations.
Selecting a blocked production control
writes an unreached/not-killed not_implemented receipt and exits 69. A successful
mutation phase explicitly leaves product acceptance incomplete.

The changed-bytes fixture mutates the body at the CaptureRecord's actual
BlobRef ID. It keeps the original length and declared hash, changes only a
trailing JSON newline to a space, and confirms the quota remains recognized.
The original short replacement accidentally exercised truncation: the mock
returned the shorter first chunk and then not_found on the remaining range.
Missing-blob now has its own control. TestCaptureBytesHash verifies that a
present body with truthful per-chunk hashes fails the complete-blob checksum;
the blob-hash mutation removes only that comparison and must fail this test.
The complete-blob verifier and the changed-bytes expected integrity code are
unchanged.

This is separate from the public CLI case and cannot pass WATCHDOG acceptance.
All test fixtures avoid synthetic credential assignments (H6). Neither entry
is executed on the authoring Mac; only py_compile is allowed.

## Draft.4 regression controls

ContinuationRequest has only IntentID and Swap. swap-fence exercises
TestIntentHandoff with all former generation/epoch/eligibility assertions kept
in Swap. current-run exercises TestCurrentRunSnapshot against a store that can
truthfully return historical exact-run projections. paid-escalation exercises
TestPaidProfileAffinity/free-to-paid with positive spend. The paid-budget
fixture uses an already paid source so the spend guard remains independently
necessary and its original assertion still fails when that guard is removed.

write-preflight exercises TestWriteCatalogPreflight: foreign grant/policy/judge/
channel/mail writes, foreign events/guards, internal replies, state-changing
reads and missing public mutation replies cannot reach the state writer.
The shared catalog is the store's structural contract, not command policy.
obs-human-read, obs-fresh-session and obs-dashboard-scope exercise test_human_cli
with recording subprocesses, checking proof/binding selection, fresh exact
proof bytes and unchanged configuration/lane binding. All privacy-checked test
directories are explicitly ordinary, owned and 0700. The no-room restoration
control rejects a new run while the fixture is still exhausted, and its
healthy restoration control remains separate from the restart cell.

## d4fix1 port-review controls

The reached flag is set before the first real lane operation in a cell.
Assertion failures, missing optional JSON fields, malformed time/type values
and runtime unsupported/unavailable errors remain failed reached assertions
with observed_exit 1. Only named missing fixtures or failures before the cell
are unreached. Raw capture reads use event.tail capture.appended/capture.gap
records with service origin and outside service/worker actors, then blob.read
with independent exact-byte/hash validation. They consume no human proof.
The final dashboard.lifecycle gate still requires the separate human peer
described in CONTRACT-GAPS.md; that known missing handoff is an unreached
setup failure, with the actual authentication refusal retained.

Turn, stop and resume operation receipts are awaited. Resume races require
the next run's outside zero-survivor observation. Every successful stop fences
later launches from the earliest stopping event, including when another stop
appears afterward. A stop that loses the CAS retries against the current run
within the existing bounded observation deadline and awaits the winning stop.

Tamper errors are probe-specific: forge requires forbidden, invalid_request
or unauthenticated; file requires errno 1, 13 or 30; signal requires 1, 3 or 13.
ENOENT (2) is always a missing target, never protection. Signal ESRCH (3) still
requires the independent confined canary's target-present and unchanged facts.
Neither a lane report nor an observer unit projection proves OS protection.

exit-clock and room-clock substitute the actual pre-call timestamps.
counter-reset and budget-reset mutate the Go journal's preserved accounting;
obs-counters and obs-budget independently mutate the CLI observer. obs-restore
removes only the exhausted-room run guard against a bad trace; it does not
change the fixture's restore action. New pending, control, wait-history, turn,
policy and blob-class guards are mapped in ACCEPTANCE.md. All new positive/red
execution remains for the authorized disposable Linux machine.

## d4fix2 mutation diagnostics and recipe audit

The red runner now reports classification, named-test reach/pass/fail facts and
the observed exit for each entry. A non-killed entry includes the last twelve
lines of retained build/test stdout and stderr, with bounded console previews.
survived means the named test actually ran and passed with exit zero;
not_reached means it did not run, with build_failed identified from the saved
build receipt. Crashes, contradictory pass/fail records and unexpected exits
receive no kill. Complete original output files remain retained.

The original profile-scope recipe inserted adjacent false operands, producing
the vet diagnostic “redundant or: false || false” before its named test ran.
The corrected recipe removes the two driver/provider operands cleanly. Its
test still requires nil selection and A-only outside room reads; no expected
diagnostic or assertion is weakened.

The static dependency audit also found overlapping missing-wait protection:
removing the presence check alone still fails the operation-binding check.
waiting-record now disables missing-history refusal in both checks while
preserving operation validation for a present record. The separate
waiting-operation entry and all existing history assertions remain unchanged.

All 96 recipes from profile-scope onward were applied to isolated scratch
copies outside the worktree and compared byte for byte with the intended edits.
The 62 Go copies were vetted for Linux, Linux with laneboss_faults and Darwin;
the 34 observer copies were checked with py_compile. This establishes static
validity of their source recipes, not runtime mutation kills. The full
normal/faults red matrix must still run on the authorized Linux test machine.

## Draft.4 fix 10 adoption

The shared continuation-operation request is now closed by the contract and
api.ValidateContinuationOperation. The watchdog uses that validator at selection,
reply and replay. TestFix10Operation covers pending/running and a completed phase
that advances during Continue, plus foreign/intent IDs, changed operation and
pending/claimed-as-succeeded refusals. TestFix10SelectionReceipt keeps an invalid
durable pending result from reaching lifecycle. Existing operation-binding and
completed-receipt mutations now remove the shared validator; they retain their
tests and strict refusals. shared-operation-phase and shared-selection-phase
exercise the new phase requirement without an old local-rule fallback.

The capture/launch fixtures retain complete shape-valid plans and computed JCS
spec/binding hashes. They supply no native authority or measured process result.
TestFix10LaunchPins covers reserved level/role/driver, missing capture, unknown
drain and an approved-but-refused capture disposition. The installed case requires
BindingID on new captures and the same operation on swapped/continued-launch
events. Its observer controls are obs-live-binding and obs-shared-operation.
The catalog has 108 component and 38 observer entries, 146 total. These additions
and the amended recipes require Linux candidate/red execution; the earlier
reported 222/222 kills cover 7dcd08e, not this adoption.

## Draft.4 d4fix11 operation read-back

The supervisor found only TestFix10Operation/swapped-operation failing in the
acf0b58 unit/faults/race candidate. That case keeps its typed invalid_request
assertion and now injects the stored operation replacement during the original
operation lookup, before lifecycle. Its zero-dispatch assertion is explicit;
the lifecycle probe still returns integrity for an unstored/different request.

The watchdog rereads the intent after that lookup and compares its operation,
Swap and store receipt with the original observation through the shared
validator. claimed-operation removes this guard and targets
TestFix10Operation/swapped-operation. The old receipt is deliberately retained
so an old-snapshot-only check cannot mask removal. The named typed assertion
fails if the stale request reaches the unchanged lifecycle probe.
completed-receipt and shared-selection-phase use the guard's updated anchor.
All earlier entries remain: 108 component and 38 observer entries, 146 total.
Static recipe/compilation checks do not establish a candidate pass or red kill;
both candidate modes and the complete matrix still require authorized Linux.

## Draft.4 d4fix12 delta and fix 11

The supervising brief reports the 8e5453a unit/faults/race and 121-recipe matrix
green. This delta changes those bytes; that report is not a pass for this source.
TestOwnTurnAfterLaunch was written and archived against the old guard first.
Its normal lane.resumed/own lane.turn sequence must continue, while different
later turns still cancel. own-turn-order restores sequence-only cancellation;
turn-run-scope removes the historical-run distinction. Linux must confirm the
suspected normal-path failure and the candidate before crediting red-to-green.

Old claimed-run cancellation preserves the current next-run life and epoch.
Expired pending room/eligibility enters reassessment under continuation CAS;
one fresh room check is required, and a concurrent claim wins. A successful
replan retains newly measured receipts and never dispatches the old Swap.
Malformed, future or foreign receipts still refuse without reassessment.

New limits require committed normalized outside usage evidence and exact pinned
TSV/source/producer/private-ACL validation. The component installation callback
supplies retained native facts and protected enrollment; missing real binding
fails closed. Reassessment refreshes an aged usage result through UsageWindowSource
and retains the new immutable envelope reference, keeping the causing limit's
other facts. The observer requires that reference on the actual swap/launch.
These fixtures and reference checks prove no native worker or vendor execution.

Fresh policy uses PolicyGenerationFor/RefreshLanePolicy and new life fences;
the turn's immutable approved snapshot is read through PolicyAt. Historical
launch/grant objects are not rewritten. Completed replay retains its snapshot.

A dashboard forbidden/unauthenticated reply is reached unless the harness context
explicitly sets human_reader_handoff_available=false. Missing binding/proof files
remain named fixture failures. A true/absent marker cannot hide a real service
authentication defect. The marker grants no principal or human-read authority.

The current catalog is 108 Go component plus 38 observer recipes, 146 total.
All prior IDs remain. Static compilation/anchor checks do not establish a test
assertion, runtime kill, live provenance or installed acceptance.

## Draft.4 d4fix13 policy backoff and pending usage

TestWaitingPolicyBackoff was written and archived before the production edit.
It models a no-room five-second wait, approved policy publish, repeated limit
inside backoff and post-deadline reconciliation. Its unchanged-life/no-refresh
assertion would fail on the old early refresh. After the deadline it requires
one refresh and a second journal write with consistent fences.
waiting-policy-backoff restores the early write. Linux must run both sources.

Pending policy drift stays read-only until fresh planning validates the limit.
Policy refresh follows capture/exit/room/usage corroboration and pins the
selected approved snapshot. limit-policy-order and pending-policy-order check
unchanged lives for refused fresh evidence.

Pending usage age is read from the immutable normalized envelope after exact
byte verification. Over thirty seconds triggers outside remeasurement under
continuation CAS even when room/eligibility remain live. Exact thirty-second,
future and foreign-target controls are separate. Old bytes/hash stay unchanged.
Room/eligibility controls keep usage fresh so their checks are not masked.

The active catalog has 108 component and 38 observer entries, 146 total,
retaining all 139 baseline IDs. Static compilation proves no runtime kill,
native usage-worker execution or installed acceptance. Candidate and the full
normal/faults red matrix remain authorized-Linux work.
