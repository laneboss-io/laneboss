# Item 7, round 2

This is a partial gate implementation on the merged round 1 source. It is not
an installed watchdog E2E, authenticated vendor test or owner confirmation.

## 7C: reservation, slot and completion

`cont.go` reserves a pending selection once, without requiring an already
acquired slot. It preserves the actual selection operation and canonical
`ContinuationRequest` bytes, creates one durable planning effect and leaves
the operation pending. A business reservation is not an execution lease.

`cont_slot.go` provides the private `KeepContinueSlot` port. It rereads the
actual live planning claim, current policy and cancellation fences, selected
grant and immutable credential stage before persisting that exact slot. The
planner calls it before injection. A retry uses the same acquisition result;
missing, foreign, stale and replaced inputs refuse.

`cont_data.go` permits only the exact previous bound prompt and workspace
snapshot references to retain their true original operation. New data still
needs the current operation's actual receipt. `cont_done.go` completes the
intent and emits one `watchdog.swapped` only with the actual opened plan,
retained process and completed child stages, in the effect completion commit.
The service's continued-launch hook reuses the original briefing and adds the
actual profile swap to the next launch event.

The store tests traverse genuine SQLite selection, reservation, claims,
retention, plan, binding and completion. Their helper, worker and native
observation inputs are explicit component receipts. The retained component
profile is not proof of a public two-profile swap or authenticated vendor run.

## 7C: complete frames

`frame.go` derives separate immutable JSON-line records from contiguous raw
chunks only after every registered stream has an acknowledged EOF and the
run has its retained exited, zero-survivor observation. Original partial
records remain unchanged. Derived records have independent IDs, exact byte
ranges and hashes, retained source pins and `capture.framed` events.

Lookup, replay, restart and state verification rebuild the source relationship.
The generic emitter cannot submit this event. The automatic watchdog invokes
the private `FrameCapture` port; adapter composition binds `CaptureFrame`.
The consumer accepts the registered structured stream without treating a raw
partial range as complete. Missing EOF and forged EOF state remain refusals.

## Regression failures and controls

`TestPendingReserve` first reached a missing selection digest, then the absent
slot-free reservation. `TestContSlot` failed on the missing live-claim handoff.
`TestPlanContinuation` found a slot lost before injection. `TestContOpen` found
the prior-object provenance refusal, then an opened intent left claimed.
`TestContInput` found the nonexistent replacement briefing. `TestFrames` and
`TestFramesNeedEOF` found the absent frame port. `TestFramedRun` reached the
partial-capture refusal even with derived frames present. Each corresponding
candidate check then passed on the Linux box.

Controls reject foreign configuration, epoch, operation, binding and claimant,
missing stage/source/EOF, a changed slot and stale effect claim. Replay checks
one reservation, one slot, one opened swap event and stable derived records.
Restart reuses the same frames; a forged EOF projection fails store reopening.
Test-helper compilation errors and invalid fixture shapes were corrected and
were not counted as product red tests.

## Open work, in brief order

7C still needs a real separately confined usage job implementing `StartUsage`
and `RunUsage`, with the actual native input/result frames, sealed bootstrap,
protected worker mapping and narrow grants. The existing command engine and
usage provenance reader cannot create those native facts. No event-service
usage subprocess or fabricated worker scope was introduced.

The next native work crosses three existing boundaries: the protected reverse
mapping in `worker_bootstrap.go`, the fixed job selector in
`dataworker/internal.go`, and the separately owned broker's dependency binding
in `credbroker_linux.go`. The fixed selector currently accepts only
materialization and archive. Adding an assembly adapter alone cannot satisfy
the required authentic input and result frames.

7E still needs the outside quota/history fixture and native forge, file,
signal and restart controls, all driven through the installed public flow.
The six watchdog cells have not passed. 7D still needs an enrolled human
reader process and transport. Missing human setup remains a typed wait before
upload or dispatch. 7A's incoming per-run enrollment file was absent here;
no competing enrollment interface was written. Its vendor/profile/home and
live-slot controls remain required after integration.

Owner steps remain waits: root installation, applicable D6 confirmation,
authenticated human session, chosen same-provider profiles and approved live
budget, plus any required human send or browser gesture. No real model call,
sign-in, message, commit, push, merge or deployment was performed.
