# Ordinary peer and audit lifetime: run 33

Run 34 adds an independent primary pidfd observation and a bounded acceptance
window for inherited stderr, while retaining every byte through eventual EOF.
Its current behavior and deciding controls are in
[the compatibility and wait handoff](BWRAP-COMPAT.md). The run-33 findings below
remain historical source/evidence scope, not an installed acceptance claim.

Green31 on 273d677c stops at admin.publication, command
056-publication-org-validate, with identity unauthenticated: connecting process
has ended. This is earlier than green30's step 42. The exact installed syscall
cause is not established by the retained log. The candidate corrects a
false-refusal path in native liveness observation and the run-32 audit-owner
defect, and adds real ordinary-process and full-lifetime output regressions.
Getting back to step 42 or further remains an installed green32 requirement.

## Peer regression evidence and source trace

The supplied verify-273d677c-20261017-041540.log was read completely and retained
privately. It contains 525 lines, 68,397 bytes and SHA-256 prefix
0b75abb23a0375e1. The exact refusal appears twice. There is no signal-zero or
poll errno/result detail. The bootstrap marker does not occur in those retained
log bytes. No runtime argv, settings, process identifiers or environment values
were printed during this investigation.

For ordinary org validate argv, both new RunBootstrapEntry calls reach the
first marker mismatch and immediately return false/zero. That branch performs
no fork, exec, descriptor access, signal change, UID change or process exit.
The marker handler, main call and RunContext call are preserved unchanged in
this run. Removing the bootstrap entry would neither establish a cause nor
satisfy the regression. General client/session and identity authentication
logic also remains intact.

The reported text comes from native peer liveFD. Its old signal-zero branch
treated every error except EPERM as an ended process. Its poll branch treated
every error, including EINTR, as an ended process. The retained x/sys source
shows that Poll returns Ppoll directly without restarting interruptions.
The same liveFD code existed before run 32, so source alone cannot prove that
EINTR explains this new installed failure. No new-entry PID-changing action
was found. Suspected: an interrupted observation falsely reports the still-live
CLI as ended. The candidate fixes that defined error case and retains the
actual deciding operation for any further refusal; it does not claim the
specific green31 cause was measured.

## Strict liveness handling

The actual socket-bound SO_PEERPIDFD remains mandatory. Each signal-zero or
zero-timeout poll retries only EINTR, with at most four attempts. A successful
check still requires the same permitted signal-zero result (or the existing
foreign-UID EPERM case), then a successful poll with zero event count and zero
returned flags. Exhausted interruptions, all other errors, readable/invalid/
hangup/unexpected events still refuse with unauthenticated. UID/GID, process
generation, containment and all later checks are unchanged. No numerical-PID
fallback, dead-process exception or constant live result is introduced.

Refusals now distinguish signal_zero from poll, with a closed errno vocabulary
or a fixed event category. This does not disclose a PID, descriptor, bitmap,
private argument or arbitrary error string. An unavailable observation is not
described as proven process death. A real readable pidfd remains an ended peer.

## Audit-owner defect and repair

Run 32 replaced the child's direct file stderr with an exec copy writer whose
destination was the caller's os.File. startConfinedGate closes that original
handle when preparation returns. After readiness, the vendor could therefore
write to the child pipe while the Go copy attempted to write a closed file.
The one-second WaitDelay could also cut off an inherited pipe after the primary
process exited. The automated finding remains a suspected installed security
gap until its Linux canary and control run; the descriptor ownership defect is
visible in the source and is corrected here.

attachBootstrapStderr now duplicates the actual writable capture descriptor
with close-on-exec before any child starts. A nil, closed or read-only sink
refuses without installing a writer or starting a child. The duplicate retains
the same underlying file/pipe and access mode; no pathname is reopened and no
file permission, namespace, credential or capability is widened.

The starter owns that duplicate until the native wait owner takes it. For a
prepared gate, cmd.Wait drains stderr through the entire producer lifetime,
then the gate's wait owner closes the duplicate before publishing done. A
capture-close failure makes collection unavailable even when a child ExitError
also exists; actual ProcessState remains retained. Prefix freeze stops only
the bounded diagnostic observation, while all output continues to the owned
capture sink. WaitDelay is zero so it cannot truncate vendor or inherited
stderr. Readiness retains its original deadline and strict proof.

## Regressions and controls

All runtime observations below are pending on the authorized Linux machine.
The Mac run only compiled/vetted these tests. The catalog retains all 362 prior
IDs and adds 11, for 373, each with one unique source edit and named assertion.
The runner grants only two new exact file exceptions (the bootstrap CLI wrapper
and native peer file) and one exact test package; its source roots stay unchanged.

| Regression | Deciding control/failure |
| --- | --- |
| TestOrdinaryBootstrapPeer | ordinary-entry-peer makes the actual entry wrapper intercept ordinary argv. The real CLI child must exit before connecting and fail the native-peer assertion. The candidate passes both actual entry points and ordinary RunContext; the test-only operation adapter holds a real Unix socket for verification. It must retain the original child PID, actual UID/GID/generation and a live native peer across 32 exchanges, then refuse after that child's actual exit. It does not claim a human session or org-validation result. |
| TestLiveInterrupted/signal and poll | peer-signal-interrupt and peer-poll-interrupt remove the corresponding restart. One injected EINTR must be followed by the complete real kernel operation on an actual live pidfd; losing that completed check fails. The fault seam does not supply a positive kernel result. |
| TestLiveInterruptedRefusals | peer-incomplete-refusal admits a failed observation; peer-interrupt-bound changes the retry count. Persistent EINTR and another failed poll must still refuse with the required finite call count. |
| TestLiveExitDuringRetry | peer-exit-during-retry removes the actual event refusal. The canary ends and reaps a real child between the interrupted read and retry; native polling must then refuse the ended child. A continued process is never substituted. |
| TestGateStderrLifetime | stderr-owned-destination restores the borrowed caller handle, while stderr-freeze-owner closes the duplicate at freeze. Both must fail exact post-readiness capture after the caller closes its original. The fixture waits for a real 256-byte captured prefix, marks readiness, freezes diagnostics, closes the original, then lets the child emit the large remaining randomized stream before actual exit. Every final byte must match. |
| TestGateStderrLifetime timer/close guards | stderr-no-truncation-timer sets a nonzero WaitDelay and must fail its policy assertion. stderr-drained-owner-close omits actual close; a retained owner handle must remain writable and fail the independent final-close assertion. The frozen prefix must remain exact while the full capture grows. |
| TestGateStderrInputs | stderr-readonly-refusal removes the native access-mode guard. The actual read-only descriptor must be incorrectly admitted and fail the owned-writer/no-child assertion. Nil and already-closed inputs also require real typed refusal. |

The ordinary-command fixture replaces only the operation adapter inside its
re-executed test process. The native connector, SO_PEERPIDFD verifier, actual
identity/lifetime observations, dispatch, exchanges and child exit are real.
Its containment registry deliberately returns unavailable and is never used
for the human-class native peer. No positive service, authorization, storage
or containment receipt is fabricated. Separate installed publication/native
qualification remains required.

## Static checks and green32 contract

All 16 candidate vet configurations passed with the shared cache, local Go
toolchain, readonly modules and downloads disabled. Admin, CLI, native peer,
main and production/test importers are covered for Linux amd64/arm64 default,
faults, partial/authenticator, combined, integration and integration/faults;
Darwin amd64/arm64 default and partial/authenticator. Formatting, diff checks,
serve Python compilation and the separate mutation-runner compile are retained
in the final evidence. No mutant overlay was vetted on this Mac.

No runtime test, live box query, installed service, machine launch, model
request, commit, merge or new agent session ran here. The requested extra
syscall evidence was not present in the supplied log; no missing errno is
invented. Green32 must get back to step 42 or further. If publication still
refuses, retain the new exact operation/errno/event facts and identify that
observed cause before another repair. Full installed native containment and
full audit-lifetime red/candidate qualification remain mandatory. Presence is
simulated and human_approval=not_proven; no authenticated AI-service result is
claimed.
