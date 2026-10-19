# Draft.4 fix 15 report

This candidate starts at c4e3cf5.
It repairs the surviving natural-measured-process control by changing its
test fixture and refusal assertion. Production code, mutation edits, selected
test/subtest and required red marker remain unchanged. No control is removed,
blocked or credited for an arbitrary failure.

## 1. Live guard and masking fixture

The measurement guard remains in store/natural_completion.go and is unchanged
from 9e3a8ed. validateLaunchTransaction still calls validateNaturalCompletion
under the writer path. The component test calls that same validator directly;
the dispatcher ownership change did not move or bypass its measurement check.
The natural-measured-process edit still removes the live containment_unknown
return, with one exact anchor.

The old still_running fixture supplied an empty handle containment ID,
generation, prompt status and observation timestamp. Stored projections use
decodeStored, which accepts those zero values. After the mutant removes the
measurement refusal, the validator decodes the lane.ended payload with
wire.Decode. That strict decoder rejects the empty containment ID first;
the prompt enum and timestamp are independently invalid too. The test accepted
any nonnil error, so this later schema refusal masked the missing guard.
This diagnosis follows source inspection; it is not a new runtime measurement.

The supplied red log shows TestNaturalObservationFence (still_running) passing
under the mutant, exit 0, followed by the runner's exact refusal:
"red did not reach its intended failing assertion". It records 107 completed
normal red/candidate pairs and stops at this row. Although the brief reports
only one surviving control and a green unit box, the supplied log does not
establish faults results or results for rows after this stopping point.

## 2. Test correction and deciding assertion

TestNaturalObservationFence (still_running) now first stores a complete exited,
zero-survivor observation with an exit code, containment identity, process
generation, prompt status and UTC timestamp. It requires the real validator
to accept the resulting transaction, including its CAS, cancellation epoch,
unchanged budget and matching end/state events.

The test then changes the retained observation and matching end payload to
running with one survivor and no exit code. It advances the observation
projection generation and explicitly requires wire.Decode to accept the new
end payload before calling the validator. A schema error has its own fixture
failure and cannot earn the catalog's red credit.

Without the measurement refusal, source tracing reaches the final nil return:
the current lane write, request target, controller, CAS, epoch, budget and both
decoded events still match. That nil must trigger exactly
"natural completion accepted a still running observation". The unchanged
candidate must return api.CodeContainmentUnknown; a different error now fails
the test. The positive control and decoder assertion run inside the selected
subtest, including a focused mutation invocation.

The test observes returned behavior and retained component state. It does not
read source, detect a mutant, inspect its literal or substitute a constant
validator result. The observation is a component fixture, not an observation
of a real process. Linux must still demonstrate the deciding red followed by
the unchanged candidate green in both builds; static inspection earns neither.

## 3. Other d4fix14 targets

The comparison is 9e3a8ed to c4e3cf5. The conservative inventory includes every
row targeting a changed production file, every changed existing edit and all
new controls. Assembly and the lifecycle stub changed dependency wiring but
have no catalog mutation target. No other existing row changed its file,
anchor, selector or assertion.

The following existing controls have unchanged live anchor regions in files
that changed elsewhere, except capture-peer-generation whose replacement
changed. Their normal kills and candidate passes are recorded in the supplied
input log, before the natural-measured-process stop. No faults result is
claimed for them.

| Control | Target change and trace to the deciding assertion |
| --- | --- |
| mutation-gate | dispatch_mutation.go gained ownership handling after the initial receipt lookup. The unchanged mutant still invokes the registered handler on not_implemented from that lookup; TestMutationCannotBypassReceipt then observes integrity instead of its required not_implemented. The new atomic port cannot intercept that early return. |
| receipt-exact-bytes | receipts.go gained ReserveMutation, while the completed-receipt lookup anchor stayed in place. Clearing Reply.Result still reaches TestReservedExactReply's comparison after reopen and fails "restart changed exact receipt". Its reservation wrapper delegates to the actual store insertion. |
| freeze-host-admission | dispatch_mutation.go gained the atomic port after admission. Removing admission still reaches the explicit ledger's ReserveMutation, which forwards to its observed reservation refusal. TestFrozenHostKeepsReads therefore fails its unavailable assertion with integrity. The fixture forwarding added in d4fix14 preserves that deciding path. |
| capture-peer-generation | The replacement now retains a read of facts and accepts a wrong nonempty generation; capture.go itself did not change. TestCaptureProducerGeneration (peer_generation) first appends successfully, then changes only peer generation and retries. The mutant accepts that retry, reaching "capture replay accepted changed peer_generation". |

The eleven new controls target the added atomic reservation/ownership code.
Each was traced with its selected component fixture and required marker. None
is reached in the supplied log, so their red/candidate execution remains
pending even though their source paths are consistent.

| Control | Selected test (subtest) and intended failure |
| --- | --- |
| reservation-one-owner | TestReservationOneWinner (identical_invocations): replay returns won=true, so eight identical invocations yield multiple winners instead of exactly one. All share the same real pending operation. |
| reservation-insertion-owner | TestReservationOneWinner (identical_invocations): insertion returns won=false, so the same observed winner count is zero. Both winner-count mutants reach "identical reservations did not have exactly one winner". |
| dispatch-await-winner | TestMutationRetryAwaitsWinner (same_request): two genuine absent lookups race at the sole writer. The changed loser condition sends both through owned invocation instead of AwaitReceipt; the second preflight reaches "same request ran mutation preflight twice". Timeout and cleanup failures have separate messages and earn no credit. |
| mutation-owner-context | TestMutationOwnerFences (fresh_context): a live valid owner succeeds first. Returning true at the context fence grants a fresh context ownership and reaches "mutation ownership accepted fresh_context". |
| mutation-owner-operation | TestMutationOwnerFences (foreign_operation): after the same live control, the altered operation is accepted at the changed fence and reaches "mutation ownership accepted foreign_operation". |
| mutation-owner-actor | TestMutationOwnerFences (foreign_actor): the altered actor is accepted before receipt lookup and reaches "mutation ownership accepted foreign_actor". |
| mutation-owner-key | TestMutationOwnerFences (foreign_key): the altered idempotency key is accepted before the later key comparison and reaches "mutation ownership accepted foreign_key". |
| mutation-owner-retirement | TestMutationOwnerFences (retired): deleting active retirement leaves the saved capability active after the callback, with the actual receipt still pending, and reaches "mutation ownership accepted retired". |
| dispatch-atomic-port | TestMutationNeedsAtomicStore (missing_port): a wrapper omits the private port while retaining the real store. The mutant calls the registered handler, and its observed call flag reaches "dispatcher without atomic winner ran preflight" before checking the typed refusal. |
| dispatch-reservation-config | TestMutationReservationPins (foreign_config): a real winning reservation is returned with only its DTO config changed. Removing the metadata refusal invokes the handler and reaches "mutation reservation accepted foreign_config". The stored reservation remains real. |
| dispatch-reservation-frame | TestMutationReservationPins (foreign_frame): the same wrapper changes only the returned raw-frame DTO. Removing the pending/frame refusal invokes the handler and reaches "mutation reservation accepted foreign_frame". |

These traces found no further masking refusal or moved guard requiring a
source/test/catalog edit. The 171-control catalog is retained. Its literal
anchor review and all check observations are recorded in external evidence;
the static review does not claim executable compilation or red credit.

## Checks and handoff

Implementation was complete before the authorized static checks. The authoring
environment was Darwin arm64, Go 1.26.5 and Python 3.13.11. The changed Go file
was formatted first and has no trailing blank lines. Checks retain the exact
command, output and exit, including empty output, in external JSON records.

| Check | Observed result | What makes the check fail |
| --- | --- | --- |
| Literal source review | All 178 edits across 171 controls have one anchor; IDs unique, no controls removed, no test file mutated | Missing/duplicate anchor, no-op edit, duplicate/removed ID or test-file target |
| gofmt -w | Exit 0 for fix11_policy_linux_test.go before the checks | Parse/format error |
| gofmt -l | Exit 0 with empty output | Any listed path or nonzero exit |
| Python py_compile | Exit 0 for mutations.py, run.py and scenario.py | Missing input or Python syntax error |
| bash -n | Both service shell entry scripts exit 0 | Shell syntax error |
| Linux amd64 vet | Exit 1 on an existing Go build-cache entry: operation not permitted | Vet/compiler diagnostic or unavailable cache |
| Linux laneboss_faults and Darwin vet | Skipped under the brief's explicit cache-refusal route | Not measured |
| Unit/mutation/installed runtime | Not run on this Mac | Linux must reach the named assertion under the mutant and pass the unchanged path |

The vet command was GOWORK=off GOOS=linux GOARCH=amd64 GOPROXY=off GOSUMDB=off
go vet ./internal/v2/store ./internal/v2/service. Its exact cache path and
refusal are retained verbatim in vet-linux.json and vet-linux.log. No cache
was changed or redirected and no vet retry was attempted. After the refusal,
only reporting and evidence collection continued; no implementation edit or
further verification followed. A compilable candidate or killed mutant is
not claimed from this static round.

The supervisor can first run the focused pair in both builds on the disposable
Linux box, then the full inventory documented in MUTATIONS.md:

```sh
bash e2e/v2/cases/service/run-mutations.sh --source /test/source --evidence /tmp/lb-v2-service-mut-f15 --mutation natural-measured-process --variant both
```

The external evidence directory is d4fix15-c4e3cf5 in the lane's evidence root.
It retains the brief, configuration rules, supplied log, source revision and
HEAD archive, original target diff, final source bytes/diff/status, static
review, check records and manifest. No tested binary exists for this round.
The supervisor owns Linux red/candidate verification, final review and commit.
This candidate remains uncommitted.
