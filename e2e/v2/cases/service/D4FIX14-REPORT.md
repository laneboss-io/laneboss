# Draft.4 fix 14 report

The candidate starts at 9e3a8ed and remains uncommitted in the same checkout.
No staging, commit, branch change, remote access, machine operation or model
request was performed. The scope is the capture red control, four launch-plan
selectors and the approved lifecycle owner's dispatcher dependency.

## Per-item outcome

| Item | Source outcome | Verification limit |
| --- | --- | --- |
| capture-peer-generation | The mutant now replaces the peer-generation comparison with an empty-generation check. It still reads facts, so it does not create the reported unused-variable error. It accepts a different nonempty generation and therefore remains a meaningful bad predicate for the unchanged peer_generation assertion. Production capture code is unchanged. | The exact mutant and a vet overlay are retained. Gofmt parsed/formatted it, but both-tag compilation and the deciding red/candidate pair remain unmeasured because vet hit a cache refusal. |
| Four launch-plan selectors | Already present at HEAD and retained: launch-plan-reservation selects foreign_reservation; launch-plan-policy selects stale_policy; launch-starter-grants selects stale_grants; launch-claim-expiry selects expired_claim. The static catalog audit confirms each exact selector. The supplied normal red run also progressed beyond these controls. launch-replay-comparisons continues to target its trailing top-level assertion. | No gratuitous catalog edit was made to these four entries. The current full inventory still needs its Linux run. |
| Atomic reservation winner | Store.ReserveMutation returns the actual insertion winner under the single writer and commits the original operation/request bytes before returning true. An existing reservation or receipt returns false, including an identical request ID/frame. ReserveRequest retains its original public signature and delegates to that same implementation. | TestReservationOneWinner races eight identical requests and requires one winner and one original operation, then checks an identical retry. These are authored component tests, not observed runtime results. |
| OwnsMutation | The dispatcher issues a private, live context capability only after winning that atomic reservation. It binds service instance, authenticated scope, key, operation and original request. OwnsMutation checks those pins and the actual current pending receipt. A fresh invocation has no grant; a retired handler loses it. Request IDs, frames and connections are not an ownership lookup key. | TestMutationOwnerFences covers a fresh context, foreign operation, actor and key, and retired capability. Deciding mutation controls accompany each case. |
| Retry dispatch | A reservation loser awaits the retained receipt without invoking the handler. Every dispatch entry shadows any inherited ownership context. Existing local flight serialization remains in place. Missing atomic-store support and inconsistent reservation pins fail before preflight. | TestMutationRetryAwaitsWinner makes two dispatchers genuinely observe an absent receipt, then race the real SQLite store with the same lane.stop request ID, frame, connection, key and digest. One handler reaches its preflight ledger; the other must reach AwaitReceipt and replay the actual retained error receipt. No lifecycle helper or process is executed by this fixture. |
| Lifecycle wiring | Assembly passes Dispatch: server into lifecycle.Dependencies. The current lifecycle stub receives only the matching dependency field, with the exact private signature from approved owner commit 0b139e1. No shared API schema or lifecycle implementation is replaced here. | This checkout still contains the lifecycle stub. Merge the approved lifecycle implementation while preserving Dispatch wiring before claiming assembled lifecycle execution. The dispatcher/store regression is not that integration measurement. |

## Concrete private handoff

Hosted store wrappers must forward the real store's concrete private port:

```go
ReserveMutation(context.Context, api.RequestReservation) (
    api.MutationReceipt, bool, error)
```

The boolean is true only for the insertion committed by that call under the
writer lock. A wrapper must not infer it from a missing earlier lookup, a
request ID, raw frame or connection. There is no permissive fallback when the
port is missing. The original ReceiptStore interface is unchanged.

The service provides the approved lifecycle dependency with this signature:

```go
OwnsMutation(context.Context, api.Scope, api.RequestKey, api.ID) (
    bool, error)
```

Only the winning handler receives its unexported context capability. Ownership
is valid during that handler invocation and while its exact receipt remains
pending. Retirement invalidates saved contexts. A restart does not mint a new
owner for old pending work; that work keeps its existing receipt/reconciliation
route. This capability does not replace authentication, current policy, proof,
life CAS, cancellation or launch-plan authority checks.

The minimal lifecycle stub field is a compatibility bridge for the owner merge.
The approved implementation already declares Dispatch with the same interface.
During integration, retain assembly's assignment and use the real owner's
dependency declaration; do not retain two lifecycle implementations or turn
its missing capability into true ownership.

## Controls and authored regressions

The catalog has 171 controls: the 160 existing IDs plus eleven ownership
controls. That is 342 targeted red/candidate pairs across normal and faults,
with the existing ten final component suites. The static literal audit found
one matching anchor for every edit, no no-op edit and no mutated test file.
It retained the four launch selectors explicitly in catalog-review.json.

| New control group | Deciding assertion |
| --- | --- |
| reservation-one-owner and reservation-insertion-owner | Identical reservations must have exactly one winner. |
| dispatch-await-winner | The identical request must not run preflight twice. |
| mutation-owner-context, operation, actor and key | The selected ownership boundary must remain false. |
| mutation-owner-retirement | A saved capability must be false after its handler returns, even while the real receipt is pending. |
| dispatch-atomic-port | A dispatcher lacking atomic winner evidence cannot invoke preflight. |
| dispatch-reservation-config and frame | Returned reservation metadata must remain bound to the actual request. |

TestMutationNeedsAtomicStore and TestMutationReservationPins use the real store
behind wrappers that respectively omit the private port or alter only returned
DTO pins. They require a typed refusal and no handler call. The race fixture
delays genuine lookup results to expose the insertion race; it does not choose
or manufacture the winner. Its final typed refusal is a component result kept
by the real store, not a successful outside execution claim.

All new tests and reds await actual Linux execution. The supplied input log
records 95 completed normal pairs on 9e3a8ed before the old capture mutant's
compile error. It is not runtime evidence for this candidate or the faults run.

## Static results and stopped vet

The environment was Darwin arm64, Go 1.26.5 and Python 3.13.11.

| Check | Observed result | Failure criterion |
| --- | --- | --- |
| Literal mutation audit | All edits across 171 controls have unique anchors; test files unchanged per mutant | Missing/duplicate anchor, no-op edit or test-file mutation |
| gofmt -w | Exit 0 for eight changed Go files and the retained capture mutant | Go parse/format error |
| gofmt -l | Exit 0, empty output | Any listed path or nonzero exit |
| py_compile | Exit 0 for the three service Python inputs | Missing input or syntax error |
| bash -n | Both entry scripts exited 0 | Shell syntax error |
| Linux vet | Exit 1: four existing cache entries refused access | Vet/compiler diagnostic or unavailable cache |
| Remaining candidate/mutant vet | Skipped under the brief's cache-refusal route | Not measured |
| Unit/mutation/native execution | Not run on this Mac | Exact named assertions and unchanged candidate controls |

Linux vet targeted service, store, assembly and lifecycle with GOWORK off,
Linux amd64 and downloads disabled. The exact command, exit and four operation
not permitted diagnostics are retained outside the checkout. No cache was
changed, redirected or retried. No implementation edit or further verification
followed the refusal; reporting/evidence collection alone continued.

The capture overlay is prepared but was not vetted after that refusal.
Compilation in either tag build is therefore not claimed. No test/product
binary, project interpreter beyond authorized py_compile, authenticated service
request or installed lifecycle/capture run was performed.

Evidence is in the lane's external evidence root under d4fix14-9e3a8ed:
brief, supplied red/review input, approved lifecycle handoff bytes, HEAD and
phase/final source archives, exact mutant/overlay, catalog review, diffs/status,
commands/logs/exits and manifest. No tested binary exists for this round.
Component DTOs and helper observations are not installed isolation, hardware
presence or an authenticated AI-service test. The supervisor owns Linux vet,
deciding reds/candidate greens, lifecycle integration, review and commit.
