# Draft.4 fix 12 report

The candidate starts at a34d672. The supervisor concluded the earlier merge;
this round contains uncommitted edits in the same checkout. No staging,
commit, branch change, remote access or machine operation was performed.
The scope is the four supplied unit failures, followed by the mutation
runner's dependency snapshot. Earlier Group B limits remain in the fix-11
report and are not claimed resolved by this round.

## Supplied failures and source changes

| Item | Classification and correction | Required deciding evidence |
| --- | --- | --- |
| Retained launch and natural completion | Fixture defect. ControlledChild reused its parent's already-opened ProcessHandle after preparing the child gate. PrepareJob now clears that old observation when it obtains a new prepared gate. Observation then creates a handle for the current target, containment and process generation. RecordLaunchObservation and its consumed-permit/full-tuple guard remain enforced. | Rerun TestLaunchRetainedReservation, TestLaunchRetainedGuards and TestNaturalCompletionCommit in both builds. The supplied unit log records the failing baseline; the corrected candidate has not run here. |
| Capture refusal publication | Both fixture and product consumer. The fixture supplied a bare ChangeReceipt where the event schema requires ChangeEvent, and its approval DTO omitted required identities/timestamps. It now supplies the complete wrapper and required nested fields. The authority lookup selects payload.receipt.id for org.change.applied. The capture consumer compares the actual event, receipt and change with the retained application, and compares any included approval with the consumed approval. | TestCaptureRefusalD6Provenance must accept the complete valid event and refuse changed receipt, change, origin and approval subtests. Five new controls require their named assertions, including the missing-event gate. Physical capture and a real D6 ceremony remain outside this fixture. |
| Host freeze/drain/thaw | Fixture defect. The component effect used cancellation epoch zero after the socket fixture began creating a real lane with epoch one. The fixture now reads Lane.CancellationEpoch and uses that actual fence in the effect cause. ClaimEffect and checkEffectFence are unchanged. | Rerun TestHostFreezeDrainThaw and TestFreezeCancelFailureStaysClosed. They still require the retained freeze, actual watchdog ledger calls, pending-work barriers and explicit unsupported measured-drain result. |
| Policy history integrity | Fixture defect. The hash negative attempted UPDATE against the real immutable-history trigger. It now creates one malformed historical row in a separate corruption fixture without editing an existing row or disabling a trigger. The conflicting-generation case uses the actual policy transaction and requires CodeConflict, then reads back the unchanged historical snapshot. It inserts no competing historical row. | TestPolicyHistoryIntegrity must reach the digest and typed conflict assertions. The policy-history-ambiguous control now removes the deciding generation guard in atomic_support.go. A raw SQLite error is not accepted as success or as the expected typed conflict. |

The supplied unit log reported BUILD-OK and failures in both tag builds.
Those measurements belong to the supplied a34d672 run, not this candidate.

## Mutation runner snapshot

The runner keeps the v2 mutation targets and discovers local package inputs
with `go list -mod=readonly -deps -test -json` for all five component packages
in both normal and laneboss_faults modes. CLI remains in discovery, candidate
builds and final suites. Imported internal/typesafe and internal/jsontext are
selected from the actual graph, rather than maintained exceptions.

For each main-module package, the snapshot retains Go source, native inputs,
resolved embeds and testdata. Generated test mains and external module caches
are not source inputs. Module files remain pinned. Discovery must include
every component root and succeed before copying/building the candidate.
There is no fallback to an incomplete fixed root set.

Discovery stdout and stderr are retained separately, so tool diagnostics cannot
corrupt the JSON stream. Both streams have command metadata and hashes. The
package inventory and dependency-input inventory accompany the existing
candidate manifest. Runtime mutation selection, exact failing assertions,
unchanged candidate tests and CLI coverage remain enforced.

## Static results and stopped verification

The environment was Darwin arm64, Go 1.26.5 and Python 3.13.11. Gofmt write/list,
isolated py_compile of the three actual service Python files, and bash syntax
checks of both entry scripts passed. Gofmt list output was empty. No test or
product binary was built and no project interpreter ran beyond py_compile.

The next authorized step was dependency discovery for Linux amd64, with
GOWORK off and module downloads disabled. It named wire, client, service,
store and CLI. Go list exited 1 because access to two existing go-build cache
entries was refused with operation not permitted. The exact command, stdout,
stderr and exit are retained outside the checkout. This is not a source
compilation result or a successful snapshot.

The brief explicitly permits skipping vet when the Go cache is refused. This
executor did not change caches, retry discovery, redirect GOCACHE or reshape
the refused command. Faults discovery, reduced snapshot materialization, both
Linux vet modes, Darwin vet and the final mutation-anchor audit were not run.
Compilation on the actual reduced snapshot remains unproven. No full-tree
check is substituted for that required result.

| Check | Observed result | Failure criterion |
| --- | --- | --- |
| gofmt -w | Exit 0 on all six changed Go files | Go parse/format error |
| gofmt -l | Exit 0, zero output bytes | Any listed path or nonzero exit |
| py_compile | Exit 0 for mutations.py, run.py and scenario.py | Missing input or syntax error |
| bash -n | Both entry scripts exited 0 | Shell syntax error |
| Linux dependency list | Exit 1, existing cache access refused | Nonzero Go list or incomplete/invalid graph |
| Reduced snapshot and vet | Not run after refusal | Missing dependency, compilation/vet diagnostic or unavailable cache |
| Unit and mutation runs | Not run on this Mac | Named assertions and exact paths in MUTATIONS.md |

The inventory contains 160 authored controls: all 155 earlier IDs plus five
publication controls. That is 320 targeted red/candidate pairs in the two
variants, followed by ten final component suites. The new assertions and
retargeted conflict control await Linux red/candidate evidence and anchor
validation. They do not establish a passing inventory.

## Handoff and retained evidence

Evidence is retained in the lane's external evidence root under
`d4fix12-a34d672`: both briefs, source revision archive, supplied unit/red logs,
phase and final source bytes/diffs, exact static commands/results, cache
refusal and manifest. No tested binary exists for this static-only candidate.
Component helper and approval DTOs are not installed confinement, hardware
presence or an authenticated AI-service test.

The supervisor must run actual dependency discovery and reduced-snapshot vet
in both tag modes where the cache is available, then rerun the four unit
groups and mutation controls. Review, staging and commit remain supervisor work.
