# Draft.4 fix 19 report

This round starts at 1d9921bd64da with the merge of
2a55fa8d65d6 already open. The starting tree includes
the materialization merge and its resolved fix11_stubs.go. The complete brief,
rules, merge input, parent revisions and source bytes are retained externally.
This round neither stages nor concludes, aborts or restarts that merge.

## 1. Current approved policy and fresh launch fences

CurrentApprovedPolicy is implemented, rather than replaced by not_implemented.
It is called by the new API launch fence and the service's launch-binding source.
It validates the service scope, reads the protected policy head under the store
mutex and ignores historical Scope.PolicyGeneration and ReadView selectors.
Absent, malformed, foreign or closed-store reads remain failures.

The single writer binds the API's private launch-policy stamp before validating
fresh agent helper_prepare/helper_open transactions. A private locked source
avoids reacquiring the writer mutex. Worker-only writes keep their existing
leased-job authority. Exact committed internal replay is selected before the
fresh head read, so a later policy publication does not rewrite that receipt.
The API rejects a new write with an old reservation generation, foreign effect
or reused stamp. The service binding source explicitly uses CurrentApprovedPolicy;
LaunchControlIntent also retains its currentLaunch check under the writer lock
immediately before producing open authority.

TestCurrentApprovedHead compares an actual older SQLite read snapshot with the
new protected head. TestPolicyHeadRefusal covers absent, malformed and closed
sources. TestWriterOpenPolicy performs an actual helper-open store transition,
then publishes a newer protected policy, requires exact replay and rejects a
new invocation at the old generation. TestCurrentPolicySource requires the
service to propagate the original current-source error. These authored component checks
do not establish native pre-exec ordering or an installed gate race.

## 2. Shared effect states and recovery

All service/store effect writes use the typed shared states. Initial intent is
EffectPending; initial and reclaimed leases are EffectClaimed. A succeeded
EffectOutcome produces EffectCompleted, and a failed outcome produces EffectFailed.
Outcome.Status and Operation.Status retain their separate succeeded/failed
vocabulary. No EffectState-to-string cast is used to repair a comparison.

Every serialized effect record goes through encodeEffectState and
api.ValidEffectState plus claim/outcome consistency checks. Effect lookup,
pending inventory, full dispatch inventory and whole-store verification reject
foreign states and malformed claim metadata. Verification compares the typed
state with its outcome through the explicit mapping. The SQL failed-state
inventory continues to derive the enclosing operation's actual outcome.

Recovery no longer depends on the removed reconciling label. Pending generation
1 advances to generation 2 on the first claim; later claims advance beyond 2
and reconcile that same immutable effect. runEffect also requires the shared
claimed state and the actual current claim. Lost allocation replies remain
containment_unknown instead of repeating native allocation.

Three additional merged consumers needed adaptation: secrets' planning and
worker credential claims now require EffectClaimed and no terminal outcome;
Codex materialization requires EffectCompleted while its outcome still says
succeeded. Positive fixtures use those same shared states. The two affected
Codex red anchors retain their IDs, selectors and diagnostics.

TestStoredEffectStates uses real claims/completion, replay, verification and
close/reopen for both terminal outcomes. TestEffectReclaimState checks the
reclaimed state, generation and stale-claim refusal. TestEffectStateRefusal
installs an outbox-state corruption fixture without altering immutable intent
or history guards, and requires all four read/verification paths to refuse.
TestReclaimedAllocation uses real SQLite claim expiry/reclaim and an allocation
call observer; its deciding assertion requires no repeated native work.

No silent migration of obsolete persisted running/reconciling/succeeded effect
states is added. Such a store fails integrity verification under the new closed
contract. Any installed upgrade requiring those old bytes needs an explicit
owned migration; this round does not rewrite their evidence.

## 3. Remaining fix-12 service obligations

The merged API already requires a valid nonempty logical_turn_id for every
lane.turn envelope, regardless of emitter. The store additionally joins that
envelope to its same-transaction or protected retained TurnSnapshot and exact
life/run. TestTurnEnvelopeStore has positive retained/written controls and
foreign life, run, missing-ID and foreign-ID refusals. It calls the actual
writer predicate; it is not a complete lifecycle or installed turn E2E.

The five CredentialProjectionStore methods remain explicit lb-v2-service
not_implemented ports. Source inspection found no production callers of those
store methods in this merged tree. The broker, native helper binder and
identity projection producer are also owner-named stubs; assembly's deferred
binder preserves their refusal before an actual credential-bearing launch.
RuntimeServices already carries both narrow credential clients, and the host
retains that full configured structure. Health/enrollment construction is not
changed to eagerly invoke the native binder.

Durable credential reservation, held receipt, withdrawal fence and measured
completion remain OPEN. Their implementation must join protected source
versions, native peer/installation facts, the real current claim, cancellation,
canonical refresh ownership and unique prepared-gate CAS through the sole
writer. CredentialProjectionRequest alone carries no authenticated native peer
or protected source-inventory producer. No invented authority, empty successful
projection, second writer, raw descriptor or credential value is introduced.
The owner handoff in LAUNCH-PLAN-CONTROLS.md and the complete fix-12/review/delta
contract remain acceptance requirements, including final envp/native canaries.

## 4. Red runner timeout

The brief reports a previous candidate failure in TestCaptureRangeGuards from
a package timeout, not a reached assertion. Candidate suites, targeted candidate tests and mutants
now all receive -test.timeout=10m. Their parent process is bounded at 660 seconds,
then retains the existing PID-owned process-group termination and 30-second
collection bound. Builds and other commands retain their 300-second default.
The exact parent timeout is included in command observations.

Timeouts, panics, races, surviving groups and unrelated diagnostics still earn
no red credit. The ten-minute bound is a selected allowance for the grown race
suite, not a measured duration or proof that the entire suite fits. The
supervisor must rerun the unchanged store candidate and inventory on Linux.

## 5. Controls, checks and handoff

The service catalog retains all 215 merged control IDs and adds thirteen, for
228 controls and 238 edits. Normal/faults therefore contain 456 targeted pairs
and ten final package/tag suites. The separate Codex catalog retains its 128
rows. MUTATIONS.md identifies every new test/subtest and deciding diagnostic.
Every new top-level test name and selected path is shorter than 40 characters.
No test reads a mutant's literal and no constant success or bypass is credited.

The thirteen new controls remove the actual state/read/policy/turn checks or
restore the old recovery behavior. A malformed-head mutant also blanks the
otherwise-unused import solely to preserve compilation. Every control must
compile, reach its own exact failing assertion and pass that same assertion
in the unchanged candidate. Source anchor inspection is not a runtime red.

The authoring environment was Darwin arm64, Go 1.26.5 and Python 3.13.11.
All 27 changed Go files were formatted before the other checks. The observed
results and failure conditions are:

| Check | Observed result | What makes it fail |
| --- | --- | --- |
| Service literal source review | 228 unique controls, 238 unique edit anchors, all 215 prior IDs retained, all named tests present; new selected paths at most 32 characters | Missing/duplicate anchor or ID, removed ID, no-op, absent test or mutated test file |
| Codex literal source review | All 128 rows have unique anchors after the two vocabulary retargets | Missing/duplicate anchor |
| gofmt -w | Exit 0 for all 27 changed Go files | Go parse/format error |
| gofmt -l | Exit 0 with empty output | Any listed file or nonzero exit |
| Python py_compile | Exit 0 for six service/Codex scripts | Python syntax or missing-input error |
| bash -n | All three service/Codex wrappers exit 0 | Shell syntax error |
| Linux amd64 vet | Exit 1: missing standard-library vendored cpu package and multiple Go cache access refusals | Toolchain/cache failure or vet/compiler diagnostic |
| Linux faults and Darwin vet | Skipped using the brief's explicit cache-refusal route | Not measured |
| Runtime unit/red/candidate/native/installed | Not run on this Mac | Exact new red assertions, unchanged candidate greens and actual native acceptance remain required |

The attempted command was:

```sh
GOWORK=off GOOS=linux GOARCH=amd64 GOPROXY=off GOSUMDB=off go vet ./...
```

vet-linux.json and vet-linux.log in external evidence retain the exact command,
output and exit. The toolchain could not find vendor/golang.org/x/sys/cpu and
could not access Go cache entries. No cache or toolchain was changed, redirected
or retried. Only reporting and evidence collection followed this refusal; no
implementation edit or further source check followed. Compilation is not
established, including resolution of the supervisor-supplied compiler errors.
The source adaptations are authored repairs, not a claimed successful build.

No unit/mutation/native/installed tests, product builds, project interpreter
execution, remote machine or additional agent ran in this Mac round.

The supervisor must run Linux, Linux faults and Darwin vet, the new exact
red/candidate pairs, the normal/faults service inventory, the adapted secrets
and Codex suites/catalogs, and the fix-12 integration controls. Dedicated
authenticator variants and installed native credential delivery remain
separate acceptance work. No authenticated AI-service request was tested.

Final evidence includes source archives, the incremental and full merge diffs,
index/status records, exact commands/outputs/exits, new mutant bytes and a
SHA-256 manifest. There is no tested product binary in this static authoring
round. The resolved fix11_stubs.go and the materialization path in transaction.go
are preserved; transaction.go changes only effect-state serialization.
