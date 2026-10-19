# Draft.4 fix 10 service/store delta report

This uncommitted candidate starts at
fbbf771 in the same service checkout. The
active brief and the complete supplied DELTA1 review were read. The supervisor
reported the prior fix-9 unit run green in both builds, with its 87-control
red run in progress. Those reports are not runtime results for this delta.

The six requested implementation/control findings are addressed in source.
Findings 6 and 7 are recorded as deferred performance work without changing
those paths. Formatting, source-anchor inspection and Python/shell syntax
checks pass. Linux vet was refused by the existing Go cache; the brief's
explicit fallback was used for the remaining variants. Compilation and
Linux runtime acceptance of this candidate remain unverified.

## Per-finding result

| Finding | Candidate change and deciding coverage | Current status |
| --- | --- | --- |
| 1, P2: issued child grant ceiling and original request | checkIssuedLaunchGrants loads launch_authority and the protected original start/adopt frame. It checks reserved set/life/policy/generation, expiry, parent/source identities and delegation; derives GrantRequest entries and applies launchCeiling to the retained ceiling and a one-to-one requested-entry ceiling. Paths/access/expiry may narrow; source identities, destinations and delegation cannot widen. Both separate grant staging and plan sourcing use it, including an already present child set. TestIssuedLaunchGrants submits the actual wider planner transaction; TestIssuedGrantCannotBeStaged submits the separate-write route. launch-issued-ceiling and launch-issued-request name their own foreign_source and request_access assertions. | Source implemented; positive/refusal and two red controls authored. Runtime pending. |
| 2, P3: unreserved lane identity | Every lane-actor identity.bound now requires a retained launch_plan and the complete atomic recovery binding. The current closed catalogs declare no historical identity-import kind, so there is no exception for lifecycle_effect, migration_apply or a legacy_import label. TestLaneIdentityRequiresPlan covers ordinary and legacy origins; TestHistoricalIdentityStaysInert retains inert record history and refuses promotion into a current launch. Existing full ready/binding tests cover the permitted plan-backed path. Two controls target the exact ordinary/legacy assertions. | Source implemented with no historical identity-import exception enabled. Runtime pending. |
| 3, P3: synthetic public request digest | CompleteEffect omits request_sha256 when the operation has no receipt, while retaining the actual receipt digest for public operations. EncodeOperationEvent and the owned wire shape use the same optional field. An explicitly present invalid digest and unknown fields still refuse. TestOperationDigestProvenance covers real public/internal completions and journal verification; TestOperationEventOptionalDigest covers encoding/decoding and strict invalid-field cases. internal-operation-digest restores the old synthetic hash for its named internal assertion. | Source implemented without editing the shared API DTO. Runtime pending. |
| 4, P3: failed plan reserves name forever | reserveNewLife releases an existing name when its previous plan is failed and no Lane projection exists. A present Lane still requires Cleaned. TestFailedLaunchNameReuse commits the actual failed transition and failed effect completion, confirms no Lane, supplies a fresh primitive root ticket, reuses the name for distinct issued IDs and retains the old failed history. The nonterminal-name refusal control remains. launch-failed-name-release names the reuse assertion. | Source implemented; refusal/reuse controls authored. Runtime pending. |
| 5, P3: sibling subtest receives red credit | The four reviewed guard tables have 44 distinct refusal assertions derived from their unique fault names; the continuation table adds five. Relevant controls declare an exact subtest. The driver selects that path, requires the exact FAIL path set for the selected leaf and ancestors, and requires its Go assertion log line. The candidate must run/pass the same paths. A sibling failure, setup failure or free-standing marker cannot earn credit. | Source and static metadata checks complete; driver runtime behavior and actual reds remain unmeasured. |
| 6, P3: open-time full verification | CONTRACT-GAPS records the full journal walk under the existing 120-second open context and the future checkpoint/explicit-full-verify work. | Recorded only; store.go unchanged and no performance measurement claimed. |
| 7, P3: one SQLite handle per pinned read | CONTRACT-GAPS records the read-only handle per BeginRead, its closure with the view and a future pool that preserves transaction/head isolation. | Recorded only; snapshot.go unchanged and no performance measurement claimed. |
| 8, P3: missing deciding red controls | Added launch-claimant for the ClaimEffect scope check; launch-completion-claimant for the completed PlanLaunch replay's claimant check; launch-foreign-cause for the retained reservation refusal; capture-peer-generation and capture-launch-generation for each producer lifetime source. Every control names its own assertion. | Five controls and their real-store component cases authored; runtime pending. |

## Grant and identity test scope

The foreign-source case commits through the actual State.Transact planner
entry under the retained PlanLaunch claim. It supplies the reserved GrantSetID,
matching inputs and grants.issued event, and a separately retained protected
manifest that the starter's grant set never held. Its data entry uses rw at
/work/main, with the matching project-source reference, so a source-shape
mismatch does not supply the intended red. The mutation removes the data
source ID/hash fence in launch_issuance.go, leaving tests unchanged.

Additional issuance cases cover source digest, requested access/path/expiry/
delegation, extra entries and main-workspace destination. The main destination
case is refused first by the shared typed shape with invalid_request; the
other cases require forbidden. After each refusal, the same reservation
commits its requested valid set. A separate test refuses staging unheld
grants without a plan write, rather than assuming all callers source in one
transaction.

The identity exception policy is explicit: no current emitter is designated
as a historical identity-import kind. The positive historical case retains
inert legacy_import record provenance through migration_apply; the negative
case refuses an imported identity as current authority. No new shared enum,
schema key, historical permit or permissive label was invented. An actual
future historical identity-import facility needs its shared contract.

TestBoundLaneCannotEmitForeignLife and TestReplayRechecksRevocation were moved
to the external store test package so they can obtain a real reservation,
sourced plan and ready binding through the existing fixture. Their deciding
assertions and control names remain. They no longer require the removed
unreserved identity projection path.

The new producer-generation cases use actual committed worker identity events
and explicit component peer observations. The retained-generation case creates
a second worker launch through Transact; it does not corrupt an immutable
launch projection and depend on a permissive reopen. All these fixtures remain
store/transport components, not native helper or OS authentication acceptance.

## Mutation inventory and static inspection

All 87 prior controls remain. Eleven additions bring the inventory to 98
controls, 105 edit anchors in 35 production files, two variants, 196
red/candidate pairs and ten final package/tag suites. Twenty-nine controls
select a subtest; the remaining top-level controls still require only their
own failure path, and any failing child is an extra path that defeats credit.

Every original candidate anchor and sequential edit anchor occurs exactly
once. All named tests have one declaration in the inspected component source.
Each in-memory mutant changes only its named production file; tests remain
unchanged. Static inspection confirms unique fault lists/messages for all
five guard tables and that the driver requires exact failure and candidate
path sets. No project Python module was imported to obtain this result.

MUTATIONS.md contains every exact test/subtest and required assertion. These
are source observations, not runtime reds. Compiler errors, setup failures,
wrong diagnostics, unrelated subtests, skips, races, panics, timeouts and
surviving process groups still receive no credit.

## Static checks

Host: Darwin arm64. Tool versions: Go 1.26.5, Python 3.13.11, Bash 5.3.15.

| Check | Observed result | Failure condition |
| --- | --- | --- |
| gofmt -w | All 14 changed/new Go files; exit 0. | A formatter error. Formatting-only edits were expressly authorized. |
| Final gofmt -l | The same 14 files; exit 0 with empty output. | Any listed file or nonzero exit. |
| Trailing blank lines | None in all 20 changed text files. | Any trailing blank line; formatting-only normalization is authorized. |
| Test-name length | All 60 declarations in changed test files are at most 40 characters. | A new test name exceeding the brief's bound. |
| Literal anchors and metadata | All 98 controls / 105 anchors unique; prior inventory retained; exact targets and unique guard assertions present. | Missing/duplicate anchor, dropped control, changed test target, unrelated source mutation or shared deciding guard assertion. |
| Python syntax | scenario.py, mutations.py and run.py; isolated py_compile with -I -S and a protected external pycache_prefix; exit 0. | Invalid syntax or a compiler error. Target modules were not executed. |
| Shell syntax | bash -n on run.sh and run-mutations.sh individually; each exit 0. | Invalid syntax or a parser error. |
| Linux go vet | GOOS=linux GOARCH=amd64; attempted once, exit 1 because existing Go-cache opens returned operation not permitted. | Cache refusal prevented a useful analysis result. No passing vet/compilation result is claimed. |
| Linux faults go vet | GOOS=linux GOARCH=amd64 with -tags laneboss_faults; skipped under the brief's explicit cache-refusal route. | Not run; no pass is claimed. |
| Darwin go vet | GOOS=darwin GOARCH=arm64; skipped under the same route. | Not run; no pass is claimed. |

The vet package scope was:

```sh
GOOS=linux GOARCH=amd64 go vet ./internal/v2/client/... ./internal/v2/service/... ./internal/v2/store/... ./internal/v2/cli/...
```

The protected evidence retains the full verbatim vet-linux.log and command
exit. No cache setting, alternate cache, override or repeat was used. The
supervisor must run all three vet variants in its permitted environment.

No test, test binary build, product binary execution, project interpreter run,
remote action, machine, model request, staging or commit was performed in this
authoring round. The prior fix-9 green report does not supply before/after
credit for these new methods or controls. The supervisor must run the actual
Linux reds and unchanged candidate tests, then the composed installed gate.

## Evidence and remaining handoff

The fresh protected round is lb-v2-service-evidence/d4fix10-fbbf771. It retains
the exact brief and full delta review, clean baseline revision/source bytes,
phase and final candidate source including new files, diffs/status, parser/
literal inventory, all per-anchor and assertion metadata, static commands/
outputs/exits, cache refusal/skipped variants, and final manifest/checksums.
There is no tested product binary in this static-only round.

The existing real planner/grant/helper/capture and integrate fix-11 enrollment
dependencies remain in CONTRACT-GAPS and LAUNCH-PLAN. The concrete ports remain
HumanEnrollments(context.Context, string) ([]api.HumanEnrollment, error) and
InstallHumanEnrollment(context.Context, api.Scope, api.InternalIntent,
api.EnrollmentInstall, api.ObjectWrite) (api.Commit, error). Authentication,
attestation/UP/UV and ceremony entry remain their owners' work.

The candidate is ready for source review and the supervisor's permitted
verification. It has not been accepted, staged or committed.
