# Grants mutation map

mutations.json gives each named mutation a changed check, a focused test and
its expected failure. The runner changes only a disposable copy of this lane's
production files. A `ready` entry has an implemented unit injection point;
it does not claim a measured red result. A `blocked` entry has no implemented
OS check to mutate yet. Selecting one returns 69 and a not_implemented result.

## Each acceptance rule and its failing control

| Acceptance rule | Named mutation and focused test | Remaining OS proof |
| --- | --- | --- |
| L5 to L3 narrow file/repository selection matches the child view | narrow-preview → TestNarrowPreview; selected-view → TestSubtreeSelection | os-inside-view → actual GRANT-BOUND view, blocked on confined copy and output identity. |
| Wider path requests refuse before effects | traversal → TestWideningRefused, dot-alias case | Actual registered-source path and descriptor canaries are pending. |
| Wider access refuses | data-access → TestWideningRefused, ro-to-rw case | Repeat through CLI and inside read/write controls. |
| Delegation never grows | delegation → TestWideningRefused, delegation case | Repeat through real nested lives. |
| Expiry never grows; expired authority refuses | expiry-ceiling and expired-grant → TestWideningRefused, corresponding cases | Repeat before release and resume. |
| Resource selection and concurrency/cost stay bounded | resource-region, resource-active, resource-hourly, resource-total → TestAllCapabilityFamilies | Actual CLI refusal needs the installed service. These tests provision nothing. |
| Secret, profile, network and channel selections stay bounded | secret-version, profile-selection, network-selection, channel-selection → TestAllCapabilityFamilies | Enrollment and secret injection remain live-cell dependencies. |
| Level never widens authority | strict-lower → TestWideningRefused, same-level case | Authentic L5 to L3 CLI fixture depends on identity/lifecycle. |
| Recheck on resume/revocation | grant-revocation → TestRevokedChain; materialize-recheck → every TestMaterializeRecheck case | os-resume-revocation → actual resume after revoke, blocked on lifecycle and durable cleanup. |
| Source reads cannot hide a concurrent authority change | after-source-recheck → every TestSourceReadRecheck case; final-recheck → TestMaterializeFinalCheck | Final release still needs ancestor/policy CAS and a matching permit. |
| Child resume/stop during candidate reads invalidates testing | child-read-recheck → every TestChildReadRecheck case | Worker release must serialize with lifecycle. |
| No extra Git refs or common administration | git-administration → TestGitAdministration, including pointer, commondir, alternates, refs and hooks | os-git-extra-refs → actual independent objects, blocked on requested-history and Git jobs. |
| Symlink escape/alias refuses | source-link → TestFileGrantAndLinkBoundary | os-source-swap → actual broker source swap, blocked on opened identity/lease delivery. |
| External hardlink refuses | hardlink-kind → TestSpecialObjectKinds, hardlink case | os-hardlink → actual intake canary, blocked on descriptor importer. JSON kind rejection is not this proof. |
| Nested mount refuses | nested-mount-kind → TestSpecialObjectKinds, mount case | os-nested-mount → actual registered export, blocked on recursive mount identity. |
| Real child test/Git hook cannot read parent canary | parent-worker-scope → TestChildTestScope checks the exact set sent to the worker | os-parent-execution → CHILD-CODE using child_probe.c and the Git-invoked hook; job/permit/capture ports are missing. |
| Ordinary child build succeeds | narrow-preview and selected-view preserve ordinary inputs; os-deny-build must fail the actual CHILD-CODE build control | Existing scripts require real build_exit and git_exit records from private scratch. This OS mutation is blocked until worker execution works. |
| Bypassed subset/FD resolution fails | data-access, delegation, traversal, selected-view and source-link cover implemented checks | os-source-swap and os-nested-mount cover the pending FD boundary. No unit certifies it. |
| Parent/sibling inputs cannot silently enter a child test | artifact-origin → TestArtifactOrigins; parent-worker-scope → TestChildTestScope | Actual scope/canary still needs os-parent-execution. |
| Materialization identities match grants and independent destinations | materialized-alias and materialization-fields → TestMaterializeReceipts | Actual inode/snapshot read-back remains a worker dependency. |
| Worker result has a valid durable receipt | operation-status and operation-fields → TestDurableTestReceipt; worker-false-success → TestWorkerMissingPorts | Actual exit, capture and quiescence remain worker-framework proofs. |
| Source/RPC input is not substituted | source-digest → TestBlobDigest; reference-size → TestReferenceBounds; duplicate-key → TestStrictJSON; launch-revoked → TestWideningRefused | Transport/peer identity remains the service/identity lanes' OS proof. |

The store, launcher and receipt fixtures are in-memory unit wiring fixtures.
They do not certify an actual copy, inode, Git import, process or sandbox. The
blocked OS entries are planned named scenarios, not implemented Go subtests or
successful canaries. Their production checks and complete cases must land
before a mutation can be applied or any full acceptance can be claimed.

Draft.3 retains all 36 earlier ready controls and adds seven below, giving
43 ready unit mutations and eight blocked OS plans. None of these counts is
a measured Linux red/green result.

| Draft.3 boundary | Mutation and failing assertion |
| --- | --- |
| Actual committed object metadata overrides caller labels | committed-metadata → every TestCommittedMetadata case; bypassing the metadata identity/size/digest/class/config checks must expose the mismatch. |
| An authentic child event also needs actual child ownership | artifact-metadata → every TestArtifactMetadata case; service/sibling/parent ownership must refuse even with a matching child event. |
| Large files use bounded ordered parts and an exact total | assembly-shape → every TestAssemblyShape case; a bypass accepts malformed digest/size/part declarations and the invalid-input assertion fails. |
| Files have one byte source, and directories/links have no assembly | assembly-entry → every TestAssemblyEntry case; bypassing entry validation accepts ambiguous metadata. |
| Parts yield the declared ordered byte digest and length | assembly-bytes → every TestAssemblyBytes case; ignoring concatenated bytes lets changed order, size or digest pass. |
| Current authority cannot reuse a stale response snapshot | authority-snapshot → TestPinnedChildRecheck; reusing the borrowed snapshot reaches the fixture's explicit fresh-read refusal. |
| D6 preflight binds configuration, source generation and renderer | render-snapshot → every TestRenderSnapshot case; removing its validation reaches the typed unavailable renderer instead of rejecting malformed input. |

The original source-digest control now corrupts actual bytes while retaining
matching committed metadata and the input ref. The reference-size fixture
injects metadata claiming a prefix. This preserves both earlier byte controls
after the metadata checks are added. Assembly shape references are synthetic;
ordered-byte tests use small real parts. They do not certify an OS installation.

## Run a red assertion followed by its unchanged green control

On the authorized Linux box, from the exact candidate source:

```sh
python3 -E e2e/v2/cases/grants/prove-red.py \
  --source /test/source --evidence /test/grants-red-access \
  --mutation data-access
```

Require exit 0, the targeted red failure for the catalog's reason, the same
focused test passing in the unchanged candidate, and the final pass line.
results.json names all failed tests, both exits, both source digests and the
retained unit binary digests. Raw JSON test events, stdout/stderr, exact
commands, source bytes and binary bytes remain beside it. Compile errors,
timeouts, unmatched anchors, no reached test, or a different assertion failure
stop the proof; they cannot kill a mutation.

Use `--mutation all-ready` for all implemented unit mutations. Use a new
evidence directory and `--tags laneboss_faults` for the tagged build. `--list`
prints names and availability. The all-ready result retains the blocked list
and full_os_acceptance false. A blocked selection returns 69 without inventing
an injection point or executing a stand-in.

The runner discovers the actual main-module test dependency closure through
Go, including tests and embedded files. Dispatcher controls also retain their
actual Python runtime inputs and the sealing helper's Go dependency closure.
It retains one unchanged snapshot and copies each red tree from it.
It builds only the selected package and executes
only the named tests, red before green. It never changes the checkout, Git
index, frozen contracts or another lane's production files. Go module updates
are disabled. The source digest's scope is the retained main-module dependency
closure plus declared dispatcher runtime inputs; the Go toolchain and external module versions remain pinned tool
inputs recorded by metadata and go.mod/go.sum.

All executable proof work stays on the Linux box. Mac checks remain static.

## Final draft.4 review controls

There are now 174 ready unit mutations and eight blocked OS plans. All 43 earlier
unit controls remain. Three entries were ported with their assertions retained:
grant-revocation uses the live/stored validator split; source-link removes both
the intermediate traversal floor and final bound; assembly-bytes targets the
streaming worker primitive. No runtime red/green result is claimed by this map.

| Finding | Named mutation / required failing test |
| --- | --- |
| Normal ancestor states retain checked authority | ancestor-live-state / TestAncestorLiveStates (all five previously refused normal states). |
| Human read sessions bind principal/config/endpoint/time | human-read-session / TestHumanReadAuthority. |
| Human mutations bind verified frame, params, digest, target and unused proof | human-operation-proof / every TestHumanMutationProof case. |
| A human job cannot escape the atomic proof/effect gate | human-worker-handoff / TestHumanWorkerGuard. |
| Root issuance preserves exact proof target and state writes | root-proof-binding and root-grant-write / TestRootAtomicIssue. |
| Root replies describe a completed durable operation and exact sealed result | root-operation-status, root-durable-reply, root-reply-seal / corresponding TestRootDurableReceipt subcases. |
| Root channels use current enrollment and expiry | root-channel-enrollment and root-channel-expiry / TestRootChannelEnrollment. |
| Intermediate link traversal cannot leave the selected root | intermediate-link-floor / TestIntermediateLinkEscape using actual escaping link entries. |
| Directory links cannot create self/parent/sibling cycles | directory-link-cycle / TestDirectoryLinkCycles. |
| Filesystem aliases and root nodes are unambiguous | filesystem-case-alias and object-root-kind / TestFilesystemAliases; destination-case-alias / TestDestinationAliases. |
| Implicit directories stay within a bounded index | implicit-directory-bound / TestImplicitDirectoryBound. |
| Authorized stored history remains inspectable | stored-grant-history / every TestStoredGrantHistory case. |
| Invisible grant existence is hidden in get/revoke | grant-existence-hidden / TestGrantExistenceHidden. |
| Policy/source reads retain lane context and a live snapshot | policy-lane-context and source-pinned-view / TestRevalidationContext. |
| Referenced entry blobs have actual committed metadata | source-entry-metadata / every TestSourceEntryMetadata case. |
| Service preflight does not read file bodies or repeat per-entry metadata | service-file-body and candidate-meta-dedup / TestCandidateReadBounds. |
| Candidate totals and service verification work are bounded | candidate-disk-total / TestCandidateReadBounds; service-byte-budget and service-meta-budget / TestServiceReadBudget. |
| Plan authority refusal precedes a caller-selected candidate disk ceiling | child-test-budget-order / TestChildTestScope; moving the ceiling earlier must produce budget_exhausted where forbidden is required. |
| Candidate manifests have the manifest class | candidate-manifest-class / TestCandidateClass. |
| Member expiry does not clamp unrelated grants | set-expiry-ceiling and derived-expiry-ceiling / TestExpiryUpperCeiling. |
| Configuration names follow the frozen spelling | configuration-spelling / TestConfigSpelling. |
| Lane requests cannot carry human proof authority | lane-human-proof / TestLaneProofRefused. |
| Every grants file form registers its shared semantic check before proof/key/transport work | cli-input-registration / every TestCLIFileValidators method, request/positional form and invalid/valid case. |

The CLI validator round ports candidate-manifest-class to the shared
manifest/input.go check without changing its assertion. The new registration
control removes only this lane's five initializer rows and requires all 20
file-form assertions to fail at that missing-registration boundary. The runner
can mutate only commands_grants.go in the shared CLI package; other CLI files
remain outside its source ownership.

The before-fix/candidate evidence must come from the Linux runner, including
each listed required subcase and its exact assertion. A compile error, setup
failure, missing test, assertion from another boundary or surviving mutation
fails that run. The source and binaries are retained for both phases.

## Draft.4 fix 9 consumer controls

All 77 prior unit controls remain unchanged. The 31 new launch-* controls
bring the ready count to 108; the eight OS plans remain blocked. These are
implemented injection points, not measured runtime results.

| Boundary | Named controls and required assertions |
| --- | --- |
| Reserved identities and inert replay | launch-reserved-ids / both TestReservedGrantResolution modes; launch-reserved-life / TestReservedParentDelegation. |
| Original input belongs to the reservation | launch-reservation-selector, launch-original-origin, launch-original-operation, launch-original-private and launch-original-digest / corresponding TestReservedGrantGuards cells. |
| Root ticket retains current authority | launch-root-principal, launch-root-endpoint, launch-root-consumed, launch-root-expiry and launch-root-redelegation / corresponding TestReservedGrantGuards cells. |
| Issued and current ceilings remain exact | launch-issued-replay / issued-changed; launch-fresh-authority / TestReservedFreshAuthority; launch-parent-creation / TestReservedParentGuards/creation. |
| File/subtree never inherits reachable history | launch-history-ceiling / TestReservedHistoryCeiling, removing both the reducer and independent source-root check. |
| Retained life uses its real recovery/session/base | launch-retained-binding, launch-retained-history and launch-retained-base / corresponding TestRetainedGrantGuards cells; launch-retained-result / all three TestRetainedGrantResolution modes. |
| Current enrolled executable remains pinned | launch-source-enrollment / TestLaunchDataGuards/executable. |
| Sourced selector refuses before helper lookup | launch-data-reservation / TestLaunchDataGuards/foreign-grants, requiring no storage lookup. |
| Current and retained storage ownership agree | launch-storage-life and launch-storage-replay / storage-life and changed-home. |
| Output provenance belongs to the original operation | launch-output-operation / output-operation. |
| An allocation alone cannot claim completed work | launch-data-barrier / TestLaunchDataMissingFramework. |
| Verified retained data can be replayed | launch-data-replay / TestLaunchDataReplay. |
| Service verification is fixed and bounded | launch-service-bytes and launch-service-reads / TestLaunchServiceBounds. |
| Caller paths/executables/child IDs are not request fields | launch-selector-fields / all three named TestReservedLaunchSelectors field cells. |
| An already cancelled operation performs no reads | launch-cancel-boundary / TestLaunchEarlyRefusals/cancelled. |

The byte-bound control supplies actual 64 MiB artifact bytes, not a falsely
declared oversized object. Read-only replay tests do not certify the missing
fixed-worker bootstrap, initial Git/copy job, UID allocation or real agent
launch. Those stay open under LP-DATA-JOB-1 and the existing OS plans.

## Draft.4 fix 10 consumer controls

All 116 prior catalog entries remain unchanged. The 41 new fix10-* controls
bring the total to 149 ready unit controls plus eight blocked OS plans, with
159 exact source patch anchors. These are source injection definitions. No Mac
static result is a reached red or candidate runtime pass.

| Boundary | Controls and deciding assertions |
| --- | --- |
| Start/adopt consume stored pins | fix10-start-level/role/driver/ticket and fix10-adopt-level/role/driver/ticket / the matching TestLaunchReservationPins mode/pin cell. Valid records retain their stored pins while only the original body changes. |
| Consumed proof and lane/root separation | fix10-consumed-proof / every TestLaunchConsumedProof cell. |
| Actual current starter record | fix10-starter-current / kind / revoked / actor / run / corresponding TestLaunchStarterAuthority cells. |
| Retained plan and current life agree on pins | fix10-retained-level/role/driver / TestRetainedReservationPins; each removes both deciding checks to expose the same substituted pin. |
| Recovery is an agent binding with exact role | fix10-prepared-binding / all TestRetainedPreparedBinding cells, with correctly recomputed record hashes. |
| Refused capture blocks retained execution | fix10-retained-capture / resume, turn and continue in TestRetainedCaptureRequired. |
| Capture exception is protected current policy | fix10-capture-policy and fix10-capture-recheck / disabled and changed-during-read in TestLaunchCaptureCurrentPolicy. |
| Runtime agrees with stored driver | fix10-source-driver / TestLaunchSourceDriverPin; a merely sourced record cannot replace the driver's pin. |
| Continuation keeps its operation and truthful phase | fix10-continue-operation and fix10-continue-pending / intent-id and pending-success in TestLaunchContinuationOperation. |
| Worker authority is current and claim-bound | fix10-worker-lease and fix10-worker-claim / lease and claim in TestChannelJobPreflight. |
| Channel job is the retained enrolled job | fix10-channel-effect / runtime / destination / input / corresponding TestChannelJobPreflight cells. |
| Sealed bytes have service provenance and digest | fix10-worker-input-origin and fix10-channel-payload / origin and payload in TestChannelJobPreflight. |
| Channel execution uses fixed argv and committed identity | fix10-channel-execution and fix10-channel-binding / argv and binding in both send/readback modes of TestChannelExecutionPreflight. |
| Missing preparation backend cannot become success | fix10-channel-barrier / valid-closed in TestChannelJobPreflight. |
| Review candidates bind the job/run/end and evidence classes | fix10-review-run / end / diff-class / check-class / plan / corresponding TestReviewJobPreflight cells. |
| Missing measured verifier cannot become coverage | fix10-review-barrier / valid-closed in TestReviewJobPreflight. |

Fixture construction calls production validators, including actual ticket/proof/
cancellation request shapes. Registered capture and approved refused capture
are distinct inputs. No fixture bypasses a live validator. Preflight barrier
tests require an owning error and no usable handoff, provider receipt or review
coverage. They do not authenticate a worker or measure a provider/test job.

Shared API controls for the closed coverage vocabulary, actual review acceptance,
prepared transaction writes without LaunchPlans, launch_plan emitter union,
lane.check/lane.state and complete continuation intent/swap/result validation
remain in the integration catalog. Grants does not widen that write authority
or copy shared-source mutants into its owned catalog. Actual native worker,
capture/D6 consumption, independent review and provider read-back still require
their installed Linux/Darwin acceptance rows and the missing job handoffs.

## Draft.4 fix 11 data-stage controls

All 149 previous ready control IDs stay ready. Resource-total removes only its
upper ceiling; its original replacement duplicated a negative clause and was
rejected by bool vet. The unchanged total=101 test has no second parent-total
ceiling. launch-data-barrier follows the actual missing Controls refusal. No
control is removed or marked blocked. There are 25 new f11-data-* controls,
174 ready rows, eight blocked OS plans and 184 exact patch anchors.

| Controls | Deciding assertion |
| --- | --- |
| f11-data-parent, input, storage, open, argv, epoch and grants | Matching TestMaterializationStageGuards cell: invalid stage cannot reach helper storage/await, before later duplicate defences. |
| f11-data-result, readback, source, run, operation and process | Matching TestMaterializationResultGuards cell: invalid result cannot reach acknowledged-object reads; changed Data is re-acknowledged to prevent a stale-hash mask. |
| f11-data-flow | TestMaterializationStageFlow requires exact returned data from one awaited and acknowledged child stage. |
| f11-data-home | TestMaterializationCopyAndAck reads the actual private vendor directory. |
| f11-data-bootstrap | input rejects valid JSON whose exact sealed bytes changed. |
| f11-data-bytes | source-bytes rejects real altered data through the shared copy/read-back digest primitive. |
| f11-data-hardlink | hardlink rejects an actual external source-file link. |
| f11-data-root | root prevents a foreign empty private root from reaching object reads. |
| f11-data-tree-readback | output-extra prevents acknowledgement with actual ungranted destination files. |
| f11-data-ack | ack refuses changed result acknowledgement bytes. |
| f11-data-replay | TestMaterializationRetainedStage preserves completed data after historical job expiry without executing again. |
| f11-data-owner | TestMaterializationOwnerErrors/stage requires the actual owner error identity. |
| f11-data-runtime | TestMaterializationRuntimePin blocks a foreign artifact before opened storage. |
| f11-data-exclusive | destination-race preserves actual bytes and requires EEXIST for a file created after the empty-root check. |

Fixtures call real stage/principal/input/result validators and perform actual
ordinary private file IO on Linux. Native UID/claim/process facts are synthetic;
they do not prove installed confinement or terminal observation. The proof
runner requires every named diagnostic and rejects unexpected failing subtests.
Static source validity and the private 149-row audit cannot replace each reached
red and same-candidate pass in both Linux builds.

## Draft.4 fix 12 regression controls

All 174 prior ready entries and their assertions remain unchanged. Six new
f12-* controls bring the catalog to 180 ready unit controls and eight blocked
OS plans. These are source definitions pending Linux red/green measurement.

| Control | Deciding assertion |
| --- | --- |
| f12-helper-error | TestLaunchDataMissingFramework requires the exact injected helper error identity, owner, code and one exact source-port request. Reconstructing even the same admin error must fail. The helper is local, independent of the real admin constructor. |
| f12-root-template | TestHumanRootTemplateRead/valid issues a real root through GrantsRoot, stores its transaction, and requires exact get equality without inventing a Lane. |
| f12-root-session | The root read's principal, config, endpoint, expired and idle cases require forbidden and no returned grant data. Other connection checks and lane visibility remain in force. |
| f12-root-lane | The same issued root remains hidden from a lane caller without a target Lane, with not_found and no grant data. |
| f12-root-mode | TestMaterializationRootMode/public, restricted and output-public require the exact typed invalid error before any workspace/home entries or acknowledgement. Late integrity refusal cannot satisfy these assertions. |
| f12-root-private | TestMaterializationRootMode/private requires actual copied bytes and the worker acknowledgement while both root modes remain 0700. |

The worker-only root-mode fixture reseals the actual manifests, narrow grants,
job input and principal pins. Native facts remain synthetic. Existing implicit
root copy tests continue to cover an omitted `.` entry. The shared outside-walk
ReadBackSHA256 contract remains with the API/service owners.

## Draft.4 fix 13 authority and filesystem controls

The catalog has 192 distinct ready source mutations, eleven selectable legacy
aliases and eight blocked OS plans. All 180 earlier ready names remain
selectable. The six duplicate stage names alias f11-data-parent, which now
requires all seven TestMaterializationStageGuards cases. The five duplicate
result names alias f11-data-result, which requires all six result cases. Each
shared validator call is one actual fault, with no claim of thirteen distinct
source mutations. Alias requests and canonical IDs are retained in results.

Nine earlier test functions now use independent named subtests. The two expiry
controls directly exercise manifest.Set and derive respectively, so a preflight
failure cannot satisfy the derive control. Root proof/writes, policy/source
contexts, candidate bodies/metadata/disk, child worker/budget/run/subtree,
file/link boundaries, filesystem case/root nodes, directory cycle forms and
configuration spellings each have their own deciding case. No earlier assertion
or test function was removed. Existing f11-data-home/hardlink and f12-root-lane
patches were ported across the new defenses; the hardlink control removes both
pre-open and opened checks, and lane visibility removes both read gates.

| Boundary | New controls and deciding tests |
| --- | --- |
| Authenticated template ownership | f13-root-owner / TestHumanRootTemplateRead / other-principal supplies a different valid read session and requires not_found with no grants; f13-root-issuance requires the retained issuer event. |
| Session time bounds | f13-root-time and f13-root-idle target absolute and idle expiry separately; f12-root-session retains the three principal/config/endpoint cases. |
| Current and delegating lifecycle state | f13-direct-state requires all four post-exit direct-parent refusals; f13-current-state rejects an unknown current life. |
| Actual retained starter authority | f13-retained-authority requires every sibling / self / kind / revoked / actor / run / policy / level / role case for both resume and turn. f13-retained-revoked separately mutates the actual LaunchRecord revocation predicate. |
| Retained request budget | f13-retained-budget and f13-retained-disk target invalid and undersized original budgets. |
| Live narrow worker grants | f13-worker-expiry, ceilings and identities each target their own named test group and source guard. f13-worker-release expires narrower grants during real fixture copying while the native-shaped lease remains live. |
| Granted output shape and metadata | f13-snapshot-tree and metadata target separate TestLaunchSnapshotAuthority groups; altered byte refs have matching actual retained artifact bytes so another metadata mismatch cannot mask the shape guard. f13-output-manifest checks a separate materialization manifest while the workspace snapshot remains correct. |
| Kernel open flags | f13-open-nofollow requires actual file/intermediate symlink refusals after an observable regular control; f13-open-nonblocking reads the actual FIFO descriptor flags through SyscallConn with a paired peer, so its red run cannot hang. |
| Source kind before opening | f13-source-preopen requires the exact pre-open integrity refusal for a real FIFO, symlink-to-FIFO and symlink-to-file. The separate kernel-open controls remain required. |
| Exclusive and exact home | f13-home-exclusive refuses an existing directory; f13-home-readback refuses actual extra files. |
| Directory permission handoff | f13-directory-mode / TestJobDirectoryModes requires the actual copied directory mode before complete file/mode read-back. |

The parser rejects duplicate (test, failure) keys and duplicate source patch
sets before source discovery or building. catalog_test.py supplies independent
duplicate-assertion, duplicate-patch, alias-collision and real-catalog checks.
All executable proofs remain Linux-only. Static validity, fixture DTOs and a
read of O_NOFOLLOW in source are not installed race/confinement acceptance.

## G3 protected root-profile controls

All 192 prior ready canonical entries, eleven aliases and eight blocked plans
remain. Thirteen new controls bring the ready count to 205. Every new control
uses the real encrypted broker backend with declared synthetic enrollment
metadata. No credential, profile lease or authenticated vendor is supplied.

| Control | Focused deciding assertion |
| --- | --- |
| g3-profile-stub | TestRootProfiles/enrolled fails resolution if the old stub returns. |
| g3-profile-retention | The same positive test requires both exact driver selectors in the durable result; dropping Profiles fails its separate preservation assertion. |
| g3-profile-only | TestRootProfiles/profiles-only requires a root with no data/channel grant. |
| g3-profile-missing | missing requires the native not_found and zero transactions; swallowing the actual Read error must fail. |
| g3-profile-foreign | foreign requires forbidden for a locally encrypted payload whose configuration differs. |
| g3-profile-identity | identity requires forbidden when the payload ID differs from its journal selector. |
| g3-profile-driver / provider / paid | Each named subcase changes only its protected field and requires forbidden before the root transaction. |
| g3-profile-generation | generation requires integrity for zero protected generation. |
| g3-profile-exclusion | excluded requires forbidden under current policy. |
| g3-profile-ceiling | Both ceiling and source-expiry must reach and fail the enrollment-guard assertion when their shared bound check is removed. |
| g3-profile-policy | TestRootProfileOrder/changed-policy requires a fresh policy check before any profile read after journal lock entry. |

Positive tests additionally require fresh distinct member IDs, exact raw human
input/proof, no WorkerLeases or effects and the enrollment lock during commit.
Locked and unwired backends remain prerequisite failures. Proof, manifest and
initial-policy ordering cases require no profile reads and no transaction.
Mac static checks cannot prove any of these executable assertions; retain the
Linux red and same-candidate green evidence before crediting them.

## G3 round-b review controls

The catalog now has 216 ready canonical controls, eleven aliases and eight
blocked OS plans. All previous control IDs, focused tests and diagnostics stay.
The prior g3-profile-exclusion mutation removes both initial and final exclusion
checks so its original assertion cannot be masked by the new release defense.

| Finding | New control and deciding assertion |
| --- | --- |
| P0 rejects every evidence class | g3b-evidence-valid restores the old validator and must fail TestProfileEvidence/valid at credential evidence rejected a valid profile. |
| P0 malformed evidence | g3b-evidence-fields bypasses the credential reference check; class, ID, digest, negative and oversize cases must each fail their malformed-evidence assertion. |
| P1 unwired profile | g3b-unwired-code restores not_implemented; TestRootAndRevokeStayClosed must fail its exact prerequisite/no-write assertion. |
| P1 other capability families | g3b-capability-codes requires all secrets/network/resources cases; g3b-export-code requires the non-copy export case. Each demands not_implemented with no result/write. |
| P2 provider name | g3b-provider-name supplies the same malformed provider in manifest and encrypted record, preventing equality from masking the missing grammar check. |
| P2 optional usage | g3b-usage-fields removes usage validation and requires all fourteen invalid usage-field cases. Valid Claudock usage and the absent-usage controls must remain accepted. |
| P3 fresh view | g3b-release-view reuses the pre-source snapshot and must fail the positive data control's actual transaction-view assertion. |
| P3 generation | g3b-release-policy requires data-policy and channel-policy to fail the changed-authority assertion. |
| P3 exclusions | g3b-release-exclusions requires data-excluded and channel-excluded; both change only current exclusions after initial resolution. |
| P3 scope | g3b-release-scope requires data-scope and channel-scope; each ends the human peer during its source read. |

The unchanged expiry tests require forbidden. They cannot be rewritten to
accept an earlier integrity refusal. Evidence validation does not add a class
to manifest.Blob, fetch a credential, mint a profile lease or run a vendor query.
All assertions remain unmeasured until their Linux red/green execution.

## G7 reserved profile controls

All 216 previous ready canonical controls, eleven aliases and eight blocked
OS plans remain unchanged. Eight new controls bring the ready count to 224.

| Control | Deciding assertion |
| --- | --- |
| g7-issued-member | All six TestLaunchProfilePick root/adopt/child and codex/cli cases require exact equality with the canonical issued member and reject the original parent ID. |
| g7-profile-choice | TestLaunchProfileChoice requests the second of two approved profiles; selecting another approved entry must fail. |
| g7-selector-fallback | TestLaunchProfileGuards/selector requires forbidden and no returned member for an unknown original selector. |
| g7-selector-ambiguity | ambiguous requires the early forbidden result; allowing duplicated selectors to reach a later shape error cannot satisfy it. |
| g7-profile-driver | driver requires forbidden even when the selected profile is otherwise granted. |
| g7-profile-spend | TestLaunchProfileSpend/paid-none refuses a paid profile without the original budget's spend authority; free and paid-authorized cases remain valid. |
| g7-profile-excluded | excluded refuses a current policy exclusion. |
| g7-profile-fresh | changed-profile mutates the protected ceiling during the actual fixture source read and requires conflict with no usable profile; reusing the first resolution must fail. |

Additional negative cells retain profile identity, expiry, delegation, scope,
policy, revocation, stored-set replay and original-input verification through
the shared canonical resolver. A retained-mode case refuses remapping resume
as a new start. These fixtures prove no actual credential, lease or agent work.
At that routing-only handoff, G11 had no executable removal port to mutate.
The collector controls below supersede that gap; a placeholder result or
source-only helper read still supplies no runtime proof.

## G11 cleanup collector controls

All 224 prior ready controls, eleven aliases and eight blocked OS plans stay.
Nine new source controls bring the ready count to 233. They mutate owned
collector code only and are compiled/executed by the Linux proof runner.

| Control | Deciding assertion |
| --- | --- |
| g11-collector-stub | TestCleanupCollector requires the actual independently verified retained receipt. |
| g11-independent-readback | TestCleanupRefusals/namespace restores removed fixture bytes after retention; bypassing VerifyCleanup must fail its typed refusal/no-receipt assertion. |
| g11-protected-objects | referenced and unowned both require forbidden before workspace removal when the writer response proposes an illegal removal. |
| g11-workspace-fence | post-objects requires no administrator operation after the claim is lost during object collection, even if the administrator would independently refuse. |
| g11-object-fence | fence requires no writer object operation after workspace inspection invalidates the claim. |
| g11-original-intent | intent requires the protected intent mismatch to stop before inventory access. |
| g11-receipt-read | receipt-read requires the exact injected owner refusal from the actual retained receipt lookup. |
| g11-claim-executor | TestCleanupHelperPort uses different original cause and current claimant IDs; using the cause actor must fail the positive collection assertion. |
| g11-dirty-gate | dirty requires retention before the object writer is called, even if that writer has its own dirty-work guard. |

The positive case checks actual fixture removal/retention bytes, all independent
reads, exact receipt identity and fresh replay. There is no constant success,
skipped error, native helper substitute or collector-owned lane.cleaned commit.
No control overlay is vetted on the Mac; static anchors are not reached red
assertions or candidate runtime passes.

## G11 round-2 refusal gates

Eight controls bring the ready count to 241; all 233 earlier ready controls,
eleven aliases and eight blocked OS plans remain. They cover the added
pre-administrator object validator and each previously uncovered refusal gate.

| Control | Deciding assertion |
| --- | --- |
| g11-object-readbacks | TestCleanupObjectGate requires all four before-absent, after-present, eligible-retained and retained-absent results to refuse with invalid_request before any administrator, retention, lookup or independent verification call. |
| g11-replay-echo | TestCleanupReplayGate/echo-replay refuses the old after observation by its exact integrity message before another writer or administrator operation. |
| g11-replay-order | TestCleanupReplayGate/unordered-replay refuses a distinct observation older than the actual journal's after time; the observation passes the earlier shared removal validator. |
| g11-dirty-result | TestCleanupRefusalGates/retain-dirty requires conflict for a valid retain_dirty administrator result after a clean preflight, without retaining a receipt or claiming removal. |
| g11-retained-match | TestCleanupRefusalGates/retain-swap refuses a self-consistent retained receipt that changes the proposal before any lookup or verification. |
| g11-readback-match | TestCleanupRefusalGates/read-swap refuses self-consistent substituted lookup bytes before independent verification, with the exact retained-readback integrity message. |
| g11-object-count | TestCleanupRefusalGates/omit-object requires the original omitted-disposition integrity refusal and zero administrator/receipt calls. |
| g11-object-order | TestCleanupRefusalGates/reorder-object requires the original substituted-object integrity refusal and zero administrator/receipt calls. |

The count/order controls bypass both their specific guard and the shared
preflight. Their specific branch returns without indexing a missing result,
then the bypass makes the administrator reachable; only a late receipt check
refuses. Exact codes/messages and call counts must kill that mutation, so a
late refusal cannot fake coverage and a panic is not the deciding diagnostic.
All fixtures retain actual byte maps and journal/read-back validation. This
round adds no current-claim replay workaround, native implementation or Mac
runtime result. Every named red and unchanged focused green still runs only
on the authorized Linux runner.

## G11 successor-claim replay controls

Six controls bring the ready count to 247; the 241 earlier ready controls,
eleven aliases and eight blocked plans remain unchanged. Production code fetches
the original removing claim only from the installed store port, preserves it
unchanged, and retains the receipt under the current claim.

| Control | Deciding assertion |
| --- | --- |
| g11-reclaim-live | TestCleanupReclaim/after-remove and /after-receipt require replay after A expires and B reclaims, a B receipt with the unchanged A journal, actual store-port proof reads, independent verification and no second workspace removal. |
| g11-strict-current | TestCleanupStrictClaim requires current-claim cleanup and exact retry to work without the optional historical port. |
| g11-reclaim-proof | TestCleanupReclaimRefusals / unknown-remover and /no-removal-reads require integrity and no receipt/administrator call. Its two patches bypass only the component store's claim-ID mismatch refusal and the missing-adapter guard; normal proof lookup and the other refusal gates remain active. |
| g11-reclaim-effect | TestCleanupReclaimRefusals / foreign-effect requires invalid_request at the consumer's shared validation before any receipt retention; normalizing A's effect must fail the error/operation-count assertion. |
| g11-reclaim-generation | TestCleanupReclaimRefusals / higher-generation requires invalid_request for A later than B before receipt retention; making A look older must fail the assertion. |
| g11-reclaim-intent | TestCleanupReclaimRefusals / foreign-intent requires the store's exact-journal integrity refusal; rewriting the lookup's intent must fail the exact code/message assertion. |

All refused cases assert the exact code, owner, message, writer/admin/receipt/
verification calls and claim-port reads. A later writer/receipt refusal cannot
stand in for the consumer boundary. Corrupted effect/generation returns are
explicit adversarial component inputs; the real store also validates A before
returning it. A serialized restart copies actual object/blob/journal bytes and
does not hand an old claim to the collector as an argument. No process, native
Git or SQLite durability proof is claimed by these fixtures or Mac vet.

The proof control keeps the whole TestCleanupReclaimRefusals selection and its
original two required failures. It does not skip the common proof-port call:
foreign-effect and higher-generation still obtain their retained claim and
reach the shared replay validator, while foreign-intent still reaches the
component store's independent exact-journal comparison. The missing-adapter
patch applies only when no port exists. The unretained-remover patch changes
the component port's structural claim-ID branch, leaving candidate Go source,
test inputs/assertions and the real store unchanged. The Linux red result must
contain only unknown-remover and no-removal-reads; the other three subcases
must pass with their original exact errors and call counts.

## Secret upload reply correlation controls

These three controls are prepared, with Linux RED/GREEN measurements pending.
They preserve the shared flow plan, strict decoder and restrictive default.

| Control | Deciding assertion |
| --- | --- |
| operator-stage-correlation | TestGrantsFlowDispatch must fail at secret.stage with the original not_implemented projection-correlated-reply diagnostic when only its switch case is removed. The unchanged candidate must complete key/stage/import and exact stage/import replay through SQLite. |
| operator-stage-projection | TestSecretStageReplyProjection must reject reply expiry, independently persisted allocation ID, name, version, expiry, config, owner, session, connection, request, request ID, operation and key changes, a missing allocation, and a mismatched publication. Removing only the comparison must fail every cataloged negative with `secret stage projection mismatch escaped correlation`; the valid baseline must still pass. |
| operator-secret-projection | TestSecretInfoReplyProjection must reject forged version, independent source/head changes, another operation and missing source/head for both import and rotation. Removing only the source/head comparison must fail every cataloged negative with `secret source projection mismatch escaped correlation`; valid baselines must still pass. |

The publication negative intercepts a real owner's allocation and changes only
the proposed reply. It requires the actual writer to refuse before retaining
either its allocation projection or its successful receipt. The other negative
cases first obtain real successful owner/backend/SQLite commits and then change
one stored input. They do not seed a successful stage or import reply.
The runner's declared dispatcher runtime inputs and helper sources are kept
in every candidate/mutant inventory, so a missing producer, build failure or
catalog refusal cannot count as the deciding RED. BOX-SUITE.sh selects all three
in normal and fault builds and stops on the first failed step.

The eventless-stage repair adds operator-stage-empty-range, which restores the
old positive-first-sequence requirement. It must fail the complete
TestGrantsFlowDispatch at secret.import with the original live-session-stage
not_found message, after the stage's successful receipt has been returned.
The candidate keeps the actual ciphertext allocation and imports on the same
connection/session. Existing store enrollment/metadata/projection tests cover
direct calls whose original failure was secret stage has no exact committed
reply. Successful stages retain the real (0, 0) journal range; no event is
invented to satisfy a receipt check.

operator-stage-range-binding bypasses the strengthened sequence comparison.
Both TestStageCommitRangeBinding negatives must fail with stage accepted
sequence range outside its committed operation: one changes only the commit
envelope's range, the other supplies a half empty operation/envelope range.
The component ledger actually commits first; its adversarial wrapper changes
only the returned envelope. Projection correlation, exact reply checks and
failed-stage cleanup remain active. The new controls require measured Linux
RED followed by the unchanged focused candidate GREEN in both builds.
