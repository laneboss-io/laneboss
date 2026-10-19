# Focused template mutation proofs

`mutations.py` applies one deliberate source mutation in a new retained copy.
It never edits the input checkout, changes its Git index or touches a neighbor's
implementation. Each entry in `catalog()` names its owned source file, exact
one-occurrence before/after bytes, acceptance boundary, focused Go test and the
assertion message that must fail. Tests are not modified. These are component
mutation proofs; the socket/launch case remains a separate acceptance cell.

## Acceptance coverage

| Acceptance rule | Named mutations | Focused tests that must fail |
| --- | --- | --- |
| Print the selected level and role | `selected-level`, `selected-role` | `TestTplSelectedContext`, across the published L3–L6 role pairs |
| Keep exact task bytes, including CRLF, Unicode and no final newline | `drop-task` | `TestTplExactTask` |
| Check committed task size and digest | `task-length`, `task-hash`, `chunk-hash` | `TestTplTaskLength`; `TestRenderRejectsScopeDrift` case `task-hash`; `TestBlobIntegrityAndNoFakePrompt` case `hash` |
| Return and print the selected template hash and generation | `template-hash`, `template-generation`, `printed-hash`, `printed-generation` | `TestTplTemplateBinding` |
| Bind the actual rendered bytes | `rendered-hash` | `TestTplRenderedHash` |
| Print exact grant scopes without widening or mutating them | `drop-grants`, `grant-copy` | `TestTplGrantProjection` compares the complete structured projection and the unchanged input |
| Reject wrong-life, revoked or stale grants | `grant-life`, `grant-revoked`, `policy-generation` | `TestRenderRejectsScopeDrift` cases `grant-life`, `revoked`, `policy-gen` |
| Print the authentic direct parent, including a parent below the root | `report-parent`, `lineage-check` | `TestTplReportLine`; `TestRenderRejectsScopeDrift` case `lineage` |
| Print the selected worktree and workspace | `worktree-path`, `drop-workspace` | `TestTplWorkspace` |
| Retain independent source bytes and every consumed rule source | `source-alias`, `drop-rule-source` | `TestResolveOrgFallbackAndCopies`; `TestTplSourceRefs` |
| Missing local layer inherits the org default | `org-fallback` | `TestTplOrgFallback` |
| Partial or malformed local layers cannot silently inherit | `partial-local`, `malformed-source` | `TestTplPartialLocal`; `TestResolveRejectsBadSources` case `malformed` |
| Wrong-role sources and request labels cannot widen scope | `wrong-role`, `scope-role`, `duplicate-cli`, `duplicate-json` | `TestResolveRejectsBadSources` case `wrong-role`; `TestRenderRejectsScopeDrift` case `wrong-role`; CLI and strict-body tests |
| Wrong source hash and generation fail | `wrong-hash`, `wrong-generation` | `TestResolveRejectsBadSources` cases `hash`, `generation` |
| Role driver selection cannot widen the org primary catalog | `widen-drivers` | `TestResolveRejectsBadSources` case `widen` |
| Every briefing references the scoped rule-list route | `drop-list-route` | `TestTplRuleListRoute` |
| Exactly twelve seeded workflow entries retain their routes | `seed-count`, `seed-route` | `TestTplSeedCount`; `TestTplSeedRoutes` changes each published route in turn |
| The six tmux entries concern agent sessions, not private builds/tests | `tmux-agent-scope` | `TestTplTmuxScope` |
| Bare Claude is not a primary driver | `bare-claude` | `TestTplPrimaryCatalog` changes the org catalog, so the separate local ceiling cannot mask the missing check |
| Unfamiliar ordinary work has no implicit permission-list gate | `unknown-tool` | `TestTplOrdinaryWork` uses a valid task and an empty effective blacklist |
| Briefing starts no work or lifecycle intent | `brief-state-write` | `TestTplBriefingReadOnly` observes the service store and rejects a transaction even when the RPC subsequently fails |
| Shared CLI helper names carry the lane prefix | `cli-namespace` | `TestTemplatesCLINamespace` statically checks package-level declarations, except the four frozen dispatch slots |
| Consumer metadata matches the selected source hash and generation | `brief-source-hash`, `brief-source-gen` | `TestTplBriefMetadata` cases `hash`, `generation` |
| Returned sources and lane groups are consistent | `brief-role-path`, `brief-source-duplicate`, `brief-life-duplicate` | `TestTplBriefMetadata` cases `wrong-role`, `source-duplicate`, `repeated-life` |
| Empty or unavailable capability checks cannot pass | `brief-checks-empty`, `brief-check-unavailable` | `TestTplBriefMetadata` cases `checks-empty`, `check-unavailable` |
| A consumer verifies actual prompt size, digest and text | `verify-prompt-size`, `verify-prompt-hash`, `verify-prompt-text` | `TestTplVerifyPromptBytes` cases `length`, `hash`, `text` |
| A consumer compares task bytes and their framing | `verify-task-bytes`, `verify-task-frame` | `TestTplVerifyTaskBinding` cases `different-task`, `missing-frame` |
| Task text cannot mask a missing launcher rule-list reference | `task-route-mask` | `TestTplTaskCannotSupplyRoute` places the command only inside task text |
| The common reader verifies complete objects and blob enums | `blob-full-hash`, `blob-class` | `TestTplVerifiedBlobRead` cases `whole-hash`, `class` |
| Cancellation before or during reading yields no usable bytes | `blob-cancel-before`, `blob-cancel-during` | `TestTplBlobCancellation` cases `before-read`, `during-read` |
| Start uses the actual retained assignment | `original-task` | `TestOriginalTaskBinding` rejects a different visible task |
| Snapshot belongs to the bound config and current generation | `snapshot-config`, `snapshot-current`, `source-revision` | `TestApprovedSnapshotGuards` cases `config`, `stale`, `revision` |
| Source identity maps to exact committed content | `source-content-map` | `TestApprovedSnapshotGuards` case `source-map` |
| An installed or unreadable local pair cannot be called absent | `hidden-local-pair`, `local-status-error` | `TestApprovedSnapshotGuards` cases `hidden-local`, `local-error` |
| Real committed metadata outranks caller class labels | `metadata-authority`, `metadata-config`, `metadata-origin` | `TestCommittedMetadataGuards` cases `class`, `config`, `origin` |
| Exact-end reads reject undeclared suffix bytes | `blob-exact-end` | `TestBlobExactEnd` supplies a valid prefix hash of a longer object |
| Retention failures propagate and actual input refs are kept | `retain-error`, `input-provenance` | `TestPromptRetentionFailure`; `TestApprovedPromptRetention` |
| Authorized lane groups survive rendering | `authorized-groups` | `TestApprovedPromptRetention` compares the returned groups |
| The service really inherits an absent local pair | `service-no-fallback` | `TestServiceOrgFallback` reads approved org bytes through the new ports |
| A human overview invents no assigned task | `overview-task` | `TestHumanOverviewIsReadOnly` observes actual retained overview bytes and zero lifecycle transactions |
| Org validity includes unselected role pairs | `org-full-sources` | `TestOrgChecksUnselectedRole` supplies a malformed unselected role |
| Other org data with a roles folder stays inert | `unrelated-role-data` | `TestOrgValidationNeedsSources` includes a plugin document outside the level/role roots |
| Service rendering belongs to an authentic reserved lifecycle operation | `lifecycle-life-binding`, `lifecycle-cause` | `TestLifecycleRenderReservation` checks the reserved life and retained original lane/human operation/requester under a bound service call |
| Bootstrap proof and absence CAS share the effect transaction | `bootstrap-absence`, `bootstrap-proof-use`, `bootstrap-renderer-pin` | `TestBootstrapAtomicIntent` inspects the actual submitted typed transaction and pending reply |
| Bootstrap replay precedes proof and base preflight | `bootstrap-replay` | `TestBootstrapAtomicIntent` injects an unavailable base after the first committed reply |
| Bootstrap rejects existing orgs | `bootstrap-existing-org` | `TestBootstrapExistingOrg` requires a conflict and zero submitted transactions |
| Bootstrap verifies expiry, principal, endpoint, class, nonce use and target | `bootstrap-proof-expiry`, `bootstrap-proof-principal`, `bootstrap-proof-endpoint`, `bootstrap-proof-class`, `bootstrap-proof-consumed`, `bootstrap-proof-target` | `TestBootstrapProofGuards`, one focused case per fact |
| Bootstrap binds the exact framed intent | `bootstrap-frame-hash` | `TestBootstrapFrameBinding` changes framed params while keeping the old digest label |
| Commit failures and missing durable reply content cannot succeed | `bootstrap-commit-error`, `bootstrap-reply-shape` | `TestBootstrapCommitFailure` cases `transaction`, `empty-reply` |
| Lane/worker claims refuse before selected input/object reads | `own-grant-before-read`, `worker-own-life`, `own-life-before-read` | `TestOwnLifeClaimsBeforeSelectedReads` observes exact lane selectors and zero selected input/source/metadata/blob/retention calls |
| Worker level/role claims agree with the authentic lane | `worker-own-role`, `worker-own-level` | `TestWorkerRoleClaimsBeforeSelectedReads` requires forbidden before selected input/source/metadata/blob/retention calls |
| Lifecycle labels preserve the caller's own role | `own-context-before-life` | `TestLifecycleLabelCannotBypassOwnLife` requires forbidden before even a life lookup |
| Own-life renders use the authenticated selector | `own-input-selector` | `TestOwnLifeBriefings` checks successful lane/worker output, exact input life selectors and no transactions |
| Render/start inputs preserve current run and generation | `render-current-run`, `start-current-run`, `render-current-generation`, `start-current-generation` | `TestCurrentLifeInputBinding`, corresponding mode/field, requires integrity before source/prompt reads |
| Retained bootstrap replies keep configuration/key/principal domains | `bootstrap-receipt-config`, `bootstrap-receipt-key`, `bootstrap-receipt-actor` | `TestBootstrapReplayReceiptDomain` injects foreign backend receipt fields after a correctly scoped lookup and forbids a reply or repeated proof use |
| Lifecycle receipt domains survive backend lookup | `lifecycle-receipt-config`, `lifecycle-receipt-key`, `lifecycle-receipt-actor` | `TestLifecycleRenderReservation` receipt subtests require integrity and no extra retained prompt |
| Malformed proofs and lane proofs refuse before replay lookup | `bootstrap-replay-proof-id`, `bootstrap-replay-proof-digest`, `bootstrap-replay-lane-proof` | `TestBootstrapProofBeforeReplay` records unchanged receipt/proof/transaction call counts |
| Four common file methods have owned semantic registrations | `file-render-validator`, `file-start-validator`, `file-org-validator`, `file-bootstrap-validator` | `TestCLIFileSemantics`, matching method subtest, requires exit 2 and invalid_request owned by templates before transport |
| Registered validators check actual semantics | `file-render-semantics`, `file-start-semantics`, `file-org-semantics`, `file-bootstrap-semantics` | The same focused file tests reject wrong task/manifest class, reserved level or zero generation |
| Service labels require a genuine cause and original actor | `service-render-label`, `service-render-life`, `service-render-actor`, `service-original-requester` | `TestServiceRenderGuards` rejects unrelated labels, life and requester kinds; `TestLifecycleRenderReservation` compares the original receipt requester |
| Queued replies must still bind the active operation | `service-reply-binding` | `TestServiceReply` checks a valid pending reply and rejects a foreign operation/life or completed reply |
| Human lifecycle requesters remain valid original actors | `service-human-requester` | `TestServiceHuman` checks the actual retained requester and operation for a human-originated resume |
| The production bootstrap/org paths require the workflow pack | `seed-required-production`, `seed-parse-production`, `seed-org-production`, `seed-source-discovery` | `TestBootstrapWorkflow`, `TestOrgWorkflow` and the existing full-org positive test read actual manifest/source bytes; missing, eleven-entry and changed-route packs refuse |
| Repeated renders reuse the same immutable prompt key | `prompt-stable-key` | `TestPromptObjectKey` compares actual refs/object count and separates runs/owners |
| CLI typed calls and exact file calls keep their distinct paths | `cli-typed-subcalls`, `cli-file-exact-bytes` | `TestTemplatesCLI` runs all four positive handlers through the common mock transport; `TestTemplatesFileBytes` checks exact params and one session before reads |
| Session staging, start identity and bounded file open are enforced | `cli-session-staging`, `cli-start-identity`, `cli-file-nonblocking` | `TestTemplatesStage`, `TestTemplatesIdentity`, `TestTemplatesFIFO` require actual request ordering, typed refusal or bounded FIFO rejection |

The actual CLI Markdown, approved source lookup/retention, launch-event prompt
comparison and prompt-delivery receipt are asserted by `run.sh` under
`TPL-SCOPE`/`LB-FIRST`. Those observations still need service, policy, approval
and lifecycle integration. The component controls prove their formatter and
validation boundaries; they do not assert that an agent launched, that a tool
executed, that D6 approval succeeded or that an OS boundary was exercised.

The catalog has 181 named component controls: 111 earlier entries
(91 draft.3 controls and 20 draft.4 controls), 24 first port-read regressions,
15 fixes 9–11 regressions, five r3 corrections, eight G2/source controls and
15 G8 review/initial-shape controls and three projection/context follow-ups.
The r3 additions preserve
every prior control definition.
This inventory is not an executed red/green result.
The shared reader is used by
both service input reads and CLI prompt reads; the existing `chunk-hash`
mutation now targets its implementation in `blob.go`. The source-provenance and
prompt-consumer tests use explicit in-memory metadata fixtures. They do not
pretend that a fixture BlobRef was committed to a service store.

The chunk-hash fixture changes only a nonempty data chunk's hash, leaving the
separate end receipt valid. The cancellation fixture returns an invalid chunk
after cancelling and requires cancellation before chunk interpretation. These
keep the original reader controls observable after the added exact-end checks;
a later independent check must not accidentally make a removed check look proved.

Draft.4's shared transaction validator remains enabled in the fixture. The
atomic-bootstrap test inspects its actual submitted CAS, proof guard and effect
before asserting successful completion. A removed proof guard therefore fails
the named atomic-use assertion even if the common shape validator refuses it.
The valid candidate must still return the actual stamped durable pending reply.
The retry fixture marks its proof consumed and makes proof revalidation fail;
only replay of the original retained reply can pass.

Receipt fixtures index config, actor kind/principal/life, method and key, and
retain original metadata. Deliberately foreign backend receipts use a separate
post-lookup fault hook, so a scoped fixture lookup cannot mask the component's
domain checks. `TestTemplateReceiptFixtureDomains` checks that fixture boundary.
`TestBootstrapCLICommittedInput` separately requires exact local validation
errors before transport for missing committed references and changed manifest
bytes. Positive shared/borrowed transport behavior still needs common CLI and
installed-service coverage; those local refusals are not serve E2E evidence.

## What counts as red, then green

For each selected mutation the script makes exactly one checked replacement,
retains the before/after Go bytes and their hashes, builds an actual Linux test
binary, and runs the named test through `go tool test2json`. The red proof needs
exit 1, the exact selected test run and failure, its named assertion message and
a package failure. A compiler/setup error, panic, skip, unrelated failed test,
missing test, malformed trace or abnormal exit cannot kill a mutation.
Compiler refusals print the mutation ID, phase, exit and complete retained
compiler stdout/stderr. The same refusal remains fatal; diagnostics never turn
a compile failure into a killed control.

Only after observing that red does the script restore the original source in
the copy, verify its entire source manifest, build a separate retained binary
and run the same focused test. Green needs exit 0, an observed test pass, a
package pass and no failures/skips. It verifies the input checkout again and
checks that the tested binary bytes did not change while running. Red and green
must have distinct actual binary hashes. A new or missing source input in the
copy also fails the proof.

An unexpected result stops the matrix. Remaining entries are recorded as not
reached, and the overall result is false. Copies, failed outputs and binaries
are retained for the supervisor; the script does not delete past a failed gate.
Observed failed-test names are retained before classification, including when
the failure is rejected as unrelated or the assertion message does not match.
It stops its own timed-out command by its recorded PID and never claims a
surviving or unobserved process group was collected.

`test_mutations.py` separately tests this classification with synthetic Go trace
fixtures, including setup crashes, wrong assertions, skipped/missing tests and
a surviving mutant. These infrastructure unit fixtures are not product test
results. Its anchor test checks every catalog entry against the actual input
source, including drift and ambiguous matches.

## Linux commands

Run only on the authorized disposable Ubuntu 24.04 box. From the source root,
first check the classifier and catalog anchors:

```sh
PYTHONPYCACHEPREFIX=/tmp/lb-tpl-pycache \
  python3 -m unittest discover -s e2e/v2/cases/templates -p 'test_*.py'
```

Run one proof, supplying the actual absolute checkout path and a new external
evidence directory whose path carries the lane name:

```sh
python3 e2e/v2/cases/templates/mutations.py \
  --source /test/source \
  --work-root /test/evidence/lb-v2-templates-red \
  --mutation wrong-hash
```

Run the complete named matrix without and with the fault tag:

```sh
python3 e2e/v2/cases/templates/mutations.py \
  --source /test/source \
  --work-root /test/evidence/lb-v2-templates-matrix \
  --all

python3 e2e/v2/cases/templates/mutations.py \
  --source /test/source \
  --work-root /test/evidence/lb-v2-templates-faults \
  --tags laneboss_faults --all
```

The default command deadline is 240 seconds and the entire matrix deadline is
1,800 seconds; neither timeout is a pass. A fresh `--work-root` is required for
every invocation. `result.json` must have `ok: true`, every selected mutation
`proved`, actual red failed-test names, the same green test passing, no missing
evidence, unchanged manifest-selected input bytes/modes/links and quiescent
process groups. Read and hash
back the referenced files before collecting the test machine. This schema is
specific to component mutation evidence, not the shared E2E result schema.

The copied inputs include all Git-tracked files plus this lane's untracked
authored Go/Python/shell/JSON/Markdown/TOML sources. Private runtime directories
and unrelated new files are not selected. Links must stay within the source
tree. The source archive, inventory, revision, Go version, commands, outputs,
exits, binary bytes and SHA-256 hashes are retained under the supplied root.

For a source archive without `.git`, the supervisor can supply `--file-list`
and `--revision-file` together. These are file inputs, not inline documents.
The file list contains NUL-terminated repo-relative names from the exact staged
source, and the revision file contains its Git source revision. Preserve both
alongside the uploaded source archive; the script hashes actual copied bytes
and labels the revision as supplied metadata. These read-only collection
commands may be run by the supervisor after it stages/commits the exact tree:

```sh
git ls-files -z > /test/inputs/source-files
git rev-parse HEAD > /test/inputs/source-revision
```

On the box, append the two supplied input paths to either matrix command:

```sh
python3 e2e/v2/cases/templates/mutations.py \
  --source /test/source \
  --work-root /test/evidence/lb-v2-templates-archive \
  --file-list /test/inputs/source-files \
  --revision-file /test/inputs/source-revision --all
```

The authoring Mac runs static checks only. No red, green, runtime classifier or
full E2E result is claimed from syntax checks or the catalog's existence.

## Static materialisation check

When the active brief authorizes static materialisation, `--vet-only` checks
every selected mutation in a retained source copy with whole-tree `go vet
-mod=readonly ./...`, including the selected fault tag. It vets the unchanged
baseline first, preserves each complete before/after source and actual command
outputs/exits, and restores and verifies the source after each successful vet.
The first failed vet stops the batch and retains the failed edit and diagnostics.
No test binary is compiled or executed by this mode. The normal runtime mode
still requires the disposable Ubuntu 24.04 box and the exact named red/green
assertions.

For example, from the assigned checkout with an existing evidence parent:

```sh
GOOS=linux GOARCH=amd64 python3 e2e/v2/cases/templates/mutations.py \
  --vet-only --all --source /test/source \
  --work-root /test/evidence/lb-v2-templates-vet-a

GOOS=linux GOARCH=amd64 python3 e2e/v2/cases/templates/mutations.py \
  --vet-only --all --tags laneboss_faults --source /test/source \
  --work-root /test/evidence/lb-v2-templates-vet-b
```

Static reports use `laneboss.templates-mutation-vet.v1`, scope `static-only`
and status `vetted`; they never use runtime status `proved`. A static pass
establishes compile/vet viability only. Each control must still fail its own
named assertion and pass the restored test on the authorized Linux box.

The `lifecycle-cause` edit appends `-wrong` to the actual `causeID` rather than
replacing the field with an empty literal. It still corrupts that causal
operation and targets the unchanged lifecycle requester/operation assertion.
Keeping the variable in the corrupted expression avoids draft.4's unused
variable error after own-life checks stopped using the cause as a bypass.

The new CLI tests are an owned test asset at internal/v2/templates/_cli_test.go.
The runner retains a Go overlay mapping that asset into a virtual test file in
package cli. It never writes a shared CLI file or adds a production test hook.
Five new controls select that exact CLI package; all previous entries keep the
templates package. test2json package binding, selected test/descendants, named
assertion, normal exit and distinct retained binaries remain required. The
positive CLI group covers render, start, validate and bootstrap; its render
and start paths deliberately lack unrelated features' file validators so a
mistaken InvokeRaw cannot pass merely because a combined adapter registered one.
Static vet uses the same retained overlay to type-check these fixtures.

Service receipt fixtures now pin the specific lifecycle service identity and
return the original lane/human receipt for it. Public fixture receipt lookups
keep their strict actor domains. Direct-caller actor corruption cases still
exercise the exact actor-equality refusal, while service cases test truthful
requester propagation and operation/life binding. Original control IDs and
assertion strings remain. Fixes 9–11 adapt the policy-generation boundary to
ordered history, move original-task to Start's gate, and update bootstrap
replay/commit-error anchors for the provenance-aware reply helper. No static vet result is a
runtime kill, and no mocked transport result is installed-CLI acceptance.

The delta controls cover live policy drift and new-life equality, continuation
planning, failed/stale plans, original requesters, reserved run fences, active
turn tasks, CLI task references, verified/receipt presence consistency, queued
operation stamping, commit/replay marks, and service preflight before input
selection. Their focused tests use short names under 40 characters including
selected subtests. `TestPolicyLive` checks both render and start before/after
lane refresh. `TestPlanRender` checks genuine start/resume/turn/continue inputs;
guard tests require no input selection for invalid causal claims. The source
catalog retains each exact named assertion. These remain pending runtime
red/green observations until executed on the authorized Linux machine.

`test_symlink_root` in the case-input tests creates an actual directory symlink
and checks canonical primary reuse and an independently selected fallback. It
tests path routing only, not authentication or product execution.

The r3 box failure was a fixture error: start's six GrantRequest arrays and
turn's MailIDs were nil and encoded as null. Shared body builders now emit
empty arrays. TestPlanFrames runs those actual builders through the unchanged
PrepareRequest shape check and separately requires deliberately null arrays to
refuse. No mutation is allowed to edit test files or weaken the decoder.

The plan-start-flow and plan-turn-flow controls select the actual positive
TestPlanRender/start and /turn assertions. They deliberately remove the active
planning path; a fixture/setup error cannot satisfy their expected rendering
assertion. The plan-public-grants, plan-public-launch and plan-continue-launch
controls restore the skipped-mismatch behavior. TestPlanMatch first renders a
valid plan, then changes a matched selector with an expired claim or failed plan
and requires the exact integrity failure before another input lookup, prompt
retention or receipt lookup. Public cases keep a usable receipt present so a
fallback cannot hide the defect; the internal case requires integrity rather
than an unrelated no-plan refusal. Runtime red/green evidence remains required.

The eight G2/source controls cover exact snapshot selectors, semantic Sources,
structural Derived, nonempty generated inventory, complete source-only callback
validation, exact SourceRef resolution and partial-local-pair refusal. The
source store adapters still need their actual backend; no template component
fixture is credited as a persistent store or installed-service observation.
All Go verification in this G8 round uses the shared lane cache named by the
active brief; no new private Go cache is created by the executor.

The G8 review controls name these additional assertions:

| Boundary | Controls | Required observation |
| --- | --- | --- |
| Every template path has its semantic kind | `org-kind-path` | `TestOrgKinds/callback/unselected` rejects the mislabelled unselected role. The same regression covers both org validation and the source-only callback, org/local prompts and drivers, and workflow policy. |
| Org IDs belong to the bound configuration | `org-bound-snapshot`, `org-bound-validate`, `org-bound-render` | `TestOrgBoundary` rejects foreign inventories, rejects before policy validation, and rejects provided foreign selectors before snapshot lookup. |
| Store views remain configuration-bound | `store-view-config`, `store-empty-config` | `TestSourceView` refuses foreign/unbound views and empty config pairs without closing a borrowed view, and reuses a valid view. |
| Object ACL generation is committed | `store-acl-generation` | `TestSourceMetadata/generation` rejects generation zero; positive metadata and other provenance failures are covered too. |
| Request precedence, bounds and syntax | `store-source-order`, `store-template-order`, `store-template-range`, `store-source-claim`, `source-ref-claim` | `TestSourceRequests` and `TestSourceClaim` require forbidden before malformed cross-config claims and invalid before backend lookup for malformed in-config claims. Valid missing refs stay not_found; stale positive refs stay conflict. |
| Initial Derived has the exact frozen shape | `initial-source-shape`, `initial-nil-shape`, `initial-extra-shape` | `TestInitialShape` accepts generation one's explicit empty array through selection and both full gates. `TestInitialGuards` rejects null/unexpected initial entries, empty later generations and corrupt metadata/content. |

Three older controls are adapted to fix 13's shared kind/shape gate. Semantic
and structural-kind mutants remove the common gate and selectively disable the
corresponding local kind check in one contiguous replacement. The required
derived-inventory mutant removes the common gate. Their original named tests
and assertion strings remain. The structural-source fixture now uses a generic
notes path so the new template-path gate cannot mask that earlier assertion.
No candidate check is removed. All other prior controls remain as authored.

Only internal/v2/store/sources.go is additionally eligible for mutations, paired
with the store test package; its focused source_test.go fixture is retained as
an owned input. This does not permit editing other store sources or tests in a
mutation. Runtime classification remains exact about package, focused test,
assertion, normal failure, restored pass and distinct binary hashes.

The round-11 authoring brief permits candidate-only vet on the Mac. Do not run
the static materialisation commands above, mutant vet, control overlays or any
runtime tests there. The 15 new controls and three adapted controls are authored
Linux work, with no red/green observation claimed by their presence or by syntax
checks. Execute the complete candidate and red/green gates on the authorized
disposable Linux environment before acceptance.

The round-13 projection/context follow-ups change production gates as well as
their regression expectations. Foreign returned configuration/org identity or
an invalid returned generation refuses with integrity; only a stale supported
generation uses conflict. The public org gate and source-only callback now
enforce that distinction before policy/content reads. The provided foreign
selector remains conflict before lookup. Both store adapters use the shared
exact projection validator through sourceSnapshot.

`callback-org-code` selects TestOrgRead/callback/org and requires the named
foreign-projection classification assertion. `store-org-code` selects
TestSourceSnapshot/org and requires the same distinction at the production
projection gate used by both store adapters. `store-context-preflight` selects
TestSourceContext/new/level and requires invalid context to refuse before view
acquisition. TestSourceContext also covers borrowed views, invalid roles and
instance IDs, valid role contexts and cross-config precedence. The older
generation-preflight fixture now supplies a valid role so context rejection
cannot mask its generation-range control. The org-bound-validate anchor is
updated for the separate identity and generation gates.

These tests exercise actual production validators and adapter preflight, not
a persistent store backend. They remain authored runtime checks until the
authorized Linux runner observes their failures and restored passes. The Mac
runs candidate-only vet and syntax checks; no control overlay is authorized.
