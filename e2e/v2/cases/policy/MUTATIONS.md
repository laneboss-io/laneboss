# Policy red-before-green controls

This is the component mutation ladder for BL-RESP and SKIP. It is separate from
the full CLI/socket case in this directory. Run only on the authorized disposable
Ubuntu 24.04 test machine. The authoring Mac has not executed this runner or
its Python/Go tests.

The catalog contains 121 named mutations. All 118 earlier IDs and focused
test/subtest/marker mappings remain, including the two permanent P1 controls.
Three follow-up controls extend them. The
spend-with-zero ID now targets TestBatchesShareCost and its batch-count marker
because zero lane spend now refuses; this retargeting preserves the separate
no new call after reservation exhaustion check. Each changes exactly one
anchored production fragment in a **new copy** of the supplied source artifact.
Test files are copied unchanged. The script never stages Git, edits the input
tree, switches a binding, starts a service, or calls a model endpoint.

For every mutation it:

1. Retains a hash/size manifest of every copied input file and verifies read-back.
2. Requires the catalog's source anchor exactly once; missing/ambiguous anchors
   fail setup. Mutations may target only policy production code or the owned CLI
   command file. Tests and other lanes' production files cannot be targets.
3. Retains original/mutant file bytes and a diff, builds a red test binary, hashes
   it, and runs the catalog's focused test through Go's actual test2json tool.
4. Requires exit 1, the named test's run/fail events, and every expected assertion
   marker. A compile failure, panic, signal, timeout, skipped/missing test,
   unrelated failure, wrong assertion or surviving mutation fails the phase.
5. Restores the exact source bytes and verifies the entire copied inventory,
   then builds and runs the same focused test as the green control. Every
   selected test must run/pass and the process must exit 0.
6. Verifies the red/green binaries differ and the original input remains
   byte-identical. It retains both executed binaries, exact stdout/stderr,
   actual exits, commands, source bytes and structured results.

No later phase runs after an unexpected failure. The failed copy, binaries and
transcripts remain for inspection. Evidence is never overwritten: output must
be a new directory outside the input tree and carry the lane name. A timeout
stops the owned process group identified by the command's process ID. This
utility provisions no machine and makes no whole-machine collection claim.

From a Git source checkout, after laneboss has staged/scanned the new files:

```sh
sh e2e/v2/cases/policy/run-mutations.sh \
  --source /test/source \
  --mutation cache-start-time \
  --output /test/evidence/lb-v2-policy-age
```

An extracted source archive without Git metadata must supply its retained,
newline-separated inventory of normalized repository-relative file paths. The
inventory must include all new production/test/runner files:

```sh
evidence=/test/evidence
sh e2e/v2/cases/policy/run-mutations.sh \
  --source /test/source \
  --files /test/artifacts/source-files.txt \
  --all \
  --output "$evidence/lb-v2-policy-plain"
sh e2e/v2/cases/policy/run-mutations.sh \
  --source /test/source \
  --files /test/artifacts/source-files.txt \
  --all --faults \
  --output "$evidence/lb-v2-policy-faults"
python3 -m unittest discover \
  -s e2e/v2/cases/policy -p 'test_*.py'
```

Each command must exit 0. The mutation-set results.json must say pass, contain
every requested ID exactly once, and reference a per-mutation pass with phase
order red then green, verified binary/source hashes and input_unchanged true.
A partial set is fail. The observer unit tests use clearly synthetic test2json
frames to prove false-red rejection; those fixtures are not Go mutation evidence.

The source copy and evidence directories are created private (0700), owned by
the executing test identity. The runner sets umask 077 before creating any
copy; it never relaxes production privacy checks. Run from an isolated
unbound disposable Linux test process. Never clear a live session binding.

Draft.3 changes the audit-gap control to remove the durable-reply error return.
That mutant returns and caches the uncommitted verdict; the test observes both
the invalid first reply and reuse after the store recovers. The original guard
now returns a typed error with the operation ID. The policy CAS control removes
the approved org-generation comparison because the closed draft.3 catalog no
longer admits a policy comparison. Cache cwd/raw anchors include the retained
turn argument. All other earlier check/test/assertion mappings remain.

## Acceptance mapping

| Acceptance requirement | Named controls |
| --- | --- |
| Words/source list, Instead and enforcing hook outcome | list-routes, list-sources, drop-instead, hook-no-block, hook-no-route |
| Matching cloud/PR/plugin denies and unfamiliar unrelated work | allow-matching, deny-empty, deny-unmatched, warn-blocks |
| Judge-only membership, no historical pattern veto | legacy-veto |
| Org + own + all higher roles; no peers/lower; org fallback | omit-org, omit-higher, inherit-lower, inherit-peer |
| Applicable role scope and defining threshold/calibration authority | ignore-rule-scope, flatten-thresholds, inactive-source, source-forgery |
| Canonical source/version and dependency failures cannot become success | policy-hash, omit-policy-cas, hide-judge-stub |
| Full exact request data, scope and rules bind cached outcomes | cache-scope, cache-cwd, cache-raw, cache-expiry, cache-start-time |
| Skip is positive-only; miss invokes Judge; denies/critical remain active | skip-no-proof, skip-miss-refuses, skip-critical |
| Rule/role/context changes invalidate cache and skip | cache-scope, cache-cwd, cache-raw, skip-stale |
| Timeout/partial/cost outages close only critical refuse entries | reset-deadline, partial-scored, cap-ignored, close-noncritical, close-warn |
| Unknown fit/overflow/stack mismatch cannot start inference | fit-unproved, fit-bytes, fit-tokens, fit-tokenizer, ignore-model-pin |
| Exhausted/unknown inference cost never becomes zero new spend | spend-with-zero, reservation-reset |
| Unscored is absent probability; scored uncertainty stays scored | unscored-zero, uncertainty-closes, cache-unscored |
| Exact retained input and durable audit precede semantic reuse | ignore-readback, omit-audit, cache-audit-gap |
| Unknown CLI input fails before transport | unknown-flags |

Cloud/PR/plugin wording is table data through the same membership contract,
not three program-specific engines. Role union and scored-band guards are
component controls. The actual human D6 proof/installation, kernel identity,
hook/socket transport, calibrated self-hosted semantic membership, and briefing
integration still require the full case's dependency implementations. These
component mutations cannot substitute for those public acceptance operations.
D6 itself is owned by approval; this lane tests the canonical-source and current-
generation checks at its own boundary rather than modifying another lane's code.

## Draft.4 baseline controls

The earlier draft.4 baseline added retained configuration / principal / life / method / key / digest
receipt checks; lane/malformed/missing human proof rejection before replay;
atomic human ProofUse with the resolved target; replay without re-consuming
the original nonce; resolved default Clef spelling; caller-retained CLI mutation
keys; and propagation of scoped authorization/provider refusals.

The Go fixture stores real request/object bytes and original receipt facts.
Its receipt map uses the configuration, actor kind/principal/life, method and
key. It applies the actual shared transaction catalogs. The earlier preview
ProofUse interpretation is superseded by fixes 3-7 below.
TestReceiptDomainBoundaries checks this fixture's isolation; it is not
native identity or cryptographic assertion evidence. The feature controls below
change production checks only. No test or shared contract is mutated.

## Draft.4 fixes 3-7

All 80 earlier mutation IDs remain. The human-proof, proof-target and proof-guard
controls now pin the session-scoped preview contract: missing/foreign live
authority refuses before replay/work, and a consuming guard is prohibited.
The tests still retain the human actor, verify exact result replay and forbid
expired/closed/revoked/cross-connection authority. Human preview does not consume
an operation proof. The fixture's proofUses counter observes attempted proof
guards; it is required to stay zero for this method.

Three new controls remove the input registration, replace semantic validation
with unconditional acceptance, or omit current human session resolution.
Invalid policy files require the exact production validator's code/message/owner
before a deliberately absent proof file, mutation key or socket can be used.
The valid input still reaches the retained-key guard. Unit and mutation runtime
results remain for the authorized Linux box.

## Mutation diagnostics and static audit

Failures now print their exact phase and reason to stdout through the shell
wrapper. A diagnostic mismatch names the test and every missing required
marker. The latest command and latest test include exit/timeout facts and the
last 20 lines of stdout/stderr; test2json output is rendered as readable test
text. The raw streams remain unchanged on disk. Each result and the set index
also retain the failure phase/reason. The verdict requirements above are
unchanged, including byte-exact restoration before the green build and the
full inventory/binary comparisons after it.

The d4fix3 review statically traced all 83 catalog entries against the focused
test, its fixtures and intervening production checks. Every anchor occurs
once. Every ID, selected test/subtest and required diagnostic is retained.
The six previously reported successful entries were also re-read; this is not
a claim that the remaining controls passed at runtime.

The old omit-org mutation deselected the org source as well as its rules.
Resolve still set GuidanceSource to that source, so validatePolicy returned
`invalid guidance defining source` before the absent-role test could compare
its union. The observer correctly refused that failure because it lacked the
required `union:` marker. The mutation now omits only org rules, preserving
the source and guidance provenance. The production validators and test remain
unchanged. This is the static explanation; the discarded box transcript does
not establish a measured failure phase.

The review also found that human-replay's configured policyErr was ignored by
the human BriefingInput fixture. A mutant could rerun preflight and fall through
to the store's completed-receipt replay. BriefingInput now propagates the
configured policy error, as Policy already did. The unchanged test then catches
preflight at its existing completed-human-receipt assertion. This strengthens
the fixture, with no simulated native authentication claim.

The remaining control families retain their intended assertion paths:

- Role/threshold/provenance controls reach union, authority or typed-error
  assertions. ignore-rule-scope already includes resolver errors in its scope
  assertion, so the independent effective-scope validator does not hide it.
- Scoring, outage, budget and fit controls preserve valid retained inputs and
  the selected band's assertion; cache/skip controls preserve policy hashes,
  approval/source facts and the fixtures' current context before testing reuse.
- Audit/source/receipt controls are checked through their typed errors or
  explicit premature-work assertions. reserved-frame intentionally reaches
  retention before the later transaction rejects it; its unchanged premature-
  work marker checks that case. retained-input-refs and proof-guard intentionally
  use the fixture/catalog error text already required by their entries.
- Human/session/replay and CLI controls keep their scoped authority, replay,
  semantic-validation and retained-key assertions. The repaired human fixture
  exposes human-replay's existing preflight injection.

The Python observer tests include synthetic stdout/tail checks for diagnostic
mismatches, a failed green build, source restoration/input integrity and failure
before any command. They do not build Go or stand in for actual red/green runs.
All runtime checks, including these Python tests, still require Linux.

## Read-method file validators

All four policy-owned methods now register an input validator at CLI
initialization, and a registration error panics. The three read-method
registrations share their production checks with service handlers:

- policy.get admits an empty life selector or a valid supplied life ID.
- config.read checks its known view and any supplied role/level/instance
  context. Valid views whose projections are unfinished still reach their
  service-owned typed dependency error.
- config.validate uses the exact Empty decoder, admitting an empty JSON
  object and rejecting extra fields, duplicate keys, nulls and non-objects.
  Its service wire handler uses the same raw validator. The common CLI shape
  decoder rejects malformed Empty input before any semantic hook; the test
  requires that exact typed invalid_request, with its shared decoder owner.

TestCLIReadInvalidFiles requires each invalid request to fail before an absent
proof file, malformed request IDs or a missing binding can be processed.
Semantic policy.get/config.read errors retain owner lb-v2-policy and their
exact shared error. TestCLIReadValidFiles uses a private directory and an
explicitly absent binding. It requires exit 69, no output, an error not owned
by policy and one of exactly two codes: not_implemented for the isolated
transport stub or prerequisite_missing for the combined client's binding
refusal. It does not assert another lane's stub message or accept arbitrary
errors as transport evidence.

Three controls independently drop the new registrations and require the
corresponding valid-file row to fail at its existing transport assertion.
Three further controls remove life/view checks or validate a manufactured
empty body; the semantic and exact-empty tests must reject these mutants.
The manufactured body appears only in the deliberate red mutation. Runtime
red/green results remain pending the authorized Linux run.

## Permanent review enforcement controls

The named judge-not-consulted and hook-ignores-deny controls are permanent
acceptance gates. They must run in both build modes on every candidate.

- judge-not-consulted substitutes zero for the approved positive cost ceiling.
  TestConfiguredInferenceBudget requires an actual scoped judge request with
  that ceiling and a scored refusal for a matching noncritical deny. Its exact
  failure is approved inference ceiling did not reach the judge.
- hook-ignores-deny removes the typed hook refusal. TestInstalledHookExit drives
  the real cli.Run --command-file adapter. Its actual deny case must print
  the typed decision yet exit zero under this mutant, with deny exited zero
  and installed hook decision/exit mismatch: failed cases=deny in the parent
  stream. A missing transport, compile error or unrelated failure cannot kill it.

TestInstalledHookExit compiles an owned testdata file into package cli through
Go's overlay, using the CLI's existing synthetic test transport. It adds no
production bypass or physical file in another lane. Allow, deny, warn and
ordinary unscored outcomes must all run; it also forwards a command larger
than the provider cap but within the wire bound. The child CLI binary, exact
fixture bytes, overlay, hash and separate build/test streams are retained in
a private directory outside source. The runner supplies a per-phase evidence
root and indexes every nested artifact. Plain/fault builds retain their actual
tag. Timeout collection uses only the owned process group PID.

The read controls cover live human connection/session authority, cleaned or
revoked/stale lane authority, instance selection, projection metadata and life
ACLs. Config views use only the seven frozen values. Local command/key checks
precede target lookup. Constructor configuration is mandatory. Fresh judging
with rules and zero lane spend is a typed budget_exhausted refusal with an
approved-budget Instead route. The budget outage fixtures now inject an actual
scoped-judge budget error under a positive cap; zero lane spend no longer stands
in for an outage.

Skip approval now has a stable work digest and a separate fully caller-bound
positive proof. The new controls catch ephemeral approval bindings and a human
proof seeding a lane. Three earlier mutants were retargeted without changing
their test or diagnostic requirements: cli-mutation-key injects before the new
local key guard; skip-miss-refuses compares the stable approval hash; skip-stale
reuses an actual cached audited allow while bypassing current bindings. Its
critical guard stays in place. The original cache/context invalidation and
positive-only skip assertions remain intact.

The Python checker tests add explicit premature skip/cache/unscored warm-proof
failures and exact command-file retention checks. They are synthetic checker
inputs, separate from the public native CLI/socket case. No new runtime result
is claimed from the authoring Mac.

The four delta controls add the zero-spend refusal, invalid/not-found judge
error propagation in both fit/evaluate, and accurate recorded/current generation
diagnostics. Fix 11 now permits older historical pins, and the diagnostic
control rejects a future live pin with its actual generation values. The
Scope/current-policy check remains mandatory. TestConfiguredInferenceBudget inspects the real evaluation
error alongside the judge request, preserving the permanent judge-not-consulted
marker even when the zero-ceiling mutant reaches the new budget refusal.

TestRawFileHookOutcome remains an unskipped gate outside this catalog. Its
retained overlay child now drives actual cli.Run --request for allow, deny,
warn and unscored cases. Fix 11 requires all four to return exactly unsupported,
owner lb-v2-policy, exit 69, the product message/Instead and empty stdout before
generic file/socket work. A stub transport error or any other nonzero exit fails.
The deciding branch-removal control f11-hook-file lives in integrate's catalog
because cli.go is outside policy mutation ownership. The ordinary hook adapter
and its permanent hook-ignores-deny control retain their decision-aware contract.

The ten new rows are consumer controls on generation.go. The six matching
fix-11 names cover policy's evaluation, replay, exact binding, projection pin,
event and life CAS responsibilities; the shared API assertions in the handoff
remain unchanged and must also run. The additional four rows cover cancellation,
history/hash, result stamp and real protected-port errors. Selection/retained
turn controls belong to guidance and launch/unopened-plan controls to lifecycle;
policy does not edit their implementations. receipt-preflight and human-replay
only retarget their source anchors to replayPolicy and preserve all original
tests/subtests/markers. The Python checker separately rejects a missing D6
change, a read that refreshes the lane, changed live identity and invalid refresh
events. No runtime result is claimed from this Mac.

The follow-up controls verify that a human preview makes no refresh request or
lane.policy event while a real lane still performs its protected refresh. The
zero-spend-order mutant moves the same typed budget refusal behind both refresh
and protected input retention. TestZeroSpendBeforeSideEffects checks lane and
human callers, requires the correct budget code/route, then separately requires
no refresh request, no lane.policy event, no retained input and unchanged lane
state. A correct code after those effects must fail. zero-spend-allow retargets
only its source fragment to the early guard and retains its focused assertion.
The hook README requires a new retained key for every command invocation and
permits reuse only to resume a cut-off call; exact replay behavior stays intact.

## Exact mutation/test ledger

| Mutation | Check removed or inverted | Focused test | Expected assertion text |
| --- | --- | --- | --- |
| `deny-empty` | Invert the empty deny-union default. | `TestNoRulesAndNoBudget` | `absence of denies must allow` |
| `deny-unmatched` | Remove judged match threshold from a refuse entry. | `TestJudgedBands` (`unfamiliar`) | `scored band lost:` |
| `allow-matching` | Invert the semantic match comparison. | `TestJudgedBands` (`match-boundary`) | `scored band lost:` |
| `warn-blocks` | Remove the refuse-band restriction from scored refusal. | `TestJudgedBands` (`warn-never-refuses`) | `scored band lost:` |
| `drop-instead` | Drop the defining entry's Instead route. | `TestJudgedBands` (`match-boundary`) | `scored band lost:` |
| `legacy-veto` | Restore a tmux lexical veto after semantic nonmembership. | `TestExactInputsAndAudit` | `semantic nonmembership was replaced` |
| `omit-org` | Omit org rules while preserving defining-source provenance. | `TestResolveLayerUnion` (`absent`) | `union:` |
| `omit-higher` | Remove higher-level deny inheritance. | `TestResolveLayerUnion` (`executor`) | `union:` |
| `inherit-lower` | Include lower levels in deny inheritance. | `TestResolveLayerUnion` (`supervisor`) | `union:` |
| `inherit-peer` | Remove the own-level role equality check. | `TestResolveLayerUnion` (`executor`) | `union:` |
| `flatten-thresholds` | Replace a defining source threshold with the org scalar. | `TestResolveLayerUnion` (`executor`) | `defining authority lost:` |
| `inactive-source` | Do not validate an unselected role's rule. | `TestResolveLayerUnion` | `want invalid_request;` |
| `ignore-rule-scope` | Remove rule applicability filtering. | `TestResolveScopeAndValidation` | `scope did not exclude executor:` |
| `source-forgery` | Remove the defining-source equality guard. | `TestResolveScopeAndValidation` | `want invalid_request;` |
| `unscored-zero` | Manufacture a numeric zero for an unscored outcome. | `TestOutageBands` (`timeout`) | `outage was scored or closed another band:` |
| `close-noncritical` | Close noncritical refuse entries during an outage. | `TestOutageBands` (`timeout`) | `outage was scored` + `RuleID:ordinary` |
| `close-warn` | Allow critical warn entries to close during an outage. | `TestOutageBands` (`timeout`) | `outage was scored` + `RuleID:notice` |
| `uncertainty-closes` | Treat scored uncertainty as a critical outage. | `TestJudgedBands` (`uncertain`) | `scored band lost:` |
| `partial-scored` | Remove the complete-response status check. | `TestOutageBands` (`partial`) | `critical outage did not close:` |
| `cap-ignored` | Remove the returned-cost ceiling check. | `TestOutageBands` (`cost-reply`) | `critical outage did not close:` |
| `spend-with-zero` | Call another batch after the command's inference reservation reaches zero. | `TestBatchesShareCost` | `batching reset cost or omitted the unresolved critical entry` |
| `reservation-reset` | Reset the inference reservation after an unknown-cost failure. | `TestUnknownCostStopsBatches` | `unknown provider cost was treated as zero` |
| `fit-unproved` | Remove the unproved fit guard before inference. | `TestFitStopsBeforeInference` (`unproved`) | `invalid fit reached inference` |
| `fit-bytes` | Remove the bytes fit guard before inference. | `TestFitStopsBeforeInference` (`bytes`) | `invalid fit reached inference` |
| `fit-tokens` | Remove the tokens fit guard before inference. | `TestFitStopsBeforeInference` (`tokens`) | `invalid fit reached inference` |
| `fit-tokenizer` | Remove the tokenizer fit guard before inference. | `TestFitStopsBeforeInference` (`tokenizer`) | `invalid fit reached inference` |
| `ignore-model-pin` | Ignore the selected model pin. | `TestOutageBands` (`wrong-model`) | `critical outage did not close:` |
| `reset-deadline` | Replace the caller's deadline with a new independent clock. | `TestParentDeadlineIsRetained` | `policy restarted the caller deadline` |
| `cache-scope` | Drop source/role/policy dependencies from the cache key. | `TestCacheContextBindings` (`rules`, `role`, `policy`) | `stale semantic allow survived` |
| `cache-cwd` | Remove both copies of cwd from context binding. | `TestCacheContextBindings` (`cwd`) | `stale semantic allow survived cwd` |
| `cache-raw` | Remove exact raw bytes and their digest from context binding. | `TestCacheContextBindings` (`raw`) | `stale semantic allow survived raw` |
| `cache-expiry` | Remove cache TTL expiry at lookup. | `TestCacheExpiryAndCopies` | `expired allow was reused` |
| `cache-start-time` | Age cache and skip receipts at request arrival instead of lookup. | `TestCacheAgesDuringRead` (`cache`, `skip`) | `expired receipt survived input-retention wait` |
| `cache-unscored` | Cache an unscored outage as a semantic verdict. | `TestOutageBands` (`timeout`) | `unscored evaluation was cached` |
| `cache-audit-gap` | Return and cache an uncommitted verdict after a failed durable reply. | `TestAuditGapDoesNotCache` | `audit gap was cached` |
| `skip-no-proof` | Permit skipping nonempty rules without a scored positive proof. | `TestSkipCannotCancelDeny` | `skip overrode an explicit deny` |
| `skip-miss-refuses` | Turn a skip-context miss into a refusal after semantic allow. | `TestSkipRequiresPositiveProof` | `skip miss became an allowlist refusal` |
| `skip-stale` | Use any audited allow proof instead of current skip/rule/context bindings. | `TestSkipInvalidation` (`rule-update`, `context-update`, `generation-update`) | `stale skip/proof allowed changed work` |
| `skip-critical` | Invert the critical-entry skip guard when an approved skip exists. | `TestCriticalCannotSkip` | `skip hid an unresolved critical rule` |
| `omit-audit` | Remove the durable audit call while falsely claiming completion. | `TestExactInputsAndAudit` | `returned result differs from durable policy event` |
| `ignore-readback` | Compare read-back bytes to themselves instead of exact input. | `TestScopeAndReceiptFailures` (`bad-readback`) | `want integrity;` |
| `omit-policy-cas` | Remove the approved org generation comparison at policy audit commit. | `TestScopeAndReceiptFailures` (`policy-race`) | `want conflict;` |
| `hide-judge-stub` | Treat an unimplemented judge as an ordinary scored/outage path. | `TestScopeAndReceiptFailures` (`judge-stub`) | `want not_implemented;` |
| `hook-no-block` | Suppress the hook's enforcing outcome. | `TestHookOutcome` (`refuse`) | `want forbidden;` |
| `hook-no-route` | Remove the hook refusal's Instead validation. | `TestHookOutcome` (`missing-route`) | `want integrity;` |
| `unknown-flags` | Allow an unknown policy flag to reach transport. | `TestCLIRejectsAmbiguousInputs` | `input reached transport or produced success:` |
| `policy-hash` | Check hash shape but stop comparing canonical content identity. | `TestScopeAndReceiptFailures` (`bad-policy-hash`) | `want integrity;` |
| `list-routes` | Omit the actual Instead value from human rule listing. | `TestPolicyListText` | `rule list omitted actual words or provenance:` |
| `list-sources` | Omit empty-layer source provenance from human rule listing. | `TestPolicyListText` | `rule list omitted actual words or provenance:` |
| `approved-config` | Ignore the approved snapshot's configuration binding. | `TestApprovedSnapshots` (`wrong-config`) | `want integrity;` |
| `source-generation` | Permit source references from a stale org generation. | `TestApprovedSnapshots` (`stale-source`) | `want integrity;` |
| `approved-membership` | Skip effective source membership in the approved inventory. | `TestApprovedSnapshots` (`unapproved-source`) | `want conflict;` |
| `source-content` | Stop comparing the resolved committed source content. | `TestApprovedSnapshots` (`changed-source`) | `want integrity;` |
| `turn-task` | Permit a turn snapshot with a different retained task. | `TestApprovedSnapshots` (`changed-task`) | `want conflict;` |
| `object-metadata` | Ignore the actual retained object's configuration ACL. | `TestApprovedSnapshots` (`metadata`) | `want integrity;` |
| `committed-reply` | Return the proposed decision without a retained committed reply. | `TestApprovedSnapshots` (`reply`) | `want integrity;` |
| `receipt-preflight` | Re-run module preflight instead of replaying a completed receipt. | `TestReceiptReplayBeforePreflight` | `retry did not replay its exact original result` |
| `frame-envelope` | Stop binding the typed envelope to the exact verified frame. | `TestFrameAndReservation` (`frame`) | `want integrity;` |
| `frame-params` | Stop binding module parameters to the authenticated envelope. | `TestFrameAndReservation` (`params`) | `want integrity;` |
| `frame-digest` | Ignore the authenticated envelope's claimed intent digest. | `TestFrameAndReservation` (`digest`) | `want integrity;` |
| `reserved-frame` | Ignore exact raw request retention in the pending reservation. | `TestFrameAndReservation` (`reservation`) | `unbound request performed inference, retention or commit` |
| `turn-cache` | Drop retained task, prompt and turn generation from context hashing. | `TestTurnChangesInvalidateCache` | `changed retained turn reused a cached semantic allow` |
| `human-principal` | Borrow a lane principal for the human target's source lookup. | `TestHumanTargetKeepsPrincipal` | `human targeted preview borrowed a lane principal` |
| `validate-org-generation` | Use policy generation in the complete org source validator. | `TestSourceGenerationIsOrg` | `source validator did not receive the org generation` |
| `source-policy-generation` | Conflate independent org source and policy generations. | `TestSourceGenerationIsOrg` | `invalid policy provenance` |
| `retained-input-refs` | Drop the actual approved source/task input references from retention. | `TestExactInputsAndAudit` | `fixture retention lacks actual input references` |
| `receipt-config` | Ignore the retained receipt's configuration. | `TestForeignPolicyReceipt` (`config`) | `want integrity;` |
| `receipt-principal` | Ignore the retained actor kind, principal and life. | `TestForeignPolicyReceipt` (`principal`, `life`, `kind`) | `want integrity;` |
| `receipt-key` | Ignore the receipt method and retained mutation key. | `TestForeignPolicyReceipt` (`method`, `key`) | `want integrity;` |
| `receipt-digest` | Ignore the receipt intent digest. | `TestForeignPolicyReceipt` (`digest`) | `want integrity;` |
| `lane-proof` | Permit a lane proof to reach completed receipt replay. | `TestProofBeforePolicyReplay` (`lane-proof`) | `want forbidden;` |
| `human-proof` | Omit live human session authority before replay. | `TestProofBeforePolicyReplay` (`missing-human`) | `want forbidden;` |
| `proof-id` | Ignore proof ID shape before replay. | `TestProofBeforePolicyReplay` (`bad-id`) | `want invalid_request;` |
| `proof-digest` | Ignore proof binding to the exact operation before replay. | `TestProofBeforePolicyReplay` (`wrong-digest`) | `want invalid_request;` |
| `proof-guard` | Inject a consuming proof guard into a session-scoped preview. | `TestHumanPolicyGuardAndReplay` | `invalid typed transaction shape` |
| `proof-target` | Skip binding the live human session principal before policy work. | `TestHumanPolicyTargetGuard` | `mismatched proof target performed policy work` |
| `judge-default-spelling` | Reject the approved empty Clef provider/model spelling. | `TestDefaultJudgeSpelling` | `default judge spelling did not produce a scored allow` |
| `cli-mutation-key` | Invent a mutation key instead of requiring the retained caller key. | `TestCLIRetainsMutationKey` | `missing retained mutation key reached transport or succeeded` |
| `human-replay` | Re-run human preflight instead of replaying the committed proof result. | `TestHumanPolicyGuardAndReplay` | `completed human receipt revalidated or consumed its proof again` |
| `scoped-judge-refusal` | Treat a scoped authorization/provider refusal as an inference outage. | `TestScopedJudgeRefusal` (`fit`, `evaluate`) | `want forbidden;` |
| `policy-validator-register` | Skip the method-owned policy input registration. | `TestCLIRejectsPolicyFiles` (`run`, `turn`, `cwd`, `digest`) | `policy file semantic error did not precede proof/key/transport` |
| `policy-validator-semantics` | Accept every structurally typed policy request without semantic checks. | `TestCLIRejectsPolicyFiles` (`run`, `turn`, `cwd`, `digest`) | `policy file semantic error did not precede proof/key/transport` |
| `session-before-replay` | Reuse cached human facts after connection/session authority changes. | `TestHumanSessionBeforeReplay` (`closed`, `revoked`, `connection`, `principal`, `config`, `endpoint`) | `want forbidden;` |
| `get-input-registration` | Drop the policy.get semantic input registration. | `TestCLIReadValidFiles` (`policy-get`) | `valid read file did not reach transport` |
| `config-read-registration` | Drop the config.read semantic input registration. | `TestCLIReadValidFiles` (`config-read`) | `valid read file did not reach transport` |
| `config-validate-registration` | Drop the config.validate semantic input registration. | `TestCLIReadValidFiles` (`config-validate`) | `valid read file did not reach transport` |
| `get-input-semantics` | Accept an invalid supplied policy life identifier. | `TestReadInputSemantics` | `want invalid_request;` |
| `config-read-semantics` | Accept an unknown or empty configuration view. | `TestReadInputSemantics` | `want invalid_request;` |
| `empty-config-semantics` | Ignore the actual empty-method body and validate a manufactured empty object. | `TestEmptyConfigInput` (`extra-field`) | `want invalid_request;` |
| `missing-cost-config` | Accept omitted assembly inference configuration. | `TestConfiguredInferenceBudget` | `want prerequisite_missing;` |
| `judge-not-consulted` | Silently replace the approved positive inference ceiling with zero. | `TestConfiguredInferenceBudget` | `approved inference ceiling did not reach the judge` |
| `missing-judge-allow` | Treat an absent judge port as an ordinary noncritical outage allow. | `TestMissingJudgeRefusesEvaluation` | `want not_implemented;` |
| `hook-ignores-deny` | Map a refusing hook decision to exit zero through the prescribed cli.Run form. | `TestInstalledHookExit` | `installed hook decision/exit mismatch: failed cases=deny` + `deny exited zero` |
| `human-read-session` | Omit current human connection/session authority for all public reads. | `TestHumanReadAuthority` (`missing`, `closed`, `principal`) | `invalid human read authority reached protected work` |
| `lane-read-authority` | Omit live lane launch/grant/cleaned checks before policy/config reads. | `TestLaneReadAuthority` (`cleaned`, `launch`, `grants`, `expiry`) | `want forbidden;` |
| `lane-read-instance` | Allow a foreign instance selector to reach a conflict instead of target refusal. | `TestReadInstanceTarget` | `want forbidden;` |
| `projection-source-scope` | Expose unselected org source metadata in a lane configuration projection. | `TestProjectionSourceScope` (`lane-path`) | `configuration source visibility differs` |
| `projection-life-acl` | Drop the lane life from the retained projection intent and object ACL. | `TestProjectionSourceScope` (`lane-path`) | `configuration projection lost its principal/life ACL` |
| `config-view-catalog` | Admit config/read view values outside the frozen catalog. | `TestCLIClosedViews` (`config`, `read`) | `noncatalog configuration view reached transport` |
| `client-provider-cap` | Refuse a wire-valid provider overflow on the ergonomic hook client. | `TestInstalledHookExit` | `installed hook decision/exit mismatch: failed cases=unscored` + `provider overflow refused locally` |
| `late-command-check` | Resolve a missing target before local command/cwd/tool validation. | `TestCLILocalPreflight` (`cwd`, `tool`) | `local preflight reached target lookup` |
| `late-key-check` | Resolve a missing target before checking the retained mutation key. | `TestCLILocalPreflight` (`key`) | `local preflight reached target lookup` |
| `skip-overbound` | Bind an approved work exemption to ephemeral caller/launch/turn facts. | `TestStableSkipApproval` (`turn`) | `stable skip approval was not reusable` |
| `positive-proof-scope` | Drop full caller context from the positive allow proof key. | `TestHumanCannotSeedLaneSkip` | `human preview seeded a lane positive proof` |
| `zero-spend-allow` | Turn a zero-spend fresh judgment into an ordinary unscored allow. | `TestZeroSpendRefusesJudgment` | `zero-spend evaluation did not refuse before judging` |
| `judge-invalid-allow` | Treat a judge invalid-request error as an ordinary outage allow. | `TestScopedJudgeRefusal` (`fit-invalid`, `evaluate-invalid`) | `want invalid_request;` |
| `judge-not-found-allow` | Treat a judge not-found error as an ordinary outage allow. | `TestScopedJudgeRefusal` (`fit-not-found`, `evaluate-not-found`) | `want not_found;` |
| `generation-values-swapped` | Report the current and recorded policy generations in the wrong positions. | `TestLanePolicyGenerationDiagnostic` (`policy.get`, `config.read`, `config.validate`, `policy.evaluate`) | `generation refusal lost recorded/current values or reached protected work` |
| `f11-policy-eval` | Use the retained launch generation for a fresh policy evaluation. | `TestPolicyCurrentEvaluation` | `fresh policy evaluation did not use the current approved generation` |
| `f11-policy-replay` | Select current policy instead of the completed receipt's retained generation. | `TestPolicyHistoricalReplay` | `exact policy replay lost its retained generation or performed fresh work` |
| `f11-policy-replay-key` | Bypass the exact replay config/actor/key/digest binding. | `TestPolicyReplayBinding` (`config`, `actor`, `key`, `digest`) | `want invalid_request;` |
| `f11-policy-pin` | Accept a widened live policy projection in the protected refresh receipt. | `TestPolicyAdvanceReceiptRefusals` (`pin`) | `want invalid_request;` |
| `f11-policy-event` | Accept an incorrect lane.policy event in the protected refresh receipt. | `TestPolicyAdvanceReceiptRefusals` (`event`) | `want invalid_request;` |
| `f11-policy-cas` | Supply a stale life CAS to the protected policy refresh. | `TestPolicyAdvanceFence` | `lane policy refresh used a stale life fence` |
| `f11-policy-epoch` | Lose the current cancellation epoch on the protected policy refresh. | `TestPolicyAdvanceFence` | `lane policy refresh used a stale life fence` |
| `f11-policy-history` | Accept a foreign generation or hash from the immutable history port. | `TestPolicyReplayHistoryRefusals` (`generation`, `hash`) | `want integrity;` |
| `f11-policy-reply` | Accept a completed decision that differs from its receipt generation. | `TestPolicyReplayHistoryRefusals` (`reply`) | `want integrity;` |
| `f11-policy-refresh-port` | Swallow a protected refresh conflict or owner-named missing implementation. | `TestPolicyAdvancePortFailure` | `policy refresh failure became judgment or success` |
| `human-preview-refresh` | Refresh a target lane's live projection during a verified human preview. | `TestHumanPreviewKeepsLaneProjection` | `human preview refreshed the target lane policy projection` |
| `lane-refresh-omitted` | Skip the protected refresh for actual lane evaluations. | `TestPolicyCurrentEvaluation` | `fresh policy evaluation omitted its one protected lane refresh` |
| `zero-spend-order` | Return the same budget refusal only after refresh and input retention. | `TestZeroSpendBeforeSideEffects` (`lane`, `human`) | `zero-spend refusal refreshed or retained input` |
