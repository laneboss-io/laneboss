# Policy integration gates after the draft.4 review

These are concrete requests for the named owners. No shared API, CLI dispatcher,
assembly, store or source-loader file is changed by this lane. Source inspection
and component fixtures do not establish a passing composed serve path.

1. **Assembly inference configuration: lb-v2-serve.** The installed startup now
   uses NewInstalled with the real Store, Judge, Clock, command deadline and a
   dependency-safe real templates source validator. It permits host startup and
   policy reads, but fresh evaluation without an approved cost ceiling returns
   the named integration not_implemented before inference. No cap is invented.
   The strict New constructor still refuses an omitted
   or nonpositive MaxCostMicros with prerequisite_missing, owner lb-v2-integrate,
   and the message "policy inference cost ceiling is not configured". At that
   call, pass the positive org/installation-approved inference ceiling, approved
   CommandDeadlineMS, and ValidateSources bound to TemplatesAPI.OrgValidate.
   Construct templates/the validator first, or provide a dependency-safe closure
   that propagates its actual error; never return a fabricated valid result.
   Supply policy.Dependencies fields Store, Judge, Clock, MaxCostMicros,
   CommandDeadlineMS and ValidateSources with actual approved values. No invented
   config key, arbitrary positive default, MaxInt64 substitute or zero-as-free
   fallback is authorized. The effective call cap remains the minimum of this
   ceiling and lane.BudgetRemaining.SpendMicros. A new rule-covered request with
   zero remaining spend now returns budget_exhausted with an Instead route to
   obtain an approved budget and retry with a new retained key. It cannot produce
   an unscored allow or silently choose a free judge. The check now precedes lane
   refresh, input retention and semantic cache/skip lookup. Exact completed
   replay remains before that check; empty rules require no budget. Rebind approved
   limits on reload. A scoped judge's genuine cost-cap outage under a positive
   call cap still follows the frozen unscored rule; it is a separate case from
   a lane starting with no spend.
   TestConfiguredInferenceBudget exercises the omitted construction shape and
   a positive cap reaching an actual scoped judge call and matching refusal.
   Permanent controls: missing-cost-config, judge-not-consulted and
   missing-judge-allow. Approved cost enrollment remains an operation gate;
   startup alone does not establish inference readiness.

2. **Raw hook form resolved by fix 11; runtime evidence required.** The shared
   Run branch now refuses org hook --request FILE before generic file/socket
   handling with unsupported, owner lb-v2-policy, exit 69 and empty stdout.
   TestRawFileHookOutcome now drives actual cli.Run for allow, deny, warn and
   unscored input cases and requires that exact code, owner, message, Instead
   and exit. A transport failure, any other nonzero exit or printed decision
   fails. The prior invokeFile-success expectation is replaced because the
   product now explicitly refuses the raw form; no assertion is skipped.
   TestInstalledHookExit keeps the ordinary --command-file decision-aware path
   and permanent hook-ignores-deny control. The case worker prescribes that
   adapter and refuses nonempty argv/declared_paths instead of dropping them.
   Arbitrary full CommandData raw hooks remain unsupported by contract. The
   shared f11-hook-file control belongs to integrate's CLI catalog; no shared
   dispatcher is edited here. Raw refusal and ordinary native socket behavior
   still need the authorized Linux run. Raw config validate outcome semantics
   remain a separate shared CLI concern; the hook decision did not define them.

3. **Retention emitter row and read causality: contract/store owners.** Amend
   InternalObjectRetain's emitter catalog to authorize service component
   lb-v2-policy for classes judge_request and policy. Preserve the real human
   or lane RequestedBy, configuration, life and request/operation causality,
   object ACLs, actual input references, metadata and byte read-back. Policy
   must not impersonate records, judge or another approved emitter. Evaluation
   objects carry the reserved policy operation. ConfigRead uses the separate
   trusted retention port with no invented public mutation operation; define
   its pinned-read visibility and read causality, or provide precommitted typed
   projection reads. Lane projection ACLs now include their actual life. Human
   reads refresh live connection authority, and the fixture's retention port
   independently refuses stale human authority. Its acceptance is not evidence
   that the production emitter gate permits policy. This gate blocks serve E2E.

4. **Canonical union loader: lb-v2-service/source-loader owner.** StateStore.Policy
   and target/context BriefingInput must use policy.Resolve as their canonical
   constructor from approved retained source bytes. Decode the complete org
   baseline and every role layer into policy.Layer with its Source and DefinedAt,
   defining thresholds/calibration, rules and skip entries. Call Resolve with
   the distinct effective policy generation, resolved role/instance, approved
   judge pins and guidance half-life. Validate unselected layers too; preserve
   org + own pair + every higher role and no lower/peer inheritance. The current
   projection lacks defining scope, so validation of an already flattened
   EffectivePolicy cannot prove an omitted layer. Do not substitute a no-op
   callback or rederive from lane-controlled files. Use the same loader for
   human targets without borrowing the target's lane principal. No production
   caller is supplied by the current store implementation; this wiring is an
   explicit acceptance blocker outside this lane's file ownership.

5. **Complete typed configuration projection: source-loader/integrate owners.**
   ConfigProjection exists, but no normalized context-aware reader supplies
   show/settings/roles/channels/plugins. Add the canonical internal read or
   assign its approved loader; return screened typed values, defining sources,
   complete catalogs and the exact approved generation, without host-state paths
   or environment discovery. List/path are implemented: lanes see only their
   effective policy sources and verified humans may inspect the full approved
   inventory. The other five frozen views remain typed not_implemented. All four
   policy CLI input validators are registered; config/read are not view enums.

6. **Defining warning threshold: next shared contract revision.** api.Thresholds
   still has only Match, UncertainLow, UncertainHigh and CalibrationID. Add Warn
   with defining-source fallback and calibration semantics, update the tagged
   field map and its loader / judge / template / approval / dashboard consumers. The
   existing 0.50 cutoff is retained until that field exists; uncertainty bounds
   cannot substitute for it. Warn never blocks. No shared contract is edited here.

7. **Fix-11 generation rule adopted; protected store ports: lb-v2-service.**
   Fresh evaluation uses PolicyGenerationFor(PolicyNewEvaluation) with the
   current approved policy and unchanged current Scope check. Historical
   launch/grant pins and an older live Lane projection do not refuse merely
   because D6 advanced. Zero/future pins, stale current scope and actual
   launch/grant/cleaned/instance failures still refuse. Reads never refresh.
   After exact receipt lookup proves new work and target/turn/budget checks
   succeed, a lane caller uses RefreshLanePolicy with the observed life CAS and cancellation
   epoch, and validates the returned narrow projection and lane.policy event
   using ValidatePolicyAdvance. Its returned life generation binds cache and
   audit. Verified human previews never call that port or emit lane.policy;
   they judge current policy under their own authority without advancing the
   target's live projection. Already-current lane work makes no refresh call or duplicate event.
   Production store.RefreshLanePolicy must implement the actual current
   authority/policy/grants recheck, atomic CAS/epoch, one service event and
   unchanged issuance/run/task/budget facts. Its owner-named stub still fails.
   Exact replay uses PolicyGenerationForReplay's config/actor/key/digest binding
   and the current authenticated scope generation, then loads approved immutable
   history through PolicyAt and verifies the actual policy hash, generation and
   decision stamp. It performs no fresh source preflight, lane refresh or judge
   call. Current authentication/revocation/receipt visibility remain the
   dispatcher/store's mandatory pre-replay gates. Production PolicyAt must
   enforce that visibility and return actual retained snapshots, never current
   policy relabelled as old. Its owner-named stub still fails. No fix11_stubs.go
   exists in this policy package; these two store implementations are outside
   this lane's ownership and are not replaced by its test-only DTO ports.
   The policy consumer controls cover current evaluation, exact replay/binding,
   history/result integrity, refresh pins/event/CAS/epoch and port errors.
   Shared selection/retained-turn controls belong to guidance; fresh launch and
   unopened-plan controls belong to lifecycle/watchdog. The public E2E now
   records lane status before an actual mid-run rules apply, lists current
   policy without a refresh, evaluates under the new generation on the same
   life/run/launch/turn/grants, and verifies the single lane.policy event.
   Both runtime modes and the real D6 case remain required acceptance evidence.

The source-generation review item is already resolved by the frozen contract:
docs/design/v2-contracts.md states "SourceRef.Generation is the current snapshot
generation; ResourceFile separately retains the original RevisionGeneration
for unchanged file history." Policy's strict equality and its independent
org-versus-policy generation tests follow that rule. No less-or-equal relaxation
or further generation contract amendment is needed.

Skip approval now uses SkipContextDigest over exact command/tool/argv/paths/cwd,
configuration, role/instance, policy generation and judge pins. It no longer asks
D6 to predict launch or turn identifiers. Cache and positive-proof keys still
bind the full caller / life / launch / endpoint / grants / turn / task context. Each new
authority context must judge before using the existing approved exemption, and
a human preview cannot seed a lane proof. The approval/loader harness should use
that exported stable digest for the resulting D6 policy generation.

The frozen unjudgeable-input rule remains critical-refuse-only unscored behavior;
the review's owner choice is recorded in OWNER-QUESTIONS.md. No real owner
message, D6 change, model call or production acceptance is claimed.
