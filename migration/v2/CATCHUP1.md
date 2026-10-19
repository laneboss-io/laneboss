# Migration catch-up 1

This audit compares `708e71e` with `d7403ec` for
`internal/v2/api` and `docs/design/v2-contracts.md`, then checks the merged
candidate at `74071cb`.
The earlier unit and eleven-mutation green results are supplied checkpoint
evidence, not measurements of this candidate. This round permits static
checks on macOS; runtime tests and the red catalog remain supervisor Linux
work.

Two fixture compile errors were reproduced in order. First, memWorker lacked
DataWorker.MaterializeLaunch. It now has a compile-time interface assertion and
returns a typed migration-owned NotImplemented from that unused port. The
module's relaunch helper calls the unchanged Materialize port; it does not
call MaterializeLaunch or claim a live launch. Second, CompleteEffect assigned
the string EffectOutcome.Status to the newly typed EffectRecord.State.
The fixture now maps succeeded to EffectCompleted and failed to EffectFailed,
retains the original operation status, and rejects nonterminal outcomes before
changing its effect map. It does not cast succeeded into an invalid effect
state. No production function, existing test assertion, skip or build tag was
changed.

Each row below records a contract item and its migration disposition. API
filenames are relative to internal/v2/api. Migration references are relative
to internal/v2/migration unless prefixed with cli or assembly.

| Contract item and changed source | Disposition and inspected consumer |
| --- | --- |
| Migration RPC signatures, ownership and request/result shapes: interfaces.go; unchanged methods.go and ports.go | No change: stub.go:13, :55 and :59 still implement MigrationAPI and Module with StateStore, HumanVerifier and DataWorker; migration.plan and migration.apply keep their original typed bodies and owner. |
| Error codes and Error fields: unchanged base.go | No change: readers.go:185 and the injected dependency tests preserve exact typed errors; no error vocabulary or accepted-code assertion changed. |
| DataWorker.MaterializeLaunch: interfaces.go:209; materialization.go and launch_plan.go | Adapted memWorker in migration_test.go with the exact new method and an interface assertion; the unused method returns NotImplemented. PrepareRelaunch at relaunch.go:120 still calls Materialize, whose signature is unchanged. |
| EffectState vocabulary: effect_state.go; transactions.go EffectRecord; contract section 14 and fix 12d | Adapted memStore.CompleteEffect at migration_test.go:203 to map operation outcomes to completed/failed; operation status remains succeeded/failed. Existing claimed and pending fixture literals are already valid effect states. |
| StateStore extension: transactions.go:262 | No migration call changes: credential projection, current/historical policy, launch-data stages, channel preparation, launch reservations and capture ports belong to live service workflows. Migration uses the existing receipt, read-view, blob, object, deployment, backup, effect and decision ports. The current assembly store satisfies the expanded interface. |
| HumanVerifier and proof target: interfaces.go:107 | No signature change. apply.go:60 still invokes CheckProof and compares exact reference, target, principal, config, endpoint, credential, nonce and consumption facts before its transaction. |
| IdentityStore inventory/ceremony/worker/revocation additions: humanstate.go; enrollment.go; worker_identity.go; revocation.go | No new identity implementation in migration. It neither enrolls credentials nor binds/revokes a live launch. Its sole human dependency is HumanVerifier, and historical labels remain inert records. |
| Read sessions: bindings.go ReadAuthority; read_session.go | No change: cli/commands_migration.go uses the shared invocation, and the existing CLI session case requires human.session on the same connection. Migration does not cache or refresh ReadAuthority or open a second connection. |
| Presence provenance: common.go Operation/ProofRef; identity.go Ticket/HumanSession; approval.go; humanstate.go; assertion.go | No field reconstruction: apply.go carries the whole ProofRef in ProofUse, decodes the store's whole Operation reply and returns the whole completion Operation. CLI also exact-decodes current DTOs. Current store receipts preserve the verified mark; imported history is not new human authority. |
| Credential presence rules and build separation: human_presence.go, human_presence_release.go, human_presence_testbuild.go | No change: migration does not select a software authenticator or validate enrollment. It delegates actual proof verification and one-use validation to identity/store. Fixture proof checks are unit doubles, not physical-presence evidence. |
| Administrator enrollment transport and inventory: enrollment.go, enrollment_wire.go | No change: migration imports no enrollment or private signing key and exposes no administrator enrollment entry. Current startup/enrollment owners retain these new gates. |
| Protected attestation policy: attestation_policy.go; fix 13 Q2 | No change: migration does not construct identity or choose roots, AAGUIDs or installation policy. Assembly owns the protected identity constructor mapping; legacy config bytes never install new trust. |
| Receipt policy generation: transactions.go MutationReceipt; policy_generation.go | No change: apply.go:102 reads the scoped exact receipt before plan/proof work and returns its retained reply without policy re-evaluation. Store LookupReceipt enforces current scope and exact actor/key/digest; migration does not replace retained policy metadata with a launch-time label. |
| Current policy and lane projection advance: policy_generation.go; policy.go | No change: migration creates no live Lane or guidance selection and does not call PolicyAt or RefreshLanePolicy. A later real adopt/launch must resolve current approved policy and grants through lifecycle. |
| Effect union and serialization: interfaces.go Effect, including PlanLaunch and omitted inactive arms | No change: apply.go:88 creates exactly one Migration arm with its original migration_apply intent. import.go does not enqueue an agent PlanLaunch, helper or cleanup effect. The new JSON tags serialize existing typed values without a migration wire shim. |
| EffectOutcome.LaunchPlan and deferred completion: transactions.go; deferred.go | No change: CompleteMigration at apply.go:253 submits its existing succeeded outcome and source Output; it does not complete an org publication or supply a competing LaunchPlan result. |
| Public/internal write catalogs: write_catalog.go | No migration row changed. Public apply still writes only Deployments and queues Migration with an exact reply/proof guard; internal migration_apply still permits the original deployment/object/history completion and Cancellation guard. TestMigrationWriteCatalog retains its negative assertions. |
| New transaction preflights: validation.go | No migration shape bypass: existing code continues to call ValidateTransactionShape. Migration writes no LaunchPlans/Guidance and emits no lane.turn, so added plan/guidance/loop checks do not require fabricated authority fields. |
| Retained launch reservation, sources, home and recovery: launch_plan.go, launch_authority.go, launch_validation.go | No new launch implementation: PrepareRelaunch prepares AdoptionManifest/AdoptRequest only. It does not reserve a life, build LaunchSpec, bind identity or open a gate. Actual adoption must pass the new lifecycle planner; legacy lane/session labels grant none of that authority. |
| Internal grant resolution: interfaces.go GrantResolver.Resolve | No change: migration has no GrantResolver dependency or Resolve call. Its existing Materialize call is not represented as a reserved, authorized LaunchData result. |
| HelperControl extensions and LaunchBinding.Recovery: bindings.go | No change: migration calls neither HelperControl nor BindLaunch; its import transaction creates no active identity binding. The real assembly helper/identity owners handle storage, capture, credential projection and retained recovery. |
| Required bound plan for prepared agents: prepared_validation.go | No change: migration transactions use migration_apply, not helper_prepare, and have no Lane/IdentityBindings writes. Imported launch history remains record.appended, so no fake matching plan is added to satisfy a live gate. |
| Fresh prepare/open policy fence: gate_policy.go; interfaces.go private transaction field | No change: migration has no helper_prepare/helper_open transaction and cannot construct the private fence. Relaunch metadata must later pass the real writer's current-policy fence. |
| Installed launch-plan reads: plan_read.go | No change: migration does not read or reconstruct live LaunchPlanRecord from an adoption reference. Real launchers must use the installed LaunchControlSource. |
| Durable materialization child job and held storage: materialization.go | No live data-stage claim is invented by migration. The new fixture method refuses; the existing helper materialization is not evidence of a confined import, private home preparation or an opened agent. |
| Live capture registration, append/recovery and refusal policy: capture.go, capture_validation.go; policy.go | No change: migration emits no live CaptureBinding or capture append. Legacy bytes remain historical content; an imported transcript cannot satisfy a new primary-pipe, EOF, coverage or D6 capture-exception gate. |
| Capture field additions: runtime.go CaptureRecord; views.go CaptureGap | No change: historical imports may omit BindingID under fix 9. Migration stores exact legacy content as inert records instead of manufacturing new primary capture metadata. |
| Capture stream vocabulary stdout/stderr/vendor: contract appendix and fix 9 | No legacy rewrite: migration does not produce a new live CaptureRecord from a legacy stream label. The new stream vocabulary is enforced by the current capture producer and its consumers. |
| Event payload catalog additions: events.go | No change: launch.planned, loop.reserved, lane.policy and capture.bound/refused/closed are not synthesized. import.go:14 emits record.appended and migration.completed with existing payload types; historical event kinds live inside record content. |
| Mandatory logical turn on lane.turn: validation.go; fix 12 | No change: migration emits no new lane.turn. Existing import assertions continue to forbid active starter/identity authority rather than filling a new event envelope from legacy labels. |
| Trigger idle to loop and private scheduler scope: common.go; loop_turn.go | No change: migration creates no scheduler binding, LoopTurnCause or automatic turn and cannot fill the private scope authority. Historical trigger strings do not become live loop permission. |
| Review evidence and closed coverage: lifecycle.go, review.go, review_validation.go | No change: migration neither issues ReviewReceipt nor marks a live lane accepted. Imported archives/review-like records remain historical and cannot authorize new acceptance without current measured evidence. |
| Channel preparation/runtime/payload/read-back: delivery.go, mail.go, channel_worker.go, channel_validation.go | No change: import.go preserves delivered mail as inert records and the existing red forbids a new delivery effect. It neither prepares a ChannelJob nor turns injection or a worker exit into confirmed delivery. |
| One continuation operation: turns.go; continuation_validation.go | No change: migration creates no ContinuationIntent or ProfileSwap and does not call Continue. Adoption metadata is not a continuation of an authenticated v2 life. |
| Guidance owner/attempt/CAS/await: turns.go; guidance_claim.go | No change: migration does not reserve/evaluate guidance or call AwaitGuidance. Its decision read-back uses the unchanged TurnStore.Decision port only to ensure imported history acquired no canonical decision authority. |
| Outside usage evidence: runtime.go LimitSignal; usage_window.go | No change: migration does not derive a quota signal from imported stdout or issue a profile continuation. A historical log cannot substitute for the new outside usage worker evidence. |
| Worker native bootstrap and permitted operations: worker_identity.go | No worker principal, endpoint, lease or current claim is fabricated by migration. Confined import/rollback execution remains a separate installed integration requirement; passing fixture tests is not that evidence. |
| Credential projection store/native ports: credential_projection.go, credential_validation.go; interfaces.go CredentialBroker | No change: migration has no credential broker/helper dependency and never exports, imports or stores credential values. New StateStore ports and runtime metadata are consumed by the installed native owners. |
| Final-only credential environment and secure names: credential_env.go | No change: migration runs no vendor exec and constructs no credential environment. Relaunch metadata cannot bypass the real helper's final UID/capability/isolation and selected-target checks. |
| One-use credential binder and certified retry: credential_binding.go | No change: migration does not bind or retry a credential projection. Assembly's deferred launcher remains the only shared composition path; no permissive migration adapter was added. |
| RuntimeServices constructor additions: composition.go | No migration constructor change: assembly/assembly.go:214 supplies Store, Human and Worker, :229 passes that same instance into RuntimeServices.Migration, and :237 includes it once in the module list. Extra credentials/identity/planner fields do not add migration dependencies. |
| Canonical org kinds and exact current snapshot: org_snapshot.go; fix 13 Q1 | No change: migration performs no OrgSnapshot selection/publication and imports legacy configuration/source bytes as historical data. It neither converts semantic sources to file nor installs old org authority. |
| Initial publication marker: sources.go | No change: migration does not create or interpret InitialPublicationMarker as an installed publication. Legacy source archival cannot bootstrap a current org. |
| Atomic failed-plan cleanup: plan_cleanup.go | No change: migration performs no PlanCleanup/FailPlan write and does not give a migration effect launch-plan cleanup authority. Existing migration deployment CAS and matched rollback remain distinct. |
| Authorized collection and independent read-back: collection.go, collection_proof.go | No change: optional CleanupObjectStore/CleanupDataWorker capabilities were not added to the migration dependencies. ExecuteRollback does not claim Lane.Cleaned or remove an authorized live worktree/branch. |
| Public health and raw hook file behavior: contract fixes 8 and 11 | No change: migration uses neither pre-auth health nor the org hook adapter. Its plan/apply exact-file semantic registrations and shared proof/transport path remain active. |
| Red-runner broken-anchor reporting: contract fix 14b | Migration's separate eleven-control script already requires one exact anchor and treats setup/compile failure as failure. This round rechecks every anchor, focused assertion and diagnostic without running or vetting mutant overlays on macOS. |

The API-only regression files in the compared delta are retained unchanged.
They add or strengthen the shared contract controls rather than a migration
consumer signature. Their named topics are covered by the corresponding rows
above: capture_test.go; catalog_test.go; channel_test.go; collection_test.go;
continuation_test.go; contracts13_test.go; credential_projection_test.go;
deferred_test.go; fix11_auth_test.go; fix11_data_test.go; fix11_jobs_test.go;
fix11_policy_test.go; gate_policy_test.go; human_presence_test.go;
launch_authority_test.go; launch_plan_test.go;
loop_turn_test.go; plan_cleanup_test.go; review12_delta_test.go;
review12_test.go; review_test.go. The supervisor's complete unit suite includes
these files; none were removed, weakened or hidden by this catch-up.

Assembly registration remains exact: stub.go:Register calls migration.plan
once and migration.apply once, preserving errors. assembly/registry.go:claim
rejects duplicate/unknown/foreign ownership, and registerModules verifies the
whole catalog. The migration entry occurs once. Existing
TestNewAndRegisterValidation checks both handlers with a duplicate-refusing
registrar. Registration completeness is not installed migration completion.

The eleven existing production mutations are retained unchanged. The static
catalog check requires unique source anchors, one replacement, existing focused
test/subtest names and exact assertion diagnostics. No new production refusal
was added, so no additional production mutation is needed for the fixture-only
compatibility fixes. Existing positive migration/relaunch tests must continue
through their needed ports; accidental use of the unused launch port fails
instead of returning a dummy success.

The final checks use the one shared Go cache required by the brief. The whole
tree is vetted, covering migration, migration/v2, CLI, assembly, the executable
and indirect test importers:

| Candidate check | Result |
| --- | --- |
| linux/amd64 go vet ./... | Passed, exit 0. |
| linux/arm64 go vet ./... | Passed, exit 0. |
| linux/amd64 go vet -tags laneboss_faults ./... | Passed, exit 0. |
| linux/arm64 go vet -tags laneboss_faults ./... | Passed, exit 0. |
| darwin/arm64 go vet ./... | Passed, exit 0. |

Formatting, whitespace and the final static eleven-control inventory are
recorded with the external catch-up evidence. The named cache folder was
accepted; no fallback cache was created. Vet compiles/analyzes test sources but
does not execute their assertions. The supervisor still must run the complete
normal/faults unit suites, each reached-red/candidate control and independent
reviews on the committed combined candidate. No authenticated AI-service,
native worker, hardware ceremony, installed migration/relaunch/rollback or
serve acceptance is claimed from this catch-up.
