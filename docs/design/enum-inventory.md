# V2 enum inventory and rename plan

This inventory describes revision 6fc7c91d11a1. It is a plan only; this
step changes no Go source. The rename must follow the API-key lane.

Scope is every Go file under internal/v2, including platform files, build
variants and test support. A group includes literal constants in validators,
switches and catalogs, as well as const declarations. This matters because
RawProfileMode and PublicSlotMode currently have no const declarations.
Fields that merely contain names, IDs, paths, model names, versions, arbitrary
provider labels or explanatory text are not closed enums. The exclusions at
the end distinguish those from the enumerated groups.

All source references below are relative to internal/v2. Short directory
aliases keep path tokens readable: cw = client/wire; rc = runner/codex;
rd = runner/claudock; il = isolation/linux; as = assembly;
bs = secrets/bstate; sn = secrets/native; tf = store/testfx.
A reference such as rd/validation.go:127 therefore names the real source file
in runner/claudock. A field list names every primitive field boundary;
a function list names primitive parameters or results, rather than every
function that receives a whole enclosing struct.

Overlap labels identify files the API-key lane may edit: A = api;
K = admin/apikey*; S = secrets; G = grants; R = runner/claudock;
W = client/wire. A dash means no direct overlap in the identified sources.
These labels are coordination warnings, not permission to edit those files.

## Contract and execution vocabulary

Each row gives the proposed named type, its defining values and source, the
current primitive boundaries, and the overlap. Unless stated otherwise the
underlying type is string. Empty strings used as absent optional values must
remain explicit boundary validation cases, not new successful enum members.

| ID | Proposed type and values, with source | Primitive fields and functions | Overlap |
|---|---|---|---|
| E01 | RawProfileMode: headless_token, helper, file_login, codex-file, claudock-headless. secrets/profiles.go:36; grants/root_profiles.go:100. | bs/state.go:21 Profile.Mode. as/profiles_partial.go:90 standInMode returns string. Keep the raw profile separate from the public slot even where spellings coincide. | S G |
| E02 | PublicSlotMode: claudock-headless, claudock-helper, claudock-api, codex-file, codex-api, codex-local. cw/schema.go:97. | api/runtime.go:37 CredentialSlot.Mode; secrets/credential_slots.go:344 publicSlotMode returns string. Its current raw-mode fallthrough needs a checked conversion, not a cast. | A S R W |
| E03 | LaunchMode: start, adopt, resume, turn, continue. api/launch_validation.go:89. | api/launch_plan.go:27 LaunchReservation.Mode; store/launch_prompt.go:47 launchPromptTrigger(mode); lifecycle/reservation.go:104 reservePublicLaunch(mode). | A S G R |
| E04 | RunnerMode: start, resume, turn. rc/runner.go:121; rd/service.go:161. | rc/runner.go:133 plan(mode); rc/launch.go:21 launchInput(mode); rd/service.go:161 plan(method); rd/launch.go:100 planning(method); as/run_check.go:60 verifyRun(mode). Adopt and continue are translated to resume explicitly. | R |
| E05 | LaunchKind: agent, worker. il/validate.go:129. | api/runtime.go:165 LaunchSpec.Kind; api/runtime.go:218 LaunchRecord.Kind. | A S R |
| E06 | ActorKind: lane, human, service, scheduler, watchdog, worker. cw/schema.go:34. | api/common.go:4 Actor.Kind. String concatenation at api/read_projection.go:27 and store/store.go:417 principal must serialize this type explicitly. watchdog/evidence.go:455 outsideEvent takes variadic string kinds. | A W |
| E07 | OrgLevel (int): 3, 4, 5, 6; 0 means absent for non-lane actors. api/launch_validation.go:105; cw/schema.go:261. | Actor.Level, Lane.Level, StartRequest.Level, AdoptRequest.Level, LaunchReservation.Level, RoleContext.Level, BriefingRequest.Level, DashboardQuery.Level, TreeNode.Level, RefusalCount.Level, RelationFacts.Level, TicketIssueRequest.Level, Ticket.Level, GrantValidateRequest.ChildLevel, TicketUse.Level; RuleScope.Levels and DecisionApplicability.Levels are []int. Sources: api/common.go:7, api/lifecycle.go:41, api/launch_plan.go:28, api/policy.go:66, api/views.go:6, api/delivery.go:118, api/identity.go:32, api/grants.go:140, api/transactions.go:124, api/turns.go:34. secrets/launch_binding.go:169 validateReservedSelection(level); rc/launch.go:18 launchInput.level and grants/launch.go:38 launchSelection.level remain int. | A S G |
| E08 | LaneState: preparing, running, stopping, verifying, idle, profile_wait, lost, accepted, merged, abandoned. cw/schema.go:40. The extra ended spelling is read in admin/launch_sources.go:179 and is not a public member. | api/lifecycle.go:43 Lane.State and :99 MarkRequest.State; api/events.go:81 StateEvent.From, .To; api/delivery.go:120 RelationFacts.State; api/collection.go:26 CleanupIntent.Decision is the merged/abandoned subset. grants/launch_authority.go:11 delegationState(state); dashboard/views.go:29 isActiveLaneState(state). | A G W |
| E09 | OperationStatus: pending, running, succeeded, failed, cancelled. cw/schema.go:38. | api/common.go:71 Operation.Status; templates/bootstrap.go:211 slicesContainStatus(status). Do not reuse the effect record's existing EffectState. | A S G W |
| E10 | EffectOutcomeStatus: succeeded, failed. store/effect_state.go:14. | api/transactions.go:228 EffectOutcome.Status. | A S |
| E11 | ProcessState: prepared, running, exited, unknown. cw/schema.go:42. not_started is a separate internal abort observation at admin/abort.go:125 and admin/arch_retire_linux.go:221. | api/runtime.go:209 ProcessObservation.State; tf/launch_linux.go:760 Observation(state). Preserve the abort sentinel explicitly when choosing the final public/private split. | A W |
| E12 | PromptStatus: not_written, written, cut, unknown, completed. cw/schema.go:44. | api/runtime.go:213 ProcessObservation.PromptStatus; api/mail.go:33 MailReceipt.PromptStatus; api/events.go:105 TurnEvent.Status. messaging/receipts.go:19 validPromptStatus(status); il/control.go:198 validPromptStatus(value). | A R W |
| E13 | RunEndReason: exit, stop, timeout, limit, dropped, revoked, service_lost, capture_full, launch_failed. cw/schema.go:46. | api/events.go:74 RunEndEvent.Reason; api/mail.go:34 MailReceipt.Cause. messaging/receipts.go:28 validEndReason(reason). HelperStopRequest.Reason and Launcher.Stop(reason) carry stop labels and must be checked against their actual callers before sharing this type. | A W |
| E14 | TriggerKind: start, adopt, manual, mail, idle, profile_limit. cw/schema.go:95. | api/lifecycle.go:11 Trigger.Kind. LaunchMode cannot be assigned directly: resume maps to manual, turn maps to mail/idle, and continue maps to profile_limit. | A W |
| E15 | CaptureCoverage: complete, partial, unsupported, missing. api/review.go:5 CoverageComplete, CoveragePartial, CoverageUnsupported, CoverageMissing are the untyped const group. | api/runtime.go:78 CaptureRecord.Coverage; api/lifecycle.go:111 ReviewReceipt.Coverage; api/review.go:53 ReviewInventory.ToolCoverage and :70 ReviewEvidence.Coverage; api/review_validation.go:5 validCoverage(value); lifecycle/review.go:18 reviewCoverage(coverage). | A R W |
| E16 | CaptureStream: stdout, stderr, structured, transcript; vendor is used by the private binding/adapter path. cw/schema.go:89; api/capture_validation.go:37. | api/runtime.go:73 CaptureRecord.Stream; api/views.go:41 CaptureGap.Stream; api/capture.go:7 CaptureStreamBinding.Stream; watchdog/signals.go:44 Diagnostic.Stream. Preserve the public/private subset distinction. | A R W |
| E17 | CaptureBindingStatus: registered, refused. api/capture_validation.go:14. | api/capture.go:26 CaptureBinding.Status. | A R |
| E18 | BlobClass: full catalog below; public upload is a narrower subset. cw/schema.go:48; grants/manifest/values.go:118. | api/common.go:35 BlobRef.Class and :39 BlobBeginRequest.Class; api/objects.go:24 ObjectWrite.Class and :34 UploadLease.Class. Primitive class parameters/results are listed in the boundary index below. | A S G R W |
| E19 | ObjectOrigin: service, observation, legacy_import, worker, identity. api/objects.go:17; dataworker/materialization_stage.go:137; identity/human.go:161. | api/objects.go:17 ObjectMetadata.Origin and :28 ObjectWrite.Origin. This is broader than public event origin. | A S |
| E20 | EventOrigin: service, observation, legacy_import. cw/schema.go:36. | api/events.go:28 Event.Origin; api/ports.go:10 Record.Origin. Do not substitute ObjectOrigin unchecked. | A W |
| E21 | ObjectAudience: owner, life, participants, config, human, service, private. store/objects.go:262. | api/objects.go:9 ObjectACL.Audience; store/materialization.go:467 retainDataBytes(audience). service/private are confined internal subsets. | A |
| E22 | ObjectEntryKind: file, directory, symlink. cw/schema.go:87. | api/manifests.go:21 ObjectEntry.Kind; migration/readers.go:1474 legacy archive entry Type is the corresponding import boundary. | A G W |
| E23 | DataAccess: ro, rw. cw/schema.go:79. | api/grants.go:15 DataGrantRequest.Access and :77 DataGrant.Access. il/rules.go:29 already defines a separate named Access enum; convert at that boundary rather than aliasing it to this string. | A G W |
| E24 | DataDelivery: copy, mount, bind_ro. cw/schema.go:81. | api/grants.go:16 DataGrantRequest.Delivery permits copy/mount; :78 DataGrant.Delivery also permits private bind_ro. | A G W |
| E25 | SecretDelivery: env, file. cw/schema.go:85; api/credential_validation.go:42. | api/grants.go:27 SecretDelegation.Delivery and :92 SecretGrant.Delivery; api/delivery.go:49 WorkerCredential.Delivery; api/credential_projection.go:68 CredentialTarget.Delivery. api/credential_validation.go:37 credentialTaskTarget(delivery); grants/manifest/values.go:149 SecretTarget(delivery). | A S G W |
| E26 | NetworkMode: internet, service, publish. cw/schema.go:77. | api/grants.go:113 NetworkGrant.Mode. | A G W |
| E27 | HistoryScope: snapshot, tree, reachable. grants/manifest/grants.go:125; api/launch_validation.go:60. | api/grants.go:83 DataGrant.HistoryScope; api/launch_plan.go:100 ProjectEnrollment.HistoryScope and :112 ProjectLaunchSource.HistoryScope. grants/subset.go:241 derivedHistory returns string. Launch enrollment accepts tree/reachable; materialization currently accepts tree only. | A G |
| E28 | BoundaryBackend: linux-bwrap-landlock, darwin-seatbelt. cw/schema.go:99. | LaunchSpec.Backend, IsolationCapabilities.Backend, HelperLeaseRequest.Backend, LaunchRuntime.Backend, InstalledBinding.Backend, ContainmentBinding.Backend, ReleaseReceipt.Backend, CredentialExecEnvironment.Backend, bstate.Slot.Backend, LaunchEvent.BoundaryBackend. Sources: api/runtime.go:155, api/runtime.go:170, api/runtime.go:243, api/launch_plan.go:118, api/bindings.go:35, api/bindings.go:83, api/bindings.go:181, api/credential_env.go:16, bs/state.go:66, api/events.go:50. | A S W |
| E29 | ProviderLimitKind: usage_limit, session_limit, rate_limit, auth_expired. watchdog/signals.go:23 already types these as LimitKind, but API/runner boundaries erase that type. | api/runtime.go:85 LimitSignal.Kind; rd/capture.go:162 quotaKind and :178 limitEvent return string; rc/validate.go:314 limitFixture.Kind is another string mirror. Move the shared type to api and retain an adapter alias if needed. | A R |
| E30 | ModelEffort: minimal, low, medium, high, xhigh, max, ultra. migration/legacy_inputs.go:61. Claudock supports low/medium/high/max; Codex validates the installed compatibility receipt's subset. | api/runtime.go:51 RunnerRequest.Effort; api/lifecycle.go:33 Lane.Effort, :69 StartRequest.Effort, :131 AdoptRequest.Effort; rc/validate.go:310 compatibilityProof.Efforts; migration/relaunch.go:19 RelaunchOptions.Effort; migration/readers.go:136 LegacyUnfinishedSession.Effort; lifecycle/plan_claim.go:25 launchInput.effort. migration/legacy_inputs.go:54 legacyEffort(effort). | A R |
| E31 | InnerSandboxMode: off, disabled. rd/service.go:263; rc/runner.go:259; il/validate.go:146. | api/runtime.go:65 RunnerPlan.InnerSandbox. The two existing disabled spellings are not silently interchangeable. | A R |
| E32 | WorkerKind: test, import, export, archive, render, box_run, channel, usage, owner_sheet, gateway, materialize; capture is an internal worker identity branch at identity/worker.go:92. cw/schema.go:101. | api/manifests.go:45 WorkerPlan.Kind; api/delivery.go:33 WorkerLease.Kind; api/materialization.go:91 WorkerJobInput.Kind; api/events.go:150 WorkerEvent.Kind. api/worker_identity.go:43 workerPermits(kind); il/validate.go:288 workerKind(kind). | A S W |
| E33 | RecordCollection: decisions, observations, ledger, refusals, tools, reports, archives, judge_egress, embeddings. cw/schema.go:54; records/service.go:582. | api/ports.go:5 Record.Collection, :21 RecordQuery.Collection, :34 RecordAppendRequest.Collection, :52 TransferRequest.Collection. records/service.go:581 collection(name); dashboard/views.go:110 readAllRecords(collection); migration/stub.go:142 mapLegacyEventCollection and cli/commands_integrate.go:50 integrateAliasCollection return string. | A W |
| E34 | RecordSearchMode: keyword, vector, hybrid. cw/schema.go:59. | api/ports.go:24 RecordQuery.SearchMode. | A W |
| E35 | DecisionAction: add, supersede, annotate, feedback, embed. cw/schema.go:61. | api/ports.go:45 DecisionMutateRequest.Action and :14 Record.Action. | A W |
| E36 | MailStatus: queued, delivering, delivered, returned, answered. cw/schema.go:63. | api/mail.go:23 Mail.Status; migration/import.go:122 legacyMailStatus returns string. | A W |
| E37 | MailReceiptStatus: queued, delivering, delivered, returned; new receipts accept delivered/returned only. cw/schema.go:65; messaging/receipts.go:10. | api/mail.go:32 MailReceipt.Status. Keep answered out of receipt construction. | A W |
| E38 | MailSource: cli, dashboard, scheduler, watchdog, worker. cw/schema.go:67. | api/mail.go:20 Mail.Source. | A W |
| E39 | DispatchSource: cli, dashboard, scheduler, watchdog, worker, service; empty is an internal unbound scope. api/common.go:17; service/server.go:480. | api/common.go:17 Scope.Source; service/dashboard.go:53 dispatchSource returns string. Explicit conversion is needed when queueing Mail.Source. | A |
| E40 | ChannelDeliveryStatus: delivered is the only currently verified terminal discriminant. api/channel_validation.go:96. Other Delivery.Status spellings are not given a closed catalog by this tree. | api/mail.go:56 Delivery.Status. Treat it separately from MailStatus and the richer send evidence outcome. | A |
| E41 | ChannelSendOutcome: confirmed, uncertain, failed, unsupported. api/channel_validation.go:71. | api/channel_worker.go:58 ChannelSendEvidence.Outcome; dataworker/channel_http.go:51 local fail(code, outcome, message). | A |
| E42 | ChannelReconcileMode: provider_key, receipt_id, unsupported. api/channel_validation.go:13. | api/channel_worker.go:10 ChannelRuntime.Reconcile. | A |
| E43 | ConfigViewKind: list, show, path, settings, roles, channels, plugins. cw/schema.go:93. | api/policy.go:304 ConfigReadRequest.View; api/projections.go:17 ConfigProjection.View. | A W |
| E44 | ResourceDeltaAction: add, replace, delete. cw/schema.go:69. | api/approval.go:5 ResourceDelta.Action. | A W |
| E45 | ChangeStatus: proposed, approved, applied, rejected. approval/validate.go:85. | api/approval.go:32 ChangeRequest.Status; approval/validate.go:85 validChangeStatus(status). | A |
| E46 | JudgePurpose: blacklist, guidance, preview. cw/schema.go:71. | api/policy.go:204 JudgeRequest.Purpose. The provider question.Type is the separate fixed noul discriminant at judge/wire/request.go:209. | A W |
| E47 | JudgeReplyStatus: scored, partial, unavailable. cw/schema.go:73. | api/policy.go:226 JudgeReply.Status. | A W |
| E48 | JudgmentStatus: scored, unscored. cw/schema.go:75. | api/policy.go:217 Judgment.Status. | A W |
| E49 | GuidanceStatus: scored, empty, unavailable. guidance/snapshot.go:116. | api/policy.go:268 Guidance.Status; lifecycle/plan_runner.go:18 launchPrompt.GuidanceStatus. | A |
| E50 | RuleBand: refuse, warn. policy/resolve.go:210. | api/policy.go:87 Rule.Band; templates/workflow.go:17 seedEntry.Band. | A |
| E51 | PolicyResult: allow, warn, refuse. policy/hook.go:11. | api/policy.go:153 RuleDecision.Result and :164 PolicyDecision.Result; policy/evaluate.go:554 baseDecision(result), :592 aggregate returns string. Dashboard additionally recognizes legacy refused, warned, unscored, critical_unscored at dashboard/views.go:1315; normalize only at that read boundary. | A |
| E52 | JudgeProvider: clef-sglang, typesafe. api/policy.go:5 DefaultJudgeProvider and :12 ResolveJudgeConfig. DefaultJudgeModel is a model pin, not another provider enum member. | api/policy.go:119 JudgeConfig.Provider; as/judges.go:24 scopedJudge.provider; as/judge_worker.go:36 worker config Provider. | A |
| E53 | JudgeOutagePolicy: critical-only, open. judge/wire/request.go:92. | api/policy.go:129 JudgeConfig.OutagePolicy. policy/resolve.go:263 accepts critical-only only. | A |
| E54 | DecisionAuthorityKind: human, d6; empty is absent authority. guidance/rank.go:190; store/authority.go:163. | api/turns.go:26 DecisionAuthority.Kind. | A |
| E55 | DecisionQueryKind: binding, reminder. store/guidance.go:47; guidance/snapshot.go:179. | api/turns.go:57 DecisionQuery.Kind; store/guidance.go:135 anonymous snapshot cursor Kind. | A |
| E56 | DecisionStatus: active, superseded. records/service.go:236. | api/turns.go:50 DecisionProjection.Status. | A |
| E57 | TurnStatus: preparing, prepared, running. messaging/delivery.go:84; watchdog/context.go:25; store/launch_prompt.go:235. | api/turns.go:20 TurnSnapshot.Status. This is distinct from TurnEvent.Status, which is PromptStatus. | A |
| E58 | GuidanceClaimStatus: pending, completed. api/guidance_claim.go:55. | api/turns.go:109 GuidanceReservation.Status. | A |
| E59 | ContinuationStatus: waiting, pending, claimed, completed, cancelled. watchdog/journal.go:41. | api/turns.go:168 ContinuationIntent.Status. api/continuation_validation.go:12 accepts only pending/claimed/completed at the operation boundary. | A |
| E60 | JudgeExecutionOutcome: pending, completed. store/judge_execution.go:110. | api/judge_execution.go:19 JudgeExecution.Outcome. | A |
| E61 | LaunchAuthorityKind: ticket, starter, proof, scheduler. store/launch_reservation.go:206; api/launch_validation.go:105; api/loop_turn.go:219. | api/launch_plan.go:17 LaunchAuthority.Kind. | A S |
| E62 | LaunchPlanPhase: reserved, sourced, planned, spec_retained, bound, opened, failed. api/launch_plan.go:185; api/launch_validation.go:351. | api/launch_plan.go:192 LaunchPlanRecord.Phase. | A S R |
| E63 | PlanCleanupKind: withdraw, release, revoke_injection. api/plan_cleanup.go:170. | api/plan_cleanup.go:12 PlanCleanup.Kind, :54 PlanCleanupReceipt.Kind, :70 PlanCleanupBrokerReceipt.Kind. | A S |
| E64 | PlanCleanupState: pending, claimed, completed. store/plan_cleanup.go:471. | api/plan_cleanup.go:81 PlanCleanupStatus.State; store/plan_cleanup.go:39 planCleanupRecord.State. | A |
| E65 | CredentialProjectionState: reserved, held, withdrawing, withdrawn. api/credential_projection.go:148. | api/credential_projection.go:154 CredentialProjectionRecord.State. | A S |
| E66 | CredentialWithdrawReason: refused, revoked, expired, cancelled, release, restart. api/credential_validation.go:348. | api/credential_projection.go:180 CredentialWithdrawalRequest.Reason; admin/credstop.go:14 credentialStop.Reason. admin/credstop.go:17 fenceStopped(reason); admin/credlife_linux.go:404 withdrawProjection(reason). | A S |
| E67 | InjectionOutcome: prepared. api/credential_validation.go:203. | api/runtime.go:151 Injection.Outcome; api/events.go:59 LaunchEvent.InjectionOutcome. This singleton discriminant is deliberately not a credential lease outcome. | A S |
| E68 | SecretMutationOutcome: imported, rotated, revoked. secrets/mutations.go:315. | api/events.go:118 SecretEvent.Outcome is derived from the typed EventKind suffix. | A S |

## Blob class catalog and primitive boundaries

E18 contains these values. The first paragraph is the public upload subset
from cw/schema.go:53; the second is private reference vocabulary from :51.
The diff, check and message spellings are additionally accepted by grants/manifest/values.go:121 and dataworker/review_stubs.go:40
and are absent from that wire catalog; retain this mismatch as a rename issue.

~~~text
task prompt report artifact capture transcript policy manifest
judge_request judge_raw archive record launch_request launch_spec
materialize_input archive_input worker_input channel_input
channel_payload channel_receipt worker_result credential_evidence
usage_input usage_raw usage_window
diff check message
~~~

Every primitive class parameter is listed here. Fields embedding BlobRef
inherit E18 and do not introduce another raw string field.

| Package | Source and function |
|---|---|
| api | launch_validation.go:27 launchBlob(class) |
| approval | validate.go:71 validBlobClass(class) |
| policy | audit.go:24 put(class) |
| grants | sources.go:15 readCommitted(class); root_profiles.go:157 rootProfileRef(class) |
| lifecycle | plan_claim.go:152 retain(stage, class); :164 retainBytes(stage, class) |
| migration | jcs.go:58 ValidBlobClass(c); :67 ValidateBlobRef(expectedClass) |
| rd | launch.go:65 objectBytes(class); capture_binding.go:177 usageObject(class) |
| rc | usage.go:109 usageObject(class) |
| secrets | usage_source.go:156 retainUsage(class) |
| judge | audit.go:128 auditObject(class); judge/wire/adapter.go:234 keep(class); api/judge_execution.go:38 JudgeWorker.EvaluateLeased callback string |
| store | materialization.go:467 retainDataBytes(class); archive.go:491 archiveBytes(class) |
| tf | launch_linux.go:471 Retain(class) |
| watchdog | context.go:229 blobClass(class) |
| cli | commands_migration.go:180 migrationUploadBlob(class); commands_templates.go:437 templatesBlob(class); :563 templatesUpload(class) |


## Private journals, parsers and local selectors

These are separate groups even when their words overlap. In particular,
reserved in a lease journal cannot become reserved in a credential projection
by an unreviewed conversion.

| ID | Proposed type and values, with source | Primitive fields and functions | Overlap |
|---|---|---|---|
| E69 | AttachMode: read, interactive. lifecycle/input.go:119; lifecycle/attach.go:64 defaults empty to read. | api/lifecycle.go:155 AttachRequest.Mode; lifecycle/attach_cursor.go:20 attachCursor.Mode. | A |
| E70 | BriefingMode: lane, overview. templates/approved.go:301. | api/sources.go:76 BriefingInput.Mode. | A |
| E71 | LocalTemplateStatus: absent, present. templates/approved.go:233. | api/sources.go:59 TemplateSources.LocalStatus. | A |
| E72 | ResourceFileKind: prompt, drivers, policy, source, task for source entries; file for derived entries. templates/approved.go:167; templates/org.go:22. config, channel, grants and decision are also classified in store/change_semantics.go:33. | api/sources.go:23 ResourceFile.Kind; templates/approved.go:167 snapshotKind(kind); templates/org.go:22 templateSourceKind returns string. | A |
| E73 | DashboardResourceKind: plugin, script, tool, template, note, config. dashboard/views.go:1460. | api/views.go:66 Resource.Kind; dashboard/views.go:1459 classifyResourceKind returns string. | A |
| E74 | CleanupObjectRole: transient, event, input, capture, report, archive, history, unknown. api/collection.go:213. | api/collection.go:46 CleanupObject.Role. | A |
| E75 | PresenceState: present, absent. api/collection.go:255; api/collection.go:282. | api/collection.go:61 ObjectReadback.State; :76 WorkspaceReadback.WorktreeState and .BranchState; api/collection.go:255 cleanupObjectReadback(state). Keep filesystem presence distinct from process and lane states. | A |
| E76 | ObjectDispositionAction: retain, remove. api/collection.go:236. | api/collection.go:69 ObjectDisposition.Action; api/collection.go:236 cleanupDisposition returns its action as string; store/collection.go:372 cleanupAction has the same two string results. | A |
| E77 | ObjectDispositionReason: unknown, unowned, referenced, event, input, capture, report, archive, history, unreferenced. api/collection.go:234 returns a role for non-transient objects. | api/collection.go:69 ObjectDisposition.Reason; cleanupDisposition's second string result; store/collection.go:372 cleanupAction's second string result. transient is part of the role vocabulary but does not reach that branch; preserve the narrower actual returned subset. | A |
| E78 | WorkspaceRemovalAction: retain_dirty, remove_clean. api/collection.go:286. | api/collection.go:83 WorkspaceRemoval.Action. | A |
| E79 | DeploymentPhase: planned, migrating, activating, complete. migration/apply.go:82; :192; migration/import.go:117. | api/deployment.go:47 DeploymentPlan.Phase. Other coordinator phases are not implemented in this tree. | A |
| E80 | ManifestSchema: laneboss.migration.v2, laneboss.objects.v2, laneboss.adoption.v2, laneboss.quiescence.v2, laneboss.verification.v2. migration/jcs.go:23 declares SchemaMigrationManifest, SchemaObjectManifest, SchemaAdoptionManifest, SchemaQuiescence, SchemaVerification without a named type. | api/manifests.go:14 ObjectManifest.Schema, :54 MigrationManifest.Schema, :64 AdoptionManifest.Schema; migration/readers.go:32 QuiescenceReceipt.Schema and :48 VerificationReceipt.Schema. Other unrelated singleton schema pins are excluded below. | A |
| E81 | CloudProvider: aws, gcp. cw/schema.go:103. | api/ports.go:75 BoxLaunchRequest.Provider and :96 Box.Provider; api/grants.go:190 ResourceGrant.Provider. ProfileGrant.Provider is independently enrolled metadata, not this enum. | A G W |
| E82 | WebAuthnClientType: webauthn.get, webauthn.create. identity/webauthn.go:122; identity/enrollment.go:99. | identity/webauthn.go:123 clientData.Type. | - |
| E83 | SignatureAlgorithm: ES256, RS256, Ed25519, EdDSA. identity/human.go:81; identity/enrollment.go:174. | api/humanstate.go:13 HumanCredential.Algorithm; identity/enrollment.go:156 registrationKey's string result. EdDSA is an accepted historical alias. | A |
| E84 | AttestationFormat: packed, fido-u2f. identity/attestation.go:90. | api/humanstate.go:7 HumanCredential.AttestationFormat; identity/attestation.go:90 format local from the raw attestation map. | A |
| E85 | COSEKeyType (int64): 1 OKP, 2 EC2, 3 RSA. identity/enrollment.go:161. | registrationKey's raw map value kind; no primitive function/struct boundary yet. | - |
| E86 | COSEAlgorithm (int64): -7 ES256, -8 EdDSA, -257 RS256. identity/enrollment.go:162; identity/attestation.go:105. | registrationKey's algorithm local and raw attestation alg local; no primitive argument field outside those parsers. | - |
| E87 | COSECurve (int64): 1 P-256, 6 Ed25519. identity/enrollment.go:174. | COSE map key -1 inside registrationKey; no primitive function or struct boundary yet. | - |
| E88 | CBORMajorType (byte): 0 unsigned, 1 negative, 2 bytes, 3 text, 4 array, 5 map. identity/registration_cbor.go:42. | registrationCBOR.value decodes major as byte; unhandled 6/7 are rejected after the switch. | - |
| E89 | BrokerRecordKind: profile, slot, login, projection, plan_cleanup, usage. sn/broker.go:58. | sn/broker.go:22 brokerRecord.Kind; brokerName(kind), brokerView.Read(kind), brokerView.Write(kind); bs/state.go:137 Journal.Read/Write string selectors; secrets/journal_stage.go:28 stagedJournal.Read and :40 Write. | S |
| E90 | BrokerSlotKind: profile, selection, task, worker. secrets/credential_slots.go:314; :398; :427; secrets/worker_credentials.go:176. | bs/state.go:61 Slot.Kind; secrets/credential_slots.go:14 slotID(kind) and :25 newSlot(kind). | S |
| E91 | HelperMethod: full catalog below, plus unknown diagnostic fallback. admin/helper_journal.go:43; :64; admin/lease.go:470. | admin/wire.go:23 helperRequest.Method; admin/helper_journal.go:20 helperRequestTrace.method; all helper dispatch/call boundaries are indexed below. This is not the public api.Method type. | - |
| E92 | EnrollmentMethod: initial_publish, enroll_begin, enroll_complete. api/enrollment_wire.go:47. | api/enrollment_wire.go:20 AdminEnrollmentFrame.Method; service/enrollment_listener.go:184 and admin/enroll_linux.go:302 dispatch it. | A |
| E93 | CredentialBrokerMethod: source_versions, reserve, transfer, acknowledge, begin_withdrawal, finish_withdrawal, refresh, guard_lock, guard_check. as/credbroker_linux.go:154; admin/credwire_linux.go:369. | Credential component dispatch method string; admin credentialChannel.call(method), as/credbroker_linux.go broker handler's method; guard ownership ends with its live session. | - |
| E94 | CredentialStoreMethod: unlock, names, read, write, refresh_check, refresh_close, refresh_held. as/credcomp_linux.go:188; :201. | as/credcomp_linux.go:146 storage(method) and :92 Call(method) and the credential client call boundary; these operate on the broker's separate native component socket. | - |
| E95 | CredentialIdentityMethod: authorize, check_launch, select_worker. as/credcomp_linux.go:247. | as/credcomp_linux.go:243 Call(method) and the credential client call boundary. | - |
| E96 | CredentialPeerRole: helper, broker. admin/credential_verify_linux.go:23. | admin/credential_verify.go:9 CredentialPeerVerification.Role; admin/credential_verify.go:15 VerifyCredentialNativePeer(role). | - |
| E97 | CredentialComponentSocket: credential-broker.sock, credential-identity.sock, credential-component.sock, component.sock. admin/credwire_linux.go:369; admin/credowner_linux.go:313. | admin/credwire_linux.go:48 credentialChannel.socket; credential-owner publication matches the same fixed basenames. | - |
| E98 | LeasePhase: reserved, active, releasing, released, aborting, aborted. admin/lease.go:158. | admin/lease.go:39 leaseRecord.Phase. | - |
| E99 | GateJournalState: preparing, prepared, opening, opened, ended, aborted. admin/gate.go:385. | admin/gate.go:17 gateJournal.State. | - |
| E100 | GateReconcileState: prepared, opened, ended, aborted, consumed. admin/gate.go:303; :329. | api/bindings.go:217 LaunchReconciliation.GateState. Other native states must be fenced rather than returned as successful reconciliation. | A |
| E101 | DataJobState: reserved, open, registered, preparing, prepared, opening, opened, returning, measured, revoked, collected. admin/data.go:237. | admin/data.go:52 dataJob.State. | - |
| E102 | DataGateState: reserved, preparing, prepared, opening, opened. admin/data.go:309. | admin/data.go:66 dataGate.State, also embedded by archive/channel native workers. | - |
| E103 | NativeWorkerState: reserved, allocated, registered, preparing, prepared, opening, opened, exited. admin/arch_ctl.go:97; admin/channel_journal.go:50. | admin/arch.go:38 archiveWorker.State; admin/channel.go:22 channelNative.State. | - |
| E104 | ArchiveJournalPhase: withdrawing, frozen. admin/arch_ctl.go:65. | admin/arch.go:18 archiveJournal.Phase. | - |
| E105 | StoreArchivePhase: freezing, sealed, verified, failed. store/arch_verify.go:42. | store/archive.go:26 archiveRecord.Phase. | - |
| E106 | DataStagePhase: reserved, sealed, claimed, bound, opened. store/materialization.go:296. | store/materialization.go:21 dataStageRecord.Phase. | - |
| E107 | WorkspacePhase: reserved, budget_refused, repository, imported, linked, published. admin/workspace.go:61. | admin/workspace.go:39 workspaceJournal.Phase. | - |
| E108 | CleanupJournalPhase: decided, retaining_dirty, removing, worktree_removed, complete, retained_unmerged. admin/cleanup.go:45. | admin/cleanup.go:13 cleanupJournal.Phase. | - |
| E109 | NetworkJournalPhase: creating, ready, collecting, collected. admin/network.go:31. | admin/network.go:13 networkJournal.Phase. | - |
| E110 | ProbeReservationPhase: reserved, collected. admin/proof_linux.go:201; :237. | admin/proof_store_linux.go:20 probeReservation.Phase. | - |
| E111 | CaptureNativePhase: preparing, registered. admin/capture_io_linux.go:274; :372. | admin/launch_capture.go:30 captureNativeJournal.Phase. | - |
| E112 | CredentialNativeState: receiving, held, withdrawing, withdrawn. admin/credentials.go:306; :360. | admin/credentials.go:29 credentialJournal.State. This differs from CredentialProjectionState's reserved initial state. | - |
| E113 | FixedBootstrapMode: prepared-gate, capture-spool. admin/bootstrap_linux.go:95; admin/capture_io_linux.go:342. | admin/gate_linux.go:46 gatePayload.Mode; admin/bootstrap_linux.go:46 runFixedBootstrap(mode), :50 executeFixedBootstrap(mode); admin/gate_args_linux.go:14 nativeGateArgs(mode); admin/platform_other.go:19 stub's last string parameter. | - |
| E114 | IsolationBootstrapMode: options, run, probe. il/bootstrap_linux.go:167. | il/layout_linux.go:61 launchPayload.Mode. Do not reuse FixedBootstrapMode. | - |
| E115 | ProjectionKind: full catalog below. store/atomic_support.go:156; store/transaction.go:632. | store/list.go:28 cursor.Kind; store/guidance.go:135 snapshot cursor Kind is DecisionQueryKind instead. Primitive projection selectors are indexed below. | - |
| E116 | StateWriteField: full StateWrites field catalog below. store/atomic_support.go:218. | projectionWrites(name), identityWrites(kind), uploadWrites(kind) receive reflected field names as strings. Reflection remains an external decoding boundary. | A |
| E117 | CompatibilityKind: file-login, structured-errors, supervisor-3, supervisor-4, supervisor-5, supervisor-6. rc/runner.go:167; :192; rc/capture.go:414. | rc/validate.go:305 compatibilityProof.Kind; :318 compatibility(kind); :323 loadCompatibility(kind). | - |
| E118 | ClaudockFindingKind: unreadable-or-bounded, unreadable, link, hardlink, special. rd/home.go:323. | rd/home.go:29 Finding.Kind. | R |
| E119 | CodexFindingKind: unreadable, symlink, special, hardlink, unexpected-runtime-entry, directory, file. rc/home.go:286; :313. | rc/home.go:218 Observation.Kind. | - |
| E120 | CodexAuthMode: chatgpt; empty is accepted legacy subscription syntax. rc/credential.go:88; :103. | rc/credential.go:88 auth document Mode; as/profiles_partial.go:129 fixture auth document Mode. API-key modes must be re-inventoried after that lane lands. | - |

## Parser and diagnostic vocabularies

These are closed discriminants or validated labels, rather than the free
explanatory Message, Reason and Instead text fields.

| ID | Proposed type and values, with source | Primitive fields and functions | Overlap |
|---|---|---|---|
| E121 | JSONShapeReason: empty, frame_limit, utf8, surrogate, duplicate, depth, syntax, trailing, nonfinite, encoding, null, type, missing, unknown, length, base64, range, unsupported, bounds. api/json_diagnostic.go:138. | api/json_diagnostic.go:14 jsonShapeProblem.reason; :45 shapeProblem(reason); :119 JSONFailureFacts's second result. | A |
| E122 | ErrorComponentKind: full catalog below. api/error_component.go:12; :34. | api/base.go:57 Error.component; api/error_component.go:7 WithErrorComponent(component); :26 ErrorComponent returns string. | A |
| E123 | ErrorOwner: lb-v2-service, lb-v2-admin, lb-v2-identity, lb-v2-lifecycle, lb-v2-grants, lb-v2-secrets, lb-v2-policy, lb-v2-guidance, lb-v2-judge, lb-v2-templates, lb-v2-approval, lb-v2-dashboard, lb-v2-integrate, lb-v2-migration, lb-v2-packaging, lb-v2-linux, lb-v2-darwin, lb-v2-codex, lb-v2-claudock, lb-v2-client, lb-v2-messaging, lb-v2-serve, lb-v2-store, lb-v2-watchdog. api/methods.go:15; api/error_component.go:34. | api/base.go:63 Error.Owner; api/methods.go:12 MethodSpec.Owner; api/base.go:71 NotImplemented(owner); api/dependencies.go:7 RequireDependencies(owner); cli/cli.go:65 RegisterInputValidator(owner); admin/ipc.go:114 refusalOwner local. | A S G R W |
| E124 | HelperReason: complete allowlist below. api/helper_reason.go:38. | api/helper_reason.go:13 WithHelperReasonObserver callback string, :17 ObserveHelperReason(reason), :38 ValidHelperReason(reason), :74 helperReasonError.reason, :89 WithHelperReason(reason), :96 HelperReason result. admin/helper_journal.go:21 helperRequestTrace.check; :52 helperCheck(reason), :56 helperContextCheck(reason); admin/wire.go:33 helperResponse.Reason; service/effect_journal.go:25 effectAttempt.helperReasons values and :28 observeHelperReason(reason). | A S R W |
| E125 | EnrollmentFailureField: complete allowlist below. api/enrollment_wire.go:72. | api/enrollment_wire.go:30 AdminEnrollmentReply.FailureField, :59 adminEnrollmentFailure.field; :68 AdminEnrollmentFailure(field), :83 AdminEnrollmentFailedField result. | A |
| E126 | ConnectionStage: connection, peer_credentials, frame, deadline, authentication, admission, response_write. service/authentication.go:97. | service/authentication.go:86 connectionRefusal(stage), :96 journalConnection(stage); its journal Stage string. | - |
| E127 | InitialPublishStage: native_context, protected_read, load_validate, bundle_validate, object_hashes, policy_validate, template_validate, revalidate, plan, seal, commit, read_object, read_back, total. service/initial.go:53. | service/initial.go:52 journalInitialStage(stage); admin/initial_timing.go:19 WithInitialTiming observer string and :23 initialStage(stage); their journal Stage strings. | - |
| E128 | ClientTransportStage: binding, artifact, credentials, dial, server_identity, deadline, request_write, response_read, connection. client/client.go:417. | client/client.go:411 transportAt(stage). | - |
| E129 | EffectKind: PlanLaunch, Launch, Stop, Deliver, HelperAllocate, HelperPrepare, HelperRelease, HelperAbort, Worker, Channel, Clean, Swap, ApplyChange, Migration, Upgrade, Rebuild, Bootstrap, Unknown. service/effect_journal.go:165. | service/effect_journal.go:19 effectAttempt.kind; :84 diagnostic Kind; :164 effectKind result; api/write_catalog.go:15 publicWrites.effects serializes the real variants without diagnostic Unknown. | - |
| E130 | EffectAttemptOutcome: started, fault, deferred, held, completed, failed. service/effect_journal.go:101; :108; :136; service/reconcile_attempt.go:24. | service/effect_journal.go:20 effectAttempt.outcome; :85 diagnostic Outcome; :77 write(outcome), :81 writeTo(outcome). reason is a composition of stage, ErrorCode, ErrorComponent and HelperReason, not one enum to flatten. | - |
| E131 | BootstrapStage: the full bootstrapStageCodes keys below, plus bwrap_setup, go_runtime_or_init, loader_or_exec, other. admin/bootstrap_entry.go:9. | admin/readiness_linux.go:92 bootstrapErrorReason result, :103 bootstrapPacketReason result, and admin/bootstrap_entry.go:44 bootstrapExitStage's result; producer and stderr classification stages must stay distinct. | - |
| E132 | BootstrapExitCode (int): all numeric values of bootstrapStageCodes below; 1 bwrap setup, 2 Go runtime, 126/127 loader. admin/bootstrap_entry.go:7; :44. | bootstrapExitStage(code). Ordinary vendor exit codes are not members of this internal mapping. | - |
| E133 | BwrapFailureKind: none, unavailable, namespace_denied, namespace_setup_failed, option_unsupported, userns_policy_failed, mount_source_unavailable, bind_mount_failed, destination_create_failed, mount_propagation_failed, root_switch_failed, cwd_failed, capability_setup_failed, parent_death_setup_failed, no_new_privileges_failed, child_sync_failed, seccomp_setup_failed, process_create_failed, allocation_failed, runtime_thread_failed, runtime_memory_failed, descriptor_or_path_unavailable, mount_failed, exec_failed, identity_map_failed, other. admin/bootstrap_err_linux.go:93. | bootstrapStderr.fact and classifyBwrapStderr return string; admin/bootstrap_mount_linux.go:50 category local receives it. | - |
| E134 | SeccompMode (int): 0 none, 1 strict, 2 filter. admin/spawn_facts_linux.go:46. | admin/spawn_facts_linux.go:41 nativeThreadMode(value) when seccomp is true. | - |
| E135 | NoNewPrivilegesMode (int): 0 off, 1 on. admin/spawn_facts_linux.go:55. | nativeThreadMode(value) when seccomp is false; the current boolean selector conflates two integer domains. | - |
| E136 | NativeFactState: present, absent, none, strict, filter, off, on, unrecognized, empty, nonempty, openable; errors are unavailable(errno). admin/spawn_facts_linux.go:28; :41; :93; :131. | nativeCapabilityBit, nativeThreadMode, nativeCgroupValue, nativeCgroupWriteOpen and admin/process_caps_linux.go:88 processCapabilityFacts return string. Prefer typed result variants plus formatting rather than an enum containing formatted error strings. | - |
| E137 | CgroupDomain: domain, threaded, domain threaded, domain invalid. admin/spawn_facts_linux.go:98. | nativeCgroupValue(value) when domain is true. The other branch consumes arbitrary control-file contents, not this enum. | - |
| E138 | RuntimeOS: linux, darwin. rc/validate.go:304; rc/validate.go:334; platform build tags. | api/ports.go:138 ReleaseArtifact.OS; rc/validate.go:304 compatibilityProof.Platform. Release metadata is broader in principle; reject unsupported platforms at an explicit boundary. | A |
| E139 | RuntimeArch: amd64, arm64. il/seccomp_linux.go:14; admin/bootstrap_linux.go:321. | api/ports.go:139 ReleaseArtifact.Arch; api/manifests.go:38 BoxSpec.Architecture. runtime.GOARCH is the external string boundary. | A |
| E140 | LandlockAccessMask (uint64 flags): execute=1<<0, writeFile=1<<1, readFile=1<<2, readDir=1<<3, removeDir=1<<4, removeFile=1<<5, makeChar=1<<6, makeDir=1<<7, makeReg=1<<8, makeSock=1<<9, makeFIFO=1<<10, makeBlock=1<<11, makeSym=1<<12, refer=1<<13, truncate=1<<14, ioctlDev=1<<15. il/rules.go:11. | il/rules.go:49 PathRule.AllowedAccess and :55 Ruleset.HandledAccessFS; BuildRuleset's local allowed mask is uint64. This is a bitmask, so exhaustive switches do not apply. | - |
| E141 | VendorLimitCode: usage_limit_reached, usage_limit_exceeded, UsageLimitExceeded, session_limit_reached, rate_limit_exceeded, rate_limit_error, rate_limit, token_expired, refresh_token_expired, refresh_token_reused, expired_auth_token. watchdog/signals.go:114. | codeSignal(code); raw vendor map error codes feed this string. Unknown codes are intentionally non-evidence. | - |
| E142 | ClaudockRecordKind: assistant, result, rate_limit_event, error, system, user. rd/capture.go:178; rd/capture.go:88; rd/home.go:488. | Vendor map type key in captured/limitEvent; system is inspected for session initialization. Other vendor types are open and ignored, so use a parser result with an unknown variant. | R |
| E143 | CodexRecordKind: thread.started, turn.started, turn.completed, turn.failed, error, item.completed. rc/capture.go:299; :397; watchdog/signals.go:189. | Raw JSON type field read by codexSession and the runner's captured-record consumers; use an unknown parser variant for other vendor records. | - |
| E144 | LegacyStoreRecordKind: decision, owner-word, lane-report, ledger-row, receipt. migration/stub.go:153. | LegacyEventRecord.Payload["kind"] is map data, not a typed field. | - |
| E145 | LegacyTextKind: q_text, d_text. migration/readers.go:1076; :1325. | migration/readers.go:98 LegacyVectorItem.WhichText and :111 LegacyEgressItem.WhichText; import parser which local. | - |
| E146 | TemplateCommandMode: render, start, validate, bootstrap. cli/commands_templates.go:348. | cli/commands_templates.go:335 templatesParseFlags(mode). | - |
| E147 | CLIOutputFormat: json, markdown, text, jsonl. cli/commands_templates.go:343; cli/commands_lifecycle.go:128; cli/commands_policy.go:316. | CLI option format strings, including templatesFlags.format and lifecycle/messaging flag locals. This is independent of watchdog.OutputFormat. | - |
| E148 | CredentialExecStage: vendor_exec. api/credential_env.go:43. | api/credential_env.go:12 CredentialExecEnvironment.Stage is a singleton stage discriminant. | A |

## Remaining contract selectors

| ID | Proposed type and values, with source | Primitive fields and functions | Overlap |
|---|---|---|---|
| E149 | MethodAccess: change-owner, content, control, human-endpoint, human-proof, human-read, judge-preview, l6, owner, parent, public, relation, report-line, resource, reviewer, self, spawn, tree. api/methods.go:15. | api/methods.go:11 MethodSpec.Access; service/server.go:548 reads the human-endpoint subset. | A |
| E150 | NetworkProtocol: tcp. api/launch_validation.go:46. | api/launch_plan.go:89 NetworkEndpoint.Protocol is a singleton transport discriminant; this does not make arbitrary Protocol/schema-version pins one enum. | A |
| E151 | VerifyScope: all. store/verify.go:22. | api/ports.go:58 VerifyRequest.Scope is a singleton scope selector. | A |
| E152 | LaunchStage: briefing, guidance, credential-slot, injection, runner, capture. lifecycle/plan_runner.go:109; :128; :237; :273; :327; lifecycle/plan_capture.go:53. | lifecycle/plan_stage.go:25 retainedLaunchStageFailure.stage; :31 RetainedLaunchStage result; :36 launchStage(name). Other deterministic stage strings used only to derive object IDs are not this enum. | - |
| E153 | ReadSelectorKind: record, change, upgrade, object, grants, org, lane, new_object. store/projection_reads.go:73. | The local kind and selector table at store/projection_reads.go:73; object/new_object are read-pin categories rather than stored ProjectionKind values. | - |
| E154 | CgroupLimitBucket: unavailable, unlimited, below_64MiB, 64_to_255MiB, at_least_256MiB, below_16, 16_to_63, at_least_64. admin/gate_cgroup_linux.go:85. | nativeLimitRange returns string; :147 nativeLimitFact(value) consumes these buckets. | - |
| E155 | CgroupCounterState: unavailable, zero, positive. admin/gate_cgroup_linux.go:114. | nativeCounter.fact returns string. | - |
| E156 | CgroupCounterChange: unavailable, increased, decreased, unchanged. admin/gate_cgroup_linux.go:124. | nativeCounterDelta returns string. | - |
| E157 | LegacyStreamKind: record, model, vector, egress. migration/readers.go:992. | Legacy JSONL typ local chooses the record decoder. | - |
| E158 | LegacyEventKind: archive.completed, archive.verified, brief.rendered, lane.adopted, lane.mailed, lane.refusal, lane.refusal_reviewed, lane.started, lane.workaround_suspected, report.sent, store.record, tool.submitted. migration/stub.go:143; migration/readers.go:718. | migration/readers.go:61 LegacyEventRecord.Kind. These are recognized import cases, not the current api.EventKind catalog; unknown legacy events are inert. | - |
| E159 | RuntimeFixtureMode: state, lifecycle; empty preserves the existing fixture default. as/fixture.go:187. | as/fixture.go:24 fixtureEnrollment.Mode. | - |
| E160 | ClaudockRecordSubtype: init, success, error_during_execution. rd/capture.go:88; :209. | Raw vendor subtype map field; init is valid for system records, and success/error_during_execution for result records. | R |
| E161 | RuntimeObjectRole: serve-fixture-config, serve-fixture-agent, serve-fixture-task, claudock, claude are recognized selectors. as/fixture.go:142; as/real_runtime.go:52; admin/initial_inventory.go:112. | api/bindings.go:246 RuntimeObject.Role remains extensible enrolled metadata. Parse the known selector subset with an explicit unknown result rather than rejecting arbitrary enrolled asset roles. | A |
| E162 | SchemaEnumField: all 48 keys below. cw/schema.go:33. | cw/schema.go:27 enum(object, field, value) currently forms an untyped composite selector from two strings. The enum domains in E01-E161 remain distinct after this routing key is typed. | W |

## Full catalogs

The following are complete value lists for the large groups above, not
examples. They come from the referenced source allowlists and writer/reader
selectors at this revision.

### E91 HelperMethod

abort admin_enrollment allocate allocate_launch archive_bytes archive_check
archive_freeze archive_lease archive_observe archive_open archive_prepare
archive_reconcile archive_register archive_retire capture_drain_ack
capture_drain_read capture_drain_snapshot channel_collect channel_lease
channel_prepare channel_reconcile channel_register cleanup_inspect
cleanup_journal cleanup_read cleanup_remove cleanup_resolve containment
containment_revoke credential_bind credential_binding
credential_gate_observe credential_peer_verify credential_projection_observe
credential_projection_observe_id credential_projection_source
credential_withdrawal_observe data_collect data_gate data_lease data_measure
data_native data_observe data_open data_prepare data_query data_register
data_revoke data_selector isolation_evidence observe_gate open_gate
plan_cleanup_native_read prepare probe reconcile_capture reconcile_gate
register_capture register_spec release resolve_runtime resolve_storage
runner_prompt stop_gate unknown worker_check worker_launch

The helper envelope's Method string is also reused under credentialProtocol
for E93-E95. Split those private envelopes or add a checked protocol-specific
conversion; assigning all credential methods to HelperMethod would retain the
same category error under a different spelling.

| Source | Primitive method boundaries |
|---|---|
| admin/client_linux.go:14 | Service.call(method) |
| admin/lease.go:470 | leaseManager.dispatch(method) |
| admin/arch_fs_linux.go:582 | dispatchArchiveStorage(method) |
| admin/arch_ctl.go:554 | dispatchArchiveWorker(method) |
| admin/capture_drain_linux.go:17 | dispatchCaptureDrain(method) |
| admin/clean_linux.go:525 | dispatchCleanup(method) |
| admin/data_ctl.go:659 | dispatchData(method) |
| admin/channel_recover.go:119 | dispatchChannel(method) |
| admin/worker_launch_linux.go:140 | request(method), :166 call(method), :172 exchange(method) |
| admin/helper_journal.go:27 | journalHelperTurn(operation); :43 helperTimingMethod(method); :64 helperMethod(method), including their string results |
| admin/credential_operation.go:39 | credentialMetadataMethod(method) |
| admin/human_enrollment.go:21 | enrollmentCaller(method); :35 newEnrollmentFrame(method), both E92 |
| admin/credwire_linux.go:277 | credentialChannel.call(method), carrying E93/E95 |
| admin/credential_component_linux.go:102 | CredentialComponentClient.Call(method), carrying E94 |
| as/credbroker_linux.go:146 | credentialBrokerSession.Call(method), E93 |
| as/credcomp_linux.go:92 | credentialComponentSession.Call(method); :146 storage(method), E94 |
| as/credcomp_linux.go:243 | credentialIdentitySession.Call(method), E95 |
| as/credential_remote_linux.go:17 | credentialRemoteCall(method); :164 credentialRemoteStorage.call(method); :176 empty(method), E94/E95 |

### E115 ProjectionKind

~~~text
application approval approval_use archive_job briefing capture_drain
capture_failure capture_receipt capture_state challenge change channel
channel_ack channel_stage collection collection_delete collection_object
continuation continuation_claim credential_projection
credential_projection_id credential_worker_handoff data_ack data_measurement
data_stage decision decision_snapshot delegation_lease dispatch_freeze
dispatch_state endpoint enrollment enrollment_ceremony enrollment_challenge
enrollment_receipt enrollment_validation frame_source frames
grant_transport_close grant_worker_close grants guidance guidance_turn
internal_commit judge_audit judge_execution judge_request_id lane launch
launch_authority launch_binding launch_bytes launch_control launch_name
launch_observation launch_operation launch_plan launch_process
launch_revocation loop_end loop_receipt mail mail_turn_selection
object_inputs org org_apply org_apply_gate org_snapshot owned_failure
plan_cleanup policy policy_history proof proof_use read_session record
reservation_actor reservation_policy secret_head secret_source source
template ticket turn upgrade worker_lease
~~~

These selectors include private durable projections, not just the public
CompareKind subset. The read-pin-only values object and new_object are E153.

| Source | Primitive kind boundaries |
|---|---|
| store/transaction.go:632 | projection(kind); :647 put(kind) |
| store/atomic_support.go:156 | storedProjection(kind); :350 putGenerated(kind) |
| store/projection_reads.go:11 | scopedProjection(kind); :32 identityProjection(kind) |
| store/grant_cascade.go:57 | projectionValues(kind) |
| store/list.go:11 | listProjection(kind); anonymous cursor.Kind at :28 |
| store/collect_refs.go:26 | collectionProjection(kind) |
| tf/launch_linux.go:268 | Replace(kind); :279 Corrupt(kind) |

store/loop_write.go:38 lastLoop(kind) instead accepts EventKind serialized as
string, and must use the existing named api.EventKind rather than ProjectionKind.

### E116 StateWriteField

~~~text
LaunchPlans Grants JudgeAudits Channels WorkerLeases Lanes Endpoints
Decisions Enrollments IdentityBindings Challenges Proofs Counters Tickets
ReadSessions Objects UploadBegins UploadChunks UploadCommits Changes
Approvals Applications OrgSnapshots Turns Guidance Continuations Mail
Deliveries Deployments Policy
~~~

api/write_catalog.go:15 publicWrites.fields is a space-separated representation
of these values. Its effects field similarly serializes the effect variants;
the guards field serializes Proof, Ticket, Approval and Cancellation.
The events field serializes the already named EventKind.

The primitive writer boundaries are store/atomic_support.go:256
projectionWrites(name), store/identity_writes.go:14 identityWrites(kind), and
store/objects.go:353 uploadWrites(kind). These functions use narrower subsets
of StateWriteField; narrow at dispatch rather than pretending they handle all
30 members.

### E122 ErrorComponentKind

~~~text
store_scope store_read_view store_read_connection store_object_view
store_object store_projection store_lane store_launch store_launch_plan
store_worker store_materialization store_grants store_policy store_source
store_template store_guidance lifecycle_authorize service_authorize
templates_scope secrets_scope secrets_worker dependency integrate
isolation_linux isolation_darwin service grants secrets templates admin
identity guidance runner
~~~

The exported function ErrorComponent already occupies that identifier in api;
the proposed type therefore has the Kind suffix.

### E124 HelperReason

~~~text
plan_entry plan_claim plan_record plan_original plan_sources plan_allocation
plan_materialize plan_runner plan_capture plan_validate plan_verify
plan_seal plan_recovery pv_reservation pv_inputs pv_lease pv_storage
pv_material pv_receipt pv_runner pv_loop pv_credentials pv_capture
pv_cap_policy pv_cap_rule pv_cap_binding plan_slot_mode plan_retain
plan_events plan_publish effect_claim effect_support plan_policy agent_stage
cred_bind agent_record agent_prepare agent_bind agent_child_done
agent_bound_child agent_binding agent_binding_plan agent_recover agent_open
agent_observe agent_measure agent_publish agent_input agent_endpoint
agent_bind_tx agent_bind_read agent_open_tx linux_spec linux_handoff
linux_original linux_plan linux_register linux_runtime linux_prepare_cause
linux_prepare linux_prepared_tuple plan_profile plan_prompt
plan_credential_slot plan_injection plan_runner_call transport_window
caller_identity caller_lifetime caller_containment caller_privileges
caller_executable planning_dispatch planning_wait materialization_context
materialization_parent materialization_claim materialization_inputs
materialization_grants materialization_sources materialization_owner
materialization_storage materialization_allocation materialization_seal
materialization_handoff materialization_endpoint materialization_register
materialization_prepare materialization_bind materialization_open
materialization_process materialization_result materialization_receipt
materialization_deadline materialization_child_claim
materialization_exit_status materialization_exit_code materialization_signal
materialization_survivors materialization_wait request_frame request_decode
request_binding caller_role installation cancellation operation_input
operation peer_lifetime response_encode reply_transport connection_close
call_context call_identity call_binding call_socket call_peer call_encode
call_write reply_decode reply_binding reply_result launch_authority
launch_sources launch_allocation lease_allocation lease_activation
lease_records lease_save lease_read lease_write lease_duplicate
lease_recovery_transition lease_recovery_owner lease_recovery_identity
lease_archive lease_capture_drain lease_cleanup lease_credentials
lease_projection_alias lease_network lease_gate lease_launch lease_identity
lease_phase lease_abort_state lease_abort_receipt lease_allocation_history
lease_spec_state lease_spec lease_release_state lease_receipt_state
lease_release lease_receipt lease_data_identity lease_data_job
lease_capture_identity lease_data_registration lease_data_lease
lease_data_parent lease_data_state lease_data_evidence lease_data_allocation
lease_data_storage lease_data_seal lease_data_stage lease_data_result
lease_data_collection lease_data_gate allocation_enrollment uid_scan
uid_inventory uid_threads uid_status uid_shape uid_survivor cgroup_open
cgroup_read cgroup_write cgroup_population cgroup_limits
capture_registration capture_boot capture_phase capture_storage_missing
capture_storage_unready capture_supervisor capture_uid capture_cgroup
capture_runtime capture_spool capture_gate capture_publish
capture_retained_failure prompt_input bootstrap_lifetime gate_observation
active_lease storage_root storage_parent storage_directory storage_inode
storage_mappings spec_registration gate_prepare runtime_enrollment
data_retry
~~~

There are 207 members. Unknown strings are currently discarded by
ValidHelperReason; the named type does not remove validation of decoded input.
The complete allowlist switch has no default and falls through to false.

### E125 EnrollmentFailureField

~~~text
admin_enrollment protocol contract_revision config generation
artifact_sha256 nonce method params frame connection deadline
peer_credentials peer_uid peer_lifetime helper_executable helper_artifact
helper_unit helper_socket socket scope enroll_begin enroll_complete
initial_publish response response_write journal enrollment
~~~

Empty means there was no failure. The enrollment spelling is the explicit
fallback for an unknown diagnostic label.

### E131 BootstrapStage and E132 BootstrapExitCode

| Stage | Code |
|---|---|
| prompt.reference | 139 |
| prompt.seals | 140 |
| prompt.read | 141 |
| prompt.measure | 142 |
| prompt.digest | 143 |
| descriptors.inventory | 144 |
| descriptors.missing | 145 |
| descriptors.socket | 146 |
| descriptors.seals | 147 |
| descriptors.projection | 148 |
| descriptors.retain | 149 |
| exec_proof.create | 150 |
| exec_proof.transfer | 151 |
| limit.nofile_read | 152 |
| limit.nofile_set | 153 |
| limit.nofile_readback | 154 |
| entry.route | 80 |
| entry.arguments | 81 |
| entry.config | 82 |
| entry.context | 83 |
| input.decode | 84 |
| entry.route_close | 85 |
| unclassified | 99 |
| input.seals | 100 |
| input.read | 101 |
| identity | 102 |
| groups | 103 |
| control.peer | 104 |
| release.pipe | 105 |
| capabilities.read | 106 |
| capabilities.retained | 107 |
| capabilities.absent | 108 |
| input.executable | 109 |
| input.argument | 110 |
| cwd | 111 |
| readiness.write | 112 |
| dumpable | 113 |
| no_new_privileges | 114 |
| limit.cpu | 115 |
| limit.core | 116 |
| landlock.abi | 117 |
| landlock.create | 118 |
| landlock.path | 119 |
| landlock.open | 120 |
| landlock.type | 121 |
| landlock.rule | 122 |
| landlock.restrict | 123 |
| seccomp.architecture | 124 |
| seccomp.install | 125 |
| descriptors.cloexec | 136 |
| release.token | 137 |
| release.eof | 138 |
| readiness.close | 129 |
| vendor.exec | 130 |
| capture.input | 131 |
| capture.pipe | 132 |
| capture.file | 133 |
| capture.cloexec | 134 |
| capture.readiness | 135 |

The classification-only results bwrap_setup, go_runtime_or_init, loader_or_exec
and other are returned for 1, 2, 126/127 and unrecognized exits respectively.
The map has 59 entries. These are internal bootstrap-stage codes,
not a restriction on ordinary child process exit values.

### E162 SchemaEnumField

~~~text
Actor.kind Event.origin Record.origin Operation.status Lane.state
StateEvent.from StateEvent.to MarkRequest.state ProcessObservation.state
ProcessObservation.prompt_status MailReceipt.prompt_status TurnEvent.status
RunEndEvent.reason BlobRef.class BlobBeginRequest.class Record.collection
RecordQuery.collection RecordAppendRequest.collection
TransferRequest.collection RecordQuery.search_mode
DecisionMutateRequest.action Mail.status MailReceipt.status Mail.source
ResourceDelta.action JudgeRequest.purpose JudgeReply.status Judgment.status
NetworkGrant.mode DataGrant.access DataGrantRequest.access
DataGrant.delivery DataGrantRequest.delivery SecretGrant.delivery
SecretDelegation.delivery ObjectEntry.kind CaptureRecord.stream
CaptureGap.stream CaptureRecord.coverage ReviewReceipt.coverage
ConfigReadRequest.view Trigger.kind CredentialSlot.mode LaunchSpec.backend
LaunchEvent.boundary_backend WorkerPlan.kind Box.provider
BoxLaunchRequest.provider
~~~

## Two shared catalog boundaries

| ID | Proposed type and values, with source | Primitive fields and functions | Overlap |
|---|---|---|---|
| E163 | TransactionGuardKind: Proof, Ticket, Approval, Cancellation. api/write_catalog.go:15; api/transactions.go:142. | publicWrites.guards is a space-separated string catalog; the guard validator derives name from each nonnil reflected field. Use a typed collection of these names. | A |
| E164 | DashboardNodeState: configured, preparing, running, stopping, verifying, idle, profile_wait, lost, accepted, merged, abandoned. dashboard/views.go:434; :472. | api/views.go:20 TreeNode.State. This display union adds configured to LaneState; adapt explicitly from a lane so the new display state cannot enter a launch reservation. | A |


## Additional result classifiers

These groups finish the primitive result boundaries. Formatted diagnostics
remain separate from the typed classification and its optional detail.

| ID | Proposed type and values, with source | Primitive fields and functions | Overlap |
|---|---|---|---|
| E165 | BwrapMountOperation: proc, tmpfs, dev, mqueue, remount, other, bind. admin/bootstrap_mount_linux.go:77. | bwrapMountOperation returns string; the input message is open OS text, not this enum. | - |
| E166 | NativeErrnoName: EACCES, EAGAIN, EBADF, EBUSY, EFAULT, EINVAL, EIO, ELOOP, EMFILE, ENFILE, ENODEV, ENOENT, ENOEXEC, ENOMEM, ENOSPC, ENOSYS, ENOTDIR, EOPNOTSUPP, EPERM, EROFS, other. admin/bootstrap_mount_linux.go:125; admin/native_spawn_linux.go:49. | bwrapErrnoName(text) and nativeSpawnErrno(err) return string. unix.Errno remains the existing named numeric boundary; the two display mappings support different subsets. | - |
| E167 | PrimaryProcessFact: waited, unavailable, live, exited. admin/gate_failure_linux.go:15. | nativeGate.primaryFactLocked returns string. These are diagnostic observations, not ProcessObservation.State values. | - |
| E168 | WorkerStderrClass: none, cli_configuration_required, worker_error_unclassified, runtime_thread_limit, runtime_thread_denied, runtime_thread_failed, runtime_failure, panic; worker_ followed by a recognized ErrorCode; otherwise an E133 BwrapFailureKind. admin/worker_exit_linux.go:54. | classifyWorkerStderr returns string. Model this as a tag plus optional ErrorCode or nested bwrap class so formatting cannot merge the domains. | - |
| E169 | SpawnLifetimeFact: unavailable, released, missing, locked_present. admin/spawn_lifetime_linux.go:74. | nativeSpawnLifetime.fact returns string. | - |
| E170 | JudgeReplyProblem: unscored_or_invalid_reply, invalid_probability_mapping, incomplete_probability_mapping; empty means no problem. policy/evaluate.go:530. | invalidReply returns string before the caller renders RuleDecision.Reason text. | - |
| E171 | JudgeFailureReason: invalid_request, unauthenticated, forbidden, not_found, conflict, idempotency_conflict, version_mismatch, unavailable, prerequisite_missing, unsupported, integrity, budget_exhausted, unscored, cursor_expired, containment_unknown, cancelled, deadline_exceeded, judge_unavailable. policy/evaluate.go:628. | errorReason returns string. Reuse ErrorCode through a checked conversion for the typed-error branch; the fallback is a separate reason. | - |
| E172 | CredentialReceiveClass: empty, deadline, closed, reset, pipe, badf, other, or errno with the OS errno name. admin/credwire_linux.go:569. | recvClass returns string. Nonempty labels currently include a leading space; preserve those bytes in formatting, and keep the errno value as a separate typed member. | - |
| E173 | JudgeQuestionType: noul. judge/wire/request.go:209. | judge/wire/request.go:127 question.Type is a fixed provider schema discriminant rather than JudgePurpose. | - |
| E174 | LinuxBoundaryCheck: bwrap_options, namespace_boundary, seccomp_deny_filter, uid_pool, cgroup_containment, controlled_egress, runtime_projection, capture_pipes, launch_gate. il/service.go:497. | installedBoundary(name) takes string. api/common.go:99 Capability.Name is the enclosing open capability label field; convert this platform-specific subset explicitly. | A |

E174's switch at il/service.go:498 has no default and names all nine members;
its fallback is false. E165 and E166 switch over raw OS message text rather
than over their returned classification. E168 switches over the already named
ErrorCode, and E172 uses error predicates. Their formatted inputs are not
additional missing enum members.


## Switch coverage before the rename

The table lists every identified switch over an inventoried domain that lacks
a default or omits a current member from its explicit case clauses. It includes
intentional subset dispatch, rejection defaults and the full switches without
defaults. Missing here means not explicitly named in a case, not that the
default or a preceding guard necessarily behaves incorrectly. No runtime
failure is inferred from this static inventory.

Each Missing cell is the complete difference from the domain's values above.
E11 includes its documented internal not_started sentinel for this comparison.
The legacy-only E51 aliases remain raw at the dashboard read boundary.
A default must not be treated as proof of exhaustiveness in the analyzer.
The additional short directory alias dw means dataworker.

| Domain | Source | Default | Missing explicit cases |
|---|---|---|---|
| E02 | rd/validation.go:127 | yes | codex-file, codex-api, codex-local |
| E03 | admin/launch_authority.go:264 | yes | continue |
| E03 | api/launch_profile.go:14 | yes | resume, turn, continue |
| E03 | as/run_check.go:237 | no | continue |
| E03 | grants/launch.go:52 | yes | resume, turn, continue |
| E03 | lifecycle/plan_input.go:80 | no | continue |
| E03 | lifecycle/plan_runner.go:328 | yes | adopt, resume, continue |
| E03 | rd/launch.go:256 | no | start, adopt |
| E03 | rc/launch.go:291 | no | start, adopt, continue |
| E03 | secrets/launch_binding.go:196 | no | continue |
| E03 | store/launch_prompt.go:52 | yes | continue |
| E03 | store/launch_prompt.go:166 | yes | continue |
| E06 | dashboard/views.go:952 | yes | scheduler, watchdog, worker |
| E06 | guidance/authority.go:29 | yes | service, scheduler, watchdog, worker |
| E06 | policy/service.go:98 | yes | service, scheduler, watchdog, worker |
| E06 | store/launch_reservation.go:377 | yes | service, scheduler, watchdog, worker |
| E06 | store/transaction.go:539 | no | none |
| E08 | dashboard/views.go:33 | yes | verifying, lost, accepted, merged, abandoned |
| E08 | grants/launch_authority.go:55 | yes | preparing, running, stopping, verifying, idle, profile_wait, lost |
| E08 | messaging/routing.go:252 | yes | merged, abandoned |
| E08 | store/delegation_lease.go:228 | yes | preparing, running, stopping, lost |
| E08 | store/loop_chain.go:23 | yes | lost, accepted, merged, abandoned |
| E08 | watchdog/context.go:220 | no | preparing, running, verifying, idle, profile_wait, lost |
| E08 | watchdog/evidence.go:293 | yes | preparing, idle, lost |
| E09 | cli/commands_templates.go:301 | yes | failed, cancelled |
| E09 | messaging/queue.go:159 | yes | failed, cancelled |
| E09 | watchdog/journal.go:243 | no | none |
| E11 | lifecycle/control.go:149 | yes | not_started |
| E11 | messaging/receipts.go:53 | yes | not_started |
| E12 | il/control.go:199 | no | none |
| E18 | approval/validate.go:72 | yes | launch_request, launch_spec, materialize_input, archive_input, worker_input, channel_input, channel_payload, channel_receipt, worker_result, credential_evidence, usage_input, usage_raw, usage_window, diff, check, message |
| E18 | grants/manifest/values.go:118 | yes | worker_input, credential_evidence, usage_input, usage_raw, usage_window |
| E18 | migration/jcs.go:59 | no | launch_request, launch_spec, materialize_input, archive_input, worker_input, channel_input, channel_payload, channel_receipt, worker_result, credential_evidence, usage_input, usage_raw, usage_window, diff, check, message |
| E18 | store/collect_graph.go:264 | no | worker_input, channel_input, channel_payload, channel_receipt, credential_evidence, usage_input, usage_raw, usage_window, diff, check, message |
| E18 | templates/service_inputs.go:76 | yes | launch_request, launch_spec, materialize_input, archive_input, worker_input, channel_input, channel_payload, channel_receipt, worker_result, credential_evidence, usage_input, usage_raw, usage_window, diff, check, message |
| E18 | watchdog/context.go:230 | no | launch_request, launch_spec, materialize_input, archive_input, worker_input, channel_input, channel_payload, channel_receipt, worker_result, credential_evidence, usage_input, diff, check, message |
| E21 | store/loop_write.go:27 | no | owner, config, service, private |
| E22 | admin/tree_linux.go:206 | yes | symlink |
| E22 | archive/stream.go:53 | no | none |
| E25 | dw/channel_worker.go:101 | no | none |
| E30 | migration/legacy_inputs.go:61 | no | none |
| E30 | rd/validation.go:132 | yes | minimal, xhigh, ultra |
| E32 | api/worker_identity.go:53 | no | capture |
| E32 | identity/worker_bind.go:178 | yes | test, import, export, render, box_run, channel, usage, owner_sheet, gateway, capture |
| E32 | il/validate.go:289 | no | none |
| E32 | secrets/contract_stubs.go:95 | yes | materialize, capture |
| E33 | records/service.go:582 | no | none |
| E51 | dashboard/views.go:1315 | no | allow |
| E59 | api/continuation_validation.go:12 | yes | waiting, cancelled |
| E59 | store/watchdog_journal.go:36 | yes | claimed, completed, cancelled |
| E62 | api/launch_validation.go:351 | no | none |
| E72 | store/change_semantics.go:33 | no | prompt, drivers, source, task, file |
| E72 | templates/approved.go:171 | no | file, config, channel, grants, decision |
| E72 | templates/initial.go:34 | no | policy, source, task, file, config, channel, grants, decision |
| E91 | admin/arch_ctl.go:573 | no | abort, admin_enrollment, allocate, allocate_launch, archive_bytes, archive_check, archive_freeze, archive_open, archive_register, archive_retire, capture_drain_ack, capture_drain_read, capture_drain_snapshot, channel_collect, channel_lease, channel_prepare, channel_reconcile, channel_register, cleanup_inspect, cleanup_journal, cleanup_read, cleanup_remove, cleanup_resolve, containment, containment_revoke, credential_bind, credential_binding, credential_gate_observe, credential_peer_verify, credential_projection_observe, credential_projection_observe_id, credential_projection_source, credential_withdrawal_observe, data_collect, data_gate, data_lease, data_measure, data_native, data_observe, data_open, data_prepare, data_query, data_register, data_revoke, data_selector, isolation_evidence, observe_gate, open_gate, plan_cleanup_native_read, prepare, probe, reconcile_capture, reconcile_gate, register_capture, register_spec, release, resolve_runtime, resolve_storage, runner_prompt, stop_gate, unknown, worker_check, worker_launch |
| E91 | admin/arch_fs_linux.go:587 | no | abort, admin_enrollment, allocate, allocate_launch, archive_lease, archive_observe, archive_open, archive_prepare, archive_reconcile, archive_register, archive_retire, capture_drain_ack, capture_drain_read, capture_drain_snapshot, channel_collect, channel_lease, channel_prepare, channel_reconcile, channel_register, cleanup_inspect, cleanup_journal, cleanup_read, cleanup_remove, cleanup_resolve, containment, containment_revoke, credential_bind, credential_binding, credential_gate_observe, credential_peer_verify, credential_projection_observe, credential_projection_observe_id, credential_projection_source, credential_withdrawal_observe, data_collect, data_gate, data_lease, data_measure, data_native, data_observe, data_open, data_prepare, data_query, data_register, data_revoke, data_selector, isolation_evidence, observe_gate, open_gate, plan_cleanup_native_read, prepare, probe, reconcile_capture, reconcile_gate, register_capture, register_spec, release, resolve_runtime, resolve_storage, runner_prompt, stop_gate, unknown, worker_check, worker_launch |
| E91 | admin/capture_drain_linux.go:51 | no | abort, admin_enrollment, allocate, allocate_launch, archive_bytes, archive_check, archive_freeze, archive_lease, archive_observe, archive_open, archive_prepare, archive_reconcile, archive_register, archive_retire, capture_drain_snapshot, channel_collect, channel_lease, channel_prepare, channel_reconcile, channel_register, cleanup_inspect, cleanup_journal, cleanup_read, cleanup_remove, cleanup_resolve, containment, containment_revoke, credential_bind, credential_binding, credential_gate_observe, credential_peer_verify, credential_projection_observe, credential_projection_observe_id, credential_projection_source, credential_withdrawal_observe, data_collect, data_gate, data_lease, data_measure, data_native, data_observe, data_open, data_prepare, data_query, data_register, data_revoke, data_selector, isolation_evidence, observe_gate, open_gate, plan_cleanup_native_read, prepare, probe, reconcile_capture, reconcile_gate, register_capture, register_spec, release, resolve_runtime, resolve_storage, runner_prompt, stop_gate, unknown, worker_check, worker_launch |
| E91 | admin/channel_recover.go:131 | no | abort, admin_enrollment, allocate, allocate_launch, archive_bytes, archive_check, archive_freeze, archive_lease, archive_observe, archive_open, archive_prepare, archive_reconcile, archive_register, archive_retire, capture_drain_ack, capture_drain_read, capture_drain_snapshot, channel_register, cleanup_inspect, cleanup_journal, cleanup_read, cleanup_remove, cleanup_resolve, containment, containment_revoke, credential_bind, credential_binding, credential_gate_observe, credential_peer_verify, credential_projection_observe, credential_projection_observe_id, credential_projection_source, credential_withdrawal_observe, data_collect, data_gate, data_lease, data_measure, data_native, data_observe, data_open, data_prepare, data_query, data_register, data_revoke, data_selector, isolation_evidence, observe_gate, open_gate, plan_cleanup_native_read, prepare, probe, reconcile_capture, reconcile_gate, register_capture, register_spec, release, resolve_runtime, resolve_storage, runner_prompt, stop_gate, unknown, worker_check, worker_launch |
| E91 | admin/data_ctl.go:660 | yes | abort, admin_enrollment, allocate, allocate_launch, archive_bytes, archive_check, archive_freeze, archive_lease, archive_observe, archive_open, archive_prepare, archive_reconcile, archive_register, archive_retire, capture_drain_ack, capture_drain_read, capture_drain_snapshot, channel_collect, channel_lease, channel_prepare, channel_reconcile, channel_register, cleanup_inspect, cleanup_journal, cleanup_read, cleanup_remove, cleanup_resolve, containment, containment_revoke, credential_bind, credential_binding, credential_gate_observe, credential_peer_verify, credential_projection_observe, credential_projection_observe_id, credential_projection_source, credential_withdrawal_observe, data_lease, data_observe, data_open, data_prepare, isolation_evidence, observe_gate, open_gate, plan_cleanup_native_read, prepare, probe, reconcile_capture, reconcile_gate, register_capture, register_spec, release, resolve_runtime, resolve_storage, runner_prompt, stop_gate, unknown, worker_check, worker_launch |
| E91 | admin/data_ctl.go:741 | no | abort, admin_enrollment, allocate, allocate_launch, archive_bytes, archive_check, archive_freeze, archive_lease, archive_observe, archive_open, archive_prepare, archive_reconcile, archive_register, archive_retire, capture_drain_ack, capture_drain_read, capture_drain_snapshot, channel_collect, channel_lease, channel_prepare, channel_reconcile, channel_register, cleanup_inspect, cleanup_journal, cleanup_read, cleanup_remove, cleanup_resolve, containment, containment_revoke, credential_bind, credential_binding, credential_gate_observe, credential_peer_verify, credential_projection_observe, credential_projection_observe_id, credential_projection_source, credential_withdrawal_observe, data_collect, data_gate, data_measure, data_native, data_query, data_register, data_revoke, data_selector, isolation_evidence, observe_gate, open_gate, plan_cleanup_native_read, prepare, probe, reconcile_capture, reconcile_gate, register_capture, register_spec, release, resolve_runtime, resolve_storage, runner_prompt, stop_gate, unknown, worker_check, worker_launch |
| E91 | admin/helper_journal.go:44 | no | abort, admin_enrollment, allocate, allocate_launch, archive_bytes, archive_check, archive_freeze, archive_lease, archive_observe, archive_open, archive_prepare, archive_reconcile, archive_register, archive_retire, capture_drain_ack, capture_drain_read, capture_drain_snapshot, channel_collect, channel_lease, channel_prepare, channel_reconcile, channel_register, cleanup_inspect, cleanup_journal, cleanup_read, cleanup_remove, cleanup_resolve, containment, containment_revoke, credential_bind, credential_binding, credential_withdrawal_observe, data_collect, data_gate, data_lease, data_measure, data_native, data_observe, data_open, data_prepare, data_query, data_register, data_revoke, data_selector, isolation_evidence, observe_gate, open_gate, plan_cleanup_native_read, prepare, probe, reconcile_capture, reconcile_gate, register_capture, register_spec, release, resolve_runtime, resolve_storage, runner_prompt, stop_gate, unknown, worker_check, worker_launch |
| E91 | admin/helper_journal.go:65 | no | capture_drain_ack, capture_drain_read, capture_drain_snapshot, credential_gate_observe, credential_peer_verify, credential_projection_observe, credential_projection_observe_id, credential_projection_source, unknown, worker_check |
| E91 | admin/helper_journal.go:81 | yes | abort, admin_enrollment, allocate, allocate_launch, archive_bytes, archive_check, archive_freeze, archive_lease, archive_observe, archive_open, archive_prepare, archive_reconcile, archive_register, archive_retire, capture_drain_ack, capture_drain_read, capture_drain_snapshot, channel_collect, channel_lease, channel_prepare, channel_reconcile, channel_register, cleanup_inspect, cleanup_journal, cleanup_read, cleanup_remove, cleanup_resolve, containment, containment_revoke, credential_bind, credential_binding, credential_gate_observe, credential_peer_verify, credential_projection_observe, credential_projection_observe_id, credential_projection_source, credential_withdrawal_observe, data_collect, data_lease, data_measure, data_native, data_observe, data_query, data_register, data_revoke, data_selector, isolation_evidence, observe_gate, open_gate, plan_cleanup_native_read, prepare, probe, reconcile_capture, reconcile_gate, register_capture, register_spec, release, resolve_runtime, resolve_storage, runner_prompt, stop_gate, unknown, worker_check, worker_launch |
| E91 | admin/lease.go:478 | yes | admin_enrollment, isolation_evidence, probe, runner_prompt, unknown, worker_check, worker_launch |
| E91 | admin/worker_handoff_linux.go:366 | yes | abort, admin_enrollment, allocate, allocate_launch, archive_bytes, archive_check, archive_freeze, archive_lease, archive_observe, archive_prepare, archive_reconcile, archive_register, archive_retire, capture_drain_ack, capture_drain_read, capture_drain_snapshot, channel_collect, channel_lease, channel_prepare, channel_reconcile, channel_register, cleanup_inspect, cleanup_journal, cleanup_read, cleanup_remove, cleanup_resolve, containment_revoke, credential_bind, credential_binding, credential_gate_observe, credential_peer_verify, credential_projection_observe, credential_projection_observe_id, credential_projection_source, credential_withdrawal_observe, data_collect, data_lease, data_measure, data_native, data_observe, data_open, data_prepare, data_register, data_revoke, data_selector, isolation_evidence, observe_gate, open_gate, plan_cleanup_native_read, prepare, probe, reconcile_capture, reconcile_gate, register_capture, register_spec, release, resolve_runtime, resolve_storage, runner_prompt, stop_gate, unknown, worker_launch |
| E93 | as/credbroker_linux.go:154 | no | none |
| E94 | as/credcomp_linux.go:188 | no | unlock, names, read, write |
| E94 | as/credcomp_linux.go:201 | no | refresh_check, refresh_close, refresh_held |
| E95 | as/credcomp_linux.go:247 | no | none |
| E97 | admin/credowner_linux.go:313 | no | credential-component.sock |
| E97 | admin/credwire_linux.go:369 | no | credential-component.sock, component.sock |
| E106 | store/materialization_owner.go:47 | yes | reserved |
| E106 | store/materialization_verify.go:70 | yes | bound |
| E115 | store/atomic_support.go:166 | no | application, approval, approval_use, archive_job, capture_drain, capture_failure, capture_receipt, capture_state, challenge, change, channel, channel_ack, channel_stage, collection, collection_delete, collection_object, continuation, continuation_claim, credential_projection, credential_projection_id, credential_worker_handoff, decision, decision_snapshot, delegation_lease, dispatch_freeze, dispatch_state, enrollment, enrollment_ceremony, enrollment_challenge, enrollment_receipt, enrollment_validation, frame_source, frames, grant_transport_close, grant_worker_close, guidance_turn, internal_commit, judge_audit, judge_execution, judge_request_id, launch_bytes, launch_control, launch_name, launch_observation, launch_process, launch_revocation, loop_end, loop_receipt, mail, mail_turn_selection, object_inputs, org, org_apply, org_apply_gate, owned_failure, plan_cleanup, proof, proof_use, read_session, record, reservation_actor, reservation_policy, secret_head, secret_source, ticket, turn, upgrade |
| E116 | store/atomic_support.go:218 | yes | Deliveries |
| E116 | store/atomic_support.go:278 | yes | LaunchPlans, Decisions, Enrollments, IdentityBindings, Challenges, Proofs, Counters, Tickets, ReadSessions, Objects, UploadBegins, UploadChunks, UploadCommits, Guidance, Deliveries, Policy |
| E116 | store/identity_writes.go:26 | no | LaunchPlans, Grants, JudgeAudits, Channels, WorkerLeases, Lanes, Endpoints, Decisions, Enrollments, IdentityBindings, Counters, Objects, UploadBegins, UploadChunks, UploadCommits, Changes, Approvals, Applications, OrgSnapshots, Turns, Guidance, Continuations, Mail, Deliveries, Deployments, Policy |
| E116 | store/objects.go:354 | no | LaunchPlans, Grants, JudgeAudits, Channels, WorkerLeases, Lanes, Endpoints, Decisions, Enrollments, IdentityBindings, Challenges, Proofs, Counters, Tickets, ReadSessions, Objects, Changes, Approvals, Applications, OrgSnapshots, Turns, Guidance, Continuations, Mail, Deliveries, Deployments, Policy |
| E122 | api/error_component.go:12 | yes | dependency, integrate, isolation_linux, isolation_darwin, service, grants, secrets, templates, admin, identity, guidance, runner |
| E123 | admin/ipc.go:114 | yes | lb-v2-lifecycle, lb-v2-secrets, lb-v2-guidance, lb-v2-judge, lb-v2-approval, lb-v2-dashboard, lb-v2-integrate, lb-v2-migration, lb-v2-packaging, lb-v2-linux, lb-v2-darwin, lb-v2-codex, lb-v2-claudock, lb-v2-client, lb-v2-messaging, lb-v2-serve, lb-v2-store, lb-v2-watchdog |
| E123 | api/error_component.go:34 | yes | lb-v2-policy, lb-v2-judge, lb-v2-approval, lb-v2-dashboard, lb-v2-migration, lb-v2-packaging, lb-v2-client, lb-v2-messaging, lb-v2-serve, lb-v2-store, lb-v2-watchdog |
| E124 | api/helper_reason.go:39 | no | none |
| E125 | api/enrollment_wire.go:72 | yes | enrollment |
| E128 | client/client.go:417 | yes | connection |
| E133 | admin/bootstrap_mount_linux.go:50 | yes | unavailable, namespace_denied, namespace_setup_failed, option_unsupported, userns_policy_failed, mount_source_unavailable, destination_create_failed, root_switch_failed, cwd_failed, capability_setup_failed, parent_death_setup_failed, no_new_privileges_failed, child_sync_failed, seccomp_setup_failed, process_create_failed, allocation_failed, runtime_thread_failed, runtime_memory_failed, descriptor_or_path_unavailable, exec_failed, identity_map_failed |
| E141 | watchdog/signals.go:115 | no | none |
| E142 | rd/capture.go:179 | no | system, user |
| E143 | rc/capture.go:397 | no | thread.started, error, item.completed |
| E143 | watchdog/signals.go:189 | no | thread.started, turn.started, turn.completed |
| E144 | migration/stub.go:153 | no | none |
| E146 | cli/commands_templates.go:348 | no | none |
| E149 | service/server.go:548 | no | change-owner, content, control, judge-preview, l6, owner, parent, public, relation, report-line, resource, reviewer, self, spawn, tree |
| E154 | admin/gate_cgroup_linux.go:148 | yes | unavailable |
| E157 | migration/readers.go:992 | no | none |
| E158 | migration/readers.go:718 | no | archive.completed, archive.verified, lane.refusal, lane.refusal_reviewed, lane.workaround_suspected, report.sent, store.record, tool.submitted |
| E158 | migration/stub.go:143 | no | brief.rendered, lane.adopted, lane.mailed, lane.started |
| E161 | as/fixture.go:142 | no | claudock, claude |
| E162 | cw/schema.go:33 | no | none |
| E174 | il/service.go:498 | no | none |

There are 99 rows in this table. The helper dispatch rows are deliberately
narrow ports; convert to a narrower type or handle unsupported members
explicitly during the rename instead of adding blanket suppressions.

Numeric and compound switches need these additional observations:

| Domain | Source | Coverage observation |
|---|---|---|
| E88 | identity/registration_cbor.go:42 | No default; cases 0/1, 2/3, 4, 5 cover the supported majors. External CBOR majors 6 and 7 reach the unsupported return after the switch. |
| E85 E86 E87 | identity/enrollment.go:173 | No default in the predicate switch. The three accepted key/algorithm/curve combinations are EC2/-7/1, OKP/-8/6, and RSA/-257. Other combinations reach the unsupported return. |
| E134 | admin/spawn_facts_linux.go:46 | No default; 0, 1 and 2 are present. Unrecognized kernel values reach the fallback after the switch. |
| E135 | admin/spawn_facts_linux.go:55 | No default; 0 and 1 are present. |
| E134 | admin/gate_failure_linux.go:92 | No default; raw status strings 0, 1 and 2 are all named. Decode into SeccompMode at this boundary. |
| E135 | admin/gate_failure_linux.go:101 | No default; raw status strings 0 and 1 are named. |
| E02 | api/credential_validation.go:82 | The predicate switch has a default and supports codex-file and claudock-headless. claudock-helper, claudock-api, codex-api and codex-local are rejected rather than projected. |
| E03 | grants/launch_retained.go:59 | The predicate switch names resume, turn and continue; start/adopt are outside this retained-launch port and reach its refusal default. |
| E98 | admin/launch_capture.go:185 | No default in the predicate switch. The phase inequality rejects every phase other than active; the active path continues after the guards. |
| E32 | service/host.go:309 | The predicate switch gives archive a dedicated branch, while the generic Worker branch handles the other kinds. |
| E32 | service/reconcile.go:184 | The same archive-specialized and generic-worker partition applies here. |

Specific differences to preserve as review decisions:

- E03 contains continue, but TriggerKind does not. The current fixture at
  tf/launch_linux.go:644 assigns r.Mode directly to Trigger.Kind.
- The public CaptureRecord stream catalog omits vendor even though the
  capture-binding validator and adapters use it.
- BlobClass has diff, check and message in the manifest validator but not
  the public wire catalog. Do not widen upload authority while typing it.
- E31 has off in Claudock and disabled in Codex; the Linux validator requires
  off. This is a static vocabulary difference, not a tested launch result.
- E116 has Deliveries, but store/atomic_support.go:218 has no case for it.
- DataStagePhase contains bound, but store/materialization_verify.go:70 does
  not name it. The table records the fallback rather than assuming success.
- RawProfileMode aliases and PublicSlotMode must remain different Go types;
  publicSlotMode needs an explicit, validated mapping with a failure result.

## Existing named enums

These groups already own a named type and do not need a replacement type.
Their switch findings remain visible in exhaustive. Plain-string mirrors
should reuse the existing type instead of defining a competing enum.

| Existing type | Source of members |
|---|---|
| api.ErrorCode | api/base.go:35; admin/native_error.go:11 adds two named-code members |
| api.Driver | api/runtime.go:5 |
| api.EndpointClass | api/bindings.go:11 |
| api.CompareKind | api/transactions.go:10 |
| api.InternalKind | api/transactions.go:27 |
| api.EffectState | api/effect_state.go:6 |
| api.WorkerOperation | api/worker_identity.go:11 |
| api.PolicyUse | api/policy_generation.go:10 |
| api.JSONFrameKind | api/json_diagnostic.go:18 |
| api.Method | api/base.go:31; api/methods.go:15 typed catalog |
| api.EventKind | api/base.go:32; api/events.go:158 typed catalog |
| watchdog.LimitKind | watchdog/signals.go:23; raw mirrors are E29 |
| watchdog.OutputFormat | watchdog/signals.go:32 |
| wire.screenPath | judge/wire/screen_bounds.go:43 |
| admin.recordReadiness | admin/journal.go:14 |
| service.attemptResult | service/reconcile_attempt.go:14 |
| linux.Access | il/rules.go:31 |

api/write_catalog.go:15 publicWrites.events currently serializes EventKind
members as whitespace-separated strings. store/loop_write.go:38 lastLoop's
kind parameter also erases EventKind. The API catalog's deferred member already
uses InternalKind.

## Exclusions and completeness boundary

All const declarations were inspected, including nested declarations and test
files. No additional test-only const group defines an execution enum. Test
table labels such as fault names and mutation names are open fixture selectors,
not a new product protocol. Existing test-support mirrors of the production
enums are identified with their production group.

The following groups are not missed enum declarations:

- Size limits, deadlines, retry thresholds, schema-version numbers, frame
  bounds, ABI bounds, fixed modes/umasks and mathematical constants are
  quantities or masks. E140 separately records the Landlock flag vocabulary.
- URL/header names, regex fragments, canonical filenames, fixed paths, one
  protocol/version pin per record and template source paths are identifiers
  or parser keys rather than interchangeable mode/kind members. The groups
  in cw/binding.go:18, templates/sources.go:18, il/layout_linux.go:22,
  rd/service.go:14 and admin/binding.go:12 therefore do not get enum types.
  A path can still require an opaque named path type in a separate change.
- Closed forbidden-name sets for credential environment keys, config keys,
  filesystem operands and executable flags screen an open input vocabulary.
  They are not runtime state enums. This covers rc/config.go:38,
  grants/manifest/values.go:174, secrets/wire/wire.go:121,
  il/validate.go:315, judge/wire/screen_fields.go:8 and the CLI flag parsers.
- Provider/model names, roles, currencies, IDs, account names, hostnames,
  arbitrary enrolled runtime asset roles, user paths and source versions are
  open installation data. E81 does not replace every Provider string.
  E161 identifies only recognized runtime role selectors.
- Box.State, CredentialEvent.Outcome, Room.Reason, Capability.Reason,
  CaptureGap.Reason, WatchdogEvent.Reason, ChangeEvent.Reason,
  ProfileEligibility.Reason, TokenFit.Reason, rule/provider explanations,
  channel DeliverySemantics and general stop reasons have no closed constant
  group in this implementation. Do not invent members for unfinished ports.
  The supported channel transport is http-json at
  dw/channel_worker.go:53, but enrollment currently accepts arbitrary transport
  metadata; a transport capability type would be a separate port contract.
- Schema fields used as dictionary keys, JSON punctuation, status-file field
  names and translated OS error text remain parser data. E162 records the
  actual closed enum router rather than declaring every schema member an enum.

No admin/apikey* source exists in this revision. The K overlap remains reserved
for the other lane's new files; re-read them after that lane lands. The A/S/G/R/W
labels above mark the current files whose enum boundaries overlap its work.

## Rename order and checks

1. Wait for the API-key lane, update this inventory from its landed tree, and
   settle the raw-profile/public-slot conversion first. Define RawProfileMode
   in the private profile contract and PublicSlotMode in api; give each its
   own constants and decoder validation.
2. Add shared API types for launch/actor/worker kinds, states, statuses,
   streams, coverage and grant delivery. Convert struct fields and primitive
   parameters together. A type alias to string does not satisfy this goal.
3. Give private journal phases, helper methods, read selectors and parser
   results their own types. Keep schema/protocol adapters explicit and keep
   accepted public subsets narrower than private ones. Do not turn metadata
   labels into authorization.
4. Replace catalog strings with typed slices or maps, including StateWriteField,
   TransactionGuardKind, EffectKind and the already named EventKind. Preserve
   exact serialized values and intentional unknown/unsupported behavior.
5. Resolve each switch row by enumerating all members, narrowing the input
   domain at a validated adapter, or retaining an explicit rejection for
   unsupported members. Keep input validation after JSON decoding; Go named
   types do not prevent arbitrary values from untrusted bytes.
6. Run the same local analyzers and the separately authorized Linux tests
   after the Go rename. Flip CI and preflight to strict only after its
   diagnostic baseline is addressed; this step changes neither integration.

The ten priority types are RawProfileMode, PublicSlotMode, LaunchMode,
LaunchKind, ActorKind, LaneState, OperationStatus, PromptStatus, WorkerKind
and BlobClass. The inventory contains 174 proposed groups, including parser
selector sets, private journals, singleton discriminants and the flag group.

## Observed local analysis

bash scripts/lint.sh completed with exit 0 on macOS while analyzing
GOOS=linux over ./internal/v2/... both without extra tags and with
laneboss_root_canary. It reported 48 unique staticcheck findings and 58 unique
exhaustive findings. Duplicate diagnostics across those two configurations
are counted once. Test source is analyzed by the tools' default settings;
no test executable runs.

The first staticcheck findings include unused archiveByLease
(admin/arch_ctl.go:190, U1000), the ineffective registeredExport.File
assignment (admin/export.go:75, SA4005), and nil contexts
(admin/initial.go:68, SA1012). The first exhaustive findings include
reflect.Kind cases in admin/credentials.go:85 and syscall.Signal cases in
admin/gate_failure_linux.go:55; api/guidance_claim.go:105 also misses
InternalKind members. Those diagnostics concern existing named types, so
they do not imply the untyped domains are already covered by exhaustive.

bash scripts/lint.sh --strict returned 1 with byte-identical findings.
Each missing-analyzer control returned 2. Bash syntax checking and ShellCheck
passed. A missing tool, analyzer failure, invalid diagnostic JSON or compile
failure is an error even in report mode. The recorded expected failures are
strict findings and missing tools, not ignored checks.

The script keeps GOCACHE at the shared cache required by the brief, sets
GOFLAGS to trim paths plus the selected tag set, and disables downloads.
Staticcheck's separate default cache is created under the ignored
.lane-gocache/staticcheck directory; an explicit caller cache is preserved.
The earlier denied cache attempt remains in the lane evidence. No cache
permission refusal was converted to a successful count.

The evidence directory for this lane retains report-3.log, report-3.exit,
strict-3.log, strict-3.exit, syntax-3.log, shellcheck-3.log and both missing-tool
outputs and exits with the -3 suffix. Full first-ten diagnostics are in
report-3.log; inputs.sha256 identifies the reviewed files. Earlier runs remain.
Only scripts/lint.sh and docs/design/enum-inventory.md are authored changes.
No Go source changed, and no project binary or test executable ran.
No network operations or authenticated model requests ran in this step.







