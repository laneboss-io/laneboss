# Draft.4 integration requests and incomplete work

Fix 14's dispatcher dependency is described in
[D4FIX14-REPORT.md](D4FIX14-REPORT.md). The concrete store port ReserveMutation
returns the actual atomic insertion winner. Hosted StateStore wrappers must
forward it; ReserveRequest alone cannot prove who won. Server.OwnsMutation
implements the approved lifecycle MutationDispatch signature and is wired as
Dispatch in assembly. The current lifecycle stub has only a matching field
bridge; integrate approved owner commit 0b139e1 before exercising that lifecycle
implementation. Preserve the server wiring and real owner dependency type.
No request/connection-keyed or constant ownership fallback is authorized.

The candidate and exact capture mutant still need both-tag Linux compilation,
unit/mutation execution and assembled lifecycle verification. The local cache
refusal prevented vet; it does not establish those results. Earlier Group B
and installed-runtime limits below remain outstanding.

The current fix-11 candidate is documented in
[D4FIX11-REPORT.md](D4FIX11-REPORT.md). It is uncommitted, with the merge index
still open. Validation stopped at a py_compile command with a missing input;
no runtime or complete static result is claimed.

| Current owner work | Remaining requirement |
| --- | --- |
| Service/store and identity | Finish the actual RevokeLaunch coordinator and deciding native close/delivery controls. Causal store and connection invalidation support alone do not establish installed revocation. |
| Service/store, native identity and admin | Implement WorkerBinding using the protected helper registry/boot, consumed fixed lease, current stage/claim and native principal. The older capture fixture path is not fix-11 mapping. |
| Service/store, admin and dataworker | Implement LaunchDataStage, MaterializationStage, AwaitMaterialization, WorkerInput and WorkerResult with actual opened storage, durable child worker/outbox and observed output/exit. These ports retain typed barriers. |
| Service/store and guidance/judge | Correct existing-claim replay ordering before fresh task/epoch preflight. Join complete measured judge request/raw/audit/cost evidence before enabling scored guidance completion. The current completion port refuses scores. |
| Admin and identity | Consume the separate mode-0600 fixed begin/complete framing in the current report and supply real create-attestation validation. Store InstallHumanEnrollment rechecks the native channel under its writer; generic admin_enroll Transact is not an entry. |
| Supervisor and installed E2E owners | Recover the failed check invocation, run all static and Linux component controls, the dedicated software-authenticator build, and installed startup/enrollment/launch/restart gates. |

The earlier tables below retain integration history. Current ports and status
in D4FIX11-REPORT.md take precedence over their stale stub descriptions.

The d4fix10 delta starts at fbbf771.
[D4FIX10-REPORT.md](D4FIX10-REPORT.md) records its per-finding source/static
results. Issued child grants are checked against the retained ceiling and
original start/adopt request, including a separate staged grant write. A
failed plan with no Lane projection releases its name for a new reservation.

No historical identity-import emitter is declared by the current closed API
and store catalogs. There is therefore no exception to the launch-plan fence
for a lane identity. Neither lifecycle_effect, migration_apply nor the
legacy_import origin label grants that exception. Migration may retain inert
historical records; it cannot promote them into current launch authority. A
future identity-import kind requires an explicit shared contract and a route
that preserves inert provenance; none is invented in this lane.

The delta review's findings 6 and 7 are deferred performance notes. Open still
runs the full journal Verify under a 120-second context in store.go; a large
healthy journal can exceed that window. A future retained checkpoint or
explicit full store.verify path must preserve restart integrity. BeginRead in
snapshot.go still opens a separate read-only SQLite handle for each pinned
view and closes it with the view. A future small read-only pool must preserve
the same transaction/head isolation and close behavior. Neither path is
changed or benchmarked in d4fix10.

The d4fix9 service/store source handoff is [LAUNCH-PLAN.md](LAUNCH-PLAN.md).
It supersedes the earlier launch-reservation / control-source / child-ancestry
stub descriptions below. It includes the protected inventory and initial
administrator-enrollment addendum. No Linux runtime acceptance is claimed.

| Owner | Fix-9/addendum dependency that remains explicit |
| --- | --- |
| lb-v2-lifecycle | PlanLaunch is called with the authentic current EffectLease and execution Scope. Its current stub's typed not_implemented propagates. Supply real source/grant/data/credential/runner orchestration, atomic helper_prepare ready binding and helper_open opened transition. A successful plan effect is credited only after exact opened-plan/process read-back. Unsupported Swap coordination/completion and LP-CAPTURE-IO-1 remain separate barriers. |
| lb-v2-grants / dataworker | Resolve/Revalidate and MaterializeLaunch remain actual owner calls. A completed import stage must retain LaunchDataRequest selectors as WorkerPlan.Input, its real output manifest and measured successful worker exit/zero survivors through CompleteEffect. The planner cannot substitute a shaped workspace/materialization for that receipt. No generic service-side worker command executor is added. |
| lb-v2-admin / lb-v2-linux | Supply real protected enrollment/storage resolution, helper allocation/preparation/gates, live capture registration/spool reconciliation and independent IsolationEvidence. Source/control methods reload retained objects and propagate owning errors. Allocation/release/abort reply loss still needs the helper's actual journal receipt lookup; unknown outcomes stop without replacement allocation or fabricated collection. |
| lb-v2-admin / lb-v2-integrate | Wire the authenticated fixed outside-job channel to Server.CaptureState, RetainCapture and AppendCapture. RetainCapture derives object authority; AppendCapture accepts no incoming internal intent. RegisterCapture/ReconcileCapture and physical pipes/spool/kernel producer are not implemented by a store fixture. Freeze the post-revocation drain-claim/spool attestation handoff: old epochs currently refuse, and no permissive drain claim is synthesized. |
| lb-v2-serve / assembly | Forward HumanEnrollments(context.Context, string) exactly as expected by serve 58d70272. Forward the concrete launch recovery ports listed in LAUNCH-PLAN.md through any hosted-store wrapper. Pass lifecycle LaunchPlanner and real helper/worker/launcher; launch readiness requires the active recovery/capture loop. Supply an independent helper evidence source, never the launcher itself, for service Probe. |
| lb-v2-integrate / lb-v2-identity / lb-v2-admin | The concrete initial ceremony store entry is InstallHumanEnrollment behind its verified native administrator channel and retained validation. Direct InternalAdminEnroll Transact lacks the private capability. The current report specifies fixed framing; identity still owns real attestation/UP/UV. Later current-key changes return the typed missing-ceremony error. The inventory preserves revoked markers, and principal selection uses the actual installed human endpoint. |
| lb-v2-lifecycle / lb-v2-claudock / lb-v2-codex | Review/accept and capture-dependent continuation must retain the explicit refused/incomplete status. Pipe registration or EOF is not tool inventory/session/limit interpretation. LP-CAPTURE-IO-1 and actual pinned vendor-byte interpretation keep their typed barriers. |
| lb-v2-serve / lb-v2-e2e | Execute the real installed lane.start after the human root ticket, restart at each retained phase and exercise native capture/job boundaries. Run the component reds and unchanged candidate tests on Linux. Static checks, fake identities and helper receipt DTO fixtures do not accept SERVE-STATE, OS-LINUX or LIFECYCLE-TREE. |

The current d4fix4 round starts from 3f1a97b with draft.4 fix 8. Receipt storage
binds Config in a retained envelope and in the typed field. Ticket storage
binds principal, configuration and endpoint generation. No shared contract
file was edited in this round.

The installed Linux host, core receipts, objects, pinned reads and selected
effect paths are implemented in source. They are not runtime acceptance.
Only the composed serve E2E, red on the base for its intended reason and green
on the candidate, accepts this round.

| Owner | Concrete handoff required |
| --- | --- |
| lb-v2-serve | The supervisor now reports a real installed service reaching its first public Health call. Rerun that gate with d4fix4, then continue the enrolled service case and retain base/candidate artifacts and results. PUBLIC-HEALTH.md records the transport fix and unmeasured component regressions. |
| lb-v2-identity, lb-v2-admin, lb-v2-linux | Supply actual native peer/containment verification, enrolled identity/boot setup and the separately protected endpoint binding. The host reads exactly one pinned first frame, handles public Health without identity, and gives identity ConnectionContext before dispatching any other method. Every-fragment FrameContext is retained. No fixture identity is enabled by public construction. |
| lb-v2-serve, lb-v2-admin, lb-v2-integrate | Confirm the installed endpoint composition: this host owns one binding/listener per Server. Explain how the installation supplies a genuine lane-class endpoint alongside human and worker endpoints. A child binding naming a human-class listener is refused. |
| lb-v2-identity | Verify that mutation delivery/replay authorization recognizes the exact committed receipt after its human proof is consumed. Entry, commit and delivery checks remain enabled. A consumed proof must not authorize a different key/content. Human read sessions remain on their opening socket. |
| lb-v2-serve, lb-v2-integrate, lb-v2-service | Resolve request-scoped receipt/event/effect cardinality observation. records.append permits zero outbox payloads in the frozen matrix. The case can measure one record and exact replay; there is no public request-scoped receipt/outbox inventory. Specify the intended observable effect or a reviewed independent observation port. The case will not inspect SQLite or invent an effect. |
| lb-v2-e2e, lb-v2-serve | Supply the protected context.controls controller, enrolled restart selector and real confined DB/WAL/journal/FD canaries. The service case consumes restart_service and validates controller identity/correlation/evidence. A deterministic outage window and watcher load controller are still needed; the current action set has no stop/pause window. |
| lb-v2-lifecycle, lb-v2-service | Supply the installed event.tail producer and implement the service case's load, overflow and cursor-recovery phase. Component producers do not count as installed evidence. |
| lb-v2-admin, lb-v2-integrate | Add or define recovery lookup for lost helper allocation/release/abort receipts by causal operation/effect. Allocation may lose the lease ID; LaunchReconciliation has no release/abort receipt. Unknown outcomes are retained rather than blindly repeated. |
| lb-v2-packaging, lb-v2-lifecycle, lb-v2-integrate, lb-v2-service | Supply measured capture backlog and complete process inventory for DrainDispatch. Host2 persists/reopens freeze receipts and checks reservations/all incomplete effects, then stops with typed not_implemented. Freeze/thaw are implemented but unmeasured; new deployment effect claims also remain blocked until their frozen execution handoff is defined. No unknown count is substituted with zero. |
| lb-v2-grants, lb-v2-integrate, lb-v2-service | Define the frozen rebuild executor and read-back/reconcile receipt. DataWorker has no rebuild method. Other generic worker/coordinator paths also need implementation; existing typed APIs are not runtime evidence. |
| lb-v2-templates, lb-v2-integrate | Specify ResourceFile kind/path selection for org/local prompt/drivers and historical role snapshots. Store source/briefing readers remain implementation backlog. |
| lb-v2-approval, lb-v2-integrate | Clarify mutable ChangeRequest CompareChange versioning; BaseGeneration is the approved org base, not necessarily a mutable status generation. Org-change projection events currently refuse. |
| lb-v2-lifecycle, lb-v2-integrate, lb-v2-service | Confirm the public lane intent versus service/internal authoritative-event convention in the final matrix. Lane-origin foreign-life or authoritative events are refused. Full lifecycle transitions, including authentic child ancestry, still need the reviewed coordinator path. |
| lb-v2-integrate, lb-v2-service | Runtime-verify host2 startup against more than one runnable page and unexpired claims. BindRuntime now uses the concrete store's complete incomplete-effect inventory, so the first-page-only source limitation is removed without changing shared APIs. |
| lb-v2-integrate | Add focused ergonomic service-adapter controls in the common CLI test surface. This lane may edit commands_service.go but not neighboring CLI test files. The component runner now includes the CLI suite; the installed case uses the exact --request form. |

HANDOFF.md separately lists this lane's remaining implementation backlog:
guidance/candidate snapshots, continuation claims, retained source/briefing
assembly, delivery jobs/receipts, backup/drain transitions, child ancestry,
content search, partial verification and unsupported effect coordinators.
Those items are not all missing contracts and are not claimed fixed.

The draft.3 statements that public opening, receipt ports and blob handlers
were unconditional stubs are superseded by this round's source changes.
Runtime verification is still outstanding. The installed service case explicitly
fails at the first unmet acceptance gate, records remaining rows as not_run,
and cannot produce a full candidate pass in its current state.
