# Installed lifecycle backlog

This order follows the serve owner's installed-lifecycle STEPS.md and
REQUESTS.md. The scenario enrolls a human, obtains a real read session, issues
root grants/tickets, starts one L5 root for each driver, checks/stops them,
marks only abandoned, then archives and cleans. Its device/vendor fixtures
declare simulated presence and do not prove human approval or model service
authentication. Missing owner ports remain failed/unrun rows.

| Priority in that flow | Remaining boundary | Required authoritative input and current owner |
| --- | --- | --- |
| Root grants, before either L5 can start | Protected profile journal binding; secret/network/resource handles and non-copy data | GrantsRoot now resolves each exact profile selector in the administrator/secrets encrypted broker journal, after human proof, immutable-manifest and current-scope checks. The journal lock remains held through durable issuance. Assembly must bind its real native backend as grants.Dependencies.Profiles, and the protected owner must unlock it and enroll both actual driver profiles. Missing/locked enrollment remains an owning typed failure; the credential-free fixture cannot manufacture it. Data-copy and enrolled-channel issuance remain implemented. Other requested capability families still need their own protected resolver. See PROFILES.md. |
| G7, before the start/adopt credential slot | Original approved selector versus reservation-issued profile | ResolveProfile now uses the protected original request and canonical reserved grant resolver, retaining driver/profile identity, expiry, delegation, scope and current policy checks. This checkout has only lifecycle/launch_plan_stubs.go; the real plan_runner.go is absent. The exact pinned consumer patch is retained for lifecycle/integration, along with the required issued-member persistence and original-frame provenance handoff. See LAUNCH-PROFILE.md. |
| Launch preparation and worker completion | RunInternal; actual MaterializationStage / AwaitMaterialization / WorkerInput / WorkerResult / WorkerBinding and helper projection flow | The confined tree core and consumer are implemented. Service/store/outbox must retain and claim the child stage, identity must authenticate the native worker, admin must project held roots, and client must supply the private bootstrap/principal/root bridge. The current shared client.Open is an owner-named failure and Client has no such private bridge. An argv lease, local actor struct or service-side copy cannot supply it. |
| Archive, before clean | DataWorker.Archive | ArchiveRequest carries only target and expected generation. It has no operation/effect claim, protected source inventory, destination lease or independent archive read-back/result handoff. Service/lifecycle/admin must supply those bindings. A LaunchRecord ID is not a process handle, and an invented receipt/hash cannot authorize collection. |
| G11, clean/collected after a verified archive | Installed owned-data removal and retained-object completion | CollectCleanup now orchestrates the real CleanupObjectStore and WorkspaceCollector under the original claim, checks dirty work and protected identities before object operations, retains the exact receipt and calls independent VerifyCleanup before returning it. Service/store own the final completion and lane.cleaned transaction. Native administrator workspace/Git and read-back capabilities remain required; missing support stays an owning typed failure. See dataworker/CLEANUP-GAP.md and store/ARCHIVE.md. |
| No explicit child-test row in this lifecycle scope | DataWorker.Materialize/TestChild and human GrantsTestChild | The lane-start path uses MaterializeLaunch. Generic materialization and child testing still need a scoped claimed worker job and result/capture handoff; human testing must atomically carry ProofUse into that transaction. These are required for the separate grants CHILD-CODE gate, not a substitute for starting the disposable roots. |
| No acceptance/review request in these rows | VerifyReview | The scenario marks abandoned and claims no positive review. Real review execution, terminal measurement and coverage remain required before any acceptance flow. |
| No channel send/read-back row in these steps | PrepareChannel / SendChannel / ReadBackChannel | Confined claimed channel worker, fixed provider runtime, credential delivery and actual provider acknowledgement/read-back remain dependencies for messaging acceptance. |
| No explicit org change/publication row; protected setup may depend on it | DataWorker.Render and OrgPublisher.PublishChange / ReconcileChange / PublishBootstrap | Protected org root/generation/pointer, pinned renderer job, publication marker and crash read-back remain absent. Template briefing/source setup is separately required by the serve owner. SourceRef paths or generated files do not establish a published generation. |
| No revoke/resume row in this lifecycle scope | GrantsRevoke | Real subtree/endpoint/continuation inventory and stop/credential/export collection are still required. LaneStop's operation and known zero survivors must not be relabeled as completed grant revocation. |
| No ended-parent child delegation in these rows | Post-exit ancestor Revalidate | A sealed delegation lease projection/verifier remains missing for lost/accepted/merged/abandoned ancestors. Direct parent and retained starter checks now enforce the same boundary. Existing rights on the current retained life do not mint new ancestor authority. |

The remaining installation, worker and archive handoffs require their owning
assembly, secrets, service, lifecycle and native descriptor implementations.
The protected profile resolver uses the existing private broker contract; no
shared API change is needed. This phase keeps every actual dependency failure.
It does not guess store IDs, launch a worker as the service, bypass proof
consumption or treat pending work as completion.

The installed path also needs the serve owner's admin enrollment entry,
credential selector handback, real templates, vendor enrollment/callbacks,
capture and lifecycle collection. Completing a grants library method alone
cannot credit those installed rows. The broader serve-state recovery/count/
capture scope remains independent of installed-lifecycle.
