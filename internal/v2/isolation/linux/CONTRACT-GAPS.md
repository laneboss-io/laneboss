# Draft.4 fix 11 Linux consumer

The current base is b8d960b8, the supervisor's clean merge of fix 11 onto the
Linux fix-10 slice. This adoption edits only the owned Linux files; no staging
or commit is performed here. The supervisor's reported fix-10 off-cell result
and fix-11 contract controls are prior-tree evidence, not this candidate's
runtime result.

## Shared retained plan lookup

**LP-LINUX-PLAN-READ-1:** fix 11 now supplies LaunchControlSource.Plan and
ReadLaunchPlan. [plan.go](plan.go) calls the shared reader with the original
selector, preserves the source error and validates the returned retained record.
A foreign selector or malformed record refuses; partial data with an error is
discarded. Linux manufactures no Scope, fallback plan or launch-ID map.

The Linux consumer implementation is no longer a stub. Service.Plan still must
resolve its actual durable claim and StateStore authority. Its current owning
not_implemented propagates unchanged. With valid retained metadata, preparation
continues through the existing phase, handoff and exact-byte checks to the
helper. A retained read is not native authority or an installed launch result.

## Fix-11 worker and materialization boundary

| Item | Linux checks and remaining owner implementation |
| --- | --- |
| Worker actor | Worker records require their own worker actor, level zero, empty agent role and no agent Recovery. Helper control causes stay service-owned and retain the original requester; they are not the worker bootstrap identity. |
| Closed operations | Linux has no private worker-operation dispatcher and adds no public RPC. Identity/store/service must use WorkerBinding and ValidateWorkerPrincipal on every frame/delivery, with the fixed operation map: capture state/append only; channel/usage input/object/result plus authorized credential injection; materialize and other fixed jobs input/object/result only. A label, copied peer tuple or requester actor cannot replace native mapping. |
| Child materialization | The fixed materialize kind uses the exact internal worker/binding/lease grammar, bounded materialize_input and a separate worker endpoint. Its grants contain one read-only bind_ro project source at /job/source, relative dot, retained parent grant and closed history scope; no resource, secret, profile, network or channel capabilities are allowed. Other worker/agent grant destinations and executable rules remain. |
| Storage and process ownership | Source/grants are comparison metadata. Service/store must retain DataStageID, distinct parent/child claims, narrow issued set, worker lease, actual process and receipts. Admin.OpenLaunchDataStorage must hold the source/workspace/home descriptors behind OpenToken, project the exact roots at the fixed job paths and use a distinct worker UID/containment. Linux does not reopen labels as host paths or invent those receipts. |
| Worker scratch | LaunchSpec keeps the existing /work/main logical scratch convention. Fixed /job/workspace and /job/home writes come solely from the helper's held stage projection, outside the generic data-grant channel. The diagnostic builder is not a production descriptor adapter. No arbitrary cwd or path resolver was introduced. |
| Completion | Dataworker.RunInternal and the private worker endpoint must validate sealed input and exact result bytes under the real mapping. AwaitMaterialization must return actual terminal zero, acknowledgement and manifest read-back. Linux creates no copy/Git/home result and does not run a job as the service account. |

The new materialization metadata fixture calls ValidateLaunchDataStage before
testing the Linux spec. Its held-root/claim/process labels establish shape only;
they are not an opened descriptor or a running worker. Current policy and
revocation checks remain with service/helper. Historical bindings are not
rewritten to match a new policy generation.

## Fix-10 consumer adoption

| Contract item | Linux adoption and remaining owner boundary |
| --- | --- |
| Reservation authority | Fixtures validate the complete original frame and scope-bound TicketUse with ValidateLaunchReservationRequest, then validate the retained Authority and phases. Consumed ticket/proof provenance, D9 and actual parent grant ceilings remain store/grants checks. Linux does not issue or consume authority. |
| Stored child pins | Binding actors compare level/role with the retained reservation, including when the altered record has a valid new hash. Runtime driver compares with the reservation pin. Fixture runner inputs and bound actors use those stored pins. Shared plan/binding validators remain mandatory. |
| Prepared binding | Live records require explicit agent/worker Kind and the corresponding lane/worker actor. Missing/legacy Kind refuses. Workers cannot acquire agent recovery authority. The store's unconditional helper_prepare transaction validator owns same-transaction plan/Lane/event requirements; Linux does not emit those projections. |
| Capture refusal | Default metadata capture is registered. Explicit refused cases retain approval/generation metadata and the policy snapshot. Linux calls ValidateCapturePolicy and compares the snapshot generation with the reservation. Real consumed D6 approval and current policy/revocation immediately before release remain service/store/admin obligations. No request enables the exception. |
| Fixed channel worker | Only the exact internal channel/binding/lease argv is admitted. Sealed input class/size/ID and executable ID are checked. The runtime must expose the exact worker lease and enrolled executable content. This grammar does not widen other worker or agent executable rules. |
| Channel result and recovery | Linux returns only its actual process/control receipts. Dataworker/service/identity must verify ChannelExecution and exact sealed input/job provenance, current claim and fixed runtime, and retain the identity/gate handoff. Messaging/dataworker must validate measured provider acknowledgement and read-back; process exit or injection success is not delivery. |
| Emitter and natural end | Linux emits no launch_plan or lane.state transaction. The E2E reader retains generic events and does not relabel an observation as a service event. Shared service/lifecycle/store catalogs own the added rows. |
| Review coverage | The OS case forwards the actual lane.review receipt for abandoned collection. It builds no coverage/evidence and does not accept a lane. New live acceptance, closed coverage and verifier evidence remain lifecycle/dataworker/store duties. |
| Continuation operation | Linux preserves the original cause operation across helper requests and reconciles that operation. It neither creates a continuation operation nor substitutes an intent ID. Watchdog/store/lifecycle own the single stamped selection/claim/launch operation. |
| Native transport | First-frame deadlines, health no-reply rules and Darwin writer tokens belong to service/native peers. No transport or Darwin source is changed here. |

## Per-method implementation and remaining dependencies

ControlSource is an alias of api.LaunchControlSource. Assembly now passes its
Server as that installed dependency; the earlier missing-wiring statement is
superseded. The Server's methods in this checkout are still failing stubs.

| Method | Linux consumer behavior | Exact remaining owner dependencies |
| --- | --- | --- |
| Probe | Preserve current host prerequisites; require independent helper/runtime/capture/gate evidence, matching backend, kernel and ABI; keep retained evidence for every production boundary. | service.Probe must read independent installed-helper evidence. admin must measure the real prepared canary and UID/cgroup/network/runtime/capture/gate boundaries. It must not recurse through Doctor or BindIsolationProbe. |
| Prepare | Validate current spec metadata and installed manifest, retained original length/hash/strict decode/JCS, the retained LaunchPlanRecord, ValidateAgentLaunchSpec and exact retained handoff. Require spec_retained; a bound/opened plan must recover its original gate. Validate actual RegisterSpec and ResolveRuntime replies, enrolled executable content, private workspace/home, endpoint/network and a distinct current prepare cause. Accept only the helper's actual prepared containment. | service.Handoff, Original and PrepareIntent; service.Plan under its durable claim; store's retained plan/spec and current policy/grant/claim checks; admin.RegisterSpec, ResolveRuntime and Prepare. ResolveRuntime must independently reload enrollment, private storage registry identities and the same plan. Missing registry data cannot allocate replacements. |
| Launch | Reload Binding, compute its actual JCS record digest and compare the permit/identity/prepared tuple. An agent requires bound/opened plan plus complete retained recovery. ValidateLaunchBindingPlan checks the original request, home, capture, lease and record; reload exact original spec bytes and recheck metadata/expiry. Require the same requester, operation, request and cancellation epoch in the distinct open cause. Reconcile that same lease/launch/prepared/operation before OpenGate. Reuse only the exact consumed permit and actual observed process; unknown state cannot open another gate. | service.Binding, Original and Open; service.Plan under its durable claim; StateStore.LaunchBinding and the atomic identity.bound tuple; identity.BindLaunch; admin.ReconcileGate, OpenGate and ObserveGate. The helper independently checks current grants/policy, epoch, endpoint, enrollment and one-use permit consumption. Fixed worker jobs retain their separate authenticated worker lease; an absent agent recovery is never treated as legacy. |
| Observe | Resolve the current protected lease/handle; return only a helper observation with known state, matching containment/generation, prompt status and valid exit/signal facts. Unknown counts do not become zero. | service.Observe and admin.ObserveGate, including current registry ownership and actual kernel observation. A launch-ID map or caller label cannot supply it. |
| Stop | Resolve the distinct stop cause and reason plus the current observe binding; require the same actual lease/handle. Return the helper's terminal zero observation without changing it. | service.Stop and Observe; admin.StopGate must stop the whole owned containment and independently observe actual terminal zero. |
| Abort | Resolve the original never-opened prepared gate and distinct abort cause. Validate the helper's actual nonexecuting AbortReceipt, original generation, prepared state and measured zero; pass the unchanged receipt to RecordAbort. | service.Abort and RecordAbort; admin.AbortGate must independently prove the gate never executed and is quiescent. Store CompleteEffect must retain that exact receipt under the original effect claim. No process exit is invented for abort. |
| Collect | Treat caller zero as comparison only. Resolve Release and Observe under current authority; reobserve the exact containment, require stable terminal zero and call helper Release. Validate measured receipt bindings and all four zero counts, then pass the unchanged actual receipt to RecordRelease. | service.Release, Observe and RecordRelease; admin.ObserveGate and Release; store CompleteEffect and helper.released must atomically retain the actual ReleaseReceipt. Unknown completion keeps ownership for reconciliation and never recycles a UID, namespace, writable export or descriptor. |

All dependency errors propagate; a typed not_implemented is a failed operation.
No nil-error stub, synthetic gate, invented process, successful empty receipt or
availability flag substitutes for an owner implementation.

## Helper and capture boundaries

The installed admin helper remains responsible for protected enrollment and
root-relative object resolution, descriptor-pinned storage and runtime,
selected sealed slots, real UID/GID inventory, cgroup/network ownership and the
one-use gate. Its gate must invoke the fixed unprivileged bootstrap, preserving
the existing mount-ID, symlink, Git administration, protected-root, stream,
Landlock, seccomp and descriptor checks. No agent is run as root by this package.
The unexported builder remains diagnostic until that installed route exists;
this change adds no arbitrary path/argv or descriptor-transfer RPC.

The plan and spec must carry registered capture or the exact allowed explicit
refused disposition. The shared validator rejects integrity, authentication,
ownership and guard errors as fallback reasons. Linux does not invent a
producer, pipes, captured bytes, EOF, tool coverage or collection. Lifecycle,
admin and service must retain capture.bound/refused before release and supply
actual supervisor/spool receipts. Partial or unknown capture resources stop
launch until independently quiescent and collected. LP-CAPTURE-IO-1 remains
the shared follow-up for scoped input/attach and pinned vendor interpretation.

## Verification and acceptance limits

The new metadata controls advance reserved, sourced, planned and spec_retained
shapes before testing the consumer validators. They supply no host storage
paths. Direct binding tuples test only validator correlation and are never
returned as a successful agent ControlSource.Binding reply. The public Prepare
control consumes the real shared read and stops at the failing helper
registration test double. Source errors, foreign selectors and malformed
records stop before the helper. No test supplies a successful fake agent launch
or production probe.

The controls cover caller executable/cwd/manifest changes, foreign reservation,
changed budget/grants/policy, expiry, replay bytes, runtime/private storage,
distinct causes and cancellation, missing recovery and incomplete capture.
Current store policy/revocation/claim enforcement remains an owner dependency,
not something a shape test proves. The Linux mutation guide describes reached
red-before-candidate execution on disposable Linux. Every new
control still needs that execution; static checks are not runtime evidence.

No Go tests, binaries, project interpreters or E2E cases run on the authoring
Mac. The required static scope is gofmt, Linux vet, fault-tagged Linux vet,
Darwin vet, Python compilation and Bash parsing. The final evidence report
names their exact results and retains the consumed bytes. A Go-cache refusal
uses only the brief's explicit skip-vet recovery.

Installed serve, LIFECYCLE-TREE and OS-LINUX acceptance remain pending real
service/helper/planner implementations, the live service plan read and executed
positive/refusal/restart controls. Keep both restriction cells, both hook
modes, inner sandbox off, the ABI 3 floor, and every prior mount, network and
cleanup matrix cell. Prior component results remain historical support in
[REVIEW-STATUS.md](REVIEW-STATUS.md); they do not prove this changed tree.
