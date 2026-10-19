# Draft.4 service/store launch handoff

The current candidate is based on 01c866a with the incoming cf894d1 merge.
[D4FIX11-REPORT.md](D4FIX11-REPORT.md) supersedes the older inventory and port
status below. It records the regression-fixture repair, Group A source,
155 authored controls, failed Python check and unfinished Group B work.
Static/runtime verification and merge staging remain supervisor work.

## Earlier launch-plan implementation

The current fix-10 delta starts at fbbf771.
[D4FIX10-REPORT.md](D4FIX10-REPORT.md) records its current verification scope;
[D4FIX9-REPORT.md](D4FIX9-REPORT.md) retains the earlier recovery results.
The inventory now has 98 controls. Compilation and runtime acceptance require
the supervisor's permitted checks and composed installed gate.

New-life issuance now reloads launch_authority and the private original
start/adopt frame, checks the parent's immutable source identities, and applies
launchCeiling against both the retained starter set and a one-to-one requested
entry ceiling. Paths/access/expiry may narrow, and destinations/delegation may
not widen. Separate child-grant staging uses the same fence. Lane-actor
identity.bound requires its existing plan and atomic recovery binding; no
historical identity-import kind is declared. A failed plan releases its name
only when there is no Lane projection. Internal completions omit the public
request digest when no receipt exists; the owned wire schema accepts absence
and still rejects an explicitly invalid digest.

This slice starts at e4e125c, the clean
merge of ad7cfab5 and the prior service validators. It also implements the
subsequent protected-human-inventory and initial-enrollment addendum. Changes
are confined to this lane's client, service, store and component-case files.
The shared API, assembly, helper, lifecycle, identity and runner sources remain
their owners' work.

The changes below are source implementation. The permitted checks in this
round are static checks on macOS. Unit tests, mutation reds/candidates, actual
helper execution and installed launch/restart acceptance must run on the
supervisor's disposable Linux machine. An authenticated AI-service session is
not exercised by the component fixtures.

## Per-item implementation

| Item | Store/service behavior and deciding evidence |
| --- | --- |
| ReserveLaunch | Uses the existing reservation, exact receipt and single writer. Issues child/reservation/launch/spec/grant-set IDs; consumes the bound root ticket once, or derives the authentic parent event and D9 chain. Reserves the name before a Lane exists. Commits the original private launch_request bytes, reserved plan, immutable pending public reply and one PlanLaunch effect together. Exact duplicates and restart reuse those IDs. Foreign operations, changed frames/digests, used/foreign tickets, stale policy/grant ceilings and occupied names refuse. |
| Retained lives | Resume/turn require the old life/run/generation, complete retained recovery, unchanged private home/session/workspace identity, current life-owned grants, bounded remaining budget and an independently retained helper end matching lane.ended. Run/launch IDs advance under the same writer. Counters and starter edges remain intact. Grant revalidation may narrow the retained set under grant CAS; it cannot replace its identity or widen its scope. |
| Continue | ClaimContinuation reads the actual current swap effect, claimant, expiry, durable intent, epoch, eligibility, slot, room, private session and primary capture. ReserveLaunch with ContinuationID retains the canonical bytes of that real typed internal claim input; it does not manufacture a public human frame. The reservation keeps the genuine service/scheduler/watchdog requester and logical turn. No paid fallback or budget reset is selected. |
| LaunchPlan / Transact | Private reads reload retained bytes. Updates require the original reservation/cause/requester, actual current claim, revision CAS and cancellation fence, including the reserved-life fence before Lane creation. Phases advance monotonically and prior inputs/plan/handoff remain immutable. Objects are retained before reference validation in the same transaction. Planned data requires the actual retained allocation and completed fixed import job, narrow selector input, output bytes, successful worker exit and zero survivors. Generic writes cannot mint PlanLaunch reservations or live capture events, and cannot advance an existing run without its reserved ready binding. |
| ClaimEffect / CompleteEffect | Reload the reservation and current policy/grants/epoch under the writer. Launch claims bind their claimant to the authentic execution scope. Completion rechecks claim ID/generation/expiry and correlates measured payloads. Successful PlanLaunch completion requires the retained opened plan and helper-reconciled process. Worker completion requires exact retained output and independently supplied successful quiescence. The original public pending reply is immutable; operation.get reports later measured state. |
| LaunchBinding | helper_prepare writes the complete ready Lane/Turn, installed lane endpoint, identity event and recovery tuple with phase bound. The store stamps the actual event ID/sequence and canonical record digest. Lookup validates the retained plan, exact request/spec bytes, home/capture/lease pins and committed identity event. Missing agent recovery refuses, including at reopen. Historical identity metadata alone cannot produce a new agent binding or permit. |
| CaptureState / AppendCapture | Registration retains explicit registered/refused status. Registered streams and one-use pipe IDs are unique; the fixed worker lease and narrow retained input match the reservation. Append authenticates the worker endpoint, producer lifetime and lease; checks sealed binding, actual private capture bytes/class/hash/length/source operation, epoch, contiguous offsets, EOF and CAS; derives primary record/event/acknowledgement. Exact range/hash replay precedes stale-revision rejection. Changed bytes conflict. Reopen reconstructs offsets/EOF from immutable events and verifies acknowledgements and retained bytes. |
| Service capture ingress | Server derives Scope from the live worker connection/frame and Authenticate. A supplied Scope actor is discarded and a body-supplied InternalIntent is refused. RetainCapture supplies the narrow bounded byte-upload half: service-issued object ID, derived capture class/ACL/original cause and exact bytes. It adds no public method or generic object authority. |
| LaunchControlSource | Handoff/Original load complete committed objects and original bytes. Prepare/Open/Observe/Stop/Abort/Release resolve durable stage claims and original requests. Binding reloads the complete recovery tuple. RecordRelease/RecordAbort complete only the exact original effect with the actual helper receipt. No context.Value authority label or mutable launch-ID map is used. Probe calls an independent installed-helper evidence port, never Launcher.Probe or Doctor. |
| Runtime/restart jobs | BindRuntime inventories all incomplete effects, including unexpired claims, and requires LaunchPlanner / helper / data-worker / launcher for planning. Launch readiness additionally requires the running launch/capture recovery job and a successful pass. Diagnostic binding without launch dependencies does not admit new launches. Recovery reads the same binding, calls ReconcileGate/ReconcileCapture on original IDs and retains actual observations/gaps. It never speculatively opens or allocates a replacement. Owner not_implemented failures propagate and leave the operation uncredited. |
| HumanEnrollments | Concrete protected startup/identity port has exactly HumanEnrollments(context.Context, string) ([]api.HumanEnrollment, error), matching assembly/software_auth.go in serve commit 58d70272. Reads every enrollment and credential, including revoked entries, retaining exact credential IDs, raw marker bytes, keys, algorithm, counters and generations. Wrong configuration, malformed/ambiguous inventory, cancellation and a closed store refuse. There is no public RPC or path/principal selector. |
| Initial admin_enroll | Transact accepts the fixed internal ceremony's absent baseline with one private service-origin artifact, actual public credentials and its matching blob.committed event. Evidence bytes/hash/length/ACL/source operation, principal/configuration and absent CAS commit together or none. A different second baseline refuses globally. Exact intent replay retains its commit. Later current-key changes keep identity's typed missing-ceremony barrier. InstallHumanEnrollment is the concrete convenience entry described below. |

## In-process wiring

The fixed initial ceremony must use the verified native administrator endpoint
and this concrete store port; a generic InternalAdminEnroll Transact does not
carry the private commit capability:

```go
InstallHumanEnrollment(context.Context, api.Scope, api.InternalIntent,
    api.EnrollmentInstall, api.ObjectWrite) (api.Commit, error)
```

The scope and intent must be the installed service's authenticated fixed
ceremony, with matching service actor/configuration and InternalAdminEnroll.
Initial ExpectedGeneration is zero and enrollment Generation is one. The
CeremonyEvidence reference must name the same transaction's nonempty bounded
artifact; Origin is service, ACL owner is that service actor, audience owner,
no life/participants, generation one. The entry verifies the native root helper
artifact/lifetime/frame, and the store rechecks that channel under its writer.
The retained identity handoff owns real attestation and hardware-presence
verification; component enrollment DTO fixtures do not establish those facts.

The outside capture channel can bind api.CaptureStore to Server. Its transport
Scope contains only the native ConnectionContext/FrameContext; AppendCapture's
incoming Intent is zero. For byte retention its narrow concrete port is:

```go
RetainCapture(context.Context, api.Scope, api.ID, []byte) (api.BlobRef, error)
```

The ID selects a retained capture binding. No caller supplies a class, object
ID, executable, path, ACL or original operation. Native channel construction,
the installed outside supervisor, protected spool and bounded stopping remain
admin/lifecycle assembly work, not a new public wire protocol in this slice.

The concrete store also supplies these service-only recovery ports. A hosted
store wrapper must forward them rather than dropping them behind StateStore:

```go
LaunchInventory(context.Context) ([]api.LaunchPlanRecord, error)
LaunchControlIntent(context.Context, api.InternalKind, api.ID) (api.InternalIntent, api.EffectRecord, error)
RetainedProcess(context.Context, api.ProcessHandle) (api.LaunchBindingRequest, error)
RecordLaunchObservation(context.Context, api.ID, api.LaunchReconciliation) error
RecordCaptureFailure(context.Context, api.CaptureBinding, *api.Error) error
```

Independent probe evidence is service.Dependencies.IsolationEvidence, or a
Helper implementing IsolationEvidence(context.Context)
(api.IsolationCapabilities, error). Missing evidence returns the admin-owned
typed dependency error. Do not wire the launcher back into this port.

## Tests and limits

The new store tests cover duplicate starts, retained exact replies, restart,
foreign reservations/tickets, policy/grants/claim expiry, CAS/epoch fences,
immutable plan replay, complete binding recovery, helper-observed completion,
retained runs, parent ancestry/D9, continuation claims, primary capture bytes,
offset/hash/revision/EOF/replay, foreign producer/lease and one-use pipes.
Enrollment tests cover actual generated public-key bytes, initial baseline,
atomic evidence refusal, replay/reopen and complete revoked-marker inventory.

Service tests use the real store for each reservation/plan/binding/byte lookup.
They cover every LaunchControlSource method, authenticated capture ingress,
independent probe selection, the real lifecycle stub's owning refusal,
LaunchPlanner/readiness gates and the actual recovery-loop entry. Helper
observations and transport identities are explicit component fixtures. They
do not claim actual kernel confinement, helper execution, Git materialization,
secret injection, hardware presence, physical pipe ownership or an agent run.
The fixture installs one primitive ticket only while the writer is closed;
it never seeds a lane, reservation, plan or binding for a positive launch test.
Corruption/expiry controls explicitly alter protected fixture state after
closing the writer.

Twenty-five new unchanged-test mutation controls are in mutations.py. The
complete inventory is 98 controls in both variants: 196 red/candidate pairs
and ten final package/tag suites. Source anchors and static compilation are
not runtime red credit. The actual Linux driver must retain run/fail with
the named assertion, then candidate run/pass for every control.

Outstanding owner contracts and installed dependencies are in CONTRACT-GAPS.
In particular, unknown helper allocation/release/abort outcomes, a missing
capture drain attestation after epoch change, unsupported vendor/input schemas
and unavailable real outside jobs retain explicit barriers. No unknown count
is converted into zero, no missing binding is treated as a legacy launch, and
no registered producer failure is converted into a refused registration.
