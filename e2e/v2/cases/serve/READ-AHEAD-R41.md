# Read-ahead on the committed run-40 tree, steps 42–78

Base: ce566a4. This is a static trace of the
installed-lifecycle catalog in scripts/v2-serve/lifecycle.py, called by
scripts/v2-serve/run.py:926. The evidence contains the 78-row catalog derived
from literal source data without importing or executing the harness on Mac.
“Fine” below means no additional unconditional source barrier found on that
row's supplied fixture path. It is not an installed or runtime pass. All Linux
regressions, red/candidate pairs and debug-box acceptance remain required.

## Fixed in this candidate

F1. ResolveRuntime returned the protected manifest's empty Bindings inventory
and its internal nonempty denied-network namespace lease. The Linux reader at
internal/v2/isolation/linux/control.go:120 requires exactly one run endpoint;
its validateNetwork also requires no egress lease for an offline spec. The
service-side administrator now validates the original helper manifest and
private namespace receipt exactly as before, then derives the same lane binding
used by the listener and mount producer. laneRuntimeProjection in
internal/v2/admin/runtime_resolve.go:89 adds that binding to the returned view
and returns a zero egress lease with a real empty EndpointIDs array. The pinned
manifest and helper-owned namespace remain unchanged. Both strict JSON readers
must preserve the complete returned DTO in TestLaneRuntimeProjection.

F2. startNativeGate supplied stdout/stderr but no stdin. The fixture at
cmd/laneboss/serve-fixture/main.go:224 requires nonempty bounded prompt bytes,
so a released fixture would read EOF and exit before its CLI identity call.
RegisterSpec now reads the exact committed private prompt through its existing
bound object view, with operation/life/reference/length/digest checks. Private
helper IPC streams bounded BlobChunk frames plus an exact end receipt rather
than placing a potentially 64-MiB object inside one 1-MiB frame. The helper
checks the active registered spec/cause, every range and chunk hash, actual
retained bytes, mode and all four immutable seals. It retains only a read-only
memfd and reopens an independent offset-zero input for the gate. The bootstrap
independently checks actual FD 0 against its sealed prompt reference before
attesting readiness. See internal/v2/admin/runner_prompt.go:70,
runner_prompt_linux.go:23, gate_linux.go:547 and bootstrap_linux.go:98.
The helper source remains CLOEXEC and closes during network/lease collection;
only standard stdin is forwarded. No extra inherited target, caller path,
frame limit or deadline is added. Multi-frame, corruption, actual child stdin,
offset, spec-identity and native endpoint regressions are prepared.

F3. scripts/v2-serve/lifecycle.py:155 sends the required empty review for
abandonment. The API strict DTO reader accepts that shape; wire's ordinary
Actor.kind and BlobRef.class enums refused its empty values. The contextual
case in internal/v2/client/wire/abandon.go:13 first applies the complete shared
strict DTO check, then permits only state=abandoned with the exactly empty
review. Accepted/merged states, positive review data, missing fields, unknown
fields, explicit nulls, duplicates and bad types retain their existing checks.
No review ID, reviewer or evidence is invented. TestAbandonEmptyReview reaches
both readers and a real typed request envelope.

F4. descriptorReferences treated every foreign NSFS descriptor as a retained
mount namespace. Network, PID and user namespace handles have the same fs type.
internal/v2/admin/collection_linux.go:205 now pins the actual inode and asks
NS_GET_NSTYPE. Only known non-mount families cease to set the mount-retention
flag. Wrong inodes, unreadable/unknown native types and every foreign mount
namespace still refuse collection. TestRetainedNamespaceKind uses actual
kernel descriptors and a real child; the existing mount-namespace refusal test
is unchanged. The remaining actual foreign-mount condition at line 305 is a
conservative gate, not permission to ignore or manufacture coverage. Whether
the installed host reaches it still needs a native observation/control.

F5. All five stale anchors are repaired. The two binding controls follow the
shared sealed reader's owned FD and parameterized socket comparison. The two
filesystem controls follow materialization_open_linux.go. Its nofollow control
substitutes a real kernel open that follows links while keeping the restricted
walker preflight, so redundant NO_SYMLINKS enforcement cannot turn the red into
a regular-control setup failure. The nonblocking control removes the actual
kernel flag. The endpoint-class control follows the effective connection class.
IDs, nominated tests and deciding failures are retained. No production source
in those filesystem/service areas was changed for the catalog repairs.

F6. Review found an error in the run-40 native regression: it invoked
startConfinedGate without a credential receiver, so it could not reach its
endpoint assertion. The test now requires that exact production refusal, then
uses the shared production endpoint composer and actual native gate for its
separate endpoint component canary. It still reads the sealed binding through
the actual installed CLI, pins the socket, measures the request after release
and requires CLI exit zero. It has no credential-projection or capture-approval
claim. The composed E2E must exercise those real owners. The existing append
control follows the extracted shared composer; its deciding request observation
is preserved. No production credential guard was bypassed or weakened.

## Exact findings for serve2b / composition owner

B1. After the launch effect completes, correct native observations have no
current claimed effect. lifecycle/control.go:163 always calls Launcher.Observe,
including LaneCheck, mark, archive and clean. service/launch_control.go:304
processClaim accepts only an unexpired, outcome-free claimed Launch, Stop or
HelperRelease effect. After completion it returns conflict, “process observation
has no current durable stage claim.” The ordinary human LaneCheck operation
does not create one of those effects. This blocks 45/49 and 69/73, and the same
observe prerequisite appears in mark/archive/clean. Provide a real current
authorized monitoring/control capability with retained process/native identity;
do not fake a claim, reuse a completed claim or omit observation. No lifecycle
or service launch-planning source is edited by this candidate.

B2. Installed composition never supplies store.Dependencies.CleanupNative:
assembly/assembly.go:76 constructs the store with Config, Directory, Enrollment
and Clock only. No later native binding setter exists in this tree.
store/owned_fail.go:113 therefore reports CleanupNativeReady=false, and
service/host.go:284 refuses the Clean effect with not_implemented,
“installed protected cleanup native ports.” Even without that preflight,
store/collection.go:123 returns not_implemented for the protected registry and
readbacks. admin.Service already implements ResolveCleanupWorkspace,
ReadWorkspaceRemoval and ReadCleanupWorkspace (admin/cleanup.go:170). Wire
these actual typed ports through the composition cycle before declaring native
readiness. A one-use late-bound forwarding capability is one possible route;
neither a true availability constant nor an empty cleanup result is a fix.
After wiring, the actual enrolled Git/workspace registry and unforced removal
must also be measured; private copied storage alone is not a Git receipt.

## Step-by-step trace

Every lifecycle CLI uses the registered adapter, service dispatcher, actual
identity/proof/session gate and owner handler. The shared registrations are in
assembly/registry.go:74 and assembly/assembly.go:250; lifecycle adapters are in
cli/commands_lifecycle.go. Rows sharing a driver follow the same native path.

| Step | Required row | Calls after planning / verdict |
| --- | --- | --- |
| 42 | human.claudock.ticket | Fine, source: human.py:155 → ticket.issue → identity TicketIssue/store; uses actual grants and simulated proof/ticket. No helper launch yet. |
| 43 | lane.claudock.inputs | Fine, source: lifecycle.py run → validate_initial_launch; protected input selectors and approved L5 driver/role/task. |
| 44 | lane.claudock.start | Fixed F1/F2/F6; planning remains for serve2b. lane.start → reservation/outbox → PlanLaunch → Linux Prepare → RegisterSpec/ResolveRuntime → PrepareIntent/listener → helper prepare/credential projection → commit identity → helper open/release. Arbitrary runtime bindings and unsupported network/data modes still refuse. |
| 45 | lane.claudock.running | For serve2b B1. status/read plus signed lane.check → lifecycle/control.go:195 → observe → service processClaim → helper ObserveGate. Released fixture also invokes actual identity.self through the two sealed projections. |
| 46 | lane.claudock.events | Fine, source: lifecycle.py events → event.tail → lifecycle/read.go:250/store pages; requires lane.created, identity.bound, lane.started for exact life/run. Depends on successful launch. |
| 47 | lane.claudock.reason | Fine, source: human.py:139 → blob begin/chunk/commit; actual task-class stop bytes, session proof and retry key. |
| 48 | lane.claudock.stop | Fine stage shape, depends on B1 for status/observation prerequisites: lifecycle/control.go:389 → committed Stop outbox → service Stop intent → Linux Stop/helper kill, credential fence/withdrawal and measured wait. No alternate kill route. |
| 49 | lane.claudock.quiescent | For serve2b B1; fixed namespace-family conflation F4. Repeated lane.check must measure exit/signal plus zero survivors; actual foreign-mount/reference uncertainty still refuses. |
| 50 | lane.claudock.abandon | Fixed F3; B1 remains an observe prerequisite. lane.mark → lifecycle/review.go:265; only abandonment is requested, with exact empty review. |
| 51 | lane.claudock.archive | For serve2b B1 prerequisite. Archive ports are present: lifecycle/archive.go:9 → store ReserveArchive → service/archive.go runArchive → real helper archive worker, authenticated input/parts/result, retirement and independent read-back. No missing-module claim; native acceptance pending. |
| 52 | lane.claudock.clean | For serve2b/composition B1/B2. lifecycle/archive.go:146 → Clean outbox → supportsEffect → store BeginCleanup → CleanupDataWorker/helper WorkspaceCollector → verified writer receipt. Missing native store binding is unconditional today. |
| 53 | lane.claudock.collected | Fine reader, dependent on B2: status must say cleaned=true and abandoned; event.tail must contain actual lane.cleaned. |
| 54 | human.codex.session.challenge | Fine, source: human.py:72 → human.challenge with exact read-session intent. Human endpoint, no lane containment lookup. |
| 55 | human.codex.session.confirm | Fine, source: real test authenticator signature/counter → human.confirm; simulated provenance required. |
| 56 | human.codex.grants.challenge | Fine, source: human.challenge for the exact root grant request. |
| 57 | human.codex.grants.confirm | Fine, source: human.confirm for that digest/counter; no caller-created grants. |
| 58 | human.codex.ticket.challenge | Fine, source: human.challenge for the separately issued Codex ticket. |
| 59 | human.codex.ticket.confirm | Fine, source: human.confirm binds principal/config/level/role/grants and current counter. |
| 60 | human.codex.read.challenge | Fine, source: fresh same-socket read session proof. |
| 61 | human.codex.read.confirm | Fine, source: real confirmation; read-session authority is not a control proof. |
| 62 | human.codex.control.challenge | Fine, source: exact lane-control intent/target/generation, through human.challenge. |
| 63 | human.codex.control.confirm | Fine, source: advancing authenticator counter and exact control digest. |
| 64 | human.codex.session | Fine, source: human.session on its actual installed socket, bounded session and simulated mark. |
| 65 | human.codex.grants | Fine, source: grants.root and actual current manifest/profile resolver; issued IDs are copied from the service response. |
| 66 | human.codex.ticket | Fine, source: ticket.issue; separate one-use ticket, same actual approved Codex/L5 scope. |
| 67 | lane.codex.inputs | Fine, source: same protected input checks as 43; first lane must already be collected. |
| 68 | lane.codex.start | Fixed F1/F2/F6; same native path as 44, with Codex plan/slot/environment. Planning fix is for serve2b. |
| 69 | lane.codex.running | For serve2b B1; same real status/check and fixture identity CLI path as 45. |
| 70 | lane.codex.events | Fine, source: same paginated committed-event checks as 46. |
| 71 | lane.codex.reason | Fine, source: same committed blob ceremony as 47. |
| 72 | lane.codex.stop | Fine stage shape, dependent on B1 prerequisites; same original stop intent, kernel collection and credential withdrawal as 48. |
| 73 | lane.codex.quiescent | For serve2b B1; fixed F4; genuine foreign mount/reference uncertainty remains a refusal. |
| 74 | lane.codex.abandon | Fixed F3; B1 remains an observe prerequisite. |
| 75 | lane.codex.archive | For serve2b B1 prerequisite; same implemented archive worker/parts/retirement/read-back path as 51. |
| 76 | lane.codex.clean | For serve2b/composition B1/B2; same protected native collector binding requirement as 52. |
| 77 | lane.codex.collected | Fine reader, dependent on actual B2 completion and lane.cleaned commit. |
| 78 | cleanup | Fine owned shutdown route, dependent on both collections: run.py:1004 → stop_owned → journal retention → named systemd units stop → MainPID=0, ExecMainStatus=0 and socket absence. service/host.go:200 cancels owned listeners/connections and requires actual worker/store drain. |

## Deadlines, capabilities and remaining native limits

No deadline is raised. Public request/client windows are 30 seconds
(service/server.go:332, client/client.go:353), admission is 5 seconds, helper
work/reply/call composition remains 13/1/15 seconds, native readiness is 3
seconds and credential exec is 5 seconds. Harness operation observation is 120
seconds; it does not extend an expired effect claim. Synchronous archive waits
inside its public request window while its actual worker/retirement may use an
owned deadline; completion time must be measured before any timeout policy
change. The 16-task and 60-second fixture budgets are preserved. They may stop
an actual Go fixture plus CLI if measured usage exceeds them; static inspection
does not establish that it happens on the debug box.

The helper unit already includes SYS_PTRACE and the required UID/mount/native
observer capabilities. No capability, ambient set, unit restriction, syscall
filter, namespace requirement, Landlock right or broad descriptor/path allowance
is added. The exact worker input/binding/socket projections and archive/data
native bridges are present in this merged source. Non-Linux native stubs,
deployment, review-verifier and channel publication stubs are outside these
fixture rows. They are not replaced with successes.

All native observations remain pending the supervisor's installed debug box.
presence=simulated; human_approval=not_proven. The vendor and authenticator are
declared fixtures, not authenticated AI-service or hardware-presence tests.
