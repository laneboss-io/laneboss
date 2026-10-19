# Installed service owner requests

Run 35 follows green33's actual SIGKILL/EOF with unclassified setup stderr.
The creator thread now remains owned through actual primary exit, and failure
collection records before-stop facts plus actual helper signal results. Kernel
cgroup event/limit readbacks distinguish missing data from zero; setup stderr
has seventeen more closed operation families. Bounds, kill policy, unprivileged
bwrap and seccomp remain. See [the signal provenance handoff](SIGNAL-CAUSE.md)
for attribution limits, eight regressions, 33 controls and the green34 contract.

Run 34 follows green32's return to step 42 and its actual bwrap setup refusal
with option_unsupported. The native builder removes preserve-fds; both builders
use standard bind options with their same pinned proc-fd sources. New tests
compare actual production argv with real unprivileged vendor help and execute
a descriptor inheritance/closure canary. Primary pidfd exit is now independent
of stderr drain; an exceeded one-second acceptance window retains output and
the lease with a typed refusal. See [the current compatibility handoff](BWRAP-COMPAT.md)
for every option, each confinement owner, eleven controls and the green33 contract.

Run 33 follows green31's earlier admin.publication refusal: identity reports
an ended connector at publication-org-validate. Ordinary bootstrap-marker
mismatch returns without PID or descriptor changes. The candidate restarts
only interrupted native liveness calls, still requires complete live checks,
and records the deciding operation for further refusal. The supplied log does
not identify its syscall/errno, so installed EINTR attribution is suspected.
The run-32 stderr writer's borrowed destination is replaced with a gate-owned
duplicate through final drain, with no WaitDelay truncation. New regressions
measure a real ordinary native peer and output continuing after readiness and
caller close. See [the peer/audit handoff](PEER-AND-AUDIT.md) for both source
findings, 11 controls, scope limits and green32's required return to step 42.

Run 32 follows green30's actual EOF and spawned-child exit 1 without a
bootstrap report. The supplied namespace receipts record restriction=0,
profile_action=not_needed and unchanged switches; source attachment and
userns grant match /usr/bin/bwrap. No missing-profile cause is established.
The candidate pins the descriptor reason route before bootstrap parsing,
uses distinct failure exits and retains bounded closed bwrap stderr facts.
All native authority/proof gates remain. See
[the exit-path handoff](BOOTSTRAP-EXIT.md) for the complete access inventory,
15 new controls, static results and green31 contract. Runtime qualification
and a specific cause repair remain pending that actual stderr observation.

Run 31 follows green29's confirmed capability fix: the helper has CAP_SETUID
and the child spawns, then closed readiness refuses with containment_unknown.
The supplied log does not identify the failing bootstrap step. The candidate
retains actual EOF/deadline/errno/truncation/token cases, the spawned child's
wait result and a closed bootstrap failure report; no speculative cause
repair or deadline increase is supplied. L6's startup rule now requires root
real/effective/saved UIDs and the exact permitted set from the single embedded
installer template. All 16 candidate vet configurations pass. Runtime controls
and the installed green30 result remain pending. See
[the readiness handoff](BOOTSTRAP-READINESS.md) for the end-to-end trace,
18 controls, source scope and required next measurement.

Run 30 locks in the measured CAP_SETUID fix from 4d73e6ea. On
lb-v2-capbisect1 (systemd 255.4-1ubuntu8.17, kernel 7.0.0-1014-aws), the full
helper property set loses permitted CAP_SETUID only until User or
NoNewPrivileges is removed; every other single-property removal retains the
loss, while individual properties with User=root retain the bit. The template
now uses default root with no User directive, preserving all hardening and
bounding capabilities. The helper now refuses at helper.before_accounts if
either permitted credential-drop capability is missing. The real-template,
startup and default-User regressions have eight new Go controls, for 329.
All 16 candidate vet configurations and serve Python compilation passed.
Linux reached-red/candidate and installed qualification remain pending.
See [the measured capability-loss handoff](CAP-SETUID-LOSS.md) for exact scope,
tests, deciding controls and the next installed-run contract: pass startup and
progress past lane.claudock.start, or report the actual next failure.

The following run-27 through run-29 diagnoses record the earlier evidence
boundary. Their open-cause statements are superseded by the measured bisect
and fix above; their unchanged native proof requirements still apply.

Run 28 retains green26's actual spawn EPERM and size-zero clone3 EINVAL.
The named log and adjacent retained inputs do not contain the helper-policy,
capability or kernel snapshot described in the brief; its path was requested.
The source already delegates cpu/memory/pids, moves the helper to control,
creates gates under separate lanes/ID leaves, and includes both credential-drop
capabilities. No missing Delegate or missing template capability was found.
Failure-only observations now carry actual calling-thread effective capability,
NNP/seccomp and pinned cgroup-state verdicts without exposing identifiers or
changing controls. No speculative unit, ambient capability or placement change
is supplied. See [the setup-facts handoff](GATE-SETUP-FACTS.md) for source facts,
regressions, the missing installed observation and the green27 contract.
That run's policy-repair question is resolved by the later scoped bisect above.

Run 27 traces green25's creation refusal to cmd.Start in both branches of
startInNetworkNamespace. The production constructor requires
clone3(CLONE_INTO_CGROUP), with CLONE_VM/CLONE_VFORK and optional CLONE_PIDFD;
its Go namespace flags are zero. This error precedes successful exec of bwrap,
its namespace/mount setup, the later pidfd_open and bootstrap Landlock/seccomp.
At that point the retained log had no errno or effective helper-policy
observation, so the cause could not yet be selected from that log alone. Both
branches now retain a fixed safe spawn errno and a noncreating size-zero
clone3 entry observation. No unit, kernel switch, confinement gate or installer
setting changes. See [the creation diagnosis](GATE-CREATION.md) for the exact
source trace, regressions, required installed observations and green26 contract.
The 16 candidate static vet configurations passed; Linux red/candidate and
installed qualification remain pending.

Run 26 follows LB-275: the helper retains RestrictSUIDSGID=yes. The pin now
uses a descriptor-relative component walk only after ENOSYS or EPERM from its
strict initial openat2. Forced-error tests exercise real nested/link/escape
fixtures and final metadata checks; the intermediate O_NOFOLLOW control must
reach its forced-fallback assertion. Safe errno categories remain. See
[the current native mount handoff](NATIVE-MOUNT-UNIT.md) for all cross-lane
files, test failure conditions, remaining direct-syscall gates and green25
expectations. The run-25 unit-policy proposal below is superseded. No green24
result or native runtime pass is claimed by this source change.

Run 25 traces green23's native mount refusal to the strict openat2 pin of
installed runtime files during the G5 probe, before lane workspace/home or
data-worker mounts. The installer already copies those ordinary protected
sources. The helper template's RestrictSUIDSGID policy conflicts with the
required syscall; the candidate corrects that template while retaining every
pin/metadata/digest/proof check and adding safe errno categories. The old log
contains no errno, so the installed test must confirm this source diagnosis.
See [the native mount handoff](NATIVE-MOUNT-UNIT.md) for all cross-lane files,
the policy tradeoff, regressions and required green24 observations. Static
checks passed; native qualification remains pending.

Run 24 traces green22's invalid object ID to the root grant producer's omitted
grants.issued Event.ID. It now mints that ID with the existing grants helper;
the profile identifiers and strict validators are unchanged. The in-progress
administrator 2f5f91f integration retains the real guarded Server.Probe and
constructor dependency wiring, removes obsolete stubs and adapts the exact
probe regression/control. The administrator provider and worker handoff bytes
remain untouched. See [the two-item handoff](ROOT-EVENT-AND-ISOLATION-MERGE.md)
for every cross-lane file, regression, static result and required green23
observation. The source conflicts are resolved; index stages and merge
conclusion remain with the supervisor. Runtime qualification is pending.

Run 23 traces green21's root-profile not_found to omitted protected enrollment.
The executable-only fixture.enrollment row never called InstallProfile; the
enrollment and grants keys/backend were already the same. The tagged installed
assembly now binds the real installer to native initial publication, which
retains unavailable service evidence and installs both exact encrypted profile
records before returning success. Store audience authority and the private
reference codec are composed without public upload authority. See
[the enrollment trace](PROFILE-ENROLLMENT.md) for every cross-lane file,
regression, retry behavior, static result and required green22 observation.
Runtime red/candidate and installed qualification remain pending.

Run 22 makes the installed policy/source callback acyclic: assembly calls the
merged templates.ValidateSources source-only gate, preserving the callback,
binding refusal and full retained source/derived byte checks. The generation-one
read-through now reaches the merged store.Source, whose SelectSource calls
checkSnapshot. templates/approved.go:130 unconditionally rejects empty Derived
before fix 13's generation-aware gate, so the next expected error is the
templates-owned integrity refusal. See [the callback trace](ORG-VALIDATION-CALLBACK.md)
for the exact route, separate owner correction and required green21 evidence.
Green20's runtime result is not claimed here.

Run 21 traces green19's remaining selector failure to policy.approvedSources,
whose empty OrgSnapshotRequest survived after the templates selectors landed.
It now selects ID(scope.Config) and the common generation in the real stored
policy's SourceRefs, preserving the distinction from policy generation and all
store/validator gates. See [the selector trace](ORG-SNAPSHOT-SELECTORS.md) for
the cross-lane policy file list, generation-one Derived analysis, regressions
and required green20 results. The next expected refusal is store.Source;
the later full-validation callback cycle also remains an owner request.
No templates G8 source is changed and no runtime validation pass is credited.

Run 20 composes the merged identity G1/G4 work with the real store/dispatcher.
The protected ReadSessionCommit loads and independently checks the durable
receipt, initial session, current enrollment and consumed proof in one snapshot.
Dispatch finalizes every successful session receipt and preserves post-commit
finalization failures. The root-start harness now retains its request/key and
passes a fresh --session-proof to the merged same-socket CLI prelude. The two
merged test compile failures are repaired against HelperControl and EffectState.
See [the G1/G4 integration](SESSION-FINALIZATION.md) for the cross-lane file list,
controls, static results and required green18 observations. Runtime qualification
is pending; G3 and its assembly integration remain separate owner work.

Run 19 addresses green16b's next blocker, human.read.confirm. Identity proposed
a consumed challenge without advancing its stored revision, while the store
correctly requires prior.Generation+1. The authorized cross-lane producer fix,
signed-handoff regression, store CAS controls and registered omission control
are described in [the confirmation trace](HUMAN-CONFIRM-GENERATION.md). All ten
static vet configurations passed; runtime red/pass qualification and installed
acceptance remain pending for green17. The ceremony sequence is unchanged.

Run 18 attributes green15's first `human.read.challenge` refusal to identity's
emitted `Event.origin=cli`, copied from `Scope.Source`, rather than the valid
`HumanChallengeRequest.method=human.session`. The producer now uses service
origin as the event contract requires. See [the enum trace](HUMAN-CHALLENGE-ENUM.md)
for the measured error, exact source path, evidence limits and required green16
observations. G1/G4, G3 and G2 remain their owners' separate work. The existing
78-row run-16 prewalk below remains a static inventory, not a runtime result.

Current prewalk source is 179f3f0, with run-16 harness assertions. PREWALK.md
contains every one of the 78 lifecycle catalog steps; PREWALK.json contains
structured references and predicted refusals. Source-ready is conditional source
readiness, never a runtime pass. Blocked names a source-derived refusal after
prior gates. Unknown remains unmeasured. Shared proof rows can execute earlier
than their catalog position, including during admin.publication.

## Run 16 dispatch order

These requests are ordered by the earliest affected catalog step, not by which
owner must wait for another installed run. G1-G11 can be dispatched in parallel
with their stated dependencies. No owner message, test, authentication or real
model request was sent by this static prewalk.
Package-relative paths below are under internal/v2. Bare run.py/lifecycle.py
paths are under scripts/v2-serve; full paths and incoming revisions are explicit.

### G0. Steps 21-22: publication and exact retry, lb-v2-service

The supplied brief says the quadratic read-back repair is being landed. This
run did not change the store or wait for that work. Preserve its real persisted
byte verification, ten-second work limit, timing retention and exact receipt
replay. The earlier measured-size/source gap is retained below. The incoming
fix still needs its installed result; neither the prewalk nor a typed receipt
without complete read-backs credits this step.

### G1. Step 23 first public read; steps 26, 40 and 64 sessions: identity and service

internal/v2/identity/human.go:262 calls Store.ReadSession on the newly committed
session before line 275 calls BindReadAuthority. The store method at
internal/v2/store/contract_stubs.go:103 already calls connection.ReadAuthority.
internal/v2/service/connection.go:96 therefore returns lb-v2-service,
unauthenticated, exactly "connection has no current read authority". No other
production caller binds it earlier. HumanPolicyGeneration in identity/binding.go:
72 solves initial authentication but does not solve this session read-back cycle.
admin.publication already hits the cycle through HumanRoot.read's CLI prelude.

Also preserve the post-commit boundary: identity's session transaction can be
durable before binding fails. service/dispatch_mutation.go:119-124 attempts to
retain the handler error and then reloads the receipt; store/transaction.go:47-72
replays the existing successful commit. A standalone CLI may return a real
session receipt without proving connection usability. The harness now retains
its existing receipt checks and additionally requires an actual session prelude
and identity.self on the same fresh CLI socket, with a separate new proof.
That read is expected to expose the refusal above rather than credit the receipt.

Provide a private identity-only read-back/finalization path for the exact new
same-connection session, with independent durable principal/credential/endpoint/
expiry/proof binding checks before the one-use authority bind. Preserve strict
public ReadSession and refresh/CAS checks. A committed receipt must not stand
in for finalizing that connection. Add a native same-socket success and a stale/
foreign-session refusal control; do not bind from caller-supplied session labels.

### G2. Step 23 full org validation: templates, policy, integrate, service and admin

The harness now invokes the real org.validate using the actual committed
receipt's generation and requires exactly valid=true and an empty problems
array before admin.publication can pass. It does not relabel source kinds.

1. templates/stub.go:193 supplies an empty OrgSnapshotRequest. Store
   contract_stubs.go:127 returns lb-v2-service invalid_request, exactly
   "org snapshot requires this configuration and an exact generation".
   templates/approved.go:184 supplies OrgID but omits Generation as well.
   Pass ID(scope.Config)/request.Generation and the complete provided.Snapshot
   selectors respectively. The fixture's public request already supplies its
   exact generation; it cannot fix missing fields inside the owner implementation.
2. After that repair, templates/stub.go:201 calls Policy.ConfigValidate;
   policy/service.go:359 invokes ValidateSources; assembly/assembly.go:164
   calls the same briefings.OrgValidate again. This is a source recursion, not
   an observed timeout or a known successful validation. Supply an acyclic full
   source/policy validator dependency, preserving complete gates. The narrow
   initial validator is not a substitute for full validation.
3. templates/approved.go:139 requires Kind=file in both arrays. The canonical
   rule in integrate 39ac09e/fd1ab1a is semantic Sources (prompt, drivers,
   policy, source, task), structural Derived=file, and structural manifest-tree
   entries=file. The current full gate would return lb-v2-templates integrity:
   "approved source inventory has invalid kind, mode, digest or revision generation".
   Split the kind check and preserve every content, path, mode, renderer,
   ownership, digest and revision gate; do not accept file as alternate Sources.
4. fd1ab1a:internal/v2/api/org_snapshot.go:7 additionally requires nonempty
   Derived. The current templates/initial.go:19 requires empty Derived, and
   scripts/v2-serve/bundle/main.go:215 intentionally emits that initial shape.
   Admin/templates must coordinate initial publication of a real generated
   derived inventory and ownership manifest; then serve2 can supply and pin its
   actual bytes. Adding a placeholder or converting semantic source kinds
   would break one side or weaken the requested validation.
5. Full source validation later calls Store.Source at templates/org.go:99.
   store/contract_stubs.go:149 returns lb-v2-service not_implemented,
   "store.Source is not implemented". Preserve authorized exact SourceRef-to-
   committed-content lookup and current publication binding when implementing it.

### G3. Steps 41 and 65 root grants: lb-v2-grants and protected enrollment owners

The approved fixture manifest includes both drivers' profile selectors. In
internal/v2/grants/root.go:13-14, any nonempty Profiles collection returns
lb-v2-grants not_implemented, exactly "root enrolled capability handles require
the protected enrollment resolver is not implemented". GrantsRoot first checks
the actual human proof, immutable manifest and current scope. Implement that
protected resolver with the administrator/secrets profile enrollment; removing
profiles would invalidate the launch being tested. The fixture has no real
vendor credentials or account authorization, and no profile lease may be invented.

Ticket issue itself has a real durable implementation in identity/human.go:185;
its challenge/confirm and receipt checks can proceed only after real root grants.

### G4. Steps 44 and 68 fresh root start: common CLI, identity, lifecycle and service

lifecycle.py:209 sends lane.start in a fresh CLI with a ticket and no same-socket
session prelude. lifecycle/launch.go:57 reads Policy under that human scope.
Store readScope at store/snapshot.go:118 has no operation proof or bound read
authority, so service/connection.go:96 predicts the same lb-v2-service
unauthenticated message as G1. This assumes the normal healthy launch-admission
prerequisite has passed; otherwise dispatch_mutation.go:61 refuses readiness first.

A harness --proof substitution is not a valid fix: cli/cli.go:392 treats this
spawn mutation's supplied proof as an envelope proof, and identity/service.go:
265 rejects it with forbidden "operation does not accept an envelope proof".
Coordinate an explicit same-connection session prelude or a narrowly authorized
ticket-bound preflight read contract. Preserve the separate one-use root ticket
and proof meanings. Serve2 will then pass only the real fresh proof through the
supported CLI route; it will not borrow the closed human.session CLI's socket.

### G5. Steps 44-45 and 68-69 probe: lb-v2-admin, Linux and assembly owners

After G4, LaneStart's launchAvailability reaches Launcher.Probe. Assembly binds
service.Server as Linux Controls at assembly/platform_linux.go:19. Server.Probe
at service/launch_control.go:445-449 has no IsolationEvidence dependency and
admin.Service implements no such provider, so it returns lb-v2-admin
not_implemented: "independent installed helper isolation evidence is not implemented".
isolation/linux/service.go:456-479 requires actual independent retained boundary evidence,
not merely helper availability. Admin's probe_linux.go:57 also declares egress
handoff unimplemented. Provide measured owner evidence and wire that real port;
mapping helper checks to constant available values is not permitted.

### G6. Planning before running: lb-v2-admin, dataworker, identity and service

PlanLaunch sources, allocates and materializes before runnerPlan. Even the
credential-free materialization worker reaches admin/gate_linux.go:393:
lb-v2-admin not_implemented, "worker input and endpoint descriptors require the
fixed worker handoff is not implemented". Fixed immutable input/endpoint/native
worker bindings must be supplied, not replaced by an in-process copy. The
identity worker BindLaunch path at identity/service.go:326 also lacks its retained
fixed-worker/native-lease handoff. These are downstream of source/claim checks,
not reasons to skip materialization, worker observations or committed results.

### G7. Planning profile selection: lb-v2-grants and lifecycle

The harness binds only an actual root member ID at run.py:503. Grants derives
new reservation-bound members at grants/launch.go:187 and grants/subset.go:154.
Lifecycle retains the original request's ProfileGrantID at plan_input.go:74,
but plan_runner.go:184 compares it directly with the child profile ID. Once
preceding gates succeed, the mismatch predicts lb-v2-lifecycle forbidden,
"launch profile is not delegated" (plan_runner.go:192). Resolve the original
approved selector to its exact issued member under the protected reservation.
The harness cannot predict a not-yet-created reservation ID or fabricate that
member. Preserve driver/profile identity, scope, expiry and grant-ceiling checks.

### G8. Planning briefing/guidance: lb-v2-service and templates

runnerPlan calls prompt before acquiring credentials; plan_runner.go:112 enters
the real BriefRender. templates/stub.go:89 first calls Store.BriefingInput;
store/contract_stubs.go:154 returns lb-v2-service not_implemented,
"store.BriefingInput is not implemented". TemplateSources at line 144 and Source
at line 149 are also explicit unimplemented ports. Implement reserved/current
life, original task, policy, grant and exact source selection. G2's complete
snapshot selectors/kinds still apply. The later GuidanceSelect path is real,
but its own current turn, candidate snapshot and measured judgment gates remain
required; no empty or unavailable success is inserted by assembly or the fixture.

### G9. Native agent/capture after planning: admin, service, secrets and identity

Agent Prepare requires real credential projection. store/credential_stubs.go:
17-33 and admin/credential_stubs.go:13-33 retain owning not_implemented ports.
admin/gate_linux.go:366 refuses a nonempty slot/injection with lb-v2-admin
not_implemented, "credential projection requires its protected descriptor owner
is not implemented"; line 376 similarly refuses unresolved endpoint projections.
Keep slots, descriptors, grants, exact transfer and withdrawal receipts real.

admin/launch_capture.go:209 creates a refused binding with the underlying
lb-v2-admin not_implemented operation "fixed outside capture supervisor descriptor
handoff". The fixture's policy does not approve capture refusal; api/
capture_validation.go:61 refuses that path with invalid_request "capture refusal
is not enabled by current D6 policy" before an allowed-refusal launch can pass.
Provide the real capture producer/descriptor and retain exact stream/EOF and
recovery evidence. The fixture runner's SessionFromCapture/LimitFromCapture also
remain explicit unimplemented consumers of attested capture bytes; no stub result
is credited here. First running/terminal observations remain unknown until these
owners' native implementations execute.

### G10. Steps 51 and 75 archive: lb-v2-lifecycle and dataworker

After genuine zero-survivor quiescence, lifecycle/archive.go:40 returns
lb-v2-lifecycle not_implemented, exactly "durable quiescent archive worker intent
is not implemented". Supply the durable fenced archive worker, immutable
manifest, actual archive hash and independent read-back receipt. The harness
keeps this required step; process exit is not an archive receipt.

### G11. Steps 52-53 and 76-77 clean/collected: grants, lifecycle and dataworker

Even with a real verified archive, lifecycle/archive.go:127 returns lb-v2-grants
not_implemented: "owned data removal and retained-object receipt is not implemented".
Implement authorized owned-object/workspace/branch collection and retained
completion under the actual lifecycle intent. Launcher process-lease collection
cannot substitute for workspace removal or lane.cleaned. The harness requests
abandoned only, retains exact proofs and refuses alternate cleanup after an
authority refusal. No positive acceptance/review or Git merge is fabricated.

### Incoming lifecycle review

894a31f changes plan_claim.go, plan_stage.go, plan_fail.go, credential projection
lookup, replay/history and collection/revocation checks. It preserves the
LaneStart public handler and reservation path. c43d622 changes tests/catalogs
only. The retained diffs show neither removes the G1-G11 blockers. These
commits are reviewed incoming code, not a claim that this lane merged them or
ran their tests. Reconcile shared cleanup types with integrate fix 13 before
claiming an installed cleanup pass.

## Green13 CPU gap for lb-v2-service and lb-v2-admin

The retained green13 log reports the first admin.publish refusal as
deadline_exceeded owned by lb-v2-service at initial_publish, after 10602 ms.
Its publication_input has 21 objects, 30736922 total bytes and a largest object
of 26522426 bytes. Fourteen relevant files from the tested source archive match
the run's starting source byte for byte. The unit CPU observation is aggregate
service CPU, not a profile of a particular function; the exact slow stage is
still unmeasured. Commit state is unknown without the durable receipt/read-back.

There is a concrete quadratic read-back path in the service-owned store:

* internal/v2/admin/initial_commit.go:127 requests each object in at most 262144
  byte chunks. The existing public Blob bound is not changed.
* internal/v2/store/read.go:523 implements Blob; line 540 calls objectRow for
  every chunk, before selecting the requested range.
* internal/v2/store/objects.go:17 selects both metadata and the complete data
  column, and line 27 hashes all those bytes before returning any chunk.
* internal/v2/admin/initial_commit.go:197 first calls ObjectMetadata for that
  same object; ObjectMetadata also calls objectRow and discards the full bytes.

For the measured largest object, 102 Blob calls cause at least 2705287452 bytes
of full-object database transfer and hashing. Including its metadata lookup,
the count is 2731809878 bytes, before chunk copies/hashes and the final digest.
These are source-derived operation/byte counts using the retained input size,
not a measured profile or a claim that read-back was reached in green13.
Work scales as B * ceil(B / chunk), rather than B. No change to fixture size or
timeout can correct that algorithm.

lb-v2-service owns the required store fix, with an admin read-back adapter if
needed: provide a private, request-bound verified object read/view which loads
the actual persisted bytes and checks their metadata, ACL, identity, length and
whole-object digest once, then serves its bounded ranges without repeating the
full SQL read/hash. It must be tied to the existing native publication channel,
read lifetime and immutable object pin. Do not use pre-commit bundle bytes as
read-back, add a global authority cache, remove public Blob bounds, or omit the
final exact digest and receipt/event/operation checks. A counting control must
show linear persisted-byte reads, and corrupt persisted bytes/metadata must
still fail the deciding integrity assertion. This lane records that exact owner
gap rather than changing the store's public authorization/read contract.

Other real costs remain instrumented rather than guessed away. The installed
load validates the bundle and commitInitial deliberately validates it again.
Sealing and VerifyInitialTransaction serialize/hash the actual transaction,
and the store repeats the protected verification before Transact. Native channel
rechecks hash the protected installed artifact. The policy path resolves and
validates judge configuration; it does not execute a judge. Initial publication
does not enter authenticator attestation. The inspected store path uses SQLite
object bytes and SHA-256, with no per-object password KDF or encryption call to
retune. Do not remove the second validation, native rechecks or sealed-byte guard
without a separately proven immutable handoff and its mutation controls.

The service now journals only stage and actual elapsed_ms for native_context,
protected_read, load_validate, bundle_validate, object_hashes, policy_validate,
template_validate, revalidate, plan, seal, commit, read_object, read_back and total.
The fixed stage prefix is initial_publish. These are monotonic wall durations;
parent stages include their nested child stages and must not be summed together.
Per-object reads carry no object IDs, paths, hashes or other input values. Sink
failure remains an error, including after commit, and cannot credit publication.

The harness keeps the exact service journal bytes, verifies their retained
read-back, and attaches parsed timing records with line, stdout path and hash to
the original failed step or cleanup. Report restoration preserves them. The
summary prints initial_timing records for both failed and successful runs.
Missing or malformed required timing fails collection; it cannot produce an
aggregate pass. A successful first publication requires every stage family in
the retained journal. The original RPC refusal keeps its owner/code.

Green14 must first establish which measured stage dominates. A dominant
read_object/read_back result selects the store gap above; a deadline in an
earlier stage means read-back amplification is not that run's first bottleneck.
The service work bound stays ten seconds, with no automatic retry after failure.

## Historical green11 relay gap, resolved by administrator d4fix17

The following source references describe 354e614, not the current relay.
The run-14 merge retained d4fix17's 10/12/13/14/15-second nested contract and
one-second refusal windows. Green13's service-owned typed timeout demonstrates
delivery of that refusal; the older request for a relay repair is resolved.

The retained green11 log has the original admin-owned unavailable refusal,
"helper frame receive failed", at line 81. Its service-unit journal, already
retained in the serve observation, is more specific: lines 146 and 147 contain
deadline_exceeded owned by lb-v2-service at initial_publish, followed by integrity
owned by lb-v2-admin at deadline. The request reached the service's publication
handler; a missing installed publish mode, initial request frame size or an
earlier socket/descriptor gate does not explain those observations. The exact
substage consuming the publication budget is unmeasured, and commit outcome is
unknown without the required receipt/read-back. No retry ran after the failure.

That historical call chain had competing lifetimes:

* internal/v2/admin/human_enrollment.go:352 gives the external ceremony call
  fifteen seconds. Its relay reads the daemon reply at enroll_linux.go:559.
* internal/v2/admin/helper_linux.go:173 imposes ten seconds and sets that deadline
  on both directions of the CLI socket at line 176. replyError at line 180 writes
  through the same expired deadline, without a separate refusal-write window.
* The daemon's forwardEnrollment at internal/v2/admin/enroll_linux.go:601 creates
  a fifteen-second child of that ten-second context, so it cannot extend the
  parent's budget. Line 614 sets the resulting service-socket deadline; line 617
  closes that socket on cancellation. Line 630 waits for the service reply.
* The assembled service listener in internal/v2/service, file
  enrollment_listener.go:93, has its own ten-second work context. Before run 12,
  line 95 also closed the socket when that work context expired. The bounded
  writer later tried to renew its write deadline (now line 287), matching the
  retained deadline-field journal after the handler timeout.
* internal/v2/admin/peer_linux.go:187 maps every receive error to the same
  unavailable message, losing the distinction between timeout and EOF/closed.
  This function is used on both relay hops, so that surface message alone cannot
  identify which read failed first.

The serve adapter now separates its ten-second work context from an eleven-second
transport lifetime, preserving the existing one-second refusal-write window.
Parent shutdown still closes the connection immediately. No publication or
integrity check is skipped.
That local repair does not remove the administrator daemon's earlier deadline.
Please provide a coordinated bounded publication budget and refusal-write
contract across CLI, daemon and service. Preserve cancellation, native identity,
exact nonce/installation binding and complete read-back; do not solve this by an
unbounded call, omitted object verification or automatic retry. The helper must
preserve the actual receive category and retain value-free stage/code/owner
diagnostics when it cannot deliver a reply.

A source cost candidate also needs measurement: initialRead at
internal/v2/admin/initial_commit.go:106 reads each object in bounded chunks;
store.Blob at internal/v2/store/read.go:540 calls objectRow, which selects and
hashes the complete object at internal/v2/store/objects.go:17 and line 27. Large artifacts
therefore incur repeated full-object work during read-back. This is not proof
that read-back was green11's slow substage. Keep phase timing for load, validate,
commit and read-back before choosing the corrected budget. The harness now
retains actual command elapsed milliseconds and bundle object/byte counts.

The requested history comparison is complete. The 59b16ca..63578ba administrator
range changes initial_linux.go to use readProtectedMode with descriptor-bound
0444 checking, plus gate/revocation/recovery work and tests. It changes none of
enroll_linux.go, helper_linux.go, peer_linux.go, client_linux.go,
human_enrollment.go or initial_commit.go relative to 59b16ca. It does not fix
this relay deadline path. Compared with this lane's 354e614, the incoming branch
does not contain the later root-daemon relay integration and stronger initial
receipt bindings already present here. Preserve those additions during the
coordinated merge; replacing the files with the incoming versions would discard
the path on which green11 enrollment passed. This lane performed no merge.

## Green10 installer finding for lb-v2-admin

The retained green10 log on a282b26 reports admin.install exit 3 with the generic
protected-boot exception message. It does not identify a native fstat, immutable
mode, ownership, link, pin or pairing refusal. The tested source archive and this
base have identical administrator boot.py, initial_linux.go and files_linux.go.

There is a concrete data-flow defect in scripts/v2-admin/boot.py:482 on that
source: key holds the supplied 32-byte native data key. The required nonempty
initial-object loops at lines 566 and 623 then assign string object IDs to key.
Line 635 passes that string to put; publish's binary stream.write at line 161
requires bytes and raises TypeError. The generic exception handler at line 743
produces the observed message. No valid nonempty initial bundle can preserve
that old variable binding; changing IDs, modes or hashes cannot correct it.
The run-11 repair gives the native bytes a separate native_key binding through
the handle calculation and protected write. It changes no validator, file mode,
owner, link rule, path, digest algorithm or publication/boot pairing.

The bundle still uses a fresh protected /opt input directory, single-link
root-owned 0444 initial descriptors and objects, and exact byte pins. Pairing is
checked at boot.py:260, object digests at line 281, and native validation runs at
line 568 before installation. The harness now reads that command's actual exit
and result from protected evidence, requiring valid=true and the exact supplied
manifest/ID before admin.install can pass. A failed installer remains failed;
its actual native typed refusal is retained when available. A matching validator
result alone cannot make a later installer exception pass.

The administrator version boundary is now identified. In both
the tested and current source, internal/v2/admin/files_linux.go:78 uses fstat for
regular type, root owner, nonwritable mode, single link and size.
internal/v2/admin/initial_linux.go:167 calls that read, then line 173 checks 0444
with Lstat. The described d4fix15 descriptor-based 0444 check is absent from these
bytes. The incoming 7a93ee4 change, included in 63578ba, supplies the descriptor
check; its merge is owned by laneboss. This lane does not alter either check or
claim a proven security gap. No contradictory
permission or digest requirement has been demonstrated by the retained log.

The native-key writer defect is established by source flow; green10's generic
exception does not prove it was the first failing runtime instruction. Green11
retained matching native validation and passed install/check read-backs; that
regression is resolved in the measured run. Native key bytes remain excluded
from source, reports and evidence copies.

## Resolved integrate fix-13 rules

39ac09e and fd1ab1a resolve the former contract questions: Sources use semantic
prompt/drivers/policy/source/task kinds; Derived uses file and the full shared
gate requires a nonempty generated inventory. Manifest entries keep filesystem
file classification. Both OrgSnapshot selectors are mandatory and select the
current expected head in the authenticated configuration; omitted/zero selectors
are invalid_request and a different current generation is conflict. G2 lists
the still-conflicting callers/validators and the initial/full Derived boundary.
These are adoption gaps, not open policy choices. No harness-only kind
conversion or zero-selector fallback is authorized.

## Remaining installed handoffs

| Owner | Current boundary | Required handoff |
| --- | --- | --- |
| admin | Enrollment installation and helper IPC | Endpoint publication now uses explicit protected boot origin/RP policy and derived installation pins. CLI enrollment modes already existed; the service/store codec now matches the helper. No origin default, approval claim or synthetic receipt is supplied. Runtime acceptance remains pending. |
| admin and service | Private enrollment unit proof | The supervisor identified cross-user helper_executable denial. The CLI now goes through the installed root daemon, which verifies its mapped artifact and forwards only the fixed ceremony. The service checks native UID/PID/writer/lifetime, the sole fixed control PID, protected root socket and actual installed artifact bytes. Typed diagnostics remain; positive and negative Linux controls are pending. |
| serve | Enrollment helper input placement | Both ceremony requests now use exact retained copies under private protected /opt, instead of passing the evidence file below shared /var/tmp. Native metadata for the helper, configuration, requests and every ancestor is retained. Product checks and installer modes remain unchanged; Linux runtime acceptance is pending. |
| admin, serve and service | Protected first-install publication | Default mode now assembles the owned fixture bundle before installation; explicit --config/--boot remains supported unchanged. The standalone harness assembler uses real policy/source/launch/manifest validators and actual byte pins. Native publication, retry and exact durable read-backs remain mandatory. The relay and composed listener support initial_publish. Installed Linux acceptance of the new input remains pending. |
| identity | Registration credential selector | Real validated software registration now preserves the shared public software selector after the production-presence policy check. The signer uses that selector without guessing inventory. Hardware IDs and cryptographic verification remain unchanged. |
| service, identity and serve | First human-endpoint request and later rechecks | Private HumanPolicyGeneration removes the session-bootstrap cycle; CurrentConnectionScope preserves the original peer. The host sends an owned, correlated refusal before teardown and retains value-free stages. The harness captures actual caller/socket metadata without probing or retrying. Require Linux positive and refusal controls; the exact old native failure was not journaled. |
| grants and admin | Root capability/source/profile enrollment | The harness now supplies the fixture's committed root-manifest proposal and protected L5 project/profile/task inputs for both drivers, with empty secret/resource/network/channel grants. issueRoot still returns its owned not_implemented for profile handles without the protected resolver. Only real returned IDs can bind the default launch proposal. Grants/lifecycle must reconcile original root profile selectors with reservation-derived member IDs. |
| lb-v2-service and lb-v2-service-mat | LaunchDataStage, MaterializationStage, AwaitMaterialization, WorkerInput, WorkerResult and WorkerBinding | These methods are real after service 420237d. Require installed proof of the retained claim, confined native worker and measured result. Existing peer rechecks now use CurrentConnectionScope. No in-process substitute or interface-only runtime pass is credited. |
| admin and service | Opened launch data and native data worker | Administrator OpenLaunchDataStorage and the retained worker lease/register/prepare/open/measure flow are real after aba9611. Supply genuine service-owned stage, claim, grant and worker records to those strict ports. The prior administrator merge request is resolved in this base. |
| templates and service | Briefing methods and source reads | BriefRender and BriefStart are real after 7d498c5 and retain validated prompt bytes. Initial publication now supplies genuine retained source/task/policy inputs and OrgSnapshot reads its exact current projection. Store BriefingInput, TemplateSources and Source remain service-owned not_implemented ports. No default briefing or source is supplied. |
| templates, policy, service and admin | Adopt resolved fix-13 source-kind and exact selector rules | G2 gives the canonical split, mandatory selectors, validation dependency cycle and initial/full Derived conflict. The same published generation now goes through a required installed org.validate. No contract fallback or full-validation pass is supplied. |
| admin | Native credential and endpoint projections | The fixed native gate still lacks the protected credential descriptor owner, registered endpoint ownership, selected environment projection and fixed worker descriptor handoff. These four absent integrations now return admin-owned not_implemented. Network and export policy refusals retain their actual codes. No slot, path or environment claim authorizes a projection. |
| service and lifecycle | Pending mutation ownership and launch/capture/recovery | LaunchControlSource.Plan and the existing retained launch recovery methods are preserved through the concrete store wrapper. Missing dispatcher/review/capture ports remain actual failures. The fixture's capture interpretation, resume and turn still return named gaps; no lane transcript is process authority. |
| runner owners and assembly | Production vendor enrollment | Real Claudock/Codex constructors receive the current store, clock, source/storage, credential, usage and materialization ports where supported. Protected vendor pins, current operation/read views, callback bindings and independent compatibility receipts remain required. Startup binds the actual NewInstalled service; each operation still passes its strict runtime constructor/checks. No generic unavailable runner replaces a real implementation. |
| dashboard, migration and packaging | Operation implementations | Constructors now validate/store dependencies and register actual typed methods. Operations remain owner-named failures until their implementation lands. No zero-value constructor fallback is used. The earlier nonexistent dashboard fixture remains removed. |
| policy and assembly | Approved inference configuration | NewInstalled supports host startup and reads without inventing a cost ceiling. A fresh evaluation without approved configuration refuses at the operation boundary; strict policy.New remains unchanged. Bind actual approved cost data before inference, and use the real templates source validator. |
| lifecycle, dataworker and admin | Stop, archive and clean | Require the actual contained process, exact operation/CAS, known terminal zero survivors, verified archive/read-back and owned-object collection. The driver requests abandoned only and supplies no positive review. A refused control is not retried by another route. Unit shutdown alone cannot credit lane collection. |
| service and capture owners | Broader serve-state gate | Protected workspace/capture mapping, lost socket reply control, exact receipt/event/effect counts and restart recovery remain unavailable. These required rows remain FAIL/unrun. The old unready.owner label now requires a real judge configuration projection; not_implemented cannot pass it. |

The shared inventory check already runs in store.New before any listener.
The duplicate assembly guard was removed. Software signing and fixture execution
compile only with the dedicated E2E tag; fixture adapters also require the partial
tag and both declared driver enrollments. Every dependent row and aggregate report
retains presence=simulated and human_approval=not_proven.

These are owner requests, not fabricated typed errors. When an installed call
runs, report.json retains its actual owner, code, raw output path and failing step.
A forbidden, prerequisite, setup or compilation failure is never relabeled.
The summary validates the complete scope catalog independently of the report's
claimed required rows, rejects stored refusals and preserves the original failure
through cleanup. All unreached dependent steps remain FAIL.
The one-shot health-client repair is included from service 2a46490. Public health and
later harness commands use separate CLI processes; the ordinary CLI has no
automatic health preflight. Its same-socket read setup uses human.session.
