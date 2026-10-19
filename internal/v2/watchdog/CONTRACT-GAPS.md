# Watchdog draft.4 consumer gaps

The current item-7 integration status and remaining native hooks are in
[`IT7-HANDOFF.md`](../../../e2e/v2/cases/watchdog/IT7-HANDOFF.md).
The draft notes below are historical; the service scheduler, real-store
watchdog reads and protected usage-provenance reader are now implemented.

The watchdog code uses draft.4 fix 11 merged from cf894d10.
No shared API, common CLI, composition or another lane's source is edited.
The following are requests to their owning lanes, not claims that a runtime
failure or security bypass has been measured on this authoring Mac.

## Independent human dashboard reader

Consumers: the E2E/controller owner, identity, dashboard, service/client and
watchdog case. Draft.4 requires dashboard.raw/dashboard.lifecycle to use an
authenticated human connection. The watchdog action caller is an authentic L6
lane so it can start/control its children. A binding file or human.session
proof cannot change that lane process's native UID/containment into a human
principal. The current subprocess invocations inherit their caller's identity.

The frozen harness control schema has only restart_service,
run_confined_canary and advance_fixture_clock. None defines an independently
authenticated human CLI-read invocation or a split-principal observation phase.
Please specify the harness-owned handoff, retaining exact request/source bytes,
artifact/config/life/run and nonce correlation, actual separate human peer,
fresh session proof and CLI stdout/stderr/exit. It must execute the installed
CLI's shared session/read path; no lane proof, transferred session ID or changed
socket permissions can replace that authority. No product swap RPC is needed.

The case's human_reads input preparation selects an absolute human binding and
fresh protected proof files, retaining their exact bytes. Its observer tests
only check the CLI arguments and file selection. This is insufficient to run
that CLI as a separate human principal. Until the shared handoff is specified
and the independent fixture supplies it, the installed dashboard portion is
unreached/failing, never a product or mutation pass. Capture assertions now use
service-origin capture.appended/capture.gap events from event.tail and the
exact blob.read bytes. The final dashboard assertion still requires the
separate human peer. Its forbidden/unauthenticated reply is retained as an
explicit missing-reader setup failure, never a red kill. Other reached runtime
failures, including unsupported/unavailable replies and missing or malformed
fields, remain reached failures.

## Exact cause of cancellation

Consumers: lifecycle, grants/service, watchdog and assembly. Cancel(context,
LifeRef) still carries no caller Scope/InternalIntent. Its watchdog marker
cannot reconstruct a manual stop/resume/revocation request/operation/principal.
Lifecycle must retain that actual cause in its own control transaction. If the
watchdog cancellation marker must carry the identical cause, coordinate an
internal cause argument in the shared API. The present marker uses watchdog as
actor/requester and leaves unavailable causal IDs empty; it fabricates none.

Lifecycle must cancel outstanding claims before replying to manual control.
Cancel returns without writing when no waiting/pending/claimed intent exists.
If manual control already advanced the life epoch and generation, watchdog
cancels the live intent under that fence without a second life bump. Lifecycle
must also leave profile_wait in that atomic control transaction. A direct
watchdog cancellation moves profile_wait to verifying; it never claims an
executing process exited, releases a slot, or changes a claimed next run.
An already advanced epoch still paired with profile_wait is refused as an
incomplete manual-control projection, rather than silently double-bumped or
reported as a successful cancellation that leaves a wait behind.

## Live turn and effective profile policy

The current TurnSnapshot.Status is free-form. The quota path admits running
and refuses terminal, empty or unknown statuses. Please freeze the live status
vocabulary across lifecycle and the watchdog before broadening it.

Contract request to integrate: require logical_turn_id on every lane.turn
event, including helper_open and mail_deliver emission paths. Lifecycle/service
must fill the actual retained logical-turn identity and run from trusted state;
ordinary Event.logical_turn_id may remain optional for other event kinds.
Freeze the requirement in v2-contracts.md and its kind-specific validation.
The current heuristic compares only nonempty IDs and cannot infer a missing
turn from sequence or run alone. Missing metadata grants no authority: current
turn/run/epoch checks, continuation CAS and lifecycle's atomic Swap checks remain
mandatory. This is a representation request, not a measured fail-open claim.

Store.Policy accepts Scope without an explicit target argument. The watchdog
keeps its own authenticated actor and supplies the current trusted LaunchID
and PolicyGeneration to read that life's effective profile exclusions. Please
confirm this target resolution for internal consumers; no lane identity is
borrowed to obtain the policy. Failed/mismatched policy reads refuse selection
and pending replay. Service scheduling must call Reconcile after the committed
watchdog.waiting deadline; the watchdog starts no scheduler.

## Implementation and acceptance dependencies

Outside usage requires an installed private provenance handoff. The shared
UsageWindowSource returns the normalized envelope, but does not return the
WorkerPrincipal or protected vendor-profile spelling needed by the two shared
validators. WorkerBinding itself requires actual installed endpoint/native peer
facts; watchdog must not reconstruct those from producer labels in the envelope.
Dependencies.ResolveUsage(ctx, scope, BlobRef) is the explicit local installation
binding to that real retained job/producer and protected enrollment read. It
returns UsageProvenance with the exact Evidence reference, Producer, VendorProfile,
Executable and RuntimeManifest. Missing binding refuses with the secrets owner's
not_implemented. Owners: secrets, identity/store and assembly. No native identity
or successful command is supplied by the component fixture.

ReadUsageWindow refresh must retain the actual normalized usage_window object
and exact usage_raw bytes privately. Its returned ID is looked up through the
existing ObjectMetadata port and its exact bytes must match the returned envelope.
The owner must provide that committed reference mapping, real private ACL/producer
ownership and current native/credential authorization. If that mapping is absent,
the read error remains a stopped dependency; watchdog guesses no object ID,
endpoint, peer, profile spelling or alternate TSV schema. Shared worker validation
is correlation, not a replacement for those actual native/store checks.

Lifecycle still owns the consumed-once continuation claim and persisted slot
handoff, current eligibility/grants/payment/exclusion checks, actual helper
quiescence/release receipt, launch and logical-turn mail completion. The service
owns restart reconciliation, dispatch freeze and current authority at commit.
These are implementation obligations under existing draft.4 ports. This
checkout still contains typed dependency stubs outside this lane. Component
tests of the submitted transactions and CLI-observer tests cannot satisfy the
installed serve case or the real slot/process/canary gates.

The former shared-operation/stamping request is answered by fix 10's “One
continuation operation” and api.ValidateContinuationOperation. It is adopted,
not an open gap: see CONTRACT.md. Store/lifecycle still must implement the
actual pending operation, same-operation claim/launch/reconciliation and the
retained launch/capture read ports. A typed stub cannot satisfy runtime gates.
