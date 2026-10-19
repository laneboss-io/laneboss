# Identity draft.4 fix 11 integration and serve handoff

## Installed G6/G9 identity adoption on b50be312

The complete 6cd128f7 serve request was inspected against this checkout before
editing. Its file/line references name another source revision. G6 was still
refused here; G9's identity consumer was already implemented. This is static
source adoption, not a measured installed run or native-worker acceptance.

G6 is implemented now on the identity side in worker_bind.go. BindLaunch has a
separate worker selector and always reloads its committed binding before deciding
the worker path. It does not apply the agent-only launch-plan validator to a
genuine worker. Worker request labels cannot select a different retained kind or
change any committed tuple. The worker actor is a separate job principal with
empty LifeID/level/role, matching the actual helper's validateWorkerRecord; target
life/run remain in WorkerLease rather than relabelling the worker as a lane.

The private constructor dependency is `identity.Dependencies.Workers
identity.WorkerLaunchSource`. Its AcquireWorkerLaunch(ctx, config, preparedID)
returns a live WorkerLaunchGuard, not a serializable success receipt. Authority
contains the exact retained binding, PreparedSpecHandoff and WorkerPrincipal.
The guard supplies the actual borrowed input/endpoint os.File handles and pinned
native bootstrap peer, rechecks the authenticated helper's allocation/gate, and
collects borrowed resources on Close. Identity independently reads the handles
with fstat/fcntl/ReadAt: anonymous regular 0444 objects, read-only access,
FD_CLOEXEC, complete write/grow/shrink/seal seals, bounded exact bytes and distinct
objects. Input bytes must match the retained object; the endpoint must decode
to the protected installed worker binding. No pathname or caller byte slice is
used to manufacture that observation. Non-Linux platforms retain an explicit
unsupported native-descriptor dependency rather than an empty success.

The frozen materialize argv, executable/version/artifact, input, runtime, grants,
spec/record digests, helper lease, endpoint, operation/request/claim and committed
identity event must agree. Identity compares current WorkerBinding, native peer
facts, live containment registry, claim, grants, policy and cancellation before
and after native verification; it reads the committed binding again before a
permit. Native/close/refusal errors return no permit. It calls no in-process
materializer or alternate worker implementation. Other worker kinds remain
explicit integration requests until their separate fixed bootstrap is frozen.

**G6 routing to lb-v2-admin, lb-v2-service/service-mat and assembly:** implement
the protected WorkerLaunchSource producer and wire it into identity.New. It must
resolve the already retained service/helper job and actual prepared gate; hold
the helper allocation/gate lock through the enclosing one-use OpenGate exec
acknowledgement; and return the exact live immutable input/endpoint duplicates
and native bootstrap lifetime used by that gate. Check must authenticate/recheck
that native handoff, never return a constant or copy a request's labels. A
serialized Authority is insufficient. The handles are borrowed until guard
Close, which must close/collect them on every path. Do not weaken descriptor
checks or replace a worker with a Go data-copy call to supply this capability.

The inspected remaining producers are admin/gate_linux.go startConfinedGate's
worker descriptor refusal, admin/worker_linux.go startDataGate's native worker
mount/gate path, and admin/data.go's retained dataJob/dataGate. The latter already
has protected Input/Endpoint/Prepared/PID fields but does not expose this private
guard to identity. The current store/fix11_stubs.go WorkerBinding and service/
fix11_stubs.go materialization/bootstrap methods remain owner-named stubs here,
even though the serve request reports newer service implementations elsewhere.
The installed dataworker/internal.go RunInternal still names its private native
principal/bootstrap/projected-root bridge as unavailable in this checkout.
Assembly must supply the protected producer; default Workers is nil and therefore
ordinary installed worker permit acquisition remains closed until that wiring.
The source report supplies exact current file:line locations for these routes.

G9's identity contract is already real in credential_stubs.go despite that
historical filename. AuthorizeCredentialProjection loads and copies the protected
reservation; compares complete request/targets/source versions, installed helper
and outside broker pins; validates live prepare claim, grants, policy and
cancellation; requires native VerifyCredentialProjection; and repeats protected
and peer reads afterward. CheckLaunchCredentials reloads the exact binding and
held projection, checks prepared-spec recovery and current state, then runs the
actual shared ValidateCredentialProjectionGate. Existing TestProjAuth/TestProjGate/
TestProjPermit and their omission controls remain unchanged and are supporting
consumer evidence, not installed credential delivery.

**G9 routing:** the actual native CredentialProjectionPeers verifier is not
implemented by this checkout's peer/linux.Verifier or its Darwin composition.
The existing identity port refuses exports without it. Admin/native-control and
the outside broker must authenticate both live private channels and remeasure
pinned executables, lifetimes, installation and boot; a numerical PID/path or a
metadata copy cannot satisfy it. Store/admin credential_stubs.go and the owned
descriptor/injection branches remain their owners' explicit prerequisites.
No credential value or synthetic receipt is introduced here. Already-real refers
to the identity consumer, not to the complete installed G9 path.

The human Origin service line was already present. Confirmation now increments
stored.Generation immediately after setting Consumed. TestConfirmRevision uses
real signed assertions at revisions 1 and 41 and checks the exact consumed
challenge, proof/counter/evidence handoff together. Kernel-backed descriptor
fixtures and metadata/peer projections are explicitly labelled. No runtime result
is inferred from compilation or static inspection. All 306 prior IDs remain;
two moved worker controls retain their selectors/diagnostics. Twenty controls
and two fixtures give 326 controls/105 fixtures (652/210 normal/faults rows).

Current source routes (line numbers name this candidate, not the prewalk):

| Request | Status and exact location | Owner / required next handoff |
| --- | --- | --- |
| G6 identity permit | Implemented now: internal/v2/identity/worker_bind.go:41; descriptor verification at worker_files_linux.go:52. | lb-v2-identity consumes the protected fixed materialize handoff. |
| G6 native producer | Routed: internal/v2/admin/gate_linux.go:393; native materialize gate at admin/worker_linux.go:61; retained record checks at admin/data.go:565. | lb-v2-admin must supply the live locked guard, actual projected handles and pinned bootstrap peer. |
| G6 durable stage / bootstrap | Routed: internal/v2/store/fix11_stubs.go:34; service/fix11_stubs.go:22, :28 and :31; dataworker/internal.go:27. | lb-v2-service / service-mat must supply current durable worker bindings and the genuine private worker bootstrap/result bridge. |
| G6 composition | Routed: internal/v2/assembly/assembly.go:110. | lb-v2-integrate / assembly wires only the protected WorkerLaunchSource producer. |
| G9 identity authorization | Already real: internal/v2/identity/credential_stubs.go:24 and :174. | lb-v2-identity retains complete consumer and gate checks. |
| G9 native channels | Routed: identity/credential_stubs.go:63; peer/linux/native_linux.go:31 currently constructs the ordinary verifier. | lb-v2-admin/native IPC and lb-v2-secrets must provide authenticated helper/broker channels and executable/lifetime pins, coordinated with identity's native adapter. |
| G9 durable/descriptor owners | Routed: internal/v2/store/credential_stubs.go:11 and :15; admin/credential_stubs.go:12 and :20. | lb-v2-service and lb-v2-admin / lb-v2-secrets must land reservation, held-descriptor projection and broker binding. |
| Human confirmation | Implemented now: internal/v2/identity/human.go:156. | lb-v2-identity advances the consumed revision; lb-v2-service retains its existing exact CAS. |
| Human event origin | Already real: internal/v2/identity/human.go:365. | Origin service is retained; no transport label substitutes for event trust. |

The guard must borrow the enclosing native OpenGate authority without a callback
cycle or second acquisition of the same helper lock. Guard Close collects its
borrowed resources; the enclosing helper retains the actual gate/allocation lock
and must recheck the permit through the one-use exec acknowledgement.

## G1/G4 round b continuation

This continuation keeps efd9e9b3 and the uncommitted G1/G4 candidate. The prior
failed catalog check is preserved in the earlier evidence, and the supervisor
explicitly authorized recovery. omit-bound-authority-id now anchors the complete
BindReadAuthority call. Its ID, test, diagnostic and connection-ID corruption
are unchanged; deriving the expected authority separately is no longer ambiguous.

The common CLI now implements `--session-proof FILE` for lane.start/lane.adopt.
Both separate and equals forms use the existing common option parser, with
duplicate/empty/foreign-method and simultaneous --proof refusal. The proof file
must describe the exact human.session intent. Invocation prepares that separate
request, reuses its one open client, checks the actual identity.self projection,
and only then sends the original spawn bytes with RootTicketID unchanged and
nil envelope Proof. Response correlation, normal request/input validation,
retained idempotency keys and connection ownership remain. A session receipt
whose connection cannot perform the read does not reach the spawn call.

Cross-lane files changed for this blocker are internal/v2/cli/cli.go (common
option and invocation), internal/v2/cli/commands_identity.go (proof preparation
and actual public-read prelude), internal/v2/cli/prelude_test.go (regressions),
and internal/v2/assembly/assembly.go (private capability wiring). Assembly takes
SessionReadback only from its already-constructed protected store. If the store
does not implement it, the dependency remains nil and identity refuses a session
before commit. No caller or public configuration can supply this capability.
The control harness adds only cli.go to its exact client-only mutation allowlist;
it still refuses arbitrary CLI files and incorrect package/kind combinations.

commitHuman now emits Origin `service`, matching the authoritative event contract
and serve2 71ab8f4. The authenticated Actor/RequestedBy and raw request frame
remain distinct from that trust origin. TestHumanEventSource exercises the actual
typed transaction and checks both the origin and requester; restoring scope.Source
must fail the named positive assertion before the store handoff.

The remaining service/store/lifecycle work is large in this checkout, whose
constructors and main operations are still owner-named stubs. Route these exact
items rather than assuming the installed implementation is present here:

- lb-v2-service/store must implement protected ReadSessionCommit over its actual
  durable receipt/session/enrollment/proof tables, with the coherent snapshot and
  independent checks described below. internal/v2/store/stub.go still has New,
  Transact and Policy stubs, and contract_stubs.go has LookupReceipt/ReadSession
  and proof lookup stubs. No database schema/transaction implementation exists
  here to extend with a small read-back patch. Do not copy the native fixture.
- lb-v2-service must consume FinalizeHumanSession on the actual dispatch success
  and replay paths. internal/v2/service/server.go still has NewServer/Register/
  Serve stubs. The prewalk's dispatch_mutation.go successful-receipt reload branch
  must preserve a post-commit finalization error and finalize every returned
  successful session receipt. The prewalk's connection.go must retain one-use
  binding and current public read/refresh checks. Those production files are not
  present in this checkout. The private identity hook is implemented here.
- lb-v2-lifecycle must land its genuine LaneStart/LaneAdopt and policy/grants/
  ticket transaction implementation; internal/v2/lifecycle/stub.go still returns
  not_implemented for New/LaneStart/LaneAdopt. Its production launch preflight
  must keep the original authenticated same-connection scope, not synthesize it
  from ticket labels, and retain the existing atomic one-use TicketUse guard.
- The lifecycle CLI owner must supply its actual StartRequest/AdoptRequest input
  validators through RegisterInputValidator. The current commands_lifecycle.go
  ergonomic functions are also stubs. Common `--request` deliberately continues
  to refuse a missing feature validator; the new flag does not bypass it. The
  installed branch that already reaches lifecycle policy can consume this common
  CLI change with its existing real validator, while this stub checkout cannot
  claim an installed root start. Serve2 should pass a fresh session proof through
  the new option with its existing exact request file and retained spawn key.

The current catalog has 306 controls and 103 fixtures (612/206 normal/faults
rows). It retains every prior ID and diagnostic; only the authorized old binding
anchor changed. Linux runtime qualification, composed G1/G4 installed canaries
and independent review remain required after the routed implementations land.

## Installed requests G1 and G4: session finalization

This round starts at efd9e9b3 and consumes G1/G4 from the complete installed
serve requests at 27ab7f19. Their reported read-authority cycle is a static
prewalk finding, not an installed result measured here. This checkout retains
store/service stubs in several of the cited production locations. The identity
consumer is implemented here; the real store and dispatcher wiring below must
be routed to their owners before claiming installed success.

G1 replaces the first public ReadSession call with the constructor-only
`identity.Dependencies.Sessions identity.SessionReadback` capability. Its sole
method is `ReadSessionCommit(context.Context, api.Scope) (identity.SessionCommit,
error)`. The scope must be the original authenticated human.session frame;
there is no session-ID input, new RPC, session-label authorization or general
read-authority grant. Missing capability refuses before the session transaction.
Public ReadSession and refresh/CAS paths remain strict and unchanged.

**Request to lb-v2-service/store and assembly:** supply a protected identity-only
adapter at construction. Under one store read lock/snapshot, resolve the actual
request key from the verified frame and load the persisted MutationReceipt,
current StoredReadSession selected by its typed reply, current HumanEnrollment
for the protected endpoint principal, and original VerifiedHumanProof with its
actual ConsumedBy operation. Return owned snapshot bytes. Verify native endpoint,
principal/configuration and identity-component access without calling the public
ReadSession/connection.ReadAuthority gate that this path must establish. Do not
project these facts from the proposed write, a caller label or receipt alone.
Release the store lock before identity calls transport; never call transport
from inside that lock. No other module receives this private capability.

Identity independently checks the exact request key/raw frame, receipt actor,
configuration/policy, completed operation/reply and commit sequences/time; the
initial session revision and bounded absolute/idle deadlines; current principal,
credential and presence provenance; and the exact proof/target/digest/evidence
binding with ConsumedBy equal to that operation. Proof lifetime is checked at
the retained commit instant, not renewed during finalization. The stored session
must still match this live connection, principal, credential and endpoint and
be unrevoked/unexpired. Only then does identity call the one-use bind and read
back the actual transport authority. False transport success closes the socket.
An exact already-bound initial authority may be finalized again without rebinding.
A refreshed/stale initial revision or a foreign socket cannot activate a receipt.

**Request to lb-v2-service dispatch:** consume the private
`FinalizeHumanSession(context.Context, api.Scope) (api.HumanSession, error)` hook
on successful human.session receipt replay, before reporting connection success.
The ordinary handler already finalizes after commit and compares the read-back
reply with its completed reply. Keep the successful durable mutation receipt
immutable if finalization fails, but return that finalization error to this call.
Do not retain/reload an existing successful receipt over the post-commit bind
error. A receipt proves the mutation committed; it does not prove this socket
is usable. A new socket needs a new session proof/request key, not borrowed
authority from an old human.session CLI process. Exact replay finalization here
requires the retained raw request bytes, including correlation fields. Route any
broader retry-correlation policy through integration rather than fabricating them.

G4 chooses an **explicit same-connection session prelude**, rather than giving a
ticket read authority. Identity now requires and refreshes the live read session
for human spawn authorization, while preserving the prohibition on envelope
proofs for lane.start/lane.adopt. A ticket by itself gives no read authority and
is not inspected or consumed by this preflight. The eventual lifecycle atomic
TicketUse remains the separate one-use root-launch guard.

**Common CLI implementation, completed in round b:** `--session-proof FILE` is
implemented for human lane.start/lane.adopt. Parse a real ProofRef for the exact human.session `{}` intent;
prepare a separate human.session request/key, call it on the same open RPC client,
validate its response, then call identity.self on that socket and require the
actual authenticated projection before sending the unchanged spawn request.
Keep RootTicketID in the spawn body and leave its envelope Proof nil. Do not
reinterpret a lane.start proof as a session proof, move the ticket into Proof,
borrow a closed CLI socket, or make the harness's current --proof substitution
look supported. Preserve exact request files, correlation, idempotency, response
validation and connection cleanup. Reject incompatible proof options. The
existing common session-prelude implementation can supply the connection reuse
and separate session request; its current mutation-proof classification needs
this explicit option. Round b adds it while preserving the feature-owned input
validator requirement and the larger composition requests above.

**Request to lifecycle/service:** run original-scope policy/grant preflight only
after the authenticated prelude has established current read authority. Populate
any internal read snapshot through the actual connection, not the ticket or a
serialized Scope. Keep strict public store authorization and refresh/CAS checks.
Lifecycle still validates the live issued ticket's principal/configuration/
endpoint, expiry, root grants and intended level/role, and consumes it exactly
once in the existing launch transaction. Session proof use must neither redeem
that ticket nor authorize a launch. No ticket-bound read capability was added.

TestSessionFinalize, TestSessionReplay and TestRootPrelude cover the identity
consumer and errors. TestNativeSession uses a real Linux Unix socket, native
peer/writer credentials, challenge, signed assertion, atomic-shaped handoffs,
same-socket session and first public read, plus stale and second-socket controls.
Its store is an explicit in-memory projection, not installed durable persistence.
All 273 prior controls and 96 fixtures remain, with twenty controls and four
fixtures added (293/100 totals; 586/200 normal/faults rows). Static checks on this
Mac cannot count runtime red/pass, native execution or installed acceptance.
The composed Linux service must run those controls and the G1/G4 installed
canaries after the requested store/dispatch/CLI/lifecycle wiring lands.

## Current attestation request: owner R131

The initial attestation round starts at 20fc030b; this compatibility follow-up
starts at a7b4aa6b. It supersedes the historical registration
description below: ordinary `none` and packed self-attestation now refuse.
Production registration accepts certificate-backed `packed` and `fido-u2f`
only when the chain verifies against explicit installation-pinned DER X.509
CA roots. There are no built-in manufacturer roots, operating-system roots,
network metadata downloads or environment overrides. An optional canonical
lower-case AAGUID allowlist narrows those roots; an AAGUID alone is public and
cannot prove possession of a hardware attestation key. Operators must select
roots whose attestation issuance policy meets the hardware requirement.

Packed leaves may omit Key Usage, as permitted by WebAuthn 8.2.1. The common
leaf verifier still refuses an explicitly incompatible usage; certificate-chain
and statement-signature verification remain mandatory even with no Key Usage.
For U2F, WebAuthn 8.6 does not compare the certificate's model AAGUID extension
with the all-zero authenticator-data AAGUID. That packed-only extension check is
skipped after the common trust verification; U2F root trust, the data-AAGUID
allowlist and its real signature remain required. Unsupported formats now return
`unsupported` before their format-specific signature fields are inspected.

**Request to lb-v2-integrate, with lb-v2-admin and assembly:** freeze a protected
installation trust source, its lifecycle and validation, then pass
`identity.Dependencies.Attestation` at service construction. The constructor-only
`identity.AttestationPolicy` carries `Config`, `InstallationGeneration`,
`RootsDER` and optional `AllowedAAGUIDs`. Bind the protected policy to the same
configuration and installation generation as the enrollment challenge. Do not
accept roots or allowlist entries from the registration request or a public
RPC. Snapshot policy bytes; install/rotation must replace the protected policy
and construct the service for the current installation. The shared manifest and
assembly were not changed in this owned lane; they currently supply no roots.
Consequently ordinary enrollment is closed until this request is integrated,
while identity construction and existing non-enrollment operations remain
available. No existing CLI flag or manifest key is implied by this request.

**Informational A, request for routing to lb-v2-service/store:** the inspected
`internal/v2/store/fix11_stubs.go` still returns `not_implemented` from both
`ReserveEnrollment` and `EnrollmentChallenge`. These are an independent blocker
before identity can reserve/load a real protected enrollment challenge, even
after trust-policy wiring. Implement durable reservation and lookup against the
same store with the frozen ceremony, challenge, lifetime/generation and one-use
transaction semantics. Identity propagates these refusals and supplies no fake
challenge or fixture fallback. Both this store work and protected trust wiring
must land before the owner-operated R131 ceremony.

**Informational C, request to the admin/browser producer:** request WebAuthn
`userVerification: "required"` together with `attestation: "direct"` and
retain the exact client data and attestation object through the existing private
evidence transaction. Browser suppression to `none` is a refusal, not a fallback.
The owner's real key needs a configured PIN or biometric to satisfy UV. A
touch-only/CTAP1 device cannot satisfy this policy, and UV is not relaxed here.
Packed requires an X.509 v3 non-CA signing leaf with the WebAuthn country,
organization, `Authenticator Attestation` OU and common-name subject fields.
Its optional noncritical FIDO AAGUID extension must decode to the same sixteen
authenticator-data bytes. The attestation signature uses ES256/P-256, RS256
(2048–8192-bit RSA) or Ed25519; its key may differ from the credential key.
The credential COSE algorithms remain ES256, RS256 and Ed25519.

FIDO U2F requires zero AAGUID, one trusted signing certificate and P-256
credential and attestation keys. It verifies the format's exact
`0x00 || rpIdHash || clientDataHash || credentialID || publicKeyU2F` payload.
An allowlist used for U2F must explicitly include the zero AAGUID; it does not
distinguish U2F models, so pinned roots remain mandatory. Neither format relaxes
the existing RP/origin/challenge, UP, UV or attested-data checks. A legacy U2F
device without UV will therefore refuse even though its format is understood.
Certificate verification checks validity at the service clock and uses only
the supplied roots; request `x5c` entries are intermediates, never trust anchors.
Verification is offline: no MDS, CRL or OCSP fetch/revocation policy is claimed.
Trust removal requires protected installation policy rotation; revalidation of
already enrolled hardware credentials after such removal needs an integration
decision. This change does not silently upgrade historical enrollments.

Only the exact reserved software AAGUID/marker pair derives simulated presence.
It may use empty `none` or signed packed self-attestation in the existing
`laneboss_e2e_authenticator` build through `api.ValidateCredentialPresence`.
Ordinary unmarked `none` remains forbidden in that build as well. No new build
constant or production bypass is introduced, and the reserved credential ID,
simulated flag and evidence are retained. Normal production still refuses all
marked credentials through the existing shared policy.

Synthetic CA/signature fixtures and twelve added omission controls cover direct
formats, generic `none`, self-attestation, unknown allowlisted AAGUID, chain,
certificate subject/AAGUID, signatures and installation context. All 255 prior
control IDs and 93 fixtures remain; the moved signature check retains its old
control ID/selector/diagnostic. The initial round's 267 controls and 96 fixtures
are superseded by the six compatibility controls:
all 267 prior IDs and all 96 fixtures remain, giving 273 controls and 96 fixtures
(546 and 192 normal/faults rows). They cover no-Key-Usage acceptance with actual
chain/signature negative controls, incompatible usage refusal, U2F model-AAGUID
compatibility and unsupported-format classification. Static checks on this Mac
cannot establish red controls, runtime acceptance or hardware
presence. The Linux normal/faults matrices, dedicated-authenticator tests and
independent review remain required. Under R131 the owner himself must enroll
his real security key at final acceptance. No such enrollment was performed
or claimed in this authoring round.

## Current adoption: fix 12

The base is 175cab85, including shared 2a55fa8 and review corrections 12b-12d.
CredentialProjectionIdentity now consumes the protected projection store before
any export authorization and before a new agent BindLaunch permit. It compares
the complete request with the reserved record, checks actual helper peer facts,
distinct installed helper/broker executable and process pins, boot/installation,
current sources/targets, the prepare effect claim, life/cancellation and issued
grants. Agent prepare/open uses current policy; workers retain separate current
leased-job authority and may retain historical issuance under a later policy.
Metadata is copied before validation and returned without protected aliases.
Source/fence changes and cancellation during verification refuse on fresh reads.
CheckLaunchCredentials runs the actual held-receipt gate before returning a
permit. Existing plan, event, grant and prepared-binding checks remain.

One mandatory native dependency remains explicit. The installed PeerVerifier
must implement identity.CredentialProjectionPeers.VerifyCredentialProjection.
It receives the actual VerifiedPeer and protected authority, and must authenticate
each writer on the distinct private helper/broker channel, remeasure both pinned
executables and process lifetimes, and check current boot and installation pins.
The ordinary frozen VerifiedPeer exposes only Facts/Alive/Close; a matching UID,
PID or broker socket pathname cannot establish executable/channel authority.
The current Linux/Darwin composition does not supply this extra native port.
Identity therefore returns a typed not_implemented rather than accepting any
ordinary connection. Native/admin/integrate must wire the actual producer or
agree a shared narrow port; the metadata fixture is not its implementation.

The protected CredentialProjection lookup must resolve the same durable
configuration/prepared-gate reservation and current canonical slot lease,
enrolled worker selection/sealed job input, source versions/revocation and fence.
The broker/store must establish that reservation before export authorization;
missing/unavailable state is never an empty credential set. Identity joins the
actual current Effect, Lane, Grants and Policy ports again after native checks.
Native descriptor transfer, writable-alias measurement, the canonical refresh
lease and LockCredentialProjection held through real OpenGate/exec remain broker/
helper ownership. Neither this read check nor a DTO authorizes a second gate.

The serve2 normalization rule is adopted: verified simulated-presence registration
uses SoftwareAuthenticatorCredentialID while preserving raw credential ID, key,
evidence, counter and simulation markers. The merged enrollment source did not
contain that normalization, so it is added here. ValidateCredentialPresence still
rejects marked credentials in production; the dedicated tagged signed flow now
also checks the normalized ID. No simulated mark is removed or upgraded.

The logical-turn boundary is unchanged by the frozen schema. Identity emits
human.challenge/human.confirm/ticket.issued/human.session, not lane.turn, and
does not create vendor Session or lane-turn receipts. Session and HumanSession
have no LogicalTurnID member. Producers lifecycle/helper_open/mail_deliver must
copy the actual TurnSnapshot.LogicalTurnID to every lane.turn Event envelope;
the shared validator now enforces it for all emitters. The read-only TestTurnEvent
fixture is added to this lane's inventory. No Session field or operation-ID
fallback is invented, and vendor-session correlation remains the owning producer.

All 235 prior control IDs and 84 fixtures remain. Nineteen omission controls
and nine fixtures give 254 controls and 93 fixtures (508 and 186 normal/faults
rows). Four existing plan selectors use TestPlanFence so an independent new
credential check cannot hide the omitted plan predicate. The original complete
permit/plan fixtures retain their assertions. New test paths are under 40
characters. Static compilation is not reached-red or native acceptance.
Historical before catalogs remain for their archived matched sources; current
helper tests cannot be overlaid onto those older identity implementations and
counted as a compile-failure red. Qualify the current omission matrix on Linux.

## Prior adoption: d4fix14

The follow-up starts from a522d51b and consumes fix-11 section 10 without a
shared API change. A running lane resolves current approved policy into its
connection scope. Its immutable launch and issued-grant generations remain
historical facts; currentLaunch requires record <= live projection <= scope,
with nonzero issuance, unchanged identity facts and current revocation checks.
checkGrants still pins the grant-set generation/hash to its launch and refuses
expiry/revocation or current policy below issuance. Current policy/store owners
still enforce capability ceilings and object ACLs; a historical grant label is
not permission to perform new work under an older policy.

IdentitySelf returns the current scope generation and independently checks it
against current approved policy, retaining the existing future-scope refusal.
Human and worker scopes still compare their generation on every request; only
generation drift returns conflict to reload, while changed principal/config/
launch/endpoint facts remain unauthenticated. A new launch permit resolves a
current scope, then checks ValidateLaunchPolicyCurrent against the sealed
reservation and issued grants at its final plan-authority check.
A policy change returns the contract's conflict/reconciliation instruction,
even after the coordinator advances the live lane; no old plan bytes are edited.

The new running-lane fixture crosses a generation-3 to generation-4 D6 change
on the same connection, validates the coordinator projection through the shared
ValidatePolicyAdvance contract, and preserves historical launch/grant/endpoint
bytes. It models the protected store update; it does not implement the policy
coordinator or prove installed reload, CAS races, capability re-resolution or
native gate reconciliation. Five fixtures and ten controls supplement all prior
225 control IDs and 79 fixture IDs. Two existing policy controls follow their
effective guards. fix14-before-cases.json nominates five matched assertions on
a522d51b. All runtime qualification remains on the authorized Linux box.

The receipt connection control keeps its single comparison omission. The fixture
now counts refused as well as successful BindReadAuthority attempts and requires
invalid receipts to stop before transport activation. This distinguishes the
receipt check from the independent transport connection check without weakening
either production boundary. The prior normal-build survivor stopped redbox7;
there is no observed faults-build mutation row for it in that log.

## Prior adoption: d4fix13

The current base is f5f6ba9a, including shared fix 11 and the supervisor's landed
62d895d. The supervisor reports approved Fable/gemini review, green prior units,
384 killed identity controls and 120 fixtures, plus a green shared fix-11 box.
Those are received results. This authoring phase is static only and has no
runtime, installed ceremony, worker or hardware-presence acceptance result.

The identity EnrollmentValidator stubs are replaced. BeginEnrollment reads the
actual protected ReserveEnrollment challenge and validates its complete ceremony,
origin/RP, generation, lifetime and unused state. ValidateEnrollment loads that
exact challenge, verifies webauthn.create, actual nonce/origin/RP, UP/UV/AT flags,
bounded CBOR/COSE and the actual credential key. ES256, RS256 and Ed25519 keys are
supported. At that earlier stage registration supported none and packed
self-attestation. The current R131 attestation request above supersedes that
behavior with install-pinned certificate verification. No untrusted certificate
becomes a root.

AAGUID comes from attested data. The dedicated software marker stays an explicit
EnrollmentValidationRequest field. Identity derives SimulatedPresence only for
the reserved pair and calls the actual shared build/marker policy. Partial pairs,
legacy reserved identities and marked production credentials refuse. The producer
retains the exact typed registration request's byte fields in its evidence hash.
The EnrollmentInstall descriptor uses that hash/size and the same evidence on the
credential. Service/admin must write json.Marshal(EnrollmentValidationRequest) as
the private evidence ObjectWrite in the same admin_enroll transaction as challenge
consumption/enrollment. This descriptor is not a claim of an earlier object commit.
The existing service-owned initial-only inventory lock and genuine administrator
channel remain mandatory; identity validation also supports later D6 proposals.

humanEnrollment checks the shared credential policy on every service verification,
including revoked marked entries. The shared assembly startup guard already calls
CheckHumanEnrollmentPolicy on the complete protected inventory before construction
and listening; store startup must enforce it too. Errors are never an empty
inventory. Confirm derives the mark from the selected current credential and
preserves it in VerifiedHumanProof, returned/event ProofRef and the exact original
assertion evidence handoff. Proof checks compare the current credential's mark.
Ticket, HumanSession, ReadAuthority and returned operation receipts preserve it.
Store still owns actual ProofUseReceipt/MutationReceipt stamping and one-use
validation against the current enrollment. Dashboard/report/review consumers must
show presence=simulated and human_approval=not_proven for all dependent rows.

Read authorization now serializes the same connection's refresh, calls the actual
RefreshReadSession CAS port and validates the committed next revision. It keeps
absolute expiry, requires the five-minute idle cap and preserves identity and
presence. The store's commit instant is inferred from its returned idle deadline
within the observed call interval, avoiding equality between independent clock
calls. Capped idle uses the unchanged absolute expiry. A conflict reloads only
that same session's next committed revision; it never replaces the one-use bind.
ReadAuthorityRefresher is required before the store update. The transport update
and its read-back must match the committed projection. Invalid/unknown commit or
failed local update closes the connection; no store callback enters transport
under a writer lock. IdentitySelf retains its current-session check, while the
dispatcher authorization performs the activity update once.

RevokeLaunch now reads the committed LaunchRevocation and current record, checks
the actual identity.revoked event/cause/sequence, calls the bound transport and
validates measured zero connections and deliveries. Unknown/nonzero counts,
changed event/cause, future completion time or changed retained decision refuse.
BindConnections stores one real provider; absence or provider failure is typed.
No revocation transaction, event, new operation, UID release or process-quiescence
claim is manufactured by this ID-only reconciliation method.

Worker authentication now calls WorkerBinding only after native verification,
checks the real shared principal validator, current helper allocation/boot, grants,
claim/epoch/expiry and endpoint, and returns a separate zero-level/role worker actor.
The private endpoint may pass the frozen WorkerOperation through Authenticator.
Authorize with a verified Request frame; these names are not public RPC methods
and are not registered in Methods. Current mapping/native authority is reloaded
on each operation, and human proof, public operations, foreign frames and illegal
job permissions refuse. The service private dispatcher still owns routing,
sealed input/result classes and each data-store handoff, including every delivery.

One worker gate remains a contract request. BindLaunch has only Record, Prepared,
Identity and optional agent Recovery. It has no installed WorkerLeaseID/endpoint,
fixed worker spec/stage/claim or native connector handle. WorkerBinding requires
the genuine complete installed endpoint and native PeerFacts; those are available
to Authenticate, not pre-gate BindLaunch. No protected pre-gate launch-to-worker
authority lookup is frozen. Owners integrate/service/admin must provide a reviewed
handoff or protected lookup of the actual current job/lease/stage/claim/epoch,
fixed spec and helper prepared/native authority keyed by the committed worker
launch. A lease guessed from UIDLeaseID, synthetic peer facts or a local launch-ID
map is insufficient. The existing stored-worker BindLaunch refusal remains typed
and returns no permit until that input exists. This round implements the real
connection/per-operation mapping; it does not claim a worker launch permit.

All 192 prior control IDs/diagnostics and 60 fixture IDs remain. Thirty-three owned
consumer controls and 19 fixtures give 225 controls and 79 fixtures. Six fixtures
read the shared API tests without mutating shared code. API mutation paths remain
outside the identity runner's ownership allowlist. Nine session control selectors
use the new isolated preflight matrix so independent store/transport validators
cannot conceal the deciding early guard. The original full authorization matrix
and all its assertions still run. Two activation anchors follow the new exact
ReadAuthorityFromSession projection. The new absolute/connection refresh and
registration marker/nonce controls omit both independent consumer validator calls
where either would reject. No shared validator is weakened.

fix11-before-cases.json nominates 10 assertions on this matched f5f6ba9a contract
with identical candidate test bytes. The older 30- and 10-case catalogs are
byte-identical historical evidence; their APIs cannot compile current fix-11
fixture fields. Current before qualification must select the new catalog.
The dedicated tagged crypto/projection fixture follows actual registration/get
signatures through proof, proof-use guard, operation, ticket/session and read
authority. Its positive Linux builds are separate from production/faults refusal
controls. No signer enters a production binary and no result proves hardware.

The older sections below preserve earlier dated handoffs. Their pre-fix-11
idle-refresh, revocation-cause and software-registration requests are superseded
by the current consumer implementations above. Production backend/private endpoint
implementations and the worker pre-gate handoff remain the explicit current limits.

## Prior follow-up: d4fix12

The current base is fc1599f0, the supervisor's merge of identity 7a10057 and
shared b5c5f96. Shared draft.4 fix 11 is explicitly deferred. The supervisor
reports green unit boxes and approved Fable review, followed by redbox5's
passing before/harness stages and partial fixture/control results. Both CLI
stages failed to compile their reduced snapshots; no complete runtime matrix
pass is claimed from those partial rows.

The exact snapshot and require-borrowed-cli-client mutation were materialized
without running project Python. Linux vet in both tag modes reproduced the
missing internal/jsontext import from commands_guidance.go. A partial fix then
exposed the omitted internal/typesafe import from judge/audit.go; that check
stopped and its error is retained. The runner now retains both existing local
dependencies. The CLI fixture and its mutation stay
in the catalogs unchanged. Two reporter regressions require each dependency's
actual bytes/digest/mode in inventory and the copied snapshot. They must fail
against the old input list and then pass on the candidate on Linux.

BindLaunch now evaluates the worker dependency gate only after the protected
stored binding lookup and against durable.Record.Kind/Actor.Kind. Existing
agent request preflight remains before that lookup. TestWorkerPermitGapFixture
stores the worker tuple and keeps a separate valid agent request; its typed
not_implemented and empty-permit assertions remain. A new fixture requires
invalid_request for worker request labels over stored agent authority, with
no permit or stored mutation. Two controls restore the wrong source/order.
The worker mapping dependency remains unresolved; this is a refusal-order fix,
not implemented native worker authentication.

All 190 prior control IDs/assertions and 59 fixture IDs remain. The catalogs
now contain 192 controls and 60 fixtures. All 10 matched-contract before IDs
remain; the worker row's baseline diagnostic becomes integrity because the
updated stored worker has no agent Recovery and the 9f7b5ad0 base reaches that
retained-plan guard. Its candidate still must return not_implemented. No shared
API or production CLI change is needed. The current authoring phase permits
static checks only; actual reporter, fixture/control and installed acceptance
results remain Linux supervisor work.

## Prior adoption: d4fix11

The current source base is 9f7b5ad0, the supervisor's merge of identity
8aca1218 and shared c332c33, including the fix-10 contract from 0ab9e171.
The supervisor reports a counted Fable approval and 344/344 killed controls
for 8aca1218. The attempted combined landing then failed identity fixtures in
both builds because their reservations lacked the new child pins and consumed
authority fields. These are received results; this static authoring phase has
not run any test or produced a tested binary.

The fixture now retains Level, Role and Driver on every reservation, an agent
LaunchRecord.Kind, and the exact authority reference the store would retain:
the consumed ticket for a human root, the authentic starter launch for a lane
child, and the consumed proof for human resume. Resume retains its original
proof reference in the original request; identity never issues or consumes it
again. Refused capture has explicit approved policy metadata and a separate
protected policy snapshot; the registered path clears refusal metadata.

BindLaunch still reads the actual stored plan and executes the shared
ValidateLaunchPlanRecord and ValidateLaunchBindingPlan validators. Thus the
reservation decides child pins and authority; a request does not supply those
pins as a substitute. Existing missing-recovery and missing-plan assertions
remain. Identity cannot create a helper_prepare transaction and does not
invent a fallback for a producer that omitted LaunchPlans. The shared
TestLaunchBoundTransaction/no_plan_bind and no_plan_lane rows cover that
unconditional transaction boundary; they must run with the combined tree.

Before returning an agent permit identity compares the ready life's pins to
the reservation and re-reads protected current policy for a refused capture,
using ValidateCapturePolicy. Store/helper still owns the atomic release fence
and actual consumed D6 approval. Live authentication/authorization requires
Kind=agent, so historical records missing Kind and worker records cannot gain
lane authority. Genuine worker BindLaunch receives the typed dependency
refusal described below and no permit.

The two permitted P3 changes are included. identity.bound must have exactly
the retained handoff cause actor. Current grants compare all actual metadata,
values and nonempty order while treating zero-length slices as equivalent.
Nested resource slice headers are normalized on a cloned resource slice; both
stored grant projections remain unchanged and no digest is recomputed.

All 172 previous controls and 53 fixture IDs are retained. Eighteen controls
and six fixtures add pin/authority validation, current capture policy, exact
event actor, kind separation and grant projection checks, giving 190 controls
and 59 fixtures. The authority/driver controls omit both identity validator
calls when both independently reject the bad stored plan. The role/level
controls change a correctly hashed record and omit only binding-plan validation.
Tests call the actual retained-plan consumer to keep later redundant checks
from concealing the deciding API boundary. No shared validator is weakened.

The historical 30-case catalog remains byte-identical for its original
84ae053 contract generation. Current fixture DTOs require fix 10, so that old
API cannot compile a current test overlay. before.py now takes --case-plan;
fix10-before-cases.json nominates 10 reached assertions on 9f7b5ad0 production
with identical candidate test bytes. Keep the old qualification as historical
evidence; do not silently overlay a different API onto its base. All new
runtime red/candidate rows remain Linux box work. The exact commands and
failure diagnostics are in the case manifests and CONTROLS.md.

The rest of this document retains earlier owner handoffs and their limits.

Target contract: v2.0-draft.4 fix 9 at ad7cfab, merged by the supervisor at
84ae053 with identity f8af1b1. This phase changes only owned identity/peer/case
files and needs no shared-source overlay. No shared source, index, other
branch or other worktree is edited. The supervisor reports that f8af1b1 passed
its Linux box and its counted static review approved with no P0/P1; these are
received results, not a runtime measurement made by this authoring session.

The sole acceptance gate for this round is the installed CLI/socket serve E2E
owned by lb-v2-serve. It must fail on the nominated base for the observed,
correct reason and pass on the composed candidate. No serve result was
measured here. Unit, kernel fixture, omission-control and static results are
supporting evidence only. The authoring host permits static checks only.

## Prior lane follow-up: d4fix10 mutation runner

This follow-up starts from supervisor-committed ccd2470. The received box log
contains 60 qualified before-change rows, 106 fixture-pass rows and one failed
mutation snapshot row. These are received Linux results, not local runtime
measurements. The mutation guards have not yet been qualified on that box.

Static inspection identifies one invalid selector under the old runner regex:
omit-human-root-endpoint targets TestTicketEndpointFixture/lane.start. The
old name check rejects its literal dot before any mutation starts. Fixture
selectors contain no such component. Neither source inventory nor selection
uses Git metadata; the reported root names satisfy the same path rules as the
successful fixture mode. The archive shape is not the cause of this validation
failure. The runner now permits literal dotted components and still escapes
each component when building the exact test selector. Pattern metacharacters,
slashes, empty names and dot-only names remain invalid.

Failures now print the exception type/text, relevant path, actual subprocess
argv or runner invocation, and the current operation to stdout, and retain
the same data in report.json. Source bytes/modes, ownership, unique anchors,
immutable tests, binary identity, reached assertions and cleanup gates remain
mandatory. Inventory also refuses a symlink in any fixed input ancestor.
Reporter regressions exercise an archive without .git, dotted selectors,
stdout failure context, byte-exact copies and ancestor-link refusal. They must
run on Linux; static compilation does not count as their runtime evidence.

## L6 declared software authenticator: shared contract request

The second addendum authorizes a declared software WebAuthn authenticator for
installed serve: real key pair, real registration/enrollment ceremony and real
signed assertions, with presence explicitly simulated. This is an authorized
test substitution, not evidence of a human's hardware presence. This addendum's
identity implementation is pending the shared inputs below; it is not closed
by the existing software signature fixtures.

Coordinate these shared constant names with lb-v2-serve and lb-v2-integrate:
SoftwareAuthenticatorAAGUID, SoftwareAuthenticatorAttestationMarker and
SoftwareAuthenticatorBuildTag. Serve owns the reserved AAGUID bytes, exact
attestation marker and dedicated test build tag; none is present in this head
or in the received brief. Identity does not choose a different identifier/tag,
guess their values or reuse laneboss_faults as implicit authorization. These
names are a contract request, not constants already defined in this checkout.

HumanCredential currently retains only ID/raw ID, key/algorithm, counter,
generation and revocation. It has no AAGUID, attestation/marker/evidence or
simulated-presence field. HumanVerifier has only Challenge/Confirm/CheckProof,
and this owned slice has no enrollment/install ceremony entry point. The
registration producer must pass authenticated registration attestation through
a reviewed identity validation handoff before StateWrites.Enrollments is
committed. A get assertion does not carry the registration AAGUID: this code
correctly rejects the AT flag in get assertions, so ClientDataJSON or a request
label cannot fill the missing enrollment data.

Required shared changes, owned by lb-v2-integrate/admin/service with serve:

- Retain the exact registration AAGUID, attestation marker/format and private
  immutable ceremony evidence on each HumanCredential, together with a
  SimulatedPresence flag derived by identity from that declared reserved pair.
  Freeze the identity enrollment-validation port and its actual caller. The
  same reserved identity with missing/changed marker, or marker with a different
  AAGUID, must refuse rather than silently become a normal hardware credential.
- Freeze the build tag named by SoftwareAuthenticatorBuildTag. Both production
  enrollment and verification of a retained declared test credential must
  refuse in an untagged binary. The tagged path still verifies real origin/RP,
  registration evidence, key/algorithm, challenge, signature, UP/UV and counters;
  it changes the provenance claim only and offers no signature/proof shortcut.
- Add SimulatedPresence to VerifiedHumanProof and its returned/event ProofRef.
  Neither currently has a mark. Freeze propagation through ProofUseReceipt and
  the store's mutation/approval audit receipts, and retain it for any derived
  ticket/read session so reports cannot later call simulated approval proven
  human presence. The store must compare that provenance to the current
  enrolled credential under proof use, rejecting a missing/changed mark.
  Dashboard/review/report consumers must display the explicit simulated mark.
- Update the strict DTO/event/transaction maps, assertion matrix and shared
  fixtures jointly. validAssertionEvidence currently requires the evidence
  object to be exactly json.Marshal(HumanConfirmRequest); it has no metadata
  wrapper. Do not hide a mark in those bytes, a credential ID, Algorithm,
  Source/Origin label, bearer reference or an unknown client-data member.

Once that amendment and the actual constants/tag arrive, the owned consumer can
implement recognition, the compile-time refusal and marked proof production
without a private alternate schema. Required reached-red/candidate tests are:
the real reserved registration records its identity; malformed/partial pairs
refuse; untagged enrollment and verification refuse; a tagged genuinely signed
assertion writes/returns the mark; removing or changing that mark in a receipt
refuses; tagged proof/session/ticket/approval retries preserve it. A fake
dependency, direct store insert or always-true presence flag cannot qualify.
Current typed unimplemented enrollment/store composition is not bypassed.

## Implemented owned boundaries

- Authenticate receives a fresh ConnectionContext, verifies its raw Conn with
  its per-connection InstalledBinding through the native verifier, calls
  BindPeer once, then derives scope from current launch/enrollment/policy.
  It never requires an already authenticated Scope to resolve containment.
  Failed authentication closes an unbound peer and the transport connection;
  successful authentication transfers peer ownership to transport.
- Authorize rechecks live scope, current launch/life/grants/policy, exact
  request bytes/digest and Frame.Verify. Lane actor spelling is lane, as in
  normative section 4. No UID, environment label or client actor supplies
  authority. Human self/content/tree reads need a stored session; only public
  methods are exempt. api.HumanSessionMethod also governs human blob staging
  and previews. Such requests, reads, ceremonies and root spawn refuse an
  envelope Proof. Human spawn uses its issued root ticket.
- Root tickets require a human endpoint before ticket lookup. Lane/worker
  claims cannot switch to that path. Lane child level must be below its
  current authenticated level; L6-only operations, own-life briefings,
  template grants/context/instance and grant-parent claims are checked.
  The L6 gate rejects every non-lane actor before the non-lane return; current
  launch checks still reject revoked or forged L6 lane lives. Lane Proof use
  is refused before decoding start/adopt parameters.
  Roots use root=self, empty chain and starter sequence zero. Children retain
  the actual root-to-parent chain and nonzero authentic starter sequence.
- BindLaunch first reads the complete stored LaunchBinding, including required
  LaunchRecovery. It reads LaunchPlan with the stored handoff's causal service
  actor, preserving its separate original RequestedBy. The caller's recovery
  copy never supplies the metadata read identity. It calls the real
  ValidateLaunchPlanRecord and ValidateLaunchBindingPlan, requires bound/opened
  phase and the exact retained handoff, then compares the entire caller/store
  recovery tuple before the existing committed record/prepared/receipt checks.
  It reads back the actual identity.bound event at its committed sequence and
  checks ID, kind, config, target, original requester/request/operation and
  decoded LaunchRecord. Current life/lineage, projected reservation generation and
  cancellation epoch, exact issued grants and policy must still match. Only
  that stored Prepared.ID and committed sequence/digest produce the permit.
  Missing restart recovery is an integrity refusal; no legacy fallback, path
  resolver, permit cache or gate release is introduced. Store errors propagate.
  A later life revision for the same opened run is permitted; the projection
  may not precede the reserved ready generation, and the exact cancellation,
  run/launch, grants and policy checks still apply.
- Linux peer.New probes actual SO_PEERPIDFD. Verify consumes the raw Unix
  socket plus InstalledBinding. SO_PEERCRED, the socket-bound pidfd, host
  procfs UID/GID/start time and the real cgroup directory determine facts.
  Descendants retain their own pinned process generation. Registry calls run
  without the verifier mutex held; state is rechecked after resolution.
- peer/linux.NewRegistry supplies a helper-facing live kernel projection.
  Registration validates config, lease, life/run, backend, boot/allocation
  generation and nonzero UID/GID, then pins an owned CLOEXEC directory
  duplicate. It refuses cgroup root, another filesystem/mount, unprotected or
  replaced directories, and reused ID/lease/directory/UID allocations.
  ResolveContainment independently reads real process/cgroup facts and checks
  the exact current registration. Revoke retains the directory, UID and ID
  tombstones; revocation does not prove quiescence or release a helper lease.
- Confirm retains actual verified assertion bytes with a private owner ACL,
  proof, consumed challenge and counter change in one proposed transaction.
  CheckProof remains nonconsuming; current credential/principal/config/
  endpoint/intent/expiry/evidence/use facts are checked before ProofUse.
- VerifyAssertion permits unknown WebAuthn client-data members only. The common
  canonical JSON parser rejects duplicate keys and malformed encoding over
  all original bytes, then the known fields retain the strict identity shape
  checks. Ceremony, nonce, pinned origin/RP, crossOrigin and topOrigin are
  checked; this first-party contract rejects any topOrigin. Signatures hash
  the original clientDataJSON, including unknown fields. Public identity
  request/file decoders remain strict. Extra-member, nested/null-extra,
  wrong-type, duplicate and unsigned-extra fixtures use actual signatures.
- Ticket issue writes, ticket.issued payloads and returned retained tickets
  carry PrincipalID, Config and EndpointGeneration directly from Scope, in
  addition to approved role/level/root grants/expiry. Foreign receipt
  provenance refuses. Lifecycle/store must validate the same TicketUse tuple.
- HumanSession submits its proof guard with a 30-minute absolute/five-minute
  idle session. Only a committed stored session matching that exact live
  connection / principal / credential / config / endpoint is passed to
  BindReadAuthority. No public session ID activates a fresh connection.
  Bound authority carries the same ConnectionID; reads verify it and any
  dispatcher Scope.ReadAuthority snapshot against the current connection.
  Blob begin/chunk/commit, policy/guidance/judge previews and secret.stage
  use the current read session without an extra operation proof. Human self
  projection retains the current PolicyGeneration and no internal authority.
- Human mutations retain the original frame and require the actual completed
  store reply and commit sequences. Replay returns retained bytes, not a new
  random proposal. The identity CLI uses common InvokeRaw/shared socket and
  retained-key preparation; it does not require a nonnil borrowed Client.
  All five owned CLI methods register the same ValidateInput preflight used
  by service handlers; registration failure stops initialization. The ticket
  input validator checks its UTC expiry format; current expiry remains a
  server preflight after receipt lookup, so exact retries can reach receipts.

## Closed contract request: atomic assertion evidence

Integration closed the earlier 74354cd matrix mismatch in c6c68ca. The public
human.confirm row now permits Objects and calls validAssertionEvidence before
Store.Transact. It checks the exact assertion bytes/digest, private owner ACL,
principal/config/endpoint/nonce, consumed challenge, proof, counter identity,
reply and event in the same transaction. No assertion evidence is removed and
no alternate object-retention path is introduced.

TestHumanWritesFixture/confirm remains the unchanged positive handoff. The
omit-challenge-use-write and expose-assertion-evidence edits now fail at this
stronger API preflight: an unconsumed challenge and public evidence ACL are
each explicitly refused by validAssertionEvidence. Their expected diagnostic
is now the focused test's invalid typed transaction shape failure before its
Store callback. The runner still requires the identical unmodified candidate
test to pass afterward; a setup, compile or unrelated failure cannot qualify.
The counter-advance omission still targets the callback's before/after counter
assertion. Its expected diagnostic and positive assertion are unchanged.

## Admin/helper integration request

Owners: lb-v2-admin and lb-v2-linux, composed by lb-v2-service/lb-v2-serve.
Admin's protected RegisterContainment / ResolveContainment / RevokeContainment
facade must delegate to one live peer/linux.Registry for the same boot.
Validate and durably journal actual helper allocation before registration.
Reconstruct it from real retained allocation handles on recovery. peer.New
does not create a fallback registry or enroll an arbitrary caller cgroup.

Directory returned by ResolveContainment is borrowed until Registry.Close;
callers must not close it. Registration owns its duplicate, not the supplied
file. Keep the helper allocation until measured quiescence and peer cleanup.
Close peers and stop deliveries before closing the shared registry. There is
no release-on-revoke shortcut; the helper owns the actual ReleaseReceipt and
quiescence decision. The unused verifier BindContainment/UnbindContainment
surface and its groups/used maps are removed. Only Registry owns production
cgroup pins and allocation tombstones. Native fixtures duplicate their test
directory into their explicit fixture registry, immediately close the original
descriptor, and revoke through that registry. No second containment authority
or unused verifier-owned descriptor remains.

The genuine authorized serve caller is still a composed dependency. Supply
the reviewed protected enrollment and lifecycle launch entries, real helper
Allocate / RegisterSpec / Prepare / OpenGate / ResolveRuntime, durable launch binding,
bounded grants and current policy. Run the installed client inside that
actual namespace with its installed binding, and exercise records.append.
A staging human UID, manually forged Scope, read-only binding, fixture registry
or direct database write is insufficient. Any software assertion used for
credential-free setup must traverse real verification and atomic storage;
label it as a software fixture and never as hardware-presence evidence.

## Fix 9 service/store dependency

Owner lb-v2-service must implement StateStore.LaunchBinding, LaunchPlan and
Events over the same durable store. At this inspected head LaunchBinding and
Events remain owner-named stubs, and launch_plan_stubs.go explicitly leaves
LaunchPlan not_implemented. Identity calls these ports normally and returns
their original errors. No fixture store is installed as a production fallback.
LaunchBinding must return the complete atomic recovery/identity tuple, and
LaunchPlan must allow the installed identity component's private read under
the stored genuine causal service principal, retaining RequestedBy separately.
BindLaunch has no public RPC or caller-supplied Scope parameter. The store must
not grant a public/worker request private metadata merely because it carries a
serialized service Actor. Its identity.bound event must be available by the
actual committed sequence, not synthesized from the binding on lookup.

The helper_prepare projection must already exist when identity reads the child
life. Keep allocation, original frame/spec bytes, object ACLs and actual helper
receipts under the original effect claim. Identity validates the resulting
cross-object pins; it neither reconstructs a missing plan nor implements the
other owners' stages. A genuine installed launch remains necessary for serve,
LIFECYCLE-TREE and OS-LINUX.

## Remaining owned not_implemented paths and conventions

- RevokeLaunch still has only a launch ID and no causal request/effect.
  Owners lb-v2-integrate, lb-v2-lifecycle and lb-v2-service must freeze whether
  lifecycle first commits revocation and identity only invalidates it, or
  supply the authorized causal handoff. Returning nil without that decision
  would be false success. Fix 9 adds no input to Authenticator.RevokeLaunch and
  supplies no transport connection-invalidation dependency. The missing input
  is an authentic internal revocation cause with original operation/requester,
  target/current cancellation fence and the transport's close completion.
  Identity will consume that reviewed handoff. A fixture verifies the typed
  refusal, unchanged record and exact propagation of the store's own refusal;
  it is not an implemented revocation claim.
- Worker endpoint authentication remains not_implemented. DeliveryStore has
  WorkerLease lookup, but the authenticated bootstrap mapping from installed
  WorkerLeaseID/launch/containment to current job principal and permitted
  operation is not frozen here. Do not alias a worker to a lane or human.
  Owners: lb-v2-integrate, lb-v2-service, lb-v2-identity and the confined worker
  owners. Fix 9's CaptureBinding does carry ProducerID/kernel/boot and a
  WorkerLeaseID, but InstalledBinding carries no CaptureBindingID and there is
  no protected reverse lookup from the installed worker lease to that binding.
  WorkerLease itself still has no principal/config/endpoint or kernel/UID/
  containment binding and no closed permitted-operation mapping. Possession of
  a lease ID cannot fill those fields. Freeze a protected lookup that verifies
  those actual worker facts, current claim/epoch/expiry and job authority;
  CaptureState requires an already authenticated worker and cannot bootstrap
  it. Authenticate retains the typed gap and closes the acquired peer and
  connection. Authorize never relabels a worker as its original requester, a
  human or a lane. Worker and root-ticket fixtures establish refusals only.
  Shared fix 10 adds ChannelExecution and a fixed worker handoff, but the
  Authenticator's BindLaunch/Authenticate inputs still have no protected
  reverse lookup from the installed worker lease/launch to that execution's
  current principal, native allocation and permitted job operation. A caller's
  serialized ChannelExecution cannot replace that missing lookup. BindLaunch
  therefore also returns not_implemented for genuine worker-kind/worker-actor
  input, rather than applying agent reservation authority to a worker.
- Review P2(4), moving read-session idle expiry, remains a contract dependency,
  not a completed fix. IdentityStore.ReadSession is a lookup with no write/CAS
  semantics. The only write row permitting ReadSessions is public human.session,
  which requires a fresh proof and cannot be used during a read. No internal
  idle-refresh kind, session compare/guard or atomic refresh port exists in
  fix 9. ConnectionContext.BindReadAuthority is one-use; it cannot replace the
  retained idle deadline, and Scope.ReadAuthority snapshots must agree with it.
  Owners lb-v2-integrate/lb-v2-service must freeze an authorized post-check
  read-session update that checks the prior deadline, live connection,
  principal/credential/config/endpoint, revocation and expected session revision
  before setting IdleExpiresAt=min(now+5m, absolute expiry). The transport also
  needs an identity-only same-session deadline refresh/snapshot contract, or a
  reviewed authoritative deadline read that preserves the one-use bind. Then
  identity/dashboard can consume it on each authorized read. A local timer,
  optional unreviewed interface, forged human.session or out-of-catalog
  transaction would not implement durable refresh. Until that port lands the
  existing five-minute deadline is enforced conservatively; activity does not
  extend it. This remains an observable correctness limit.
- Enrollment initially resolves the protected installed human endpoint with
  no asserted Actor.ID. Admin/store must return its enrolled principal and
  current public credentials; login UID or request labels are not proof.
  Supported key spellings are ES256, RS256 and Ed25519/EdDSA.
- Store/helper must agree on the producer's committed RecordSHA256 bytes.
  Identity compares the authoritative stored tuple and needs no invented
  local re-encoding. Store must implement receipt lookup before proof/base
  preflight, exact replay, atomic counters/challenges/ProofUse/TicketUse and
  current object ACLs. Final MutationReceipt.Config belongs in all producers.
- Linux transport must set SO_PASSCRED before use and verify every recvmsg
  fragment's single SCM_CREDENTIALS writer against the connector lifetime and
  containment. Reject missing/extra/truncated controls and SCM_RIGHTS, closing
  all received descriptors. Connector credentials alone do not identify every
  writer. Authorize calls Frame.Verify; a fixture frame is not proof of the
  installed transport implementation.
- Shared CLI dispatch still names runIdentitySelf, runHumanChallenge,
  runHumanConfirm, runHumanSession and runTicketIssue. Those five referenced
  entries remain; auxiliary names have the identity prefix.

## Exact requests to the serve case owner

The current owned checkout does not include the installed serve case's driver.
The latest supervisor brief reports that its real Ubuntu installation now
passes through health. Its next authorized caller must come from the genuine
composed launch described above, and its human setup uses the L6-declared
software authenticator with the explicit provenance contract requested above.
Preserve the installed CLI/socket route and all checks; do not add a replacement
host or SQL-only observation. No result from that external driver was measured
in this authoring session.

| Serve checks | Identity contribution and remaining owner |
| --- | --- |
| platform, source, build | No identity acceptance claim; lb-v2-serve retains exact base/candidate source and installed artifacts. |
| namespace.install, namespace.check, admin.install, installation | lb-v2-admin/lb-v2-linux must publish complete protected boot/bindings, installed units and real namespaces. In particular the actual unit must carry --installation. |
| serve | Real peer.New, identity.New and authentication order remove this lane's constructor blocker; lb-v2-service still owns the real host/store/runtime, and admin supplies installation/registry wiring. |
| health | Native connection/frame/current-authority paths enable a real public health call; lb-v2-service owns transport and truthful Health/readiness. |
| state.authorized | Registry and BindLaunch support the current native lane principal. lb-v2-admin/lb-v2-linux/lb-v2-lifecycle must allocate, enroll and launch the real caller; lb-v2-service persists its authority. |
| state.append, state.read | Identity authenticates/authorizes its actual frame. lb-v2-integrate/records and lb-v2-service/store own append, committed content and read ACLs; lb-v2-serve drives and observes them. |
| state.drop-reply, state.restart, state.retry | lb-v2-service/store supplies exact durable receipts and restart/reconciliation; lb-v2-serve needs the reviewed lost-reply mechanism. No proof may be consumed twice. |
| state.receipt-count, state.event-count, state.effect-count, state.changed-bytes | lb-v2-integrate and lb-v2-service must expose authorized existing observations; lb-v2-serve checks cardinality/bytes. Record append emits a record event and no outbox effect in the inspected code. Freeze which observable effect is intended. |
| unready.owner | lb-v2-serve/lb-v2-integrate retain catalog-owner refusals for partial registration. They must still traverse real authentication. |
| direct-open.db, direct-open.wal, direct-open.journal | lb-v2-admin/lb-v2-linux/lb-v2-service own actual isolation and filesystem permissions; lb-v2-serve runs the direct-open canaries. |
| cleanup | Transport closes the peer/context, library closes owned pins, and helper retains/releases its lease only after quiescence. lb-v2-service/admin/linux/serve own installed collection evidence. |

Retain the actual first base failure. A missing installation, peer stub or
service-host stub cannot be relabeled as a missing-handler failure. Run on the
composed Linux box, retaining the nominated base result separately:

```sh
sudo -n bash e2e/v2/cases/serve/run.sh \
  --source /test/candidate \
  --evidence /test/evidence/lb-v2-serve-green
```

## Supporting evidence and required box work

The fix-9 manifests retain all 151 prior omission IDs and 44 fixture IDs and
add 21 controls and nine fixtures, for 172 controls and 53 fixtures. Both still
require draft.4. Native
composition lives in e2e/v2/cases/identity/native; its production dependencies
are only API and the two owned packages. It uses a real Unix socket, native
verifier, real kernel writer credentials and two generated public-key
fingerprints. Its store enrollment/policy are controlled projections. It does
not provide the installed authorized lane caller or a durable enrollment test.

The installed identity reporter retains all prior scenarios and adds current
session/own-life/ticket provenance canaries. It is supporting coverage, not the
sole serve gate. The package control runner requires the named reached red
assertion before the same unchanged candidate test passes; build/setup/skip/
panic/timeout/collection failures cannot kill a mutation. The confirmation
rows above now target c6c68ca's atomic evidence preflight and remain required.

CLI file tests cover each owned method with an invalid file before a missing
proof/key/binding and a valid file reaching transport. The accepted valid-file
refusals are prerequisite_missing or not_implemented, exit 69, with an owner
other than identity and never invalid_request; no other lane's stub message is
pinned. Empty-method invalid objects fail the common shape decoder before the
feature hook, as section 14 requires. Their typed invalid_request has API
shape ownership, while semantic invalid challenge/confirm/ticket requests
must carry lb-v2-identity. Both empty validators independently enforce {}.

The installed identity reporter accepts explicit per-scenario binding aliases,
including paths visible only inside a namespace. Only ticket-wrong-config may
select another configuration, using its real protected binding; collection is
an independent observer. Missing JSON keys/type errors produce a failed row;
malformed JSON is failed and unreached. Later checks/collection still run and
red qualification stays strict. Result/evidence paths must resolve inside the
physical test root, including through symlinked parents. Reporter-only tests
use synthetic outputs and establish none of the installed identity behavior.

The new launch fixtures supply independent caller and store byte copies and
execute the actual API validators. They check the identity consumer only;
their controlled store is not protected enrollment, helper allocation or a
completed launch plan. Successful rows explicitly require the real consumer's
plan/event reads and exact permit. Dependency refusals must retain error
identity and return no permit. The omission manifest targets each deciding
new check. Base/candidate runtime qualification, including missing recovery,
foreign reservation, changed replay/path/executable and stale authority, is
still required on Linux. Nothing measured by static checks counts as that run.
The old omit-json-duplicate ID now omits the owned call to the complete client
JSON validation, and omit-root-cgroup-check targets Registry's two dedicated
root checks. The old omit-binding-gate ID targets the existing direct prepared
tuple preflight; the new API validation independently checks the durable gate.
All old IDs and their stricter runtime qualification remain present.

before.py and before-cases.json additionally nominate 30 focused assertions
against 84ae053 production with the unchanged candidate identity test files.
The Linux-only runner archives the original base, exact test overlay and
candidate, validates immutable input/test bytes, then requires the named reached
base exit-1 assertion before a candidate pass. It reuses the same strict
test2json and pidfd/subreaper collection logic as omission controls. Compile,
setup, skip, panic, timeout or cleanup failures cannot qualify. Reporter-only
overlay tests cover retained base production, removed tests and byte drift.

Preserve the descriptor regression fixes: MSG_CMSG_CLOEXEC is informational;
payload/control truncation, other bits, counts/marker, actual FD_CLOEXEC and
rejection cleanup are checked. The real passed-socket and reject-cloexec-flag
controls must run again in both builds. All fixtures, all 172 omission controls,
reporter tests, full units in both builds, scanner and the installed serve
base/candidate pair remain box work. No runtime pass is claimed from this host.
