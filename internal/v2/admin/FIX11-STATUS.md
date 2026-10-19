# Draft.4 fix 11 administrator adoption

The enrollment slice began at dc0e9d1; this materialization continuation starts
at 6b512aa. It contains the supplied Linux corrections, administrator enrollment
consumer and materialization helper implementation. Composed installed
serve acceptance remains incomplete. Only static checks are authorized on the
authoring host; unit/mutation/native/authentication results require the retained
source on the supervisor's disposable Linux environment.

## Reported Linux findings

The private storage resolver no longer relies on os.Root.OpenFile to reject an
in-root symlink. It opens each journaled name through openat2 with
RESOLVE_BENEATH, RESOLVE_NO_SYMLINKS and RESOLVE_NO_MAGICLINKS, then compares
the held descriptor with an AT_SYMLINK_NOFOLLOW directory-entry observation.
The containing private root is also opened without links in any component.
Collection uses that same root-opening primitive. The originally failing
TestLaunchStorageRefusals/linked-home is unchanged. Additional controls use
actual ancestor links and an actual held directory whose name is replaced.

The doctor-input-drop control remains in mutations.json with the same source
mutation, test and diagnostic. TestAdminDoctorFiles/valid now inspects the
actual registered validator, checks its valid and invalid inputs, and only
then accepts the expected later transport refusal. Missing registration cannot
pass through another owner's not_implemented error.

## Task 1: initial administrator enrollment

The fixed CLI forms are:

```text
laneboss internal helper --config NAME --installation FILE --enroll-begin FILE
laneboss internal helper --config NAME --installation FILE --enroll-complete FILE
```

They are mutually exclusive, accept canonical absolute protected files and no
arbitrary argv, URL, key or endpoint selector. The begin file is the frozen
EnrollmentCeremonyRequest. The complete file is EnrollmentValidationRequest:
ceremony/challenge IDs, exact ClientDataJSON and AttestationObject bytes, and
the optional explicit attestation marker. No authenticator private key is
accepted or retained by this boundary. Existing helper-unit and sealed bootstrap
modes keep their separate fixed grammar.

RunEnrollment verifies real/effective root UID/GID equality, the protected
helper installation, actual installed executable identity/digest, the protected
service installation's optional admin_enrollment capability and its distinct
installed human endpoint. Missing capability refuses. It connects only to that
private administrator socket. It pins the service UID/GID, pidfd, executable
and installed service cgroup, checks per-fragment native message writers and
refuses passed descriptors. It compares nonce, protocol, contract revision,
installation generation and artifact, and reloads installation before returning.
There is no public RPC or serialized InternalIntent route to these messages.

BindEnrollment now retains exactly one nonnil service implementation. It does
not start a background listener or claim enrollment availability. The service
must run ServeEnrollment(ctx, endpoint) under its own error/context lifecycle
when the protected optional capability is present. The final directory requires
exclusive service ownership and mode 0700, with no untrusted/shared-writable
ancestor or link. The distinct socket requires mode 0600 and the dedicated
service account. Both SO_PEERCRED/SO_PEERPIDFD and every recvmsg writer are checked.
The connecting root process must be the exact installed helper executable,
with all real/effective/saved/filesystem UID/GID fields root. A root login or
service label alone creates no enrollment authority or human proof.

ServeEnrollment also reads Dependencies.BindingFile as the protected installed
human binding and retains/rechecks that exact object on the native channel.
Pass that same verified InstalledBinding to NewInitialEnrollmentValidator.
Its EndpointGeneration is independent of the helper installation generation;
fresh challenges compare both actual values separately. The component fixture
uses human endpoint generation 7 with installation generation 1 and an internal
service Scope whose connection-specific endpoint stamp is zero. No public
endpoint generation is invented on an internal store Scope.

The listener supplies a private, nonserializable channel capability after these
native checks. CheckEnrollmentChannel repeats current peer/artifact/generation
checks. No public Scope can construct it. InitialEnrollmentValidator implements
the existing api.EnrollmentValidator consumer port around the real identity
producer. It checks the whole HumanEnrollments(ctx, config) inventory, including
revoked prior credentials and other principals, before calling identity. Errors
never mean empty. ExpectedGeneration must be zero. Begin reloads the actual
stored challenge; complete checks the exact stored nonce, origin/RP, installation,
expiry and identity-derived EnrollmentInstall. The wrapper calls the shared
production/test-tag credential-presence guard; it supplies no crypto shortcut.

ValidateInitialRegistration produces a private in-memory ValidatedRegistration
only after that identity callback and validation. Its public Install method
returns independent credential byte slices. CheckInitialEnrollmentInstall is
the private registration-validation check for the store's existing signature:

```text
HumanEnrollments(ctx, config) ([]api.HumanEnrollment, error)
InstallHumanEnrollment(ctx, scope, intent, install, evidence) (api.Commit, error)
```

The store must call CheckInitialEnrollmentInstall with the actual channel
context under its writer lock, then enforce the complete configuration-wide
absent baseline, exact stored create challenge and one-use consumption in that
same transaction. The check reads no store API and sends no transport message.
It compares the actual retained identity validation and exact evidence hash and
bytes, rather than trusting a service Actor, ValidationID string or client bool.
The signatures match the service-owned implementation; these administrator
checks do not replace the store's atomic lock or durable ceremony receipt.

CommitInitialEnrollment accepts that validated handoff from the same live
channel, original private service Scope/InternalIntent and exact private
ObjectWrite. It reloads the challenge, rechecks initial-generation/presence and
current inventory/channel, then invokes InstallHumanEnrollment. Evidence uses
the existing EnrollmentValidationRequest JSON shape with the original signed
byte arrays; preserve the identity producer's raw JSON bytes as the artifact.
The adapter never constructs a credential from the file or seeds a database.

After commit, it reads the actual successful operation, blob.committed event,
committed sequence, private object metadata/bytes, complete enrolled baseline
and consumed challenge. It derives EnrollmentReceipt from those records, with
the identity-derived simulated mark. Missing, changed, unconsumed or unreadable
records refuse after retaining the actual commit for diagnosis. No synthetic
enrolled event or guessed event ID/sequence is used.

Lost-reply replay belongs before fresh validation in the service handler.
The service reloads the exact retained ceremony receipt and calls
VerifyEnrollmentReplay using its real original bound store Scope. That method
performs the same read-back and compares the retained registration request's
ClientDataJSON/AttestationObject bytes with the retry. A changed retry conflicts;
a new principal cannot reopen initial enrollment. The listener returns a complete
receipt only after CommitInitialEnrollment or VerifyEnrollmentReplay has marked
that same private native channel with its verified read-back. Callback success
alone cannot acknowledge completion.

An untagged production/faults build rejects the reserved software credential
through api.ValidateCredentialPresence, including legacy markers and revoked
startup inventory. No software signer was added here. The dedicated
laneboss_e2e_authenticator tag remains the only shared test-device enablement.
CLI receipts with SimulatedPresence=true display presence=simulated and
human_approval=not_proven. Registration and these component controls do not prove
physical presence, authenticated vendor use or a human approval.

### Required owner integration

Service must supply the protected human BindingFile to admin.Dependencies, start
and supervise ServeEnrollment with its installed optional endpoint, supply that
same actual human binding to NewInitialEnrollmentValidator with the identity
validator and original store Scope, use
the validated handoff/commit adapter, and replay durable ceremony receipts before
revalidating consumed challenges. Store must use the validation check under its
writer lock and atomically consume the create challenge, install one baseline,
retain exact Objects and save the original ceremony/operation receipt. The
signature-compatible earlier store commit alone does not establish all fix-11
invariants. Identity must implement BeginEnrollment/ValidateEnrollment with real
WebAuthn registration crypto and retain the exact private request evidence.

The checked-out identity/service/store fix-11 methods still return their
owner-named failures. Common composition files were not edited. Consequently
this slice does not advertise a working ceremony or claim Task 1's composed
serve/runtime acceptance. Production refusal, tagged real registration, concurrent
first-enrollment attempts, a second revoked-principal baseline, and lost/changed
reply replay all require Linux execution with those actual owners.

## Task 2: materialization child worker and mapping

OpenLaunchDataStorage now resolves the actual service planning claim, retained
LaunchDataStage, allocation journal and narrow grants. The helper reserves its
own pool UID/GID and cgroup durably before any resource or ownership operation.
Agent, capture and other materialization reservations exclude that UID. The
worker LaunchRecord must have its own worker actor, zero level and empty role;
it cannot use the requester or service principal. Native containment registration
joins the child lease, actual cgroup inode, boot, generation and sealed spec.
Every ResolveContainment repeats the helper journal read before native process
and writer verification. This is admin's native mapping half; it does not create
an identity WorkerPrincipal from labels.

The protected source cache is helper-state-relative: sources/SHA256 contains
manifest.json and tree, both installed by the administrator from the approved
immutable project object. The source hash is the exact enrolled manifest hash;
no request supplies a host path. Cache parents and source inodes require private
root ownership. A missing cache is an explicit prerequisite failure. A tree
source requires Base equal to the manifest digest. Reachable Git remains an
explicit refusal until its granted export and protected Git runtime are installed.

The helper independently walks and hashes the enrolled source, then stages only
that granted input under jobs/STAGE/source for the new worker UID. The staged
input is read-only in the child. Workspace/home are separate real allocated
inodes, both empty and mode 0700 before ownership transfer. The helper retains
all three root descriptors plus their parents and names. OpenToken, actual
device:inode identities and exact evidence bytes persist in the parent journal.
A replay uses those held descriptors. Losing the registry, changing a root or
restarting the helper refuses; the saved token cannot reopen a pathname.

The service-only admin.DataWorkerControl provides DataWorkerLease,
RegisterDataWorker, PrepareDataWorker, OpenDataWorker, ObserveDataWorker,
MeasureDataWorker, RevokeDataStorage and CollectDataStorage. Register uses the
actual retained spec, installed worker binding and exact grants-owned
laneboss.materialize-input.v2 bytes. First input assignment is allowed only
before sealing; changed bytes conflict. There is no public RPC or caller argv.
Service must use this fixed job handoff rather than the generic agent launcher.

Prepare uses the existing real bwrap/bootstrap/pidfd/wait implementation. It
projects the original roots at /job/source, /job/workspace and /job/home, seals
the read-only /runtime/laneboss-worker.json binding and pins only this job's Unix
socket at /runtime/laneboss-worker.sock. The host socket is derived from the
issued WorkerLease ID beneath the installed runtime's workers directory. That
directory must be owned exclusively by the service with mode 0700; its socket
must be service-owned with mode 0666 so only the inaccessible namespace projection
can be used by the distinct worker UID. The helper verifies the installed runtime
and matching executable bytes/version. It preserves the frozen worker argv,
translating only logical argv[0] to its enrolled namespace executable. The child
has no network grant or credentials and receives a fresh offline namespace.

Open checks the exact retained child claim, original cause, committed worker
identity and one-use permit. It journals the attempt before release. Lost or
uncertain gates cannot be replaced. Completion requires the owned native wait's
actual known exit 0, plus independent cgroup and UID quiescence. A WorkerResult
acknowledgement alone cannot complete the job. The helper decodes the exact
acknowledged JCS LaunchData, checks its real receipt/hash/length/generation,
source and destination identities, input and candidate manifest, then separately
walks and hashes the held source/workspace and verifies the exact private home
inventory. Extra/missing entries, traversal, special inodes, links to external
trees, hardlinks, changed ownership/modes, ACLs/capabilities and content mismatches
refuse. Only after these reads does it emit ReadBackSHA256. Workspace/home contents
return to the agent UID through descriptor-relative ownership changes, with
journaling before that transfer. An interrupted transfer remains uncertain.

Read-back retries repeat the actual observation and filesystem checks, then
return the same retained result and original audit timestamp. Historical result
read-back uses the retained helper/service stage, not fresh execution rights from
an expired parent. Current launch/grant revocation still refuses. The service
also applies shared ValidateLaunchDataResult to the actual stored stage.

Revocation does not depend on a still-running planning claim. It first journals
the token revoked, then stops and observes the real child, requires quiescence,
and closes all pins. RevokeContainment also invalidates associated child tokens;
later native resolution reads that revoked state. A failed stop retains the UID.
Explicit collection of a measured job checks actual source references and mount
namespaces, removes the staged input and cgroup in journaled order, and only
then permits UID reuse. Unmeasured/uncertain failures retain their records and
require administrator recovery. Parent release counts every uncollected child.

Service/store/outbox still owns creation/claiming of LaunchDataStage, current
WorkerLease/WorkerBinding, endpoint listener, exact WorkerInput/WorkerResult
acknowledgement and CompleteEffect. Identity owns native/current worker
authentication. Grants/dataworker owns the actual confined copy and its private
authenticated client bridge. Common CLI must support the frozen worker argv:
it presently requires --config and strips --binding before dispatch, while the
frozen argv contains --binding and no --config. These other-owner files were
not edited. Grants selects runtime.Artifact while lifecycle selects
runtime.Bootstrap; enrollment must make the real executable pins agree, not
pretend different bytes match. A source-cache installer and that endpoint/client
composition must be supplied for installed acceptance. Admin does not create a
listener or a WorkerPrincipal from a serialized label to conceal these gaps.

The new focused controls exercise actual temporary filesystem bytes and explicit
component identity/receipt/observation inputs. They do not prove an installed
helper, a running fixed worker, authenticated bootstrap, mutation reds or
successful materialization. Those results remain pending on Linux.

## Task 3: credential projection ownership

lb-v2-secrets owns CredentialBroker.Acquire, Inject and InjectWorker. They return
logical CredentialSlot/Injection metadata. Fix 11 adds worker identity and usage
evidence but defines no credential-to-helper native descriptor transfer port,
protected mapping resolver or projection ownership/revocation handoff. No named
port for that transfer exists in this contract generation; inventing a method,
slot mode or host path would create new authority.

Admin owns consuming and confining an authorized native projection after that
broker port exists. Until then startConfinedGate refuses any slot/task-secret
projection before opening runtime mounts or executing the vendor. Every normal
validated agent plan requires its runner slot in Injection.SlotIDs, so standard
Prepare remains unavailable. TestCredentialProjectionUnavailable and its control
pin that actual early refusal; omitting the required slot is not a recovery.
