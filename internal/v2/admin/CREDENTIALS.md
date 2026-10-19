# Draft.4 fix 12 administrator receiver

## Current installed counterpart

The fresh-install native binding canary now passes on the disposable Linux
machine under the shipped helper unit properties. It runs the actual source
installer and installed helper, broker and service, binds the native peers,
refuses changed UID/executable/cgroup pins and invalidates an exited broker.
This verifies peer installation and binding, not an authenticated AI-service
request or the complete installed preparation/transfer/serve lifecycle.

The red canary journal identified `publication_cross_mount`: source and target
were under separate `ReadWritePaths` bind mounts, so the kernel refused the
atomic rename. Both owner-created source directories and the protected final
sockets now live under `/run/lb-v2-cred/HASH`, where HASH is the first 32 hex
characters of SHA-256 of the configuration name. The longest socket path is
90 bytes, including a 32-character configuration's fixed-length hash. The helper
publishes within one writable mount using the same directory, socket identity
and no-replacement checks. Publication diagnostics contain fixed words only.

The installed owners can call back while a metadata source read is pending.
The metadata endpoint now accepts those native streams independently and joins
all readers at shutdown. The ordinary mutation listener and existing helper
state lock remain serialized; only the current outside call can lend that lock.
The native concurrent-reader canary failed when its second real socket response
timed out behind the first read, then passed with both original response bytes
preserved. The existing foreign-context lock-refusal control also passes.

Security review flag: the helper's credential write scope is the one protected
configuration directory. The service has a writable `owners/identity` child,
and the outside broker has a writable `owners/broker` child; both are mode
0700 with their distinct owners. The root-owned common parents are mode 0755
without shared writes. Neither unprivileged unit can write final socket names
or its sibling's directory. Review the three unit templates and the installer's
directory/tmpfiles declarations together. No capability or namespace guard was
removed to permit publication.

The source installer now supplies the protected credential-peer catalog, a
distinct broker account and the fixed `laneboss-credential` unit. Assembly
provides the native broker and identity stream owners. The broker uses the
real secrets projection implementation, validators and encrypted journal;
its separate metadata channel exposes only the required typed component ports
and encrypted storage operations. Systemd supplies its key through the fixed
credential mount. No fixture receipt or production catalog is written by a
runtime request.

Both unprivileged owners create their own listeners before the root helper
publishes them. Native UID/GID, socket-bound pidfd, executable, cgroup, boot
and process-generation checks remain on the helper's credential channels.
The additional service metadata channel cannot receive credential descriptors.
Its process and private socket publication are pinned to this installation.
The `source_versions` reply is an object containing `Sources`, preserving
strict object decoding for an empty or populated inventory.

The round history and original counterpart handoff below describe the earlier
receiver-only implementation. Their statements that no catalog or listener
is installed are superseded by this section. A passing catalog-install test
alone does not establish native transfer, installed preparation or the full
serve lifecycle; those require their actual Linux canaries.

## Receiver implementation history

This is an implementation candidate for the private Linux receiving side. Mac
verification includes Go vet compilation; runtime canaries have not run here.
Static formatting, compilation or source checks cannot establish descriptor delivery, isolation, broker authentication,
revocation, refresh correctness or installed launch acceptance.

The public helper and launcher interfaces are unchanged. The service retains
only the bound metadata clients. It asks its authenticated root helper to bind
the native receiver. Descriptor operations on the ordinary service object
refuse and close any supplied duplicates; credentials cannot be routed through
the event-service process as a fallback.

Round 4 corrects a production encoding mismatch exposed by the round-3 Linux
run. DecodeObject rejects explicit nulls, while the newly retained credential
request included untagged optional effect arms, claim outcome and worker fields.
The receiving/held journal also emitted null optional record, refresh, receipt,
fence and withdrawal fields. A typed save could succeed and publish bytes that
the file-backed inventory then quarantined before selecting a stop/revocation
owner. The same claim representation made the private prepare envelope fail
shape validation before reaching the existing preparation prerequisite check.

Optional fields now use omitempty with their existing names. Required fields,
unknown-field refusal, explicit-null refusal and semantic claim/ownership checks
remain intact. No generic decoder or containment ordering was relaxed. The stop
fixture now rereads and validates the actual persisted credential journal before
using its original real canary. Its process kill, process wait, broker-order and
ownership assertions remain unchanged. cred-journal-json restores a null refresh
field and must reach that added persisted-readback assertion.

The helper's staged withdrawal receipt also omits the two broker-owned counts
until the broker supplies them. Completed-withdrawal validation still requires
both counts to be present and measured zero; omission cannot complete cleanup.

The round-3 Linux run failed seven named tests in both builds and reported 24
incomplete red rows. This correction is source-reviewed only on the Mac; it does
not convert those failures into passing evidence. Ordinary/faults reruns remain
required. Existing malformed journal bytes are retained for reconciliation;
this patch performs no migration or rewriting of retained state.

Round 5 addresses five source-review findings. Read-only views now clone and
seal the helper's source mount before entering the child mount namespace, then
move the detached mount through the retained child parent. The namespace action
runs on a locked OS thread that exits after the action; its private fs_struct
and mount namespace are never returned to the Go thread pool. TestCredROView
uses a real root Linux child mount namespace for task and headless paths and
checks the original inode, ordinary canary bytes, read-only/nosuid/nodev/noexec
mount flags and write refusal through the child's proc root. It does not mock
setns. TestCredViewThread performs a real CLONE_FS unshare and observes the
thread disappear. These cases require Linux runtime execution. The view test
file requires the laneboss_root_canary build tag. With that tag, TestCredROView
fails on a non-root host or missing mount privileges; no skip is used. Every
cred-view-* mutation is root-run only and the runner supplies the root tag,
combined with laneboss_faults when requested. An ordinary build excluding the
file is not root-canary evidence.

An uncertain credential stream exchange closes its connection after transport
starts, including socket deadline, nonce, decode and disposition failures. A
fully correlated, descriptor-free owner refusal keeps the shared stream live.
A reconnecting service observes a consumed uncertain transport
through the existing live-channel checks. TestCredCallFailure keeps its context
live while the actual Unix socket read deadline expires, then requires a closed
transport and refusal of a late reply. Its decode/nonce/refusal cases use the
same production exchange and real socket credentials. This is component
transport evidence, not native broker/catalog authentication.

Round 6 reserves the process leader in Linux main-package init and in the
administrator test binary. The view worker locks its OS thread, then rejects
Gettid()==Getpid() before running any namespace/fs action. Nonleader workers
still exit while locked. TestCredLeaderGuard invokes that exact worker directly
on the actual process leader during child init; it requires a prerequisite
error with no action execution, so an accidentally different worker TID cannot
supply a pass. TestCredViewThread also requires a retired nonleader TID, and
both view/thread cases compare the leader's proc mount namespace before/after.

Only a complete, correctly correlated refusal with no returned descriptors may
leave the stream known and reusable. Reply protocol, revision, nonce, the exact
result/error alternative and descriptor disposition are checked first. Refused
transfers cannot return descriptors even when successful transfers could.
TestCredCallFailure/refusal now requires the original error, a live transport,
and a second successful exchange with a fresh nonce on the same connection.
Additional real SCM_RIGHTS, wrong-nonce and mixed-result refusal cases require
descriptor disposal and closure. Deadline/decode/nonce failures still close the
connection and refuse a late reply. Cancellation interrupts I/O through its
deadline and its callback finishes before the shared mutex is released; a
completed call's later cancellation cannot affect reuse. The cancellation
case still requires closure for an incomplete exchange. These runtime checks
remain pending Linux.

Round 7 corrects the root view fixture's child lifetime. Its former Pdeathsig
was tied to the OS thread that created the child, not to the parent process.
The production view worker intentionally retires threads, so a later action
could terminate the fixture child. TestCredLeaderGuard runs in a separate
executable child and cannot leave namespace state in the test process. The
fixture now uses its hold pipe and 20-second command context for ownership,
deliberately starts the child on a retiring view-worker thread, and requires
the child to remain live after that exact thread disappears. cred-view-parent
restores Pdeathsig to make the failure observable without scheduler luck.
This source-supported fixture diagnosis still requires a root runtime rerun;
production view code is unchanged in round 7.

The task/headless order is unchanged. Both cases perform a valid projection,
an actual move_mount refusal at an absent destination, and another valid
projection before the original inode/bytes/mount/write assertions. This covers
worker recovery after refusal without replacing or reordering the existing
checks. TestCredCallFailure now suppresses GC through alias inventory, as the
existing native-frame test does. Its cancel mode gives the exchange a one-hour
deadline and requires completion within two seconds of cancellation after the
request has arrived; cred-call-cancel delays the interrupt to reach that exact
assertion. Socket deadline expiry cannot stand in for cancellation.

Round 8 diagnoses the subsequent root cleanup failure as shared propagation
on repeated acceptance. A detached clone can retain its helper source mount's
shared peer group. After the first successful attachment, a second mount over
that shared child view can propagate onto the corresponding input path in
the helper namespace. The actual missing-destination refusal does not attach
its clone and still closes its descriptor. The child's original recursive
private-root setup does not apply to later imported mounts.

The production MountSetattr now makes the detached clone MS_PRIVATE while
applying its existing read-only/nosuid/nodev/noexec attributes, before entering
the child namespace. Both root cases prepare an independently shared source
bind and reopen the source through it. They inventory and compare helper
mount counts and device/root/mountpoint multiplicities before and after the
first accepted projection, native refusal and repeated accepted projection.
cred-view-private removes only the private propagation field and must reach
the accepted-projection helper-mount assertion. The fixture ordinarily
unmounts only its own source bind after child exit and descriptor closure;
it adds no lazy unmount and keeps TempDir cleanup. The source diagnosis and
proposed fix still require Linux root ordinary/faults red/candidate evidence;
the security consequence of retained credential inodes remains suspected.

The exact credential exec packet and its temporary sealed exports are prepared
and bounded before saving opening or consuming the permit. An oversized packet
keeps the gate prepared with no permit/open journal; temporary exports remain
owned and are closed on every exit. The bounded packet is then handed off while
the existing live guard remains held. Empty object lists encode as arrays for
strict child decoding. TestCredExecBound uses a real closed gate and file-backed
journal to check refusal before permit consumption, and checks the bounded
no-environment encoding. The 64 KiB sender/receiver limit is unchanged.

Canonical refresh acknowledgement must advance the source generation above
ExpectedSourceGeneration. A retry of the same export may return the original
advanced receipt; echoing the expected generation does not acknowledge a
canonical update. TestCredRefreshRetry retains its original export/lost-reply
and foreign-receipt assertions and adds an unchanged-generation refusal.

The round-5 Mac phase compiles/vets all packages and their importers for Linux
amd64/arm64, both with and without laneboss_faults, and Darwin arm64. Runtime
regressions, red controls and composed installed acceptance remain external.

## Binding and native counterpart handoff

The helper reads a protected, bounded, root-owned regular file at
` / etc / laneboss-v2 / credential-peers / CONFIG.json`. Its private Go representation is
`credentialPeerCatalog` in credwire_linux.go. The fields are Schema
(`laneboss.credential-peers.v2`), Config, installation Generation, Broker and
Identity. Each peer has UID, GID, Executable (ID, SHA256, Version), executable
Bytes, Cgroup and ContainmentID. These are administrator installation pins,
not a lane request or a credential value. The broker UID must differ from root,
the service UID and every lane UID. Identity uses the installed service account.
The catalog and its parent chain must satisfy the existing protected-path
checks. No catalog, endpoint or new account is provisioned by this patch.

The fixed endpoints are `credential-broker.sock` and
`credential-identity.sock` beneath the installed configuration runtime root.
Their socket inodes have the pinned UID/GID and mode 0600. An installation must
arrange protected endpoint creation and ownership; the unprivileged owners do
not gain write permission over the helper runtime directory. Both owners must
authenticate the helper independently, including its root credentials, pidfd,
process start generation, installed artifact and control cgroup. The helper
checks the owners' SO_PEERPIDFD, native credentials, cgroup and executable hash,
then rechecks lifetime, membership and executable on every received fragment.

Endpoint publication must preserve the expected outside owner's actual native
SO_PEERCRED and listener lifetime. Changing a socket inode's ownership is not
a replacement for that native identity. The deployment handoff must provide
an owner-created listener and protected publication while retaining the peer
checks above. This patch supplies neither a listener publisher nor an inode-
ownership shortcut for a root-created broker listener.

The private stream protocol is `laneboss.credential-native.v2`. It uses the
existing helperRequest/helperResponse metadata envelopes, contract revision,
installation generation, artifact digest, a fresh nonce, strict JSON and the
existing four-byte big-endian bounded frame length. This is a proposed private
counterpart protocol, not an already installed service or a new public RPC.
Both bound owner connections remain open across requests. A half-closed or
closed transport refuses attachment even when its peer process is still alive;
the native check observes POLLRDHUP/HUP/ERR/NVAL without consuming data.

| Owner | Method | Parameters and result |
| --- | --- | --- |
| Identity | authorize | PeerFacts for the independently pinned broker plus the exact CredentialProjectionRequest; returns CredentialProjectionAuthority. The owner authenticates the calling helper itself. |
| Identity | check_launch | Exact LaunchBindingRequest; returns the current protected CredentialProjectionRecord. |
| Broker | transfer | Exact CredentialProjectionRequest; returns transfer authority and exactly the selected SCM_RIGHTS descriptors in target order. The authority must equal identity's independent authorization/reservation. |
| Broker | acknowledge | Exact remeasured CredentialProjectionReceipt; durably commits held and returns that record. Originals remain broker-owned until this acknowledgement commits. |
| Broker | guard_lock | CredentialGateRequest on a dedicated connection; returns the locked projection. The worker retains the actual source/refresh lock until this connection closes. |
| Broker | guard_check | Empty parameters on that same locked connection; revalidates and returns the unchanged current projection. |
| Broker | begin_withdrawal | CredentialWithdrawalRequest; fences new locks and waits for acquired guards, then returns the exact withdrawing record. |
| Broker | refresh | CredentialRefresh metadata plus one anonymous export descriptor; validates and acknowledges the canonical source update by CredentialSourceVersion. |
| Broker | finish_withdrawal | Record and Receipt fields; adds its independently measured BrokerDescriptors and RefreshLeases and returns withdrawn. Every helper measurement must remain byte-equivalent as metadata. |

Every stream fragment must carry the authenticated writer's SCM_CREDENTIALS.
Descriptor receives use MSG_CMSG_CLOEXEC, enforce the 64-descriptor bound and
close all accepted duplicates on malformed framing, wrong writer, truncation,
owner refusal or metadata failure. Neither source pathname nor value nor
content digest is serialized. Owner errors are reduced to a generic private
control refusal before propagation.

One successful bind consumes the process-local binding. Nil clients,
contradictory replies, transport uncertainty, malformed pins and partial binds
also consume it. Only actual catalog absence before any binding receives an
owning unavailable/retryable CredentialBindingFailure with Unbound certified.
The service resets its attempt only for that exact API retry predicate.

## Exact ports requested from the other owners

These signatures already exist in internal/v2/api/credential_projection.go.
The owner implementations still return their named not_implemented errors in
this checkout. The following is the required implementation handoff; it does
not advertise that a native listener or durable store adapter exists.

### Secrets owner: lb-v2-secrets

Provide the complete api.CredentialProjectionBroker implementation:

```go
TransferCredentials(context.Context, api.VerifiedPeer, api.CredentialProjectionRequest) (api.CredentialTransfer, error)
AcknowledgeCredentials(context.Context, api.CredentialProjectionReceipt) (api.CredentialProjectionRecord, error)
LockCredentialProjection(context.Context, api.CredentialGateRequest) (api.CredentialGateGuard, error)
BeginCredentialWithdrawal(context.Context, api.CredentialWithdrawalRequest) (api.CredentialProjectionRecord, error)
AcceptCredentialRefresh(context.Context, api.VerifiedPeer, api.CredentialRefresh) (api.CredentialSourceVersion, error)
FinishCredentialWithdrawal(context.Context, api.CredentialProjectionRecord, api.CredentialWithdrawalReceipt) (api.CredentialProjectionRecord, error)
```

Supply the actual outside worker, its measured executable/cgroup/account pins
for the administrator catalog, and its native broker listener at the fixed
socket above. The root receiver's native adapter maps these methods to transfer,
acknowledge, guard_lock/guard_check, begin_withdrawal, refresh and
finish_withdrawal respectively. A guard uses a separate authenticated connection;
socket lifetime must own the actual native lock and canonical refresh lease.
Check must revalidate the live current projection under that lock. Withdrawal
must fence new guards and wait for acquired guards before credential cleanup.
Local containment kill/wait does not wait for broker authorization or liveness.

Transfer resolves the selected current slot/grant sources from protected
inventory and validates the original claim, cancellation epoch, grants,
runtime, helper identity and independent identity reservation. It returns one
private sealed read-only source descriptor per target in the exact target
order, with matching Authority and source versions. The worker retains its
originals until the exact durable acknowledgement commits. A lost response
must not create another source export or another reservation. Repeated exact
acknowledge/begin/finish requests return the original committed transition;
changed input conflicts. Every received refresh duplicate is owned immediately
and closed on success, refusal and partial decode.

Refresh must independently validate quiescence, helper lifetime, slot, current
source generation and the actual anonymous descriptor facts. It atomically
updates the canonical credential under the existing refresh lease, retaining
an idempotent receipt for the exact projection/generation, slot, expected source
generation and export-object identity. A lost acknowledgement returns that
same source-version receipt on retry, without a second canonical update.
Plaintext remains inside the native owners and descriptor path. It never
enters an event, generic blob, argv, diagnostic or metadata response.

Finish supplies the worker's own measured BrokerDescriptors and RefreshLeases.
All other withdrawal fields must equal the helper receipt. Missing/unknown
counts refuse completion; a successful socket write is not a durable receipt.
Source revocation and unresolved aliases require rotation while ownership
remains retained. A connection close alone never means a projection was empty.

### Identity owner: lb-v2-identity

Provide api.CredentialProjectionIdentity on both the bound metadata client and
the fixed private native identity listener:

```go
AuthorizeCredentialProjection(context.Context, api.VerifiedPeer, api.CredentialProjectionRequest) (api.CredentialProjectionAuthority, error)
CheckLaunchCredentials(context.Context, api.LaunchBindingRequest) (api.CredentialProjectionRecord, error)
```

The native authorize request has exactly Peer and Request fields, with types
api.PeerFacts and api.CredentialProjectionRequest. Peer describes the broker
that the helper independently pinned; the listener must independently verify
it and the actual connecting helper. The listener derives the helper's native
facts from its authenticated socket/pidfd, installed artifact and cgroup.
Serialized PeerFacts and InternalIntent alone are not authorization. Reserve
the exact request through the protected store and return the same Authority
that the broker's transfer returns; do not produce a second reservation.

CheckLaunchCredentials returns the protected current record for the exact
committed LaunchBindingRequest. It verifies prepared/spec/lease/home identity,
source versions, cancellation, revocation and the complete holding receipt
before issuing a new launch permit. The service-side OpenGate also calls this
port before the helper acquires its native guard. Historical process
reconciliation must retain its original identity and consumed permit and must
not issue a new permit from an expired preparation claim.

### Store owner: lb-v2-service

Provide the existing api.CredentialProjectionStore implementation:

```go
CredentialProjection(context.Context, string, api.ID) (api.CredentialProjectionRecord, error)
ReserveCredentialProjection(context.Context, api.Scope, api.CredentialProjectionRequest) (api.CredentialProjectionRecord, error)
CommitCredentialProjection(context.Context, api.Scope, api.CredentialProjectionReceipt) (api.CredentialProjectionRecord, error)
FenceCredentialProjection(context.Context, api.Scope, api.CredentialWithdrawalRequest) (api.CredentialProjectionRecord, error)
CompleteCredentialWithdrawal(context.Context, api.Scope, api.CredentialWithdrawalReceipt) (api.CredentialProjectionRecord, error)
```

Reservation must join the real current claimed preparation effect, its exact
helper input, protected spec bytes, grants/policy/source inventory, consumed
worker lease when applicable, native peer observations and cancellation fence
under the store writer lock. The reservation is idempotent for that exact
request. CredentialProjection is a protected owner lookup, not a public method.
Only the same native holding receipt commits reserved generation g to held
g+1. Fence advances once to withdrawing after a valid current cleanup cause;
complete advances once only after both native owners report measured zeros.
Each write enforces CAS/current source generations and durable exact replay.
No caller-provided bool, counter or service Actor can substitute for a native
owner or a current store claim.

The store/broker must also retain the canonical refresh update and its exact
source-version acknowledgement atomically under the existing refresh lease.
AcceptCredentialRefresh cannot derive success from an old file, an absent
receipt or an uncommitted source version. Scope and native authority come from
the authenticated owner adapter, not deserialized public request fields.

### Native wire and missing recovery/worker joins

The existing wire.go structures are the exact envelope grammar. Requests have
protocol, contract_revision, config, generation, artifact_sha256, nonce,
method and params. Responses have protocol, contract_revision, nonce and one
of result or error. The protocol value is laneboss.credential-native.v2; the
revision is api.ContractRevision. Return the request nonce unchanged. Use
strict API decoding, the four-byte big-endian frame bound and per-fragment
SCM_CREDENTIALS. The two descriptor-bearing messages are transfer responses
and refresh requests; no other method passes descriptors. The API types retain
their declared JSON field names; File/Files are excluded from JSON.

For an authorization reply lost before its projection ID was received, the
landed lookup-by-ID port alone is insufficient. The helper now retains the
complete original request/claim before calling authorize. A protected owner
reconciliation lookup must join that retained request's config, preparation,
lease, spec, home and original causal/claim identity to the original reservation
and native ownership. It must return only the existing record or an explicit
unknown outcome, never export descriptors or call reserve/transfer again.
This additional read-only join is not a landed API or an implemented protocol
method here. The service/store and identity owners must freeze its exact port
with the administrator before automatic recovery can proceed. Expired original
claims remain historical ownership evidence; cleanup still needs a new current
HelperStop/Abort/Release cause. Until then the uncertain allocation is retained
with containment_unknown and requires reconciliation/rotation.

General channel/usage workers need a protected prelaunch join from the exact
HelperLaunchRequest and current preparation claim to WorkerLease, WorkerPlan,
original immutable input bytes/reference, granted enrolled WorkerCredentials,
and the worker InstalledBinding. Existing WorkerLease lookup, WorkerInput and
WorkerBinding ports do not provide this complete prelaunch join: WorkerInput
and WorkerBinding require an already authenticated worker principal. A caller
argv lease selector or a fabricated worker Scope cannot fill the gap. Service/
store must supply that retained causal join and endpoint enrollment; identity
must independently resolve the same worker/credential selection during
authorize. The administrator can then seal the fixed input/endpoint projection
and set CredentialProjectionRequest.Worker/WorkerCredentials from that result.
This receiver does not add an invented public method or permit secrets for
materialize/capture workers while that handoff is missing.

The administrator validates protected catalog bytes and native peers, but
catalog publication cannot be completed from invented UID/executable/cgroup
pins. The outside-owner deployments must supply their measured identities and
fixed listener lifecycle before the matching installation input can be frozen.

## Restart ownership and binding attachment

leaseManager, Service and credentialChannel are pointer-owned mutex holders.
No active owner is copied by value. A service reconnect keeps the same helper
manager, including its mutex, native channels, held descriptors, one-use state,
gates, capture/network owners and recovery state. The test checks the actual
shared mutex while it is held and reobserves the original closed native gate.
A helper restart constructs a fresh manager through newLeaseManager and reopens
the journal through a fresh store/root handle. It deliberately has no recovered
native descriptors; reconciliation must refuse with containment_unknown rather
than relaunching or claiming the old process. This is a component reconstruction
test, not an installed helper-process restart acceptance result.

A new service process first uses the private read-only credential_binding
helper query. Bound requires the same helper owner and both original native
channels, current installation/boot identity and live pinned peers. The query
does not replace a channel, reset a binding attempt, export a descriptor or
change a projection. Only Fresh permits the separate one-use credential_bind
operation; a retained failed/partial attempt cannot become Fresh. Service-side
BindCredentialProjection remains one-use for that service object, including
after a successful attachment. Helper restart can bind new native channels but
cannot recreate a lost projection or gate from a journal snapshot.

## Prepare, holding and final exec

Prepare carries the durable claimed effect lease into the helper. The helper
retains receiving with the exact request/claim before authorization, then the reserved authority before
transfer. Loss of a reply never requests a replacement export. A helper restart
retains journal ownership but cannot recreate the nonserializable holding;
it returns containment_unknown and requires protected reconciliation/rotation.

Native fstat/fcntl observations require regular, unlinked, mode-0600, read-only,
CLOEXEC source memfds sealed against writes, growth, shrink and seal changes.
Projection makes distinct destinations. Codex uses the lane-owned private
`.codex/auth.json`; task files use their exact granted path beneath
`.laneboss-secrets`, mode 0400 and a 0500 parent. The headless token has its fixed
private path and a kernel read-only view. The helper enters the held child's
mount namespace on a locked thread, installs the read-only mount and verifies
the actual inode and ST_RDONLY through the child root. Failure refuses prepare.
The original private-home inode is independently pinned and checked throughout.

Environment delivery uses root-owned anonymous sealed destinations. The helper
closes and independently checks its received source handles, retains one actual
destination descriptor per target, and remeasures names, modes, ownership,
read-only views and the closed gate before acknowledging. The saved source
facts remain facts about the original received handles; destinations are never
substituted into a transfer validation as though they were broker sources.

Open holds the local lease mutex and live native broker guard through the
durable one-use opening reservation, descriptor delivery, release and native
exec acknowledgement. Immediately before release it checks the guard again.
The private readiness socket receives new root-owned sealed copies for selected
environment targets, never original escrow descriptors or lane-owned token FDs.
The outer bwrap environment stays empty. The sealed bootstrap payload contains
only fixed namespace environment values and metadata.

After the release token and EOF, the fixed bootstrap verifies its actual
nonzero UID/GID and zero permitted/effective/ambient capabilities and the
completed-isolation stage. It validates the complete intended environment name
vector before reading any values. It appends values only to the envp passed to
the existing final unix.Exec; it does not call Setenv, put values in argv or
emit them. Descriptor 5 remains CLOEXEC so the helper observes its EOF at exec,
then verifies the retained native lifetime and actual executable bytes while
the guard is still held. An exited-before-observation executable remains an
unknown result and cannot authorize another release.

## Withdrawal and refresh

Causal HelperStop, unopened AbortGate and native registry revocation first
perform local containment kill and wait. The helper attempts the native
cgroup kill and its held pidfd kill independently and retains every error;
a failed kill is still followed by the available supervisor/population wait.
No broker call is a prerequisite for containment. Revocation records Revoked
before the kill attempt and continues stopping matched owners despite a
credential failure.

The credential journal's local_stop records the immutable local cause/reason
and keeps the lease revoked and uncollectable. It does not advance the broker
record, invent an acknowledgement or report a broker fence that never happened.
After local containment has completed, the helper attempts broker withdrawal.
On refusal or unreachability it returns the error, retains the last broker
record/generation and every held credential object, and leaves local_stop in
place. New acquisition/opening refuses a revoked lease. A later HelperStop or
withdrawal may finish cleanup; recovery cannot erase or weaken local_stop.

The selector-only revocation route synthesizes an InternalHelperStop cleanup
intent from the retained preparation target/config/requester/epoch, with a new
identifier retained in local_stop. This is a native revocation cleanup cause,
not a fabricated claimed outbox effect or fresh launch authority. If an outside
owner refuses that cleanup cause, local containment is already stopped and the
credential ownership remains retained for a later authorized cleanup. Data and
capture invalidations are preserved when the parent journal is reread before
credential publication.

Release still requires its terminal observation and complete independent
cleanup measurements. A later release cannot downgrade a local revoked/refused
reason to normal release. Revoked containment cannot return a normal Codex
refresh; withdrawal requires rotation even if an earlier broker fence used a
release reason. No lease collection is permitted until both owners complete
the measured withdrawal.

Withdrawal waits for the original supervisor and native containment to become
quiescent. It compares each file name with the retained destination inode,
unlinks through held parents, verifies zero remaining links on the original
held file, closes descriptors, checks source disposal, and scans native
references to the retained inode inventory. It also measures the actual release
descriptor inventory. Missing objects, aliases, replaced names, incomplete
projection and unreadable references retain ownership and require reconciliation
and rotation. They never produce fabricated zero receipts or recycle the UID.
The broker must supply its own measured zero escrow and refresh-lease counts.

Only a normal fenced Codex release can return refresh. The original lane copy
must remain the exact unaliased inode with the required private mode. A fresh
anonymous root-owned sealed export is measured and sent directly back to the
broker. Uncertain acknowledgement reuses that same export and metadata; the
broker must make acceptance idempotent for the exact projection/generation,
slot, source generation and export object. The helper journals the returned
version before closing its export. A restart cannot create another export or
infer a canonical update from an absent response.

## Regression and acceptance status

The mutation inventory names its own assertion for every added control. These
tests and controls are authored but unexecuted here. No red or green result is
claimed. Test doubles represent port refusals and ordering only; native files,
socketpairs and UID/capability observations are used where indicated.

| Obligation | Focused regression | Red control |
| --- | --- | --- |
| Permanent and certified-unbound binding | TestCredBindPermanent; TestCredBindRetry | cred-bind-permanent; cred-bind-certified |
| Independent immutable destination | TestCredAnonDistinct; TestCredDescriptorSeals | cred-distinct-object; cred-source-seals |
| SCM writer/disposition and service exclusion | TestCredNativeFrame/writer; TestCredNoServiceFD; TestCredSourceDisposal | cred-frame-writer; cred-frame-close; cred-service-fd-close; cred-source-count |
| Acknowledge only actual holding | TestCredAckHolding | cred-ack-held |
| Guard through exec acknowledgement | TestCredGuardLifetime; TestCredGuardRefusal | cred-guard-live; cred-guard-check |
| Measured cleanup and retained ownership | TestCredCleanupEcho/files; TestCredCollectionFence; TestCredRecoveryRetains | cred-cleanup-measured; cred-collect-fence; cred-recovery-retain |
| Original refresh export and canonical receipt | TestCredRefreshRetry; TestCredRefreshLost | cred-refresh-receipt; cred-refresh-lost |
| Final unprivileged isolated exec stage | TestCredExecStage | cred-env-stage |
| Same helper mutex/state on service reconnect; fresh owner after helper loss | TestGateRetainedReconciliation | gate-service-lock-owner; gate-helper-owner-loss |
| Partial binding remains fenced; missing native owners cannot attach | TestCredAttachBoundary | cred-attach-partial; cred-attach-native |
| Live native owner transport | TestCredChannelLifetime | cred-channel-lifetime |
| Exact request/claim durable before authorization | TestCredRequestDurable | cred-request-journal |
| Broker failure cannot prevent revocation, process kill or wait | TestCredRevokeFailure | cred-revoke-contain |
| Broker failure cannot prevent stop or unopened abort | TestCredStopFailure; TestCredAbortFailure | cred-stop-contain; cred-abort-contain |
| Failure/ownership remain visible after containment | TestCredStopFailure; TestCredRevokeFailure | cred-stop-error; cred-stop-local; cred-stop-collect |
| Failed population wait prevents credential cleanup | TestCredWaitFailure | cred-stop-wait |
| Recovery cannot erase or weaken the local stop fence | TestCredFenceRecovery | cred-stop-recovery |
| Later release preserves the local revoked reason | TestCredRevokeFailure | cred-stop-reason |
| Kill success does not replace the native wait | TestCredStopFailure | cred-contain-wait |
| Missing native owner still requires population waiting and an error | TestRevokeTerminal | cred-wait-owner |
| Kill errors cannot skip the remaining wait | TestCredKillFailure | cred-kill-wait |

The round-3 stop regressions use a real process, pidfd kill and native process
wait with an error-returning broker port. Their owner fixture covers that
single-process ordering; it does not claim actual cgroup/UID quiescence,
authenticated projection or successful withdrawal. Linux ordinary/faults
red-before-green and installed containment/broker-outage rows remain required.

The landed secrets, identity and store credential methods remain stubs in this
checkout. Their native endpoints, protected pin enrollment and durable lock,
claim/cancellation/source checks must be implemented by their owners. General
credential-bearing channel/usage workers still lack the existing protected
WorkerLease / original-input / WorkerCredentials gate handoff; this patch does not
turn the credential-free materializer into that worker. Those launches remain
refused. Ordinary and faults Linux builds/vet, component tests, every named
red-before-green control and installed Codex/headless/task-file/task-env,
partial-transfer, guard/withdrawal race and restart/rotation rows are required.
The full brief is therefore not accepted or complete as a composed launch.
