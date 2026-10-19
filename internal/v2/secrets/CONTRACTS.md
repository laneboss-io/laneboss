# Secrets contract and native format

This lane implements secret.key, session-bound in-memory secret.stage,
proof-guarded secret.import/rotate/revoke, and the secrets consumer of draft.4
fixes 9 and 10, plus fix 11's outside usage producer and credential-worker
mapping consumers. Acquire, Inject, InjectWorker, Release, RevokeInjection, Room and
Eligibility call their real implementations. They propagate failures from the
installed store, grants, helper and launch-control ports. They return no
success based only on an ID, caller observation or caller-selected path.
The public API shape is unchanged. SecretList now uses the protected native
metadata reader and the current session/life/grant scope; RunInternal still needs the installed fixed
credential job and protected channel. CONTRACT-GAPS.md names the remaining
producer, composition and runtime acceptance requirements.

## Metadata enumeration

`native.WithMetadata` authenticates encrypted records under the ordinary
cross-process mutation lock and exports only `SecretInfo` to its callback.
`SecretList` checks the current stored human read-session revision or exact
lane/run and revalidated grants before enumeration, reads one pinned internal
configuration-event snapshot, and checks authority again before delivery.
Human results contain committed current public heads. Lane results contain
only exact delegated source/version selections; unrelated protected profile
sources stay unpublished. An interrupted change to an existing public name is
a reconciliation conflict. Locked or damaged records fail before a result.

The single store writer projects `secret_head` and `secret_source` from the
actual secret event. Import/rotate replies must equal that operation's source
metadata. Mutation events must match the exact name/version/current base in
the original proof-bound request. Verification reconstructs these projections
from the immutable journal. Secret events use the supported `service` origin.
No secret value is retained by these projections. Historical successful event
stores without these private projections still need a reviewed migration;
verification does not silently repair them.

## Installed inputs and clocks

Native.New requires Directory, Config, KeyHandle and Clock (api.Clock); it
starts locked. Missing installed inputs return prerequisite_missing. Keys arrive
only through Unlock's exact protected 32-byte reader. Secrets.New requires
Backend, Store, Human, Clock and Config. Assembly supplies installed.Config to
both constructors, its clock to both, and Grants: delegation to Secrets.New.
If ServiceScope is absent, Secrets.New derives the fixed internal service scope
{Config: installed.Config, Actor: {Kind: service, ID: secrets}}. A supplied scope
must have that configuration and a valid service principal. It is an internal
lookup scope, never caller-supplied authority. Assembly still owns the approved
protected unlock and worker lifetime; no key is inferred from a handle or path.

No exported api read-window constants exist in this draft. The local
readIdleLimit is 5 minutes and readAbsoluteLimit is 30 minutes of remaining
authority. TestReadWindowContract pins both durations and exercises the exact
boundary and one nanosecond over it. Identity must publish a shared constant
before changing those bounds. The actual connection's ReadAuthority must have
its ConnectionID, current principal/config/endpoint, live session/credential,
valid expiry and a matching retained Scope.ReadAuthority when supplied.
Read/stage/lane calls reject attached operation proofs. Mutations reject missing,
malformed, expired or different-intent ProofRefs before verifier/backend work.

Native Fetch uses the required injected Clock for expiry. SealStage accepts an
optional api.Clock for deterministic callers and controls; an omitted clock is
the client UTC wall clock. Supplying a nil clock or more than one refuses.
There is no store-side wall-clock override or key fallback.

## Session staging

The private upload key and importable stage remain in protected service memory.
Secret.stage also commits its exact metadata reply through the normal request
transaction, with the original encrypted request frame and current bound read
authority. The receipt contains no plaintext material or private upload key.
Completed metadata replay does not recreate a lost key or importable stage.
Both bind principal, actual connection, human read-session and endpoint generation.
The lifetime is at most 120 seconds and also bounded by the issuing read
authority and key expiry. Staging validates ciphertext bounds without decrypting.
It deep-copies the encrypted input, caps keys at 4 per principal / 128 total,
and caps live stages at 128. An in-process identical stage retry returns its
original receipt; changed intent with the same retry key conflicts. Expired
entries are removed and owned ciphertext slices cleared when accessed.
Restart loses unconsumed stages; the human must stage again.

The stage handler publishes no success until that exact reply is committed.
A failed reply commit clears and removes its unacknowledged in-memory stage;
it returns the original failure. An identical in-process retry still retains
the original proposal and passes the same live-key/session checks before the
ordinary receipt transaction. The dispatcher integrity check is unchanged.

Import/rotate verifies the exact operation proof before backend access and
decrypts only the selected session-bound stage, authenticated with the staging
AAD and algorithm already frozen in section 5. An in-memory claim binds that
stage to one exact mutation request key/digest. A failed backend write can retry
that same claim. A successful commit retires it. Plaintext material is cleared
after Store returns and never enters events, raw metadata replies, generic
objects, logs, arguments or source archives.

## Mutation ordering, version checks and recovery

The dispatcher/StateStore owns durable request reservations. The module checks
LookupReceipt and reserves an absent request before external work. It never
awaits its own pending reservation. Completed same-key/same-digest receipts
replay before stage/version checks or another proof consumption; current
transport and StateStore visibility/revocation checks still apply.

The native lane-local WithMutation capability holds its mutex and the ordinary
cross-process directory lock through authenticated metadata inspection, version
comparison, Store/Revoke and the single StateStore.Transact. Its callback receives
a temporary backend view which cannot be used after the callback ends and does
not permit Fetch. StateStore must not call back into native while holding its
write lock. Other backends need an equivalent protected capability before this
lane can administer them; SecretBackend's grant-scoped Fetch interface is
unchanged.

Only committed secret events advance the current name/version. Import requires
an absent name; rotation/revocation require the exact current nonrevoked version.
Rotation writes a fresh immutable version; exact existing version grants remain
pinned to their selected source. The broker never infers a broader selection.
For this lane's replay mapping, an imported/rotated event's opaque ID equals its
SourceHandle. The event contains one name/version and key ID, empty grant IDs
and the imported/rotated/revoked outcome. Revocation advances that head's status.
The module replays the configuration's ordered committed events under the
backend lock and correlates them with authenticated backend metadata. It refuses
unmapped/malformed history; it does not guess which old backend record is newest.
This mapping is local implementation format, not a new shared schema key.

The backend write happens first. One transaction then carries the exact verified
request frame, one ProofUse for AuthorizationTarget, one secret event and the
typed final reply. CheckProof verifies facts without consuming them; Transact
rechecks and consumes the proof atomically with the event and retained reply.
No success is returned from a pending commit, failed backend or failed transaction.

Source handles derive from config/principal/method/retained retry key/digest,
so an exact retry finds the same authenticated source. An interrupted Store
leaves ciphertext without a committed event and no consumed proof. Unrelated
operations on that name stop for reconciliation. The original request can
reconcile the existing source even after restart has lost its stage, without
writing a new nonce or value. Native Store itself also replays identical
metadata/material without rewriting; changed reuse conflicts. Revocation
tombstones additionally bind the original operation ID. A different request
cannot adopt an interrupted tombstone; an exact retry authenticates and reuses
it, then commits proof/event/reply once. StateStore transaction failures must
retain pending reservations for this retry route rather than fabricate a final
success. The owning dispatcher/store must preserve this broker retry distinction.
Post-backend transaction interruptions carry the original operation ID; typed
unavailable/deadline/cancelled errors are retryable. They are distinct from a
failed module preflight, which the dispatcher can finalize with its typed error.

## Native encrypted files and authenticated data

The installed final directory is ordinary, service-owned mode 0700. Open first
Lstats its preexisting parent and requires an ordinary nonsymlink directory owned
by the effective UID with no group/other write bits. It creates only the final
directory. A pinned os.Root confines I/O; record/lock files are ordinary,
single-link, service-owned mode 0600. Directory/lock privacy and the opened lock's
pathname identity are rechecked before protected I/O. Lock(ctx) retries
nonblocking flock every 10 milliseconds until acquisition, cancellation or the
context deadline; it never returns contention as an immediate conflict.
Writes fsync ciphertext, atomically rename it, then fsync the directory.

Regular files are SourceHandle.json with schema laneboss.secret-record.v2,
configuration, SecretInfo, nonce and ciphertext. AES-256-GCM uses a fresh random
96-bit nonce. The AAD is the compact canonical ASCII JSON object with sorted
keys config, key_id, name, revoked, schema, source_handle and version. This is
the lane's full on-disk AAD superset; source/schema/revocation are deliberate
additional authenticated fields. Broker tombstones have the optional top-level
revocation_id. When present, that nonempty opaque ID is also included in AAD
between name and revoked. Omitting it preserves the preceding seven-field
format for ordinary records and administrative backend tombstones. A nonempty
revocation_id requires revoked true. Removing/changing it invalidates the tag.

First successful Unlock writes .key-KEY_ID.json with its own schema
laneboss.secret-key-check.v2, config, key_id, nonce and ciphertext. Its AES-GCM
plaintext is empty; ciphertext is the 16-byte authentication tag. Its canonical
AAD keys are config, key_id and schema. Every subsequent Unlock authenticates
that record, including an otherwise empty store, before installing the key.
The sealed check is excluded from regular Names enumeration, while its
mode/identity/link checks remain mandatory. It stores neither a key nor a key
hash. Reopening starts locked. Independent recovery uses a separate protected
32-byte recovery key and config/key-ID/schema AAD; no environment discovery,
plaintext key file, keychain or automatic replacement key is available.

The OS must still protect worker memory and files from lanes. Native encryption
does not protect against compromise of that trusted UID or the kernel. Owned
key/material slices are cleared, but Go does not guarantee erasure of every
temporary key schedule.

## Reserved launch inputs and protected slots

Acquire/Inject resolve the target's actual Lane or issued reserved-life grant
set, then call the installed GrantResolver.Revalidate and compare the complete
result. They recheck policy generation, revocation and expiry. For a reserved
life they discover selectors through bounded PendingEffects, reload the running
EffectRecord with its claim/generation/claimant/deadline, and reload the sourced
LaunchPlanRecord. The reservation must match configuration, life/run, original
operation/request/requester and cancellation epoch. A reserved child never
becomes a fabricated ready Lane.

The broker reads protected objects in contiguous chunks of at most 256 KiB,
checks each returned chunk hash and the complete object hash within the 1 MiB
input bound, then strictly decodes the original request bytes.
It checks their metadata/origin and selects the exact requested profile/model.
Resume/turn reload the previous binding, plan and run. Internal continuation
uses the retained ContinuationRequest, current ContinuationIntent, unchanged
swap/eligibility/room, previous private session and original epoch; it does not
invent a public continuation RPC. Its exact retention requirement is recorded
in CONTRACT-GAPS.md. Current claims, input records, grants and policy are read
again during protected preparation. Continuation rechecks inside the journal
use store data only, avoiding recursive entry into the encrypted backend lock.

ResolveLaunchSources and ResolveLaunchStorage are actual HelperControl calls.
The source enrollment, helper allocation event and private storage must match
the reserved input and original cause. Retained home/history is reused only as
private history, never as a credential slot. Stable slot IDs and full input
fingerprints preserve exact retries without rewriting material. Changed inputs
or a changed injection subset conflict, including after partial preparation.
Inject requires the exact prepared profile slot and the selected task grants;
its result contains metadata and opaque slot IDs, with outcome prepared.

Native WithBroker uses the existing mutex, private directory and contextual
cross-process flock. Its callback receives only a temporary Journal with
Read/Write/Fetch; it cannot perform a public secret mutation. The view refuses
use after callback completion and refuses writes after cancellation. The
closed file kinds are profile, slot and login. Their files are
.broker-KIND-ID.json, schema laneboss.credential-state.v2, with config, kind,
id, key_id, a fresh 96-bit nonce and AES-256-GCM ciphertext. The canonical AAD
keys are config, id, key_id, kind and schema. The ciphertext holds the typed
profile/slot/login payload, including any material. Full tagged/default Go
field maps are decoded strictly, with 192 KiB plaintext and 256 KiB envelope
bounds. Broker files remain subject to ordinary ownership/link/mode checks
even when excluded from regular secret metadata enumeration.

## Protected profile evidence and refresh ownership

InstallProfile is a concrete service-private installer method, absent from the
RPC registry. It accepts metadata only: canonical login ID, generation, exact
source grant, supported mode, driver/provider/paid status, executable pin,
supported models/vendor versions, allowed refresh fields and protected evidence.
Supported modes are headless_token, helper and file_login. It performs no
authentication, environment discovery, keyring lookup or host-home import.
The installed administrator and fixed credential worker must produce these
facts from the actual enrolled profile.

The private helper spelling describes opaque retrieval. New public slots use
claudock-helper for Claudock and codex-api for Codex, the existing frozen wire
names. Projection compares that same public name with the actual current
profile, in addition to the unchanged generation, expiry, policy, grant and
exact retained-slot checks. This changes neither credential bytes nor native
login formats. Real adapters keep their unavailable helper/API-mode gates.
Retained slots and failed stage outcomes are not rewritten during replay.

Room checks actual immutable service-origin credential_evidence bytes, hash,
ACL, configuration, canonical login / profile / generation / driver / provider and
successful producer operation. CheckedAt is a UTC Z timestamp, no later than
the injected clock, and precedes an expiry at most five minutes later. It
returns the producer's actual available/unavailable result with bounded expiry.
Eligibility preserves current source profile, session/history, model, grants,
driver/provider, paid-fallback and exclusion checks. Compatibility requires
both enrolled model/vendor sets and the same executable pin, plus the exact
retained launch/history binding. Its typed result includes the original
request, a stable assessment ID and existing protected producer evidence. The
continuation owner retains that complete result under its own claim; this read
does not borrow a completed helper effect for a new object-retention write.

All aliases of a file_login use one encrypted canonical-login record and exact
base source. Ownership is persisted before copying any bytes. A second
reservation waits contextually for the owner, even when the old slot has
expired or the service has restarted. Missing ownership or unknown retained
binding cannot free it. Supported returned fields are access_token,
refresh_token and expires_at, limited further by enrollment. Tokens are bounded
nonempty strings; expires_at is a future UTC Z timestamp. Every non-refresh
identity field is immutable, and unknown/removed fields refuse.

ReturnSlot stores returned bytes only for the original bound file-login slot,
profile generation and canonical owner. Measured release imports that refresh
into the encrypted canonical record with its original refresh-slot ID. It
does not create an uncommitted regular secret version or mutate the enrolled
immutable source. The run slot is tombstoned before freeing the owner; an
interrupted retry can complete that same sequence. Later aliases copy the
latest canonical bytes while still checking the enrolled source's revocation.
The canonical registry is retained private state, not a mount for a lane.

## Nonexecuting delivery and measured cleanup

PreparedSlotMaterial is a concrete service-private material port for the
installed helper adapter. For agents it requires phase spec_retained, the
complete validated plan/spec, original spec bytes, Control.Handoff and actual
Helper.ResolveRuntime receipt/home/workspace/executable pins. No ready identity
binding is fabricated before Prepare. SlotMaterial is the separate post-binding
lookup; it requires the complete retained LaunchBinding and recovery tuple.
Both recheck current grants, slot state/expiry and actual source revocation
before copying bytes. These methods never register an RPC or put material in
generic BlobRefs, events, logs or arguments.

InjectWorker prepares encrypted slots before a final spec exists. It reloads
the exact WorkerLease, live fixed Worker effect, protected input bytes and
RuntimeManifest/bootstrap pin. It fingerprints the complete job, manifest,
current grants and requested selection. Only exact selected SecretGrants are
supported; a channel handle alone supplies no invented version or delivery.
PrepareWorkerMaterial then requires the complete spec/handoff, exact retained
injection, real Control.Handoff and Helper.ResolveRuntime before returning
bytes. It retains that final handoff for retry and cleanup. A changed spec
cannot rebind an existing slot. The helper/worker owners still implement the
actual private env/file projection and its physical collection.

Release/RevokeInjection reload and validate the retained binding/plan or fixed
worker handoff. Caller quiescence is only a comparison claim. A fresh
Helper.ObserveGate must agree with its exact process generation and exit facts;
Control.Release supplies the real causal helper-release request. The broker
calls Helper.Release, requires known-zero processes/connections/jobs/writable
exports, records the actual receipt through Control.RecordRelease, and reads
the correlated committed helper.released receipt back before clearing material.
All selected slots are validated before any injection cleanup. Exact replays
reuse that retained measurement; even released slots refuse a changed process
generation. Unknown/nonzero resources, missing/revoked recovery data and missing
receipts retain the slot and canonical owner. No force removal or speculative
reuse is implemented.

## Fix 10 reservation and prepared delivery

New reservations and fixtures retain Level, Role, Driver and the consumed
Authority. Start/adopt compare their exact original selection and root ticket
with those stored pins. Resume/turn preserve the original consumed proof ID
and intent digest, and compare the prior binding's role, level and driver.
Continuation uses its retained previous-launch authority and requires registered
capture. Agent prepared delivery calls ValidateAgentLaunchSpec and checks the
current protected capture policy before returning material. A refused capture
needs its retained policy generation and approval, with the current flag and
approval still enabled. Worker bindings carry Kind=worker and a separate
zero-level worker actor. Fixtures call the shared validators; they do not remove
shape gates to make legacy records pass.

## Fix 11 outside usage and active workers

ReadUsageWindow implements UsageWindowSource. It reloads the causing Claudock
binding/plan, exact from-profile and actual zero-survivor lane.ended observation,
then checks the protected usage enrollment. UsageProfile contains only private
vendor spelling, adapter version and executable/runtime pins. No lane output,
destination room or caller-supplied TSV is an evidence source.

The installed local UsageJobControl adapter dispatches/reconciles a separate
usage worker and returns its real input/result connection frames. WorkerInput
and WorkerResult use the shared bootstrap interface. Native peer liveness and
frame verification precede the real Store.WorkerBinding read and shared
ValidateWorkerPrincipal comparison against those independent native facts.
The claim, lease, endpoint and producer are rechecked throughout the query.
The job has a distinct retained grant set with exactly the selected source,
bounded nondelegable network grants, and no workspace, resource, profile or
channel capabilities. Source revocation is checked before and after measurement.

The source validates the sealed input and protected runtime manifest, checks
the actual successful result, and reads back the acknowledged worker-result
bytes and producer ACL. It retains exact private usage_raw and usage_window
objects under the original object-retain claim. Immutable retries preserve
the same bytes and authority; stale observations require a newly measured job,
never a relabelled timestamp. Both shared usage validators run before return.
The header is exactly PROFILE, PLAN, WINDOW, USED_PERCENT, RESETS_UTC in that
order, separated by tabs. Every row has finite nonnegative usage, a valid UTC
reset or explicit unknown marker, and a consistent plan per profile. Only an
exhausted selected row with a known future reset can prove a limit. The
observation must follow the actual run end, cannot be in the future, and is
at most 30 seconds old. Failed/partial command output never proves exhaustion.

RunUsageCommand is the separately installed Linux worker's command engine. It
checks its actual UID/GID/PID, kernel generation and boot, copies the held
native executable to a sealed memfd, hashes the sealed bytes against enrollment,
and executes those bytes with argv claudock usage --max-age 0. It uses the
helper-held worker-owned mode-0700 home, explicit HOME/XDG_CONFIG_HOME/PATH/LANG,
a timeout of at most 60 seconds and bounded separate stdout/stderr. It preserves
the actual exit and observation time. The helper must project the selected
profile in that private home's real vendor format and confine settings, network,
keyring and descendant processes. This engine creates no login or containment.
Other platforms return unsupported; absent Linux sealing support refuses.

The command checks an already-cancelled context before input/executable work,
starts its single timeout before preparation, and checks that context again
before dispatch. After the real process is waited, actual output overflow has
typed unavailable precedence; otherwise cancelled/deadline contexts keep their
typed error instead of becoming a generic process failure. Both stdout and
stderr remain bounded, and refused results return no raw evidence.

InjectMappedWorker and MappedWorkerMaterial are concrete private delivery ports
for active worker connections. Only channel and usage workers may use
credential.inject. A copied consumed lease is not authentication. Delivery
checks the current mapped principal, exact retained injection/binding, current
job grants and actual source revocation, then rechecks the mapping before
returning bytes. Pre-spec InjectWorker remains an installed service operation;
its grant lookup now uses the lease's actual job grant set. Assembly and the
service/store owners must connect these ports. The generic RunInternal entry
still refuses without its installed job dispatcher and material channel.

## Evidence limits

Mac checks in this round are static: gofmt, Linux vet, Linux vet with
laneboss_faults, Darwin vet and Python compilation. The retained Linux handoff
requires exact-source unit/race checks and every available named red control
before green, plus the separate outside-observer/probe controls. None has been
executed on this Mac. Static checks, component fixtures and the credential-free
demo are not authenticated AI-service, live credential, native Mac or
OS-boundary acceptance. SECRET-INJECT and CREDENTIAL-BOUND remain unclaimed.
The catalogue retains all 153 preceding Go controls and adds seven fix-10 and
nineteen fix-11 controls and thirty fix-12 controls, for 209 available rows. Nine full live controls remain
unavailable. Every new runtime assertion and both corrected red-box controls
still require their exact-source Linux red-then-green evidence. Consumer fixtures
use synthetic bytes and post-authentication records. The native command fixture
installs an exact mode-0500 copy of the test binary as a synthetic file-backed
program; it is not claudock
or an authenticated quota query. The real dispatcher, mapping, bootstrap and
vendor-profile projection remain composition requirements.

The command fixture no longer assumes cmd/go's temporary executable has
installed-runtime permissions. The compiler's output mode depends on umask;
the fixture installs and reads back an exact private copy. The product's
non-writable executable check and all argv/environment/stdout assertions stay
intact. A separate negative makes that installed copy group writable. The
started-child cancellation test observes a real private readiness pipe before
cancelling, and stdout/stderr overflow cells execute real child writes. The
reported prior box output omitted the engine's actual error code, so writable
build permissions are a suspected masking cause until the Linux rerun records
the new value-free diagnostics.

## Fix 12 native projection

Secrets.New requires ProjectionIdentity in production. Existing human-only
component fixtures install an explicitly denying identity port; none can
silently authorize a native helper. The broker implements all six private
CredentialProjectionBroker methods. It validates the complete retained handoff,
actual helper runtime/home receipt, current prepare claim, current approved
policy, current grants, exact selected slots and canonical source inventory.
The two native modes remain codex-file and claudock-headless. Legacy helper,
file_login and API modes are not relabelled as those native shapes.

TransferCredentials reserves and reads back the unique prepared-gate record
before creating any export. It writes a protected projection journal before
export, binds slots to that projection, and creates one ordered anonymous
descriptor per fixed CredentialTarget. Linux sources are private mode-0600
memfds with write/grow/shrink/seal protection, read-only access, close-on-exec,
zero links and no writable aliases. Source object facts come from fstat/fcntl.
A read-only reopening of the owning broker's own sealed memfd is local
preparation; no source path or fd number is sent as control metadata.

SendProjection uses a private unixpacket connection with actual SCM_RIGHTS.
It verifies the socket peer and every recvmsg writer, rejects unexpected or
truncated controls/counts, and uses MSG_CMSG_CLOEXEC on received rights.
Received duplicates are owned immediately and are closed on refusals.
The sender retains originals until AcknowledgeCredentials independently calls
the helper observer, validates exact held destinations/counts, commits and
reads back the same held record. SendProjection returns completion only after
that acknowledgement. A partial/lost exchange fences its original allocation;
a missing record or changed retry never becomes empty credentials.

LockCredentialProjection holds the existing cross-process canonical journal
lock through the live guard. Check reloads the protected held record, exact
permit/binding, current open control, claimed effect, approved policy, grants,
source revocation/generation, life epoch and native peer lifetime. It does not
recursively acquire a refresh lease. GuardProjection holds this guard across
the helper's native exec acknowledgement. The helper still owns its lease
lock, one-use OpenGate, native UID/capability/isolation measurements and final
ValidateCredentialEnvironment call. The broker never creates task envp or
places values into an outer/helper/bootstrap environment.

BeginCredentialWithdrawal closes new admission before draining an acquired
guard, journals the fence and reads back the store's exact causal transition.
FinishCredentialWithdrawal requires independent helper cleanup and known
zero counts before closing originals, tombstoning slots, releasing canonical
ownership and completing/read-backing withdrawn. Ordinary Release/RevokeInjection
cannot release a slot whose projection has not completed withdrawal. Unknown
counts, rotation requirements, nonrelease exposure after execution and failed
dependencies retain the allocation. Exact retries preserve the original record.

ReceiveRefresh receives the root helper's reverse SCM_RIGHTS export.
AcceptCredentialRefresh closes every received duplicate on all paths, measures
its actual immutable descriptor, requires a normal-release fence and real
zero-survivor helper observation, then invokes the pinned Codex subscription
account validator under the canonical journal lock. Protected account identity
is retained across aliases. The same immutable return object replays its
receipt without applying another update, including after interrupted journal
receipt completion; actual source revocation is rechecked. No lane pathname
is opened as refresh input. Native facts/values stay outside generic blobs,
events, argv and errors. Vendor validator refusals use fixed broker diagnostics.

Darwin and other non-Linux exports currently refuse with an owning typed
failure: exclusive immutable unlinked ownership has not been established there.
New-process recovery with an uncertain original broker lifetime also remains
fenced until the identity/store/helper owners establish authoritative recovery.
No fresh export or automatic credential/home/UID reuse substitutes for it.

## Installed vendor projection pins

Prepared material and native credential transfer validate the selected agent
against the protected installed runtime manifest independently of the helper's
observation. Canonical `claudock` and `claude` files use their matching vendor
roles, with exactly one object bearing the selected ID in each manifest. The
complete object must agree across those reads: root, path, content reference,
digest, size and mode. Vendor files require mode `0555`, artifact content and
the selected executable's digest. The gate Bootstrap remains a separate exact
installed pin. Combined Bootstrap/agent runtimes and the build-tagged stand-in
retain their existing checks; vendor roles do not authorize a stand-in.

An internal storage `not_found` is not by itself a failed launch. First-use
key checks, selection markers and journal generations intentionally probe for
an absent record before creating one. First projection transfer reads its
absent journal and probes its prior generation before writing; replay finds
the retained journal. Failure cleanup also probes for a projection that may
not have been created, then preserves the original error. Missing required
sources, profiles and slots still propagate a refusal. Selector-free storage
journal lines cannot identify which record was probed. The Linux vendor
projection component test observes the real encrypted-file reads, successful
transfer/replay and missing-required-source refusal; it does not claim a full
installed vendor lifecycle or an authenticated model request.

## Review follow-ups in this revision

Broker envelopes now authenticate an explicit increasing generation in AAD;
writes authenticate the preceding envelope before advancing it. Old envelopes
without that field refuse and need protected migration. This binds the
generation to bytes; it does not by itself detect replay of a complete older
authenticated envelope without an external monotonic inventory.

Metadata retries fetch the actual source again and reject expired profile
slots. Live retained selections permit approved historical grant issuance only
after the Lane policy projection is current; unopened launches and new worker
preparation still require current policy. Resume/turn decode and compare the
original target/base and current launch/epoch. Usage grant revalidation compares
the complete retained set and launch digest. Usage executables reject every
write bit and special mode bits. Each actor has at most eight staged uploads,
within the existing global 128 bound. Head replay has page, event and byte
limits; a durable authenticated head index remains future work. Handoff command
paths are corrected. Additional loader/language-control names are refused.

The existing usage-command HOME=/proc/self/fd/4 behavior is unchanged. Whether a
pinned vendor's descendant preserves that descriptor needs a real canary and a
stable helper-projected namespace path; guessing a host pathname here would
weaken descriptor ownership. That P3 remains open.

All new regressions and controls require their named Linux failure followed
by candidate success. The projection fixture validates shared contracts but
models authenticated helper ownership/holding observations. Real Linux export,
sealing, SCM_RIGHTS bytes and the owned process are distinct measured scopes
when those tests run. They do not prove a root helper, cross-UID confinement,
final task envp, signed identity or a live vendor session.

## Runner validation ports

The secrets production package does not import a runner. Its installed
CodexCredentialValidator and HeadlessCredentialValidator interfaces are narrow
outside-worker ports. The runner-owned codex.CredentialValidator and
claudock.CredentialValidator adapters call their unchanged NewCredential
implementations and clear the temporary owned copy. No schema, credential type,
constant or destination rule is copied into secrets. CredentialTargets remains
the shared destination authority in api.

The lb-v2-integrate outside-broker composition must supply
Dependencies.CodexValidator: codex.CredentialValidator{} and
Dependencies.HeadlessValidator: claudock.CredentialValidator{} for the selected
installed modes. A missing selected-mode validator returns prerequisite_missing
before export or canonical refresh; it cannot authorize material. This lane
does not edit assembly or install those native processes. Configured validation,
account affinity, fixed broker errors and every existing control are retained.
The Linux projection fixture installs the actual runner adapters. Codex's
usage_test.go and its import of secrets remain unchanged.

## Round 4 delivery and release fences

Worker credentials require exact equality between the issued grant policy
generation and the current policy at preparation and material delivery. They
do not borrow the live agent's retained-selection policy advance. Bound worker
delivery repeats the full grant/policy check under its final journal lock
before copying bytes; prepared delivery already rechecks there.

Both ordinary release paths re-read the slot's ProjectionID under the same
canonical journal lock that writes Released. A changed projection conflicts.
A retained nonempty projection must have both its private released marker and
the store's validated withdrawn receipt. The locked validator takes the caller's
journal and never recursively acquires WithBroker. The outer helper measurement
remains an early check and does not reserve the later projection field.

Two new controls exercise stale-generation delivery and a late projection bind.
The release regression pauses after a committed helper measurement, performs
the binding while that operation is suspended, then resumes cleanup. Its profile
cell uses actual broker transfer/acknowledgement into held; its worker cell
models the binder's protected slot write. These remain post-authentication
fixtures. Mac static checks do not confirm either suspected security finding;
the named Linux red-then-green runs remain required.

## Round 6 protected publication

Native projection uses a durable journal view acquired with the caller context.
After acquisition its write lifetime is bounded to 45 seconds, allowing the
30-second native control guard to record failure fencing before it unlocks.
Caller cancellation still aborts work; it does not suppress the fence write.
Send, acknowledgement, guard failure, timeout and export-close errors fence
under their owning transaction. Original descriptor facts remain authenticated
metadata on held replay; closed originals cannot be measured again.

Worker projection validates its complete retained selection marker and binds
the handoff, launch, helper lease and backend onto each worker slot. All material
and refresh paths re-read current policy, grants, expiry and revocation while
holding the canonical journal. Exposed Codex logins are quarantined with their
slot ownership retained, and broker originals close before exposure refusal.
Withdrawal decisions, store fence/completion and read-back share that lock.
Store completion precedes private slot or owner release.

Preparation stages bounded private writes in memory until every source fetch
and final validation passes. It then writes a pending selection marker before
publication and completes that marker last. A pending marker refuses retry.
Legacy profile binds without a completion marker and old task markers without
a completed Injection require protected reconciliation; no migration is inferred.
Grouped release validates and measures every slot before flushing any writes.
Canonical owners carry PendingRelease while slot writes flush and are freed
only after all those writes succeed. A failed flush retains that lease for
the exact cleanup retry. These are ordered, fenced file writes under a lock,
not a claim of filesystem-wide atomic rollback.

The eight r6 controls and their focused regressions remain pending Linux
red-then-green execution. The post-authentication fixtures do not establish
installed helper authentication, cross-UID isolation, root-owned positive
refresh or final environment placement.

## Round 7 live measurements and authority

Withdrawal never fills broker counts with expected zeros. It validates the
helper-owned shape first, closes original exports, and samples every tracked
File handle with Stat; only ErrClosed establishes absence for that handle.
Any other error or an open original retains the slots and refuses completion.
Live inventory belongs to the original broker process; a fresh empty flight
cannot stand in for a lost process's allocation.

Codex projection acquires a real exclusive kernel lock for each selected
canonical login. The empty private lock file contains no credential bytes.
Acknowledgement, gate use and refresh require the owning live lease. Withdrawal
closes those handles and independently opens each pinned lock target to probe
kernel exclusion. Duplicated descriptors and other holders remain observable.
The final shared validator receives these actual counts before store completion.
Canonical journal ownership stays allocated through completion and slot cleanup;
it is neither a live count nor released early to manufacture one. Missing live
inventory, unavailable measurement and changed lock identity refuse.

Linux descriptor facts enumerate the observing process's live FD table and count
write-access aliases to the exact device/inode. This is a scoped sample; immutable
seals separately prohibit writes through unobserved or later aliases. The field
comment states that scope. Regressions require actual zero, nonzero and closed
alias observations and a failed write through the sealed alias.

Begin and finish retain round 6's single canonical transaction and preserve
fresh refresh metadata. Begin reads back the exact private fence as well as the
store fence; released projections cannot begin withdrawal. Exposure quarantine
is written and read back before the production refusal. Both new and retained
slot acquisition refuse quarantined or collecting owners immediately.

Selected Material and Returned have one deferred cleanup before ownership is
passed to the successful result. Both slices clear on all selection failures,
including canonical-login read and ownership failures. All credential policy
reads use CurrentApprovedPolicy, including worker preparation, material delivery,
agent grants, profile acquisition, capture and eligibility. Historical scoped
policy cannot silently substitute for the approved head. The gate ticker runs
the full live gate check every 250 milliseconds and persists its refusal fence;
periodic checks do not replace the explicit final open checks.

Eleven r7 controls retain named assertion failures for these changes, alongside
the preceding 209 available controls. Their Linux runtime results remain pending.

## Round 8 prepared copies and interface refusal

Both prepared material producers call deliveryPolicy under the final canonical
journal lock before copying bytes. Agent task delivery also re-reads the exact
selected profile slot from its validated retained plan, checks its binding and
applies the same owner/policy check. A profile, task or worker retry cannot use
an earlier successful read as authority for a later copy. Worker checks precede
both the first handoff publication and the retained-handoff return branch.
deliveryPolicy uses CurrentApprovedPolicy, as corrected in round 7.

LockCredentialProjection converts the private concrete guard into its public
interface only after successful acquisition. Refusal returns a nil interface
with the original error. It does not add a no-op Close, ignore a failed policy
check or weaken the durable fence. The original gate-refusal test is retained.

Four r8 controls and focused regressions cover these paths. Authority changes
occur at the final selected-slot read under the actual encrypted journal.
Positive comparisons still require exact selected bytes and a usable guard.
The fixture models authenticated store/helper authority and does not establish
installed authentication or OS isolation. The old Linux nil-receiver failure
is retained evidence; corrected-source Linux runtime results remain pending.
