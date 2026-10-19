# Secrets dependencies after draft.4 fixes 10 and 11

This note applies to the secrets consumer draft on the fix-11 shared contract.
Acquire, Inject, InjectWorker, Release, RevokeInjection, Room and Eligibility
now have implementations in this lane. Their earlier owner-named placeholder
replies are removed. This does not establish a composed launch, a vendor login
or a live acceptance result. Round 7 splits the existing API withdrawal validator
into helper-shape and complete-receipt checks and clarifies measurement scope.
It changes no wire field, assembly, helper, identity or store implementation.

## Consumer implementation and actual dependencies

| Consumer | Implemented behavior | Required owning ports |
| --- | --- | --- |
| Acquire / Inject | Current reserved-life grants, exact sourced inputs/original selection, helper allocation/storage, private encrypted slots and exact retries. | StateStore.PendingEffects / Effect / LaunchPlan / Lane / Grants / Policy / ObjectMetadata / Blob / Events, GrantResolver.Revalidate, Helper.ResolveLaunchSources / ResolveLaunchStorage. |
| InjectWorker | Pre-spec encrypted preparation from a real claimed fixed Worker effect, exact WorkerLease/input/runtime and selected current SecretGrants. | StateStore.WorkerLease/Effect and protected object/grant ports; actual fixed worker enrollment and claim producer. |
| Prepared material | Validate the retained complete spec/handoff and helper runtime before returning selected bytes to the installed adapter. | LaunchControlSource.Handoff and Helper.ResolveRuntime; assembly must connect the concrete private delivery ports. |
| Room / Eligibility | Protected producer evidence, exact profile/model/vendor/runtime compatibility and retained private session/history binding; current paid/exclusion rules remain. | Protected profile enrollment and successful credential-evidence producer; actual store binding/plan/authority implementations. |
| Release / RevokeInjection | Compare a fresh helper observation, require measured zero-resource release, commit and reread its exact receipt, then tombstone run material and finish canonical refresh. | Helper.ObserveGate/Release, LaunchControlSource.Release/RecordRelease, retained LaunchBinding/LaunchPlan/Events and actual projection collection. |
| UsageWindowSource | Validate the actual causing run/from-profile, native usage mapping, sealed bootstrap/result, exact TSV and private retained raw/envelope bytes. | Real Store.WorkerBinding, WorkerBootstrap, installed UsageJobControl dispatch, protected profile/runtime enrollment and ObjectStore.RetainObject/read-back. |
| Active credential workers | Revalidate the actual native connection/frame, current worker claim, closed credential.inject operation and exact selected material. | Identity/native peer registry and every-frame writer checks; service routing to InjectMappedWorker/ MappedWorkerMaterial. |

Failures from these calls are returned unchanged. A missing constructor
dependency returns prerequisite_missing. A real owning method that is still
not_implemented remains an error; there is no permissive adapter, fabricated
Lane, successful source resolver or alternate privileged command in this lane.

## Composition and source-producer requirements

1. **Installed constructor inputs and unlock.** Assembly supplies installed
   Config, Clock and GrantResolver, plus the actual HelperControl and service
   LaunchControlSource for broker paths. ServiceScope is an installed internal
   lookup scope, never request data. Native starts locked and accepts its key
   only through the protected exact 32-byte reader. The fixed credential worker,
   authenticated endpoint/lease and key/material channel still need their owning
   implementation. RunInternal remains a typed barrier; argv alone cannot claim
   a job, find a key, refresh a login or fetch material.

2. **Profile enrollment and evidence production.** This lane defines the
   concrete protected InstallProfile method and encrypted profile/login records.
   The installed administrator/credential worker must supply a real canonical
   login ID across aliases, exact source grant, mode, full runtime/model/vendor
   enrollment and actual protected credential_evidence bytes. Room verifies
   their metadata/hash/generation/time and successful source operation; it does
   not authenticate a provider itself. No test-generated success or availability
   bit can serve as that production evidence. Supported returned file-login
   fields are the explicitly enrolled flat access_token, refresh_token and
   expires_at representation documented in CONTRACTS.md. Actual vendor formats
   and versions require an installed validated adapter; the synthetic JSON
   fixture is not proof that a vendor's raw refresh format is supported.

3. **Concrete protected material adapter.** The shared CredentialBroker
   interface still returns opaque metadata, not secret bytes. This consumer
   supplies PreparedSlotMaterial / PrepareWorkerMaterial for nonexecuting delivery,
   SlotMaterial for a retained binding, and ReturnSlot for the original refresh
   owner. They are concrete service-private methods, not RPC registrations,
   BlobRefs or an added public protocol. Assembly/helper must connect them through
   the installed protected channel, project only selected env/read-only files,
   avoid broad environment or registry inheritance, and collect those physical
   projections before lease/UID reuse. This lane does not claim an actual mount,
   process environment or removed runtime file based on an in-memory byte copy.

4. **Active reservation discovery.** The frozen Acquire/Inject signatures carry
   a LifeRef rather than ReservationID. The consumer uses PendingEffects only
   for bounded selectors, then independently reloads and checks the actual
   running claim and LaunchPlanRecord. The store must expose the relevant active
   claimed launch selector in that inventory. More than 256 selectors returns
   budget_exhausted; absent, ambiguous or stale selectors refuse. The current
   shared port has no next-page response cursor. Store/planner integration must
   verify these semantics and scale limits; a local launch-ID authority map is
   not an alternative.

5. **Internal continuation retention.** Public start/adopt/resume/turn use their
   exact retained Request frame and RequestDigest. Continue is a separate
   existing typed internal call. This consumer reads its original
   ContinuationRequest bytes, requires their JCS digest and reloads the current
   claimed ContinuationIntent, exact swap/eligibility/room, original operation,
   run/generation/epoch and previous binding. Lifecycle/store must agree on that
   original internal input representation and claimed-state projection. Fix 9
   names the launch_request object but does not separately enumerate an internal
   Continue envelope. No invented public continuation command is registered,
   and this consumer does not accept a differently shaped record as a fallback.
   The component fixture checks this explicit consumer requirement; composed
   continuation remains unverified until its owners run the same retained input.

6. **Unknown or interrupted cleanup.** Only the original retained binding and
   real helper measurement can release run credentials. Missing/revoked recovery,
   lost/unknown containment, an uncommitted receipt or an interrupted unbound
   preparation retains the slot and canonical owner. This lane adds no recovery
   authorization, force deletion or speculative UID reuse for those cases.
   Lifecycle/helper/store must supply the original stop/abort/reconciliation
   route and its retained binding/receipt; the consumer will not infer one from
   expiry or an empty process observation. The canonical latest refresh stays
   encrypted private registry state after a successful run-slot tombstone.

7. **Installed metadata acceptance and migration.** SecretList now authenticates
   the native metadata inventory and filters it through current human-session
   or life/run/grant authority. It uses a pinned internal event snapshot, without
   a public configuration-wide event route or value lookup. The real-store
   import/rotation/revocation, exact replay, intent fences and projection
   verification are implemented. The installed secrets client retains its
   actual same-connection metadata request/response. Installed recovery/injection
   acceptance and migration of historical successful events lacking the new
   private metadata projections remain open; see e2e/v2/ITEM-2-HANDOFF.md.

ChannelDestination.CredentialHandle still supplies no name/version/delivery
mapping by itself. InjectWorker accepts only exact SecretGrants already in the
job's current grant set. Messaging/enrollment must provide any channel-specific
authorized mapping through its owning implementation rather than widening this
consumer's caller selection.

## Verification and acceptance limits

The catalogue retains 153 earlier Go controls and adds seven fix-10 and nineteen
fix-11 and thirty fix-12 controls, for 209 available rows. The seven observer/probe controls and two runner regressions
remain separate. Nine full installed live controls remain unavailable. The
fix-9 positive and refusal tests cover reserved targets, foreign/stale authority,
changed inputs, caller paths/executables, missing binding after restart,
protected evidence, worker pre/post-spec ordering, measured cleanup, canonical
alias exclusion and supported refresh fields. The catalogue binds each deliberate
production edit to its exact focused test and assertion diagnostic.

All these runtime results are pending. Only the authorized Mac static checks
run here. The fixture stores/reloads actual JSON/blob/ciphertext bytes in the
API's bounded chunks, resolves independently retained source enrollment, hashes
real synthetic runtime files, and measures its owned Linux process/resources
when executed on Linux. Its authority records begin after authentication; it
does not implement a production StateStore, authenticated helper, OS containment
or vendor service. Its process measurement covers that owned fixture process
and its resource directories, not detached descendants or the whole machine.

The supervisor must run the exact retained source's unit/race tests and every
available red control before green on the authorized disposable Linux machine,
with both tag settings, then run the installed outside-observed acceptance cell
when its real dependencies exist. Preserve commands, exits, source/tool/binary
bytes and primary evidence. Static vet/formatting and the credential-free demo
runner are not authenticated AI-service tests. SECRET-INJECT,
CREDENTIAL-BOUND, OS-LINUX, LIFECYCLE-TREE and installed serve remain unclaimed.

## Usage dispatch and native integration still required

The source implementation replaces the owned UsageWindowSource placeholder.
It does not replace owner-named failures in service/store/native implementations.
UsageJobControl is a local installed adapter, not a shared API or public RPC.
No production implementation is installed by this lane or by the current
assembly. The outbox owner must allocate/reconcile one durable usage job under
the exact cause, retain its sealed UsageInput and narrow job grants, claim and
launch it through the real helper, and supply its actual input/result frames.
The separately confined worker calls RunUsageCommand with helper-held handles;
the adapter returns its actual result and the service commits/read-backs it
through the shared bootstrap port. A missing adapter returns prerequisite_missing;
an owner stub is returned unchanged. No event-service-UID query is a fallback.

The installed administrator must supply the protected vendor profile spelling,
runtime pins and real selected-profile projection in the worker-only home.
The Linux engine uses only standard private HOME/XDG paths and a fixed PATH;
it does not invent vendor credential-store switches or authenticate a provider.
The helper/native owners must prevent lane writes, broad registry mounts,
keyring/host-home fallback and escaped descendants. Memfd sealing protects the
bytes executed after hashing; it is not worker containment or authorization.

Component fixtures retain real synthetic input/object/journal bytes and actual
pipe exits. Their native worker facts identify the owned Linux test process;
their mapping records begin after authentication. They do not prove kernel
peer authentication, connector registry membership or a private worker UID.
The command fixture runs the actual test binary as a synthetic program, checks
fixed argv/private home/environment and file-backed stdout/exit, and tests the
real executable seals. The synthetic executable is installed as an exact private
mode-0500 copy, rather than trusting the Go build output's umask-dependent mode.
A group-writable copy must still refuse. A private readiness pipe proves the
real child started before the cancellation cell cancels; both actual stdout
and stderr overflow cells require unavailable and empty returned raw bytes.
Run these as an authorized nonroot Linux UID/GID. The
fresh outside vendor query and same-lane forged-pipe canary remain installed
acceptance work; no result in this draft proves either live boundary.

## Fix 12 composition boundaries

The owned broker methods and Linux SCM_RIGHTS exchange are implemented.
ProjectionIdentity is mandatory. Assembly already supplies that named field;
no assembly or shared API source was edited in this lane. The private native
worker host must call SendProjection, GuardProjection, ReceiveRefresh on the
authenticated root-helper connection. These library ports do not create a
listener or start a worker as the event-service UID.

Identity still owns real executable/kernel/audit-token/lifetime authorization.
Store owns unique projection reservation, writer CAS/epoch, current approved
policy and durable acknowledgement/fence/completion. Helper owns actual fixed
destination creation, copied/closed received descriptors, held-object receipts,
stop/abort/withdrawal measurement and final unprivileged execve placement.
Their current not_implemented errors propagate. A local Go fixture or metadata
receipt does not replace those native producers.

Darwin export refuses until exclusive immutable ownership is implemented.
Uncertain original-process recovery remains fenced and needs the owning
identity/store/native recovery decision; the broker never re-exports a new
slot on a missing live export. NATIVE-TASK-ENVP-1 still needs its actual canary
in helper, bootstrap, boundary/outer launcher and final child with an early-env
control. No such run, root helper, vendor login or AI-service call occurred here.

The native journal format now requires authenticated envelope generation.
Legacy envelopes need protected migration; rollback of a complete authenticated
record still needs an external monotonic inventory. Bounded head replay remains
linear within its explicit page/event/byte window. The usage HOME fd path P3
remains open until its pinned subprocess behavior or helper namespace path is
established. These limitations are not reported as completed native acceptance.

The outside-broker composition owned by lb-v2-integrate must install the
runner-owned codex.CredentialValidator{} as Dependencies.CodexValidator and
claudock.CredentialValidator{} as Dependencies.HeadlessValidator. Secrets holds
only their narrow interfaces and refuses a missing selected-mode validator.
Neither vendor validation nor native host installation is replaced by a
broker-side schema copy. Existing runner parsers and controls remain unchanged.

Round 4 restores exact current-policy equality for worker preparation and
delivery and adds a final bound-delivery recheck. Ordinary release checks the
latest projection in its tombstone transaction. The stale-policy and interleaved
binding controls require their own Linux failure and candidate success before
the suspected scan findings can be considered demonstrated and closed.

## Round 6 recovery and verification limits

The native backend now implements the private DurableBackend capability.
Another installed backend must provide equivalent bounded failure journaling;
projection refuses without it. Ordinary WithBroker cancellation semantics are
unchanged. Failure to persist a fence is itself returned, with ownership retained.

Incomplete preparation markers and pre-upgrade binds without complete markers
need an authorized protected reconciliation route. This lane does not invent
migration authority, recycle those slots or resume a partial bind. Failed
group cleanup retains PendingRelease on its canonical owner until its exact
retry completes. Store/helper/identity producers and both counted reviews
remain independent acceptance requirements.

## Round 7 measurement limits

The native private journal supplies actual kernel refresh locks. An alternate
journal implementation must implement that private acquisition port and its
live Check, Close and independent Held observation; journal flags and a constant
count do not satisfy it. The API receipt shape remains unchanged. Helper-shape
validation is separate from the mandatory complete measured receipt validation.

Kernel probes cover the selected canonical login locks; original export probes
cover the original broker flight's tracked material descriptors. The FD alias
sample covers the current Linux process and still requires full immutable seals.
Unknown original-broker lifetime, changed probe identity and missing inventory
refuse. Runtime Linux red-before-green controls, installed native producers and
both independent reviews are still required. Mac vet establishes static validity
only. No authenticated AI-service result is claimed by a demo or component model.

## Round 8 remaining verification

Prepared profile, task and worker copies now apply current delivery authority
in their final journal scope. The source ambiguity was already removed in
round 7. The public gate wrapper also preserves refusal without returning a
typed nil pointer in its interface. These corrections retain the same installed
ports and wire shape; no assembly, identity or helper implementation is added.

The prior source's race and race-faults log shows a nil guard receiver during
cleanup after policy refusal. The new wrapper and assertions need the exact
candidate's Linux run. Prepared-copy security effects remain suspected until
the focused ordinary-byte controls demonstrate the removed gate fails and the
candidate passes. Static vet and a fixture's claimed authority do not establish
root-helper authentication, final environment placement or a live vendor test.
